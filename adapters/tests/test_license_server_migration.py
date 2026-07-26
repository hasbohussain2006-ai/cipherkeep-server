"""
اختبار شامل لـ license_server.py المُرحَّل — Flask test client حقيقي
+ مستودعات وهمية (Fakes) محقونة بدل Supabase الحقيقية. صفر شبكة.

الهدف: التأكد إن الاستجابات (JSON + أكواد HTTP) مطابقة حرفيًا لسلوك
license_server.py الأصلي قبل الترحيل.
"""

import os
import sys
import struct
import base64
import unittest

# جذر المشروع (لـcipherkeep_core/cipherkeep_dal) + مجلد adapters/
# (لـimport license_server) — صريحان، بلا اعتماد على ترتيب استيراد ضمني.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_ADAPTERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, _ADAPTERS_DIR)

os.environ["ADMIN_TOKEN"] = "test-admin-token"

import license_server
from cipherkeep_core import CipherKeepCore, ServerModeService
from cipherkeep_core.crypto import MAGIC, HEADER_FMT
from cipherkeep_core.fakes import FakeCodeRepository, FakeDeviceRepository
from cipherkeep_dal.supabase_repositories import SupabaseRequestError
import requests

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _build_test_blob(key, filename, source):
    name_bytes = filename.encode("utf-8")
    inner = struct.pack(">H", len(name_bytes)) + name_bytes + source
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, inner, associated_data=MAGIC)
    header = struct.pack(HEADER_FMT, MAGIC, 2, 3, 0, b"\x00" * 16, nonce)
    return header + ciphertext


class TestLicenseServerMigration(unittest.TestCase):
    def setUp(self):
        # حقن مستودعات وهمية بدل Supabase الحقيقية
        self.codes = FakeCodeRepository()
        self.devices = FakeDeviceRepository(self.codes)
        core = CipherKeepCore(self.codes, self.devices)
        license_server._core = core
        license_server._server_mode = ServerModeService(core)

        # تفريغ حالة تحديد المعدل بين الاختبارات
        license_server._fail_tracker.clear()

        self.client = license_server.app.test_client()

    # ---------- /admin/create ----------

    def test_admin_create_requires_token(self):
        resp = self.client.post("/admin/create", json={})
        self.assertEqual(resp.status_code, 401)
        self.assertFalse(resp.get_json()["ok"])

    def test_admin_create_success_shape(self):
        resp = self.client.post(
            "/admin/create",
            json={"label": "عميل تجريبي", "max_devices": 2},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertIn("code", data)
        self.assertIn("key_b64", data)
        # المفتاح فعليًا مخزَّن بـFake repo عبر Core
        stored = self.codes.get(data["code"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored.max_devices, 2)
        self.assertEqual(stored.label, "عميل تجريبي")

    def test_admin_create_trial_forces_single_device(self):
        resp = self.client.post(
            "/admin/create",
            json={"trial": True, "max_devices": 5},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        data = resp.get_json()
        stored = self.codes.get(data["code"])
        self.assertEqual(stored.max_devices, 1)
        self.assertTrue(stored.trial)
        self.assertIsNotNone(stored.expires_at)

    # ---------- /verify ----------

    def _create_code(self, max_devices=1, label=None):
        key = os.urandom(32)
        self.codes.create(
            code="TEST-CODE",
            key_material=key,
            label=label,
            max_devices=max_devices,
            trial=False,
            expires_at=None,
        )
        return key

    def test_verify_unknown_code_matches_original_shape(self):
        resp = self.client.post(
            "/verify",
            json={"code": "GHOST", "device_id": "d1", "ciphertext_b64": ""},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json(), {"ok": False, "reason": "invalid_or_revoked"})

    def test_verify_revoked_code_matches_original_shape(self):
        self._create_code()
        self.codes._force_revoke("TEST-CODE")
        resp = self.client.post(
            "/verify",
            json={"code": "TEST-CODE", "device_id": "d1", "ciphertext_b64": ""},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.get_json()["reason"], "invalid_or_revoked")

    def test_verify_success_full_roundtrip(self):
        key = self._create_code(max_devices=1, label="عميل")
        blob = _build_test_blob(key, "hello.py", b"print(1)")
        resp = self.client.post(
            "/verify",
            json={
                "code": "TEST-CODE",
                "device_id": "d1",
                "ciphertext_b64": base64.b64encode(blob).decode("ascii"),
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["name"], "hello.py")
        self.assertEqual(base64.b64decode(data["source_b64"]), b"print(1)")

    def test_verify_device_limit_matches_original_shape(self):
        key = self._create_code(max_devices=1)
        blob = _build_test_blob(key, "hello.py", b"print(1)")
        b64 = base64.b64encode(blob).decode("ascii")

        self.client.post(
            "/verify", json={"code": "TEST-CODE", "device_id": "d1", "ciphertext_b64": b64}
        )
        resp2 = self.client.post(
            "/verify", json={"code": "TEST-CODE", "device_id": "d2", "ciphertext_b64": b64}
        )
        self.assertEqual(resp2.status_code, 403)
        self.assertEqual(resp2.get_json(), {"ok": False, "reason": "device_limit"})

    def test_verify_decrypt_error_matches_original_shape(self):
        self._create_code(max_devices=1)
        resp = self.client.post(
            "/verify",
            json={"code": "TEST-CODE", "device_id": "d1", "ciphertext_b64": "not-valid-base64!!"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json(), {"ok": False, "reason": "decrypt_error"})

    def test_verify_same_device_twice_both_succeed(self):
        key = self._create_code(max_devices=1)
        blob = _build_test_blob(key, "hello.py", b"print(1)")
        b64 = base64.b64encode(blob).decode("ascii")

        r1 = self.client.post(
            "/verify", json={"code": "TEST-CODE", "device_id": "d1", "ciphertext_b64": b64}
        )
        r2 = self.client.post(
            "/verify", json={"code": "TEST-CODE", "device_id": "d1", "ciphertext_b64": b64}
        )
        self.assertTrue(r1.get_json()["ok"])
        self.assertTrue(r2.get_json()["ok"])


class _BrokenCodeRepo:
    """مستودع أكواد وهمي يفشل عمدًا -- يحاكي انقطاع اتصال حقيقي أو
    رد خطأ فعلي من Supabase، لاختبار إصلاح #19."""

    def __init__(self, exc):
        self._exc = exc

    def get(self, code):
        raise self._exc

    def create(self, *a, **kw):
        raise self._exc

    def revoke(self, code):
        raise self._exc

    def extend(self, code, new_expires_at):
        raise self._exc


class _BrokenDeviceRepo:
    def __init__(self, exc):
        self._exc = exc

    def claim_device_slot(self, *a, **kw):
        raise self._exc


class _BrokenAdminCodeRepo:
    def __init__(self, exc):
        self._exc = exc

    def list_all_codes(self):
        raise self._exc


class TestBackendUnavailableHandling(unittest.TestCase):
    """
    اختبار إصلاح #19: أي فشل اتصال/طلب فعلي بـSupabase (لا فشل
    تهيئة عند الإقلاع -- ذاك مختبَر بحالات أخرى) يجب أن يُترجَم لرد
    JSON نظيف موحَّد (ok:false, reason:backend_unavailable, 500)،
    بلا أي Stack Trace متسرّب، على كل نقاط الدخول الأربع التي تلمس
    DAL. يغطي كلا نوعي الفشل: SupabaseRequestError (رد HTTP غير
    ناجح من Supabase) وrequests.exceptions.RequestException (فشل
    شبكي أدنى مستوى، قبل وصول أي رد أصلًا).
    """

    def _make_broken_core(self, exc):
        core = CipherKeepCore(
            _BrokenCodeRepo(exc),
            _BrokenDeviceRepo(exc),
            admin_codes=_BrokenAdminCodeRepo(exc),
        )
        license_server._core = core
        license_server._server_mode = ServerModeService(core)
        license_server._fail_tracker.clear()
        return license_server.app.test_client()

    def test_verify_returns_backend_unavailable_on_connection_error(self):
        client = self._make_broken_core(requests.exceptions.ConnectionError("boom"))
        resp = client.post(
            "/verify", json={"code": "X", "device_id": "d", "ciphertext_b64": ""}
        )
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.get_json(), {"ok": False, "reason": "backend_unavailable"})

    def test_admin_create_returns_backend_unavailable_on_supabase_request_error(self):
        client = self._make_broken_core(SupabaseRequestError("simulated 503"))
        resp = client.post(
            "/admin/create",
            json={"label": "x"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.get_json(), {"ok": False, "reason": "backend_unavailable"})

    def test_admin_revoke_returns_backend_unavailable_on_connection_error(self):
        client = self._make_broken_core(requests.exceptions.ConnectionError("boom"))
        resp = client.post(
            "/admin/revoke",
            json={"code": "GHOST"},
            headers={"X-Admin-Token": "test-admin-token"},
        )
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.get_json(), {"ok": False, "reason": "backend_unavailable"})

    def test_admin_pause_all_returns_backend_unavailable_on_supabase_request_error(self):
        # هذا الاختبار تحديدًا يغطي الاكتشاف الثاني بإصلاح #19: كان
        # "except RuntimeError" العام سابقًا يبتلع SupabaseRequestError
        # صامتًا (لأنها وريثة RuntimeError) ويرجع نجاحًا وهميًا. بعد
        # الإصلاح (RepositoryNotConfigured منفصلة الوراثة)، الخطأ
        # الحقيقي يصل الآن لمعالج backend_unavailable كما يجب.
        client = self._make_broken_core(SupabaseRequestError("simulated 503"))
        resp = client.post(
            "/admin/pause_all", json={}, headers={"X-Admin-Token": "test-admin-token"}
        )
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.get_json(), {"ok": False, "reason": "backend_unavailable"})

    def test_admin_pause_all_without_admin_codes_still_works_normally(self):
        # سيناريو الانحدار: Core بلا admin_codes إطلاقًا (حالة طبيعية،
        # لا خطأ) يجب أن يبقى يعمل بنجاح محلي فقط، بلا لمس المعالج
        # الجديد إطلاقًا -- التأكد إن الإصلاح ما كسر السلوك الطبيعي.
        codes = FakeCodeRepository()
        devices = FakeDeviceRepository(codes)
        core_no_admin_codes = CipherKeepCore(codes, devices)  # بلا admin_codes
        license_server._core = core_no_admin_codes
        license_server._server_mode = ServerModeService(core_no_admin_codes)
        client = license_server.app.test_client()

        resp = client.post(
            "/admin/pause_all", json={}, headers={"X-Admin-Token": "test-admin-token"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["supabase_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
