"""
اختبارات لطبقة SupabaseCodeRepository / SupabaseDeviceRepository،
باستخدام unittest.mock لمحاكاة استجابات HTTP.

⚠️ تنبيه صريح: هذي الاختبارات تثبت صحة *منطق بايثون الداخلي*
(بناء الطلب، تحليل الرد، معالجة الأخطاء) — لا تثبت التوافق الفعلي
مع Supabase حية، لأن بيئة التنفيذ هنا بلا اتصال شبكي. الإثبات
الفعلي يحتاج smoke_test_supabase.py يُشغَّل ببيئة فيها شبكة
وبيانات اعتماد Supabase حقيقية.
"""

import sys
import os
import base64
import unittest
from unittest.mock import MagicMock
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from cipherkeep_dal.supabase_repositories import (
    SupabaseCodeRepository,
    SupabaseDeviceRepository,
    SupabaseModeratorRepository,
    SupabaseRequestError,
)
from cipherkeep_core.models import DeviceClaimStatus


def _fake_response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else []
    resp.text = text
    return resp


class TestSupabaseCodeRepository(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.repo = SupabaseCodeRepository(
            base_url="https://fake-project.supabase.co",
            service_key="fake-service-key",
            passphrase="fake-passphrase",
            session=self.session,
        )

    def test_create_sends_base64_encoded_key_and_correct_rpc_endpoint(self):
        self.session.post.return_value = _fake_response(status_code=201)

        self.repo.create(
            code="ABC-123",
            key_material=b"raw-secret-bytes",
            label="عميل تجريبي",
            max_devices=2,
            trial=False,
            expires_at=None,
        )

        self.session.post.assert_called_once()
        called_url = self.session.post.call_args.args[0]
        called_payload = self.session.post.call_args.kwargs["json"]

        self.assertTrue(called_url.endswith("/rest/v1/rpc/ck_create_code"))
        self.assertEqual(called_payload["p_code"], "ABC-123")
        self.assertEqual(
            base64.b64decode(called_payload["p_key_material_b64"]), b"raw-secret-bytes"
        )
        self.assertEqual(called_payload["p_label"], "عميل تجريبي")
        self.assertEqual(called_payload["p_max_devices"], 2)
        self.assertEqual(called_payload["p_passphrase"], "fake-passphrase")
        self.assertIsNone(called_payload["p_expires_at"])
        # moderator_id لم يُمرَّر → يجب أن يصل None (توافق خلفي مع Phase 1)
        self.assertIsNone(called_payload["p_moderator_id"])

    def test_create_sends_moderator_id_when_provided(self):
        self.session.post.return_value = _fake_response(status_code=201)

        self.repo.create(
            code="ABC-123",
            key_material=b"raw-secret-bytes",
            label=None,
            max_devices=1,
            trial=False,
            expires_at=None,
            moderator_id="mod-1",
        )

        called_payload = self.session.post.call_args.kwargs["json"]
        self.assertEqual(called_payload["p_moderator_id"], "mod-1")

    def test_create_raises_on_http_error(self):
        self.session.post.return_value = _fake_response(status_code=400, text="bad request")
        with self.assertRaises(SupabaseRequestError):
            self.repo.create("X", b"k", None, 1, False, None)

    def test_get_returns_none_when_no_rows(self):
        self.session.post.return_value = _fake_response(status_code=200, json_data=[])
        result = self.repo.get("MISSING-CODE")
        self.assertIsNone(result)

    def test_get_parses_row_into_license_code_with_decoded_key(self):
        raw_key = b"decrypted-key-material"
        row = {
            "code": "ABC-123",
            "key_material_b64": base64.b64encode(raw_key).decode("ascii"),
            "label": "test",
            "max_devices": 3,
            "trial": True,
            "revoked": False,
            "expires_at": "2026-08-01T00:00:00+00:00",
            "created_at": "2026-07-12T10:00:00+00:00",
            "moderator_id": "mod-1",
        }
        self.session.post.return_value = _fake_response(status_code=200, json_data=[row])

        result = self.repo.get("ABC-123")

        self.assertIsNotNone(result)
        self.assertEqual(result.code, "ABC-123")
        self.assertEqual(result.key_material, raw_key)
        self.assertEqual(result.max_devices, 3)
        self.assertTrue(result.trial)
        self.assertFalse(result.revoked)
        self.assertEqual(result.expires_at, datetime(2026, 8, 1, tzinfo=timezone.utc))
        self.assertEqual(result.moderator_id, "mod-1")

    def test_get_parses_row_without_moderator_id_key_as_none(self):
        # صف قديم (قبل migration الحقل) — .get() يجب ألا يفشل
        raw_key = b"decrypted-key-material"
        row = {
            "code": "ABC-123",
            "key_material_b64": base64.b64encode(raw_key).decode("ascii"),
            "label": None,
            "max_devices": 1,
            "trial": False,
            "revoked": False,
            "expires_at": None,
            "created_at": "2026-07-12T10:00:00+00:00",
            # لا يوجد مفتاح "moderator_id" إطلاقًا بهذا الصف
        }
        self.session.post.return_value = _fake_response(status_code=200, json_data=[row])

        result = self.repo.get("ABC-123")
        self.assertIsNone(result.moderator_id)

    def test_revoke_sends_correct_rpc_payload(self):
        self.session.post.return_value = _fake_response(status_code=200)
        self.repo.revoke("ABC-123")

        called_url = self.session.post.call_args.args[0]
        called_payload = self.session.post.call_args.kwargs["json"]
        self.assertTrue(called_url.endswith("/rest/v1/rpc/ck_revoke_code"))
        self.assertEqual(called_payload["p_code"], "ABC-123")

    def test_revoke_raises_on_http_error(self):
        self.session.post.return_value = _fake_response(status_code=404, text="not found")
        with self.assertRaises(SupabaseRequestError):
            self.repo.revoke("ABC-123")

    def test_extend_sends_correct_rpc_payload(self):
        self.session.post.return_value = _fake_response(status_code=200)
        new_expiry = datetime(2026, 12, 1, tzinfo=timezone.utc)
        self.repo.extend("ABC-123", new_expiry)

        called_url = self.session.post.call_args.args[0]
        called_payload = self.session.post.call_args.kwargs["json"]
        self.assertTrue(called_url.endswith("/rest/v1/rpc/ck_extend_code"))
        self.assertEqual(called_payload["p_code"], "ABC-123")
        self.assertEqual(called_payload["p_new_expires_at"], new_expiry.isoformat())

    def test_extend_raises_on_http_error(self):
        self.session.post.return_value = _fake_response(status_code=500, text="server error")
        with self.assertRaises(SupabaseRequestError):
            self.repo.extend("ABC-123", datetime(2026, 12, 1, tzinfo=timezone.utc))


class TestSupabaseDeviceRepository(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.repo = SupabaseDeviceRepository(
            base_url="https://fake-project.supabase.co",
            service_key="fake-service-key",
            session=self.session,
        )

    def test_claim_device_slot_sends_correct_rpc_payload(self):
        self.session.post.return_value = _fake_response(status_code=200, json_data="registered")
        now = datetime(2026, 7, 12, 10, 0, 0, tzinfo=timezone.utc)

        result = self.repo.claim_device_slot("ABC-123", "device-xyz", now)

        called_url = self.session.post.call_args.args[0]
        called_payload = self.session.post.call_args.kwargs["json"]
        self.assertTrue(called_url.endswith("/rest/v1/rpc/ck_claim_device_slot"))
        self.assertEqual(called_payload["p_code"], "ABC-123")
        self.assertEqual(called_payload["p_device_fingerprint"], "device-xyz")
        self.assertEqual(called_payload["p_now"], now.isoformat())
        self.assertEqual(result, DeviceClaimStatus.REGISTERED)

    def test_claim_device_slot_parses_already_registered(self):
        self.session.post.return_value = _fake_response(
            status_code=200, json_data="already_registered"
        )
        result = self.repo.claim_device_slot("ABC-123", "device-xyz", datetime.now(timezone.utc))
        self.assertEqual(result, DeviceClaimStatus.ALREADY_REGISTERED)

    def test_claim_device_slot_parses_limit_reached(self):
        self.session.post.return_value = _fake_response(
            status_code=200, json_data="limit_reached"
        )
        result = self.repo.claim_device_slot("ABC-123", "device-xyz", datetime.now(timezone.utc))
        self.assertEqual(result, DeviceClaimStatus.LIMIT_REACHED)

    def test_claim_device_slot_handles_list_wrapped_response_defensively(self):
        # حالة احتياطية: لو PostgREST غلّف القيمة الاسكالر بقائمة —
        # هذا السلوك بالذات يحتاج تأكيدًا من الاختبار الحي، لا أقدر
        # أثبته من بيئتي بلا شبكة.
        self.session.post.return_value = _fake_response(status_code=200, json_data=["registered"])
        result = self.repo.claim_device_slot("ABC-123", "device-xyz", datetime.now(timezone.utc))
        self.assertEqual(result, DeviceClaimStatus.REGISTERED)

    def test_claim_device_slot_raises_on_http_error(self):
        self.session.post.return_value = _fake_response(status_code=500, text="server error")
        with self.assertRaises(SupabaseRequestError):
            self.repo.claim_device_slot("ABC-123", "device-xyz", datetime.now(timezone.utc))


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestSupabaseModeratorRepository(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock()
        self.repo = SupabaseModeratorRepository(
            base_url="https://fake-project.supabase.co",
            service_key="fake-service-key",
            session=self.session,
        )

    def test_create_sends_correct_rpc_payload(self):
        self.session.post.return_value = _fake_response(status_code=201)

        self.repo.create(
            moderator_id="mod-1",
            external_id="telegram-999",
            display_name="أحمد",
            can_encrypt_server=True,
            can_decrypt=False,
        )

        called_url = self.session.post.call_args.args[0]
        called_payload = self.session.post.call_args.kwargs["json"]
        self.assertTrue(called_url.endswith("/rest/v1/rpc/ck_register_moderator"))
        self.assertEqual(called_payload["p_moderator_id"], "mod-1")
        self.assertEqual(called_payload["p_external_id"], "telegram-999")
        self.assertEqual(called_payload["p_display_name"], "أحمد")
        self.assertTrue(called_payload["p_can_encrypt_server"])
        self.assertFalse(called_payload["p_can_decrypt"])

    def test_create_raises_on_http_error(self):
        self.session.post.return_value = _fake_response(status_code=400, text="bad request")
        with self.assertRaises(SupabaseRequestError):
            self.repo.create("mod-1", "telegram-999", None, False, False)

    def test_get_by_external_id_returns_none_when_no_rows(self):
        self.session.post.return_value = _fake_response(status_code=200, json_data=[])
        result = self.repo.get_by_external_id("ghost-id")
        self.assertIsNone(result)

    def test_get_by_external_id_parses_row_into_moderator(self):
        row = {
            "moderator_id": "mod-1",
            "external_id": "telegram-999",
            "display_name": "أحمد",
            "can_encrypt_server": True,
            "can_decrypt": False,
            "created_at": "2026-07-16T10:00:00+00:00",
        }
        self.session.post.return_value = _fake_response(status_code=200, json_data=[row])

        result = self.repo.get_by_external_id("telegram-999")

        self.assertIsNotNone(result)
        self.assertEqual(result.moderator_id, "mod-1")
        self.assertEqual(result.external_id, "telegram-999")
        self.assertEqual(result.display_name, "أحمد")
        self.assertTrue(result.can_encrypt_server)
        self.assertFalse(result.can_decrypt)

    def test_get_by_external_id_raises_on_http_error(self):
        self.session.post.return_value = _fake_response(status_code=500, text="server error")
        with self.assertRaises(SupabaseRequestError):
            self.repo.get_by_external_id("telegram-999")
