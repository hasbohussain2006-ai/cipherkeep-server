#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
live_proof_supabase.py — إثبات حي كامل لـ license_server.py الحقيقي
(الملف نفسه، بلا أي تبسيط) ضد Supabase فعلية.

قبل التشغيل، رتّب هذي الملفات كلها بنفس المجلد:
    license_server.py
    cipherkeep_core/   (المجلد كامل بكل ملفاته الفرعية ومجلد tests)
    cipherkeep_dal/     (المجلد كامل بكل ملفاته الفرعية ومجلد tests)
    live_proof_supabase.py   (هذا الملف)

عبّي 4 قيم تحت، وشغّل.

ملاحظة: يستخدم Flask test_client (توجيه داخل نفس العملية بدل فتح
منفذ شبكة فعلي) -- هذا لا يمس أي شيء نتحقق منه، لأن التواصل الفعلي
مع Supabase (عبر CipherKeepCore + DAL الحقيقيين) يمر بالكامل عبر
HTTPS حقيقي، بلا محاكاة إطلاقًا.
"""

import os
import sys
import base64
import struct
import json

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
_PROJECT_ROOT = os.path.abspath(_PROJECT_ROOT)
_ADAPTERS_DIR = os.path.join(_PROJECT_ROOT, "adapters")
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, _ADAPTERS_DIR)

# ============================================================
# عبّي هذي القيم الأربع قبل التشغيل
# ============================================================
os.environ["ADMIN_TOKEN"] = "CipherKeep_Admin_2026_X9m!Secure"
os.environ["SUPABASE_URL"] = "https://YOUR_PROJECT.supabase.co"
os.environ["SUPABASE_SERVICE_KEY"] = "YOUR_SUPABASE_SERVICE_ROLE_KEY"
os.environ["CIPHERKEEP_MASTER_KEY"] = "CipherKeep_Master_2026_7x!A9#QmL2@Secure"
# ============================================================

if "ضع_" in os.environ["SUPABASE_URL"]:
    print("❌ خطأ: عبّي القيم الأربع بأعلى الملف قبل التشغيل.")
    sys.exit(1)

# استيراد license_server بعد ضبط env vars -- عشان يقرأها صح عند الإقلاع
import license_server  # noqa: E402

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cipherkeep_core.crypto import MAGIC, HEADER_FMT  # noqa: E402

# ── تتبّع استدعاءات الإشعار، بدون الحاجة لبوت تيليجرام حقيقي ──
_notify_calls = []


def _capturing_notify(msg):
    _notify_calls.append(msg)
    print(f"  📨 (محاكاة إشعار) كان سيُرسَل لتيليجرام: {msg!r}")


license_server._notify = _capturing_notify


def _build_test_blob(key, filename, source):
    name_bytes = filename.encode("utf-8")
    inner = struct.pack(">H", len(name_bytes)) + name_bytes + source
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, inner, associated_data=MAGIC)
    header = struct.pack(HEADER_FMT, MAGIC, 2, 3, 0, b"\x00" * 16, nonce)
    return header + ciphertext


def _print_step(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def _print_request(method, path, headers=None, body=None):
    print(f"→ {method} {path}")
    if headers:
        print(f"  Headers: {headers}")
    if body is not None:
        shown = dict(body)
        if "ciphertext_b64" in shown:
            shown["ciphertext_b64"] = shown["ciphertext_b64"][:30] + "...(مقصوص للعرض)"
        print(f"  Body: {json.dumps(shown, ensure_ascii=False)}")


def _print_response(resp):
    print(f"← الحالة: {resp.status_code}")
    data = resp.get_json()
    shown = dict(data) if data else data
    if shown and "source_b64" in shown:
        shown["source_b64"] = shown["source_b64"][:30] + "...(مقصوص للعرض)"
    print(f"  الرد: {json.dumps(shown, ensure_ascii=False)}")
    return data


def main():
    if license_server._core is None:
        print("❌ فشل الاتصال بـ Supabase عند إقلاع license_server.py.")
        print("راجع رسالة التحذير اللي طلعت فوق وتأكد من القيم الأربع.")
        sys.exit(1)

    print("✅ license_server.py اتصل بـ Supabase الحقيقية بنجاح عند الإقلاع.")
    client = license_server.app.test_client()

    # ---------- الخطوة 1: إنشاء كود عبر /admin/create فعليًا ----------
    _print_step("الخطوة 1: POST /admin/create")
    body = {"label": "إثبات حي - الخطوة 4", "max_devices": 1}
    headers = {"X-Admin-Token": os.environ["ADMIN_TOKEN"]}
    _print_request("POST", "/admin/create", headers, body)
    resp = client.post("/admin/create", json=body, headers=headers)
    data = _print_response(resp)

    if resp.status_code != 200 or not data.get("ok"):
        print("\n❌ فشلت الخطوة 1. توقف الاختبار.")
        sys.exit(1)

    code = data["code"]
    key = base64.b64decode(data["key_b64"])
    print(f"\n✅ الكود أُنشئ فعليًا بـ Supabase: {code}")

    stored = license_server._core._codes.get(code)
    print(f"🔍 تأكيد قراءة مباشرة من Supabase عبر Core: "
          f"label={stored.label!r}, max_devices={stored.max_devices}")

    blob = _build_test_blob(key, "proof.py", b"print('hello from live proof')")
    blob_b64 = base64.b64encode(blob).decode("ascii")

    # ---------- الخطوة 2: أول تحقق (جهاز جديد) ----------
    _print_step("الخطوة 2: POST /verify (جهاز أول، أول مرة)")
    body2 = {"code": code, "device_id": "live-device-A", "ciphertext_b64": blob_b64}
    _print_request("POST", "/verify", None, body2)
    notify_count_before = len(_notify_calls)
    resp2 = client.post("/verify", json=body2)
    data2 = _print_response(resp2)

    if not data2.get("ok"):
        print("\n❌ فشلت الخطوة 2. توقف الاختبار.")
        sys.exit(1)

    decoded_source = base64.b64decode(data2["source_b64"])
    print(f"\n✅ فك التشفير نجح فعليًا. المحتوى المسترجَع: {decoded_source!r}")
    assert decoded_source == b"print('hello from live proof')"
    print("✅ المحتوى مطابق تمامًا لما شُفِّر.")
    notified_step2 = len(_notify_calls) > notify_count_before
    print(f"📬 هل أُرسل إشعار بهذي الخطوة؟ {notified_step2} (يُتوقَّع: True — أول جهاز)")

    # ---------- الخطوة 3: نفس الجهاز مرة ثانية ----------
    _print_step("الخطوة 3: POST /verify (نفس الجهاز الأول، مرة ثانية)")
    _print_request("POST", "/verify", None, body2)
    notify_count_before = len(_notify_calls)
    resp3 = client.post("/verify", json=body2)
    data3 = _print_response(resp3)
    if not data3.get("ok"):
        print("\n❌ فشلت الخطوة 3. توقف الاختبار.")
        sys.exit(1)
    notified_step3 = len(_notify_calls) > notify_count_before
    print(f"\n✅ نجح التحقق الثاني لنفس الجهاز.")
    print(f"📬 هل أُرسل إشعار بهذي الخطوة؟ {notified_step3} (يُتوقَّع: False — جهاز معروف)")

    # ---------- الخطوة 4: جهاز ثانٍ (max_devices=1، يُفترض يُرفض) ----------
    _print_step("الخطوة 4: POST /verify (جهاز ثانٍ مختلف، max_devices=1)")
    body4 = {"code": code, "device_id": "live-device-B", "ciphertext_b64": blob_b64}
    _print_request("POST", "/verify", None, body4)
    resp4 = client.post("/verify", json=body4)
    data4 = _print_response(resp4)

    if data4.get("ok") or data4.get("reason") != "device_limit":
        print("\n❌ مشكلة حقيقية: كان يفترض رفض الجهاز الثاني بسبب device_limit.")
        sys.exit(1)
    print("\n✅ الرفض صحيح تمامًا (device_limit) — حد الأجهزة يشتغل فعليًا.")

    # ---------- تأكيد نهائي: لا أي اعتماد على licenses.json ----------
    _print_step("تأكيد نهائي: هل licenses.json له أي علاقة بهذا الكود؟")
    if license_server.DATA_FILE.exists():
        local_data = json.loads(license_server.DATA_FILE.read_text(encoding="utf-8"))
        found_locally = code in local_data.get("codes", {})
        print(f"هل الكود '{code}' موجود بـ licenses.json المحلي؟ {found_locally}")
        if found_locally:
            print("❌ تحذير: موجود محليًا أيضًا — غير متوقع، راجعه.")
        else:
            print("✅ الكود غير موجود إطلاقًا بـ licenses.json — Supabase المصدر الوحيد فعليًا.")
    else:
        print("✅ licenses.json غير موجود أصلًا بهذي البيئة — لا يوجد أي اعتماد عليه.")

    print("\n" + "=" * 60)
    print("ملخص الإشعارات المُرسَلة بكل الاختبار:", _notify_calls)
    print("=" * 60)
    print("✅ كل الخطوات نجحت. الخطوة 4 مثبتة حيًا على Supabase فعلية.")
    print("انسخ كل هذا الناتج كامل وابعثه بالمحادثة.")
    print("=" * 60)


if __name__ == "__main__":
    main()
