#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
full_lifecycle_proof.py — إثبات حي شامل (Roadmap خطوة 7):
إنشاء → تشفير → تحقق → محاكاة إعادة نشر Render → تحقق مرة ثانية.

الفرق عن live_proof_supabase.py: هذا يحاكي إعادة نشر فعلية بإعادة
بناء كائن license_server.app + Core + DAL من الصفر منتصف السكربت
(بدل الاعتماد على نفس الكائن طول الوقت) -- يثبت إن البيانات تصمد
فعليًا عبر "إعادة إقلاع"، لا مجرد نفس الجلسة.

نفس متطلبات الملفات والقيم الأربع مثل live_proof_supabase.py.
"""

import os
import sys
import base64
import struct
import importlib

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
_PROJECT_ROOT = os.path.abspath(_PROJECT_ROOT)
_ADAPTERS_DIR = os.path.join(_PROJECT_ROOT, "adapters")
sys.path.insert(0, _PROJECT_ROOT)
sys.path.insert(0, _ADAPTERS_DIR)

os.environ["ADMIN_TOKEN"] = "CipherKeep_Admin_2026_X9m!Secure"
os.environ["SUPABASE_URL"] = "https://YOUR_PROJECT.supabase.co"
os.environ["SUPABASE_SERVICE_KEY"] = "YOUR_SUPABASE_SERVICE_ROLE_KEY"
os.environ["CIPHERKEEP_MASTER_KEY"] = "CipherKeep_Master_2026_7x!A9#QmL2@Secure"

if "ضع_" in os.environ["SUPABASE_URL"]:
    print("❌ عبّي القيم الأربع قبل التشغيل.")
    sys.exit(1)

import license_server
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cipherkeep_core.crypto import MAGIC, HEADER_FMT


def _build_blob(key, filename, source):
    name_bytes = filename.encode("utf-8")
    inner = struct.pack(">H", len(name_bytes)) + name_bytes + source
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, inner, associated_data=MAGIC)
    header = struct.pack(HEADER_FMT, MAGIC, 2, 3, 0, b"\x00" * 16, nonce)
    return header + ciphertext


def _step(title):
    print("\n" + "=" * 60 + f"\n{title}\n" + "=" * 60)


def main():
    if license_server._core is None:
        print("❌ فشل الاتصال بـ Supabase عند الإقلاع الأول.")
        sys.exit(1)

    client = license_server.app.test_client()

    _step("1) إنشاء كود (قبل محاكاة إعادة النشر)")
    resp = client.post(
        "/admin/create",
        json={"label": "إثبات دورة كاملة", "max_devices": 1},
        headers={"X-Admin-Token": os.environ["ADMIN_TOKEN"]},
    )
    data = resp.get_json()
    if not data.get("ok"):
        print("❌ فشل الإنشاء:", data)
        sys.exit(1)
    code, key = data["code"], base64.b64decode(data["key_b64"])
    print(f"✅ الكود: {code}")

    blob = _build_blob(key, "proof.py", b"print('lifecycle ok')")
    blob_b64 = base64.b64encode(blob).decode("ascii")

    _step("2) تحقق أول (قبل محاكاة إعادة النشر)")
    resp2 = client.post(
        "/verify", json={"code": code, "device_id": "dev-1", "ciphertext_b64": blob_b64}
    )
    data2 = resp2.get_json()
    if not data2.get("ok"):
        print("❌ فشل التحقق الأول:", data2)
        sys.exit(1)
    print("✅ نجح، المحتوى:", base64.b64decode(data2["source_b64"]))

    _step("3) محاكاة إعادة نشر Render — إعادة بناء الوحدة بالكامل من الصفر")
    print("(يعيد استيراد license_server وإعادة تهيئة الاتصال بـ Supabase من جديد،")
    print(" بدل استخدام نفس الكائن — هذا يحاكي عملية جديدة كليًا بعد إعادة نشر)")
    importlib.reload(license_server)
    if license_server._core is None:
        print("❌ فشل إعادة الاتصال بـ Supabase بعد \"إعادة النشر\".")
        sys.exit(1)
    print("✅ الاتصال بـ Supabase أُعيد تأسيسه بنجاح من الصفر.")

    client2 = license_server.app.test_client()

    _step("4) تحقق ثانٍ (بعد محاكاة إعادة النشر) — بنفس الكود القديم")
    resp3 = client2.post(
        "/verify", json={"code": code, "device_id": "dev-1", "ciphertext_b64": blob_b64}
    )
    data3 = resp3.get_json()
    if not data3.get("ok"):
        print("❌ فشل التحقق بعد إعادة النشر — الكود ضاع! هذا فشل حقيقي.")
        sys.exit(1)
    print("✅ نجح التحقق بعد \"إعادة النشر\" — الكود نجا فعليًا.")
    assert base64.b64decode(data3["source_b64"]) == b"print('lifecycle ok')"
    print("✅ المحتوى المفكوك مطابق تمامًا لما شُفِّر قبل إعادة النشر.")

    print("\n" + "=" * 60)
    print("✅ الدورة الكاملة نجحت: إنشاء → تحقق → محاكاة إعادة نشر → تحقق ثانٍ بلا فقدان بيانات.")
    print("هذا يثبت حل المشكلة الأصلية اللي بدأ منها كل هذا المشروع فعليًا، لا نظريًا.")
    print("=" * 60)
    print("انسخ هذا الناتج كامل وابعثه بالمحادثة.")


if __name__ == "__main__":
    main()
