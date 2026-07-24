#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
concurrency_test_supabase.py — اختبار تلقائي للتزامن (Race Condition)

يسوي محاولتين لجهازين مختلفين لنفس الكود، بنفس اللحظة تقريبًا،
عن طريق Threading (بدل ما تحاول تفتح نافذتين وتضغط بنفس الثانية
يدويًا). لو الحماية شغالة صح: وحدة بس تنجح. لو الاثنين نجحوا،
فيه مشكلة حقيقية لازم نرجعلها.

نفس شروط smoke_test_supabase.py: شغّله ببيئة فيها إنترنت، بعد ما
تعبّي القيم الثلاث تحت.
"""

import os
import sys
import threading

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ.setdefault("SUPABASE_URL", "ضع_رابط_مشروعك_هنا")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "ضع_مفتاح_service_role_هنا")
os.environ.setdefault("CIPHERKEEP_MASTER_KEY", "ضع_عبارة_سرية_هنا")

from datetime import datetime, timezone
from cipherkeep_core import CipherKeepCore
from cipherkeep_dal import SupabaseCodeRepository, SupabaseDeviceRepository


def main():
    if "ضع_" in os.environ["SUPABASE_URL"]:
        print("❌ خطأ: عبّي القيم الثلاث بأعلى الملف قبل التشغيل.")
        sys.exit(1)

    codes = SupabaseCodeRepository()
    devices = SupabaseDeviceRepository()
    core = CipherKeepCore(codes, devices)

    test_code = "RACE-TEST-" + datetime.now(timezone.utc).strftime("%H%M%S")
    print(f"1) إنشاء كود بحد أقصى جهاز واحد فقط: {test_code}")
    core.create_code(
        code=test_code,
        key_material=b"race-test-key-000000000000000000",
        label="اختبار تزامن — يمكن حذفه بعدين",
        max_devices=1,
    )
    print("   ✅ تم.")

    results = {}

    def try_device(name):
        results[name] = core.verify_code(test_code, name)

    print("\n2) إطلاق محاولتين بنفس اللحظة (device-A و device-B)...")
    t1 = threading.Thread(target=try_device, args=("device-A",))
    t2 = threading.Thread(target=try_device, args=("device-B",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    a_ok = results["device-A"].ok
    b_ok = results["device-B"].ok

    print(f"\n   نتيجة device-A: ok={a_ok}, reason={results['device-A'].reason}")
    print(f"   نتيجة device-B: ok={b_ok}, reason={results['device-B'].reason}")

    print("\n" + "=" * 50)
    if a_ok and b_ok:
        print("❌ مشكلة حقيقية: نجح الجهازان معًا رغم max_devices=1.")
        print("   الحماية من التزامن غير فعّالة — لازم نراجعها قبل أي خطوة ثانية.")
        sys.exit(1)
    elif a_ok != b_ok:
        print("✅ ممتاز — نجح جهاز واحد فقط، والثاني رُفض بسبب device_limit_reached.")
        print("   الحماية من التزامن شغّالة صح.")
    else:
        print("⚠️ غريب: فشل الاثنان معًا. راجع رسائل الخطأ فوق.")
        sys.exit(1)


if __name__ == "__main__":
    main()
