# هيكل المشروع (Project Structure)

هذا الملف يوثّق التنظيم الفعلي للمشروع بعد إغلاق Phase 1 وبدء Phase 2. أي تعديل بنيوي مستقبلي يجب أن يُحدَّث هنا فورًا.

```
CipherKeep/
│
├── README.md                       # مدخل سريع
├── PROJECT_SUMMARY.md              # ملخص كامل للمشروع من الصفر
├── PROJECT_STRUCTURE.md            # هذا الملف
│
├── docs/                          # كل التوثيق — المصدر الوحيد للحقيقة (SSOT)
│   ├── 00_VISION.md
│   ├── 01_ARCHITECTURE.md
│   ├── 02_ROADMAP.md
│   ├── 03_RULES.md
│   ├── 04_PROGRESS.md
│   ├── 05_DECISIONS.md
│   ├── 06_TODO.md
│   ├── 07_API.md
│   ├── 08_TESTS.md
│   ├── 09_AI_GUIDELINES.md
│   ├── 10_CHANGELOG.md
│   ├── PHASE1_CHECKLIST.md         # 🟢 مغلَقة بالكامل (22/22)
│   └── PHASE2_PREPARATION.md
│
├── migrations/
│   └── 001_phase2_moderator_schema.sql   # جاهز، غير مُطبَّق حيًا بعد (Phase 2)
│
├── cipherkeep_core/
│   ├── __init__.py                 # يُصدِّر: CipherKeepCore, RepositoryNotConfigured,
│   │                                # CodeQueryRepository, CodeValidityResult,
│   │                                # DeviceRegistrationResult + كل ما سبق
│   ├── core.py                     # + _resolve_valid_record (خاصة), check_code_validity,
│   │                                # register_device, admin_force_revoke, admin_pause_all
│   ├── models/
│   │   ├── __init__.py             # + تصدير CodeValidityResult, DeviceRegistrationResult
│   │   ├── codes.py
│   │   ├── devices.py              # + DeviceRegistrationResult
│   │   ├── verification.py         # + CodeValidityResult (VerifyResult بلا تغيير)
│   │   ├── mutations.py
│   │   └── moderators.py
│   ├── interfaces.py               # + CodeQueryRepository (منفصلة عن CodeRepository)
│   ├── crypto.py
│   ├── service_server_mode.py      # مُعاد هيكلته: تحقق → فك تشفير → حجز (إصلاح R1)
│   ├── fakes.py                    # + FakeCodeQueryRepository
│   └── tests/
│       ├── test_core.py            # 26 اختبار (يشمل RepositoryNotConfigured)
│       └── test_service_server_mode.py  # 11 اختبار (اختباران مُحدَّثان لإصلاح R1)
│
├── cipherkeep_dal/
│   ├── __init__.py                 # + تصدير SupabaseCodeQueryRepository
│   ├── supabase_repositories.py    # + SupabaseCodeQueryRepository (C1)
│   │                                # + Compatibility Fix: p_moderator_id شرطي
│   └── tests/
│       └── test_supabase_repositories.py   # 20 اختبار
│
├── adapters/
│   ├── license_server.py           # + معالج backend_unavailable موحَّد (إصلاح #19)
│   │                                # + مسار C1 لـ/admin/revoke و/admin/pause_all
│   │                                # + H1 (رد /verify موحَّد)، L1، H2 (تدوير يدوي)
│   ├── encryptor.py                # + H4 (سياسة كلمة مرور)، H6 (إزالة _CODE)
│   ├── encryption_bot.py           # + H5 (حذف الملف الأصلي)، H6، L2 (فرض HTTPS)
│   └── tests/
│       └── test_license_server_migration.py  # 14 اختبار (5 جديدة لإصلاح #19)
│
└── tools/                          # بلا تغيير
    ├── live_proof_supabase.py
    ├── full_lifecycle_proof.py
    └── concurrency_test_supabase.py
```

## قواعد التنظيم الملزمة (بلا تغيير)

1. `cipherkeep_core/` لا يستورد شيئًا من `adapters/` أو `cipherkeep_dal/` أو `tools/` — اتجاه الاعتماد دائمًا للداخل.
2. `adapters/` لا يوصل `cipherkeep_dal/` مباشرة — يمر عبر `cipherkeep_core/` حصرًا.
3. كل مجلد كود له `tests/` بجانبه مباشرة.
4. `tools/` منفصل عن `tests/` عمدًا.
5. تشغيل كل الاختبارات من جذر المشروع:
   ```bash
   python3 -m unittest discover -s . -p "test_*.py"
   ```
   (71 اختبارًا متوقَّعة، مقسَّمة: 26 + 11 + 20 بالمجموعة الرئيسية، + 14 بـ`adapters` — الأخيرة تحتاج تشغيلًا منفصلًا حاليًا بسبب طبيعة اكتشاف الحزم بمجلد `adapters/` بلا `__init__.py` على مستواه الأعلى)
