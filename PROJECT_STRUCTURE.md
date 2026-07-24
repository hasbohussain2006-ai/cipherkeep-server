# هيكل المشروع (Project Structure)

هذا الملف يوثّق التنظيم الفعلي للمشروع بعد Baseline Consolidation. أي تعديل بنيوي مستقبلي (نقل/إعادة تسمية مجلدات) يجب أن يُحدَّث هنا فورًا.

```
CipherKeep/
│
├── docs/                          # كل التوثيق — المصدر الوحيد للحقيقة (SSOT)
│   ├── 00_VISION.md
│   ├── 01_ARCHITECTURE.md         # مُجمَّد (Architecture Freeze)
│   ├── 02_ROADMAP.md
│   ├── 03_RULES.md
│   ├── 04_PROGRESS.md
│   ├── 05_DECISIONS.md
│   ├── 06_TODO.md
│   ├── 07_API.md
│   ├── 08_TESTS.md
│   ├── 09_AI_GUIDELINES.md
│   ├── 10_CHANGELOG.md
│   ├── PHASE1_CHECKLIST.md
│   └── PHASE2_PREPARATION.md
│
├── migrations/                    # سكربتات SQL — تُطبَّق يدويًا على Supabase
│   └── 001_phase2_moderator_schema.sql
│
├── cipherkeep_core/                # طبقة Core — منطق الأعمال، بلا معرفة بأي تقنية خارجية
│   ├── __init__.py
│   ├── core.py                    # CipherKeepCore — نقطة الدخول الوحيدة لمنطق الأعمال
│   ├── models/                     # نماذج المجال، مقسَّمة حسب المفهوم
│   │   ├── __init__.py             # يُصدِّر كل شيء — توافق خلفي كامل مع from .models import X
│   │   ├── codes.py                 # LicenseCode
│   │   ├── devices.py               # DeviceRecord, DeviceClaimStatus
│   │   ├── verification.py          # VerifyResult (عقد مُغلَق)
│   │   ├── mutations.py             # RevokeResult, ExtendResult
│   │   └── moderators.py            # Moderator
│   ├── interfaces.py               # CodeRepository, DeviceRepository, ModeratorRepository (Protocols)
│   ├── crypto.py                   # فك تشفير خالص، بلا منطق أعمال
│   ├── service_server_mode.py      # ServerModeService — خدمة مجال بالتركيب فوق Core
│   ├── fakes.py                    # مستودعات وهمية بالذاكرة — للاختبار فقط
│   └── tests/
│       ├── test_core.py
│       └── test_service_server_mode.py
│
├── cipherkeep_dal/                 # Data Access Layer — تنفيذ فعلي ضد Supabase
│   ├── __init__.py
│   ├── supabase_repositories.py    # SupabaseCodeRepository, SupabaseDeviceRepository, SupabaseModeratorRepository
│   └── tests/
│       └── test_supabase_repositories.py
│
├── adapters/                       # طبقة الواجهات (Adapters) — نقل فقط، بلا قرار عمل
│   ├── license_server.py           # Flask — /verify, /admin/*
│   ├── encryptor.py                # أداة التشفير المحلية (تُستدعى من encryption_bot.py)
│   ├── encryption_bot.py           # بوت تيليجرام للتشفير — عميل HTTP خالص لـ license_server
│   └── tests/
│       └── test_license_server_migration.py
│
└── tools/                          # أدوات إثبات حي (تشغيل يدوي، تحتاج اتصال Supabase حقيقي)
    ├── live_proof_supabase.py
    ├── full_lifecycle_proof.py
    └── concurrency_test_supabase.py
```

## قواعد التنظيم الملزمة

1. **`cipherkeep_core/` لا يستورد شيئًا من `adapters/` أو `cipherkeep_dal/` أو `tools/`** — اتجاه الاعتماد دائمًا للداخل (Adapters → Core → DAL)، أبدًا العكس.
2. **`adapters/` لا يوصل `cipherkeep_dal/` مباشرة** — يمر عبر `cipherkeep_core/` حصرًا (`01_ARCHITECTURE.md` §1-2).
3. **كل مجلد كود له `tests/` بجانبه مباشرة**، لا مجلد اختبارات مركزي منفصل — يبقي الاختبار قريبًا مما يختبره.
4. **`tools/` منفصل عن `tests/` عمدًا** — الفرق مفهومي: `tests/` اختبارات آلية (unittest، صفر شبكة)، `tools/` أدوات تشغيل يدوي تحتاج اتصال Supabase حي فعليًا.
5. **تشغيل كل الاختبارات من جذر المشروع:**
   ```bash
   python3 -m unittest discover -s . -p "test_*.py"
   ```
