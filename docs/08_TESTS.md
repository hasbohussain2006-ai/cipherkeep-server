# 08 — الاختبارات (Tests)

## الفلسفة (بلا تغيير)

اختبار فعلي حقيقي إلزامي قبل أي تسليم. `unittest` القياسي (متوافق أيضًا مع `pytest`، مؤكَّد فعليًا على Termux). تمييز صريح دائمًا بين **مختبَر محليًا** و**مثبَت حيًا**.

## جرد الاختبارات الحالي — 71 اختبارًا (بعد المراجعة الأمنية الشاملة)

| ملف الاختبار | العدد | يغطي |
|---|---|---|
| `cipherkeep_core/tests/test_core.py` | 26 | `CipherKeepCore` كاملًا، شامل `RepositoryNotConfigured` (إصلاح #19) |
| `cipherkeep_core/tests/test_service_server_mode.py` | 11 | `ServerModeService` + `crypto.py` — اختباران مُحدَّثان لإصلاح R1 (`test_invalid_ciphertext_fails_before_device_limit_check`, `is_new_device=False` عند فشل فك تشفير) |
| `cipherkeep_dal/tests/test_supabase_repositories.py` | 20 | منطق طلبات/ردود HTTP، شامل تحديث اختبار Compatibility Fix (`assertNotIn("p_moderator_id", ...)` بدل `assertIsNone`) |
| `adapters/tests/test_license_server_migration.py` | 14 | `license_server.py` كاملًا، + 5 اختبارات جديدة لإصلاح #19 (`TestBackendUnavailableHandling`) |
| **المجموع الآلي المحلي** | **71** | — |

**تشغيل المجموعة الرئيسية (57 اختبارًا: Core+DAL) من جذر المشروع:**
```bash
python3 -m unittest discover -s . -p "test_*.py"
```
**تشغيل `adapters` بمعزل (14 اختبارًا، بسبب طبيعة اكتشاف الحزم):**
```bash
python3 -m unittest adapters.tests.test_license_server_migration
```
**أو، عبر `pytest` (يكتشف كليهما بنداء واحد، مؤكَّد فعليًا حيًا):**
```bash
pytest -v
```

## الإثبات الحي — مكتمل بالكامل (Phase 1 مغلَقة)

| العنصر | الحالة |
|---|---|
| مخطط Supabase | 🟢 مثبَت حيًا |
| Data Access Layer | 🟢 مثبَت حيًا (إنشاء/تحقق/فك تشفير/حد أجهزة/تزامن حقيقي) |
| ترحيل `license_server.py` (`/verify`+`/admin/create`) | 🟢 مثبَت حيًا (`live_proof_supabase.py`) |
| إثبات الدورة الكاملة (إعادة نشر محاكاة) | 🟢 مثبَت حيًا (`full_lifecycle_proof.py`) |
| `encryption_bot.py` (دورة كاملة عبر تيليجرام حقيقي) | 🟢 مثبَت حيًا — كود `EFU-YNRV`، سجلات إشعار مطابقة حرفيًا |
| سيناريو فشل الاتصال بـSupabase | 🟢 مثبَت حيًا — اكتُشف وأُصلح اكتشافان فعليان أثناء الاختبار (تسرّب استثناء خام، ابتلاع صامت بـ`admin_pause_all`) |
| المجموعة الآلية الكاملة (71) | 🟢 مثبَتة حيًا عبر `pytest` على بيئة Termux Android حقيقية (Python 3.14.6)، لا محليًا بمعزل فقط |

**Phase 1 لا تحتاج أي إثبات حي إضافي — مغلَقة بالكامل.**

## قاعدة الاختبار الحي (بلا تغيير)

1. أقصى اختبار آلي ممكن محليًا (Fakes/محاكاة HTTP)
2. أداة إثبات حي مستقلة يشغّلها المستخدم بنفسه
3. لا تُعتبَر أي خطوة "مثبَتة حيًا" إلا بنتيجة فعلية من المستخدم — **مبدأ طُبِّق بصرامة طوال دورة الإغلاق**، بما فيها رفض قبول ادعاءات وصفية بلا دليل حرفي (سطر Log، رد API فعلي) أكثر من مرة أثناء تصحيح Compatibility Fix.
