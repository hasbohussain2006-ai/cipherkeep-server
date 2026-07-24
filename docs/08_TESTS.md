# 08 — الاختبارات (Tests)

## الفلسفة

- اختبار فعلي حقيقي إلزامي قبل أي تسليم (`03_RULES.md` #5) — لا افتراض.
- `unittest` القياسي (بلا `pytest`) — بيئات التنفيذ غالبًا بلا اتصال شبكي لتثبيت حزم إضافية؛ `unittest` مضمَّن بلغة بايثون نفسها.
- تمييز صريح دائمًا بين: **مختبَر محليًا** (Fakes/محاكاة HTTP) و**مثبَت حيًا** (اتصال حقيقي). التفاصيل الحية بـ`04_PROGRESS.md`.

## مبدأ DIP وأثره على الاختبار

الواجهات المجرَّدة (`CodeRepository`, `DeviceRepository`) تمكّن اختبار `CipherKeepCore` بمستودعات وهمية بالذاكرة (`fakes.py`)، بمعزل تام عن Supabase — هذا هو المبرر الهندسي الأساسي لـDIP بالمشروع (`05_DECISIONS.md`).

## جرد الاختبارات الحالي

**تحديث بعد Baseline Consolidation:** المسارات أدناه تعكس الهيكل بعد إعادة التنظيم الاحترافية (`adapters/`, `tools/`, `docs/`) — راجع `PROJECT_STRUCTURE.md` لتفاصيل الهيكل الكامل.

| ملف الاختبار | العدد | يغطي |
|---|---|---|
| `cipherkeep_core/tests/test_core.py` | 26 | `CipherKeepCore` كاملًا: إنشاء/تحقق/حد أجهزة/إلغاء/انتهاء/`is_new_device` (11 أصلية) + `revoke_code`/`extend_code`/عزل الملكية (8) + `register_moderator`/`resolve_moderator` (7) — بمستودعات وهمية |
| `cipherkeep_core/tests/test_service_server_mode.py` | 11 | `ServerModeService` + `crypto.py`، منها Roundtrip تشفير حقيقي |
| `cipherkeep_dal/tests/test_supabase_repositories.py` | 15 | منطق طلبات/ردود HTTP لـ`SupabaseCodeRepository`/`SupabaseDeviceRepository` (9 أصلية + 2 موسَّعة لـmoderator_id) + `SupabaseModeratorRepository` (5 جديدة) — محاكاة عبر `unittest.mock` |
| `adapters/tests/test_license_server_migration.py` | 9 | `license_server.py` كاملًا عبر Flask test client، بمستودعات وهمية محقونة |
| **المجموع الآلي المحلي** | **66** | — |

## أدوات إثبات حي (خارج عدّ الاختبارات الآلية أعلاه — تشغيل يدوي فقط)

توجد الآن بمجلد `tools/` منفصلة عن اختبارات الوحدة (فرق مفهومي: هذي أدوات تشغيل يدوي تحتاج اتصال Supabase حقيقي، لا اختبارات آلية تُدرَج بعدّاد CI):
- `tools/live_proof_supabase.py`
- `tools/full_lifecycle_proof.py`
- `tools/concurrency_test_supabase.py`

## الإثبات الحي (خارج الاختبارات الآلية، تشغيل فعلي بمعرفة المستخدم)

- مخطط Supabase: مؤكَّد حيًا (تنفيذ SQL ناجح فعليًا)
- Data Access Layer: مؤكَّد حيًا (إنشاء، تحقق، فك تشفير، حد أجهزة، وتزامن حقيقي عبر Threading — نجاح جهاز واحد فقط من محاولتين متزامنتين، بما يثبت `ck_claim_device_slot` فعليًا)
- ترحيل `license_server.py`: أداة إثبات حي جاهزة (`live_proof_supabase.py`)، **النتيجة الفعلية لم تصل بعد** — الحالة `04_PROGRESS.md`

## قاعدة الاختبار الحي عند غياب الشبكة ببيئة التنفيذ

عند تعذّر اتصال شبكي مباشر أثناء التطوير:
1. يُبنى أقصى اختبار آلي ممكن محليًا (Fakes/محاكاة HTTP).
2. تُبنى أداة إثبات حي مستقلة، بسجل مخرجات واضح، يشغّلها المستخدم بنفسه.
3. لا تُعتبَر أي خطوة "مثبَتة حيًا" إلا بنتيجة فعلية من المستخدم.
