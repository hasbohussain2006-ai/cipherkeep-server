# CipherKeep

منصة حماية أدوات المطورين وإدارة التراخيص. الرؤية الكاملة والقرارات المعمارية موثَّقة بالكامل بمجلد [`docs/`](docs/) — هذا الملف مدخل سريع فقط، **ليس** مصدر حقيقة.

## ابدأ من هنا

| تريد تعرف | اذهب لـ |
|---|---|
| ملخص كامل للمشروع من الصفر | [`PROJECT_SUMMARY.md`](PROJECT_SUMMARY.md) |
| رؤية المشروع والفلسفة العامة | [`docs/00_VISION.md`](docs/00_VISION.md) |
| المعمارية الكاملة | [`docs/01_ARCHITECTURE.md`](docs/01_ARCHITECTURE.md) |
| هيكل المجلدات الفعلي | [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md) |
| ما اكتمل وما تبقّى | [`docs/04_PROGRESS.md`](docs/04_PROGRESS.md) |
| كل القرارات المعمارية موثَّقة | [`docs/05_DECISIONS.md`](docs/05_DECISIONS.md) |
| العقود الحالية (Contracts) | [`docs/07_API.md`](docs/07_API.md) |
| قواعد التطوير الملزمة | [`docs/03_RULES.md`](docs/03_RULES.md) |
| شروط إغلاق Phase 1 (مكتملة) | [`docs/PHASE1_CHECKLIST.md`](docs/PHASE1_CHECKLIST.md) |
| تحضير Phase 2 | [`docs/PHASE2_PREPARATION.md`](docs/PHASE2_PREPARATION.md) |

## الحالة الحالية (باختصار)

**🟢 Phase 1 = Closed رسميًا.** كل بنود `PHASE1_CHECKLIST.md` (22/22) مكتملة ومُثبَتة حيًا فعليًا — شامل مراجعة أمنية شاملة (Security & Architecture Review) اكتُشفت وأُصلحت أثناء دورة الإغلاق نفسها (تفاصيل كاملة بـ`04_PROGRESS.md` و`10_CHANGELOG.md`).

**Phase 2 (المهمة الأولى — ترحيل أوامر الإدارة لـSupabase، ثم نظام صلاحيات المشرفين):** قيد البدء. راجع `docs/PHASE2_PREPARATION.md` للنطاق الدقيق والحدود.

## التشغيل السريع

```bash
# تثبيت المتطلبات
pip install flask cryptography requests

# تشغيل كل الاختبارات المحلية (71 اختبار، صفر شبكة مطلوبة)
python3 -m unittest discover -s . -p "test_*.py"
```

لتشغيل أدوات الإثبات الحي (تحتاج بيانات اعتماد Supabase حقيقية)، راجع التعليمات داخل كل ملف بمجلد [`tools/`](tools/).

## قواعد لا تُخالَف

1. لا كود جديد بدون إذن صريح ("ابدأ") — التفاصيل بـ`docs/03_RULES.md`.
2. `docs/01_ARCHITECTURE.md` تحدّده القرارات المعتمدة بـ`docs/05_DECISIONS.md` — أي تعديل معماري جديد يحتاج موافقة مسبقة.
3. `docs/` هي المصدر الوحيد للحقيقة — لا اعتماد على أي محادثة أو سياق خارجي بعد اعتماد هذي النسخة.
