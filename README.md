# CipherKeep

منصة حماية أدوات المطورين وإدارة التراخيص. الرؤية الكاملة والقرارات المعمارية موثَّقة بالكامل بمجلد [`docs/`](docs/) — هذا الملف مدخل سريع فقط، **ليس** مصدر حقيقة.

## ابدأ من هنا

| تريد تعرف | اذهب لـ |
|---|---|
| رؤية المشروع والفلسفة العامة | [`docs/00_VISION.md`](docs/00_VISION.md) |
| المعمارية الكاملة (مُجمَّدة) | [`docs/01_ARCHITECTURE.md`](docs/01_ARCHITECTURE.md) |
| هيكل المجلدات الفعلي | [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md) |
| ما اكتمل وما تبقّى | [`docs/04_PROGRESS.md`](docs/04_PROGRESS.md) |
| العقود الحالية (Contracts) | [`docs/07_API.md`](docs/07_API.md) |
| قواعد التطوير الملزمة | [`docs/03_RULES.md`](docs/03_RULES.md) |
| شروط إغلاق Phase 1 | [`docs/PHASE1_CHECKLIST.md`](docs/PHASE1_CHECKLIST.md) |

## الحالة الحالية (باختصار)

**Phase 1 = 🧊 Frozen (Pending Live Validation)** — الكود مكتمل ومختبَر محليًا بالكامل، بانتظار تشغيل حي فعلي (`tools/`) لإغلاقها رسميًا. التفاصيل الكاملة بـ`docs/04_PROGRESS.md` و`docs/05_DECISIONS.md`.

**Phase 2 (أول مهمة — صلاحيات المشرفين):** طبقتا Core/DAL منفَّذتان ومختبَرتان محليًا بالكامل. **بوت الإدارة نفسه لم يُبدأ بعد.**

## التشغيل السريع

```bash
# تثبيت المتطلبات
pip install flask cryptography requests

# تشغيل كل الاختبارات المحلية (66 اختبار، صفر شبكة مطلوبة)
python3 -m unittest discover -s . -p "test_*.py"
```

لتشغيل أدوات الإثبات الحي (تحتاج بيانات اعتماد Supabase حقيقية)، راجع التعليمات داخل كل ملف بمجلد [`tools/`](tools/).

## قواعد لا تُخالَف

1. لا كود جديد بدون إذن صريح ("ابدأ") — التفاصيل بـ`docs/03_RULES.md`.
2. `docs/01_ARCHITECTURE.md` مُجمَّد — أي تعديل معماري يحتاج موافقة مسبقة.
3. `docs/` هي المصدر الوحيد للحقيقة — لا اعتماد على أي محادثة أو سياق خارجي.
