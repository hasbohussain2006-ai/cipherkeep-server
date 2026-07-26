"""عقد نتيجة عملية التحقق (VerifyResult) — مُغلَق نهائيًا، لا إضافات جديدة."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VerifyResult:
    """
    نتيجة عملية verify_code. reason تكون None فقط لما ok=True.
    القيم الممكنة لـ reason عند الفشل:
        'not_found'            الكود غير موجود إطلاقًا
        'revoked'               الكود مُلغى
        'expired'               الكود منتهي الصلاحية
        'device_limit_reached'  تجاوز الحد الأقصى للأجهزة

    is_new_device: معلومة مجال محسوبة أصلًا داخل verify_code (عبر
    DeviceClaimStatus) — للقراءة فقط، الغرض الوحيد منها تمكين طبقات
    فوقية (Adapter) من اتخاذ قرارات خاصة بها (مثل إشعار "جهاز جديد")
    دون إعادة استنتاجها بنفسها. لا تُستخدم لأي قرار عمل داخل Core.

    label: معلومة موجودة أصلًا داخل LicenseCode، تُكشَف هنا بدل ما
    يعيد المستدعي قراءتها من طبقة ثانية. آخر حقل مسموح إضافته لهذا
    العقد بهذي المرحلة (Roadmap Phase 1، الخطوة 4).

    ⚠️ هذا العقد مُغلَق نهائيًا (07_API.md، 03_RULES.md #3) — أي
    إضافة جديدة تحتاج موافقة مسبقة صريحة، بلا استثناء إضافي.
    """
    ok: bool
    reason: Optional[str]
    key_material: Optional[bytes]
    is_new_device: bool = False
    label: Optional[str] = None


@dataclass(frozen=True)
class CodeValidityResult:
    """نتيجة CipherKeepCore.check_code_validity — مضافة لإصلاح R1."""
    ok: bool
    reason: Optional[str]
    key_material: Optional[bytes]
    label: Optional[str] = None
