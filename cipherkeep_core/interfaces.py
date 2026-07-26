"""
الواجهات المجرَّدة (Protocols) اللي يعتمد عليها CipherKeep Core.

حسب Core Architecture (Dependency Inversion Principle):
Core يعرف فقط هذي التوقيعات، ولا يعرف شيئًا عن Supabase أو PostgreSQL
أو أي تقنية تخزين فعلية. طبقة Data Access Layer هي اللي تنفّذ هذي
الواجهات فعليًا. أي تنفيذ وهمي (Fake) للاختبار يطابق نفس التوقيع.

استُخدم typing.Protocol (بنية هيكلية خفيفة) بدل ABC/الوراثة، حسب
القرار المعتمد بالوثيقة — لا حاجة لإطار حقن تبعيات بحجم هذا المشروع.
"""

from typing import Protocol, Optional, List
from datetime import datetime

from .models import LicenseCode, DeviceClaimStatus, Moderator


class CodeRepository(Protocol):
    def create(
        self,
        code: str,
        key_material: bytes,
        label: Optional[str],
        max_devices: int,
        trial: bool,
        expires_at: Optional[datetime],
        moderator_id: Optional[str] = None,
    ) -> None:
        """
        ينشئ سجل كود جديد. لا يتحقق من التكرار — مسؤولية المستدعي.

        moderator_id: مضاف بقرار جلسة تصميم Phase 2 — اختياري
        (نداءات Phase 1 القديمة بلا مشرف تبقى صحيحة بلا تعديل).
        """
        ...

    def get(self, code: str) -> Optional[LicenseCode]:
        """يرجع سجل الكود، أو None لو غير موجود."""
        ...

    def revoke(self, code: str) -> None:
        """
        ينفّذ إلغاء الكود فعليًا (تحديث revoked=True) — عملية تحديث
        بسيطة بلا فحص ملكية هنا. فحص "هل هذا المشرف يملك هذا الكود"
        مسؤولية CipherKeepCore.revoke_code() حصرًا (قرار جلسة تصميم
        Phase 2، 05_DECISIONS.md) — لا يُكرَّر بهذي الطبقة.
        """
        ...

    def extend(self, code: str, new_expires_at: datetime) -> None:
        """
        ينفّذ تمديد expires_at فعليًا — عملية تحديث بسيطة، بلا فحص
        ملكية (نفس الملاحظة أعلاه بـrevoke).
        """
        ...


class DeviceRepository(Protocol):
    def claim_device_slot(
        self, code: str, device_fingerprint: str, now: datetime
    ) -> DeviceClaimStatus:
        """
        عملية ذرية واحدة: تحاول حجز سلوت جهاز على هذا الكود.

        حسب Transaction/Concurrency Policy المعتمدة: الذرّية تحت
        التزامن تُضمن داخل التنفيذ الفعلي (قفل صف على مستوى قاعدة
        البيانات) — لا داخل Core ولا بايثون. هذا العقد المجرَّد
        يخفي تلك الآلية بالكامل عن Core.
        """
        ...


class ModeratorRepository(Protocol):
    """
    مضافة بقرار معماري أثناء تنفيذ Phase 2 (سجَّله core.py بالتفصيل):
    لازمة لتحويل external_id خام إلى سجل مشرف داخلي، بنفس نمط
    CodeRepository — لا فرق جوهري، عملية create/get بسيطة.
    """

    def create(
        self,
        moderator_id: str,
        external_id: str,
        display_name: Optional[str],
        can_encrypt_server: bool,
        can_decrypt: bool,
    ) -> None:
        """ينشئ سجل مشرف جديد. لا يتحقق من التكرار — مسؤولية المستدعي."""
        ...

    def get_by_external_id(self, external_id: str) -> Optional[Moderator]:
        """يرجع سجل المشرف المطابق لهذا المعرّف الخارجي، أو None."""
        ...


class CodeQueryRepository(Protocol):
    """
    واجهة استعلام إدارية — مضافة لإصلاح C1 (Kill Switch). منفصلة
    تمامًا عن CodeRepository عمدًا: CodeRepository مسؤول عن عمليات
    الـAggregate الفردية (create/get/revoke/extend لكود واحد بمعرفه)،
    بينما هذي الواجهة مسؤولة حصرًا عن استعلام جماعي إداري (سرد كل
    الأكواد) لا علاقة له بمنطق الـAggregate نفسه — فصل مسؤوليات
    واعٍ، لا توسيع لواجهة قائمة بمسؤولية مختلفة عنها جوهريًا.
    """

    def list_all_codes(self) -> List[str]:
        """يرجع كل رموز الأكواد الموجودة — لأغراض إدارية جماعية فقط
        (مثل kill-switch)، لا لأي قرار عمل فردي."""
        ...
