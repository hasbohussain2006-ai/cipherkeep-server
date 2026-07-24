"""
CipherKeep Core — منطق الأعمال بالكامل.

يعتمد فقط على الواجهات المجرَّدة بـ interfaces.py — صفر معرفة بـ
Supabase أو تيليجرام أو أي تفصيلة تخزين. أي واجهة (بوت، لوحة ويب،
API عام مستقبلًا) تستدعي هذا الصف، لا تعيد كتابة منطقه.

نطاق Phase 1: create_code و verify_code، حسب Roadmap المعتمد.

نطاق Phase 2 (أول مهمة، قرار جلسة تصميم مخصَّصة — 05_DECISIONS.md):
أُضيفت revoke_code() و extend_code() لدعم نظام صلاحيات المشرفين.
فحص الملكية (هل المشرف المطالِب يملك هذا الكود فعلًا) يحدث هنا
داخل Core حصرًا — لا بالـAdapter ولا بطبقة DAL — حسب القرار
الصريح المعتمد. لا خطر تزامن حقيقي هنا (بعكس claim_device_slot):
كل كود له مالك واحد ثابت وقت الإنشاء، فلا يوجد سيناريو "طرفان
شرعيان يتنافسان بنفس اللحظة" يستدعي قفل صف ذري على مستوى RPC.
"""

from datetime import datetime, timezone
from typing import Optional

from .interfaces import CodeRepository, DeviceRepository, ModeratorRepository
from .models import VerifyResult, DeviceClaimStatus, RevokeResult, ExtendResult, Moderator


class CipherKeepCore:
    def __init__(
        self,
        codes: CodeRepository,
        devices: DeviceRepository,
        moderators: Optional[ModeratorRepository] = None,
    ):
        self._codes = codes
        self._devices = devices
        # اختياري عمدًا — كل نداءات Phase 1 الحالية (license_server.py,
        # أدوات الإثبات الحي، إلخ) تُنشئ Core بمعاملين فقط ويجب أن
        # تبقى صحيحة بلا أي تعديل. لا كسر توافق.
        self._moderators = moderators

    def create_code(
        self,
        code: str,
        key_material: bytes,
        label: Optional[str] = None,
        max_devices: int = 1,
        trial: bool = False,
        expires_at: Optional[datetime] = None,
        moderator_id: Optional[str] = None,
    ) -> None:
        self._codes.create(
            code, key_material, label, max_devices, trial, expires_at, moderator_id
        )

    def verify_code(
        self,
        code: str,
        device_fingerprint: str,
        now: Optional[datetime] = None,
    ) -> VerifyResult:
        now = now or datetime.now(timezone.utc)

        record = self._codes.get(code)
        if record is None:
            return VerifyResult(ok=False, reason="not_found", key_material=None)

        if record.revoked:
            return VerifyResult(ok=False, reason="revoked", key_material=None)

        if record.expires_at is not None and now > record.expires_at:
            return VerifyResult(ok=False, reason="expired", key_material=None)

        # عملية ذرية واحدة — لا فحص وتسجيل منفصلين، حسب
        # Transaction/Concurrency Policy المعتمدة.
        claim = self._devices.claim_device_slot(code, device_fingerprint, now)

        if claim == DeviceClaimStatus.LIMIT_REACHED:
            return VerifyResult(ok=False, reason="device_limit_reached", key_material=None)

        # REGISTERED أو ALREADY_REGISTERED كلاهما نجاح من منظور العميل.
        # is_new_device وlabel معلومتان محسوبتان أصلًا — لا فرع قرار جديد.
        return VerifyResult(
            ok=True,
            reason=None,
            key_material=record.key_material,
            is_new_device=(claim == DeviceClaimStatus.REGISTERED),
            label=record.label,
        )

    def _check_ownership(self, code: str, moderator_id: str):
        """
        فحص داخلي مشترك بين revoke_code وextend_code. يرجّع
        (record, error_reason) — error_reason=None يعني الفحص نجح.

        قرار افتراضي محافظ: كود بلا مالك معروف (moderator_id=None،
        أُنشئ قبل نظام المشرفين) يُرفَض دائمًا، لا يُعامَل كـ"متاح
        لأي مشرف". هذا افتراض غير محسوم صراحة بجلسة التصميم — مسجَّل
        هنا بوضوح للمراجعة، وليس قرارًا صامتًا.
        """
        record = self._codes.get(code)
        if record is None:
            return None, "not_found"
        if record.moderator_id is None or record.moderator_id != moderator_id:
            return None, "not_owner"
        return record, None

    def revoke_code(self, code: str, moderator_id: str) -> RevokeResult:
        _, error = self._check_ownership(code, moderator_id)
        if error is not None:
            return RevokeResult(ok=False, reason=error)

        self._codes.revoke(code)
        return RevokeResult(ok=True)

    def extend_code(
        self, code: str, moderator_id: str, new_expires_at: datetime
    ) -> ExtendResult:
        _, error = self._check_ownership(code, moderator_id)
        if error is not None:
            return ExtendResult(ok=False, reason=error)

        self._codes.extend(code, new_expires_at)
        return ExtendResult(ok=True, new_expires_at=new_expires_at)

    def register_moderator(
        self,
        moderator_id: str,
        external_id: str,
        display_name: Optional[str] = None,
        can_encrypt_server: bool = False,
        can_decrypt: bool = False,
    ) -> None:
        """
        يُنشئ سجل مشرف جديد. الصلاحيات ترفض بشكل افتراضي (deny by
        default) — يجب منحها صراحة وقت التسجيل، لا افتراض ثقة.

        يرفع RuntimeError لو لم يُزوَّد Core بـModeratorRepository —
        نفس نمط "فشل واضح" بدل سلوك صامت غير متوقَّع.
        """
        if self._moderators is None:
            raise RuntimeError(
                "هذا الـCore أُنشئ بلا ModeratorRepository — "
                "لا يقدر يدير مشرفين."
            )
        self._moderators.create(
            moderator_id, external_id, display_name, can_encrypt_server, can_decrypt
        )

    def resolve_moderator(self, external_id: str) -> Optional[Moderator]:
        """
        يحوّل معرّفًا خارجيًا خامًا (بأي صيغة قناة، Core لا يعرف
        مصدرها) لسجل مشرف داخلي، أو None لو غير موجود أو لو لم
        يُزوَّد Core بـModeratorRepository أصلًا.
        """
        if self._moderators is None:
            return None
        return self._moderators.get_by_external_id(external_id)
