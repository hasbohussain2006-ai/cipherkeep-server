"""نماذج مجال الأكواد/التراخيص (Code/License domain models)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class LicenseCode:
    """يمثل صف واحد من جدول codes، بعد فك تشفير key_material."""
    code: str
    key_material: bytes
    label: Optional[str]
    max_devices: int
    trial: bool
    revoked: bool
    expires_at: Optional[datetime]
    created_at: datetime
    # moderator_id: مضاف بقرار جلسة تصميم Phase 2 (05_DECISIONS.md).
    # Nullable عمدًا — الأكواد المُنشأة قبل نظام المشرفين تبقى بلا
    # مالك (None)؛ Core.revoke_code/extend_code يرفضان أي طلب على
    # كود بلا مالك معروف (قرار افتراضي محافظ، موثَّق بتعليق core.py).
    moderator_id: Optional[str] = None
