"""نماذج مجال المشرفين (Moderator domain models) — Phase 2."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class Moderator:
    """
    يمثل صف واحد من جدول moderators.

    external_id: معرّف خارجي مجرَّد (نص عام)، بنفس فلسفة
    device_fingerprint — Core لا يعرف مصدره (تيليجرام أو أي قناة
    مستقبلية)، تحويل القيمة الخام لهذا الشكل مسؤولية DAL/Adapter،
    لا Core (01_ARCHITECTURE.md §2). لا علاقة لهذا الحقل بمخطط
    "معرّف مشرف مقيَّد 3-5 أحرف" المعلَّق بـ06_TODO.md #4 — ذاك بند
    منفصل غير محسوم، لم يُقرَّر هنا.

    can_encrypt_server / can_decrypt: صلاحيات boolean صريحة بسيطة،
    لا مخطط RBAC (قرار جلسة تصميم Phase 2). القدرة على إلغاء/تمديد
    أكواد المشرف نفسه ليست صلاحية منفصلة هنا — هي عزل بنيوي متأصّل
    عبر moderator_id على codes (CipherKeepCore.revoke_code/extend_code)،
    لا تُفعَّل أو تُعطَّل.
    """
    moderator_id: str
    external_id: str
    display_name: Optional[str]
    can_encrypt_server: bool
    can_decrypt: bool
    created_at: datetime
