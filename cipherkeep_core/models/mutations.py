"""
عقود نتائج العمليات الإدارية المُغيِّرة (revoke/extend) — Phase 2.

كل عملية لها عقد مستقل تمامًا (لا MutationResult موحَّد) — قرار
جلسة تصميم Phase 2 (05_DECISIONS.md)، مبني على درس VerifyResult
(فُتح مرتين قبل إغلاقه — عقد موحَّد مبكر يقود لفتحه المتكرر).
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class RevokeResult:
    """
    نتيجة عملية revoke_code.

    القيم الممكنة لـ reason عند الفشل:
        'not_found'   الكود غير موجود إطلاقًا
        'not_owner'   الكود موجود لكن لا يخص المشرف المطالِب
                      (يشمل الأكواد بلا مالك معروف — moderator_id=None)
    """
    ok: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class ExtendResult:
    """
    نتيجة عملية extend_code.

    القيم الممكنة لـ reason عند الفشل: نفس RevokeResult
    ('not_found', 'not_owner').
    """
    ok: bool
    reason: Optional[str] = None
    new_expires_at: Optional[datetime] = None
