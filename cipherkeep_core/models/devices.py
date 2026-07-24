"""نماذج مجال الأجهزة (Device domain models)."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class DeviceClaimStatus(str, Enum):
    """
    نتيجة محاولة حجز سلوت جهاز — قيم ثابتة بدل نصوص حرة، حسب
    قرار Transaction/Concurrency Policy المعتمد.
    """
    REGISTERED = "registered"
    ALREADY_REGISTERED = "already_registered"
    LIMIT_REACHED = "limit_reached"


@dataclass(frozen=True)
class DeviceRecord:
    """يمثل صف واحد من جدول devices."""
    code: str
    device_fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime
