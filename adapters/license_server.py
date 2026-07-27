#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
license_server.py -- سيرفر تفعيل وترخيص لملفات CipherKeep (وضع السيرفر)
==========================================================================

وظيفته: يستقبل طلب تفعيل من ملف .enc.py يشتغل عند صديقك، يتحقق من
صلاحية الكود (مو ملغى، مو منتهي، الجهاز ضمن الحد المسموح)، ولو تمام
يفك تشفير الكود المرسل له ويرجعه -- المفتاح نفسه ما يطلع من السيرفر أبداً.

انشر هذا الملف على Render أو Railway (فيهم خطة مجانية). تحتاج تحط
متغيرات بيئة (Environment Variables) بلوحة تحكم الاستضافة:

    ADMIN_TOKEN          كلمة سر طويلة عشوائية تختارها -- تحمي أوامر الإدارة
    TELEGRAM_BOT_TOKEN   (اختياري) توكن بوت تيليجرام للتنبيهات والأوامر
    OWNER_TELEGRAM_ID    (اختياري) رقم حسابك -- بس هو يقدر يرسل أوامر إدارة

    -- مطلوبة لـ /verify و /admin/create فقط (Roadmap Phase 1، الخطوة 4) --
    SUPABASE_URL           رابط مشروع Supabase
    SUPABASE_SERVICE_KEY   مفتاح service_role (أو sb_secret_...)
    CIPHERKEEP_MASTER_KEY  عبارة تشفير key_material -- سرّية تمامًا

⚠️ ملاحظة مهمة على وضع الترحيل الحالي (Phase 1، الخطوة 4):
    /verify و /admin/create يعتمدان بالكامل على Supabase (عبر
    CipherKeepCore + DAL). باقي نقاط الإدارة (revoke/extend/pause_all/
    list) ما زالت تعتمد على licenses.json المحلي مؤقتًا -- يعني فيه
    مصدرا حقيقة منفصلان حاليًا لأنواع عمليات مختلفة، لحين ترحيل باقي
    النقاط بمراحل مستقلة لاحقة.

التشغيل محلياً للتجربة:
    pip install flask cryptography requests
    ADMIN_TOKEN=test123 python license_server.py

نقاط الإدارة (تحتاج Header: X-Admin-Token: <ADMIN_TOKEN>):
    POST /admin/create      {label, max_devices, expire_days, trial}
    POST /admin/revoke      {code}
    POST /admin/extend      {code, days}
    POST /admin/pause_all   {}                      (كل-سويتش: يلغي كل شي دفعة وحدة)
    GET  /admin/list

أو نفس أوامر الإدارة (عدا create) عن طريق تيليجرام مباشرة -- ترسل رسالة
لبوتك من حساب OWNER_TELEGRAM_ID بس:
    /list                 عرض كل الأكواد وحالتها
    /revoke CODE          إلغاء كود فوراً
    /extend CODE DAYS     تمديد صلاحية كود
    /pause_all            إيقاف كل الأكواد دفعة وحدة (طوارئ)

نقطة التحقق (يستخدمها الملف المشفر تلقائياً، ما تحتاج تلمسها):
    POST /verify   {code, device_id, ciphertext_b64}
"""

import base64
import json
import os
import secrets
import string
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

# bootstrap: هذا الملف انتقل إلى adapters/ ضمن إعادة الهيكلة الاحترافية
# (Baseline Consolidation). cipherkeep_core/cipherkeep_dal يعيشان بجذر
# المشروع، خطوة واحدة أعلى — هذا يضمن عمل الملف بغض النظر عن طريقة
# التشغيل (مباشرة، أو عبر -m، أو باستيراد من أي مكان).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, jsonify, request

try:
    import requests
except ImportError:
    requests = None

from cipherkeep_core import CipherKeepCore, ServerModeService, RepositoryNotConfigured
from cipherkeep_dal import (
    SupabaseCodeRepository,
    SupabaseDeviceRepository,
    SupabaseCodeQueryRepository,
    SupabaseRequestError,
)


# ── يجب أن يطابق نفس الثوابت الموجودة بأداة CipherKeep (encryptor.py) ──
# ملاحظة: MAGIC/HEADER_FMT/فك التشفير انتقلوا لـ cipherkeep_core/crypto.py
# (الخطوة 4، Roadmap Phase 1) -- هذا الملف ما يعود يحتفظ بأي نسخة منهم.

DATA_FILE = Path(__file__).parent / "licenses.json"
LOG_FILE = Path(__file__).parent / "activity.log"

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
# إصلاح H2: بنية قابلة للتوسع لدعم تدوير ADMIN_TOKEN مستقبلًا --
# معطَّلة افتراضيًا تمامًا (القيمة الافتراضية فارغة، فالسلوك الحالي
# يبقى مطابقًا حرفيًا ما لم تُفعَّل صراحة). التفعيل: عبّ متغيّر بيئة
# ADMIN_TOKENS_ROTATION بتوكنات إضافية صالحة مفصولة بفاصلة -- يسمح
# بتدوير آمن بلا انقطاع خدمة (التوكن القديم والجديد صالحان معًا
# مؤقتًا خلال فترة الانتقال، ثم يُحذَف القديم من القائمة لاحقًا).
_ADMIN_TOKENS_ROTATION = [
    t.strip() for t in os.environ.get("ADMIN_TOKENS_ROTATION", "").split(",") if t.strip()
]
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
OWNER_ID = os.environ.get("OWNER_TELEGRAM_ID", "")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
CIPHERKEEP_MASTER_KEY = os.environ.get("CIPHERKEEP_MASTER_KEY", "")

app = Flask(__name__)
_lock = threading.Lock()


@app.errorhandler(SupabaseRequestError)
@app.errorhandler(requests.exceptions.RequestException)
def _handle_supabase_unavailable(e):
    """
    إصلاح #19 -- معالج أخطاء موحَّد يغطي أي فشل اتصال/طلب فعلي بـ
    Supabase (لا فشل تهيئة عند الإقلاع -- ذاك يُعالَج مسبقًا بـ
    _init_supabase_core ويرجع server_misconfigured). هذا المعالج
    يمسك أي استثناء من هذا النوع يرتفع من أي نقطة تستدعي DAL --
    /verify, /admin/create, /admin/revoke, /admin/pause_all -- بلا
    حاجة لتكرار try/except بكل نقطة على حدة، ويضمن عدم تسرّب أي
    Stack Trace أو تفاصيل داخلية (رابط، مفتاح، رسالة خطأ خام) للعميل.

    SupabaseRequestError: يُرفَع صراحة من DAL عند رد HTTP غير ناجح من
    Supabase نفسها (مثلًا 404/500 من PostgREST).
    requests.exceptions.RequestException: فشل شبكي أدنى مستوى (انقطاع
    اتصال، DNS، timeout) قبل حتى وصول أي رد من Supabase.
    """
    _log("SUPABASE_UNAVAILABLE error=" + str(e))
    return jsonify(ok=False, reason="backend_unavailable"), 500


# ── تهيئة Core + DAL لـ /verify و /admin/create فقط ─────────────
# باقي نقاط الإدارة (revoke/extend/pause_all/list) ما زالت تعتمد
# على licenses.json المحلي أدناه، بانتظار ترحيلها بمرحلة مستقلة.

_core = None
_server_mode = None


def _init_supabase_core() -> None:
    global _core, _server_mode
    if not (SUPABASE_URL and SUPABASE_SERVICE_KEY and CIPHERKEEP_MASTER_KEY):
        print("تحذير: SUPABASE_URL/SUPABASE_SERVICE_KEY/CIPHERKEEP_MASTER_KEY "
              "غير مكتملة -- /verify و /admin/create راح يرفضان الطلبات.")
        _notify("⚠️ license_server.py بدأ بدون إعداد Supabase كامل — "
                "/verify و /admin/create معطَّلان حاليًا.")
        return
    try:
        code_repo = SupabaseCodeRepository(
            base_url=SUPABASE_URL,
            service_key=SUPABASE_SERVICE_KEY,
            passphrase=CIPHERKEEP_MASTER_KEY,
        )
        device_repo = SupabaseDeviceRepository(
            base_url=SUPABASE_URL, service_key=SUPABASE_SERVICE_KEY
        )
        admin_codes_repo = SupabaseCodeQueryRepository(
            base_url=SUPABASE_URL, service_key=SUPABASE_SERVICE_KEY
        )
        _core = CipherKeepCore(code_repo, device_repo, admin_codes=admin_codes_repo)
        _server_mode = ServerModeService(_core)
    except Exception as e:
        print("تحذير: فشل تهيئة الاتصال بـ Supabase: " + str(e))
        _notify("⚠️ فشل اتصال license_server.py بـ Supabase عند الإقلاع: " + str(e))


# ── تخزين بسيط بملف JSON (كافي لحجم استخدام شخصي) ─────────────

def _load() -> dict:
    with _lock:
        if not DATA_FILE.exists():
            return {"codes": {}}
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    with _lock:
        DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _log(event: str) -> None:
    line = datetime.now(timezone.utc).isoformat() + "  " + event + "\n"
    with _lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def _notify(text: str) -> None:
    if not BOT_TOKEN or not OWNER_ID or requests is None:
        return
    try:
        requests.post(
            "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage",
            json={"chat_id": OWNER_ID, "text": text},
            timeout=5,
        )
    except Exception as e:
        # إصلاح L1: التنبيه ثانوي فعلًا (ما لازم يوقف السيرفر لو فشل)،
        # لكن الفشل الصامت الكامل يعني فقدان الرؤية تمامًا وقت حادثة
        # فعلية (مثلًا استنزاف/هجوم بالتزامن مع تعطّل تيليجرام). يُسجَّل
        # الفشل بـactivity.log على الأقل، بلا رفع استثناء يوقف الطلب.
        try:
            _log("NOTIFY_FAILED error=" + str(e))
        except Exception:
            pass  # حتى لو فشل التسجيل نفسه، _notify ما ترفع استثناء أبدًا


# _notify مُعرَّفة الآن -- نستدعي التهيئة هنا عشان تنبيهات الفشل تشتغل صح
_init_supabase_core()


# ── بوت تيليجرام لأوامر الإدارة (اختياري، يحتاج BOT_TOKEN + OWNER_ID) ──

def _tg_get_updates(offset):
    url = "https://api.telegram.org/bot" + BOT_TOKEN + "/getUpdates?timeout=25"
    if offset is not None:
        url += "&offset=" + str(offset)
    try:
        resp = requests.get(url, timeout=30)
        return resp.json().get("result", [])
    except Exception:
        return []


def _handle_admin_command(text: str) -> str:
    parts = text.strip().split()
    if not parts:
        return "اكتب /help لعرض الأوامر"
    cmd = parts[0].lower()

    if cmd in ("/start", "/help"):
        return (
            "أوامر التحكم بتراخيص CipherKeep:\n"
            "/list -- عرض كل الأكواد وحالتها\n"
            "/revoke CODE -- إلغاء كود فوراً\n"
            "/extend CODE DAYS -- تمديد صلاحية كود\n"
            "/pause_all -- إيقاف كل الأكواد دفعة وحدة (طوارئ)"
        )

    if cmd == "/list":
        data = _load()
        if not data["codes"]:
            return "ما فيه أكواد لسا."
        lines = []
        for code, e in data["codes"].items():
            status = "ملغى" if e.get("revoked") else "فعال"
            devices = str(len(e.get("devices", []))) + "/" + str(e.get("max_devices", 1))
            exp = e.get("expires_at", "")[:10] if e.get("expires_at") else "دائم"
            lines.append(code + "  [" + status + "]  اجهزة:" + devices + "  ينتهي:" + exp + "  " + e.get("label", ""))
        return "\n".join(lines)

    if cmd == "/revoke" and len(parts) >= 2:
        code = parts[1].upper()
        data = _load()
        if code not in data["codes"]:
            return "ما لقيت الكود: " + code
        data["codes"][code]["revoked"] = True
        _save(data)
        _log("REVOKE(tg) code=" + code)
        return "تم إلغاء " + code

    if cmd == "/extend" and len(parts) >= 3 and parts[2].lstrip("-").isdigit():
        code, days = parts[1].upper(), int(parts[2])
        data = _load()
        if code not in data["codes"]:
            return "ما لقيت الكود: " + code
        entry = data["codes"][code]
        base_dt = datetime.fromisoformat(entry["expires_at"]) if entry.get("expires_at") else datetime.now(timezone.utc)
        entry["expires_at"] = (base_dt + timedelta(days=days)).isoformat()
        _save(data)
        _log("EXTEND(tg) code=" + code + " days=" + str(days))
        return "تم تمديد " + code + " لين " + entry["expires_at"][:10]

    if cmd == "/pause_all":
        data = _load()
        for e in data["codes"].values():
            e["revoked"] = True
        _save(data)
        _log("PAUSE_ALL(tg)")
        return "تم إيقاف كل الأكواد (" + str(len(data["codes"])) + ")"

    return "أمر غير مفهوم. اكتب /help"


def _tg_poll_loop() -> None:
    offset = None
    while True:
        for u in _tg_get_updates(offset):
            offset = u["update_id"] + 1
            msg = u.get("message") or {}
            chat_id = str(msg.get("chat", {}).get("id", ""))
            text = msg.get("text", "")
            if not text or not chat_id:
                continue
            if chat_id != str(OWNER_ID):
                continue  # يتجاهل أي حد غير المالك المحدد بـ OWNER_TELEGRAM_ID
            reply = _handle_admin_command(text)
            try:
                requests.post(
                    "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage",
                    json={"chat_id": chat_id, "text": reply},
                    timeout=5,
                )
            except Exception:
                pass
        time.sleep(1)


def start_telegram_admin_bot() -> None:
    if not BOT_TOKEN or not OWNER_ID or requests is None:
        return
    threading.Thread(target=_tg_poll_loop, daemon=True).start()


def _gen_code() -> str:
    alphabet = string.ascii_uppercase + string.digits

    def part(n):
        return "".join(secrets.choice(alphabet) for _ in range(n))

    return part(3) + "-" + part(4)


def _require_admin() -> bool:
    if not ADMIN_TOKEN:
        return False
    token = request.headers.get("X-Admin-Token", "")
    # كل التوكنات الصالحة حاليًا: الأساسي + أي توكنات تدوير مفعَّلة
    # صراحة (فارغة افتراضيًا -- لا تغيير بالسلوك ما لم تُفعَّل).
    valid_tokens = [ADMIN_TOKEN] + _ADMIN_TOKENS_ROTATION
    return any(secrets.compare_digest(token, valid) for valid in valid_tokens)


# ── فك التشفير انتقل بالكامل لـ cipherkeep_core/crypto.py (الخطوة 4) ──


# ── نقاط الإدارة ────────────────────────────────────────────────

@app.route("/admin/create", methods=["POST"])
def admin_create():
    if not _require_admin():
        return jsonify(ok=False, reason="unauthorized"), 401
    if _core is None:
        return jsonify(ok=False, reason="server_misconfigured"), 500

    body = request.get_json(force=True, silent=True) or {}
    label = str(body.get("label", ""))[:100]
    max_devices = max(1, int(body.get("max_devices", 1)))
    trial = bool(body.get("trial", False))
    expire_days = body.get("expire_days")
    if trial:
        expire_days = expire_days or 3
        max_devices = 1

    key = os.urandom(32)
    code = _gen_code()

    expires_at = None
    if expire_days:
        # timezone-aware إلزاميًا -- Core.verify_code يقارنها بـ
        # datetime.now(timezone.utc)، ومقارنة naive/aware تطيح بخطأ.
        expires_at = datetime.now(timezone.utc) + timedelta(days=int(expire_days))

    try:
    _core.create_code(
        code=code,
        key_material=key,
        label=label,
        max_devices=max_devices,
        trial=trial,
        expires_at=expires_at,
    )
except Exception as e:
    import traceback
    traceback.print_exc()
    return jsonify(ok=False, error=str(e)), 500

    key_b64 = base64.b64encode(key).decode("ascii")
    _log("CREATE code=" + code + " label=" + label + " trial=" + str(trial))
    _notify("كود جديد: " + code + ("  (" + label + ")" if label else ""))
    return jsonify(ok=True, code=code, key_b64=key_b64)


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    if not _require_admin():
        return jsonify(ok=False, reason="unauthorized"), 401
    code = str((request.get_json(force=True, silent=True) or {}).get("code", ""))
    data = _load()
    found_locally = code in data["codes"]
    if found_locally:
        data["codes"][code]["revoked"] = True
        _save(data)

    # إصلاح C1 (Kill Switch): إلغاء على Supabase أيضًا، بالتوازي مع
    # licenses.json المحلي — بلا فحص ملكية (مسار إداري منفصل تمامًا
    # عن revoke_code العادية المخصَّصة للمشرفين الأفراد).
    found_on_supabase = False
    if _core is not None:
        result = _core.admin_force_revoke(code)
        found_on_supabase = result.ok

    if not found_locally and not found_on_supabase:
        return jsonify(ok=False, reason="not_found"), 404

    _log("REVOKE code=" + code)
    _notify("تم إلغاء الكود: " + code)
    return jsonify(ok=True)


@app.route("/admin/extend", methods=["POST"])
def admin_extend():
    if not _require_admin():
        return jsonify(ok=False, reason="unauthorized"), 401
    body = request.get_json(force=True, silent=True) or {}
    code, days = str(body.get("code", "")), int(body.get("days", 0))
    data = _load()
    if code not in data["codes"]:
        return jsonify(ok=False, reason="not_found"), 404
    entry = data["codes"][code]
    base_dt = datetime.fromisoformat(entry["expires_at"]) if entry.get("expires_at") else datetime.now(timezone.utc)
    entry["expires_at"] = (base_dt + timedelta(days=days)).isoformat()
    _save(data)
    _log("EXTEND code=" + code + " days=" + str(days))
    return jsonify(ok=True, expires_at=entry["expires_at"])


@app.route("/admin/pause_all", methods=["POST"])
def admin_pause_all():
    if not _require_admin():
        return jsonify(ok=False, reason="unauthorized"), 401
    data = _load()
    for entry in data["codes"].values():
        entry["revoked"] = True
    _save(data)
    local_count = len(data["codes"])

    # إصلاح C1 (Kill Switch): إيقاف جماعي على Supabase أيضًا.
    supabase_count = 0
    if _core is not None:
        try:
            supabase_count = _core.admin_pause_all()
        except RepositoryNotConfigured:
            # Core أُنشئ بلا CodeQueryRepository (نظريًا غير متوقَّع هنا
            # لأن _init_supabase_core تمررها دائمًا لو Supabase مهيَّأ،
            # لكن فشل واضح أفضل من كسر صامت لو حدث تغيير مستقبلي).
            #
            # ⚠️ إصلاح #19: كانت هذي الكتلة تلتقط "except RuntimeError"
            # عامة سابقًا -- بما أن SupabaseRequestError نفسها وريثة
            # RuntimeError، أي فشل اتصال حقيقي بـSupabase أثناء سرد
            # الأكواد كان يُبتلَع صامتًا هنا، ويرجع النجاح الوهمي
            # (ok:true, count:0) بدل رد فشل حقيقي -- أخطر تسرّب من كل
            # ما اكتُشف بمراجعة #19 (كذب صامت بنجاح Kill Switch فشل
            # فعليًا). RepositoryNotConfigured لا ترث RuntimeError
            # عمدًا (راجع core.py)، فلا يوجد تصادم بعد الآن --
            # SupabaseRequestError تفلت من هذي الكتلة وتصل لمعالج
            # _handle_supabase_unavailable العام بدلًا من ذلك.
            pass

    _log("PAUSE_ALL")
    _notify("تم إيقاف كل الأكواد دفعة وحدة (kill-switch)")
    return jsonify(ok=True, count=local_count, supabase_count=supabase_count)


@app.route("/admin/list", methods=["GET"])
def admin_list():
    if not _require_admin():
        return jsonify(ok=False, reason="unauthorized"), 401
    data = _load()
    safe = {}
    for code, entry in data["codes"].items():
        safe[code] = {k: v for k, v in entry.items() if k != "key_b64"}
    return jsonify(ok=True, codes=safe)


# ── نقطة التحقق (يستخدمها الملف المشفر تلقائياً) ────────────────

class FailureTrackerRepository(Protocol):
    """
    واجهة تتبع محاولات الفشل لأغراض Rate Limiting — مضافة كنقطة
    تكامل لإصلاح H3 (العدّاد الحالي بالذاكرة يُصفَّر مع كل إعادة
    نشر، مما يسمح لمهاجم يعرف/يسبّب توقيت إعادة النشر بتجاوز الحد).

    هذي الواجهة فقط — لا تنفيذ Supabase حي بعد. نقل التنفيذ الفعلي
    لقاعدة بيانات يحتاج تعديل مخطط (جدول/RPC جديدة)، خارج حدود هذا
    الإصلاح (يحتاج فتح Phase 2 لقاعدة البيانات صراحة). راجع
    SupabaseFailureTrackerRepository أدناه لتفاصيل المتطلبات الكاملة.
    """

    def record_failure(self, ip: str, now: datetime) -> None:
        """يسجّل محاولة فاشلة لهذا الـIP بهذا التوقيت."""
        ...

    def count_recent_failures(self, ip: str, window_seconds: int, now: datetime) -> int:
        """يرجع عدد المحاولات الفاشلة لهذا الـIP خلال آخر window_seconds ثانية."""
        ...


class InMemoryFailureTracker:
    """
    التنفيذ الافتراضي الحالي — بالذاكرة فقط، نفس سلوك المتغيّر
    القديم _fail_tracker حرفيًا بلا أي تغيير سلوكي. يُصفَّر مع كل
    إعادة نشر/إعادة تشغيل — هذا بالضبط القيد الموثَّق بـH3، غير
    محلول هنا عمدًا (يحتاج Supabase، مؤجَّل لـPhase 2).
    """

    def __init__(self) -> None:
        self._store: dict = {}

    def record_failure(self, ip: str, now: datetime) -> None:
        self._store.setdefault(ip, []).append(now.timestamp())

    def count_recent_failures(self, ip: str, window_seconds: int, now: datetime) -> int:
        window = self._store.setdefault(ip, [])
        cutoff = now.timestamp() - window_seconds
        window[:] = [t for t in window if t > cutoff]
        return len(window)


class SupabaseFailureTrackerRepository:
    """
    ⚠️ غير منفَّذة — نقطة تكامل موثَّقة فقط لإصلاح H3 الكامل مستقبلًا
    (Phase 2، بعد فتحها صراحة). عند التنفيذ الفعلي، تحتاج:

      1. جدول جديد بـSupabase، مثلًا:
         verify_failures(ip text, occurred_at timestamptz)
      2. دالتا RPC جديدتان:
         ck_record_verify_failure(p_ip)
         ck_count_recent_verify_failures(p_ip, p_window_seconds)
      3. آلية تنظيف دورية للسجلات القديمة (TTL/مهمة مجدولة منفصلة)،
         لمنع نمو الجدول بلا حدود.

    ترفع NotImplementedError حاليًا — لا تُستخدَم افتراضيًا، ولا
    يوجد أي كود يستدعيها بهذي المرحلة.
    """

    def record_failure(self, ip: str, now: datetime) -> None:
        raise NotImplementedError(
            "SupabaseFailureTrackerRepository تحتاج تنفيذ Phase 2 "
            "لقاعدة البيانات (جدول + RPC جديدة) — غير منفَّذة بعد."
        )

    def count_recent_failures(self, ip: str, window_seconds: int, now: datetime) -> int:
        raise NotImplementedError(
            "SupabaseFailureTrackerRepository تحتاج تنفيذ Phase 2 "
            "لقاعدة البيانات (جدول + RPC جديدة) — غير منفَّذة بعد."
        )


# نقطة التبديل المستقبلية لإصلاح H3 الكامل: استبدل هذا السطر بتنفيذ
# SupabaseFailureTrackerRepository حين تُفتَح Phase 2 لقاعدة البيانات.
_failure_tracker: FailureTrackerRepository = InMemoryFailureTracker()

# توافق خلفي: test_license_server_migration.py يستدعي
# license_server._fail_tracker.clear() مباشرة بين كل اختبار — هذا
# الاسم يبقى متاحًا بنفس الصيغة (dict حقيقي، لا نسخة) بلا أي تعديل
# على ملف الاختبار.
_fail_tracker = _failure_tracker._store


def _rate_limited(ip: str) -> bool:
    return _failure_tracker.count_recent_failures(
        ip, window_seconds=3600, now=datetime.now(timezone.utc)
    ) >= 5


def _mark_fail(ip: str) -> None:
    _failure_tracker.record_failure(ip, datetime.now(timezone.utc))


@app.route("/verify", methods=["POST"])
def verify():
    ip = request.remote_addr or "unknown"
    if _rate_limited(ip):
        return jsonify(ok=False, reason="rate_limited"), 429
    if _server_mode is None:
        return jsonify(ok=False, reason="server_misconfigured"), 500

    body = request.get_json(force=True, silent=True) or {}
    code = str(body.get("code", ""))
    device_id = str(body.get("device_id", ""))[:200]
    ciphertext_b64 = str(body.get("ciphertext_b64", ""))

    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        # نفس سلوك الأصل: base64 تالف يُعامَل كفشل فك تشفير، لا خطأ
        # منفصل -- نمرره فارغًا فيفشل طبيعيًا بمرحلة فك التشفير.
        ciphertext = b""

    result = _server_mode.verify_and_decrypt(code, device_id, ciphertext)

    if not result.ok:
        # إصلاح H1 (Oracle Leak): not_found/revoked/expired تُعطى نفس
        # الرد تمامًا (نفس status، نفس body، نفس الرسالة) — لا يجوز
        # لأي طرف خارجي استنتاج أيًا من الحالات الثلاث فرق بينها عبر
        # /verify. لو احتاج العميل الشرعي معرفة السبب الحقيقي، فذلك
        # عبر قناة إدارية (لوحة الإدارة/بوت الإدارة) لا هذي النقطة.
        reason_map = {
            "not_found": "invalid_or_revoked",
            "revoked": "invalid_or_revoked",
            "expired": "invalid_or_revoked",
            "device_limit_reached": "device_limit",
            "decrypt_error": "decrypt_error",
        }
        wire_reason = reason_map.get(result.reason, result.reason)
        status_code = 400 if wire_reason == "decrypt_error" else 403

        # Fail Closed: معاملة موحَّدة تمامًا لكل حالات صلاحية الكود
        # (invalid_or_revoked) — بلا أي استثناء لأي سبب داخلي حقيقي،
        # وإلا يتسرّب فرق سلوكي عبر الزمن (Rate Limit) حتى لو تطابق
        # نص الرد ظاهريًا. هذا يستبدل الاستثناء القديم الذي كان يعفي
        # "expired" من العدّاد — ذاك الاستثناء بحد ذاته كان قناة
        # استطلاع خفية (Oracle عبر توقيت الحظر، لا نص الرد).
        _mark_fail(ip)

        # السبب الحقيقي (result.reason) يُسجَّل بالسجل الداخلي فقط
        # للتشخيص الإداري — لا يظهر إطلاقًا بالرد الشبكي (wire_reason).
        _log("VERIFY_FAIL code=" + code + " device=" + device_id + " reason=" + result.reason)
        return jsonify(ok=False, reason=wire_reason), status_code

    if result.is_new_device:
        label_suffix = (" (" + result.label + ")") if result.label else ""
        _notify("جهاز جديد فعّل الكود " + code + label_suffix)

    _log("VERIFY_OK code=" + code + " device=" + device_id)
    return jsonify(
        ok=True,
        name=result.filename,
        source_b64=base64.b64encode(result.source_bytes).decode("ascii"),
    )


@app.route("/", methods=["GET"])
def health():
    return jsonify(ok=True, service="cipherkeep-license-server")


start_telegram_admin_bot()  # يشتغل عند استيراد الملف (يغطي gunicorn وأي طريقة تشغيل)

if __name__ == "__main__":
    if not ADMIN_TOKEN:
        print("تحذير: ADMIN_TOKEN مو محدد -- كل أوامر الإدارة راح تترفض")
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
