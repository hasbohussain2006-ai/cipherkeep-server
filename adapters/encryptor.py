#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CipherKeep v2.1 -- أداة تشفير شخصية لملفات بايثون (AES-256-GCM)
==================================================================

  encrypt  → name.py       يصير  →  name.enc.py  (يشتغل مباشرة + محمي)
  decrypt  → name.enc.py   يرجع  →  name.py       (نص واضح، لو احتجته)

ثلاث طرق لإدارة المفتاح وقت التشفير:
  1) باسورد يدوي   (Scrypt)      -- يُطلب وقت كل تشغيل
  2) مفتاح عشوائي  (secret.key)  -- يُقرأ تلقائياً من ملف جنب السكربت
  3) سيرفر (تفعيل عن بعد)        -- يحتاج license_server.py يشتغل بمكان
     تتحكم فيه (Render/Railway). يعطيك كود تفعيل تبعثه لصاحب النسخة.
     تقدر تلغي/تحدد صلاحيته بأي وقت من مكان واحد.

المتطلبات: Python 3.8+
  أوضاع 1 و2 تحتاج: مكتبة cryptography
      Termux  : pkg install python-cryptography
      Pydroid : Pip -> فعل Use prebuilt libraries repository -> cryptography
  وضع 3 لا يحتاج مكتبة cryptography عند الطرف الثاني إطلاقاً (urllib بس،
  مكتبة قياسية بايثون) -- أسهل توزيع للأصدقاء.

إعدادات اختيارية (settings.txt بجنب السكربت):
    APP_NAME=...
    OWNER_SIGNATURE=...
    LICENSE_SERVER_URL=https://your-server.onrender.com
    LICENSE_ADMIN_TOKEN=نفس-قيمة-ADMIN_TOKEN-بالسيرفر

بواسطة: HASBOOO
"""

from __future__ import annotations

import base64
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("مكتبة cryptography غير مثبتة (لازمة لوضع الباسورد/المفتاح، مو لوضع السيرفر).")
    print("Termux : pkg install python-cryptography")
    print("Pydroid: Pip -> فعل Use prebuilt libraries repository -> cryptography")
    sys.exit(1)


# ── إعدادات عامة ──────────────────────────────────────────────

APP_NAME = "CipherKeep"
OWNER_SIGNATURE = "HASBOOO"
TOOL_VERSION = "2.1"
SETTINGS_FILENAME = "settings.txt"
LICENSE_SERVER_URL = ""
LICENSE_ADMIN_TOKEN = ""

MAGIC = b"SFCL0002"
VERSION = 1

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

MODE_PASSWORD = 1
MODE_KEYFILE = 2
MODE_SERVER = 3

DEFAULT_SCRYPT_N_LOG2 = 15
SCRYPT_R = 8
SCRYPT_P = 1

OUTPUT_SUFFIX = ".enc.py"
DEFAULT_KEY_FILENAME = "secret.key"
DEFAULT_PASSWORD_BACKUP = "password_backup.txt"
SERVER_KEYS_FILENAME = "server_keys.json"

HEADER_FMT = ">8sBBB16s12s"
HEADER_LEN = struct.calcsize(HEADER_FMT)

SELF_PATH = Path(__file__).resolve()
TOOL_OWN_FILES = (DEFAULT_KEY_FILENAME, DEFAULT_KEY_FILENAME + ".backup",
                  DEFAULT_PASSWORD_BACKUP, SETTINGS_FILENAME, SERVER_KEYS_FILENAME)

_PAYLOAD_RE = re.compile(r'_PAYLOAD_B64\s*=\s*"([A-Za-z0-9+/=]+)"')
_CODE_RE = re.compile(r'_CODE\s*=\s*"([A-Za-z0-9\-]+)"')


# ── واجهة نصية بسيطة (git/npm) ────────────────────────────────

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"


_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}" if _USE_COLOR else text


def ok(msg: str) -> None:
    print(f"  {c('+', Colors.GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"  {c('!', Colors.YELLOW)} {msg}")


def fail(msg: str) -> None:
    print(f"  {c('x', Colors.RED)} {msg}")


def info(msg: str) -> None:
    print(f"  {c('i', Colors.CYAN)} {msg}")


def banner() -> None:
    print(f"{c(APP_NAME, Colors.BOLD)} v{TOOL_VERSION} -- AES-256-GCM -- local only, no network*")


def load_settings() -> None:
    global APP_NAME, OWNER_SIGNATURE, LICENSE_SERVER_URL, LICENSE_ADMIN_TOKEN
    settings_path = Path.cwd() / SETTINGS_FILENAME
    if not settings_path.exists():
        return
    try:
        for line in settings_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip().upper(), value.strip()
            if key == "APP_NAME" and value:
                APP_NAME = value
            elif key == "OWNER_SIGNATURE" and value:
                OWNER_SIGNATURE = value
            elif key == "LICENSE_SERVER_URL" and value:
                LICENSE_SERVER_URL = value.rstrip("/")
            elif key == "LICENSE_ADMIN_TOKEN" and value:
                LICENSE_ADMIN_TOKEN = value
    except OSError:
        pass


# ── مسارات ────────────────────────────────────────────────────

def read_path(prompt: str, must_exist: bool = True) -> Path:
    while True:
        raw = input(prompt).strip().strip('"').strip("'")
        if not raw:
            fail("ما كتبت شي، جرب ثانية")
            continue
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()
        if must_exist and not path.exists():
            fail(f"المسار مو موجود: {path}")
            continue
        info(f"المسار: {path}")
        return path


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 1
    stem, suffix = path.stem, path.suffix
    while True:
        candidate = path.with_name(f"{stem} ({counter}){suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def pick_path_interactive(title: str, only_suffix: Optional[str] = None) -> Path:
    cwd = Path.cwd()

    def matches(p: Path) -> bool:
        if p.resolve() == SELF_PATH:
            return False
        if p.is_dir():
            return True
        return only_suffix is None or p.suffix == only_suffix

    entries = sorted((p for p in cwd.iterdir() if matches(p)), key=lambda p: (p.is_file(), p.name.lower()))

    print()
    print(title)
    info(f"المجلد الحالي: {cwd}")
    print(f"  1) [all]  كل المجلد الحالي")
    for i, p in enumerate(entries, 2):
        tag = "[dir]" if p.is_dir() else "[file]"
        print(f"  {i}) {tag} {p.name}")
    print("  0) [path] اكتب مسار يدوي")

    choice = input("اختر رقم: ").strip()

    if choice == "0":
        return read_path("اكتب المسار كامل: ")
    if choice == "1":
        info(f"اخترت: كل المجلد {cwd}")
        return cwd
    if not choice.isdigit() or not (2 <= int(choice) <= len(entries) + 1):
        fail("رقم غير موجود، جرب ثانية")
        return pick_path_interactive(title, only_suffix)

    chosen = entries[int(choice) - 2].resolve()
    info(f"اخترت: {chosen}")
    return chosen


def print_progress(current: int, total: int) -> None:
    pct = int(current / total * 100)
    bar_len = 22
    filled = int(bar_len * current / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    print(c(f"  [{bar}] {pct:3d}%  ({current}/{total})", Colors.DIM))


# ── إدارة المفاتيح المحلية ─────────────────────────────────────

def load_or_create_keyfile(key_path: Path) -> bytes:
    if key_path.exists():
        data = key_path.read_bytes()
        if len(data) != KEY_LEN:
            fail(f"{key_path.name} تالف أو مو مفتاح صحيح")
            sys.exit(1)
        ok(f"تحميل المفتاح من {key_path.name}")
        return data

    key = os.urandom(KEY_LEN)
    key_path.write_bytes(key)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    backup_path = key_path.with_name(key_path.name + ".backup")
    try:
        backup_path.write_bytes(key)
        os.chmod(backup_path, 0o600)
    except OSError:
        pass

    ok(f"مفتاح عشوائي جديد: {key_path.name} (+ نسخة احتياطية {backup_path.name})")
    warn("انسخ وحدة من النسختين لمكان ثاني بعيد -- لو ضاع الاثنين، ما فيه رجعة")
    return key


_PASSWORD_MIN_LEN = 12


def _password_policy_violations(pw: str) -> list:
    """
    يرجّع قائمة بالشروط الناقصة فقط (فارغة = الباسورد مطابق للسياسة).
    مستخرجة كدالة مستقلة عشان تُطبَّق فقط وقت إنشاء باسورد جديد --
    لا وقت إدخاله لفك تشفير ملف قديم (راجع استخدام confirm أدناه).
    """
    issues = []
    if len(pw) < _PASSWORD_MIN_LEN:
        issues.append(f"{_PASSWORD_MIN_LEN} حرف على الأقل")
    if not any(c.isupper() for c in pw):
        issues.append("حرف كبير واحد على الأقل (A-Z)")
    if not any(c.islower() for c in pw):
        issues.append("حرف صغير واحد على الأقل (a-z)")
    if not any(c.isdigit() for c in pw):
        issues.append("رقم واحد على الأقل (0-9)")
    if not any(not c.isalnum() for c in pw):
        issues.append("رمز خاص واحد على الأقل (!@#$...)")
    return issues


def prompt_password(confirm: bool) -> bytes:
    while True:
        pw1 = input("اكتب الباسورد: ")

        if confirm:
            # سياسة قوة أدنى -- تُفرَض فقط عند إنشاء باسورد جديد
            # (وضع التشفير). لا تُفرَض عند إدخال باسورد لفك تشفير ملف
            # موجود مسبقًا (confirm=False بـrun_decrypt) -- ملفات
            # قديمة مشفَّرة بباسوردات أقصر يجب أن تبقى قابلة لفك
            # التشفير بلا كسر توافق.
            issues = _password_policy_violations(pw1)
            if issues:
                fail("الباسورد لازم يحتوي: " + "، ".join(issues))
                continue
        elif len(pw1) < 1:
            fail("ما كتبت شي، جرب ثانية")
            continue

        if confirm:
            pw2 = input("أكد الباسورد: ")
            if pw1 != pw2:
                fail("الباسوردين مو متطابقين")
                continue
        return pw1.encode("utf-8")


def maybe_backup_password(password: bytes, backup_path: Path) -> None:
    if backup_path.exists():
        return
    answer = input("تحفظ نسخة من الباسورد بملف نصي؟ (y/n): ").strip().lower()
    if answer != "y":
        return
    backup_path.write_text(password.decode("utf-8"), encoding="utf-8")
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass
    warn(f"انحفظ بنص واضح داخل {backup_path.name} -- انقله لمكان آمن بعدين")


def derive_key(password: bytes, salt: bytes, n_log2: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2 ** n_log2, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password)


# ── سيرفر الترخيص (طلبات الإدارة من الأداة) ────────────────────

def _http_post_json(url: str, data: dict, headers: Optional[dict] = None) -> dict:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers or {"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {"ok": False, "reason": "http_" + str(e.code)}
    except Exception as e:
        return {"ok": False, "reason": "connection_error: " + str(e)}


def load_server_keys() -> dict:
    path = Path.cwd() / SERVER_KEYS_FILENAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_server_key(code: str, key_b64: str, label: str) -> None:
    path = Path.cwd() / SERVER_KEYS_FILENAME
    data = load_server_keys()
    data[code] = {"key_b64": key_b64, "label": label, "created_at": time.strftime("%Y-%m-%d %H:%M")}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def create_server_code() -> Optional[tuple]:
    server_url = LICENSE_SERVER_URL
    admin_token = LICENSE_ADMIN_TOKEN
    if not server_url:
        server_url = input("رابط سيرفر الترخيص (https://...): ").strip().rstrip("/")
    if not admin_token:
        admin_token = input("توكن الإدارة (ADMIN_TOKEN): ").strip()

    label = input("تسمية (مين راح ياخذ هذا الكود؟): ").strip()
    trial = input("تجربة مجانية 3 أيام؟ (y/n): ").strip().lower() == "y"
    max_devices = 1
    expire_days = None
    if not trial:
        raw_md = input("عدد الأجهزة المسموحة [افتراضي 1]: ").strip()
        max_devices = int(raw_md) if raw_md.isdigit() else 1
        raw_exp = input("ينتهي بعد كم يوم؟ [فاضي = ما ينتهي]: ").strip()
        expire_days = int(raw_exp) if raw_exp.isdigit() else None

    info("اتصال بسيرفر الترخيص...")
    resp = _http_post_json(
        server_url + "/admin/create",
        {"label": label, "max_devices": max_devices, "expire_days": expire_days, "trial": trial},
        {"X-Admin-Token": admin_token, "Content-Type": "application/json"},
    )
    if not resp.get("ok"):
        fail(f"فشل الاتصال بالسيرفر: {resp.get('reason', 'unknown')}")
        return None

    code, key_b64 = resp["code"], resp["key_b64"]
    save_server_key(code, key_b64, label)
    ok(f"كود التفعيل: {code}")
    info("هذا الكود تبعثه لصاحب الملف -- خليك تحتفظ بنسخة منه (انحفظ محلياً بالفعل)")
    return code, base64.b64decode(key_b64), server_url


# ── تشفير/فك تشفير أساسي (على مستوى البايتات) ────────────────

def pack_header(mode: int, salt: bytes, nonce: bytes, n_log2: int) -> bytes:
    return struct.pack(HEADER_FMT, MAGIC, VERSION, mode, n_log2, salt, nonce)


def encrypt_bytes(data: bytes, original_name: str, key: bytes, mode: int, salt: bytes, n_log2: int) -> bytes:
    name_bytes = original_name.encode("utf-8")
    inner = struct.pack(">H", len(name_bytes)) + name_bytes + data
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, inner, associated_data=MAGIC)
    return pack_header(mode, salt, nonce, n_log2) + ciphertext


def decrypt_bytes(blob: bytes, key: bytes) -> tuple[str, bytes]:
    nonce = blob[HEADER_LEN - NONCE_LEN:HEADER_LEN]
    ciphertext = blob[HEADER_LEN:]
    inner = AESGCM(key).decrypt(nonce, ciphertext, associated_data=MAGIC)
    name_len = struct.unpack(">H", inner[:2])[0]
    name = inner[2:2 + name_len].decode("utf-8")
    data = inner[2 + name_len:]
    return name, data


# ── قالب اللانشر (الملف المشفر القابل للتشغيل) ────────────────
# ملاحظة: منطق وضع السيرفر مكتوب بأسماء مختصرة عمداً (تشويش خفيف) --
# هذا يرفع الجهد المطلوب لأي حد يحاول يعدل الشرط يدوياً، مو حماية مطلقة.

_LAUNCHER_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ملف محمي بواسطة __APP_NAME__ -- الكود الأصلي مشفر بالكامل بالأسفل
# يفك تشفيره بالذاكرة فقط وقت التشغيل، بدون أي نسخة مكشوفة على القرص.
import sys, os, struct, base64

_PAYLOAD_B64 = __PAYLOAD__
_CODE = __CODE__
_SRV_B64 = __SERVER_URL_B64__
_HEADER_FMT = ">8sBBB16s12s"
_HEADER_LEN = struct.calcsize(_HEADER_FMT)
_MODE_PASSWORD = 1
_MODE_KEYFILE = 2
_MODE_SERVER = 3


def _rs(_x, _y):
    return _x if _y else None


def _z9(_blob):
    import urllib.request, urllib.error, json, uuid
    _h = os.path.dirname(os.path.abspath(__file__))
    _df = os.path.join(_h, ".ck_dev")
    _af = os.path.join(_h, ".ck_act")

    if os.path.exists(_df):
        _dev = open(_df, "r", encoding="utf-8").read().strip()
    else:
        _dev = uuid.uuid4().hex
        open(_df, "w", encoding="utf-8").write(_dev)

    _code = _CODE
    if not _code:
        if os.path.exists(_af):
            _code = open(_af, "r", encoding="utf-8").read().strip()
        else:
            _code = input("اكتب كود التفعيل: ").strip()

    _srv = base64.b64decode(_SRV_B64).decode("utf-8")
    _pl = json.dumps({"code": _code, "device_id": _dev, "ciphertext_b64": _blob}).encode("utf-8")
    _req = urllib.request.Request(_srv + "/verify", data=_pl,
                                   headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(_req, timeout=15) as _r:
            _resp = json.loads(_r.read())
    except urllib.error.HTTPError as _e:
        try:
            _resp = json.loads(_e.read())
        except Exception:
            print("خطأ بالاتصال بسيرفر الترخيص: HTTP " + str(_e.code))
            sys.exit(1)
    except Exception as _e:
        print("خطأ بالاتصال بسيرفر الترخيص: " + str(_e))
        sys.exit(1)

    if not _rs(_resp.get("ok"), True):
        print("خطأ: " + str(_resp.get("reason", "unknown")))
        sys.exit(1)

    if not os.path.exists(_af):
        open(_af, "w", encoding="utf-8").write(_code)

    return _resp["name"], base64.b64decode(_resp["source_b64"])


def _main():
    blob_raw = base64.b64decode(_PAYLOAD_B64)
    magic, version, mode, n_log2, salt, nonce = struct.unpack(_HEADER_FMT, blob_raw[:_HEADER_LEN])

    if mode == _MODE_SERVER:
        original_name, source_code_bytes = _z9(_PAYLOAD_B64)
        source_code = source_code_bytes.decode("utf-8")
        real_path = os.path.abspath(__file__)
        g = {"__name__": "__main__", "__file__": real_path}
        exec(compile(source_code, original_name, "exec"), g)
        return

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.exceptions import InvalidTag
    except ImportError:
        print("مكتبة cryptography غير مثبتة. ثبتها بـ: pip install cryptography")
        sys.exit(1)

    ciphertext = blob_raw[_HEADER_LEN:]

    if mode == _MODE_PASSWORD:
        password = input("اكتب الباسورد: ")
        kdf = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=8, p=1)
        key = kdf.derive(password.encode("utf-8"))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        default_path = os.path.join(here, "secret.key")
        raw = input("مسار ملف المفتاح [Enter = secret.key]: ").strip()
        key_path = raw if raw else default_path
        if not os.path.exists(key_path):
            print("خطأ: ملف المفتاح مو موجود: " + key_path)
            sys.exit(1)
        with open(key_path, "rb") as kf:
            key = kf.read()

    try:
        inner = AESGCM(key).decrypt(nonce, ciphertext, associated_data=magic)
    except InvalidTag:
        print("خطأ: الباسورد/المفتاح غلط")
        sys.exit(1)

    name_len = struct.unpack(">H", inner[:2])[0]
    original_name = inner[2:2 + name_len].decode("utf-8")
    source_code = inner[2 + name_len:].decode("utf-8")

    real_path = os.path.abspath(__file__)
    g = {"__name__": "__main__", "__file__": real_path}
    exec(compile(source_code, original_name, "exec"), g)


if __name__ == "__main__":
    _main()
'''


def extract_blob_from_launcher(path: Path) -> Optional[bytes]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    m = _PAYLOAD_RE.search(text)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1))
    except Exception:
        return None


def extract_code_from_launcher(path: Path) -> Optional[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    m = _CODE_RE.search(text)
    return m.group(1) if m else None


def peek_header_py(path: Path) -> Optional[dict]:
    blob = extract_blob_from_launcher(path)
    if blob is None or len(blob) < HEADER_LEN:
        return None
    magic, version, mode, n_log2, salt, nonce = struct.unpack(HEADER_FMT, blob[:HEADER_LEN])
    if magic != MAGIC:
        return None
    return {"version": version, "mode": mode, "n_log2": n_log2, "salt": salt, "nonce": nonce, "blob": blob}


def build_and_verify_launcher(
    source_path: Path, key: bytes, mode: int, salt: bytes, n_log2: int,
    code: str = "", server_url: str = "",
) -> Path:
    source_bytes = source_path.read_text(encoding="utf-8").encode("utf-8")

    try:
        compile(source_bytes, source_path.name, "exec")
    except SyntaxError as e:
        raise RuntimeError(f"الملف فيه خطأ صياغة بايثون ({e.msg}, سطر {e.lineno}) -- ما راح يشتغل لو شفرناه")

    blob = encrypt_bytes(source_bytes, source_path.name, key, mode, salt, n_log2)

    verify_name, verify_data = decrypt_bytes(blob, key)
    if verify_name != source_path.name or verify_data != source_bytes:
        raise RuntimeError("فشل التحقق الفوري بعد التشفير")

    payload_b64 = base64.b64encode(blob).decode("ascii")
    server_url_b64 = base64.b64encode(server_url.encode("utf-8")).decode("ascii")

    launcher_code = (
        _LAUNCHER_TEMPLATE
        .replace("__APP_NAME__", APP_NAME)
        .replace("__PAYLOAD__", '"' + payload_b64 + '"')
        .replace("__CODE__", '"' + code + '"')
        .replace("__SERVER_URL_B64__", '"' + server_url_b64 + '"')
    )

    out_path = unique_path(source_path.with_name(source_path.stem + OUTPUT_SUFFIX))
    out_path.write_text(launcher_code, encoding="utf-8")
    return out_path


# ── جمع الملفات ───────────────────────────────────────────────

def collect_py_files(target: Path) -> list[Path]:
    if target.is_file():
        if target.resolve() == SELF_PATH or target.name in TOOL_OWN_FILES:
            return []
        return [target] if peek_header_py(target) is None else []
    files = []
    for p in sorted(target.rglob("*.py")):
        if p.is_file() and p.resolve() != SELF_PATH and p.name not in TOOL_OWN_FILES:
            if peek_header_py(p) is None:
                files.append(p)
    return files


def collect_encrypted_py_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    files = []
    for p in sorted(target.rglob("*.py")):
        if p.is_file() and p.resolve() != SELF_PATH and p.name not in TOOL_OWN_FILES:
            if peek_header_py(p) is not None:
                files.append(p)
    return files


# ── تشفير ─────────────────────────────────────────────────────

def run_encrypt() -> None:
    print()
    print(c("encrypt", Colors.BOLD))
    print("  1) باسورد يدوي")
    print("  2) مفتاح عشوائي")
    print("  3) سيرفر (تفعيل عن بعد)")
    choice = input("اختر (1/2/3): ").strip()

    code = ""
    server_url = ""

    if choice == "1":
        mode = MODE_PASSWORD
        password = prompt_password(confirm=True)
        salt = os.urandom(SALT_LEN)
        n_log2 = DEFAULT_SCRYPT_N_LOG2
        key = derive_key(password, salt, n_log2)
        maybe_backup_password(password, Path.cwd() / DEFAULT_PASSWORD_BACKUP)
    elif choice == "2":
        mode = MODE_KEYFILE
        salt = b"\x00" * SALT_LEN
        n_log2 = 0
        key = load_or_create_keyfile(Path.cwd() / DEFAULT_KEY_FILENAME)
    elif choice == "3":
        result = create_server_code()
        if result is None:
            return
        code, key, server_url = result
        mode = MODE_SERVER
        salt = b"\x00" * SALT_LEN
        n_log2 = 0
    else:
        fail("اختيار غير صحيح")
        return

    target = pick_path_interactive("اختار ملف .py أو مجلد:", only_suffix=".py")
    files = collect_py_files(target)

    if not files:
        warn("ما فيه ملفات .py تحتاج تشفير بهذا المسار")
        return

    print(f"\nراح نشفر {len(files)} ملف...\n")
    done = 0
    for i, f in enumerate(files, 1):
        try:
            out_path = build_and_verify_launcher(f, key, mode, salt, n_log2, code="", server_url=server_url)
            ok(f"{f.name}  ->  {out_path.name}")
            done += 1
        except Exception as e:
            fail(f"{f.name}: {e}")
        print_progress(i, len(files))

    print()
    ok(f"خلص، {done} من {len(files)} ملف")
    if mode == MODE_SERVER:
        info(f"كود التفعيل اللي تبعثه: {code}")
    info("الملف الأصلي لسا موجود -- جرب الجديد أول قبل ما تحذف الأصلي")
    print(c(f"  {OWNER_SIGNATURE} -- {time.strftime('%Y-%m-%d %H:%M')}", Colors.DIM))


# ── فك تشفير (استخراج النص الأصلي) ────────────────────────────

def run_decrypt() -> None:
    print()
    print(c("decrypt", Colors.BOLD))
    info("يرجع الملف المحمي لنص بايثون عادي واضح -- ما يشغّل أي شي")

    target = pick_path_interactive("اختار ملف .enc.py أو مجلد:", only_suffix=".py")
    files = collect_encrypted_py_files(target) if target.is_dir() else [target]

    if not files:
        warn("ما لقيت أي ملف محمي بهذي الأداة بهذا المسار")
        return

    session: dict = {"password": None, "keyfile_bytes": None}
    hint_shown: dict = {MODE_PASSWORD: False, MODE_KEYFILE: False, MODE_SERVER: False}
    server_keys = load_server_keys()

    def resolve_key(mode: int, salt: bytes, n_log2: int, f: Path) -> Optional[bytes]:
        if mode == MODE_SERVER:
            code = extract_code_from_launcher(f)
            if not code:
                # الملفات المُنشأة بعد إزالة تضمين الكود (Compatibility
                # Fix أمني) لا تحمل الكود بنص واضح داخلها -- نطلبه يدويًا
                # بدل فشل صامت.
                code = input(f"{f.name}: اكتب كود التفعيل المرتبط بهذا الملف: ").strip()
            entry = server_keys.get(code) if code else None
            if entry is None:
                fail(f"{f.name}: ما لقيت مفتاح هذا الكود محلياً ({code})")
                return None
            return base64.b64decode(entry["key_b64"])

        if not hint_shown[mode]:
            hint_shown[mode] = True
            info("محتاج: مفتاح ملف" if mode == MODE_KEYFILE else "محتاج: باسورد")

        if mode == MODE_KEYFILE:
            if session["keyfile_bytes"] is None:
                default_path = (target if target.is_dir() else target.parent) / DEFAULT_KEY_FILENAME
                raw = input(f"مسار ملف المفتاح [Enter = {default_path.name}]: ").strip().strip('"').strip("'")
                key_path = Path(raw).expanduser().resolve() if raw else default_path
                if not key_path.exists():
                    fail(f"ملف المفتاح مو موجود: {key_path}")
                    return None
                session["keyfile_bytes"] = key_path.read_bytes()
            return session["keyfile_bytes"]
        else:
            if session["password"] is None:
                session["password"] = prompt_password(confirm=False)
            return derive_key(session["password"], salt, n_log2)

    print(f"\nراح نحاول فك تشفير {len(files)} ملف...\n")
    done = 0
    for i, f in enumerate(files, 1):
        header = peek_header_py(f)
        if header is None:
            fail(f"{f.name}: مو ملف محمي بهذي الأداة")
            print_progress(i, len(files))
            continue

        key = resolve_key(header["mode"], header["salt"], header["n_log2"], f)
        if key is None:
            print_progress(i, len(files))
            continue

        try:
            name, data = decrypt_bytes(header["blob"], key)
        except InvalidTag:
            fail(f"{f.name}: الباسورد/المفتاح غلط")
            print_progress(i, len(files))
            continue
        except Exception as e:
            fail(f"{f.name}: خطأ غير متوقع ({e})")
            print_progress(i, len(files))
            continue

        out_path = unique_path(f.parent / name)
        out_path.write_text(data.decode("utf-8"), encoding="utf-8")
        ok(f"{f.name}  ->  {out_path.name}")
        done += 1
        print_progress(i, len(files))

    print()
    ok(f"خلص، {done} من {len(files)} ملف")


# ── معلومات (بدون فك تشفير) ────────────────────────────────────

def run_inspect() -> None:
    print()
    print(c("info", Colors.BOLD))
    info("يفحص الملف بس -- ما يطلب باسورد وما يفك أي شي")

    target = pick_path_interactive("اختار ملف أو مجلد تبي تفحصه:", only_suffix=".py")
    files = collect_encrypted_py_files(target) if target.is_dir() else [target]

    if not files:
        warn("ما فيه ملفات من هذي الأداة بهذا المسار")
        return

    mode_names = {MODE_PASSWORD: "باسورد", MODE_KEYFILE: "مفتاح ملف", MODE_SERVER: "سيرفر"}

    print()
    for f in files:
        header = peek_header_py(f)
        if header is None:
            fail(f"{f.name}: مو ملف محمي بهذي الأداة")
            continue
        mode_txt = mode_names.get(header["mode"], "غير معروف")
        size_kb = f.stat().st_size / 1024
        mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(f.stat().st_mtime))
        print(f"  {f.name}")
        print(f"      يحتاج: {mode_txt}")
        if header["mode"] == MODE_SERVER:
            code = extract_code_from_launcher(f)
            print(f"      كود التفعيل: {code if code else '(غير مضمَّن بالملف -- أدخله يدويًا وقت فك التشفير)'}")
        print(f"      الحجم: {size_kb:.1f} KB   |   آخر تعديل: {mtime}")
        print(c("      (الاسم الأصلي مخفي لحد ما تفك التشفير)", Colors.DIM))
        print()


# ── main ──────────────────────────────────────────────────────

def main() -> None:
    load_settings()
    banner()
    print("1) encrypt   2) decrypt   3) info")
    choice = input("اختر (1/2/3): ").strip()

    if choice == "1":
        run_encrypt()
    elif choice == "2":
        run_decrypt()
    elif choice == "3":
        run_inspect()
    else:
        fail("اختيار غير صحيح")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("تم الإيقاف")
        sys.exit(130)
