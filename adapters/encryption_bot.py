#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
encryption_bot.py -- بوت تيليجرام لتشفير ملفات بايثون عن بعد
================================================================
يستقبل ملف .py، يسأل بأزرار عن طريقة التشفير (باسورد/مفتاح/سيرفر)،
ويرجع الملف المشفر .enc.py جاهز -- بدون ما تحتاج تشغل شي يدوي بالجوال.

يستخدم encryptor.py مباشرة كموديول (لازم يكون بنفس المجلد) --
ما فيه تكرار لمنطق التشفير، نفس الكود المختبر بالضبط.

إعداد قبل التشغيل (متغيرات بيئة، أو عدلها مباشرة تحت):
    ENCRYPT_BOT_TOKEN   توكن بوت التشفير (بوت منفصل عن بوت الإدارة)
    ALLOWED_USER_IDS    آيدي المستخدمين المسموح لهم، مفصولين بفاصلة
    LICENSE_SERVER_URL  رابط سيرفر الترخيص (لوضع السيرفر فقط)
    LICENSE_ADMIN_TOKEN توكن إدارة السيرفر (لوضع السيرفر فقط)

بواسطة: HASBOOO
"""

import os
import sys
import json
import time
from pathlib import Path

import requests

import encryptor  # نفس ملف encryptor.py -- يستورد دواله مباشرة

# ================= إعدادات =================
BOT_TOKEN = os.environ.get("ENCRYPT_BOT_TOKEN", "ضع_توكن_بوت_التشفير_هنا")
ALLOWED_USER_IDS = set(
    x.strip() for x in os.environ.get("ALLOWED_USER_IDS", "ضع_آيديك_هنا").split(",") if x.strip()
)
LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "https://cipherkeep-server-1.onrender.com")
LICENSE_ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "")

WORK_DIR = Path.cwd() / "_bot_tmp"
WORK_DIR.mkdir(exist_ok=True)

API = "https://api.telegram.org/bot" + BOT_TOKEN

# حالة كل مستخدم وهو بمنتصف عملية تشفير (بالذاكرة -- يكفي لمشروع شخصي)
pending = {}  # chat_id(str) -> {"path": Path, "name": str}


# ================= أدوات تيليجرام أساسية =================

def tg_get(method, params=None):
    try:
        r = requests.get(API + "/" + method, params=params, timeout=30)
        return r.json()
    except Exception as e:
        print("tg_get error:", method, e)
        return {}


def tg_post(method, data=None, files=None):
    try:
        r = requests.post(API + "/" + method, data=data, files=files, timeout=30)
        return r.json()
    except Exception as e:
        print("tg_post error:", method, e)
        return {}


def send_text(chat_id, text, reply_markup=None):
    data = {"chat_id": chat_id, "text": text}
    if reply_markup:
        data["reply_markup"] = json.dumps(reply_markup)
    return tg_post("sendMessage", data=data)


def send_document(chat_id, file_path: Path, caption=""):
    with open(file_path, "rb") as f:
        return tg_post(
            "sendDocument",
            data={"chat_id": chat_id, "caption": caption},
            files={"document": (file_path.name, f)},
        )


def answer_callback(callback_id, text=""):
    tg_post("answerCallbackQuery", data={"callback_query_id": callback_id, "text": text})


def download_telegram_file(file_id, dest_path: Path):
    info = tg_get("getFile", {"file_id": file_id})
    file_path = info.get("result", {}).get("file_path")
    if not file_path:
        return False
    url = "https://api.telegram.org/file/bot" + BOT_TOKEN + "/" + file_path
    r = requests.get(url, timeout=30)
    dest_path.write_bytes(r.content)
    return True


def mode_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "🔑 باسورد يدوي", "callback_data": "mode_password"}],
            [{"text": "🗝️ مفتاح عشوائي", "callback_data": "mode_keyfile"}],
            [{"text": "🌐 سيرفر (تفعيل عن بعد)", "callback_data": "mode_server"}],
        ]
    }


def server_trial_keyboard():
    return {
        "inline_keyboard": [
            [{"text": "🧪 تجربة (3 أيام، جهاز واحد)", "callback_data": "server_trial"}],
            [{"text": "✅ نسخة كاملة (تختار التفاصيل)", "callback_data": "server_full"}],
        ]
    }


def device_count_keyboard():
    return {
        "inline_keyboard": [
            [
                {"text": "1", "callback_data": "server_devices_1"},
                {"text": "3", "callback_data": "server_devices_3"},
                {"text": "5", "callback_data": "server_devices_5"},
                {"text": "10", "callback_data": "server_devices_10"},
            ]
        ]
    }


def expire_days_keyboard():
    return {
        "inline_keyboard": [
            [
                {"text": "7 أيام", "callback_data": "server_days_7"},
                {"text": "30 يوم", "callback_data": "server_days_30"},
            ],
            [
                {"text": "90 يوم", "callback_data": "server_days_90"},
                {"text": "بلا حد", "callback_data": "server_days_none"},
            ],
        ]
    }


# ================= منطق التشفير (يستخدم encryptor.py مباشرة) =================

def encrypt_password_mode(chat_id, src_path: Path, password: str):
    if len(password) < 4:
        send_text(chat_id, "الباسورد قصير كثير (أقل من 4 أحرف). أرسل باسورد أطول:")
        return False
    salt = os.urandom(encryptor.SALT_LEN)
    n_log2 = encryptor.DEFAULT_SCRYPT_N_LOG2
    key = encryptor.derive_key(password.encode("utf-8"), salt, n_log2)
    out_path = encryptor.build_and_verify_launcher(
        src_path, key, encryptor.MODE_PASSWORD, salt, n_log2
    )
    send_document(chat_id, out_path, caption="تم التشفير بباسورد. لا تنسى الباسورد -- ما فيه استرجاع بدونه.")
    src_path.unlink(missing_ok=True)  # حذف المصدر الأصلي بعد نجاح التشفير فقط
    return True


def encrypt_keyfile_mode(chat_id, src_path: Path):
    salt = b"\x00" * encryptor.SALT_LEN
    n_log2 = 0
    key = os.urandom(encryptor.KEY_LEN)
    key_path = src_path.with_name("secret.key")
    key_path.write_bytes(key)
    out_path = encryptor.build_and_verify_launcher(
        src_path, key, encryptor.MODE_KEYFILE, salt, n_log2
    )
    send_document(chat_id, out_path, caption="الملف المشفر.")
    send_document(
        chat_id, key_path,
        caption="ملف المفتاح secret.key -- لازم يكون بنفس مجلد الملف المشفر وقت التشغيل. "
                "احتفظ بنسخة احتياطية بمكان ثاني، لو ضاع ما فيه استرجاع.",
    )
    src_path.unlink(missing_ok=True)  # حذف المصدر الأصلي بعد نجاح التشفير فقط
    return True


def encrypt_server_mode(chat_id, src_path: Path, label: str, max_devices: int, trial: bool, expire_days):
    if not LICENSE_ADMIN_TOKEN:
        send_text(chat_id, "وضع السيرفر مو مفعّل بعد -- محتاج LICENSE_ADMIN_TOKEN بإعدادات البوت.")
        return False
    resp = encryptor._http_post_json(
        LICENSE_SERVER_URL + "/admin/create",
        {"label": label, "max_devices": max_devices, "expire_days": expire_days, "trial": trial},
        {"X-Admin-Token": LICENSE_ADMIN_TOKEN, "Content-Type": "application/json"},
    )
    if not resp.get("ok"):
        send_text(chat_id, "فشل الاتصال بسيرفر الترخيص: " + str(resp.get("reason", "unknown")))
        return False
    code = resp["code"]
    key = __import__("base64").b64decode(resp["key_b64"])
    salt = b"\x00" * encryptor.SALT_LEN
    n_log2 = 0
    out_path = encryptor.build_and_verify_launcher(
        src_path, key, encryptor.MODE_SERVER, salt, n_log2, code="", server_url=LICENSE_SERVER_URL
    )
    days_txt = (str(expire_days) + " يوم") if expire_days else "بلا حد"
    send_document(chat_id, out_path, caption="الملف المشفر (وضع السيرفر).")
    send_text(
        chat_id,
        "كود التفعيل: " + code +
        "\nالأجهزة المسموحة: " + str(max_devices) +
        "\nالمدة: " + days_txt +
        ("\n(تجربة)" if trial else "") +
        "\nابعثه لصاحب الملف. تقدر تلغيه بأي وقت من بوت الإدارة.",
    )
    src_path.unlink(missing_ok=True)  # حذف المصدر الأصلي بعد نجاح التشفير فقط
    return True


# ================= معالجة الرسائل =================

def handle_document(chat_id, message):
    doc = message["document"]
    name = doc.get("file_name", "file.py")
    if not name.endswith(".py"):
        send_text(chat_id, "ابعث ملف .py فقط.")
        return

    dest = WORK_DIR / (chat_id + "_" + name)
    if not download_telegram_file(doc["file_id"], dest):
        send_text(chat_id, "فشل تحميل الملف من تيليجرام، حاول مرة ثانية.")
        return

    try:
        compile(dest.read_text(encoding="utf-8"), name, "exec")
    except SyntaxError as e:
        send_text(chat_id, "الملف فيه خطأ صياغة بايثون (سطر %s) -- ما راح يشتغل لو شفرناه." % e.lineno)
        dest.unlink(missing_ok=True)
        return
    except Exception as e:
        send_text(chat_id, "ما قدرت أقرأ الملف: " + str(e))
        dest.unlink(missing_ok=True)
        return

    pending[chat_id] = {"path": dest, "name": name}
    send_text(chat_id, "اختر طريقة التشفير لملف " + name + ":", reply_markup=mode_keyboard())


def handle_callback(cb):
    chat_id = str(cb["message"]["chat"]["id"])
    data = cb["data"]
    answer_callback(cb["id"])

    state = pending.get(chat_id)
    if not state:
        send_text(chat_id, "ابعث ملف .py أول.")
        return

    if data == "mode_password":
        state["awaiting"] = "password"
        send_text(chat_id, "أرسل الباسورد الآن كرسالة نصية (4 أحرف أو أكثر):")

    elif data == "mode_keyfile":
        ok = encrypt_keyfile_mode(chat_id, state["path"])
        if ok:
            pending.pop(chat_id, None)

    elif data == "mode_server":
        send_text(chat_id, "اختر نوع الكود:", reply_markup=server_trial_keyboard())

    elif data == "server_trial":
        ok = encrypt_server_mode(
            chat_id, state["path"], label="tg:" + chat_id,
            max_devices=1, trial=True, expire_days=3,
        )
        if ok:
            pending.pop(chat_id, None)

    elif data == "server_full":
        send_text(chat_id, "كم جهاز مسموح؟", reply_markup=device_count_keyboard())

    elif data.startswith("server_devices_"):
        state["server_max_devices"] = int(data.split("_")[-1])
        send_text(chat_id, "كم مدة الصلاحية؟", reply_markup=expire_days_keyboard())

    elif data.startswith("server_days_"):
        raw = data.split("_")[-1]
        expire_days = None if raw == "none" else int(raw)
        max_devices = state.get("server_max_devices", 1)
        ok = encrypt_server_mode(
            chat_id, state["path"], label="tg:" + chat_id,
            max_devices=max_devices, trial=False, expire_days=expire_days,
        )
        if ok:
            pending.pop(chat_id, None)


def handle_text(chat_id, text):
    state = pending.get(chat_id)
    if not state or state.get("awaiting") != "password":
        return  # ما فيه عملية تشفير معلقة بانتظار باسورد -- تجاهل

    ok = encrypt_password_mode(chat_id, state["path"], text)
    if ok:
        pending.pop(chat_id, None)


# ================= حلقة الاستطلاع (نفس أسلوب license_server.py) =================

def get_updates(offset):
    url = API + "/getUpdates?timeout=25"
    if offset is not None:
        url += "&offset=" + str(offset)
    try:
        resp = requests.get(url, timeout=30)
        return resp.json().get("result", [])
    except Exception:
        return []


def poll_loop():
    offset = None
    print("بوت التشفير شغال...")
    while True:
        for u in get_updates(offset):
            offset = u["update_id"] + 1
            try:
                if "callback_query" in u:
                    cb = u["callback_query"]
                    chat_id = str(cb["message"]["chat"]["id"])
                    if chat_id not in ALLOWED_USER_IDS:
                        answer_callback(cb["id"], "غير مصرح لك.")
                        continue
                    handle_callback(cb)
                    continue

                msg = u.get("message") or {}
                chat_id = str(msg.get("chat", {}).get("id", ""))
                if not chat_id:
                    continue
                if chat_id not in ALLOWED_USER_IDS:
                    send_text(chat_id, "غير مصرح لك تستخدم هذا البوت.")
                    continue

                if "document" in msg:
                    handle_document(chat_id, msg)
                elif "text" in msg:
                    if msg["text"] == "/start":
                        send_text(chat_id, "ابعثلي ملف .py وراح أسألك عن طريقة التشفير.")
                    else:
                        handle_text(chat_id, msg["text"])
            except Exception as e:
                print("خطأ بمعالجة تحديث:", e)
        time.sleep(1)


def main():
    if BOT_TOKEN.startswith("ضع_") or not ALLOWED_USER_IDS or "ضع_" in list(ALLOWED_USER_IDS)[0]:
        print("خطأ: عبّي ENCRYPT_BOT_TOKEN و ALLOWED_USER_IDS قبل التشغيل.")
        sys.exit(1)
    if not LICENSE_SERVER_URL.startswith("https://"):
        print("خطأ: LICENSE_SERVER_URL يجب أن يبدأ بـ https:// -- رفض التشغيل "
              "لحماية LICENSE_ADMIN_TOKEN من الانكشاف عبر قناة غير مشفَّرة.")
        sys.exit(1)
    poll_loop()


if __name__ == "__main__":
    main()
