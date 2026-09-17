"""
app.py - License Server for PAK Tool
"""
import os
import hmac
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from dotenv import load_dotenv

from database import db

load_dotenv()

# ==================== CONFIG ====================
SERVER_SECRET = os.getenv("SERVER_SECRET", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "300"))
PORT = int(os.getenv("PORT", "8000"))

if len(SERVER_SECRET) < 32:
    raise RuntimeError("SERVER_SECRET must be >= 32 chars")
if len(ADMIN_PASSWORD) < 8:
    raise RuntimeError("ADMIN_PASSWORD must be >= 8 chars")

app = Flask(__name__)


# ==================== HELPERS ====================
def get_client_ip():
    for h in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        v = request.headers.get(h)
        if v:
            return v.split(",")[0].strip()
    return request.remote_addr or "unknown"


def generate_key():
    return "BT-" + secrets.token_hex(8).upper()


def generate_token():
    return secrets.token_urlsafe(32)


def sign_response(payload):
    data = {k: v for k, v in payload.items() if k != "signature"}
    msg = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        SERVER_SECRET.encode(),
        msg.encode(),
        hashlib.sha256
    ).hexdigest()


def check_key_valid(key_data, hwid):
    if not key_data:
        return "INVALID_KEY"
    if not key_data.get("active", True):
        return "DEACTIVATED"
    try:
        expiry = datetime.fromisoformat(key_data["expiry"])
    except Exception:
        return "INVALID_EXPIRY"
    if datetime.now() > expiry:
        return "EXPIRED"
    stored_hwid = key_data.get("hwid")
    if stored_hwid is None:
        return None
    if stored_hwid != hwid:
        return "WRONG_DEVICE"
    return None


def is_valid_hwid(hwid):
    if not hwid or not (8 <= len(hwid) <= 128):
        return False
    return all(c.isalnum() or c in "-_" for c in hwid)


def err_response(reason):
    payload = {"valid": False, "reason": reason}
    payload["signature"] = sign_response(payload)
    return jsonify(payload)


def ok_response(payload):
    payload["signature"] = sign_response(payload)
    return jsonify(payload)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        password = data.get("admin_password") or request.args.get("password") or ""
        if not secrets.compare_digest(password, ADMIN_PASSWORD):
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper


# ==================== PUBLIC API ====================
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "PAK License Server",
        "status": "running",
        "version": "1.0.0"
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "time": datetime.now().isoformat(),
        "live_now": db.live_count()
    })


@app.route("/api/verify", methods=["POST"])
def verify():
    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip()
    tool_version = data.get("tool_version", "1.0.0")
    ip = get_client_ip()

    if not is_valid_hwid(hwid):
        db.log("verify_denied", key_str, "invalid_hwid", ip, hwid)
        return err_response("INVALID_HWID")

    key_data = db.get_key(key_str)
    reason = check_key_valid(key_data, hwid)
    if reason:
        db.log("verify_denied", key_str, reason, ip, hwid)
        return err_response(reason)

    if key_data.get("hwid") is None:
        db.update_key(key_str, hwid=hwid)

    token = generate_token()
    session_expires = (datetime.now() + timedelta(seconds=SESSION_TIMEOUT)).isoformat()
    db.create_session(token, key_str, hwid, session_expires, ip)
    db.update_key(key_str, last_seen=datetime.now().isoformat(), last_ip=ip)
    db.log("verify_ok", key_str, "v=" + tool_version, ip, hwid)

    crypto_seed = secrets.token_hex(32)
    payload = {
        "valid": True,
        "username": key_data["username"],
        "expiry": key_data["expiry"],
        "session_token": token,
        "session_expires": session_expires,
        "crypto_seed": crypto_seed,
        "server_time": datetime.now().isoformat(),
    }
    return ok_response(payload)


@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    hwid = data.get("hwid", "")
    ip = get_client_ip()

    session = db.get_session(token)
    if not session:
        return err_response("INVALID_SESSION")

    if session["hwid"] != hwid:
        db.delete_session(token)
        db.log("heartbeat_denied", session["key"], "hwid_mismatch", ip, hwid)
        return err_response("WRONG_DEVICE")

    try:
        exp = datetime.fromisoformat(session["expires_at"])
    except Exception:
        return err_response("BAD_SESSION")

    if datetime.now() > exp:
        db.delete_session(token)
        return err_response("SESSION_EXPIRED")

    key_data = db.get_key(session["key"])
    reason = check_key_valid(key_data, hwid)
    if reason:
        db.delete_session(token)
        db.log("heartbeat_denied", session["key"], reason, ip, hwid)
        return err_response(reason)

    new_expires = (datetime.now() + timedelta(seconds=SESSION_TIMEOUT)).isoformat()
    db.create_session(token, session["key"], session["hwid"], new_expires, ip)
    db.log("heartbeat_ok", session["key"], "", ip, hwid)

    return ok_response({
        "valid": True,
        "session_expires": new_expires,
        "server_time": datetime.now().isoformat(),
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    session = db.get_session(token)
    if session:
        db.delete_session(token)
        db.log("logout", session["key"])
    return jsonify({"ok": True})


# ==================== ADMIN API ====================
@app.route("/api/admin/create", methods=["POST"])
@admin_required
def admin_create():
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    days = int(data.get("days", 30))
    note = data.get("note", "")

    if not username:
        return jsonify({"ok": False, "error": "username required"}), 400
    if not (1 <= days <= 3650):
        return jsonify({"ok": False, "error": "days must be 1-3650"}), 400

    new_key = generate_key()
    expiry = (datetime.now() + timedelta(days=days)).isoformat()
    db.create_key(new_key, username, expiry, note)
    db.log("admin_create", new_key, "user=" + username + " days=" + str(days))

    return jsonify({
        "ok": True,
        "key": new_key,
        "username": username,
        "expiry": expiry,
        "days": days,
    })


@app.route("/api/admin/list", methods=["GET"])
def admin_list():
    password = request.args.get("password", "")
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    return jsonify({"ok": True, "keys": db.list_keys()})


@app.route("/api/admin/revoke", methods=["POST"])
@admin_required
def admin_revoke():
    data = request.get_json() or {}
    key = (data.get("key") or "").upper()
    if not db.get_key(key):
        return jsonify({"ok": False, "error": "key not found"}), 404
    db.delete_key(key)
    db.log("admin_revoke", key, "deleted")
    return jsonify({"ok": True, "message": "Key deleted"})


@app.route("/api/admin/toggle", methods=["POST"])
@admin_required
def admin_toggle():
    data = request.get_json() or {}
    key = (data.get("key") or "").upper()
    active = bool(data.get("active", True))
    if not db.get_key(key):
        return jsonify({"ok": False, "error": "key not found"}), 404
    db.update_key(key, active=1 if active else 0)
    db.log("admin_toggle", key, "active=" + str(active))
    return jsonify({"ok": True, "key": key, "active": active})


@app.route("/api/admin/reset-hwid", methods=["POST"])
@admin_required
def admin_reset_hwid():
    data = request.get_json() or {}
    key = (data.get("key") or "").upper()
    if not db.get_key(key):
        return jsonify({"ok": False, "error": "key not found"}), 404
    db.update_key(key, hwid=None)
    db.log("admin_reset_hwid", key, "hwid cleared")
    return jsonify({"ok": True, "message": "HWID reset"})


@app.route("/api/admin/extend", methods=["POST"])
@admin_required
def admin_extend():
    data = request.get_json() or {}
    key = (data.get("key") or "").upper()
    days = int(data.get("days", 30))
    key_data = db.get_key(key)
    if not key_data:
        return jsonify({"ok": False, "error": "key not found"}), 404
    try:
        current = datetime.fromisoformat(key_data["expiry"])
    except Exception:
        current = datetime.now()
    new_expiry = (max(current, datetime.now()) + timedelta(days=days)).isoformat()
    db.update_key(key, expiry=new_expiry)
    db.log("admin_extend", key, "+" + str(days) + " days")
    return jsonify({"ok": True, "key": key, "new_expiry": new_expiry, "days": days})


@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    password = request.args.get("password", "")
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    return jsonify({"ok": True, "stats": db.stats()})


@app.route("/api/admin/live", methods=["GET"])
def admin_live():
    password = request.args.get("password", "")
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    sessions = db.live_sessions()
    return jsonify({
        "ok": True,
        "online_now": len(sessions),
        "sessions": sessions
    })


@app.route("/api/admin/logs", methods=["GET"])
def admin_logs():
    password = request.args.get("password", "")
    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        return jsonify({"ok": False, "error": "Forbidden"}), 403
    limit = int(request.args.get("limit", 100))
    return jsonify({"ok": True, "logs": db.recent_logs(limit)})


@app.route("/api/admin/cleanup", methods=["POST"])
@admin_required
def admin_cleanup():
    n = db.cleanup_expired_sessions()
    return jsonify({"ok": True, "deleted_sessions": n})


# ==================== START ====================
if __name__ == "__main__":
    print("=" * 50)
    print("PAK License Server starting...")
    print("Port: " + str(PORT))
    print("Live users now: " + str(db.live_count()))
    print("=" * 50)
    app.run(host="0.0.0.0", port=PORT, debug=False)
