
# app.py
import os
import json
from services.browser_discovery_service import (
    discover_browser_pages,
    discover_authenticated_pages,
    start_authenticated_discovery_session,
    crawl_from_logged_in_page,
    _fill_otp_and_submit,
)
from services.page_discovery_service import discover_public_pages
from urllib.parse import unquote_plus
from urllib.parse import quote_plus
from urllib.parse import urlparse
import hashlib
import re
import uuid
import time
import secrets
from urllib.parse import unquote_plus, parse_qs
from datetime import datetime, timedelta
from auth_middleware import auth_required
from auth_middleware import auth_required, admin_required
from flask import Flask, request, jsonify , send_file
from flask_cors import CORS
from dotenv import load_dotenv
import secrets
load_dotenv()
from bson import ObjectId
from xai.xai.xai_report import (
     xai_bp,
    _predict,
    _severity,
    _detect_sqli_subtype,
    _detect_xss_subtype,
    _detect_lfi_subtype,
    _top_terms,
    _attack_specific_explanation,
    _attack_specific_impact_and_mitigation,
    _save_json,
    _save_pdf,
)

DISCOVERY_SESSIONS = {}
DISCOVERY_SESSION_TTL_SECONDS = 300  # 5 minutes

from db import users, admins, sites, attacks

PHONE_RE = re.compile(r"^\+?\d{7,15}$")
LOCATION_RE = re.compile(r"^[A-Za-z]+(?:[A-Za-z\s-]*[A-Za-z])?(?:,\s*[A-Za-z]+(?:[A-Za-z\s-]*[A-Za-z])?)$")

# ✅ reset link token service
from reset_token_service import (
    create_reset_token,
    verify_reset_token,
    RESET_TOKEN_TTL_MINUTES,
)
from flask_pymongo import PyMongo

app = Flask(__name__)

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "hwacs_db")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is missing in .env file")

app.config["MONGO_URI"] = MONGO_URI

mongo = PyMongo(app)

with app.app_context():
    mongo.db.site_pages.create_index(
        [("site_id", 1), ("path", 1)],
        unique=True
    )


CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
        }
    },
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization", "X-API-KEY"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)

# ✅ DB collections
from db import users, admins, admin_requests, sites, attacks
from pymongo import MongoClient

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

attacks_col = db["attacks"]
sites_col = db["sites"]
# ✅ Email helpers
from email_service import (
    send_owner_admin_request_email,
    send_admin_approved_activation_email,
    send_otp_email,
    send_reset_link_email, # ✅ NEW (reset link email)
    send_attack_alert_email 
)

# ✅ JWT
from jwt_service import generate_jwt, verify_jwt

from otp_service import (
    create_otp_session,
    verify_otp_code,
    resend_otp_code,
)



# app = Flask(__name__)
# CORS(app, supports_credentials=True)

# CORS(
#     app,
#     supports_credentials=True,
#     resources={r"/api/*": {"origins": ["http://localhost:5173"]}},
# )


# ✅ XAI blueprint
app.register_blueprint(xai_bp)

from xai.xai.bruteforce_api import bf_bp
app.register_blueprint(bf_bp)

# =========================================================
# ✅ Helpers
# =========================================================

BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLD = 5


def _cleanup_discovery_session(session_id: str):
    session = DISCOVERY_SESSIONS.pop(session_id, None)

    if not session:
        return

    try:
        session["browser"].close()
    except Exception:
        pass

    try:
        session["playwright"].stop()
    except Exception:
        pass


def _cleanup_expired_discovery_sessions():
    now = time.time()

    expired_ids = []

    for session_id, session in DISCOVERY_SESSIONS.items():
        created_at = session.get("created_at", now)

        if now - created_at > DISCOVERY_SESSION_TTL_SECONDS:
            expired_ids.append(session_id)

    for session_id in expired_ids:
        _cleanup_discovery_session(session_id)

def _extract_login_identifier(payload: str):
    """
    payload se username/email/login value nikalta hai.
    Works with form payload and JSON payload.
    """
    payload = payload or ""

    # JSON payload support
    try:
        obj = json.loads(payload)
        if isinstance(obj, dict):
            for key in ["email", "username", "user", "login", "uname"]:
                if obj.get(key):
                    return str(obj.get(key)).strip().lower()
    except Exception:
        pass

    # query/form payload support
    try:
        parsed = parse_qs(payload)
        for key in ["email", "username", "user", "login", "uname"]:
            value = parsed.get(key)
            if value and len(value) > 0:
                return str(value[0]).strip().lower()
    except Exception:
        pass

    return "unknown"


def _looks_like_login_attempt(url: str, method: str, payload: str):
    """
    Check karta hai ke request login/password type attempt lag rahi hai ya nahi.
    """
    url_l = (url or "").lower()
    method_l = (method or "").upper()
    payload_l = (payload or "").lower()

    if method_l not in ["POST", "PUT", "PATCH"]:
        return False

    login_url_keywords = [
        "login",
        "signin",
        "sign-in",
        "auth",
        "account",
        "admin",
        "wp-login",
    ]

    password_keywords = [
        "password",
        "pass",
        "pwd",
        "passwd",
    ]

    has_login_url = any(k in url_l for k in login_url_keywords)
    has_password_payload = any(k in payload_l for k in password_keywords)

    return has_login_url or has_password_payload


def _detect_brute_force(site, url: str, method: str, payload: str):
    """
    Same IP + same site + same username/email par repeated login attempts detect karta hai.
    """
    if not _looks_like_login_attempt(url, method, payload):
        return None

    now = datetime.utcnow()
    since = now - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    site_id = str(site.get("_id"))
    username = _extract_login_identifier(payload)

    attempt_doc = {
        "site_id": site_id,
        "user_id": str(site.get("user_id")),
        "honeypot": site.get("site_name", "Unknown"),
        "ip": ip,
        "username": username,
        "url": url,
        "method": method,
        "payload": payload,
        "created_at": now,
    }

    mongo.db.bruteforce_attempts.insert_one(attempt_doc)

    count = mongo.db.bruteforce_attempts.count_documents({
        "site_id": site_id,
        "ip": ip,
        "username": username,
        "created_at": {"$gte": since},
    })

    if count >= BRUTE_FORCE_THRESHOLD:
        return {
            "attempt_count": count,
            "threshold": BRUTE_FORCE_THRESHOLD,
            "window_minutes": BRUTE_FORCE_WINDOW_MINUTES,
            "ip": ip,
            "username": username,
            "decision_reason": "repeated_login_attempts_detected",
        }

    return None


def _now():
    return datetime.utcnow()

def _expires(minutes: int):
    return _now() + timedelta(minutes=minutes)

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _require_json():
    try:
        return request.get_json(force=True) or {}
    except Exception:
        return {}

def _is_gmail(email: str) -> bool:
    return (email or "").lower().endswith("@gmail.com")

def _clean_email(email: str) -> str:
    return (email or "").strip().lower()

def _make_phone_pk(phone: str) -> str:
    return (phone or "").strip()

def _public_owner_email() -> str:
    return (os.getenv("OWNER_EMAIL") or "").strip()

def _frontend_base() -> str:
    return (os.getenv("FRONTEND_BASE_URL") or "http://localhost:5173").strip()

def _backend_base() -> str:
    return (os.getenv("BACKEND_BASE_URL") or "http://127.0.0.1:5000").strip()

def _normalize_url(url: str) -> str:
    return (url or "").strip().rstrip("/")

def _log_admin_activity(email: str, action: str, status: str = "success", severity: str = "low"):
    try:
        mongo.db.admin_activity_logs.insert_one({
            "email": _clean_email(email),
            "action": action,
            "status": status,
            "severity": severity,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "user_agent": request.headers.get("User-Agent"),
        })
    except Exception as e:
        print("Admin activity log failed:", str(e))
        
def _log_user_activity(email: str, action: str, status: str = "success", severity: str = "low"):
    try:
        mongo.db.user_activity_logs.insert_one({
            "email": _clean_email(email),
            "action": action,
            "status": status,
            "severity": severity,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "user_agent": request.headers.get("User-Agent"),
        })
    except Exception as e:
        print("User activity log failed:", str(e))
        
        
def _normalize_path(path: str):
    path = (path or "/").strip()

    if not path.startswith("/"):
        path = "/" + path

    # remove trailing slash except root "/"
    if len(path) > 1:
        path = path.rstrip("/")

    return path


def _extract_path_from_url(url: str):
    try:
        parsed = urlparse(url or "")
        path = parsed.path or "/"
        return _normalize_path(path)
    except Exception:
        return "/"


def _save_or_update_site_page(site_id: str, user_id: str, path: str, full_url: str, source="collector_auto"):
    path = _normalize_path(path)
    if not path:
        return

    existing = mongo.db.site_pages.find_one({
        "site_id": site_id,
        "path": path
    })

    if existing:
        mongo.db.site_pages.update_one(
            {
                "site_id": site_id,
                "path": path
            },
            {
                "$set": {
                    "last_seen": _now(),
                    "full_url": full_url,
                },
                "$inc": {
                    "hit_count": 1
                }
            }
        )
        return

    mongo.db.site_pages.insert_one({
        "site_id": site_id,
        "user_id": user_id,
        "path": path,
        "full_url": full_url,
        "page_trap_enabled": True,
        "source": source,
        "hit_count": 1,
        "discovery_count": 0,
        "created_at": _now(),
        "last_seen": _now(),
    })





def _is_page_trap_enabled(site_id: str, path: str):
    path = _normalize_path(path)

    page = mongo.db.site_pages.find_one({
        "site_id": site_id,
        "path": path
    })

    if not page:
        print("PAGE TRAP CHECK: page not found, allowing:", site_id, path)
        return True

    enabled = page.get("page_trap_enabled", True) is not False

    print("PAGE TRAP CHECK:", {
        "site_id": site_id,
        "path": path,
        "page_trap_enabled": page.get("page_trap_enabled", True),
        "allowed": enabled
    })

    return enabled
        
def _save_discovered_pages(site_id: str, user_id: str, pages: list):
    saved_count = 0

    for page in pages:
        path = (page.get("path") or "").strip()
        full_url = (page.get("full_url") or "").strip()
        source = page.get("source") or "public_crawler"

        if not path:
            continue

        existing = mongo.db.site_pages.find_one({
            "site_id": site_id,
            "path": path
        })

        if existing:
            mongo.db.site_pages.update_one(
                {
                    "site_id": site_id,
                    "path": path
                },
                {
                    "$set": {
                        "last_seen": _now(),
                        "full_url": full_url,
                    },
                    "$inc": {
                        "discovery_count": 1
                    }
                }
            )
            continue

        mongo.db.site_pages.insert_one({
            "site_id": site_id,
            "user_id": user_id,
            "path": path,
            "full_url": full_url,
            "page_trap_enabled": True,
            "source": source,
            "hit_count": 0,
            "discovery_count": 1,
            "created_at": _now(),
            "last_seen": _now(),
        })

        saved_count += 1

    return saved_count


def _validate_strong_password(password: str):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]~`]", password):
        return False, "Password must contain at least one special character."

    return True, ""

# def _get_request_actor():
#     auth_header = request.headers.get("Authorization", "")
#     if not auth_header.startswith("Bearer "):
#         return None, None, jsonify({"error": "Missing token"}), 401

#     token = auth_header.split(" ", 1)[1].strip()

#     try:
#         payload = verify_jwt(token)
#         actor_id = payload.get("user_id") or payload.get("sub")

#         if not actor_id or not ObjectId.is_valid(actor_id):
#             return None, None, jsonify({"error": "Invalid token subject"}), 401

#         oid = ObjectId(actor_id)

#         # normal user
#         actor = users.find_one({"_id": oid})
#         if actor:
#             return actor, False, None, None

#         # admin user
#         actor = admins.find_one({"_id": oid})
#         if actor:
#             return actor, True, None, None

#         return None, None, jsonify({"error": "Account not found"}), 401

#     except Exception:
#         return None, None, jsonify({"error": "Invalid or expired token"}), 401
def _get_request_actor():
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None, None, jsonify({"error": "Missing token"}), 401

    token = auth_header.split(" ", 1)[1].strip()

    try:
        payload = verify_jwt(token)

        actor_id = (
            payload.get("user_id")
            or payload.get("admin_id")
            or payload.get("sub")
            or payload.get("id")
        )
        actor_email = payload.get("email")

        # 1) Try users/admins by ObjectId
        if actor_id and ObjectId.is_valid(str(actor_id)):
            oid = ObjectId(str(actor_id))

            actor = users.find_one({"_id": oid})
            if actor:
                return actor, False, None, None

            actor = admins.find_one({"_id": oid})
            if actor:
                return actor, True, None, None

        # 2) Fallback: Try users/admins by email
        if actor_email:
            actor = users.find_one({"email": actor_email})
            if actor:
                return actor, False, None, None

            actor = admins.find_one({"email": actor_email})
            if actor:
                return actor, True, None, None

        return None, None, jsonify({"error": "Account not found"}), 401

    except Exception:
        return None, None, jsonify({"error": "Invalid or expired token"}), 401

# =========================================================
# ✅ Auth helpers (JWT verify properly)
# =========================================================
def _get_bearer_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth.replace("Bearer ", "").strip()

def _require_user():
    """
    Returns: (user_doc, error_response_or_None)
    """
    token = _get_bearer_token()
    if not token:
        return None, (jsonify({"error": "Missing Authorization Bearer token"}), 401)

    payload = verify_jwt(token)  # ✅ must verify signature
    if not payload:
        return None, (jsonify({"error": "Invalid or expired token"}), 401)

    if payload.get("role") != "user":
        return None, (jsonify({"error": "User token required"}), 403)

    email = _clean_email(payload.get("email"))
    if not email:
        return None, (jsonify({"error": "Invalid token payload"}), 401)

    user = users.find_one({"email": email})
    if not user:
        return None, (jsonify({"error": "User not found"}), 404)

    return user, None

def _require_admin():
    """
    Returns: (admin_doc, error_response_or_None)
    """
    token = _get_bearer_token()
    if not token:
        return None, (jsonify({"error": "Missing Authorization Bearer token"}), 401)

    payload = verify_jwt(token)
    if not payload:
        return None, (jsonify({"error": "Invalid or expired token"}), 401)

    if payload.get("role") != "admin":
        return None, (jsonify({"error": "Admin token required"}), 403)

    email = _clean_email(payload.get("email"))
    if not email:
        return None, (jsonify({"error": "Invalid token payload"}), 401)

    admin = admins.find_one({"email": email})
    if not admin:
        return None, (jsonify({"error": "Admin not found"}), 404)

    return admin, None


# =========================================================
# ✅ USER AUTH (Register/Login) — OTP Flow
# =========================================================

@app.post("/api/auth/register", endpoint="user_register")
def user_register():
    data = _require_json()
    firstName = (data.get("firstName") or "").strip()
    lastName = (data.get("lastName") or "").strip()
    username = (data.get("username") or "").strip()
    email = _clean_email(data.get("email"))
    password = (data.get("password") or "").strip()

    if not firstName or not lastName or not username or not email or not password:
        return jsonify({"error": "Please fill all fields."}), 400

    if not _is_gmail(email):
        return jsonify({"error": "Only @gmail.com email is allowed."}), 400

    if len(username) < 6:
        return jsonify({"error": "Username must be at least 6 characters."}), 400

    if users.find_one({"email": email}):
        return jsonify({"error": "User already exists. Please login."}), 400

    users.insert_one({
        "firstName": firstName,
        "lastName": lastName,
        "name": f"{firstName} {lastName}".strip(),
        "username": username,
        "email": email,
        "password": password,  # TODO: hash password
        "role": "user",
        "is_verified": False,
        "created_at": _now(),
    })

    otp_code = create_otp_session(email=email, purpose="user_signup")
    send_otp_email(email, otp_code)

    return jsonify({
        "message": "User registered. OTP sent to email.",
        "requires_otp": True,
        "email": email,
        "role": "user"
    }), 200


# ✅ ALWAYS OTP on every login
# @app.post("/api/auth/login", endpoint="user_login")
# def user_login():
#     data = _require_json()
#     email = _clean_email(data.get("email"))
#     password = (data.get("password") or "").strip()

#     if not email or not password:
#         return jsonify({"error": "Email and password are required."}), 400

#     if not _is_gmail(email):
#         return jsonify({"error": "Only @gmail.com email is allowed."}), 400

#     user = users.find_one({"email": email})
#     if not user:
#         return jsonify({"error": "Invalid email or password."}), 401

#     # ✅ Check account status before password/OTP
#     account_status = user.get("account_status", "active")

#     if account_status == "blocked":
#         return jsonify({
#             "error": "Your account has been blocked by admin. Please contact support."
#         }), 403

#     if account_status == "suspended":
#         suspended_until = user.get("suspended_until")

#         if suspended_until and suspended_until > _now():
#             return jsonify({
#                 "error": "Your account is temporarily suspended. Please try again later."
#             }), 403

#         # ✅ If suspension time is completed, activate user automatically
#         users.update_one(
#             {"_id": user["_id"]},
#             {
#                 "$set": {
#                     "account_status": "active"
#                 },
#                 "$unset": {
#                     "suspended_until": "",
#                     "suspended_at": "",
#                     "suspended_by": ""
#                 }
#             }
#         )

#     if user.get("password") != password:
#         return jsonify({"error": "Invalid email or password."}), 401

#     otp_code = create_otp_session(email=email, purpose="user_login")
#     send_otp_email(email, otp_code)

#     return jsonify({
#         "message": "OTP sent to email.",
#         "requires_otp": True,
#         "email": email,
#         "role": "user",
#         "name": user.get("name", "")
#     }), 200

@app.post("/api/auth/login", endpoint="user_login")
def user_login():
    data = _require_json()
    email = _clean_email(data.get("email"))
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    if not _is_gmail(email):
        return jsonify({"error": "Only @gmail.com email is allowed."}), 400

    user = users.find_one({"email": email})

    if not user:
        # Optional: this will save failed attempt for unknown email too
        _log_user_activity(
            email,
            "Failed login attempt - email not found",
            "error",
            "medium"
        )
        return jsonify({"error": "Invalid email or password."}), 401

    # ✅ Check account status before password/OTP
    account_status = user.get("account_status", "active")

    if account_status == "blocked":
        _log_user_activity(
            user["email"],
            "Login blocked - account blocked by admin",
            "error",
            "high"
        )
        return jsonify({
            "error": "Your account has been blocked by admin. Please contact support."
        }), 403

    if account_status == "suspended":
        suspended_until = user.get("suspended_until")

        if suspended_until and suspended_until > _now():
            _log_user_activity(
                user["email"],
                "Login blocked - account temporarily suspended",
                "error",
                "medium"
            )
            return jsonify({
                "error": "Your account is temporarily suspended. Please try again later."
            }), 403

        # ✅ If suspension time is completed, activate user automatically
        users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "account_status": "active"
                },
                "$unset": {
                    "suspended_until": "",
                    "suspended_at": "",
                    "suspended_by": ""
                }
            }
        )

    if user.get("password") != password:
        # ✅ THIS IS THE MAIN FIX
        _log_user_activity(
            user["email"],
            "Failed login attempt - wrong password",
            "error",
            "medium"
        )
        return jsonify({"error": "Invalid email or password."}), 401

    otp_code = create_otp_session(email=email, purpose="user_login")
    send_otp_email(email, otp_code)

    _log_user_activity(
        user["email"],
        "OTP sent for login",
        "success",
        "low"
    )

    return jsonify({
        "message": "OTP sent to email.",
        "requires_otp": True,
        "email": email,
        "role": "user",
        "name": user.get("name", "")
    }), 200


# =========================================================
# ✅ ADMIN AUTH (Login) — only after approved+activated
# =========================================================

@app.post("/api/auth/admin/login", endpoint="admin_login")
def admin_login():
    data = _require_json()
    email = _clean_email(data.get("email"))
    password = (data.get("password") or "").strip()

    if not email or not password:
        if email:
            _log_admin_activity(
                email,
                "Failed admin login attempt - missing email or password",
                "error",
                "medium"
            )
        return jsonify({"error": "Email and password are required."}), 400

    admin = admins.find_one({"email": email})

    if not admin:
        _log_admin_activity(
            email,
            "Failed admin login attempt - admin not found or not approved",
            "error",
            "high"
        )
        return jsonify({"error": "Admin not found or not approved."}), 401

    if not admin.get("is_active"):
        _log_admin_activity(
            email,
            "Failed admin login attempt - admin account inactive",
            "error",
            "high"
        )
        return jsonify({
            "error": "Admin not active yet. Complete activation (OTP) first."
        }), 403

    if admin.get("password") != password:
        _log_admin_activity(
            email,
            "Failed admin login attempt - incorrect password",
            "error",
            "high"
        )
        return jsonify({"error": "Invalid email or password."}), 401

    otp_code = create_otp_session(email=email, purpose="admin_login")
    send_otp_email(email, otp_code)

    _log_admin_activity(
        email,
        "Admin login password verified - OTP sent",
        "success",
        "medium"
    )

    return jsonify({
        "message": "OTP sent to admin email.",
        "requires_otp": True,
        "email": email,
        "role": "admin",
        "name": admin.get("name", "")
    }), 200

@app.route("/api/auth/admin/request-signup", methods=["POST", "OPTIONS"])
def admin_request_signup():

    # ✅ Handle CORS preflight
    if request.method == "OPTIONS":
        return ("", 204)

    data = _require_json()

    firstName = (data.get("firstName") or "").strip()
    lastName  = (data.get("lastName") or "").strip()
    email     = _clean_email(data.get("email"))
    phone     = (data.get("phone") or "").strip()
    password  = (data.get("password") or "").strip()

    if not firstName or not lastName or not email or not phone or not password:
        return jsonify({"error": "Please fill all fields."}), 400

    # Optional validation
    if not _is_gmail(email):
        return jsonify({"error": "Only @gmail.com email is allowed."}), 400

    if phone and not PHONE_RE.match(phone):
        return jsonify({"error": "Invalid phone number."}), 400

    # Already admin?
    if admins.find_one({"email": email}):
        return jsonify({"error": "Admin already exists."}), 400

    # Already requested?
    if admin_requests.find_one({
        "email": email,
        "status": {"$in": ["pending", "approved"]}
    }):
        return jsonify({"error": "Admin request already submitted."}), 400

    # =====================================================
    # ✅ SAVE REQUEST IN DB
    # =====================================================
    admin_requests.insert_one({
        "firstName": firstName,
        "lastName": lastName,
        "name": f"{firstName} {lastName}".strip(),
        "email": email,
        "phone": phone,
        "password": password,   # TODO: hash later
        "status": "pending",
        "created_at": _now(),
    })

    # =====================================================
    # ✅ SEND EMAIL TO OWNER
    # =====================================================
    owner_email = _public_owner_email()

    if not owner_email:
        print("❌ OWNER_EMAIL not configured")
        return jsonify({
            "message": "Request saved but OWNER_EMAIL not configured.",
            "saved": True
        }), 201

    admin_name = f"{firstName} {lastName}".strip()
    admin_email = email   # ✅ IMPORTANT (matches email_service signature)

    secret = (os.getenv("OWNER_APPROVAL_SECRET") or "").strip()
    encoded_email = quote_plus(email)

    approve_link = f"{_backend_base()}/api/auth/admin/approve?email={encoded_email}&secret={secret}"
    reject_link  = f"{_backend_base()}/api/auth/admin/reject?email={encoded_email}&secret={secret}"

    try:
        send_owner_admin_request_email(
            owner_email,
            admin_email,
            admin_name,
            approve_link,
            reject_link
        )

        print("✅ Owner email sent successfully")

    except Exception as e:
        print("❌ Email failed:", str(e))
        return jsonify({
            "message": "Admin request submitted, but email failed.",
            "saved": True,
            "email_error": str(e)
        }), 201

    return jsonify({
        "message": "Admin request submitted successfully.",
        "saved": True
    }), 201

@app.get("/api/auth/admin/approve")
def approve_admin_request():

    email = _clean_email(request.args.get("email"))
    secret = (request.args.get("secret") or "").strip()
    expected = (os.getenv("OWNER_APPROVAL_SECRET") or "").strip()

    if not secret or secret != expected:
        return jsonify({"error": "Invalid secret"}), 403

    req = admin_requests.find_one({"email": email})
    if not req:
        return jsonify({"error": "Request not found"}), 404

    if not admins.find_one({"email": email}):
        admins.insert_one({
            "name": req.get("name"),
            "email": email,
            "phone": req.get("phone"),
            "password": req.get("password"),
            "is_active": False,
            "created_at": _now(),
        })

    # 🔥 Generate activation token
    activation_token = secrets.token_urlsafe(32)

    admins.update_one(
        {"email": email},
        {"$set": {
            "activation_token": activation_token,
            "activation_expires": _expires(30),
            "is_active": False
        }}
    )

    admin_requests.update_one(
        {"email": email},
        {"$set": {"status": "approved", "approved_at": _now()}}
    )

    activation_link = f"{_frontend_base()}/#/admin-activate?token={activation_token}"

    send_admin_approved_activation_email(email, activation_link)

    return jsonify({"message": "Admin approved & activation email sent"}), 200


@app.get("/api/auth/admin/reject")
def reject_admin_request():
    email = _clean_email(request.args.get("email"))
    secret = request.args.get("secret")

    if secret != (os.getenv("OWNER_APPROVAL_SECRET") or "").strip():
        return jsonify({"error": "Invalid secret"}), 403

    req = admin_requests.find_one({"email": email})
    if not req:
        return jsonify({"error": "Request not found"}), 404

    admin_requests.update_one(
        {"email": email},
        {"$set": {"status": "rejected", "rejected_at": _now()}}
    )

    return jsonify({"message": "Admin rejected successfully"}), 200

@app.post("/api/auth/admin/activate")
def activate_admin():

    data = _require_json()
    token = (data.get("token") or "").strip()

    if not token:
        return jsonify({"error": "Missing activation token"}), 400

    admin = admins.find_one({"activation_token": token})
    if not admin:
        return jsonify({"error": "Invalid activation link"}), 400

    if admin.get("activation_expires") < _now():
        return jsonify({"error": "Activation link expired"}), 400

    admins.update_one(
        {"_id": admin["_id"]},
        {"$set": {
            "is_active": True
        },
         "$unset": {
            "activation_token": "",
            "activation_expires": ""
         }}
    )

    return jsonify({"message": "Account activated successfully"}), 200

# =========================================================
# ✅ OTP VERIFY + RESEND (works for user+admin)
# =========================================================


    

@app.route("/api/admin/profile/password/verify-otp", methods=["POST", "OPTIONS"])
def admin_verify_password_change_otp():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    data = _require_json()
    otp = (data.get("otp") or "").strip()
    current_password = (data.get("currentPassword") or "").strip()
    new_password = (data.get("newPassword") or "").strip()

    if not otp or not current_password or not new_password:
        return jsonify({"error": "OTP, current password, and new password are required."}), 400

    is_valid_password, password_error = _validate_strong_password(new_password)
    if not is_valid_password:
     return jsonify({"error": password_error}), 400

    email = _clean_email(actor.get("email"))
    if not email:
        return jsonify({"error": "Admin email not found in token."}), 401

    ok, reason = verify_otp_code(email=email, otp=otp)
    if not ok:
        return jsonify({"error": reason or "Invalid or expired OTP."}), 400

    admin = admins.find_one({"email": email})
    if not admin:
        return jsonify({"error": "Admin not found."}), 404

    if admin.get("password") != current_password:
        return jsonify({"error": "Current password is incorrect."}), 401

    admins.update_one(
        {"email": email},
        {
            "$set": {
                "password": new_password,
                "updated_at": _now()
            }
        }
    )

    return jsonify({
        "message": "Password updated successfully."
    }), 200

@app.post("/api/auth/verify-otp", endpoint="verify_otp")
def verify_otp():
    data = _require_json()
    email = _clean_email(data.get("email"))
    otp = (data.get("otp") or "").strip()
    otpFlow = (data.get("otpFlow") or "").strip()

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required."}), 400

    # ✅ verify OTP only once
    ok, reason = verify_otp_code(email=email, otp=otp)

    if not ok:
        if otpFlow == "admin_login":
            _log_admin_activity(
                email,
                "Failed admin login attempt - invalid or expired OTP",
                "error",
                "high"
            )

        return jsonify({
            "error": reason or "Invalid or expired OTP."
        }), 400

    # =====================================================
    # ✅ ADMIN FLOWS
    # =====================================================
    if otpFlow in ["admin_activation", "admin_login"]:
        admin = admins.find_one({"email": email})

        if not admin:
            if otpFlow == "admin_login":
                _log_admin_activity(
                    email,
                    "Failed admin login attempt - admin not found after OTP",
                    "error",
                    "high"
                )

            return jsonify({"error": "Admin not found."}), 404

        # ✅ Admin activation flow
        if otpFlow == "admin_activation":
            admins.update_one(
                {"email": email},
                {
                    "$set": {
                        "is_active": True,
                        "activated_at": _now()
                    }
                }
            )

            admin_requests.update_one(
                {"email": email},
                {
                    "$set": {
                        "status": "active",
                        "activated_at": _now()
                    }
                }
            )

            _log_admin_activity(
                email,
                "Admin account activated successfully",
                "success",
                "medium"
            )

        # ✅ Admin login flow
        if otpFlow == "admin_login":
            if not admin.get("is_active"):
                _log_admin_activity(
                    email,
                    "Failed admin login attempt - admin account inactive after OTP",
                    "error",
                    "high"
                )

                return jsonify({"error": "Admin not active yet."}), 403

            _log_admin_activity(
                email,
                "Logged in to admin dashboard",
                "success",
                "low"
            )

        token = generate_jwt({
    "user_id": str(admin["_id"]),
    "id": str(admin["_id"]),
    "email": admin["email"],
    "role": "admin"
})

        return jsonify({
            "token": token,
            "email": email,
            "name": admin.get("name", ""),
            "role": "admin"
        }), 200

    # =====================================================
    # ✅ USER FLOWS
    # =====================================================
    user = users.find_one({"email": email})

    if not user:
        return jsonify({"error": "User not found."}), 404

    users.update_one(
        {"email": email},
        {
            "$set": {
                "is_verified": True
            }
        }
    )
    _log_user_activity(
    email,
    "Logged in to dashboard",
    "success",
    "low"
)    


    token = generate_jwt({
            "user_id": str(user["_id"]),
    "id": str(user["_id"]),
    "email": user["email"],
    "role": user.get("role", "user")
    })


    return jsonify({
        "token": token,
        "email": email,
        "name": user.get("name", ""),
        "role": "user"
    }), 200

# @app.route("/api/admin/users/<user_id>/block", methods=["PATCH", "OPTIONS"])
# def admin_block_user(user_id):
#     if request.method == "OPTIONS":
#         return ("", 204)

#     actor, is_admin, err, status = _get_request_actor()
#     if err:
#         return err, status

#     if not is_admin:
#         return jsonify({"error": "Admin access required"}), 403

#     if not ObjectId.is_valid(user_id):
#         return jsonify({"error": "Invalid user id"}), 400

#     user = users.find_one({"_id": ObjectId(user_id)})
#     if not user:
#         return jsonify({"error": "User not found"}), 404

#     users.update_one(
#         {"_id": ObjectId(user_id)},
#         {
#             "$set": {
#                 "account_status": "blocked",
#                 "blocked_at": _now(),
#                 "blocked_by": actor.get("email", "")
#             },
#             "$unset": {
#                 "suspended_until": ""
#             }
#         }
#     )

#     return jsonify({
#         "message": "User blocked successfully.",
#         "user_id": user_id
#     }), 200

@app.route("/api/admin/users/<user_id>/unblock", methods=["PATCH", "OPTIONS"])
def admin_unblock_user(user_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"error": "Invalid user id"}), 400

    user = users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "account_status": "active",
                "unblocked_at": _now(),
                "unblocked_by": actor.get("email", "")
            },
            "$unset": {
                "suspended_until": "",
                "blocked_at": "",
                "blocked_by": "",
                "suspended_at": "",
                "suspended_by": ""
            }
        }
    )

    return jsonify({
        "message": "User unblocked successfully.",
        "user_id": user_id
    }), 200

@app.post("/api/auth/resend-otp", endpoint="resend_otp")
def resend_otp():
    data = _require_json()
    email = _clean_email(data.get("email"))
    purpose = (data.get("purpose") or "").strip()

    if not email:
        return jsonify({"error": "Email is required."}), 400

    otp_code = resend_otp_code(email=email, purpose=purpose)
    if not otp_code:
        return jsonify({"error": "Cannot resend OTP right now. Try later."}), 400

    send_otp_email(email, otp_code)
    return jsonify({"message": "OTP resent successfully."}), 200


# =========================================================
# ✅ FORGOT / RESET PASSWORD (User/Admin) — RESET LINK FLOW ✅
# =========================================================

@app.post("/api/auth/forgot-password", endpoint="forgot_password")
def forgot_password():
    data = _require_json()
    email = _clean_email(data.get("email"))

    if not email:
        return jsonify({"error": "Email is required."}), 400

    # ✅ Do NOT reveal if account exists
    generic_msg = {"message": "If an account exists, a reset link has been sent to your email."}

    exists = users.find_one({"email": email}) or admins.find_one({"email": email})
    if not exists:
        return jsonify(generic_msg), 200

    token = create_reset_token(email)
    reset_link = f"{_frontend_base()}/#/reset-password?token={token}"

    send_reset_link_email(email, reset_link, RESET_TOKEN_TTL_MINUTES)

    return jsonify(generic_msg), 200



@app.post("/api/auth/reset-password", endpoint="reset_password")
def reset_password():
    data = _require_json()
    token = (data.get("token") or "").strip()
    new_password = (data.get("newPassword") or "").strip()

    if not token or not new_password:
        return jsonify({"error": "Reset link and new password are required."}), 400

    ok, reason, payload = verify_reset_token(token)
    if not ok:
        return jsonify({"error": reason or "Invalid or expired reset link."}), 400

    email = _clean_email(payload.get("sub"))
    if not email:
        return jsonify({"error": "Invalid reset token payload."}), 400

    updated = False

    if users.find_one({"email": email}):
        users.update_one(
            {"email": email},
            {"$set": {"password": new_password, "updated_at": _now()}},
        )
        updated = True

    if admins.find_one({"email": email}):
        admins.update_one(
            {"email": email},
            {"$set": {"password": new_password, "updated_at": _now()}},
        )
        updated = True

    if not updated:
        return jsonify({"error": "Account not found."}), 400

    return jsonify({"message": "Password reset successfully. Please login."}), 200

@app.route("/api/admin/profile/password/request-otp", methods=["POST", "OPTIONS"])
def admin_request_password_change_otp():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    data = _require_json()
    current_password = (data.get("currentPassword") or "").strip()
    new_password = (data.get("newPassword") or "").strip()

    if not current_password or not new_password:
        return jsonify({"error": "Current password and new password are required."}), 400

    is_valid_password, password_error = _validate_strong_password(new_password)
    if not is_valid_password:
        return jsonify({"error": password_error}), 400

    email = _clean_email(actor.get("email"))
    if not email:
        return jsonify({"error": "Admin email not found in token."}), 401

    admin = admins.find_one({"email": email})
    if not admin:
        return jsonify({"error": "Admin not found."}), 404

    if admin.get("password") != current_password:
        return jsonify({"error": "Current password is incorrect."}), 401

    otp_code = create_otp_session(email=email, purpose="admin_password_change")
    send_otp_email(email, otp_code)

    return jsonify({
        "message": "OTP sent to your admin email."
    }), 200

# =========================================================
# ✅ USER: Register External Honeypot Site (Step-1)
# =========================================================



@app.post("/api/sites/register")
def register_site():
    user, err = _require_user()
    if err:
        return err

    data = _require_json()
    site_name = (data.get("site_name") or "").strip()
    base_url = _normalize_url(data.get("base_url") or "")

    if not site_name or not base_url:
        return jsonify({"error": "site_name and base_url are required"}), 400

    existing_active_site = sites.find_one({
        "base_url": base_url,
        "is_active": True
    })

    if existing_active_site:
        existing_owner = existing_active_site.get("user_email") or "another user"
        return jsonify({
            "error": f"This website is already registered as an active honeypot by {existing_owner}"
        }), 409

    site_token = secrets.token_urlsafe(32)
    site_token_hash = _hash_token(site_token)

    doc = {
        "user_id": str(user.get("_id")),
        "user_email": user.get("email"),
        "site_name": site_name,
        "base_url": base_url,
        "site_token_hash": site_token_hash,
        "is_active": True,
        "trap_enabled": True,
        "monitor_mode": "all_pages",
        "monitored_pages": [],
        "created_at": _now(),
        "last_activity": None,
        "attacks_today": 0,
    }

    inserted = sites.insert_one(doc)
    try:
            discovered_pages = discover_public_pages(base_url)
            saved_pages_count = _save_discovered_pages(
                site_id=str(inserted.inserted_id),
                user_id=str(user.get("_id")),
                pages=discovered_pages
            )
    except Exception as e:
            print("Public page discovery failed:", str(e))
            saved_pages_count = 0

    return jsonify({
            "message": "Site registered successfully",
            "site_token": site_token,
            "site_name": site_name,
            "base_url": base_url,
            "public_pages_discovered": saved_pages_count,
            "discovered_pages_count": saved_pages_count,
        }), 201


@app.route("/api/sites/my", methods=["GET", "OPTIONS"], endpoint="my_sites_unique")
def my_sites():
    # ✅ CORS preflight
    if request.method == "OPTIONS":
        return ("", 204)

    user, err = _require_user()
    if err:
        return err

    cursor = sites.find({"user_id": str(user.get("_id"))}).sort("created_at", -1)

    result = []
    for s in cursor:
        result.append({
            "_id": str(s.get("_id")),                      # ✅ keep _id for frontend key
            "name": s.get("site_name") or s.get("name"),   # ✅ unify name
            "websiteUrl": s.get("base_url") or s.get("websiteUrl"),
            "status": "active" if s.get("is_active", True) else "inactive",
            "created_at": s.get("created_at"),
            "verificationMethod": s.get("verificationMethod", "api_key"),
            "apiKey": s.get("apiKey") or s.get("api_key"),
            "last_activity": s.get("last_activity"),
            "attacks_today": s.get("attacks_today", 0),
        })

    return jsonify({"sites": result}), 200


@app.route("/api/sites/<site_id>/pages/<page_id>/trap", methods=["PATCH", "OPTIONS"])
def toggle_site_page_trap(site_id, page_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not ObjectId.is_valid(site_id) or not ObjectId.is_valid(page_id):
        return jsonify({"error": "Invalid site/page id"}), 400

    site = sites.find_one({"_id": ObjectId(site_id)})
    if not site:
        return jsonify({"error": "Site not found"}), 404

    if not is_admin and site.get("user_id") != str(actor.get("_id")):
        return jsonify({"error": "Forbidden"}), 403

    body = _require_json()
    enabled = body.get("page_trap_enabled")

    if not isinstance(enabled, bool):
        return jsonify({"error": "page_trap_enabled must be true or false"}), 400

    page = mongo.db.site_pages.find_one({
        "_id": ObjectId(page_id),
        "site_id": site_id
    })

    if not page:
        return jsonify({"error": "Page not found"}), 404

    mongo.db.site_pages.update_one(
        {"_id": ObjectId(page_id)},
        {
            "$set": {
                "page_trap_enabled": enabled,
                "updated_at": _now()
            }
        }
    )

    return jsonify({
        "message": f"Page trap {'enabled' if enabled else 'disabled'} successfully",
        "site_id": site_id,
        "page_id": page_id,
        "page_trap_enabled": enabled
    }), 200
    
    
@app.route("/api/sites/<site_id>/discover-auth-start", methods=["POST", "OPTIONS"])
def discover_auth_start(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    _cleanup_expired_discovery_sessions()

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not ObjectId.is_valid(site_id):
        return jsonify({"error": "Invalid site id"}), 400

    site = sites.find_one({"_id": ObjectId(site_id)})
    if not site:
        return jsonify({"error": "Site not found"}), 404

    if not is_admin and site.get("user_id") != str(actor.get("_id")):
        return jsonify({"error": "Forbidden"}), 403

    data = _require_json()

    login_url = (data.get("login_url") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not login_url or not username or not password:
        return jsonify({
            "error": "Login URL, username, and password are required."
        }), 400

    base_url = (
        site.get("base_url")
        or site.get("websiteUrl")
        or site.get("website_url")
        or ""
    )

    if not base_url:
        return jsonify({"error": "Site base URL not found"}), 400

    try:
        session = start_authenticated_discovery_session(
            base_url=base_url,
            login_url=login_url,
            username=username,
            password=password,
        )

        if session.get("requires_otp"):
            session_id = str(uuid.uuid4())

            DISCOVERY_SESSIONS[session_id] = {
                **session,
                "site_id": site_id,
                "user_id": str(site.get("user_id", "")),
                "created_at": time.time(),
            }

            return jsonify({
                "message": "OTP required. Please enter OTP to continue discovery.",
                "requires_otp": True,
                "session_id": session_id,
                "current_url": session.get("current_url"),
            }), 200

        discovered_pages = crawl_from_logged_in_page(
            page=session["page"],
            base_url=base_url,
            max_pages=80,
            max_depth=2,
        )

        saved_count = _save_discovered_pages(
            site_id=site_id,
            user_id=str(site.get("user_id", "")),
            pages=discovered_pages,
        )

        try:
            session["browser"].close()
        except Exception:
            pass

        try:
            session["playwright"].stop()
        except Exception:
            pass

        return jsonify({
            "message": "Authenticated discovery completed successfully.",
            "requires_otp": False,
            "discovered_count": len(discovered_pages),
            "saved_count": saved_count,
            "pages": discovered_pages,
        }), 200

    except Exception as e:
        print("Auth start discovery failed:", str(e))
        return jsonify({
            "error": "Authenticated discovery failed.",
            "details": str(e),
        }), 500
        
@app.route("/api/sites/<site_id>/discover-auth-otp", methods=["POST", "OPTIONS"])
def discover_auth_otp(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    _cleanup_expired_discovery_sessions()

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    data = _require_json()

    session_id = (data.get("session_id") or "").strip()
    otp = (data.get("otp") or "").strip()

    if not session_id or not otp:
        return jsonify({"error": "Session ID and OTP are required."}), 400

    session = DISCOVERY_SESSIONS.get(session_id)

    if not session:
        return jsonify({
            "error": "Discovery session expired or not found. Please start again."
        }), 400

    if session.get("site_id") != site_id:
        return jsonify({"error": "Invalid discovery session for this site."}), 400

    site = sites.find_one({"_id": ObjectId(site_id)})

    if not site:
        _cleanup_discovery_session(session_id)
        return jsonify({"error": "Site not found"}), 404

    if not is_admin and site.get("user_id") != str(actor.get("_id")):
        _cleanup_discovery_session(session_id)
        return jsonify({"error": "Forbidden"}), 403

    base_url = (
        site.get("base_url")
        or site.get("websiteUrl")
        or site.get("website_url")
        or session.get("base_url")
        or ""
    )

    try:
        page = session["page"]

        _fill_otp_and_submit(page, otp)

        discovered_pages = crawl_from_logged_in_page(
            page=page,
            base_url=base_url,
            max_pages=80,
            max_depth=2,
        )

        saved_count = _save_discovered_pages(
            site_id=site_id,
            user_id=str(site.get("user_id", "")),
            pages=discovered_pages,
        )

        _cleanup_discovery_session(session_id)

        return jsonify({
            "message": "OTP verified. Authenticated discovery completed successfully.",
            "requires_otp": False,
            "discovered_count": len(discovered_pages),
            "saved_count": saved_count,
            "pages": discovered_pages,
        }), 200

    except Exception as e:
        print("OTP discovery failed:", str(e))
        _cleanup_discovery_session(session_id)

        return jsonify({
            "error": "OTP verification or discovery failed.",
            "details": str(e),
        }), 500


@app.route("/api/sites/<site_id>/discover-browser-pages", methods=["POST", "OPTIONS"])
def discover_site_browser_pages(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not ObjectId.is_valid(site_id):
        return jsonify({"error": "Invalid site id"}), 400

    site = sites.find_one({"_id": ObjectId(site_id)})
    if not site:
        return jsonify({"error": "Site not found"}), 404

    if not is_admin:
        if site.get("user_id") != str(actor.get("_id")):
            return jsonify({"error": "Forbidden"}), 403

    base_url = (
        site.get("base_url")
        or site.get("websiteUrl")
        or site.get("website_url")
        or ""
    )

    if not base_url:
        return jsonify({"error": "Site base URL not found"}), 400

    try:
        discovered_pages = discover_browser_pages(
            base_url=base_url,
            max_pages=60,
            max_depth=2
        )

        saved_count = _save_discovered_pages(
            site_id=str(site.get("_id")),
            user_id=str(site.get("user_id", "")),
            pages=discovered_pages
        )

        return jsonify({
            "message": "Browser discovery completed successfully.",
            "site_id": site_id,
            "discovered_count": len(discovered_pages),
            "saved_count": saved_count,
            "pages": discovered_pages
        }), 200

    except Exception as e:
        print("Browser discovery failed:", str(e))
        return jsonify({
            "error": "Browser discovery failed.",
            "details": str(e)
        }), 500
        
        
@app.route("/api/sites/<site_id>/discover-auth-pages", methods=["POST", "OPTIONS"])
def discover_site_authenticated_pages(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not ObjectId.is_valid(site_id):
        return jsonify({"error": "Invalid site id"}), 400

    site = sites.find_one({"_id": ObjectId(site_id)})
    if not site:
        return jsonify({"error": "Site not found"}), 404

    if not is_admin:
        if site.get("user_id") != str(actor.get("_id")):
            return jsonify({"error": "Forbidden"}), 403

    data = _require_json()

    login_url = (data.get("login_url") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    if not login_url or not username or not password:
        return jsonify({
            "error": "Login URL, username, and password are required."
        }), 400

    base_url = (
        site.get("base_url")
        or site.get("websiteUrl")
        or site.get("website_url")
        or ""
    )

    if not base_url:
        return jsonify({"error": "Site base URL not found"}), 400

    try:
        discovered_pages = discover_authenticated_pages(
            base_url=base_url,
            login_url=login_url,
            username=username,
            password=password,
            max_pages=80,
            max_depth=2
        )

        saved_count = _save_discovered_pages(
            site_id=str(site.get("_id")),
            user_id=str(site.get("user_id", "")),
            pages=discovered_pages
        )

        return jsonify({
            "message": "Authenticated discovery completed successfully.",
            "site_id": site_id,
            "discovered_count": len(discovered_pages),
            "saved_count": saved_count,
            "pages": discovered_pages
        }), 200

    except Exception as e:
        print("Authenticated discovery failed:", str(e))
        return jsonify({
            "error": "Authenticated discovery failed.",
            "details": str(e)
        }), 500


@app.route("/api/sites/<site_id>/pages", methods=["GET", "OPTIONS"])
def get_site_pages(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not ObjectId.is_valid(site_id):
        return jsonify({"error": "Invalid site id"}), 400

    site = sites.find_one({"_id": ObjectId(site_id)})
    if not site:
        return jsonify({"error": "Site not found"}), 404

    if not is_admin:
        if site.get("user_id") != str(actor.get("_id")):
            return jsonify({"error": "Forbidden"}), 403

    pages = list(
        mongo.db.site_pages
        .find({"site_id": site_id})
        .sort("path", 1)
    )

    result = []

    for page in pages:
        result.append({
            "_id": str(page.get("_id")),
            "site_id": page.get("site_id"),
            "path": page.get("path"),
            "full_url": page.get("full_url"),
            "page_trap_enabled": page.get("page_trap_enabled", True),
            "source": page.get("source", "public_crawler"),
            "hit_count": page.get("hit_count", 0),
            "discovery_count": page.get("discovery_count", 0),
            "created_at": page.get("created_at"),
            "last_seen": page.get("last_seen"),
        })

    return jsonify({
        "site_id": site_id,
        "pages": result,
        "count": len(result)
    }), 200

@app.route("/api/admin/users/<user_id>", methods=["DELETE", "OPTIONS"])
def admin_delete_user(user_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"error": "Invalid user id"}), 400

    user = users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # ✅ Delete user's honeypots
    sites.delete_many({"user_id": user_id})

    # ✅ Delete user's attack logs
    mongo.db.attacks.delete_many({"user_id": user_id})

    # ✅ Delete user's notifications
    mongo.db.notifications.delete_many({"user_id": user_id})

    # ✅ Delete user's brute force attempts
    mongo.db.bruteforce_attempts.delete_many({"user_id": user_id})

    # ✅ Delete user account
    users.delete_one({"_id": ObjectId(user_id)})

    return jsonify({
        "message": "User and related honeypots/logs deleted successfully",
        "deleted_user_id": user_id
    }), 200

@app.route("/api/admin/users", methods=["GET", "OPTIONS"])
def admin_get_users():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    result = []
    for u in users.find({"is_verified": True}).sort("created_at", -1):
        user_id = str(u.get("_id"))

        honeypot_count = sites.count_documents({"user_id": user_id})

        latest_site = sites.find_one(
            {"user_id": user_id},
            sort=[("created_at", -1)]
        )

        result.append({
            "_id": user_id,
            "name": u.get("name") or f"{u.get('firstName', '')} {u.get('lastName', '')}".strip() or "Unnamed User",
            "email": u.get("email", ""),
            "role": u.get("role", "user"),
            "status": "Active" if u.get("is_verified", True) else "Inactive",
            "honeypots": honeypot_count,
            "website": latest_site.get("base_url") if latest_site else "No website registered",
            "created_at": u.get("created_at"),
            "account_status": u.get("account_status", "active"),
            "suspended_until": u.get("suspended_until").isoformat() if u.get("suspended_until") else None,
        })

    return jsonify({"users": result}), 200




@app.route("/api/admin/users/<user_id>/suspend", methods=["PATCH", "OPTIONS"])
def admin_suspend_user(user_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"error": "Invalid user id"}), 400

    user = users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    suspended_until = _now() + timedelta(minutes=10)

    users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "account_status": "suspended",
                "suspended_until": suspended_until,
                "suspended_at": _now(),
                "suspended_by": actor.get("email", "")
            }
        }
    )

    return jsonify({
        "message": "User suspended for 10 minutes successfully.",
        "user_id": user_id,
        "suspended_until": suspended_until.isoformat()
    }), 200


@app.route("/api/admin/users/<user_id>/unsuspend", methods=["PATCH", "OPTIONS"])
def admin_unsuspend_user(user_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"error": "Invalid user id"}), 400

    user = users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if user.get("account_status") == "blocked":
        return jsonify({"error": "Blocked user cannot be unsuspended. Please unblock first."}), 400

    users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "account_status": "active",
                "unsuspended_at": _now(),
                "unsuspended_by": actor.get("email", "")
            },
            "$unset": {
                "suspended_until": "",
                "suspended_at": "",
                "suspended_by": ""
            }
        }
    )

    return jsonify({
        "message": "User unsuspended successfully.",
        "user_id": user_id
    }), 200


@app.route("/api/admin/users/<user_id>/block", methods=["PATCH", "OPTIONS"])
def admin_block_user(user_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    if not ObjectId.is_valid(user_id):
        return jsonify({"error": "Invalid user id"}), 400

    user = users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404

    users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "account_status": "blocked",
                "blocked_at": _now(),
                "blocked_by": actor.get("email", "")
            },
            "$unset": {
                "suspended_until": "",
                "suspended_at": "",
                "suspended_by": ""
            }
        }
    )

    return jsonify({
        "message": "User blocked successfully.",
        "user_id": user_id
    }), 200


# @app.route("/api/admin/users/<user_id>/unblock", methods=["PATCH", "OPTIONS"])
# def admin_unblock_user(user_id):
#     if request.method == "OPTIONS":
#         return ("", 204)

#     actor, is_admin, err, status = _get_request_actor()
#     if err:
#         return err, status

#     if not is_admin:
#         return jsonify({"error": "Admin access required"}), 403

#     if not ObjectId.is_valid(user_id):
#         return jsonify({"error": "Invalid user id"}), 400

#     user = users.find_one({"_id": ObjectId(user_id)})
#     if not user:
#         return jsonify({"error": "User not found"}), 404

#     users.update_one(
#         {"_id": ObjectId(user_id)},
#         {
#             "$set": {
#                 "account_status": "active",
#                 "unblocked_at": _now(),
#                 "unblocked_by": actor.get("email", "")
#             },
#             "$unset": {
#                 "suspended_until": "",
#                 "suspended_at": "",
#                 "suspended_by": "",
#                 "blocked_at": "",
#                 "blocked_by": ""
#             }
#         }
#     )

#     return jsonify({
#         "message": "User unblocked successfully.",
#         "user_id": user_id
#     }), 200


@app.route("/api/sites", methods=["POST", "OPTIONS"], endpoint="create_site_unique")
def create_site():
    if request.method == "OPTIONS":
        return ("", 204)

    user, err = _require_user()
    if err:
        return err

    body = _require_json()
    websiteUrl = _normalize_url(body.get("websiteUrl") or "")
    name = (body.get("name") or "").strip()
    verificationMethod = (body.get("verificationMethod") or "api_key").strip()

    if not websiteUrl or not name:
        return jsonify({"error": "websiteUrl and name are required"}), 400
    

    existing_active_site = sites.find_one({
        "base_url": websiteUrl,
        "is_active": True
    })

    if existing_active_site:
        existing_owner = existing_active_site.get("user_email") or "another user"
        return jsonify({
            "error": f"This website is already registered as an active honeypot by {existing_owner}"
        }), 409

    api_key = secrets.token_hex(16)

    doc = {
        "user_id": str(user.get("_id")),
        "user_email": user.get("email"),
        "site_name": name,
        "base_url": websiteUrl,
        "verificationMethod": verificationMethod,
        "apiKey": api_key,
        "is_active": True,
        "trap_enabled": True,
        "monitor_mode": "all_pages",
        "monitored_pages": [],
        "created_at": datetime.utcnow().isoformat(),
        "last_activity": None,
        "attacks_today": 0,
    }

    inserted = sites.insert_one(doc)
    
    try:
        discovered_pages = discover_public_pages(websiteUrl)
        saved_pages_count = _save_discovered_pages(
            site_id=str(inserted.inserted_id),
            user_id=str(user.get("_id")),
            pages=discovered_pages
        )
    except Exception as e:
        print("Public page discovery failed:", str(e))
        saved_pages_count = 0

    return jsonify({
        "site": {
            "_id": str(inserted.inserted_id),
            "name": doc["site_name"],
            "websiteUrl": doc["base_url"],
            "verificationMethod": doc["verificationMethod"],
            "apiKey": doc["apiKey"],
            "status": "active",
            "created_at": doc["created_at"],
            "attacks_today": 0,
            "last_activity": None,
            "ownerEmail": doc["user_email"],
            "trapEnabled": doc["trap_enabled"],
            "monitorMode": doc["monitor_mode"],
            "monitoredPages": doc["monitored_pages"],
            "discovered_pages_count": saved_pages_count,
        }
    }), 201

@app.route("/api/auth/logout", methods=["POST"])
@auth_required
def logout():
    user_id = request.user.get("_id") or request.user.get("id")

    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "status": "Inactive",
                "is_online": False,
                "last_logout": datetime.utcnow(),
                "last_seen": datetime.utcnow()
            }
        }
    )

    return jsonify({"message": "Logged out successfully"}), 200

# =========================================================
# ✅ USER: Delete External Honeypot Site
# =========================================================
@app.route("/api/sites/<site_id>", methods=["DELETE", "OPTIONS"], endpoint="delete_site_unique")
def delete_site(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    user, err = _require_user()
    if err:
        return err

    try:
        site = sites.find_one({
            "_id": ObjectId(site_id),
            "user_id": str(user.get("_id"))
        })
    except Exception:
        return jsonify({"error": "Invalid site id"}), 400

    if not site:
        return jsonify({"error": "Site not found"}), 404

    site_name = site.get("site_name") or site.get("name") or "Unknown Site"
    base_url = site.get("base_url") or site.get("websiteUrl") or ""
    mongo.db.attacks.delete_many({
        "user_id": str(user.get("_id")),
        "$or": [
            {"honeypot": site_name},
            {"url": {"$regex": f"^{re.escape(base_url)}"}}
        ]
    })

    # ✅ delete related notifications of this user + site
    mongo.db.notifications.delete_many({
        "user_id": str(user.get("_id")),
        "$or": [
            {"title": {"$regex": re.escape(site_name), "$options": "i"}},
            {"message": {"$regex": re.escape(base_url), "$options": "i"}},
            {"message": {"$regex": re.escape(site_name), "$options": "i"}}
        ]
    })

    # ✅ delete the site itself
    sites.delete_one({
        "_id": ObjectId(site_id),
        "user_id": str(user.get("_id"))
    })

    return jsonify({
        "message": "Honeypot deleted successfully",
        "deleted_site_id": site_id,
        "deleted_site_name": site_name
    }), 200

# added 2:56 5/12/2026
@app.route("/api/admin/sites/<site_id>", methods=["DELETE", "OPTIONS"])
def admin_delete_site(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    try:
        site = sites.find_one({"_id": ObjectId(site_id)})
    except Exception:
        return jsonify({"error": "Invalid site id"}), 400

    if not site:
        return jsonify({"error": "Site not found"}), 404

    site_name = site.get("site_name") or site.get("name") or "Unknown Site"
    base_url = site.get("base_url") or site.get("websiteUrl") or ""
    owner_user_id = site.get("user_id")

    delete_attack_query = {
        "$or": [
            {"honeypot": site_name},
            {"url": {"$regex": f"^{re.escape(base_url)}"}}
        ]
    }
    if owner_user_id:
        delete_attack_query["user_id"] = owner_user_id

    mongo.db.attacks.delete_many(delete_attack_query)

    delete_notification_query = {
        "$or": [
            {"title": {"$regex": re.escape(site_name), "$options": "i"}},
            {"message": {"$regex": re.escape(base_url), "$options": "i"}},
            {"message": {"$regex": re.escape(site_name), "$options": "i"}},
        ]
    }
    if owner_user_id:
        delete_notification_query["user_id"] = owner_user_id

    mongo.db.notifications.delete_many(delete_notification_query)

    sites.delete_one({"_id": ObjectId(site_id)})

    return jsonify({
        "message": "Honeypot deleted successfully",
        "deleted_site_id": site_id,
        "deleted_site_name": site_name
    }), 200
    
    
@app.route("/api/admin/sites/<site_id>/trap", methods=["PATCH", "OPTIONS"])
def admin_toggle_site_trap(site_id):
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    body = _require_json()
    trap_enabled = body.get("trap_enabled")

    if not isinstance(trap_enabled, bool):
        return jsonify({"error": "trap_enabled must be true or false"}), 400

    try:
        site = sites.find_one({"_id": ObjectId(site_id)})
    except Exception:
        return jsonify({"error": "Invalid site id"}), 400

    if not site:
        return jsonify({"error": "Site not found"}), 404

    sites.update_one(
        {"_id": ObjectId(site_id)},
        {"$set": {"trap_enabled": trap_enabled}}
    )

    return jsonify({
        "message": f"Trap {'enabled' if trap_enabled else 'disabled'} successfully",
        "site_id": site_id,
        "trap_enabled": trap_enabled
    }), 200
# =========================================================
# ✅ Honeypot collect endpoint (later we will link with token)
# =========================================================

# @app.post("/api/honeypot/collect")
# def collect_attack():
#     data = request.get_json(force=True) or {}

#     attack_log = {
#         "honeypot": data.get("honeypot", "DVWA"),
#         "url": data.get("url"),
#         "method": data.get("method"),
#         "payload": data.get("payload"),
#         "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
#         "user_agent": request.headers.get("User-Agent"),
#         "created_at": datetime.utcnow().isoformat() + "Z",
#     }

#     print("🔥 Attack Captured:", attack_log)

#     return jsonify({
#         "message": "Attack captured",
#         "received": True
#     }), 200
def is_suspicious_payload(payload: str) -> bool:
    if not payload:
        return False

    p = payload.lower()

    suspicious_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "union select",
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "sleep(",
        "benchmark(",
        "../",
        "..\\",
        "/etc/passwd",
        "information_schema",
        "xp_cmdshell",
        "load_file(",
        "into outfile",
    ]

    return any(pattern in p for pattern in suspicious_patterns)
def fallback_attack_from_payload(payload: str):
    p = (payload or "").lower().strip()
    if not p:
        return None, None

    # XSS
    if (
        "<script" in p
        or "javascript:" in p
        or "onerror=" in p
        or "onload=" in p
        or "<svg" in p
        or "<iframe" in p
    ):
        return "XSS", _detect_xss_subtype(payload)

    # SQLi
    if (
        "union select" in p
        or "' or '1'='1" in p
        or "\" or \"1\"=\"1" in p
        or "sleep(" in p
        or "waitfor delay" in p
        or "information_schema" in p
        or "@@version" in p
        or "select" in p and "from" in p
    ):
        return "SQLi", _detect_sqli_subtype(payload)

    # LFI
    if (
        "../" in p
        or "..\\" in p
        or "/etc/passwd" in p
        or "php://filter" in p
        or "php://input" in p
        or "file://" in p
        or "win.ini" in p
        or "boot.ini" in p
    ):
        return "LFI", _detect_lfi_subtype(payload)

    return None, None
@app.post("/api/honeypot/collect")
def collect_attack():
    data = request.get_json(force=True) or {}

    api_key = request.headers.get("X-API-KEY")
    site = mongo.db.sites.find_one({"apiKey": api_key})

    if not site:
        return jsonify({"error": "Invalid API key"}), 401

    if not site.get("is_active", True):
        return jsonify({"message": "Site is inactive. Collection skipped."}), 202

    
        if not site.get("trap_enabled", True):
          return jsonify({"message": "Trap is disabled. Collection skipped."}), 202

    # ✅ PAGE-LEVEL TRAP CHECK START
    request_url = (
        data.get("url")
        or data.get("page_url")
        or data.get("full_url")
        or data.get("current_url")
        or ""
    )

    current_path = _extract_path_from_url(request_url)

    site_id = str(site.get("_id"))
    user_id = str(site.get("user_id", ""))

    # ✅ Real traffic se page auto-save/update hoga
    _save_or_update_site_page(
        site_id=site_id,
        user_id=user_id,
        path=current_path,
        full_url=request_url,
        source="collector_auto"
    )

    # ✅ Agar specific page ka trap OFF hai to attack detect/save nahi hoga
    if not _is_page_trap_enabled(site_id, current_path):
        return jsonify({
            "message": "Page trap is disabled. Request skipped.",
            "captured": False,
            "reason": "page_trap_disabled",
            "path": current_path
        }), 200
    # ✅ PAGE-LEVEL TRAP CHECK END

    raw_payload = (data.get("payload") or "").strip()
    
    decoded_payload = unquote_plus(raw_payload).strip()

    brute_force_debug = _detect_brute_force(
        site=site,
        url=data.get("url"),
        method=data.get("method"),
        payload=decoded_payload,
    )

    if brute_force_debug:
        pred = 4
        attack_type = "Brute Force"
        confidence = 0.95
        err = None
        decision_debug = brute_force_debug
    else:
        pred, attack_type, confidence, err, decision_debug = _predict(decoded_payload)

    if err:
        return jsonify({
            "error": "XAI model not ready",
            "details": err
        }), 500

    subtype = "N/A"

    if attack_type == "SQLi":
        subtype = _detect_sqli_subtype(decoded_payload)
    elif attack_type == "XSS":
        subtype = _detect_xss_subtype(decoded_payload)
    elif attack_type == "LFI":
        subtype = _detect_lfi_subtype(decoded_payload)
    elif attack_type == "Brute Force":
        subtype = "Repeated Login Attempts"

    # fallback if model says Normal
    if attack_type == "Normal":
        fallback_type, fallback_subtype = fallback_attack_from_payload(decoded_payload)

        if fallback_type:
            attack_type = fallback_type
            subtype = fallback_subtype or "N/A"
            pred = {"SQLi": 1, "XSS": 2, "LFI": 3, "Brute Force": 4}.get(fallback_type, 0)
            confidence = confidence if confidence is not None else 0.70
            decision_debug = {
                "decision_reason": "fallback_pattern_match_after_model_normal"
            }

    # still normal => ignore
    if attack_type == "Normal":
        return jsonify({
            "message": "Normal request ignored",
            "received": True,
            "suspicious": False,
            "attack_type": attack_type,
            "confidence": confidence,
        }), 200

    severity = _severity(attack_type, confidence, subtype)
    safe_decision_debug = json.loads(json.dumps(decision_debug, default=str))

    attack_log = {
        "user_id": user_id,
        "honeypot": site.get("site_name", data.get("honeypot", "DVWA")),
        "url": data.get("url"),
        "method": data.get("method"),
        "payload": decoded_payload,
        "raw_payload": raw_payload,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "user_agent": request.headers.get("User-Agent"),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "label": pred,
        "attack_type": attack_type,
        "subtype": subtype,
        "severity": severity,
        "confidence": confidence,
        "decision": safe_decision_debug,
    }

    res = mongo.db.attacks.insert_one(attack_log)

    mongo.db.sites.update_one(
        {"_id": site["_id"]},
        {
            "$set": {
                "last_activity": datetime.utcnow().isoformat() + "Z"
            },
            "$inc": {
                "attacks_today": 1
            }
        }
    )

    notification = {
        "user_id": user_id,
        "type": "attack",
        "title": f"{attack_type} attack detected",
        "message": f"{attack_log['honeypot']} | {attack_log['method']} | {attack_log['url']}",
        "severity": severity.lower(),
        "attack_id": str(res.inserted_id),
        "read": False,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    mongo.db.notifications.insert_one(notification)

    try:
        user_doc = users.find_one({"_id": ObjectId(user_id)})

        if user_doc and user_doc.get("email"):
            send_attack_alert_email(
                to_email=user_doc["email"],
                honeypot=attack_log["honeypot"],
                method=attack_log["method"],
                url=attack_log["url"],
                payload=attack_log["payload"],
                severity=severity,
            )
    except Exception as e:
        print("Attack alert email failed:", str(e))

    return jsonify({
        "message": "Suspicious attack captured",
        "received": True,
        "suspicious": True,
        "attack_type": attack_type,
        "subtype": subtype,
        "severity": severity,
        "confidence": confidence,
    }), 200
# @app.get("/api/notifications/unread-count")
# def unread_count_apikey():
#     api_key = request.headers.get("X-API-KEY")
#     site = mongo.db.sites.find_one({"apiKey": api_key})
#     if not site:
#         return jsonify({"error": "Invalid API key"}), 401

#     user_id = str(site.get("user_id"))
#     count = mongo.db.notifications.count_documents({"user_id": user_id, "read": False})
#     return jsonify({"unread_count": count}), 200
@app.get("/api/notifications/unread-count")
def unread_count():
    user, err = _require_user()
    if err:
        return err

    user_id = str(user.get("_id"))
    count = mongo.db.notifications.count_documents({
        "user_id": user_id,
        "read": False
    })

    return jsonify({"unread_count": count}), 200


# @app.get("/api/notifications")
# def get_notifications():
#     api_key = request.headers.get("X-API-KEY")
#     site = mongo.db.sites.find_one({"apiKey": api_key})
#     if not site:
#         return jsonify({"error": "Invalid API key"}), 401

#     user_id = str(site.get("user_id"))
#     limit = int(request.args.get("limit", 10))

#     items = list(
#         mongo.db.notifications
#         .find({"user_id": user_id})
#         .sort("created_at", -1)
#         .limit(limit)
#     )

#     for n in items:
#         n["_id"] = str(n["_id"])

#     return jsonify({"notifications": items}), 200
# @app.get("/api/notifications")
# def get_notifications():
#     user, err = _require_user()
#     if err:
#         return err

#     user_id = str(user.get("_id"))
#     limit = int(request.args.get("limit", 20))

#     items = list(
#         mongo.db.notifications
#         .find({"user_id": user_id})
#         .sort("created_at", -1)
#         .limit(limit)
#     )

#     unread_count = mongo.db.notifications.count_documents({
#         "user_id": user_id,
#         "read": False
#     })

#     for n in items:
#         n["_id"] = str(n["_id"])

#     return jsonify({
#         "notifications": items,
#         "unread_count": unread_count
#     }), 200

@app.get("/api/notifications")
def get_notifications():
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    limit = int(request.args.get("limit", 20))

    query = {}
    if not is_admin:
        query["user_id"] = str(actor.get("_id"))

    items = list(
        mongo.db.notifications
        .find(query)
        .sort("created_at", -1)
        .limit(limit)
    )

    unread_query = {"read": False}
    if not is_admin:
        unread_query["user_id"] = str(actor.get("_id"))

    unread_count = mongo.db.notifications.count_documents(unread_query)

    for n in items:
        n["_id"] = str(n["_id"])

    return jsonify({
        "notifications": items,
        "unread_count": unread_count
    }), 200
    
    
@app.patch("/api/notifications/<notification_id>/read")
def mark_one_notification_read(notification_id):
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    try:
        notif = mongo.db.notifications.find_one({"_id": ObjectId(notification_id)})
    except Exception:
        return jsonify({"error": "Invalid notification id"}), 400

    if not notif:
        return jsonify({"error": "Notification not found"}), 404

    if not is_admin:
        if notif.get("user_id") != str(actor.get("_id")):
            return jsonify({"error": "Forbidden"}), 403

    mongo.db.notifications.update_one(
        {"_id": ObjectId(notification_id)},
        {"$set": {"read": True}}
    )

    return jsonify({"ok": True}), 200


# @app.patch("/api/notifications/<notif_id>/read")
# def mark_read(notif_id):
#     api_key = request.headers.get("X-API-KEY")
#     site = mongo.db.sites.find_one({"apiKey": api_key})
#     if not site:
#         return jsonify({"error": "Invalid API key"}), 401

#     user_id = str(site.get("user_id"))

#     mongo.db.notifications.update_one(
#         {"_id": ObjectId(notif_id), "user_id": user_id},
#         {"$set": {"read": True}}
#     )
#     return jsonify({"ok": True}), 200

# =========================================================
# ✅ USER/ADMIN: Vulnerability Stats
# =========================================================
# =========================================================
# ✅ ADMIN: Get All Registered Honeypot Sites
# =========================================================
@app.route("/api/sites/all", methods=["GET", "OPTIONS"])
def all_sites():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    cursor = sites.find({}).sort("created_at", -1)

    result = []
    for s in cursor:
        owner_email = s.get("user_email")

        if not owner_email and s.get("user_id"):
            try:
                owner_doc = users.find_one({"_id": ObjectId(s.get("user_id"))})
                if owner_doc:
                    owner_email = owner_doc.get("email")
            except Exception:
                pass

        result.append({
            "_id": str(s.get("_id")),
            "name": s.get("site_name") or s.get("name"),
            "websiteUrl": s.get("base_url") or s.get("websiteUrl"),
            "ownerEmail": owner_email or "Unknown",
            "status": "active" if s.get("is_active", True) else "inactive",
            "created_at": s.get("created_at"),
            "verificationMethod": s.get("verificationMethod", "api_key"),
            "apiKey": s.get("apiKey") or s.get("api_key"),
            "last_activity": s.get("last_activity"),
            "attacks_today": s.get("attacks_today", 0),
            "trapEnabled": s.get("trap_enabled", True),
            "monitorMode": s.get("monitor_mode", "all_pages"),
            "monitoredPages": s.get("monitored_pages", []),
            "user_id": s.get("user_id"),
        })

    return jsonify({"sites": result}), 200
@app.route("/api/stats/vulnerabilities", methods=["GET", "OPTIONS"])
def vulnerability_stats():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    honeypot = (request.args.get("honeypot") or "").strip()
    base_url = (request.args.get("base_url") or "").strip()

    query = {}

    if not is_admin:
        query["user_id"] = str(actor.get("_id"))

    if honeypot:
        query["honeypot"] = honeypot

    if base_url:
        query["url"] = {"$regex": f"^{re.escape(base_url)}"}

    pipeline = [
        {"$match": query},
        {
            "$group": {
                "_id": {"$ifNull": ["$attack_type", "Unknown"]},
                "count": {"$sum": 1}
            }
        }
    ]

    grouped = list(attacks_col.aggregate(pipeline))

    mapped = {
        "SQL Injection": 0,
        "XSS": 0,
        "Brute Force": 0,
        "Port Scan": 0,
        "LFI": 0,
    }

    for row in grouped:
        raw = (row.get("_id") or "").strip()
        count = int(row.get("count", 0))

        if raw in ["SQLi", "SQL Injection"]:
            mapped["SQL Injection"] += count
        elif raw == "XSS":
            mapped["XSS"] += count
        elif raw in ["Brute Force", "Bruteforce"]:
            mapped["Brute Force"] += count
        elif raw in ["Port Scan", "PortScan"]:
            mapped["Port Scan"] += count
        elif raw == "LFI":
            mapped["LFI"] += count

    data = [
        {"name": "SQL Injection", "value": mapped["SQL Injection"], "severity": "high"},
        {"name": "XSS", "value": mapped["XSS"], "severity": "high"},
        {"name": "Brute Force", "value": mapped["Brute Force"], "severity": "medium"},
        {"name": "Port Scan", "value": mapped["Port Scan"], "severity": "low"},
        {"name": "LFI", "value": mapped["LFI"], "severity": "critical"},
    ]

    total_attacks = sum(x["value"] for x in data)

    return jsonify({
        "data": data,
        "total_attacks": total_attacks,
        "selected_honeypot": honeypot or None,
        "selected_base_url": base_url or None,
    }), 200
    
    
# =========================================================
# ✅ USER/ADMIN: Dashboard Stats
# =========================================================
@app.route("/api/stats/dashboard", methods=["GET", "OPTIONS"])
def dashboard_stats():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    honeypot = (request.args.get("honeypot") or "").strip()
    base_url = (request.args.get("base_url") or "").strip()

    attacks_query = {}
    sites_query = {}

    if not is_admin:
        attacks_query["user_id"] = str(actor.get("_id"))
        sites_query["user_id"] = str(actor.get("_id"))

    if honeypot:
        attacks_query["honeypot"] = honeypot
        sites_query["site_name"] = honeypot

    if base_url:
        attacks_query["url"] = {"$regex": f"^{re.escape(base_url)}"}
        sites_query["base_url"] = base_url

    active_honeypots = sites.count_documents({**sites_query, "is_active": True})
    attacks_blocked = attacks_col.count_documents(attacks_query)

    latest_attack_doc = attacks_col.find_one(attacks_query, sort=[("created_at", -1)])
    last_attack = latest_attack_doc.get("created_at") if latest_attack_doc else None

    admin_stats = None
    if is_admin:
        admin_stats = {
            "total_users": users.count_documents({}),
            "total_honeypots": sites.count_documents({}),
            "active_threats": attacks_col.count_documents({}),
            "total_attacks": attacks_col.count_documents({}),
        }

    return jsonify({
        "active_honeypots": active_honeypots,
        "attacks_blocked": attacks_blocked,
        "last_attack": last_attack,
        "uptime": "99.8%",
        "admin": admin_stats,
        "selected_honeypot": honeypot or None,
        "selected_base_url": base_url or None,
    }), 200
    
# =========================================================
# ✅ USER/ADMIN: Traffic Stats
# =========================================================
@app.route("/api/stats/traffic", methods=["GET", "OPTIONS"])
def traffic_stats():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    honeypot = (request.args.get("honeypot") or "").strip()
    base_url = (request.args.get("base_url") or "").strip()

    attacks_query = {}

    if not is_admin:
        attacks_query["user_id"] = str(actor.get("_id"))

    if honeypot:
        attacks_query["honeypot"] = honeypot

    if base_url:
        attacks_query["url"] = {"$regex": f"^{re.escape(base_url)}"}

    blocked_docs = list(attacks_col.find(attacks_query))
    total_blocked = len(blocked_docs)

    estimated_legitimate = max(total_blocked * 4, 0)
    total_requests = total_blocked + estimated_legitimate
    block_rate = round((total_blocked / total_requests) * 100, 1) if total_requests > 0 else 0.0

    buckets = [
        {"time": "00:00", "blocked": 0},
        {"time": "04:00", "blocked": 0},
        {"time": "08:00", "blocked": 0},
        {"time": "12:00", "blocked": 0},
        {"time": "16:00", "blocked": 0},
        {"time": "20:00", "blocked": 0},
    ]

    def get_bucket(hour: int):
        if 0 <= hour < 4:
            return "00:00"
        if 4 <= hour < 8:
            return "04:00"
        if 8 <= hour < 12:
            return "08:00"
        if 12 <= hour < 16:
            return "12:00"
        if 16 <= hour < 20:
            return "16:00"
        return "20:00"

    bucket_map = {b["time"]: b for b in buckets}

    for doc in blocked_docs:
        created_at = doc.get("created_at")
        if not created_at:
            continue
        try:
            dt = created_at
            if isinstance(created_at, str):
                dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            bucket_key = get_bucket(dt.hour)
            bucket_map[bucket_key]["blocked"] += 1
        except Exception:
            continue

    timeline = []
    for b in buckets:
        blocked = b["blocked"]
        legitimate = blocked * 4
        requests_total = blocked + legitimate
        timeline.append({
            "time": b["time"],
            "requests": requests_total,
            "blocked": blocked,
            "legitimate": legitimate,
        })

    return jsonify({
        "total_requests": total_requests,
        "attacks_blocked": total_blocked,
        "legitimate_traffic": estimated_legitimate,
        "block_rate": block_rate,
        "timeline": timeline,
        "selected_honeypot": honeypot or None,
        "selected_base_url": base_url or None,
    }), 200

@app.patch("/api/notifications/<notif_id>/read")
def mark_read(notif_id):
    user, err = _require_user()
    if err:
        return err

    user_id = str(user.get("_id"))

    mongo.db.notifications.update_one(
        {"_id": ObjectId(notif_id), "user_id": user_id},
        {"$set": {"read": True}}
    )

    return jsonify({"ok": True}), 200


# @app.post("/api/notifications/mark-all-read")
# def mark_all_read():
#     api_key = request.headers.get("X-API-KEY")
#     site = mongo.db.sites.find_one({"apiKey": api_key})
#     if not site:
#         return jsonify({"error": "Invalid API key"}), 401

#     user_id = str(site.get("user_id"))

#     mongo.db.notifications.update_many(
#         {"user_id": user_id, "read": False},
#         {"$set": {"read": True}}
#     )
#     return jsonify({"ok": True}), 200

# @app.post("/api/notifications/mark-all-read")
# def mark_all_read():
#     user, err = _require_user()
#     if err:
#         return err

#     user_id = str(user.get("_id"))

#     mongo.db.notifications.update_many(
#         {"user_id": user_id, "read": False},
#         {"$set": {"read": True}}
#     )

#     return jsonify({"ok": True}), 200

@app.post("/api/notifications/mark-all-read")
def mark_all_read():
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    query = {"read": False}
    if not is_admin:
        query["user_id"] = str(actor.get("_id"))

    mongo.db.notifications.update_many(
        query,
        {"$set": {"read": True}}
    )

    return jsonify({"ok": True}), 200

# @app.get("/api/attacks")
# def get_attacks():
#     honeypot = (request.args.get("honeypot") or "").strip()
#     base_url = (request.args.get("base_url") or "").strip()
#     limit = int(request.args.get("limit", 50))

#     query = {}
#     if honeypot:
#         query["honeypot"] = honeypot
        
#     if base_url:
#         query["url"] = {"$regex": f"^{re.escape(base_url)}"}    

#     cursor = mongo.db.attacks.find(query).sort("created_at", -1).limit(limit)
#     data = []
#     for doc in cursor:
#         doc["_id"] = str(doc["_id"])
#         data.append(doc)

#     return jsonify({"count": len(data), "attacks": data}), 200

@app.get("/api/attacks")
def get_attacks():
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    honeypot = (request.args.get("honeypot") or "").strip()
    base_url = (request.args.get("base_url") or "").strip()
    limit = int(request.args.get("limit", 50))

    query = {}

    # ✅ Normal user can only see own logs
    # ✅ Admin can see all logs
    if not is_admin:
        query["user_id"] = str(actor.get("_id"))

    if honeypot:
        query["honeypot"] = honeypot

    if base_url:
        query["url"] = {"$regex": f"^{re.escape(base_url)}"}

    cursor = mongo.db.attacks.find(query).sort("created_at", -1).limit(limit)

    data = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        data.append(doc)

    return jsonify({
        "count": len(data),
        "attacks": data
    }), 200
    
@app.post("/api/attacks/<attack_id>/generate-report")
def generate_attack_report(attack_id):
    # ✅ user/admin dono support
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    data = request.get_json(force=True) or {}
    report_format = (data.get("format") or "pdf").strip().lower()

    if report_format != "pdf":
        return jsonify({"error": "Only pdf format is supported"}), 400

    # ✅ validate attack id
    if not ObjectId.is_valid(attack_id):
        return jsonify({"error": "Invalid attack id"}), 400

    # ✅ Admin can generate report for any attack
    # ✅ User can generate report only for own attack
    if is_admin:
        attack = mongo.db.attacks.find_one({
            "_id": ObjectId(attack_id)
        })
    else:
        attack = mongo.db.attacks.find_one({
            "_id": ObjectId(attack_id),
            "user_id": str(actor.get("_id"))
        })

    if not attack:
        return jsonify({"error": "Attack not found or access denied"}), 404

    payload = attack.get("payload", "") or ""
    attack_type = attack.get("attack_type", "Normal")
    subtype = attack.get("subtype", "N/A")
    severity = attack.get("severity", "LOW")
    confidence = attack.get("confidence", "-")
    decision = attack.get("decision", {}) or {}

    if attack_type == "SQLi":
        subtype = _detect_sqli_subtype(payload)
    elif attack_type == "XSS":
        subtype = _detect_xss_subtype(payload)
    elif attack_type == "LFI":
        subtype = _detect_lfi_subtype(payload)

    explanation = _top_terms(payload, top_k=10) if attack_type != "Normal" else []
    pattern_hits = decision.get("pattern_hits", {}) if isinstance(decision, dict) else {}

    specific_explanation = _attack_specific_explanation(
        attack_type=attack_type,
        subtype=subtype,
        payload=payload,
        hits=pattern_hits,
    )

    impact, mitigation, attack_preconditions = _attack_specific_impact_and_mitigation(
        attack_type, subtype
    )

    report = {
        "report_id": secrets.token_hex(8),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "generated_by": {
            "email": actor.get("email", ""),
            "role": "admin" if is_admin else "user",
        },
        "payload": payload,
        "label": attack.get("label", 0),
        "attack_type": attack_type,
        "subtype": subtype,
        "confidence": confidence,
        "explanation": explanation,
        "specific_explanation": specific_explanation,
        "meta": {
            "honeypot": attack.get("honeypot", "-"),
            "ip": attack.get("ip", "-"),
            "user_agent": attack.get("user_agent", ""),
            "path": attack.get("url", ""),
            "method": attack.get("method", ""),
            "created_at": attack.get("created_at", ""),
        },
        "decision": decision,
        "summary": {
            "message": (
                "Looks normal / benign input."
                if attack_type == "Normal"
                else f"{attack_type} detected with subtype: {subtype}"
            ),
            "severity": severity,
        },
        "impact": {"possible_impact": impact},
        "attack_preconditions": attack_preconditions,
        "mitigation": mitigation,
    }

    _save_json(report)
    pdf_path = _save_pdf(report)

    filename_base = f"HWACS_Report_{attack.get('honeypot', 'honeypot')}_{attack_type}_{str(attack['_id'])}"

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"{filename_base}.pdf",
        mimetype="application/pdf",
    )
# @app.post("/api/attacks/<attack_id>/generate-report")
# def generate_attack_report(attack_id):
#     user, err = _require_user()
#     if err:
#         return err

#     data = request.get_json(force=True) or {}
#     report_format = (data.get("format") or "pdf").strip().lower()

#     if report_format != "pdf":
#         return jsonify({"error": "Only pdf format is supported"}), 400

#     attack = mongo.db.attacks.find_one({
#         "_id": ObjectId(attack_id),
#         "user_id": str(user.get("_id"))
#     })

#     if not attack:
#         return jsonify({"error": "Attack not found"}), 404

#     payload = attack.get("payload", "") or ""
#     attack_type = attack.get("attack_type", "Normal")
#     subtype = attack.get("subtype", "N/A")
#     severity = attack.get("severity", "LOW")
#     confidence = attack.get("confidence", "-")
#     decision = attack.get("decision", {}) or {}

#     if attack_type == "SQLi":
#         subtype = _detect_sqli_subtype(payload)
#     elif attack_type == "XSS":
#         subtype = _detect_xss_subtype(payload)
#     elif attack_type == "LFI":
#         subtype = _detect_lfi_subtype(payload)

#     explanation = _top_terms(payload, top_k=10) if attack_type != "Normal" else []
#     pattern_hits = decision.get("pattern_hits", {}) if isinstance(decision, dict) else {}

#     specific_explanation = _attack_specific_explanation(
#         attack_type=attack_type,
#         subtype=subtype,
#         payload=payload,
#         hits=pattern_hits,
#     )

#     impact, mitigation, attack_preconditions = _attack_specific_impact_and_mitigation(
#         attack_type, subtype
#     )

#     report = {
#         "report_id": secrets.token_hex(8),
#         "created_at": datetime.utcnow().isoformat() + "Z",
#         "payload": payload,
#         "label": attack.get("label", 0),
#         "attack_type": attack_type,
#         "subtype": subtype,
#         "confidence": confidence,
#         "explanation": explanation,
#         "specific_explanation": specific_explanation,
#         "meta": {
#             "ip": attack.get("ip", "-"),
#             "user_agent": attack.get("user_agent", ""),
#             "path": attack.get("url", ""),
#             "method": attack.get("method", ""),
#         },
#         "decision": decision,
#         "summary": {
#             "message": (
#                 "Looks normal / benign input."
#                 if attack_type == "Normal"
#                 else f"{attack_type} detected with subtype: {subtype}"
#             ),
#             "severity": severity,
#         },
#         "impact": {"possible_impact": impact},
#         "attack_preconditions": attack_preconditions,
#         "mitigation": mitigation,
#     }

#     _save_json(report)
#     pdf_path = _save_pdf(report)

#     filename_base = f"HWACS_Report_{attack.get('honeypot', 'honeypot')}_{attack_type}_{str(attack['_id'])}"

#     return send_file(
#         pdf_path,
#         as_attachment=True,
#         download_name=f"{filename_base}.pdf",
#         mimetype="application/pdf",
#     )



@app.get("/api/profile")
def get_profile():
    user, err = _require_user()
    if err:
        return err

    return jsonify({
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "phone": user.get("phone", ""),
        "location": user.get("location", "")
    }), 200

@app.get("/api/admin/profile")
def get_admin_profile():
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({
        "name": actor.get("name", ""),
        "email": actor.get("email", ""),
        "phone": actor.get("phone", ""),
        "location": actor.get("location", ""),
        "profile_image": actor.get("profile_image", "")
    }), 200

@app.route("/api/admin/activity-logs", methods=["GET", "OPTIONS"])
def get_admin_activity_logs():
    if request.method == "OPTIONS":
        return ("", 204)

    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    email = _clean_email(actor.get("email"))
    limit = int(request.args.get("limit", 50))

    logs = list(
        mongo.db.admin_activity_logs
        .find({"email": email})
        .sort("created_at", -1)
        .limit(limit)
    )

    result = []
    for log in logs:
        result.append({
            "_id": str(log.get("_id")),
            "action": log.get("action", ""),
            "status": log.get("status", "success"),
            "severity": log.get("severity", "low"),
            "timestamp": log.get("created_at", ""),
            "ip": log.get("ip", ""),
        })

    return jsonify({"logs": result}), 200

@app.patch("/api/admin/profile")
def update_admin_profile():
    actor, is_admin, err, status = _get_request_actor()
    if err:
        return err, status

    if not is_admin:
        return jsonify({"error": "Admin access required"}), 403

    data = _require_json()

    phone = (data.get("phone") or "").strip()
    location = (data.get("location") or "").strip()
    profile_image = data.get("profile_image") or ""

    update_doc = {}

    # ✅ Full name/email intentionally not editable here
    if phone:
        if not re.fullmatch(r"\d{11}", phone):
         return jsonify({"error": "Phone number must be exactly 11 digits."}), 400
    update_doc["phone"] = phone

    if location:
        update_doc["location"] = location

    if profile_image:
        update_doc["profile_image"] = profile_image

    if not update_doc:
        return jsonify({"error": "Nothing to update"}), 400

    admins.update_one(
        {"_id": actor["_id"]},
        {"$set": {**update_doc, "updated_at": _now()}}
    )

    return jsonify({
        "message": "Admin profile updated successfully",
        "updated": update_doc
    }), 200
    
@app.route("/api/profile/activity-logs", methods=["GET", "OPTIONS"])
def get_user_activity_logs():
    if request.method == "OPTIONS":
        return ("", 204)

    user, err = _require_user()
    if err:
        return err

    email = _clean_email(user.get("email"))
    limit = int(request.args.get("limit", 50))

    logs = list(
        mongo.db.user_activity_logs
        .find({"email": email})
        .sort("created_at", -1)
        .limit(limit)
    )

    result = []
    for log in logs:
        result.append({
            "_id": str(log.get("_id")),
            "action": log.get("action", ""),
            "status": log.get("status", "success"),
            "severity": log.get("severity", "low"),
            "timestamp": log.get("created_at", ""),
            "ip": log.get("ip", ""),
        })

    return jsonify({"logs": result}), 200

    
@app.route("/api/profile/password/request-otp", methods=["POST", "OPTIONS"])
def user_request_password_change_otp():
    if request.method == "OPTIONS":
        return ("", 204)

    user, err = _require_user()
    if err:
        return err

    data = _require_json()

    current_password = (data.get("currentPassword") or "").strip()
    new_password = (data.get("newPassword") or "").strip()
    confirm_password = (data.get("confirmPassword") or "").strip()

    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "Current password, new password, and confirm password are required."}), 400

    if user.get("password") != current_password:
        return jsonify({"error": "Current password is incorrect."}), 401

    if new_password != confirm_password:
        return jsonify({"error": "New password and confirm password do not match."}), 400

    if current_password == new_password:
        return jsonify({"error": "New password cannot be the same as current password."}), 400

    is_valid_password, password_error = _validate_strong_password(new_password)
    if not is_valid_password:
        return jsonify({"error": password_error}), 400

    email = _clean_email(user.get("email"))
    if not email:
        return jsonify({"error": "User email not found."}), 401

    otp_code = create_otp_session(email=email, purpose="user_password_change")
    send_otp_email(email, otp_code)

    return jsonify({
        "message": "OTP sent to your email."
    }), 200
@app.route("/api/profile/password/verify-otp", methods=["POST", "OPTIONS"])
def user_verify_password_change_otp():
    if request.method == "OPTIONS":
        return ("", 204)

    user, err = _require_user()
    if err:
        return err

    data = _require_json()

    otp = (data.get("otp") or "").strip()
    current_password = (data.get("currentPassword") or "").strip()
    new_password = (data.get("newPassword") or "").strip()
    confirm_password = (data.get("confirmPassword") or "").strip()

    if not otp or not current_password or not new_password or not confirm_password:
        return jsonify({"error": "OTP, current password, new password, and confirm password are required."}), 400

    if user.get("password") != current_password:
        return jsonify({"error": "Current password is incorrect."}), 401

    if new_password != confirm_password:
        return jsonify({"error": "New password and confirm password do not match."}), 400

    if current_password == new_password:
        return jsonify({"error": "New password cannot be the same as current password."}), 400

    is_valid_password, password_error = _validate_strong_password(new_password)
    if not is_valid_password:
        return jsonify({"error": password_error}), 400

    email = _clean_email(user.get("email"))
    if not email:
        return jsonify({"error": "User email not found."}), 401

    ok, reason = verify_otp_code(email=email, otp=otp)
    if not ok:
        return jsonify({"error": reason or "Invalid or expired OTP."}), 400

    users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password": new_password,
                "updated_at": _now()
            }
        }
    )
    _log_user_activity(
    email,
    "Changed password",
    "success",
    "medium"
)

    return jsonify({
        "message": "Password updated successfully."
    }), 200



@app.patch("/api/profile")
def update_profile():
    user, err = _require_user()
    if err:
        return err

    data = _require_json()
    phone = (data.get("phone") or "").strip()
    location = (data.get("location") or "").strip()

    # ✅ validate phone
    if phone and not PHONE_RE.match(phone):
        return jsonify({"error": "Invalid phone. Use only digits and optional + (7–15 digits)."}), 400

    # ✅ validate location: "Country, City"
    if location and not LOCATION_RE.match(location):
        return jsonify({"error": "Invalid location. Use format: Country, City (letters only)."}), 400

    update_doc = {}
    if phone:
        update_doc["phone"] = phone
    if location:
        update_doc["location"] = location

    if not update_doc:
        return jsonify({"error": "Nothing to update"}), 400

    users.update_one(
        {"_id": user["_id"]},
        {"$set": {**update_doc, "updated_at": _now()}}
    )
    _log_user_activity(
    user.get("email"),
    "Updated profile information",
    "success",
    "low"
)
    return jsonify({"message": "Profile updated", "updated": update_doc}), 200



# =========================================================
# ✅ Run
# =========================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
