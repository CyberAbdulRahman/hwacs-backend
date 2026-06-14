import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from flask import Blueprint, jsonify, request
from pymongo import MongoClient
from pymongo.collection import Collection

bf_bp = Blueprint("bf_bp", __name__)

# -----------------------------
# Mongo Config
# -----------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("MONGO_DB", "hwacs_db")

COLLECTION_LOGIN_EVENTS = os.getenv("BF_LOGIN_COLLECTION", "login_events")


def _utc_now() -> datetime:
    return datetime.utcnow()


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "Z"


def _client_ip() -> str:
    # allow demo of fake attacker ip via X-Forwarded-For header
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _user_agent() -> str:
    return request.headers.get("User-Agent", "")


def _get_collection() -> Collection:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    return db[COLLECTION_LOGIN_EVENTS]


def _require_json() -> Dict[str, Any]:
    try:
        return request.get_json(force=True) or {}
    except Exception:
        return {}


# -----------------------------
# Brute-force Thresholds (DEMO)
# -----------------------------
# Window ke andar agar itni attempts + itna failure ratio ho => brute-force
DEFAULT_WINDOW_SECONDS = 60

BF_MIN_ATTEMPTS = 20          # >=20 attempts in window
BF_MIN_FAIL_RATE = 0.90       # 90%+ failures
BF_MIN_UNIQUE_USERS = 5       # >=5 different usernames tried
BF_MIN_RPS = 0.50             # >=0.50 req/sec (30 req/min)


def _analyze_events(events: List[Dict[str, Any]], window_seconds: int) -> Tuple[bool, Dict[str, Any], List[str]]:
    attempts = len(events)
    fails = sum(1 for e in events if not bool(e.get("success", False)))
    fail_rate = (fails / attempts) if attempts > 0 else 0.0

    usernames = [str(e.get("username", "")).strip().lower() for e in events if e.get("username")]
    unique_usernames = len(set([u for u in usernames if u]))

    # request rate
    rps = attempts / max(window_seconds, 1)

    # avg interval (optional explainability)
    times = []
    for e in events:
        ts = e.get("ts")
        if isinstance(ts, datetime):
            times.append(ts)
    times.sort()
    avg_interval = None
    if len(times) >= 2:
        diffs = [(times[i] - times[i - 1]).total_seconds() for i in range(1, len(times))]
        avg_interval = sum(diffs) / len(diffs) if diffs else None

    # decision
    is_bruteforce = (
        attempts >= BF_MIN_ATTEMPTS
        and fail_rate >= BF_MIN_FAIL_RATE
        and (unique_usernames >= BF_MIN_UNIQUE_USERS or rps >= BF_MIN_RPS)
    )

    features = {
        "attempts": attempts,
        "fails": fails,
        "fail_rate": round(fail_rate, 4),
        "unique_usernames": unique_usernames,
        "requests_per_second": round(rps, 4),
        "avg_interval_seconds": (round(avg_interval, 4) if avg_interval is not None else None),
        "window_seconds": window_seconds,
    }

    reasons = []
    if attempts >= BF_MIN_ATTEMPTS:
        reasons.append(f"High attempts: {attempts} in {window_seconds}s (threshold: {BF_MIN_ATTEMPTS}+).")
    else:
        reasons.append(f"Attempts low: {attempts} in {window_seconds}s (needs {BF_MIN_ATTEMPTS}+).")

    if fail_rate >= BF_MIN_FAIL_RATE:
        reasons.append(f"High failure rate: {round(fail_rate*100,2)}% (threshold: {int(BF_MIN_FAIL_RATE*100)}%+).")
    else:
        reasons.append(f"Failure rate normal: {round(fail_rate*100,2)}% (below {int(BF_MIN_FAIL_RATE*100)}%).")

    if unique_usernames >= BF_MIN_UNIQUE_USERS:
        reasons.append(f"Many usernames tried: {unique_usernames} (threshold: {BF_MIN_UNIQUE_USERS}+).")
    else:
        reasons.append(f"Usernames tried: {unique_usernames} (needs {BF_MIN_UNIQUE_USERS}+ OR high RPS).")

    if rps >= BF_MIN_RPS:
        reasons.append(f"High request rate: {round(rps,2)} req/sec (threshold: {BF_MIN_RPS}+).")
    else:
        reasons.append(f"Request rate normal: {round(rps,2)} req/sec (below {BF_MIN_RPS}).")

    return is_bruteforce, features, reasons


# -----------------------------
# Routes
# -----------------------------

@bf_bp.get("/api/bruteforce/health")
def bf_health():
    try:
        col = _get_collection()
        col.estimated_document_count()  # quick check
        return jsonify({
            "ok": True,
            "mongo_uri": MONGO_URI,
            "db": DB_NAME,
            "collection": COLLECTION_LOGIN_EVENTS,
            "thresholds": {
                "window_seconds_default": DEFAULT_WINDOW_SECONDS,
                "min_attempts": BF_MIN_ATTEMPTS,
                "min_fail_rate": BF_MIN_FAIL_RATE,
                "min_unique_usernames": BF_MIN_UNIQUE_USERS,
                "min_rps": BF_MIN_RPS,
            }
        }), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ✅ Honeypot Login (Demo)
# Logs EVERY attempt into Mongo.
@bf_bp.post("/api/honeypot/login")
def honeypot_login():
    data = _require_json()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()

    ip = _client_ip()
    ua = _user_agent()

    # demo: you can make ONE valid pair for "normal success"
    # (helps to show difference between legit vs brute-force)
    success = (username == "demo_user" and password == "demo_pass")

    doc = {
        "ts": _utc_now(),
        "ip": ip,
        "username": username,
        "success": bool(success),
        "user_agent": ua,
        "source": "honeypot_login",
    }

    col = _get_collection()
    col.insert_one(doc)

    if success:
        return jsonify({"ok": True, "message": "Login success (demo)."}), 200

    return jsonify({"ok": False, "message": "Invalid credentials (honeypot)."}), 401


# ✅ Brute-force Report (Explainable)
@bf_bp.get("/api/bruteforce/report")
def bruteforce_report_get():
    ip = request.args.get("ip") or _client_ip()
    window_seconds = int(request.args.get("window") or DEFAULT_WINDOW_SECONDS)

    since = _utc_now() - timedelta(seconds=window_seconds)

    col = _get_collection()
    events = list(col.find(
        {"ip": ip, "ts": {"$gte": since}},
        {"_id": 0}
    ).sort("ts", 1))

    is_bf, features, reasons = _analyze_events(events, window_seconds)

    attack_type = "Brute Force" if is_bf else "Normal"
    severity = "HIGH" if (is_bf and features["attempts"] >= 50) else ("MEDIUM" if is_bf else "LOW")

    return jsonify({
        "created_at": _iso(_utc_now()),
        "ip": ip,
        "attack_type": attack_type,
        "severity": severity,
        "features": features,
        "explainable_reasons": reasons,
        "thresholds_used": {
            "min_attempts": BF_MIN_ATTEMPTS,
            "min_fail_rate": BF_MIN_FAIL_RATE,
            "min_unique_usernames": BF_MIN_UNIQUE_USERS,
            "min_rps": BF_MIN_RPS,
            "window_seconds": window_seconds,
        }
    }), 200
