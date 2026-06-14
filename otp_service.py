
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple

# ✅ Support BOTH names (otp_collection OR otp_sessions)
try:
    from db import otp_collection as _otp_col
except Exception:
    from db import otp_sessions as _otp_col  # fallback

MAX_ATTEMPTS = 5
OTP_TTL_SECONDS = 60


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _generate_otp() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def _hash_otp(email: str, otp: str) -> str:
    data = f"{email}-{otp}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def create_otp_session(email: str, purpose: str = "") -> str:
    """
    ✅ app.py expects this
    - saves hashed otp in DB
    - returns OTP (so app.py can email it)
    """
    email = _normalize_email(email)
    otp = _generate_otp()

    doc = {
        "email": email,
        "otp_hash": _hash_otp(email, otp),
        "expires_at": datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS),
        "attempts": 0,
        "purpose": purpose,
        "created_at": datetime.utcnow(),
    }

    _otp_col.update_one({"email": email}, {"$set": doc}, upsert=True)
    return otp


def verify_otp_code(email: str, otp: str) -> Tuple[bool, str]:
    email = _normalize_email(email)
    otp = (otp or "").strip()

    record = _otp_col.find_one({"email": email})
    if not record:
        return False, "No OTP found. Please request a new code."

    expires_at = record.get("expires_at")
    if expires_at and expires_at < datetime.utcnow():
        _otp_col.delete_one({"email": email})
        return False, "OTP expired. Please request a new code."

    attempts = record.get("attempts", 0)
    if attempts >= MAX_ATTEMPTS:
        return False, "Too many invalid attempts. Please request a new code."

    if _hash_otp(email, otp) != record.get("otp_hash"):
        _otp_col.update_one({"email": email}, {"$inc": {"attempts": 1}})
        return False, "Invalid OTP. Please try again."

    _otp_col.delete_one({"email": email})
    return True, "OTP verified successfully."


def resend_otp_code(email: str, purpose: str = "") -> Optional[str]:
    email = _normalize_email(email)
    if not email:
        return None
    return create_otp_session(email=email, purpose=purpose)
