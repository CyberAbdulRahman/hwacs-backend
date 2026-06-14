# # reset_password_service.py
# import hashlib
# import secrets
# from datetime import datetime, timedelta

# from db import password_reset_collection, users_collection
# from email_service import send_reset_password_email

# RESET_TTL_MINUTES = 10
# MAX_ATTEMPTS = 5


# def _normalize_email(email: str) -> str:
#     return (email or "").strip().lower()


# def _generate_otp() -> str:
#     return f"{secrets.randbelow(10**6):06d}"


# def _hash_otp(email: str, otp: str) -> str:
#     data = f"reset-{email}-{otp}".encode("utf-8")
#     return hashlib.sha256(data).hexdigest()


# def create_and_send_reset_otp(email: str) -> bool:
#     """
#     ✅ security: response should be same even if user not exist
#     """
#     email = _normalize_email(email)

#     user = users_collection.find_one({"email": email})
#     if not user:
#         return True  # don't reveal existence

#     otp = _generate_otp()
#     otp_hash = _hash_otp(email, otp)
#     expires_at = datetime.utcnow() + timedelta(minutes=RESET_TTL_MINUTES)

#     doc = {
#         "email": email,
#         "otp_hash": otp_hash,
#         "expires_at": expires_at,
#         "attempts": 0,
#         "created_at": datetime.utcnow(),
#     }

#     password_reset_collection.update_one({"email": email}, {"$set": doc}, upsert=True)
#     return send_reset_password_email(email, otp, RESET_TTL_MINUTES)


# def verify_reset_otp(email: str, otp: str):
#     email = _normalize_email(email)
#     otp = (otp or "").strip()

#     record = password_reset_collection.find_one({"email": email})
#     if not record:
#         return False, "No reset request found. Please request again."

#     expires_at = record.get("expires_at")
#     if expires_at and expires_at < datetime.utcnow():
#         password_reset_collection.delete_one({"email": email})
#         return False, "Reset code expired. Please request a new code."

#     attempts = record.get("attempts", 0)
#     if attempts >= MAX_ATTEMPTS:
#         return False, "Too many invalid attempts. Please request a new code."

#     otp_hash = _hash_otp(email, otp)
#     if otp_hash != record.get("otp_hash"):
#         password_reset_collection.update_one({"email": email}, {"$inc": {"attempts": 1}})
#         return False, "Invalid reset code. Please try again."

#     return True, "Reset code verified."


# def consume_reset_and_update_password(email: str, otp: str, new_password_hash: str):
#     """
#     OTP verify + password update + reset record delete
#     """
#     ok, msg = verify_reset_otp(email, otp)
#     if not ok:
#         return False, msg

#     email = _normalize_email(email)

#     user = users_collection.find_one({"email": email})
#     if not user:
#         password_reset_collection.delete_one({"email": email})
#         return False, "Unable to reset password. Please request again."

#     users_collection.update_one(
#         {"email": email},
#         {"$set": {"password_hash": new_password_hash, "updated_at": datetime.utcnow()}},
#     )

#     password_reset_collection.delete_one({"email": email})
#     return True, "Password reset successfully. Please login."
# reset_password_service.py
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Tuple

# ✅ Support BOTH names (password_reset_sessions OR password_reset_collection)
try:
    from db import password_reset_sessions as _reset_col
except Exception:
    from db import password_reset_collection as _reset_col  # fallback

RESET_TTL_MINUTES = 10
MAX_ATTEMPTS = 5


def _normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def _generate_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def _hash_code(email: str, code: str) -> str:
    data = f"reset-{email}-{code}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def create_reset_session(email: str) -> str:
    """
    ✅ app.py expects this
    returns reset code (app.py emails it)
    """
    email = _normalize_email(email)
    code = _generate_code()

    doc = {
        "email": email,
        "code_hash": _hash_code(email, code),
        "expires_at": datetime.utcnow() + timedelta(minutes=RESET_TTL_MINUTES),
        "attempts": 0,
        "created_at": datetime.utcnow(),
    }

    _reset_col.update_one({"email": email}, {"$set": doc}, upsert=True)
    return code


def verify_reset_code(email: str, code: str) -> Tuple[bool, str]:
    email = _normalize_email(email)
    code = (code or "").strip()

    record = _reset_col.find_one({"email": email})
    if not record:
        return False, "No reset request found. Please request again."

    expires_at = record.get("expires_at")
    if expires_at and expires_at < datetime.utcnow():
        _reset_col.delete_one({"email": email})
        return False, "Reset code expired. Please request a new code."

    attempts = record.get("attempts", 0)
    if attempts >= MAX_ATTEMPTS:
        return False, "Too many invalid attempts. Please request a new code."

    if _hash_code(email, code) != record.get("code_hash"):
        _reset_col.update_one({"email": email}, {"$inc": {"attempts": 1}})
        return False, "Invalid reset code. Please try again."

    return True, "Reset code verified."


def set_new_password(email: str, code: str, new_password: str, users, admins):
    """
    ✅ app.py expects this signature:
    set_new_password(email, code, new_password, users=users, admins=admins)

    NOTE: currently your project stores plain passwords in app.py.
    So we set password as plain too (you can hash later).
    """
    ok, msg = verify_reset_code(email=email, code=code)
    if not ok:
        return False, msg

    email = _normalize_email(email)

    # update in users OR admins
    updated = False

    if users.find_one({"email": email}):
        users.update_one(
            {"email": email},
            {"$set": {"password": new_password, "updated_at": datetime.utcnow()}},
        )
        updated = True

    if admins.find_one({"email": email}):
        admins.update_one(
            {"email": email},
            {"$set": {"password": new_password, "updated_at": datetime.utcnow()}},
        )
        updated = True

    _reset_col.delete_one({"email": email})

    if not updated:
        return False, "Account not found."

    return True, "Password updated successfully."
