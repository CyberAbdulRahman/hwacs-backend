# reset_token_service.py
import os
import jwt
import secrets
from datetime import datetime, timedelta

RESET_TOKEN_TTL_MINUTES = 10
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"

def create_reset_token(email: str) -> str:
    email = (email or "").strip().lower()
    jti = secrets.token_hex(16)  # unique id so you can revoke/use-once if you want

    payload = {
        "sub": email,
        "jti": jti,
        "type": "password_reset",
        "exp": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_reset_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if payload.get("type") != "password_reset":
            return False, "Invalid token type", None
        return True, "OK", payload
    except jwt.ExpiredSignatureError:
        return False, "Reset link expired. Please request a new one.", None
    except Exception:
        return False, "Invalid reset link. Please request a new one.", None
