import os
from datetime import datetime, timedelta, timezone
import jwt

JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret")
JWT_ALGORITHM = "HS256"

# 5 minutes inactivity/expiry for demo
JWT_EXPIRE_MINUTES = 5


def generate_jwt(payload: dict) -> str:
    data = payload.copy()

    now = datetime.now(timezone.utc)

    data["iat"] = now
    data["exp"] = now + timedelta(minutes=JWT_EXPIRE_MINUTES)

    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None