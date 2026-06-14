# # auth_middleware.py
# from functools import wraps
# from flask import request, jsonify
# from jwt_service import verify_jwt

# def _extract_user_id(payload: dict):
#     # common patterns
#     if not isinstance(payload, dict):
#         return None

#     if payload.get("id"):
#         return payload.get("id")
#     if payload.get("_id"):
#         return payload.get("_id")
#     if payload.get("user_id"):
#         return payload.get("user_id")
#     if payload.get("sub"):
#         return payload.get("sub")

#     # nested user object pattern: { user: { id: ... } }
#     u = payload.get("user")
#     if isinstance(u, dict):
#         return u.get("id") or u.get("_id") or u.get("user_id")

#     return None

# def auth_required(fn):
#     @wraps(fn)
#     def wrapper(*args, **kwargs):
#         auth = request.headers.get("Authorization", "")
#         if not auth.startswith("Bearer "):
#             return jsonify({"error": "Missing token"}), 401

#         token = auth.split(" ", 1)[1].strip()
#         try:
#             payload = verify_jwt(token)
#         except Exception:
#             return jsonify({"error": "Invalid/Expired token"}), 401

#         user_id = _extract_user_id(payload)
#         role = payload.get("role") or (payload.get("user") or {}).get("role")

#         if not user_id:
#             return jsonify({"error": "User id not found in token"}), 401

#         # normalize (important!)
#         request.user = {
#             "id": str(user_id),
#             "role": role or "user",
#             "raw": payload
#         }

#         return fn(*args, **kwargs)
#     return wrapper

# def admin_required(fn):
#     @wraps(fn)
#     @auth_required
#     def wrapper(*args, **kwargs):
#         if getattr(request, "user", {}).get("role") != "admin":
#             return jsonify({"error": "Admin only"}), 403
#         return fn(*args, **kwargs)
#     return wrapper

from functools import wraps
from flask import request, jsonify
from jwt_service import verify_jwt

def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401

        token = auth.split(" ", 1)[1].strip()
        try:
            payload = verify_jwt(token)
        except Exception:
            return jsonify({"error": "Invalid/Expired token"}), 401

        uid = payload.get("id") or payload.get("_id") or payload.get("user_id")
        if not uid or str(uid).lower() == "none":
            return jsonify({"error": "User id not found in token"}), 401

        request.user = payload
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @auth_required
    def wrapper(*args, **kwargs):
        if getattr(request, "user", {}).get("role") != "admin":
            return jsonify({"error": "Admin only"}), 403
        return fn(*args, **kwargs)
    return wrapper


