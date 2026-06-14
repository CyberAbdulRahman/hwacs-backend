# invite_service.py
import os
import secrets
from datetime import datetime, timedelta
from db import admin_invites_collection
from email_service import send_email  # assume you have send_email()

INVITE_TTL_MINUTES = 30

def create_admin_invite(email: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(minutes=INVITE_TTL_MINUTES)

    admin_invites_collection.insert_one({
        "token": token,
        "email": email,
        "used": False,
        "expires_at": expires_at,
        "created_at": datetime.utcnow(),
    })

    return token

def consume_admin_invite(token: str):
    doc = admin_invites_collection.find_one({"token": token})
    if not doc:
        return False, "Invalid activation token."

    if doc.get("used"):
        return False, "Activation link already used."

    if datetime.utcnow() > doc["expires_at"]:
        return False, "Activation link expired."

    admin_invites_collection.update_one({"token": token}, {"$set": {"used": True}})
    return True, doc["email"]

def send_admin_activation_email(email: str, token: str):
    frontend = (os.getenv("FRONTEND_URL") or "http://localhost:5173").rstrip("/")
    link = f"{frontend}/admin-activate?token={token}"

    subject = "HWACS Admin Activation Link"
    body = f"""
Your admin request has been approved ✅

Click this one-time activation link (expires in {INVITE_TTL_MINUTES} minutes):
{link}

If you did not request this, ignore this email.
"""
    return send_email(email, subject, body)
