import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

# ===============================
# SMTP CONFIG
# ===============================
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

APP_NAME = os.getenv("APP_NAME", "HWACS Security")
SENDER_NAME = os.getenv("SENDER_NAME", "HWACS Security")


# ===============================
# COMMON SMTP SENDER
# ===============================
def _send_email(msg: EmailMessage) -> bool:
    if not (SMTP_USER and SMTP_PASS):
        print("❌ SMTP_USER / SMTP_PASS missing in .env")
        return False

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        return True
    except Exception as e:
        print("❌ Email sending failed:", e)
        return False


# =========================================================
# LOGIN / VERIFY OTP EMAIL
# =========================================================
def send_otp_email(to_email: str, otp: str) -> bool:
    msg = EmailMessage()

    msg["Subject"] = "HWACS Verification Code"
    msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
    msg["To"] = to_email

    text_fallback = (
        f"Your HWACS verification code is: {otp}\n\n"
        "This code will expire in 30 seconds.\n"
        "If you didn’t request this, ignore this email."
    )
    msg.set_content(text_fallback)

    html = f"""
    <div style="font-family: Arial; background:#f6f9fc; padding:24px;">
      <div style="max-width:520px; margin:auto; background:#ffffff;
           border-radius:12px; padding:24px; border:1px solid #e6eef7;">

        <h2 style="text-align:center; color:#0f172a;">HWACS Verification</h2>

        <p style="text-align:center; color:#475569;">
          Use this code to complete your sign-in
        </p>

        <div style="text-align:center; margin:22px 0;">
          <div style="display:inline-block; padding:14px 20px;
              border-radius:10px; background:#e0f2fe; border:1px solid #bae6fd;">
            <span style="font-size:26px; letter-spacing:6px;
                font-weight:bold; color:#0284c7;">
              {otp}
            </span>
          </div>
        </div>

        <p style="color:#334155;">This code expires in <b>30 seconds</b>.</p>

        <hr style="border:none; border-top:1px solid #e6eef7;" />

        <p style="font-size:12px; color:#94a3b8;">
          © {APP_NAME} • Security Notification
        </p>
      </div>
    </div>
    """

    msg.add_alternative(html, subtype="html")

    return _send_email(msg)


# =========================================================
# RESET PASSWORD OTP
# =========================================================
# def send_reset_password_email(to_email: str, otp: str, ttl_minutes: int = 10) -> bool:
#     msg = EmailMessage()

#     msg["Subject"] = "HWACS Password Reset Code"
#     msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
#     msg["To"] = to_email

#     text_fallback = (
#         f"Your HWACS password reset code is: {otp}\n\n"
#         f"This code will expire in {ttl_minutes} minutes."
#     )
#     msg.set_content(text_fallback)

#     html = f"""
#     <div style="font-family: Arial; background:#f6f9fc; padding:24px;">
#       <div style="max-width:520px; margin:auto; background:#ffffff;
#            border-radius:12px; padding:24px; border:1px solid #e6eef7;">

#         <h2 style="text-align:center; color:#0f172a;">Reset Your Password</h2>

#         <p style="text-align:center; color:#475569;">
#           Use the code below to reset your password``
#         </p>

#         <div style="text-align:center; margin:22px 0;">
#           <div style="display:inline-block; padding:14px 20px;
#               border-radius:10px; background:#fee2e2; border:1px solid #fecaca;">
#             <span style="font-size:26px; letter-spacing:6px;
#                 font-weight:bold; color:#b91c1c;">
#               {otp}
#             </span>
#           </div>
#         </div>

#         <p style="color:#334155;">
#           This code expires in <b>{ttl_minutes} minutes</b>.
#         </p>

#         <hr style="border:none; border-top:1px solid #e6eef7;" />

#         <p style="font-size:12px; color:#94a3b8;">
#           © {APP_NAME} • Security Notification
#         </p>
#       </div>
#     </div>
#     """

#     msg.add_alternative(html, subtype="html")

#     return _send_email(msg)


# =========================================================
# OWNER → ADMIN APPROVAL REQUEST
# =========================================================
def send_owner_admin_request_email(
    owner_email: str,
    admin_email: str,
    admin_name: str,
    approve_link: str,
    reject_link: str
) -> bool:

    msg = EmailMessage()
    msg["Subject"] = "HWACS: Admin Signup Request Approval"
    msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
    msg["To"] = owner_email

    msg.set_content(f"""
Hello Owner,

New admin signup request received:

Name: {admin_name}
Email: {admin_email}

Approve: {approve_link}
Reject: {reject_link}

Regards,
HWACS
""")

    html = f"""
    <div style="font-family:Arial; background:#f6f9fc; padding:24px;">
      <div style="max-width:520px; margin:auto; background:#ffffff;
           border-radius:12px; padding:24px; border:1px solid #e6eef7;">

        <h2 style="text-align:center; color:#0f172a;">Admin Signup Request</h2>

        <p>A new admin wants access to the system:</p>

        <ul style="color:#334155;">
          <li><b>Name:</b> {admin_name}</li>
          <li><b>Email:</b> {admin_email}</li>
        </ul>

        <div style="text-align:center; margin:24px 0;">
          <a href="{approve_link}"
             style="background:#16a34a; color:white; padding:12px 18px;
                    text-decoration:none; border-radius:8px;">
            ✅ Approve
          </a>

          &nbsp;

          <a href="{reject_link}"
             style="background:#dc2626; color:white; padding:12px 18px;
                    text-decoration:none; border-radius:8px;">
            ❌ Reject
          </a>
        </div>

        <hr style="border:none; border-top:1px solid #e6eef7;" />

        <p style="font-size:12px; color:#94a3b8;">
          © {APP_NAME} • Admin Control
        </p>
      </div>
    </div>
    """

    msg.add_alternative(html, subtype="html")

    return _send_email(msg)


# =========================================================
# ADMIN ACTIVATION EMAIL
# =========================================================
def send_admin_approved_activation_email(
    admin_email: str,
    activation_link: str
) -> bool:

    msg = EmailMessage()
    msg["Subject"] = "HWACS: Admin Approved – Activate Your Account"
    msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
    msg["To"] = admin_email

    msg.set_content(f"""
Hello,

Your admin request has been approved.

Activate your account using the link below:
{activation_link}

Regards,
HWACS
""")

    html = f"""
    <div style="font-family:Arial; background:#f6f9fc; padding:24px;">
      <div style="max-width:520px; margin:auto; background:#ffffff;
           border-radius:12px; padding:24px; border:1px solid #e6eef7;">

        <h2 style="text-align:center; color:#0f172a;">Admin Access Approved</h2>

        <p>Your admin request has been approved by the owner.</p>

        <div style="text-align:center; margin:24px 0;">
          <a href="{activation_link}"
             style="background:#2563eb; color:white; padding:14px 22px;
                    text-decoration:none; border-radius:10px;">
            Activate Account
          </a>
        </div>

        <p style="font-size:12px; color:#64748b;">
          If you did not request this, you can ignore this email.
        </p>

        <hr style="border:none; border-top:1px solid #e6eef7;" />

        <p style="font-size:12px; color:#94a3b8;">
          © {APP_NAME} • Security Notification
        </p>
      </div>
    </div>
    """

    msg.add_alternative(html, subtype="html")

    return _send_email(msg)

# =========================================================
# RESET PASSWORD LINK (NEW SECURE FLOW)
# =========================================================
def send_reset_link_email(to_email: str, reset_link: str, ttl_minutes: int = 10) -> bool:
    msg = EmailMessage()

    msg["Subject"] = "HWACS Password Reset"
    msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
    msg["To"] = to_email

    # Fallback text (for email clients that don't support HTML)
    text_fallback = (
        f"You requested a password reset.\n\n"
        f"Click the link below to reset your password:\n"
        f"{reset_link}\n\n"
        f"This link will expire in {ttl_minutes} minutes.\n"
        f"If you did not request this, ignore this email."
    )

    msg.set_content(text_fallback)

    # Beautiful HTML version (same style as your OTP emails)
    html = f"""
    <div style="font-family: Arial; background:#f6f9fc; padding:24px;">
      <div style="max-width:520px; margin:auto; background:#ffffff;
           border-radius:12px; padding:24px; border:1px solid #e6eef7;">

        <h2 style="text-align:center; color:#0f172a;">
          Reset Your Password
        </h2>

        <p style="text-align:center; color:#475569;">
          We received a request to reset your password.
        </p>

        <div style="text-align:center; margin:28px 0;">
          <a href="{reset_link}"
             style="display:inline-block;
                    background:#2563eb;
                    color:white;
                    padding:14px 22px;
                    border-radius:10px;
                    text-decoration:none;
                    font-weight:bold;">
            Reset Password
          </a>
        </div>

        <p style="color:#334155;">
          This link will expire in <b>{ttl_minutes} minutes</b>.
        </p>

        <p style="color:#64748b; font-size:14px;">
          If you didn’t request this, you can safely ignore this email.
        </p>

        <hr style="border:none; border-top:1px solid #e6eef7;" />

        <p style="font-size:12px; color:#94a3b8;">
          © {APP_NAME} • Security Notification
        </p>

      </div>
    </div>
    """
    
    

    msg.add_alternative(html, subtype="html")

    return _send_email(msg)
  
  
def send_attack_alert_email(to_email, honeypot, method, url, payload, severity="HIGH"):
    import os
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    # ✅ If your existing email_service.py uses different env names,
    # replace these with the same names already used there.
    smtp_email = os.getenv("SMTP_USER") or os.getenv("EMAIL_USER")
    smtp_password = os.getenv("SMTP_PASS") or os.getenv("EMAIL_PASS")

    if not smtp_email or not smtp_password:
        raise ValueError("Missing EMAIL_USER or EMAIL_PASS in environment")

    short_payload = (payload or "-")[:500]

    subject = f"HWACS Alert: {severity} {honeypot} Attack Detected"

    body = f"""
A suspicious attack has been detected by HWACS.

Honeypot: {honeypot}
Severity: {severity}
Method: {method}
URL: {url}

Payload:
{short_payload}

Please login to your HWACS dashboard to review the full attack details.
""".strip()

    msg = MIMEMultipart()
    msg["From"] = smtp_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(smtp_email, smtp_password)
    server.sendmail(smtp_email, to_email, msg.as_string())
    server.quit()