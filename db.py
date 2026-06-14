# # db.py
# import os
# from dotenv import load_dotenv
# from pymongo import MongoClient

# load_dotenv()

# MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
# DB_NAME = os.getenv("DB_NAME", "hwacs_db")

# client = MongoClient(MONGO_URI)
# db = client[DB_NAME]
# sites = db["sites"]
# attacks = db["attacks"]
# # ============================
# # CORE COLLECTIONS
# # ============================

# users_collection = db["users"]
# users_collection.create_index("email", unique=True)

# otp_collection = db["user_opts"]
# otp_collection.create_index("expiresAt", expireAfterSeconds=0)

# password_reset_collection = db["password_reset_codes"]

# # ============================
# # ADMIN FLOW COLLECTIONS
# # ============================

# admin_requests_collection = db["admin_requests"]
# admin_invites_collection = db["admin_invites"]

# admin_invites_collection.create_index("token", unique=True)
# admin_invites_collection.create_index("expires_at", expireAfterSeconds=0)

# admins_collection = db["admins"]
# admins_collection.create_index("email", unique=True)

# # ============================
# # ✅ ALIASES (THIS FIXES YOUR ERROR)
# # ============================

# users = users_collection
# admins = admins_collection
# otp_sessions = otp_collection
# password_reset_sessions = password_reset_collection
# admin_requests = admin_requests_collection
# admin_invites = admin_invites_collection

# db.py
import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "hwacs_db")

if not MONGO_URI:
    raise RuntimeError("MONGO_URI is missing in .env file")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

# ============================
# CORE COLLECTIONS
# ============================

users_collection = db["users"]
admins_collection = db["admins"]
sites_collection = db["sites"]
attacks_collection = db["attacks"]
notifications_collection = db["notifications"]
site_pages_collection = db["site_pages"]

otp_collection = db["user_opts"]
password_reset_collection = db["password_reset_codes"]

# ============================
# ADMIN FLOW COLLECTIONS
# ============================

admin_requests_collection = db["admin_requests"]
admin_invites_collection = db["admin_invites"]

# ============================
# INDEXES
# ============================

try:
    users_collection.create_index("email", unique=True)
except Exception as e:
    print("Users email index warning:", str(e))

try:
    admins_collection.create_index("email", unique=True)
except Exception as e:
    print("Admins email index warning:", str(e))

try:
    otp_collection.create_index("expiresAt", expireAfterSeconds=0)
except Exception as e:
    print("OTP TTL index warning:", str(e))

try:
    admin_invites_collection.create_index("token", unique=True)
except Exception as e:
    print("Admin invite token index warning:", str(e))

try:
    admin_invites_collection.create_index("expires_at", expireAfterSeconds=0)
except Exception as e:
    print("Admin invite TTL index warning:", str(e))

try:
    site_pages_collection.create_index(
        [("site_id", 1), ("path", 1)],
        unique=True
    )
except Exception as e:
    print("Site pages index warning:", str(e))

# ============================
# ALIASES
# ============================

users = users_collection
admins = admins_collection
sites = sites_collection
attacks = attacks_collection
notifications = notifications_collection
site_pages = site_pages_collection

otp_sessions = otp_collection
password_reset_sessions = password_reset_collection

admin_requests = admin_requests_collection
admin_invites = admin_invites_collection