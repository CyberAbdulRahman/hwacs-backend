import random
import csv
import argparse
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient

# Label convention (separate from your 0-3 payload classes)
# 0 = Normal login behavior
# 1 = Brute Force behavior
LABEL_NORMAL = 0
LABEL_BRUTEFORCE = 1

COMMON_USERS = [
    "admin", "administrator", "root", "test", "user", "guest",
    "rayyan", "demo", "support", "dev", "manager"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "curl/8.0",
    "python-requests/2.31.0",
]

ENDPOINTS = ["/login", "/api/auth/login", "/admin/login"]

def rand_ip():
    # random public-like ip (avoid 127.x)
    return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def rand_password():
    base = ["123456", "password", "admin123", "qwerty", "letmein", "welcome", "111111"]
    # some random variants
    if random.random() < 0.7:
        return random.choice(base)
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(random.randint(6, 12)))

def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()

def make_normal_events(count: int, start: datetime):
    events = []
    for _ in range(count):
        dt = start + timedelta(seconds=random.randint(0, 3600))
        username = random.choice(COMMON_USERS)
        ip = rand_ip()

        # Normal traffic: mostly low attempts and some successes
        success = True if random.random() < 0.65 else False

        events.append({
            "created_at": iso(dt),
            "event_type": "auth_login",
            "ip": ip,
            "username": username,
            "endpoint": random.choice(ENDPOINTS),
            "success": success,
            "attempt_id": random.randint(100000, 999999),
            "user_agent": random.choice(USER_AGENTS),
            "label": LABEL_NORMAL,
            # "explainable_features" can be filled later by detector
        })
    return events

def make_bruteforce_events(attacker_ips: int, users_per_ip: int, attempts_per_user: int, start: datetime):
    """
    Generates bursts:
    - same IP
    - multiple usernames
    - many attempts in short time window
    - mostly failures
    """
    events = []
    for _ in range(attacker_ips):
        ip = rand_ip()
        base_dt = start + timedelta(seconds=random.randint(0, 600))  # early in hour
        for u in range(users_per_ip):
            username = random.choice(COMMON_USERS) if random.random() < 0.7 else f"user{random.randint(1,999)}"
            for a in range(attempts_per_user):
                # tight burst: 0-3 seconds apart
                dt = base_dt + timedelta(seconds=(u * attempts_per_user + a) * random.randint(0, 3))
                # brute force: mostly failures, rare success
                success = True if random.random() < 0.03 else False

                events.append({
                    "created_at": iso(dt),
                    "event_type": "auth_login",
                    "ip": ip,
                    "username": username,
                    "endpoint": random.choice(ENDPOINTS),
                    "success": success,
                    "attempt_id": random.randint(100000, 999999),
                    "user_agent": random.choice(USER_AGENTS),
                    "label": LABEL_BRUTEFORCE,
                })
    return events

def save_csv(path: str, rows):
    fieldnames = ["created_at", "event_type", "ip", "username", "endpoint", "success", "attempt_id", "user_agent", "label"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def insert_mongo(uri: str, db_name: str, collection: str, rows):
    client = MongoClient(uri)
    col = client[db_name][collection]
    if rows:
        col.insert_many(rows)
    return col.count_documents({})

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mongo", default="mongodb://localhost:27017")
    ap.add_argument("--db", default="hwacs_db")
    ap.add_argument("--collection", default="bruteforce_events")
    ap.add_argument("--out_csv", default="datasets/bruteforce_events.csv")
    ap.add_argument("--normal", type=int, default=500)
    ap.add_argument("--attacker_ips", type=int, default=6)
    ap.add_argument("--users_per_ip", type=int, default=6)
    ap.add_argument("--attempts_per_user", type=int, default=25)
    args = ap.parse_args()

    start = datetime.now(timezone.utc) - timedelta(hours=1)

    normal = make_normal_events(args.normal, start)
    brute = make_bruteforce_events(args.attacker_ips, args.users_per_ip, args.attempts_per_user, start)

    rows = normal + brute
    random.shuffle(rows)

    # ensure datasets folder exists-ish
    try:
        import os
        os.makedirs("datasets", exist_ok=True)
    except Exception:
        pass

    save_csv(args.out_csv, rows)
    total = insert_mongo(args.mongo, args.db, args.collection, rows)

    print("✅ Generated events:", len(rows))
    print("✅ Saved CSV:", args.out_csv)
    print(f"✅ Inserted into Mongo: {args.db}.{args.collection}")
    print("✅ Total docs in collection now:", total)

if __name__ == "__main__":
    main()
