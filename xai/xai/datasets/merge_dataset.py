import csv
import re

BASE_CSV = "merged_payloads.csv"
EXTRA_TXT = "extra_payloads.txt"
OUT_CSV = "merged_training.csv"

# Treat these as "ambiguous single tokens" => keep them Normal (label=0)
AMBIGUOUS_NORMAL = {
    "'", "''", '"', '""', "`", "``", ",", "/", "//", "\\", "\\\\", ";", "#", "--", "-- -",
    "=", "==", "-",
}

# Add more benign/normal samples (safe UI/feature text)
MORE_NORMAL = [
    "sign in",
    "sign out",
    "create account",
    "reset password link sent",
    "email address required",
    "password must be at least 8 characters",
    "confirm your email",
    "verify your account",
    "otp sent to your email",
    "resend otp",
    "profile updated",
    "settings saved",
    "search by keyword",
    "filter applied",
    "sort by price",
    "add shipping address",
    "remove saved card",
    "payment pending",
    "order confirmed",
    "download invoice",
    "upload started",
    "upload failed",
    "try again in a moment",
    "rate your experience",
    "submit feedback",
    "contact support team",
    "ticket submitted",
    "view notifications",
    "mark all as read",
    "session timeout warning",
    "access token refreshed",
    "loading data",
    "request timed out",
    "server error",
    "maintenance mode",
]

def normalize_payload(s: str) -> str:
    # Keep exact payload for training, but normalize for dedupe comparisons
    return re.sub(r"\s+", " ", s.strip())

def read_base_rows(path: str):
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return rows, reader.fieldnames

def read_extra_payloads(path: str):
    payloads = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            payloads.append(line)
    return payloads

def main():
    base_rows, fieldnames = read_base_rows(BASE_CSV)

    # Ensure expected columns exist
    expected = ["id", "payload", "label", "attack_type", "notes"]
    if fieldnames != expected:
        # If columns differ, still try to work with them, but enforce output schema
        fieldnames = expected

    seen = set()
    max_id = -1

    cleaned_base = []
    for r in base_rows:
        payload = r.get("payload", "")
        key = normalize_payload(payload)
        if key in seen:
            continue
        seen.add(key)
        cleaned_base.append({
            "id": r.get("id", ""),
            "payload": payload,
            "label": r.get("label", "0"),
            "attack_type": r.get("attack_type", "Normal"),
            "notes": r.get("notes", ""),
        })
        try:
            max_id = max(max_id, int(r.get("id", -1)))
        except:
            pass

    next_id = max_id + 1 if max_id >= 0 else 0

    # Add extra payloads (from your own list) without generating new ones
    extra_payloads = read_extra_payloads(EXTRA_TXT)

    new_rows = []
    for p in extra_payloads:
        p_clean = normalize_payload(p)
        if not p_clean or p_clean in seen:
            continue

        if p_clean in AMBIGUOUS_NORMAL:
            label = "0"
            attack_type = "Normal"
            notes = "single token / ambiguous"
        else:
            label = "1"
            attack_type = "SQLi"
            notes = "user-provided sqli payload pattern"

        new_rows.append({
            "id": str(next_id),
            "payload": p,
            "label": label,
            "attack_type": attack_type,
            "notes": notes,
        })
        seen.add(p_clean)
        next_id += 1

    # Add extra benign samples
    for p in MORE_NORMAL:
        p_clean = normalize_payload(p)
        if p_clean in seen:
            continue
        new_rows.append({
            "id": str(next_id),
            "payload": p,
            "label": "0",
            "attack_type": "Normal",
            "notes": "",
        })
        seen.add(p_clean)
        next_id += 1

    all_rows = cleaned_base + new_rows

    with open(OUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "payload", "label", "attack_type", "notes"], quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"✅ Wrote {len(all_rows)} rows to {OUT_CSV}")
    print(f"   Added {len(new_rows)} new rows (extra list + more normal).")

if __name__ == "__main__":
    main()
