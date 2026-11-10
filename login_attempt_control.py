import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ==========================================
# LOGIN ATTEMPT CONTROL SYSTEM
# ==========================================

MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PBKDF2_ITERATIONS = 200_000

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "security_audit.log"

LOG_DIR.mkdir(exist_ok=True)

# ==========================================
# USER ACCOUNT MANAGEMENT
# ==========================================

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )


def create_user(password):
    salt = os.urandom(16)
    return {
        "salt": salt,
        "password_hash": hash_password(password, salt)
    }


USERS = {
    "alice": create_user("AliceSecure123!"),
    "admin": create_user("AdminSecure123!")
}

# ==========================================
# SECURITY TRACKING
# ==========================================

failed_attempts = {}
ip_failed_attempts = {}
account_locks = {}
ip_locks = {}


# ==========================================
# AUDIT LOGGING
# ==========================================

def log_event(event, username, ip, details):

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "username": username,
        "ip_address": ip,
        "details": details
    }

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(entry) + "\n")

    print(f"[AUDIT] {event}: {details}")


# ==========================================
# LOCKOUT MANAGEMENT
# ==========================================

def check_lock(lock_dictionary, key):

    lock_time = lock_dictionary.get(key)

    if lock_time is None:
        return False

    now = datetime.now(timezone.utc)

    if now < lock_time:
        remaining = int((lock_time - now).total_seconds())
        return remaining + 1

    del lock_dictionary[key]

    if lock_dictionary is account_locks:
        failed_attempts.pop(key, None)
        log_event(
            "LOCKOUT_EXPIRED",
            key,
            "N/A",
            "Account lockout expired."
        )

    elif lock_dictionary is ip_locks:
        ip_failed_attempts.pop(key, None)
        log_event(
            "IP_LOCKOUT_EXPIRED",
            "N/A",
            key,
            "IP lockout expired."
        )

    return False


# ==========================================
# LOGIN AUTHENTICATION
# ==========================================

def attempt_login(username, password, ip):

    username = username.strip().lower()
    ip = ip.strip()

    account_remaining = check_lock(account_locks, username)
    ip_remaining = check_lock(ip_locks, ip)

    if account_remaining or ip_remaining:

        remaining = max(
            account_remaining or 0,
            ip_remaining or 0
        )

        log_event(
            "LOGIN_BLOCKED",
            username,
            ip,
            f"Active lockout. {remaining} seconds remaining."
        )

        print("\n[BLOCKED] Login rejected due to active lockout.")
        print(f"Remaining time: {remaining} seconds")
        return False

    user = USERS.get(username)

    # Use a dummy hash for unknown usernames.
    if user is None:
        salt = b"LoginSystemDummySalt"
        expected_hash = hash_password(
            "DummyPassword123!",
            salt
        )
    else:
        salt = user["salt"]
        expected_hash = user["password_hash"]

    supplied_hash = hash_password(password, salt)

    password_valid = hmac.compare_digest(
        supplied_hash,
        expected_hash
    )

    if user is not None and password_valid:

        failed_attempts.pop(username, None)
        ip_failed_attempts.pop(ip, None)

        log_event(
            "LOGIN_SUCCESS",
            username,
            ip,
            "Authentication successful."
        )

        print("\n[SUCCESS] Login successful!")
        print(f"Welcome, {username}!")

        return True

    # Record failed attempts.
    failed_attempts[username] = (
        failed_attempts.get(username, 0) + 1
    )

    ip_failed_attempts[ip] = (
        ip_failed_attempts.get(ip, 0) + 1
    )

    user_count = failed_attempts[username]
    ip_count = ip_failed_attempts[ip]

    log_event(
        "LOGIN_FAILURE",
        username,
        ip,
        f"Username failures: {user_count}, IP failures: {ip_count}"
    )

    print("\n[FAILED] Invalid username or password.")
    print(f"Username failures: {user_count}/{MAX_ATTEMPTS}")
    print(f"IP failures: {ip_count}/{MAX_ATTEMPTS}")

    # Account lockout.
    if user_count >= MAX_ATTEMPTS:

        account_locks[username] = (
            datetime.now(timezone.utc)
            + timedelta(minutes=LOCKOUT_MINUTES)
        )

        log_event(
            "ACCOUNT_LOCKOUT",
            username,
            ip,
            f"Account locked for {LOCKOUT_MINUTES} minutes."
        )

        print("\n[SECURITY ALERT] ACCOUNT LOCKED!")

    # IP lockout.
    if ip_count >= MAX_ATTEMPTS:

        ip_locks[ip] = (
            datetime.now(timezone.utc)
            + timedelta(minutes=LOCKOUT_MINUTES)
        )

        log_event(
            "IP_LOCKOUT",
            username,
            ip,
            f"IP blocked for {LOCKOUT_MINUTES} minutes."
        )

        print("[SECURITY ALERT] IP ADDRESS BLOCKED!")

    return False


# ==========================================
# BRUTE-FORCE SIMULATION
# ==========================================

def simulate_brute_force():

    username = "alice"
    ip = "192.0.2.25"

    print("\n====================================")
    print(" BRUTE-FORCE ATTACK SIMULATION")
    print("====================================")

    print(f"Target username: {username}")
    print(f"Source IP: {ip}")

    for attempt in range(1, MAX_ATTEMPTS + 1):

        print(f"\nAttack attempt {attempt}/{MAX_ATTEMPTS}")

        attempt_login(
            username,
            "WrongPassword123!",
            ip
        )

    print("\n====================================")
    print(" SIMULATION COMPLETED")
    print("====================================")

    print("Expected result: Account and IP locked.")
    print(f"Lockout duration: {LOCKOUT_MINUTES} minutes")


# ==========================================
# SECURITY STATUS
# ==========================================

def show_security_status():

    print("\n========== SECURITY STATUS ==========")

    print("\nFailed username attempts:")

    if failed_attempts:
        for username, count in failed_attempts.items():
            print(f"{username}: {count}")
    else:
        print("No failed attempts.")

    print("\nFailed IP attempts:")

    if ip_failed_attempts:
        for ip, count in ip_failed_attempts.items():
            print(f"{ip}: {count}")
    else:
        print("No failed IP attempts.")

    print("\nLocked accounts:")

    if not account_locks:
        print("No locked accounts.")

    for username in list(account_locks):
        remaining = check_lock(account_locks, username)

        if remaining:
            print(f"{username}: LOCKED ({remaining} seconds)")
        else:
            print(f"{username}: Lockout expired")

    print("\nBlocked IP addresses:")

    if not ip_locks:
        print("No blocked IP addresses.")

    for ip in list(ip_locks):
        remaining = check_lock(ip_locks, ip)

        if remaining:
            print(f"{ip}: BLOCKED ({remaining} seconds)")
        else:
            print(f"{ip}: Block expired")

    print("====================================")


# ==========================================
# MAIN MENU
# ==========================================

def main():

    print("\n============================================")
    print("       LOGIN ATTEMPT CONTROL SYSTEM")
    print("============================================")

    print("\nSecurity Features:")
    print("- Failed login tracking")
    print("- Username and IP monitoring")
    print("- Five-attempt lockout")
    print("- 15-minute temporary lockout")
    print("- Security audit logging")
    print("- Brute-force attack simulation")

    print("\nDemo Accounts:")
    print("Alice: AliceSecure123!")
    print("Admin: AdminSecure123!")

    while True:

        print("\n--------------- MAIN MENU ---------------")
        print("1. Login")
        print("2. Simulate brute-force attack")
        print("3. View security status")
        print("4. Exit")
        print("-----------------------------------------")

        choice = input("Enter your choice (1-4): ").strip()

        if choice == "1":

            username = input("Enter username: ")
            password = input("Enter password: ")
            ip = input("Enter source IP address: ")

            attempt_login(username, password, ip)

        elif choice == "2":
            simulate_brute_force()

        elif choice == "3":
            show_security_status()

        elif choice == "4":

            print("\nExiting Login Attempt Control System.")
            break

        else:
            print("\n[ERROR] Invalid choice. Try again.")


if __name__ == "__main__":
    main()
