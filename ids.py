from collections import defaultdict
import time

FAILURE_WINDOW = 60  # seconds
MAX_FAILURES = 3

failure_records = defaultdict(list)  # username -> list of timestamps

def record_failure(username):
    now = time.time()
    failure_records[username].append(now)
    # Clean old entries
    failure_records[username] = [t for t in failure_records[username] if now - t <= FAILURE_WINDOW]

def check_alert(username):
    if len(failure_records[username]) >= MAX_FAILURES:
        alert_msg = f"Intrusion alert: {username} exceeded {MAX_FAILURES} failures in {FAILURE_WINDOW}s."
        log_event("critical", alert_msg)
        print("!!! " + alert_msg)
        return True
    return False