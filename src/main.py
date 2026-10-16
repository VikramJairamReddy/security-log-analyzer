
from pathlib import Path
from datetime import datetime

def convert_log(line):
    """Convert a log line into a structured event."""
    parts = line.split()

    if len(parts) < 3:
        return None

    try:
        timestamp = datetime.fromisoformat(f"{parts[0]}T{parts[1]}")
    except ValueError:
        return None

    level = parts[2]
    fields = {}

    for item in parts[3:]:
        if "=" not in item:
            continue

        key, value = item.split("=", 1)
        fields[key] = value

    required = {"user", "ip", "action", "status"}

    if not required.issubset(fields):
        return None

    if fields["action"] != "login":
        return None

    if fields["status"] not in {"success", "failed"}:
        return None

    return {
        "timestamp": timestamp,
        "level": level,
        "user": fields["user"],
        "ip": fields["ip"],
        "action": fields["action"],
        "status": fields["status"],
    }

def load_events(file_path):
    """Read a log file and return valid authentication events."""
    events = []
    invalid_lines = 0

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            event = convert_log(line)

            if event is None:
                invalid_lines += 1
            else:
                events.append(event)

    return events, invalid_lines

def detect_suspicious_ip(events, threshold=3):
    """Find IP addresses with repeated failed login attempts."""
    failed_attempts = {}

    for event in events:
        if event["status"] != "failed":
            continue

        ip = event["ip"]
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    alerts = {}

    for ip, count in failed_attempts.items():
        if count >= threshold:
            alerts[ip] = count

    return alerts


def main():
    project_root = Path(__file__).resolve().parent.parent
    log_file = project_root / "sample_data" / "auth.log"

    events, invalid_lines = load_events(log_file)

    failed_count = sum(
        event["status"] == "failed" for event in events
    )

    alerts = detect_suspicious_ip(events)

    print("=== Security Log Analyzer ===")
    print(f"Total events: {len(events)}")
    print(f"Failed logins: {failed_count}")
    print(f"Invalid lines: {invalid_lines}")

    print("\n=== Security Alerts ===")

    if not alerts:
        print("No suspicious activity detected.")
    else:
        for ip, count in alerts.items():
            print(f"ALERT: {ip} has {count} failed login attempts.")


if __name__ == "__main__":
    main()
