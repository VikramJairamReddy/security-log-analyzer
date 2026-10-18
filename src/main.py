from pathlib import Path
from datetime import datetime
import json
import argparse
from .database import save_events, get_events, get_security_summary

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

def detect_suspicious_ip(events, threshold=3, window_minutes=5):
    """Find IPs with repeated failed logins within a time window."""
    failed_attempts = {}

    for event in events:
        if event["status"] != "failed":
            continue

        ip = event["ip"]
        timestamp = event["timestamp"]

        if ip not in failed_attempts:
            failed_attempts[ip] = []

        failed_attempts[ip].append(timestamp)

    alerts = {}
    window_seconds = window_minutes * 60

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            count = 0

            for j in range(i, len(timestamps)):
                elapsed = (timestamps[j] - timestamps[i]).total_seconds()

                if elapsed > window_seconds:
                    break

                count += 1

            if count >= threshold:
                alerts[ip] = count
                break

    return alerts

def export_report(report, file_path):
    """Save a analysis report as a JSON file."""
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze logs for suspicious activity."
    )

    parser.add_argument(
        "--log-file",
        default="sample_data/auth.log",
        help="Path to the authentication log file.",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of failed logins needed to trigger an alert (default: 3).",
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Time window in minutes for detecting failed logins (default: 5).",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    if args.window < 1:
        parser.error("--window must be at least 1")

    project_root = Path(__file__).resolve().parent.parent
    log_file = Path(args.log_file)

    if not log_file.is_absolute():
        log_file = project_root / log_file

    db_file = project_root / "security.db"
    report_file = project_root / "security_report.json"

    try:
        events, invalid_lines = load_events(log_file)

        save_events(events, db_file)

        successful_logins = sum(
            1 for event in events if event["status"] == "success"
        )
        failed_logins = sum(
            1 for event in events if event["status"] == "failed"
        )

        suspicious_ips = detect_suspicious_ip(
            events,
            threshold=args.threshold,
            window_minutes=args.window,
        )
    except FileNotFoundError:
        print(f"Error: Log file not found: {log_file}")
        return

    report = {
        "total_events": len(events),
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "invalid_lines": invalid_lines,
        "threshold": args.threshold,
        "window_minutes": args.window,
        "suspicious_ips": suspicious_ips,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
    }

    export_report(report, report_file)

    print(f"\nReport saved to: {report_file}\n")
    print("=== Security Log Analyzer ===")
    print(f"Total events: {len(events)}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed logins: {failed_logins}")
    print(f"Invalid lines: {invalid_lines}")
    print(f"Detection threshold: {args.threshold} failed logins")
    print(f"Detection window: {args.window} minutes")

    print("\n=== Security Alerts ===")

    if not suspicious_ips:
        print("No suspicious activity detected.")
    else:
        for ip, count in suspicious_ips.items():
            print(
                f"ALERT: {ip} has {count} failed login attempts "
                f"within {args.window} minutes."
            )


if __name__ == "__main__":
    main()
