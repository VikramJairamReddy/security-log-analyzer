from src.main import convert_log, load_events, detect_suspicious_ip
from datetime import datetime
from pathlib import Path

def test_convert_valid_log_line():
    line = ("2026-10-16 09:01:00 WARN "
            "user=admin ip=203.0.113.25 "
            "action=login status=failed")

    event = convert_log(line)

    assert event is not None
    assert event["user"] == "admin"
    assert event["ip"] == "203.0.113.25"
    assert event["status"] == "failed"


def test_reject_invalid_timestamp():
    line = ("not-a-date 09:01:00 WARN "
            "user=admin ip=203.0.113.25 "
            "action=login status=failed")

    assert convert_log(line) is None


def test_detect_ip_at_threshold():
    events = [
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:00:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:01:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:02:00"),
        },
    ]

    alerts = detect_suspicious_ip(events, threshold=3)

    assert alerts == {"203.0.113.25": 3}


def test_successful_logins_do_not_trigger_alerts():
    events = [
        {"ip": "203.0.113.25", "status": "success"},
        {"ip": "203.0.113.25", "status": "success"},
        {"ip": "203.0.113.25", "status": "success"},
    ]

    alerts = detect_suspicious_ip(events, threshold=3)

    assert alerts == {}

def test_detect_failures_within_five_minutes():
    events = [
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:00:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:02:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:04:00"),
        },
    ]

    alerts = detect_suspicious_ip(events, threshold=3)

    assert alerts == {"203.0.113.25": 3}


def test_failures_spread_over_time_do_not_trigger_alert():
    events = [
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:00:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T12:00:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T15:00:00"),
        },
    ]

    alerts = detect_suspicious_ip(events, threshold=3)

    assert alerts == {}

def test_missing_log_file():
    missing_file = Path("sample_data/does_not_exist.log")

    try:
        load_events(missing_file)
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass

def test_load_events_skips_invalid_lines(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "invalid log entry\n"
        "2026-10-16 09:01:00 WARN "
        "user=admin ip=203.0.113.25 "
        "action=login status=failed\n",
        encoding="utf-8",
    )

    events, invalid_lines = load_events(log_file)

    assert len(events) == 1
    assert invalid_lines == 1

def test_detect_multiple_suspicious_ips():
    events = [
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:00:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:01:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:02:00"),
        },
        {
            "ip": "198.51.100.8",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T10:00:00"),
        },
        {
            "ip": "198.51.100.8",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T10:01:00"),
        },
        {
            "ip": "198.51.100.8",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T10:02:00"),
        },
    ]

    alerts = detect_suspicious_ip(events, threshold=3)

    assert alerts == {
        "203.0.113.25": 3,
        "198.51.100.8": 3,
    }

def test_successful_logins_do_not_count_toward_threshold():
    events = [
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:00:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "success",
            "timestamp": datetime.fromisoformat("2026-10-16T09:01:00"),
        },
        {
            "ip": "203.0.113.25",
            "status": "failed",
            "timestamp": datetime.fromisoformat("2026-10-16T09:02:00"),
        },
    ]

    alerts = detect_suspicious_ip(events, threshold=3)

    assert alerts == {}