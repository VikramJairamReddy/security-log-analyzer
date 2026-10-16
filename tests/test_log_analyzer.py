from src.main import convert_log, detect_suspicious_ip


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
        {"ip": "203.0.113.25", "status": "failed"},
        {"ip": "203.0.113.25", "status": "failed"},
        {"ip": "203.0.113.25", "status": "failed"},
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
