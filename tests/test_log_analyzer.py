from src.main import convert_log, load_events, detect_suspicious_ip, export_report, main
from src.database import initialize_database,save_events, get_events, filter_events, get_security_summary
import sqlite3
from datetime import datetime
from pathlib import Path
import json
import subprocess
import sys

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

def test_export_report_to_json(tmp_path):
    report_file = tmp_path / "report.json"

    report = {
        "total_events": 7,
        "successful_logins": 2,
        "failed_logins": 5,
        "invalid_lines": 0,
        "suspicious_ips": {
            "203.0.113.25": 4
        },
        "generated_at": "2026-10-17T20:00:00",
    }

    export_report(report, report_file)

    with report_file.open("r", encoding="utf-8") as file:
        saved_report = json.load(file)

    assert saved_report == report

def test_initialize_database_creates_events_table(tmp_path):
    db_path = tmp_path / "security.db"

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        result = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'events'
            """
        ).fetchone()

    assert result is not None
    assert result[0] == "events"


def test_save_events_to_database(tmp_path):
    db_path = tmp_path / "security.db"

    events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30, 0),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        }
    ]

    save_events(events, db_path)

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT username, ip, status FROM events"
        ).fetchall()

    assert rows == [("vikram", "203.0.113.25", "failed")]


def test_get_events_from_database(tmp_path):
    db_path = tmp_path / "security.db"

    original_events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30, 0),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        }
    ]

    save_events(original_events, db_path)
    retrieved_events = get_events(db_path)

    assert retrieved_events == original_events


def test_saving_same_events_twice_does_not_create_duplicates(tmp_path):
    db_path = tmp_path / "security.db"

    events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30, 0),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        }
    ]

    save_events(events, db_path)
    save_events(events, db_path)

    retrieved_events = get_events(db_path)

    assert len(retrieved_events) == 1


def test_filter_events_by_status(tmp_path):
    db_path = tmp_path / "security.db"

    events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 31),
            "level": "INFO",
            "user": "admin",
            "ip": "198.51.100.8",
            "action": "login",
            "status": "success",
        },
    ]

    save_events(events, db_path)

    result = filter_events(db_path, status="failed")

    assert len(result) == 1
    assert result[0]["user"] == "vikram"
    assert result[0]["status"] == "failed"


def test_filter_events_by_ip(tmp_path):
    db_path = tmp_path / "security.db"

    events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 31),
            "level": "INFO",
            "user": "admin",
            "ip": "198.51.100.8",
            "action": "login",
            "status": "success",
        },
    ]

    save_events(events, db_path)

    result = filter_events(db_path, ip="198.51.100.8")

    assert len(result) == 1
    assert result[0]["user"] == "admin"
    assert result[0]["ip"] == "198.51.100.8"


def test_filter_events_by_status_and_ip(tmp_path):
    db_path = tmp_path / "security.db"

    events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 31),
            "level": "INFO",
            "user": "admin",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "success",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 32),
            "level": "INFO",
            "user": "guest",
            "ip": "198.51.100.8",
            "action": "login",
            "status": "failed",
        },
    ]

    save_events(events, db_path)

    result = filter_events(
        db_path,
        status="failed",
        ip="203.0.113.25",
    )

    assert len(result) == 1
    assert result[0]["user"] == "vikram"


def test_get_security_summary(tmp_path):
    db_path = tmp_path / "security.db"

    events = [
        {
            "timestamp": datetime(2026, 10, 17, 12, 30),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 31),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 32),
            "level": "INFO",
            "user": "vikram",
            "ip": "203.0.113.25",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": datetime(2026, 10, 17, 12, 33),
            "level": "INFO",
            "user": "admin",
            "ip": "198.51.100.8",
            "action": "login",
            "status": "success",
        },
    ]

    save_events(events, db_path)

    summary = get_security_summary(db_path)

    assert summary["total_events"] == 4
    assert summary["successful_logins"] == 1
    assert summary["failed_logins"] == 3
    assert summary["suspicious_ips"] == {"203.0.113.25": 3}


def test_main_help_option():
    result = subprocess.run(
        [sys.executable, "-m", "src.main", "--help"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "--log-file" in result.stdout
    assert "--threshold" in result.stdout
    assert "--window" in result.stdout


def test_main_rejects_invalid_threshold():
    result = subprocess.run(
        [sys.executable, "-m", "src.main", "--threshold", "0"],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "--threshold must be at least 1" in result.stderr


def test_main_rejects_invalid_window():
    result = subprocess.run(
        [sys.executable, "-m", "src.main", "--window", "0"],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "--window must be at least 1" in result.stderr

def test_report_uses_current_log_events(tmp_path, monkeypatch):

    log_file = tmp_path / "auth.log"
    db_file = tmp_path / "security.db"
    report_file = tmp_path / "security_report.json"

    log_file.write_text(
        "2026-10-18 10:00:00 INFO user=alice "
        "ip=198.51.100.10 action=login status=success\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "src.main.Path.resolve",
        lambda self: tmp_path / "src" / "main.py",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--log-file", str(log_file)],
    )

    main()

    report = json.loads(report_file.read_text(encoding="utf-8"))

    assert report["total_events"] == 1
    assert report["successful_logins"] == 1
    assert report["failed_logins"] == 0
    assert report["suspicious_ips"] == {}
