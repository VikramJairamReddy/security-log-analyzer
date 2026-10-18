import sqlite3
from pathlib import Path
from datetime import datetime



def initialize_database(db_path):
    """Create the database and its events table."""
    db_path = Path(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS unique_security_event
            ON events (timestamp, level, username, ip, action, status)
            """
        )



def save_events(events, db_path):
    """Save security events to the SQLite database."""
    db_path = Path(db_path)

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        connection.executemany(
            """
            INSERT OR IGNORE INTO events (
                timestamp, level, username, ip, action, status
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    event["timestamp"].isoformat(),
                    event["level"],
                    event["user"],
                    event["ip"],
                    event["action"],
                    event["status"],
                )
                for event in events
            ],
        )


def get_events(db_path):
    """Read all security events from the SQLite database."""
    db_path = Path(db_path)

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT timestamp, level, username, ip, action, status
            FROM events
            ORDER BY timestamp
            """
        ).fetchall()

    events = []

    for row in rows:
        events.append({
            "timestamp": datetime.fromisoformat(row[0]),
            "level": row[1],
            "user": row[2],
            "ip": row[3],
            "action": row[4],
            "status": row[5],
        })

    return events
