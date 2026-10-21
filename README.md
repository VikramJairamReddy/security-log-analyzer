# Cloud-Based Security Log Analyzer

This project uses Python to check login logs for suspicious activity. It finds IP addresses with repeated failed login attempts, saves events in an SQLite database, and creates a JSON report.

## Features

- Read and check login logs.
- Find repeated failed login attempts.
- Set the number of failed attempts needed to trigger an alert.
- Set the time window for checking failed attempts.
- Save events in an SQLite database.
- Avoid saving duplicate events.
- Filter events by IP address and login status.
- Create a JSON report.
- Handle common errors.
- Run automated tests.

## Technologies

- Python
- SQLite
- JSON
- pytest
- Git and GitHub

## Project Structure

```text
security-log-analyzer/
├── src/
│   ├── main.py
│   └── database.py
├── tests/
│   └── test_log_analyzer.py
├── sample_data/
│   └── auth.log
├── requirements.txt
└── README.md
```

## Setup

Clone the repository:

```bash
git clone https://github.com/VikramJairamReddy/security-log-analyzer.git
cd security-log-analyzer
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required packages:

```bash
pip install -r requirements.txt
```

## Run the Project

Start the analyzer:

```bash
python3 -m src.main
```

You can change the number of failed attempts and the time window:

```bash
python3 -m src.main --threshold 5 --window 10
```

This command checks for five failed login attempts within ten minutes.

## Run with Docker

Make sure Docker Desktop is installed and running.

Build the Docker image:

```bash
docker build -t security-log-analyzer .
```

Run the analyzer:

```bash
mkdir -p data
docker run --rm -v "$(pwd)/data:/app/data" security-log-analyzer
```

The analyzer reads the sample log file and prints the results in the terminal.

The `data` folder stores the SQLite database and JSON report on your computer. These files remain available after the container stops.

To run the tests locally:

```bash
python3 -m pytest -v
```

## Run the Tests

Run this command:

```bash
python3 -m pytest -v
```

The project currently has 25 passing tests.

## Sample Log

```text
2026-10-18 10:00:00 INFO user=alice ip=198.51.100.10 action=login status=failed
```

Each log entry contains the time, log level, username, IP address, action, and login status.

## Current Status

The analyzer can read logs, detect repeated failed logins, save events in SQLite, and create JSON reports. Cloud deployment is still planned.
