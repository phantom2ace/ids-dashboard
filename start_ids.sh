#!/bin/bash

# Define virtual environment python
VENV_PYTHON="/home/spade/ids-dashboard/.venv/bin/python3"
GUNICORN="/home/spade/ids-dashboard/.venv/bin/gunicorn"

echo "[+] Initializing Database..."
$VENV_PYTHON init_db.py

echo "[+] Starting Suricata Log Parser..."
$VENV_PYTHON parser.py > parser.log 2>&1 &
PARSER_PID=$!

sleep 2

echo "[+] Starting Flask Dashboard with Gunicorn..."
$GUNICORN --workers 3 --bind 0.0.0.0:5000 app:app > dashboard.log 2>&1 &
GUNICORN_PID=$!

# Trap termination signals to cleanly kill child processes
trap "kill $PARSER_PID $GUNICORN_PID 2>/dev/null" SIGINT SIGTERM EXIT

echo "[+] IDSSD Platform Running in Production Mode"
echo "[*] Gunicorn PID: $GUNICORN_PID | Parser PID: $PARSER_PID"
echo "[*] Logs: parser.log, dashboard.log"

# Wait for either process to exit
wait -n

echo "[-] A core process exited. Shutting down."
kill $PARSER_PID $GUNICORN_PID 2>/dev/null
