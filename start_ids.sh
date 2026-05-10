#!/bin/bash

# Define virtual environment python
VENV_PYTHON="/home/spade/ids-dashboard/.venv/bin/python3"

# Kill any existing processes
pkill -f "python3 app.py"
pkill -f "python3 parser.py"

echo "[+] Initializing Database..."
$VENV_PYTHON init_db.py

echo "[+] Starting Suricata Log Parser..."
nohup $VENV_PYTHON parser.py > parser.log 2>&1 &

sleep 2

echo "[+] Starting Flask Dashboard..."
nohup $VENV_PYTHON app.py > dashboard.log 2>&1 &

echo "[+] IDSSD Platform Running"
echo "[*] Logs: parser.log, dashboard.log"
