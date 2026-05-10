#!/bin/bash

echo "[+] Initializing Database..."
python3 init_db.py

echo "[+] Starting Suricata Log Parser..."
python3 parser.py &

echo "[+] Starting Flask Dashboard..."
python3 app.py &

echo "[+] IDSSD Platform Running"
wait
