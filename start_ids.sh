#!/bin/bash

echo "[+] Starting Flask Dashboard..."
python3 app.py &

sleep 3

echo "[+] Starting Telegram Bot..."
python3 alert_bot.py &

echo "[+] IDS Platform Running"
wait
