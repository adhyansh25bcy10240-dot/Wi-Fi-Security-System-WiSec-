#!/bin/bash
echo "[*] Starting NIDS Environment..."

# 1. Run Sniffer in background on 'lo'
sudo /home/asus/projects/.venv/bin/python /home/asus/projects/wifi-scanner/ai/live_ai_sniffer.py lo &
SNIFFER_PID=$!

# 2. Run Flask Dashboard in background
/home/asus/projects/.venv/bin/python app.py &
FLASK_PID=$!

echo "[*] NIDS is running! Press Ctrl+C to stop everything."
trap "kill $SNIFFER_PID $FLASK_PID; exit" INT
wait
