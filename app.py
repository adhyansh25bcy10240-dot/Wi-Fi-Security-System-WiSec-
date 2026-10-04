import os
import sys
import sqlite3
import subprocess
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "devices.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

try:
    import visualization
except ImportError:
    visualization = None

@app.route('/api/devices', methods=['GET'])
def api_devices():
    try:
        conn = get_db_connection()
        devices_raw = conn.execute('SELECT * FROM devices').fetchall()
        conn.close()

        device_list = []
        threats_count = 0

        for row in devices_raw:
            d = dict(row)
            raw_ports = d.get('open_ports') or ""
            ports_array = [{"port": int(p.strip())} for p in raw_ports.split(",") if p.strip().isdigit()]

            status = d.get('status', 'Normal')
            threat_score = float(d.get('threat_score', 0.0))

            if status != 'Normal' or threat_score > 0.70:
                threats_count += 1

            device_list.append({
                "ip": d.get('ip', 'Unknown'),
                "mac": d.get('mac', '00:00:00:00:00:00'),
                "hostname": d.get('hostname', 'Unknown Device'),
                "vendor": d.get('vendor', 'Generic Vendor'),
                "open_ports": ports_array,
                "last_seen": d.get('last_seen', ''),
                "ai_security": {
                    "status": status,
                    "threat_score": threat_score,
                    "is_blocked": bool(d.get('is_blocked', 0)),
                    "alert_message": f"Suspicious activity detected: {status}" if status != 'Normal' else "Clean traffic"
                }
            })

        dashboard_img = visualization.generate_dashboard() if visualization else None

        return jsonify({
            "summary": {
                "total_devices": len(device_list),
                "active_devices": len(device_list),
                "threats_detected": threats_count,
                "network_health": "ATTENTION_REQUIRED" if threats_count > 0 else "HEALTHY"
            },
            "devices": device_list,
            "dashboard_image": dashboard_img
        })

    except Exception as e:
        print(f"[!] API Error: {e}")
        return jsonify({"summary": {"total_devices": 0, "active_devices": 0, "threats_detected": 0, "network_health": "ERROR"}, "devices": []}), 500


@app.route('/')
def index():
    dashboard_img = visualization.generate_dashboard() if visualization else None
    return render_template('index.html', dashboard_image=dashboard_img)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3001, debug=True)
