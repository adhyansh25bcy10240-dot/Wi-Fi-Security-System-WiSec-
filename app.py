from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import subprocess
import sys
import os

import visualization

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "devices.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():

    conn = get_db_connection()

    devices = conn.execute(
        'SELECT * FROM devices'
    ).fetchall()

    conn.close()

    # Generate/update visualization
    dashboard_image = visualization.generate_dashboard()

    return render_template(
        'index.html',
        devices=devices,
        dashboard_image=dashboard_image
    )


# ===================== NETWORK RESCAN =====================

@app.route('/rescan', methods=['POST'])
def rescan():

    try:

        subprocess.run(
            [sys.executable, 'history_tracker.py'],
            cwd=BASE_DIR,
            check=True
        )

    except subprocess.CalledProcessError as e:

        print("[!] Network rescan failed:", e)

    return redirect(url_for('index'))


# ===================== PORT SCAN =====================

@app.route('/portscan', methods=['POST'])
def portscan():

    target_ip = request.form.get('ip')

    if target_ip:

        try:

            subprocess.run(
                [
                    sys.executable,
                    'port_scan_menu.py',
                    target_ip
                ],
                cwd=BASE_DIR
            )

        except Exception as e:

            print("[!] Port scan failed:", e)

    return redirect(url_for('index'))


# ===================== RUN =====================

if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=3001,
        debug=True
    )