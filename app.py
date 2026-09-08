from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import subprocess

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('devices.db') 
    conn.row_factory = sqlite3.Row 
    return conn

@app.route('/')
def index():
    conn = get_db_connection()
    devices = conn.execute('SELECT * FROM devices').fetchall() 
    conn.close()
    return render_template('index.html', devices=devices)

# NEW: Route to trigger a full network rescan
@app.route('/rescan', methods=['POST'])
def rescan():
    # Executes the existing history_tracker.py script
    try:
        subprocess.run(['python3', 'history_tracker.py'], check=True)
    except subprocess.CalledProcessError:
        pass # In a real app, we'd flash an error message here
    
    # Reload the dashboard to show the fresh data
    return redirect(url_for('index'))

# NEW: Route to trigger a port scan for a specific IP
@app.route('/portscan', methods=['POST'])
def portscan():
    target_ip = request.form.get('ip')
    if target_ip:
        # Executes the port scanner against the specific IP
        # Assuming port_scan_menu.py can take an IP argument, or you can point this to the C++ binary
        try:
            subprocess.run(['python3', 'port_scan_menu.py', target_ip])
        except Exception:
            pass
            
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
