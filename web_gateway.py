from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
from functools import wraps
import os
import json
import subprocess
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Constants from environment
S_PASS = os.getenv("ADMIN_PASSWORD", "admin123")
DETAILED_LOG = "/home/taqy/Nexus-Cyber/logs/detailed_alerts.log"
ALERT_FILE = "/home/taqy/Nexus-Cyber/logs/sentinel.log"

def check_auth(username, password):
    """Check if a username / password combination is valid."""
    return username == 'admin' and password == S_PASS

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Administrator Override Required.\n', 401,
        {'WWW-Authenticate': 'Basic realm="Nexus-Cyber Admin"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def set_hardware_alert(status):
    """Reset hardware LED to safe state."""
    try:
        color = "0000ff" # Blue (Safe)
        if status == "MALICIOUS":
            color = "ff0000" # Red (Danger)
            
        cmd = f'echo "{S_PASS}" | sudo -S asusctl aura effect static -c {color}'
        subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

@app.route('/')
def index():
    """Redirect home to admin panel."""
    return redirect(url_for('admin_panel'))

@app.route('/admin')
@requires_auth
def admin_panel():
    """Main Administrator Dashboard."""
    return render_template('admin.html')

@app.route('/api/logs')
@requires_auth
def get_all_logs():
    """Fetch the latest 50 logs for the live telemetry dashboard."""
    if not os.path.exists(DETAILED_LOG):
        return jsonify([])
    
    logs = []
    try:
        with open(DETAILED_LOG, 'r') as f:
            lines = f.readlines()[-50:]
            for line in reversed(lines):
                try:
                    logs.append(json.loads(line))
                except: continue
        return jsonify(logs)
    except:
        return jsonify([])

@app.route('/api/status')
@requires_auth
def get_status():
    """System health check."""
    proxy_running = False
    try:
        # Check if tcp_proxy is running
        output = subprocess.check_output(["pgrep", "-f", "tcp_proxy.py"])
        proxy_running = True if output else False
    except:
        proxy_running = False
        
    return jsonify({
        "proxy": "ONLINE" if proxy_running else "OFFLINE",
        "database": "CONNECTED", # Prototype assumption
        "timestamp": time.ctime()
    })

@app.route('/reset', methods=['POST'])
@requires_auth
def reset_system():
    """Manual system purge by Administrator."""
    try:
        # Reset Forensic Logs to SAFE state
        with open(DETAILED_LOG, "w") as f:
            f.write('{"status": "CLEAN", "reason": "System Purged", "action": "Manual Override", "timestamp": "' + time.ctime() + '", "target_ip": "GLOBAL"}\n')
            
        # Clear other legacy logs if they exist
        for log in [ALERT_FILE, "/home/taqy/Nexus-Cyber/logs/web.log"]:
            if os.path.exists(log):
                open(log, 'w').close()
                
        # Reset Hardware LED
        set_hardware_alert("CLEAN")
        
        return jsonify({"status": "success", "message": "System Purged and Sensors Normalized."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    # Listen on all interfaces (0.0.0.0)
    app.run(host='0.0.0.0', port=5000)
