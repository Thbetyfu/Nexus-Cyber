from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
from functools import wraps
import os
import json
import ollama
import subprocess
import threading
import time
import shutil
import shutil
import sentinel_brain
app = Flask(__name__)
UPLOAD_FOLDER = '/home/taqy/Nexus-Cyber/quarantine'
ALERT_FILE = '/home/taqy/Nexus-Cyber/logs/alerts.txt'
SESSION_MAP_FILE = '/home/taqy/Nexus-Cyber/logs/session_map.json'
MODEL = 'llama3'
S_PASS = "Thoriqtaqy2006$"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    try:
        if status == "MALICIOUS":
            cmd = f'echo "{S_PASS}" | sudo -S asusctl aura effect static -c ff0000'
        else:
            cmd = f'echo "{S_PASS}" | sudo -S asusctl aura effect static -c 0000ff'
        subprocess.run(cmd, shell=True, check=False)
    except:
        pass

def detonate_file(filepath):
    """
    Sandbox execution (Auto-Detonate) in a secure environment.
    Uses Firejail to prevent network access and disk changes outside quarantine.
    """
    try:
        filename = os.path.basename(filepath)
        print(f"[*] Auto-Detonate initialized for: {filename}")
        
        # Step 3: Make executable
        os.chmod(filepath, 0o755)
        
        # Step 4 & 5: Run in Firejail sandbox with 10s timeout
        subprocess.run(
            ["firejail", "--quiet", "--net=none", f"--private={UPLOAD_FOLDER}", filepath],
            timeout=10,
            check=False,
            capture_output=True # Silent execution
        )
        print(f"[+] Detonation process finished for {filename}")
        
    except subprocess.TimeoutExpired:
        print(f"[!] Detonation Timeout: {os.path.basename(filepath)} was killed after 10s.")
    except Exception as e:
        # Step 7: Handle non-executable or error cases
        print(f"[!] Detonation Error for {os.path.basename(filepath)}: {e}")

def initiate_background_analysis(filepath):
    """Trigger the dynamic analysis workflow in the background."""
    try:
        sentinel_brain.analyze_file_dynamic(filepath)
    except Exception as e:
        print(f"[!] Background analysis error: {e}")


@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/status')
def get_status():
    """Poll for the latest detailed alert status for the specific user."""
    detailed_log = "/home/taqy/Nexus-Cyber/logs/detailed_alerts.log"
    if not os.path.exists(detailed_log):
        return jsonify({"status": "safe"})
    
    user_ip = request.remote_addr
    
    try:
        with open(detailed_log, 'r') as f:
            lines = f.readlines()
            if not lines:
                return jsonify({"status": "safe"})
            
            # Scan from bottom up to find the latest alert relevant to this IP or GLOBAL reset
            for line in reversed(lines):
                try:
                    entry = json.loads(line)
                    target_ip = entry.get("target_ip", "GLOBAL")
                    
                    if target_ip == "GLOBAL" and entry.get("status") == "CLEAN":
                        return jsonify({"status": "safe"})
                        
                    if target_ip == user_ip or target_ip == "GLOBAL":
                        # If a specific file is being polled, ignore other background alerts
                        target_file = request.args.get("filename")
                        if target_file and entry.get("raw_file") != target_file and target_ip != "GLOBAL":
                            continue
                            
                        if entry.get("status") == "MALICIOUS":
                            return jsonify({
                                "status": "danger",
                                "reason": entry.get("reason"),
                                "action": entry.get("action"),
                                "timeline": entry.get("timeline", []),
                                "network_target": entry.get("network_target", {})
                            })
                        elif entry.get("status") == "CLEAN":
                             return jsonify({"status": "clean", "reason": entry.get("reason"), "raw_file": entry.get("raw_file")})
                except:
                    continue
    except:
        pass
    
    return jsonify({"status": "safe"})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        
        # Step 6: Start detonation in a background thread to avoid lag
        detonation_thread = threading.Thread(target=detonate_file, args=(filepath,))
        detonation_thread.start()
        
        # Step 7: Start dynamic AI analysis in background
        analysis_thread = threading.Thread(target=initiate_background_analysis, args=(filepath,))
        analysis_thread.start()
        
        return render_template('upload.html', message="File submitted. AI Forensic Analysis in progress...")

@app.route('/upload-ajax', methods=['POST'])
def upload_file_ajax():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"})
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"})
    
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        
        # Save IP to session map
        user_ip = request.remote_addr
        smap = {}
        if os.path.exists(SESSION_MAP_FILE):
             try:
                 with open(SESSION_MAP_FILE, 'r') as sm:
                     smap = json.load(sm)
             except: pass
        smap[file.filename] = user_ip
        with open(SESSION_MAP_FILE, 'w') as sm:
             json.dump(smap, sm)
        
        detonation_thread = threading.Thread(target=detonate_file, args=(filepath,))
        detonation_thread.start()
        
        # Step 7: Run dynamic AI analysis synchronously to hold the loading screen
        try:
            analysis = sentinel_brain.analyze_file_dynamic(filepath)
            status_code = analysis.get("status", "CLEAN")
            
            if status_code == "MALICIOUS":
                # Reflex Brain flagged it
                return jsonify({"status": "danger", "message": "Threat Detected! System Locking Down..."})
            else:
                # Add a brief dramatic pause if it's too fast
                time.sleep(1)
                return jsonify({"status": "success", "message": "Deep AI Scan Complete. File marked SAFE."})
        except Exception as e:
            print(f"Analysis Failed: {e}")
            return jsonify({"status": "success", "message": "Scan failed or interrupted."})

@app.route('/admin')
@requires_auth
def admin_panel():
    return render_template('admin.html')

@app.route('/reset', methods=['POST'])
@requires_auth
def reset_system():
    try:
        # Reset Forensic Logs to SAFE state
        detailed_log = "/home/taqy/Nexus-Cyber/logs/detailed_alerts.log"
        with open(detailed_log, "w") as f:
            f.write('{"status": "CLEAN", "reason": "System Purged", "action": "Manual Override", "timeline": [], "network_target": {}}\n')
            
        open(ALERT_FILE, 'w').close()
        open("/home/taqy/Nexus-Cyber/logs/sentinel.log", "w").close()
        open("/home/taqy/Nexus-Cyber/logs/web.log", "w").close()
        
        # Clear Quarantine Directory
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")
                
        # Recreate .gitkeep to ensure folder structure is intact
        open(os.path.join(UPLOAD_FOLDER, '.gitkeep'), 'a').close()
                
        # Reset Hardware LED
        set_hardware_alert("CLEAN")
        
        return jsonify({"status": "success", "message": "System Purged"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

if __name__ == '__main__':
    # Listen on all interfaces (0.0.0.0) so other devices in Wi-Fi can access
    app.run(host='0.0.0.0', port=5000)
