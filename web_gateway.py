from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
import json
import ollama
import subprocess
import threading

app = Flask(__name__)
UPLOAD_FOLDER = '/home/taqy/Nexus-Cyber/quarantine'
ALERT_FILE = '/home/taqy/Nexus-Cyber/logs/alerts.txt'
MODEL = 'llama3'
S_PASS = "Thoriqtaqy2006$"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

def scan_file(filepath):
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    
    # Bypass AI for known safe binary/image extensions
    safe_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3']
    if ext in safe_extensions:
        set_hardware_alert("CLEAN")
        return f"File scanned ({ext}) and marked as CLEAN (AI Bypass)."

    # Read first 2KB of file for context
    try:
        with open(filepath, 'rb') as f:
            snippet = f.read(2048).decode('utf-8', errors='ignore')
    except:
        snippet = "Binary/Unreadable content"

    # Enhanced AI Prompt for structured forensics
    prompt = (
        f"Analyze this uploaded file metadata and content snippet. Filename: {filename}\nSnippet: {snippet}\n"
        "If it looks like an active exploit or binary malware, respond ONLY with a valid JSON in this format: "
        '{"status": "MALICIOUS" or "CLEAN", "reason": "Short explanation", "action": "Action taken"}'
    )
    
    try:
        response = ollama.chat(model=MODEL, messages=[
            {'role': 'system', 'content': 'You are a malware analysis engine. Output JSON only.'},
            {'role': 'user', 'content': prompt}
        ])
        raw_result = response['message']['content'].strip()
        start = raw_result.find('{')
        end = raw_result.rfind('}') + 1
        analysis = json.loads(raw_result[start:end])
        
        if analysis.get("status") == "MALICIOUS" or "MALICIOUS" in raw_result.upper():
            alert_data = {
                "timestamp": threading.current_thread().name, # Placeholder or actual time
                "status": "MALICIOUS",
                "reason": analysis.get("reason", "Malicious file detected"),
                "action": analysis.get("action", "File quarantined and sandbox killed"),
                "raw_file": filename
            }
            with open("/home/taqy/Nexus-Cyber/logs/detailed_alerts.log", "a") as df:
                df.write(json.dumps(alert_data) + "\n")
            
            with open(ALERT_FILE, 'a') as f:
                f.write(f"--- UPLOAD ALERT ---\nFile: {filename}\nStatus: MALICIOUS\n")
            set_hardware_alert("MALICIOUS")
            return f"ALERT: {analysis.get('reason')}"
        else:
            set_hardware_alert("CLEAN")
            return "File scanned and marked as CLEAN."
    except Exception as e:
        return f"Scan failed or JSON error: {str(e)}"

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/status')
def get_status():
    """Poll for the latest detailed alert status."""
    detailed_log = "/home/taqy/Nexus-Cyber/logs/detailed_alerts.log"
    if not os.path.exists(detailed_log):
        return jsonify({"status": "safe"})
    
    try:
        with open(detailed_log, 'r') as f:
            lines = f.readlines()
            if not lines:
                return jsonify({"status": "safe"})
            
            # Get the very last detailed entry
            last_entry = json.loads(lines[-1])
            if last_entry.get("status") == "MALICIOUS":
                return jsonify({
                    "status": "danger",
                    "reason": last_entry.get("reason"),
                    "action": last_entry.get("action")
                })
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
        
        result = scan_file(filepath)
        return render_template('upload.html', message=result)

if __name__ == '__main__':
    # Listen on all interfaces (0.0.0.0) so other devices in Wi-Fi can access
    app.run(host='0.0.0.0', port=5000)
