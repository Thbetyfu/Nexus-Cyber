from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
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

    prompt = (
        f"Analyze this uploaded file metadata and content snippet. Filename: {filename}\nSnippet: {snippet}\n"
        "Context: If the file is a standard image (jpg, png) or the snippet says 'Binary/Unreadable content', "
        "it is highly likely CLEAN unless there is explicit malware metadata. "
        "Respond ONLY with 'MALICIOUS' if there is clear evidence of a script or exploit, otherwise respond with 'CLEAN'."
    )
    
    try:
        response = ollama.chat(model=MODEL, messages=[
            {'role': 'system', 'content': 'You are a malware analysis engine. Do NOT flag standard media/image files as malicious unless explicit script/exploit code is found. Answer ONLY "MALICIOUS" or "CLEAN".'},
            {'role': 'user', 'content': prompt}
        ])
        result = response['message']['content'].strip().upper()
        if "MALICIOUS" in result:
            with open(ALERT_FILE, 'a') as f:
                f.write(f"--- UPLOAD ALERT ---\nFile: {filename}\nStatus: MALICIOUS\n")
            set_hardware_alert("MALICIOUS")
            return "File flagged as MALICIOUS by Llama 3!"
        else:
            set_hardware_alert("CLEAN")
            return "File scanned and marked as CLEAN."
    except Exception as e:
        return f"Scan failed: {str(e)}"

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/status')
def get_status():
    """Poll for the latest alert status."""
    if not os.path.exists(ALERT_FILE):
        return jsonify({"status": "safe"})
    
    try:
        with open(ALERT_FILE, 'r') as f:
            lines = f.readlines()
            if not lines:
                return jsonify({"status": "safe"})
            
            # Look for 'MALICIOUS' in the last few lines or last block
            num_lines = len(lines)
            last_lines = "".join(lines[max(0, num_lines - 10):])
            if "MALICIOUS" in last_lines:
                return jsonify({"status": "danger"})
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
