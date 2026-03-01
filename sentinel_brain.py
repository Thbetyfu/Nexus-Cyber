import json
import os
import time
import ollama
import subprocess

LOG_FILE = "/home/taqy/Nexus-Cyber/tetragon.json"
QUARANTINE_DIR = "/home/taqy/Nexus-Cyber/quarantine"
ALERT_FILE = "/home/taqy/Nexus-Cyber/logs/alerts.txt"
MODEL = "llama3"

# System password provided by user
S_PASS = "Thoriqtaqy2006$"

def set_keyboard_color(status):
    """Control ASUS keyboard lighting based on threat status."""
    try:
        if status == "MALICIOUS":
            # Red Static (Red: ff, Green: 00, Blue: 00)
            cmd = f'echo "{S_PASS}" | sudo -S asusctl aura effect static -c ff0000'
        else:
            # Blue Static (Red: 00, Green: 00, Blue: ff)
            cmd = f'echo "{S_PASS}" | sudo -S asusctl aura effect static -c 0000ff'
        subprocess.run(cmd, shell=True, check=False, capture_output=True)
    except Exception as e:
        print(f"Error controlling hardware: {e}")

def analyze_with_ai(content_desc, source_name):
    """Send log or file info to Llama 3 for analysis."""
    # Pre-filter for system binaries to avoid noise
    if '"binary": "/usr/lib' in content_desc or '"binary": "/usr/bin' in content_desc:
        return False
        
    # Ignore our own python processes from the virtual environment
    if '"binary": "/home/taqy/Nexus-Cyber/venv/bin/python3"' in content_desc:
        return False
        
    prompt = (
        f"Analyze this data for security threats. Source: {source_name}. "
        "Context: This is a Pop!_OS Linux system. Ignore standard system background processes. "
        "If it looks like an active exploit, unauthorized data extraction (like cat /etc/shadow), "
        "or a typical malware payload, respond ONLY with 'MALICIOUS'. Otherwise, respond with 'CLEAN'.\n\n"
        f"Data: {content_desc}"
    )
    
    try:
        response = ollama.chat(model=MODEL, messages=[
            {'role': 'system', 'content': 'You are a cybersecurity expert. Do NOT flag standard system services as malicious. Respond ONLY "MALICIOUS" or "CLEAN".'},
            {'role': 'user', 'content': prompt},
        ])
        result = response['message']['content'].strip().upper()
        return "MALICIOUS" in result
    except Exception as e:
        print(f"AI Error: {e}")
        return False

def watch_quarantine():
    """Monitor industrial quarantine folder for new uploads."""
    # This function is used by the web server to trigger a scan
    pass

def follow_logs():
    """Real-time monitoring of Tetragon syscall logs."""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
        
    with open(LOG_FILE, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                data = json.loads(line)
                # Filter for sys_openat and sys_connect related entries
                simplified = {
                    "binary": data.get("process_kprobe", {}).get("process", {}).get("binary"),
                    "func": data.get("process_kprobe", {}).get("function_name"),
                    "args": data.get("process_kprobe", {}).get("args")
                }
                
                if analyze_with_ai(json.dumps(simplified), "Tetragon Log"):
                    print(f"[!] MALICIOUS ACTIVITY: {simplified['binary']}")
                    set_keyboard_color("MALICIOUS")
                    with open(ALERT_FILE, 'a') as af:
                        af.write(f"[{time.ctime()}] MALICIOUS SYSCALL: {line}\n")
                else:
                    set_keyboard_color("CLEAN")
                    
            except Exception as e:
                pass

if __name__ == "__main__":
    print("Sentinel-Brain Hardware-Sync Active...")
    # Initial color: Blue
    set_keyboard_color("CLEAN")
    follow_logs()
