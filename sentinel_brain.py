import json
import os
import time
import ollama
import subprocess
import requests

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

def get_ip_location(ip):
    """Retrieve Geo-IP information for a given address."""
    if ip in ["127.0.0.1", "0.0.0.0", "localhost"] or ip.startswith("192.168."):
        return "INTERNAL/LOCAL"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return f"{data.get('city')}, {data.get('country')}"
        return "UNKNOWN LOCATION"
    except:
        return "OFFLINE/TIMEOUT"

def analyze_with_ai(content_desc, source_name):
    """Send log or file info to Llama 3 for structured forensic analysis."""
    # Pre-filter for common system binaries and activities to reduce noise
    system_whitelist = [
        '"binary": "/usr/lib', '"binary": "/usr/bin', '"binary": "/bin',
        '"binary": "/usr/sbin/chronyd', '"binary": "/usr/sbin',
        '"binary": "/home/taqy/Nexus-Cyber/venv/bin/python3"',
        '"binary": "/usr/share/antigravity', '"binary": "/usr/local/bin/ollama'
    ]
    
    if any(item in content_desc for item in system_whitelist):
        return {"status": "SAFE"}
        
    prompt = (
        f"Role: Digital Forensic Expert Expert.\n"
        f"Data Source: {source_name} (Kernel Syscalls via eBPF).\n"
        "Instructions: Based on the provided log, reconstruct a Chronological Timeline of events. "
        "Summarize specifically if there is evidence of exploitation, data access, or CNC connection. "
        "You MUST respond ONLY with a valid JSON in exactly this format:\n"
        '{"status": "MALICIOUS" or "SAFE", "reason": "Overview", "timeline": ["step 1", "step 2", "step 3"], "action": "Countermeasure"}\n\n'
        f"Data: {content_desc}"
    )
    
    try:
        response = ollama.chat(model=MODEL, messages=[
            {'role': 'system', 'content': 'You are a Digital Forensic Analyst. Response MUST be valid JSON only. Focus on chronological reasoning.'},
            {'role': 'user', 'content': prompt},
        ])
        raw_content = response['message']['content'].strip()
        start = raw_content.find('{')
        end = raw_content.rfind('}') + 1
        if start != -1 and end != 0:
            return json.loads(raw_content[start:end])
        return {"status": "SAFE"}
    except Exception as e:
        print(f"AI/JSON Parsing Error: {e}")
        return {"status": "SAFE"}

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
                
                analysis = analyze_with_ai(json.dumps(simplified), "Tetragon Log")
                
                if analysis.get("status") == "MALICIOUS":
                    # Extract network data if present
                    net_target = {"ip": "N/A", "location": "N/A", "port": "N/A"}
                    args = simplified.get("args", [])
                    for arg in args:
                        if isinstance(arg, dict) and "sockaddr" in str(arg).lower():
                            addr = arg.get("sockaddr", {})
                            ip = addr.get("addr", "N/A")
                            port = addr.get("port", "N/A")
                            net_target["ip"] = ip
                            net_target["port"] = port
                            net_target["location"] = get_ip_location(ip)

                    print(f"[!] MALICIOUS ACTIVITY: {simplified['binary']} -> {net_target['ip']}")
                    set_keyboard_color("MALICIOUS")
                    
                    # Store comprehensive forensic log
                    alert_data = {
                        "timestamp": time.ctime(),
                        "status": "MALICIOUS",
                        "reason": analysis.get("reason", "Malicious activity detected"),
                        "timeline": analysis.get("timeline", ["Suspicious activity detected in kernel"]),
                        "action": analysis.get("action", "Process restricted by sensor"),
                        "network_target": net_target,
                        "raw_binary": simplified['binary']
                    }
                    
                    with open("/home/taqy/Nexus-Cyber/logs/detailed_alerts.log", "a") as df:
                        df.write(json.dumps(alert_data) + "\n")
                        
                    with open(ALERT_FILE, 'a') as af:
                        af.write(f"[{time.ctime()}] MALICIOUS SYSCALL: {line}\n")
                # Removed 'else' to latch alert as per previous fix
                    
            except Exception as e:
                pass

if __name__ == "__main__":
    print("Sentinel-Brain Hardware-Sync Active...")
    # Initial color: Blue
    set_keyboard_color("CLEAN")
    follow_logs()
