import json
import os
import time
import ollama
import subprocess
import requests

LOG_FILE = "/home/taqy/Nexus-Cyber/tetragon.json"
QUARANTINE_DIR = "/home/taqy/Nexus-Cyber/quarantine"
ALERT_FILE = "/home/taqy/Nexus-Cyber/logs/alerts.txt"
SESSION_MAP_FILE = '/home/taqy/Nexus-Cyber/logs/session_map.json'
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
    except Exception as e:
        print(f"Geo-IP Error: {e}")
        return "OFFLINE/TIMEOUT"

def scrape_tetragon_for_ip(filename, max_lines=500):
    """
    Search backwards through tetragon.json for the most recent network activity 
    associated with the detonated filename. 
    Looks specifically for 'sockaddr' or 'sin_addr' in the 'args' array.
    """
    if not os.path.exists(LOG_FILE):
        return "Local/None"

    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            
            # Read from bottom to top (most recent first)
            for line in reversed(lines[-max_lines:]):
                if filename in line:
                    try:
                        data = json.loads(line)
                        kprobe = data.get("process_kprobe", {})
                        if isinstance(kprobe, dict):
                            args = kprobe.get("args")
                            if isinstance(args, list):
                                # Search for sockaddr or sin_addr in arguments
                                for arg in args:
                                    if isinstance(arg, dict):
                                        sockaddr = arg.get("sockaddr") or arg.get("sin_addr")
                                        if sockaddr and isinstance(sockaddr, dict):
                                            ip = sockaddr.get("addr")
                                            if ip:
                                                # Ignore IPv6 loopbacks and local unroutable
                                                if ip in ["::1", "127.0.0.1", "0.0.0.0"]:
                                                    continue
                                                return ip
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error scraping Tetragon logs: {e}")
        
    return "Local/None"


def analyze_with_ai(content_desc, source_name, injected_network=None):
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
        f"Data Source: {source_name} (Kernel Syscalls/File Metadata).\n"
    )
    
    if injected_network and injected_network['ip'] != "Local/None":
        prompt += (
            f"CRITICAL INSTRUCTION: Gunakan data IP dan Lokasi yang saya berikan di bawah ini "
            f"untuk mengisi field network_target di JSON Anda. JANGAN menulis N/A jika saya sudah memberikan datanya.\n"
            f"IP Target: {injected_network['ip']}, Lokasi: {injected_network['location']}, Port: {injected_network.get('port', 'N/A')}.\n"
            f"Pastikan timeline mencerminkan koneksi ke jaringan ini (contoh: 'Detected network attempt to {injected_network['ip']} ({injected_network['location']})').\n"
        )

    prompt += (
        "Instructions: Based on the provided data, reconstruct a Chronological Timeline of events. "
        "Summarize specifically if there is evidence of exploitation, data access, or CNC connection. "
        "You MUST respond ONLY with a valid JSON in exactly this format:\n"
        '{"status": "MALICIOUS" or "SAFE", "reason": "Overview", "timeline": ["step 1", "step 2", "step 3"], "action": "Countermeasure", "network_target": {"ip": "...", "location": "...", "port": "..."}}\n\n'
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

def analyze_file_dynamic(filepath):
    """
    Synchronized forensic workflow:
    1. Wait for Firejail execution (3 seconds).
    2. Scrape Tetragon logs for networking IPs related to the file.
    3. Geo-IP lookup.
    4. Call Llama-3 with injected network data for a guaranteed complete JSON report.
    """
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    
    # Bypass AI for known safe binary/image extensions
    safe_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3']
    if ext in safe_extensions:
        return {"status": "CLEAN", "message": f"File scanned ({ext}) and marked as CLEAN (AI Bypass)."}

    print(f"[*] analyze_file_dynamic sleeping for 3 seconds to harvest network logs for {filename}...")
    time.sleep(3) # Wait for Firejail to finish or at least make the network call
    
    # Scrape Tetragon logs backwards
    detected_ip = scrape_tetragon_for_ip(filename)
    location = get_ip_location(detected_ip) if detected_ip != "Local/None" else "Local/None"
    
    injected_network = {
        "ip": detected_ip,
        "location": location,
        "port": "N/A" # We can extrapolate or rely on Llama if it reads the log, but IP/Loc are the most important
    }
    
    print(f"[+] Harvested Dynamic Data for {filename}: IP={detected_ip}, Loc={location}")

    # Read first 2KB of file for context
    try:
        with open(filepath, 'rb') as f:
            snippet = f.read(2048).decode('utf-8', errors='ignore')
    except:
        snippet = "Binary/Unreadable content"

    # Let Llama 3 analyze the static file snippet + the dynamic network knowledge we just gathered
    analysis = analyze_with_ai(snippet, f"File Content: {filename}", injected_network)
    
    if analysis.get("status") in ["MALICIOUS"]:
        # Get session IP
        target_ip = "UNKNOWN"
        try:
            if os.path.exists(SESSION_MAP_FILE):
                with open(SESSION_MAP_FILE, 'r') as sm:
                    smap = json.load(sm)
                    target_ip = smap.get(filename, "UNKNOWN")
        except:
            pass

        alert_data = {
            "timestamp": time.ctime(),
            "status": "MALICIOUS",
            "reason": analysis.get("reason", "Malicious file detected based on dynamic behavior"),
            "timeline": analysis.get("timeline", ["1. File execution monitored", "2. Suspicious activity flagged"]),
            "action": analysis.get("action", "File quarantined and execution blocked"),
            "network_target": analysis.get("network_target", injected_network),
            "raw_file": filename,
            "target_ip": target_ip
        }

        with open("/home/taqy/Nexus-Cyber/logs/detailed_alerts.log", "a") as df:
            df.write(json.dumps(alert_data) + "\n")
            
        print(f"[!] DYNAMIC ANALYSIS DETECTED THREAT: {filename}")
        set_keyboard_color("MALICIOUS")
        
    return analysis

def watch_quarantine():
    """Monitor industrial quarantine folder for new uploads."""
    # This function is used by the web server to trigger a scan using async detonate_file
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

                    # Associate with IP from session map
                    target_ip = "UNKNOWN"
                    try:
                        if os.path.exists(SESSION_MAP_FILE):
                            with open(SESSION_MAP_FILE, 'r') as sm:
                                smap = json.load(sm)
                                # Firejail copies the binary to /quarantine, so we extract just the filename
                                binary_name = os.path.basename(simplified.get('binary', ''))
                                target_ip = smap.get(binary_name, "UNKNOWN")
                    except Exception as e:
                        print(f"Session map error: {e}")

                    print(f"[!] MALICIOUS ACTIVITY ({target_ip}): {simplified['binary']} -> {net_target['ip']}")
                    
                    # Store comprehensive forensic log
                    alert_data = {
                        "timestamp": time.ctime(),
                        "status": "MALICIOUS",
                        "reason": analysis.get("reason", "Malicious activity detected"),
                        "timeline": analysis.get("timeline", ["Suspicious activity detected in kernel"]),
                        "action": analysis.get("action", "Process restricted by sensor"),
                        "network_target": net_target,
                        "raw_binary": simplified['binary'],
                        "target_ip": target_ip
                    }
                    
                    with open("/home/taqy/Nexus-Cyber/logs/detailed_alerts.log", "a") as df:
                        df.write(json.dumps(alert_data) + "\n")
                        
                    with open(ALERT_FILE, 'a') as af:
                        af.write(f"[{time.ctime()}] MALICIOUS SYSCALL ({target_ip}): {line}\n")
                        
                    # Hardware alert is physical, so it's a global indicator naturally.
                    set_keyboard_color("MALICIOUS")
                # Removed 'else' to latch alert as per previous fix
                    
            except Exception as e:
                pass

if __name__ == "__main__":
    print("Sentinel-Brain Hardware-Sync Active...")
    # Initial color: Blue
    set_keyboard_color("CLEAN")
    follow_logs()
