import json
import os
import time
import ollama
import subprocess
import requests
import threading

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

def hardware_cooldown():
    """Wait 5 seconds, then calm down the fan and LED."""
    time.sleep(5)
    try:
        print("[*] Calming down hardware (Balanced Mode)...")
        # Back to Balanced (or Quiet)
        cmd_fan = f'echo "{S_PASS}" | sudo -S asusctl profile -P Balanced'
        subprocess.run(cmd_fan, shell=True, check=False, capture_output=True)
        # Revert color to Blue (SAFE)
        set_keyboard_color("CLEAN")
    except Exception as e:
        print(f"Hardware Cooldown Error: {e}")

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

def send_telegram_alert(message):
    """Send an alert to the admin's Telegram via Bot API."""
    token = "8434796194:AAE2NEu5wJg9UxDaU0JF9JPX5CISvIjbVv0"
    chat_id = "7564036407"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        requests.post(url, json=payload, timeout=3)
    except Exception as e:
        print(f"Telegram Alert Error: {e}")

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
            {'role': 'system', 'content': 'You are a Digital Forensic Analyst. Response MUST be valid JSON only. Focus on chronological reasoning. Do not include any text outside the JSON block. Ensure all strings are properly escaped for JSON.'},
            {'role': 'user', 'content': prompt},
        ])
        raw_content = response['message']['content'].strip()
        
        # Look for the first '{' and last '}'
        start = raw_content.find('{')
        end = raw_content.rfind('}') + 1
        
        if start != -1 and end != 0:
            json_str = raw_content[start:end]
            try:
                # First attempt: direct parse
                return json.loads(json_str)
            except json.JSONDecodeError:
                # Second attempt: try simple fixes for common LLM JSON errors (like unescaped backslashes)
                try:
                    # Clean up common AI formatting artifacts
                    fixed_json = json_str.replace('\\', '\\\\').replace('\\\\"', '\\"')
                    return json.loads(fixed_json)
                except:
                    print(f"[-] AI JSON Parse Failed. Raw head: {raw_content[:100]}...")
                    return {"status": "SAFE"}
        
        print(f"[-] No JSON found in AI response. Raw head: {raw_content[:100]}...")
        return {"status": "SAFE"}
    except Exception as e:
        print(f"AI/JSON Parsing Error: {e}")
        return {"status": "SAFE"}

def reflex_decision(log_data):
    # Whitelist checks are now handled in follow_logs()
    pass
    prompt = f"Berdasarkan log eBPF atau file snippet ini, tentukan apakah ini ancaman berbahaya. Jawab HANYA dengan 1 kata mutlak: BLOCK atau ALLOW.\n\nData: {log_data}"
    
    try:
        response = ollama.chat(model="qwen2.5-coder", messages=[
            {'role': 'system', 'content': 'You are a cybersecurity reflex engine. Return ONLY the word BLOCK or ALLOW. No explanation. ALLOW normal user applications and OS background tasks. BLOCK only clear malicious anomalies like reverse shells, data exfiltration, or anomalous executions.'},
            {'role': 'user', 'content': prompt}
        ])
        decision = response['message']['content'].strip().upper()
        # Ensure it purely starts with BLOCK or equals BLOCK to evade hallucinatory text "DO NOT BLOCK"
        if decision == "BLOCK" or decision.startswith("BLOCK"):
            return "BLOCK"
        return "ALLOW"
    except Exception as e:
        print(f"Reflex Brain Error: {e}")
        return "ALLOW"
        
def forensic_analysis_task(log_data, filename, source_name, injected_network, target_ip="SYSTEM", force_malicious=False):
    """The Forensic Brain: Slow, detailed analysis in a background thread."""
    try:
        print(f"[*] Forensic Brain starting analysis for: {filename}...")
        analysis = analyze_with_ai(log_data, source_name, injected_network)
        
        if force_malicious:
            analysis["status"] = "MALICIOUS"
            if "reason" not in analysis or analysis.get("status", "") == "SAFE":
                analysis["reason"] = "Threat contained by Reflex Brain (Auto-Kill). AI Forensic generated."
                
        alert_data = {
            "timestamp": time.ctime(),
            "status": analysis.get("status", "CLEAN").upper(),
            "reason": analysis.get("reason", "File deemed safe by AI Forensics."),
            "timeline": analysis.get("timeline", ["Analysis completed successfully."]),
            "action": analysis.get("action", "Allow Execution."),
            "network_target": analysis.get("network_target", injected_network) if injected_network else analysis.get("network_target", {}),
            "raw_file": filename,
            "target_ip": target_ip
        }

        # ALWAYS write to detailed_alerts.log so the Web UI knows Forensic is done
        with open("/home/taqy/Nexus-Cyber/logs/detailed_alerts.log", "a") as df:
            df.write(json.dumps(alert_data) + "\n")
            
        if analysis.get("status") in ["MALICIOUS"]:
            print(f"[+] Forensic Brain finished analyzing {filename}. Details sent to UI.")
        else:
            print(f"[+] Forensic Brain cleared {filename} as SAFE. Logged in background.")
            
    except Exception as e:
        print(f"[-] Forensic Brain Thread Error: {e}")

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
        "port": "N/A"
    }
    
    print(f"[+] Harvested Dynamic Data for {filename}: IP={detected_ip}, Loc={location}")
    print(f"[*] Requesting Deep AI Analysis for {filename} with model: {MODEL}...")

    # Read first 2KB of file for context
    try:
        with open(filepath, 'rb') as f:
            snippet = f.read(2048).decode('utf-8', errors='ignore')
    except:
        snippet = "Binary/Unreadable content"

    # Use the Reflex Brain for msec-level lockdown
    decision = reflex_decision(snippet)
    
    # Get session IP first
    target_ip = "SYSTEM"
    try:
        if os.path.exists(SESSION_MAP_FILE):
            with open(SESSION_MAP_FILE, 'r') as sm:
                smap = json.load(sm)
                target_ip = smap.get(filename, "SYSTEM")
    except:
        pass
        
    if decision == "BLOCK":
        print(f"[!] REFLEX BRAIN DETECTED THREAT: {filename}")
        set_keyboard_color("MALICIOUS")
        alert_msg = (
            f"🚨 *NEXUS-CYBER: THREAT TERMINATED* 🚨\n\n"
            f"💀 *Target Destroyed:* `[WEB] {filename}`\n"
            f"⏱️ *Time:* `{time.ctime()}`\n"
            f"🛡️ *Action:* `BLOCK Sandbox Execution` via Reflex"
        )
        send_telegram_alert(alert_msg)
        with open(ALERT_FILE, 'a') as af:
            af.write(f"[{time.ctime()}] REFLEX BLOCK: {filename} from {target_ip} -> {detected_ip} ({location})\n")
    else:
        print(f"[+] Reflex Brain allowed execution for: {filename}")
        
    # Kick off the Forensic Brain asynchronously to avoid waiting
    threading.Thread(target=forensic_analysis_task, args=(snippet, filename, f"File Content: {filename}", injected_network, target_ip, decision == "BLOCK")).start()
    
    return {"status": "MALICIOUS" if decision == "BLOCK" else "CLEAN"}

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
                
                # OPTIMIZATION: Prevent Qwen overload! Only analyze network/file syscalls and execs!
                if simplified["func"] not in [None, "", "__x64_sys_openat", "__x64_sys_connect", "tcp_connect", 'tcp_v4_connect', 'tcp_v6_connect']:
                    continue

                log_data_str = json.dumps(simplified)
                
                # Global Whitelist: Ignore normal system background tasks for both AI Brains
                system_whitelist = [
                    '"binary": "/usr/lib"', '"binary": "/usr/lib/', '"binary": "/usr/libexec"',
                    '"binary": "/opt/"', '"binary": "/home/taqy/Nexus-Cyber/venv/bin/python3"',
                    '"binary": "/usr/share/"', '"binary": "/usr/local/bin/ollama"',
                    '"binary": "/etc/"', '"binary": "/var/"', '"binary": "/snap/"', 
                    '"binary": "/run/"', '"binary": "/sys/"', '"binary": "/proc/"',
                    '"binary": "/usr/bin/gnome-', '"binary": "/usr/bin/Xwayland"',
                    '"binary": "/usr/bin/dbus"', '"binary": "/usr/bin/pulseaudio"',
                    '"binary": "/usr/bin/pkill"', '"binary": "/usr/share/code"',
                    '"binary": "/usr/bin/asusd"', '"binary": "/usr/bin/asusctl"',
                    '"binary": "/usr/bin/sudo"', '"binary": "/usr/bin/systemctl"',
                    '"binary": "/usr/bin/journalctl"', '"binary": "/usr/bin/grep"',
                    '"binary": "/usr/bin/tail"', '"binary": "/usr/bin/git"'
                ]
                if any(item in log_data_str for item in system_whitelist):
                    continue
                
                decision = reflex_decision(log_data_str)
                
                # Extract basic info quickly
                binary_name = os.path.basename(simplified.get('binary', ''))
                pid = data.get("process_kprobe", {}).get("process", {}).get("pid")
                target_ip = "SYSTEM"
                try:
                    if os.path.exists(SESSION_MAP_FILE):
                        with open(SESSION_MAP_FILE, 'r') as sm:
                            smap = json.load(sm)
                            target_ip = smap.get(binary_name, "SYSTEM")
                except:
                    pass
                
                if decision == "BLOCK":
                    print(f"[!] REFLEX BRAIN SYSCALL BLOCK: {binary_name}")
                    
                    # Automated Containment (Auto-Kill)
                    kill_status = "Syscall Blocked (No PID)"
                    if pid:
                        try:
                            # Attempt to aggressively kill the malicious process
                            kill_cmd = f'echo "{S_PASS}" | sudo -S kill -9 {pid}'
                            result = subprocess.run(kill_cmd, shell=True, check=False, capture_output=True)
                            if result.returncode == 0:
                                print(f"[KILL] Process {pid} ({binary_name}) forcefully killed.")
                                kill_status = "SIGKILL (-9) Success"
                            else:
                                print(f"[KILL] Process {pid} may already be dead or unreachable.")
                                kill_status = "Target Already Dead / Terminated"
                        except Exception as e:
                            print(f"[KILL ERROR] Failed to execute kill command on {pid}: {e}")
                            kill_status = "SIGKILL Error"

                    alert_msg = (
                        f"🚨 *NEXUS-CYBER: THREAT TERMINATED* 🚨\n\n"
                        f"💀 *Target Detect:* `{binary_name}`\n"
                        f"🔢 *PID:* `{pid}`\n"
                        f"⏱️ *Time:* `{time.ctime()}`\n"
                        f"🛡️ *Action:* `{kill_status}` via Reflex"
                    )
                    send_telegram_alert(alert_msg)

                    set_keyboard_color("MALICIOUS")
                    try:
                        cmd_fan_max = f'echo "{S_PASS}" | sudo -S asusctl profile -P Performance'
                        subprocess.run(cmd_fan_max, shell=True, check=False, capture_output=True)
                    except: pass
                    
                    # Start asynchronous hardware cooldown
                    threading.Thread(target=hardware_cooldown).start()

                    with open(ALERT_FILE, 'a') as af:
                        af.write(f"[{time.ctime()}] REFLEX SYSCALL BLOCK & KILLED: {binary_name} ({target_ip}) PID:{pid}\n")
                        
                # 2. Forensic Brain (Slow Path Async)
                net_target = {"ip": "Local/None", "location": "Local/None", "port": "N/A"}
                args = simplified.get("args", [])
                for arg in args:
                    if isinstance(arg, dict) and "sockaddr" in str(arg).lower():
                        addr = arg.get("sockaddr", {})
                        ip = addr.get("addr", "N/A")
                        port = addr.get("port", "N/A")
                        net_target["ip"] = ip
                        net_target["port"] = port
                        net_target["location"] = get_ip_location(ip)
                        
                threading.Thread(target=forensic_analysis_task, args=(log_data_str, binary_name, "Tetragon Syscall Log", net_target, target_ip, decision == "BLOCK")).start()
                
            except Exception as e:
                pass

if __name__ == "__main__":
    print("Sentinel-Brain Hardware-Sync Active...")
    # Initial color: Blue
    set_keyboard_color("CLEAN")
    follow_logs()
