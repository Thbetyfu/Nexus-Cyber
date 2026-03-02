#!/bin/bash
# Nexus-Cyber Emergency Purge Script
# Fallback mechanism if the web gateway /reset endpoint fails.

echo "[*] Initiating Emergency System Purge..."

# 1. Clear Quarantine
echo "[*] Purging Quarantine Directory..."
rm -rf /home/taqy/Nexus-Cyber/quarantine/*
touch '/home/taqy/Nexus-Cyber/quarantine/.gitkeep'

# 2. Reset Forensic Logs to SAFE state
echo "[*] Wiping Forensic Logs..."
echo '{"status": "CLEAN", "reason": "System Purged Globally", "action": "Manual Administrator Override", "timeline": [], "network_target": {}}' > /home/taqy/Nexus-Cyber/logs/detailed_alerts.log
> /home/taqy/Nexus-Cyber/logs/alerts.txt
> /home/taqy/Nexus-Cyber/logs/sentinel.log
> /home/taqy/Nexus-Cyber/logs/web.log

# 3. Reset Hardware LED (Blue)
echo "[*] Resetting Hardware Interlocks..."
echo "Thoriqtaqy2006$" | sudo -S asusctl aura effect static -c 0000ff > /dev/null 2>&1

# 4. Restart Background Daemons
echo "[*] Restarting Sentinel AI..."
echo "Thoriqtaqy2006$" | sudo -S systemctl restart nexus-sentinel.service

echo "[+] Emergency Purge Complete. System Secure."
