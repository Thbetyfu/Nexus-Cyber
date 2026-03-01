#!/bin/bash
# Ghost Mode Starter Script for Nexus-Cyber
# This script launches the core defense components in the background.

PROJECT_DIR="/home/taqy/Nexus-Cyber"
VENV_PATH="$PROJECT_DIR/venv/bin/activate"

echo "[*] Initializing Nexus-Cyber Ghost Mode..."

# Activate Virtual Environment
if [ -f "$VENV_PATH" ]; then
    source "$VENV_PATH"
else
    echo "[!] Virtual environment not found at $VENV_PATH"
    exit 1
fi

# Ensure log directory exists
mkdir -p "$PROJECT_DIR/logs"

# Kill any existing instances to avoid port/resource conflicts
pkill -f "sentinel_brain.py" || true
pkill -f "web_gateway.py" || true

# Start Sentinel-Brain (AI Syscall Monitor & Hardware Sync)
nohup python3 -u "$PROJECT_DIR/sentinel_brain.py" > "$PROJECT_DIR/logs/sentinel.log" 2>&1 &
echo "[+] Sentinel-Brain launched as Daemon."

# Start Web Gateway (Secure Upload & Sandbox Detonator)
nohup python3 -u "$PROJECT_DIR/web_gateway.py" > "$PROJECT_DIR/logs/web.log" 2>&1 &
echo "[+] Web Gateway launched as Daemon (Port 5000)."

echo "[*] Ghost Mode Deployment Complete. System is now autonomous."
