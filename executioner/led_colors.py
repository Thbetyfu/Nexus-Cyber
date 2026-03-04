import subprocess

HEX_COLORS = {
    "CRITICAL_RED": "ff0000",
    "SAFE_GREEN": "00ff00",
    "NORMAL_BLUE": "0000ff"
}

def is_asus_tuf():
    try:
        # Check if asusctl exists (indicates ASUS Linux support)
        result = subprocess.run(["which", "asusctl"], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False
