import subprocess
import logging

logger = logging.getLogger("Executioner")

def drop_connection(client_ip: str):
    """
    Blocks a malicious IP at the system firewall level using iptables.
    """
    try:
        if client_ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
            logger.warning("Attempted to block localhost. Skipping iptables rule.")
            return

        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", client_ip, "-p", "tcp", "--dport", "3306", "-j", "DROP"]
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"Successfully dropped and banned IP: {client_ip}")

    except Exception as e:
        logger.error(f"Failed to apply iptables execution on {client_ip}: {e}")
