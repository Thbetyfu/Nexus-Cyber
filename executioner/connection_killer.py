import subprocess
import asyncio
import logging
from .led_colors import HEX_COLORS, is_asus_tuf

logger = logging.getLogger(__name__)

class ConnectionKiller:
    """Drop TCP connections and block IPs."""
    
    async def drop_connection(self, source_ip):
        """Block malicious IP immediately."""
        
        logger.critical(f"🔴 EXECUTING KILL on {source_ip}")
        
        try:
            # We don't want to block localhost during testing, bypass iptables for 127.0.0.1
            if source_ip == "127.0.0.1":
                logger.warning("Attempted to block localhost. Skipping iptables rule.")
            else:
                # Method 1: iptables DROP (permanent during session)
                cmd = f'sudo iptables -I INPUT -s {source_ip} -j DROP'
                subprocess.run(cmd, shell=True, check=False)
                logger.info(f"[+] iptables rule added for {source_ip}")
                
                # Method 2: Close active connections (if using conntrack)
                cmd2 = f'sudo conntrack -D -s {source_ip}'
                subprocess.run(cmd2, shell=True, check=False)
                logger.info(f"[+] Active connections from {source_ip} terminated")
            
            # Trigger ASUS fan turbo + keyboard red
            await self._trigger_hardware_alert()
            
        except Exception as e:
            logger.error(f"Kill execution error: {e}")
            
    async def _trigger_hardware_alert(self):
        """Make ASUS fan scream and keyboard glow red."""
        try:
            # Check if this is an asus TUF laptop by using our module
            if is_asus_tuf():
                # Password must be echoed over stdin for sudo commands normally
                password = "Thoriqtaqy2006$"
                # Fan to Turbo
                subprocess.run(f'echo "{password}" | sudo -S asusctl profile -P Performance', shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Keyboard Red
                subprocess.run(f'echo "{password}" | sudo -S asusctl aura effect static -c ff0000', shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            pass
