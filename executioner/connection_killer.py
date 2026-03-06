"""
Connection Killer: Kill TCP connections and ban IPs
Implements:
- TCP connection termination
- iptables firewall rule injection
- IP blacklist tracking
- Graceful error handling
"""

import subprocess
import logging
import os
import sys
from typing import Tuple, Dict, Optional
from datetime import datetime, timedelta
import asyncio

logger = logging.getLogger(__name__)

# ===========================
# CONFIGURATION
# ===========================

SUDO_PASSWORD = os.getenv('ADMIN_PASSWORD', 'default_password')
ENABLE_IPTABLES = os.getenv('ENABLE_IPTABLES', 'true').lower() == 'true'
BAN_DURATION_HOURS = int(os.getenv('BAN_DURATION_HOURS', 24))

# ===========================
# CONNECTION KILLER
# ===========================

class ConnectionKiller:
    """Kill malicious connections and ban IPs"""
    
    def __init__(self):
        self.logger = logger
        self.blocked_ips = set()  # In-memory cache of blocked IPs
        self.kill_attempts = {}   # Track kill attempts per IP
    
    async def kill_connection(self, 
                             source_ip: str,
                             reason: str = "Threat detected") -> Tuple[bool, str]:
        """
        Kill TCP connection from malicious IP
        
        Steps:
        1. Check if IP already blocked
        2. Ban IP via iptables
        3. Kill existing connections (optional: killall)
        4. Log incident
        
        Returns: (success, message)
        """
        
        self.logger.critical(f"🔴 EXECUTING KILL on {source_ip}: {reason}")
        
        # NEVER kill/ban localhost (for safety during testing)
        if source_ip in ['127.0.0.1', 'localhost', '::1']:
            self.logger.warning(f"Skipping kill for WHITELISTED localhost IP: {source_ip}")
            return True, "Skipped whitelist IP"

        # Check if already blocked
        if source_ip in self.blocked_ips:
            self.logger.warning(f"IP {source_ip} already blocked")
            return True, f"IP already blocked"
        
        success = True
        messages = []
        
        # Step 1: Block IP via iptables
        if ENABLE_IPTABLES:
            result, msg = await self._block_ip_iptables(source_ip)
            if result:
                self.blocked_ips.add(source_ip)
                messages.append(msg)
            else:
                success = False
                messages.append(f"Failed to block IP: {msg}")
        
        # Step 2: Kill existing connections from this IP
        result, msg = await self._kill_connections_from_ip(source_ip)
        messages.append(msg)
        
        if not result:
            success = False
        
        # Step 3: Record kill attempt
        self.kill_attempts[source_ip] = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'success': success
        }
        
        # Step 4: Log in application log
        log_msg = " | ".join(messages)
        self.logger.critical(f"Kill executed for {source_ip}: {log_msg}")
        
        return success, log_msg
    
    async def _block_ip_iptables(self, source_ip: str) -> Tuple[bool, str]:
        """
        Block IP using iptables
        
        Command: sudo iptables -I INPUT -s <IP> -j DROP
        """
        
        try:
            # Construct iptables command
            iptables_cmd = f'echo "{SUDO_PASSWORD}" | sudo -S iptables -I INPUT -s {source_ip} -j DROP'
            
            self.logger.debug(f"Executing: {iptables_cmd}")
            
            # Execute command
            result = await asyncio.to_thread(
                subprocess.run,
                iptables_cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                self.logger.info(f"✓ iptables rule added for {source_ip}")
                return True, f"iptables DROP rule added for {source_ip}"
            else:
                error = result.stderr or "Unknown error"
                self.logger.error(f"iptables error: {error}")
                return False, f"iptables error: {error}"
        
        except subprocess.TimeoutExpired:
            self.logger.error(f"iptables command timeout for {source_ip}")
            return False, "iptables command timeout"
        
        except Exception as e:
            self.logger.error(f"iptables exception: {e}")
            return False, str(e)
    
    async def _kill_connections_from_ip(self, source_ip: str) -> Tuple[bool, str]:
        """
        Kill all existing connections from IP
        
        Uses: netstat/ss to find connections, killall to terminate
        """
        
        try:
            # Find processes connected from this IP
            netstat_cmd = f"netstat -ntp | grep {source_ip} | awk '{{print $7}}' | cut -d'/' -f1"
            
            result = await asyncio.to_thread(
                subprocess.run,
                netstat_cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            pids = result.stdout.strip().split('\n')
            pids = [pid for pid in pids if pid and pid != '-']
            
            if pids:
                for pid in pids:
                    try:
                        kill_cmd = f'echo "{SUDO_PASSWORD}" | sudo -S kill -9 {pid}'
                        kill_result = await asyncio.to_thread(
                            subprocess.run,
                            kill_cmd,
                            shell=True,
                            capture_output=True,
                            timeout=5
                        )
                        
                        if kill_result.returncode == 0:
                            self.logger.info(f"✓ Killed process {pid}")
                    
                    except Exception as e:
                        self.logger.warning(f"Failed to kill {pid}: {e}")
                
                return True, f"Killed {len(pids)} connection(s)"
            else:
                return True, "No active connections found (connection already closed)"
        
        except Exception as e:
            self.logger.warning(f"Failed to kill connections: {e}")
            return True, f"No connections killed (may already be closed): {e}"
    
    async def block_ip(self, 
                      source_ip: str,
                      reason: str = "Threat detected",
                      duration_hours: int = None) -> Tuple[bool, str]:
        """
        Block IP without killing connection
        
        Softer action than kill_connection
        """
        
        if duration_hours is None:
            duration_hours = BAN_DURATION_HOURS
        
        self.logger.warning(f"⚠️  BLOCKING IP {source_ip}: {reason}")
        
        # NEVER block localhost
        if source_ip in ['127.0.0.1', 'localhost', '::1']:
            self.logger.warning(f"Skipping block for WHITELISTED localhost IP: {source_ip}")
            return True, "Skipped whitelist IP"

        if source_ip in self.blocked_ips:
            self.logger.warning(f"IP {source_ip} already blocked")
            return True, "IP already blocked"
        
        # Add to iptables
        if ENABLE_IPTABLES:
            success, msg = await self._block_ip_iptables(source_ip)
            if success:
                self.blocked_ips.add(source_ip)
                return True, msg
            else:
                return False, msg
        else:
            self.blocked_ips.add(source_ip)
            return True, "IP blocked in-memory (iptables disabled)"
    
    async def unblock_ip(self, source_ip: str) -> Tuple[bool, str]:
        """
        Unblock previously blocked IP
        """
        
        self.logger.info(f"🟢 UNBLOCKING IP {source_ip}")
        
        if source_ip not in self.blocked_ips:
            return True, "IP not in blocked list"
        
        try:
            # Remove iptables rule
            if ENABLE_IPTABLES:
                iptables_cmd = f'echo "{SUDO_PASSWORD}" | sudo -S iptables -D INPUT -s {source_ip} -j DROP'
                
                result = await asyncio.to_thread(
                    subprocess.run,
                    iptables_cmd,
                    shell=True,
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                
                if result.returncode == 0:
                    self.blocked_ips.discard(source_ip)
                    self.logger.info(f"✓ iptables rule removed for {source_ip}")
                    return True, f"IP unblocked: {source_ip}"
                else:
                    return False, result.stderr or "Unknown error"
            else:
                self.blocked_ips.discard(source_ip)
                return True, "IP unblocked in-memory"
        
        except Exception as e:
            self.logger.error(f"Error unblocking IP: {e}")
            return False, str(e)
    
    def is_blocked(self, source_ip: str) -> bool:
        """Check if IP is blocked"""
        return source_ip in self.blocked_ips
    
    def get_blocked_ips(self) -> list:
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
    
    def get_kill_stats(self) -> Dict:
        """Get kill statistics"""
        successful_kills = sum(1 for v in self.kill_attempts.values() if v['success'])
        
        return {
            'total_kills_attempted': len(self.kill_attempts),
            'successful_kills': successful_kills,
            'failed_kills': len(self.kill_attempts) - successful_kills,
            'blocked_ips_count': len(self.blocked_ips),
            'blocked_ips': list(self.blocked_ips),
            'recent_kills': list(self.kill_attempts.items())[-10:]  # Last 10
        }

# ===========================
# HARDWARE ALERTING
# ===========================

class HardwareAlerter:
    """Control ASUS hardware to signal threats"""
    
    def __init__(self, admin_password: str = SUDO_PASSWORD):
        self.admin_password = admin_password
        self.logger = logger
    
    async def trigger_alert(self, alert_type: str = "CRITICAL"):
        """
        Trigger hardware alerts
        
        Alert types:
        - CRITICAL: Red RGB + Turbo fan
        - WARNING: Yellow/Orange RGB + Performance fan
        - CLEAR: Blue RGB + Balanced fan
        """
        
        if alert_type == "CRITICAL":
            await self._set_keyboard_color("ff0000")  # Red
            await self._set_fan_mode("Performance")
            self.logger.critical("🔴 CRITICAL ALERT: RGB Red + Fan Performance")
        
        elif alert_type == "WARNING":
            await self._set_keyboard_color("ffaa00")  # Orange
            await self._set_fan_mode("Performance")
            self.logger.warning("🟠 WARNING: RGB Orange + Fan Performance")
        
        elif alert_type == "CLEAR":
            await self._set_keyboard_color("0000ff")  # Blue
            await self._set_fan_mode("Balanced")
            self.logger.info("🔵 CLEAR: RGB Blue + Fan Balanced")
    
    async def _set_keyboard_color(self, hex_color: str):
        """Set ASUS keyboard RGB color"""
        
        try:
            cmd = f'echo "{self.admin_password}" | sudo -S asusctl aura effect static -c {hex_color}'
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                self.logger.debug(f"✓ Keyboard color set to {hex_color}")
            else:
                self.logger.warning(f"Failed to set keyboard color: {result.stderr}")
        
        except Exception as e:
            self.logger.warning(f"Hardware alert error (non-critical): {e}")
    
    async def _set_fan_mode(self, mode: str = "Balanced"):
        """Set ASUS fan profile"""
        
        try:
            cmd = f'echo "{self.admin_password}" | sudo -S asusctl profile -P {mode}'
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                self.logger.debug(f"✓ Fan mode set to {mode}")
            else:
                self.logger.warning(f"Failed to set fan mode: {result.stderr}")
        
        except Exception as e:
            self.logger.warning(f"Fan control error (non-critical): {e}")

# ===========================
# TELEGRAM ALERTING
# ===========================

class TelegramAlerter:
    """Send alerts via Telegram"""
    
    def __init__(self, token: str = None, chat_id: str = None):
        self.token = token or os.getenv('TELEGRAM_TOKEN')
        self.chat_id = chat_id or os.getenv('TELEGRAM_CHAT_ID')
        self.logger = logger
    
    async def send_alert(self, message: str, severity: str = "INFO"):
        """Send alert to Telegram"""
        
        if not self.token or not self.chat_id:
            self.logger.warning("Telegram not configured")
            return
        
        try:
            import aiohttp
            
            # Format message with emoji
            emoji_map = {
                'CRITICAL': '🔴',
                'WARNING': '🟠',
                'INFO': 'ℹ️',
                'SUCCESS': '✅'
            }
            
            emoji = emoji_map.get(severity, '📢')
            formatted_msg = f"{emoji} **{severity}**\n{message}"
            
            url = f"https://api.telegram.org/bot{self.token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': formatted_msg,
                'parse_mode': 'Markdown'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=5) as resp:
                    if resp.status == 200:
                        self.logger.debug("✓ Telegram alert sent")
                    else:
                        self.logger.warning(f"Telegram error: {resp.status}")
        
        except Exception as e:
            self.logger.warning(f"Telegram send failed (non-critical): {e}")

# ===========================
# TEST FUNCTION
# ===========================

async def test_killer():
    """Test connection killer"""
    
    killer = ConnectionKiller()
    
    print("🧪 Testing Connection Killer...")
    
    # Test 1: Block IP
    print("\n1. Testing IP block...")
    success, msg = await killer.block_ip("192.168.1.255", "Test block")
    print(f"   Result: {success}, {msg}")
    
    # Test 2: Check if blocked
    is_blocked = killer.is_blocked("192.168.1.255")
    print(f"   Is blocked: {is_blocked}")
    
    # Test 3: Get blocked IPs
    blocked = killer.get_blocked_ips()
    print(f"   Blocked IPs: {blocked}")
    
    # Test 4: Get stats
    stats = killer.get_kill_stats()
    print(f"   Kill stats: {stats}")
    
    print("\n✅ Connection killer tests completed")

if __name__ == '__main__':
    asyncio.run(test_killer())
