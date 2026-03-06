"""
Firewall Rules Manager: Manage iptables rules and IP blacklist
"""

import logging
import subprocess
import asyncio
import os
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

SUDO_PASSWORD = os.getenv('ADMIN_PASSWORD', 'default_password')
ENABLE_IPTABLES = os.getenv('ENABLE_IPTABLES', 'true').lower() == 'true'

# ===========================
# FIREWALL RULE DATACLASS
# ===========================

@dataclass
class FirewallRule:
    """Represents a firewall rule"""
    ip_address: str
    action: str  # DROP, REJECT, ACCEPT
    rule_num: int = None  # iptables rule number
    created_at: datetime = None
    reason: str = ""
    permanent: bool = False  # If True, don't expire
    expires_at: Optional[datetime] = None

# ===========================
# FIREWALL MANAGER
# ===========================

class FirewallManager:
    """Manage firewall rules"""
    
    def __init__(self):
        self.logger = logger
        self.rules: Dict[str, FirewallRule] = {}
    
    async def add_drop_rule(self, 
                           ip_address: str,
                           reason: str = "",
                           permanent: bool = True) -> Tuple[bool, str]:
        """
        Add DROP rule for IP
        
        Command: iptables -I INPUT -s <IP> -j DROP
        """
        
        if ip_address in self.rules:
            self.logger.warning(f"Rule already exists for {ip_address}")
            return True, f"Rule already exists"
        
        if not ENABLE_IPTABLES:
            self.logger.info(f"ENABLE_IPTABLES is false. Tracking {ip_address} in memory only.")
            rule = FirewallRule(
                ip_address=ip_address,
                action='DROP',
                created_at=datetime.now(),
                reason=reason,
                permanent=permanent
            )
            self.rules[ip_address] = rule
            return True, "IP blocked in-memory"

        try:
            cmd = f'echo "{SUDO_PASSWORD}" | sudo -S iptables -I INPUT -s {ip_address} -j DROP'
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                # Store rule
                rule = FirewallRule(
                    ip_address=ip_address,
                    action='DROP',
                    created_at=datetime.now(),
                    reason=reason,
                    permanent=permanent
                )
                self.rules[ip_address] = rule
                
                self.logger.info(f"✓ DROP rule added for {ip_address}")
                return True, f"DROP rule added for {ip_address}"
            else:
                return False, result.stderr or "Unknown error"
        
        except Exception as e:
            self.logger.error(f"Error adding rule: {e}")
            return False, str(e)
    
    async def remove_rule(self, ip_address: str) -> Tuple[bool, str]:
        """
        Remove DROP rule for IP
        
        Command: iptables -D INPUT -s <IP> -j DROP
        """
        
        if ip_address not in self.rules:
            self.logger.warning(f"No rule found for {ip_address}")
            return True, "Rule not found"
        
        if not ENABLE_IPTABLES:
            self.logger.info(f"ENABLE_IPTABLES is false. Removing {ip_address} from memory only.")
            del self.rules[ip_address]
            return True, "IP unblocked in-memory"

        try:
            cmd = f'echo "{SUDO_PASSWORD}" | sudo -S iptables -D INPUT -s {ip_address} -j DROP'
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                shell=True,
                capture_output=True,
                timeout=5,
                text=True
            )
            
            if result.returncode == 0:
                del self.rules[ip_address]
                self.logger.info(f"✓ Rule removed for {ip_address}")
                return True, f"Rule removed for {ip_address}"
            else:
                return False, result.stderr or "Unknown error"
        
        except Exception as e:
            self.logger.error(f"Error removing rule: {e}")
            return False, str(e)
    
    async def list_rules(self) -> List[FirewallRule]:
        """List all active rules"""
        return list(self.rules.values())
    
    async def cleanup_expired_rules(self) -> int:
        """Remove expired rules"""
        
        now = datetime.now()
        expired = [
            ip for ip, rule in self.rules.items()
            if rule.expires_at and rule.expires_at < now and not rule.permanent
        ]
        
        removed_count = 0
        for ip in expired:
            success, _ = await self.remove_rule(ip)
            if success:
                removed_count += 1
        
        if removed_count > 0:
            self.logger.info(f"Cleaned up {removed_count} expired rules")
        
        return removed_count
    
    async def get_statistics(self) -> Dict:
        """Get firewall statistics"""
        
        total_rules = len(self.rules)
        permanent_rules = sum(1 for r in self.rules.values() if r.permanent)
        temporary_rules = total_rules - permanent_rules
        
        return {
            'total_rules': total_rules,
            'permanent_rules': permanent_rules,
            'temporary_rules': temporary_rules,
            'blocked_ips': list(self.rules.keys()),
            'rules_detail': [
                {
                    'ip': ip,
                    'action': rule.action,
                    'reason': rule.reason,
                    'created_at': rule.created_at.isoformat() if rule.created_at else None,
                    'permanent': rule.permanent
                }
                for ip, rule in self.rules.items()
            ]
        }
