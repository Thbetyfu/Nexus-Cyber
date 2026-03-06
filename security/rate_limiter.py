"""
Rate limiting and DoS protection
Prevents abuse and brute force attacks
"""

import logging
import time
from typing import Dict, Tuple, Optional
from collections import defaultdict
from threading import Lock
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiting by IP address"""
    
    def __init__(self,
                 max_requests: int = 100,
                 time_window: int = 60,
                 cleanup_interval: int = 300):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Max requests per time window
            time_window: Time window in seconds
            cleanup_interval: Cleanup old entries (seconds)
        """
        
        self.max_requests = max_requests
        self.time_window = time_window
        self.cleanup_interval = cleanup_interval
        
        self.requests: Dict[str, list] = defaultdict(list)
        self.last_cleanup = time.time()
        self.lock = Lock()
    
    def is_allowed(self, ip: str) -> Tuple[bool, Dict]:
        """
        Check if IP is allowed to make request
        
        Returns: (allowed, info_dict)
        """
        
        with self.lock:
            now = time.time()
            
            # Cleanup old entries periodically
            if now - self.last_cleanup > self.cleanup_interval:
                self._cleanup(now)
                self.last_cleanup = now
            
            # Get request timestamps for IP
            timestamps = self.requests[ip]
            
            # Remove old timestamps outside window
            cutoff = now - self.time_window
            timestamps[:] = [ts for ts in timestamps if ts > cutoff]
            
            # Check limit
            if len(timestamps) >= self.max_requests:
                return False, {
                    'current_requests': len(timestamps),
                    'max_requests': self.max_requests,
                    'reset_in_seconds': int(timestamps[0] - cutoff)
                }
            
            # Record this request
            timestamps.append(now)
            
            return True, {
                'current_requests': len(timestamps),
                'max_requests': self.max_requests,
                'requests_remaining': self.max_requests - len(timestamps)
            }
    
    def _cleanup(self, now: float):
        """Remove old IP entries"""
        
        cutoff = now - self.time_window * 2
        ips_to_remove = []
        
        for ip, timestamps in self.requests.items():
            active = [ts for ts in timestamps if ts > cutoff]
            if not active:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.requests[ip]
        
        if ips_to_remove:
            logger.debug(f"Cleaned up {len(ips_to_remove)} IP entries")
    
    def get_stats(self, ip: str) -> Dict:
        """Get stats for an IP"""
        
        with self.lock:
            timestamps = self.requests.get(ip, [])
            return {
                'ip': ip,
                'total_requests': len(timestamps),
                'in_window': len([ts for ts in timestamps 
                                 if ts > time.time() - self.time_window])
            }


class BruteForceDetector:
    """Detect brute force attacks"""
    
    def __init__(self,
                 max_failures: int = 5,
                 lockout_duration: int = 900):  # 15 minutes
        """
        Initialize brute force detector
        
        Args:
            max_failures: Failed attempts before lockout
            lockout_duration: Lockout duration in seconds
        """
        
        self.max_failures = max_failures
        self.lockout_duration = lockout_duration
        
        self.failed_attempts: Dict[str, list] = defaultdict(list)
        self.locked_ips: Dict[str, float] = {}
        self.lock = Lock()
    
    def is_locked(self, ip: str) -> bool:
        """Check if IP is locked out"""
        
        with self.lock:
            if ip not in self.locked_ips:
                return False
            
            lockout_until = self.locked_ips[ip]
            if time.time() < lockout_until:
                return True
            else:
                # Unlock
                del self.locked_ips[ip]
                return False
    
    def record_failure(self, ip: str):
        """Record failed login attempt"""
        
        with self.lock:
            now = time.time()
            
            # Add failure
            self.failed_attempts[ip].append(now)
            
            # Remove old failures (older than lockout_duration)
            cutoff = now - self.lockout_duration
            self.failed_attempts[ip] = [
                ts for ts in self.failed_attempts[ip] if ts > cutoff
            ]
            
            # Check if should lock
            if len(self.failed_attempts[ip]) >= self.max_failures:
                lockout_until = now + self.lockout_duration
                self.locked_ips[ip] = lockout_until
                logger.warning(f"IP {ip} locked out due to brute force attempts")
    
    def record_success(self, ip: str):
        """Record successful login"""
        
        with self.lock:
            # Clear failures on success
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]
                
            # Unlock if locked
            if ip in self.locked_ips:
                del self.locked_ips[ip]
            
            logger.info(f"Successful login from {ip}")
    
    def get_stats(self, ip: str) -> Dict:
        """Get stats for an IP"""
        
        with self.lock:
            is_locked = self.is_locked(ip)
            failures = len(self.failed_attempts.get(ip, []))
            
            return {
                'ip': ip,
                'is_locked': is_locked,
                'failed_attempts': failures,
                'max_failures': self.max_failures,
                'remaining_attempts': max(0, self.max_failures - failures)
            }
