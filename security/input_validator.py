"""
Input validation and sanitization
Prevents injection attacks and malformed data
"""

import re
import logging
from typing import Any, Dict, Optional
from ipaddress import ip_address, AddressValueError

logger = logging.getLogger(__name__)

class InputValidator:
    """Validate and sanitize user input"""
    
    # Validation patterns
    IP_PATTERN = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$',
        re.IGNORECASE
    )
    
    USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,32}$')
    
    QUERY_MIN_LENGTH = 1
    QUERY_MAX_LENGTH = 100000
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validate IP address format (IPv4 or IPv6)
        
        Args:
            ip: IP address string
        
        Returns: True if valid, False otherwise
        """
        
        try:
            ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format"""
        
        if not username:
            return False
        
        return bool(InputValidator.USERNAME_PATTERN.match(username))
    
    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        """
        Validate password strength
        
        Returns: Dict with 'valid' boolean and 'issues' list
        """
        
        issues = []
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain lowercase letters")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain uppercase letters")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain digits")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain special characters")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues
        }
    
    @staticmethod
    def validate_query(query: str) -> Dict[str, Any]:
        """
        Validate SQL query
        
        Returns: Dict with 'valid' boolean and issues
        """
        
        issues = []
        
        if not query:
            issues.append("Query cannot be empty")
        
        if len(query) < InputValidator.QUERY_MIN_LENGTH:
            issues.append(f"Query too short (min {InputValidator.QUERY_MIN_LENGTH})")
        
        if len(query) > InputValidator.QUERY_MAX_LENGTH:
            issues.append(f"Query too long (max {InputValidator.QUERY_MAX_LENGTH})")
        
        # Null byte check (SQL injection attempt)
        if '\x00' in query:
            issues.append("Query contains null bytes")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues
        }
    
    @staticmethod
    def sanitize_log_message(message: str) -> str:
        """
        Sanitize log message (remove potentially sensitive data)
        
        Args:
            message: Message to sanitize
        
        Returns: Sanitized message
        """
        
        # Remove potential credentials
        message = re.sub(r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 
                        'password=[REDACTED]', 
                        message, 
                        flags=re.IGNORECASE)
        
        message = re.sub(r'token["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 
                        'token=[REDACTED]', 
                        message, 
                        flags=re.IGNORECASE)
        
        message = re.sub(r'secret["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 
                        'secret=[REDACTED]', 
                        message, 
                        flags=re.IGNORECASE)
        
        return message
    
    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML special characters"""
        
        escape_map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }
        
        for char, escape in escape_map.items():
            text = text.replace(char, escape)
        
        return text

# Test function
def test_validator():
    """Test input validator"""
    
    validator = InputValidator()
    
    print("🧪 Testing Input Validator...")
    
    # Test IP validation
    assert validator.validate_ip("192.168.1.1") is True
    assert validator.validate_ip("2001:db8::1") is True
    assert validator.validate_ip("invalid") is False
    print("✓ IP validation working")
    
    # Test username validation
    assert validator.validate_username("user_123") is True
    assert validator.validate_username("a") is False
    print("✓ Username validation working")
    
    # Test password validation
    result = validator.validate_password("Weak")
    assert result['valid'] is False
    result = validator.validate_password("StrongPass123!")
    assert result['valid'] is True
    print("✓ Password validation working")
    
    # Test query validation
    result = validator.validate_query("SELECT * FROM users")
    assert result['valid'] is True
    result = validator.validate_query("SELECT * FROM users\x00")
    assert result['valid'] is False
    print("✓ Query validation working")
    
    print("\n✅ Input validator tests passed")

if __name__ == '__main__':
    test_validator()
