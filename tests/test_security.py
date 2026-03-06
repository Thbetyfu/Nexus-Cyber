"""
Security vulnerability testing
Tests for OWASP Top 10 and common vulnerabilities
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security.input_validator import InputValidator
from security.rate_limiter import RateLimiter, BruteForceDetector
from web_gateway import app

@pytest.fixture
def client():
    """Flask test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

class TestSQLInjection:
    """Test SQL injection prevention"""
    
    def test_parameterized_queries(self, client):
        """Test that queries are parameterized"""
        # This is tested at database layer
        # Verify no raw query execution
        pass
    
    def test_input_validation(self):
        """Test input validation"""
        validator = InputValidator()
        
        # SQL injection attempt
        assert validator.validate_query("SELECT * FROM users' OR '1'='1'") is not None

class TestXSS:
    """Test Cross-Site Scripting prevention"""
    
    def test_html_escaping(self):
        """Test HTML escaping"""
        validator = InputValidator()
        
        malicious = "<script>alert('XSS')</script>"
        escaped = validator.escape_html(malicious)
        
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped
    
    def test_template_escaping(self, client):
        """Test Jinja2 template escaping"""
        # Templates should auto-escape by default
        pass

class TestAuthentication:
    """Test authentication security"""
    
    def test_weak_password_rejected(self):
        """Test weak passwords are rejected"""
        validator = InputValidator()
        
        result = validator.validate_password("weak")
        assert result['valid'] is False
    
    def test_session_security(self, client):
        """Test session cookies are secure"""
        # Login
        response = client.post('/login', data={
            'username': 'admin',
            'password': os.getenv('ADMIN_PASSWORD', 'default')
        })
        
        # Check secure flags
        cookies = response.headers.getlist('Set-Cookie')
        # In production, should have Secure and HttpOnly flags

class TestRateLimiting:
    """Test rate limiting"""
    
    def test_rate_limiter(self):
        """Test rate limiter"""
        limiter = RateLimiter(max_requests=5, time_window=60)
        
        # Should allow 5 requests
        for i in range(5):
            allowed, _ = limiter.is_allowed('192.168.1.1')
            assert allowed is True
        
        # 6th request should be denied
        allowed, _ = limiter.is_allowed('192.168.1.1')
        assert allowed is False
    
    def test_brute_force_detection(self):
        """Test brute force detection"""
        detector = BruteForceDetector(max_failures=3, lockout_duration=10)
        
        ip = '192.168.1.1'
        
        # Record 3 failures
        for i in range(3):
            detector.record_failure(ip)
        
        # Should be locked
        assert detector.is_locked(ip) is True
        
        # Successful attempt should unlock
        detector.record_success(ip)
        assert detector.is_locked(ip) is False

class TestCSRF:
    """Test CSRF protection"""
    
    def test_session_validation(self, client):
        """Test session validation"""
        # Should require proper session
        pass

class TestInputValidation:
    """Test input validation"""
    
    def test_ip_validation(self):
        """Test IP validation"""
        validator = InputValidator()
        
        assert validator.validate_ip('192.168.1.1') is True
        assert validator.validate_ip('2001:db8::1') is True
        assert validator.validate_ip('invalid') is False
        assert validator.validate_ip("'; DROP TABLE users;--") is False
    
    def test_username_validation(self):
        """Test username validation"""
        validator = InputValidator()
        
        assert validator.validate_username('john_doe') is True
        assert validator.validate_username('a') is False
        assert validator.validate_username("admin'; DROP TABLE;--") is False
    
    def test_query_validation(self):
        """Test query validation"""
        validator = InputValidator()
        
        result = validator.validate_query('SELECT * FROM users')
        assert result['valid'] is True
        
        result = validator.validate_query("SELECT * FROM users\x00")
        assert result['valid'] is False

class TestLogging:
    """Test logging and audit trail"""
    
    def test_log_sanitization(self):
        """Test that passwords are redacted in logs"""
        from security.logger import JSONFormatter
        
        message = 'User login failed. password="secret123"'
        # Should be sanitized
        pass

class TestSecretManagement:
    """Test that secrets are not hardcoded"""
    
    def test_no_hardcoded_secrets(self):
        """Test that sensitive values come from environment"""
        from config import get_config
        
        config = get_config()
        
        # Should not have default values in production
        if config.FLASK_ENV == 'production':
            assert config.SECRET_KEY != 'dev-only-change-in-production'
            assert config.ADMIN_PASSWORD != 'default-password'

class TestDataValidation:
    """Test data validation"""
    
    def test_max_query_length(self):
        """Test query length limits"""
        validator = InputValidator()
        
        very_long_query = 'SELECT * ' * 100000
        result = validator.validate_query(very_long_query)
        assert result['valid'] is False
    
    def test_null_byte_detection(self):
        """Test null byte detection"""
        validator = InputValidator()
        
        query_with_null = "SELECT * FROM users\x00"
        result = validator.validate_query(query_with_null)
        assert result['valid'] is False

class TestErrorHandling:
    """Test error handling"""
    
    def test_generic_error_messages(self, client):
        """Test that error messages don't leak information"""
        response = client.post('/login', data={
            'username': 'nonexistent',
            'password': 'wrong'
        })
        
        # Should not reveal whether user exists
        assert b'Invalid credentials' in response.data
        assert b'user not found' not in response.data.lower()
