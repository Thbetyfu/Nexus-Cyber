"""
Unit tests for threat detection engine
Run with: pytest tests/test_detection.py -v
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from detection.rules import (
    ThreatDetectionEngine, SQLInjectionDetector, 
    ExfiltrationDetector, RateLimitDetector,
    ThreatType, RiskLevel
)
from detection.verdict import VerdictEngine, VerdictAction

class TestSQLInjectionDetection:
    """Test SQL injection detection"""
    
    detector = SQLInjectionDetector()
    
    def test_classic_or_injection(self):
        """Test classic ' OR '1'='1 pattern"""
        query = "SELECT * FROM users WHERE id='1' OR '1'='1'"
        is_sqli, patterns, conf = self.detector.detect(query)
        
        assert is_sqli is True
        assert len(patterns) > 0
        assert conf > 0.5
    
    def test_union_select_injection(self):
        """Test UNION SELECT injection"""
        query = "SELECT id FROM users UNION SELECT password FROM admins"
        is_sqli, patterns, conf = self.detector.detect(query)
        
        assert is_sqli is True
        assert "UNION SELECT" in str(patterns)
    
    def test_drop_table_injection(self):
        """Test DROP TABLE injection"""
        query = "SELECT * FROM users; DROP TABLE users;--"
        is_sqli, patterns, conf = self.detector.detect(query)
        
        assert is_sqli is True
        assert len(patterns) > 0
    
    def test_sleep_injection(self):
        """Test time-based blind SQLi"""
        query = "SELECT * FROM users WHERE id=1 AND SLEEP(5)"
        is_sqli, patterns, conf = self.detector.detect(query)
        
        assert is_sqli is True
        assert "SLEEP" in str(patterns)
    
    def test_clean_query_no_sqli(self):
        """Test legitimate query"""
        query = "SELECT id, name FROM users WHERE id=1 LIMIT 10"
        is_sqli, patterns, conf = self.detector.detect(query)
        
        assert is_sqli is False
        assert conf == 0.0


class TestExfiltrationDetection:
    """Test exfiltration detection"""
    
    detector = ExfiltrationDetector()
    
    def test_select_star_no_limit(self):
        """Test SELECT * without LIMIT"""
        query = "SELECT * FROM ktp_data"
        is_exfil, patterns, conf = self.detector.detect(query)
        
        assert is_exfil is True
        assert conf > 0.8
    
    def test_select_star_with_reasonable_limit(self):
        """Test SELECT * with reasonable LIMIT"""
        query = "SELECT * FROM users LIMIT 100"
        is_exfil, patterns, conf = self.detector.detect(query)
        
        assert is_exfil is False
        assert conf == 0.0
    
    def test_select_star_with_excessive_limit(self):
        """Test SELECT * with excessive LIMIT"""
        query = "SELECT * FROM users LIMIT 10000000"
        is_exfil, patterns, conf = self.detector.detect(query)
        
        assert is_exfil is True
        assert conf > 0.8
    
    def test_normal_select_with_where(self):
        """Test normal SELECT with WHERE clause"""
        query = "SELECT id, name FROM users WHERE status='active' LIMIT 100"
        is_exfil, patterns, conf = self.detector.detect(query)
        
        assert is_exfil is False


class TestRateLimitDetection:
    """Test rate limiting detection"""
    
    def test_rate_limit_exceeded(self):
        """Test exceeding query rate limit"""
        detector = RateLimitDetector()
        detector.QUERIES_PER_MINUTE = 5  # Lower for testing
        
        test_ip = "192.168.1.100"
        
        # Send 6 queries
        for i in range(6):
            detector.record_query(test_ip)
        
        is_exceeded, reason, conf = detector.check_rate(test_ip)
        
        assert is_exceeded is True
        assert conf > 0.0
    
    def test_within_rate_limit(self):
        """Test within rate limit"""
        detector = RateLimitDetector()
        detector.QUERIES_PER_MINUTE = 100
        
        test_ip = "192.168.1.101"
        
        # Send 50 queries
        for i in range(50):
            detector.record_query(test_ip)
        
        is_exceeded, reason, conf = detector.check_rate(test_ip)
        
        assert is_exceeded is False
        assert conf == 0.0


class TestThreatDetectionEngine:
    """Test main detection engine"""
    
    engine = ThreatDetectionEngine()
    
    def test_safe_query(self):
        """Test completely safe query"""
        query = "SELECT id, name FROM users WHERE id=1 LIMIT 10"
        result = self.engine.detect_threat(query, "192.168.1.100")
        
        assert result.risk_level == RiskLevel.SAFE
        assert result.threat_type == ThreatType.NONE
    
    def test_sql_injection_threat(self):
        """Test SQL injection detection"""
        query = "SELECT * FROM users WHERE id='1' OR '1'='1'"
        result = self.engine.detect_threat(query, "192.168.1.100")
        
        assert result.risk_level in [RiskLevel.DANGEROUS, RiskLevel.CRITICAL]
        assert result.threat_type == ThreatType.SQL_INJECTION
        assert result.confidence > 0.5
    
    def test_exfiltration_threat(self):
        """Test mass exfiltration detection"""
        query = "SELECT * FROM ktp_data"
        result = self.engine.detect_threat(query, "192.168.1.100")
        
        assert result.risk_level in [RiskLevel.DANGEROUS, RiskLevel.CRITICAL]
        assert result.threat_type == ThreatType.MASS_EXFILTRATION
    
    def test_privilege_escalation_threat(self):
        """Test privilege escalation detection"""
        query = "GRANT ALL PRIVILEGES ON *.* TO hacker@localhost"
        result = self.engine.detect_threat(query, "192.168.1.100")
        
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.threat_type == ThreatType.PRIVILEGE_ESCALATION


class TestVerdictEngine:
    """Test verdict engine"""
    
    verdict_engine = VerdictEngine()
    detection_engine = ThreatDetectionEngine()
    
    def test_safe_verdict(self):
        """Test verdict for safe query"""
        query = "SELECT id, name FROM users WHERE id=1 LIMIT 10"
        detection = self.detection_engine.detect_threat(query, "192.168.1.100")
        verdict = self.verdict_engine.generate_verdict(detection, "192.168.1.100")
        
        assert verdict['action'] == VerdictAction.FORWARD.value
    
    def test_sqli_verdict_block(self):
        """Test verdict for SQL injection"""
        query = "SELECT * FROM users' OR '1'='1"
        detection = self.detection_engine.detect_threat(query, "192.168.1.100")
        verdict = self.verdict_engine.generate_verdict(detection, "192.168.1.100")
        
        assert verdict['action'] in [VerdictAction.BLOCK.value, VerdictAction.KILL.value]
    
    def test_priv_escalation_verdict_kill(self):
        """Test verdict for privilege escalation"""
        query = "GRANT ALL PRIVILEGES ON *.* TO hacker"
        detection = self.detection_engine.detect_threat(query, "192.168.1.100")
        verdict = self.verdict_engine.generate_verdict(detection, "192.168.1.100")
        
        assert verdict['action'] == VerdictAction.KILL.value
