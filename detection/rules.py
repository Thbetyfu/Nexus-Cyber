"""
Threat detection rules for SQL queries
Supports:
- SQL Injection patterns
- Mass exfiltration detection
- Anomalous behavior detection
- Rate limiting
"""

import re
import logging
from enum import Enum
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ===========================
# THREAT ENUMS & DATA CLASSES
# ===========================

class ThreatType(Enum):
    """Types of threats"""
    SQL_INJECTION = "SQL_INJECTION"
    MASS_EXFILTRATION = "MASS_EXFILTRATION"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    ANOMALOUS_TIME = "ANOMALOUS_TIME"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    NONE = "NONE"

class RiskLevel(Enum):
    """Risk severity levels"""
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"
    CRITICAL = "CRITICAL"

@dataclass
class DetectionResult:
    """Result of threat detection"""
    threat_type: ThreatType
    risk_level: RiskLevel
    confidence: float  # 0.0 to 1.0
    matched_patterns: List[str]
    reason: str
    severity_score: int  # 0-100
    recommended_action: str

# ===========================
# SQL INJECTION DETECTION
# ===========================

class SQLInjectionDetector:
    """Detect SQL injection attacks"""
    
    # Common SQLi patterns
    SQL_INJECTION_PATTERNS = [
        # Classic boolean-based
        (r"'\s*OR\s*'1'\s*=\s*'1", "Classic OR 1=1"),
        (r"'?\s+OR\s+1\s*=\s*1", "OR 1=1 variant"),
        (r"'\s*OR\s*''\s*=\s*'", "OR ''='' variant"),
        
        # UNION-based
        (r"UNION\s+SELECT", "UNION SELECT"),
        (r"UNION\s+ALL\s+SELECT", "UNION ALL SELECT"),
        
        # Comment-based
        (r"'?\s*--\s*$", "SQL comment terminator"),
        (r"/\*.*?\*/", "Block comment"),
        (r"#\s*$", "Hash comment"),
        
        # Stacked queries
        (r";\s*DROP\s+TABLE", "DROP TABLE injection"),
        (r";\s*DELETE\s+FROM", "DELETE injection"),
        (r";\s*INSERT\s+INTO", "INSERT injection"),
        (r";\s*UPDATE\s+", "UPDATE injection"),
        
        # Time-based blind
        (r"SLEEP\s*\(\s*\d+\s*\)", "SLEEP function"),
        (r"BENCHMARK\s*\(", "BENCHMARK function"),
        
        # Error-based
        (r"EXTRACTVALUE\s*\(", "EXTRACTVALUE function"),
        (r"UpdateXML\s*\(", "UpdateXML function"),
        
        # Other dangerous functions
        (r"LOAD_FILE\s*\(", "LOAD_FILE function"),
        (r"INTO\s+OUTFILE", "INTO OUTFILE"),
        (r"INTO\s+DUMPFILE", "INTO DUMPFILE"),
        
        # Encoding bypass attempts
        (r"0x[0-9a-fA-F]+", "Hex encoding"),
        (r"CHAR\s*\(\s*\d+", "CHAR encoding"),
    ]
    
    # Case-insensitive regex compilation
    COMPILED_PATTERNS = [
        (re.compile(pattern, re.IGNORECASE), name) 
        for pattern, name in SQL_INJECTION_PATTERNS
    ]
    
    @staticmethod
    def detect(query: str) -> Tuple[bool, List[str], float]:
        """
        Detect SQL injection in query
        
        Returns: (is_sqli, matched_patterns, confidence)
        """
        matched = []
        confidence = 0.0
        
        if not query:
            return False, [], 0.0
        
        # Check each pattern
        for pattern, pattern_name in SQLInjectionDetector.COMPILED_PATTERNS:
            if pattern.search(query):
                matched.append(pattern_name)
                confidence += 0.6  # Increased from 0.4 to 0.6
        
        # Confidence cap at 1.0
        confidence = min(confidence, 1.0)
        
        # If multiple patterns matched, increase confidence significantly
        if len(matched) >= 2:
            confidence = min(confidence + 0.3, 1.0)
        
        is_sqli = len(matched) > 0
        
        return is_sqli, matched, confidence

# ===========================
# MASS EXFILTRATION DETECTION
# ===========================

class ExfiltrationDetector:
    """Detect attempts to extract large amounts of data"""
    
    # Thresholds
    DEFAULT_ROW_LIMIT = 1000  # Queries without LIMIT should have reasonable limit
    MAX_ROWS_NORMAL = 100000  # Normal bulk operation limit
    SUSPICIOUS_TIME_HOURS = [0, 1, 2, 3, 4, 5]  # Off-hours (midnight to 5am)
    
    @staticmethod
    def has_limit_clause(query: str) -> Tuple[bool, Optional[int]]:
        """
        Check if query has LIMIT clause
        Returns: (has_limit, limit_value)
        """
        # Match LIMIT patterns
        match = re.search(r'LIMIT\s+(\d+)', query, re.IGNORECASE)
        if match:
            limit = int(match.group(1))
            return True, limit
        
        return False, None
    
    @staticmethod
    def detect_select_star_no_limit(query: str) -> Tuple[bool, str, float]:
        """
        Detect dangerous pattern: SELECT * without LIMIT
        
        Returns: (is_dangerous, reason, confidence)
        """
        query_upper = query.upper().strip()
        
        # Check for SELECT * specifically (avoiding COUNT(*), SUM(*), etc)
        # Regex looks for SELECT followed by whitespace then * then whitespace then FROM
        if not re.search(r'SELECT\s+\*\s+FROM', query_upper):
            return False, "Not a dangerous SELECT * query", 0.0
        
        # Check for LIMIT
        has_limit, limit_value = ExfiltrationDetector.has_limit_clause(query)
        
        if not has_limit:
            return True, "Dangerous SELECT * without LIMIT clause", 0.95
        
        # Check if limit is reasonable
        if limit_value and limit_value > ExfiltrationDetector.MAX_ROWS_NORMAL:
            return True, f"SELECT * with excessive LIMIT ({limit_value})", 0.85
        
        return False, "SELECT * with reasonable LIMIT", 0.0
    
    @staticmethod
    def detect_suspicious_time(query: str, hour: Optional[int] = None) -> Tuple[bool, str, float]:
        """
        Detect queries during suspicious hours (e.g., midnight - 5am)
        """
        if hour is None:
            hour = datetime.now().hour
        
        query_upper = query.upper()
        
        # Only suspicious for large SELECT queries
        if 'SELECT' not in query_upper:
            return False, "Not a SELECT query", 0.0
        
        # Check if query looks like bulk extraction
        # Fixed: Use regex to check for actual SELECT * (excluding COUNT(*))
        is_select_star = re.search(r'SELECT\s+\*\s+FROM', query_upper)
        # Or a query with a large numeric fetch pattern (e.g. from many records)
        is_large_fetch = re.search(r'SELECT.*FROM.*\s+LIMIT\s+\d{4,}', query_upper) # LIMIT > 1000
        
        if (is_select_star or is_large_fetch) and hour in ExfiltrationDetector.SUSPICIOUS_TIME_HOURS:
            return True, f"Bulk SELECT query at {hour}:00 (suspicious time)", 0.70
        
        return False, "Query at normal time or non-bulk", 0.0
    
    @staticmethod
    def detect(query: str, estimated_rows: Optional[int] = None) -> Tuple[bool, List[str], float]:
        """
        Detect mass exfiltration attempts
        
        Returns: (is_exfil, matched_patterns, confidence)
        """
        matched = []
        confidence = 0.0
        
        # Check SELECT * without LIMIT
        is_dangerous, reason, conf = ExfiltrationDetector.detect_select_star_no_limit(query)
        if is_dangerous:
            matched.append(reason)
            confidence += conf
        
        # Check suspicious timing
        is_suspicious, reason, conf = ExfiltrationDetector.detect_suspicious_time(query)
        if is_suspicious:
            matched.append(reason)
            confidence += conf
        
        # Cap confidence
        confidence = min(confidence, 1.0)
        
        is_exfil = len(matched) > 0
        
        return is_exfil, matched, confidence

# ===========================
# RATE LIMITING DETECTION
# ===========================

class RateLimitDetector:
    """Detect excessive query rates from single IP"""
    
    # Rate limits
    QUERIES_PER_MINUTE = 100
    BYTES_PER_MINUTE = 10 * 1024 * 1024  # 10MB
    
    def __init__(self):
        self.ip_stats = {}  # {ip: {queries: count, bytes: count, timestamp: last_reset}}
    
    def check_rate(self, source_ip: str) -> Tuple[bool, str, float]:
        """
        Check if IP exceeds rate limits
        
        Returns: (is_exceeded, reason, confidence)
        """
        now = datetime.now()
        
        if source_ip not in self.ip_stats:
            self.ip_stats[source_ip] = {
                'queries': 0,
                'bytes': 0,
                'timestamp': now
            }
            return False, "First query from IP", 0.0
        
        stats = self.ip_stats[source_ip]
        elapsed = (now - stats['timestamp']).total_seconds()
        
        # Reset if >1 minute elapsed
        if elapsed > 60:
            stats['queries'] = 0
            stats['bytes'] = 0
            stats['timestamp'] = now
            return False, "Rate limit reset", 0.0
        
        # Check limits
        if stats['queries'] > self.QUERIES_PER_MINUTE:
            confidence = min(0.5 + (stats['queries'] - self.QUERIES_PER_MINUTE) / 1000, 1.0)
            return True, f"Rate limit exceeded: {stats['queries']} queries/min", confidence
        
        return False, "Within rate limits", 0.0
    
    def record_query(self, source_ip: str, bytes_count: int = 0):
        """Record query for rate limiting"""
        if source_ip not in self.ip_stats:
            self.ip_stats[source_ip] = {
                'queries': 0,
                'bytes': 0,
                'timestamp': datetime.now()
            }
        
        self.ip_stats[source_ip]['queries'] += 1
        self.ip_stats[source_ip]['bytes'] += bytes_count

# ===========================
# PRIVILEGE ESCALATION DETECTION
# ===========================

class PrivilegeEscalationDetector:
    """Detect privilege escalation attempts"""
    
    DANGEROUS_KEYWORDS = [
        'GRANT',
        'CREATE USER',
        'ALTER USER',
        'SET PASSWORD',
        'CHANGE MASTER',
        'SUPER',
        'FILE',
        'PROCESS',
    ]
    
    @staticmethod
    def detect(query: str) -> Tuple[bool, List[str], float]:
        """
        Detect privilege escalation attempts
        
        Returns: (is_priv_esc, matched_keywords, confidence)
        """
        query_upper = query.upper()
        matched = []
        confidence = 0.0
        
        for keyword in PrivilegeEscalationDetector.DANGEROUS_KEYWORDS:
            if keyword in query_upper:
                matched.append(keyword)
                confidence = 0.90
        
        return len(matched) > 0, matched, confidence

# ===========================
# MAIN DETECTION ENGINE
# ===========================

class ThreatDetectionEngine:
    """Main detection engine combining all detectors"""
    
    def __init__(self):
        self.sqli_detector = SQLInjectionDetector()
        self.exfil_detector = ExfiltrationDetector()
        self.priv_detector = PrivilegeEscalationDetector()
        self.rate_detector = RateLimitDetector()
        self.logger = logger
    
    def detect_threat(self, 
                     query: str,
                     source_ip: str,
                     query_bytes: int = 0) -> DetectionResult:
        """
        Comprehensive threat detection
        
        Returns: DetectionResult with full details
        """
        matched_patterns = []
        max_confidence = 0.0
        threat_type = ThreatType.NONE
        severity_score = 0
        recommended_action = "FORWARD"
        
        # 1. SQL Injection Detection
        is_sqli, sqli_patterns, sqli_conf = self.sqli_detector.detect(query)
        if is_sqli:
            matched_patterns.extend(sqli_patterns)
            max_confidence = max(max_confidence, sqli_conf)
            threat_type = ThreatType.SQL_INJECTION
            severity_score = int(sqli_conf * 100)
            recommended_action = "BLOCK"
        
        # 2. Exfiltration Detection
        is_exfil, exfil_patterns, exfil_conf = self.exfil_detector.detect(query)
        if is_exfil:
            matched_patterns.extend(exfil_patterns)
            # Prioritize SQL_INJECTION over MASS_EXFILTRATION if both detected
            if threat_type != ThreatType.SQL_INJECTION:
                if exfil_conf > max_confidence:
                    max_confidence = exfil_conf
                    threat_type = ThreatType.MASS_EXFILTRATION
            else:
                # If already SQL_INJECTION, we just keep the higher confidence for risk level assessment
                max_confidence = max(max_confidence, exfil_conf)
                
            severity_score = max(severity_score, int(exfil_conf * 100))
            recommended_action = "BLOCK" if exfil_conf > 0.8 else "LOG"
        
        # 3. Privilege Escalation Detection
        is_priv, priv_keywords, priv_conf = self.priv_detector.detect(query)
        if is_priv:
            matched_patterns.extend(priv_keywords)
            max_confidence = max(max_confidence, priv_conf)
            threat_type = ThreatType.PRIVILEGE_ESCALATION
            severity_score = max(severity_score, 90)
            recommended_action = "BLOCK"
        
        # 4. Rate Limiting Check
        is_rate_exceeded, rate_reason, rate_conf = self.rate_detector.check_rate(source_ip)
        if is_rate_exceeded:
            matched_patterns.append(rate_reason)
            max_confidence = max(max_confidence, rate_conf)
            threat_type = ThreatType.RATE_LIMIT_EXCEEDED
            severity_score = max(severity_score, int(rate_conf * 100))
            recommended_action = "BLOCK"
        
        self.rate_detector.record_query(source_ip, query_bytes)
        
        # 5. Determine risk level
        if max_confidence == 0:
            risk_level = RiskLevel.SAFE
        elif max_confidence < 0.5:
            risk_level = RiskLevel.SUSPICIOUS
        elif max_confidence < 0.8:
            risk_level = RiskLevel.DANGEROUS
        else:
            risk_level = RiskLevel.CRITICAL
        
        # Build reason
        if threat_type == ThreatType.NONE:
            reason = "No threats detected"
        else:
            reason = f"{threat_type.value} detected with {max_confidence*100:.1f}% confidence"
        
        return DetectionResult(
            threat_type=threat_type,
            risk_level=risk_level,
            confidence=max_confidence,
            matched_patterns=matched_patterns,
            reason=reason,
            severity_score=severity_score,
            recommended_action=recommended_action
        )

# ===========================
# TEST FUNCTION
# ===========================

def test_detection():
    """Test detection engine"""
    engine = ThreatDetectionEngine()
    
    test_cases = [
        # (query, expected_threat_type)
        ("SELECT * FROM users", ThreatType.NONE),
        ("SELECT * FROM users LIMIT 10", ThreatType.NONE),
        ("SELECT * FROM users' OR '1'='1", ThreatType.SQL_INJECTION),
        ("SELECT * FROM ktp_data", ThreatType.MASS_EXFILTRATION),
        ("SELECT * FROM users; DROP TABLE users;--", ThreatType.SQL_INJECTION),
        ("GRANT ALL ON *.* TO hacker@localhost", ThreatType.PRIVILEGE_ESCALATION),
    ]
    
    print("🧪 Testing Detection Engine...")
    passed = 0
    
    for query, expected_threat in test_cases:
        result = engine.detect_threat(query, "192.168.1.100", len(query))
        
        if result.threat_type == expected_threat:
            passed += 1
            print(f"✅ PASS: {query[:50]}")
        else:
            print(f"❌ FAIL: {query[:50]}")
            print(f"   Expected: {expected_threat}, Got: {result.threat_type}")
    
    print(f"\n✅ {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)

if __name__ == '__main__':
    if test_detection():
        print("\n✅ Detection tests passed!")
    else:
        print("\n❌ Detection tests failed!")
