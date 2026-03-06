"""
Verdict Engine: Convert detection results to actionable verdicts
"""

import logging
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional, List
from datetime import datetime
import json

from detection.rules import DetectionResult, RiskLevel, ThreatType

logger = logging.getLogger(__name__)

# ===========================
# ACTION ENUMS
# ===========================

class VerdictAction(Enum):
    """Actions to take based on verdict"""
    FORWARD = "FORWARD"  # Allow query to execute
    LOG = "LOG"          # Log and allow (suspicious but not blocking)
    BLOCK = "BLOCK"      # Block query
    KILL = "KILL"        # Kill connection and ban IP
    ALERT = "ALERT"      # Send immediate alert

# ===========================
# VERDICT DECISION TREE
# ===========================

class VerdictEngine:
    """Generate verdicts and recommend actions"""
    
    def __init__(self):
        self.logger = logger
    
    def generate_verdict(self, 
                        detection_result: DetectionResult,
                        source_ip: str) -> Dict:
        """
        Generate verdict with action recommendation
        
        Returns: Verdict dictionary
        """
        
        # Decision tree based on risk level and threat type
        if detection_result.risk_level == RiskLevel.SAFE:
            action = VerdictAction.FORWARD
            reason = "No threats detected"
        
        elif detection_result.risk_level == RiskLevel.SUSPICIOUS:
            action = VerdictAction.LOG
            reason = f"Suspicious: {detection_result.reason}"
        
        elif detection_result.risk_level == RiskLevel.DANGEROUS:
            # Depends on threat type
            if detection_result.threat_type == ThreatType.SQL_INJECTION:
                action = VerdictAction.BLOCK
                reason = "SQL Injection detected - BLOCKING"
            elif detection_result.threat_type == ThreatType.MASS_EXFILTRATION:
                action = VerdictAction.BLOCK
                reason = "Mass exfiltration attempt - BLOCKING"
            elif detection_result.threat_type == ThreatType.PRIVILEGE_ESCALATION:
                action = VerdictAction.BLOCK
                reason = "Privilege escalation attempt - BLOCKING"
            elif detection_result.threat_type == ThreatType.RATE_LIMIT_EXCEEDED:
                action = VerdictAction.BLOCK
                reason = "Rate limit exceeded - BLOCKING"
            else:
                action = VerdictAction.LOG
                reason = f"Dangerous behavior: {detection_result.reason}"
        
        elif detection_result.risk_level == RiskLevel.CRITICAL:
            # CRITICAL = immediate action required
            if detection_result.threat_type == ThreatType.SQL_INJECTION:
                action = VerdictAction.KILL
                reason = f"CRITICAL SQL Injection detected - KILLING CONNECTION and IP BAN"
            elif detection_result.threat_type == ThreatType.PRIVILEGE_ESCALATION:
                action = VerdictAction.KILL
                reason = "CRITICAL Privilege escalation - KILLING CONNECTION and IP BAN"
            else:
                action = VerdictAction.BLOCK
                reason = f"CRITICAL threat: {detection_result.reason}"
        
        else:
            action = VerdictAction.FORWARD
            reason = "Unknown state - forwarding"
        
        verdict = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'threat_type': detection_result.threat_type.value,
            'risk_level': detection_result.risk_level.value,
            'confidence': detection_result.confidence,
            'severity_score': detection_result.severity_score,
            'action': action.value,
            'reason': reason,
            'matched_patterns': detection_result.matched_patterns,
            'recommended_action': detection_result.recommended_action
        }
        
        return verdict
    
    def log_verdict(self, verdict: Dict):
        """Log verdict for audit trail"""
        log_message = (
            f"[{verdict['timestamp']}] "
            f"IP: {verdict['source_ip']} | "
            f"Threat: {verdict['threat_type']} | "
            f"Risk: {verdict['risk_level']} | "
            f"Action: {verdict['action']} | "
            f"Confidence: {verdict['confidence']:.2%}"
        )
        
        if verdict['action'] in ['BLOCK', 'KILL']:
            self.logger.warning(log_message)
        elif verdict['action'] == 'LOG':
            self.logger.info(log_message)
        else:
            self.logger.debug(log_message)

# ===========================
# TEST FUNCTION
# ===========================

def test_verdict():
    """Test verdict engine"""
    from detection.rules import ThreatDetectionEngine
    
    engine = ThreatDetectionEngine()
    verdict_engine = VerdictEngine()
    
    test_cases = [
        ("SELECT * FROM users LIMIT 10", VerdictAction.FORWARD),
        ("SELECT * FROM ktp_data", VerdictAction.BLOCK),
        ("SELECT * FROM users' OR '1'='1", VerdictAction.KILL),
        ("GRANT ALL ON *.* TO hacker", VerdictAction.KILL),
    ]
    
    print("🧪 Testing Verdict Engine...")
    passed = 0
    
    for query, expected_action in test_cases:
        detection = engine.detect_threat(query, "192.168.1.100", len(query))
        verdict = verdict_engine.generate_verdict(detection, "192.168.1.100")
        
        actual_action = verdict['action']
        expected_str = expected_action.value
        
        if actual_action == expected_str:
            passed += 1
            print(f"✅ PASS: {query[:50]}")
            print(f"   Action: {actual_action}")
        else:
            print(f"❌ FAIL: {query[:50]}")
            print(f"   Expected: {expected_str}, Got: {actual_action}")
    
    print(f"\n✅ {passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)

if __name__ == '__main__':
    if test_verdict():
        print("\n✅ Verdict tests passed!")
    else:
        print("\n❌ Verdict tests failed!")
