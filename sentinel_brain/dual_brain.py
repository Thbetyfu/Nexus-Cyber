"""
Unified Dual-Brain System
- Reflex (fast decision)
- Forensic (deep analysis)
- Coordinated verdict
"""

import asyncio
import logging
import json
from typing import Dict, Optional
from datetime import datetime
import time

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sentinel_brain.reflex_brain import ReflexBrain
from sentinel_brain.forensic_brain import ForensicWorker
from database.db_config import DatabaseManager

logger = logging.getLogger(__name__)

# ===========================
# DUAL-BRAIN COORDINATOR
# ===========================

class DualBrain:
    """Coordinate Reflex and Forensic brains"""
    
    def __init__(self):
        self.reflex = ReflexBrain()
        self.forensic_worker = ForensicWorker()
        self.db = DatabaseManager()
        self.logger = logger
    
    async def analyze_threat(self,
                            query: str,
                            source_ip: str,
                            detected_patterns: list = None) -> Dict:
        """
        Analyze threat using both brains
        
        Process:
        1. Reflex brain: Fast decision (<100ms) - BLOCKING
        2. Forensic worker: Deep analysis (background) - NON-BLOCKING
        
        Returns: Combined verdict with both analyses
        """
        
        start_time = time.time()
        
        self.logger.info(f"Dual-brain analysis starting for {source_ip}")
        
        # STEP 1: Reflex Brain (Fast, blocking)
        reflex_verdict = await self.reflex.analyze_threat(
            query=query,
            source_ip=source_ip,
            detected_patterns=detected_patterns or []
        )
        
        reflex_time = time.time() - start_time
        
        # STEP 2: Forensic Worker (Deep, non-blocking background)
        # Only run forensic analysis for serious threats
        if reflex_verdict.get('threat_detected', False):
            self.forensic_worker.analyze_async(
                query=query,
                source_ip=source_ip,
                threat_type=reflex_verdict.get('threat_type', 'UNKNOWN'),
                reflex_verdict=reflex_verdict,
                callback=self._forensic_callback
            )
        
        # STEP 3: Combine verdicts
        combined_verdict = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            
            # Reflex verdict (primary decision)
            'threat_detected': reflex_verdict.get('threat_detected', False),
            'threat_type': reflex_verdict.get('threat_type', 'NONE'),
            'confidence': reflex_verdict.get('confidence', 0.0),
            'severity': reflex_verdict.get('severity', 'LOW'),
            'risk_score': reflex_verdict.get('risk_score', 0),
            'recommended_action': reflex_verdict.get('recommended_action', 'FORWARD'),
            'reflex_reasoning': reflex_verdict.get('reasoning', ''),
            
            # Latencies
            'reflex_latency_ms': int(reflex_time * 1000),
            'total_latency_ms': int((time.time() - start_time) * 1000),
            
            # Forensic info (populated async)
            'forensic_analysis_pending': reflex_verdict.get('threat_detected', False),
            'forensic_analysis': None
        }
        
        # Log to database
        try:
            self.db.log_verdict(
                query=query,
                source_ip=source_ip,
                detection_result={'matched_patterns': detected_patterns or []},
                verdict=combined_verdict
            )
        except Exception as e:
            self.logger.error(f"Failed to log verdict to DB: {e}")
        
        return combined_verdict
    
    def _forensic_callback(self, report: Dict):
        """Callback when forensic analysis completes"""
        
        incident_id = report.get('incident_id')
        source_ip = report.get('source_ip')
        
        self.logger.info(f"Forensic analysis completed: {incident_id} ({source_ip})")
        
        # Store to database
        try:
            self.db.log_incident(
                incident_type=report.get('threat_type', 'FORENSIC_ANALYSIS'),
                severity=report.get('severity_rating', 'HIGH'),
                source_ip=source_ip,
                forensic_data=report,
                summary=report.get('incident_summary', '')
            )
        except Exception as e:
            self.logger.error(f"Failed to store forensic report: {e}")
    
    def get_statistics(self) -> Dict:
        """Get combined statistics"""
        
        return {
            'reflex_stats': self.reflex.get_stats(),
            'forensic_stats': self.forensic_worker.brain.get_stats(),
            'timestamp': datetime.now().isoformat()
        }

if __name__ == '__main__':
    async def test():
        brain = DualBrain()
        verdict = await brain.analyze_threat("SELECT * FROM users", "127.0.0.1")
        print(json.dumps(verdict, indent=2))
        await asyncio.sleep(5) # Wait for async
    asyncio.run(test())
