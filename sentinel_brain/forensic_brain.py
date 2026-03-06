"""
Forensic Brain: Deep AI analysis using Llama3
- Runs asynchronously in background (non-blocking)
- Generates detailed forensic reports
- Attack timeline & behavior profiling
- Runs in separate thread to not block main proxy
"""

import asyncio
import logging
import json
import threading
import os
from typing import Dict, Optional, List
from datetime import datetime
import time

logger = logging.getLogger(__name__)

# ===========================
# FORENSIC BRAIN
# ===========================

class ForensicBrain:
    """
    Deep forensic analysis AI using Llama3
    
    Purpose: Generate detailed incident analysis in background
    """
    
    def __init__(self,
                 model_name: str = "llama3",
                 ollama_host: str = "http://localhost:11434"):
        self.model_name = model_name
        self.ollama_host = ollama_host
        self.logger = logger
        
        self.reports = {}  # Store generated reports
        self.analysis_count = 0
    
    async def _call_ollama(self, prompt: str, temperature: float = 0.3) -> Optional[str]:
        """
        Call Ollama API for inference
        """
        
        try:
            import httpx
            
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "top_p": 0.95,
                }
            }
            
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    f"{self.ollama_host}/api/generate",
                    json=payload
                )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                self.logger.error(f"Ollama error: {response.status_code}")
                return None
        
        except Exception as e:
            self.logger.error(f"Ollama call failed: {e}")
            return None
    
    async def analyze_incident(self,
                              query: str,
                              source_ip: str,
                              threat_type: str,
                              reflex_verdict: Dict) -> Dict:
        """
        Generate deep forensic analysis
        """
        
        start_time = time.time()
        self.logger.info(f"Forensic analysis starting for {source_ip}: {threat_type}")
        
        # Build detailed prompt
        prompt = f"""You are a cybersecurity forensicator analyzing a database attack.

INCIDENT DETAILS:
- Query: {query}
- Source IP: {source_ip}
- Threat Type: {threat_type}
- Detected At: {datetime.now().isoformat()}
- Reflex Verdict: {json.dumps(reflex_verdict, indent=2)}

Generate a comprehensive forensic report (JSON format ONLY):
{{
    "incident_id": "INC-XXXXXX",
    "incident_summary": "One sentence summary of the attack",
    "attack_timeline": [
        {{
            "stage": "1. Reconnaissance",
            "description": "How attacker discovered target",
            "confidence": 0.0-1.0
        }},
        {{
            "stage": "2. Exploitation",
            "description": "Method used to exploit vulnerability",
            "confidence": 0.0-1.0
        }},
        {{
            "stage": "3. Data Extraction",
            "description": "How data would be exfiltrated",
            "confidence": 0.0-1.0
        }}
    ],
    "affected_data": {{
        "tables": ["ktp_data", ...],
        "estimated_rows_at_risk": 1000,
        "sensitivity": "HIGH",
        "pii_indicators": true
    }},
    "attack_vectors": [
        {{
            "vector": "SQL Injection via WHERE clause",
            "severity": "CRITICAL",
            "remediation": "Use prepared statements"
        }}
    ],
    "attacker_profile": {{
        "skill_level": "ADVANCED|INTERMEDIATE|NOVICE",
        "intent": "Data theft|System takeover|Testing",
        "organization": "Individual|Group|Nation-state",
        "confidence": 0.0-1.0
    }},
    "recommended_actions": [
        "Immediate action 1",
        "Short-term action 2",
        "Long-term action 3"
    ],
    "severity_rating": "CRITICAL|HIGH|MEDIUM|LOW",
    "urgency": "IMMEDIATE|HIGH|MEDIUM|LOW"
}}"""
        
        try:
            # Call AI
            response = await self._call_ollama(prompt, temperature=0.3)
            
            if not response:
                self.logger.error("No response from Llama3")
                return self._get_default_forensic(threat_type)
            
            # Parse JSON response
            try:
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                
                if json_start == -1 or json_end <= json_start:
                    self.logger.warning("No JSON in Llama3 response")
                    return self._get_default_forensic(threat_type)
                
                json_str = response[json_start:json_end]
                report = json.loads(json_str)
                
                # Add metadata
                report['timestamp'] = datetime.now().isoformat()
                report['source_ip'] = source_ip
                report['latency_ms'] = int((time.time() - start_time) * 1000)
                report['model'] = self.model_name
                
                # Store report
                incident_id = report.get('incident_id', f"INC-{int(time.time())}")
                self.reports[incident_id] = report
                self.analysis_count += 1
                
                self.logger.info(
                    f"Forensic report generated ({incident_id}) "
                    f"in {report['latency_ms']}ms"
                )
                
                return report
            
            except json.JSONDecodeError as e:
                self.logger.error(f"JSON parse error: {e}")
                return self._get_default_forensic(threat_type)
        
        except Exception as e:
            self.logger.error(f"Forensic brain error: {e}")
            return self._get_default_forensic(threat_type)
    
    def _get_default_forensic(self, threat_type: str) -> Dict:
        """Default forensic report when AI fails"""
        return {
            'incident_id': f"INC-{int(time.time())}",
            'incident_summary': f'Potential {threat_type} attack detected',
            'attack_timeline': [
                {
                    'stage': '1. Reconnaissance',
                    'description': 'Attacker probed database for vulnerabilities',
                    'confidence': 0.5
                }
            ],
            'affected_data': {
                'tables': ['Multiple tables potentially affected'],
                'estimated_rows_at_risk': 'Unknown',
                'sensitivity': 'HIGH',
                'pii_indicators': True
            },
            'attack_vectors': [
                {
                    'vector': threat_type,
                    'severity': 'HIGH',
                    'remediation': 'Review security controls'
                }
            ],
            'recommended_actions': [
                'Block attacker IP immediately',
                'Review database access logs',
                'Audit user permissions',
                'Implement WAF rules'
            ],
            'severity_rating': 'HIGH',
            'urgency': 'IMMEDIATE'
        }
    
    def get_stats(self) -> Dict:
        """Get Forensic brain statistics"""
        return {
            'model': self.model_name,
            'total_analyses': self.analysis_count,
            'reports_stored': len(self.reports),
            'recent_incidents': list(self.reports.keys())[-5:] if self.reports else []
        }

# ===========================
# BACKGROUND FORENSIC WORKER
# ===========================

class ForensicWorker:
    """Run forensic analysis in background thread"""
    
    def __init__(self):
        self.brain = ForensicBrain()
        self.logger = logger
    
    def analyze_async(self,
                     query: str,
                     source_ip: str,
                     threat_type: str,
                     reflex_verdict: Dict,
                     callback = None):
        """
        Run forensic analysis in background thread
        """
        def run_analysis():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                report = loop.run_until_complete(
                    self.brain.analyze_incident(
                        query, source_ip, threat_type, reflex_verdict
                    )
                )
                
                if callback:
                    callback(report)
                
            except Exception as e:
                self.logger.error(f"Forensic worker error: {e}")
            finally:
                loop.close()
        
        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()
        self.logger.debug(f"Forensic analysis thread started for {source_ip}")

if __name__ == '__main__':
    async def test():
        brain = ForensicBrain()
        report = await brain.analyze_incident("SELECT * FROM users' OR '1'='1'", "127.0.0.1", "SQL_INJECTION", {})
        print(json.dumps(report, indent=2))
    asyncio.run(test())
