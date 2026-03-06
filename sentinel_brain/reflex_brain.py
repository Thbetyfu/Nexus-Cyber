"""
Reflex Brain: Fast AI threat detection using Qwen2.5-Coder
- Uses httpx to call Ollama directly
- <100ms response time requirement
- Confidence scoring (0.0-1.0)
- Supports caching for repeated queries
"""

import asyncio
import logging
import json
import hashlib
import os
import sys
from typing import Dict, Optional, Tuple
from datetime import datetime
import time

# Add parent directory to path for imports if needed
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

logger = logging.getLogger(__name__)

# ===========================
# REFLEX BRAIN
# ===========================

class ReflexBrain:
    """
    Fast threat detection AI using Qwen2.5-Coder
    
    Purpose: Make quick threat/no-threat decisions in real-time
    """
    
    def __init__(self, 
                 model_name: str = "qwen2.5-coder",
                 ollama_host: str = "http://localhost:11434"):
        self.model_name = model_name
        self.ollama_host = ollama_host
        self.logger = logger
        
        # Query cache to avoid duplicate analysis
        self.cache = {}
        self.cache_hits = 0
        self.cache_misses = 0
    
    def _get_cache_key(self, query: str) -> str:
        """Generate cache key from query"""
        return hashlib.md5(query.encode()).hexdigest()
    
    async def _call_ollama(self, prompt: str, temperature: float = 0.1) -> Optional[str]:
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
                    "top_p": 0.9,
                    "top_k": 40,
                }
            }
            
            async with httpx.AsyncClient(timeout=5) as client:
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
    
    async def analyze_threat(self,
                            query: str,
                            source_ip: str,
                            detected_patterns: list = None) -> Dict:
        """
        Analyze query for threat using AI with performance optimizations
        """
        
        start_time = time.time()
        query_upper = query.upper().strip()
        
        # 1. WHITELIST CHECK (Ultra-fast)
        SAFE_QUERIES = [
            "SELECT 1", "SELECT @@VERSION", "SELECT @@VERSION_COMMENT",
            "SHOW TABLES", "SHOW DATABASES", "SELECT DATABASE()",
            "SHOW COLLATION", "SHOW VARIABLES", "SET NAMES", "SET CHARACTER SET",
            "SELECT COUNT", "DESC ", "DESCRIBE "
        ]
        if any(sq in query_upper for sq in SAFE_QUERIES) and len(detected_patterns or []) == 0:
            return {
                'threat_detected': False, 'threat_type': 'NONE', 'confidence': 1.0, 
                'severity': 'LOW', 'reasoning': 'Whitelisted safe query',
                'recommended_action': 'FORWARD', 'risk_score': 0, 'latency_ms': 0
            }

        # 2. CACHE CHECK
        cache_key = self._get_cache_key(query)
        if cache_key in self.cache:
            self.logger.debug(f"Cache HIT for query: {query[:50]}")
            self.cache_hits += 1
            return self.cache[cache_key]
        
        self.cache_misses += 1
        
        # 3. LENGTH LIMIT (Don't send massive queries to AI)
        if len(query) > 1000:
            query = query[:1000] + "... [TRUNCATED]"

        # Build enhanced prompt for Qwen2.5
        detected_patterns_str = ", ".join(detected_patterns) if detected_patterns else "None"
        
        # SYSTEM RULES
        system_rules = """
        - You are a SQL security sentinel.
        - MASS_EXFILTRATION: Flag any SELECT * or large data dumps from sensitive tables (e.g., users, ktp_data) without strict WHERE/LIMIT as HIGH severity.
        - SQL_INJECTION: Flag boolean bypasses ('OR 1=1') as CRITICAL.
        - Respond ONLY with JSON.
        """

        prompt = f"""{system_rules}
        
        Analyze this query:
        QUERY: {query}
        SOURCE_IP: {source_ip}
        DETECTED_PATTERNS: {detected_patterns_str}
        TIMESTAMP: {datetime.now().isoformat()}

        {{
            "threat_detected": boolean,
            "threat_type": "SQL_INJECTION|MASS_EXFILTRATION|PRIVILEGE_ESCALATION|ANOMALY|NONE",
            "confidence": float (0.0-1.0),
            "severity": "LOW|MEDIUM|HIGH|CRITICAL",
            "reasoning": "Reason here",
            "recommended_action": "FORWARD|LOG|BLOCK|KILL",
            "risk_score": 0-100
        }}"""
        
        try:
            # Call AI
            response = await self._call_ollama(prompt, temperature=0.1)
            
            if not response:
                self.logger.error("No response from Qwen2.5")
                return self._get_fallback_verdict(query)
            
            # Parse JSON response
            try:
                # Extract JSON from response (in case of extra text)
                json_start = response.find('{')
                json_end = response.rfind('}') + 1
                
                if json_start == -1 or json_end <= json_start:
                    self.logger.warning("No JSON found in response")
                    return self._get_fallback_verdict(query)
                
                json_str = response[json_start:json_end]
                verdict = json.loads(json_str)
                
                # Add metadata
                verdict['timestamp'] = datetime.now().isoformat()
                verdict['source_ip'] = source_ip
                verdict['latency_ms'] = int((time.time() - start_time) * 1000)
                
                # Cache result
                self.cache[cache_key] = verdict
                
                # Log decision
                self.logger.info(
                    f"Reflex verdict: {verdict.get('threat_type', 'UNKNOWN')} "
                    f"({verdict.get('confidence', 0):.2%} confidence) "
                    f"in {verdict.get('latency_ms', 0)}ms"
                )
                
                return verdict
            
            except json.JSONDecodeError as e:
                self.logger.error(f"JSON parse error: {e}")
                return self._get_fallback_verdict(query)
        
        except Exception as e:
            self.logger.error(f"Reflex brain error: {e}")
            return self._get_fallback_verdict(query)
    
    def _get_fallback_verdict(self, query: str) -> Dict:
        """Fallback verdict when AI fails"""
        query_upper = query.upper()
        if any(keyword in query_upper for keyword in ["' OR", "1=1", "UNION"]):
            return {
                'threat_detected': True,
                'threat_type': 'SQL_INJECTION',
                'confidence': 0.70,
                'severity': 'HIGH',
                'reasoning': 'Fallback: SQLi pattern detected',
                'recommended_action': 'BLOCK',
                'risk_score': 70
            }
        elif "SELECT *" in query_upper and "LIMIT" not in query_upper:
            return {
                'threat_detected': True,
                'threat_type': 'MASS_EXFILTRATION',
                'confidence': 0.65,
                'severity': 'MEDIUM',
                'reasoning': 'Fallback: SELECT * without LIMIT',
                'recommended_action': 'LOG',
                'risk_score': 65
            }
        else:
            return {
                'threat_detected': False,
                'threat_type': 'NONE',
                'confidence': 0.95,
                'severity': 'LOW',
                'reasoning': 'Fallback: No obvious threats',
                'recommended_action': 'FORWARD',
                'risk_score': 5
            }
    
    def get_stats(self) -> Dict:
        """Get Reflex brain statistics"""
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = (self.cache_hits / total_requests * 100) if total_requests > 0 else 0
        return {
            'model': self.model_name,
            'total_requests': total_requests,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': f"{hit_rate:.1f}%",
            'cache_size': len(self.cache)
        }

if __name__ == '__main__':
    async def test():
        brain = ReflexBrain()
        verdict = await brain.analyze_threat("SELECT * FROM users WHERE id='1' OR '1'='1'", "127.0.0.1")
        print(json.dumps(verdict, indent=2))
    asyncio.run(test())
