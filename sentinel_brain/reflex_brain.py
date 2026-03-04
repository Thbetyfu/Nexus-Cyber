import asyncio
import ollama
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Reflex_Brain:
    """Qwen 2.5-Coder: Fast SQL threat detection (<100ms)."""
    
    def __init__(self, model='qwen2.5-coder'):
        self.model = model
        self.client = ollama.Client()  # Local Ollama
    
    async def analyze_sql(self, query, source_ip, timestamp):
        """Analyze SQL query for threats."""
        
        prompt = f"""You are a SQL security expert. Analyze this query for threats:

QUERY: {query}
SOURCE IP: {source_ip}
TIMESTAMP: {timestamp}

Identify if this is:
1. SQL INJECTION - Attempt to modify/extract unintended data
2. EXFILTRATION - Mass data extraction (SELECT * without LIMIT)
3. PRIVILEGE_ESCALATION - Trying to gain admin rights
4. BENIGN - Normal query

Respond ONLY with JSON:
{{
    "threat_type": "INJECTION|EXFILTRATION|PRIVILEGE_ESCALATION|BENIGN",
    "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation"
}}"""

        try:
            # Note: We run this in a thread to not block since ollama python client is synchronous
            response = await asyncio.to_thread(
                self.client.generate,
                model=self.model,
                prompt=prompt,
                stream=False
            )
            
            result = self._parse_response(response['response'])
            return result
            
        except Exception as e:
            logger.error(f"Reflex Brain error: {e}")
            return {
                'risk_level': 'UNKNOWN',
                'threat_type': 'ERROR',
                'reasoning': str(e)
            }
    
    def _parse_response(self, response_text):
        """Parse Qwen response."""
        import json
        try:
            # Extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            if start_idx != -1 and end_idx != 0:
                json_str = response_text[start_idx:end_idx]
                return json.loads(json_str)
            return {'risk_level': 'UNKNOWN', 'threat_type': 'PARSE_ERROR'}
        except:
            return {'risk_level': 'UNKNOWN', 'threat_type': 'PARSE_ERROR'} # Fail open to prevent blocking legitimate traffic if AI fails
