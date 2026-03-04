import asyncio
import ollama
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class Forensic_Brain:
    """Llama 3: Deep forensic analysis & timeline generation."""
    
    def __init__(self, model='llama3'):
        self.model = model
        self.client = ollama.Client()
    
    async def analyze_threat(self, query_info, client_addr):
        """Generate forensic report for threat."""
        
        prompt = f"""You are a cybersecurity forensicator. Analyze this SQL threat:

QUERY: {query_info['query']}
SOURCE IP: {client_addr[0]}
REFLEX VERDICT: {query_info['verdict']}

Generate a comprehensive forensic report in JSON format:
{{
    "incident_summary": "...",
    "attack_timeline": [...],
    "affected_data": {{...}},
    "attack_vectors": [...],
    "attacker_profile": "...",
    "recommended_actions": [...],
    "severity": "CRITICAL|HIGH|MEDIUM|LOW"
}}"""

        try:
            # We want to use to_thread so it doesn't block asyncio main loop
            response = await asyncio.to_thread(
                self.client.generate,
                model=self.model,
                prompt=prompt,
                stream=False
            )
            
            forensic_report = self._parse_response(response['response'])
            
            # Save to database (in our case detailed_alerts.log)
            await self._save_forensic_report(forensic_report, query_info, client_addr)
            
            return forensic_report
            
        except Exception as e:
            logger.error(f"Forensic Brain error: {e}")
    
    async def _save_forensic_report(self, report, query_info, client_addr):
        """Save to audit log."""
        log_file = "/home/taqy/Nexus-Cyber/logs/detailed_alerts.log"
        time_str = datetime.now().strftime("%a %b %2d %H:%M:%S %Y")
        
        # Determine status from Reflex verdict
        reflex_v = query_info.get('verdict', {})
        status = "MALICIOUS" if reflex_v.get('risk_level') in ['CRITICAL', 'HIGH'] else "SAFE"
        if status == "MALICIOUS":
            action = "Connection Dropped. Threat isolated."
        else:
            action = "Allow Execution."
            
        json_log = {
            "timestamp": time_str,
            "status": status,
            "reason": report.get('incident_summary', reflex_v.get('reasoning', 'No reason provided.')),
            "timeline": report.get('attack_timeline', []),
            "action": action,
            "network_target": {"ip": client_addr[0], "location": "Local", "port": client_addr[1]},
            "query": query_info['query'],
            "target_ip": client_addr[0],
            "risk_level": report.get('severity', reflex_v.get('risk_level', 'LOW'))
        }
        
        try:
             with open(log_file, "a") as f:
                 f.write(json.dumps(json_log) + "\n")
        except:
             pass
    
    def _parse_response(self, response_text):
        """Parse Llama response."""
        import json
        try:
            json_str = response_text[response_text.find('{'):response_text.rfind('}')+1]
            return json.loads(json_str)
        except:
            return {}
