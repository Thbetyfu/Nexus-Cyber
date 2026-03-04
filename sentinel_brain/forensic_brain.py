import os
import json
import time
import ollama
import logging

logger = logging.getLogger("ForensicBrain")

def forensic_analysis_task(query: str, client_ip: str, reflex_blocked: bool):
    """
    Background job to deeply analyze dropped/allowed SQL queries via Llama3.
    """
    logger.info(f"[*] Forensic Brain starting analysis for query from {client_ip}...")
    prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "behavioral_analysis.md")
    
    try:
        with open(prompt_path, "r") as f:
            template = f.read()
            
        full_prompt = template.replace("{query}", query).replace("{client_ip}", client_ip).replace("{reflex_blocked}", str(reflex_blocked))
        
        response = ollama.chat(model="llama3", messages=[
            {'role': 'user', 'content': full_prompt}
        ])
        
        response_text = response['message']['content'].strip()
        start_idx = response_text.find('{')
        end_idx = response_text.rfind('}') + 1
        
        if start_idx != -1 and end_idx != 0:
            json_str = response_text[start_idx:end_idx]
            analysis = json.loads(json_str)
        else:
            raise ValueError("No JSON object extracted")

    except Exception as e:
        logger.error(f"[-] Forensic Brain JSON Error: {e}")
        # Baseline fallback
        analysis = {
            "status": "MALICIOUS" if reflex_blocked else "SAFE",
            "reason": f"AI Parsing failed. Fallback based on Reflex Action. Query: {query}",
            "timeline": ["Query intercepted", "Reflex triggered", "Forensic failure"],
            "action": "Dropped Connection" if reflex_blocked else "Allowed Execution",
            "risk_level": "CRITICAL" if reflex_blocked else "LOW"
        }

    alert_data = {
        "timestamp": time.ctime(),
        "source_ip": client_ip,
        "query": query,
        "status": analysis.get("status", "MALICIOUS" if reflex_blocked else "SAFE"),
        "reason": analysis.get("reason", "Malicious SQL Payload"),
        "timeline": analysis.get("timeline", []),
        "action": analysis.get("action", "Dropped Connection" if reflex_blocked else "Allowed"),
        "risk_level": analysis.get("risk_level", "HIGH" if reflex_blocked else "LOW")
    }

    # Write alert log
    log_dir = "/home/taqy/Nexus-Cyber/logs"
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "detailed_alerts.log"), "a") as df:
        df.write(json.dumps(alert_data) + "\n")
        
    logger.info(f"[+] Forensic Brain completed analysis for {client_ip}. Logged.")

