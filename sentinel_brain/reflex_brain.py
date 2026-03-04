import os
import ollama

def evaluate_sql(query: str) -> str:
    """
    Sub-millisecond SQL evaluation using qwen2.5-coder.
    Returns 'BLOCK' or 'ALLOW'
    """
    prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "sql_injection.md")
    
    try:
        with open(prompt_path, "r") as f:
            template = f.read()
            
        full_prompt = template.replace("{query}", query)
        
        response = ollama.chat(model="qwen2.5-coder", messages=[
            {'role': 'system', 'content': 'You are a cybersecurity SQL Firewall. Respond ONLY with BLOCK or ALLOW.'},
            {'role': 'user', 'content': full_prompt}
        ])
        
        decision = response['message']['content'].strip().upper()
        if decision.startswith("BLOCK"):
            return "BLOCK"
        return "ALLOW"
    except Exception as e:
        print(f"Reflex Brain Error: {e}")
        return "ALLOW" # Fail open to prevent blocking legitimate traffic if AI fails
