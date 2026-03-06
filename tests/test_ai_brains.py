import asyncio
import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sentinel_brain.reflex_brain import Reflex_Brain
from sentinel_brain.forensic_brain import Forensic_Brain

async def test_reflex():
    print("\n🧠 Testing Reflex Brain (Qwen 2.5)...")
    reflex = Reflex_Brain()
    
    queries = [
        "SELECT * FROM users WHERE id = 1",
        "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        "DROP TABLE users"
    ]
    
    for query in queries:
        print(f"\nEvaluating: {query}")
        result = await reflex.analyze_sql(query, "127.0.0.1", "2024-03-04 12:00:00")
        print(f"Result: {json.dumps(result, indent=2)}")

async def test_forensic():
    print("\n🕵️ Testing Forensic Brain (Llama 3)...")
    forensic = Forensic_Brain()
    
    query_info = {
        'query': "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        'verdict': {'action': 'BLOCK', 'reason': 'SQL Injection pattern detected'},
        'ai_reflex': {
            'risk_level': 'HIGH',
            'threat_type': 'INJECTION',
            'reasoning': 'Query contains persistent true condition (1=1)'
        }
    }
    
    print("\nGenerating report for detected SQLi...")
    report = await forensic.analyze_threat(query_info, ("127.0.0.1", 12345))
    print(f"Forensic Report: {json.dumps(report, indent=2)}")

async def main():
    try:
        await test_reflex()
        await test_forensic()
    except Exception as e:
        print(f"❌ Test error: {e}")

if __name__ == '__main__':
    asyncio.run(main())
