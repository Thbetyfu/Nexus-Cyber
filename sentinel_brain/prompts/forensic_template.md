# Forensic Analysis Template

## Incident Report Structure

```json
{
    "incident_id": "INC-{timestamp}",
    "incident_summary": "One-line summary",
    
    "attack_timeline": [
        {
            "stage": "Stage name",
            "description": "What happened",
            "confidence": 0.0-1.0,
            "duration": "estimated time"
        }
    ],
    
    "affected_data": {
        "tables": ["table1", "table2"],
        "estimated_rows": number,
        "estimated_size_mb": number,
        "sensitivity": "CRITICAL|HIGH|MEDIUM|LOW",
        "pii_indicators": boolean
    },
    
    "attack_vectors": [
        {
            "vector": "Vulnerability name",
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "cvss_score": 0-10,
            "remediation": "How to fix"
        }
    ],
    
    "attacker_profile": {
        "skill_level": "ADVANCED|INTERMEDIATE|NOVICE",
        "intent": "Data theft|System takeover|Testing|Espionage",
        "organization_type": "Individual|Group|APT|Nation-state",
        "tools_used": ["tool1", "tool2"],
        "confidence": 0.0-1.0
    },
    
    "recommended_actions": [
        "IMMEDIATE: Action for now",
        "SHORT-TERM: Action for this week",
        "LONG-TERM: Preventive measures"
    ],
    
    "severity_rating": "CRITICAL|HIGH|MEDIUM|LOW",
    "urgency": "IMMEDIATE|HIGH|MEDIUM|LOW",
    "estimated_impact": "Description of potential impact"
}
```

## Analysis Guidelines

1. **Attack Timeline**: Reconstruct sequence of events
2. **Data Risk**: Estimate what data could be stolen
3. **Attacker Profile**: Infer capabilities and intent
4. **Remediation**: Provide actionable steps
5. **Impact**: Quantify potential harm
