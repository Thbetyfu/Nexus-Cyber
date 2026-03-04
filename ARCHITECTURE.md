# 🏗️ Nexus-Cyber Data-Vault Gateway - Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────┐
│                   CLIENT APPLICATION                     │
│              (Banking App, ERP, CMS, etc)               │
└──────────────────┬──────────────────────────────────────┘
                   │ SQL Query (Port 3306)
                   ↓
┌─────────────────────────────────────────────────────────┐
│        NEXUS-CYBER DATA-VAULT GATEWAY (Port 3306)       │
│  ┌────────────────────────────────────────────────────┐ │
│  │          TCP Proxy Listener                        │ │
│  │  - Accept MySQL connections                       │ │
│  │  - Extract query from protocol                    │ │
│  │  - Forward to detection engine                    │ │
│  └────────────────────────────────────────────────────┘ │
│                       ↓                                   │
│  ┌────────────────────────────────────────────────────┐ │
│  │       SQL Parser & Threat Detection               │ │
│  │  - Parse SQL syntax                               │ │
│  │  - Pattern matching (SQLi, exfil, etc)           │ │
│  │  - Generate risk score                            │ │
│  └────────────────────────────────────────────────────┘ │
│                       ↓                                   │
│  ┌────────────────────────────────────────────────────┐ │
│  │            DUAL-BRAIN AI ANALYSIS                 │ │
│  │  ⚡ REFLEX BRAIN (Qwen2.5)                        │ │
│  │     Fast verdict: BLOCK / ALLOW                   │ │
│  │     Response time: <100ms                         │ │
│  │                                                    │ │
│  │  🕵️ FORENSIC BRAIN (Llama3)                      │ │
│  │     Deep analysis in background                   │ │
│  │     Generate forensic report                      │ │
│  └────────────────────────────────────────────────────┘ │
│                       ↓                                   │
│  ┌────────────────────────────────────────────────────┐ │
│  │              VERDICT ENGINE                        │ │
│  │  - SAFE: Forward to database                      │ │
│  │  - SUSPICIOUS: Log, forward, monitor             │ │
│  │  - DANGEROUS: Block, log incident               │ │
│  │  - CRITICAL: Kill connection, ban IP            │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          ↓            ↓            ↓
      [FORWARD]   [RESPONSE]  [ALERT]
          │            │            │
          ↓            │            ↓
   ┌────────────┐ ┌────────────┐ ┌────────────┐
   │  DATABASE  │ │   CLIENT   │ │ ALERTING  │
   │(Port 3307) │ │            │ │(Telegram, │
   │ MySQL 8.0  │ └────────────┘ │Hardware)  │
   └────────────┘                 └────────────┘
```

## Component Description

### 1. TCP Proxy Listener
**File**: `interceptor/tcp_proxy.py`
**Language**: Python (asyncio)
**Port**: 3306 (listen), 3307 (backend)

**Responsibility**:
- Accept incoming MySQL connections from applications
- Parse MySQL protocol packets
- Extract SQL query strings
- Forward raw protocol to backend database
- Receive responses & forward back to client
- Log all traffic

**Tech**:
- asyncio for async I/O
- socket for TCP handling
- MySQL protocol parsing (packet structure understanding)

---

### 2. SQL Parser & Analyzer
**File**: `interceptor/sql_parser.py`
**Language**: Python

**Responsibility**:
- Extract query from MySQL protocol packet
- Parse SQL syntax (SELECT, INSERT, UPDATE, DELETE, etc.)
- Extract:
  - Tables accessed
  - Columns affected
  - WHERE conditions
  - LIMIT clauses
  - JOIN types
- Detect suspicious patterns

**Tech**:
- sqlparse library for SQL parsing
- Regex for pattern matching
- Custom logic for protocol parsing

---

### 3. Threat Detection Engine
**Files**: `detection/rules.py`, `detection/verdict.py`
**Language**: Python

**Responsibility**:
- Pattern matching for SQL injection
- Volume/timing analysis for exfiltration
- Anomalous query detection
- Return structured verdict

**Rules Implemented**:
1. **SQL Injection Detection**
   - Pattern: `' OR '1'='1`
   - Pattern: `UNION SELECT`
   - Pattern: `; DROP TABLE`
   - Pattern: SQL comments (`--`, `/* */`)

2. **Mass Exfiltration Detection**
   - Pattern: `SELECT *` without LIMIT
   - Pattern: >100k rows in <5 seconds
   - Pattern: Queries at odd hours (2-5am)

3. **Rate Limiting**
   - >100 queries per minute per IP
   - >10MB data per minute per IP

---

### 4. Dual-Brain AI System

#### Reflex Brain (Qwen2.5-Coder)
**File**: `sentinel_brain/reflex_brain.py`
**Model**: Qwen2.5-coder (local via Ollama)
**Response Time**: <100ms
**Purpose**: FAST threat verdict

**Input**:
```json
{
  "query": "SELECT * FROM ktp_data WHERE id='1' OR '1'='1'",
  "source_ip": "192.168.1.100",
  "timestamp": "2024-09-01T14:30:00Z",
  "detected_patterns": ["SQL_INJECTION"]
}
```

**Output**:
```json
{
  "threat_type": "SQL_INJECTION",
  "risk_level": "CRITICAL",
  "confidence": 0.98,
  "action": "BLOCK",
  "reason": "Classic SQL injection attempt detected"
}
```

#### Forensic Brain (Llama3)
**File**: `sentinel_brain/forensic_brain.py`
**Model**: Llama3 (local via Ollama)
**Purpose**: DEEP analysis for forensic report

**Input**: Full incident context
**Output**: 
```json
{
  "incident_summary": "SQL injection attempt from China",
  "attack_timeline": [...],
  "affected_data": "ktp_data table (estimate 1000 rows)",
  "attack_vectors": ["SQLi via WHERE clause"],
  "attacker_profile": "Professional threat actor",
  "recommendations": ["Update DB filters", "Monitor IP"]
}
```

---

### 5. Response & Executioner
**File**: `executioner/connection_killer.py`
**Language**: Python

**Responsibility**:
- Kill TCP connection immediately
- Ban IP via iptables
- Log action to audit trail
- Trigger alerts

**Actions**:
1. Drop TCP socket
2. Execute: `sudo iptables -I INPUT -s <IP> -j DROP`
3. Log to audit_log table
4. Send Telegram alert
5. Trigger ASUS alerts (RGB, fan)

---

### 6. Database Layer
**Type**: MySQL 8.0
**Port**: 3307 (actual), 3306 (proxy)
**Location**: Docker container

**Tables**:
1. **ktp_data** (dummy data)
   - Fields: id, nik, nama, alamat, telp, email
   - Rows: 1000+

2. **query_audit_log** (threat tracking)
   - Fields: timestamp, source_ip, query, risk_level, action, forensic_json

3. **blocked_ips** (IP ban list)
   - Fields: ip, reason, timestamp, unblock_date

---

### 7. Web Dashboard & Admin Panel
**File**: `web_gateway.py`
**Framework**: Flask
**Port**: 5000
**Authentication**: Basic Auth

**Endpoints**:
- `GET /admin` - Dashboard
- `GET /api/queries` - Live query stream
- `GET /api/incidents` - Blocked query history
- `POST /api/unblock-ip/<ip>` - Manual unblock
- `POST /api/reset` - System reset

---

## Data Flow Example: Attack Scenario

```
Step 1: Attacker connects to port 3306
  → TCP proxy accepts connection

Step 2: Attacker sends malicious query
  → Query: SELECT * FROM ktp_data WHERE id='1' OR '1'='1'

Step 3: SQL Parser extracts query
  → Identified as SQLi pattern

Step 4: Detection engine runs rules
  → Triggers: SQL_INJECTION pattern match

Step 5: Reflex Brain (Qwen) makes quick decision
  → Response: CRITICAL, BLOCK, Confidence 98%

Step 6: Verdict Engine
  → Decision: CRITICAL → KILL CONNECTION

Step 7: Executioner acts
  → Kill socket
  → Ban IP via iptables
  → Log to query_audit_log
  → Send Telegram alert
  → RGB keyboard → RED
  → Fan → TURBO

Step 8: Forensic Brain (Llama) in background
  → Generate detailed forensic report

Step 9: Admin sees in dashboard
  → Incident logged with full forensics
```

---

## Security Layers

1. **Network Layer**: TCP proxy intercepts all connections
2. **Protocol Layer**: MySQL packet parsing & validation
3. **Query Layer**: SQL parsing & pattern matching
4. **AI Layer**: Qwen2.5 + Llama3 threat analysis
5. **Response Layer**: Automatic blocking & IP bans
6. **Alert Layer**: Telegram + Hardware notifications
7. **Audit Layer**: Complete forensic logging

---

## Deployment Architecture

```
Production Server
├── Docker
│   └── MySQL 8.0 (Port 3307)
├── systemd services
│   ├── nexus-datavault-proxy
│   ├── nexus-datavault-web
│   └── nexus-datavault-ai
└── Configuration
    └── .env (secrets, DB creds, etc)
```

---

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | 3.10+ |
| Async | asyncio | Built-in |
| Web | Flask | 2.3+ |
| Database | MySQL | 8.0+ |
| Containerization | Docker | Latest |
| AI | Ollama | Latest |
| Models | Qwen2.5, Llama3 | Latest |
| Security | iptables | Built-in |

---
