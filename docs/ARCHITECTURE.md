# 🏗️ Nexus-Cyber Architecture

## System Components

### 1. TCP Proxy Interceptor
- **File:** `interceptor/tcp_proxy.py`
- **Port:** 3306 (client) → 3307 (backend)
- **Purpose:** Intercept all MySQL queries
- **Technology:** Python asyncio

### 2. Detection Engine
- **Files:** `detection/rules.py`, `detection/verdict.py`
- **Purpose:** Pattern matching & rule-based threat detection
- **Technology:** Regex patterns, scoring engine

### 3. Dual-Brain AI
- **Reflex Brain:** `sentinel_brain/reflex_brain.py` (Qwen2.5)
  - Fast decision (<100ms)
  - Real-time threat assessment
  
- **Forensic Brain:** `sentinel_brain/forensic_brain.py` (Llama3)
  - Deep analysis in background
  - Forensic report generation

### 4. Response Automation
- **File:** `executioner/connection_killer.py`
- **Purpose:** Kill connections, ban IPs, trigger alerts
- **Actions:** Connection termination, iptables rules, hardware alerts

### 5. Web Dashboard
- **Framework:** Flask + SocketIO
- **Port:** 5000
- **Features:** Real-time monitoring, incident history, admin controls

### 6. Database Layer
- **Engine:** MySQL 8.0 (Docker)
- **Port:** 3307 (internal), 3306 (proxy)
- **Purpose:** Store audit logs, incidents, blocked IPs

### 7. Configuration Management
- **File:** `config.py`
- **Source:** Environment variables (.env)
- **Purpose:** Centralized configuration

---

## Data Flow

```
[Application] 
    ↓ (query on :3306)
[TCP Proxy] ← detects query
    ↓
[Query Parser] ← extracts SQL
    ↓
[Rules Engine] ← pattern matching
    ↓
[Dual-Brain AI]
├─ Reflex (fast) ← verdict
└─ Forensic (async) ← analysis
    ↓
[Verdict Engine] ← decision
    ↓
[Actions]
├─ FORWARD → backend database
├─ LOG → audit table
├─ BLOCK → close connection
└─ KILL → ban IP + alerts
    ↓
[Response] → [Real Database :3307]
    ↓
[Results] ← return to application
```

---

## Security Layers

1. **Network Layer**
   - TCP proxy intercepts all connections
   - iptables firewall rules
   - Rate limiting per IP

2. **Application Layer**
   - Input validation (SQL, IP, credentials)
   - Authentication & authorization
   - Session management

3. **AI Layer**
   - Pattern-based detection
   - AI-powered threat assessment
   - Behavioral analysis

4. **Response Layer**
   - Automatic connection killing
   - IP banning
   - Alert system (Telegram, hardware)

5. **Logging Layer**
   - Comprehensive audit logs
   - Forensic data capture
   - Alert notifications

---

## Performance Characteristics

| Component | Latency | Throughput |
|-----------|---------|-----------|
| TCP Proxy | <10ms | >1000 QPS |
| Rules Detection | <50ms | >500 QPS |
| Reflex Brain (AI) | <100ms | >100 QPS |
| Web Dashboard | <500ms | >1000 req/min |
| Database | <10ms | >1000 queries/s |

---

## Scalability

### Vertical Scaling
- Increase proxy chunk size
- Increase database pool size
- More CPU cores for AI

### Horizontal Scaling (Future)
- Multiple proxy instances with load balancer
- Database replication
- Distributed AI inference

---

## Deployment Model

### Development
- Single machine
- All-in-one
- SQLite or local MySQL

### Production
- Dedicated server
- Docker for MySQL
- Systemd for services
- Logging to persistent storage

---

**Version:** 1.0.0  
**Last Updated:** 2024
