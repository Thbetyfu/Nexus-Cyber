# 🛡️ Nexus-Cyber: Data-Vault Gateway
## AI-Powered SQL Interception & Threat Detection

![Data-Vault Gateway](https://img.shields.io/badge/Security-Data--Vault-blueviolet)
![Status](https://img.shields.io/badge/Status-Development-orange)

**Nexus-Cyber Data-Vault Gateway** adalah sistem keamanan database berbasis AI yang melindungi data Indonesia dari pencurian dan SQL injection. Sistem ini mengintersepsi SEMUA query database, menganalisis dengan AI, dan memblokir ancaman dalam hitungan milidetik.

---

## 🎯 Problem It Solves

### 🚨 Masalah di Indonesia
- **2024 PDN Ransomware**: 200+ institusi pemerintah terkena
- **INAFIS Breach**: 10 juta fingerprint dicuri
- **Insider Threats**: Karyawan membocorkan data KTP/medis
- **Mass Exfiltration**: Hacker download database dalam semalam

### 💡 Solusi Nexus-Cyber
1. **Real-time SQL Interception** - Semua query dipantau
2. **AI Threat Detection** - Qwen2.5 + Llama3 analisis ancaman
3. **Automatic Response** - Blok, kill, alert dalam milidetik
4. **Forensic Analysis** - Timeline lengkap per insiden
5. **Multi-layer Protection**:
   - SQL Injection detection
   - Mass exfiltration prevention
   - Anomalous behavior flagging
   - Insider threat detection

---

## 🏗️ Architecture

```
Application
    ↓
[Port 3306 - Nexus-Cyber Gateway] ← INTERCEPT POINT
    ↓
[SQL Parser] - Extract & Analyze Query
    ↓
[Detection Engine] - Pattern matching
    ↓
[Dual-Brain AI]:
  ⚡ Qwen2.5 (Fast decision: BLOCK/ALLOW)
  🕵️ Llama3 (Deep forensic analysis)
    ↓
[Verdict]:
  - SAFE → Forward to database
  - SUSPICIOUS → Log & forward
  - DANGEROUS → Block & log
  - CRITICAL → Kill connection & ban IP
    ↓
Real Database (Port 3307)
```

---

## ⚙️ Features

- ✅ **Real-time SQL Query Monitoring** - Live dashboard
- ✅ **SQL Injection Prevention** - Pattern + AI detection
- ✅ **Mass Exfiltration Prevention** - Volume & timing analysis
- ✅ **Automatic IP Blocking** - iptables integration
- ✅ **Forensic Reports** - Timeline + attacker profile
- ✅ **Hardware Alerts** - ASUS RGB + Fan control
- ✅ **Telegram Notifications** - Real-time alerts
- ✅ **Admin Dashboard** - Control & monitoring
- ✅ **Audit Logging** - Complete incident trail

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Ollama (for local AI)

### Setup
1. Clone repository
2. Copy `.env.example` to `.env`
3. Start database: `docker-compose -f database/docker-compose.yml up -d`
4. Install dependencies: `pip install -r requirements.txt`
5. Start proxy: `python interceptor/tcp_proxy.py`
6. Access dashboard: `http://localhost:5000/admin`

---

## 📊 Current Status

| Phase | Status | Timeline |
|-------|--------|----------|
| Phase 0: Setup | ✅ In Progress | 3 days |
| Phase 1: Database | ⏳ Upcoming | 5 days |
| Phase 2: Proxy | ⏳ Upcoming | 7 days |
| Phase 3: Detection | ⏳ Upcoming | 6 days |
| Phase 4: Response | ⏳ Upcoming | 3 days |
| Phase 5: AI | ⏳ Upcoming | 7 days |
| Phase 6: Dashboard | ⏳ Upcoming | 5 days |
| Phase 7: Security | ⏳ Upcoming | 4 days |
| Phase 8: Deployment | ⏳ Upcoming | 3 days |

**Total ETA: 6 weeks to MVP**

---

## 📖 Documentation

- [ROADMAP.md](./ROADMAP.md) - Detailed phase breakdown
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Deployment guide
- [API.md](./docs/API.md) - API documentation

---

## ⚖️ License & Legal

This project is engineered for advanced security research and database protection in Indonesia. **Do not use to bypass legitimate database security controls.**

---

**Created with precision for Indonesian cybersecurity. 🇮🇩🛡️**
