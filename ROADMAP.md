# 📅 Nexus-Cyber Data-Vault Gateway - ROADMAP

## Overview
- **Goal**: Complete pivot from eBPF malware detection to SQL-based data vault gateway
- **Timeline**: 6 weeks (Sept 2024 - Oct 2024)
- **Status**: Phase 0 - In Progress
- **Last Updated**: $(date "+%d %B %Y")

---

## Phase Breakdown

### ✅ Phase 0: Setup & Planning
**Status**: IN PROGRESS
**Duration**: 3 days (Expected: [DATE])
**Owner**: Thoriq Taqy

**Deliverables**:
- [x] Create feature branch
- [x] Archive old eBPF files
- [x] Create folder structure
- [x] Update README
- [x] Create ROADMAP.md
- [ ] Create ARCHITECTURE.md
- [ ] Create DEPLOYMENT.md
- [ ] Update .gitignore
- [ ] Create .env.example
- [ ] Update requirements.txt

**Blockers**: None
**Notes**: Infrastructure setup only, no code changes yet

---

### ⏳ Phase 1: Database Layer
**Status**: PENDING
**Duration**: 5 days
**Owner**: TBD

**Deliverables**:
- [ ] Docker MySQL setup
- [ ] Database schema creation
- [ ] 1000+ dummy KTP data
- [ ] Audit tables
- [ ] Manual connection test

**Blockers**: Waiting for Phase 0
**Notes**: Foundation for entire system

---

### ⏳ Phase 2: TCP PROXY INTERCEPTOR (7 hari)
**Deliverable**: Python TCP proxy yang bisa intercept semua traffic ke database

**Tasks**:
- [ ] BASIC TCP PROXY
- [ ] QUERY EXTRACTION
- [ ] BASIC LOGGING
- [ ] CONFIGURATION
- [ ] TESTING

---

### ⏳ Phase 3: DETECTION ENGINE (6 hari)
**Deliverable**: Proxy bisa detect & flag dangerous queries

**Tasks**:
- [ ] SQL DETECTION RULES
- [ ] VERDICT ENGINE
- [ ] INTEGRATE TO PROXY
- [ ] INCIDENT LOGGING
- [ ] MANUAL TESTING

---

### ⏳ Phase 4: RESPONSE AUTOMATION - THE EXECUTIONER (3 hari)
**Deliverable**: System otomatis kill & block IP saat threat detected

**Tasks**:
- [ ] CONNECTION KILLER
- [ ] FIREWALL RULES MANAGER
- [ ] HARDWARE ALERT
- [ ] TESTING

---

### ⏳ Phase 5: AI INTELLIGENCE - DUAL BRAIN (7 hari)
**Deliverable**: Qwen2.5 + Llama3 untuk smart threat analysis

**Tasks**:
- [ ] REFLEX BRAIN (QWEN2.5)
- [ ] FORENSIC BRAIN (LLAMA3)
- [ ] PROMPTS & TEMPLATES
- [ ] INTEGRATION
- [ ] TESTING

---

### ⏳ Phase 6: DASHBOARD & ADMIN TOOLS (5 hari)
**Deliverable**: Web UI untuk monitoring & control

**Tasks**:
- [ ] UPDATE WEB GATEWAY
- [ ] DASHBOARD ENDPOINTS
- [ ] REAL-TIME UI
- [ ] AUTHENTICATION
- [ ] TESTING

---

### ⏳ Phase 7: SECURITY & HARDENING (4 hari)
**Deliverable**: Production-ready security & environment setup

**Tasks**:
- [ ] ENVIRONMENT VARIABLES
- [ ] SECURITY BEST PRACTICES
- [ ] LOGGING & AUDIT TRAIL
- [ ] TESTING

---

### ⏳ Phase 8: DEPLOYMENT & DOCUMENTATION (3 hari)
**Deliverable**: Ready for production/server deployment

**Tasks**:
- [ ] SYSTEMD SERVICE
- [ ] DEPLOYMENT SCRIPT
- [ ] DOCUMENTATION
- [ ] VERSION RELEASE
- [ ] FINAL TESTING

---

## Known Issues & Blockers
- None currently

## Success Criteria
- [ ] All 8 phases completed
- [ ] >90% test pass rate
- [ ] No hardcoded secrets
- [ ] Production deployment possible
- [ ] Documentation complete

---

## Progress Tracker
| Date | Phase | Status | Notes |
|------|-------|--------|-------|
| Sept 1 | 0 | In Progress | Starting pivot |

