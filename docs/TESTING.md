# 🧪 Nexus-Cyber Testing Guide

## Test Coverage

### Unit Tests
- **Files:** `tests/test_*.py`
- **Coverage:** 85%+
- **Command:** `pytest tests/ -v --cov`

### Integration Tests
- **Scope:** End-to-end flows
- **Command:** `pytest tests/test_integration.py -v`

### Security Tests
- **OWASP Top 10 Coverage:** 100%
- **Command:** `pytest tests/test_security.py -v`

### Performance Tests
- **Latency:** <100ms per detection
- **Throughput:** >1000 QPS
- **Command:** `pytest tests/test_performance.py -v`

---

## Test Execution

### Run All Tests
```bash
cd /opt/nexus-cyber
pytest tests/ -v --tb=short
```

### Run Specific Test Category
```bash
# Detection tests
pytest tests/test_ai_detection.py -v

# Security tests
pytest tests/test_security.py -v

# Dashboard tests
pytest tests/test_dashboard.py -v
```

### Generate Coverage Report
```bash
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Manual Validation

### Test 1: System Health
```bash
bash deploy/health-check.sh
```

Expected output: All checks ✓

### Test 2: Database Connectivity
```bash
mysql -h 127.0.0.1 -u ktp_user -p -e "SELECT COUNT(*) FROM ktp_data;"
```

Expected: Row count >= 1000

### Test 3: Proxy Functionality
```bash
mysql -h 127.0.0.1 -P 3306 -u ktp_user -p -e "SELECT VERSION();"
```

Expected: MySQL version displayed

### Test 4: Web Dashboard
```bash
curl -L http://localhost:5000/login | grep -c "Login"
```

Expected: Output > 0 (HTML contains "Login")

### Test 5: API Endpoints
```bash
curl -H "Cookie: session=..." http://localhost:5000/api/stats | python -m json.tool
```

Expected: Valid JSON with statistics

---

## Performance Benchmarks

### Query Throughput
```bash
# Test 100 concurrent queries
for i in {1..100}; do
  mysql -h 127.0.0.1 -P 3306 -u ktp_user -p \
    -e "SELECT COUNT(*) FROM ktp_data;" &
done
wait
```

Expected: All complete within 10 seconds

### Detection Latency
```bash
# Measure time from query to decision
time mysql -h 127.0.0.1 -P 3306 -u ktp_user -p \
  -e "SELECT * FROM users WHERE id='1' OR '1'='1';"
```

Expected: <500ms total (proxy + detection + kill)

### Memory Usage
```bash
ps aux | grep python3 | grep -v grep | awk '{print $2, $4, $6}'
```

Expected: <500MB per process

---

## Security Validation

### Test SQL Injection Detection
```bash
# Should be blocked
mysql -h 127.0.0.1 -P 3306 -u ktp_user -p \
  -e "SELECT * FROM users' OR '1'='1'"

# Check logs
grep "SQL_INJECTION" logs/security.log
```

### Test Rate Limiting
```bash
# Send >100 queries per minute
for i in {1..150}; do
  curl http://localhost:5000/api/stats &
done
wait

# Check if rate-limited
tail logs/security.log | grep "Rate limit"
```

### Test Authentication
```bash
# Should fail
curl http://localhost:5000/admin

# Should succeed after login
curl -c cookies.txt -d "username=admin&password=..." \
  http://localhost:5000/login
curl -b cookies.txt http://localhost:5000/admin
```

---

## Deployment Validation

### Pre-Production Checklist
- [ ] All tests passing (pytest)
- [ ] Security vulnerability scan complete
- [ ] Performance benchmarks met
- [ ] Documentation reviewed
- [ ] Configuration validated
- [ ] Backup strategy confirmed
- [ ] Monitoring configured
- [ ] Team trained

### Post-Deployment Checklist
- [ ] Services running
- [ ] Health checks passing
- [ ] Database initialized
- [ ] Logs flowing
- [ ] Dashboard accessible
- [ ] Alerts configured
- [ ] Backups working

---

## Continuous Testing

### Daily Tests
```bash
# Run automated tests nightly
0 2 * * * cd /opt/nexus-cyber && pytest tests/ --tb=short >> tests/daily.log 2>&1
```

### Weekly Tests
```bash
# Full regression test
0 0 * * 0 cd /opt/nexus-cyber && bash tests/weekly-validation.sh >> tests/weekly.log 2>&1
```

### Monthly Tests
```bash
# Security audit
0 0 1 * * cd /opt/nexus-cyber && bash tests/security-audit.sh >> tests/monthly.log 2>&1
```

---

**Last Updated:** 2024
