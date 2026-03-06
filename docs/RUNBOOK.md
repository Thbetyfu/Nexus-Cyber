# 🚀 PANDUAN LENGKAP: MENJALANKAN & TESTING NEXUS-CYBER

## 📋 TABLE OF CONTENTS

1. [Pre-requisites](#pre-requisites)
2. [Setup Environment](#setup-environment)
3. [Start Services](#start-services)
4. [Run Automated Tests](#run-automated-tests)
5. [Manual Testing](#manual-testing)
6. [Verify Everything Works](#verify-everything-works)
7. [Troubleshooting](#troubleshooting)

---

## 🔍 PRE-REQUISITES

### System Requirements Check

```bash
# Check Python version
python3 --version
# Should be: Python 3.10+

# Check if pip installed
pip3 --version

# Check if Docker installed
docker --version
docker-compose --version

# Check if MySQL client installed
mysql --version

# Check if git installed
git --version
```

### Clone Repository

```bash
# Clone project
git clone https://github.com/Thbetyfu/Nexus-Cyber.git
cd Nexus-Cyber

# Verify you're on correct branch
git branch -v

# Or checkout the branch
git checkout feature/data-vault-pivot
```

---

## ⚙️ SETUP ENVIRONMENT

### Step 1: Create Virtual Environment

```bash
# Create venv
python3 -m venv venv

# Activate venv
# Linux/macOS:
source venv/bin/activate
```

### Step 2: Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install requirements
pip install -r requirements.txt
```

### Step 3: Setup Environment Variables

```bash
# Copy template
cp .env.example .env

# Edit with your settings
# Set required critical variables:
# FLASK_SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD
```

### Step 4: Verify Configuration

```bash
# Check if config loads
python3 config.py
```

---

## 🗄️ START SERVICES

### Step 1: Start MySQL Database

```bash
# Start MySQL in Docker
cd database
docker-compose up -d

# Wait 10 seconds for MySQL to be ready
sleep 10
```

### Step 2: Initialize Database

```bash
# Initialize database schema
mysql -h 127.0.0.1 -u ktp_user -p ktp_database < database/init_db.sql
```

### Step 3: Generate Dummy Data

```bash
# Generate 1000 test records
python3 database/generate_ktp_data.py
```

### Step 4: Start TCP Proxy

```bash
# In Terminal 1
source venv/bin/activate
python3 interceptor/tcp_proxy.py
```

### Step 5: Start Web Gateway

```bash
# Open NEW terminal, then:
source venv/bin/activate
python3 web_gateway.py
```

### Step 6: Verify All Services Running

```bash
bash deploy/health-check.sh
```

---

## 🧪 RUN AUTOMATED TESTS

### Test 1: Run ALL Tests at Once

```bash
# Run all tests with coverage
pytest tests/ -v --tb=short --cov=. --cov-report=term-missing
```

---

## 🔬 MANUAL TESTING

### Test 1: Test Proxy Connection

```bash
mysql -h 127.0.0.1 -P 3306 -u ktp_user -p ktp_database -e "SELECT COUNT(*) FROM ktp_data;"
```

### Test 2: Test Safe Query (Should Execute)

```bash
mysql -h 127.0.0.1 -P 3306 -u ktp_user -p ktp_database -e "SELECT id, nama FROM ktp_data LIMIT 10;"
```

### Test 3: Test SQL Injection (Should Be Blocked)

```bash
mysql -h 127.0.0.1 -P 3306 -u ktp_user -p ktp_database -e "SELECT * FROM ktp_data WHERE id='1' OR '1'='1';"
```

### Test 4: Access Web Dashboard

```
http://localhost:5000/login
```

---

## ✅ VERIFY EVERYTHING WORKS

Run `verify_all.sh` from the root directory to automatically assess the system's operational status.

---

## 🐛 TROUBLESHOOTING

- **Port 3306 already in use**: Use `lsof -i :3306` and `kill -9 <PID>`
- **MySQL connection refused**: Check if docker is running `docker ps` and restart if necessary
- **Permission denied for proxy**: Run `chmod +x interceptor/tcp_proxy.py`

---

**SEKARANG ANDA SIAP UNTUK MENJALANKAN NEXUS-CYBER!** 🚀
