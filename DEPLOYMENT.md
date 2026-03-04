# 📦 DEPLOYMENT GUIDE - Nexus-Cyber Data-Vault Gateway

## Pre-requisites

### System Requirements
- Linux OS (Ubuntu 20.04+ or similar)
- Python 3.10+
- Docker & Docker Compose
- 2GB RAM minimum
- 10GB disk space

### Software Requirements
```bash
# Check Python version
python3 --version  # Should be 3.10+

# Install Docker (if not present)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Verify Docker installation
docker --version
docker-compose --version
```

---

## Installation Steps

### Step 1: Clone Repository
```bash
git clone https://github.com/Thbetyfu/Nexus-Cyber.git
cd Nexus-Cyber
git checkout feature/data-vault-pivot
```

### Step 2: Setup Python Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your values
nano .env
```

### Step 4: Start Database
```bash
# Start MySQL in Docker
cd database/
docker-compose up -d

# Verify database is running
docker-compose logs mysql
```

### Step 5: Initialize Database
```bash
# Create schema and generate dummy data
python generate_ktp_data.py
```

### Step 6: Start Services
```bash
# Start proxy
python interceptor/tcp_proxy.py &

# Start web gateway
python web_gateway.py &

# Check logs
tail -f logs/*.log
```

### Step 7: Verify Installation
```bash
# Test database connection
mysql -h localhost -u ktp_user -p -e "SELECT COUNT(*) FROM ktp_data;"

# Test proxy (should connect via 3306)
mysql -h localhost -u ktp_user -p -e "SELECT VERSION();"

# Access dashboard
open http://localhost:5000/admin
```

---

## Systemd Service Setup (for Auto-start)

```bash
# Create service file
sudo nano /etc/systemd/system/nexus-datavault.service
```

```ini
[Unit]
Description=Nexus-Cyber Data-Vault Gateway
After=network.target

[Service]
Type=forking
User=nexus
WorkingDirectory=/opt/Nexus-Cyber
EnvironmentFile=/opt/Nexus-Cyber/.env
ExecStart=/opt/Nexus-Cyber/venv/bin/python /opt/Nexus-Cyber/interceptor/tcp_proxy.py
ExecStart=/opt/Nexus-Cyber/venv/bin/python /opt/Nexus-Cyber/web_gateway.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable nexus-datavault.service
sudo systemctl start nexus-datavault.service

# Check status
sudo systemctl status nexus-datavault.service
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Port 3306 already in use | `lsof -i :3306` and kill process |
| MySQL connection refused | Check `docker-compose logs mysql` |
| Python package error | `pip install --upgrade pip` then reinstall |
| Permission denied | Add user to docker group: `sudo usermod -aG docker $USER` |

---
