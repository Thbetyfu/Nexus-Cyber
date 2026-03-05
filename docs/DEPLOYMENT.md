# 📦 Nexus-Cyber Data-Vault Gateway - Deployment Guide

## Table of Contents
1. [Pre-Requisites](#pre-requisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Starting Services](#starting-services)
5. [Verification](#verification)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)
8. [Upgrading](#upgrading)
9. [Backup & Recovery](#backup--recovery)

---

## Pre-Requisites

### System Requirements
- OS: Ubuntu 20.04 LTS or later / Debian 11+
- CPU: 4 cores minimum
- RAM: 8GB minimum
- Disk: 100GB minimum
- Network: Static IP, internet connectivity

### Software Requirements
- Python 3.10+
- Docker & Docker Compose
- MySQL 8.0+
- Git
- Ollama (for AI features)

### User Permissions
- Root access for initial setup
- Dedicated `nexus` user for service operation

---

## Installation

### Step 1: Clone Repository

```bash
git clone -b main https://github.com/Thbetyfu/Nexus-Cyber.git /opt/nexus-cyber
cd /opt/nexus-cyber
```

### Step 2: Run Automated Deployment

```bash
sudo bash deploy/deploy.sh
```

This script will:
- Check dependencies
- Create Python virtual environment
- Install Python packages
- Initialize database
- Create systemd services
- Start services
- Run health checks

### Step 3: Manual Verification

If automated script fails, follow these steps:

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start MySQL
docker-compose -f database/docker-compose.yml up -d

# Initialize database
mysql -h 127.0.0.1 -u ktp_user -p database/init_db.sql < ktp_database

# Start services
python3 interceptor/tcp_proxy.py &
python3 web_gateway.py &
```

---

## Configuration

### 1. Environment File

Create production `.env` file:

```bash
cp .env.example .env
nano .env
```

**Critical settings:**

```bash
# Flask
FLASK_ENV=production
FLASK_SECRET_KEY=<use: python3 -c "import secrets; print(secrets.token_urlsafe(32))">
FLASK_DEBUG=false

# Database
DB_HOST=localhost
DB_PORT=3307
DB_USER=ktp_user
DB_PASSWORD=<strong-password>
DB_NAME=ktp_database

# Admin
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<strong-password>

# Telegram (optional)
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=<your-bot-token>
TELEGRAM_CHAT_ID=<your-chat-id>

# Ollama/AI
OLLAMA_HOST=http://localhost:11434

# Security
ENABLE_IPTABLES=true
BAN_DURATION_HOURS=24
```

### 2. Validate Configuration

```bash
python3 config.py
```

Should output: `Valid: True`

### 3. Generate Secrets

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Use output for `FLASK_SECRET_KEY`

---

## Starting Services

### Automatic Startup

Services auto-start on boot:

```bash
# Check status
systemctl status nexus-proxy
systemctl status nexus-web

# Enable/disable
systemctl enable nexus-proxy
systemctl enable nexus-web

# Start/stop
systemctl start nexus-proxy
systemctl start nexus-web

systemctl stop nexus-proxy
systemctl stop nexus-web
```

### Manual Startup

```bash
# Terminal 1: Proxy
source /opt/nexus-cyber/venv/bin/activate
cd /opt/nexus-cyber
python3 interceptor/tcp_proxy.py

# Terminal 2: Web gateway
source /opt/nexus-cyber/venv/bin/activate
cd /opt/nexus-cyber
python3 web_gateway.py
```

---

## Verification

### Check Services

```bash
# Proxy listening
netstat -tulpn | grep 3306

# Web gateway listening
netstat -tulpn | grep 5000

# Database running
docker ps | grep mysql

# Ollama running (if enabled)
curl http://localhost:11434/api/tags
```

### Test Connectivity

```bash
# Test proxy
mysql -h 127.0.0.1 -P 3306 -u ktp_user -p ktp_database \
  -e "SELECT COUNT(*) FROM ktp_data;"

# Test web gateway
curl -L http://localhost:5000/login

# Test API
curl -H "Cookie: session=..." http://localhost:5000/api/stats
```

### Health Check Script

```bash
bash deploy/health-check.sh
```

Expected output:
```
✓ nexus-proxy running
✓ nexus-web running
✓ Port 3306 accessible
✓ Port 5000 accessible
```

---

## Monitoring

### View Logs

```bash
# Real-time proxy logs
tail -f logs/proxy.log

# Real-time web logs
tail -f logs/app.log

# Security events
tail -f logs/security.log

# Audit trail
tail -f logs/audit.log

# Systemd logs
journalctl -u nexus-proxy -f
journalctl -u nexus-web -f
```

### Monitor Resources

```bash
# CPU/Memory usage
top -p $(pgrep -f tcp_proxy.py)
top -p $(pgrep -f web_gateway.py)

# Network connections
netstat -an | grep 3306 | wc -l

# Database connections
mysql -h 127.0.0.1 -u ktp_user -p ktp_database \
  -e "SHOW PROCESSLIST;"
```

### Set Up Alerts

Configure Telegram/Email alerts in `.env`:

```bash
TELEGRAM_ENABLED=true
TELEGRAM_TOKEN=<bot-token>
TELEGRAM_CHAT_ID=<chat-id>
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 3306
lsof -i :3306

# Kill process
kill -9 <PID>

# Or use different port in .env
PROXY_LISTEN_PORT=3306
```

### MySQL Connection Refused

```bash
# Check MySQL status
docker-compose -f database/docker-compose.yml logs

# Restart MySQL
docker-compose -f database/docker-compose.yml restart

# Check credentials
mysql -h 127.0.0.1 -u ktp_user -p ktp_database -e "SELECT 1;"
```

### Services Not Starting

```bash
# Check systemd status
systemctl status nexus-proxy -l

# View detailed logs
journalctl -u nexus-proxy -n 50

# Check .env file permissions
ls -la .env
```

### High Memory Usage

```bash
# Check process memory
ps aux | grep python3

# Restart services
systemctl restart nexus-proxy
systemctl restart nexus-web

# Check for connection leaks
mysql -e "SHOW PROCESSLIST;" | grep nexus | wc -l
```

### Database Performance Issues

```bash
# Check slow queries
mysql -e "SELECT query, SUM(rows) FROM query_audit_log GROUP BY query ORDER BY SUM(rows) DESC LIMIT 10;"

# Check indexes
mysql -e "SHOW INDEX FROM query_audit_log;"

# Clear old data
mysql -e "DELETE FROM query_audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);"
```

---

## Upgrading

### Update from Repository

```bash
cd /opt/nexus-cyber

# Stop services
sudo systemctl stop nexus-proxy nexus-web

# Update code
git fetch origin
git checkout main
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Start services
sudo systemctl start nexus-proxy nexus-web

# Verify
bash deploy/health-check.sh
```

### Database Migration

```bash
# Backup current database
mysqldump -h 127.0.0.1 -u ktp_user -p ktp_database > backup.sql

# Apply new schema
mysql -h 127.0.0.1 -u ktp_user -p ktp_database < database/init_db.sql

# Verify
mysql -e "SELECT COUNT(*) FROM query_audit_log;"
```

---

## Backup & Recovery

### Automatic Backups

```bash
# Create backup script
cat > /opt/nexus-cyber/backup.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/backup/nexus-cyber"
mkdir -p $BACKUP_DIR

# Backup database
mysqldump -h 127.0.0.1 -u ktp_user -p$DB_PASSWORD ktp_database > \
  $BACKUP_DIR/ktp_database_$(date +%Y%m%d_%H%M%S).sql

# Backup config
cp /opt/nexus-cyber/.env $BACKUP_DIR/.env_$(date +%Y%m%d_%H%M%S)

# Backup logs
tar -czf $BACKUP_DIR/logs_$(date +%Y%m%d_%H%M%S).tar.gz \
  /opt/nexus-cyber/logs/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -mtime +30 -delete
EOF

chmod +x /opt/nexus-cyber/backup.sh
```

### Schedule Daily Backups

```bash
# Add to crontab
crontab -e

# Add line
0 2 * * * /opt/nexus-cyber/backup.sh
```

### Recovery

```bash
# Restore database
mysql -h 127.0.0.1 -u ktp_user -p ktp_database < backup.sql

# Restore config
cp .env_backup .env

# Restart services
sudo systemctl restart nexus-proxy nexus-web
```

---

## Security Hardening

### Firewall Rules

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow web gateway
sudo ufw allow 5000/tcp

# Allow proxy (internal only)
sudo ufw allow from 192.168.0.0/16 to any port 3306

# Allow DNS
sudo ufw allow 53

# Enable firewall
sudo ufw enable
```

### SSL/TLS Configuration (Optional)

```bash
# Generate self-signed certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/nexus-cyber.key \
  -out /etc/ssl/certs/nexus-cyber.crt

# Update Flask to use SSL
FLASK_SSL_CERT=/etc/ssl/certs/nexus-cyber.crt
FLASK_SSL_KEY=/etc/ssl/private/nexus-cyber.key
```

---

## Performance Optimization

### Database Optimization

```bash
# Enable query cache
mysql -e "SET GLOBAL query_cache_size = 268435456;"  # 256MB

# Increase max connections
mysql -e "SET GLOBAL max_connections = 1000;"

# Check slow queries
mysql -e "SET GLOBAL slow_query_log = 'ON';"
```

### Proxy Optimization

Edit `.env`:
```bash
PROXY_CHUNK_SIZE_BYTES=131072      # 128KB chunks
DB_POOL_SIZE=20                     # Increase pool
RATE_LIMIT_QUERIES_PER_MINUTE=500  # Adjust for load
```

### Web Gateway Optimization

```bash
# Use production WSGI server
pip install gunicorn

# Run with Gunicorn
gunicorn --workers 4 --threads 2 --worker-class gthread \
  --bind 0.0.0.0:5000 web_gateway:app
```

---

## Contact & Support

For issues and questions:
- GitHub Issues: https://github.com/Thbetyfu/Nexus-Cyber/issues
- Documentation: https://github.com/Thbetyfu/Nexus-Cyber/docs
- Email: admin@nexus-cyber.local

---

**Version:** 1.0.0  
**Last Updated:** 2024  
**Status:** Production Ready
