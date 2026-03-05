#!/bin/bash

# ===========================
# NEXUS-CYBER HEALTH CHECK
# ===========================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_service() {
    if systemctl is-active --quiet $1; then
        echo -e "${GREEN}✓${NC} $1 running"
        return 0
    else
        echo -e "${RED}✗${NC} $1 stopped"
        return 1
    fi
}

check_port() {
    if nc -z 127.0.0.1 $1 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Port $1 accessible"
        return 0
    else
        echo -e "${RED}✗${NC} Port $1 not accessible"
        return 1
    fi
}

check_endpoint() {
    if curl -s $1 > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $1 responding"
        return 0
    else
        echo -e "${RED}✗${NC} $1 not responding"
        return 1
    fi
}

echo "🏥 Nexus-Cyber Health Check"
echo "============================"
echo ""

# Check services
echo "📋 Service Status:"
check_service nexus-proxy
check_service nexus-web

echo ""
echo "🔌 Port Availability:"
check_port 3306  # Proxy
check_port 3307  # MySQL
check_port 5000  # Web gateway
check_port 11434 # Ollama

echo ""
echo "🌐 Endpoint Health:"
check_endpoint "http://localhost:5000/login"
check_endpoint "http://localhost:5000/api/stats"

echo ""
echo "✅ Health check complete"
