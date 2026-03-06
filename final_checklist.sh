#!/bin/bash

echo "🎯 FINAL VERIFICATION CHECKLIST"
echo "================================"
echo ""

PASS=0
FAIL=0

check() {
    if eval "$1" > /dev/null 2>&1; then
        echo "✅ $2"
        PASS=$((PASS+1))
    else
        echo "❌ $2"
        FAIL=$((FAIL+1))
    fi
}

# Infrastructure checks
check "python -c 'import flask'" "Flask installed"
check "python -c 'import mysql.connector'" "MySQL connector installed"
check "python -c 'import pytest'" "Pytest installed"
check "python config.py" "Configuration valid"

# Connectivity checks
check "python -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect_ex((\"127.0.0.1\", 3306))==0 or exit(1)'" "Proxy port 3306 open"
check "python -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect_ex((\"127.0.0.1\", 3307))==0 or exit(1)'" "MySQL port 3307 open"
check "python -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect_ex((\"127.0.0.1\", 5000))==0 or exit(1)'" "Web port 5000 open"

# Database checks
check "python -c 'from config import get_config; import mysql.connector; conn = mysql.connector.connect(**{\"host\": get_config().DB_HOST, \"port\": get_config().DB_PORT, \"user\": get_config().DB_USER, \"password\": get_config().DB_PASSWORD, \"database\": get_config().DB_NAME}); print(\"OK\")'" "Database connection"
check "test -f logs/proxy.log" "Proxy log file exists"
check "test -f logs/app.log" "App log file exists"

# Services check
check "ps aux | grep tcp_proxy.py | grep -v grep" "TCP Proxy running"
check "ps aux | grep web_gateway.py | grep -v grep" "Web Gateway running"

# Docker check - use sudo as taqy might not have permission on some systems
# Check for project name or image name
check "sudo docker ps | grep -E 'mysql|nexus-cyber-db'" "MySQL container running"

echo ""
echo "================================"
echo "Results: $PASS passed, $FAIL failed"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 ALL CHECKS PASSED - SYSTEM READY!"
    exit 0
else
    echo "⚠️  Some checks failed - review above"
    exit 1
fi
