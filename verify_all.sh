#!/bin/bash

echo "🔍 NEXUS-CYBER VERIFICATION CHECKLIST"
echo "======================================"
echo ""

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

# Check 1: Python & venv
echo "1️⃣  Python Virtual Environment..."
if [ -n "$VIRTUAL_ENV" ] || [ -d ".venv" ] || [ -d "venv" ]; then
    echo "   ✅ venv directory exists or is active"
else
    echo "   ❌ venv not found"
    exit 1
fi

# Check 2: Dependencies
echo ""
echo "2️⃣  Python Dependencies..."
python3 -c "import flask, mysql, pytest" 2>/dev/null && echo "   ✅ All dependencies installed" || echo "   ❌ Missing dependencies"

# Check 3: Config
echo ""
echo "3️⃣  Configuration..."
python3 config.py > /dev/null 2>&1 && echo "   ✅ Config valid" || echo "   ❌ Config invalid"

# Check 4: Database
echo ""
echo "4️⃣  Database Connection..."
if python3 -c "import mysql.connector; from config import get_config; c=get_config(); mysql.connector.connect(host=c.DB_HOST, user=c.DB_USER, password=c.DB_PASSWORD, database=c.DB_NAME, port=c.DB_PORT).close()" >/dev/null 2>&1; then
    echo "   ✅ Database connected"
else
    echo "   ❌ Database not accessible"
fi

# Check 5: MySQL Data
echo ""
echo "5️⃣  Database Tables & Data..."
COUNT=$(python3 -c "import mysql.connector; from config import get_config; c=get_config(); conn=mysql.connector.connect(host=c.DB_HOST, user=c.DB_USER, password=c.DB_PASSWORD, database=c.DB_NAME, port=c.DB_PORT); curr=conn.cursor(); curr.execute('SELECT COUNT(*) FROM ktp_data'); print(curr.fetchone()[0]); curr.close(); conn.close()" 2>/dev/null || echo "0")
if [ -n "$COUNT" ] && [ "$COUNT" -gt 1000 ]; then
    echo "   ✅ Database has $COUNT records"
else
    echo "   ❌ Database has only ${COUNT:-0} records (expected >1000)"
fi

# Check 6: Ports
echo ""
echo "6️⃣  Service Ports..."
nc -z 127.0.0.1 3306 2>/dev/null && echo "   ✅ Port 3306 (Proxy) open" || echo "   ❌ Port 3306 closed"
nc -z 127.0.0.1 3307 2>/dev/null && echo "   ✅ Port 3307 (MySQL) open" || echo "   ❌ Port 3307 closed"
nc -z 127.0.0.1 5000 2>/dev/null && echo "   ✅ Port 5000 (Web) open" || echo "   ❌ Port 5000 closed"

# Check 7: Tests
echo ""
echo "7️⃣  Running Unit Tests..."
pytest tests/test_database.py -q 2>/dev/null && echo "   ✅ Database tests passed" || echo "   ⚠️  Database tests failed"

# Final summary
echo ""
echo "======================================"
echo "✅ VERIFICATION COMPLETE"
echo "======================================"
