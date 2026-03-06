#!/bin/bash

echo "🧪 SQL Injection Test Suite"
echo "============================"
echo ""

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_USER=${DB_USER:-"ktp_user"}
DB_PASSWORD=${DB_PASSWORD:-"ktp_password"}
DB_NAME=${DB_NAME:-"ktp_database"}

run_query() {
    python -c "import mysql.connector; conn=mysql.connector.connect(host='127.0.0.1', port=3306, user='$DB_USER', password='$DB_PASSWORD', database='$DB_NAME', ssl_disabled=True); cursor=conn.cursor(); cursor.execute(\"$1\"); print('Query Executed without error'); cursor.close(); conn.close()" 2>/dev/null || echo "Query blocked or error"
}

# Test 1: OR 1=1
echo "Test 1: Classic OR 1=1"
echo "Expected: DANGEROUS threat detected (Query blocked)"
run_query "SELECT * FROM ktp_data WHERE id='1' OR '1'='1'"
echo ""

# Test 2: UNION SELECT
echo "Test 2: UNION SELECT"
echo "Expected: DANGEROUS threat detected (Query blocked)"
run_query "SELECT id FROM ktp_data UNION SELECT password FROM admin"
echo ""

# Test 3: Comment injection
echo "Test 3: Comment injection (--)"
echo "Expected: DANGEROUS threat detected (Query blocked)"
run_query "SELECT * FROM ktp_data WHERE id='1' OR '1'='1'--"
echo ""

# Test 4: SLEEP function
echo "Test 4: Time-based blind (SLEEP)"
echo "Expected: DANGEROUS threat detected (Query blocked)"
run_query "SELECT * FROM ktp_data WHERE id=1 AND SLEEP(2)"
echo ""

# Check logs
echo "📋 Checking Proxy Logs for detections:"
grep -i "sql_injection\|dangerous\|critical\|blocking" logs/proxy.log | tail -10
