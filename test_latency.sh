#!/bin/bash

echo "🧪 Detection Latency Test"
echo "========================"
echo ""

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_USER=${DB_USER:-"ktp_user"}
DB_PASSWORD=${DB_PASSWORD:-"ktp_password"}
DB_NAME=${DB_NAME:-"ktp_database"}

cat > run_query.py << 'PYTHON_SCRIPT'
import mysql.connector
import sys, os

query = sys.argv[1]

try:
    conn = mysql.connector.connect(
        host='127.0.0.1', 
        port=3306, 
        user=os.environ.get('DB_USER', 'ktp_user'), 
        password=os.environ.get('DB_PASSWORD', ''), 
        database=os.environ.get('DB_NAME', 'ktp_database'),
        ssl_disabled=True
    )
    cursor = conn.cursor()
    cursor.execute(query)
    cursor.fetchall()
    cursor.close()
    conn.close()
except Exception as e:
    sys.exit(1)
PYTHON_SCRIPT

# Test 1: Safe query latency
echo "Test 1: Safe Query Latency"
START=$(date +%s%N)
python3 run_query.py "SELECT COUNT(*) FROM ktp_data LIMIT 10" > /dev/null
END=$(date +%s%N)
LATENCY=$((($END - $START) / 1000000))
echo "Safe query latency: ${LATENCY}ms"

# Test 2: Threat detection latency
echo ""
echo "Test 2: Threat Detection Latency"
START=$(date +%s%N)
python3 run_query.py "SELECT * FROM ktp_data WHERE id='1' OR '1'='1'" > /dev/null 2>&1
END=$(date +%s%N)
LATENCY=$((($END - $START) / 1000000))
echo "Threat detection latency: ${LATENCY}ms"

rm run_query.py
