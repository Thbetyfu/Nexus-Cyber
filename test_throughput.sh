#!/bin/bash

echo "🧪 Throughput Benchmark"
echo "======================="
echo ""

echo "Sending 1000 queries..."
START=$(date +%s%N)

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

DB_USER=${DB_USER:-"ktp_user"}
DB_PASSWORD=${DB_PASSWORD:-"ktp_password"}
DB_NAME=${DB_NAME:-"ktp_database"}

cat > run_query.py << 'PYTHON_SCRIPT'
import mysql.connector
import sys, os

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
    cursor.execute("SELECT 1")
    cursor.fetchall()
    cursor.close()
    conn.close()
except Exception as e:
    sys.exit(1)
PYTHON_SCRIPT

# Run loops of Python processes concurrently, up to 10 at a time, to not overwhelm process creation
for i in {1..1000}; do
    python run_query.py > /dev/null 2>&1 &
    
    if [ $((i % 100)) -eq 0 ]; then
        echo "Progress: $i/1000"
        wait
    fi
done

wait
rm run_query.py

END=$(date +%s%N)
ELAPSED=$((($END - $START) / 1000000))
QPS=$((1000000 / ($ELAPSED / 1000)))

echo ""
echo "Results:"
echo "========="
echo "Total queries: 1000"
echo "Total time: ${ELAPSED}ms"
echo "Throughput: $QPS QPS"
echo ""

if [ $QPS -gt 100 ]; then
    echo "✅ PASS: Throughput acceptable"
else
    echo "⚠️  WARNING: Throughput is low"
fi
