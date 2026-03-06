#!/bin/bash

echo "🧪 Rate Limiting Test"
echo "===================="
echo ""
echo "Sending 150 queries in 1 minute..."
echo "Threshold: 100 queries/minute"
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
import threading
import time

def worker(i):
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
        pass
    if i > 0 and i % 20 == 0:
        print(f"Progress: {i}/150 queries sent")

threads = []
for i in range(1, 151):
    t = threading.Thread(target=worker, args=(i,))
    t.start()
    threads.append(t)
    time.sleep(0.01) # slight delay to avoid overwhelming connection queue

for t in threads:
    t.join()
PYTHON_SCRIPT

# Use python instead of python3 to respect active venv
python run_query.py
rm run_query.py

echo "✅ All queries sent"
echo ""
echo "Checking logs for rate limit violations:"
grep -i "rate.*limit\|too.*many\|block" logs/proxy.log | tail -5
