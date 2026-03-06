#!/bin/bash

echo "🧪 Brute Force Protection Test"
echo "==============================="
echo ""
echo "Attempting 10 failed logins..."
echo ""

for i in {1..10}; do
    echo "Attempt $i:"
    curl -X POST http://localhost:5000/login \
        -d "username=admin&password=wrongpassword$i" \
        -s -o /dev/null -w "Status: %{http_code}\n"
    
    sleep 1
done

echo ""
echo "Checking if account locked:"
curl -X POST http://localhost:5000/login \
    -d "username=admin&password=admin123" \
    -s -o /dev/null -w "Status: %{http_code}\n"
