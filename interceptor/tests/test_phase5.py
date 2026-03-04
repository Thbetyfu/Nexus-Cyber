import pymysql
import time

def connect():
    return pymysql.connect(
        host='127.0.0.1',
        port=3306,
        user='ktp_user',
        password='ktp_password_123',
        database='ktp_database'
    )

print("\n--- 1. Normal Query (Should PASS) ---")
try:
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT id, nama, email FROM ktp_data LIMIT 1")
    print(f"Success! Result: {cursor.fetchone()}")
    conn.close()
except Exception as e:
    print(f"Error: {e}")

print("\n--- 2. SQL Injection (Should BLOCK) ---")
try:
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ktp_data WHERE id = '1' OR '1'='1'")
    print("Unexpected pass?")
except Exception as e:
    print(f"Blocked successfully! {e}")

print("\n--- 3. Mass Exfiltration Volume ---")
try:
    # Trigger unbounded load
    conn = connect()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ktp_data")
    print("Fetched unbounded data.")
except Exception as e:
    print(f"Blocked successfully! {e}")

print("\n--- 4. Rate Limiting (150 Queries / 1 min) ---")
time.sleep(1) # wait a moment for stable connection
try:
    # Using a single connection to spam
    conn = connect()
    cursor = conn.cursor()
    for i in range(150):
        try:
            cursor.execute("SELECT 1")
            print(f"[{i+1}/150] Query executed", end="\r")
        except Exception as e:
            print(f"\nBlocked at query {i+1}! Reason: {e}")
            break
    conn.close()
except Exception as e:
    print(f"\nBlock connection failed! {e}")

