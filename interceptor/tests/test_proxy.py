import pymysql

print("[+] Connecting to Nexus Data-Vault Gateway...")
try:
    conn = pymysql.connect(
        host='127.0.0.1',
        port=3306,
        user='ktp_user',
        password='ktp_password_123',
        database='ktp_database'
    )
    cursor = conn.cursor()
    
    print("\n[-] TEST 1: Normal Query (Should ALLOW)")
    try:
        cursor.execute("SELECT id, nama, email FROM ktp_data LIMIT 1")
        print(f"Success! Result: {cursor.fetchone()}")
    except Exception as e:
        print(f"Failed: {e}")
        
    print("\n[!] TEST 2: Malicious SQL Injection (Should BLOCK)")
    try:
        # We need to reconnect since if blocked, the connection might be dead
        cursor.execute("SELECT * FROM ktp_data WHERE nik = '123' OR 1=1--")
        print(f"Unexpected Success? Result count: {len(cursor.fetchall())}")
    except Exception as e:
        print(f"Blocked successfully! Connection Dropped: {e}")
        
    conn.close()

except Exception as e:
    print(f"Failed to connect: {e}")
