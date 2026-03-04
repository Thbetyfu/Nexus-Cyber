import mysql.connector
import os

def check_logs():
    try:
        conn = mysql.connector.connect(
            host='127.0.0.1',
            port=3307,
            user='ktp_user',
            password='ktp_password_secure_2024',
            database='ktp_database'
        )
        cursor = conn.cursor()
        cursor.execute("SELECT query, source_ip FROM query_audit_log WHERE risk_level='SAFE' ORDER BY id DESC LIMIT 5")
        rows = cursor.fetchall()
        print("Recent logs in query_audit_log:")
        for row in rows:
            print(f"- {row[0]} (from {row[1]})")
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_logs()
