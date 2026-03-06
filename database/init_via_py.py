import mysql.connector
from config import get_config

config = get_config()

with open('database/init_db.sql', 'r') as f:
    sql = f.read()

conn = mysql.connector.connect(
    host=config.DB_HOST,
    port=config.DB_PORT,
    user=config.DB_USER,
    password=config.DB_PASSWORD,
    database=config.DB_NAME,
    autocommit=True
)

cursor = conn.cursor()

# Split by semicolon but be careful with multi-line statements
# For this simple script, splitting by ';' is mostly okay since standard SQL uses it.
for statement in sql.split(';'):
    stmt = statement.strip()
    if stmt:
        # Skip permission-related commands as ktp_user doesn't have them
        if any(cmd in stmt.upper() for cmd in ["GRANT", "FLUSH PRIVILEGES"]):
            print(f"Skipping permission command: {stmt[:50]}...")
            continue
            
        try:
            cursor.execute(stmt)
            # Drain any results (especially for the SELECTs at the end)
            while cursor.nextset():
                pass
            if cursor.with_rows:
                cursor.fetchall()
        except Exception as e:
            # We expect some "already exists" errors if re-running
            if "already exists" not in str(e).lower() and "Duplicate entry" not in str(e).lower():
                print(f"Error executing: {stmt[:50]}...")
                print(f"Reason: {e}")

cursor.close()
conn.close()
print("Initialized DB successfully via Python.")
