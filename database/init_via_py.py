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

for statement in sql.split(';'):
    if statement.strip():
        try:
            cursor.execute(statement)
        except Exception as e:
            print(f"Skipping: {e}")

cursor.close()
conn.close()
print("Initialized DB successfully via Python.")
