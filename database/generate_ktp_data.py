#!/usr/bin/env python3
"""
Generate dummy KTP data for testing Nexus-Cyber
Requirements: faker, mysql-connector-python
"""

import mysql.connector
from mysql.connector import Error
from faker import Faker
import random
import os
import sys
from datetime import datetime, timedelta

# Configuration
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', 3307))
DB_USER = os.getenv('DB_USER', 'ktp_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'ktp_password_secure_2024')
DB_NAME = os.getenv('DB_NAME', 'ktp_database')

# Number of records to generate
NUM_RECORDS = 1000

class KTPDataGenerator:
    def __init__(self):
        self.faker = Faker('id_ID')  # Indonesian locale
        self.connection = None
        self.cursor = None
    
    def connect(self):
        """Connect to MySQL database"""
        try:
            self.connection = mysql.connector.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASSWORD,
                database=DB_NAME,
                autocommit=False  # For batch inserts
            )
            self.cursor = self.connection.cursor()
            print(f"✅ Connected to {DB_HOST}:{DB_PORT}/{DB_NAME}")
        except Error as e:
            print(f"❌ Connection failed: {e}")
            sys.exit(1)
    
    def generate_nik(self):
        """Generate realistic Indonesian NIK (16 digits)"""
        # Format: DDMMYY-SSSS-CCCC (date-state-code)
        dd = f"{random.randint(1, 28):02d}"
        mm = f"{random.randint(1, 12):02d}"
        yy = f"{random.randint(50, 99):02d}"
        ss = f"{random.randint(1, 34):02d}"  # 34 provinces in Indonesia
        cc = f"{random.randint(1000, 9999):04d}"
        nik = f"{dd}{mm}{yy}{ss}{cc}"
        return nik
    
    def generate_ktp_record(self):
        """Generate single KTP record"""
        birth_date = self.faker.date_of_birth(minimum_age=18, maximum_age=80)
        
        return {
            'nik': self.generate_nik(),
            'nama': self.faker.name(),
            'alamat': self.faker.address().replace('\n', ', '),
            'tanggal_lahir': birth_date,
            'tempat_lahir': random.choice([
                'Jakarta', 'Surabaya', 'Bandung', 'Medan',
                'Semarang', 'Makassar', 'Palembang', 'Jogjakarta',
                'Malang', 'Bogor', 'Tangerang', 'Depok'
            ]),
            'jenis_kelamin': random.choice(['L', 'P']),
            'telp': f"08{random.randint(10, 99)}{random.randint(10000000, 99999999)}",
            'email': self.faker.email()
        }
    
    def insert_bulk_data(self, batch_size=100):
        """Insert KTP records in batches"""
        query = """
        INSERT INTO ktp_data 
        (nik, nama, alamat, tanggal_lahir, tempat_lahir, jenis_kelamin, telp, email)
        VALUES 
        (%(nik)s, %(nama)s, %(alamat)s, %(tanggal_lahir)s, %(tempat_lahir)s, 
         %(jenis_kelamin)s, %(telp)s, %(email)s)
        """
        
        records_inserted = 0
        batch = []
        
        print(f"\n📊 Generating {NUM_RECORDS} KTP records...")
        
        try:
            for i in range(NUM_RECORDS):
                record = self.generate_ktp_record()
                batch.append(record)
                
                # Insert batch when reaching batch size
                if len(batch) >= batch_size or i == NUM_RECORDS - 1:
                    self.cursor.executemany(query, batch)
                    self.connection.commit()
                    records_inserted += len(batch)
                    
                    # Progress indicator
                    progress = (records_inserted / NUM_RECORDS) * 100
                    print(f"   Progress: {records_inserted}/{NUM_RECORDS} ({progress:.1f}%)")
                    
                    batch = []
            
            print(f"\n✅ Successfully inserted {records_inserted} KTP records")
            
        except Error as e:
            print(f"❌ Error inserting data: {e}")
            self.connection.rollback()
            sys.exit(1)
    
    def verify_data(self):
        """Verify inserted data"""
        try:
            # Count total records
            self.cursor.execute("SELECT COUNT(*) FROM ktp_data")
            total_count = self.cursor.fetchone()[0]
            
            # Sample records
            self.cursor.execute("SELECT id, nik, nama, email FROM ktp_data LIMIT 5")
            samples = self.cursor.fetchall()
            
            print(f"\n📋 Data Verification:")
            print(f"   Total records: {total_count}")
            print(f"   Expected: {NUM_RECORDS}")
            
            if total_count >= NUM_RECORDS:
                print(f"   ✅ Data insertion successful")
            else:
                print(f"   ⚠️  Warning: Expected {NUM_RECORDS}, got {total_count}")
            
            print(f"\n   Sample records:")
            for row in samples:
                print(f"   - ID: {row[0]}, NIK: {row[1]}, Nama: {row[2]}, Email: {row[3]}")
            
            # Statistics
            self.cursor.execute("""
            SELECT 
                COUNT(*) as total,
                MIN(created_at) as oldest,
                MAX(created_at) as newest
            FROM ktp_data
            """)
            stats = self.cursor.fetchone()
            print(f"\n   Statistics:")
            print(f"   - Total records: {stats[0]}")
            print(f"   - Oldest record: {stats[1]}")
            print(f"   - Newest record: {stats[2]}")
            
        except Error as e:
            print(f"❌ Verification error: {e}")
            sys.exit(1)
    
    def close(self):
        """Close database connection"""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        print("\n👋 Database connection closed")

def main():
    generator = KTPDataGenerator()
    
    try:
        print("🚀 Nexus-Cyber KTP Data Generator")
        print("=" * 50)
        
        generator.connect()
        generator.insert_bulk_data(batch_size=100)
        generator.verify_data()
        
        print("\n" + "=" * 50)
        print("✅ Data generation completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️  Data generation interrupted by user")
        sys.exit(1)
    
    finally:
        generator.close()

if __name__ == '__main__':
    main()
