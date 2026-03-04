"""
Unit tests for TCP Proxy
Run with: pytest tests/test_proxy.py -v
"""

import pytest
import asyncio
import sys
import os
import mysql.connector
from time import sleep

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from interceptor.sql_parser import SQLParser
from database.db_config import DatabaseManager

class TestSQLParser:
    """Test SQL parser"""
    
    def test_query_extraction(self):
        """Test extracting query from MySQL packet"""
        query = "SELECT * FROM ktp_data"
        # Simplified packet construction
        command = b'\x03'
        payload = command + query.encode()
        payload_len = len(payload)
        header = payload_len.to_bytes(3, 'little') + b'\x00'
        packet = header + payload
        
        extracted = SQLParser.extract_query_from_buffer(packet)
        assert extracted == query
    
    def test_query_type_detection(self):
        """Test query type detection"""
        test_cases = [
            ("SELECT * FROM users", "SELECT"),
            ("INSERT INTO users VALUES(...)", "INSERT"),
            ("UPDATE users SET id=1", "UPDATE"),
            ("DELETE FROM users WHERE id=1", "DELETE"),
            ("CREATE TABLE users (...)", "CREATE"),
        ]
        
        for query, expected_type in test_cases:
            result = SQLParser.get_query_type(query)
            assert result == expected_type, f"Failed for: {query}"
    
    def test_table_extraction(self):
        """Test table name extraction"""
        query = "SELECT * FROM users JOIN orders ON users.id = orders.user_id"
        tables = SQLParser.extract_tables(query)
        
        # Normailize tables to uppercase for comparison
        upper_tables = [t.upper() for t in tables]
        assert "USERS" in upper_tables
        assert "ORDERS" in upper_tables
    
    def test_query_sanitization(self):
        """Test query sanitization for logging"""
        query = "SELECT * FROM users\nWHERE id=1"
        sanitized = SQLParser.sanitize_query_for_logging(query)
        
        # Should not contain newlines
        assert '\n' not in sanitized
        # Should NOT necessarily collapse spaces to NO double spaces if it's just one space replacement
        # The implementation uses ' '.join(sanitized.split()) which collapses all whitespace
        assert '  ' not in sanitized


class TestProxyLogging:
    """Test proxy logging to database"""
    
    @pytest.fixture
    def db(self):
        return DatabaseManager()
    
    def test_query_logging_to_db(self, db):
        """Test that queries are logged to database"""
        test_query = "SELECT * FROM ktp_data WHERE id=1"
        test_ip = "192.168.100.100"
        
        query_id = db.log_query(
            query=test_query,
            source_ip=test_ip,
            risk_level='SAFE',
            action_taken='FORWARD'
        )
        
        assert query_id is not None
        assert isinstance(query_id, int)
    
    def test_multiple_queries_logged(self, db):
        """Test logging multiple queries"""
        for i in range(10):
            query_id = db.log_query(
                query=f"SELECT * FROM ktp_data LIMIT {i}",
                source_ip=f"192.168.1.{i}",
                risk_level='SAFE',
                action_taken='FORWARD'
            )
            assert query_id is not None


class TestProxyConnectivity:
    """Test proxy connectivity (requires proxy running)"""
    
    @pytest.fixture(scope="class")
    def mysql_connection(self):
        """Fixture: MySQL connection via proxy"""
        try:
            conn = mysql.connector.connect(
                host='127.0.0.1',
                port=3306,  # PROXY PORT
                user='ktp_user',
                password='ktp_password_secure_2024',
                database='ktp_database',
                autocommit=True
            )
            yield conn
            conn.close()
        except Exception as e:
            pytest.skip(f"Proxy not available: {e}")
    
    def test_proxy_select_query(self, mysql_connection):
        """Test SELECT through proxy"""
        cursor = mysql_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM ktp_data")
        count = cursor.fetchone()[0]
        # Previous phase inserted 1002 records
        assert count >= 1000, f"Expected >= 1000 records, got {count}"
        cursor.close()
    
    def test_proxy_insert_query(self, mysql_connection):
        """Test INSERT through proxy"""
        cursor = mysql_connection.cursor()
        test_nik = '9999999999999999'
        
        try:
            cursor.execute(
                "INSERT INTO ktp_data (nik, nama) VALUES (%s, %s)",
                (test_nik, 'Proxy Test User')
            )
            mysql_connection.commit()
            
            # Verify insert
            cursor.execute("SELECT * FROM ktp_data WHERE nik=%s", (test_nik,))
            result = cursor.fetchone()
            assert result is not None
        
        finally:
            # Cleanup
            cursor.execute("DELETE FROM ktp_data WHERE nik=%s", (test_nik,))
            mysql_connection.commit()
            cursor.close()
    
    def test_proxy_update_query(self, mysql_connection):
        """Test UPDATE through proxy"""
        cursor = mysql_connection.cursor()
        
        # Insert test record
        test_nik = '8888888888888888'
        cursor.execute(
            "INSERT INTO ktp_data (nik, nama, email) VALUES (%s, %s, %s)",
            (test_nik, 'Original', 'original@test.com')
        )
        mysql_connection.commit()
        
        try:
            # Update
            cursor.execute(
                "UPDATE ktp_data SET nama=%s WHERE nik=%s",
                ('Updated', test_nik)
            )
            mysql_connection.commit()
            
            # Verify update
            cursor.execute("SELECT nama FROM ktp_data WHERE nik=%s", (test_nik,))
            name = cursor.fetchone()[0]
            assert name == 'Updated'
        
        finally:
            # Cleanup
            cursor.execute("DELETE FROM ktp_data WHERE nik=%s", (test_nik,))
            mysql_connection.commit()
            cursor.close()
