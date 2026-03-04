"""
Unit tests for database module
Run with: pytest tests/test_database.py
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.db_config import DatabaseManager, DatabasePool
import json

class TestDatabaseConnection:
    """Test database connectivity"""
    
    @pytest.fixture
    def db(self):
        """Fixture: database manager instance"""
        return DatabaseManager()
    
    def test_connection(self, db):
        """Test basic connection"""
        try:
            connection = db.pool.get_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM ktp_data")
            count = cursor.fetchone()[0]
            assert count >= 2, f"Expected >=2 records (initial tests), got {count}"
            cursor.close()
            connection.close()
        except Exception as e:
            pytest.fail(f"Connection test failed: {e}")
    
    def test_ktp_data_exists(self, db):
        """Test that KTP data table exists and has data"""
        connection = db.pool.get_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM ktp_data")
        count = cursor.fetchone()[0]
        assert count > 0, "KTP data table is empty"
        cursor.close()
        connection.close()
    
    def test_audit_log_table_exists(self, db):
        """Test that audit log table exists"""
        connection = db.pool.get_connection()
        cursor = connection.cursor()
        cursor.execute("SHOW TABLES LIKE 'query_audit_log'")
        result = cursor.fetchone()
        assert result is not None, "query_audit_log table not found"
        cursor.close()
        connection.close()


class TestQueryLogging:
    """Test query logging functionality"""
    
    @pytest.fixture
    def db(self):
        return DatabaseManager()
    
    def test_log_query(self, db):
        """Test logging a query"""
        query_id = db.log_query(
            query="SELECT * FROM ktp_data LIMIT 1",
            source_ip="192.168.1.100",
            risk_level="SAFE",
            action_taken="FORWARD"
        )
        assert query_id is not None, "Query logging failed"
        assert isinstance(query_id, int), "Query ID should be integer"
    
    def test_log_query_with_verdict(self, db):
        """Test logging a query with AI verdict"""
        verdict = {
            'threat_type': 'SQL_INJECTION',
            'risk_level': 'CRITICAL',
            'confidence': 0.98
        }
        query_id = db.log_query(
            query="SELECT * FROM ktp_data' OR '1'='1'",
            source_ip="10.0.0.50",
            risk_level="CRITICAL",
            action_taken="BLOCK",
            ai_verdict=verdict
        )
        assert query_id is not None


class TestIPBlocking:
    """Test IP blocking functionality"""
    
    @pytest.fixture
    def db(self):
        return DatabaseManager()
    
    def test_block_ip(self, db):
        """Test blocking an IP"""
        test_ip = "192.168.99.99"
        result = db.block_ip(test_ip, "SQLi attempt", duration_hours=24)
        assert result is True
        
        # Verify IP is blocked
        is_blocked = db.is_ip_blocked(test_ip)
        assert is_blocked is True
        
        # Cleanup
        db.unblock_ip(test_ip)
    
    def test_unblock_ip(self, db):
        """Test unblocking an IP"""
        test_ip = "192.168.99.98"
        db.block_ip(test_ip, "Test block", duration_hours=1)
        
        result = db.unblock_ip(test_ip)
        assert result is True
        
        is_blocked = db.is_ip_blocked(test_ip)
        assert is_blocked is False


# Run tests
if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
