"""
Database configuration and connection pooling for Nexus-Cyber
"""

import mysql.connector
from mysql.connector import pooling
import os
from typing import Optional, Dict, List, Any
import json
from datetime import datetime

class DatabaseConfig:
    """Database configuration from environment"""
    
    def __init__(self):
        self.host = os.getenv('DB_HOST', 'localhost')
        self.port = int(os.getenv('DB_PORT', 3307))
        self.user = os.getenv('DB_USER', 'ktp_user')
        self.password = os.getenv('DB_PASSWORD', 'ktp_password_secure_2024')
        self.database = os.getenv('DB_NAME', 'ktp_database')
        self.pool_size = int(os.getenv('DB_POOL_SIZE', 5))
        self.pool_name = 'nexus_cyber_pool'
    
    def get_connection_config(self) -> Dict:
        """Get connection configuration dictionary"""
        return {
            'host': self.host,
            'port': self.port,
            'user': self.user,
            'password': self.password,
            'database': self.database,
            'autocommit': False  # Manual commit for transactions
        }


class DatabasePool:
    """MySQL connection pool manager"""
    
    _instance = None
    _pool = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabasePool, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._pool is None:
            config = DatabaseConfig()
            self._pool = pooling.MySQLConnectionPool(
                pool_name=config.pool_name,
                pool_size=config.pool_size,
                pool_reset_session=True,
                **config.get_connection_config()
            )
    
    def get_connection(self):
        """Get connection from pool"""
        return self._pool.get_connection()
    
    def close_all(self):
        """Close all pooled connections"""
        if self._pool:
            # Note: mysql-connector doesn't have a direct close_all method
            # Connections are closed when they go out of scope
            pass


class DatabaseManager:
    """High-level database operations manager"""
    
    def __init__(self):
        self.pool = DatabasePool()
    
    def log_query(self, 
                  query: str, 
                  source_ip: str,
                  risk_level: str = 'SAFE',
                  action_taken: str = 'FORWARD',
                  ai_verdict: Optional[Dict] = None) -> int:
        """
        Log a query to audit log
        
        Returns: ID of inserted record
        """
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            insert_query = """
            INSERT INTO query_audit_log 
            (query, source_ip, risk_level, action_taken, ai_verdict, confidence_score)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            verdict_json = json.dumps(ai_verdict) if ai_verdict else None
            confidence = ai_verdict.get('confidence', 0) if ai_verdict else 0
            
            cursor.execute(insert_query, (
                query,
                source_ip,
                risk_level,
                action_taken,
                verdict_json,
                confidence
            ))
            
            connection.commit()
            query_id = cursor.lastrowid
            
            return query_id
            
        except Exception as e:
            connection.rollback()
            print(f"❌ Error logging query: {e}")
            raise
        
        finally:
            cursor.close()
            connection.close()
    
    def log_verdict(self,
                    query: str,
                    source_ip: str,
                    detection_result: Any,
                    verdict: Dict) -> int:
        """
        Log threat detection verdict to database
        """
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            insert_query = """
            INSERT INTO query_audit_log
            (query, source_ip, risk_level, action_taken, 
             ai_verdict, confidence_score, detection_patterns)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            
            # Extract detection_result if it's a dataclass/object
            if hasattr(detection_result, 'matched_patterns'):
                patterns = detection_result.matched_patterns
                confidence = detection_result.confidence
            elif isinstance(detection_result, dict):
                patterns = detection_result.get('matched_patterns', [])
                confidence = detection_result.get('confidence', 0)
            else:
                patterns = []
                confidence = 0
                
            verdict_json = json.dumps(verdict)
            patterns_json = json.dumps(patterns)
            
            # Support both rules-based (dict or object) and AI-based formats
            raw_risk = (verdict.get('risk_level') or verdict.get('severity', 'SAFE')).upper()
            
            # Map AI levels to DB ENUM ('SAFE','SUSPICIOUS','DANGEROUS','CRITICAL')
            risk_mapping = {
                'LOW': 'SUSPICIOUS',
                'MEDIUM': 'SUSPICIOUS',
                'HIGH': 'DANGEROUS',
                'CRITICAL': 'CRITICAL',
                'SAFE': 'SAFE',
                'NONE': 'SAFE'
            }
            risk_level = risk_mapping.get(raw_risk, 'SUSPICIOUS')
            
            action_taken = verdict.get('action') or verdict.get('recommended_action', 'FORWARD')
            
            cursor.execute(insert_query, (
                query,
                source_ip,
                risk_level,
                action_taken,
                verdict_json,
                confidence,
                patterns_json
            ))
            
            connection.commit()
            return cursor.lastrowid
            
        except Exception as e:
            connection.rollback()
            print(f"❌ Error logging verdict: {e}")
            raise
        
        finally:
            cursor.close()
            connection.close()

    def log_incident(self,
                    incident_type: str,
                    severity: str,
                    source_ip: str,
                    forensic_data: Optional[Dict] = None,
                    summary: str = '') -> int:
        """Log security incident"""
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            insert_query = """
            INSERT INTO incidents
            (incident_type, severity, source_ip, forensic_data, summary)
            VALUES (%s, %s, %s, %s, %s)
            """
            
            forensic_json = json.dumps(forensic_data) if forensic_data else None
            
            cursor.execute(insert_query, (
                incident_type,
                severity,
                source_ip,
                forensic_json,
                summary
            ))
            
            connection.commit()
            incident_id = cursor.lastrowid
            
            return incident_id
            
        except Exception as e:
            connection.rollback()
            print(f"❌ Error logging incident: {e}")
            raise
        
        finally:
            cursor.close()
            connection.close()
    
    def block_ip(self,
                 ip_address: str,
                 reason: str,
                 duration_hours: int = 24) -> bool:
        """Add IP to block list"""
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            insert_query = """
            INSERT INTO blocked_ips
            (ip_address, reason, block_duration_hours, unblock_at)
            VALUES (%s, %s, %s, DATE_ADD(NOW(), INTERVAL %s HOUR))
            ON DUPLICATE KEY UPDATE
            incidents_count = incidents_count + 1,
            last_incident_at = NOW()
            """
            
            cursor.execute(insert_query, (
                ip_address,
                reason,
                duration_hours,
                duration_hours
            ))
            
            connection.commit()
            return True
            
        except Exception as e:
            connection.rollback()
            print(f"❌ Error blocking IP: {e}")
            return False
        
        finally:
            cursor.close()
            connection.close()
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP is currently blocked"""
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            query = """
            SELECT id FROM blocked_ips
            WHERE ip_address = %s
            AND (unblock_at IS NULL OR unblock_at > NOW())
            LIMIT 1
            """
            
            cursor.execute(query, (ip_address,))
            result = cursor.fetchone()
            
            return result is not None
            
        finally:
            cursor.close()
            connection.close()
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Remove IP from block list"""
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            delete_query = "DELETE FROM blocked_ips WHERE ip_address = %s"
            cursor.execute(delete_query, (ip_address,))
            connection.commit()
            
            return cursor.rowcount > 0
            
        except Exception as e:
            connection.rollback()
            print(f"❌ Error unblocking IP: {e}")
            return False
        
        finally:
            cursor.close()
            connection.close()
    
    def get_recent_threats(self, limit: int = 100) -> List[Dict]:
        """Get recent security incidents"""
        connection = self.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT *  FROM v_recent_threats
            LIMIT %s
            """
            
            cursor.execute(query, (limit,))
            return cursor.fetchall()
            
        finally:
            cursor.close()
            connection.close()

    def get_dashboard_stats(self) -> Dict:
        """Get summary statistics for dashboard"""
        connection = self.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            stats = {}
            
            # Total queries in last 24h
            cursor.execute("SELECT COUNT(*) as count FROM query_audit_log WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)")
            stats['queries_24h'] = cursor.fetchone()['count']
            
            # Total threats (risk_level != 'SAFE') in last 24h
            cursor.execute("SELECT COUNT(*) as count FROM query_audit_log WHERE risk_level != 'SAFE' AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)")
            stats['threats_24h'] = cursor.fetchone()['count']
            
            # Currently blocked IPs
            cursor.execute("SELECT COUNT(*) as count FROM blocked_ips WHERE unblock_at IS NULL OR unblock_at > NOW()")
            stats['blocked_ips_count'] = cursor.fetchone()['count']
            
            return stats
            
        finally:
            cursor.close()
            connection.close()

    def get_top_offenders(self, limit: int = 5) -> List[Dict]:
        """Get IPs with most incidents"""
        connection = self.pool.get_connection()
        cursor = connection.cursor(dictionary=True)
        
        try:
            query = """
            SELECT source_ip, incidents_count, last_incident_at, reason
            FROM blocked_ips
            ORDER BY incidents_count DESC
            LIMIT %s
            """
            cursor.execute(query, (limit,))
            return cursor.fetchall()
            
        finally:
            cursor.close()
            connection.close()


    def log_kill_action(self,
                       source_ip: str,
                       reason: str,
                       query: str,
                       success: bool) -> int:
        """
        Log IP kill/ban action to database
        """
        connection = self.pool.get_connection()
        cursor = connection.cursor()
        
        try:
            # Insert to incidents table
            insert_query = """
            INSERT INTO incidents
            (incident_type, severity, source_ip, forensic_data, summary, response_action)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            forensic_data = json.dumps({
                'query': query,
                'reason': reason,
                'action_success': success,
                'action_timestamp': datetime.now().isoformat()
            })
            
            severity = 'CRITICAL' if success else 'HIGH'
            
            cursor.execute(insert_query, (
                'SQL_INJECTION',  # incident_type
                severity,
                source_ip,
                forensic_data,
                reason,
                'KILL_CONNECTION_AND_BAN_IP'
            ))
            
            connection.commit()
            return cursor.lastrowid
            
        except Exception as e:
            connection.rollback()
            print(f"❌ Error logging kill action: {e}")
            raise
        
        finally:
            cursor.close()
            connection.close()

# Test connectivity
def test_connection():
    """Test database connection"""
    try:
        manager = DatabaseManager()
        connection = manager.pool.get_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print(f"✅ Database connection successful: MySQL {version[0]}")
        cursor.close()
        connection.close()
        return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False


if __name__ == '__main__':
    test_connection()
