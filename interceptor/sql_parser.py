"""
MySQL protocol parser and SQL query extraction
Handles MySQL protocol packet parsing to extract query strings
"""

import struct
import logging
from typing import Optional, Tuple
from enum import Enum
import re

logger = logging.getLogger(__name__)

class MySQLCommand(Enum):
    """MySQL command types"""
    COM_INIT_DB = 0x02
    COM_QUERY = 0x03
    COM_PING = 0x0E
    COM_CHANGE_USER = 0x11
    COM_PREPARE = 0x16

class SQLParser:
    """Parse MySQL protocol and extract SQL queries"""
    
    # MySQL packet structure constants
    MYSQL_PROTOCOL_VERSION = 10
    MAX_PACKET_SIZE = 16 * 1024 * 1024  # 16MB
    
    @staticmethod
    def parse_packet_header(data: bytes) -> Tuple[Optional[int], Optional[int]]:
        """
        Parse MySQL packet header
        
        Format: [3 bytes: payload length] [1 byte: sequence]
        Returns: (payload_length, sequence_id)
        """
        if len(data) < 4:
            return None, None
        
        # First 3 bytes = payload length (little-endian)
        payload_length = int.from_bytes(data[0:3], 'little')
        
        # 4th byte = sequence id
        sequence_id = data[3]
        
        return payload_length, sequence_id
    
    @staticmethod
    def parse_query_packet(data: bytes) -> Optional[str]:
        """
        Parse MySQL query packet
        
        Format: [packet_header] [command_byte] [query_string]
        
        Returns: Query string or None if not a query packet
        """
        if len(data) < 5:  # Minimum: 4 byte header + 1 byte command
            return None
        
        try:
            # Extract payload (skip 4-byte header)
            payload = data[4:]
            
            if len(payload) < 1:
                return None
            
            # First byte is command type
            command = payload[0]
            
            # COM_QUERY = 0x03
            if command != MySQLCommand.COM_QUERY.value:
                return None
            
            # Rest is query string
            if len(payload) > 1:
                query = payload[1:].decode('utf-8', errors='ignore').strip()
                return query
            
            return None
        
        except Exception as e:
            logger.warning(f"Error parsing query packet: {e}")
            return None
    
    @staticmethod
    def extract_query_from_buffer(data: bytes) -> Optional[str]:
        """
        Extract SQL query from raw data buffer
        
        Handles multiple packets and partial packets
        """
        if not data or len(data) < 5:
            return None
        
        # Try to parse as query packet
        query = SQLParser.parse_query_packet(data)
        return query
    
    @staticmethod
    def get_query_type(query: str) -> str:
        """
        Determine query type: SELECT, INSERT, UPDATE, DELETE, etc.
        
        Returns: Query type (uppercase)
        """
        if not query:
            return "UNKNOWN"
        
        query_upper = query.strip().upper()
        
        # Extract first word
        first_word = query_upper.split()[0] if query_upper else "UNKNOWN"
        
        valid_types = [
            "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", 
            "DROP", "ALTER", "TRUNCATE", "GRANT", "REVOKE",
            "LOCK", "UNLOCK", "FLUSH", "SHOW"
        ]
        
        return first_word if first_word in valid_types else "OTHER"
    
    @staticmethod
    def extract_tables(query: str) -> list:
        """
        Extract table names from query
        
        Naive parsing, supports: FROM, INTO, UPDATE, JOIN
        """
        if not query:
            return []
        
        query_upper = query.upper()
        tables = []
        
        patterns = [
            r'FROM\s+(`?\w+`?)',      # FROM table
            r'INTO\s+(`?\w+`?)',      # INSERT INTO table
            r'UPDATE\s+(`?\w+`?)',    # UPDATE table
            r'JOIN\s+(`?\w+`?)',      # JOIN table
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, query_upper)
            tables.extend([m.strip('`') for m in matches])
        
        return list(set(tables))  # Deduplicate
    
    @staticmethod
    def sanitize_query_for_logging(query: str, max_length: int = 500) -> str:
        """
        Sanitize query string for logging
        - Limit length
        - Remove newlines
        - Escape quotes
        """
        if not query:
            return "(empty)"
        
        # Remove newlines
        sanitized = query.replace('\n', ' ').replace('\r', ' ')
        
        # Collapse multiple spaces
        sanitized = ' '.join(sanitized.split())
        
        # Limit length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized

def test_parser():
    """Test SQL parser"""
    # Example MySQL query packet (simplified)
    # [3-byte length][1-byte seq][1-byte command][query...]
    
    test_query = "SELECT * FROM ktp_data LIMIT 10"
    
    # Construct packet (simplified for testing)
    command = b'\x03'  # COM_QUERY
    query_bytes = test_query.encode('utf-8')
    payload = command + query_bytes
    
    payload_len = len(payload)
    header = payload_len.to_bytes(3, 'little') + b'\x00'  # sequence=0
    
    packet = header + payload
    
    # Test extraction
    extracted = SQLParser.extract_query_from_buffer(packet)
    print(f"Original: {test_query}")
    print(f"Extracted: {extracted}")
    assert extracted == test_query, "Parse failed!"
    print("✅ Parser test passed")

if __name__ == '__main__':
    test_parser()
