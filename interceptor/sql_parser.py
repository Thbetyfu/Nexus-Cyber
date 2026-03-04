import re
import logging

logger = logging.getLogger(__name__)

class SQLParser:
    """Parse MySQL protocol and extract SQL queries."""
    
    def __init__(self):
        # MySQL command types
        self.COMMAND_QUERY = 0x03
        
    def extract_query(self, data):
        """Extract SQL from MySQL protocol packet."""
        try:
            if len(data) < 5:
                return None
            
            # Check if it's a COM_QUERY packet
            if data[4] != self.COMMAND_QUERY:
                return None
            
            # Extract query text (skip header bytes 0-4)
            query_text = data[5:].decode('utf-8', errors='ignore').strip()
            return query_text
            
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return None
    
    def is_sql_injection(self, query):
        """Detect common SQL injection patterns."""
        injection_patterns = [
            r"('\s*OR\s*'1'\s*=\s*'1)",  # ' OR '1'='1
            r"(\d+\s*OR\s*\d+\s*=\s*\d+)",  # 1 OR 1=1
            r"(UNION.*SELECT)",  # UNION SELECT
            r"(';.*DROP)",  # '; DROP
            r"(--.*\n)",  # SQL comments
            r"(/\*.*\*/)",  # Block comments
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        
        return False
    
    def is_mass_exfiltration(self, query, context=None):
        """Detect SELECT * queries without LIMIT (especially at odd times)."""
        
        # Check for SELECT * without LIMIT
        if re.search(r"SELECT\s+\*\s+FROM", query, re.IGNORECASE):
            if "LIMIT" not in query.upper():
                return True, "SELECT * without LIMIT"
        
        # Check for bulk extraction patterns
        if re.search(r"SELECT.*FROM.*ktp_data", query, re.IGNORECASE):
            if context and context.get('hour') in [0, 1, 2, 3, 4, 5]:  # 3am queries
                return True, "Bulk KTP extraction at suspicious time"
        
        return False, None
    
    def analyze_query_context(self, query):
        """Return query analysis result."""
        return {
            'is_injection': self.is_sql_injection(query),
            'is_exfiltration': self.is_mass_exfiltration(query)[0],
            'tables_accessed': self.extract_tables(query),
            'columns_accessed': self.extract_columns(query),
            'has_limit': 'LIMIT' in query.upper(),
        }
    
    def extract_tables(self, query):
        """Extract table names from query."""
        matches = re.findall(r'FROM\s+(\w+)|JOIN\s+(\w+)', query, re.IGNORECASE)
        return [m[0] if m[0] else m[1] for m in matches]
    
    def extract_columns(self, query):
        """Extract column names from SELECT clause."""
        match = re.search(r'SELECT\s+(.*?)\s+FROM', query, re.IGNORECASE)
        if match:
            cols = match.group(1).split(',')
            return [c.strip() for c in cols]
        return []
