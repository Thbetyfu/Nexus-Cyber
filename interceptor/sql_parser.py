class SQLParser:
    """
    Parses MySQL packets to extract plaintext SQL queries.
    This is a simplified version targeting the COM_QUERY packet type.
    """
    @staticmethod
    def extract_query(packet_data: bytes) -> str:
        if len(packet_data) < 5:
            return ""
        
        # MySQL packet format: [Length: 3 bytes] [Sequence ID: 1 byte] [Payload]
        # For COM_QUERY, payload starts with 0x03
        payload = packet_data[4:]
        
        if len(payload) > 0 and payload[0] == 0x03:
            try:
                # The rest of the payload is the SQL query
                query = payload[1:].decode('utf-8', errors='ignore')
                return query.strip()
            except Exception:
                return ""
        
        return ""
