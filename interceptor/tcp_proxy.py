#!/usr/bin/env python3
"""
Nexus-Cyber TCP Proxy for MySQL
- Listens on 0.0.0.0:3306
- Forwards to backend 127.0.0.1:3307
- Logs all connections and traffic
- Handles concurrent clients
- Integrated with MySQL query extraction and logging
"""

import asyncio
import logging
import os
import sys
import hashlib
from datetime import datetime
from typing import Optional, Tuple, Dict
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.db_config import DatabaseManager
from interceptor.sql_parser import SQLParser

# ===========================
# CONFIGURATION
# ===========================

PROXY_LISTEN_HOST = os.getenv('PROXY_LISTEN_HOST', '0.0.0.0')
PROXY_LISTEN_PORT = int(os.getenv('PROXY_LISTEN_PORT', 3306))

BACKEND_HOST = os.getenv('PROXY_BACKEND_HOST', 'localhost')
BACKEND_PORT = int(os.getenv('PROXY_BACKEND_PORT', 3307))

PROXY_LOG_FILE = os.getenv('PROXY_LOG_FILE', 'logs/proxy.log')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# Ensure logs directory exists
os.makedirs(os.path.dirname(PROXY_LOG_FILE) or '.', exist_ok=True)

# ===========================
# LOGGING SETUP
# ===========================

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(PROXY_LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# ===========================
# PROXY STATISTICS
# ===========================

class ProxyStats:
    """Track proxy statistics"""
    
    def __init__(self):
        self.total_connections = 0
        self.active_connections = 0
        self.bytes_received = 0
        self.bytes_sent = 0
        self.total_errors = 0
        self.start_time = datetime.now()
    
    def increment_connection(self):
        self.total_connections += 1
        self.active_connections += 1
    
    def decrement_connection(self):
        self.active_connections -= 1
    
    def add_bytes(self, received: int, sent: int):
        self.bytes_received += received
        self.bytes_sent += sent
    
    def increment_error(self):
        self.total_errors += 1
    
    def get_stats(self) -> dict:
        uptime = (datetime.now() - self.start_time).total_seconds()
        return {
            'uptime_seconds': uptime,
            'total_connections': self.total_connections,
            'active_connections': self.active_connections,
            'bytes_received': self.bytes_received,
            'bytes_sent': self.bytes_sent,
            'total_errors': self.total_errors,
            'throughput_mbps': (self.bytes_received + self.bytes_sent) / 1024 / 1024 / uptime if uptime > 0 else 0
        }

# Global stats instance
stats = ProxyStats()

# ===========================
# QUERY LOGGING
# ===========================

class QueryLogger:
    """Log queries to database"""
    
    def __init__(self):
        try:
            self.db = DatabaseManager()
            self.logger = logger
        except Exception as e:
            logger.error(f"Failed to initialize DB Manager: {e}")
            self.db = None
    
    def log_query(self, 
                  query: str,
                  source_ip: str,
                  source_port: int,
                  execution_time_ms: int = 0):
        """
        Log query to database
        """
        if not self.db or not query:
            return
        
        try:
            # Sanitize query
            safe_query = SQLParser.sanitize_query_for_logging(query)
            
            # Generate query hash for deduplication (optional, but requested in init_db script)
            query_hash = hashlib.sha256(query.encode()).hexdigest()
            
            # Extract tables (for forensic info, matching init_db schema)
            tables = SQLParser.extract_tables(query)
            
            # Log via DatabaseManager
            # Note: DatabaseManager.log_query should handle risk_level and action_taken
            query_id = self.db.log_query(
                query=safe_query,
                source_ip=source_ip,
                risk_level='SAFE',  # Phase 2: all queries are SAFE
                action_taken='FORWARD'
            )
            
            logger.debug(f"Query logged (ID: {query_id}) from {source_ip}")
        
        except Exception as e:
            logger.warning(f"Failed to log query: {e}")

# ===========================
# PROXY CORE
# ===========================

class MySQLProxy:
    """MySQL TCP Proxy"""
    
    def __init__(self):
        self.server = None
        self.logger = logger
        self.query_logger = QueryLogger()
    
    async def pipe_data(self, 
                       reader: asyncio.StreamReader, 
                       writer: asyncio.StreamWriter,
                       label: str,
                       direction: str,
                       client_ip: Optional[str] = None,
                       client_port: Optional[int] = None) -> int:
        """
        Pipe data from reader to writer
        """
        bytes_count = 0
        chunk_count = 0
        
        try:
            while True:
                # Read chunk from source
                data = await reader.read(65536)  # 64KB chunks
                
                if not data:
                    self.logger.debug(f"[{label}] {direction}: EOF reached")
                    break
                
                bytes_count += len(data)
                chunk_count += 1
                
                # If C2B direction, try to extract and log query
                if direction == "C→B" and client_ip:
                    try:
                        query = SQLParser.extract_query_from_buffer(data)
                        if query:
                            self.query_logger.log_query(query, client_ip, client_port or 0)
                    except Exception as e:
                        self.logger.debug(f"Parser error on chunk: {e}")
                
                # Write to destination
                writer.write(data)
                await writer.drain()
            
            # Graceful close
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
            
            self.logger.debug(f"[{label}] {direction}: Closed ({bytes_count} total bytes)")
            
        except asyncio.CancelledError:
            self.logger.debug(f"[{label}] {direction}: Task cancelled")
            raise
        
        except Exception as e:
            self.logger.error(f"[{label}] {direction}: Error - {e}")
            stats.increment_error()
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
        
        return bytes_count
    
    async def handle_client(self, 
                          client_reader: asyncio.StreamReader,
                          client_writer: asyncio.StreamWriter):
        """
        Handle a single client connection
        """
        # Get client address
        client_addr = client_writer.get_extra_info('peername')
        client_ip = client_addr[0]
        client_port = client_addr[1]
        
        label = f"{client_ip}:{client_port}"
        stats.increment_connection()
        
        self.logger.info(f"[{label}] ✓ NEW CLIENT CONNECTED (Active: {stats.active_connections})")
        
        try:
            # Connect to backend database
            try:
                backend_reader, backend_writer = await asyncio.wait_for(
                    asyncio.open_connection(BACKEND_HOST, BACKEND_PORT),
                    timeout=10
                )
                self.logger.debug(f"[{label}] ✓ Connected to backend {BACKEND_HOST}:{BACKEND_PORT}")
            
            except asyncio.TimeoutError:
                self.logger.error(f"[{label}] ✗ Backend connection timeout")
                client_writer.close()
                await client_writer.wait_closed()
                return
            
            except ConnectionRefusedError:
                self.logger.error(f"[{label}] ✗ Backend connection refused (DB down?)")
                client_writer.close()
                await client_writer.wait_closed()
                return
            
            except Exception as e:
                self.logger.error(f"[{label}] ✗ Backend connection error: {e}")
                client_writer.close()
                await client_writer.wait_closed()
                return
            
            # Pipe data bidirectionally
            c2b_task = asyncio.create_task(
                self.pipe_data(client_reader, backend_writer, label, "C→B", client_ip, client_port)
            )
            b2c_task = asyncio.create_task(
                self.pipe_data(backend_reader, client_writer, label, "B→C")
            )
            
            # Wait for both to complete
            c2b_bytes, b2c_bytes = await asyncio.gather(c2b_task, b2c_task)
            
            # Update stats
            stats.add_bytes(c2b_bytes, b2c_bytes)
            
            self.logger.info(f"[{label}] ✓ CLOSED ({c2b_bytes} bytes ↓ | {b2c_bytes} bytes ↑)")
        
        except Exception as e:
            self.logger.error(f"[{label}] ✗ Unexpected error: {e}")
            stats.increment_error()
        
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except:
                pass
            stats.decrement_connection()
    
    async def start(self):
        """Start the proxy server"""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                PROXY_LISTEN_HOST,
                PROXY_LISTEN_PORT
            )
            
            self.logger.info("=" * 60)
            self.logger.info(f"🛡️  NEXUS-CYBER TCP PROXY STARTED")
            self.logger.info(f"   Listen: {PROXY_LISTEN_HOST}:{PROXY_LISTEN_PORT}")
            self.logger.info(f"   Backend: {BACKEND_HOST}:{BACKEND_PORT}")
            self.logger.info(f"   Log: {PROXY_LOG_FILE}")
            self.logger.info("=" * 60)
            
            async with self.server:
                await self.server.serve_forever()
        
        except OSError as e:
            self.logger.error(f"❌ Failed to start proxy: {e}")
            self.logger.error(f"   Port {PROXY_LISTEN_PORT} might be in use")
            sys.exit(1)
        
        except Exception as e:
            self.logger.error(f"❌ Fatal error: {e}")
            sys.exit(1)
    
    async def stop(self):
        """Stop the proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            
            stats_dict = stats.get_stats()
            self.logger.info("=" * 60)
            self.logger.info("📊 FINAL STATISTICS")
            self.logger.info(f"   Uptime: {stats_dict['uptime_seconds']:.1f}s")
            self.logger.info(f"   Total Connections: {stats_dict['total_connections']}")
            self.logger.info(f"   Bytes Received: {stats_dict['bytes_received'] / 1024 / 1024:.2f} MB")
            self.logger.info(f"   Bytes Sent: {stats_dict['bytes_sent'] / 1024 / 1024:.2f} MB")
            self.logger.info(f"   Total Errors: {stats_dict['total_errors']}")
            self.logger.info(f"   Throughput: {stats_dict['throughput_mbps']:.2f} Mbps")
            self.logger.info("=" * 60)

# ===========================
# MAIN ENTRY POINT
# ===========================

async def main():
    """Main entry point"""
    proxy = MySQLProxy()
    try:
        await proxy.start()
    except asyncio.CancelledError:
        await proxy.stop()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n✓ Proxy stopped cleanly")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
