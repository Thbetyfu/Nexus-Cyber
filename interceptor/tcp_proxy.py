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
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.db_config import DatabaseManager
from interceptor.sql_parser import SQLParser
from detection.rules import ThreatDetectionEngine, ThreatType
from detection.verdict import VerdictEngine, VerdictAction
from executioner.connection_killer import ConnectionKiller, HardwareAlerter, TelegramAlerter
from executioner.firewall_rules import FirewallManager
from sentinel_brain.dual_brain import DualBrain

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

# QueryLogger removed - replaced by VerdictEngine and DatabaseManager.log_verdict

# ===========================
# PROXY CORE
# ===========================

class MySQLProxy:
    """MySQL TCP Proxy with Threat Detection"""
    
    def __init__(self):
        self.server = None
        self.logger = logger
        self.db_manager = DatabaseManager()
        self.detection_engine = ThreatDetectionEngine()
        self.verdict_engine = VerdictEngine()
        self.killer = ConnectionKiller()           # ADDED
        self.hardware_alerter = HardwareAlerter()
        self.telegram_alerter = TelegramAlerter()
        self.firewall_mgr = FirewallManager()
        self.dual_brain = DualBrain()  # Unified AI Brain
    
    async def pipe_data(self, 
                       reader: asyncio.StreamReader, 
                       writer: asyncio.StreamWriter,
                       label: str,
                       direction: str) -> int:
        """
        Simple pipe data from reader to writer
        """
        bytes_count = 0
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                bytes_count += len(data)
                writer.write(data)
                await writer.drain()
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"[{label}] {direction} pipe error: {e}")
        return bytes_count

    async def execute_verdict(self,
                             verdict: Dict,
                             source_ip: str,
                             query: str,
                             ai_verdict: Optional[Dict] = None) -> bool:
        """
        Execute verdict action
        
        Returns: Should close connection?
        """
        
        action = verdict['action']
        reason = verdict['reason']
        
        # UPGRADE VERDICT BASED ON AI (Qwen 2.5)
        if ai_verdict and ai_verdict.get('risk_level') == 'CRITICAL' and action != VerdictAction.KILL.value:
            self.logger.critical(f"[{source_ip}] 🧠 AI UPGRADE: Action upgraded to KILL based on Reflex Brain analysis!")
            action = VerdictAction.KILL.value
            reason = f"AI Upgrade: {ai_verdict.get('reasoning', reason)}"
        
        if action == VerdictAction.FORWARD.value:
            # Allow query
            return False
        
        elif action == VerdictAction.LOG.value:
            # Log and allow
            self.logger.info(f"[{source_ip}] LOG: {reason}")
            return False
        
        elif action == VerdictAction.BLOCK.value:
            # Block query (close connection)
            self.logger.warning(f"[{source_ip}] 🚫 BLOCKING: {reason}")
            
            # Trigger warning alert
            await self.hardware_alerter.trigger_alert("WARNING")
            
            # Send Telegram warning
            await self.telegram_alerter.send_alert(
                f"⚠️ Blocked query from {source_ip}\n\nQuery: {query[:100]}\n\nReason: {reason}",
                severity="WARNING"
            )
            
            return True  # Close connection
        
        elif action == VerdictAction.KILL.value:
            # Kill connection and ban IP
            self.logger.critical(f"[{source_ip}] 🔴 KILLING: {reason}")
            
            # Optimization: Trigger alerts and killing in background to avoid blocking proxy
            async def run_kill_sequence():
                try:
                    # Trigger critical alert
                    await self.hardware_alerter.trigger_alert("CRITICAL")
                    
                    # Send Telegram critical alert
                    await self.telegram_alerter.send_alert(
                        f"🔴 CRITICAL: Killed connection from {source_ip}\n\n"
                        f"Query: {query[:100]}\n\n"
                        f"Reason: {reason}\n\n"
                        f"Action: IP BANNED",
                        severity="CRITICAL"
                    )
                    
                    # Kill connection and log success
                    success, msg = await self.killer.kill_connection(source_ip, reason)
                    
                    # Log kill action to database
                    try:
                        self.db_manager.log_kill_action(
                            source_ip=source_ip,
                            reason=reason,
                            query=query,
                            success=success
                        )
                    except Exception as e:
                        self.logger.error(f"Failed to log kill action to DB: {e}")
                except Exception as e:
                    self.logger.error(f"Kill sequence error: {e}")

            # Fire and forget the kill sequence
            asyncio.create_task(run_kill_sequence())
            
            return True  # Close connection immediately in proxy
        
        return False

    async def pipe_with_detection(self,
                               reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter,
                               label: str,
                               direction: str,
                               client_ip: str,
                               client_port: int) -> int:
        """
        Pipe data with query extraction and threat detection
        """
        bytes_count = 0
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                
                bytes_count += len(data)
                
                # Try to extract query
                query = SQLParser.extract_query_from_buffer(data)
                
                if query:
                    # Run detection
                    detection_result = self.detection_engine.detect_threat(
                        query=query,
                        source_ip=client_ip,
                        query_bytes=len(data)
                    )
                    
                    # Generate verdict
                    verdict = self.verdict_engine.generate_verdict(
                        detection_result,
                        client_ip
                    )
                    
                    # Log verdict to file
                    self.verdict_engine.log_verdict(verdict)
                    
                    # Log verdict to database
                    try:
                        self.db_manager.log_verdict(
                            query=query,
                            source_ip=client_ip,
                            detection_result=detection_result,
                            verdict=verdict
                        )
                    except Exception as e:
                        self.logger.error(f"Failed to log verdict to DB: {e}")
                    
                    # DUAL-BRAIN AI ANALYST (Reflex + Forensic)
                    # Optimization: If rules say FORWARD or LOG, run AI in background to avoid latency
                    if verdict['action'] in [VerdictAction.FORWARD.value, VerdictAction.LOG.value]:
                        asyncio.create_task(self.run_background_ai(
                            query=query,
                            source_ip=client_ip,
                            detection_result=detection_result,
                            rules_verdict=verdict,
                            writer=writer
                        ))
                        # Rules decided to allow for now
                        should_close = False
                    else:
                        # Rules already flagged it, wait for AI to potentially confirm/upgrade
                        ai_verdict = await self.dual_brain.analyze_threat(
                            query=query,
                            source_ip=client_ip,
                            detected_patterns=detection_result.matched_patterns
                        )
                        
                        self.logger.info(f"[{client_ip}] 🧠 AI Verdict: {ai_verdict.get('severity')} ({ai_verdict.get('threat_type')})")
                        
                        # EXECUTE VERDICT (Rules + AI)
                        should_close = await self.execute_verdict(
                            verdict,
                            client_ip,
                            query,
                            ai_verdict
                        )
                    
                    if should_close:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except:
                            pass
                        return bytes_count
                
                # Forward to destination
                writer.write(data)
                await writer.drain()
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            self.logger.debug(f"[{label}] {direction} pipe error: {e}")
        return bytes_count
    
    async def run_background_ai(self, query, source_ip, detection_result, rules_verdict, writer):
        """Analyze threat in background and take retrospective action if needed"""
        try:
            ai_verdict = await self.dual_brain.analyze_threat(
                query=query,
                source_ip=source_ip,
                detected_patterns=detection_result.matched_patterns
            )
            
            # If AI finds it critical, execute a retrospective verdict (Banning IP)
            if ai_verdict.get('severity') == 'CRITICAL':
                self.logger.critical(f"[{source_ip}] 🧠 BACKGROUND AI DETECTED CRITICAL THREAT! Taking retrospective action.")
                await self.execute_verdict(
                    verdict=rules_verdict,
                    source_ip=source_ip,
                    query=query,
                    ai_verdict=ai_verdict
                )
                
                # Try to close the writer if it's still alive in this high-level connection
                try:
                    if not writer.is_closing():
                        writer.close()
                        await writer.wait_closed()
                except:
                    pass
            elif ai_verdict.get('threat_detected'):
                self.logger.info(f"[{source_ip}] 🧠 Background AI analysis complete: {ai_verdict.get('threat_type')} ({ai_verdict.get('severity')})")
                
        except Exception as e:
            self.logger.error(f"Background AI processing error: {e}")

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
                self.pipe_with_detection(client_reader, backend_writer, label, "C→B", client_ip, client_port)
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
