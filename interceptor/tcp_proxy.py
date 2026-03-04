import asyncio
import logging
import json
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentinel_brain.reflex_brain import Reflex_Brain
from sentinel_brain.forensic_brain import Forensic_Brain
from executioner.connection_killer import ConnectionKiller
from interceptor.sql_parser import SQLParser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("ProxyInterceptor")

class SQLInterceptor:
    def __init__(self, listen_host='0.0.0.0', listen_port=3306, 
                 backend_host='127.0.0.1', backend_port=3307):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        
        # Instantiate Dual-Brain components and Executioner
        self.reflex = Reflex_Brain()      # Qwen 2.5
        self.forensic = Forensic_Brain()  # Llama 3
        self.parser = SQLParser()
        self.killer = ConnectionKiller()
        
        # Phase 5: State tracking for anomaly detection and rate limiting
        self.blocked_ips = set()
        self.query_rate_tracker = {} # ip -> [timestamps...]
        self.volume_tracker = {} # ip -> {"bytes": 0, "start_time": time.time()}
        
    async def check_ip_reputation(self, ip_addr):
        """Feature: Check IP Reputation against mock intel sets."""
        known_malicious = ["185.15.1.20", "45.22.1.99"]
        return ip_addr in known_malicious
        
    async def check_rate_limit(self, ip_addr):
        """Feature: Connection Rate Limiting (>100 queries/min)."""
        now = time.time()
        if ip_addr not in self.query_rate_tracker:
            self.query_rate_tracker[ip_addr] = []
            
        # keep only queries in last 60 seconds
        self.query_rate_tracker[ip_addr] = [t for t in self.query_rate_tracker[ip_addr] if now - t < 60]
        self.query_rate_tracker[ip_addr].append(now)
        
        if len(self.query_rate_tracker[ip_addr]) > 100:
            return True
        return False
        
    async def monitor_data_volume(self, ip_addr, packet_bytes, time_window=5):
        """Feature: Query Volume Monitoring (Detect bulk exports >100,000 rows in <5 detik)."""
        now = time.time()
        if ip_addr not in self.volume_tracker:
            self.volume_tracker[ip_addr] = {"bytes": 0, "start_time": now}
            
        tracker = self.volume_tracker[ip_addr]
        time_elapsed = now - tracker["start_time"]
        
        if time_elapsed > time_window:
            # Reset window
            tracker["bytes"] = packet_bytes
            tracker["start_time"] = now
        else:
            tracker["bytes"] += packet_bytes
            
        # Estimate: 1 row is approx 50 bytes conservatively. 100,000 rows = ~5MB (5,000,000 bytes)
        estimated_rows = tracker["bytes"] / 50
        if estimated_rows > 100000 and time_elapsed < time_window:
            return True
        return False
        
    async def check_anomalous_time(self, query):
        """Feature: Anomalous Time Detection (Queries pada jam 3-5 pagi dengan SELECT *)."""
        hour = datetime.now().hour
        if hour in [0, 1, 2, 3, 4, 5] and "SELECT *" in query.upper():
            return True
        return False

    async def handle_client(self, client_reader, client_writer):
        client_addr = client_writer.get_extra_info('peername')
        ip_addr = client_addr[0] if isinstance(client_addr, tuple) else "127.0.0.1"
        
        if ip_addr in self.blocked_ips:
            client_writer.close()
            return

        if await self.check_ip_reputation(ip_addr):
            logger.critical(f"🚨 BLOCKED KNOWN MALICIOUS IP: {ip_addr}")
            self.blocked_ips.add(ip_addr)
            await self.killer.drop_connection(ip_addr)
            client_writer.close()
            return
            
        logger.info(f"[+] New connection from {client_addr}")
        
        try:
            backend_reader, backend_writer = await asyncio.open_connection(
                self.backend_host, self.backend_port
            )
            
            await asyncio.gather(
                self.forward_and_inspect(client_reader, backend_writer, client_addr, "REQUEST"),
                self.forward_and_inspect(backend_reader, client_writer, client_addr, "RESPONSE")
            )
            
        except Exception as e:
            logger.error(f"[ERROR] {client_addr}: {e}")
        finally:
            client_writer.close()
            await client_writer.wait_closed()
            
    async def forward_and_inspect(self, source, dest, client_addr, direction):
        ip_addr = client_addr[0] if isinstance(client_addr, tuple) else "127.0.0.1"
        
        try:
            while True:
                data = await source.read(4096)
                if not data:
                    break
                    
                if direction == "REQUEST":
                    query = self.parser.extract_query(data)
                    if query:
                        logger.info(f"[SQL] Client {client_addr}: {query}")
                        
                        # Phase 5: Check Rate Limit
                        if await self.check_rate_limit(ip_addr):
                            logger.warning(f"🚨 RATE LIMIT EXCEEDED FOR {ip_addr} (>100 queries/min)")
                            self.blocked_ips.add(ip_addr)
                            await self.killer.drop_connection(ip_addr)
                            dest.close()
                            return
                            
                        # Phase 5: Check Anomalous Time
                        is_anomalous = await self.check_anomalous_time(query)
                        if is_anomalous:
                             logger.warning(f"⚠️ SUSPICIOUS TIME DETECTED (3-5 AM) FOR SELECT * FROM {ip_addr}")
                        
                        # Dual-Brain: Reflex AI check
                        verdict = await self.reflex.analyze_sql(
                            query=query, 
                            source_ip=ip_addr, 
                            timestamp=datetime.now().isoformat()
                        )
                        
                        risk_level = verdict.get('risk_level', 'LOW')
                        if is_anomalous and risk_level == 'LOW':
                              risk_level = 'HIGH' # Upgrade risk level due to anomalous timing logic
                              verdict['risk_level'] = risk_level
                              verdict['reasoning'] = "Upgraded to HIGH due to anomalous operations block list."
                              
                        logger.info(f"[*] Reflex Brain Risk: {risk_level} | Threat: {verdict.get('threat_type')}")
                        
                        query_info = {
                             'query': query,
                             'source_ip': ip_addr,
                             'verdict': verdict
                        }
                        
                        if risk_level in ["CRITICAL", "HIGH"]:
                            if risk_level == "CRITICAL":
                                logger.critical(f"🛑 CRITICAL THREAT. BLOCKING: {query_info}")
                                self.blocked_ips.add(ip_addr)
                                await self.killer.drop_connection(ip_addr)
                                
                            # Always fire Forensic Analysis to review the event
                            asyncio.create_task(self.forensic.analyze_threat(query_info, client_addr))
                            
                            if risk_level == "CRITICAL":
                                dest.close()
                                return
                        else:
                            # Log safe queries too via Forensic Brain
                            asyncio.create_task(self.forensic.analyze_threat(query_info, client_addr))

                elif direction == "RESPONSE":
                    # Phase 5: Handle Data Volume Exfiltration Monitoring dynamically
                    is_exfil = await self.monitor_data_volume(ip_addr, len(data))
                    if is_exfil:
                         logger.critical(f"🛑 EXFILTRATION PATTERN DETECTED from {ip_addr}! Dropping Connection.")
                         self.blocked_ips.add(ip_addr)
                         await self.killer.drop_connection(ip_addr)
                         
                         query_info = {
                             'query': 'UNKNOWN_VOLUMETRIC_EXFILTRATION_ACTIVITY',
                             'source_ip': ip_addr,
                             'verdict': {
                                 'risk_level': 'CRITICAL', 
                                 'threat_type': 'EXFILTRATION', 
                                 'reasoning': 'Detected >100,000 rows extracted within a <5s window. Volumetric alert.'
                             }
                         }
                         # Forensic capture of Exfiltration
                         asyncio.create_task(self.forensic.analyze_threat(query_info, client_addr))
                         dest.close()
                         return

                # Proceed to forward data unhindered if checks pass
                dest.write(data)
                await dest.drain()
                
        except Exception as e:
            pass # Socket close/fail is normal, suppressed to avoid noise
            
    async def start(self):
        server = await asyncio.start_server(
            self.handle_client,
            self.listen_host,
            self.listen_port
        )
        logger.info(f"🛡️  SQL Data-Vault Interceptor Engine v2.0 listening on {self.listen_host}:{self.listen_port}")
        logger.info(f"   Forwarding traffic securely to backend db {self.backend_host}:{self.backend_port}")
        async with server:
            await server.serve_forever()

async def main():
    interceptor = SQLInterceptor()
    await interceptor.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Proxy stopped by user.")
