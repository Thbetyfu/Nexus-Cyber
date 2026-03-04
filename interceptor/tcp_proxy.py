import asyncio
import logging
import json
from datetime import datetime
import sys
import os

# Allow imports from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sentinel_brain.reflex_brain import evaluate_sql
from sentinel_brain.forensic_brain import forensic_analysis_task
from executioner.connection_killer import drop_connection
from interceptor.sql_parser import SQLParser
import threading

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
        self.parser = SQLParser()
        
    async def handle_client(self, client_reader, client_writer):
        """Handle incoming client connection (potential hacker)."""
        client_addr = client_writer.get_extra_info('peername')
        logger.info(f"[+] New connection from {client_addr}")
        
        try:
            # Connect to backend database
            backend_reader, backend_writer = await asyncio.open_connection(
                self.backend_host, self.backend_port
            )
            
            # Proxy traffic in both directions with inspection
            await asyncio.gather(
                self.forward_and_inspect(client_reader, backend_writer, client_addr, "C2S"),
                self.forward_and_inspect(backend_reader, client_writer, client_addr, "S2C")
            )
            
        except Exception as e:
            logger.error(f"[ERROR] {client_addr}: {e}")
        finally:
            client_writer.close()
            await client_writer.wait_closed()
            
    async def forward_and_inspect(self, source, dest, client_addr, direction):
        """Forward data while inspecting SQL queries."""
        try:
            while True:
                data = await source.read(4096)
                if not data:
                    break
                    
                if direction == "C2S":
                    query = self.parser.extract_query(data)
                    if query:
                        logger.info(f"[SQL] Client {client_addr}: {query}")
                        # Send query to Reflex Brain asynchronously to not block event loop
                        decision = await asyncio.to_thread(evaluate_sql, query)
                        logger.info(f"[*] Reflex Brain Decision: {decision}")
                        
                        ip_addr = client_addr[0] if isinstance(client_addr, tuple) else "127.0.0.1"
                        
                        if decision == "BLOCK":
                            logger.warning(f"[!!!] DROPPING MALICIOUS CONNECTION: {client_addr}")
                            # Execute hardware ban
                            drop_connection(ip_addr)
                            
                            # Launch Forensic analysis on background thread
                            threading.Thread(target=forensic_analysis_task, args=(query, ip_addr, True)).start()
                            
                            # Break loop to stop forwarding and drop the connection
                            dest.close()
                            return
                        else:
                            threading.Thread(target=forensic_analysis_task, args=(query, ip_addr, False)).start()

                # Forward to destination
                dest.write(data)
                await dest.drain()
                
        except Exception as e:
            pass # Socket easily drops, silence to avoid log spam
            
    async def start(self):
        """Start listening for connections."""
        server = await asyncio.start_server(
            self.handle_client,
            self.listen_host,
            self.listen_port
        )
        
        logger.info(f"🛡️  SQL Interceptor listening on {self.listen_host}:{self.listen_port}")
        logger.info(f"   Forwarding to {self.backend_host}:{self.backend_port}")
        
        async with server:
            await server.serve_forever()

async def main():
    interceptor = SQLInterceptor()
    await interceptor.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Proxy stopped.")
