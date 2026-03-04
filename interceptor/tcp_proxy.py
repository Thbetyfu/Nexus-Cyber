import asyncio
import yaml
import logging
import sys
import os

# Allow imports from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sql_parser import SQLParser
from sentinel_brain.reflex_brain import evaluate_sql
from sentinel_brain.forensic_brain import forensic_analysis_task
from executioner.connection_killer import drop_connection
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ProxyInterceptor")

class TCPProxy:
    def __init__(self, listen_host, listen_port, target_host, target_port):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
    
    async def handle_client(self, client_reader, client_writer):
        client_addr = client_writer.get_extra_info('peername')
        logger.info(f"[+] New connection from {client_addr}")
        
        try:
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )
        except Exception as e:
            logger.error(f"[-] Cannot connect to database backend: {e}")
            client_writer.close()
            return

        async def forward(source_reader, destination_writer, direction="C2S"):
            while True:
                try:
                    data = await source_reader.read(4096)
                    if not data:
                        break
                        
                    # If Client to Server, attempt to parse SQL
                    if direction == "C2S":
                        query = SQLParser.extract_query(data)
                        if query:
                            logger.info(f"[SQL] Client {client_addr}: {query}")
                            # Send query to Reflex Brain asynchronously to not block event loop
                            decision = await asyncio.to_thread(evaluate_sql, query)
                            logger.info(f"[*] Reflex Brain Decision: {decision}")
                            
                            if decision == "BLOCK":
                                logger.warning(f"[!!!] DROPPING MALICIOUS CONNECTION: {client_addr}")
                                ip_addr = client_addr[0] if isinstance(client_addr, tuple) else "127.0.0.1"
                                # Execute hardware ban
                                drop_connection(ip_addr)
                                
                                # Launch Forensic analysis on background thread
                                threading.Thread(target=forensic_analysis_task, args=(query, ip_addr, True)).start()
                                
                                # Break loop to stop forwarding and drop the connection
                                break
                            else:
                                ip_addr = client_addr[0] if isinstance(client_addr, tuple) else "127.0.0.1"
                                threading.Thread(target=forensic_analysis_task, args=(query, ip_addr, False)).start()
                            
                    destination_writer.write(data)
                    await destination_writer.drain()
                except Exception as e:
                    logger.debug(f"Connection ended ({direction}): {e}")
                    break
            
            destination_writer.close()

        # Run two tasks: Client->Server and Server->Client
        asyncio.create_task(forward(client_reader, target_writer, "C2S"))
        asyncio.create_task(forward(target_reader, client_writer, "S2C"))

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port
        )
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"Serving on {addrs} forwarding to {self.target_host}:{self.target_port}")

        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    # Default Config Fallbacks
    config = {
        'proxy': {'listen_host': '0.0.0.0', 'listen_port': 3306, 'target_host': '127.0.0.1', 'target_port': 3307}
    }
    try:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.warning(f"Failed to load config.yaml, using defaults: {e}")

    P = config.get('proxy', {})
    
    proxy = TCPProxy(
        listen_host=P.get('listen_host', '0.0.0.0'),
        listen_port=P.get('listen_port', 3306),
        target_host=P.get('target_host', '127.0.0.1'),
        target_port=P.get('target_port', 3307)
    )
    
    try:
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        logger.info("Proxy shutting down.")
