import asyncio
import time
from typing import Dict, List

class PingScanner:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    @staticmethod
    def parse_host_port(raw: str, default_port: int = 443) -> tuple:
        s = raw.strip().replace("https://", "").replace("http://", "").strip("/")
        if s.count(":") == 1:
            h, p = s.split(":", 1)
            if p.isdigit():
                return h, int(p)
        return s, default_port

    async def ping(self, host: str, port: int = 443) -> Dict:
        """Performs a TCP 'ping' by trying to open a connection."""
        start_time = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            latency = (time.time() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
            return {
                "host": host,
                "port": port,
                "status": "ONLINE",
                "latency": f"{latency:.2f}ms"
            }
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "status": "OFFLINE",
                "latency": "N/A",
                "error": str(e)
            }

    async def scan_list(self, hosts: List[str], default_port: int = 443) -> List[Dict]:
        tasks = []
        for h in hosts:
            host, p = self.parse_host_port(h, default_port)
            tasks.append(self.ping(host, p))
        return await asyncio.gather(*tasks)
