import asyncio
from core.network import NetworkEngine
from typing import List, AsyncGenerator

class SNIScanner:
    def __init__(self, threads: int = 10, timeout: int = 5, exclude_redirects: bool = False):
        self.sem = asyncio.Semaphore(threads)
        self.network = NetworkEngine(timeout=timeout)
        self.exclude_redirects = exclude_redirects

    async def scan_host(self, host: str, port: int = 443) -> dict:
        """Scans a single host for SNI bug capabilities."""
        async with self.sem:
            # First clean the host input
            host = host.replace("https://", "").replace("http://", "").strip("/")
            if ":" in host:
                host, port_str = host.split(":")
                port = int(port_str)
                
            result = await self.network.probe_sni(host, port)
            result['host'] = host
            result['port'] = port
            
            # Simple heuristic for "CDN" based on common behaviors (to be expanded)
            # This is where we would check headers, but currently probe_sni just gets the status line
            # We can expand probe_sni later if needed, or do a deeper analysis in HostAnalyzer
            
            return result

    async def scan_list(self, hosts: List[str]) -> AsyncGenerator[dict, None]:
        """Scans a list of hosts concurrently yielding results as they finish."""
        tasks = [self.scan_host(h) for h in hosts]
        for task in asyncio.as_completed(tasks):
            yield await task
