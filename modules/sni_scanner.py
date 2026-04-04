import asyncio
from core.network import NetworkEngine
from typing import List, AsyncGenerator

class SNIScanner:
    def __init__(self, threads: int = 10, timeout: int = 5, exclude_redirects: bool = False, method: str = "HEAD"):
        self._threads = max(1, threads)
        self.sem = asyncio.Semaphore(self._threads)
        self.network = NetworkEngine(timeout=timeout)
        self.exclude_redirects = exclude_redirects
        self.method = method

    async def scan_host(self, host: str, port: int = 443, method: str = None) -> dict:
        """Scans a single host for SNI bug capabilities."""
        if method is None:
            method = self.method
            
        async with self.sem:
            # First clean the host input
            host = host.replace("https://", "").replace("http://", "").strip("/")
            if ":" in host:
                host, port_str = host.split(":")
                port = int(port_str)
                
            result = await self.network.probe_sni(
                host, port, method=method, include_peer_cert=False
            )
            result['host'] = host
            result['port'] = port
            
            return result

    async def scan_list(self, hosts: List[str]) -> AsyncGenerator[dict, None]:
        """Scan hosts with bounded concurrency; schedule in batches to limit Task count on huge lists."""
        batch = min(2048, max(64, self._threads * 8))
        for i in range(0, len(hosts), batch):
            chunk = hosts[i : i + batch]
            tasks = [asyncio.create_task(self.scan_host(h)) for h in chunk]
            for coro in asyncio.as_completed(tasks):
                yield await coro
