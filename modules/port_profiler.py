import asyncio
from core.network import NetworkEngine
from typing import List, Dict

class PortProfiler:
    def __init__(self, ports: List[int] = [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 8880]):
        self.ports = ports
        self.network = NetworkEngine(timeout=3)

    async def scan_host_ports(self, host: str) -> Dict[int, bool]:
        results = {}
        for port in self.ports:
            is_open = await self.network.check_port(host, port)
            results[port] = is_open
        return results
    
    async def scan_ports(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Scan specific ports on a host and return status."""
        results = {}
        for port in ports:
            try:
                is_open = await self.network.check_port(host, port)
                results[port] = 'open' if is_open else 'closed'
            except Exception as e:
                results[port] = 'error'
        return results

