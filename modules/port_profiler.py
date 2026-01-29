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
    
    async def detect_services(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Attempt to grab banners from open ports."""
        results = {}
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2
                )
                # Send a generic request for common services
                if port == 80:
                    writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                elif port == 443:
                    # For 443 we'd need SSL wrapping, but let's just mark it HTTPS for now
                    results[port] = "HTTPS"
                    writer.close(); await writer.wait_closed(); continue
                
                banner = await asyncio.wait_for(reader.read(100), timeout=2)
                results[port] = banner.decode(errors='ignore').strip().split('\n')[0][:30]
                writer.close()
                await writer.wait_closed()
            except:
                results[port] = "Unknown"
        return results
    async def scan_ports(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Scan specific ports on a host and return status."""
        results = {}
        for port in ports:
            try:
                is_open = await self.network.check_port(host, port)
                results[port] = 'open' if is_open else 'closed'
            except Exception:
                results[port] = 'error'
        return results
