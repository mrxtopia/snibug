import asyncio
from core.network import NetworkEngine
from typing import List, Dict

class PortProfiler:
    def __init__(self, ports: List[int] = [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 8880]):
        self.ports = ports
        self.network = NetworkEngine(timeout=3)

    async def scan_host_ports(self, host: str) -> Dict[int, bool]:
        pairs = await asyncio.gather(
            *[self.network.check_port(host, p) for p in self.ports]
        )
        return dict(zip(self.ports, pairs))
    
    async def _grab_banner(self, host: str, port: int) -> tuple:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=2,
            )
            if port == 80:
                writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 443:
                writer.close()
                await writer.wait_closed()
                return port, "HTTPS"
            banner = await asyncio.wait_for(reader.read(100), timeout=2)
            text = banner.decode(errors="ignore").strip().split("\n")[0][:30]
            writer.close()
            await writer.wait_closed()
            return port, text
        except Exception:
            return port, "Unknown"

    async def detect_services(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Attempt to grab banners from open ports (parallel)."""
        pairs = await asyncio.gather(*[self._grab_banner(host, p) for p in ports])
        return dict(pairs)
    async def scan_ports(self, host: str, ports: List[int]) -> Dict[int, str]:
        """Scan specific ports on a host and return status (parallel)."""
        async def one(p: int) -> tuple:
            try:
                ok = await self.network.check_port(host, p)
                return p, "open" if ok else "closed"
            except Exception:
                return p, "error"

        pairs = await asyncio.gather(*[one(p) for p in ports])
        return dict(pairs)
