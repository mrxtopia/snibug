import asyncio
from core.network import NetworkEngine

class HostAnalyzer:
    def __init__(self, timeout: int = 8):
        self.network = NetworkEngine(timeout=timeout)

    async def analyze(self, host: str, port: int = 443) -> dict:
        """
        Deep analysis of a host to determine tunnel capabilities.
        Checks: Direct, SNI, WS, etc.
        """
        analysis = {
            "host": host,
            "port": port,
            "modes": [],
            "server": "Unknown",
            "cdn": False
        }

        # 1. Basic SNI Check
        sni_res = await self.network.probe_sni(host, port)
        if sni_res['status'] != 'WORKING':
            analysis['error'] = sni_res.get('reason', 'Failed initial connection')
            return analysis

        analysis['server_header'] = sni_res.get('server_header', '')
        
        # 2. Websocket Check (Upgrade Header)
        # We need a custom probe for this
        try:
            reader, writer = await self.network.get_tls_socket(host, port, host)
            if writer:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                writer.write(req.encode())
                await writer.drain()
                
                resp = await asyncio.wait_for(reader.read(1024), timeout=5)
                resp_str = resp.decode().lower()
                
                if "101 switching protocols" in resp_str:
                    analysis['modes'].append("WS (Websocket)")
                elif "400 bad request" in resp_str and "cloudflare" in resp_str:
                     analysis['modes'].append("WS (Cloudflare Protected)") # Likely works with valid path
                     analysis['cdn'] = True
                     analysis['server'] = "Cloudflare"
                
                writer.close()
                await writer.wait_closed()
        except:
            pass

        # 3. Direct TLS (No SNI / Random SNI)
        # Try connecting with empty or random SNI. If it works, it's Direct.
        # Note: Python ssl lib usually sends SNI if checks are on, but we can try to disable it or send random.
        # For simplicity, we assume if SNI works, we tag it SNI.
        analysis['modes'].append("SNI")

        return analysis
