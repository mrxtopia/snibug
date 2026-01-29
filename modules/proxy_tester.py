import asyncio
import socket
import aiohttp
from typing import List, Dict

class ProxyTester:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def test_http_connect(self, host: str, port: int) -> Dict:
        """Tests if the host supports HTTP CONNECT method (Proxy)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            # Simple CONNECT request
            request = f"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com:443\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            
            resp_str = response.decode(errors='ignore')
            if "200 connection established" in resp_str.lower():
                return {"status": "WORKING", "type": "HTTP CONNECT", "details": "Success"}
            elif "403" in resp_str:
                 return {"status": "RESTRICTED", "type": "HTTP CONNECT", "details": "Forbidden (Auth required?)"}
            else:
                return {"status": "FAILED", "type": "HTTP CONNECT", "details": resp_str.split('\r\n')[0]}
        except Exception as e:
            return {"status": "ERROR", "type": "HTTP CONNECT", "details": str(e)}

    async def run_suite(self, host: str, ports: List[int] = None) -> List[Dict]:
        if not ports:
            ports = [80, 8080, 8888, 3128]
        
        results = []
        for port in ports:
            res = await self.test_http_connect(host, port)
            res['host'] = host
            res['port'] = port
            results.append(res)
        return results
