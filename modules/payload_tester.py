import asyncio
import aiohttp
import time
from typing import List, Dict, Optional
from rich.console import Console

console = Console()

class PayloadTester:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.payloads = [
            # 1. Direct connection (Standard)
            {"name": "Standard GET", "method": "GET", "headers": {}},
            {"name": "Standard HEAD", "method": "HEAD", "headers": {}},
            
            # 2. Host Header Tricks
            {"name": "Empty Host", "method": "GET", "headers": {"Host": ""}},
            {"name": "Space before Host", "method": "GET", "headers": {" Host": "{host}"}},
            {"name": "Duplicate Host", "method": "GET", "headers": {"Host": ["{host}", "{host}"]}},
            
            # 3. Connection/Keep-Alive tricks
            {"name": "Keep-Alive Trick", "method": "GET", "headers": {"Connection": "keep-alive", "Proxy-Connection": "keep-alive"}},
            {"name": "Close Connection", "method": "GET", "headers": {"Connection": "close"}},
            
            # 4. Forwarded-For/IP Spoofing mimics
            {"name": "X-Forwarded-For", "method": "GET", "headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"name": "X-Real-IP", "method": "GET", "headers": {"X-Real-IP": "127.0.0.1"}},
            
            # 5. User-Agent variations
            {"name": "Mobile UA", "method": "GET", "headers": {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"}},
            {"name": "Chrome Linux UA", "method": "GET", "headers": {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36"}},
            
            # 6. Encoding tricks
            {"name": "Gzip/Deflate", "method": "GET", "headers": {"Accept-Encoding": "gzip, deflate"}},
            
            # 7. Common Tunnel Headers
            {"name": "Upgrade: websocket", "method": "GET", "headers": {"Upgrade": "websocket", "Connection": "Upgrade"}},
            {"name": "X-Online-Host", "method": "GET", "headers": {"X-Online-Host": "{host}"}},
            {"name": "X-Forward-Host", "method": "GET", "headers": {"X-Forward-Host": "{host}"}},
            
            # 8. Method variations
            {"name": "OPTIONS Method", "method": "OPTIONS", "headers": {}},
            {"name": "PATCH Method", "method": "PATCH", "headers": {}},
            {"name": "TRACE Method", "method": "TRACE", "headers": {}},
            
            # 9. Cache Control
            {"name": "No-Cache", "method": "GET", "headers": {"Cache-Control": "no-cache", "Pragma": "no-cache"}},
            
            # 10. Referer tricks
            {"name": "Self Referer", "method": "GET", "headers": {"Referer": "http://{host}/"}},
            {"name": "Null Referer", "method": "GET", "headers": {"Referer": ""}},
            
            # 11. Content-Type Variations
            {"name": "JSON Content-Type", "method": "POST", "headers": {"Content-Type": "application/json"}, "data": "{}"},
            {"name": "Form Content-Type", "method": "POST", "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "data": "a=1"},
        ]

    async def test_payload(self, session: aiohttp.ClientSession, url: str, payload: Dict) -> Dict:
        name = payload["name"]
        method = payload["method"]
        headers = payload.get("headers", {}).copy()
        
        # Replace placeholders
        host = url.split("//")[-1].split("/")[0]
        for key, value in headers.items():
            if isinstance(value, str):
                headers[key] = value.replace("{host}", host)
            elif isinstance(value, list):
                headers[key] = [v.replace("{host}", host) for v in value]

        data = payload.get("data", None)
        if data and isinstance(data, str):
            data = data.replace("{host}", host)

        start_time = time.time()
        try:
            async with session.request(method, url, headers=headers, data=data, timeout=self.timeout, allow_redirects=False) as response:
                latency = (time.time() - start_time) * 1000
                return {
                    "name": name,
                    "status": response.status,
                    "latency": f"{latency:.2f}ms",
                    "working": response.status < 400,
                    "server": response.headers.get("Server", "Unknown"),
                    "length": response.content_length
                }
        except Exception as e:
            return {
                "name": name,
                "status": "ERROR",
                "latency": "N/A",
                "working": False,
                "error": str(e)
            }

    async def run_suite(self, host: str, port: int = 80) -> List[Dict]:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{host}:{port}/"
        
        results = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.test_payload(session, url, p) for p in self.payloads]
            results = await asyncio.gather(*tasks)
            
        return results
