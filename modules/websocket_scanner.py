import asyncio
import websockets
import time
from typing import Dict

class WebSocketScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def scan(self, host: str, port: int = 80, path: str = "/") -> Dict:
        """Test if a host supports WebSocket upgrades."""
        protocol = "wss" if port == 443 or port == 8443 else "ws"
        url = f"{protocol}://{host}:{port}{path}"
        
        start_time = time.time()
        try:
            # We try to connect and immediately close if successful
            async with websockets.connect(url, open_timeout=self.timeout, close_timeout=1) as websocket:
                latency = (time.time() - start_time) * 1000
                return {
                    "url": url,
                    "status": "OPEN",
                    "latency": f"{latency:.2f}ms",
                    "working": True,
                    "details": "Connection established and upgraded successfully"
                }
        except websockets.exceptions.InvalidStatusCode as e:
            return {
                "url": url,
                "status": f"FAILED ({e.status_code})",
                "latency": "N/A",
                "working": False,
                "details": f"Server rejected WebSocket upgrade"
            }
        except Exception as e:
            return {
                "url": url,
                "status": "ERROR",
                "latency": "N/A",
                "working": False,
                "details": str(e)
            }
