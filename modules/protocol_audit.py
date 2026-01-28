import ssl
import socket
import httpx
import asyncio
from typing import Dict, Any, List

class ProtocolAudit:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def audit(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Perform protocol audit (Cert, HTTP/2, HTTP/3)."""
        result = {
            "host": host,
            "port": port,
            "ssl_info": {},
            "protocols": [],
            "error": None
        }

        try:
            # 1. SSL/TLS Certificate Check
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result["ssl_info"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert.get('version'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter'),
                    }

            # 2. HTTP/2 & HTTP/3 Detection
            async with httpx.AsyncClient(http2=True, timeout=self.timeout, verify=False) as client:
                # Try HTTP/2
                resp = await client.get(f"https://{host}:{port}/")
                result["protocols"].append(resp.http_version)
                
                # Note: HTTP/3 (QUIC) detection is more complex in Python-land without specific libs
                # but we'll mark presence of Alt-Svc header as indicator
                alt_svc = resp.headers.get("alt-svc", "")
                if "h3" in alt_svc:
                    result["protocols"].append("HTTP/3 (Advertised)")

        except Exception as e:
            result["error"] = str(e)

        return result
