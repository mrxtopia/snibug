import asyncio
import ssl
import socket
from typing import Tuple, Optional, Union

class NetworkEngine:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    async def check_port(self, host: str, port: int) -> bool:
        """Checks if a TCP port is open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    async def get_tls_socket(self, host: str, port: int = 443, sni: str = None) -> Tuple[Optional[asyncio.StreamReader], Optional[asyncio.StreamWriter]]:
        """Establishes a TLS connection with custom SNI."""
        if sni is None:
            sni = host
            
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # We want to scan even broken certs often
        
        try:
            # We use open_connection with ssl argument to wrap socket
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=sni),
                timeout=self.timeout
            )
            return reader, writer
        except Exception:
            return None, None

    async def probe_sni(
        self,
        host: str,
        port: int = 443,
        sni: str = None,
        method: str = "HEAD",
        path: str = "/",
        include_peer_cert: bool = True,
    ) -> dict:
        """
        Probes an SNI to see if it responds with a valid HTTP response.
        Returns a dict with status, code, tls_version, etc.
        """
        if sni is None:
            sni = host
            
        reader, writer = await self.get_tls_socket(host, port, sni)
        
        if not writer:
            return {"status": "FAILED", "reason": "Connection/Handshake Timeout"}

        try:
            # Get TLS version from socket
            # writer.get_extra_info('ssl_object') returns the SSLObject
            ssl_obj = writer.get_extra_info("ssl_object")
            tls_version = ssl_obj.version() if ssl_obj else "Unknown"
            cipher = ssl_obj.cipher() if ssl_obj else ("Unknown", 0, 0)
            peer_cert = {}
            if include_peer_cert and ssl_obj:
                try:
                    peer_cert = ssl_obj.getpeercert() or {}
                except Exception:
                    peer_cert = {}

            # Send HTTP Request
            request = f"{method} {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # Read Response (First line is enough for status)
            line = await asyncio.wait_for(reader.readline(), timeout=self.timeout)
            line = line.decode().strip()
            
            writer.close()
            await writer.wait_closed()
            
            if not line:
                return {
                    "status": "FAILED",
                    "reason": "Empty Response",
                    "tls": tls_version,
                    "peer_cert": peer_cert,
                    "cipher": cipher[0] if cipher else "Unknown",
                }
            
            if line.startswith("HTTP/"):
                parts = line.split(" ")
                code_raw = parts[1] if len(parts) > 1 else "000"
                try:
                    status_num = int(code_raw)
                except ValueError:
                    status_num = 0
                return {
                    "status": "WORKING",
                    "code": code_raw,
                    "status_code": status_num,
                    "tls": tls_version,
                    "cipher": cipher[0],
                    "server_header": line,
                    "peer_cert": peer_cert,
                }
            else:
                return {
                    "status": "WEIRD",
                    "reason": "Non-HTTP Response",
                    "response_sample": line[:50],
                    "tls": tls_version,
                    "peer_cert": peer_cert,
                    "cipher": cipher[0] if cipher else "Unknown",
                }

        except asyncio.TimeoutError:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"status": "FAILED", "reason": "Read Timeout"}
        except Exception as e:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"status": "ERROR", "reason": str(e)}
