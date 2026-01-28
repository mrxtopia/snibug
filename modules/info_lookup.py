import socket
import whois
import asyncio
from typing import Dict, Any

class InfoLookup:
    def __init__(self):
        pass

    async def lookup_ip_info(self, host: str) -> Dict[str, Any]:
        """Get GeoIP (via public API) and Whois information."""
        result = {
            "host": host,
            "ip": "N/A",
            "geoip": {},
            "whois": {},
            "error": None
        }

        try:
            # Resolve IP
            loop = asyncio.get_event_loop()
            ip_addr = await loop.run_in_executor(None, socket.gethostbyname, host)
            result["ip"] = ip_addr

            # GeoIP via ip-api.com (free, no key for low volume)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://ip-api.com/json/{ip_addr}") as response:
                    if response.status == 200:
                        result["geoip"] = await response.json()

            # WHOIS
            try:
                # whois.whois is blocking, run in executor
                w = await loop.run_in_executor(None, whois.whois, host)
                result["whois"] = {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date),
                    "expiration_date": str(w.expiration_date),
                    "name_servers": w.name_servers,
                    "org": w.org
                }
            except Exception as e:
                result["whois_error"] = str(e)

        except Exception as e:
            result["error"] = str(e)

        return result
