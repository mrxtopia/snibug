import aiohttp
import socket
from typing import Dict, List, Optional

class CDNDetector:
    def __init__(self):
        # Common CDN header fingerprints
        self.cdn_headers = {
            "cloudflare": ["cf-ray", "cf-cache-status", "__cfduid"],
            "akamai": ["x-akamai-transformed", "x-akamai-request-id"],
            "fastly": ["x-fastly-request-id", "fastly-reassign"],
            "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
            "imperva": ["x-iinfo", "incap_ses", "visid_incap"],
            "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
            "gcore": ["x-gcore-request-id"],
            "bunny": ["x-bunny-cache", "x-bunny-request-id"]
        }
        
        # Common CDN server header values
        self.cdn_servers = {
            "cloudflare": "cloudflare",
            "akamai": "akamai",
            "google": "gse",
            "amazon": "amazon"
        }

    async def detect(self, host: str) -> Dict:
        """Detect CDN usage through header analysis and DNS."""
        result = {
            "cdn_found": False,
            "provider": "Unknown / None",
            "evidence": [],
            "ip_address": "N/A"
        }

        try:
            # 1. Check DNS for IP
            ip_addr = socket.gethostbyname(host)
            result["ip_address"] = ip_addr
            
            # 2. Check HTTP headers
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{host}", timeout=10, allow_redirects=True) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    server = headers.get("server", "").lower()

                    # Check headers
                    for cdn, fingerprints in self.cdn_headers.items():
                        for fp in fingerprints:
                            if fp in headers:
                                result["cdn_found"] = True
                                result["provider"] = cdn.capitalize()
                                result["evidence"].append(f"Header: {fp}")
                                break
                    
                    # Check server header
                    if not result["cdn_found"]:
                        for cdn, alias in self.cdn_servers.items():
                            if alias in server:
                                result["cdn_found"] = True
                                result["provider"] = cdn.capitalize()
                                result["evidence"].append(f"Server header: {server}")
                                break
                                
        except Exception as e:
            result["evidence"].append(f"Error during detection: {str(e)}")

        return result
