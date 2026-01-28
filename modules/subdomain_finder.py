import asyncio
import dns.asyncresolver # requires dnspython
from typing import List, AsyncGenerator

class SubdomainFinder:
    def __init__(self, target_domain: str, wordlist: List[str] = None):
        self.target = target_domain
        self.wordlist = wordlist or ["www", "api", "cdn", "blog", "shop", "admin", "mail", "vpn", "ns1", "test"]
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8']

    async def check_subdomain(self, sub: str) -> dict:
        full_domain = f"{sub}.{self.target}"
        try:
            answers = await self.resolver.resolve(full_domain, 'A')
            return {"domain": full_domain, "ip": answers[0].to_text(), "status": "FOUND"}
        except:
            return None

    async def run(self) -> AsyncGenerator[dict, None]:
        tasks = [self.check_subdomain(sub) for sub in self.wordlist]
        for task in asyncio.as_completed(tasks):
            res = await task
            if res:
                yield res
