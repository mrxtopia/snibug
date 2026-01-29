import asyncio
import dns.asyncresolver
import aiohttp
import re
from typing import List, AsyncGenerator, Set

class SubdomainFinder:
    def __init__(self, wordlist: List[str] = None):
        self.wordlist = wordlist or ["www", "api", "cdn", "blog", "shop", "admin", "mail", "vpn", "ns1", "test"]
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8']

    async def _fetch_crtsh(self, domain: str) -> Set[str]:
        """Fetch subdomains from crt.sh"""
        subdomains = set()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            name = entry.get('name_value', '').lower()
                            # Names can be multiple separated by \n or contain wildcards
                            for n in name.split('\n'):
                                if n.endswith(domain) and '*' not in n:
                                    subdomains.add(n)
        except Exception:
            pass
        return subdomains

    async def _fetch_hackertarget(self, domain: str) -> Set[str]:
        """Fetch subdomains from HackerTarget"""
        subdomains = set()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.split('\n'):
                            if ',' in line:
                                subdomains.add(line.split(',')[0].lower())
        except Exception:
            pass
        return subdomains

    async def find_subdomains(self, domain: str) -> List[str]:
        """Entry point for main.py - performs passive discovery"""
        self.target = domain
        
        # 1. Passive Discovery
        passive_tasks = [
            self._fetch_crtsh(domain),
            self._fetch_hackertarget(domain)
        ]
        passive_results = await asyncio.gather(*passive_tasks)
        
        all_subs = set()
        for res in passive_results:
            all_subs.update(res)
            
        # 2. Add Brute-force small wordlist just in case
        async for res in self.run():
            all_subs.add(res['domain'])
            
        return sorted(list(all_subs))

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
