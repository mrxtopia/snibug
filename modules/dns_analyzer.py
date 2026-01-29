import asyncio
import dns.asyncresolver
from typing import Dict, List

class DNSAnalyzer:
    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver(configure=False)
        self.resolver.nameservers = ['1.1.1.1', '8.8.8.8']
        self.record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

    async def get_records(self, domain: str) -> Dict[str, List[str]]:
        results = {}
        for rtype in self.record_types:
            try:
                answers = await self.resolver.resolve(domain, rtype)
                results[rtype] = [str(r) for r in answers]
            except:
                results[rtype] = []
        return results

    async def comprehensive_audit(self, domain: str) -> Dict:
        records = await self.get_records(domain)
        return {
            "domain": domain,
            "records": records,
            "summary": f"Found {sum(len(v) for v in records.values())} records across {len(records)} types."
        }
