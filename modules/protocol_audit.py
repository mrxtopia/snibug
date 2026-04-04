import asyncio
import functools
import ssl
import socket
from typing import Any, Dict, List

import httpx


def _flatten_cert_name(name_tuple: tuple) -> Dict[str, str]:
    if not name_tuple:
        return {}
    out: Dict[str, str] = {}
    for part in name_tuple:
        for k, v in part:
            out[k] = v
    return out


def _sync_fetch_cert(host: str, port: int, timeout: float) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw: Dict[str, Any] = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"error": "No certificate presented"}
                raw = {
                    "subject": _flatten_cert_name(cert.get("subject") or ()),
                    "issuer": _flatten_cert_name(cert.get("issuer") or ()),
                    "version": cert.get("version"),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                }
    except Exception as e:
        return {"error": str(e)}
    return raw


class ProtocolAudit:
    def __init__(self, timeout: int = 10):
        self.timeout = float(timeout)

    async def audit(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Certificate summary + HTTP version (HTTP/2 if offered) + Alt-Svc hints."""
        result: Dict[str, Any] = {
            "host": host,
            "port": port,
            "ssl_info": {},
            "protocols": [],
            "error": None,
        }

        loop = asyncio.get_running_loop()
        cert_task = loop.run_in_executor(
            None, functools.partial(_sync_fetch_cert, host, port, self.timeout)
        )

        async def http_probe():
            url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
            try:
                async with httpx.AsyncClient(
                    http2=True,
                    timeout=self.timeout,
                    verify=False,
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(url)
                    protos: List[str] = []
                    ver = getattr(resp, "http_version", None) or "HTTP/1.1"
                    if ver:
                        protos.append(ver if str(ver).upper().startswith("HTTP") else f"HTTP/{ver}")
                    alt = (resp.headers.get("alt-svc") or "").lower()
                    if "h3" in alt or "quic" in alt:
                        protos.append("HTTP/3 (Alt-Svc)")
                    return protos, None
            except Exception as e:
                return [], str(e)

        cert_raw, (http_protos, http_err) = await asyncio.gather(
            cert_task, http_probe()
        )

        if isinstance(cert_raw, dict) and cert_raw.get("error"):
            result["error"] = cert_raw["error"]
            if http_err:
                result["error"] = f"{result['error']}; HTTP: {http_err}"
        else:
            result["ssl_info"] = cert_raw if isinstance(cert_raw, dict) else {}

        if http_err and not result.get("ssl_info", {}).get("subject"):
            if not result.get("error"):
                result["error"] = http_err

        seen = set()
        for p in http_protos:
            if p and p not in seen:
                seen.add(p)
                result["protocols"].append(p)

        return result
