import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.network import NetworkEngine


def _flatten_x509_name(name_tuple: tuple) -> Dict[str, str]:
    if not name_tuple:
        return {}
    out: Dict[str, str] = {}
    for part in name_tuple:
        for key, value in part:
            out[key] = value
    return out


def _format_peer_cert(peer_cert: dict) -> Dict[str, Any]:
    """Turn ssl.getpeercert() dict into display-friendly fields."""
    if not peer_cert:
        return {
            "subject_cn": "—",
            "issuer_cn": "—",
            "not_before": "—",
            "not_after": "—",
            "san_preview": "—",
            "days_remaining": None,
        }

    sub = _flatten_x509_name(peer_cert.get("subject") or ())
    iss = _flatten_x509_name(peer_cert.get("issuer") or ())
    subject_cn = sub.get("commonName") or sub.get("organizationName") or "—"
    issuer_cn = iss.get("commonName") or iss.get("organizationName") or "—"

    nb = peer_cert.get("notBefore")
    na = peer_cert.get("notAfter")
    days_remaining = None
    if na:
        try:
            # e.g. 'Mar 28 12:00:00 2026 GMT'
            exp = datetime.strptime(na, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            days_remaining = (exp - datetime.now(timezone.utc)).days
        except (ValueError, TypeError):
            pass

    san_parts: List[str] = []
    for typ, val in peer_cert.get("subjectAltName") or ():
        if typ == "DNS":
            san_parts.append(val)
    san_preview = ", ".join(san_parts[:4])
    if len(san_parts) > 4:
        san_preview += f" (+{len(san_parts) - 4})"

    return {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "not_before": nb or "—",
        "not_after": na or "—",
        "san_preview": san_preview or "—",
        "days_remaining": days_remaining,
    }


class HostAnalyzer:
    """TLS + HTTP(S) + WebSocket hints for tunnel / SNI assessment (parallel probes)."""

    def __init__(self, timeout: int = 8):
        self.network = NetworkEngine(timeout=timeout)

    async def _websocket_probe(self, host: str, port: int) -> str:
        to = self.network.timeout
        try:
            reader, writer = await self.network.get_tls_socket(host, port, host)
            if not writer:
                return "—"
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            writer.write(req.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(2048), timeout=to)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            resp_str = resp.decode(errors="replace").lower()
            if "101 switching protocols" in resp_str:
                return "101 Switching Protocols"
            if "400 bad request" in resp_str and "cloudflare" in resp_str:
                return "Cloudflare edge (WS gated)"
            if "426" in resp_str or "upgrade required" in resp_str:
                return "426 Upgrade Required"
            return "No WS upgrade"
        except asyncio.TimeoutError:
            return "WebSocket read timeout"
        except Exception:
            return "—"

    async def analyze(self, host: str, port: int = 443) -> dict:
        analysis: Dict[str, Any] = {
            "host": host,
            "port": port,
            "modes": [],
            "server": "Unknown",
            "cdn": False,
            "http_status": "—",
            "tls_version": "—",
            "cipher": "—",
            "websocket": "—",
            "certificate": _format_peer_cert({}),
            "ok": False,
        }

        sni_task = asyncio.create_task(self.network.probe_sni(host, port))
        ws_task = asyncio.create_task(self._websocket_probe(host, port))
        sni_res, ws_label = await asyncio.gather(sni_task, ws_task)
        analysis["websocket"] = ws_label

        if sni_res.get("status") != "WORKING":
            analysis["error"] = sni_res.get("reason", "Probe failed")
            analysis["tls_version"] = sni_res.get("tls") or "—"
            analysis["cipher"] = sni_res.get("cipher") or "—"
            pc = sni_res.get("peer_cert") or {}
            if pc:
                analysis["certificate"] = _format_peer_cert(pc)
            return analysis

        analysis["ok"] = True
        analysis["http_status"] = str(sni_res.get("code", "—"))
        analysis["server_header"] = sni_res.get("server_header", "")
        analysis["tls_version"] = sni_res.get("tls") or "—"
        analysis["cipher"] = sni_res.get("cipher") or "—"
        analysis["certificate"] = _format_peer_cert(sni_res.get("peer_cert") or {})

        hdr = (analysis.get("server_header") or "").lower()
        if "cloudflare" in hdr:
            analysis["cdn"] = True
            analysis["server"] = "Cloudflare"
        elif "nginx" in hdr:
            analysis["server"] = "nginx"
        elif "apache" in hdr or "httpd" in hdr:
            analysis["server"] = "Apache"

        if ws_label.startswith("101"):
            analysis["modes"].append("WebSocket (101)")
        elif "cloudflare" in ws_label.lower():
            analysis["modes"].append("WS (Cloudflare edge)")
            analysis["cdn"] = True

        analysis["modes"].append("TLS + SNI")
        if analysis["http_status"] not in ("—", "", "000"):
            try:
                code = int(analysis["http_status"])
                if 200 <= code < 400:
                    analysis["modes"].append("HTTP OK class")
                elif 300 <= code < 400:
                    analysis["modes"].append("Redirect")
            except ValueError:
                pass

        return analysis

    @staticmethod
    def parse_target(raw: str, default_port: int = 443) -> Tuple[str, int]:
        s = raw.strip().replace("https://", "").replace("http://", "").strip("/")
        if s.count(":") == 1:
            h, p = s.split(":", 1)
            if p.isdigit():
                return h, int(p)
        return s, default_port
