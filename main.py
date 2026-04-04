#!/usr/bin/env python3
import argparse
import asyncio
import os
import hashlib
import sys
from typing import List
import webbrowser
import subprocess

# --- SECURITY SYSTEM ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from version import VERSION  # noqa: E402

# Expected SHA-256 hashes of protected files (update when those files change).
EXPECTED_HASHES = {
    "version.py": "3dbccf9d1fbc92e0a41e164e9de076ef1e2815019ea0d51e101454745df9a79a",
    "ui/console.py": "9ca921d017984475dfcc9c094915032f133c7f6df90693ae91c78823e2083388",
    "core/network.py": "f026937f5f62c62cec8e38df17ce25a7c57a63980698c385bcca0c4870a3319e",
    "modules/sni_scanner.py": "1dceed0256911857984e017c055406833dd0e137ea6ea91d1a7252c382b7691d",
    "modules/payload_tester.py": "3b1d643b70e138b0e6957660e97189bdae8a3001f8bc9d4b85d14e8896330828",
    "modules/websocket_scanner.py": "25e1e34284b79420e0056f258c11511d8d6a7be0c73ad0534ace182bd768d910",
    "modules/cdn_detector.py": "c788c7337b4bdcb5568f0477b0481f1b5279d9e23de5e17d6ae7169e7c066659",
    "modules/info_lookup.py": "3e228a48eafba00791a305d74505a0c23f0092d6d218458e92d69a31acf0df6d",
    "modules/protocol_audit.py": "1a22538f826219e14d7afac237fc7ac844d49e141b6df237789cbb04d4fb9ded",
}

def verify_integrity():
    """Verify that the core files have not been tampered with."""
    github_link = "https://github.com/mrxtopia/snibug/"
    for file_path, expected_hash in EXPECTED_HASHES.items():
        abs_path = os.path.join(BASE_DIR, file_path)
        if not os.path.exists(abs_path):
            continue # Allow missing optional files but warn if you want
        
        with open(abs_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            if file_hash != expected_hash:
                print("\n\033[1;31m[!] SECURITY ALERT: TAMPER DETECTION\033[0m")
                print(f"\033[1;33m[!] Error: File '{file_path}' has been edited.\033[0m")
                print("\033[1;37m[!] edited please re install from gitclone " + github_link + "\033[0m\n")
                sys.exit(1)

# Run integrity check before anything else
verify_integrity()

def check_installation_lock():
    """Ensure install marker is valid, or allow a git source tree for development."""
    marker_path = os.path.join(BASE_DIR, ".setup_success")
    git_path = os.path.join(BASE_DIR, ".git")
    expected_token = "INSTALLED_BY_MRYT_INSTALLER_2026"

    lock_error = """
\033[1;31m[!] SECURITY LOCK: ILLEGAL INSTALLATION DETECTED\033[0m
\033[1;33m[!] Error: The tool must be installed via 'termux_setup.sh'.\033[0m
\033[1;37m[!] Copy the full project from GitHub or run the official installer.\033[0m
\033[1;32m[+] Run: bash termux_setup.sh to create .setup_success\033[0m
"""

    if os.path.isfile(marker_path):
        with open(marker_path, "r", encoding="utf-8") as f:
            if f.read().strip() == expected_token:
                return
        print(lock_error)
        sys.exit(1)

    if os.path.isdir(git_path):
        print(
            "\033[1;33m[!] Running from git clone (no .setup_success). "
            "Production installs: run bash termux_setup.sh\033[0m\n"
        )
        return

    print(lock_error)
    sys.exit(1)

# Check installation lock
check_installation_lock()

from ui.console import AppUI
from modules.sni_scanner import SNIScanner
from modules.host_analyzer import HostAnalyzer
from modules.subdomain_finder import SubdomainFinder
from modules.port_profiler import PortProfiler
from modules.payload_tester import PayloadTester
from modules.websocket_scanner import WebSocketScanner
from modules.cdn_detector import CDNDetector
from modules.info_lookup import InfoLookup
from modules.protocol_audit import ProtocolAudit
from modules.proxy_tester import ProxyTester
from modules.ping_scanner import PingScanner
from modules.dns_analyzer import DNSAnalyzer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from export.saver import ResultSaver

console = Console()
app_ui = AppUI()

GLOBAL_CONFIG = {
    "threads": 10,
    "timeout": 10,
    "export_format": "json",
}

REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})


def _http_status_numeric(result: dict) -> int:
    """Normalize HTTP status from scanner output (supports legacy 'code' string)."""
    c = result.get("status_code")
    if isinstance(c, int):
        return c
    if c is not None:
        try:
            return int(c)
        except (TypeError, ValueError):
            pass
    raw = result.get("code")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


# ============================================================================
# SCAN HANDLERS
# ============================================================================

async def run_direct_scan(config: dict):
    """Direct HTTP/HTTPS scanning."""
    console.print("[bold cyan]Starting Direct Scan...[/bold cyan]")
    
    hosts = []
    if 'input_file' in config:
        try:
            with open(config['input_file'], 'r') as f:
                hosts = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            console.print(f"[red]Error: File {config['input_file']} not found.[/red]")
            return
    elif 'single_host' in config:
        hosts = [config['single_host']]
    elif 'hosts' in config:
        hosts = config['hosts']
    
    th = config.get("threads", GLOBAL_CONFIG["threads"])
    to = config.get("timeout", GLOBAL_CONFIG["timeout"])
    method = config.get("method", "HEAD")
    scanner = SNIScanner(threads=th, timeout=to, method=method)
    saver = ResultSaver()
    results = []

    console.print(f"[green]Scanning {len(hosts)} hosts with {th} threads...[/green]")

    with app_ui.create_live_display():
        async for result in scanner.scan_list(hosts):
            results.append(result)
            app_ui.add_result(result)

    app_ui.display_results_summary(results)
    json_path = saver.save_json(results)
    txt_path = saver.save_txt(results)
    console.print(f"[green]Results saved to:\n- {json_path}\n- {txt_path}[/green]")

async def run_non302_scan(config: dict):
    """DirectNon302 scanning - excludes redirect responses."""
    console.print("[bold cyan]Starting DirectNon302 Scan (Excluding Redirects)...[/bold cyan]")
    
    hosts = []
    if 'input_file' in config:
        try:
            with open(config['input_file'], 'r') as f:
                hosts = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            console.print(f"[red]Error: File {config['input_file']} not found.[/red]")
            return
    elif 'single_host' in config:
        hosts = [config['single_host']]
    elif 'hosts' in config:
        hosts = config['hosts']
    
    th = config.get("threads", GLOBAL_CONFIG["threads"])
    to = config.get("timeout", GLOBAL_CONFIG["timeout"])
    method = config.get("method", "HEAD")
    scanner = SNIScanner(threads=th, timeout=to, exclude_redirects=True, method=method)
    saver = ResultSaver()
    results = []

    console.print(f"[green]Scanning {len(hosts)} hosts (excluding redirects)...[/green]")

    with app_ui.create_live_display():
        async for result in scanner.scan_list(hosts):
            if _http_status_numeric(result) not in REDIRECT_STATUS_CODES:
                results.append(result)
                app_ui.add_result(result)
    
    app_ui.display_results_summary(results)
    json_path = saver.save_json(results)
    txt_path = saver.save_txt(results)
    console.print(f"[green]Results saved to:\n- {json_path}\n- {txt_path}[/green]")

async def run_ssl_sni_analysis(config: dict):
    """SSL/SNI analysis: parallel TLS+HTTP and WebSocket probes, Rich summary + detail panels."""
    console.print("[bold cyan]SSL / SNI analysis[/bold cyan] [dim](parallel probes per host)[/dim]")

    hosts = []
    if "input_file" in config:
        try:
            with open(config["input_file"], "r", encoding="utf-8") as f:
                hosts = [ln.strip() for ln in f if ln.strip()]
        except FileNotFoundError:
            console.print(f"[red]Error: File {config['input_file']} not found.[/red]")
            return
    elif "single_host" in config:
        hosts = [config["single_host"]]
    elif "hosts" in config:
        hosts = config["hosts"]

    if not hosts:
        console.print("[red]Error: No hosts provided for analysis.[/red]")
        return

    timeout = int(config.get("timeout", GLOBAL_CONFIG["timeout"]))
    threads = int(config.get("threads", GLOBAL_CONFIG["threads"]))
    concurrency = min(32, max(2, threads))
    targets = [HostAnalyzer.parse_target(h) for h in hosts]
    analyzer = HostAnalyzer(timeout=timeout)
    sem = asyncio.Semaphore(concurrency)
    n = len(targets)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        tid = progress.add_task("[cyan]Analyzing TLS + HTTP + WebSocket…[/cyan]", total=n)

        async def work(i: int, host: str, port: int):
            async with sem:
                r = await analyzer.analyze(host, port)
            progress.advance(tid)
            return i, r

        pairs = await asyncio.gather(*(work(i, h, p) for i, (h, p) in enumerate(targets)))

    results = [r for _, r in sorted(pairs, key=lambda x: x[0])]

    app_ui.print_ssl_analysis_summary_table(results)
    if len(results) <= 5:
        for r in results:
            app_ui.print_ssl_analysis_detail_panels(r)
    else:
        console.print(
            "[dim]Showing full certificate panels for failed targets only "
            "(use ≤5 hosts or single-host input for every detail).[/dim]"
        )
        for r in results:
            if not r.get("ok"):
                app_ui.print_ssl_analysis_detail_panels(r)

async def run_proxy_test(config: dict):
    """Proxy validation for tunneling compatibility."""
    console.print("[bold cyan]Starting Proxy Testing...[/bold cyan]")
    
    host = config.get('single_host', config.get('ip', ''))
    if not host and 'input_file' in config:
         try:
            with open(config['input_file'], 'r') as f:
                hosts = [l.strip() for l in f if l.strip()]
                host = hosts[0] if hosts else ''
         except: pass
    
    if not host:
        console.print("[red]Error: Target host required for proxy test.[/red]")
        return

    tester = ProxyTester()
    results = await tester.run_suite(host)
    
    table = Table(title=f"Proxy Test Results: {host}")
    table.add_column("Port", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Status", style="bold")
    table.add_column("Details", style="white")
    
    for r in results:
        status_style = "green" if r['status'] == "WORKING" else "yellow" if r['status'] == "RESTRICTED" else "red"
        table.add_row(str(r['port']), r['type'], f"[{status_style}]{r['status']}[/{status_style}]", r['details'])
    
    console.print(table)

async def run_ping_scan(config: dict):
    """Connectivity testing for discovered hosts."""
    console.print("[bold cyan]Starting Ping Scan...[/bold cyan]")
    
    hosts = []
    if 'input_file' in config:
        try:
            with open(config['input_file'], 'r') as f:
                hosts = [l.strip() for l in f if l.strip()]
        except: pass
    elif 'single_host' in config:
        hosts = [config['single_host']]
    
    if not hosts:
        console.print("[red]Error: No hosts to ping.[/red]")
        return

    scanner = PingScanner()
    results = await scanner.scan_list(hosts)
    
    table = Table(title="Ping Scan Results")
    table.add_column("Host", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Latency", style="green")
    
    for r in results:
        status_style = "green" if r['status'] == "ONLINE" else "red"
        table.add_row(r['host'], f"[{status_style}]{r['status']}[/{status_style}]", r['latency'])
    
    console.print(table)

async def run_custom_method_scan(config: dict):
    """Custom HTTP method scanning."""
    method = config.get('method', 'GET')
    console.print(f"[bold cyan]Starting Custom Method Scan ({method})...[/bold cyan]")
    
    hosts = []
    if 'input_file' in config:
        try:
            with open(config['input_file'], 'r') as f:
                hosts = [l.strip() for l in f if l.strip()]
        except: pass
    elif 'single_host' in config:
        hosts = [config['single_host']]
    
    th = config.get("threads", GLOBAL_CONFIG["threads"])
    to = config.get("timeout", GLOBAL_CONFIG["timeout"])
    scanner = SNIScanner(threads=th, timeout=to, method=method)
    results = []
    saver = ResultSaver()

    with app_ui.create_live_display():
        async for result in scanner.scan_list(hosts):
            results.append(result)
            app_ui.add_result(result)

    app_ui.display_results_summary(results)
    json_path = saver.save_json(results)
    txt_path = saver.save_txt(results)
    console.print(f"[green]Results saved to:\n- {json_path}\n- {txt_path}[/green]")

async def run_multi_mode_scan(config: dict):
    """Multi-mode batch scanning."""
    console.print("[bold cyan]Starting Multi-Mode Batch Scan...[/bold cyan]")
    
    hosts = []
    if 'input_file' in config:
        try:
            with open(config['input_file'], 'r') as f:
                hosts = [l.strip() for l in f if l.strip()]
        except: pass
    
    if not hosts:
        console.print("[red]Error: Hosts file required for batch scan.[/red]")
        return

    analyzer = HostAnalyzer()
    rows = []

    def _parse_target(line: str):
        s = line.strip().replace("https://", "").replace("http://", "").strip("/")
        if s.count(":") == 1:
            h, p = s.split(":", 1)
            if p.isdigit():
                return h, int(p)
        return s, 443

    with Progress() as progress:
        task = progress.add_task("[cyan]Analyzing hosts...", total=len(hosts))
        for line in hosts:
            host, port = _parse_target(line)
            res = await analyzer.analyze(host, port)
            modes = ", ".join(res.get("modes") or [])
            err = res.get("error", "")
            if err:
                note = err
            else:
                note = f"HTTP {res.get('http_status', '—')} · {res.get('tls_version', '—')}"
            rows.append((f"{host}:{port}", modes or "—", note))
            progress.update(task, advance=1)

    table = Table(title="Multi-mode batch results")
    table.add_column("Target", style="cyan")
    table.add_column("Modes", style="green")
    table.add_column("Note", style="dim")
    for target, modes, note in rows[:200]:
        table.add_row(target, modes, note)
    if len(rows) > 200:
        console.print(f"[dim]Showing 200 of {len(rows)} rows.[/dim]")
    console.print(table)
    console.print("[green]Multi-mode scan complete![/green]")

# ============================================================================
# SUBDOMAIN ENUMERATION HANDLERS
# ============================================================================

async def run_subdomain_discovery(config: dict):
    """Passive subdomain discovery."""
    console.print("[bold magenta]Starting Passive Subdomain Discovery...[/bold magenta]")
    
    domain = config.get('domain', '')
    finder = SubdomainFinder()
    
    console.print(f"[green]Discovering subdomains for: {domain}[/green]")
    
    subdomains = await finder.find_subdomains(domain)
    
    console.print(f"\n[bold green]Found {len(subdomains)} subdomains:[/bold green]")
    for sub in subdomains:
        console.print(f"  [cyan]•[/cyan] {sub}")
    
    # Save results
    output_file = f"results/subdomains_{domain.replace('.', '_')}.txt"
    os.makedirs('results', exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(subdomains))
    
    console.print(f"\n[green]Results saved to: {output_file}[/green]")

async def run_batch_domain_enum(config: dict):
    """Batch domain enumeration from a file."""
    console.print("[bold magenta]Starting Batch Domain Enumeration...[/bold magenta]")
    
    domains = []
    # Note: app_ui.get_subdomain_config would need to be updated to support files
    # but for now we'll assume the user might provide a file in config
    if 'input_file' in config:
        try:
            with open(config['input_file'], 'r') as f:
                domains = [l.strip() for l in f if l.strip()]
        except: pass
    
    if not domains:
        console.print("[red]Error: No domains to enumerate.[/red]")
        return

    finder = SubdomainFinder()
    os.makedirs("results", exist_ok=True)
    for domain in domains:
        console.print(f"[green]Enumerating: {domain}[/green]")
        subs = await finder.find_subdomains(domain)
        console.print(f"  [cyan]Found {len(subs)} subdomains[/cyan]")
        safe = domain.replace(".", "_").replace("/", "_")
        out_path = os.path.join("results", f"subdomains_batch_{safe}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(subs))
        console.print(f"  [dim]Saved: {out_path}[/dim]")

# ============================================================================
# IP LOOKUP HANDLERS
# ============================================================================

async def run_reverse_ip_lookup(config: dict):
    """Reverse IP lookup."""
    console.print("[bold yellow]Starting Reverse IP Lookup...[/bold yellow]")

    ip = config.get("ip", "")
    if not ip and config.get("file"):
        try:
            with open(config["file"], "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f if ln.strip()]
            ip = lines[0] if lines else ""
            if len(lines) > 1:
                console.print(f"[dim]Using first IP from file ({len(lines)} lines); run again for others if needed.[/dim]")
        except OSError as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            return

    if not ip:
        console.print("[red]Error: IP address or valid file required.[/red]")
        return

    lookup = InfoLookup()
    domains = await lookup.reverse_ip_lookup(ip)
    
    if domains:
        console.print(f"\n[green]Found {len(domains)} domains on {ip}:[/green]")
        for d in domains:
            console.print(f"  [cyan]•[/cyan] {d}")
    else:
        console.print(f"[yellow]No domains found for {ip}.[/yellow]")

async def run_cidr_processing(config: dict):
    """CIDR range processing."""
    console.print("[bold yellow]Starting CIDR Range Processing...[/bold yellow]")
    
    cidr = config.get('cidr', '')
    if not cidr:
        console.print("[red]Error: CIDR range required.[/red]")
        return

    lookup = InfoLookup()
    ips = lookup.process_cidr(cidr)
    
    console.print(f"[green]Expanded {cidr} into {len(ips)} IP addresses.[/green]")
    if len(ips) > 20:
        console.print(f"[dim]Showing first 20 IPs:[/dim]")
        for ip in ips[:20]:
            console.print(f"  - {ip}")
        console.print(f"[dim]... and {len(ips)-20} more.[/dim]")
    else:
        for ip in ips:
            console.print(f"  - {ip}")

async def run_multi_source_ip(config: dict):
    """Multi-source IP intelligence."""
    console.print("[bold yellow]Starting Multi-Source IP Intelligence...[/bold yellow]")
    
    target = config.get('ip', config.get('host', ''))
    if not target:
        console.print("[red]Error: Target (IP or Host) required.[/red]")
        return

    lookup = InfoLookup()
    result = await lookup.multi_source_intel(target)
    
    # GeoIP
    geo = result.get('geoip', {})
    geo_info = f"IP: {result['ip']}\nCountry: {geo.get('country', 'N/A')}\nISP: {geo.get('isp', 'N/A')}"
    console.print(Panel(geo_info, title="Intel: GeoIP", border_style="cyan"))
    
    # Domains
    domains = result.get('domains', [])
    if domains:
        domain_list = "\n".join([f"- {d}" for d in domains[:10]])
        if len(domains) > 10: domain_list += f"\n... and {len(domains)-10} more"
        console.print(Panel(domain_list, title="Intel: Reverse IP Domains", border_style="magenta"))
    else:
        console.print("[yellow]No reverse DNS domains found.[/yellow]")

# ============================================================================
# PORT SCANNER HANDLERS
# ============================================================================

async def run_quick_port_scan(config: dict):
    """Quick port scan on common tunneling ports."""
    console.print("[bold blue]Starting Quick Port Scan...[/bold blue]")
    
    target = config.get('target', '')
    ports = config.get('ports', [80, 443, 8080, 8443])
    
    profiler = PortProfiler()
    
    console.print(f"[green]Scanning {target} on ports: {', '.join(map(str, ports))}[/green]")
    
    results = await profiler.scan_ports(target, ports)
    
    console.print(f"\n[bold green]Open Ports:[/bold green]")
    for port, status in results.items():
        if status == 'open':
            console.print(f"  [green]✓[/green] Port {port}: OPEN")
        else:
            console.print(f"  [red]✗[/red] Port {port}: CLOSED")

async def run_custom_port_scan(config: dict):
    """Custom port range scanning."""
    console.print("[bold blue]Starting Custom Port Scan...[/bold blue]")
    
    target = config.get('target', '')
    ports = config.get('ports', [])
    
    profiler = PortProfiler()
    
    console.print(f"[green]Scanning {target} on {len(ports)} ports...[/green]")
    
    results = await profiler.scan_ports(target, ports)
    
    open_ports = [p for p, s in results.items() if s == 'open']
    console.print(f"\n[bold green]Found {len(open_ports)} open ports:[/bold green]")
    for port in open_ports:
        console.print(f"  [green]✓[/green] Port {port}")

async def run_service_detection(config: dict):
    """Service detection on open ports."""
    console.print("[bold blue]Starting Service Detection...[/bold blue]")
    
    target = config.get('target', '')
    ports = config.get('ports', [80, 443, 8080, 8443])
    
    profiler = PortProfiler()
    console.print(f"[green]Detecting services on {target}...[/green]")
    
    results = await profiler.detect_services(target, ports)
    
    table = Table(title=f"Service Detection: {target}")
    table.add_column("Port", style="cyan")
    table.add_column("Detected Service / Banner", style="magenta")
    
    for port, banner in results.items():
        table.add_row(str(port), banner)
    
    console.print(table)

# ============================================================================
# DNS & SSL ANALYSIS HANDLERS
# ============================================================================

async def run_dns_analysis(config: dict):
    """DNS record analysis."""
    console.print("[bold red]Starting DNS Record Analysis...[/bold red]")
    
    raw = (config.get("host") or "").strip()
    if not raw:
        console.print("[red]Error: Host required.[/red]")
        return

    host, _ = HostAnalyzer.parse_target(raw)
    analyzer = DNSAnalyzer()
    results = await analyzer.get_records(host)
    app_ui.print_dns_records_table(results, f"DNS records — {host}")

async def run_ssl_validation(config: dict):
    """SSL / SNI validation with structured certificate view."""
    console.print("[bold red]SSL certificate validation[/bold red] [dim](TLS + HTTP + WebSocket)[/dim]")

    raw = (config.get("host") or "").strip()
    host, port = HostAnalyzer.parse_target(raw)
    if not host:
        console.print("[red]Error: Host required.[/red]")
        return

    to = int(config.get("timeout", GLOBAL_CONFIG["timeout"]))
    analyzer = HostAnalyzer(timeout=to)
    result = await analyzer.analyze(host, port)
    app_ui.print_ssl_analysis_summary_table([result])
    app_ui.print_ssl_analysis_detail_panels(result)

async def run_comprehensive_audit(config: dict):
    """DNS + TLS/HTTP audit (parallel DNS lookups and protocol probe)."""
    console.print("[bold red]Comprehensive DNS + TLS audit[/bold red] [dim](parallel)[/dim]")

    raw = (config.get("host") or "").strip()
    if not raw:
        console.print("[red]Error: Host required.[/red]")
        return

    host, port = HostAnalyzer.parse_target(raw)
    to = int(config.get("timeout", GLOBAL_CONFIG["timeout"]))

    dns_analyzer = DNSAnalyzer()
    protocol_audit = ProtocolAudit(timeout=to)

    dns_task = dns_analyzer.comprehensive_audit(host)
    protocol_task = protocol_audit.audit(host, port)
    dns_res, protocol_res = await asyncio.gather(dns_task, protocol_task)

    app_ui.print_dns_records_table(dns_res["records"], f"DNS — {host}")
    app_ui.print_protocol_audit_report(protocol_res, f"TLS & HTTP — {host}:{port}")

async def run_protocol_audit(config: dict):
    """Run protocol and certificate audit (non-blocking cert fetch + httpx)."""
    target = (config.get("target") or "").strip()
    if not target:
        console.print("[red]Error: Target required.[/red]")
        return

    host, port = HostAnalyzer.parse_target(target)
    to = int(config.get("timeout", GLOBAL_CONFIG["timeout"]))
    audit = ProtocolAudit(timeout=to)
    console.print(f"[bold deep_sky_blue1]Protocol audit[/bold deep_sky_blue1] [dim]{host}:{port}[/dim]")

    result = await audit.audit(host, port)
    app_ui.print_protocol_audit_report(result, f"Protocol & certificate — {host}:{port}")

# ============================================================================
# FILE MANAGEMENT HANDLERS
# ============================================================================

def handle_file_split(config: dict):
    """Split file into smaller chunks."""
    console.print("[bold white]Starting File Split...[/bold white]")
    
    input_file = config.get('input_file', '')
    lines_per_file = config.get('lines_per_file', 1000)
    output_prefix = config.get('output_prefix', 'split_')
    
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
        
        total_files = (len(lines) + lines_per_file - 1) // lines_per_file
        
        for i in range(total_files):
            start = i * lines_per_file
            end = min((i + 1) * lines_per_file, len(lines))
            chunk = lines[start:end]
            
            output_file = f"{output_prefix}{i+1}.txt"
            with open(output_file, 'w') as f:
                f.writelines(chunk)
            
            console.print(f"[green]Created: {output_file} ({len(chunk)} lines)[/green]")
        
        console.print(f"\n[bold green]Split complete! Created {total_files} files.[/bold green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

def handle_file_merge(config: dict):
    """Merge multiple files."""
    console.print("[bold white]Starting File Merge...[/bold white]")
    
    files = config.get('files', [])
    output_file = config.get('output_file', 'merged.txt')
    
    try:
        all_lines = []
        for file in files:
            with open(file, 'r') as f:
                all_lines.extend(f.readlines())
        
        with open(output_file, 'w') as f:
            f.writelines(all_lines)
        
        console.print(f"[bold green]Merged {len(files)} files into {output_file} ({len(all_lines)} lines)[/bold green]")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

def handle_file_deduplicate(config: dict):
    """Deduplicate file entries."""
    console.print("[bold white]Starting File Deduplication...[/bold white]")
    
    input_file = config.get('input_file', '')
    output_file = config.get('output_file', 'deduped.txt')
    case_sensitive = config.get('case_sensitive', False)
    
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
        
        original_count = len(lines)
        
        if case_sensitive:
            unique_lines = list(dict.fromkeys(lines))
        else:
            seen = {}
            unique_lines = []
            for line in lines:
                key = line.lower()
                if key not in seen:
                    seen[key] = True
                    unique_lines.append(line)
        
        with open(output_file, 'w') as f:
            f.writelines(unique_lines)
        
        removed = original_count - len(unique_lines)
        console.print(f"[bold green]Deduplication complete![/bold green]")
        console.print(f"Original: {original_count} lines")
        console.print(f"Unique: {len(unique_lines)} lines")
        console.print(f"Removed: {removed} duplicates")
        console.print(f"Saved to: {output_file}")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

def handle_file_filter(config: dict):
    """Filter and clean file."""
    console.print("[bold white]Starting File Filter...[/bold white]")
    
    input_file = config.get('input_file', '')
    output_file = config.get('output_file', 'filtered.txt')
    filter_type = config.get('filter_type', 'contains')
    filter_value = config.get('filter_value', '')
    
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
        
        filtered_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            
            if filter_type == 'contains' and filter_value in line_stripped:
                filtered_lines.append(line)
            elif filter_type == 'startswith' and line_stripped.startswith(filter_value):
                filtered_lines.append(line)
            elif filter_type == 'endswith' and line_stripped.endswith(filter_value):
                filtered_lines.append(line)
            elif filter_type == 'length':
                try:
                    if len(line_stripped) >= int(filter_value):
                        filtered_lines.append(line)
                except:
                    pass
            elif filter_type == 'regex':
                import re
                if re.search(filter_value, line_stripped):
                    filtered_lines.append(line)
        
        with open(output_file, 'w') as f:
            f.writelines(filtered_lines)
        
        console.print(f"[bold green]Filter complete![/bold green]")
        console.print(f"Original: {len(lines)} lines")
        console.print(f"Filtered: {len(filtered_lines)} lines")
        console.print(f"Saved to: {output_file}")
    
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

async def run_payload_test(config: dict):
    """Run comprehensive payload suite."""
    target = config.get('target', '')
    port = config.get('port', 80)
    
    tester = PayloadTester()
    console.print(f"[bold cyan]Starting Payload Suite for {target}:{port}...[/bold cyan]")
    
    results = await tester.run_suite(target, port)
    
    table = Table(title=f"Payload Results: {target}", border_style="cyan")
    table.add_column("Payload Name", style="white")
    table.add_column("Status", style="bold")
    table.add_column("Latency", style="dim")
    table.add_column("Working", justify="center")
    
    for r in results:
        status_style = "green" if r["working"] else "red"
        working_icon = "[green]✓[/green]" if r["working"] else "[red]✗[/red]"
        table.add_row(r["name"], f"[{status_style}]{r['status']}[/{status_style}]", r["latency"], working_icon)
    
    console.print(table)

async def run_websocket_test(config: dict):
    """Test for WebSocket upgrade support."""
    target = config.get('target', '')
    port = config.get('port', 80)
    path = config.get('path', '/')
    
    scanner = WebSocketScanner()
    console.print(f"[bold magenta]Scanning WebSocket on {target}:{port}{path}...[/bold magenta]")
    
    result = await scanner.scan(target, port, path)
    
    panel_style = "green" if result["working"] else "red"
    summary = f"URL: {result['url']}\nStatus: {result['status']}\nLatency: {result['latency']}\nDetails: {result['details']}"
    console.print(Panel(summary, title="WebSocket Result", border_style=panel_style))

async def run_cdn_detection(config: dict):
    """Detect CDN and WAF providers."""
    target = config.get('target', '')
    
    detector = CDNDetector()
    console.print(f"[bold orange3]Detecting CDN for {target}...[/bold orange3]")
    
    result = await detector.detect(target)
    
    panel_style = "green" if result["cdn_found"] else "yellow"
    summary = f"IP Address: {result['ip_address']}\nCDN Found: {'Yes' if result['cdn_found'] else 'No'}\nProvider: {result['provider']}\n\nEvidence:\n" + "\n".join(f"- {e}" for e in result["evidence"])
    
    console.print(Panel(summary, title="CDN Cloud Detection", border_style=panel_style))

async def run_info_lookup(config: dict):
    """Run GeoIP and WHOIS lookup."""
    target = config.get('target', '')
    
    lookup = InfoLookup()
    console.print(f"[bold spring_green3]Gathering Intel for {target}...[/bold spring_green3]")
    
    result = await lookup.lookup_ip_info(target)
    
    if result.get('error'):
        console.print(f"[red]Error: {result['error']}[/red]")
        return

    # GeoIP Panel
    geo = result['geoip']
    geo_info = f"IP: {result['ip']}\nCountry: {geo.get('country', 'N/A')}\nCity: {geo.get('city', 'N/A')}\nISP: {geo.get('isp', 'N/A')}\nAS: {geo.get('as', 'N/A')}"
    console.print(Panel(geo_info, title="GeoIP Information", border_style="cyan"))
    
    # Whois Panel
    w = result['whois']
    whois_info = f"Registrar: {w.get('registrar', 'N/A')}\nOrg: {w.get('org', 'N/A')}\nCreated: {w.get('creation_date', 'N/A')}\nExpires: {w.get('expiration_date', 'N/A')}"
    console.print(Panel(whois_info, title="WHOIS Information", border_style="magenta"))

# ============================================================================
# SETTINGS & UTILITIES
# ============================================================================

def handle_settings():
    """Configure global settings."""
    console.print("[bold cyan]Settings Configuration[/bold cyan]")
    
    GLOBAL_CONFIG["threads"] = int(Prompt.ask("Default Threads", default=str(GLOBAL_CONFIG["threads"])))
    GLOBAL_CONFIG["timeout"] = int(Prompt.ask("Default Timeout", default=str(GLOBAL_CONFIG["timeout"])))
    GLOBAL_CONFIG["export_format"] = Prompt.ask("Export Format", choices=["json", "txt", "csv"], default=GLOBAL_CONFIG["export_format"])
    
    console.print("[green]Settings updated![/green]")

async def handle_about_me():
    """Display about author and handle sub-menu."""
    while True:
        choice = app_ui.show_about_menu()
        if choice == "1":
            app_ui.show_about_me()
            Prompt.ask("\nPress Enter to continue")
        elif choice == "2":
            await handle_update()
            Prompt.ask("\nPress Enter to continue")
        elif choice == "3":
            console.print("[bold blue]Opening Telegram channel...[/bold blue]")
            webbrowser.open("https://t.me/yt_netsa_official")
            Prompt.ask("\nPress Enter to continue")
        elif choice == "0":
            break

async def handle_update():
    """Compare local version to GitHub and update via git pull when available."""
    console.print("[bold cyan]Checking for updates...[/bold cyan]")
    repo_url = "https://github.com/mrxtopia/snibug"
    raw_version_url = "https://raw.githubusercontent.com/mrxtopia/snibug/main/version.py"

    try:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(raw_version_url) as resp:
                if resp.status != 200:
                    console.print("[red]Could not fetch version from GitHub.[/red]")
                    return
                content = await resp.text()

        remote_version = "Unknown"
        for line in content.split("\n"):
            line = line.split("#")[0].strip()
            if line.startswith("VERSION"):
                _, _, rhs = line.partition("=")
                remote_version = rhs.strip().strip('"').strip("'")
                break

        if remote_version == "Unknown":
            console.print("[red]Could not parse remote version file.[/red]")
            return

        if remote_version != VERSION:
            console.print(f"[bold green]Update available[/bold green] (v{VERSION} → v{remote_version})")
            if not Confirm.ask("Run git pull in this folder now?"):
                return
            git_dir = os.path.join(BASE_DIR, ".git")
            if os.path.isdir(git_dir):
                try:
                    subprocess.run(
                        ["git", "pull"],
                        cwd=BASE_DIR,
                        check=True,
                    )
                    console.print("[bold green]Update complete. Restart the tool.[/bold green]")
                    sys.exit(0)
                except (subprocess.CalledProcessError, FileNotFoundError) as e:
                    console.print(f"[red]Git pull failed: {e}[/red]")
            console.print(
                f"[yellow]This folder is not a git clone. Download the full project from:[/yellow]\n[cyan]{repo_url}[/cyan]"
            )
        else:
            console.print("[green]You are on the latest version.[/green]")
    except Exception as e:
        console.print(f"[red]Update check failed: {e}[/red]")

def handle_view_results():
    """View previous scan results."""
    console.print("[bold cyan]View Results[/bold cyan]")
    
    results_dir = "results"
    if os.path.exists(results_dir):
        files = [f for f in os.listdir(results_dir) if f.endswith(('.json', '.txt'))]
        
        if files:
            console.print(f"\n[green]Found {len(files)} result files:[/green]")
            for i, file in enumerate(files, 1):
                console.print(f"  {i}. {file}")
        else:
            console.print("[yellow]No result files found.[/yellow]")
    else:
        console.print("[yellow]Results directory not found.[/yellow]")

def handle_export_options():
    """Configure export options."""
    console.print("[bold cyan]Export Options[/bold cyan]")
    console.print(f"Current format: [green]{GLOBAL_CONFIG['export_format']}[/green]")
    
    new_format = Prompt.ask("Select new format", choices=["json", "txt", "csv", "md"], default=GLOBAL_CONFIG['export_format'])
    GLOBAL_CONFIG["export_format"] = new_format
    
    console.print(f"[green]Export format set to: {new_format}[/green]")

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

async def menu_host_scanner():
    while True:
        choice = app_ui.show_host_scanner_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_scan_config()
            await run_direct_scan(config)
        elif choice == "2":
            config = app_ui.get_scan_config()
            await run_non302_scan(config)
        elif choice == "3":
            config = app_ui.get_scan_config()
            await run_ssl_sni_analysis(config)
        elif choice == "4":
            config = app_ui.get_scan_config()
            await run_proxy_test(config)
        elif choice == "5":
            config = app_ui.get_scan_config()
            await run_ping_scan(config)
        elif choice == "6":
            config = app_ui.get_scan_config()
            await run_custom_method_scan(config)
        elif choice == "7":
            config = app_ui.get_scan_config()
            await run_multi_mode_scan(config)
        
        app_ui.pause()

async def menu_subdomain():
    while True:
        choice = app_ui.show_subdomain_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_subdomain_config()
            await run_subdomain_discovery(config)
        elif choice == "2":
            config = app_ui.get_subdomain_config()
            await run_batch_domain_enum(config)
            
        app_ui.pause()

async def menu_ip_lookup():
    while True:
        choice = app_ui.show_ip_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_ip_lookup_config()
            await run_reverse_ip_lookup(config)
        elif choice == "2":
            config = app_ui.get_ip_lookup_config()
            await run_cidr_processing(config)
        elif choice == "3":
            config = app_ui.get_ip_lookup_config()
            await run_multi_source_ip(config)
            
        app_ui.pause()

async def menu_port_scanner():
    while True:
        choice = app_ui.show_port_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_port_scan_config()
            await run_quick_port_scan(config)
        elif choice == "2":
            config = app_ui.get_port_scan_config()
            await run_custom_port_scan(config)
        elif choice == "3":
            config = app_ui.get_port_scan_config()
            await run_service_detection(config)
            
        app_ui.pause()

async def menu_dns_ssl():
    while True:
        choice = app_ui.show_dns_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_dns_ssl_config()
            await run_dns_analysis(config)
        elif choice == "2":
            config = app_ui.get_dns_ssl_config()
            await run_ssl_validation(config)
        elif choice == "3":
            config = app_ui.get_dns_ssl_config()
            await run_comprehensive_audit(config)
            
        app_ui.pause()

async def menu_file_management():
    while True:
        choice = app_ui.show_file_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_file_operation_config("split")
            handle_file_split(config)
        elif choice == "2":
            config = app_ui.get_file_operation_config("merge")
            handle_file_merge(config)
        elif choice == "3":
            config = app_ui.get_file_operation_config("deduplicate")
            handle_file_deduplicate(config)
        elif choice == "4":
            config = app_ui.get_file_operation_config("filter")
            handle_file_filter(config)
            
        app_ui.pause()

async def menu_settings():
    while True:
        choice = app_ui.show_settings_menu()
        if choice == "0": break
        
        if choice == "1":
            handle_settings()
        elif choice == "2":
            handle_view_results()
        elif choice == "3":
            handle_export_options()
            
        app_ui.pause()

async def menu_advanced_tools():
    while True:
        choice = app_ui.show_advanced_tools_menu()
        if choice == "0": break
        
        if choice == "1":
            config = app_ui.get_advanced_config("Payload Tester")
            await run_payload_test(config)
        elif choice == "2":
            config = app_ui.get_advanced_config("WebSocket Scanner")
            await run_websocket_test(config)
        elif choice == "3":
            config = app_ui.get_advanced_config("CDN Detector")
            await run_cdn_detection(config)
        elif choice == "4":
            config = app_ui.get_advanced_config("GeoIP & Whois")
            await run_info_lookup(config)
        elif choice == "5":
            config = app_ui.get_advanced_config("Protocol Audit")
            await run_protocol_audit(config)
            
        app_ui.pause()

async def interactive_menu():
    """Main interactive menu loop."""
    while True:
        choice = app_ui.show_main_menu()
        
        if choice == "0":
            console.print("[bold red]Exiting... Goodbye![/bold red]")
            break
        
        elif choice == "1":
            await menu_host_scanner()
        elif choice == "2":
            await menu_subdomain()
        elif choice == "3":
            await menu_ip_lookup()
        elif choice == "4":
            await menu_port_scanner()
        elif choice == "5":
            await menu_dns_ssl()
        elif choice == "6":
            await menu_file_management()
        elif choice == "7":
            await menu_settings()
        elif choice == "8":
            await menu_advanced_tools()
        elif choice == "9":
            await handle_about_me()

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Advanced Free-Internet SNI Bug Scanner")
    parser.add_argument("--scan-sni", action="store_true", help="Run SNI Scanner module")
    parser.add_argument("--analyze", type=str, help="Analyze a single host")
    parser.add_argument("--input", type=str, help="Input file path (txt)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads/concurrent tasks")
    parser.add_argument("--ui", action="store_true", help="Launch Interactive UI")
    
    args = parser.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if args.analyze:
        async def analyze():
            host, port = HostAnalyzer.parse_target(args.analyze)
            console.print(f"[cyan]SSL / SNI analysis[/cyan] [dim]{host}:{port}[/dim]")
            analyzer = HostAnalyzer(timeout=GLOBAL_CONFIG["timeout"])
            result = await analyzer.analyze(host, port)
            app_ui.print_ssl_analysis_summary_table([result])
            app_ui.print_ssl_analysis_detail_panels(result)

        loop.run_until_complete(analyze())
        return
    
    if args.scan_sni:
        if not args.input:
            console.print("[red]Error: --input <file> is required for scanning.[/red]")
            return
        
        async def scan():
            try:
                with open(args.input, 'r') as f:
                    lines = [l.strip() for l in f if l.strip()]
            except FileNotFoundError:
                console.print(f"[red]Error: File {args.input} not found.[/red]")
                return

            scanner = SNIScanner(threads=args.threads, timeout=GLOBAL_CONFIG["timeout"])
            saver = ResultSaver()
            results = []

            console.print(f"[green]Starting scan on {len(lines)} hosts with {args.threads} threads...[/green]")

            with app_ui.create_live_display():
                async for result in scanner.scan_list(lines):
                    results.append(result)
                    app_ui.add_result(result)
            
            console.print("[bold green]Scan Completed![/bold green]")
            json_path = saver.save_json(results)
            txt_path = saver.save_txt(results)
            console.print(f"Results saved to:\n- {json_path}\n- {txt_path}")
        
        loop.run_until_complete(scan())
        return

    # Launch interactive menu by default
    if args.ui or len(sys.argv) == 1:
        loop.run_until_complete(interactive_menu())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Aborted by user.[/red]")
        sys.exit(0)
