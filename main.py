#!/usr/bin/env python3
import argparse
import asyncio
import os
import hashlib
import sys
from typing import List

# --- SECURITY SYSTEM ---
# This dictionary contains the expected SHA-256 hashes of core project files.
# If any file is edited, the tool will stop working to prevent unauthorized modified versions.
EXPECTED_HASHES = {
    "ui/console.py": "9ba334fecb11d989767582d4cbbdeddb8d63641e2a23de2a8c0e0f1a19a1c94a",
    "core/network.py": "4a33943e68f283b31270070c1251165f305495a7151af72ec4995fec7913bc03",
    "modules/sni_scanner.py": "226d87ba40718971cf9a06b9e795e84cee62ac634cda1da432a5788c9ea8c7bc",
    "modules/payload_tester.py": "3b1d643b70e138b0e6957660e97189bdae8a3001f8bc9d4b85d14e8896330828",
    "modules/websocket_scanner.py": "25e1e34284b79420e0056f258c11511d8d6a7be0c73ad0534ace182bd768d910",
    "modules/cdn_detector.py": "c788c7337b4bdcb5568f0477b0481f1b5279d9e23de5e17d6ae7169e7c066659",
    "modules/info_lookup.py": "0ee54006772971784881a34eab90936cabad5d3390cd54f91e7d6e3cd8f3ccd1",
    "modules/protocol_audit.py": "b12493732a0156778925ec1aff888e8352267af8d3fc8287af3fe8670724725c"
}

def verify_integrity():
    """Verify that the core files have not been tampered with."""
    github_link = "https://github.com/mrxtopia/snibug/"
    for file_path, expected_hash in EXPECTED_HASHES.items():
        if not os.path.exists(file_path):
            continue # Allow missing optional files but warn if you want
        
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            if file_hash != expected_hash:
                print("\n\033[1;31m[!] SECURITY ALERT: TAMPER DETECTION\033[0m")
                print(f"\033[1;33m[!] Error: File '{file_path}' has been edited.\033[0m")
                print("\033[1;37m[!] edited please re install from gitclone " + github_link + "\033[0m\n")
                sys.exit(1)

# Run integrity check before anything else
verify_integrity()

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
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from export.saver import ResultSaver

console = Console()
app_ui = AppUI()

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
    
    scanner = SNIScanner(threads=config.get('threads', 10))
    saver = ResultSaver()
    results = []
    
    console.print(f"[green]Scanning {len(hosts)} hosts with {config.get('threads', 10)} threads...[/green]")
    
    with app_ui.create_live_display() as live:
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
    
    scanner = SNIScanner(threads=config.get('threads', 10), exclude_redirects=True)
    saver = ResultSaver()
    results = []
    
    console.print(f"[green]Scanning {len(hosts)} hosts (excluding 302 redirects)...[/green]")
    
    with app_ui.create_live_display() as live:
        async for result in scanner.scan_list(hosts):
            # Filter out 302 responses
            if result.get('status_code') not in [301, 302, 303, 307, 308]:
                results.append(result)
                app_ui.add_result(result)
    
    app_ui.display_results_summary(results)
    json_path = saver.save_json(results)
    txt_path = saver.save_txt(results)
    console.print(f"[green]Results saved to:\n- {json_path}\n- {txt_path}[/green]")

async def run_ssl_sni_analysis(config: dict):
    """SSL/SNI configuration analysis."""
    console.print("[bold cyan]Starting SSL/SNI Analysis...[/bold cyan]")
    
    host = config.get('single_host', '')
    if ':' in host:
        h, p = host.split(':')
        port = int(p)
        host = h
    else:
        port = 443
    
    analyzer = HostAnalyzer()
    result = await analyzer.analyze(host, port)
    
    console.print(Panel(str(result), title=f"SSL/SNI Analysis: {host}:{port}", border_style="cyan"))

async def run_proxy_test(config: dict):
    """Proxy validation for tunneling compatibility."""
    console.print("[bold cyan]Starting Proxy Testing...[/bold cyan]")
    console.print("[yellow]Proxy testing module - Coming soon![/yellow]")
    console.print("[dim]This will test hosts for proxy/tunneling compatibility[/dim]")

async def run_ping_scan(config: dict):
    """Connectivity testing for discovered hosts."""
    console.print("[bold cyan]Starting Ping Scan...[/bold cyan]")
    console.print("[yellow]Ping scanning module - Coming soon![/yellow]")
    console.print("[dim]This will perform ICMP/TCP ping tests on hosts[/dim]")

async def run_custom_method_scan(config: dict):
    """Custom HTTP method scanning."""
    console.print(f"[bold cyan]Starting Custom Method Scan ({config.get('method', 'GET')})...[/bold cyan]")
    console.print("[yellow]Custom method scanning - Coming soon![/yellow]")
    console.print(f"[dim]Will scan using method: {config.get('method', 'GET')}[/dim]")

async def run_multi_mode_scan(config: dict):
    """Multi-mode batch scanning."""
    console.print("[bold cyan]Starting Multi-Mode Batch Scan...[/bold cyan]")
    console.print("[yellow]Multi-mode scanning - Coming soon![/yellow]")
    console.print("[dim]This will run multiple scan types in parallel[/dim]")

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
    """Batch domain enumeration."""
    console.print("[bold magenta]Starting Batch Domain Enumeration...[/bold magenta]")
    console.print("[yellow]Batch enumeration - Coming soon![/yellow]")
    console.print("[dim]This will enumerate multiple domains from a file[/dim]")

# ============================================================================
# IP LOOKUP HANDLERS
# ============================================================================

async def run_reverse_ip_lookup(config: dict):
    """Reverse IP lookup."""
    console.print("[bold yellow]Starting Reverse IP Lookup...[/bold yellow]")
    console.print("[yellow]Reverse IP lookup - Coming soon![/yellow]")
    console.print("[dim]This will discover all domains hosted on target IPs[/dim]")

async def run_cidr_processing(config: dict):
    """CIDR range processing."""
    console.print("[bold yellow]Starting CIDR Range Processing...[/bold yellow]")
    console.print("[yellow]CIDR processing - Coming soon![/yellow]")
    console.print(f"[dim]Will process CIDR range: {config.get('cidr', 'N/A')}[/dim]")

async def run_multi_source_ip(config: dict):
    """Multi-source IP intelligence."""
    console.print("[bold yellow]Starting Multi-Source IP Intelligence...[/bold yellow]")
    console.print("[yellow]Multi-source IP lookup - Coming soon![/yellow]")
    console.print("[dim]This will aggregate IP data from multiple sources[/dim]")

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
    console.print("[yellow]Service detection - Coming soon![/yellow]")
    console.print("[dim]This will identify services running on open ports[/dim]")

# ============================================================================
# DNS & SSL ANALYSIS HANDLERS
# ============================================================================

async def run_dns_analysis(config: dict):
    """DNS record analysis."""
    console.print("[bold red]Starting DNS Record Analysis...[/bold red]")
    console.print("[yellow]DNS analysis - Coming soon![/yellow]")
    console.print(f"[dim]Will analyze DNS records for: {config.get('host', 'N/A')}[/dim]")

async def run_ssl_validation(config: dict):
    """SSL certificate validation."""
    console.print("[bold red]Starting SSL Certificate Validation...[/bold red]")
    
    host = config.get('host', '')
    analyzer = HostAnalyzer()
    result = await analyzer.analyze(host, 443)
    
    console.print(Panel(str(result), title=f"SSL Certificate: {host}", border_style="red"))

async def run_comprehensive_audit(config: dict):
    """Comprehensive DNS+SSL audit."""
    console.print("[bold red]Starting Comprehensive DNS+SSL Audit...[/bold red]")
    console.print("[yellow]Comprehensive audit - Coming soon![/yellow]")
    console.print(f"[dim]Will perform full DNS and SSL analysis for: {config.get('host', 'N/A')}[/dim]")

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

async def run_protocol_audit(config: dict):
    """Run Protocol and Certificate audit."""
    target = config.get('target', '')
    
    audit = ProtocolAudit()
    console.print(f"[bold deep_sky_blue1]Auditing Protocol for {target}...[/bold deep_sky_blue1]")
    
    result = await audit.audit(target)
    
    if result.get('error'):
        console.print(f"[red]Error: {result['error']}[/red]")
        return
        
    # Protocols and Cert info
    info = f"Protocols Found: {', '.join(result['protocols'])}\n\nCertificate Info:\n"
    for k, v in result['ssl_info'].get('subject', {}).items():
        info += f"  - Subject {k}: {v}\n"
    for k, v in result['ssl_info'].get('issuer', {}).items():
        info += f"  - Issuer {k}: {v}\n"
    
    console.print(Panel(info, title="Protocol & SSL Certificate Audit", border_style="bright_blue"))

# ============================================================================
# SETTINGS & UTILITIES
# ============================================================================

def handle_settings():
    """Configure global settings."""
    console.print("[bold cyan]Settings Configuration[/bold cyan]")
    console.print("[yellow]Settings module - Coming soon![/yellow]")

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
    console.print("[yellow]Export configuration - Coming soon![/yellow]")

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
            host = args.analyze
            if ":" in host:
                h, p = host.split(":")
                port = int(p)
                host = h
            else:
                port = 443
            
            console.print(f"[cyan]Analyzing {host}:{port}...[/cyan]")
            analyzer = HostAnalyzer()
            result = await analyzer.analyze(host, port)
            console.print(Panel(str(result), title="Analysis Report"))
        
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

            scanner = SNIScanner(threads=args.threads)
            saver = ResultSaver()
            results = []
            
            console.print(f"[green]Starting scan on {len(lines)} hosts with {args.threads} threads...[/green]")
            
            with app_ui.create_live_display() as live:
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
