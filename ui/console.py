from rich.console import Console
from rich.table import Table, box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from typing import List

from version import VERSION
from helpers.platform_utils import default_scan_threads, default_scan_timeout


class AppUI:
    """Console UI. Live scan table shows only WORKING hosts to stay usable on huge lists."""

    _MAX_LIVE_WORKING_ROWS = 500

    def __init__(self):
        self.console = Console()
        self._scan_total = 0
        self._scan_working = 0
        self._live_working_rows = 0
        self.table = Table(show_header=True, header_style="bold magenta")
        self._init_table_columns()

    def _init_table_columns(self):
        self.table.add_column("Host", style="cyan", no_wrap=True)
        self.table.add_column("Port", style="magenta")
        self.table.add_column("Status", style="green")
        self.table.add_column("TLS", style="yellow")
        self.table.add_column("Details", style="white")

    def reset_scan_table(self):
        self._scan_total = 0
        self._scan_working = 0
        self._live_working_rows = 0
        self.table = Table(show_header=True, header_style="bold magenta")
        self._init_table_columns()

    def print_banner(self):
        banner_text = f"""
    [bold cyan]╔═══════════════════════════════════════════════════════╗[/bold cyan]
    [bold cyan]║           MR YT Bug Scanner                          ║[/bold cyan]
    [bold cyan]╚═══════════════════════════════════════════════════════╝[/bold cyan]
    [bold green]   Telegram: @mrxtopia[/bold green]
    [dim]   v{VERSION} - Multi-Platform Reconnaissance Suite[/dim]
    """
        self.console.print(Panel(banner_text, expand=False, border_style="cyan"))


    def show_main_menu(self) -> str:
        """Display the main menu and return user's choice."""
        self.console.clear()
        self.print_banner()
        
        menu_text = """
  [bold cyan]1.[/bold cyan] 🎯 HOST SCANNER
  [bold cyan]2.[/bold cyan] 🔍 SUBDOMAIN ENUMERATION
  [bold cyan]3.[/bold cyan] 🌐 IP LOOKUP & REVERSE DNS
  [bold cyan]4.[/bold cyan] 🚪 PORT SCANNER
  [bold cyan]5.[/bold cyan] 🔎 DNS & SSL ANALYSIS
  [bold cyan]6.[/bold cyan] 📁 FILE MANAGEMENT
  [bold cyan]7.[/bold cyan] ⚙️  SETTINGS & UTILITIES
  [bold cyan]8.[/bold cyan] 🛠️  ADVANCED TOOLS
  [bold cyan]9.[/bold cyan] 🛡️  ABOUT & UPDATES

  [red]0.[/red] Exit
"""
        self.console.print(Panel(menu_text, title="[bold]Main Menu[/bold]", border_style="green"))
        
        choice = Prompt.ask(
            "[bold yellow]Select an option[/bold yellow]",
            choices=[str(i) for i in range(10)],
            default="0"
        )
        return choice

    def show_host_scanner_menu(self) -> str:
        """Display Host Scanner submenu."""
        self.console.clear()
        self.print_banner()
        
        menu_text = """
[bold cyan]🎯 HOST SCANNER[/bold cyan]
  [green]1.[/green] Direct Scanning (HTTP/HTTPS)
  [green]2.[/green] DirectNon302 Scanning (Exclude Redirects)
  [green]3.[/green] SSL/SNI Analysis
  [green]4.[/green] Proxy Testing
  [green]5.[/green] Ping Scanning
  [green]6.[/green] Custom Method Scanning (GET/POST/HEAD/etc.)
  [green]7.[/green] Multi-Mode Batch Scan

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]Host Scanner[/bold]", border_style="cyan"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(8)], default="0")

    def show_subdomain_menu(self) -> str:
        """Display Subdomain Enumeration submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold magenta]🔍 SUBDOMAIN ENUMERATION[/bold magenta]
  [green]1.[/green] Passive Subdomain Discovery
  [green]2.[/green] Batch Domain Enumeration

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]Subdomain Enumeration[/bold]", border_style="magenta"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(3)], default="0")

    def show_ip_menu(self) -> str:
        """Display IP Lookup submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold yellow]🌐 IP LOOKUP & REVERSE DNS[/bold yellow]
  [green]1.[/green] Reverse IP Lookup
  [green]2.[/green] CIDR Range Processing
  [green]3.[/green] Multi-Source IP Intelligence

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]IP Lookup[/bold]", border_style="yellow"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(4)], default="0")

    def show_port_menu(self) -> str:
        """Display Port Scanner submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold blue]🚪 PORT SCANNER[/bold blue]
  [green]1.[/green] Quick Port Scan (80, 443, 8080, 8443)
  [green]2.[/green] Custom Port Range Scan
  [green]3.[/green] Service Detection

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]Port Scanner[/bold]", border_style="blue"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(4)], default="0")

    def show_dns_menu(self) -> str:
        """Display DNS & SSL submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold red]🔎 DNS & SSL ANALYSIS[/bold red]
  [green]1.[/green] DNS Record Analysis
  [green]2.[/green] SSL Certificate Validation
  [green]3.[/green] Comprehensive DNS+SSL Audit

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]DNS & SSL[/bold]", border_style="red"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(4)], default="0")

    def show_file_menu(self) -> str:
        """Display File Management submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold white]📁 FILE MANAGEMENT[/bold white]
  [green]1.[/green] Split File
  [green]2.[/green] Merge Files
  [green]3.[/green] Deduplicate File
  [green]4.[/green] Filter & Clean File

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]File Management[/bold]", border_style="white"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(5)], default="0")

    def show_settings_menu(self) -> str:
        """Display Settings submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold cyan]⚙️  SETTINGS & UTILITIES[/bold cyan]
  [green]1.[/green] Configure Threads/Timeout
  [green]2.[/green] View Results
  [green]3.[/green] Export Options

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]Settings[/bold]", border_style="blue"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(4)], default="0")

    def show_advanced_tools_menu(self) -> str:
        """Display Advanced Tools submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold yellow]🛠️  ADVANCED TOOLS[/bold yellow]
  [green]1.[/green] ⚡ Payload Tester (20+ Tests)
  [green]2.[/green] 🌐 WebSocket Scanner
  [green]3.[/green] ☁️ CDN Detector
  [green]4.[/green] 🗺️ GeoIP & Whois Lookup
  [green]5.[/green] 🔐 Protocol & Cert Audit

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]Advanced Tools[/bold]", border_style="yellow"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(6)], default="0")

    def show_about_menu(self) -> str:
        """Display About & Update submenu."""
        self.console.clear()
        self.print_banner()
        menu_text = """
[bold cyan]🛡️  ABOUT & UPDATES[/bold cyan]
  [green]1.[/green] About Author
  [green]2.[/green] Check for Updates
  [green]3.[/green] Telegram Channel

  [red]0.[/red] Back to Main Menu
"""
        self.console.print(Panel(menu_text, title="[bold]About[/bold]", border_style="cyan"))
        return Prompt.ask("Select option", choices=[str(i) for i in range(4)], default="0")

    def show_about_me(self):
        """Display detailed about me information."""
        about_text = """
[bold yellow]Author Information[/bold yellow]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[cyan]Name:[/cyan] MR Yotopia(Yohanis)
[cyan]Bio:[/cyan] Computer Science Student & Security Enthusiast
[cyan]Origin:[/cyan] Ethiopia 🇪🇹
[cyan]Channel:[/cyan] @yt_netsa_official (35K+ Members)

[bold yellow]About This Tool[/bold yellow]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This tool is designed to help security researchers and 
network enthusiasts identify SNI bugs and analyze tunnel 
compatibility. It is part of the ongoing mission to provide 
free internet and tools for the community.

[dim]Thank you for your support![/dim]
"""
        self.console.print(Panel(about_text, title="[bold green]About Me[/bold green]", border_style="green"))

    def get_scan_config(self) -> dict:
        """Get scanning configuration from user."""
        config = {}
        
        self.console.print("\n[bold cyan]═══ Scan Configuration ═══[/bold cyan]\n")
        
        # Input source
        input_type = Prompt.ask(
            "Input type",
            choices=["file", "single", "list"],
            default="file"
        )
        
        if input_type == "file":
            config['input_file'] = Prompt.ask("Enter file path", default="list.txt")
        elif input_type == "single":
            config['single_host'] = Prompt.ask("Enter host (e.g., example.com or example.com:443)")
        else:
            config['hosts'] = []
            self.console.print("[dim]Enter hosts (one per line, empty line to finish):[/dim]")
            while True:
                host = Prompt.ask("Host", default="")
                if not host:
                    break
                config['hosts'].append(host)
        
        # Threads
        config["threads"] = int(
            Prompt.ask("Concurrent tasks", default=str(default_scan_threads()))
        )
        config["timeout"] = int(
            Prompt.ask("Timeout (seconds)", default=str(default_scan_timeout()))
        )
        
        # HTTP Method (for applicable scans)
        if Prompt.ask("Use custom HTTP method?", choices=["y", "n"], default="n") == "y":
            config['method'] = Prompt.ask(
                "HTTP Method",
                choices=["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"],
                default="GET"
            )
        
        # Custom payload
        if Prompt.ask("Add custom payload?", choices=["y", "n"], default="n") == "y":
            config['payload'] = Prompt.ask("Enter payload")
        
        return config

    def get_subdomain_config(self) -> dict:
        """Get subdomain enumeration configuration."""
        config = {}
        
        self.console.print("\n[bold magenta]═══ Subdomain Enumeration Config ═══[/bold magenta]\n")
        
        domain = Prompt.ask("Enter target domain (e.g., example.com)")
        config['domain'] = domain
        
        # API sources
        self.console.print("\n[dim]Available sources: crt.sh, hackertarget, threatcrowd, virustotal[/dim]")
        use_all = Prompt.ask("Use all sources?", choices=["y", "n"], default="y")
        
        if use_all == "y":
            config['sources'] = ['all']
        else:
            config['sources'] = Prompt.ask("Enter sources (comma-separated)").split(',')
        
        config['threads'] = int(Prompt.ask("Number of threads", default="5"))
        
        return config

    def get_ip_lookup_config(self) -> dict:
        """Get IP lookup configuration."""
        config = {}
        
        self.console.print("\n[bold yellow]═══ IP Lookup Configuration ═══[/bold yellow]\n")
        
        lookup_type = Prompt.ask(
            "Lookup type",
            choices=["single", "cidr", "file"],
            default="single"
        )
        
        if lookup_type == "single":
            config['ip'] = Prompt.ask("Enter IP address")
        elif lookup_type == "cidr":
            config['cidr'] = Prompt.ask("Enter CIDR range (e.g., 192.168.1.0/24)")
        else:
            config['file'] = Prompt.ask("Enter file path with IPs")
        
        config['reverse_dns'] = Prompt.ask("Include reverse DNS?", choices=["y", "n"], default="y") == "y"
        
        return config

    def get_port_scan_config(self) -> dict:
        """Get port scanning configuration."""
        config = {}
        
        self.console.print("\n[bold blue]═══ Port Scanner Configuration ═══[/bold blue]\n")
        
        target = Prompt.ask("Enter target host/IP")
        config['target'] = target
        
        scan_type = Prompt.ask(
            "Scan type",
            choices=["quick", "custom", "full"],
            default="quick"
        )
        
        if scan_type == "quick":
            config['ports'] = [80, 443, 8080, 8443]
        elif scan_type == "custom":
            ports_input = Prompt.ask("Enter ports (comma-separated or range like 80-100)")
            if '-' in ports_input:
                start, end = ports_input.split('-')
                config['ports'] = list(range(int(start), int(end) + 1))
            else:
                config['ports'] = [int(p.strip()) for p in ports_input.split(',')]
        else:
            config['ports'] = list(range(1, 65536))
        
        config["threads"] = int(
            Prompt.ask("Concurrent port checks", default=str(min(120, default_scan_threads())))
        )
        
        return config

    def get_dns_ssl_config(self) -> dict:
        """Get DNS/SSL analysis configuration."""
        config = {}
        
        self.console.print("\n[bold red]═══ DNS & SSL Analysis Configuration ═══[/bold red]\n")
        
        self.console.print("[dim]Hostname or host:port (e.g. example.com or edge.example.com:8443)[/dim]")
        config['host'] = Prompt.ask("Enter hostname")
        config['check_dns'] = Prompt.ask("Check DNS records?", choices=["y", "n"], default="y") == "y"
        config['check_ssl'] = Prompt.ask("Check SSL certificate?", choices=["y", "n"], default="y") == "y"
        config['check_sni'] = Prompt.ask("Check SNI compatibility?", choices=["y", "n"], default="y") == "y"
        
        return config

    def get_advanced_config(self, tool_name: str) -> dict:
        """Get configuration for advanced tools."""
        config = {}
        self.console.print(f"\n[bold yellow]═══ {tool_name} Configuration ═══[/bold yellow]\n")
        
        config['target'] = Prompt.ask("Enter target host (e.g., example.com)")
        
        if tool_name == "Payload Tester":
            config['port'] = int(Prompt.ask("Enter port", choices=["80", "443", "8080", "8443"], default="80"))
        elif tool_name == "WebSocket Scanner":
            config['port'] = int(Prompt.ask("Enter port", default="80"))
            config['path'] = Prompt.ask("Enter path", default="/")
            
        return config

    def get_file_operation_config(self, operation: str) -> dict:
        """Get file operation configuration."""
        config = {}
        
        self.console.print(f"\n[bold white]═══ {operation.upper()} Configuration ═══[/bold white]\n")
        
        if operation == "split":
            config['input_file'] = Prompt.ask("Enter input file path")
            config['lines_per_file'] = int(Prompt.ask("Lines per file", default="1000"))
            config['output_prefix'] = Prompt.ask("Output file prefix", default="split_")
            
        elif operation == "merge":
            self.console.print("[dim]Enter file paths to merge (empty line to finish):[/dim]")
            config['files'] = []
            while True:
                file = Prompt.ask("File path", default="")
                if not file:
                    break
                config['files'].append(file)
            config['output_file'] = Prompt.ask("Output file path", default="merged.txt")
            
        elif operation == "deduplicate":
            config['input_file'] = Prompt.ask("Enter input file path")
            config['output_file'] = Prompt.ask("Output file path", default="deduped.txt")
            config['case_sensitive'] = Prompt.ask("Case sensitive?", choices=["y", "n"], default="n") == "y"
            
        elif operation == "filter":
            config['input_file'] = Prompt.ask("Enter input file path")
            config['output_file'] = Prompt.ask("Output file path", default="filtered.txt")
            config['filter_type'] = Prompt.ask(
                "Filter type",
                choices=["contains", "regex", "length", "startswith", "endswith"],
                default="contains"
            )
            config['filter_value'] = Prompt.ask("Filter value/pattern")
        
        return config

    def create_live_display(self) -> Live:
        """Returns a Live display with a fresh table (only working hosts are listed during scan)."""
        self.reset_scan_table()
        return Live(self.table, console=self.console, refresh_per_second=4)

    def add_result(self, result: dict):
        """Record a probe result; live table lists WORKING hosts only (with a row cap)."""
        self._scan_total += 1
        is_working = result.get("status") == "WORKING"

        if is_working:
            self._scan_working += 1

        if is_working and self._live_working_rows < self._MAX_LIVE_WORKING_ROWS:
            details = (result.get("server_header") or "")[:40]
            if result.get("modes"):
                details = ", ".join(result["modes"])
            self.table.add_row(
                result.get("host", "N/A"),
                str(result.get("port", 443)),
                "[green]WORKING[/green]",
                result.get("tls", "N/A"),
                details,
            )
            self._live_working_rows += 1

        cap = (
            f"Probed: {self._scan_total} | Working: {self._scan_working} "
            f"(live: working hosts only"
        )
        if self._scan_working > self._MAX_LIVE_WORKING_ROWS:
            cap += f"; table shows first {self._MAX_LIVE_WORKING_ROWS}"
        cap += ")"
        self.table.caption = f"[dim]{cap}[/dim]"

    def show_progress(self, total: int, description: str = "Processing"):
        """Create and return a progress bar."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        )

    def display_results_summary(self, results: List[dict]):
        """Display a summary of scan results."""
        if not results:
            self.console.print("[yellow]No results to display.[/yellow]")
            return
        
        total = len(results)
        working = sum(1 for r in results if r.get('status') == 'WORKING')
        failed = total - working
        
        summary = f"""
[bold]Scan Summary[/bold]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Hosts Scanned: [cyan]{total}[/cyan]
Working Hosts: [green]{working}[/green]
Failed Hosts: [red]{failed}[/red]
Success Rate: [yellow]{(working/total*100):.2f}%[/yellow]
"""
        self.console.print(Panel(summary, border_style="green"))

    def print_dns_records_table(self, records: dict, title: str):
        """Formatted DNS record set (parallel-resolved)."""
        table = Table(title=title, box=box.ROUNDED, header_style="bold red", show_lines=True)
        table.add_column("Type", style="cyan", no_wrap=True, width=8)
        table.add_column("Data", style="white")
        any_rows = False
        for rtype in self.record_types_order(records):
            rdata = records.get(rtype) or []
            if not rdata:
                continue
            any_rows = True
            body = "\n".join(rdata[:15])
            if len(rdata) > 15:
                body += f"\n[dim]… {len(rdata) - 15} more[/dim]"
            table.add_row(rtype, body)
        if not any_rows:
            self.console.print(Panel("[yellow]No DNS records returned.[/yellow]", title=title, border_style="yellow"))
        else:
            self.console.print(table)

    @staticmethod
    def record_types_order(records: dict) -> List[str]:
        preferred = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR"]
        keys = [k for k in preferred if k in records]
        keys.extend(sorted(k for k in records.keys() if k not in keys))
        return keys

    def print_ssl_analysis_summary_table(self, results: List[dict]):
        """Compact overview for many hosts."""
        table = Table(
            title="[bold cyan]SSL / SNI analysis — summary[/bold cyan]",
            box=box.ROUNDED,
            header_style="bold cyan",
            show_lines=False,
        )
        table.add_column("Target", style="cyan", no_wrap=True, max_width=34, overflow="ellipsis")
        table.add_column("Status", max_width=10)
        table.add_column("HTTP", style="magenta", justify="center", max_width=6)
        table.add_column("TLS", style="green", max_width=12, overflow="ellipsis")
        table.add_column("Cipher", style="dim", max_width=20, overflow="ellipsis")
        table.add_column("WebSocket", style="yellow", max_width=22, overflow="ellipsis")
        table.add_column("Cert / expiry", max_width=26, overflow="ellipsis")

        for r in results:
            target = f"{r.get('host', '?')}:{r.get('port', 443)}"
            ok = r.get("ok")
            st = "[green]OK[/green]" if ok else "[red]Fail[/red]"
            cert = r.get("certificate") or {}
            days = cert.get("days_remaining")
            if days is not None:
                if days < 0:
                    cert_cell = f"[red]expired ({-days}d)[/red]"
                elif days < 14:
                    cert_cell = f"[yellow]{days}d left[/yellow]"
                else:
                    cert_cell = f"[dim]{days}d left[/dim]"
            else:
                cert_cell = (cert.get("not_after") or "—")[:22]
            cn = (cert.get("subject_cn") or "")[:18]
            if cn and cn != "—":
                cert_cell = f"{cn} · {cert_cell}"

            table.add_row(
                target,
                st,
                str(r.get("http_status", "—")),
                str(r.get("tls_version", "—")),
                str(r.get("cipher", "—")),
                str(r.get("websocket", "—")),
                cert_cell,
            )
        self.console.print(table)

    def print_ssl_analysis_detail_panels(self, result: dict):
        """Full breakdown for one target (professional layout)."""
        target = f"{result.get('host', '?')}:{result.get('port', 443)}"
        if result.get("error"):
            self.console.print(
                Panel(
                    f"[red bold]{result['error']}[/red bold]\n"
                    f"[dim]TLS:[/dim] {result.get('tls_version', '—')}  [dim]Cipher:[/dim] {result.get('cipher', '—')}\n"
                    f"[dim]WebSocket probe:[/dim] {result.get('websocket', '—')}",
                    title=f"[bold white on red] SSL/SNI — {target} [/bold white on red]",
                    border_style="red",
                    subtitle="[dim]HTTP probe did not complete successfully[/dim]",
                )
            )
            cert = result.get("certificate") or {}
            if cert.get("subject_cn") not in (None, "—", ""):
                self._print_cert_table(cert, f"Certificate (if any) — {target}")
            return

        conn = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        conn.add_column("k", style="cyan", justify="right")
        conn.add_column("v", style="white")
        conn.add_row("HTTP status", str(result.get("http_status", "—")))
        conn.add_row("TLS version", str(result.get("tls_version", "—")))
        conn.add_row("Cipher", str(result.get("cipher", "—")))
        conn.add_row("Server hint", (result.get("server_header") or "—")[:120])
        conn.add_row("WebSocket", str(result.get("websocket", "—")))
        modes = ", ".join(result.get("modes") or [])
        conn.add_row("Modes", modes or "—")

        self.console.print(
            Panel(
                conn,
                title=f"[bold]TLS & HTTP probe — {target}[/bold]",
                border_style="green",
                subtitle="[dim]SNI + HEAD/HTTP line · WebSocket upgrade tested in parallel[/dim]",
            )
        )
        self._print_cert_table(result.get("certificate") or {}, f"Certificate — {target}")

    def _print_cert_table(self, cert: dict, title: str):
        t = Table(show_header=False, box=box.ROUNDED, show_edge=True, padding=(0, 1))
        t.add_column("Field", style="cyan", width=14)
        t.add_column("Value", style="white")
        t.add_row("Subject (CN)", str(cert.get("subject_cn", "—")))
        t.add_row("Issuer", str(cert.get("issuer_cn", "—")))
        t.add_row("Valid from", str(cert.get("not_before", "—")))
        t.add_row("Valid to", str(cert.get("not_after", "—")))
        t.add_row("SAN (preview)", str(cert.get("san_preview", "—")))
        days = cert.get("days_remaining")
        if days is not None:
            style = "red" if days < 0 else "yellow" if days < 30 else "green"
            t.add_row("Validity", f"[{style}]{days} days[/{style}] relative to UTC")
        self.console.print(Panel(t, title=f"[bold]{title}[/bold]", border_style="blue"))

    def print_protocol_audit_report(self, result: dict, title: str):
        """TLS cert + HTTP/2 / Alt-Svc summary from ProtocolAudit."""
        info = result.get("ssl_info") or {}
        sub = info.get("subject") or {}
        iss = info.get("issuer") or {}
        has_cert = bool(sub or iss or info.get("notAfter") or info.get("notBefore"))
        protos = result.get("protocols") or []
        err = result.get("error")

        if err and not has_cert and not protos:
            self.console.print(Panel(f"[red]{err}[/red]", title=title, border_style="red"))
            return

        top = Table(show_header=False, box=box.SIMPLE)
        top.add_column("k", style="cyan")
        top.add_column("v", style="white")
        top.add_row("HTTP layers", ", ".join(protos) if protos else "—")
        top.add_row("Subject CN", str(sub.get("commonName", sub.get("CN", "—"))))
        top.add_row("Issuer", str(iss.get("commonName", iss.get("organizationName", "—"))))
        top.add_row("Not before", str(info.get("notBefore", "—")))
        top.add_row("Not after", str(info.get("notAfter", "—")))
        if err:
            top.add_row("[yellow]Note[/yellow]", str(err))

        self.console.print(Panel(top, title=f"[bold]{title}[/bold]", border_style="magenta"))

    def pause(self):
        """Pause and wait for user input."""
        Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")