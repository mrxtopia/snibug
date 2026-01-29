from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.prompt import Prompt, Confirm
from rich.text import Text
from typing import List, Optional

class AppUI:
    def __init__(self):
        self.console = Console()
        self.table = Table(show_header=True, header_style="bold magenta")
        self.layout = Layout()
        
        # Setup Table Columns
        self.table.add_column("Host", style="cyan", no_wrap=True)
        self.table.add_column("Port", style="magenta")
        self.table.add_column("Status", style="green")
        self.table.add_column("TLS", style="yellow")
        self.table.add_column("Details", style="white")


    def print_banner(self):
        banner_text = """
    [bold cyan]╔═══════════════════════════════════════════════════════╗[/bold cyan]
    [bold cyan]║           MR YT Bug Scanner                          ║[/bold cyan]
    [bold cyan]╚═══════════════════════════════════════════════════════╝[/bold cyan]
    [bold green]   Telegram: @mrxtopia[/bold green]
    [dim]   v2.0.0 - Multi-Platform Reconnaissance Suite[/dim]
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
        config['threads'] = int(Prompt.ask("Number of threads", default="10"))
        
        # Timeout
        config['timeout'] = int(Prompt.ask("Timeout (seconds)", default="10"))
        
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
        
        config['threads'] = int(Prompt.ask("Number of threads", default="50"))
        
        return config

    def get_dns_ssl_config(self) -> dict:
        """Get DNS/SSL analysis configuration."""
        config = {}
        
        self.console.print("\n[bold red]═══ DNS & SSL Analysis Configuration ═══[/bold red]\n")
        
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
        """Returns a Live object to be used as a context manager."""
        return Live(self.table, console=self.console, refresh_per_second=4)

    def add_result(self, result: dict):
        """Adds a result row to the table."""
        status_style = "green" if result.get('status') == "WORKING" else "red"
        
        details = result.get('server_header', '')[:20]
        if 'modes' in result and result['modes']:
            details = ", ".join(result['modes'])
            
        self.table.add_row(
            result.get('host', 'N/A'),
            str(result.get('port', 443)),
            f"[{status_style}]{result.get('status', 'UNKNOWN')}[/{status_style}]",
            result.get('tls', 'N/A'),
            details
        )

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

    def pause(self):
        """Pause and wait for user input."""
        Prompt.ask("\n[dim]Press Enter to continue...[/dim]", default="")