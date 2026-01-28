# Advanced Free-Internet SNI Bug Scanner Suite

A modular, multi-tool reconnaissance suite for discovering and validating bug hosts (SNI, TLS, usage) for tunneling. Designed for Termux, Linux, Windows, and macOS.

## Features
- **SNI Scanner**: Discover working SNI hosts.
- **Host Analyzer**: Detects tunnel modes (Direct, SSH+TLS, WS/WSS, etc.).
- **Multi-threaded/Async**: High performance scanning.
- **Cross-Platform**: Works on Android (Termux), Windows, Linux.
- **Smart Output**: Live tables, JSON/CSV/Config exports.

## Installation

### Termux (Android)
```bash
git clone https://github.com/mrxtopia/snibug.git
cd snibug
bash termux_setup.sh
```

## Usage
```bash
# Scan a list of hosts for SNI
python main.py --scan-sni --input list.txt

# Analyze a specific host
python main.py --analyze bug.example.com

# Open the interactive menu
python main.py --ui
```

## Modules
- **SNI Scanner**: Validates SSL/TLS handshakes.
- **CDN Detector**: Identifies Cloudflare, Cloudfront, Akamai, etc.
- **Zero-Rate Tester**: Heuristics for free data capabilities.

