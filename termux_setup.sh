#!/usr/bin/env bash
# MR YT Bug Scanner — Termux installer
# Run from the repo folder:  bash termux_setup.sh
# Or:  bash /path/to/snibug/termux_setup.sh

# --- SECURITY CONFIG ---
PASS_HASH="23649522fc9d0086da52d0608d6f420ff8b837081e8e4386d1e908a00aaf7b50"
GITHUB_URL="https://github.com/mrxtopia/snibug"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.mryt-scanner}"
# -----------------------

# Directory this script lives in (fixes "empty install" when bash /other/path/termux_setup.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

clear
echo -e "\e[1;36m╔═══════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[1;36m║           MR YT BUG SCANNER INSTALLER                 ║\e[0m"
echo -e "\e[1;36m╚═══════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[1;32m      (C) 2026 @mrxtopia | Private Security\e[0m"
echo ""
echo -e "\e[1;37m[i] Source files from: \e[1;33m$SCRIPT_DIR\e[0m"
echo -e "\e[1;37m[i] Install target:   \e[1;33m$INSTALL_DIR\e[0m"
echo ""

# Optional: skip license check for your own fork (export SNIBUG_SKIP_INSTALLER_KEY=1)
if [ "${SNIBUG_SKIP_INSTALLER_KEY:-}" = "1" ]; then
    echo -e "\e[1;33m[!] SNIBUG_SKIP_INSTALLER_KEY=1 — skipping key check (dev/fork only)\e[0m"
else
    echo -en "\e[1;33m[?] Enter Security Key: \e[0m"
    read -rs entered_pass
    echo ""
    input_hash=$(printf '%s' "$entered_pass" | sha256sum | cut -d ' ' -f 1)
    if [ "$input_hash" != "$PASS_HASH" ]; then
        echo -e "\e[1;31m[!] Invalid security key.\e[0m"
        echo -e "\e[1;37m[!] Contact: \e[1;32m@mrxtopia\e[0m"
        exit 1
    fi
    echo -e "\e[1;32m[+] Key verified.\e[0m"
fi

sleep 0.5

echo -e "\e[1;34m[*] Updating packages (this may take a few minutes)...\e[0m"
export DEBIAN_FRONTEND=noninteractive
pkg update -y
pkg upgrade -y

echo -e "\e[1;34m[*] Installing system dependencies...\e[0m"
pkg install -y python git openssl libffi clang make libxml2 libxslt
# Optional: pip as Termux package when available (ignore if unknown package)
pkg install -y python-pip 2>/dev/null || true

echo -e "\e[1;34m[*] Copying project to $INSTALL_DIR ...\e[0m"
mkdir -p "$INSTALL_DIR"
if [ "$(readlink -f "$SCRIPT_DIR" 2>/dev/null || echo "$SCRIPT_DIR")" = "$(readlink -f "$INSTALL_DIR" 2>/dev/null || echo "$INSTALL_DIR")" ]; then
    echo -e "\e[1;33m[i] Already running from install dir — skipping file copy.\e[0m"
else
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude='.git' "$SCRIPT_DIR/" "$INSTALL_DIR/"
    else
        (cd "$SCRIPT_DIR" && cp -a . "$INSTALL_DIR/")
    fi
fi

cd "$INSTALL_DIR" || { echo "Cannot cd to $INSTALL_DIR"; exit 1; }

if [ ! -f main.py ]; then
    echo -e "\e[1;31m[!] main.py not found after copy. Run this script from the snibug project root.\e[0m"
    echo -e "\e[1;33m    cd /path/to/snibug && bash termux_setup.sh\e[0m"
    exit 1
fi

echo -e "\e[1;34m[*] Bootstrapping pip...\e[0m"
python3 -m ensurepip --upgrade 2>/dev/null || true
python3 -m pip install --upgrade pip setuptools wheel

echo -e "\e[1;34m[*] Installing Python packages...\e[0m"
# Do not install "asyncio" from PyPI — it is stdlib and breaks/conflicts on Termux.
if [ -f requirements.txt ]; then
    python3 -m pip install --no-cache-dir -r requirements.txt || {
        echo -e "\e[1;33m[!] requirements.txt failed; installing core set...\e[0m"
        python3 -m pip install --no-cache-dir \
            aiohttp dnspython python-whois requests beautifulsoup4 lxml rich websockets httpx colorama aiofiles
    }
else
    python3 -m pip install --no-cache-dir \
        aiohttp dnspython python-whois requests beautifulsoup4 lxml rich websockets httpx colorama aiofiles \
        geoip2 maxminddb
fi

chmod +x main.py 2>/dev/null || true

# Storage prompt blocks automation — offer optional step
if [ -t 0 ] && [ -t 1 ]; then
    echo -e "\e[1;34m[*] Optional: grant storage (for exporting results to Downloads). Run if you need it:\e[0m"
    echo -e "\e[1;33m    termux-setup-storage\e[0m"
else
    echo -e "\e[1;33m[i] Non-interactive shell: skipped termux-setup-storage (run manually if needed).\e[0m"
fi

echo -e "\e[1;34m[*] Shell shortcut (mryt)...\e[0m"
MARK="# snibug-mryt-alias"
if [ -f "$HOME/.bashrc" ] && grep -qF "alias mryt=" "$HOME/.bashrc" 2>/dev/null; then
    echo -e "\e[1;33m[i] alias mryt already in ~/.bashrc — skipping\e[0m"
else
    {
        echo ""
        echo "$MARK"
        echo "alias mryt='python3 $INSTALL_DIR/main.py --ui'"
    } >> "$HOME/.bashrc"
fi

rm -f .setup_success
printf '%s' "INSTALLED_BY_MRYT_INSTALLER_2026" > .setup_success
chmod 400 .setup_success 2>/dev/null || chmod 600 .setup_success

echo ""
echo -e "\e[1;32m[✔] Install finished.\e[0m"
echo -e "\e[1;37m[i] Reload shell: \e[1;32msource ~/.bashrc\e[0m"
echo -e "\e[1;37m[i] Start UI:      \e[1;32mmryt\e[0m"
echo -e "\e[1;37m[i] Or:            \e[1;32mpython3 $INSTALL_DIR/main.py --ui\e[0m"
echo ""
echo -e "\e[1;33m[!] Core file edits trigger tamper protection — reinstall from $GITHUB_URL if needed.\e[0m"
