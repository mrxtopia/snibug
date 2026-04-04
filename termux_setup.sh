#!/usr/bin/env bash
#
# MR YT Bug Scanner - INSTALLER FOR ANDROID + TERMUX ONLY
#
# Prerequisites:
#   - Termux from F-Droid (recommended) or official GitHub builds.
#   - Do NOT use the old Play Store Termux (unmaintained).
#
# Usage (on your phone, inside Termux):
#   cd ~/snibug
#   bash termux_setup.sh
#
# Line endings must be LF (Unix). If you see $'\r' errors on Android:
#   sed -i 's/\r$//' termux_setup.sh && bash termux_setup.sh
#

# --- SECURITY CONFIG ---
PASS_HASH="23649522fc9d0086da52d0608d6f420ff8b837081e8e4386d1e908a00aaf7b50"
GITHUB_URL="https://github.com/mrxtopia/snibug"
# Install under Termux home (Android sandbox - normal path)
INSTALL_DIR="${INSTALL_DIR:-$HOME/.mryt-scanner}"
# -----------------------

# Must run inside Termux on Android (detect a few common cases)
TERMUX_OK=0
[ -n "${TERMUX_VERSION:-}" ] && TERMUX_OK=1
[ -d /data/data/com.termux ] && TERMUX_OK=1
case "${PREFIX:-}" in
    *com.termux*) TERMUX_OK=1 ;;
esac
if [ "$TERMUX_OK" != 1 ]; then
    echo ""
    echo "This installer is for Termux on Android."
    echo "Install Termux from F-Droid (or GitHub builds), open the app, then run:"
    echo "  cd ~/snibug && bash termux_setup.sh"
    echo ""
    exit 1
fi

# Directory containing this script (repo root when you cloned snibug)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# sha256sum is required for the key check
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "[*] Installing coreutils (sha256sum)..."
    pkg install -y coreutils
fi

clear
echo -e "\e[1;36m╔═══════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[1;36m║     MR YT BUG SCANNER - ANDROID (TERMUX) INSTALLER    ║\e[0m"
echo -e "\e[1;36m╚═══════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[1;32m      (C) 2026 @mrxtopia | Private Security\e[0m"
echo -e "\e[1;30m      Device: Termux on Android\e[0m"
echo ""
echo -e "\e[1;37m[i] Project folder:  \e[1;33m$SCRIPT_DIR\e[0m"
echo -e "\e[1;37m[i] Install goes to: \e[1;33m$INSTALL_DIR\e[0m"
echo ""

# Optional: skip license check (your own fork / dev)
if [ "${SNIBUG_SKIP_INSTALLER_KEY:-}" = "1" ]; then
    echo -e "\e[1;33m[!] SNIBUG_SKIP_INSTALLER_KEY=1 - skipping key check (dev/fork only)\e[0m"
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

echo -e "\e[1;34m[*] Updating Termux packages (Wi-Fi recommended; may take several minutes)...\e[0m"
export DEBIAN_FRONTEND=noninteractive
pkg update -y
pkg upgrade -y

echo -e "\e[1;34m[*] Installing packages for Python on Android (Termux)...\e[0m"
pkg install -y python git openssl libffi clang make libxml2 libxslt
pkg install -y python-pip 2>/dev/null || true

echo -e "\e[1;34m[*] Copying snibug into $INSTALL_DIR ...\e[0m"
mkdir -p "$INSTALL_DIR"
if [ "$(readlink -f "$SCRIPT_DIR" 2>/dev/null || echo "$SCRIPT_DIR")" = "$(readlink -f "$INSTALL_DIR" 2>/dev/null || echo "$INSTALL_DIR")" ]; then
    echo -e "\e[1;33m[i] Already in install directory - skipping copy.\e[0m"
else
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude='.git' "$SCRIPT_DIR/" "$INSTALL_DIR/"
    else
        (cd "$SCRIPT_DIR" && cp -a . "$INSTALL_DIR/")
    fi
fi

cd "$INSTALL_DIR" || { echo "Cannot cd to $INSTALL_DIR"; exit 1; }

if [ ! -f main.py ]; then
    echo -e "\e[1;31m[!] main.py missing. On Android Termux, clone or cd into the snibug folder first:\e[0m"
    echo -e "\e[1;33m    cd ~ && git clone $GITHUB_URL && cd snibug && bash termux_setup.sh\e[0m"
    exit 1
fi

echo -e "\e[1;34m[*] Python pip (inside Termux)...\e[0m"
python3 -m ensurepip --upgrade 2>/dev/null || true
python3 -m pip install --upgrade pip setuptools wheel

echo -e "\e[1;34m[*] Installing Python libraries (may compile on device; be patient)...\e[0m"
if [ -f requirements.txt ]; then
    python3 -m pip install --no-cache-dir -r requirements.txt || {
        echo -e "\e[1;33m[!] requirements.txt failed - installing minimal set...\e[0m"
        python3 -m pip install --no-cache-dir \
            aiohttp dnspython python-whois requests beautifulsoup4 lxml rich websockets httpx colorama aiofiles
    }
else
    python3 -m pip install --no-cache-dir \
        aiohttp dnspython python-whois requests beautifulsoup4 lxml rich websockets httpx colorama aiofiles \
        geoip2 maxminddb
fi

chmod +x main.py 2>/dev/null || true

echo ""
echo -e "\e[1;34m[*] Android tips:\e[0m"
echo -e "    - Export to Downloads: run \e[1;33mtermux-setup-storage\e[0m once, then use ~/storage/downloads"
echo -e "    - Long installs: keep screen on or run \e[1;33mtermux-wake-lock\e[0m (then \e[1;33mtermux-wake-unlock\e[0m when done)"
echo ""

echo -e "\e[1;34m[*] Adding \e[1;33mmryt\e[0m shortcut to ~/.bashrc ...\e[0m"
MARK="# snibug-mryt-alias-android"
if [ -f "$HOME/.bashrc" ] && grep -qF "alias mryt=" "$HOME/.bashrc" 2>/dev/null; then
    echo -e "\e[1;33m[i] alias mryt already present - skipping\e[0m"
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
echo -e "\e[1;32m[OK] Install finished on Android Termux.\e[0m"
echo -e "\e[1;37m[i] Reload: \e[1;32msource ~/.bashrc\e[0m"
echo -e "\e[1;37m[i] Start:  \e[1;32mmryt\e[0m"
echo -e "\e[1;37m[i] Or:     \e[1;32mpython3 $INSTALL_DIR/main.py --ui\e[0m"
echo ""
echo -e "\e[1;33m[!] Tamper protection is active - do not edit protected files, or reinstall from $GITHUB_URL\e[0m"
