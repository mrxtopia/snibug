#!/data/data/com.termux/files/usr/bin/bash

# MR YT Bug Scanner - Secure Installer
# Created by: @mrxtopia

# --- SECURITY CONFIG ---
# SHA256 of "MRYT": 724725c8287af3fe86707a3c301c8008779901d8984992790938361049b45e98
PASS_HASH="724725c8287af3fe86707a3c301c8008779901d8984992790938361049b45e98"
GITHUB_URL="https://github.com/mrxtopia/snibug"
INSTALL_DIR="$HOME/mr-yt-scanner"
# -----------------------

clear
echo -e "\e[1;36m╔═══════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[1;36m║           MR YT BUG SCANNER INSTALLER                 ║\e[0m"
echo -e "\e[1;36m╚═══════════════════════════════════════════════════════╝\e[0m"
echo -e "\e[1;32m      (C) 2026 @mrxtopia | Private Security\e[0m"
echo ""

# Password Check
echo -en "\e[1;33m[?] Enter Security Key: \e[0m"
read -s entered_pass
echo ""

# Encrypting input for check
input_hash=$(echo -n "$entered_pass" | sha256sum | cut -d ' ' -f 1)

if [ "$input_hash" != "$PASS_HASH" ]; then
    echo -e "\e[1;31m[!] SECURITY BREACH DETECTED!\e[0m"
    echo -e "\e[1;31m[!] Invalid license key for this device.\e[0m"
    echo ""
    echo -e "\e[1;37m[!] Contact Admin to get your key: \e[1;32m@mrxtopia\e[0m"
    echo -e "\e[1;37m[!] User identification: \e[1;33m$(whoami)_$(date +%s)\e[0m"
    exit 1
fi

echo -e "\e[1;32m[+] Key Verified! decrypting core files...\e[0m"
sleep 1.5

# Dependencies
echo -e "\e[1;34m[*] Installing tool dependencies...\e[0m"
pkg update -y && pkg upgrade -y
pkg install -y python git openssl libffi clang make

# Setup Directory
echo -e "\e[1;34m[*] Setting up local environment...\e[0m"
mkdir -p "$INSTALL_DIR"
cp -r ./* "$INSTALL_DIR/" 2>/dev/null
cd "$INSTALL_DIR"

# Python Libraries
echo -e "\e[1;34m[*] Installing Python requirements...\e[0m"
python3 -m pip install --upgrade pip
python3 -m pip install aiohttp asyncio dnspython python-whois requests beautifulsoup4 lxml rich websockets geoip2 httpx maxminddb

# Permissions
chmod +x main.py
termux-setup-storage

# Shortcut
echo -e "\e[1;34m[*] Finalizing setup...\e[0m"
if ! grep -q "alias mryt=" ~/.bashrc; then
    echo "alias mryt='cd $INSTALL_DIR && python3 main.py --ui'" >> ~/.bashrc
fi

echo -e "\e[1;32m[✔] MR YT Bug Scanner Installed Successfully!\e[0m"
echo -e "\e[1;37m[i] Run: \e[1;32msource ~/.bashrc\e[0m"
echo -e "\e[1;37m[i] Type \e[1;32mmryt\e[0m to start the tool."
echo ""
echo -e "\e[1;33m[!] WARNING: Any modification to tool files will trigger a lockdown.\e[0m"
echo -e "\e[1;33m[!] Re-install: $GITHUB_URL\e[0m"
