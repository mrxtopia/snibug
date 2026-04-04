#!/usr/bin/env bash
#
# Android Termux installer for MR YT Bug Scanner
#
# ON THE PHONE, PREFER (avoids Windows CRLF / $'\r' errors):
#   bash install_termux.sh
#
# Or fix line endings once, then:
# sed -i 's/\r$//' termux_setup.sh && bash termux_setup.sh
#
# Termux: use F-Droid or GitHub builds (not old Play Store app).
#

# --- SECURITY CONFIG ---
PASS_HASH="23649522fc9d0086da52d0608d6f420ff8b837081e8e4386d1e908a00aaf7b50"
GITHUB_URL="https://github.com/mrxtopia/snibug"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.mryt-scanner}"
# -----------------------

TERMUX_OK=0
[ -n "${TERMUX_VERSION:-}" ] && TERMUX_OK=1
[ -d /data/data/com.termux ] && TERMUX_OK=1
case "${PREFIX:-}" in
    *com.termux*) TERMUX_OK=1 ;;
esac
if [ "$TERMUX_OK" != 1 ]; then
    echo "This installer is for Termux on Android only."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

if ! command -v sha256sum >/dev/null 2>&1; then
    pkg install -y coreutils
fi

clear
echo -e "\e[1;36m=== MR YT BUG SCANNER - TERMUX (ANDROID) ===\e[0m"
echo -e "\e[1;37mProject: $SCRIPT_DIR\e[0m"
echo -e "\e[1;37mInstall: $INSTALL_DIR\e[0m"
echo ""

if [ "${SNIBUG_SKIP_INSTALLER_KEY:-}" = "1" ]; then
    echo -e "\e[1;33mSkipping key check (SNIBUG_SKIP_INSTALLER_KEY=1)\e[0m"
else
    echo -en "\e[1;33mSecurity key: \e[0m"
    read -rs entered_pass
    echo ""
    input_hash=$(printf '%s' "$entered_pass" | sha256sum | cut -d ' ' -f 1)
    if [ "$input_hash" != "$PASS_HASH" ]; then
        echo -e "\e[1;31mInvalid key. Contact @mrxtopia\e[0m"
        exit 1
    fi
    echo -e "\e[1;32mKey OK\e[0m"
fi

sleep 0.5

export DEBIAN_FRONTEND=noninteractive
echo -e "\e[1;34m[*] pkg update / upgrade ...\e[0m"
pkg update -y
pkg upgrade -y

echo -e "\e[1;34m[*] pkg install python deps ...\e[0m"
pkg install -y python git openssl libffi clang make libxml2 libxslt
pkg install -y python-pip 2>/dev/null || true

echo -e "\e[1;34m[*] Copy to $INSTALL_DIR ...\e[0m"
mkdir -p "$INSTALL_DIR"
if [ "$(readlink -f "$SCRIPT_DIR" 2>/dev/null || echo "$SCRIPT_DIR")" = "$(readlink -f "$INSTALL_DIR" 2>/dev/null || echo "$INSTALL_DIR")" ]; then
    echo -e "\e[1;33m[i] Same dir as install target - skip copy\e[0m"
else
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --exclude='.git' "$SCRIPT_DIR/" "$INSTALL_DIR/"
    else
        (cd "$SCRIPT_DIR" && cp -a . "$INSTALL_DIR/")
    fi
fi

cd "$INSTALL_DIR" || exit 1
if [ ! -f main.py ]; then
    echo -e "\e[1;31mNo main.py. Clone repo then run from snibug folder:\e[0m"
    echo "  git clone $GITHUB_URL && cd snibug && bash install_termux.sh"
    exit 1
fi

echo -e "\e[1;34m[*] pip ...\e[0m"
python3 -m ensurepip --upgrade 2>/dev/null || true
python3 -m pip install --upgrade pip setuptools wheel

if [ -f requirements.txt ]; then
    python3 -m pip install --no-cache-dir -r requirements.txt || {
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
echo -e "\e[1;33mTip: termux-setup-storage  ->  ~/storage/downloads\e[0m"
echo ""

MARK="# snibug-mryt-alias"
if [ -f "$HOME/.bashrc" ] && grep -qF "alias mryt=" "$HOME/.bashrc" 2>/dev/null; then
    echo -e "\e[1;33m[i] mryt alias already in .bashrc\e[0m"
else
    { echo ""; echo "$MARK"; echo "alias mryt='python3 $INSTALL_DIR/main.py --ui'"; } >> "$HOME/.bashrc"
fi

rm -f .setup_success
printf '%s' "INSTALLED_BY_MRYT_INSTALLER_2026" > .setup_success
chmod 400 .setup_success 2>/dev/null || chmod 600 .setup_success

echo ""
echo -e "\e[1;32mDone. Run: source ~/.bashrc  then  mryt\e[0m"
echo -e "\e[1;37mOr: python3 $INSTALL_DIR/main.py --ui\e[0m"
