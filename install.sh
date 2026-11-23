#!/bin/bash
# ============================================================
#  WebScan Pro v11.5 — Auto Installer for Kali Linux
#  Usage: chmod +x install.sh && sudo bash install.sh
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; RESET='\033[0m'

echo -e "${RED}"
cat << 'EOF'
 __        __   _     ____
 \ \      / /__| |__ / ___|  ___ __ _ _ __
  \ \ /\ / / _ \ '_ \\___ \ / __/ _` | '_ \
   \ V  V /  __/ |_) |___) | (_| (_| | | | |
    \_/\_/ \___|_.__/|____/ \___\__,_|_| |_|
  ____
 |  _ \ _ __ ___
 | |_) | '__/ _ \
 |  __/| | | (_) |
 |_|   |_|  \___/   v11.7 Installer
EOF
echo -e "${RESET}"
echo -e "${CYAN}  WebScan Pro v11.7 — Kali Linux Installer${RESET}"
echo -e "${WHITE}  ─────────────────────────────────────────${RESET}"

# ── Root check ───────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}  [!] Please run as root: sudo bash install.sh${RESET}"
    exit 1
fi

INSTALL_DIR="/opt/webscan_pro"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${CYAN}  [1/7] Updating apt package list...${RESET}"
apt-get update -qq 2>/dev/null && echo -e "${GREEN}  [✓] apt updated${RESET}" || echo -e "${YELLOW}  [!] apt update warning (continuing)${RESET}"

echo -e "\n${CYAN}  [2/7] Installing system packages...${RESET}"
SYSTEM_PKGS="python3 python3-pip python3-dev libxml2-dev libxslt1-dev zlib1g-dev libffi-dev libssl-dev dnsutils nmap curl git"
for pkg in $SYSTEM_PKGS; do
    if dpkg -l "$pkg" &>/dev/null; then
        echo -e "${GREEN}  [✓] $pkg already installed${RESET}"
    else
        apt-get install -y -qq "$pkg" && echo -e "${GREEN}  [✓] $pkg installed${RESET}" || echo -e "${YELLOW}  [!] $pkg failed (optional)${RESET}"
    fi
done

echo -e "\n${CYAN}  [3/7] Installing core Python packages...${RESET}"
CORE_PKGS="requests colorama urllib3"
for pkg in $CORE_PKGS; do
    pip3 install "$pkg" --break-system-packages -q && echo -e "${GREEN}  [✓] $pkg${RESET}" || echo -e "${RED}  [✗] $pkg FAILED${RESET}"
done

echo -e "\n${CYAN}  [4/7] Installing optional Python packages...${RESET}"
OPT_PKGS="beautifulsoup4 dnspython lxml weasyprint tldextract"
for pkg in $OPT_PKGS; do
    pip3 install "$pkg" --break-system-packages -q \
        && echo -e "${GREEN}  [✓] $pkg${RESET}" \
        || echo -e "${YELLOW}  [~] $pkg failed (optional — some features unavailable)${RESET}"
done

echo -e "\n${CYAN}  [5/7] Setting up install directory...${RESET}"
mkdir -p "$INSTALL_DIR"
# Default report output directory (auto-created by tool, but create now)
mkdir -p "$HOME/webscan-reports"
echo -e "${GREEN}  [✓] Report directory: $HOME/webscan-reports${RESET}"

cp "$SCRIPT_DIR/webscan_pro.py" "$INSTALL_DIR/" 2>/dev/null \
    || { echo -e "${YELLOW}  [!] webscan_pro.py not found next to install.sh — copy it to $INSTALL_DIR manually${RESET}"; }

# Copy wordlist if present
if [ -f "$SCRIPT_DIR/wordlist.txt" ]; then
    cp "$SCRIPT_DIR/wordlist.txt" "$INSTALL_DIR/"
    echo -e "${GREEN}  [✓] wordlist.txt copied${RESET}"
else
    echo -e "${YELLOW}  [!] wordlist.txt not found — scanning will use built-in defaults${RESET}"
fi

# Copy README if present
[ -f "$SCRIPT_DIR/README.md" ] && cp "$SCRIPT_DIR/README.md" "$INSTALL_DIR/" && echo -e "${GREEN}  [✓] README.md copied${RESET}"

chmod +x "$INSTALL_DIR/webscan_pro.py" 2>/dev/null
echo -e "${GREEN}  [✓] Files ready in $INSTALL_DIR${RESET}"

echo -e "\n${CYAN}  [6/7] Creating global 'webscan' command...${RESET}"
cat > /usr/local/bin/webscan << WRAPPER
#!/bin/bash
python3 /opt/webscan_pro/webscan_pro.py "\$@"
WRAPPER
chmod +x /usr/local/bin/webscan
echo -e "${GREEN}  [✓] 'webscan' command created → /usr/local/bin/webscan${RESET}"

echo -e "\n${CYAN}  [7/7] Verifying installation...${RESET}"
python3 -c "import requests, colorama, urllib3; print('  Core imports OK')" \
    && echo -e "${GREEN}  [✓] Core packages verified${RESET}" \
    || echo -e "${RED}  [✗] Core package import failed — check pip3 output above${RESET}"

python3 -c "import bs4; print('  BeautifulSoup OK')" 2>/dev/null \
    && echo -e "${GREEN}  [✓] BeautifulSoup4 verified${RESET}" \
    || echo -e "${YELLOW}  [~] BeautifulSoup4 not available (CSRF/Stored XSS checks limited)${RESET}"

python3 -c "import dns.resolver; print('  dnspython OK')" 2>/dev/null \
    && echo -e "${GREEN}  [✓] dnspython verified${RESET}" \
    || echo -e "${YELLOW}  [~] dnspython not available (DNS AXFR will use socket fallback)${RESET}"

python3 -c "import weasyprint; print('  weasyprint OK')" 2>/dev/null \
    && echo -e "${GREEN}  [✓] weasyprint verified (PDF generation available)${RESET}" \
    || echo -e "${YELLOW}  [~] weasyprint not available (PDF export disabled)${RESET}"

# ── Summary ──────────────────────────────────────────────────────
echo -e ""
echo -e "${WHITE}  ══════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  ✅  WebScan Pro v11.7 Installation Complete!${RESET}"
echo -e "${WHITE}  ══════════════════════════════════════════════${RESET}"
echo -e ""
echo -e "${CYAN}  Quick Start:${RESET}"
echo -e "${WHITE}  webscan https://target.com -y${RESET}"
echo -e "${WHITE}  webscan https://target.com -q -y${RESET}"
echo -e "${WHITE}  webscan https://target.com -c 'session=abc' -y${RESET}"
echo -e "${WHITE}  webscan --compare scan1.json scan2.json${RESET}"
echo -e ""
echo -e "${CYAN}  Install Directory : ${WHITE}$INSTALL_DIR${RESET}"
echo -e "${CYAN}  Reports Directory : ${WHITE}\$HOME/webscan-reports${RESET}"
echo -e "${CYAN}  Global Command    : ${WHITE}/usr/local/bin/webscan${RESET}"
echo -e ""
echo -e "${YELLOW}  ⚠  For authorized penetration testing only.${RESET}"
echo -e "${YELLOW}     Unauthorized use is illegal.${RESET}"
echo -e ""
