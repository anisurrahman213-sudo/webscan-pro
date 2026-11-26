# WebScan Pro v15.0 — Command Cheatsheet

## ── BASIC ──────────────────────────────────────────────────────────

# Minimal scan
python3 webscan_pro.py https://target.com

# Speed modes
python3 webscan_pro.py https://target.com --speed fast
python3 webscan_pro.py https://target.com --speed normal
python3 webscan_pro.py https://target.com --speed stealth
python3 webscan_pro.py https://target.com --speed thorough

# Custom timeout & threads
python3 webscan_pro.py https://target.com --timeout 15 --threads 20

# Resume interrupted scan
python3 webscan_pro.py https://target.com --resume


## ── REPORT ─────────────────────────────────────────────────────────

# HTML report
python3 webscan_pro.py https://target.com --html --output ./reports

# PDF report
python3 webscan_pro.py https://target.com --pdf --output ./reports

# Compliance report (OWASP + PCI-DSS)
python3 webscan_pro.py https://target.com --compliance --output ./reports

# Attack Path Graph
python3 webscan_pro.py https://target.com --attack-graph --output ./reports

# Burp Suite XML
python3 webscan_pro.py https://target.com --burp --output ./reports

# সব রিপোর্ট একসাথে
python3 webscan_pro.py https://target.com \
  --html --pdf --compliance --attack-graph --burp \
  --output ./reports


## ── AUTHENTICATION ─────────────────────────────────────────────────

# Login করে authenticated scan
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin \
  --login-pass admin123

# Auth + Full report
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass secret \
  --speed thorough --html --output ./reports


## ── ALERTS ─────────────────────────────────────────────────────────

# Telegram alert
python3 webscan_pro.py https://target.com \
  --alert "1234567890:AABBaabbCCDDccdd:987654321"
# Format: BOT_TOKEN:CHAT_ID

# Slack alert
python3 webscan_pro.py https://target.com \
  --slack "https://hooks.slack.com/services/T.../B.../xxx"

# Custom Webhook (JSON POST)
python3 webscan_pro.py https://target.com \
  --webhook "https://your-server.com/webhook"

# Telegram + Slack একসাথে
python3 webscan_pro.py https://target.com \
  --alert "TOKEN:CHATID" \
  --slack "https://hooks.slack.com/..."


## ── v15.0 নতুন FEATURES ────────────────────────────────────────────

# Passive recon (target-এ কোনো request নেই)
python3 webscan_pro.py https://target.com --passive

# Credential stuffing simulation
python3 webscan_pro.py https://target.com --cred-stuff

# Password spraying
python3 webscan_pro.py https://target.com --spray

# Password spraying + custom user list
python3 webscan_pro.py https://target.com \
  --spray --spray-user-list /path/to/users.txt

# HTTP Smuggling skip করুন
python3 webscan_pro.py https://target.com --no-smuggling

# WebSocket test skip করুন
python3 webscan_pro.py https://target.com --no-websocket


## ── SKIP MODULES ───────────────────────────────────────────────────

python3 webscan_pro.py https://target.com --no-nuclei
python3 webscan_pro.py https://target.com --no-services
python3 webscan_pro.py https://target.com --no-smuggling
python3 webscan_pro.py https://target.com --no-websocket

# Multiple skip
python3 webscan_pro.py https://target.com \
  --no-nuclei --no-services --no-smuggling


## ── HISTORY ────────────────────────────────────────────────────────

# Past scan history দেখুন
python3 webscan_pro.py https://target.com --history


## ── FULL WORKFLOW EXAMPLES ─────────────────────────────────────────

# 1. Quick security check
python3 webscan_pro.py https://target.com --speed fast

# 2. Bug bounty recon
python3 webscan_pro.py https://target.com \
  --passive --speed normal --output ./bugbounty

# 3. Full pentest
python3 webscan_pro.py https://target.com \
  --speed thorough \
  --output ./pentest \
  --html --pdf --compliance --attack-graph \
  --alert "TOKEN:CHATID"

# 4. Stealth scan (production)
python3 webscan_pro.py https://target.com \
  --speed stealth \
  --output ./stealth \
  --html

# 5. Cloud security audit
python3 webscan_pro.py https://target.com \
  --speed thorough \
  --passive --attack-graph \
  --output ./cloud-audit

# 6. Auth + credential testing
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass admin123 \
  --cred-stuff --spray \
  --speed thorough --html

# 7. Resume + report
python3 webscan_pro.py https://target.com \
  --resume --html --output ./reports

# 8. Environment variable দিয়ে webhook
export WEBSCAN_WEBHOOK="https://your-server.com/notify"
python3 webscan_pro.py https://target.com


## ── HELP ────────────────────────────────────────────────────────────

python3 webscan_pro.py --help
