# WebScan Pro v15.0
### Professional Web Application Penetration Testing Scanner

---

> **Single-file Python 3 security scanner** — 144 modules, 94 scan functions, 16,863 lines.
> No installation required beyond `pip install -r requirements.txt`.

**For authorized targets only. Unauthorized scanning is illegal.**

---

## Statistics

| Item | Count |
|------|-------|
| Total Modules | 144 |
| Scan Functions | 94 |
| Finding Categories | 118 |
| Total Lines | 16,863 |
| File Size | ~879 KB |
| Python Version | 3.8+ |

---

## Installation

```bash
pip install requests colorama beautifulsoup4 urllib3

# Optional
pip install httpx[http2]   # HTTP/2 deep testing
pip install weasyprint      # PDF report generation
```

---

## Quick Start

```bash
# Basic scan — all reports auto-generated
python3 webscan_pro.py https://target.com

# Fast mode
python3 webscan_pro.py https://target.com --speed fast

# Thorough mode
python3 webscan_pro.py https://target.com --speed thorough --output ./reports

# Authenticated scan
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass secret123

# Passive recon (no active requests to target)
python3 webscan_pro.py https://target.com --passive
```

---

## All Arguments

### Core Options

| Flag | Description |
|------|-------------|
| `URL` | Target URL (required) |
| `--speed {fast,normal,stealth,thorough}` | Scan speed mode (default: normal) |
| `--output DIR` | Output directory for reports |
| `--timeout N` | HTTP timeout in seconds (default: 10) |
| `--threads N` | Maximum parallel threads |
| `--resume` | Resume an interrupted scan |

### Authentication

| Flag | Description |
|------|-------------|
| `--login-url URL` | Login page URL |
| `--login-user USER` | Username |
| `--login-pass PASS` | Password |

### Reports & Output

| Flag | Description |
|------|-------------|
| `--html` | Generate HTML executive report |
| `--pdf` | Generate PDF report (requires weasyprint) |
| `--burp` | Export Burp Suite XML |
| `--compliance` | OWASP Top 10 + PCI-DSS compliance HTML |
| `--attack-graph` | Interactive Attack Path Graph HTML |

### Alerts & Notifications

| Flag | Description |
|------|-------------|
| `--alert TOKEN:CHAT_ID` | Telegram alert |
| `--slack WEBHOOK_URL` | Slack notification |
| `--webhook URL` | Custom webhook (JSON POST) |

### Scan Control

| Flag | Description |
|------|-------------|
| `--no-nuclei` | Skip Nuclei scan |
| `--no-services` | Skip port scan |
| `--no-smuggling` | Skip HTTP Request Smuggling |
| `--no-websocket` | Skip WebSocket tests |

### v15.0 New Flags

| Flag | Description |
|------|-------------|
| `--passive` | Passive recon mode only |
| `--attack-graph` | Generate Attack Path Graph |
| `--cred-stuff` | Credential stuffing simulation |
| `--spray-attack` | Password spraying simulation |
| `--spray-user-list FILE` | Username list for spraying |

### History

| Flag | Description |
|------|-------------|
| `--history` | Show past scan history |

---

## Module List

### Phase 0–8 — Core Modules (1–124)

| Range | Category |
|-------|----------|
| 1–10 | DNS, Subdomain, Port, Tech fingerprint, HTTP Headers, SSL/TLS, WHOIS, Robots |
| 11–20 | Auth, Session, Cookie, CSRF, JWT, Login brute force |
| 21–35 | SQLi (GET/POST/Blind/Error), XSS (Reflected/Stored/DOM), CMDi, SSTI, XXE |
| 36–50 | IDOR, Path Traversal, LFI, Auth bypass, Privilege escalation |
| 51–65 | Sensitive files, API keys, .env, Backup, Source code exposure |
| 66–80 | SSRF, Open redirect, CORS, Clickjacking, Security headers |
| 81–97 | GraphQL basic, Admin panels, WAF detection, API, Nuclei, Executive report |
| 98–107 | Nuclei, Authenticated scan, LDAP, XPath, RFI, Session fixation, Git/SVN, ENV, Source map, SOAP |
| 108–117 | Exposed services (FTP/SSH/Telnet/SMTP/RDP/MongoDB/Redis/Elasticsearch/etc.) |
| 118–124 | CSP analysis, Null byte, Business logic, JSON inject, API version, Unicode, Windows path |

### Phase 9d — v15.0 Modules (125–144)

| Module | Name | CVSS | Severity |
|--------|------|------|----------|
| **125** | HTTP Request Smuggling (CL.TE · TE.CL · TE.TE) | 9.0 | Critical |
| **126** | Cache Poisoning / Web Cache Deception | 8.1 | High |
| **127** | WebSocket Security (CSWSH · Injection · Hijacking) | 8.0 | High |
| **128** | Race Condition (15 parallel Turbo Intruder-style) | 8.1 | High |
| **129** | Mass Assignment / Over-posting | 8.8 | High |
| **130** | HTTP Parameter Pollution (HPP) | 5.3 | Medium |
| **131** | OAuth 2.0 / OIDC Misconfiguration (redirect_uri · state · PKCE) | 9.8 | Critical |
| **132** | JWT Algorithm Confusion (alg:none · RS256→HS256 · kid inject) | 9.8 | Critical |
| **133** | Subdomain Takeover (GitHub · Heroku · S3 · Azure · 25+ services) | 8.1 | High |
| **134** | Email Header Injection (CC/BCC via contact forms) | 5.3 | Medium |
| **135** | Cloud Storage Misconfiguration (S3 · GCS · Azure Blob) | 9.8 | Critical |
| **136** | AWS IMDSv1 SSRF Chain (EC2 Metadata Credentials) | 10.0 | Critical |
| **137** | Certificate Transparency Recon (crt.sh passive subdomain) | 5.3 | Info |
| **138** | GraphQL Deep Scan (Batching DoS · Introspection · Field Suggest) | 8.5 | High |
| **139** | Deserialization Detection (Java · PHP · Python Pickle · Ruby Marshal) | 9.8 | Critical |
| **140** | Advanced SSTI (Jinja2 · Twig · Freemarker · Smarty · Velocity · ERB) | 9.8 | Critical |
| **141** | DOM Clobbering | 6.1 | Medium |
| **142** | ReDoS — Regex Denial of Service | 7.5 | High |
| **143** | HTTP/2 Header Injection + Rapid Reset (CVE-2023-44487) | 7.5 | High |
| **144** | Passive Recon (URLScan · Wayback · HackerTarget · SecurityHeaders) | 5.3 | Info |

---

## Professional Intelligence Features

### Attack Path Graph
An interactive HTML visualization is auto-generated after every scan using the vis-network library:
- Shows exploit chains from vulnerability node to impact node
- Critical vulnerabilities highlighted in red
- Click any node to view full details
- Fully zoomable and pannable in any browser

```bash
python3 webscan_pro.py https://target.com
# Output: webscanpro_TIMESTAMP_attack_graph.html (auto-generated)
```

### Credential Stuffing (`--cred-stuff`)
Tests login endpoints against 25 of the most commonly leaked credential pairs.
Automatically stops if rate limiting is detected.

### Password Spraying (`--spray-attack`)
Sprays common passwords against all discovered usernames.
Respects per-user limits to avoid account lockout.

### Compliance Report
OWASP Top 10 2021 and PCI-DSS requirements mapped to findings with pass/fail status.
Auto-generated on every scan — no flags required.

### Scan History
All past scans are stored in a SQLite database at `~/.webscan_history.db`.

---

## Speed Modes

| Mode | Description | Best For |
|------|-------------|----------|
| `fast` | Critical checks only, short timeout | Quick recon, CTF |
| `normal` | All modules, balanced speed | General use (default) |
| `stealth` | Slow, rotating User-Agent, random delays | Production scanning |
| `thorough` | Maximum depth, all payloads | Full penetration test |

---

## Report Types

```
./reports/
├── webscanpro_TIMESTAMP_report.html       # Main technical report
├── webscanpro_TIMESTAMP_executive.html    # Executive summary
├── webscanpro_TIMESTAMP_compliance.html   # OWASP + PCI-DSS compliance
├── webscanpro_TIMESTAMP_attack_graph.html # Interactive attack path graph
└── webscanpro_TIMESTAMP_report.pdf        # PDF export (optional)
```

All reports are **auto-generated** on every scan. No extra flags needed.

---

## Alert System

### Telegram
```bash
python3 webscan_pro.py https://target.com \
  --alert "BOT_TOKEN:CHAT_ID"
```

### Slack
```bash
python3 webscan_pro.py https://target.com \
  --slack "https://hooks.slack.com/services/..."
```

### Custom Webhook
```bash
python3 webscan_pro.py https://target.com \
  --webhook "https://your-server.com/notify"
```
Sends a JSON POST with all critical and high severity findings.

---

## OWASP Top 10 2021 Coverage

| # | Category | Modules Covered |
|---|----------|-----------------|
| A01 | Broken Access Control | IDOR, Path Traversal, WebSocket, Subdomain Takeover |
| A02 | Cryptographic Failures | SSL/TLS, JWT Algorithm Confusion, Sensitive Data Exposure |
| A03 | Injection | SQLi, XSS, SSTI, LDAP, XPath, Deserialization, GraphQL |
| A04 | Insecure Design | Race Condition, Business Logic, Mass Assignment, ReDoS |
| A05 | Security Misconfiguration | CORS, Headers, Cloud Storage, HTTP/2, Cache Poisoning |
| A06 | Vulnerable Components | CVE checks, Nuclei, ReDoS |
| A07 | Auth & Identity Failures | OAuth, JWT, Session Fixation, Credential Stuffing |
| A08 | Software & Data Integrity | Deserialization, Pickle, Java gadget chains |
| A09 | Logging & Monitoring Failures | Error disclosure, Debug info exposure |
| A10 | SSRF | SSRF, AWS IMDS Chain, Cloud Metadata |

---

## Finding Structure

Every finding contains the following fields:

```json
{
  "type":        "SQL Injection",
  "severity":    "Critical",
  "url":         "https://target.com/page?id=1",
  "param":       "id",
  "payload":     "' OR '1'='1",
  "detail":      "Detailed description of the vulnerability...",
  "owasp":       "A03:2021 — Injection",
  "cwe":         "CWE-89",
  "cvss":        9.8,
  "remediation": "Use parameterized queries or prepared statements..."
}
```

---

## Severity Scale

| Severity | CVSS Range | Examples |
|----------|-----------|---------|
| Critical | 9.0–10.0 | SQLi RCE, JWT forgery, AWS IMDS, Cloud bucket exposed |
| High | 7.0–8.9 | XSS, SSRF, Race condition, WebSocket CSWSH |
| Medium | 4.0–6.9 | CSRF, HPP, Email injection, DOM Clobbering |
| Low | 1.0–3.9 | Information disclosure, missing security headers |
| Info | 0.0 | Technology detection, passive recon findings |

---

## Example Workflows

```bash
# 1. Bug bounty recon
python3 webscan_pro.py https://target.com \
  --passive --speed normal --output ./bugbounty

# 2. Full penetration test
python3 webscan_pro.py https://target.com \
  --speed thorough \
  --output ./reports \
  --html

# 3. Stealth scan with Telegram alerts
python3 webscan_pro.py https://target.com \
  --speed stealth \
  --alert "BOT_TOKEN:CHAT_ID"

# 4. Cloud security audit
python3 webscan_pro.py https://target.com \
  --speed thorough \
  --passive \
  --output ./cloud-audit

# 5. Authentication testing
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass admin123 \
  --cred-stuff --spray-attack
```

---

## Version History

| Version | Modules | What's New |
|---------|---------|-----------|
| v1.0 | 20 | Basic XSS, SQLi, Headers |
| v5.0 | 50 | Auth, CSRF, CORS, SSL |
| v10.0 | 80 | GraphQL, JWT, SSRF |
| v12.0 | 92 | Attack chain, Executive report |
| v13.0 | 97 | Telegram, Slack, PDF, Burp XML |
| v14.0 | 124 | Nuclei, Auth scan, Services, Compliance, Webhook, SQLite |
| **v15.0** | **144** | Smuggling, Cache Poison, WebSocket, Race Condition, Mass Assignment, HPP, OAuth/OIDC, JWT Confusion, Subdomain Takeover, Cloud Storage, AWS IMDS, CT Recon, GraphQL Deep, Deserialization, Advanced SSTI, DOM Clobbering, ReDoS, HTTP/2, Passive Recon, Attack Graph |

---

## Technical Details

- **Language:** Python 3.8+
- **Architecture:** Single-file, zero framework dependency
- **Parallelism:** `ThreadPoolExecutor` + `as_completed()`
- **State/Resume:** `_module_skip()` / `_module_done()` checkpoint pattern
- **Storage:** SQLite (`~/.webscan_history.db`)
- **HTTP Client:** `requests.Session()` global session + `httpx` (HTTP/2)
- **Phase Order:** Phase 0 → 1 → 2 → 3 → 4 → 5 → 6 → 6b → 7 → 8 → 9 → 9b → 9c → 9d → 10 → 11 → 12

---

## Legal Notice

> This tool is intended **only** for authorized web application security testing.
> Unauthorized scanning of systems you do not own or have explicit written permission to test
> is **illegal** and may result in criminal prosecution.
> Always stay within the scope of your bug bounty program or penetration testing agreement.
