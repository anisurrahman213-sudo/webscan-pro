# WebScan Pro v15.0
### Professional Web Application Penetration Testing Scanner

---

> **Single-file Python 3 security scanner** — 144 modules, 94 scan functions, 16,863 lines.
> No installation required beyond `pip install -r requirements.txt`.

**শুধুমাত্র authorized target-এ ব্যবহার করুন।**

---

## পরিসংখ্যান

| বিষয় | সংখ্যা |
|------|--------|
| মোট Modules | 144 |
| Scan Functions | 94 |
| Finding Categories | 118 |
| Total Lines | 16,863 |
| File Size | ~879 KB |
| Python Version | 3.8+ |

---

## ইনস্টলেশন

```bash
pip install requests colorama beautifulsoup4 urllib3

# Optional
pip install httpx[http2]   # HTTP/2 deep testing
pip install weasyprint      # PDF report
```

---

## দ্রুত শুরু

```bash
# Basic scan
python3 webscan_pro.py https://target.com

# Fast mode
python3 webscan_pro.py https://target.com --speed fast

# Thorough mode + সব রিপোর্ট
python3 webscan_pro.py https://target.com --speed thorough --output ./reports --compliance --attack-graph

# Authenticated scan
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass secret123

# Passive recon (target-এ কোনো active request নেই)
python3 webscan_pro.py https://target.com --passive
```

---

## সব Argument

### মূল Options

| Flag | বিবরণ |
|------|-------|
| `URL` | Target URL (required) |
| `--speed {fast,normal,stealth,thorough}` | Scan speed (default: normal) |
| `--output DIR` | Output directory for reports |
| `--timeout N` | HTTP timeout seconds (default: 10) |
| `--threads N` | Max parallel threads |
| `--resume` | Interrupted scan resume করুন |

### Authentication

| Flag | বিবরণ |
|------|-------|
| `--login-url URL` | Login page URL |
| `--login-user USER` | Username |
| `--login-pass PASS` | Password |

### Report ও Output

| Flag | বিবরণ |
|------|-------|
| `--html` | HTML রিপোর্ট |
| `--pdf` | PDF রিপোর্ট (weasyprint লাগবে) |
| `--burp` | Burp Suite XML export |
| `--compliance` | OWASP Top 10 + PCI-DSS compliance HTML |
| `--attack-graph` | AI Attack Path Graph HTML |

### Alert ও Notification

| Flag | বিবরণ |
|------|-------|
| `--alert TOKEN:CHAT_ID` | Telegram alert |
| `--slack WEBHOOK_URL` | Slack notification |
| `--webhook URL` | Custom webhook (JSON POST) |

### Scan Control

| Flag | বিবরণ |
|------|-------|
| `--no-nuclei` | Nuclei scan skip |
| `--no-services` | Port scan skip |
| `--no-smuggling` | HTTP Smuggling skip |
| `--no-websocket` | WebSocket test skip |

### v15.0 নতুন Flags

| Flag | বিবরণ |
|------|-------|
| `--passive` | Passive recon mode |
| `--attack-graph` | Attack Path Graph তৈরি |
| `--cred-stuff` | Credential stuffing simulation |
| `--spray` | Password spraying simulation |
| `--spray-user-list FILE` | Username list for spraying |

### History

| Flag | বিবরণ |
|------|-------|
| `--history` | Past scan history দেখান |

---

## Module তালিকা

### Phase 0–8 — Core Modules (1–124)

| Range | Category |
|-------|----------|
| 1–10 | DNS, Subdomain, Port, Tech fingerprint, HTTP Headers, SSL/TLS, WHOIS, Robots |
| 11–20 | Auth, Session, Cookie, CSRF, JWT, Login brute |
| 21–35 | SQLi (GET/POST/Blind/Error), XSS (Reflected/Stored/DOM), CMDi, SSTI, XXE |
| 36–50 | IDOR, Path Traversal, LFI, Auth bypass, Priv escalation |
| 51–65 | Sensitive files, API keys, .env, Backup, Source code |
| 66–80 | SSRF, Open redirect, CORS, Clickjacking, Security headers |
| 81–97 | GraphQL basic, Admin panels, WAF detection, API, Nuclei, Exec report |
| 98–107 | Nuclei, Authenticated scan, LDAP, XPath, RFI, Session fixation, Git/SVN, ENV, Source map, SOAP |
| 108–117 | Exposed services (FTP/SSH/Telnet/SMTP/RDP/MongoDB/Redis/Elasticsearch/etc.) |
| 118–124 | CSP analysis, Null byte, Business logic, JSON inject, API version, Unicode, Windows path |

### Phase 9d — v15.0 Modules (125–144)

| Module | নাম | CVSS | Severity |
|--------|-----|------|----------|
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
| **138** | GraphQL Deep (Batching DoS · Introspection · Field Suggest) | 8.5 | High |
| **139** | Deserialization Detection (Java · PHP · Python Pickle · Ruby Marshal) | 9.8 | Critical |
| **140** | Advanced SSTI (Jinja2 · Twig · Freemarker · Smarty · Velocity · ERB) | 9.8 | Critical |
| **141** | DOM Clobbering | 6.1 | Medium |
| **142** | ReDoS — Regex Denial of Service | 7.5 | High |
| **143** | HTTP/2 Header Injection + Rapid Reset (CVE-2023-44487) | 7.5 | High |
| **144** | Passive Recon (URLScan · Wayback · HackerTarget · SecurityHeaders) | 5.3 | Info |

---

## Professional Intelligence Features

### Attack Path Graph (`--attack-graph`)
Scan শেষে interactive HTML graph তৈরি হয় (vis-network library):
- Vulnerability node থেকে Impact node পর্যন্ত chain দেখায়
- Critical vulnerability লাল রঙে হাইলাইট
- Node click করলে details দেখা যায়
- Browser-এ open করে zoom/pan করা যায়

```bash
python3 webscan_pro.py https://target.com --attack-graph
# Output: webscanpro_TIMESTAMP_attack_graph.html
```

### Credential Stuffing (`--cred-stuff`)
25টি সবচেয়ে বেশি leaked credential pair দিয়ে login endpoint test।
Rate limit detect করলে automatically stop।

### Password Spraying (`--spray`)
Common passwords দিয়ে discovered usernames-এর বিরুদ্ধে spray।
Account lockout avoid করতে per-user limit মেনে চলে।

### Compliance Report (`--compliance`)
OWASP Top 10 2021 এবং PCI-DSS requirements-এর বিরুদ্ধে HTML রিপোর্ট।

### Scan History (`--history`)
SQLite database (`~/.webscan_history.db`) তে সব past scan সংরক্ষিত।

---

## Speed Modes

| Mode | বিবরণ | কখন ব্যবহার |
|------|-------|------------|
| `fast` | Critical checks, কম timeout | Quick check, CTF |
| `normal` | সব module, balanced | General use (default) |
| `stealth` | ধীরে, User-Agent rotate, random delay | Production scan |
| `thorough` | Maximum depth, সব payload | Full pentest |

---

## রিপোর্ট ধরন

```
./reports/
├── webscanpro_TIMESTAMP_report.html      # Main report
├── webscanpro_TIMESTAMP_executive.html   # Executive summary
├── webscanpro_TIMESTAMP_compliance.html  # OWASP + PCI-DSS
├── webscanpro_TIMESTAMP_attack_graph.html # Attack path graph
└── webscanpro_TIMESTAMP_report.pdf       # PDF (optional)
```

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
JSON POST পাঠাবে সব critical/high findings নিয়ে।

---

## OWASP Top 10 2021 Coverage

| # | Category | Covered |
|---|----------|---------|
| A01 | Broken Access Control | IDOR, Path Traversal, WebSocket, SubTK |
| A02 | Cryptographic Failures | SSL/TLS, JWT Confusion, Sensitive Data |
| A03 | Injection | SQLi, XSS, SSTI, LDAP, XPath, Deserialization, GraphQL |
| A04 | Insecure Design | Race Condition, Business Logic, Mass Assignment |
| A05 | Security Misconfiguration | CORS, Headers, Cloud Storage, HTTP/2, Cache |
| A06 | Vulnerable Components | CVE checks, Nuclei, ReDoS |
| A07 | Auth Failures | OAuth, JWT, Session Fixation, Credential Stuffing |
| A08 | Software Integrity | Deserialization, Pickle, Java gadget chains |
| A09 | Logging Failures | Error disclosure, Debug info |
| A10 | SSRF | SSRF, AWS IMDS, Cloud Metadata Chain |

---

## Finding Structure

প্রতিটি finding-এ থাকে:

```json
{
  "type":        "SQL Injection",
  "severity":    "Critical",
  "url":         "https://target.com/page?id=1",
  "param":       "id",
  "payload":     "' OR '1'='1",
  "detail":      "বিস্তারিত বিবরণ...",
  "owasp":       "A03:2021 — Injection",
  "cwe":         "CWE-89",
  "cvss":        9.8,
  "remediation": "কীভাবে ঠিক করবেন..."
}
```

---

## Severity Scale

| Severity | CVSS | উদাহরণ |
|----------|------|--------|
| Critical | 9.0–10.0 | SQLi RCE, JWT forgery, AWS IMDS, Cloud bucket |
| High | 7.0–8.9 | XSS, SSRF, Race condition, WebSocket CSWSH |
| Medium | 4.0–6.9 | CSRF, HPP, Email injection, DOM Clobbering |
| Low | 1.0–3.9 | Information disclosure, missing headers |
| Info | 0.0 | Technology detection, passive findings |

---

## উদাহরণ Workflow

```bash
# ১. Bug bounty recon
python3 webscan_pro.py https://target.com \
  --passive --speed normal --output ./bugbounty

# ২. Full pentest
python3 webscan_pro.py https://target.com \
  --speed thorough \
  --output ./reports \
  --compliance \
  --attack-graph \
  --html

# ৩. Stealth + Telegram alert
python3 webscan_pro.py https://target.com \
  --speed stealth \
  --alert "BOT_TOKEN:CHAT_ID"

# ৪. Cloud security focus
python3 webscan_pro.py https://target.com \
  --speed thorough \
  --passive \
  --attack-graph \
  --output ./cloud-audit

# ৫. Auth testing
python3 webscan_pro.py https://target.com \
  --login-url https://target.com/login \
  --login-user admin --login-pass admin123 \
  --cred-stuff --spray
```

---

## Version History

| Version | Modules | নতুন কী |
|---------|---------|---------|
| v1.0 | 20 | Basic XSS, SQLi, Headers |
| v5.0 | 50 | Auth, CSRF, CORS, SSL |
| v10.0 | 80 | GraphQL, JWT, SSRF |
| v12.0 | 92 | Attack chain, Executive report |
| v13.0 | 97 | Telegram, Slack, PDF, Burp XML |
| v14.0 | 124 | Nuclei, Auth scan, Services, Compliance, Webhook, SQLite |
| **v15.0** | **144** | Smuggling, Cache Poison, WebSocket, Race Condition, Mass Assign, HPP, OAuth/OIDC, JWT Confusion, SubTK, Cloud Storage, AWS IMDS, CT Recon, GraphQL Deep, Deserialization, SSTI Adv, DOM Clobber, ReDoS, HTTP/2, Passive Recon, Attack Graph |

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

> এই টুল শুধুমাত্র **authorized** web application-এ ব্যবহারের জন্য।
> Unauthorized scanning বেআইনি এবং শাস্তিযোগ্য অপরাধ।
> Bug bounty / pentest scope-এর বাইরে ব্যবহার করবেন না।
