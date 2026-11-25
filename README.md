# WebScan Pro

```
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
```

**Professional Web Security Scanner** | v12.0 | 91 Modules

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-purple)](https://kali.org)
[![Modules](https://img.shields.io/badge/Modules-91-green)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

> **For authorized security testing only. Always obtain written permission before scanning any target.**

---

## What is WebScan Pro?

WebScan Pro is a comprehensive, single-file Python 3 web security scanner built for professional penetration testers. It combines 91 security modules — from basic recon to advanced vulnerability detection — with AI-powered triage and enterprise-grade tool integration.

**Single file. 91 modules. No setup complexity.**

---

## Features

- **91 Security Modules** — WAF detection, XSS, SQLi, LFI, SSRF, JWT, CORS, IDOR, and 83 more
- **AI Triage** — Automatic vulnerability analysis via Anthropic Claude, OpenAI GPT, or Google Gemini
- **OpenAPI/Swagger Support** — Automatically test all API endpoints from a spec file
- **Enterprise Tool Integration** — OpenVAS/GVM, Nessus, ZAP, Metasploit, tshark
- **OSINT Intelligence** — Shodan, VirusTotal, URLScan, GitHub secrets, breach data, DNS recon
- **Professional Reports** — HTML, JSON, PDF, and Expert Validation reports
- **Checkpoint Resume** — Interrupted scans auto-resume from where they stopped
- **CVSS v3.1 Scoring** — Every finding scored with CVSS, OWASP category, CWE, and WSTG reference

---

## Installation

### Requirements

- Kali Linux (recommended) or any Debian-based Linux
- Python 3.8+
- pip packages (auto-installed on first run)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/anisurrahman213-sudo/webscan-pro.git
cd webscan-pro

# Install Python dependencies
pip3 install requests dnspython python-whois colorama fpdf2 urllib3 --break-system-packages

# Make globally accessible
sudo ln -sf $(pwd)/webscan_pro.py /usr/local/bin/webscan
chmod +x webscan_pro.py
```

### Optional Tools (for advanced modules)

```bash
# nmap — port scanning
sudo apt install nmap -y

# ZAP — passive and active scanning
sudo apt install zaproxy -y

# tshark — traffic analysis
sudo apt install tshark -y

# OpenVAS/GVM — vulnerability management
sudo apt install gvm -y
sudo gvm-setup
sudo gvm-start

# Metasploit — exploit framework (pre-installed on Kali)
# msfconsole
```

---

## Configuration

Create `~/.webscan_keys` for API keys:

```bash
# Threat Intelligence APIs
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export URLSCAN_API_KEY="your_urlscan_key"

# AI Triage (at least one required for --llm-triage)
export ANTHROPIC_API_KEY="your_anthropic_key"
export OPENAI_API_KEY="your_openai_key"
export GOOGLE_API_KEY="your_google_key"

# OpenVAS/GVM
export OPENVAS_HOST="127.0.0.1"
export OPENVAS_PORT="9390"
export OPENVAS_USER="admin"
export OPENVAS_PASS="your_gvm_password"

# Nessus Essentials
export NESSUS_URL="https://127.0.0.1:8834"
export NESSUS_API_KEY="your_nessus_api_key"
```

Auto-load on terminal start:
```bash
echo '[ -f ~/.webscan_keys ] && source ~/.webscan_keys' >> ~/.bashrc
source ~/.bashrc
```

---

## Usage

```bash
# Basic scan
source ~/.webscan_keys
python3 webscan_pro.py https://target.com

# Specific modules only
python3 webscan_pro.py https://target.com --only sqli,xss,lfi

# With AI vulnerability triage
python3 webscan_pro.py https://target.com --llm-triage

# Choose AI provider
python3 webscan_pro.py https://target.com --llm-triage --llm-provider openai

# Scan with OpenAPI/Swagger spec
python3 webscan_pro.py https://target.com --openapi https://api.target.com/swagger.json

# OpenAPI from local file
python3 webscan_pro.py https://target.com --openapi ./openapi.yaml

# Scope filter (scan specific paths only)
python3 webscan_pro.py https://target.com --scope /api/,/admin/

# Resume interrupted scan
python3 webscan_pro.py https://target.com
# (automatically resumes from checkpoint)

# Fresh scan (clear checkpoint)
rm ~/webscan-reports/checkpoint_*.json
python3 webscan_pro.py https://target.com
```

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `--only <modules>` | Comma-separated list of modules to run |
| `--scope <paths>` | Limit scanning to specific URL paths |
| `--llm-triage` | Enable AI-powered vulnerability triage |
| `--llm-provider <name>` | AI provider: `anthropic`, `openai`, `google`, `ollama` |
| `--openapi <url/file>` | Load OpenAPI/Swagger spec for API endpoint discovery |

---

## All 91 Modules

### Phase 1 — Reconnaissance
| # | Module | Description |
|---|--------|-------------|
| 1 | WAF Detection | Identify Web Application Firewalls (31 signatures) |
| 2 | Port Scan | Full port scan via nmap |
| 3 | Subdomain Enum | Subdomain discovery and enumeration |

### Phase 1a — Threat Intelligence
| # | Module | Description |
|---|--------|-------------|
| 4 | API Intel | Shodan, VirusTotal, URLScan lookups |

### Phase 1b — OSINT
| # | Module | Description |
|---|--------|-------------|
| 5 | OSINT Email | Email harvesting |
| 6 | OSINT DNS Intel | DNS intelligence gathering |
| 7 | OSINT GitHub | GitHub secret/key exposure |
| 8 | OSINT Breach | Known breach data check |
| 9 | OSINT Dorks | Google/Bing dork generation |
| 10 | OSINT JS Secrets | JavaScript file secret extraction |

### Phase 1c — External Tool Integration
| # | Module | Description |
|---|--------|-------------|
| 82 | ZAP Active Scan | OWASP ZAP CLI active scanning |
| 83 | Metasploit | Metasploit auxiliary module integration |
| 84 | tshark Traffic | Network traffic capture and analysis |
| **85** | **OpenVAS** | **GVM/OpenVAS full vulnerability scan** ✅ |
| 86 | Nessus | Nessus Essentials API integration |

### Phase 1d — Advanced Detection
| # | Module | Description |
|---|--------|-------------|
| 87 | HTTP Smuggling | CL.TE, TE.CL, TE.TE raw socket smuggling |
| 88 | Backup File Discovery | 30+ extensions, 80+ paths |
| 89 | Email Security | SPF, DKIM, DMARC validation |

### Phase 2 — Web Application Analysis
| # | Module | Description |
|---|--------|-------------|
| 11 | Tech Detection | Technology fingerprinting |
| 12 | HTTP Methods | Dangerous method detection (PUT, DELETE, TRACE) |
| 13 | Headers | Security header analysis |
| 14 | Sensitive Files | Exposed config/backup file discovery |
| 15 | Cookies | Cookie security flag analysis |
| 16 | SSL/TLS | Certificate and cipher analysis |
| 17 | SSTI | Server-Side Template Injection |
| 18 | Open Redirect | Unvalidated redirect detection |
| 19 | XSS | Reflected Cross-Site Scripting |
| 20 | CMDi | OS Command Injection |
| 21 | SQLi | SQL Injection (UNION, error-based, POST) |
| 22 | LFI | Local File Inclusion |
| 23 | CORS | Cross-Origin Resource Sharing misconfiguration |
| 24 | Directory Brute | Directory and file brute-force |
| 25 | XXE | XML External Entity injection |
| 26 | POST Injection | POST parameter injection |
| 27 | Stored XSS | Persistent Cross-Site Scripting |
| 28 | Host Header Injection | HTTP Host header manipulation |
| 29 | CRLF | Carriage Return Line Feed injection |
| 30 | IDOR | Insecure Direct Object Reference |
| 31 | Subdomain Takeover | Dangling DNS / unclaimed services |
| 32 | DNS AXFR | DNS zone transfer attempt |
| 33 | Smuggling | HTTP request smuggling |
| 34 | GraphQL | GraphQL introspection and injection |
| 35 | Rate Limit | Rate limiting bypass detection |
| 36 | CSRF | Cross-Site Request Forgery |
| 37 | SSRF | Server-Side Request Forgery |
| 38 | PrivEsc | Privilege escalation indicators |
| 39 | Auth Bypass | Authentication bypass techniques |
| 40 | JWT | JWT algorithm confusion, JWKS forging |

### Phase 2b — Advanced Modules (41–53)
| # | Module | Description |
|---|--------|-------------|
| 41–53 | Advanced Checks | Prototype pollution, cache poisoning, WebSocket, OAuth, SAML, and more |

### Phase 2d — NIKTO/ZAP-Style Checks
| # | Module | Description |
|---|--------|-------------|
| 54 | Default Creds | Default credential testing |
| 55 | Info Disclosure | Sensitive information disclosure |
| 56 | ZAP Passive | ZAP passive scan integration |
| 57 | Server Hardening | Server configuration review |

### Phase 2e — v11.5 New Modules
| # | Module | Description |
|---|--------|-------------|
| 58 | Crawler | Full site crawler |
| 59 | SSPP | Server-Side Prototype Pollution |
| 60 | NoSQL Injection | MongoDB/NoSQL injection |
| 61 | File Upload | Malicious file upload testing |
| 62 | Account Enumeration | Username/account enumeration |
| 63 | PostMessage/Storage | Client-side storage and postMessage abuse |
| 64 | Login Brute-Force | Login form brute-force |
| 65 | OOB Blind | Out-of-band blind vulnerability detection |
| 66–70 | Additional v11.5 | Further extended checks |
| 71–76 | ZAP/OWASP CLI | Extended ZAP and OWASP tool modules |

### Phase 3 — AI & API
| # | Module | Description |
|---|--------|-------------|
| **90** | **LLM AI Triage** | **AI-powered vulnerability analysis** (Claude/GPT/Gemini) |
| **91** | **OpenAPI Ingestion** | **Swagger 2.0 + OpenAPI 3.x endpoint auto-discovery** |

---

## Reports

Each scan generates 4 report files:

| Format | Description |
|--------|-------------|
| **HTML** | Interactive report with full findings |
| **JSON** | Machine-readable structured output |
| **PDF** | Professional report for clients |
| **Expert HTML** | Validation report with technical details |

Reports saved to: `~/webscan-reports/`

---

## AI Triage

WebScan Pro supports AI-powered vulnerability analysis via multiple providers:

| Provider | Model | Env Variable |
|----------|-------|-------------|
| Anthropic | claude-3-haiku | `ANTHROPIC_API_KEY` |
| OpenAI | gpt-4o-mini | `OPENAI_API_KEY` |
| Google | gemini-1.5-flash | `GOOGLE_API_KEY` |
| Ollama | llama3 (local) | *(no key needed)* |

Provider auto-detected in priority order: Anthropic → OpenAI → Google → Ollama

```bash
python3 webscan_pro.py https://target.com --llm-triage
```

---

## OpenVAS Integration

WebScan Pro integrates with GVM/OpenVAS for professional vulnerability scanning:

```bash
# Ensure GVM is running
sudo gvm-start

# Set credentials in ~/.webscan_keys
export OPENVAS_HOST="127.0.0.1"
export OPENVAS_USER="admin"
export OPENVAS_PASS="your_password"

# Run OpenVAS module
source ~/.webscan_keys
python3 webscan_pro.py https://target.com --only openvas_scan
```

The scanner automatically uses `gvm-cli` with socket connection and proper privilege handling.

---

## OpenAPI / Swagger Support

Automatically discover and test all API endpoints from an OpenAPI spec:

```bash
# From URL
python3 webscan_pro.py https://api.target.com --openapi https://api.target.com/swagger.json

# From local file
python3 webscan_pro.py https://api.target.com --openapi ./api-spec.yaml
```

Supports:
- Swagger 2.0
- OpenAPI 3.x (JSON and YAML)
- Automatic endpoint extraction and injection point discovery

---

## Checkpoint / Resume

Long scans auto-save progress. If interrupted, simply re-run the same command:

```bash
# Start scan
python3 webscan_pro.py https://target.com

# If interrupted, resume:
python3 webscan_pro.py https://target.com
# → Automatically skips completed modules
```

To start fresh:
```bash
rm ~/webscan-reports/checkpoint_*.json
```

---

## Findings Structure

Every finding includes:

```
Severity   : Critical / High / Medium / Low / Info
CVSS Score : 0.0 – 10.0 (v3.1)
OWASP      : A01:2021 – A10:2021
CWE        : CWE-XXX
WSTG       : WSTG-XXXX-XX
Evidence   : Proof of vulnerability
Remediation: Fix guidance
```

---

## Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**.

- Always obtain **written permission** from the target owner before scanning
- Unauthorized scanning may violate computer crime laws
- The authors assume no liability for misuse

---

## License

MIT License — see [LICENSE](LICENSE) for details.
