# WebScan Pro v11.5

**Professional Web Application Penetration Testing Scanner**

> Authorized penetration testing only. Unauthorized use is illegal.

---

## Overview

WebScan Pro is a comprehensive, single-file Python 3 scanner covering **70 security modules** across OWASP Top 10 (2021), CWE, and CVSS v3.1 — built for professional security assessments. It generates 4 report types: HTML, JSON, PDF, and Expert Validation Report with per-finding manual verification commands.

**70 modules · OWASP Top 10 (2021) · CVSS v3.1 · CWE · Confirmed vs Potential findings · HTML + JSON + PDF + Expert Validation · Parallel Execution · Built-in OSINT · CVE Mapping · WAF Bypass · Web Crawler · Cloud Scanner**

---

## Installation

```bash
git clone https://github.com/your-username/webscan-pro
cd webscan-pro
sudo bash install.sh
```

Installs the `webscan` global command to `/usr/local/bin/webscan`.  
Reports saved to `~/webscan-reports/` by default.

**Requirements:** Python 3.8+, pip3  
**Core:** `requests`, `colorama`, `urllib3`  
**Optional:** `beautifulsoup4`, `dnspython`, `lxml`, `weasyprint` (PDF)

---

## Usage

```bash
webscan <URL> [options]
```

---

## Common Commands

| Task | Command |
|------|---------|
| Standard scan | `webscan https://target.com -y` |
| Quiet / bug bounty | `webscan https://target.com -q -y` |
| Verbose debug | `webscan https://target.com -v -y` |
| Authenticated scan | `webscan https://target.com -c "session=abc; auth=1" -y` |
| Login form auth | `webscan https://target.com -U admin -P secret -y` |
| Fast (skip heavy modules) | `webscan https://target.com --no-advanced -y` |
| Rate-limited (1 s delay) | `webscan https://target.com --rate 1.0 -y` |
| Targeted scope | `webscan https://target.com --scope sqli,xss,jwt -y` |
| Through Burp proxy | `webscan https://target.com --proxy http://127.0.0.1:8080 -y` |
| Export Burp XML | `webscan https://target.com --burp -y` |
| Resume interrupted scan | `webscan https://target.com --resume -y` |
| Compare two scans | `webscan --compare scan1.json scan2.json` |
| Filter by CVSS score | `webscan https://target.com --cvss 7.0 -y` |
| Custom wordlist | `webscan https://target.com -w wordlist.txt -y` |
| Custom output dir | `webscan https://target.com -o /path/to/reports -y` |

---

## All Flags

| Flag | Description |
|------|-------------|
| `-y, --yes` | Auto-confirm all prompts (non-interactive) |
| `-q, --quiet` | Minimal output — findings only |
| `-v, --verbose` | Verbose output including debug info |
| `-c, --cookie` | Session cookies: `'name=value; name2=value2'` |
| `-U, --username` | Login username for form-based auth |
| `-P, --password` | Login password for form-based auth |
| `-w, --wordlist` | Custom wordlist file for directory brute-force |
| `-o, --output` | Report output directory (default: `~/webscan-reports/`) |
| `-t, --threads` | Concurrent threads (default: 50) |
| `--timeout` | Request timeout in seconds (default: 7) |
| `--proxy` | HTTP/HTTPS proxy URL: `http://127.0.0.1:8080` |
| `--rate` | Delay (seconds) between requests for rate limiting |
| `--scope` | Comma-separated module keys to run only those modules |
| `--cvss` | Minimum CVSS score to include in report (e.g. `7.0`) |
| `--burp` | Export Burp Suite XML alongside HTML/JSON |
| `--pdf` | Show warning if PDF export fails (PDF auto-generated if weasyprint installed) |
| `--resume` | Resume from last checkpoint (skips completed modules) |
| `--compare` | Compare two JSON reports: `--compare a.json b.json` |
| `--no-ports` | Skip port scanning |
| `--no-subs` | Skip subdomain enumeration |
| `--no-ssti` | Skip SSTI detection |
| `--no-cmdi` | Skip command injection |
| `--no-smuggling` | Skip HTTP request smuggling |
| `--no-idor` | Skip IDOR checks |
| `--no-advanced` | Skip all Phase 2b/2c advanced modules (faster scan) |
| `--version` | Show version and exit |

---

## Scope Modules

Use `--scope` with a comma-separated list of module keys to target specific checks.

### Phase 1 — Recon

| Key | Module |
|-----|--------|
| `waf` | WAF Detection |
| `ip_info` | IP / ASN Info |
| `ports` | Port Scan |
| `subdomains` | Subdomain Enumeration |

### Phase 1b — OSINT Intelligence (v11.3)

| Key | Module |
|-----|--------|
| `osint_email` | Email Harvest (crt.sh, security.txt, mailto links) |
| `osint_dns` | DNS Intelligence (SPF, DMARC, DKIM, MX) |
| `osint_dorks` | Google Dork Generator (16 targeted dorks) |
| `osint_breach` | Data Breach Check (HIBP, public pastes) |
| `osint_github` | GitHub Exposure (unauthenticated code search) |
| `osint_js` | JavaScript Secrets Scan (API keys, tokens, endpoints) |

### Phase 2 — Core Scanning

| Key | Module |
|-----|--------|
| `headers` | Security Headers |
| `methods` | HTTP Methods |
| `sqli` | SQL Injection |
| `xss` | Reflected XSS |
| `lfi` | Local File Inclusion |
| `ssrf` | SSRF |
| `xxe` | XXE Injection |
| `redirect` | Open Redirect |
| `cors` | CORS Misconfiguration |
| `sensitive` | Sensitive File Exposure |
| `dirs` | Directory Brute-Force |
| `ssl` | SSL/TLS Analysis |
| `tech` | Technology Fingerprint |
| `cookies` | Cookie Security |
| `csrf` | CSRF |
| `privesc` | Privilege Escalation |
| `ssti` | SSTI |
| `cmdi` | Command Injection |
| `jwt` | JWT Vulnerabilities |
| `ratelimit` | Rate Limit Check |
| `authn_bypass` | Authentication Bypass |
| `graphql` | GraphQL Security |
| `post_inject` | POST Injection |
| `stored_xss` | Stored XSS |
| `hostheader` | Host Header Injection |
| `crlf` | CRLF Injection |
| `idor` | IDOR |
| `subdomain_takeover` | Subdomain Takeover |
| `dns_axfr` | DNS Zone Transfer |
| `smuggling` | HTTP Request Smuggling |

### Phase 2b — Advanced (v10)

| Key | Module |
|-----|--------|
| `oauth2` | OAuth 2.0 Flaws |
| `hpp` | HTTP Parameter Pollution |
| `cache_poison` | Cache Poisoning |
| `proto_poll` | Prototype Pollution |
| `deserial` | Deserialization |
| `api_sec` | API Security / BOLA |
| `biz_logic` | Business Logic Flaws |

### Phase 2c — Advanced (v11)

| Key | Module |
|-----|--------|
| `websocket` | WebSocket Security |
| `saml` | SAML Misconfiguration |
| `otp_bypass` | 2FA / OTP Bypass |
| `path_norm` | Path Normalization |
| `email_inject` | Email Header Injection |
| `dep_confusion` | Dependency Confusion |
| `dom_xss` | DOM-based XSS |

### Phase 2d — Nikto/ZAP-style (v11.4)

| Key | Module |
|-----|--------|
| `default_creds` | Default Credentials Scanner (WordPress, Tomcat, Jenkins, Grafana…) |
| `srv_hardening` | Server Hardening & CGI (WebDAV, ShellShock, phpinfo, backup files) |
| `info_disclosure` | Information Disclosure (stack trace, private IP, debug mode, PII) |
| `zap_passive` | ZAP-style Passive Analysis (mixed content, autocomplete, cache, robots.txt) |

### Phase 2e — New Modules v11.5 (Modules 58–71)

| Key | Module |
|-----|--------|
| `crawler` | Web Crawler/Spider — discovers all URLs, forms, params |
| `cloud_bucket` | Cloud Storage Exposure (S3, GCS, Azure Blob) |
| `mass_assignment` | Mass Assignment — hidden field injection |
| `acct_takeover` | Account Takeover — password reset flaws |
| `redos` | ReDoS — RegEx Denial of Service patterns |
| `clickjacking` | Clickjacking — X-Frame-Options / CSP frame-ancestors |
| `jsonp_inject` | JSONP Injection — callback parameter manipulation |
| `css_inject` | CSS Injection — style/expression injection |
| `http2_vulns` | HTTP/2 Vulnerabilities — protocol-level checks |
| `cve_scan` | CVE Mapping — technology stack → known CVEs (44 CVEs, 14 stacks) |
| `s3_brute` | S3 Bucket Brute-Force — common bucket name guessing |
| `wayback_urls` | Wayback / Archive URLs — historical endpoint discovery |
| `param_discover` | Parameter Discovery — Arjun-style hidden param detection |
| `race_condition` | Race Condition — synchronized concurrent request testing |
| `waf_bypass` | WAF Bypass — obfuscated SQLi + XSS payloads |

**Example — targeted scan:**
```bash
webscan https://target.com --scope sqli,xss,jwt,cors,headers -y
```

**Example — skip all advanced modules:**
```bash
webscan https://target.com --no-advanced -y
```

---

## What's New in v11.5

| Feature | Details |
|---------|---------|
| **70 Modules** | 13 new modules added (was 57) |
| **Confirmed vs Potential** | Every finding is verified — CONFIRMED (actual evidence) or POTENTIAL (heuristic) |
| **SQLi Baseline Timing** | Measures response time before injection — no false positives on slow servers |
| **XSS Context Check** | Detects HTML-encoding — won't flag `&lt;script&gt;` as vulnerable |
| **Web Crawler (M58)** | Spiders the entire target, discovers URLs/forms/params |
| **Cloud Scanner (M59)** | Checks S3 / GCS / Azure Blob for public access |
| **CVE Mapping (M67)** | Maps detected technologies to 44 known CVEs across 14 stacks |
| **WAF Bypass (M68)** | Tests 15 SQLi + 10 XSS obfuscated payloads through WAF |
| **Parameter Discovery (M70)** | Arjun-style: discovers hidden GET params via baseline comparison |
| **Race Condition (M71)** | Synchronized concurrent requests using threading.Barrier |
| **Wayback URLs (M66)** | Fetches historical URLs from Wayback Machine CDX API |
| **Expert Validation Report** | 4th report: dark-themed HTML with manual verification commands per finding |

---

## Output Files

Every scan generates 4 reports in `~/webscan-reports/` (or the path set with `-o`):

| File | Description |
|------|-------------|
| `webscanpro_<timestamp>.html` | Full interactive HTML report (Confirmed/Potential split) |
| `webscanpro_<timestamp>.json` | Machine-readable JSON (for `--compare`, CI/CD) |
| `webscanpro_<timestamp>.pdf` | PDF export (requires `weasyprint`) |
| `webscanpro_<timestamp>_expert.html` | **Expert Validation Report** — Critical/High only, manual verification commands |

**PDF:** Auto-generated if `weasyprint` is installed. Install with:
```bash
pip3 install weasyprint --break-system-packages
```

---

## Report Contents

Each finding includes:

- **Title** and **Severity** (Critical / High / Medium / Low / Info)
- **OWASP Top 10 (2021)** category (A01–A10)
- **CWE** reference number
- **CVSS v3.1** base score
- **URL** and **Evidence** (parameter, payload, response)
- **Recommendation** (remediation steps)

---

## Examples

**CTF / lab target:**
```bash
webscan https://192.168.56.101 -y
```

**Bug bounty (quiet, rate-limited, authenticated):**
```bash
webscan https://app.target.com -q --rate 0.5 -c "session=abc123" -y
```

**Internal API audit:**
```bash
webscan https://api.internal.com --scope api_sec,authn_bypass,jwt,graphql,cors -y
```

**Full scan through Burp with Burp XML export:**
```bash
webscan https://target.com --proxy http://127.0.0.1:8080 --burp -y
```

**Compare before/after scans:**
```bash
webscan --compare ~/webscan-reports/scan_before.json ~/webscan-reports/scan_after.json
```

---

## File Structure

```
webscan-pro/
├── webscan_pro.py    # Main scanner (~7,950 lines, single file, 70 modules)
├── install.sh        # Kali Linux installer
├── wordlist.txt      # 575-entry directory wordlist
└── README.md         # This file
```

---

## Legal

This tool is for **authorized penetration testing only**.  
Always obtain written permission before scanning any system.  
Unauthorized use is illegal and unethical.
