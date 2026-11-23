# WebScan Pro v11.7

**Professional Web Application Penetration Testing Scanner**

> Authorized penetration testing only. Unauthorized use is illegal.

---

## Overview

WebScan Pro is a comprehensive, single-file Python 3 scanner covering **77 security modules** across OWASP Top 10 (2021), WSTG, ASVS v5.0, CWE, and CVSS v3.1 — built for professional security assessments. It generates 4 report types: HTML, JSON, PDF, and Expert Validation Report with per-finding manual verification commands.

**77 modules · OWASP Top 10 (2021) · WSTG + ASVS v5.0 Mapping · CVSS v3.1 · CWE · Confirmed vs Potential · HTML + JSON + PDF + Expert Validation · Parallel Execution · Built-in OSINT · CVE Mapping · WAF Bypass · Web Crawler · Cloud Scanner · CI/CD Integration**

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
| **CI/CD pipeline** | `webscan https://target.com -y --fail-on-severity high` |
| **Credential stuffing** | `webscan https://target.com --combo creds.txt -y` |
| **Password spray** | `webscan https://target.com --spray Password123 -y` |

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
| `--combo` | Credential combo file (user:pass per line) for login brute-force |
| `--spray` | Single password to spray across common usernames |
| `--fail-on-severity` | **CI/CD:** Exit code 1 if finding >= this severity (`critical`/`high`/`medium`/`low`) |
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

### Phase 1b — OSINT Intelligence

| Key | Module |
|-----|--------|
| `osint_email` | Email Harvest (crt.sh, security.txt, mailto links) |
| `osint_dns` | DNS Intelligence (SPF, DMARC, DKIM, MX) |
| `osint_dorks` | Google Dork Generator (16 targeted dorks) |
| `osint_breach` | Data Breach Check (HIBP, public pastes) |
| `osint_github` | GitHub Exposure (unauthenticated code search) |
| `osint_js` | JavaScript Secrets Scan (API keys, tokens, endpoints) |

### Phase 2 — Core Scanning

| Key | Module | WSTG | ASVS |
|-----|--------|------|------|
| `headers` | Security Headers | WSTG-CONF-07 | ASVS-14.4.1 |
| `sqli` | SQL Injection | WSTG-INPV-05 | ASVS-5.3.4 |
| `xss` | Reflected XSS | WSTG-CLNT-01 | ASVS-5.3.3 |
| `lfi` | Local File Inclusion | WSTG-ATHZ-01 | ASVS-5.3.12 |
| `ssrf` | SSRF | WSTG-INPV-19 | ASVS-5.3.17 |
| `xxe` | XXE Injection | WSTG-INPV-07 | ASVS-5.5.2 |
| `cors` | CORS Misconfiguration | WSTG-CLNT-07 | ASVS-14.5.3 |
| `csrf` | CSRF | WSTG-SESS-05 | ASVS-4.2.2 |
| `redirect` | Open Redirect | WSTG-CLNT-04 | ASVS-5.1.5 |
| `cookies` | Cookie Security | WSTG-SESS-02 | ASVS-3.4.1 |
| `ssl` | SSL/TLS Analysis | WSTG-CRYP-01 | ASVS-9.1.1 |
| `sensitive` | Sensitive File Exposure | WSTG-CONF-10 | ASVS-8.3.4 |
| `methods` | HTTP Methods | WSTG-CONF-06 | ASVS-14.5.1 |
| `tech` | Technology Fingerprint | WSTG-INFO-02 | ASVS-14.2.1 |
| `ssti` | SSTI | WSTG-INPV-18 | ASVS-5.3.17 |
| `cmdi` | Command Injection | WSTG-INPV-12 | ASVS-5.3.8 |
| `jwt` | JWT Vulnerabilities | WSTG-SESS-10 | ASVS-3.5.3 |
| `authn_bypass` | Authentication Bypass | WSTG-ATHN-01 | ASVS-2.1.1 |
| `graphql` | GraphQL Security | WSTG-INPV-11 | ASVS-13.1.1 |
| `stored_xss` | Stored XSS | WSTG-INPV-02 | ASVS-5.3.3 |
| `hostheader` | Host Header Injection | WSTG-INPV-17 | ASVS-5.3.2 |
| `crlf` | CRLF Injection | WSTG-INPV-15 | ASVS-5.3.2 |
| `idor` | IDOR | WSTG-ATHZ-04 | ASVS-4.2.1 |
| `smuggling` | HTTP Request Smuggling | WSTG-INPV-13 | ASVS-14.5.1 |

### Phase 2b — Advanced

| Key | Module |
|-----|--------|
| `oauth2` | OAuth 2.0 Flaws |
| `hpp` | HTTP Parameter Pollution |
| `cache_poison` | Cache Poisoning |
| `deserial` | Deserialization |
| `api_sec` | API Security / BOLA |
| `biz_logic` | Business Logic Flaws |

### Phase 2c — Advanced v11

| Key | Module |
|-----|--------|
| `websocket` | WebSocket Security |
| `saml` | SAML Misconfiguration |
| `otp_bypass` | 2FA / OTP Bypass |
| `dom_xss` | DOM-based XSS |
| `email_inject` | Email Header Injection |

### Phase 2d — Nikto/ZAP-style

| Key | Module |
|-----|--------|
| `default_creds` | Default Credentials Scanner |
| `srv_hardening` | Server Hardening & CGI |
| `info_disclosure` | Information Disclosure |
| `zap_passive` | ZAP-style Passive Analysis |

### Phase 2e — New Modules v11.5–v11.7

| Key | Module | WSTG | ASVS |
|-----|--------|------|------|
| `crawler` | Web Crawler/Spider | WSTG-INFO-05 | ASVS-5.1.1 |
| `cloud_bucket` | Cloud Storage Exposure (S3, GCS, Azure) | WSTG-CONF-10 | ASVS-14.2.3 |
| `mass_assignment` | Mass Assignment | WSTG-ATHZ-01 | ASVS-4.2.1 |
| `acct_takeover` | Account Takeover — password reset flaws | WSTG-ATHN-01 | ASVS-2.1.1 |
| `redos` | ReDoS — RegEx Denial of Service | WSTG-BUSL-09 | ASVS-5.3.17 |
| `clickjacking` | Clickjacking | WSTG-CLNT-09 | ASVS-14.4.7 |
| `dom_xss` | DOM-based XSS | WSTG-CLNT-01 | ASVS-5.3.3 |
| `cve_scan` | CVE Mapping (44 CVEs, 14 stacks) | WSTG-INFO-02 | ASVS-14.2.1 |
| `s3_brute` | S3 Bucket Brute-Force | WSTG-CONF-10 | ASVS-14.2.3 |
| `wayback_urls` | Wayback / Archive URLs | WSTG-INFO-01 | ASVS-8.3.4 |
| `param_discover` | Parameter Discovery | WSTG-INFO-05 | ASVS-5.1.1 |
| `race_condition` | Race Condition | WSTG-BUSL-09 | ASVS-11.1.6 |
| `waf_bypass` | WAF Bypass | WSTG-CONF-07 | ASVS-14.4.1 |
| **`nosql_inject`** | **NoSQL Injection (MongoDB $ne/$gt/$regex)** | **WSTG-INPV-01** | **ASVS-5.3.4** |
| **`sspp`** | **Server-Side Prototype Pollution** | **WSTG-CLNT-10** | **ASVS-5.3.17** |
| **`oob_blind`** | **OOB Blind SSRF/XXE (interactsh)** | **WSTG-INPV-19** | **ASVS-5.5.2** |
| **`file_upload`** | **Malicious File Upload (RCE)** | **WSTG-BUSL-08** | **ASVS-12.2.1** |
| **`postmessage`** | **PostMessage & Browser Storage** | **WSTG-CLNT-10** | **ASVS-5.3.3** |
| **`acct_enum`** | **Account Enumeration** | **WSTG-IDNT-04** | **ASVS-2.7.1** |
| **`login_brute`** | **Expert Login Brute-Force (L1–L4)** | **WSTG-ATHN-03** | **ASVS-2.2.1** |

**Example — targeted scan:**
```bash
webscan https://target.com --scope sqli,xss,jwt,cors,headers -y
```

**Example — CI/CD pipeline (fail on high+critical):**
```bash
webscan https://target.com -y --fail-on-severity high
```

**Example — credential stuffing + brute-force:**
```bash
webscan https://target.com --combo breached_creds.txt -y
webscan https://target.com --spray "Summer2024!" -y
```

---

## What's New in v11.7

| Feature | Details |
|---------|---------|
| **77 Modules** | 6 new modules added (was 71) |
| **WSTG Mapping** | Every finding maps to OWASP Web Security Testing Guide ID (e.g. WSTG-INPV-05) |
| **ASVS Mapping** | Every finding maps to ASVS v5.0 control ID (e.g. ASVS-5.3.4) |
| **Code Snippets** | Remediation fields include fix examples and verification commands |
| **NoSQL Injection (M73)** | MongoDB $ne/$gt/$regex operator auth bypass + GET param injection |
| **Prototype Pollution (M74)** | SSPP via __proto__ / constructor.prototype POST to API endpoints |
| **OOB Blind (M75)** | Out-of-band Blind SSRF (AWS/GCP/Azure metadata timing) + Blind XXE |
| **File Upload (M76)** | PHP/JSP/ASPX shell upload, double extension, null byte, MIME bypass |
| **PostMessage (M77)** | Cross-origin postMessage wildcard + localStorage sensitive data detection |
| **Account Enumeration (M78)** | Different error messages for valid vs invalid users + response size analysis |
| **CI/CD `--fail-on-severity`** | Pipeline exits with code 1 if findings meet/exceed threshold severity |

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
- **WSTG ID** (e.g. WSTG-INPV-05) — Web Security Testing Guide
- **ASVS ID** (e.g. ASVS-5.3.4) — Application Security Verification Standard v5.0
- **CWE** reference number
- **CVSS v3.1** base score
- **URL** and **Evidence** (parameter, payload, response)
- **Recommendation** with code snippets and fix examples

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
webscan https://api.internal.com --scope api_sec,authn_bypass,jwt,graphql,cors,nosql_inject,sspp -y
```

**Full scan through Burp with Burp XML export:**
```bash
webscan https://target.com --proxy http://127.0.0.1:8080 --burp -y
```

**Compare before/after scans:**
```bash
webscan --compare ~/webscan-reports/scan_before.json ~/webscan-reports/scan_after.json
```

**CI/CD — fail pipeline on Critical/High:**
```bash
webscan https://staging.app.com -y -q --fail-on-severity high
echo "Exit: $?"  # 0 = pass, 1 = fail
```

---

## File Structure

```
webscan-pro/
├── webscan_pro.py    # Main scanner (~9,481 lines, single file, 77 modules)
├── install.sh        # Kali Linux installer
├── wordlist.txt      # 575-entry directory wordlist
└── README.md         # This file
```

---

## Legal

This tool is for **authorized penetration testing only**.  
Always obtain written permission before scanning any system.  
Unauthorized use is illegal and unethical.
