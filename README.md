# Altoro-mutual-webtest
# Altoro Mutual (demo.testfire.net) — Web Application Penetration Test

A simulated black/grey-box web application penetration test against **Altoro Mutual** (`demo.testfire.net`), HCL AppScan's intentionally vulnerable demo banking application. This engagement follows a standard pentest methodology: reconnaissance → enumeration → vulnerability scanning → manual verification → exploitation → reporting.

> ⚠️ **Disclaimer:** `demo.testfire.net` is a publicly available, intentionally vulnerable training application provided by HCL for security testing practice. No unauthorized targets were tested. This report is for educational / portfolio purposes only.

---

## 📋 Table of Contents

- [Scope](#-scope)
- [Methodology](#-methodology)
- [Tools Used](#-tools-used)
- [Findings Summary](#-findings-summary)
- [Detailed Findings](#-detailed-findings)
- [Reconnaissance](#-reconnaissance)
- [Recommendations](#-recommendations)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🎯 Scope

| Item | Detail |
|---|---|
| **Application** | demo.testfire.net |
| **Resolved IP** | 65.61.137.117 |
| **In-Scope** | Hostname `demo.testfire.net`, resolved IP, all exposed TCP/UDP services |
| **Out-of-Scope** | DoS/DDoS attacks (live site), testing of external IPs |

---

## 🧭 Methodology

1. **Reconnaissance** — DNS enumeration, WHOIS, subdomain discovery, port/service scanning
2. **Enumeration** — technology fingerprinting, endpoint/directory discovery, archive/Wayback crawling
3. **Vulnerability Scanning** — Nessus, Nikto, Nuclei automated scans
4. **Manual Verification** — SSL/TLS deep-dive, HTTP method testing, traffic interception, SQL injection testing
5. **Reporting** — impact analysis and remediation guidance for each confirmed finding

---

## 🛠️ Tools Used

| Category | Tools |
|---|---|
| DNS / WHOIS | `dig`, `whois`, `dnsrecon` |
| Port/Service Scanning | `nmap` |
| Subdomain Enumeration | `subfinder`, `httpx` |
| Tech Fingerprinting | Wappalyzer |
| SSL/TLS Testing | `sslscan`, `testssl.sh` |
| Vulnerability Scanning | Nessus, Nikto, Nuclei |
| Web Proxy / Spidering | OWASP ZAP, Burp Suite (Endpointer extension) |
| Traffic Analysis | Wireshark |
| Historical Data | Wayback Machine CDX API |
| Manual Exploitation | `curl` |

---

## 📊 Findings Summary

| # | Finding | Severity |
|---|---|---|
| 1 | SQL Injection | 🔴 Critical |
| 2 | Credentials Transmitted in Plaintext (No HTTPS enforcement) | 🔴 Critical |
| 3 | Information Disclosure / Data Leakage (client files, reports, historical XML) | 🟠 High |
| 4 | Deprecated TLS Protocols (TLS 1.0 / 1.1 enabled, TLS 1.3 unsupported) | 🟠 High |
| 5 | Weak Diffie-Hellman Group — Logjam (CVE-2015-4000) | 🟠 High |
| 6 | Missing TLS Downgrade Protection (No TLS_FALLBACK_SCSV) | 🟡 Medium |
| 7 | Dangerous HTTP Methods Enabled (PUT, DELETE) | 🟡 Medium |
| 8 | Improper HTTP OPTIONS Handling (returns full page content) | 🟡 Medium |
| 9 | Missing Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.) | 🟡 Medium |
| 10 | Missing `SameSite` Cookie Attribute | 🔵 Low |
| 11 | Open Source Disclosure / Verbose Server Banner (Apache-Coyote/1.1) | 🔵 Low |

---

## 🔍 Detailed Findings

### 1. SQL Injection — Critical
The application was confirmed vulnerable to SQL Injection via error-based testing, evidenced by database error output returned to the client. This can allow an attacker to read, modify, or delete backend data, and potentially achieve full database compromise.

### 2. Credentials Transmitted in Plaintext — Critical
Traffic captured with Wireshark confirmed that login credentials are submitted over **HTTP**, not HTTPS.

**Root causes:**
- Authentication performed over HTTP instead of HTTPS
- No forced TLS redirection
- Absence of HSTS
- Login endpoint accepts credentials over insecure transport

**Impact:** Trivial credential interception by any attacker with network visibility (e.g., on shared/public networks), leading to account takeover.

### 3. Information Disclosure / Data Leakage — High
Wayback Machine (CDX API) crawling of `*.demo.testfire.net/*` surfaced historically indexed, sensitive files still reachable, including:
- `Docs.xml` — internal test/change-log data (e.g., business/product notes)
- `clients.xls` — client information spreadsheet
- `communityannualreport.pdf` — internal report

**Impact:** Exposure of internal business data and legacy artifacts, indicating weak server-side access controls and poor historical content hygiene.

### 4. Deprecated TLS Protocols — High
`testssl.sh` confirmed TLS 1.0 and TLS 1.1 are **offered** (deprecated per RFC 8996), while **TLS 1.3 is not supported**.

**Impact:** Enables downgrade to weaker encryption; fails PCI DSS, NIST, and Mozilla TLS baseline requirements.

### 5. Weak Diffie-Hellman Group (Logjam) — High
`CVE-2015-4000` — server offers a 1024-bit DH group (RFC2409/Oakley Group 2), which is cryptographically broken and susceptible to precomputation attacks.

**Impact:** Weakens confidentiality of encrypted traffic; may allow passive/active decryption under certain conditions.

### 6. Missing TLS Downgrade Protection — Medium
`TLS_FALLBACK_SCSV` (RFC 7507) is not supported, meaning an active attacker can force a protocol downgrade to a weaker TLS version — compounding the risk from Findings 4 and 5.

### 7. Dangerous HTTP Methods Enabled — Medium
Nikto identified that the server's `Allow` header advertises `PUT` and `DELETE` methods in addition to `GET, HEAD, POST, OPTIONS`.

**Impact:** If not properly access-controlled server-side, `PUT` could allow file upload/overwrite and `DELETE` could allow removal of server-side resources.

### 8. Improper HTTP OPTIONS Handling — Medium
An `OPTIONS` request to `/` returns the full HTML application content rather than a minimal method-disclosure response.

**Impact:** Increases attack surface via unintended interaction paths and unnecessary information disclosure; corroborates the unsafe-verb exposure identified by Nikto.

### 9. Missing Security Headers — Medium
Nuclei and Nikto both flagged the absence of standard hardening headers on responses:
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy` / `Cross-Origin-Embedder-Policy` / `Cross-Origin-Resource-Policy`
- `X-Permitted-Cross-Domain-Policies`
- `Clear-Site-Data`

**Impact:** Increased exposure to clickjacking, MIME-sniffing, and other client-side attacks.

### 10. Missing SameSite Cookie Attribute — Low
The `JSESSIONID` session cookie does not set a `SameSite=Strict/Lax` attribute, increasing CSRF exposure.

### 11. Verbose Server Banner — Low
The server discloses `Apache-Coyote/1.1` in response headers, aiding attacker fingerprinting/recon.

---

## 🔎 Reconnaissance

- **DNS:** Single A record resolving to `65.61.137.117`; no AAAA, NS, or MX records returned by direct query; DNSSEC not configured.
- **WHOIS:** IP block registered to Rackspace Hosting (San Antonio, TX), reassigned to Rackspace Backbone Engineering.
- **Port Scan (nmap):** Ports `80` (HTTP), `443` (HTTPS) open running Apache Tomcat/Coyote JSP engine 1.1; port `8080` open (tcpwrapped); port `8443` closed.
- **Subdomain Enumeration (subfinder):** 6 subdomains identified — `localhost`, `ftp`, `demo`, `evil`, `altoro`, `demo2` (all `.testfire.net`).
- **HTTP Method Scan:** `GET, HEAD, POST, OPTIONS` confirmed reachable via nmap; Nikto additionally observed `PUT, DELETE` advertised in the `Allow` header.
- **Automated Scanning:** Nessus, Nikto, and Nuclei scans run against the target, cross-referenced with manual verification to remove false positives.
- **Spidering:** OWASP ZAP used for site-map discovery; Wayback Machine CDX API used to recover historically archived paths and files.

---

## ✅ Recommendations

| Finding | Recommendation |
|---|---|
| SQL Injection | Use parameterized queries / prepared statements; apply input validation and a WAF as defense-in-depth |
| Plaintext credentials | Enforce HTTPS site-wide, redirect all HTTP→HTTPS, implement HSTS |
| Data leakage | Remove sensitive files from web root, submit takedown/exclusion requests to archive services, audit for other exposed legacy files |
| Deprecated TLS | Disable TLS 1.0/1.1, enable TLS 1.3, disable weak cipher suites |
| Logjam / weak DH | Replace 1024-bit DH groups with ≥2048-bit or use ECDHE exclusively |
| No downgrade protection | Enable `TLS_FALLBACK_SCSV` support |
| Dangerous HTTP methods | Disable `PUT`/`DELETE` at the web server/application level unless explicitly required and access-controlled |
| OPTIONS handling | Configure server to return minimal `Allow` header responses for `OPTIONS`, not full page content |
| Missing security headers | Implement CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and related headers |
| Cookie flags | Set `SameSite=Strict` (or `Lax`) on session cookies |
| Server banner | Suppress/minimize version disclosure in server headers |

---

## 📁 Repository Structure

```
altoro-mutual-pentest/
├── README.md
├── recon/
│   ├── dns_records.txt
│   ├── whois.txt
│   ├── nmap_scan.txt
│   └── subdomains.txt
├── ssl_tls/
│   ├── sslscan_result.txt
│   └── testssl_result.txt
├── vuln_scans/
│   ├── nessus_report.pdf
│   ├── nikto_scan.txt
│   └── nuclei_scan.txt
├── screenshots/
│   ├── wappalyzer.jpg
│   ├── zap_spider.jpg
│   ├── wireshark_test.jpg
│   ├── nessus_vuln_scan.jpg
│   ├── error_based_injection.jpg
│   ├── client_information.jpg
│   └── comm_pdfleakage.jpg
└── evidence/
    ├── clients.xls
    └── communityannualreport.pdf
```

---

## ⚖️ Disclaimer

This assessment was performed against a publicly available, intentionally vulnerable demo application (`demo.testfire.net`) provided by HCL for security research and training purposes. All testing was conducted within the defined scope and in accordance with responsible testing practices. This repository is intended solely for educational and portfolio purposes and does not constitute an authorization to test any other system.
