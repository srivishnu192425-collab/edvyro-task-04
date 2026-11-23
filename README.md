# OWASP Web Testing Lab - Security Assessment Report & Findings

**Project:** Task 04 - OWASP Web Testing Lab  
**Intern / Security Analyst:** Srivishnu R  
**Program:** Edvyro Cybersecurity Internship  
**Target Application:** OWASP Juice Shop (Locally Owned Instance `http://localhost:3000`)  
**Methodology:** OWASP Web Security Testing Guide (WSTG v4.2) / OWASP Top 10:2021  
**Deliverable Status:** Complete & Verified (Ready for Portfolio & Single-Link Submission)  

---

## 1. Executive Summary

During the authorized web application security assessment of the training application (**OWASP Juice Shop**), comprehensive penetration testing and code audits were executed across four primary security domains:
1. **Authentication**
2. **Access Control**
3. **Input Handling & Injection**
4. **Security Headers & Server Configuration**

The assessment confirmed multiple high-impact vulnerabilities resulting from missing input sanitization, insecure direct object references, absent server-side authorization checks, and unhardened transport configurations. All findings were validated strictly within the authorized training boundary using **minimal, non-destructive proofs of concept** and sanitized evidence to avoid exposing reusable attack targets.

### Vulnerability Severity Breakdown
| Severity Level | Count | Findings |
| :--- | :---: | :--- |
| **Critical** | 1 | SEC-01 (SQLi Authentication Bypass) |
| **High** | 4 | SEC-02 (Brute Force/Weak Auth), SEC-03 (Basket IDOR), SEC-04 (Admin Panel BOLA), SEC-06 (Product Search SQLi) |
| **Medium** | 2 | SEC-05 (DOM Cross-Site Scripting), SEC-07 (Missing Security Headers & Info Leakage) |
| **Total Findings** | **7** | **100% Documented with Root Cause, PoC, and Secure Code Fixes** |

---

## 2. Scope & Rules of Engagement Summary

All testing adhered to the formal [Rules of Engagement](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/RULES_OF_ENGAGEMENT.md):
- **Authorized Target:** `http://localhost:3000` (Local Node.js/Express + Angular application).
- **Prohibited Actions:** No Denial of Service (DoS), no brute-forcing of external networks, and no modification of host operating systems.
- **Evidence Sanitization:** All sensitive credentials, session tokens, and personal identifiable information (PII) captured during verification are redacted (e.g., `admin@juice-sh.op`, `Bearer eyJhb...[REDACTED]`).
- **Minimal Proofs:** Proof-of-concept demonstrations utilize minimal benign indicators (such as canary strings and `alert('XSS')`) rather than destructive payloads.

---

## 3. Master Sanitized Findings Table

The table below summarizes all confirmed vulnerabilities, mapped to OWASP Top 10:2021 categories, CWE classifications, CVSS v3.1 scores, minimal proofs, root causes, business impacts, and remediations.

| Finding ID | Vulnerability Title | OWASP / CWE | CVSS v3.1 | Affected Endpoint / Parameter | Minimal Sanitized Evidence (PoC) | Root Cause Analysis | Business & Technical Impact | Remediation / Secure Coding Fix |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | SQL Injection Authentication Bypass | A03:2021-Injection<br>A07:2021-Auth Failures<br>CWE-89 | **9.8 (Critical)**<br>`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `POST /rest/user/login`<br>`email` | Submitting `' OR 1=1--` with arbitrary password returns HTTP 200 and admin JWT for `admin@juice-sh.op`. | Unsanitized string concatenation in backend Sequelize raw SQL query without parameter binding. | Total administrative account takeover, unauthorized database access, full platform compromise. | Use parameterized queries via Sequelize ORM `where` clause or bound replacement variables. |
| **SEC-02** | Weak Password Requirements & No Rate Limiting | A07:2021-Auth Failures<br>CWE-521 / CWE-307 | **7.5 (High)**<br>`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | `POST /rest/user/login`<br>`POST /api/Users` | User accounts can be created with 1-character passwords; 100+ rapid login attempts pass without throttling. | Missing schema-level password complexity enforcement and absence of rate-limiting middleware. | Susceptibility to credential stuffing, brute-force dictionary attacks, and mass account compromise. | Implement `express-rate-limit` (5 attempts/15 min) and enforce 12+ character regex validation. |
| **SEC-03** | Insecure Direct Object Reference (IDOR) on Basket | A01:2021-Broken Access Control<br>CWE-639 | **8.5 (High)**<br>`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` | `GET /rest/basket/{bid}`<br>`basketId` | Authenticated User A (`bid=3`) alters path to `/rest/basket/2` and views User B's cart contents and prices. | Server blindly trusts client-provided path parameter without checking JWT session user ownership. | Customer PII disclosure, shopping cart manipulation, privacy law (GDPR) non-compliance. | Extract `bid` strictly from authenticated server-side JWT session token (`req.user.bid`). |
| **SEC-04** | Missing Function-Level Access Control (Admin Panel) | A01:2021-Broken Access Control<br>CWE-285 | **8.8 (High)**<br>`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | `GET /#/administration`<br>`GET /api/Users/` | Regular authenticated user can navigate directly to admin UI and retrieve list of all registered users. | Angular router lacks route guards and backend API lacks role-based access control (RBAC) middleware. | Privilege escalation, unauthorized modification/deletion of accounts, mass data exposure. | Enforce server-side role validation middleware (`verifyRole('admin')`) and Angular `AdminGuard`. |
| **SEC-05** | DOM-Based Cross-Site Scripting (XSS) in Search | A03:2021-Injection<br>CWE-79 | **6.1 (Medium)**<br>`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | `/#/search?q=`<br>`q` parameter | Submitting `<iframe src="javascript:alert('XSS')">` executes JavaScript in the victim's browser context. | Query string is rendered into DOM via Angular `bypassSecurityTrustHtml` without output encoding. | Session token theft (JWT stored in localStorage), phishing overlays, credential harvesting. | Remove security bypass, enforce default Angular interpolation `{{ query }}`, sanitize with DOMPurify. |
| **SEC-06** | Second-Order / Product Search SQL Injection | A03:2021-Injection<br>CWE-89 | **8.6 (High)**<br>`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` | `GET /rest/products/search?q=`<br>`q` | Injecting `q')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--` leaks user credentials. | Raw search query string is directly interpolated into backend SQL `LIKE` clause. | Unauthorized database extraction, mass credential leakage, exposure of proprietary pricing data. | Utilize parameterized queries using Sequelize ORM `Op.like` abstractions. |
| **SEC-07** | Missing Defensive Security Headers & Info Leakage | A05:2021-Security Misconfiguration<br>CWE-1021 / CWE-693 | **6.5 (Medium)**<br>`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` | HTTP/1.1 Response Headers | Server response lacks `CSP`, `X-Frame-Options`, `HSTS`; leaks `Server: Express` banner. | Default Express server configuration lacks security header middleware and banner suppression. | Clickjacking via iframe embedding, MIME-type sniffing, targeted exploits via version fingerprinting. | Implement `helmet` middleware suite with strict CSP, `frameguard`, HSTS, and `app.disable('x-powered-by')`. |

*(A raw CSV version is also available at [`FINDINGS_TABLE.csv`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/FINDINGS_TABLE.csv))*

---

## 4. Deep-Dive Vulnerability Analysis by Testing Domain

### Domain 1: Authentication Testing

#### Finding SEC-01: SQL Injection Authentication Bypass on Login Endpoint
- **Severity:** Critical (CVSS 9.8)
- **Vulnerable Component:** `POST /rest/user/login`
- **Minimal Sanitized Reproduction Steps:**
  1. Navigate to the login dialog (`/#/login`).
  2. In the `email` field, submit the SQL injection string: `' OR 1=1--`
  3. In the `password` field, enter any arbitrary string (e.g., `Test1234!`).
  4. Submit the request.
  5. **Result:** The application responds with HTTP `200 OK` and returns a valid JSON Web Token (JWT) authenticating the session as user ID `1` (`admin@juice-sh.op`).
- **Code-Level Root Cause:**
  The server constructs SQL statements using unsafe string concatenation:
  ```javascript
  // VULNERABLE CODE (routes/login.js)
  models.sequelize.query(
    `SELECT * FROM Users WHERE email = '${req.body.email}' AND password = '${security.hash(req.body.password)}' AND deletedAt IS NULL`,
    { model: models.User, plain: true }
  )
  ```
  The payload `' OR 1=1--` comments out the password evaluation and forces the `WHERE` condition to evaluate to true for the first row in the `Users` table (the administrator).
- **Business Impact:** Immediate, unauthenticated takeover of the primary administrator account, exposing customer records, payment details, and administrative controls.
- **Secure Remediation:** Use Sequelize's built-in parameterized query API:
  ```javascript
  // SECURE REMEDIATION
  const user = await UserModel.findOne({
    where: {
      email: req.body.email.trim().toLowerCase(),
      deletedAt: null
    }
  });
  ```
  *(See full patch in [`remediation/authentication_fix.js`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/remediation/authentication_fix.js))*

---

#### Finding SEC-02: Weak Password Complexity & Lack of Rate Limiting
- **Severity:** High (CVSS 7.5)
- **Vulnerable Component:** `POST /api/Users` & `POST /rest/user/login`
- **Minimal Sanitized Reproduction Steps:**
  1. Send a user registration request with password set to `"a"`. Registration succeeds without warning.
  2. Send 100 consecutive automated login requests with incorrect credentials using a Python script.
  3. All 100 requests return HTTP `401 Unauthorized` without any IP throttling, delay, or CAPTCHA challenge.
- **Code-Level Root Cause:** No server-side schema validation exists for password entropy or character classes, and no rate-limiting middleware is mounted on authentication endpoints.
- **Business Impact:** High exposure to credential stuffing and brute-force dictionary attacks, resulting in mass user account takeovers.
- **Secure Remediation:** Mount `express-rate-limit` and enforce password validation schemas:
  ```javascript
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many login attempts. Please try again after 15 minutes.' }
  });
  app.use('/rest/user/login', authLimiter);
  ```

---

### Domain 2: Access Control Testing

#### Finding SEC-03: Insecure Direct Object Reference (IDOR) on User Basket
- **Severity:** High (CVSS 8.5)
- **Vulnerable Component:** `GET /rest/basket/{basketId}`
- **Minimal Sanitized Reproduction Steps:**
  1. Log in as an authenticated non-admin user (assigned basket ID `3`).
  2. Capture the outgoing request: `GET /rest/basket/3` (contains the user's shopping cart).
  3. Change the path parameter to `GET /rest/basket/2` (belonging to another customer).
  4. **Result:** The server responds with HTTP `200 OK`, returning the full item contents, quantities, and pricing data of basket `2`.
- **Code-Level Root Cause:**
  ```javascript
  // VULNERABLE CODE (routes/basket.js)
  models.Basket.findOne({ where: { id: req.params.id } })
    .then(basket => res.json({ status: 'success', data: basket }));
  ```
  The endpoint queries the database directly using `req.params.id` without checking if the authenticated user's session token (`req.user.bid`) matches the requested ID.
- **Business Impact:** Horizontal privilege escalation, exposure of customer purchase behavior and PII, violation of data protection laws (GDPR Art. 32).
- **Secure Remediation:** Enforce session-to-object ownership validation:
  ```javascript
  // SECURE REMEDIATION
  if (req.user.role !== 'admin' && req.user.bid !== parseInt(req.params.id, 10)) {
    return res.status(403).json({ error: 'Access denied: You do not own this basket.' });
  }
  ```
  *(See full patch in [`remediation/access_control_fix.js`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/remediation/access_control_fix.js))*

---

#### Finding SEC-04: Missing Function-Level Access Control (Admin Panel Exposure)
- **Severity:** High (CVSS 8.8)
- **Vulnerable Component:** `GET /#/administration` & `GET /api/Users/`
- **Minimal Sanitized Reproduction Steps:**
  1. Authenticate as a standard non-administrative user.
  2. In the browser URL bar, manually navigate to `http://localhost:3000/#/administration`.
  3. The administrative dashboard loads, displaying customer accounts, email addresses, and admin actions.
  4. Issuing `GET /api/Users/` with the standard user's bearer token successfully returns all registered user records.
- **Code-Level Root Cause:** The client-side Angular router lacks route authorization guards, and the server-side REST API lacks role verification middleware on `/api/Users`.
- **Business Impact:** Vertical privilege escalation allowing standard users to view and modify administrative records and manipulate user permissions.
- **Secure Remediation:** Implement role-verification middleware on the Express API and apply Angular `CanActivate` route guards:
  ```javascript
  function requireRole(allowedRole) {
    return (req, res, next) => {
      if (!req.user || req.user.role !== allowedRole) {
        return res.status(403).json({ error: 'Forbidden: Administrative privileges required.' });
      }
      next();
    };
  }
  app.use('/api/Users', authenticateToken, requireRole('admin'));
  ```

---

### Domain 3: Input Handling & Injection Testing

#### Finding SEC-05: DOM-Based Cross-Site Scripting (XSS) in Search
- **Severity:** Medium (CVSS 6.1)
- **Vulnerable Component:** `/#/search?q=` (Search Input)
- **Minimal Sanitized Reproduction Steps:**
  1. Enter the minimal benign payload into the search bar: `<iframe src="javascript:alert('XSS')">`
  2. Press Enter or trigger search: `http://localhost:3000/#/search?q=<iframe src="javascript:alert('XSS')">`
  3. **Result:** An alert dialog displaying `XSS` appears immediately, confirming arbitrary JavaScript execution within the client's origin.
- **Code-Level Root Cause:**
  The Angular component explicitly bypasses the framework's built-in sanitizer:
  ```typescript
  // VULNERABLE CODE (search-result.component.ts)
  this.sanitizer.bypassSecurityTrustHtml(this.searchQuery);
  ```
- **Business Impact:** Malicious actors can craft phishing links that steal authentication tokens from `localStorage`, hijack user sessions, or manipulate DOM contents.
- **Secure Remediation:** Rely on Angular's context-aware string interpolation `{{ query }}` and sanitize untrusted HTML with DOMPurify:
  ```typescript
  // SECURE REMEDIATION
  import * as DOMPurify from 'dompurify';
  this.cleanSearchTerm = DOMPurify.sanitize(userQuery, { ALLOWED_TAGS: [] });
  ```
  *(See full patch in [`remediation/xss_sanitization.ts`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/remediation/xss_sanitization.ts))*

---

#### Finding SEC-06: Second-Order / Product Search SQL Injection
- **Severity:** High (CVSS 8.6)
- **Vulnerable Component:** `GET /rest/products/search?q=`
- **Minimal Sanitized Reproduction Steps:**
  1. Issue a search request with a `UNION SELECT` payload:
     `GET /rest/products/search?q=q')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--`
  2. **Result:** The application appends internal user database records (including email addresses and hashed passwords) directly into the product result list.
- **Code-Level Root Cause:** Unsanitized string concatenation in backend Sequelize raw SQL query inside `routes/search.js`.
- **Business Impact:** Total database exfiltration, unauthorized extraction of user credentials, and loss of intellectual property.
- **Secure Remediation:** Use parameterized queries via Sequelize's `Op.like` operator:
  ```javascript
  const products = await ProductModel.findAll({
    where: {
      name: { [Op.like]: `%${cleanQuery}%` }
    }
  });
  ```

---

### Domain 4: Security Headers & Server Configuration Testing

#### Finding SEC-07: Missing Defensive HTTP Headers & Technology Disclosure
- **Severity:** Medium (CVSS 6.5)
- **Vulnerable Component:** HTTP/1.1 Response Headers on `/`
- **Minimal Sanitized Reproduction Steps:**
  1. Execute the automated header audit script:
     ```bash
     python scripts/test_security_headers.py
     ```
  2. **Audit Findings Summary:**
     - ❌ **`Content-Security-Policy`**: Missing (permits unauthorized script execution and resource loading).
     - ❌ **`X-Frame-Options`**: Missing (allows application framing, enabling Clickjacking).
     - ❌ **`Strict-Transport-Security` (HSTS)**: Missing (allows SSL-stripping and downgrade attacks).
     - ❌ **`X-Content-Type-Options`**: Missing (permits MIME-type sniffing).
     - ⚠️ **`Server` / `X-Powered-By`**: Leaked (`Express`), exposing backend framework details.
- **Code-Level Root Cause:** The Node.js Express server is deployed with default configurations without security header middleware.
- **Business Impact:** Susceptibility to Clickjacking attacks (tricking users into clicking invisible UI overlays), MIME sniffing attacks, and targeted automated vulnerability scanning based on disclosed framework versions.
- **Secure Remediation:** Integrate the `helmet` middleware suite and suppress framework banners:
  ```javascript
  const helmet = require('helmet');
  app.disable('x-powered-by');
  app.use(helmet({
    contentSecurityPolicy: { directives: { defaultSrc: ["'self'"] } },
    frameguard: { action: 'deny' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    noSniff: true
  }));
  ```
  *(See full patch in [`remediation/security_headers_helmet.js`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/remediation/security_headers_helmet.js))*

---

## 5. Automated Verification & Testing Tools

An automated security header audit tool is provided in the repository to evaluate target headers in compliance with the Rules of Engagement:

- **Script:** [`scripts/test_security_headers.py`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/scripts/test_security_headers.py)
- **Execution Command:**
  ```powershell
  python scripts\test_security_headers.py
  ```
- **Generated Report:** [`scripts/audit_results.json`](file:///c:/Users/Srivishnu%20R/Documents/INTERNSHIPS/EDVYRO%20INTERN/TASK%2004/scripts/audit_results.json)

---

## 6. Repository Structure & Deliverables

```
TASK 04/
├── README.md                      # Comprehensive Assessment Report & Findings (This document)
├── CHECKLIST.md                   # Completed Starter Checklist matching portal criteria
├── RULES_OF_ENGAGEMENT.md         # Authorized Lab Scope, Boundaries, and RoE
├── FINDINGS_TABLE.md              # Markdown Sanitized Findings Table
├── FINDINGS_TABLE.csv             # Structured CSV export of all findings
├── remediation/                   # Concrete Secure Coding Fixes (Before vs. After)
│   ├── authentication_fix.js      # Parameterized login & rate limiting (SEC-01 & SEC-02)
│   ├── access_control_fix.js      # Object-level ownership & RBAC middleware (SEC-03 & SEC-04)
│   ├── xss_sanitization.ts        # Safe Angular template binding & DOMPurify (SEC-05)
│   └── security_headers_helmet.js # Production Helmet.js header configuration (SEC-07)
└── scripts/                       # Verification Tools
    ├── test_security_headers.py   # Automated HTTP security header inspection script
    └── audit_results.json         # Automated audit results log
```

---

## 7. Submission Instructions (One Proof Link)

Per the task submission guidelines:
> *"Submit: Submit one public or view-only link. Put supporting files in the same repository, folder, or project page so one link is enough."*

To submit:
1. **GitHub Repository Submission:**
   Push this `TASK 04` directory to a public GitHub repository (e.g., `https://github.com/<your-username>/owasp-web-testing-lab`). The root `README.md` will display the full formatted security assessment report, findings table, and links to all supporting code.
2. **Google Drive / Cloud Folder Submission:**
   Zip or upload this entire `TASK 04` directory to Google Drive, set permissions to **"Anyone with the link can view"**, and submit that single view-only link in the portal.
