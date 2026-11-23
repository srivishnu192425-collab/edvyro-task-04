# OWASP Web Testing Lab - Starter Checklist

**Project:** Task 04 - OWASP Web Testing Lab  
**Student/Intern:** Srivishnu R  
**Platform:** Edvyro Internship  
**Status:** Completed & Ready for Submission  

---

## Lab Preparation & Scope Compliance
- [x] **Step 0.1:** Review Rules of Engagement (`RULES_OF_ENGAGEMENT.md`) and verify authorized local testing boundaries.
- [x] **Step 0.2:** Identify target endpoints, network parameters, and application architecture (Node.js/Express, Angular SPA, SQLite/Sequelize).
- [x] **Step 0.3:** Establish evidence sanitization protocols (masking credentials, tokens, PII).

---

## Core Testing Phases (Requirements to Pass)

### 1. Authentication Testing
- [x] **Step 1.1:** Test login interface against SQL Injection authentication bypass (`' OR 1=1--`).
- [x] **Step 1.2:** Verify session token issuance upon successful authentication bypass.
- [x] **Step 1.3:** Test password complexity requirements and credential brute-force protection / rate limiting.
- [x] **Step 1.4:** Capture minimal, sanitized proof of concept for confirmed authentication flaws.
- [x] **Step 1.5:** Document code-level root cause and business impact (account takeover, administrative compromise).

### 2. Access Control Testing
- [x] **Step 2.1:** Inspect client-side routing definitions for unlinked administrative interfaces (`/#/administration`).
- [x] **Step 2.2:** Verify lack of server-side role-based access control (RBAC) on administrative endpoints.
- [x] **Step 2.3:** Test for Insecure Direct Object References (IDOR / BOLA) on basket and order APIs (`/rest/basket/{basketId}`).
- [x] **Step 2.4:** Capture non-destructive proof demonstrating unauthorized cross-user data access.
- [x] **Step 2.5:** Document root cause (missing authorization middleware) and business impact (data leakage, GDPR breach).

### 3. Input Handling & Injection Testing
- [x] **Step 3.1:** Test search parameter handling for Cross-Site Scripting (XSS) vectors.
- [x] **Step 3.2:** Execute DOM-based XSS verification using benign proof-of-concept payload (`<iframe src="javascript:alert('XSS')">`).
- [x] **Step 3.3:** Test SQL Injection vulnerabilities in backend product and review search APIs.
- [x] **Step 3.4:** Confirm absence of context-aware output encoding and parameterized queries.
- [x] **Step 3.5:** Document root cause and business impact (session hijacking, defacement, unauthorized database exfiltration).

### 4. Security Headers & Configuration Testing
- [x] **Step 4.1:** Inspect HTTP response headers for defensive browser headers:
  - [x] Content-Security-Policy (CSP)
  - [x] Strict-Transport-Security (HSTS)
  - [x] X-Frame-Options (Clickjacking defense)
  - [x] X-Content-Type-Options (MIME-sniffing defense)
  - [x] Referrer-Policy & Permissions-Policy
- [x] **Step 4.2:** Identify information leakage via server signature headers (`Server: Express`, `X-Powered-By`).
- [x] **Step 4.3:** Formulate Helmet.js hardening middleware configuration for production deployment.

---

## Deliverables & Submission Verification
- [x] **Step 5.1:** Compile comprehensive **Sanitized Findings Table** with:
  - Vulnerability ID & Title
  - OWASP Top 10 & CWE classifications
  - CVSS v3.1 Severity Rating & Score
  - Sanitized Minimal Evidence / Proof of Concept
  - Root Cause Analysis
  - Business & Operational Impact
  - Actionable Secure Coding Remediation
- [x] **Step 5.2:** Export findings table into structured CSV format (`FINDINGS_TABLE.csv`).
- [x] **Step 5.3:** Create concrete secure coding remediation examples (`remediation/`) with before-and-after source code diffs.
- [x] **Step 5.4:** Write automated non-destructive verification script (`scripts/test_security_headers.py`).
- [x] **Step 5.5:** Assemble complete portfolio-grade security assessment report (`README.md`).
- [x] **Step 5.6:** Verify repository structure is self-contained and ready for single-link submission.
