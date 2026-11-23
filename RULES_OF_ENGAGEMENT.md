# Authorised Lab Rules of Engagement (RoE)

**Project:** OWASP Web Testing Lab (Task 04)  
**Target Application:** OWASP Juice Shop (Locally Owned Instance)  
**Evaluator/Platform:** Edvyro Cybersecurity Internship  
**Assessment Type:** Web Application Penetration Testing & Vulnerability Assessment  
**Testing Standard:** OWASP Web Security Testing Guide (WSTG v4.2) / OWASP Top 10:2021  

---

## 1. Executive Statement of Authority
This security evaluation is performed under explicit authorization within a dedicated, locally owned training environment. The sole objective is to connect fundamental web security concepts to reproducible technical findings, business impact assessments, and defensive secure coding remediation.

Testing is restricted to the pre-approved training instance and strictly prohibits any offensive activities against external infrastructure, shared systems, or unauthorized third parties.

---

## 2. Scope Boundaries

### 2.1 In-Scope Targets
| Component | Target Identifier / URL | Description |
| :--- | :--- | :--- |
| **Local Web Application** | `http://localhost:3000/` | Main user interface (Angular Single Page Application) |
| **Backend REST APIs** | `http://localhost:3000/rest/*` | Express.js REST endpoints handling authentication, basket, user, and product data |
| **Data Layer** | SQLite / Sequelize ORM | Relational models storing users, credentials, products, and feedback |
| **HTTP Response Headers** | `http://localhost:3000/` | Transport layer and browser defense configuration |

### 2.2 Out-of-Scope Targets & Prohibited Actions
The following activities, targets, and methods are strictly prohibited:
- **Denial of Service (DoS / DDoS):** Volumetric flooding, resource starvation attacks, or disruption of the host machine.
- **Underlying Host & OS Exploitation:** Attempting privilege escalation or lateral movement outside the Node.js application process.
- **Third-Party Infrastructure:** Attacking external identity providers, CDNs, or external package registries.
- **Destructive Payloads:** Dropping ransomware, wiping system files, or altering underlying system configurations beyond reproducible non-destructive proof-of-concept tests.
- **Social Engineering & Phishing:** Simulating phishing attacks against human users or internship personnel.

---

## 3. Guiding Testing Domains
In compliance with the internship brief, testing is systematically concentrated on four core security domains:
1. **Authentication:** Verification of login mechanisms, credential validation, session issuance, and brute-force defenses.
2. **Access Control:** Validation of horizontal and vertical authorization, object-level access controls (BOLA/IDOR), and privilege escalation.
3. **Input Handling & Injection:** Evaluation of server and client-side input validation, parameter handling, Cross-Site Scripting (XSS), and SQL Injection (SQLi).
4. **Security Headers & Server Configuration:** Inspection of browser security directives, frame sandboxing, transport protection, and technology stack information leakage.

---

## 4. Evidence Sanitization & Responsible Disclosure Standards

To ensure safety and professionalism without exposing reusable attack targets:
- **Minimal Proof of Concept (PoC):** Proofs must be strictly minimal, deterministic, and non-destructive (e.g., executing benign `alert(1)` or retrieving canary strings rather than harvesting sensitive credentials).
- **Data Redaction & Sanitization:** All sensitive data (session tokens, email hashes, credit card numbers, passwords, and internal file paths) captured in screenshots or logs must be masked or redacted (e.g., `ad***@juice-sh.op`, `Bearer eyJhbG...[REDACTED]`).
- **No Weaponized Exploit Chaining:** Exploit demonstrations must stop at the confirmation boundary (proving the flaw exists) rather than escalating to full system compromise.

---

## 5. Finding Documentation Template
Every security finding identified during this lab must be documented using the standardized industry reporting format:
- **Finding ID & Title**
- **OWASP Top 10 & CWE Mapping**
- **CVSS v3.1 Severity Rating & Vector**
- **Vulnerable Component / Endpoint**
- **Minimal Proof of Concept (Sanitized Steps to Reproduce)**
- **Root Cause Analysis (Underlying Code Flaw)**
- **Business & Operational Impact**
- **Remediation & Secure Coding Implementation**
