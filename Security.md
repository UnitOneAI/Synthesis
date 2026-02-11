# Unitone Sentinel — Security Reference: Threat Model Templates, Grammar & OWASP Top 10

## Table of Contents

1. [Threat Model Grammar (AWS Threat Composer)](#1-threat-model-grammar-aws-threat-composer)
2. [STRIDE Framework Reference](#2-stride-framework-reference)
3. [OWASP Top 10 (2021) Threat Mapping](#3-owasp-top-10-2021-threat-mapping)
4. [Threat Statement Templates](#4-threat-statement-templates)
5. [Data Flow Diagram (DFD) Standards](#5-data-flow-diagram-dfd-standards)
6. [Threat Model Process Methodology](#6-threat-model-process-methodology)
7. [Mitigation Pattern Library](#7-mitigation-pattern-library)
8. [Sources & References](#8-sources--references)

---

## 1. Threat Model Grammar (AWS Threat Composer)

### 1.1 Canonical Grammar Structure

The AWS Threat Composer defines a structured grammar for writing consistent, actionable threat statements:

```
A [THREAT SOURCE] with [PREREQUISITES] can [THREAT ACTION],
which leads to [THREAT IMPACT], negatively impacting [IMPACTED ASSETS].
```

### 1.2 Field Definitions

| Field | Description | Purpose |
|-------|-------------|---------|
| **Threat Source** | The entity performing the threat action | Identifies WHO or WHAT is the adversary |
| **Prerequisites** | Conditions that must be true for the threat to be viable | Scopes the threat to realistic scenarios |
| **Threat Action** | The specific malicious or unintended action taken | Describes WHAT happens |
| **Threat Impact** | The direct consequence of a successful threat action | Describes the DAMAGE |
| **Impacted Assets** | The systems, data, or properties negatively affected | Identifies WHAT is at risk |

### 1.3 Extended Grammar (CIA Triad Variant)

```
A [THREAT SOURCE] with [PREREQUISITES] can [THREAT ACTION],
which leads to [THREAT IMPACT], resulting in reduced
[CONFIDENTIALITY and/or INTEGRITY and/or AVAILABILITY] of [IMPACTED ASSETS].
```

### 1.4 Grammar Construction Rules

1. **Threat Source** must be a specific actor, not generic ("An authenticated tenant user" not "a hacker")
2. **Prerequisites** should include access level, knowledge, and tooling required
3. **Threat Action** must be a concrete, verifiable action (not vague like "compromise the system")
4. **Threat Impact** should describe the business or operational consequence
5. **Impacted Assets** should reference specific system components from the DFD

### 1.5 Example Threat Statements

**Example 1 — Elevation of Privilege:**
```
A [authenticated tenant user] with [API access and knowledge of sequential building IDs]
can [modify the building_id parameter in HVAC setpoint API calls],
which leads to [unauthorized temperature manipulation in other tenants' facilities],
negatively impacting [tenant data isolation and HVAC control plane integrity].
```

**Example 2 — Information Disclosure:**
```
A [developer with repository access] with [read access to the cloud gateway configuration files]
can [extract hardcoded API keys committed to source control],
which leads to [unauthorized authentication as the gateway service account],
negatively impacting [confidentiality of the API gateway and downstream service data].
```

**Example 3 — Tampering:**
```
A [network-adjacent attacker on the building LAN] with [ARP spoofing capabilities]
can [intercept and modify MQTT messages between the cloud broker and BACnet/IP gateway],
which leads to [injection of malicious control commands to chiller units],
negatively impacting [integrity of the building control system and physical safety].
```

**Example 4 — Denial of Service:**
```
A [authenticated operator] with [access to the scheduling API]
can [create recursive HVAC scheduling rules that trigger infinite compute loops],
which leads to [exhaustion of API gateway compute resources],
negatively impacting [availability of the building management platform for all tenants].
```

**Example 5 — Spoofing (GenAI context):**
```
A [threat actor] with [access to the public-facing application]
can [inject malicious prompts that overwrite existing system prompts],
which leads to [healthcare data from other patients being returned],
negatively impacting [confidentiality of the data in the database].
```

---

## 2. STRIDE Framework Reference

### 2.1 Category Definitions

STRIDE was developed by Loren Kohnfelder and Praerit Garg at Microsoft. Each category maps to a violated security property:

| Category | Security Property Violated | Definition |
|----------|---------------------------|------------|
| **S**poofing | Authentication | Pretending to be something or someone other than yourself |
| **T**ampering | Integrity | Modifying something on disk, network, or in memory without authorization |
| **R**epudiation | Non-Repudiation | Claiming you didn't do something, or were not responsible |
| **I**nformation Disclosure | Confidentiality | Providing information to someone not authorized to see it |
| **D**enial of Service | Availability | Absorbing resources needed to provide service |
| **E**levation of Privilege | Authorization | Allowing someone to do something they are not authorized to do |

### 2.2 STRIDE-per-Element Mapping

Apply STRIDE to each element type in a Data Flow Diagram:

| DFD Element | S | T | R | I | D | E |
|-------------|---|---|---|---|---|---|
| **External Entity** | X | | | | | |
| **Process** | X | X | X | X | X | X |
| **Data Store** | | X | ? | X | X | |
| **Data Flow** | | X | | X | X | |

- `X` = applicable threat category
- `?` = applicable in some contexts

### 2.3 STRIDE Threat Examples by Category

#### Spoofing
- Stealing authentication tokens or session cookies
- DNS spoofing to redirect traffic
- ARP spoofing on local networks
- Forging email sender addresses
- Cloning API keys from configuration files

#### Tampering
- SQL injection to modify database records
- Man-in-the-middle modification of API responses
- Firmware downgrade attacks on edge devices
- Modifying log files to cover tracks
- Changing configuration files to weaken security

#### Repudiation
- Performing actions without audit logging
- Deleting or modifying audit trails
- Using shared service accounts (no individual attribution)
- Transactions without receipts or confirmations
- Unsigned API requests (no proof of origin)

#### Information Disclosure
- Verbose error messages exposing stack traces
- Directory listing enabled on web servers
- Hardcoded secrets in source code repositories
- Unencrypted data in transit or at rest
- Metadata leakage in API responses (internal IPs, versions)

#### Denial of Service
- API rate limit bypass causing resource exhaustion
- Recursive or deeply nested input processing
- Large file upload without size limits
- Connection pool exhaustion
- DNS amplification attacks

#### Elevation of Privilege
- IDOR (Insecure Direct Object Reference)
- JWT token manipulation (changing role claims)
- Path traversal to access restricted files
- Buffer overflow leading to code execution
- Exploiting default admin credentials

---

## 3. OWASP Top 10 (2021) Threat Mapping

### 3.1 Full Category Reference

#### A01:2021 — Broken Access Control

**CWEs Mapped:** 34 (most mapped category)

**Description:** Restrictions on what authenticated users are allowed to do are not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data.

**Common Patterns:**
- Violation of least privilege or deny by default
- Bypassing access control by modifying URL, app state, or HTML page
- Permitting viewing or editing someone else's account (IDOR)
- Accessing API with missing access controls for POST, PUT, DELETE
- Elevation of privilege (acting as user without login, acting as admin when logged in as user)
- CORS misconfiguration allowing unauthorized API access
- Force browsing to authenticated or privileged pages

**Threat Template:**
```
A [user with valid low-privilege credentials] with [knowledge of API endpoint patterns]
can [access or modify resources belonging to other users by manipulating resource identifiers],
which leads to [unauthorized data access or modification],
negatively impacting [data confidentiality and integrity of user resources].
```

**Mitigations:**
- Implement server-side access control, not client-side
- Deny by default except for public resources
- Use ABAC/RBAC for all API endpoints
- Disable web server directory listing
- Log access control failures and alert on repeated failures
- Rate limit API and controller access

---

#### A02:2021 — Cryptographic Failures

**CWEs Mapped:** 29

**Description:** Failures related to cryptography which often lead to sensitive data exposure or system compromise.

**Common Patterns:**
- Data transmitted in clear text (HTTP, SMTP, FTP)
- Old or weak cryptographic algorithms (MD5, SHA1, DES)
- Default or weak crypto keys, key reuse, poor key management
- Missing certificate validation
- Passwords stored with reversible encryption or unsalted hashes
- Deprecated hash functions for password storage (MD5, SHA-256 without stretching)

**Threat Template:**
```
A [network-positioned attacker] with [ability to intercept network traffic]
can [capture credentials or sensitive data transmitted without encryption],
which leads to [exposure of user credentials and personal data],
negatively impacting [confidentiality of user data and authentication secrets].
```

**Mitigations:**
- Classify data processed, stored, or transmitted and apply controls per classification
- Encrypt all data in transit with TLS 1.2+
- Encrypt all sensitive data at rest
- Use strong adaptive hashing for passwords (bcrypt, scrypt, Argon2)
- Use authenticated encryption (AES-GCM)
- Generate keys with cryptographically secure random generators

---

#### A03:2021 — Injection

**CWEs Mapped:** 33

**Description:** User-supplied data is not validated, filtered, or sanitized by the application. Includes SQL injection, NoSQL injection, OS command injection, LDAP injection, and cross-site scripting (XSS).

**Common Patterns:**
- Dynamic queries or non-parameterized calls without escaping
- Hostile data used within ORM search parameters
- Hostile data directly used or concatenated in SQL/commands
- User input reflected in HTML without output encoding (XSS)

**Threat Template:**
```
A [unauthenticated external attacker] with [access to the application's input fields]
can [inject malicious SQL/NoSQL/OS commands through unsanitized input parameters],
which leads to [unauthorized data access, modification, or deletion],
negatively impacting [integrity and confidentiality of the application database].
```

**Mitigations:**
- Use parameterized queries or prepared statements
- Use positive server-side input validation
- Escape special characters for any remaining dynamic queries
- Use LIMIT and other SQL controls to prevent mass disclosure
- Enable Content Security Policy (CSP) to mitigate XSS

---

#### A04:2021 — Insecure Design

**CWEs Mapped:** 40

**Description:** Risks related to design and architectural flaws. This is distinct from implementation bugs — it represents missing or ineffective control design.

**Common Patterns:**
- No threat modeling during design phase
- Missing business logic validation
- No defense in depth
- Missing rate limiting on sensitive operations
- Credential recovery that relies on knowledge-based answers

**Threat Template:**
```
A [malicious user] with [understanding of the application's business logic]
can [exploit missing validation in the business workflow],
which leads to [bypassing intended restrictions or manipulating business outcomes],
negatively impacting [business integrity and platform trust].
```

**Mitigations:**
- Establish and use a secure development lifecycle with AppSec professionals
- Use threat modeling for critical authentication, access control, business logic, and key flows
- Write unit and integration tests to validate all critical flows are resistant to the threat model
- Segregate tier layers and network layers depending on exposure and protection needs
- Limit resource consumption by user or service

---

#### A05:2021 — Security Misconfiguration

**CWEs Mapped:** 20

**Description:** Missing appropriate security hardening, unnecessary features enabled, default accounts with unchanged passwords, overly informative error messages.

**Common Patterns:**
- Default credentials not changed
- Unnecessary features enabled (ports, services, pages, accounts, privileges)
- Error handling reveals stack traces or sensitive information
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Software is out of date or misconfigured

**Threat Template:**
```
A [external attacker] with [access to default or exposed service endpoints]
can [exploit default configurations, unnecessary features, or verbose error responses],
which leads to [unauthorized system access or information leakage],
negatively impacting [confidentiality and integrity of the application infrastructure].
```

**Mitigations:**
- Repeatable hardening process that makes it fast and easy to deploy a properly locked-down environment
- Minimal platform without unnecessary features, components, documentation, and samples
- Review and update configurations appropriate to all security notes, updates, and patches
- Automated process to verify effectiveness of configurations and settings

---

#### A06:2021 — Vulnerable and Outdated Components

**CWEs Mapped:** 3

**Description:** Components (libraries, frameworks, OS) with known vulnerabilities are used without patching.

**Common Patterns:**
- Don't know versions of all components (client-side and server-side)
- Software is vulnerable, unsupported, or out of date
- Don't scan for vulnerabilities regularly
- Don't fix or upgrade underlying platforms, frameworks, and dependencies in a timely fashion
- Don't test compatibility of updated, upgraded, or patched libraries

**Threat Template:**
```
A [external attacker] with [knowledge of published CVEs for the application's dependencies]
can [exploit known vulnerabilities in outdated libraries or frameworks],
which leads to [remote code execution, data breach, or denial of service],
negatively impacting [availability and integrity of the application].
```

**Mitigations:**
- Remove unused dependencies, unnecessary features, components, files, and documentation
- Continuously inventory client-side and server-side component versions using SCA tools
- Only obtain components from official sources over secure links
- Monitor for components that are unmaintained or don't create security patches

---

#### A07:2021 — Identification and Authentication Failures

**CWEs Mapped:** 22

**Description:** Confirmation of the user's identity, authentication, and session management is critical. Weaknesses in these areas lead to account compromise.

**Common Patterns:**
- Permits automated attacks such as credential stuffing
- Permits brute force
- Allows default, weak, or well-known passwords
- Uses weak or ineffective credential recovery (knowledge-based answers)
- Uses plain text, encrypted, or weakly hashed password data stores
- Has missing or ineffective MFA
- Exposes session identifier in the URL

**Threat Template:**
```
A [external attacker] with [leaked credential databases from previous breaches]
can [perform automated credential stuffing attacks against the login endpoint],
which leads to [unauthorized access to user accounts],
negatively impacting [confidentiality of user accounts and integrity of user sessions].
```

**Mitigations:**
- Implement multi-factor authentication
- Do not ship or deploy with default credentials
- Implement weak password checks
- Align password length, complexity, and rotation policies with NIST 800-63b
- Harden against account enumeration attacks
- Limit or delay failed login attempts with rate limiting and account lockout

---

#### A08:2021 — Software and Data Integrity Failures

**CWEs Mapped:** 10

**Description:** Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.

**Common Patterns:**
- Application relies on plugins, libraries, or modules from untrusted sources
- Insecure CI/CD pipeline with potential for unauthorized access or code injection
- Auto-update functionality that downloads updates without sufficient integrity verification
- Insecure deserialization (objects or data are serialized without integrity checks)

**Threat Template:**
```
A [supply chain attacker] with [access to a dependency registry or CI/CD pipeline]
can [inject malicious code into a trusted dependency or build artifact],
which leads to [execution of malicious code in production environments],
negatively impacting [integrity of the software supply chain and customer trust].
```

**Mitigations:**
- Verify software and data are from the expected source via signing or similar mechanisms
- Ensure libraries and dependencies consume trusted repositories
- Use a software supply chain security tool (Dependabot, Snyk) to verify components
- Ensure there is a review process for code and configuration changes

---

#### A09:2021 — Security Logging and Monitoring Failures

**CWEs Mapped:** 4

**Description:** Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs when these mechanisms are missing or ineffective.

**Common Patterns:**
- Auditable events (logins, failed logins, high-value transactions) are not logged
- Warnings and errors generate no, inadequate, or unclear log messages
- Logs of applications and APIs are not monitored for suspicious activity
- Logs are only stored locally
- Alerting thresholds and response escalation are not effective
- Penetration testing and DAST scans do not trigger alerts

**Threat Template:**
```
A [privileged insider or external attacker] with [access to perform actions in the system]
can [perform malicious operations without generating detectable audit trails],
which leads to [inability to detect, investigate, or respond to security incidents],
negatively impacting [non-repudiation and incident response capabilities].
```

**Mitigations:**
- Ensure all login, access control, and server-side input validation can be logged with context
- Ensure logs are generated in a format that log management solutions can consume
- Ensure log data is encoded correctly to prevent injections or attacks on logging systems
- Ensure high-value transactions have an audit trail with integrity controls (append-only DB)
- Establish effective monitoring and alerting so suspicious activities are detected and responded to

---

#### A10:2021 — Server-Side Request Forgery (SSRF)

**CWEs Mapped:** 1

**Description:** SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination.

**Common Patterns:**
- Application fetches a remote resource based on user-supplied URL
- URL is not validated against an allowlist
- Internal services are accessible via the application's network
- Cloud metadata endpoints (169.254.169.254) are reachable

**Threat Template:**
```
A [authenticated user] with [access to functionality that fetches external URLs]
can [craft requests to internal services or cloud metadata endpoints via SSRF],
which leads to [exposure of internal service data, cloud credentials, or internal network topology],
negatively impacting [confidentiality of internal infrastructure and cloud credentials].
```

**Mitigations:**
- Sanitize and validate all client-supplied input data
- Enforce URL schema, port, and destination with a positive allow list
- Do not send raw responses to clients
- Disable HTTP redirections
- Use network-layer controls: deny-by-default firewall rules for intranet traffic

---

## 4. Threat Statement Templates

### 4.1 By Source Type

#### For GitHub Repository Sources

When the source is a code repository, threat statements should reference specific code patterns:

```
Template:
A [threat source] with [access to {endpoint/service/component}]
can [specific action against {file/API/function}],
which leads to [impact on {data/service/users}],
negatively impacting [{CIA property} of {specific asset}].

Code Reference:
File: {path/to/vulnerable/file}
Line: {line number}
Pattern: {what was detected — e.g., SQL concatenation, hardcoded secret}
```

#### For Design Document Sources

When the source is a design document, threat statements are more architectural:

```
Template:
A [threat source] with [prerequisite access or knowledge]
can [action against {architectural component from the design}],
which leads to [impact on {system property described in the design}],
negatively impacting [{CIA property} of {design component or data flow}].

Mitigation Suggestion:
{Prose description of recommended security control}
{Reference to relevant security standard (NIST, CIS, OWASP)}
```

### 4.2 By STRIDE Category

| Category | Template Starter |
|----------|-----------------|
| Spoofing | "A [external/internal actor] with [stolen/forged credentials] can [impersonate {entity}]..." |
| Tampering | "A [positioned attacker] with [access to {data flow/store}] can [modify/inject {data}]..." |
| Repudiation | "A [privileged user] with [access to {system}] can [perform actions without {audit trail}]..." |
| Information Disclosure | "A [unauthorized party] with [access to {channel/storage}] can [read/extract {sensitive data}]..." |
| Denial of Service | "A [attacker/user] with [access to {resource}] can [exhaust/overwhelm {service}]..." |
| Elevation of Privilege | "A [low-privilege user] with [access to {feature}] can [escalate to {higher privilege}]..." |

---

## 5. Data Flow Diagram (DFD) Standards

### 5.1 DFD Element Types

| Symbol | Element | Description |
|--------|---------|-------------|
| Rectangle | External Entity | Actors outside the system boundary (users, external services) |
| Circle / Rounded Rectangle | Process | Application components that process data (API, service, function) |
| Open Rectangle (parallel lines) | Data Store | Databases, file systems, caches, queues |
| Arrow | Data Flow | Movement of data between elements, labeled with protocol |
| Dashed boundary | Trust Boundary | Separation between zones with different trust levels |

### 5.2 Trust Boundary Types

| Boundary | Description | Example |
|----------|-------------|---------|
| Internet ↔ DMZ | Traffic crossing the public internet boundary | Browser → Load Balancer |
| DMZ ↔ Internal | Traffic entering the private network | Load Balancer → App Server |
| Service ↔ Service | Cross-service communication within the same trust zone | API → Database |
| Cloud ↔ Edge | Traffic between cloud services and on-premise/edge devices | Cloud Broker → IoT Gateway |
| User ↔ Admin | Privilege boundary between normal and elevated access | User Portal → Admin Console |

### 5.3 DFD Levels

| Level | Scope | Use Case |
|-------|-------|----------|
| Level 0 (Context) | Entire system as single process | Executive overview, scope definition |
| Level 1 (System) | Major subsystems and data stores | Primary threat modeling level |
| Level 2 (Component) | Internal components of each subsystem | Deep-dive for critical components |

For automated threat modeling, **Level 1** is the target — it provides enough detail to identify trust boundary crossings without overwhelming the model.

---

## 6. Threat Model Process Methodology

### 6.1 The Four Questions (Shostack Framework)

Every threat model answers four fundamental questions:

1. **What are we working on?** → System modeling (DFD, architecture diagram)
2. **What can go wrong?** → Threat identification (STRIDE, threat grammar)
3. **What are we going to do about it?** → Risk response (mitigate, eliminate, transfer, accept)
4. **Did we do a good enough job?** → Validation (coverage review, testing, red team)

### 6.2 Automated Threat Modeling Pipeline

In Unitone Sentinel, these questions map to automated pipeline stages:

| Question | Pipeline Stage | Automation |
|----------|---------------|------------|
| What are we working on? | Repo Analyzer → DFD Generator | Clone repo, extract architecture, generate Mermaid DFD |
| What can go wrong? | Threat Generator | LLM-powered STRIDE analysis on architecture |
| What are we going to do about it? | Fix Generator + Apply Fix | LLM generates code fixes, Git service creates PRs |
| Did we do a good enough job? | Insight Engine | Quality metrics: STRIDE coverage, mitigation rate |

### 6.3 Risk Response Options

| Response | Description | When to Use |
|----------|-------------|-------------|
| **Mitigate** | Implement controls to reduce likelihood or impact | Default for most threats — generate code fix, apply PR |
| **Eliminate** | Remove the threatened feature or component | When the feature is non-essential and risk is high |
| **Transfer** | Shift risk to another party (insurance, SLA) | When the risk is acceptable but should be contractually managed |
| **Accept** | Acknowledge the risk with documented rationale | When cost of mitigation exceeds potential impact |

---

## 7. Mitigation Pattern Library

### 7.1 Common Mitigation Patterns by STRIDE

#### Spoofing Mitigations
| Pattern | Implementation |
|---------|---------------|
| Multi-Factor Authentication | TOTP, WebAuthn, SMS verification on login |
| Certificate-Based Auth | mTLS for service-to-service communication |
| Token Validation | JWT signature verification with key rotation |
| Session Management | Secure, HttpOnly, SameSite cookies with short TTL |

#### Tampering Mitigations
| Pattern | Implementation |
|---------|---------------|
| Input Validation | Server-side validation with allowlist patterns |
| Message Signing | HMAC-SHA256 for message integrity verification |
| Integrity Monitoring | File integrity monitoring (AIDE, Tripwire) |
| Secure Boot | Firmware signature verification with anti-rollback |

#### Repudiation Mitigations
| Pattern | Implementation |
|---------|---------------|
| Immutable Audit Logs | Append-only storage (S3 Object Lock, WORM) |
| Digital Signatures | Cryptographic signing of transactions |
| Centralized Logging | Ship logs to SIEM with tamper-evident storage |
| Action Attribution | Individual service accounts, no shared credentials |

#### Information Disclosure Mitigations
| Pattern | Implementation |
|---------|---------------|
| Encryption at Rest | AES-256 for databases, S3 SSE, disk encryption |
| Encryption in Transit | TLS 1.3 for all connections, certificate pinning |
| Secret Management | HashiCorp Vault, AWS Secrets Manager, no hardcoded secrets |
| Error Handling | Generic error messages, detailed errors only in logs |

#### Denial of Service Mitigations
| Pattern | Implementation |
|---------|---------------|
| Rate Limiting | Token bucket algorithm per user/IP |
| Request Validation | Max payload size, request depth limits |
| Auto-Scaling | Horizontal scaling with load balancer health checks |
| Circuit Breakers | Fail-fast on downstream service failures |

#### Elevation of Privilege Mitigations
| Pattern | Implementation |
|---------|---------------|
| RBAC/ABAC | Role-based or attribute-based access control at API layer |
| Tenant Isolation | Scoped queries with tenant ID from JWT claims |
| Least Privilege | Minimal IAM permissions, no wildcard policies |
| Input Sanitization | Parameterized queries, no dynamic SQL construction |

---

## 8. Sources & References

### Threat Modeling Frameworks & Standards

- [AWS Threat Composer — GitHub](https://github.com/awslabs/threat-composer) — Open-source threat modeling tool from AWS Labs
- [AWS Threat Composer — Live Tool](https://awslabs.github.io/threat-composer/) — Browser-based threat modeling application
- [AWS Security Blog — How to Approach Threat Modeling](https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/) — AWS methodology for threat modeling
- [AWS Security Blog — Threat Modeling GenAI Workloads](https://aws.amazon.com/blogs/security/threat-modeling-your-generative-ai-workload-to-evaluate-security-risk/) — Applying threat grammar to AI systems
- [AWS Threat Modeling Workshop — Threat Grammar](https://catalog.workshops.aws/threatmodel/en-US/what-can-go-wrong/threat-grammar) — Interactive workshop on threat grammar construction
- [AWS Well-Architected Security Pillar — SEC01-BP07](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/sec_securely_operate_threat_model.html) — Identify threats and prioritize mitigations using a threat model
- [AWS Security Maturity Model — Threat Modeling](https://maturitymodel.security.aws.dev/en/3.-efficient/threat-modeling/) — Maturity model for threat modeling practices

### STRIDE Methodology

- [Microsoft STRIDE Model — Wikipedia](https://en.wikipedia.org/wiki/STRIDE_model) — Original STRIDE framework documentation
- [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool) — Microsoft's threat modeling tool using STRIDE

### OWASP Resources

- [OWASP Top 10:2021](https://owasp.org/Top10/) — The 2021 edition of the OWASP Top 10
- [OWASP Top 10:2021 — Introduction](https://owasp.org/Top10/2021/A00_2021_Introduction/) — Methodology and data analysis behind the 2021 list
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) — Practical guide to threat modeling methodology
- [OWASP Threat Modeling Process](https://owasp.org/www-community/Threat_Modeling_Process) — Community-maintained threat modeling process guide
- [OWASP Developer Guide — Practical Threat Modeling](https://devguide.owasp.org/en/04-design/01-threat-modeling/07-practical-threat-modeling/) — Step-by-step guide for developers
- [OWASP Security Culture — Threat Modelling](https://owasp.org/www-project-security-culture/v10/6-Threat_Modelling/) — Embedding threat modeling in security culture
- [OWASP Cheat Sheet Index — Top 10 Mapping](https://cheatsheetseries.owasp.org/IndexTopTen.html) — Cheat sheets mapped to OWASP Top 10 categories
- [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) — Open-source threat modeling tool from OWASP

### Threat Modeling Guides

- [Threat Modeling Guide: STRIDE, DFD, Risk Ranking & Mitigations](https://medium.com/@QuarkAndCode/threat-modeling-guide-stride-data-flow-diagrams-risk-ranking-mitigations-3b4d38613205) — Comprehensive guide covering DFD + STRIDE + risk ranking
- [Practical DevSecOps — What Is the STRIDE Threat Model?](https://www.practical-devsecops.com/what-is-stride-threat-model/) — Beginner-friendly STRIDE guide
- [AWS Security Digest — How to Start Threat Modelling in AWS](https://awssecuritydigest.com/articles/threat-modelling-in-aws) — AWS-specific threat modeling guide

### Tools & Integrations

- [AWS Threat Composer AI CLI & MCP](https://github.com/awslabs/threat-composer/blob/main/docs/AI-CLI-MCP.md) — AI-powered CLI and MCP server for Threat Composer
- [AWS CDK Graph Threat Composer Plugin](https://aws.github.io/aws-pdk/developer_guides/cdk-graph-plugin-threat-composer/index.html) — Generate threat models from CDK infrastructure
- [AWS Toolkit for VS Code — Threat Composer](https://docs.aws.amazon.com/toolkit-for-vscode/latest/userguide/threatcomposer.html) — VS Code integration for Threat Composer

### Vulnerability Databases

- [OWASP Top Ten Project](https://owasp.org/www-project-top-ten/) — Main project page for the OWASP Top 10
- [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) — US government vulnerability database
- [MITRE CWE (Common Weakness Enumeration)](https://cwe.mitre.org/) — Catalog of software and hardware weakness types
- [MITRE ATT&CK](https://attack.mitre.org/) — Knowledge base of adversary tactics and techniques
