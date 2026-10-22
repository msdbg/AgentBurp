---
name: AgentBurp-Skills
description: >
  Use when the user asks for authorized comprehensive web application security
  research, bug bounty hunting, architecture review, infrastructure review,
  API security testing, client-side security testing, threat modeling, PoC
  validation, vulnerability triage, or responsible disclosure report writing.
  This skill is intentionally broad and covers application, architecture,
  infrastructure, OWASP, and web-relevant CWE families.
version: 2.0.0
tags:
  - security
  - bug-bounty
  - web-application
  - architecture-review
  - infrastructure-security
  - owasp
  - cwe
  - api-security
  - responsible-disclosure
constraints:
  - authorized_targets_only
  - least_impact_validation
  - no_data_exfiltration
  - no_destructive_testing
  - no_denial_of_service
  - no_social_engineering
  - no_out_of_scope_access
  - no_cross_user_impact
coverage:
  - OWASP Top 10 2021
  - OWASP API Security Top 10 2023
  - OWASP ASVS concepts
  - OWASP WSTG concepts
  - Web-relevant CWE families
  - Architectural security flaws
  - Infrastructure-level web vulnerabilities
---

# Comprehensive Web Application Security Research and Bug Bounty

## Mission

This skill helps the user perform **authorized, comprehensive web application security research** without silently missing major vulnerability classes.

It covers:

- Application-layer vulnerabilities
- API security
- Client-side and browser security
- Authentication and session management
- Authorization and access control
- Business logic abuse
- Architectural and design flaws
- Infrastructure-level web vulnerabilities
- Cloud, proxy, CDN, DNS, and hosting-related issues where in scope
- OWASP Top 10, OWASP API Top 10, and relevant CWE families
- Safe proof-of-concept validation
- High-quality bug bounty reporting

---

## Coverage Guarantee

When the user asks for “full coverage”, “complete review”, “all OWASP”, “all web CWEs”, or “do not miss anything”, the agent must:

1. Consider all layers:
   - Architecture and design
   - Infrastructure and hosting
   - Network edge, proxy, CDN, and cache
   - Application logic
   - API endpoints
   - Client-side behavior
   - Browser security controls
   - Authentication and identity
   - Authorization and tenancy
   - Data protection and cryptography
   - Logging, monitoring, and audit
   - Dependencies and supply chain
   - Third-party integrations

2. Produce a **Coverage Matrix**.

3. Mark each area as one of:
   - Covered
   - Not applicable
   - Needs more information
   - Not authorized
   - Not enough access
   - Requires code access
   - Requires infrastructure access

4. Never claim “all CWEs covered” literally.
   - Instead, say: “All applicable web-relevant CWE families considered; unmapped or environment-specific issues marked as gaps.”

5. For every confirmed finding, include:
   - OWASP mapping
   - CWE mapping
   - Severity
   - Impact
   - Safe reproduction steps
   - Remediation

---

## Required Context Before Testing

Before performing comprehensive security research, collect or confirm:

1. **Target information**
   - Application URL
   - API base URL
   - Environment: production, staging, sandbox, local
   - In-scope assets
   - Out-of-scope assets

2. **Authorization**
   - Bug bounty program link, policy, or written permission
   - Allowed testing window
   - Safe-harbor conditions
   - Whether advanced infrastructure testing is allowed

3. **Architecture information**
   - Monolith, microservices, serverless, static frontend plus API, or hybrid
   - Authentication provider
   - Authorization model
   - Multi-tenant or single-tenant
   - Background jobs
   - Webhooks
   - Message queues
   - Caching layer
   - CDN or proxy
   - Cloud provider, if relevant

4. **Accounts and roles**
   - Anonymous access
   - Regular user
   - Admin
   - Support
   - API service account
   - Cross-tenant test accounts, if applicable

5. **Known constraints**
   - No automated scanning
   - No destructive tests
   - No password reset testing
   - No MFA bypass attempts
   - No third-party integrations
   - No cloud metadata testing
   - No cache poisoning
   - No request smuggling

If this information is missing, the agent should ask clarifying questions before proceeding.

---

## Operating Modes

Use the appropriate mode based on the user’s request.

### 1. Full Coverage Audit Mode

Use when the user asks for comprehensive testing or does not want to miss anything.

Output:

- Scope validation
- Architecture inventory
- Infrastructure inventory
- Threat model
- OWASP/CWE coverage matrix
- Prioritized test plan
- Safe validation guidance
- Gaps and limitations

### 2. Bug Hunt Mode

Use when the user asks to find likely bugs in a feature or endpoint.

Output:

- High-risk hypotheses
- Likely CWEs
- Safe tests
- Evidence to collect
- Severity expectations

### 3. Architecture Review Mode

Use when the user asks about design flaws, trust boundaries, privilege models, multi-tenancy, or systemic weaknesses.

Output:

- Trust boundary analysis
- Misuse cases
- Attack paths
- Design weaknesses
- Compensating controls
- Remediation roadmap

### 4. Infrastructure Review Mode

Use when the user asks about CDN, proxy, cache, TLS, DNS, cloud metadata, hosting, subdomain takeover, or protocol-level issues.

Output:

- Infrastructure surface
- Protocol and caching risks
- Safe validation steps
- OWASP/CWE mapping
- Remediation

### 5. API Security Mode

Use when the user asks about REST, GraphQL, gRPC-web, webhooks, or service-to-service APIs.

Output:

- API inventory
- Object-level authorization tests
- Function-level authorization tests
- Property-level authorization tests
- Rate limiting and abuse tests
- Safe validation steps

### 6. Triage and Report Mode

Use when the user already has a finding and needs validation, severity, or a report.

Output:

- Verdict
- OWASP mapping
- CWE mapping
- Severity
- Missing evidence
- Safe next steps
- Final report

---

## Comprehensive Workflow

### 1. Validate Scope

Confirm:

- What domains and subdomains are in scope?
- What APIs are in scope?
- What roles are available?
- What actions are forbidden?
- Is automated scanning allowed?
- Is infrastructure testing allowed?
- Are cloud assets in scope?
- Are third-party services in scope?
- Is cache, CDN, or proxy testing allowed?

If scope is ambiguous, produce a scope confirmation checklist instead of testing guidance.

---

### 2. Inventory the System

Create an inventory of the system surface.

Include:

- Frontend applications
- Backend APIs
- Admin panels
- Internal tools
- Support dashboards
- Authentication endpoints
- OAuth/OIDC/SAML flows
- Webhooks
- File upload/download endpoints
- Export/import endpoints
- Search endpoints
- Payment flows
- Notification flows
- Email/SMS flows
- Background jobs
- Queues
- Caches
- CDNs
- Proxies
- Object storage
- Serverless functions
- Third-party integrations
- Legacy or deprecated endpoints
- Mobile backend endpoints
- WebSocket endpoints
- GraphQL endpoints
- Static assets and source maps

Output format:

```markdown
## System Surface Inventory

### Application Components
- Web frontend
- Public API
- Admin panel
- Webhook receiver
- File upload service

### Identity Components
- Login
- Registration
- Password reset
- OAuth callback
- MFA
- Session management

### Infrastructure Components
- CDN
- Reverse proxy
- Object storage
- Cloud metadata service, if in scope
- DNS records
- TLS endpoints

### Asynchronous Components
- Background jobs
- Email workers
- Webhook processors
- Queue consumers
```

---

### 3. Perform Threat Modeling

Use trust boundaries and misuse cases.

Consider:

- Spoofing
- Tampering
- Repudiation
- Information disclosure
- Denial of service
- Elevation of privilege

For each trust boundary, ask:

- Who can send input?
- Who should be able to send input?
- What data crosses the boundary?
- Is authentication enforced?
- Is authorization enforced?
- Is input validated?
- Is output encoded?
- Is the boundary fail-open or fail-closed?
- Can a lower-privileged actor influence a higher-privileged action?
- Can one tenant affect another tenant?
- Can an external party affect internal services?
- Can asynchronous processing create inconsistent state?

Output format:

```markdown
## Threat Model

### Trust Boundaries
- Browser to web server
- Web server to API
- API to database
- API to internal services
- Application to third-party providers
- User to admin panel
- Tenant A to Tenant B

### Threat Actors
- Anonymous attacker
- Malicious authenticated user
- Malicious tenant
- Malicious admin
- Compromised third-party integration
- Malicious API client

### High-Value Assets
- User accounts
- Session tokens
- API keys
- Payment data
- Private files
- Admin functionality
- Tenant data
- Audit logs
- Cryptographic keys

### Attack Paths
1. IDOR leading to cross-tenant data access
2. SSRF through webhook URL validation
3. Cache poisoning via unkeyed header
4. Privilege escalation through admin API
5. Account takeover through OAuth redirect flaw
6. Business logic abuse through race condition
```

---

### 4. Create Control Matrix

Before testing, identify expected controls:

- Authentication
- Authorization
- Input validation
- Output encoding
- Session security
- Cryptography
- Secrets management
- Error handling
- Logging
- Monitoring
- Rate limiting
- Abuse prevention
- File handling
- Network restrictions
- Transport security
- Browser security headers
- Data retention
- Backup and recovery
- Incident response
- Dependency management
- Secure deployment

If a control is absent, treat it as a potential architectural or configuration finding.

---

### 5. Create Prioritized Test Plan

Prioritize by:

- Impact
- Exploitability
- Attack surface
- Data sensitivity
- Privilege boundary crossed
- Tenant isolation impact
- Financial impact
- Account takeover potential
- Remote code execution potential
- Infrastructure blast radius

For each test, include:

- Feature or endpoint
- Hypothesis
- Vulnerability class
- OWASP category
- CWE family
- Safe test method
- Expected evidence
- Severity if confirmed

---

### 6. Execute Safe Validation

When providing testing guidance:

- Use test accounts.
- Use benign payloads.
- Use canary endpoints.
- Use harmless markers.

---

### 7. Record Coverage Gaps

For every category not tested, record why:

- Not enough access
- Not authorized
- Not applicable
- Requires source code
- Requires infrastructure access
- Requires admin access
- Requires production logs
- Requires third-party cooperation

Do not silently skip categories.

---

### 8. Produce Final Report

For every finding, include:

- Title
- Summary
- Severity
- OWASP mapping
- CWE mapping
- Affected asset
- Affected component
- Reproduction steps
- Safe proof of concept
- Impact
- Root cause
- Remediation
- References
- Evidence redaction statement

---

## Architectural Flaw Review

The agent must explicitly check for design-level weaknesses, even if no immediate PoC exists.

### Authentication Architecture

Check for:

- Weak password policies
- Missing MFA for sensitive roles
- Insecure recovery flows
- Account enumeration
- Authentication bypass through alternate path
- Trusting email verification too broadly
- Trusting third-party identity claims without validation
- Missing brute-force protection
- Weak token generation
- Improper refresh token rotation
- Session fixation
- Missing logout invalidation
- OAuth state or PKCE absence
- SAML/OIDC signature confusion
- IdP confusion or issuer validation flaws
- Account linking weaknesses
- Impersonation features without audit or restrictions

### Authorization Architecture

Check for:

- Missing server-side authorization
- UI-only restrictions
- Role model inconsistencies
- Privilege escalation paths
- Tenant isolation weaknesses
- Object ownership model flaws
- Direct object reference without authorization
- Function-level authorization gaps
- Admin route exposure
- Internal service endpoints exposed publicly
- Trusting client-provided role claims
- Trusting headers such as `X-User-Id`, `X-Role`, or `X-Tenant-Id`
- Inconsistent authorization across web, mobile, API, and async jobs
- Fail-open authorization on errors
- Authorization bypass through error handling or fallback logic

### Multi-Tenant Architecture

Check for:

- Cross-tenant object access
- Shared cache leakage
- Search index leakage
- Object storage prefix collisions
- Tenant ID missing from backend queries
- Tenant ID taken from client-controlled header
- Background jobs processing wrong tenant data
- Webhook events routed to wrong tenant
- Feature flags leaking across tenants
- Admin/support tools crossing tenant boundaries

### Business Logic Architecture

Check for:

- State machine violations
- Workflow skipping
- Negative quantity or price manipulation
- Coupon abuse
- Refund abuse
- Trial abuse
- Invitation flow abuse
- Race conditions
- Double spending
- Duplicate submission
- Missing idempotency keys
- Event replay
- Inconsistent eventual consistency
- Compensation logic gaps
- Payment webhook validation flaws
- Receipt validation flaws
- Rate limit bypass through multiple channels
- Abuse of bulk operations
- Abuse of import/export features

### Data Flow Architecture

Check for:

- Missing validation at trust boundaries
- Different validation rules across channels
- Frontend validation only
- Backend services trusting internal callers blindly
- Data transformation losing security context
- Sensitive data copied into logs
- Sensitive data cached
- Sensitive data stored in browser storage
- Sensitive data included in analytics
- Sensitive data exposed through backups
- Sensitive data exposed through exports
- Sensitive data exposed through error messages
- Sensitive data exposed through debug endpoints

### Asynchronous Architecture

Check for:

- Webhook signature validation
- Queue message authentication
- Event schema validation
- Duplicate event handling
- Out-of-order event handling
- Replay attacks
- Race conditions between workers
- Insecure deserialization in workers
- Privilege context loss in async jobs
- Background jobs bypassing authorization
- Admin actions triggered by unauthenticated events

### Secrets and Cryptography Architecture

Check for:

- Hardcoded secrets
- Secrets in client-side code
- Secrets in source maps
- Secrets in logs
- Secrets in error messages
- Secrets in environment dumps
- Missing secret rotation
- Weak JWT signing secrets
- Predictable API keys
- Weak random token generation
- Use of weak algorithms
- Use of deprecated hash functions
- Use of ECB mode
- Predictable IVs
- Missing encryption for sensitive data
- Missing key separation
- Missing KMS or vault usage where appropriate

### Logging, Monitoring, and Audit Architecture

Check for:

- Missing audit logs for sensitive actions
- Missing authentication failure logs
- Missing authorization failure logs
- Missing admin action logs
- Missing payment or refund logs
- Log injection
- Logs containing secrets or PII
- Missing alerting on anomalous behavior
- Missing correlation IDs
- Repudiation risk for critical operations
- Inability to detect abuse
- Inability to reconstruct incident timeline

### Resilience and Fail-Secure Design

Check for:

- Fail-open behavior
- Error paths bypassing controls
- Timeouts causing inconsistent state
- Partial transaction success
- Missing rollback
- Missing compensation
- Missing circuit breakers
- Missing abuse limits
- Missing graceful degradation
- Insecure default configurations
- Insecure fallback modes

---

## Infrastructure-Level Vulnerability Review

The agent must consider infrastructure-level web vulnerabilities.

### Proxy, CDN, and Cache Layer

Check for:

- Cache poisoning
- Web cache deception
- Unkeyed headers
- Cache key normalization issues
- CDN bypass
- Cache TTL misuse
- Sensitive authenticated responses cached
- Public cache storing private content
- HTTP header parsing differences
- Request smuggling prerequisites
- Response splitting prerequisites
- Compression reflection issues
- BREACH-style risks where relevant

### HTTP Protocol and Request Interpretation

Check for:

- HTTP Request Smuggling
- HTTP/1.1 and HTTP/2 interpretation differences
- Content-Length and Transfer-Encoding conflicts
- Chunked encoding quirks
- Header injection
- Response splitting
- Host header injection
- Absolute URI handling
- URL normalization differences
- Path normalization differences
- Reverse proxy routing ambiguity

### TLS and Transport Security

Check for:

- Missing HTTPS enforcement
- Weak TLS versions
- Weak cipher suites
- Certificate issues
- Missing HSTS
- Mixed content
- Insecure redirects
- Cookie missing Secure flag
- Sensitive data sent over HTTP
- TLS downgrade paths
- Improper certificate validation in app clients

### DNS, Hosting, and Subdomain Security

Check for:

- Dangling DNS records
- Subdomain takeover
- Wildcard DNS risks
- Zone transfer exposure, if in scope
- Misconfigured CNAMEs
- Unclaimed storage buckets
- Unclaimed hosted zones
- Unclaimed SaaS service endpoints

### Cloud and Object Storage

Check for:

- Public object storage buckets
- Public read/write permissions
- Predictable object keys
- Signed URL misuse
- Long-lived signed URLs
- Metadata exposure
- Cloud metadata endpoint access, only if authorized
- Serverless function misconfiguration
- Overly permissive IAM roles, if in scope
- Public cloud dashboards
- Exposed deployment artifacts
- Exposed container registries, if in scope

### WebSockets and Real-Time Channels

Check for:

- Missing authentication on WebSocket connections
- Missing authorization on messages
- Cross-site WebSocket hijacking
- Missing origin validation
- Injection through WebSocket messages
- Rate limiting gaps
- Broadcast leakage
- Tenant leakage in real-time channels
- Insecure reconnection behavior

---

## OWASP Top 10 2021 Coverage Requirements

The agent must explicitly consider each category.

| OWASP Category | What to Check | Representative CWEs |
|---|---|---|
| A01 Broken Access Control | IDOR, privilege escalation, tenant isolation, forced browsing, API authorization gaps, CORS abuse, path traversal | CWE-285, CWE-639, CWE-862, CWE-863, CWE-22 |
| A02 Cryptographic Failures | Weak TLS, weak hashing, insecure token generation, sensitive data exposure, missing encryption, key management | CWE-310, CWE-327, CWE-330, CWE-319, CWE-321, CWE-757 |
| A03 Injection | SQL, NoSQL, command, LDAP, XPath, template, log, header, email, XSS, expression injection | CWE-89, CWE-94, CWE-79, CWE-78, CWE-90, CWE-91, CWE-96, CWE-113, CWE-117, CWE-1336 |
| A04 Insecure Design | Missing controls, flawed trust boundaries, business logic abuse, missing rate limits, missing abuse cases, fail-open design | CWE-657, CWE-840, CWE-841, CWE-693 |
| A05 Security Misconfiguration | Default configs, verbose errors, debug endpoints, unnecessary features, missing headers, permissive CORS, directory listing | CWE-2, CWE-11, CWE-13, CWE-16, CWE-260, CWE-315, CWE-614, CWE-1004, CWE-1021 |
| A06 Vulnerable and Outdated Components | Known CVEs in frameworks, libraries, plugins, JS dependencies, server components | CWE-937, CWE-1035, CWE-1104 |
| A07 Identification and Authentication Failures | Weak passwords, session fixation, credential stuffing, missing MFA, token misuse, OAuth flaws | CWE-287, CWE-288, CWE-290, CWE-384, CWE-613, CWE-640 |
| A08 Software and Data Integrity Failures | Insecure deserialization, unsigned updates, CI/CD integrity, untrusted component loading, object injection | CWE-502, CWE-345, CWE-347, CWE-353, CWE-565 |
| A09 Security Logging and Monitoring Failures | Missing audit logs, missing alerts, log injection, sensitive data in logs, repudiation risk | CWE-778, CWE-117, CWE-223, CWE-532 |
| A10 Server-Side Request Forgery | URL fetch, webhook, link preview, PDF generator, image loader, cloud metadata access | CWE-918 |

---

## OWASP API Security Top 10 2023 Coverage Requirements

| API Category | What to Check | Representative CWEs |
|---|---|---|
| API1 Broken Object Level Authorization | IDOR on resources, object ID guessing, tenant object leakage | CWE-639, CWE-862 |
| API2 Broken Authentication | Token misuse, weak auth, OAuth flaws, API key leakage | CWE-287, CWE-384 |
| API3 Broken Object Property Level Authorization | Mass assignment, excessive data exposure, over-fetching, role field manipulation | CWE-915, CWE-200 |
| API4 Unrestricted Resource Consumption | Missing rate limits, batch abuse, GraphQL depth, expensive queries, file size limits | CWE-400, CWE-770, CWE-405 |
| API5 Broken Function Level Authorization | Admin endpoints accessible by users, method-based authorization gaps | CWE-862, CWE-863 |
| API6 Unrestricted Access to Sensitive Business Flows | Bot abuse, scalping, spam, fake accounts, payment abuse | CWE-840, CWE-841 |
| API7 Server Side Request Forgery | API accepts URLs and fetches them server-side | CWE-918 |
| API8 Security Misconfiguration | Verbose API errors, missing security headers, permissive CORS, debug endpoints | CWE-16, CWE-209 |
| API9 Improper Inventory Management | Shadow APIs, zombie APIs, old versions, undocumented endpoints | CWE-912, CWE-1104 |
| API10 Unsafe Consumption of APIs | Trusting third-party API data, secondary injection, unvalidated redirects from partners | CWE-20, CWE-345 |

---

## Comprehensive Web-Relevant CWE Family Sweep

The agent must consider the following CWE families and mark coverage.

### Access Control and Authorization

- CWE-285: Improper Authorization
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control
- CWE-22: Path Traversal
- CWE-287: Improper Authentication
- CWE-384: Session Fixation
- CWE-613: Insufficient Session Expiration
- CWE-639: IDOR
- CWE-862: Missing backend authorization
- CWE-863: Incorrect role or tenant authorization

### Injection and Input Validation

- CWE-89: SQL Injection
- CWE-94: Code Injection
- CWE-79: Cross-site Scripting
- CWE-78: OS Command Injection
- CWE-90: LDAP Injection
- CWE-91: XML Injection
- CWE-96: Improper Neutralization of Directives in Statically Saved Code
- CWE-97: Server-Side Includes Injection
- CWE-113: HTTP Response Splitting
- CWE-117: Log Injection
- CWE-1336: Server-Side Template Injection
- CWE-1321: Prototype Pollution
- CWE-20: Improper Input Validation
- CWE-74: Injection in general
- CWE-93: CRLF Injection
- CWE-611: XXE
- CWE-776: XML Entity Expansion

### Deserialization and Integrity

- CWE-502: Deserialization of Untrusted Data
- CWE-345: Insufficient Verification of Data Authenticity
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-353: Missing Support for Integrity Check
- CWE-565: Reliance on Cookies without Validation
- CWE-757: Selection of Less-Secure Algorithm During Negotiation

### Cryptography and Data Protection

- CWE-310: Cryptographic Issues
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-327: Use of Broken or Risky Cryptographic Algorithm
- CWE-330: Use of Insufficiently Random Values
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-295: Improper Certificate Validation
- CWE-297: Improper Validation of Certificate with Host Mismatch
- CWE-757: Security downgrading
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-359: Exposure of Private Personal Information
- CWE-522: Insufficiently Protected Credentials
- CWE-798: Use of Hard-coded Credentials

### Information Exposure and Secrets

- CWE-200: Exposure of Sensitive Information
- CWE-209: Error Message Containing Sensitive Information
- CWE-215: Insertion of Sensitive Information into Debugging Code
- CWE-259: Hard-coded Password
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-540: Inclusion of Sensitive Information in Source Code
- CWE-548: Exposure of Information Through Directory Listing
- CWE-798: Hard-coded credentials
- CWE-1004: Sensitive Cookie Without HttpOnly
- CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute

### Configuration and Hardening

- CWE-2: Environmental Security Flaws
- CWE-11: ASP.NET Misconfiguration
- CWE-13: ASP.NET Misconfiguration
- CWE-16: Configuration
- CWE-260: Password in Configuration File
- CWE-315: Cleartext Storage in Cookie
- CWE-614: Missing Secure cookie flag
- CWE-1004: Missing HttpOnly cookie flag
- CWE-1021: Clickjacking
- CWE-693: Protection Mechanism Failure
- CWE-942: Permissive Cross-domain Policy

### Components and Supply Chain

- CWE-937: Using Components with Known Vulnerabilities
- CWE-1035: Code Vulnerabilities
- CWE-1104: Use of Unmaintained Third Party Components
- CWE-494: Download of Code Without Integrity Check
- CWE-829: Inclusion of Functionality from Untrusted Control Sphere
- CWE-830: Inclusion of Web Functionality from an Untrusted Source

### Logging, Monitoring, and Audit

- CWE-778: Insufficient Logging
- CWE-117: Improper Output Neutralization for Logs
- CWE-223: Omission of Security-relevant Information
- CWE-532: Information Exposure Through Log Files
- CWE-778: Missing security event logging

### Business Logic and Workflow

- CWE-840: Business Logic Errors
- CWE-841: Improper Enforcement of Behavioral Workflow
- CWE-696: Incorrect Behavior Order
- CWE-670: Always-Incorrect Control Flow Implementation
- CWE-362: Race Condition
- CWE-367: Time-of-check Time-of-use Race Condition
- CWE-366: Race Condition within a Thread
- CWE-405: Asymmetric Resource Consumption
- CWE-400: Uncontrolled Resource Consumption
- CWE-770: Allocation of Resources Without Limits

### Web Infrastructure and Protocol

- CWE-444: HTTP Request Smuggling
- CWE-436: Interpretation Conflict
- CWE-441: Unintended Proxy or Intermediary
- CWE-601: URL Redirection to Untrusted Site
- CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
- CWE-693: Protection Mechanism Failure
- CWE-1021: Improper Restriction of Rendering within Frames
- CWE-918: SSRF
- CWE-942: Permissive CORS
- CWE-346: Origin Validation Error

### Client-Side and Browser

- CWE-79: XSS
- CWE-80: Basic XSS
- CWE-83: XSS in Attributes
- CWE-84: XSS in URI
- CWE-85: XSS in Script
- CWE-86: XSS in HTML Attributes
- CWE-87: XSS in JavaScript
- CWE-1021: Clickjacking
- CWE-942: CORS misconfiguration
- CWE-1321: Prototype Pollution
- CWE-1336: Template injection where client-side applies
- CWE-346: Origin validation error
- CWE-565: Reliance on cookies without validation
- CWE-807: Reliance on Untrusted Inputs in Security Decision

### Redirect and Forward

- CWE-601: Open Redirect
- CWE-610: Externally Controlled Reference to a Resource
- CWE-918: SSRF when URL is fetched server-side

### File Handling

- CWE-22: Path Traversal
- CWE-73: External Control of File Name or Path
- CWE-94: Code injection through uploaded files
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-552: Files Accessible to External Parties
- CWE-538: Insertion of Sensitive Information into Externally-Accessible File
- CWE-915: Mass Assignment where file metadata is manipulable

### API and GraphQL

- CWE-200: Excessive data exposure
- CWE-285: Authorization flaws
- CWE-352: CSRF on API mutations
- CWE-400: Resource consumption
- CWE-639: BOLA/IDOR
- CWE-770: Rate limiting gaps
- CWE-862: Missing function-level authorization
- CWE-915: Mass assignment
- CWE-918: SSRF through API
- CWE-1104: Unmaintained API versions

---

## Detailed Domain Checks

### Authentication and SSO

Check:

- Login
- Registration
- Password reset
- Email verification
- MFA
- OAuth/OIDC
- SAML
- Social login
- Magic links
- API keys
- Service accounts
- Impersonation
- Remember me
- Session refresh
- Logout
- Concurrent sessions

Specific tests:

- OAuth `state` parameter missing or ignored
- OAuth `redirect_uri` validation bypass
- Missing PKCE for public clients
- Token leakage in URL fragments
- Open redirect chained with OAuth callback
- Account linking to wrong account
- Email verified claim trusted blindly
- IdP issuer confusion
- Refresh token replay
- Session fixation
- Missing session invalidation
- Predictable password reset tokens
- Password reset token leakage in referer
- User enumeration through error messages or timing

---

### Authorization and Access Control

Check:

- Horizontal privilege escalation
- Vertical privilege escalation
- IDOR
- BOLA
- BFLA
- Forced browsing
- Admin route access
- API method access
- Tenant isolation
- Object ownership
- Role switching
- Invitation flows
- Bulk operations
- Export features
- Support tools
- Internal headers

Specific tests:

- Replace object IDs with another test user’s IDs.
- Replace tenant IDs with another test tenant’s IDs.
- Access admin endpoints as low-privileged user.
- Change HTTP method to bypass authorization.
- Test alternate API versions.
- Test mobile endpoints.
- Test GraphQL aliases and mutations.
- Test direct object access after privilege downgrade.
- Test error paths for authorization bypass.

---

### Input Validation and Injection

Check:

- SQL
- NoSQL
- Command
- LDAP
- XPath
- Template
- Log
- Header
- Email
- HTML
- JavaScript
- JSON
- XML
- YAML
- GraphQL
- Search fields
- File names
- URL parameters
- HTTP headers
- Webhook payloads

---

### Output Encoding and XSS

Check:

- Reflected XSS
- Stored XSS
- DOM XSS
- Mutation XSS
- SVG XSS
- File-based XSS
- Markdown XSS
- Template XSS
- JSON context XSS
- Attribute context XSS
- JavaScript context XSS
- URL context XSS

---

### CSRF and State-Changing Requests

Check:

- Missing CSRF tokens
- Token not tied to session
- Token accepted from wrong location
- GET requests changing state
- SameSite weaknesses
- Origin/Referer bypass
- JSON endpoints vulnerable to forms
- WebSocket state changes
- GraphQL mutations
- API actions without CSRF protection

---

### SSRF and Network Request Features

Check:

- URL fetch
- Webhooks
- Link previews
- PDF generators
- Image loaders
- Import from URL
- XML parsers
- File loaders
- Proxy endpoints
- Cloud metadata access
- Internal service access

---

### File Upload, Download, and Processing

Check:

- Unrestricted upload
- Extension bypass
- MIME bypass
- Polyglot files
- SVG with script
- Archive extraction
- Path traversal in filenames
- Public upload access
- Executable upload directories
- File download authorization
- File metadata manipulation
- Image processing
- PDF processing
- ZIP slip

---

### Path Traversal and Local File Access

Check:

- File read endpoints
- File download endpoints
- Template loading
- Static asset serving
- Log viewer
- Backup export
- PDF generation
- Archive extraction

---

### Insecure Deserialization and Object Integrity

Check:

- Java deserialization
- PHP unserialize
- Python pickle
- Ruby Marshal
- .NET BinaryFormatter
- YAML unsafe load
- JSON object injection
- JWT object injection
- Cookie object injection
- Message queue payloads
- Webhook payloads

---

### Business Logic, Payments, and Race Conditions

Check:

- Price tampering
- Quantity tampering
- Negative values
- Coupon abuse
- Refund abuse
- Trial abuse
- Invitation abuse
- Workflow skipping
- Double submit
- Race conditions
- Idempotency gaps
- Replay attacks
- Event duplication
- Partial payment success
- Inventory manipulation
- Subscription downgrade abuse

---

### API, REST, GraphQL, and Webhooks

Check:

- BOLA
- BFLA
- Mass assignment
- Excessive data exposure
- Rate limiting
- GraphQL introspection
- GraphQL alias abuse
- GraphQL depth abuse
- GraphQL batching
- Mutation authorization
- Field-level authorization
- Webhook authentication
- Webhook replay
- Webhook signature validation
- API versioning
- Shadow APIs
- Deprecated APIs
- Internal APIs
- Service-to-service trust

---

### Client-Side and Browser Security

Check:

- DOM XSS
- Prototype pollution
- PostMessage origin validation
- Insecure storage in localStorage/sessionStorage
- Sensitive data in IndexedDB
- Sensitive data in cookies
- Missing Secure/HttpOnly/SameSite
- CSP weaknesses
- CORP/COOP/COEP issues
- Subresource Integrity missing
- Third-party script risks
- Clickjacking
- Open redirect in SPA router
- JSONP endpoints
- Service worker cache leakage
- Client-side route authorization bypass

---

### Caching, CDN, and Web Cache Issues

Check:

- Public caching of authenticated responses
- Cache poisoning through unkeyed headers
- Web cache deception through static-file paths
- Cache key normalization issues
- CDN header trust
- Vary header misuse
- TTL misuse
- Sensitive data in shared cache
- Cache poisoning via query parameters
- Cache poisoning via host headers

---

### HTTP Protocol and Request Smuggling

Check:

- Content-Length/Transfer-Encoding conflicts
- Chunked encoding quirks
- HTTP/2 downgrading issues
- Proxy normalization differences
- Header parsing differences
- Absolute-form requests
- Request line ambiguity
- Response queue manipulation
---

### TLS, Cookies, and Transport Security

Check:

- HTTPS enforcement
- HSTS
- Secure cookies
- HttpOnly cookies
- SameSite cookies
- Cookie domain scope
- Cookie path scope
- TLS versions
- Cipher suites
- Certificate validation
- Mixed content
- Insecure redirects
- Sensitive data in URLs
- Sensitive data in query strings
- Sensitive data in referer headers

---

### DNS, Subdomains, and Hosting

Check:

- Dangling CNAMEs
- Subdomain takeover
- Unclaimed buckets
- Unclaimed SaaS services
- Wildcard DNS
- DNS rebinding, only if authorized
- Zone transfer exposure, only if authorized
- Misconfigured hosting panels
- Exposed deployment artifacts

---

### Cloud, Serverless, and Container Exposure

Only check these if explicitly in scope.

Check:

- Public object storage
- Predictable object keys
- Signed URL expiration
- Public serverless endpoints
- Overly permissive IAM, if visible
- Cloud metadata endpoint access
- Exposed container registries
- Exposed orchestration dashboards
- Secrets in deployment artifacts
- Environment variable leakage
- Public cloud storage listings

---

### Logging, Monitoring, and Audit

Check:

- Sensitive actions logged
- Authentication failures logged
- Authorization failures logged
- Admin actions logged
- Payment actions logged
- Log injection
- Sensitive data in logs
- Missing correlation IDs
- Missing alerts for anomalous activity
- Missing audit trail for support actions
- Missing tamper resistance

---

### Dependencies and Supply Chain

Check:

- Known vulnerable libraries
- Exposed version endpoints
- Exposed source maps
- Exposed dependency manifests
- Unpinned dependencies
- Unsigned packages
- Third-party scripts without SRI
- CDN script integrity
- Build pipeline exposure, if in scope
- Compromised update mechanisms, if in scope

---

## Severity Assessment

Use this general rubric unless the program defines its own.

### Critical

- Full account takeover at scale
- Remote code execution
- Admin access bypass
- Sensitive data exposure at scale
- Authentication bypass
- Tenant isolation failure
- Payment manipulation with high financial impact
- SSRF leading to internal compromise where authorized and demonstrable
- Insecure deserialization leading to code execution
- Request smuggling leading to account takeover or cache compromise

### High

- IDOR exposing sensitive user data
- Privilege escalation
- Stored XSS with session or action impact
- SQL injection
- CSRF on critical account changes
- Business logic abuse with significant financial impact
- Path traversal exposing sensitive files
- Web cache poisoning with user impact
- OAuth account takeover
- Cross-tenant data access

### Medium

- Reflected XSS with limited context
- CSRF on low-impact actions
- Open redirect chained with authentication
- CORS misconfiguration with limited exposure
- Rate limiting weaknesses
- Information disclosure of non-sensitive internal data
- Clickjacking on sensitive action
- Prototype pollution with limited impact
- Web cache deception with limited exposure

### Low

- Minor information disclosure
- Missing security headers without direct exploitability
- Verbose errors without sensitive data
- Low-impact configuration issues
- UI inconsistencies with minimal security impact
- Non-exploitable dependency findings

### Informational

- Best-practice violations
- Missing headers without exploitability
- Version disclosure without clear impact
- Non-exploitable configuration observations
- Theoretical dependency issues without reachable function

---

## Bug Report Template

Use this template for application findings.

```markdown
# Title

[Component] Vulnerability Type in Feature/Endpoint

## Summary

A concise explanation of the vulnerability and its impact.

## Severity

[Critical / High / Medium / Low / Informational]

## Classification

- OWASP Top 10:
- OWASP API Top 10:
- CWE:
- CVSS estimate, if required:

## Affected Asset

- URL:
- Endpoint:
- Parameter:
- Component:
- Version:

## Description

Explain the vulnerability clearly.

## Steps to Reproduce

1. Step one
2. Step two
3. Step three
4. Step four

## Safe Proof of Concept

Provide request/response evidence with secrets redacted.

## Impact

Explain what an attacker can do and why it matters.

## Root Cause

Explain the missing control or flawed design.

## Recommended Remediation

Provide practical mitigation guidance.

## References

Include relevant documentation or standards.
```

---

## Architectural Flaw Report Template

Use this template when the issue is design-level and may not have a direct PoC.

```markdown
# Title

[Architecture/Design] Weakness in System Component

## Summary

Describe the design weakness and why it creates risk.

## Severity

[Critical / High / Medium / Low / Informational]

## Classification

- OWASP:
- CWE:
- Threat model category:

## Affected Design Area

- Trust boundary:
- Role model:
- Data flow:
- Async workflow:
- Tenancy:
- Authentication:
- Authorization:
- Cryptography:
- Logging/monitoring:

## Design Weakness

Explain the flaw in the design.

## Misuse Case

Describe how an attacker or malicious insider could abuse the design.

## Attack Path

1. Step one
2. Step two
3. Step three

## Impact

Explain blast radius, privilege escalation, data exposure, financial loss, or operational impact.

## Why Existing Controls Are Insufficient

Explain why current controls do not fully mitigate the issue.

## Recommended Design Remediation

Provide architecture-level fixes and compensating controls.

## Detection Recommendations

Provide logging, monitoring, and alerting recommendations.
```

---

## Infrastructure Flaw Report Template

Use this template for CDN, proxy, cache, TLS, DNS, hosting, or protocol issues.

```markdown
# Title

[Infrastructure] Vulnerability in Component/Protocol

## Summary

Describe the infrastructure weakness and impact.

## Severity

[Critical / High / Medium / Low / Informational]

## Classification

- OWASP:
- CWE:
- Protocol/component:

## Affected Component

- CDN/proxy:
- Domain:
- Endpoint:
- Header:
- Protocol:
- Storage/cloud service:

## Description

Explain the weakness.

## Safe Reproduction

Provide safe steps, requests, or observations.

## Evidence

Provide redacted evidence.

## Impact

Explain who or what can be affected.

## Remediation

Provide configuration or architectural fixes.

## Validation After Fix

Explain how to verify remediation safely.
```

---

## Full Coverage Matrix Template

When the user asks for comprehensive coverage, output this matrix and fill in status.

```markdown
## Coverage Matrix

| Area | OWASP Mapping | CWE Family | Status | Notes |
|---|---|---|---|---|
| Architecture and insecure design | A04 | CWE-657, CWE-840, CWE-841 | | |
| Authentication | A07 | CWE-287, CWE-288, CWE-384 | | |
| Session management | A07 | CWE-384, CWE-613 | | |
| Access control and authorization | A01 | CWE-285, CWE-862, CWE-863, CWE-639 | | |
| Multi-tenant isolation | A01 | CWE-284, CWE-639 | | |
| Input validation and injection | A03 | CWE-20, CWE-74, CWE-89, CWE-79, CWE-78 | | |
| Output encoding and XSS | A03 | CWE-79 | | |
| CSRF and state-changing requests | A05/A04 | CWE-352 | | |
| SSRF | A10 | CWE-918 | | |
| XXE | A05/A03 | CWE-611 | | |
| File upload and file processing | A04/A05 | CWE-434, CWE-22 | | |
| Path traversal and file access | A01 | CWE-22, CWE-73 | | |
| Insecure deserialization | A08 | CWE-502 | | |
| Business logic abuse | A04 | CWE-840, CWE-841 | | |
| Race conditions and concurrency | A04 | CWE-362, CWE-367 | | |
| Cryptography and data protection | A02 | CWE-310, CWE-327, CWE-330 | | |
| Secrets and key management | A02 | CWE-321, CWE-798, CWE-522 | | |
| Security misconfiguration | A05 | CWE-16, CWE-2, CWE-1021 | | |
| Vulnerable components | A06 | CWE-937, CWE-1104 | | |
| Logging and monitoring | A09 | CWE-778, CWE-117, CWE-532 | | |
| API security | API Top 10 | CWE-639, CWE-862, CWE-915, CWE-400 | | |
| GraphQL security | API Top 10 | CWE-400, CWE-862, CWE-200 | | |
| OAuth/OIDC/SAML | A07 | CWE-287, CWE-290, CWE-345 | | |
| CORS and cross-origin security | A05 | CWE-942, CWE-346 | | |
| Client-side and DOM security | A03 | CWE-79, CWE-1321 | | |
| Browser security headers | A05 | CWE-693, CWE-1021 | | |
| Cookie security | A02/A05 | CWE-614, CWE-1004, CWE-315 | | |
| Redirect and forward handling | A01 | CWE-601, CWE-610 | | |
| Web cache poisoning | A05 | CWE-693, CWE-444 | | |
| Web cache deception | A05 | CWE-693 | | |
| HTTP request smuggling | A05 | CWE-444, CWE-436 | | |
| Host header and HTTP header abuse | A03/A05 | CWE-644, CWE-113 | | |
| TLS and transport security | A02 | CWE-319, CWE-295, CWE-327 | | |
| DNS and subdomain takeover | A05 | CWE-284, CWE-918 where relevant | | |
| Object storage and cloud exposure | A05/A01 | CWE-200, CWE-284 | | |
| WebSockets and real-time channels | A01/A05 | CWE-287, CWE-862, CWE-346 | | |
| Webhooks and async processing | A04/A08 | CWE-345, CWE-502, CWE-362 | | |
| Rate limiting and resource consumption | API4/A04 | CWE-400, CWE-770 | | |
| Third-party integrations | API10 | CWE-20, CWE-345 | | |
| Supply chain and dependencies | A06 | CWE-937, CWE-494 | | |
| Admin and support tools | A01/A04 | CWE-862, CWE-863 | | |
| Privacy and PII exposure | A02 | CWE-200, CWE-312, CWE-359 | | |
```

Status values must be one of:

- Covered
- Not applicable
- Needs more information
- Not authorized
- Not enough access
- Requires code access
- Requires infrastructure access

---

## Definition of Done

A comprehensive review is only complete when:

- Scope has been confirmed.
- Architecture has been reviewed.
- Infrastructure has been reviewed where authorized.
- Application surface has been mapped.
- API surface has been mapped.
- Client-side surface has been reviewed.
- OWASP categories have been considered.
- CWE families have been considered.
- Coverage matrix has been produced.
- Gaps have been explicitly listed.
- Findings include safe evidence.
- Sensitive data has been redacted.
- Severity has been justified.
- All findings have been validated.

---