# Risk rules

Based on risk rules Threagile will analyze model and identify potential risks.

There are a lot of built in rules.

- DoS-risky Access Across Trust-Boundary;
- Incomplete Model;
- Missing Build Infrastructure;
- Missing File Validation;
- Accidental Secret Leak;
- Missing Cloud Hardening;
- Missing Network Segmentation;
- Missing Vault Isolation;
- Unnecessary Data Transfer;
- Missing Authentication;
- Missing Identity Propagation;
- Missing Web Application Firewall (WAF);
- Search-Query Injection;
- Unencrypted Communication;
- Unguarded Access From Internet;
- Container Base Image Backdooring;
- Container Platform Escape;
- Cross-Site Request Forgery (CSRF);
- Cross-Site Scripting (XSS);
- Push instead of Pull Deployment;
- XML External Entity (XXE);
- Code Backdooring;
- LDAP-Injection;
- Missing Hardening;
- Missing Identity Store;
- Path-Traversal;
- Unchecked Deployment;
- Wrong Communication Link Content;
- Missing Two-Factor Authentication (2FA);
- Missing Vault (Secret Storage);
- Mixed Targets on Shared Runtime;
- SQL/NoSQL-Injection;
- Unguarded Direct Datastore Access;
- Unnecessary Data Asset;
- Unnecessary Communication Link;
- Untrusted Deserialization;
- Wrong Trust Boundary Content;
- Missing Identity Provider Isolation;
- Server-Side Request Forgery (SSRF);
- Service Registry Poisoning;
- Unencrypted Technical Assets;
- Unnecessary Technical Asset;
- HTTP Request Smuggling;
- Mail Command Injection;
- Missing Clickjacking Protection;
- Shared Datastore Tampering;
- XML Entity Expansion and Oversized Payload DoS;
- Prompt Injection and Jailbreaking;
- Sensitive Data Exposure through AI Component;
- Client Reverse Engineering;
- Audit Log Manipulation;
- XML Schema Poisoning;
- Missing Brute-Force Protection;
- Missing Authorization;
- Missing Security Monitoring;
- Sensitive Data in Logs;
- Missing Redundancy (Single Point of Failure);
- Internet-Exposed Datastore;
- Weak Session Management (tag `session-tokens`);
- OS Command Injection (tag `executes-os-commands`);
- Hard-coded Credentials (tag `credentials-hardcoded` on a data asset);
- Excessive Agency of AI Component (tags `ai-agent`, `executes-code`).

The rules from HTTP Request Smuggling to XML Schema Poisoning are derived from threat patterns of [OWASP pytm](https://github.com/OWASP/pytm)
(see `docs/pytm-mapping.md`); the remaining ten close gaps found in a coverage review (see `docs/rule-proposals.md`).
The four tag-based rules only fire when the modeler sets the given tag (list all rules with their tags via `threagile list-risk-rules`).

Also there is available creation of [custom risk rules](./custom-risk-rules.md).
