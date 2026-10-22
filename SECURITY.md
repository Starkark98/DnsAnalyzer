# Security policy

## Supported versions

Only the **latest release** of DNS Analyzer receives fixes. Please update before reporting a problem.

| Version | Supported |
|---|---|
| 1.1.x (latest) | Yes |
| 1.0.x and older | No |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report them privately through GitHub: open the **Security** tab of this repository and click **Report a vulnerability**. Include:

- a description of the problem and its possible impact;
- the steps or a minimal example to reproduce it;
- the DNS Analyzer version and the Windows / PowerShell versions involved.

Do not include real server names, zone names, record names, IP addresses or reports from production networks: use the demo data (`Start Demo.cmd`) or anonymized examples.

## What to expect

DNS Analyzer is maintained in spare time, so handling is **best effort**. The aim is to acknowledge a report within a few days, agree on a fix and publish a new release before any public disclosure. Please allow reasonable time for a fix before disclosing the issue publicly.

## Scope

Examples of relevant reports: script code that could be injected through data read from the DNS server or the logs (for example a crafted record name or TXT value), the dashboard executing untrusted content, or the tool modifying server state despite being read-only.

Out of scope: findings that require an attacker who already has administrator rights on the machine running the tool, and warnings from antivirus/EDR products about the live tests behaving like a port scan (this is documented behavior).
