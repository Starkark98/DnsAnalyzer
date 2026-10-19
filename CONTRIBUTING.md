# Contributing to DNS Analyzer

Thanks for your interest in improving DNS Analyzer!

## Reporting bugs and suggesting ideas

- Search the existing **Issues** first: your problem may already be known.
- Use the **Bug report** or **Feature request** template.
- Remove server names, zone names, record names and IP addresses you do not want to make public. Never attach a real report.
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Pull requests

1. For anything beyond a small fix, **open an issue first** to discuss the change.
2. Keep pull requests focused: one fix or feature per pull request.
3. Update `README.md` and `CHANGELOG.md` when you change behavior or parameters.

## Ground rules

- **Read-only, always.** DNS Analyzer must never change the DNS server or any other system. Only `Get-*` cmdlets and read-only file access are accepted.
- **Windows PowerShell 5.1** compatibility is required (no PowerShell 7-only syntax).
- **One file, no dependencies.** The application stays a single `DnsAnalyzer.ps1`; the dashboard must work offline, without external libraries, fonts or CDNs.
- **Escape untrusted data.** Record names, record data (TXT included) and log messages come from the network: always pass them through `esc()` before inserting them into the HTML.
- **No real data** in code, tests, screenshots or examples: use the demo data (`contoso.local`, private IP ranges).

## Testing your change

- Run the demo: `.\DnsAnalyzer.ps1 -Demo` and check the dashboard in Edge or Chrome (browser console free of errors, light and dark theme).
- If you can, run it against a test DNS server, with and without the live tests, and with `-NoGui`.

## License of contributions

By submitting a contribution you confirm that you have the right to do so and you agree that it is released under the project's [license](LICENSE) (MIT with the Commons Clause), and that the maintainer may also include it in versions offered under a separate commercial license.
