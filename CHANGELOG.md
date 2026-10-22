# Changelog

## 1.1.0 (2026-10-22)

### Added
- **Compare two servers** (migration check): the window has a new mode, *Compare two servers*, with a **Source (old)** server or baseline file and a **Target (new)** server. The comparison dashboard shows a verdict, every difference (zones, static and dynamic records, server settings, forwarders, root hints, DNS policies, client subnets, scopes, AD partitions, DNSSEC) classified as critical (missing on the target), warning (different) or info (only on the target, or cosmetic), and a per-zone overview.
- **Baselines**: *Save baseline...* after an analysis (or `-SaveBaseline <file.json>`) keeps the collected data; a baseline can be the source of a comparison, also against the same server to see what changed since then.
- **Analysis reports as a source**: the report of an analysis (`.html`) made by DNS Analyzer can be the source of a comparison, like a baseline. Reports from 1.0.x are accepted: the data that version did not collect is skipped, and the dashboard says so. Comparison reports and reports of other tools are refused with a clear message.
- Clicking **Analyze** or **Compare** again with the same inputs updates the same report file; different inputs create a new one.
- Command line: `-CompareWith <server>` (with `-DnsServer`, or `-Baseline <file.json|report.html>`), `-SaveBaseline <file.json>`, `-DemoCompare`.
- New data in the analysis: DNS policies (server and zone level, query resolution and zone transfer), client subnets, zone scopes, recursion scopes, response rate limiting exceptions, Active Directory partitions, DNSSEC signing keys and zone settings, trust points, EDNS, Active Directory and global names zone settings, delegations (with a live check of the delegated name servers), and an **All settings** list with every server-level setting.
- New issues: lame delegations, signed zones without a KSK or ZSK or with an overdue key rollover, DNS application partitions this server is not enlisted in, DNS policies in use.
- Demo data for the new sections and a comparison demo (*Try the comparison demo* in the window).

### Changed
- Comparisons read the configuration only ("light" collection): no event logs, statistics or live tests, so they are quicker and send no probes.
- Baseline files are read with the .NET JSON serializer and no size limit (tested with a 30 MB baseline), faster than `ConvertFrom-Json` on Windows PowerShell 5.1.
- Clear messages when a comparison cannot start: missing or invalid source or target, same server twice, baseline file missing, damaged, not JSON or saved by another tool, and which server (source or target) could not be read.

### Security
- Every new value (policies, keys, partitions, settings, baseline contents) goes through the same escaping and number checks as the rest of the report; a baseline file is parsed and re-serialized before it reaches the page, and `-CompareWith` follows the same server-name rule as `-DnsServer`. Checked again with deliberately poisoned data, in the analysis and in the comparison.

## 1.0.0 (2026-10-19)

First version, built on the design of DHCP Analyzer.

### Added
- Whole-server analysis of Windows DNS servers: zones (primary, secondary, stub, conditional forwarders, reverse, auto-created), resource records, aging and scavenging, zone transfers, forwarders, root hints, cache, global query block list, response rate limiting, debug logging, server-level plugin DLL.
- Stale record detection based on each zone's aging window (14 days when aging is off) and checks of the scavenging configuration.
- Cross-zone checks: dangling CNAME, MX, SRV and NS records, missing and mismatched PTR records, names sharing the same IP, private subnets without a reverse zone.
- Optional live tests: recursion, authoritative answer and DC locator queries, forwarders and conditional forwarders, SOA check of every name server of every zone, liveness of static and stale A records (ping, TCP ports, ARP).
- Logs of the last 7 days: DNS audit log (dynamic updates, record, zone and server changes with the user who made them, scavenging) and DNS Server event log with hints for the best-known event IDs.
- Server statistics since the service start.
- Interactive offline HTML dashboard: prioritized issues linked to zones and tabs, zone details in tabs, global search, light/dark theme, print layout.
- WPF launcher with UAC relaunch, `-NoGui`, `-SkipLiveTests`, `-ExternalName`, `-Demo`, `-OutHtml`, `-NoElevate`, `-NoOpen`.
- Demo mode with realistic sample data.

### Security
- The dashboard carries a strict Content-Security-Policy: it cannot load anything or connect anywhere, and only its own script runs (pinned by its SHA-256 hash, no inline event handlers), even if hostile data got past the escaping.
- Every value read from the server is escaped before it reaches the page, and values shown as numbers are forced to numbers: record names, TXT data or log messages containing HTML or script are displayed as plain text (checked with deliberately poisoned data).
- `-DnsServer` and `-ExternalName`, the server name typed in the window and the remembered last server accept only host-name or IP characters and cannot start with `-`, so they cannot add arguments to the elevated relaunch.
- `-OutHtml` accepts only a folder or a `.html` / `.htm` file (a folder gets the default report name), is handled as a literal path, and a trailing `\` no longer breaks the elevated relaunch.
