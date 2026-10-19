# Changelog

## 1.0.0 (unreleased)

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
