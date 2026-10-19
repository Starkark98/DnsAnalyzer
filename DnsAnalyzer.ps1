<#
.SYNOPSIS
  DNS Analyzer by Starkark98 - read-only health check and interactive dashboard for Windows DNS servers.

.DESCRIPTION
  Opens a small window where you enter the DNS server name, then analyzes every zone, resource
  record, aging and scavenging setting, zone transfer, forwarder, conditional forwarder and server
  setting, optionally runs live tests (name servers, forwarders, resolution, liveness of static and
  stale records), and opens an interactive HTML dashboard with collapsible sections, global search
  and prioritized issues.

  The tool is READ-ONLY: it never changes anything on the DNS server.

.PARAMETER DnsServer
  DNS server to analyze. If omitted, the window asks for it.
.PARAMETER NoGui
  Runs without the window (useful for scheduled tasks).
.PARAMETER SkipLiveTests
  Skips the live tests (DNS queries to name servers and forwarders, ping and TCP probes of static
  and stale A records).
.PARAMETER ExternalName
  Internet name used to test recursion and forwarders. Default: www.microsoft.com
.PARAMETER Demo
  Opens a dashboard built from realistic sample data. No DNS server required.
.PARAMETER OutHtml
  Path of the HTML dashboard. Default: %TEMP%.
.PARAMETER NoElevate
  Does not ask for administrator rights at startup.
.PARAMETER NoOpen
  Saves the dashboard without opening it in the browser (useful with -NoGui in scheduled tasks).

.EXAMPLE
  .\DnsAnalyzer.ps1
.EXAMPLE
  .\DnsAnalyzer.ps1 -Demo
.EXAMPLE
  .\DnsAnalyzer.ps1 -DnsServer DC01 -NoGui -OutHtml C:\Reports\dns.html

.NOTES
  Author : Starkark98
  Credits: developed with the assistance of Claude Code (Anthropic's AI coding assistant),
           under the direction and review of the author.
  License: MIT with the Commons Clause (selling is not permitted) - see the LICENSE file
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9_][A-Za-z0-9._:-]{0,252}$')]
    [string]$DnsServer,
    [switch]$NoGui,
    [switch]$SkipLiveTests,
    [ValidatePattern('^[A-Za-z0-9_][A-Za-z0-9._-]{0,252}$')]
    [string]$ExternalName = 'www.microsoft.com',
    [switch]$Demo,
    [string]$OutHtml,
    [switch]$NoElevate,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$AppName    = 'DNS Analyzer'
$AppVersion = '1.0.0'

# =============================================================================
#  ANALYSIS ENGINE (runs in a background runspace)
# =============================================================================
$Collector = {
    param($Server, $Scan, $ExtName, $Sync)
    $ErrorActionPreference = 'Stop'
    try {
        Import-Module DnsServer -ErrorAction Stop

        function Safe([scriptblock]$sb) { try { & $sb } catch { } }
        function P($o, [string[]]$names) { foreach ($n in $names) { if ($null -ne $o.$n) { return $o.$n } }; $null }
        function Span($ts) { if ($ts -isnot [TimeSpan]) { return '' }; if ($ts.TotalDays -ge 1) { '{0:0.#} d' -f $ts.TotalDays } elseif ($ts.TotalHours -ge 1) { '{0:0.#} h' -f $ts.TotalHours } else { '{0:0} min' -f $ts.TotalMinutes } }
        function Sec($ts) { if ($ts -is [TimeSpan]) { [int64]$ts.TotalSeconds } else { 0 } }
        function Dt($d) { if ($d -is [datetime] -and $d.Year -gt 1601) { $d.ToString('yyyy-MM-dd HH:mm') } else { '' } }
        function Step($msg, $pct) { $Sync.Status = $msg; if ($null -ne $pct) { $Sync.Progress = [int]$pct } }
        function Short([string]$m) { $m = (("$m" -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1); if ("$m".Length -gt 160) { $m.Substring(0, 160) + '...' } else { "$m" } }

        # Record data as text, per record type
        function RData($r) {
            $d = $r.RecordData
            try {
                switch ("$($r.RecordType)") {
                    'A'     { return "$($d.IPv4Address)" }
                    'AAAA'  { return "$($d.IPv6Address)" }
                    'CNAME' { return "$($d.HostNameAlias)" }
                    'PTR'   { return "$($d.PtrDomainName)" }
                    'NS'    { return "$($d.NameServer)" }
                    'MX'    { return "$($d.Preference) $($d.MailExchange)" }
                    'SRV'   { return "$($d.Priority) $($d.Weight) $($d.Port) $($d.DomainName)" }
                    'TXT'   { return (@($d.DescriptiveText) -join ' ') }
                    'SOA'   { return "$($d.PrimaryServer) $($d.ResponsiblePerson) $($d.SerialNumber)" }
                }
                (@($d.CimInstanceProperties | Where-Object { $null -ne $_.Value -and "$($_.Value)" } | ForEach-Object { "$($_.Value)" }) -join ' ')
            } catch { '' }
        }

        # One DNS query with timing. dead = no answer at all (timeout / unreachable)
        function Q([string]$name, [string]$type, [string]$srv, [bool]$noRec = $false) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try {
                $prm = @{ Name = $name; Type = $type; Server = $srv; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
                if ($noRec) { $prm.NoRecursion = $true }
                $res = @(Resolve-DnsName @prm)
                $sw.Stop()
                $ans = @($res | Where-Object { "$($_.Section)" -eq 'Answer' })
                $soa = $res | Where-Object { "$($_.Type)" -eq 'SOA' -and $null -ne $_.SerialNumber } | Select-Object -First 1
                $txt = @($ans | ForEach-Object { if ($_.IPAddress) { $_.IPAddress } elseif ($_.NameHost) { $_.NameHost } elseif ($_.NameTarget) { $_.NameTarget } elseif ($null -ne $_.SerialNumber) { "SOA serial $($_.SerialNumber)" } } | Select-Object -Unique -First 4) -join ', '
                [pscustomobject]@{ ok = $true; dead = $false; ms = [int]$sw.ElapsedMilliseconds; res = $txt; err = ''; serial = $(if ($soa) { [int64]$soa.SerialNumber } else { $null }) }
            } catch {
                $sw.Stop(); $m = Short $_.Exception.Message
                [pscustomobject]@{ ok = $false; dead = ($m -match '(?i)time ?out|timed out|no response|unreachable|forcibly closed|actively refused|1460'); ms = [int]$sw.ElapsedMilliseconds; res = ''; err = $m; serial = $null }
            }
        }

        # Liveness of a list of IPs: ping (2 passes), TCP connect on common ports, local ARP table
        $Ports = @(22, 53, 80, 135, 443, 445, 3389, 9100)
        $arp = @{}
        Safe { Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
            ForEach-Object { $arp[$_.IPAddress] = $_.LinkLayerAddress } }
        function Probe([string[]]$ips) {
            $alive = @{}
            for ($p = 1; $p -le 2; $p++) {
                $pending = @{}; $pingers = [Collections.Generic.List[object]]::new()
                foreach ($ip in $ips) { if (-not $alive.ContainsKey($ip)) { $pg = [Net.NetworkInformation.Ping]::new(); $pingers.Add($pg); $pending[$ip] = $pg.SendPingAsync($ip, 1000) } }
                if ($pending.Count -eq 0) { break }
                try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($pending.Values)) } catch { }
                foreach ($k in $pending.Keys) { $t = $pending[$k]; if ($t.Status -eq 'RanToCompletion' -and $t.Result.Status -eq 'Success') { $alive[$k] = [int]$t.Result.RoundtripTime } }
                foreach ($pg in $pingers) { $pg.Dispose() }
            }
            $tcp  = @{}
            $todo = @($ips | Where-Object { -not $alive.ContainsKey($_) })
            for ($i = 0; $i -lt $todo.Count; $i += 64) {
                $probes = foreach ($ip in $todo[$i..([math]::Min($i + 63, $todo.Count - 1))]) {
                    foreach ($port in $Ports) { $c = [Net.Sockets.TcpClient]::new(); [pscustomobject]@{ IP = $ip; Port = $port; Client = $c; Task = $c.ConnectAsync($ip, $port) } }
                }
                try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($probes.Task), 1000) } catch { }
                foreach ($pr in $probes) {
                    if ($pr.Task.Status -eq 'RanToCompletion') { $tcp[$pr.IP] = (@($tcp[$pr.IP]) + $pr.Port | Where-Object { $_ -and $_ -ne 'refused' }) -join ',' }
                    elseif ($pr.Task.IsFaulted -and $pr.Task.Exception.InnerException.SocketErrorCode -eq 'ConnectionRefused' -and -not $tcp[$pr.IP]) { $tcp[$pr.IP] = 'refused' }
                    $pr.Client.Dispose()
                }
            }
            @{ alive = $alive; tcp = $tcp }
        }

        # ---- Server ----
        Step "Connecting to $Server..." 2
        $cands = @($Server)
        if ($Server -notmatch '^\d+\.\d+\.\d+\.\d+$' -and $Server.Contains('.')) { $cands += $Server.Split('.')[0] }
        $zones = $null; $firstErr = $null
        foreach ($cand in $cands) {
            try { $zones = @(Get-DnsServerZone -ComputerName $cand); $Server = $cand; break }
            catch { if (-not $firstErr) { $firstErr = $_ } }
        }
        if ($null -eq $zones) { throw $firstErr }

        Step 'Reading server configuration...' 5
        $set   = Safe { Get-DnsServerSetting -ComputerName $Server -All }
        $rec   = Safe { Get-DnsServerRecursion -ComputerName $Server }
        $fwd   = Safe { Get-DnsServerForwarder -ComputerName $Server }
        $roots = @(Safe { Get-DnsServerRootHint -ComputerName $Server } | Where-Object { $_ })
        $scav  = Safe { Get-DnsServerScavenging -ComputerName $Server }
        $cache = Safe { Get-DnsServerCache -ComputerName $Server }
        $gqbl  = Safe { Get-DnsServerGlobalQueryBlockList -ComputerName $Server }
        $rrl   = Safe { Get-DnsServerResponseRateLimiting -ComputerName $Server }
        $diag  = Safe { Get-DnsServerDiagnostics -ComputerName $Server }
        $stat  = Safe { Get-DnsServerStatistics -ComputerName $Server }
        $svc   = Safe { Get-Service -ComputerName $Server -Name DNS }
        $fwdIps = @($fwd.IPAddress | Where-Object { $_ } | ForEach-Object { "$_" })

        # Statistics: every numeric counter, flattened as "Group.Counter"
        $stc = [ordered]@{}; $stStart = ''
        if ($stat) {
            foreach ($p in $stat.PSObject.Properties) {
                $v = $p.Value
                if ($v -isnot [Microsoft.Management.Infrastructure.CimInstance]) { continue }
                foreach ($cp in $v.CimInstanceProperties) {
                    $cv = $cp.Value
                    if ($cv -is [datetime]) { if ($cp.Name -match 'StartTime') { $stStart = Dt $cv } }
                    elseif ($cv -is [ValueType] -and $cv -isnot [bool] -and $cv -isnot [TimeSpan]) { $stc["$($p.Name -replace 'Statistics$', '').$($cp.Name)"] = $cv }
                }
            }
        }

        # ---- Event logs (last 7 days) ----
        Step 'Reading DNS event logs...' 8
        $since = (Get-Date).Date.AddDays(-6)
        $days = [ordered]@{}
        for ($d = 0; $d -le 6; $d++) { $days[$since.AddDays($d).ToString('yyyy-MM-dd')] = [ordered]@{ dyn = 0; manual = 0; scav = 0; zone = 0; server = 0; err = 0; warn = 0 } }
        $events = @(); $evErr = ''
        try { $events = @(Get-WinEvent -ComputerName $Server -FilterHashtable @{ LogName = 'DNS Server'; Level = 1, 2, 3; StartTime = $since } -MaxEvents 2000 -ErrorAction Stop) }
        catch { if ("$($_.FullyQualifiedErrorId)" -notmatch 'NoMatching') { $evErr = $_.Exception.Message } }
        foreach ($e in $events) { $k = $e.TimeCreated.ToString('yyyy-MM-dd'); if ($days.Contains($k)) { if ($e.Level -le 2) { $days[$k].err++ } else { $days[$k].warn++ } } }
        $evGroups = @($events | Group-Object { "$($_.Id)|$($_.Level)" } | ForEach-Object {
            $g = @($_.Group | Sort-Object TimeCreated -Descending)
            $m = (("$($g[0].Message)" -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' '
            if (-not $m) { $m = '(no description available)' } elseif ($m.Length -gt 300) { $m = $m.Substring(0, 300) + '...' }
            [pscustomobject]@{ log = 'DNS Server'; id = [int]$g[0].Id; level = [int]$g[0].Level; count = $_.Count
                first = $g[-1].TimeCreated.ToString('yyyy-MM-dd HH:mm'); last = $g[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'); msg = $m }
        } | Sort-Object @{ e = 'level' }, @{ e = 'count'; Descending = $true })

        # Audit channel: who changed what (records, zones, server settings)
        Step 'Reading DNS audit log...' 11
        $auRows = [Collections.Generic.List[object]]::new(); $auErr = ''; $auCap = $false; $sids = @{}
        try {
            $au = @(Get-WinEvent -ComputerName $Server -FilterHashtable @{ LogName = 'Microsoft-Windows-DNSServer/Audit'; StartTime = $since } -MaxEvents 20000 -ErrorAction Stop)
            $auCap = $au.Count -ge 20000
            foreach ($e in $au) {
                $id = [int]$e.Id
                $cat = if ($id -in 519, 520) { 'dyn' } elseif ($id -in 515, 516, 517, 518) { 'manual' } elseif ($id -eq 521) { 'scav' } elseif ($id -lt 536) { 'zone' } else { 'server' }
                $k = $e.TimeCreated.ToString('yyyy-MM-dd'); if ($days.Contains($k)) { $days[$k][$cat]++ }
                if ($cat -in 'dyn', 'scav' -or $auRows.Count -ge 500) { continue }
                $m = "$($e.Message)"; $zn = ''
                if ($m -match '(?i)\bzone ([\w.\-]+?)\.?(\s|,|$)') { $zn = $matches[1] }
                $usr = ''
                if ($e.UserId) {
                    $sid = "$($e.UserId)"
                    if (-not $sids.ContainsKey($sid)) { $sids[$sid] = try { $e.UserId.Translate([Security.Principal.NTAccount]).Value } catch { $sid } }
                    $usr = $sids[$sid]
                }
                $m = (($m -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1); if ("$m".Length -gt 300) { $m = $m.Substring(0, 300) + '...' }
                $auRows.Add([pscustomobject]@{ time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id = $id; cat = $cat; zone = $zn; user = $usr; msg = "$m" })
            }
        } catch { if ("$($_.FullyQualifiedErrorId)" -notmatch 'NoMatching') { $auErr = $_.Exception.Message } }
        $logInfo = [pscustomobject]@{
            eventsErr = $evErr; events = $evGroups; auditErr = $auErr; auditCapped = $auCap
            days = @(foreach ($k in $days.Keys) { [pscustomobject]$days[$k] | Add-Member -NotePropertyName day -NotePropertyValue $k -PassThru })
            rows = @($auRows | Sort-Object time -Descending)
        }

        # ---- Live tests: server and forwarders ----
        $tests = @(); $fwdOut = @(); $nsCache = @{}
        $zl = @($zones | Where-Object { "$($_.ZoneName)" -ne 'TrustAnchors' } | Sort-Object @{ e = { [bool]$_.IsReverseLookupZone } }, ZoneName)
        if ($Scan) {
            Step 'Live tests: resolution and forwarders...' 13
            $t = Q $ExtName 'A' $Server
            $tests += $t | Add-Member -NotePropertyName name -NotePropertyValue 'Recursion (external name)' -PassThru | Add-Member -NotePropertyName kind -NotePropertyValue 'ext' -PassThru | Add-Member -NotePropertyName query -NotePropertyValue "$ExtName A" -PassThru
            $auth = @($zl | Where-Object { "$($_.ZoneType)" -eq 'Primary' -and -not $_.IsAutoCreated -and -not $_.IsReverseLookupZone -and "$($_.ZoneName)" -notlike '_msdcs.*' } | Sort-Object @{ e = { -not $_.IsDsIntegrated } } | Select-Object -First 1)
            foreach ($z in $auth) {
                $t = Q "$($z.ZoneName)" 'SOA' $Server $true
                $tests += $t | Add-Member -NotePropertyName name -NotePropertyValue 'Authoritative answer' -PassThru | Add-Member -NotePropertyName kind -NotePropertyValue 'auth' -PassThru | Add-Member -NotePropertyName query -NotePropertyValue "$($z.ZoneName) SOA" -PassThru
            }
            $adz = @($zl | Where-Object { $_.IsDsIntegrated -and "$($_.ZoneType)" -eq 'Primary' -and -not $_.IsReverseLookupZone -and "$($_.ZoneName)" -notlike '_msdcs.*' -and -not $_.IsAutoCreated } | Select-Object -First 5)
            foreach ($z in $adz) {
                $qn = "_ldap._tcp.dc._msdcs.$($z.ZoneName)"
                $t = Q $qn 'SRV' $Server
                if (-not $t.ok -and -not $t.dead -and $t.err -match '(?i)does not exist|9003|name error') { continue }   # not an AD domain name
                $tests += $t | Add-Member -NotePropertyName name -NotePropertyValue 'Domain controller locator' -PassThru | Add-Member -NotePropertyName kind -NotePropertyValue 'dc' -PassThru | Add-Member -NotePropertyName query -NotePropertyValue "$qn SRV" -PassThru
            }
            foreach ($ip in $fwdIps) {
                $t = Q $ExtName 'A' $ip
                $fwdOut += $t | Add-Member -NotePropertyName ip -NotePropertyValue $ip -PassThru
            }
        }

        # ---- Zones ----
        $n = 0; $tot = [math]::Max($zl.Count, 1); $scanBudget = 4096; $nsBudget = 300
        $zoneOut = foreach ($z in $zl) {
            $n++; $name = "$($z.ZoneName)"; $type = "$($z.ZoneType)"
            $base = 16 + [int](80 * ($n - 1) / $tot)
            Step "Zone $name ($n of $tot): records" $base

            $ag = $null
            if ($type -eq 'Primary') { $ag = Safe { Get-DnsServerZoneAging -ComputerName $Server -Name $name } }
            $agingOn   = $(if ($ag) { [bool]$ag.AgingEnabled } else { $null })
            $staleDays = 14
            if ($agingOn) { $staleDays = [math]::Max(1, [math]::Round(($ag.NoRefreshInterval + $ag.RefreshInterval).TotalDays, 1)) }

            $rrs = @()
            if ($type -ne 'Forwarder') { $rrs = @(Safe { Get-DnsServerResourceRecord -ComputerName $Server -ZoneName $name } | Where-Object { $_ }) }
            $total = $rrs.Count; $cap = 30000
            $recs = foreach ($r in ($rrs | Select-Object -First $cap)) {
                [pscustomobject]@{ n = "$($r.HostName)"; t = "$($r.RecordType)"; d = (RData $r); ttl = (Sec $r.TimeToLive); ts = (Dt $r.Timestamp) }
            }
            $soaR = $rrs | Where-Object { "$($_.RecordType)" -eq 'SOA' } | Select-Object -First 1
            $soa  = $null
            if ($soaR) {
                $sd = $soaR.RecordData
                $soa = [pscustomobject]@{ primary = "$($sd.PrimaryServer)"; admin = "$($sd.ResponsiblePerson)"; serial = [int64]$sd.SerialNumber
                    refresh = (Sec $sd.RefreshInterval); retry = (Sec $sd.RetryDelay); expire = (Sec $sd.ExpireLimit); minTtl = (Sec $sd.MinimumTimeToLive) }
            }
            $nsNames = @($rrs | Where-Object { "$($_.RecordType)" -eq 'NS' -and "$($_.HostName)" -eq '@' } | ForEach-Object { "$($_.RecordData.NameServer)".TrimEnd('.') } | Select-Object -Unique)

            # Name servers: does each one answer for the zone, and with which SOA serial?
            $ns = @(foreach ($nsn in $nsNames) { [pscustomobject]@{ name = $nsn; ip = ''; tested = $false; ok = $false; dead = $false; ms = 0; serial = $null; err = '' } })
            if ($Scan -and $type -in 'Primary', 'Secondary' -and -not $z.IsAutoCreated -and $nsBudget -gt 0) {
                $nsBudget--
                Step "Zone ${name}: checking name servers" ($base + [int](30 / $tot))
                foreach ($x in $ns) {
                    $x.tested = $true
                    if (-not $nsCache.ContainsKey($x.name)) {
                        $a = Q $x.name 'A' $Server
                        $nsCache[$x.name] = $(if ($a.ok -and $a.res) { "$($a.res)".Split(',')[0].Trim() } else { '' })
                    }
                    $x.ip = $nsCache[$x.name]
                    if (-not $x.ip) { $x.err = 'Name server name does not resolve to an IPv4 address'; continue }
                    $t = Q $name 'SOA' $x.ip $true
                    $x.ok = $t.ok; $x.dead = $t.dead; $x.ms = $t.ms; $x.serial = $t.serial; $x.err = $t.err
                }
            }

            # Conditional forwarders: does each master answer?
            $masters = @($z.MasterServers | Where-Object { $_ } | ForEach-Object { "$_" })
            $fwdTest = @()
            if ($Scan -and $type -eq 'Forwarder') {
                Step "Zone ${name}: testing forwarder servers" $base
                $fwdTest = @(foreach ($m in $masters) { Q $name 'SOA' $m | Add-Member -NotePropertyName ip -NotePropertyValue $m -PassThru })
            }

            # Liveness of static and stale A records (forward primary zones)
            $scanRes = $null
            if ($Scan -and $type -eq 'Primary' -and -not $z.IsReverseLookupZone -and -not $z.IsAutoCreated -and $scanBudget -gt 0) {
                $limit = (Get-Date).AddDays(-$staleDays)
                $byIp = [ordered]@{}
                foreach ($r in $rrs) {
                    if ("$($r.RecordType)" -ne 'A' -or "$($r.HostName)" -like '*_*') { continue }
                    $isStale = $r.Timestamp -is [datetime] -and $r.Timestamp.Year -gt 1601 -and $r.Timestamp -lt $limit
                    $isStatic = -not ($r.Timestamp -is [datetime] -and $r.Timestamp.Year -gt 1601)
                    if (-not ($isStale -or $isStatic)) { continue }
                    $ip = "$($r.RecordData.IPv4Address)"
                    if (-not $byIp.Contains($ip)) { $byIp[$ip] = [pscustomobject]@{ names = [Collections.Generic.List[string]]::new(); stale = $false; static = $false } }
                    $byIp[$ip].names.Add("$($r.HostName)"); if ($isStale) { $byIp[$ip].stale = $true } else { $byIp[$ip].static = $true }
                }
                $ips = @($byIp.Keys | Select-Object -First ([math]::Min(1024, $scanBudget)))
                if ($ips.Count) {
                    $scanBudget -= $ips.Count
                    Step "Zone ${name}: checking $($ips.Count) static and stale addresses (ping, ports, ARP)" ($base + [int](50 / $tot))
                    $pr = Probe $ips
                    $out = foreach ($ip in $ips) {
                        $e = $byIp[$ip]
                        $live = $pr.alive.ContainsKey($ip) -or ($pr.tcp.ContainsKey($ip)) -or $arp.ContainsKey($ip)
                        [pscustomobject]@{ ip = $ip; names = (@($e.names | Select-Object -Unique) -join ', ')
                            kind = $(if ($e.stale -and $e.static) { 'both' } elseif ($e.stale) { 'stale' } else { 'static' })
                            cls = $(if ($live) { 'live' } else { 'dead' })
                            ping = $(if ($pr.alive.ContainsKey($ip)) { $pr.alive[$ip] } else { '' }); tcp = "$($pr.tcp[$ip])"; mac = "$($arp[$ip])" }
                    }
                    $scanRes = [pscustomobject]@{ total = $byIp.Count; ips = @($out) }
                }
            }

            [pscustomobject]@{
                name = $name; type = $type; ad = [bool]$z.IsDsIntegrated; repl = "$($z.ReplicationScope)"; part = "$($z.DirectoryPartitionName)"
                dyn = "$($z.DynamicUpdate)"; rev = [bool]$z.IsReverseLookupZone; auto = [bool]$z.IsAutoCreated
                paused = [bool]$z.IsPaused; shutdown = [bool]$z.IsShutdown; signed = [bool]$z.IsSigned; file = "$($z.ZoneFile)"
                xfer = "$($z.SecureSecondaries)"; xferTo = @($z.SecondaryServers | Where-Object { $_ } | ForEach-Object { "$_" }); notify = "$($z.Notify)"
                masters = $masters; useRec = [bool](P $z 'UseRecursion'); fwdTimeout = "$(P $z 'ForwarderTimeout')"
                lastSoa = (Dt (P $z 'LastSuccessfulSOACheck')); lastXfr = (Dt (P $z 'LastSuccessfulXfr')); xferRes = "$(P $z 'LastZoneTransferResult')"
                aging = $agingOn; noRef = (Span $ag.NoRefreshInterval); refr = (Span $ag.RefreshInterval); staleDays = $staleDays
                scavAvail = $(if ($ag) { Dt $ag.AvailForScavengeTime } else { '' })
                soa = $soa; ns = $ns; fwdTest = $fwdTest
                total = $total; truncated = ($total -gt $cap); records = @($recs)
                scan = $scanRes
            }
        }

        Step 'Building dashboard...' 97
        $data = [pscustomobject]@{
            server = $Server; generated = (Get-Date).ToString('yyyy-MM-dd HH:mm'); scanned = [bool]$Scan; demo = $false; extName = $ExtName
            settings = [pscustomobject]@{
                service = "$($svc.Status)"; startType = "$($svc.StartType)"
                version = $(if ($set) { "$($set.MajorVersion).$($set.MinorVersion).$($set.BuildNumber)" } else { '' })
                rodc = $(if ($set) { [bool]$set.IsReadOnlyDC } else { $null })
                listen = @($set.ListeningIPAddress | Where-Object { $_ } | ForEach-Object { "$_" }); allIps = @($set.AllIPAddress | Where-Object { $_ } | ForEach-Object { "$_" })
                roundRobin = $(if ($set) { [bool]$set.RoundRobin } else { $null }); dnssec = $(if ($set) { [bool]$set.EnableDnsSec } else { $null })
                plugin = "$(P $set 'ServerLevelPluginDll')"; bindSec = $(if ($set) { [bool]$set.BindSecondaries } else { $null })
                recursion = $(if ($rec) { [bool]$rec.Enable } else { $null }); recTimeout = (Sec $rec.Timeout); secureResp = $(if ($rec) { [bool]$rec.SecureResponse } else { $null })
                fwdIps = $fwdIps; useRoot = $(if ($fwd) { [bool]$fwd.UseRootHint } else { $null }); fwdTimeout = (Sec $fwd.Timeout); rootN = $roots.Count
                scavOn = $(if ($scav) { [bool]$scav.ScavengingState } else { $null }); scavInt = (Span $scav.ScavengingInterval); scavIntH = $(if ($scav) { [math]::Round($scav.ScavengingInterval.TotalHours, 1) } else { 0 })
                scavNoRef = (Span $scav.NoRefreshInterval); scavRef = (Span $scav.RefreshInterval); lastScav = (Dt $scav.LastScavengeTime)
                cacheMaxKB = $(if ($cache) { [int64]$cache.MaxKBSize } else { $null }); cacheMaxTtl = (Span $cache.MaxTTL)
                pollution = $(if ($cache) { [bool]$cache.EnablePollutionProtection } else { $null }); locking = $(if ($cache) { [int]$cache.LockingPercent } else { $null })
                gqblOn = $(if ($gqbl) { [bool]$gqbl.Enable } else { $null }); gqbl = (@($gqbl.List) -join ', ')
                rrl = "$($rrl.Mode)"
                debugLog = $(if ($diag) { [bool]($diag.EnableLoggingToFile -and ($diag.SendPackets -or $diag.ReceivePackets)) } else { $null }); debugPath = "$($diag.LogFilePath)"
            }
            rootHints = @($roots | ForEach-Object { [pscustomobject]@{ name = "$($_.NameServer.RecordData.NameServer)".TrimEnd('.'); ips = (@($_.IPAddress | ForEach-Object { "$($_.RecordData.IPv4Address)$($_.RecordData.IPv6Address)" } | Where-Object { $_ }) -join ', ') } })
            tests = @($tests); forwarders = @($fwdOut)
            stats = $(if ($stc.Count) { [pscustomobject]@{ start = $stStart; c = [pscustomobject]$stc } } else { $null })
            zones = @($zoneOut)
            logs = $logInfo
        }
        $Sync.Json = ($data | ConvertTo-Json -Depth 8 -Compress)
        Step 'Analysis completed' 100
    }
    catch {
        $msg  = $_.Exception.Message
        $fqid = "$($_.FullyQualifiedErrorId)"
        $all  = "$msg $fqid $($_.Exception.InnerException.Message)"
        $admin = $false
        try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
        $hint = if ($all -match 'Access is denied|Accesso negato|0x80070005|WIN32 5\b') {
            'ACCESS DENIED. ' + $(if (-not $admin) { 'The program is not running as administrator: restart it and accept the UAC prompt. ' } else { '' }) +
            "Make sure $env:USERDOMAIN\$env:USERNAME is a member of 'DnsAdmins' (or an administrator) on the DNS server."
        } elseif ($all -match 'WinRM|WS-Management|0x80338|CimException.*(cannot|could not) (connect|complete)') {
            'CONNECTION FAILED (WinRM): the DnsServer cmdlets use WS-Management. Check the server name, that WinRM is enabled on the server (Enable-PSRemoting) and that the firewall allows TCP 5985.'
        } elseif ($all -match 'WIN32 1722|RPC') {
            'RPC SERVER UNAVAILABLE: check the server name/DNS and that the firewall allows remote management.'
        } elseif ($all -match 'WIN32 1355|WIN32 53\b|No such host|could not be resolved|cannot find the computer') {
            'SERVER NOT FOUND: check the server name and DNS resolution, or try the IP address.'
        } elseif ($all -match 'Modules_ModuleNotFound|module .DnsServer. was not loaded') {
            'DnsServer module not found: install the RSAT "DNS Server Tools" on this PC.'
        } elseif ($all -match 'WIN32 9|DNS server') {
            'The server answered, but it does not look like a Windows DNS server (or the DNS Server service is stopped).'
        } else {
            "Running as administrator: $(if ($admin) { 'yes' } else { 'no' }). Try in PowerShell: Get-DnsServerZone -ComputerName $Server"
        }
        $Sync.Error = "$msg [$fqid]`r`n$hint"
    }
    finally { $Sync.Done = $true }
}

# =============================================================================
#  DEMO DATA (realistic, fictitious)
# =============================================================================
function New-DemoData {
    $rnd = [Random]::new(2026)
    $now = Get-Date
    $dom = 'contoso.local'
    function Ts([double]$daysAgo) { $now.AddDays(-$daysAgo).AddMinutes(-$rnd.Next(600)).ToString('yyyy-MM-dd HH:mm') }
    function Rr([string]$n, [string]$t, [string]$d, [int]$ttl, [string]$ts) { [pscustomobject]@{ n = $n; t = $t; d = $d; ttl = $ttl; ts = $ts } }
    function NsR([string]$name, [string]$ip, [bool]$ok, [int]$ms, $serial, [string]$err) {
        [pscustomobject]@{ name = $name; ip = $ip; tested = $true; ok = $ok; dead = (-not $ok -and $err -match 'time'); ms = $ms; serial = $serial; err = $err }
    }
    function Soa([string]$primary, [int64]$serial, [int]$expire) { [pscustomobject]@{ primary = $primary; admin = "hostmaster.$dom"; serial = $serial; refresh = 900; retry = 600; expire = $expire; minTtl = 3600 } }
    function Zone([hashtable]$h) {
        $z = [ordered]@{ name = ''; type = 'Primary'; ad = $true; repl = 'Domain'; part = "DomainDnsZones.$dom"; dyn = 'Secure'; rev = $false; auto = $false
            paused = $false; shutdown = $false; signed = $false; file = ''; xfer = 'NoTransfer'; xferTo = @(); notify = 'NoNotify'
            masters = @(); useRec = $false; fwdTimeout = ''; lastSoa = ''; lastXfr = ''; xferRes = ''
            aging = $false; noRef = ''; refr = ''; staleDays = 14; scavAvail = ''; soa = $null; ns = @(); fwdTest = @()
            total = 0; truncated = $false; records = @(); scan = $null }
        foreach ($k in $h.Keys) { $z[$k] = $h[$k] }
        if ($z.type -ne 'Primary') { $z.aging = $null }
        $z.total = @($z.records).Count
        [pscustomobject]$z
    }
    $nsDc = @((NsR "dc01.$dom" '10.10.0.10' $true 2 2026101942 ''), (NsR "dc02.$dom" '10.10.0.11' $true 3 2026101938 ''))

    # 1 - contoso.local: AD domain zone, servers, workstations (some stale), CNAMEs
    $r1 = [Collections.Generic.List[object]]::new()
    $r1.Add((Rr '@' 'SOA' "dc01.$dom. hostmaster.$dom. 2026101942" 3600 ''))
    $r1.Add((Rr '@' 'NS' "dc01.$dom." 3600 '')); $r1.Add((Rr '@' 'NS' "dc02.$dom." 3600 ''))
    foreach ($ip in '10.10.0.10', '10.10.0.11') { $r1.Add((Rr '@' 'A' $ip 600 (Ts 0.3))); $r1.Add((Rr 'DomainDnsZones' 'A' $ip 600 (Ts 0.3))); $r1.Add((Rr 'ForestDnsZones' 'A' $ip 600 (Ts 0.3))) }
    $r1.Add((Rr 'dc01' 'A' '10.10.0.10' 3600 '')); $r1.Add((Rr 'dc02' 'A' '10.10.0.11' 3600 ''))
    foreach ($dc in 'dc01', 'dc02') {
        $r1.Add((Rr '_ldap._tcp' 'SRV' "0 100 389 $dc.$dom." 600 (Ts 0.2))); $r1.Add((Rr '_kerberos._tcp' 'SRV' "0 100 88 $dc.$dom." 600 (Ts 0.2)))
        $r1.Add((Rr '_kpasswd._udp' 'SRV' "0 100 464 $dc.$dom." 600 (Ts 0.2))); $r1.Add((Rr '_gc._tcp' 'SRV' "0 100 3268 $dc.$dom." 600 (Ts 0.2)))
    }
    $srv = [ordered]@{ 'srv-file01' = 20; 'srv-app01' = 21; 'srv-web01' = 22; 'srv-sql01' = 23; 'srv-print01' = 24; 'srv-backup01' = 25; 'srv-wsus01' = 26; 'srv-old-erp' = 30; 'nas01' = 31; 'srv-ca01' = 32; 'srv-vcenter' = 40; 'esx01' = 41; 'esx02' = 42; 'esx03' = 43 }
    foreach ($k in $srv.Keys) { $r1.Add((Rr $k 'A' "10.10.0.$($srv[$k])" 3600 '')) }
    $r1.Add((Rr 'intranet' 'CNAME' "srv-web01.$dom." 3600 '')); $r1.Add((Rr 'erp' 'CNAME' "srv-old-erp.$dom." 3600 ''))
    $r1.Add((Rr 'wiki' 'CNAME' "srv-wiki01.$dom." 3600 '')); $r1.Add((Rr 'files' 'CNAME' "srv-file01.$dom." 3600 ''))
    $r1.Add((Rr 'wsus' 'CNAME' "srv-wsus01.$dom." 3600 '')); $r1.Add((Rr 'helpdesk' 'CNAME' "srv-helpdesk.$dom." 3600 ''))
    $r1.Add((Rr 'pki' 'CNAME' "srv-ca01.$dom." 3600 ''))
    for ($i = 1; $i -le 18; $i++) { $r1.Add((Rr ('prn-floor{0}-{1:00}' -f [math]::Ceiling($i / 6), $i) 'A' "10.10.8.$(9 + $i)" 3600 '')) }
    # workstations: 360 current, 70 stale (DHCP has since given some of their IPs to other PCs)
    $pool = @(foreach ($h in 0..1) { foreach ($l in $(if ($h) { 20..250 } else { 50..250 })) { "10.10.$h.$l" } })
    $used = @{}
    for ($i = 0; $i -lt 360; $i++) {
        $ip = $pool[$i]; $used[$i] = $true
        $pfx = @('ws', 'lt', 'mac')[$rnd.Next(3)]
        $r1.Add((Rr ('{0}-{1:0000}' -f $pfx, $rnd.Next(10, 9999)) 'A' $ip 1200 (Ts ($rnd.NextDouble() * 6))))
    }
    for ($i = 0; $i -lt 70; $i++) {
        $ip = if ($i % 3 -eq 0) { $pool[$rnd.Next(360)] } else { $pool[360 + $i] }
        $r1.Add((Rr ('{0}-{1:0000}' -f @('ws', 'lt')[$rnd.Next(2)], $rnd.Next(10, 9999)) 'A' $ip 1200 (Ts (15 + $rnd.Next(160)))))
    }
    for ($i = 1; $i -le 40; $i++) { $r1.Add((Rr ('mi-ws-{0:000}' -f $i) 'A' "10.20.0.$(9 + $i)" 1200 (Ts ($rnd.NextDouble() * 5)))) }
    $staleA = @($r1 | Where-Object { $_.t -eq 'A' -and $_.ts -and ($now - [datetime]$_.ts).TotalDays -gt 14 })
    $scanIps = [Collections.Generic.List[object]]::new()
    foreach ($k in $srv.Keys) {
        $dead = $k -in 'srv-old-erp', 'nas01'
        $scanIps.Add([pscustomobject]@{ ip = "10.10.0.$($srv[$k])"; names = $k; kind = 'static'; cls = $(if ($dead) { 'dead' } else { 'live' }); ping = $(if ($dead -or $k -eq 'srv-vcenter') { '' } else { $rnd.Next(1, 3) }); tcp = $(if ($k -eq 'srv-vcenter') { '443' } else { '' }); mac = '' })
    }
    $scanIps.Add([pscustomobject]@{ ip = '10.10.0.10'; names = 'dc01'; kind = 'static'; cls = 'live'; ping = 1; tcp = ''; mac = '' })
    $scanIps.Add([pscustomobject]@{ ip = '10.10.0.11'; names = 'dc02'; kind = 'static'; cls = 'live'; ping = 1; tcp = ''; mac = '' })
    for ($i = 1; $i -le 18; $i++) { $off = $i -in 5, 11; $scanIps.Add([pscustomobject]@{ ip = "10.10.8.$(9 + $i)"; names = ('prn-floor{0}-{1:00}' -f [math]::Ceiling($i / 6), $i); kind = 'static'; cls = $(if ($off) { 'dead' } else { 'live' }); ping = $(if ($off) { '' } else { $rnd.Next(1, 4) }); tcp = ''; mac = '' }) }
    foreach ($g in ($staleA | Group-Object d)) {
        $reused = [bool]($r1 | Where-Object { $_.t -eq 'A' -and $_.d -eq $g.Name -and $_.ts -and ($now - [datetime]$_.ts).TotalDays -le 14 })
        $live = $reused -or $rnd.Next(10) -lt 2
        $scanIps.Add([pscustomobject]@{ ip = $g.Name; names = (@($g.Group.n) -join ', '); kind = 'stale'; cls = $(if ($live) { 'live' } else { 'dead' }); ping = $(if ($live) { $rnd.Next(1, 6) } else { '' }); tcp = ''; mac = '' })
    }
    $z1 = Zone @{ name = $dom; aging = $true; noRef = '7 d'; refr = '7 d'; staleDays = 14; scavAvail = (Ts 120); soa = (Soa "dc01.$dom" 2026101942 86400)
        ns = $nsDc; records = @($r1); scan = [pscustomobject]@{ total = $scanIps.Count; ips = @($scanIps) } }

    # 2 - _msdcs: forest-wide locator zone
    $r2 = @((Rr '@' 'SOA' "dc01.$dom. hostmaster.$dom. 1187" 3600 ''), (Rr '@' 'NS' "dc01.$dom." 3600 ''), (Rr '@' 'NS' "dc02.$dom." 3600 ''),
        (Rr '_ldap._tcp.dc' 'SRV' "0 100 389 dc01.$dom." 600 (Ts 0.2)), (Rr '_ldap._tcp.dc' 'SRV' "0 100 389 dc02.$dom." 600 (Ts 0.2)),
        (Rr '_kerberos._tcp.dc' 'SRV' "0 100 88 dc01.$dom." 600 (Ts 0.2)), (Rr '_kerberos._tcp.dc' 'SRV' "0 100 88 dc02.$dom." 600 (Ts 0.2)),
        (Rr '_ldap._tcp.dc' 'SRV' "0 100 389 dc03.$dom." 600 (Ts 240)),
        (Rr 'gc' 'A' '10.10.0.10' 600 (Ts 0.2)), (Rr 'gc' 'A' '10.10.0.11' 600 (Ts 0.2)),
        (Rr '3f2a9c1e-5b7d-4e21-9a0c-6d8e1f4b2a77' 'CNAME' "dc01.$dom." 600 (Ts 0.2)), (Rr '8b4e7d20-1c3f-4a9e-b5d6-0e2f9a8c7b11' 'CNAME' "dc02.$dom." 600 (Ts 0.2)))
    $z2 = Zone @{ name = "_msdcs.$dom"; repl = 'Forest'; part = "ForestDnsZones.$dom"; soa = (Soa "dc01.$dom" 1187 86400)
        ns = @((NsR "dc01.$dom" '10.10.0.10' $true 2 1187 ''), (NsR "dc02.$dom" '10.10.0.11' $true 2 1187 '')); records = $r2 }

    # 3 - reverse zone 10.10.x.x (10.20.x.x has none)
    $r3 = [Collections.Generic.List[object]]::new()
    $r3.Add((Rr '@' 'SOA' "dc01.$dom. hostmaster.$dom. 4471" 3600 '')); $r3.Add((Rr '@' 'NS' "dc01.$dom." 3600 '')); $r3.Add((Rr '@' 'NS' "dc02.$dom." 3600 ''))
    foreach ($a in @($r1 | Where-Object { $_.t -eq 'A' -and $_.n -notin '@', 'DomainDnsZones', 'ForestDnsZones' -and $_.d -like '10.10.*' })) {
        if ($a.n -in 'srv-backup01', 'srv-vcenter', 'esx02', 'esx03' -or ($a.n -like 'prn-*' -and $a.d -notlike '*.1?')) { continue }
        $o = $a.d.Split('.')
        $r3.Add((Rr "$($o[3]).$($o[2])" 'PTR' "$($a.n).$dom." 1200 $a.ts))
    }
    $r3.Add((Rr '33.0' 'PTR' "srv-legacy-ftp.$dom." 3600 '')); $r3.Add((Rr '34.0' 'PTR' "srv-file01.$dom." 3600 ''))
    $z3 = Zone @{ name = '10.10.in-addr.arpa'; rev = $true; aging = $true; noRef = '7 d'; refr = '7 d'; staleDays = 14; soa = (Soa "dc01.$dom" 4471 86400); records = @($r3)
        ns = @((NsR "dc01.$dom" '10.10.0.10' $true 2 4471 ''), (NsR "dc02.$dom" '10.10.0.11' $true 2 4471 '')) }

    # 4 - contoso.com: public zone, file-backed, open transfers, outdated secondary
    $r4 = @((Rr '@' 'SOA' "ns1.contoso.com. hostmaster.contoso.com. 2026101501" 3600 ''), (Rr '@' 'NS' 'ns1.contoso.com.' 3600 ''), (Rr '@' 'NS' 'ns2.contoso.com.' 3600 ''),
        (Rr '@' 'A' '203.0.113.10' 3600 ''), (Rr 'www' 'A' '203.0.113.10' 3600 ''), (Rr 'ns1' 'A' '203.0.113.2' 3600 ''), (Rr 'ns2' 'A' '198.51.100.2' 3600 ''),
        (Rr '@' 'MX' '10 mail.contoso.com.' 3600 ''), (Rr 'mail' 'A' '203.0.113.25' 3600 ''), (Rr 'autodiscover' 'CNAME' 'mail.contoso.com.' 3600 ''),
        (Rr 'shop' 'CNAME' 'shop-old.contoso.com.' 3600 ''), (Rr '@' 'TXT' 'v=spf1 mx ip4:203.0.113.25 -all' 3600 ''), (Rr '_sip._tls' 'SRV' '100 1 443 sip.contoso.com.' 3600 ''),
        (Rr 'vpn' 'A' '203.0.113.30' 3600 ''))
    $z4 = Zone @{ name = 'contoso.com'; ad = $false; repl = 'None'; part = ''; dyn = 'None'; file = 'contoso.com.dns'; xfer = 'TransferAnyServer'; notify = 'Notify'
        soa = (Soa 'ns1.contoso.com' 2026101501 604800); records = $r4
        ns = @((NsR 'ns1.contoso.com' '203.0.113.2' $true 18 2026101501 ''), (NsR 'ns2.contoso.com' '198.51.100.2' $true 41 2026100902 '')) }

    # 5 - legacy.local: nonsecure updates, no aging, plenty of stale records
    $r5 = [Collections.Generic.List[object]]::new()
    $r5.Add((Rr '@' 'SOA' "dc01.$dom. hostmaster.$dom. 911" 3600 '')); $r5.Add((Rr '@' 'NS' "dc01.$dom." 3600 ''))
    for ($i = 1; $i -le 46; $i++) { $r5.Add((Rr ('pos-{0:000}' -f $i) 'A' "10.10.12.$(20 + $i)" 1200 (Ts $(if ($i -le 31) { 30 + $rnd.Next(500) } else { $rnd.NextDouble() * 5 })))) }
    $r5.Add((Rr 'scanner01' 'A' '10.10.12.5' 3600 ''))
    $z5 = Zone @{ name = 'legacy.local'; dyn = 'NonsecureAndSecure'; aging = $false; soa = (Soa "dc01.$dom" 911 86400); records = @($r5)
        ns = @((NsR "dc01.$dom" '10.10.0.10' $true 2 911 '')) }

    # 6 - partner.example: secondary zone whose master is no longer reachable
    $r6 = @((Rr '@' 'SOA' 'ns.partner.example. admin.partner.example. 2026092201' 3600 ''), (Rr '@' 'NS' 'ns.partner.example.' 3600 ''),
        (Rr 'portal' 'A' '192.0.2.40' 3600 ''), (Rr 'ns' 'A' '192.0.2.10' 3600 ''), (Rr 'edi' 'A' '192.0.2.41' 3600 ''))
    $z6 = Zone @{ name = 'partner.example'; type = 'Secondary'; ad = $false; repl = 'None'; part = ''; dyn = 'None'; file = 'partner.example.dns'
        masters = @('192.0.2.10'); lastSoa = (Ts 9); lastXfr = (Ts 27); xferRes = '1460'; records = $r6
        soa = [pscustomobject]@{ primary = 'ns.partner.example'; admin = 'admin.partner.example'; serial = 2026092201; refresh = 3600; retry = 600; expire = 604800; minTtl = 3600 }
        ns = @((NsR 'ns.partner.example' '192.0.2.10' $false 4012 $null 'This operation returned because the timeout period expired')) }

    # 7 - conditional forwarders
    $z7 = Zone @{ name = 'fabrikam.com'; type = 'Forwarder'; repl = 'Forest'; part = "ForestDnsZones.$dom"; dyn = 'None'; masters = @('10.50.0.10', '10.50.0.11'); fwdTimeout = '3'
        fwdTest = @([pscustomobject]@{ ip = '10.50.0.10'; ok = $true; dead = $false; ms = 23; res = 'SOA serial 2026101801'; err = ''; serial = 2026101801 },
                    [pscustomobject]@{ ip = '10.50.0.11'; ok = $false; dead = $true; ms = 4004; res = ''; err = 'This operation returned because the timeout period expired'; serial = $null }) }
    $z8 = Zone @{ name = 'northwind.lab'; type = 'Forwarder'; ad = $false; repl = 'None'; part = ''; dyn = 'None'; masters = @('172.16.50.5'); fwdTimeout = '3'
        fwdTest = @([pscustomobject]@{ ip = '172.16.50.5'; ok = $true; dead = $false; ms = 8; res = 'SOA serial 77'; err = ''; serial = 77 }) }

    # 8 - auto-created zones
    $autos = foreach ($a in '0.in-addr.arpa', '127.in-addr.arpa', '255.in-addr.arpa') {
        Zone @{ name = $a; ad = $false; repl = 'None'; part = ''; dyn = 'None'; rev = $true; auto = $true; file = "$a.dns"; records = @((Rr '@' 'SOA' 'localhost. hostmaster. 1' 86400 ''), (Rr '@' 'NS' 'localhost.' 86400 '')) }
    }

    # Logs: last 7 days
    $since = $now.Date.AddDays(-6)
    $at = { param($d, $h) $since.AddDays($d).AddHours($h).AddMinutes($rnd.Next(60)).ToString('yyyy-MM-dd HH:mm:ss') }
    $days = foreach ($d in 0..6) {
        $wk = $since.AddDays($d).DayOfWeek -in 'Saturday', 'Sunday'
        [pscustomobject]@{ day = $since.AddDays($d).ToString('yyyy-MM-dd'); dyn = $(if ($wk) { $rnd.Next(40, 120) } else { $rnd.Next(380, 820) })
            manual = $(if ($d -in 1, 4) { 2 } else { 0 }); scav = 0; zone = $(if ($d -eq 4) { 1 } else { 0 }); server = $(if ($d -eq 2) { 1 } else { 0 })
            err = $(if ($d -in 3, 5) { $(if ($d -eq 3) { 2 } else { 1 }) } else { 0 }); warn = $(if ($wk) { 0 } else { $rnd.Next(1, 4) }) }
    }
    $rows = @(
        [pscustomobject]@{ time = (& $at 1 10); id = 516; cat = 'manual'; zone = $dom; user = 'CONTOSO\it-admin'; msg = "A resource record of type 1, name srv-wiki01.$dom and RDATA 10.10.0.35 was deleted from scope Default of zone $dom." },
        [pscustomobject]@{ time = (& $at 1 10); id = 515; cat = 'manual'; zone = $dom; user = 'CONTOSO\it-admin'; msg = "A resource record of type 5, name helpdesk.$dom and RDATA srv-helpdesk.$dom was created in scope Default of zone $dom." },
        [pscustomobject]@{ time = (& $at 2 15); id = 541; cat = 'server'; zone = ''; user = 'CONTOSO\it-admin'; msg = 'The setting Forwarders was modified on the DNS server.' },
        [pscustomobject]@{ time = (& $at 4 9); id = 515; cat = 'manual'; zone = 'contoso.com'; user = 'CONTOSO\web-team'; msg = 'A resource record of type 1, name vpn.contoso.com and RDATA 203.0.113.30 was created in scope Default of zone contoso.com.' },
        [pscustomobject]@{ time = (& $at 4 9); id = 514; cat = 'zone'; zone = 'contoso.com'; user = 'CONTOSO\web-team'; msg = 'The zone contoso.com was updated. The property SecureSecondaries was set to TransferAnyServer.' },
        [pscustomobject]@{ time = (& $at 4 11); id = 516; cat = 'manual'; zone = 'contoso.com'; user = 'CONTOSO\web-team'; msg = 'A resource record of type 1, name shop-old.contoso.com and RDATA 203.0.113.50 was deleted from scope Default of zone contoso.com.' })
    $logs = [pscustomobject]@{ eventsErr = ''; auditErr = ''; auditCapped = $false; days = @($days); rows = @($rows | Sort-Object time -Descending)
        events = @(
            [pscustomobject]@{ log = 'DNS Server'; id = 4015; level = 2; count = 3; first = (& $at 3 2).Substring(0, 16); last = (& $at 5 3).Substring(0, 16)
                msg = 'The DNS server has encountered a critical error from the Active Directory. Check that the Active Directory is functioning properly.' },
            [pscustomobject]@{ log = 'DNS Server'; id = 5504; level = 3; count = 9; first = (& $at 0 9).Substring(0, 16); last = (& $at 6 11).Substring(0, 16)
                msg = 'The DNS server encountered an invalid domain name in a packet from 10.10.1.77. The packet will be rejected.' },
            [pscustomobject]@{ log = 'DNS Server'; id = 4013; level = 3; count = 1; first = (& $at 3 1).Substring(0, 16); last = (& $at 3 1).Substring(0, 16)
                msg = 'The DNS server is waiting for Active Directory Domain Services (AD DS) to signal that the initial synchronization of the directory has been completed.' }) }

    $c = [ordered]@{ 'Query.TotalQueries' = 48213977; 'Query.TotalResponses' = 48190211; 'Query.UdpQueries' = 47011220; 'Query.TcpQueries' = 1202757
        'Error.NoError' = 45620133; 'Error.NxDomain' = 2311870; 'Error.ServFail' = 186402; 'Error.Refused' = 4310; 'Error.FormError' = 1291
        'Recursion.TotalQuestionsRecursed' = 9133412; 'Recursion.RecursionFailure' = 96221; 'Recursion.TimedoutQueries' = 61877
        'DynamicUpdate.DynamicUpdateReceived' = 391223; 'DynamicUpdate.DynamicUpdateRejected' = 1873; 'DynamicUpdate.DynamicUpdateWriteToDB' = 389350
        'ZoneTransfer.TransferRequestReceived' = 418; 'ZoneTransfer.TransferFailures' = 0 }

    [pscustomobject]@{
        server = "DC01.$dom"; generated = $now.ToString('yyyy-MM-dd HH:mm'); scanned = $true; demo = $true; extName = 'www.microsoft.com'
        settings = [pscustomobject]@{ service = 'Running'; startType = 'Automatic'; version = '10.0.20348'; rodc = $false
            listen = @(); allIps = @('10.10.0.10'); roundRobin = $true; dnssec = $true; plugin = ''; bindSec = $false
            recursion = $true; recTimeout = 8; secureResp = $true; fwdIps = @('1.1.1.1', '9.9.9.9', '192.0.2.53'); useRoot = $true; fwdTimeout = 3; rootN = 13
            scavOn = $false; scavInt = '7 d'; scavIntH = 168; scavNoRef = '7 d'; scavRef = '7 d'; lastScav = ''
            cacheMaxKB = 0; cacheMaxTtl = '1 d'; pollution = $true; locking = 100; gqblOn = $true; gqbl = 'wpad, isatap'; rrl = 'Disable'; debugLog = $false; debugPath = '' }
        rootHints = @(foreach ($l in 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm') { [pscustomobject]@{ name = "$l.root-servers.net"; ips = '' } })
        tests = @(
            [pscustomobject]@{ name = 'Recursion (external name)'; kind = 'ext'; query = 'www.microsoft.com A'; ok = $true; dead = $false; ms = 31; res = '23.53.122.18'; err = ''; serial = $null },
            [pscustomobject]@{ name = 'Authoritative answer'; kind = 'auth'; query = "$dom SOA"; ok = $true; dead = $false; ms = 2; res = 'SOA serial 2026101942'; err = ''; serial = 2026101942 },
            [pscustomobject]@{ name = 'Domain controller locator'; kind = 'dc'; query = "_ldap._tcp.dc._msdcs.$dom SRV"; ok = $true; dead = $false; ms = 2; res = "dc01.$dom, dc02.$dom, dc03.$dom"; err = ''; serial = $null })
        forwarders = @(
            [pscustomobject]@{ ip = '1.1.1.1'; ok = $true; dead = $false; ms = 14; res = '23.53.122.18'; err = ''; serial = $null },
            [pscustomobject]@{ ip = '9.9.9.9'; ok = $true; dead = $false; ms = 22; res = '23.53.122.18'; err = ''; serial = $null },
            [pscustomobject]@{ ip = '192.0.2.53'; ok = $false; dead = $true; ms = 2003; res = ''; err = 'This operation returned because the timeout period expired'; serial = $null })
        stats = [pscustomobject]@{ start = $now.AddDays(-23).ToString('yyyy-MM-dd HH:mm'); c = [pscustomobject]$c }
        zones = @($z1, $z2, $z3, $z4, $z5, $z6, $z7, $z8) + @($autos)
        logs = $logs
    }
}

# =============================================================================
#  EMBEDDED IMAGES (PNG, base64 - sources and full-size versions in docs/logo)
# =============================================================================
$IconPng = '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'
$LogoPng = 'iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAD/KSURBVHhe7V0HdBzV1V6SQBK6qcYYV1nSzqzKjmSSUEMghIDLznuzKzfsBBISQgghhGCMtdN2Vy5gMN0YW9qZ2SrZxmBMMcQkIZSEaiABQu9giunNeP/zvZmRR2N129jJr++cOdLU3Z1333u3fPe+QGAAAxjAAAYwgAEMYAADGMAA/icgy/I3svKkIZmEdHhWFUVLoWdlVKpYKrncUkmLoZBWQybLLYUsx/+WQtKmSq40FVHPKtLZpixKGVX6QU5vOGytLH/L//wB7GRo08nwXIJOtDSStFR6s6XSZ0yVfLVy/uTSbQtPLd151YzSn6/6WenOK2eU1lwxnR271dnwP47hHLvmqhml2y4/tXTj/MklS6WljEpfyKjktoxG52Y1ScrpDaP9nz+ArxnXz52wVz4R+0lOlxZkVOmhjEpLt152KmtA/C0moyVTJetNhTxgKbQtp5MFrSn6x5VzojNWLWiYuObyKSf8eeHkY/9y5ZRjbr+s4fjbFkwef+Nc6dTWJD03myDzMyopmCq531TIm/lEtHTLZdPYsyEsOV0qZVW6LqvRK3IaHbdCnriv//sNYDugWZ7xnUJCOiWnSS0Zjb5584KprFFuvHhKyVLI21lNWr2sKTrrrqumHFd68g8H+O8PBALfDAT22TcQOGRYYLcRFYHdyjh7G1ERCIwaFgjsvV8gENhiuC9tmDnorqunHr28STo/p9OVlkrewMiCz77l0mmljEbeyeo0gxFokTxud//9A9hKpLVIMJ+gTVmdPr/6UjT6jFIhGcWLv68tJV20rmV6dYcbdhs15rAR1Q3lFeEUxwk3cJzwCMcJb3Bc+MtQqL5UXX14qabme57tcHasqqq+xPPCRp4X3uK48LogF76pvDI8b9jImqmB3corvR/xuPlzrm1O7E9Zjd6NEQHTB0aJrEZfyut0XlajvPf6AfQDGVU6NqfT1lxCYr3thnmTSxmNPrisKXpuae1vBrvX7X5AZd2YCmEWxwl/5vm6DWhQQTiCbeHw90vV1WPRsJt4Pvw2zwv/4fjwQxwXvpvjwnc5G/5/kOeFpzlOeAtCgHtqa7/f/hw8k+eFD3m+7q8VFWF1r4Oqvu9+/qZ/zdx/WVP0rKxG718xd1Lpz1f/jAloTqfL8yo5rv0HDaB3yKn0+HxCug0Njt6e0egn+YR03YOLN/f0wcOrT+I4Ic3zwhvoxWgkNBjPC1/yvPBwZVBYOmpM7e/2P5Q/zh7eA7t1/JRu8a1AYMhh+w4OHjOyrPY3wWD4Oo4T/snzwmeuUOBvKCS8w3FCfsiIqgnujRgZCgnp6qxGP4Qyiakil5DWZHRyQsePGMAWMGVRwByLl4YhNaPRNzDEb9o0fw92wZ58MBgUrgiFhNfdhnCG7QcqKsKpfQeHjvU2dKlU2vXZ3C/K11w2ZdzyOdJv2dCs0mZLpSssVVxjKuQubJZCbrdUsjKrknQ+SeetmBP7/a2XNYx7Knd6cNOm1d/2fMVv7HVw8HvllYLM8+F7Q6E6Z5T5QYnn694N8nXX7X4gV2t/dvN32pLRmVmdvn7HlbYgZHXppowWqfM8bwBAemZk/4xGL8ewiR6f06S3i0npT+75EaNrJ4ZCwloMy3ajjy1xnHB3WXntmYHAQQe716GxV85rODOv04yl0n+bCtmIF3/75dPbzTuYe5iroUDedMmU0k0XT2H/4xiuc81F/M+US5V8Zan0KUxFK+c0/PZfxmmh9i8e2GfQyPLa03m+7k7oFu5UEQrV/X1YWZi6Vy1LRf+Y06X1+G3FZAxWxMLFsgSFcwAZTZqUT0gv46XndGlTPiHN37RpIet1ZWU1U3leWIfejl4WCgmvVXLhZCAwYjjOl0qlb6B353Sazmj0VUwZbiMvm9PALANLJf80VTFvyHSeqZBzLJlMMVXxFEslx7XI5BirkRyJ/9MyOTkji5NMRTzbUkjSVEjOUsh9MCXbmhocIZrBhCKjkdchZLddNkkslUrftH/JYUMqOYwMwov4rvb3rfvX6DG10+3vWtytkJTm4Tfit+YT0kv47R1exv8nLJLHHQDTye19OV269Z8t05mDZdjImlNCobqH8RLteb3u0bLy8DT33rVXTP1hPiGZWY2+D4cNpguMHpZKHs9q9NqMJk3Pa7GaG+ZO2KvDh/YDRTm6p6VJVRlFmmqp9OqMSh+BXwDD+u2Xnwph+DCfoPk7Fk5pV/ZGjQlP4nnhQVdweV54bMToMNMT8BvxW/GbVy2YWsI7wAjY4UP/17H0IvFHuYT0gt3r6YZiSvo5O7HPmFE8L9xcW/s9d159dNSYMMGpUqm0y4qm2Nk5nT4BoUFPz2oUesLtWV06e9kccaj/c7YXCppUkdPJmRlVgnfwKwggvlNWl55alor93h0V0OihkPCQK8hcqO7Wb+/NleEcfjN+uzMaPNfcOPF4/+f8T8KUyUwMqRimczq9/Zll0w7CcQyfoVDdRsyjGOrLy2tPx/FS6YFdiylJzul0PXodXnRGJY/nNOn8QkpiLxNolsXvr5g3aV7LLOlQ7+e5MOWT9kZPtlT6U0shpxoKOdNUyPnYLJX+DsfySXJcQZOqTHnq3v77u0JBl0ZmNem8jCY9Cp0CwpDT6LvFpKRh2Mc1ZRXhn/N83Sv2b6v7qpIT4jiO357VpDWeKetC//P/Z7Dw7JO+nVGpAVfq8rmTShmdKji+52A+GAoJ96OXOMrdQtcbV2ySznOVJ3aPRm/Ja7GTZTnwDf/zDZmse8j4dcmIi2dh/5Jzpe/mkvT4QkK6KA+zjOkJZCFesqXQc02FXGTIJILNUkiDpdI/MktAo5fA05jXpSXs3mTsuN5697K6dFJWl25GYzJlVqfvFBLRC5zT3+C48KX4jY4g/AO/nd2nSTJ+H+ISlkqsZvnY73R88n85Fl84/uCsJv0dvSOfiG4opKSTcHxMZc0vQ6H6L5wX8vjBh1Z/D8dvaJJOySWkJ13zyXG/Hul/rhctjeS4G+dPfh6KVkYl8dZUNFdISol8QoqaCp1h6WR4XhXHZlQpaqk0YSrkTkQGTUW8wlDEJgR6LJVem03QegSWMLrkdKmhkIpe25qKZVpT0bn5RKzd+dMd7CgiXQmlFL8Bv2VFU2w8zg0eyo/F1Gb/5vovKirCv8bx1gT9Kd4N3lFWo/finfmf+1+Jlosio3M6fdKZ759Ys2DKKBzneWEp5kU4cYK8cDmObfr3+XvlE1J+1YIpTtCF3pNVxR/7n9kZICBZjT7Y2hT70tTECc1ydDCO5TRpYVajH1gq2WCp9F1TFZ81FfHvpiy2GTIpmiopWgpZhWOWQh63VPJuRiMbMip5OKdLrQgjZ5PjD4bQFlOx6/IJqSWvkZP9n98Z4NDKatK9+C34TTmd5kprztgH5zheWIjfbusGwvU4dtvl0ki8I6YX6NJT182MlPuf+V+FJRdO4PK69KqjsP2t9Lz8nUBg2CDYyU6v/6CsolbCta1JSvKJ6JvOj383o0q/8T+vM2TkyOEZTUJDXllISIcbcfHFQjK6OKPSl3IJ6b2sTm/N6dKZ6Nm9mdtxTVqm9RmNnJPT6ap8Qnozn5BezyeleYsuGDcMJmROl0wL0UJZ7N2IoJMzc7r0nqPwrV/WJIk4XlYWpqFQ3Yd4Fzxfd28gMHQ/vKOsRv+Cd5ZLSK8vnT2xyv+8/wosnh0J5nT6OvPoqeQmHDtgSGV5KCS86DT+v/Y+kGdmHxwjcMggsgb/+fUXEWbnd4dFZ5yxa1oR52ZUUjRU+j3jovEj0TCYf3MJ6fO8Jk1adEGU9batAZTHvC5NLSSjfy8kox/lE9K/l8gTOHgtLZWuNBTxkmIx6vgCugZ+U1aXluE34rfC8YXjex0QHIPpz3knL+w/pKoCxzOadAOmDwjgf50QLJlJRrGef+UMaLYrcWzoSH5sKFT3ji3twu1w2b6YmTIoq9O7mR2fkL4wVbFXvR7avCGLt5qymLr+ognH5BNScllT7IusJt2QSRCalsWPzFniId572jQyBmSOrC7NNlVyHdhAhkLusBTyd1MR/2KppNVS6Tw0diZJOkT+XECHKKaibW1NDZ+3pWILFp590t6GTH5rKOQfWZl2jEh2gYwq/iaflD5nc70u/fXxAvMIfovj6m519IINw4fbgSZTJcuYEOjSG0tnkzH+Z+2UgIMno9GnMISBmYNjw8uqvh8K1X8MTZ/jhByOrZxHq+ENc4b8f7c09s5Hbqhi1FTI39ArDJkeAe25NRV9LKfTH7rXmErkFmjTGKKZBaDRxyyVrM/qEjO34ICBMwfzvCmT64w4kU2ZXJlR6V8yKnklq9GPczp9MadLSxCR7PgNAgFLJ8e0NTU8lk9GXzNkckZajvzBlMlqQxZ75dlzYh6OXiS9sqwpVoPjHCcYtgex/uNRo6qPYtcq5AZHMXwWeo3/WTsVinJ0N1Mh98AEsjR6D44dNipUX1VV96Hd+OHFOJaVxR8VEtJHd1wxvQQSx+JzT+yVX9yUxd+g515//oS9YF4h9Nqaijb6LtsFphxsclMW38rq9M2cJn2Q1ahlNopjixdE92GePZWMz+vSn4qp2JVtTbE5bclYuyfPkKWynBY9I69Ld+QT0ifFZPSRgk5n+M3PnE4VePSKyehMmJ2GTFYZiniu95qugN+c0+gq+AAKyejHph45EceDvHCt40b+dPjo0A9wzFLIXXinYDft1CaiIYuGM7Q9XXrgjN0PPIwfHQrVvScIrOcvwTV48cVU9Cu4cC2VMIHoDdKy+HtDEddcP3tCuJCMptuaGj4xVdrBe4ZnL2tqWJfTpZdbU9H1IHjieHbupCHFVOw3OV1aYckRZnZ5sEtRjx5VTEoL87p0ExxC3pPpVGT/XIJaqy+dhpHq2YxK2oM87Hxj5Ni2VOyjYiJWKAUCu5gKSVsKOc97TXfAdAT7v5iKwa0cwTGOE65xhOD9wcP5YKkk7wbnF0bVdFws+J+xU6A5Hjn/1oXToLR8uHxeZHQgMGofnq97HvOaO+xbWmRcMRXbhF5jKuJc/zO6gimLvzAUsmzRGXW75hPSC4Wk9Mo1F0wc4Z5vOvOoQfmEVMTwjs9fcqF0oBEnp2ME8D4HEThTIdeYirii0Ek0LidHyrMqXWQq5CZjtsiGZSiXRpysZJaBSuJtTbEvWpOxlVecdXy7/x7WQWsq+lJWo2vSsyNB5mNQIr/s8PBuYCgkCeWwrSlWsuQIc30Hg2HL9YoGApX7r144dWg+Ib2H+ENLY2S2/xk7FM2N5Ei4d2+YB2+dbSMjXm43fvjP2MccjZ6PxscP9j+jKxiy+CNDFu/A/4WEdHMhGX36Ck/wZPGsyOHL5056EaaaIYuXtTSKs9h986ftYcriF/DyeZ/HzsXFnxuyeHdOh6BuibRMToB/YMW8Bh1TDn7f5nOR8mVNsfva5sQQaWw/fvXMUwZlNfpcVqOv2NOBeKulRn7a/tAeYCiiilGmNRUrub4PnhducTrQA9hH1HL5nAbmFUU8xf+MHQLMqaBNYy5rkSMajgW58GJH2/9PIBD4duscyueT0odwiMB08z+jK8CvbzjznqXSRflE9L1FfxjXTvY0VVFcPnfSl22p2CfXnz9hiKGQSy15IiNksPMyudKQxcfbH+gBgi+GIt6f0TrXrk2ZLFg5b9LbpiwyJ40fhUT04hXzJpVMhU52j0EwMTplVboYBFZDJvf0xqR1kY5HknhHhWTsk9YmGgaJFeYy3mUwGM7gmhZZnHX7FdNhRr6ekTe/ix2GdOPELLRZQxH/iv3yYO3pNl2q7pMhQyrL31599t7oFVD40nGx2X9/dzBkMQs721LIpSBeXj97ArORgRY5Mg2afFtT7NPrL7QjafDuFaObbXLLtr1LUP7cY15g/jYUcu/18oQh7jFLpRMtldyJoNUZZ9TtCj3CkEm2VArs0vFuOHikX8FVnY5HZrjHFs8cX4ah3FDI6YYshjCCdLyrexhy5FoWKNPoG/enT91/0CHcMOgC0Alct7Epk9vxztPxSJ+evc3R0iiKMKlyCenDOxZPOvjAoVwZ/NtwcZZV2IwYmGzMKlAIbP9eg0XrVDIHpg8igGlnbgTScmQcQsGWQm5rnh2Zj2NZjYY7662mQm43ZfFG/3EXhiyeZChiprVpUhjZQcyxJIse1g8TLMVURNYD/bA0MgW91pTFdl6gIU+MQKnDs6EUGnFyZse7uoepiDc77+wf2C8rqx6Pd1pVVb9x8DCOu2extB88i5gyls6eOMV//9cCeMgyKn2NRbA08jMc4/nwQ/ZwVXsl9jEnuzZsZuaUQf5ndAVDFg+CIoX/LZU8YarEcs+ZsydU4OVaMvmTIYstS/WJh9nXRX5qyOLF3ucAaTlyFITFTHR0DLnAZ2U1+kAxFXsPoWL/eRdQWtNyhP2uDsfj5Bx4CU2FbGqZvZkKbihkiaWSz0EoQY/NekaZnmC/W/IktH4jLl6DY8Fg7QJHp1qH/YwmTnJo6Os7U2i3O5Y2Ri5nQ39cXIv9imDNbGfefxL70Pjh8iwmo180e+bl3gDDfkYlP8Ewn1HJF8Z5P2akUFk+9lsZjb4EZg7ruZ4Gb5FFyTX7/DAV8T+mQthI4QJx/LwuzcvZimWsJR65Ck4m7zV+YBQAZax9n40MhFk46OlZjb4my1HGAShcIn3XUukHhixOt+TIOEQdvc/qCRCmQiL6GWMNaSKLl/C88ATecWVlLfudUDTXXv2zUkujeJ3//u0KJD20pqJfFZKxjbddPm3kwQdXjAiF6r8EaXP06Kq69TectldWo+8gRavZic/3Fml53DDY+xk5epSlkk9bZPEX7jlTIQszGmWmnaGIpqVt9pEjmdOQCVNC/UAjGIr4If7PaZFgQY9emk9INyFIBJ4CjiMIBMugK6UQKJwrfReu7ZxOj0CDmjJZiiRUnEM8AIqZodg9FjBk8jNTETdCcA1ZzGdkwiKhvUVzfOLpGOazOt3w/IoZ+44YwddUV4/dVFVVvwk+lrULpw4tJKJf2OZj3zrZViEdF1dD8tBTsc9x4TWOZLIAB5wVOJ+WI6v89/YExOYNlVBo8KZCXnePm/IEbllTQ6l5lvh9hGdNmRS99yFK15WFgUbKqOT9tqbYqoxKM/mENB2N4r/OUMUfp7vRFwBDEX8OYqipiL/yn0s3Rn4Ac7jFExcwFfJSRiPnG4p4gaHSyzre0TPScXEFEk0MWbwB+xUVtZewaZYL34V9xEMwErfEI2v8924XmCo9GppvRqPvIXQ5YnT1Txzi5puBQGDX1hQ90VEM329JdE7P6gpI+EQDYMg3ZPEtb+83FHGtqZBb2P8yOcOUbXvfBRi+/mG2kJQOLCZjv8popGXZnIZ7ECL2nu8M6MF4vv+4M0Jchl4PZlFnAgBA4QS3wN1Py2QKCKtpJTLDUMjK5j4mkkLYszp9BylxyIu0TUPhNbzzkWNqTimVFu1qqfRtuL7hM/Hfv82RjotrWaxap3/EPseFn4SJMsahPxuK+Cy8Vc2NW7hcewSjbMtkZkYmJxiy+Ik7PEOHgMkHJwz20dBw1njvTcvRYWk5ci389a1JenwxGVvYmootLySjCoZ12OhQ1CyZHOO9zw8oVIgOLrnwpAPdY1ByLZWsheLpHoNAGhdJI9tvdIBh3lRIu+m5aNEZuxqK+H5GjhyVVsh5YCf57+kJmApgaVgqeRH7Y8bUTnbYxk9jP5ugv4Oy3RIX/+a/d5sC0Tf0fvDtS6XiN0eNqZ7kfJEncD6jkj8gfGnI4kP+e3sD9C6YYOjpXpMOBRxMWWQeRXadImagvbv7GM7zOjkhl5DWFRLRXGsqem0uSQmcMe41AAsBe57TFaAztDRGtJxMj8iqdEVGpdfn5M2uZwAOIFMRF3mPuYDzCa5rdx/uZ0MR7zA1qcJU+uYLcZGWxftYhFUTGceQ58KP4d2PHl19KhjTSGO/8eLJsI66FfCtQjoeWYn5JqvZ7FV4+pB8OWpU7cmbnj7726BdMcdIY2SLEGpPAHkDGjXm2KxON2I+xXE29MbFT1vkyOHutWlcJ0tl2aQkFVKxeYVktOjk491rydEulSH4CuBQMvQte64X8PsjWgkCR06lR/vPu0D0zx2VXLTI4gREKaF0FufYhBQQVuCWhnmHgBkCTN57egPwDFlyrEo/KD0g7+5OvRwXfhbnCzr9o+Mc6rPe1SuAkFBMRr/KaPTjV288Y/fDRlaPt3t/2On9ouIoI7f67+0NoIBBizcaxR+bCnlvraOkgbXb2hQrmTKZAzPP0ujSrEafAfunkJCaCglJXOaMBi1x8RLoKP5ne2Eq4qNd9dyiFq3L6XQxRpjWOTEV/nn/NV441gVThIGsRmPw1YMmbirii25kERaCoYivIzPJUMhVpkxZ6LevaG6MrIRynVVpAvucMwoMH10TgT6WUelHxWR0k6lt9phuM0DDxoebqm1zclz4H/jwEaNrYrYiQjYgSIHe47+3N4CWDN8+swIUsV2jhRuWRdkaIxMtjRJLJ6ebqmh0vNsGbHRTFn/vP+4F/AWGLG68Uo7u6R7L6NGj8klpSUGX2sAaco+jhzfLnbODAMcsXH7pOcfum9UlDT0UJFKcMxRSMGTCNHfAVg7JaugARj/5/9CFEPHMqPR9jLijRlUTm2dR+0+cNxXxGmaddeIQ2yogGGPI5DX8wL9ed2r5foP5oJ0vH34N5wsJ6be2EtJ/U8SURTh3QoYi3p2WRZYzwI4r4oterRzmYFc9GNG5rs55YSjkeVMlfwBrt5CIWvmElM0nbNq2F1BKDbl70y0tR+Ir5096OZ+Ivu1VTBELMGXxFfAN2HVK5CK4xSFQhtx/x01LY+QWjLTFhMQEnefDr6Mt9hsMF/G0Mjb9yOIbiEj67+034MmC27GlUXwY+xXB8OK6uiNLYypqWEOl4+LzMP0wjPvv7S0cxQ4K4KuGSlhjQNEzFPJxpjHaThcDnSrdic8fuFEet7upkGXwwvnPucC8nFHpSkQRYc7lkl1PGUyDl8XVXbmRwUpaPqcBw+5Tl/hYTfAFmAr52A00OXGBN5Gf4IxgWwSXegOYeqsumYLA2vPYLy+vlQXhSEQLGbmmJR558FbwLTyxia0GonIITixLMar2N3g+vAHeqMAeIw++bUHsSNio6bj4b/99vcXqhSd921DIKgyj8P7BW4fjRiOUJ/KB19eNWADcrh0e4AGEozNNuNgUrSsmY3PyOl1eSEQbTUX8pKdkEwCpY4ZC3eweBowcbU2xf7U2xdbDqZRujCyFz997DZRaQyHvIxaB/YxMKk2FfABhMhRxyVYwlndJx8UnQCC55dKGHwb2LDvQqZHwHtqmLSmdibaC59F/Y78A5wyUMqQ1v7jqzEGHDg+d7PD7WPjXlMWiE7nqNQ3KD1MWh8IBA3sdDe6SHy2ZEkw93lCsHSjqPDIHwP2ajouMJ4hrC0np9AIye5JRq5iITQef0DlnmAq533+/H0U5OhgOHPy/WB5fVkzFbmhratjYmoxeteiCE1gjIlwNT6T/XkMhL7tEUWj+EAhLob+EAPSFJ+AHlEnnnbdiPxgM/w1tcuiw0CnvrT1n33xC+spUxA1oO/+9fQby5iFtsEOxz3HhAlyRw8uqTyuV1n7LUslHOV36Eo3ov7e3sO1j+PkjdYYsvut+cdvjR57xXgvrANLdVZIHzDKkoRWTsfmtqVhrMRnTHHJFB2AuhkloyhLnP+dHWo4sWDan4eZ8Qvq0NRVd43X1Akzo5AhL+PSiJS7+C7Rx/I852VTI27AcWBwh2fPndgV4WHM6/QIWGfiCw0fV/NyJFDK+YDoeuZfR7joRyj4DXxaaZVFnXrBdeC68ARmu4PzddPGkCSickHYoW/0FgkumHFmALB9DIevdORxavaFsObXAYYTe6O6jl7YmGqLw/rHUrYT0dFalvwNLueOdHQHGTnejCfLz8glpwbKmhg9bU7G3MPT7rwFg+fi5CDi2Yu6kz8FrwD68mnBv47ghi/P6GiH1A5FAEEdQ8zAQGL4v2sSZBnaBT8CO1ZCr/Pf1GZhv4Nx5JH1q+d77l491nA+MqGCpJMuYqlsybfsElIFLK5GFGRUMHfEdN/yLl2fIhIWXvUBoN6dL8ZwmnVNMxpYUU7ECS95MxU6GaZaOkwbTmQa6g6OYlfzx9OtkcWg+KcGV/FExEX2skIpObmns3PQEmPtYFvNgBWPfamTchDuWNcVedVnIjCKmkPVwcDGWkyZtVbYPYhGwvFD9BPtBPnw/2mbv/bjDHzdOL7OZSqzz9EvZZID7E3M/JBf7YyrCGoaa8spaGfs4jkCH4emN/QGoW+jViANAB3Dr5xiNhCIdC5FBS6OXWApdhISPfCJ6Vy4h/SOvS7/C8O7n6yPgYijizd1ZAy7seZowli0EsZCUmltTsU+Kqeij+USsnQKOKQpOqQ43O3Dp4OACmErkfFMR1+T0iYe1NEaewPSAazIzTxkEXQrJsvZ013XYuTeANxNzvREX38E+LDJYA2Mqwsx5lZbFt1jbdRKv6DUQY0dgx6VUoZ4ek7L9y8eua55RibBoOh55zH9fX4GXA8UIAgcXqvty0mrkWEslH6RV8hOUWUNqFrRoBFyMuMjyDLoCSJ2w4/3H/YBjJqtJb2Y12lZISp8XU1FwArbI/oVZhYbzH3eRliNLcwnpL5gy3akH+gw8m/i/WZ44wlTJp3ldOhumKn6z/xl9RTourkMboC3Q8+3RWWAJOeAtOG3X7tjqM0CDwlxSSEjnYyjhuPDHqJWHkGRbSvotHBJw4Pjv6ysQr4dWjpEAwyTozzgOgYAt3ZmCaahiHiah/7gLQxNrTEVs8x93sVA+ae9CIvrrnCY9ClobUtEzstQeb/DDjhKSZZ3xCKCrgABjavQ09xh6OiKaiFlgH+agobDU8wjyErZqaHZgyISxsoop5hT6Js8Ln/J8+BOYg8WkdB7z3PqYUH0CuGzQJv96zZQjA3uNLAcxERU1cQ4FmNdcPr0DLXprgBHAsfEfMWTxdzgGHzqSOzKdULVgdsJG9x/3glG4fLGBjBatK+jRxYVk9L1CIvpGRqWzchpFFLLHKKElkxYIlrsP2lpGYTmBCUYo9biNWfURRXwHziS2D31GIU84VPdeZ0R1h7RCGqCEQzCxz3HCP9BGu+05Jnj3tZN/AOvNzanoM2BupeMELs7SpqflvQ8dWTMN839FMMxcreDZMfaLhwi5NWCBHpX+1AnZZt3jNhFkS/euMzq0+9o7Q3o2DYMjALMpq9FzC4noo4Vk9NNCIvpXVP+Qo/ZQDaWPmYRd0MddGDL5UzNKyWlSRVajBjqBO2owBpO6+X5WeUQW726/VxFNbKZMfwgWj3t8awCHGRJJ0rL4HPYrK2uvQRsdNqJ6OoptsMinLL7iBtb6hKUXTTzMUmm7AlheGZ7v2P+/Rh0/SyUb03Hxnd7Wz+kJoH0zxo3KkjkY0QEwZfIHQxFf6Hi1DdYju2DBLElKB2Z1OiOnSx/nE9LbqMSVT0hN/vCtCwSguqOPAyCNFlKxJ0BHMx2iZvs5WWzx+hTgvzDlyMz284r4LH6jJYu/641u0hvYySfiW2gnVCYdMbrmDNZJK2oX4HxaFjHCbQLP0n9vj0irkR+AYGAq7Q6gVVAy9jwgePSTGVsBRFKF/77+gs3/cXEJKFCI1rlzJ/OdKwSS3IGrD4Aj4I0LQHlEybicTmElfIhUb9QKgpu5451bAoydrujjeG5OpxcXUrHbMxpldHU/MN24HkxYRZZCSm7qWXuCihw5jZFeeuAj9AVGnNwLOtgT2en8XoMqf4A2CgbDLCSPTG3WTjI9wn9fjzDiYpRpkY6dyXPhx8H6DQSGHrp6QWw8nBDdOVH6A0MlWZhPYNSgipd73FTEf1oqWeq9FiMPCjlkFPIAnD8ZlT6J3p7T6HM5Xbomq0s/ijpZQu7Q672/MzD6uCeUimKThUT08oIu3ZjV6Gm2jyGS9o96tt9/c9ZuXpeWGzJh+XwApg5LIU9iivFety0A8xNZVzfNRxj7oIOdSmv/wjkQYJmOINOY/74eYcYjzN+cS1DGtOX58HqOC290LIA/MAugCx5+f2HI4h8NWZoO29mIi4zpAoALYNfRo/8wFfKwqYhPWxpZD3ZMVqP/QTXxjCr9trNRAmAWgSze6jpqugIUt5a4+HZej52Q16VFhYTUioohXj+DKYuG34aHCzsdj8zH6JVRyA146V6fAaYDKLasuIVM2qeFbQGQaNAWWA3FKUX3BccJ7+Ic1lhggaFe1izoAEOmCTy4LSmdgxImqKHPcQKYvwEsqWJHnGw/97YCnBZQAGH/I66NaQjH0XCI4aMANOr52UWX6IlQBJkJqZCrutIFXMCfjyCK/7gLEEQshZyODOdcgv4Nz/dfAyA7CNOF9xhIJoWkdD/i/JZK7oVS5uYLoEqJpZJSpmnKIPw2v/BsLSyZ/touTmn7KMAPwNoIKMHjmuqWQpv89/UI2Pd48Mp50WmBwF77I+TI8WE760clJqS8s9TrrQXSwJBxk0tg7razjgCWK6CQT7zJny7gJwDZorsK3IyPp5C/It/fe7zQJFUVm2JaMRVdkdHIRYjyGXGRMWw6A6hplkzHufsYdTANtTU1XIvvYSlkg9c0hnkJ1hCsJUxF7Q/aRsB7cYptsAwlDP+YBgKBwQfeOFdqAEm3MyuqR+DLIg351osbxgUCw0dgSZX2PHWF3sjy/GWRFXzcljDViUcjzXuxfOJ+yAH0kkEtld5rqpvpYl6waaMHnQS5A8hQvvHiyQcUdOnUQlIyoCS2JqO/dOMBKNwMZRCjkP9+AMJ5/UWRE5GajaJSOY3+zVQIY0FnVLLMUgnzkwBpjYYLiSiG4J+bMgS7Zz2krwAJB3wMN2eC48L3gSEUCJSNvv3S2E+YHuekr/UJSLUGFx0LMGG9HDgYeD7MeOeWIt4BBtD2+EEAaOCs0oYsXm0qm/P7wf2HUHQVfIKDpSteAkYAlHItJKVn2lKxdYVkdBbqCvqvA7qjj7fI4h/bmmKr4YMwZXpaS1z8FdzJ0FOQouVN/7IU8giihMzF3cc08d7C0OkRzqJZjJ8RDIb/jLYK7FFRddflDUeDHeTyGfoE/EDcvPbKyUcF9qgMsYqeTrUP1AJA4mdvGDX9gRMWbsVwz7JqPA1uypFp4CYuaZzAysr6wSp6OCOTOUccWkzGJhWS0hWFVKy1kJQuWTZH+rGhiDd1V3vPpY97GzMjTz4Anse2VOzJ1mT0UhTGwHEohc2N4iksHTwu2lXP7eO/yOq0hN8A/kK/TLFeAEWyEfkzFdvphDQ9VFsP7BMMu95ApJv77+sRnQoAH2Y2MJZZgQC4dKftAUwDMJ/ScXEubOglM0/Z3BgqWVBIRr/0xgLgFMk1NYzI6vSXKA1bSEbbsM5QMRVLoswrSsa418IZZCjkfvgY3GN+mLJ4HzKGMa/ndUnLJ6VVGSw4oZL0Eqd+UItdasawNLoeDiz3XrB9ILgtcuREuyB1/0mgPQErozrJOswnw3Hh27eNADhTwJ2XT/pRYLcxQSYAQXcKIHcyYmI/EkB6CzukS/7GqNfwDyToc/Kxm12aqP5dSMU+R71fSyNXQQlCrgB4hYVkdJqlkIdQSKLjUzcDc2d3iiP8EE6F8nwhGT0LUwiOQzdCESqkjmV1+mRWlzbh+7n3wWRERa+sRp+y1MhEhIa354IQGIXRGZHOhn3vFIDOi07cU8JrpwBzFc4eOH2wRItXCTQVkSmBoIv579uWMOXIia57Np+QnkEFbu95S6VLGQNW25xE6gIFGVBkwlC7NlXB10O1ULdxM02nDComoj8rpKRMTqdXFZLR9ahN6F4PLyGGfPwPbyOibRmVdOjdGZ2uxPqGTk7gEwhle89va6BUnq0Eisz7x3Hhe20lcNSY2xY0nAglsF/OJwQ3NpuB+wxymKfMR59RRcN2dvSuMubWwFTERiQ6gCWE4FNWox08gij9unxOw0bU9vceB4zzpiHLOAv3q5um5YcRF6dmNIIKIcliMtaCv9ABcC4tR2aClOqGbk2ZTkOJtqzrYfN4K4GsjkJW0ifwFKZlMdXfBJC+AMk0TuIoa2SeDz9um4EHDl45PxpjuZr9iT7Cy8c8TEkKLxJizXAEscAQ/OKsfMk2dgR1BeZgUWgTHC5OcKcDPQvkx2VNDe+0NTU8jBw67zkA3xOewKzK0qsZ8snYka3JqAJKWWtTzMhq9AWYa977MA0hDpGWJ7CEDywiVUhEPygkom8vlSd2GP3yutS8fG5DqVk+eTCrH+yMFNsbUJC9jiCOE17heaGE6myg8bN8wS7qJnQLuC7h7ctqNqGA48LrIQTMFdwkncNcweq2CWv2AvAEonb/LzH3tjXF3iokY3fOPe2IdtozEjNaU9F0Wyq2sZiM3pD1paihiijW+AXjJ6fTdYgftCVi410GMuZ12MsYYZYlYoJ7H/h7eV26jy0bN38yyrou9tYplH9z7J7FpuhthWT0zebZ4iTULYD+5HoCtzcMhcisoyZY7sIuPB/+jOPCG3CukKCsE8PF7r+vR3g8TGxoQSKiGwy6BatvXzEdc0u3jpdtCducIkWkWM0/78d7tKaif2lrir3s7/EgfBST0ZtRkTujkoewJk9Wo3fldHopW6JOjx2TVSWN1Q9IRs9qTdKjUUjCvR+chGJSasnp0o2Y301ZfAi/Na9Ja5GV5P0sxP/xHVpT0QfxndJxcp6hiMv6FX/vJwyZtGwOBg1mSSIcLzyFc7BY8N37FX5GSjMkHqXQsY+FlJEKvucBwWOeK5xWYYeKe06s2NYwVTiHIguXXBQ5qpCUbgUxsjUVm3eu9P0OBFBQzbEOQT4RfTmn068yGvmnpZFL4byB+QqOX06nKSxRm1Xp05ZKn3ECTaj49RTK0WDBBrh+c7p0H7gK7rPlGcd+p5iU5uD94LPPZpRvci3q/nq/w9cBQxb/uuqSqSUsoP3ddl5gmHlL4RyCtdZZplSPAHUJq2amFXE99isqa+eCbIC1dLEaFs4Zsvg2zDT/vdsbrGq4Ql5OyxPqEYlra2r4T2tT7LVCKjpDDmy5oBSUuqwq/QnrCbCAkkLeMBWyHmwZQxZfYDl7Kjb6GMihqH7iKoIAXMiGTD7D/J7V6LS2VOzVQiL6bxTEWNo48WjY2V15ILcnWEodSB8a3bTpkfP2cBNEKipqWakc/L7e1EPoFI4H6wU4NErPXrDP0OFVU5ySpUyjNGTxGVYRs4sQ7PYGQrwoFAlNfM4ZJ+xTSEpnImRcSEafzyWk8xGa9d/jAiYafP8Q8qw8aQjMv+6GbUwRCD+3pmJvYvEGVB7HYhGWQi9AwCrjRC2/bqC4dRG0/LjISsegSBfaaNjI6tNLr8q7QzAgIG6pnT4DmjPs/buunnp0YLdRY2BfYul1nINu0O/5ZRsBihYEAEvSwAO4+KLxJ4EGhmxd1CbO69KqjI4FGjsvCt0d0GsymvQLrPKZ1aX3CknpORRjYpFHVRQzGlmdUWhjZ9HJrwsubR/BOeyDEg4n0K77VlTdf/2p9TfDPyATVk2sX0CxBpsWbmuYHCd8xPPC5+AHFJPS2duKFr61QJAIi0QUElKm2BSb3jLrlEORgoXhHCXWkVuQ0eiLlkrXWAq9hPEM4+JUpKEzvj+KRijiuVhGDiVtsyp9IavTL3O69Cz0iKWyKGCky+nSZ/lE9LaMQnXw/P3f4+sGklJZ2l5SwvTjtg9o+99qTdHfORZAt/UNuoXrZHB9yXAFQ8nY66DKHzyR+dkYpiR2UY17R6BoRwsvbGOpYrGmnEbOyWJBKXD0VDoRbuKMSh+0VPqIiSIRCvkIiSiWQj4C2wgsX0sjSQgFKn2A5JlL0RORdsbMwzmxm1pTsXVuhvGORjoeeRAK4H1LptXssW9FlU3bt6uFIHN4q0do9Cxo0IZM3sZ+eXltHOlH5eVOqVLQpxLSpr5WwNzewLCMVUOxnExrMroUQaGCTmfBtMVaBVkdyiB5BrUIUCcAi1DbawzRH2JFkJxOZ6FWUDERM1tTUb012XA8WElLZ0/8xX1LfrlNybD9hds2SDdDlbCy8vAFTtrePHY+Lr4K/aArFnSvgR4Ok+9R87SKfQ6oFJz0I3cBA5Yc6mbA7qzASqBY7BGMYUulbOGodFx8GMEgQxH/ZsjkH44CiQUvzskmpFMQWfQ/B0vN33jJlMfgfPGf+7phyeRnd1zJuIeMZxDk7dF530OCRz/RdtpwRqmLi89stUMK6UeYZ3K6TWbkuPC7oVD9JiwA6bKD0/FIn0rB70iYSmRyW1Ps0axG32K1gmQRq3y8BZIIfP3+63dWGHHxZjiAVsyVGgKBQ3bneQFk0I/gqXXnf6yI5r+vzwDtixWIiIvM6RMMhrPMHzC66hcoTmCpWGJN+qKz/L2dFem4eHZGo68ibQwEz4xKX26J94M5u4OQvXD8wRmNfpZR6WcoDzd8VNVk20SvZdFSIy7+heluqshWKN0qoPYNkhox17906+n7DT606qdOiRhWD9ctEdMv6vEOAsge3mE8HUcFr66JoDsbDDnCqrJ5srbXsBIxw6tJae1v9szq0pdQbOHf8N/bL8Dnj0YupCRE/2BuvAufMysSdWnsGJQ0RzmUzpZV2RmAbOPWpuhZiNLBY4d8R7ixEWBiQSaV3Iv5H7n9uAbXIrHE/5ydBS1xcR38M6svbjge6w2HQnUbeZ4N/7sub4qeBuHYphxEMGu8ZeIqK2uvtcvEOcUIUCbukqlfT7XqPmCJTEZh6XesKJbR6N1gGGFzijbeieRNbPgfx9zzuBZxgNZUQ64/TqTtCfj17XQvVoMwUFZeOxOWWWVlLQs/oz4Qhn9YPP57+w1WKDIuvo5Vsu66ZvKY/Q8JVToMoTdwvpBEeBiLGkYYNXlHQ45yu+UStBGZwI6vIotIHduQVi4TLPW6xYZz7nWgcTvh38/yCUlGAMj/OTsCLfHIKih4qAOEfY4LvwT7/8AhXO2918wYAWsGNRaM+XaZnW0GM07mwxqwZHIt9oPB8P2Yd0aWVUnOypbvo04uUrL9935dQPEGKD6o4VdMRj/NqGRmy+xIDEmZhiKe1ZeNUb5nR2KWIl6AZdzamhqeRK/qLmawvYHqZGBFoSYwW6thRNUEp1TsozifUchCu1QsYQt3bFPAoVBIRjdlNfrRpnvO/e6I0VUTOxSL1kSdrV8Tj/SdgLiNgKgdiJwQREMWP0CZ2bxO/9Oaok+4Wz5BnzYU8VX/lvNdhy2jkhfxjHRcfB89CyNgS6NdvWRHoCUu3mBX/bAZPhwXfshbr9lZFaXUom2bmg1boCUu3oThJ6fZlTk4LvwMOALDR1efhLWC4VEDZ39bceA5jtuvqqr+hGCwdoutqgpb+PhQaGx9XV0d4/vBI1ZAzcHZEypQ8An++19LP5o0bcJx504df+zv8fdX0eNi9np+HbczpeMb3OuwTRl37Llzzj75CJzDs/BMPNv5aruEQnU/DoXqZZ6vu47nw4tCofoLeb5+m/zuzgB+Bpw7rAPedt4ew0ZVHe/E/tkqKHB7O2sL3+a/d5sBdrNDBHmTuR/LaqY6owCLB2RV8ie7bJxdU2BrgZfsrJfXxTYWS61jkcrXQ6G6y/bfv2ILH/3IspqWID+2VF4ZLgW5+tLo8tpOv9uoMTWL3euwVQSF0h4HVWyRPFJeXnNkKFT/INhRiI5CF8KG/53vc1t5eXXf4+89AMod3m1WtSuacZzwCN59WVkN4zFifaWvZdkYLEvikBBZpi3HhZ+yv0gtCzpgWRO2RKwcaS+Y1F9wnPAjh43c7QYhQDIEzwvramtr2+ldABZhRgPZ19Xh78bq6i0biOfDze51m6+t7VAyBiOPvTra5uv8m51CV/cKx9X1vSpHF8DKpGx9RpW8jP2yitoo63icwApGZ3V6Fti/EBL/vdscsKmRiJBR6dulx+XdRo0KnWwvFStgha9vYmEj8NSx0BEqbfrv7wt6KwDel89x4Q5ZMBwnmN4Gs62XcAf2L8DzwtLuBIDjvr8fzwtvoZf7P9e/Od+jPbN5a8AWtmSLRk0D8XOiTfwUXsU7H11eEymVZJTrfQvUr62p1t4nYF0AFmtWRJZ3HuTCax0qEls9gy0tg2XjtnJt274KADYMzcFguJ0D17kACFtU0u5ZAIS43bu3/MzONud7dFpati9IxyOtTLOP2wmeLjXPzdKy6fts7t8mAtcroM4ttE0sWojFC7GIIcrHY1FDLG64LjNlUE6nGyC16dn9nwq6EgC8XGyd9UZ7IQuBmarOMzoIAKYLLHQxfHhHu74HAfgGFsbyfx6e5eoBzvTi+x7hFu9n9BVLZ0dOwzvM6dIHjxdO32/oyKoqd+HIIUOqKu64ZvqhYD/DQmlpjLSvqfC1oDk+cZGzPAlLScJyppDMzSuIiVEs+gxnzBJ5Qr8qY/sFAC8ZES+OE9Y42z083/HF241k1zJ0ntFBAOxr8MzaDhp7dwIAnYHnwxu9jex8r1c5LpzkuPBlPC984j/v1Orpl3sc6fGFhPQJ3qFbJxHrBuMdV1bWsjWD4HhDGzQ3Rvqe+bO1QFIlFi6GixgLGeMYx9tfMBi0pwJQpaG5ZlT6r/6waPwC4PzPFk/2XJPYsocLr7o9vDMBYNxGTugQ0+9OAHheOM4viKFQ3WehULi9bHwoFP4VRiXvNRwnvFdZObbPiaEIwOGd2dlXdmZxZWUNK9PndjAsULVDF48GWuKRyc4Q9R6GfSxtjiXOMVeWlVWzzFxTIQ/Y3LSeS7X50YUAdKCgVVUJVd6e57z4d+FDcJ6xhQCgoVD32Puc7gSgslIQvY1rV+KyybEuKiuFQ8CXdL+L/T3CsBi2sDh6Ago6sAUhVMIilOXltT+1zcz6jYcdVsM/3Dxj35wuvQsBaI6LU/33f61Iy5HlbG1bxXZAlAdrz4RzKBSq3zBoCH/YA4smHwAqNSOO9JFA2hsB4Plw0D7vffGbe15nAmA3UvhTNNrm53QtADwfbvAKgPN/B7ZtVVXVIJ4X3vEKAM8LXwWDtX0qCgU3Lt5VTpfW//3qaQftN3TMoXiXMPsqK2tYLibY2uhU8Az67//agVo5WY2+zrKF43Y2rEsacYarby5LiAJ888w/EO99abneCEAwWMP3VQDsRjy8FAwK7fXzehCAST0JQGVl5f4cJ3xpK4Wuk2hsqbw81OWyc360xCMyenUxGf0in2JlZ2HyPcqmVa6W1flB0Qy8a6xUjnfvf8YOAbxP8MFDG83pdt0gnhcecIRgNfaR648FIDFlGPHeceq2twDwvNBecr47AeC4umhPAlBWVrY3xwk3hkLCWp4X1vC8cDvPCzdXVITZqmE9AZ0HCh+L5jmrpuF5eIccJ7BgD3wwbkzCzVjeadA8e2IjkhTyuvTu6oXi0MCe5QfARev8ABarBv8e0SwIQW+KTG5PAbC19PCzxzpVR7oTgGCw7uSOOgC7lyVgbgugQ6Dx0YncmgscJyyxO1DdG4E9Rh10+xWThmDeZwtzxyf2uBrKDoHhriCmksdLpTN2hVIYCtW971DI2Po1CKmiwjUqe2RVuri75dS3pwBsvraGrd3TvQBUh925veN3CRPvd+krsPBVVqNXoUOgY7iNHwwKl+OdhUL1Hw0dWlXFIn0afYI5fOSu10DY4UChJtTJc4SAeaaGja49oqqq/jNHCJgSmNXFkwrJ2EYUVOhu1a7tLQCOOciSOrsTAI7j9kR9BMfEbD8fCtV9EAoJ/SZeIsSOhkeHQP0CHHMbv6qq/vORI6vYWgeWSu7EO0VBSn+d4p0O5izxkKxGn0PACBUycWxEWejYUKjuEztyWMe8Y8jLX9o4cYvlWr3Y3gLgmIPMesGQ25UAADwfzjheRs819ewZoVBdc2/nej9QYi6ftDkGHCdc7zb+qFFVzI1sKnSFHXyTXrh21paVzHdKQLLzCelNRKgs1V7ccNho/ghMBx7FsEcP2fYTAK+pFn4fVcU5TrimOwEIhcL1+Hz/VIANghEK1b3J88IWxap6C54XVobDR7Bhf8SYKhbLQOUzvEO8y+4Wsd4pgVp6+YT0Fn5ARqNsJHB0gpccIViHxvPf58X2EAA4Zzgu/Im7jx4cDArf4/nwxd0JgP2s8KVO2HmLDd/NGSFWwCT03tcdKiury3leeAjvJBSqf+2gQ0PMu2gpdLnT+O80z9q6NQZ3GFouHF8NJxCGsKwmrcWS54HAIQeEQsL9jhB8UVFR3+XCT9tJADZwXPgmdz533cI8L8zpSQAcSvwyWwi2HAns5zEBeaysrCMvoTNUVdWP4nnhY+ddPBjYffhgKHxZja7BO8O729oFJnc4mi8chyVa/8OoZLr0+J1XTmHVOXm+bjns3Lq6ui6Vmu0kAJ9ynHAWz4e/dJ/JccJdoHX5ffmdCAADzwsLcK0/OugTgh4Xa0K8gufDK0KhOsajvOcatiTsOvauEtJzi2fbi2j/1+PaWT85BHV2ENwoJKR3C0mpV8SF7SEA2OwhX3jcfp4dO+D58H1+Lb8rAQB4Pjw+FBKeQWN3rRf03kJoTdLjCwlpPaN9afR+d9n5/xlg8WQUWIQ72PEYzvJf48f2EACcDwbDw3k+fKVfN/A2YE8CAMD7FwrVzcf38n5PbHg26vb67+kMOY1egHeCd5PRpCIqjvmv+Z8Bq8E7p6EEjxbKt8Fs9F/jYnsJQEVFzYhQCN49v3XQNwFw4TCEsah2h/uhb9TU1HTp6AJlLqPSO9HwYPyi5Iz/mv9JYDnVQir2lqmQN7oLaGwvAeC4Wg7OHayy2dnw3VcBAHg+TP2jgPOM9oUm/UAc31LIK8Vk7O2WxshP/ef/p7HognHDelp0ensJQGWlwAo+8rzwF6/i10nj9VoAAJ4Pv7jl963pdlENVFe55oIdX29op8T2EoCqKoHx5ziudqbfu7d1AiA87P++oJL7rxtAL7G9BSAYrN8iyNOZAFRXh0+qqhp7H8cJ/0R5nOrq+gegRHq/h/NZj/i/74AAbAW2twAgFIyQsH/u9gtAKBT+eW0tfPS27e+kZLE1erwYEIBtjN4IQF8pYV4BcO6/rrNpwCsAHCdM9T7DG0TyYkAAtjG6EIDHvNdUVQmC9xq74cLvgKPnPKNbAQgG6yKdKYJeAUDc308I8QtiIBD9JhZt9DqTbAHYnKQygD6iCwHAi2eRxLKysm+jB3d04TK2zkscx7Gl4XsSAIwUPC986NcFvAKARvRPE6iU5vX0cZzwy46uYdwPp1P3Aa8BdAO/ADgbFkR4kuPC/+Z54QV/w9nDs3CP5xndCoB9Tfh2/yjgFQDE+vG53s9y/v8SvnyEcrFca8fz+N7htysqNi9qMYA+ogsBYCOBu/nPOYmZrFqm84zeCMC5fj3AKwAAz4fv70xIcMwhhXQ453zmTlEy578WXQlAV5vduBAMoT2vvzcCUFlZH/I3oF8AOC78q74kh9ph5jrJ+zkD6CP6KgAwz6AT+J7RowA4y67/e0tlcrMA2PqG8ER38QN3czgGmIa2rkzr/3cgvdodXrvbbNuc9c7Vw4cP75D1GwyCy2eHbN0RAvQu7zUAzwtX+K/juJoOawuHQnWVYO10FQLGMefc84g4eu8dQD/gGQE2dbI5x+s+CoWEB0OhurP99wMcJ6SrqsZuRHavvQkbYTr6r+N54SfIvcN597rOBAWRRJBZUJwRowF6u50FxEaGL0Khulx/CaID8AFsoaqq+oquturqseXhcPcvOxQKHcxx4TKeF0a7G4Zz/3VODYD2a7q5jgGfz/P1p/K8MCsUEi4MhYSpfc0DHMAABjCAAQxgB+L/AB1sn++S9xEMAAAAAElFTkSuQmCC'

# =============================================================================
#  HTML DASHBOARD TEMPLATE (data is injected in place of __DATA__, the icon in place of __ICON__)
# =============================================================================
$Template = @'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-__SCRIPT_HASH__'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Analyzer by Starkark98</title>
<link rel="icon" type="image/png" href="data:image/png;base64,__ICON__">
<style>
:root{--bg:#f4f5f7;--card:#fff;--tx:#1f2328;--mut:#6b7280;--bd:#e5e7eb;--hd:#f0f2f5;--ok:#16a34a;--warn:#d97706;--crit:#dc2626;--info:#2563eb;--acc:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1b1f24;--tx:#e6e8eb;--mut:#9aa3ad;--bd:#2c323a;--hd:#232830}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif;background:var(--bg);color:var(--tx)}
.top{position:sticky;top:0;z-index:10;background:var(--card);border-bottom:1px solid var(--bd);padding:10px 24px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.top h1{font-size:18px;margin:0;flex:1 1 auto;white-space:nowrap}
.top h1 .logo{width:30px;height:30px;vertical-align:-8px;margin-right:9px}
.top h1 .by{font-size:12px;font-style:italic;font-weight:400;color:var(--acc);margin-left:6px}
.top h1 small{color:var(--mut);font-weight:400;font-size:13px;margin-left:10px}
.top h1 .demo{background:var(--warn);color:#fff;font-size:11px;font-weight:600;border-radius:4px;padding:2px 7px;margin-left:10px;vertical-align:2px}
.top input{padding:7px 10px;border:1px solid var(--bd);border-radius:6px;width:300px;max-width:100%;background:var(--bg);color:var(--tx);font:inherit}
button{cursor:pointer;border:1px solid var(--bd);background:var(--card);color:var(--tx);border-radius:6px;padding:5px 11px;font:inherit;font-size:13px}
button:hover{border-color:var(--acc)}
main{padding:20px 24px;max-width:1600px;margin:0 auto}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.k{background:var(--card);border-radius:10px;padding:12px 16px;border-left:5px solid var(--ok);box-shadow:0 1px 2px #0001;cursor:pointer;transition:transform .1s}
.k:hover{transform:translateY(-2px)}
.k span{display:block;color:var(--mut);font-size:12px}.k b{font-size:21px;display:block;white-space:nowrap}.k b.sm{font-size:14px;margin-top:4px;white-space:normal}
.k.warn{border-color:var(--warn)}.k.crit{border-color:var(--crit)}.k.info{border-color:var(--info)}
.sec{background:var(--card);border-radius:10px;margin-bottom:14px;box-shadow:0 1px 2px #0001;scroll-margin-top:70px}
.sec>h2{margin:0;font-size:16px;padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:10px;user-select:none}
.sec>h2:before{content:'\25B8';color:var(--mut);transition:transform .15s;display:inline-block}
.sec.open>h2:before{transform:rotate(90deg)}
.sec>.body{display:none;padding:0 18px 18px}.sec.open>.body{display:block}
h3{font-size:12px;margin:20px 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.badge{font-size:12px;border-radius:10px;padding:1px 8px;background:var(--hd);color:var(--mut);font-weight:600}
.badge.crit{background:var(--crit);color:#fff}.badge.warn{background:var(--warn);color:#fff}.badge.ok{background:var(--ok);color:#fff}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.chips button.on{background:var(--acc);border-color:var(--acc);color:#fff}.chips button.on .badge{background:#fff3;color:#fff}
.iss{display:flex;gap:10px;align-items:center;padding:8px 12px;border-radius:6px;border-left:4px solid var(--mut);background:var(--hd);margin:5px 0}
.iss.crit{border-color:var(--crit)}.iss.warn{border-color:var(--warn)}.iss.info{border-color:var(--info)}.iss.ok{border-color:var(--ok)}
.iss.lnk{cursor:pointer}.iss.lnk:hover{filter:brightness(.97)}.iss>.pill{min-width:68px;text-align:center}.iss .go{margin-left:auto;color:var(--acc);font-size:12px;white-space:nowrap}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;white-space:nowrap;background:var(--hd);color:var(--mut)}
.pill.ok{background:#16a34a22;color:var(--ok)}.pill.warn{background:#d9770622;color:var(--warn)}.pill.crit{background:#dc262622;color:var(--crit)}.pill.info{background:#2563eb22;color:var(--info)}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;background:var(--hd);padding:8px 10px;white-space:nowrap;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--mut);position:sticky;top:0}
td{padding:8px 10px;border-top:1px solid var(--bd);vertical-align:top;font-variant-numeric:tabular-nums}
td.brk{word-break:break-all}
.g tbody tr:hover td,.wrap tbody tr:hover td{background:var(--hd)}
td.num,th.num{text-align:right}
.g th{cursor:pointer}.g th:hover{color:var(--acc)}
.tw{max-height:430px;overflow:auto;border:1px solid var(--bd);border-radius:6px}
.flt{padding:6px 10px;border:1px solid var(--bd);border-radius:6px;margin-bottom:8px;width:260px;background:var(--bg);color:var(--tx);font:inherit}
.mut{color:var(--mut);font-size:12px}.hint{margin-top:8px}
tr.sc{cursor:pointer;scroll-margin-top:70px}tr.sc:hover td,tr.sc.exp td{background:var(--hd)}
tr.sc.off td{opacity:.55}tr.sc.flash td{background:#2563eb22}
tr.det>td{padding:0;border-top:none}
.detail{padding:12px 16px 16px;border-left:4px solid var(--acc);background:var(--bg)}
.tabs{display:flex;gap:4px;margin-bottom:12px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
.tabs button{border:none;border-bottom:2px solid transparent;border-radius:0;background:none;padding:7px 12px}
.tabs button.on{border-bottom-color:var(--acc);color:var(--acc);font-weight:600}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--ok)}
.dot.warn{background:var(--warn)}.dot.crit{background:var(--crit)}.dot.info{background:var(--info)}
.bar{height:8px;background:var(--hd);border-radius:4px;width:110px;overflow:hidden;margin-top:4px}.bar i{display:block;height:100%}
.bar i.ok{background:var(--ok)}.bar i.warn{background:var(--warn)}.bar i.crit{background:var(--crit)}
.tok{color:var(--ok)}.twarn{color:var(--warn)}.tcrit{color:var(--crit);font-weight:600}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px}
.kv div{background:var(--card);border:1px solid var(--bd);border-radius:6px;padding:7px 11px}
.kv span{display:block;color:var(--mut);font-size:12px}.kv b{font-weight:600;word-break:break-word}
a[data-zone]{color:var(--acc);cursor:pointer;text-decoration:underline}
.map{display:grid;grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:5px}
.t{border-radius:6px;padding:5px 4px;text-align:center;color:#fff;cursor:default;min-height:38px}.t:hover{outline:2px solid var(--tx)}
.t b{display:block;font-size:12px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}.t span{font-size:10px;display:block;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.live{background:var(--ok)}.dead{background:var(--warn)}
.leg{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin:4px 0 10px;font-size:13px}
.leg i{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:5px;vertical-align:-1px}
footer{color:var(--mut);font-size:12px;text-align:center;padding:10px 0 30px}
@media print{.top input,.top button{display:none}.sec>.body{display:block!important}.tw{max-height:none}}
#old{font:15px/1.5 'Segoe UI',Arial,sans-serif;max-width:720px;margin:60px auto;padding:24px 28px;border-left:6px solid #d97706;background:#fff;color:#1f2328}
</style></head><body>
<div id="old"><b style="font-size:18px">DNS Analyzer by Starkark98</b><br><br>
This dashboard requires a modern browser: <b>Microsoft Edge</b>, <b>Google Chrome</b> or <b>Firefox</b>.<br>
Internet Explorer is not supported. Copy this file to a PC with Edge or Chrome and open it there.</div>
<div class="top">
  <h1><img class="logo" src="data:image/png;base64,__ICON__" alt="">DNS Analyzer<span class="by">by Starkark98</span><small id="sub"></small><span id="demo"></span></h1>
  <input id="q" type="search" placeholder="Search name, IP, record data or zone...  ( / )">
  <button id="bx">Expand all</button><button id="bc">Collapse all</button>
</div>
<main id="m"></main>
<footer id="ft"></footer>
<script>
document.getElementById('old').remove();
const D=__DATA__;
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const arr=v=>Array.isArray(v)?v:(v==null?[]:[v]);
const ipN=ip=>/^\d+\.\d+\.\d+\.\d+$/.test(String(ip))?String(ip).split('.').reduce((a,o)=>a*256+(+o||0),0):-1;
const kv=(k,v)=>`<div><span>${k}</span><b>${v}</b></div>`;
const badge=(n,c)=>`<span class="badge ${c||''}">${n}</span>`;
const SEV={crit:0,warn:1,info:2}, SEVL={crit:'Critical',warn:'Warning',info:'Info'};
const plural=(n,w)=>`${fmt(n)} ${w}${n===1?'':/(s|x|ch|sh)$/.test(w)?'es':'s'}`;
const fmt=n=>Number(n||0).toLocaleString('en-US');
const z0=n=>n?fmt(n):'<span class="mut">0</span>';
const wday=d=>{const x=new Date(d+'T00:00:00');return isNaN(x)?'':x.toLocaleDateString('en-US',{weekday:'short'})};
const lc=s=>String(s??'').toLowerCase().replace(/\.$/,'');
const pDate=s=>new Date(String(s).replace(' ','T')+(String(s).length===16?':00':''));
const GEN=pDate(D.generated);
const dAge=s=>{if(!s)return null;const t=pDate(s);return isNaN(t)?null:(GEN-t)/864e5};
const ago=a=>a==null?'':a<1?'today':Math.round(a)+' d ago';
const ttlF=s=>{s=+s||0;return s>=86400&&s%3600===0?(s/86400).toFixed(s%86400?1:0)+' d':s>=3600?(s/3600).toFixed(s%3600?1:0)+' h':s>=60?Math.round(s/60)+' min':s+' s'};
const yn=(v,y,n)=>v==null?'n/a':(v?y:n);
const pct=(a,b)=>b?Math.round(a*1000/b)/10:0;

/* ---------- data normalization ---------- */
D.zones=arr(D.zones);D.tests=arr(D.tests);D.forwarders=arr(D.forwarders);D.rootHints=arr(D.rootHints);
const S=D.settings||{};['fwdIps','listen','allIps'].forEach(k=>S[k]=arr(S[k]));
const LG=D.logs||null;if(LG){['events','days','rows'].forEach(k=>LG[k]=arr(LG[k]))}
/* values shown without esc() are forced to numbers here: the report never trusts the shape of the data */
const N=v=>{const n=Number(v);return isFinite(n)?n:0},Nn=v=>v==null||v===''?null:N(v);
['recTimeout','fwdTimeout','rootN','scavIntH','cacheMaxKB','locking'].forEach(k=>S[k]=Nn(S[k]));
[...D.tests,...D.forwarders].forEach(t=>{t.ms=N(t.ms);t.serial=Nn(t.serial)});
if(LG){LG.events.forEach(e=>{e.id=N(e.id);e.level=N(e.level);e.count=N(e.count)});LG.rows.forEach(r=>r.id=N(r.id));LG.days.forEach(d=>Object.keys(d).forEach(k=>{if(k!=='day')d[k]=N(d[k])}))}
const ST=D.stats&&D.stats.c?D.stats:null;
D.zones.forEach(z=>{
  ['records','ns','masters','xferTo','fwdTest'].forEach(k=>z[k]=arr(z[k]));
  if(z.scan){z.scan.ips=arr(z.scan.ips);z.scan.total=N(z.scan.total);z.scan.ips.forEach(x=>x.cls=x.cls==='live'?'live':'dead')}
  z.staleDays=N(z.staleDays)||14;z.total=N(z.total);
  if(z.soa)['serial','refresh','retry','expire','minTtl'].forEach(k=>z.soa[k]=N(z.soa[k]));
  [...z.ns,...z.fwdTest].forEach(x=>{x.ms=N(x.ms);x.serial=Nn(x.serial)});
  z.records.forEach(r=>{r.ttl=N(r.ttl);r.n=String(r.n??'');r.t=String(r.t??'');r.d=String(r.d??'')});
  z.fq=lc(z.name);z.p=[];
  z.c={dyn:0,stat:0,stale:0,types:{}};
  z.records.forEach(r=>{
    r.fq=r.n==='@'?z.fq:lc(r.n)+'.'+z.fq;
    z.c.types[r.t]=(z.c.types[r.t]||0)+1;
    if(r.ts){z.c.dyn++;r.age=dAge(r.ts);r.stale=r.age!=null&&r.age>z.staleDays;if(r.stale)z.c.stale++}else z.c.stat++;
  });
});

/* ---------- cross-zone indexes ---------- */
const HZ=D.zones.filter(z=>(z.type==='Primary'||z.type==='Secondary')&&!z.auto);
const NAMES=new Map(),AIDX=new Map(),PTR=new Map();
const push=(m,k,v)=>{if(!m.has(k))m.set(k,[]);m.get(k).push(v)};
const revIp=fq=>{const o=fq.replace(/\.in-addr\.arpa$/,'').split('.');return o.length===4&&o.every(x=>/^\d+$/.test(x))?o.reverse().join('.'):null};
HZ.forEach(z=>z.records.forEach(r=>{
  push(NAMES,r.fq,r);
  if(r.t==='A'&&!z.rev)push(AIDX,r.d,{z,r});
  if(r.t==='PTR'&&z.rev){const ip=revIp(r.fq);if(ip)push(PTR,ip,{z,r})}
}));
const REV=HZ.filter(z=>z.rev&&/\.in-addr\.arpa$/.test(z.fq)).map(z=>({z,p:z.fq.replace(/\.in-addr\.arpa$/,'').split('.').reverse().join('.')+'.'}));
const revOf=ip=>REV.find(x=>String(ip).startsWith(x.p));
const hostedFor=n=>HZ.find(z=>!z.rev&&!z.truncated&&(n===z.fq||n.endsWith('.'+z.fq)));
const exists=n=>NAMES.has(n)||NAMES.has('*.'+n.split('.').slice(1).join('.'));
const special=r=>r.n==='@'||r.fq.includes('_')||/^(domaindnszones|forestdnszones)$/i.test(r.n);

/* ---------- record-level problems ---------- */
const addP=(z,sev,kind,name,detail)=>z.p.push({sev,kind,name,detail});
HZ.forEach(z=>z.records.forEach(r=>{
  if(!z.rev){
    if(['CNAME','MX','SRV','NS'].includes(r.t)){
      const tg=lc(r.t==='CNAME'||r.t==='NS'?r.d:String(r.d).split(' ').pop());
      if(tg&&hostedFor(tg)&&!exists(tg))addP(z,'warn',r.t==='CNAME'?'Dangling CNAME':r.t==='NS'?'Lame name server':'Missing target',r.fq,`${esc(r.t)} points to <b>${esc(tg)}</b>, which does not exist`);
    }
    if(r.t==='A'&&!special(r)){
      const rv=revOf(r.d);
      if(rv&&!PTR.has(r.d))addP(z,'info','Missing PTR',r.fq,`${esc(r.d)} has no PTR record in ${esc(rv.z.name)}`);
      const o=(AIDX.get(r.d)||[]).filter(x=>x.r!==r&&!special(x.r)&&x.r.fq!==r.fq);
      if(o.length)addP(z,'info','Duplicate IP',r.fq,`${esc(r.d)} is also used by ${o.slice(0,3).map(x=>esc(x.r.fq)+(x.r.stale?' (stale)':'')).join(', ')}${o.length>3?' and '+(o.length-3)+' more':''}${r.stale?' &middot; <b>this record is stale</b>':''}`);
    }
  }else if(r.t==='PTR'){
    const ip=revIp(r.fq),tg=lc(r.d);
    if(ip&&hostedFor(tg)){const a=(NAMES.get(tg)||[]).filter(x=>x.t==='A');
      if(!a.length)addP(z,'info','PTR without A record',ip,`PTR points to <b>${esc(tg)}</b>, which has no A record`);
      else if(!a.some(x=>x.d===ip))addP(z,'info','PTR mismatch',ip,`PTR points to <b>${esc(tg)}</b>, whose A record is ${esc(a.map(x=>x.d).join(', '))}`);}
  }
}));

/* ---------- issues ---------- */
const I=[];const add=(sev,text,zone,go,tab)=>I.push({sev,text,zone,go,tab});
const zL=z=>`Zone <b>${esc(z.name)}</b>`;
if(S.service&&S.service!=='Running')add('crit',`DNS Server service is ${esc(S.service)}`,null,'config');
if(S.plugin)add('crit',`A server-level plugin DLL is configured (<b>${esc(S.plugin)}</b>): make sure it is legitimate. This setting is abused by a known privilege-escalation technique (DnsAdmins)`,null,'config');
D.tests.forEach(t=>{if(t.ok)return;if(t.kind==='ext'&&S.recursion===false)return;
  add(t.kind==='dc'?'warn':'crit',`Live test failed: ${esc(t.name)} &middot; ${esc(t.query)} (${esc(t.err||'no answer')})`,null,'res')});
const fwBad=D.forwarders.filter(f=>!f.ok);
if(D.forwarders.length&&fwBad.length===D.forwarders.length)add('crit',`${D.forwarders.length===1?'The only forwarder does not answer':'None of the '+D.forwarders.length+' forwarders answers'}: external resolution depends on root hints only, with long delays`,null,'res');
else if(fwBad.length)add('warn',`${plural(fwBad.length,'forwarder')} not answering: ${fwBad.map(f=>esc(f.ip)).join(', ')} (every query to it waits for the timeout)`,null,'res');
D.forwarders.filter(f=>f.ok&&f.ms>300).forEach(f=>add('info',`Forwarder ${esc(f.ip)} is slow (${f.ms} ms)`,null,'res'));
if(S.recursion!==false&&!S.fwdIps.length&&(S.useRoot===false||!S.rootN))add('warn','Recursion is enabled but there are no forwarders and no root hints: the server cannot resolve external names',null,'res');
if(S.recursion===false&&S.fwdIps.length)add('info','Forwarders are configured but recursion is disabled: they are never used',null,'res');
if(S.pollution===false)add('warn','Cache pollution protection is disabled',null,'config');
if(S.gqblOn===false)add('info','Global query block list is disabled (WPAD and ISATAP names are not blocked)',null,'config');
if(S.debugLog)add('info','Debug logging is enabled: it can affect performance and fill the disk',null,'config');
const agingZ=D.zones.filter(z=>z.aging&&!z.auto);
if(S.scavOn===false&&agingZ.length)add('warn',`Scavenging is disabled on the server, but ${plural(agingZ.length,'zone')} ${agingZ.length===1?'has':'have'} aging enabled: stale records are never removed`,null,'config');
if(S.scavOn&&!agingZ.length)add('info','Scavenging is enabled on the server, but no zone has aging enabled: nothing is ever scavenged',null,'config');
if(S.scavOn&&agingZ.length){const a=dAge(S.lastScav);if(a==null||a>Math.max(3*(S.scavIntH||168)/24,8))add('warn',`Scavenging is enabled but ${a==null?'has never run':'last ran '+Math.round(a)+' days ago'}`,null,'config')}

const PK={'Dangling CNAME':['warn',n=>`${plural(n,'CNAME')} pointing to names that do not exist`],
  'Missing target':['warn',n=>`${plural(n,'MX/SRV record')} pointing to names that do not exist`],
  'Lame name server':['warn',n=>`${plural(n,'NS record')} pointing to names that do not exist`],
  'Missing PTR':['info',n=>`${plural(n,'A record')} without a PTR record (reverse lookup returns nothing)`],
  'Duplicate IP':['info',n=>`${plural(n,'A record')} sharing their IP address with another name (often a stale record)`],
  'PTR mismatch':['info',n=>`${plural(n,'PTR record')} pointing to a name with a different IP`],
  'PTR without A record':['info',n=>`${plural(n,'PTR record')} pointing to names that no longer exist`]};
D.zones.forEach(z=>{
  if(z.auto)return;const L=zL(z),id=z.name;
  if(z.shutdown)add('crit',L+' is shut down (not loaded)',id);else if(z.paused)add('warn',L+' is paused',id);
  if(z.type==='Secondary'||z.type==='Stub'){
    const sa=dAge(z.lastSoa),exp=z.soa&&z.soa.expire?z.soa.expire/86400:7;
    if(sa==null)add('crit',`${L}: never synchronized with its masters (${esc(z.masters.join(', ')||'none')})`,id);
    else if(sa>exp)add('crit',`${L} has expired: masters not reached for ${Math.round(sa)} days (expire ${ttlF(z.soa?z.soa.expire:604800)})`,id);
    else if(sa>1)add('warn',`${L}: masters not reached for ${Math.round(sa)} days`,id);
    if(z.xferRes&&z.xferRes!=='0')add('warn',`${L}: last zone transfer attempt failed (result ${esc(z.xferRes)})`,id);
  }
  if(z.dyn==='NonsecureAndSecure')add('warn',`${L} accepts nonsecure dynamic updates: any client can register or overwrite records`,id);
  if(z.xfer==='TransferAnyServer')add('warn',`${L} allows zone transfers to any server: anyone who can reach the server can download the whole zone`,id);
  const nt=z.ns.filter(n=>n.tested);
  if(nt.length){
    const bad=nt.filter(n=>!n.ok);
    if(bad.length===nt.length)add('crit',`${L}: none of its name servers answers (${bad.map(n=>esc(n.name)).join(', ')})`,id,null,'ns');
    else if(bad.length)add('warn',`${L}: ${plural(bad.length,'name server')} not answering: ${bad.map(n=>esc(n.name)).join(', ')}`,id,null,'ns');
    const ref=z.soa?z.soa.serial:null,diff=nt.filter(n=>n.ok&&n.serial!=null&&ref!=null&&n.serial!==ref);
    if(diff.length)add(z.ad?'info':'warn',`${L}: SOA serial differs on ${diff.map(n=>esc(n.name)+' ('+n.serial+')').join(', ')} vs ${ref}${z.ad?' &middot; normal for a short time in AD-integrated zones, check AD replication if it persists':' &middot; the secondary is not up to date'}`,id,null,'ns');
  }
  if(z.type==='Primary'&&!z.rev&&z.ns.length===1)add('info',`${L} has only one name server (NS record)`,id,null,'ns');
  if(z.type==='Forwarder'&&z.fwdTest.length){const b=z.fwdTest.filter(t=>!t.ok);
    if(b.length===z.fwdTest.length)add('crit',`Conditional forwarder <b>${esc(z.name)}</b>: none of its servers answers (${b.map(t=>esc(t.ip)).join(', ')})`,id);
    else if(b.length)add('warn',`Conditional forwarder <b>${esc(z.name)}</b>: ${b.map(t=>esc(t.ip)).join(', ')} not answering`,id)}
  if(z.c.stale){
    if(z.aging)add(S.scavOn===false?'warn':'info',`${L}: ${plural(z.c.stale,'dynamic record')} older than the ${z.staleDays}-day aging window${S.scavOn===false?' and never scavenged (server scavenging is off)':' (eligible for scavenging)'}`,id,null,'rec:stale');
    else add('warn',`${L}: ${plural(z.c.stale,'stale dynamic record')} (older than ${z.staleDays} days) and aging is disabled: ${z.c.stale===1?'it':'they'} will never be removed`,id,null,'rec:stale');
  }
  const kc={};z.p.forEach(p=>kc[p.kind]=(kc[p.kind]||0)+1);
  Object.keys(kc).forEach(k=>{const d=PK[k];if(d)add(d[0],`${L}: ${d[1](kc[k])}`,id,null,'prob')});
  if(z.scan){const d=z.scan.ips.filter(x=>x.cls==='dead');if(d.length)add('info',`${L}: ${plural(d.length,'static or stale address')} with no evidence of a live host (cleanup candidates)`,id,null,'live')}
  if(z.truncated)add('info',`${L} has ${fmt(z.total)} records: only the first ${fmt(z.records.length)} are in the report`,id);
});
const noRev=new Set();
if(REV.length)HZ.filter(z=>!z.rev).forEach(z=>z.records.forEach(r=>{if(r.t==='A'&&!special(r)&&/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(r.d)&&!revOf(r.d))noRev.add(r.d.split('.').slice(0,3).join('.')+'.x')}));
if(noRev.size)add('info',`A records in ${plural(noRev.size,'private /24 subnet')} have no reverse lookup zone on this server: ${esc([...noRev].slice(0,6).join(', '))}${noRev.size>6?'...':''}`,null,'zones');

const lt={dyn:0,manual:0,scav:0,zone:0,server:0,err:0,warn:0};let evErr=0,evCrit=0;
if(LG){
  LG.days.forEach(d=>Object.keys(lt).forEach(k=>lt[k]+=+d[k]||0));
  LG.events.forEach(e=>{if(e.level<=2)evErr+=e.count;if(e.level===1)evCrit+=e.count});
  if(evErr)add(evCrit?'crit':'warn',`${plural(evErr,'error event')} in the DNS Server event log in the last 7 days`,null,'logs');
  const chg=lt.manual+lt.zone+lt.server;
  if(chg)add('info',`${plural(chg,'manual change')} to records, zones or server settings in the last 7 days (see who and what in the audit log)`,null,'logs');
  if(LG.eventsErr)add('info','DNS Server event log could not be read: '+esc(LG.eventsErr),null,'logs');
  if(LG.auditErr)add('info','DNS audit log could not be read: '+esc(LG.auditErr),null,'logs');
}
D.zones.forEach(z=>z.p.sort((a,b)=>SEV[a.sev]-SEV[b.sev]||a.kind.localeCompare(b.kind)));
D.zones.forEach(z=>{const m=I.filter(i=>i.zone===z.name).sort((a,b)=>SEV[a.sev]-SEV[b.sev])[0];z.sev=m?m.sev:'ok'});
const logProb=evErr+lt.warn;
const nC=I.filter(i=>i.sev==='crit').length,nW=I.filter(i=>i.sev==='warn').length,nI=I.filter(i=>i.sev==='info').length;

/* ---------- components ---------- */
function sec(id,title,b,body,open){return `<section class="sec${open?' open':''}" id="${id}"><h2>${title} ${b||''}</h2><div class="body">${body}</div></section>`}
function chips(id,items){return `<div class="chips" data-for="${id}">${items.map((it,i)=>`<button data-f="${it[0]}" class="${i?'':'on'}">${it[1]} ${badge(it[2])}</button>`).join('')}</div>`}
function makeGrid(host,cols,rows,o={}){
  const search=o.search!==false,MAX=o.max||1000;let sk=null,sd=1,q=o.q||'';
  host.innerHTML=(search?'<input class="flt" type="search" placeholder="Filter...">':'')+'<div class="tw g"><table><thead></thead><tbody></tbody></table></div><div class="mut hint"></div>';
  const th=host.querySelector('thead'),tb=host.querySelector('tbody'),cnt=host.querySelector('.hint');
  if(search)host.querySelector('.flt').value=q;
  const val=(r,c)=>c.sv?c.sv(r):String(r[c.k]??'').toLowerCase();
  function draw(){
    th.innerHTML='<tr>'+cols.map((c,i)=>`<th data-i="${i}" class="${c.num?'num':''}">${c.t}${sk===i?(sd>0?' &#9650;':' &#9660;'):''}</th>`).join('')+'</tr>';
    let R=rows;if(q){const Q=q.toLowerCase();R=R.filter(r=>cols.some(c=>String(r[c.k]??'').toLowerCase().includes(Q)))}
    if(sk!==null){const c=cols[sk];R=[...R].sort((a,b)=>{const x=val(a,c),y=val(b,c);return(x>y?1:x<y?-1:0)*sd})}
    tb.innerHTML=R.length?R.slice(0,MAX).map(r=>'<tr>'+cols.map(c=>`<td class="${c.num?'num':''}${c.brk?' brk':''}">${c.f?c.f(r):esc(r[c.k])}</td>`).join('')+'</tr>').join(''):`<tr><td colspan="${cols.length}" class="mut">${o.empty||'No data'}</td></tr>`;
    cnt.textContent=(R.length===rows.length?plural(rows.length,'item'):`${fmt(R.length)} of ${plural(rows.length,'item')}`)+(R.length>MAX?` (showing the first ${fmt(MAX)}: use the filter to narrow down)`:'');
  }
  th.onclick=e=>{const t=e.target.closest('th');if(!t)return;const i=+t.dataset.i;if(sk===i)sd=-sd;else{sk=i;sd=1}draw()};
  if(search)host.querySelector('.flt').oninput=e=>{q=e.target.value;draw()};
  draw();
}
const res=t=>t.ok?'<span class="pill ok">OK</span>':t.dead?'<span class="pill crit">No answer</span>':'<span class="pill warn">Error</span>';
const DYN={Secure:['Secure only','ok'],NonsecureAndSecure:['Nonsecure + secure','crit'],None:['None','']};
const dynP=d=>{const x=DYN[d]||[d||'n/a',''];return `<span class="pill ${x[1]}">${esc(x[0])}</span>`};
const XFR={NoTransfer:'Not allowed',TransferToZoneNameServer:'Only to NS servers',TransferToSecureServers:'Only to listed servers',TransferAnyServer:'<span class="tcrit">To any server</span>'};
const store=z=>z.ad?`AD &middot; ${esc(z.repl)}`:z.file?'File &middot; '+esc(z.file):'&ndash;';
const recState=r=>r.ts?(r.stale?'<span class="pill warn">Stale</span>':'<span class="pill ok">Dynamic</span>'):'<span class="pill">Static</span>';

/* ---------- zones ---------- */
const ZF={all:z=>!z.auto,att:z=>z.sev==='crit'||z.sev==='warn',fwd:z=>!z.auto&&!z.rev&&z.type!=='Forwarder'&&z.type!=='Stub',rev:z=>!z.auto&&z.rev,cf:z=>z.type==='Forwarder'||z.type==='Stub',auto:z=>z.auto};
function renderZones(f){
  const L=D.zones.filter(ZF[f]||ZF.all);
  $('#zt').innerHTML=L.map(z=>{
    const fw=z.type==='Forwarder',dp=pct(z.c.stale,z.c.dyn),nt=z.ns.filter(n=>n.tested),nok=nt.filter(n=>n.ok).length;
    const fwo=z.fwdTest.filter(t=>t.ok).length;
    return `<tr class="sc${z.shutdown||z.paused?' off':''}" data-id="${esc(z.name)}">
    <td><span class="dot ${z.sev}" title="${z.sev==='ok'?'No issues':SEVL[z.sev]}"></span></td>
    <td><b>${esc(z.name)}</b>${z.signed?' <span class="pill info">DNSSEC</span>':''}${z.paused?' <span class="pill warn">paused</span>':''}${z.shutdown?' <span class="pill crit">shut down</span>':''}${z.auto?' <span class="pill">auto-created</span>':''}<div class="mut">${z.rev?'Reverse lookup':'Forward lookup'}</div></td>
    <td>${esc(fw?'Conditional forwarder':z.type)}<div class="mut">${store(z)}</div></td>
    <td>${fw?'<span class="mut">&ndash;</span>':dynP(z.dyn)}</td>
    <td class="num">${fw?`<span class="mut">${z.masters.map(esc).join('<br>')}</span>`:fmt(z.total)+`<div class="mut">${fmt(z.c.dyn)} dyn &middot; ${fmt(z.c.stat)} static</div>`}</td>
    <td>${fw?'<span class="mut">&ndash;</span>':z.c.dyn?`<div class="bar"><i class="${dp>=20?'crit':dp?'warn':'ok'}" style="width:${Math.min(dp,100)}%"></i></div><div class="mut"><b class="${z.c.stale?'twarn':''}">${fmt(z.c.stale)}</b> &middot; ${dp}% of dyn</div>`:'<span class="mut">0</span>'}</td>
    <td>${z.aging==null?'<span class="mut">&ndash;</span>':z.aging?`On<div class="mut">${esc(z.noRef)} + ${esc(z.refr)}</div>`:'<span class="mut">Off</span>'}</td>
    <td>${fw||z.type==='Stub'?'<span class="mut">&ndash;</span>':XFR[z.xfer]||esc(z.xfer)}</td>
    <td>${fw?(z.fwdTest.length?`<span class="${fwo===z.fwdTest.length?'tok':fwo?'twarn':'tcrit'}">${fwo} / ${z.fwdTest.length} answer</span>`:`${plural(z.masters.length,'server')}`)
      :nt.length?`<span class="${nok===nt.length?'tok':nok?'twarn':'tcrit'}">${nok} / ${nt.length} answer</span>`:z.ns.length?plural(z.ns.length,'server'):'<span class="mut">&ndash;</span>'}</td></tr>`}).join('')||'<tr><td colspan="9" class="mut">No zones</td></tr>';
}
function toggleZone(tr,tab,q){
  const nx=tr.nextElementSibling;
  if(nx&&nx.classList.contains('det')){nx.remove();tr.classList.remove('exp');if(!tab)return}
  const z=D.zones.find(x=>x.name===tr.dataset.id);
  const d=document.createElement('tr');d.className='det';d.innerHTML='<td colspan="9"><div class="detail"></div></td>';
  tr.after(d);tr.classList.add('exp');buildDetail(d.querySelector('.detail'),z,tab||'ov',q);
}
function buildDetail(el,z,tab,q){
  const fw=z.type==='Forwarder';
  const T=[['ov','Overview']];
  if(!fw)T.push(['rec',`Records (${fmt(z.records.length)})`],['prob',`Problems (${fmt(z.p.length)})`]);
  T.push(['ns',fw?'Forwarder servers':`Name servers (${z.ns.length})`]);
  if(z.scan)T.push(['live',`Liveness (${z.scan.ips.length})`]);
  el.innerHTML=`<div class="tabs">${T.map(t=>`<button data-tab="${t[0]}">${t[1]}</button>`).join('')}</div><div class="tab"></div>`;
  el.querySelector('.tabs').onclick=e=>{const b=e.target.closest('button');if(b){e.stopPropagation();showTab(el,z,b.dataset.tab)}};
  showTab(el,z,tab,q);
}
function showTab(el,z,t,q){
  let sub='';if(t.includes(':')){[t,sub]=t.split(':')}
  el.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('on',b.dataset.tab===t));
  const T=el.querySelector('.tab');
  if(t==='ov'){
    const s=z.soa,fw=z.type==='Forwarder';
    T.innerHTML=`<div class="kv">${kv('Type',esc(fw?'Conditional forwarder':z.type)+(z.rev?' &middot; reverse lookup':''))}${kv('Storage',z.ad?'Active Directory &middot; replication '+esc(z.repl)+(z.part?'<div class="mut">'+esc(z.part)+'</div>':''):z.file?'File '+esc(z.file):'n/a')}
      ${fw?kv('Forwarder servers',esc(z.masters.join(', ')))+kv('Timeout',z.fwdTimeout?esc(z.fwdTimeout)+' s':'n/a')
        :kv('Dynamic updates',dynP(z.dyn))+kv('Aging',z.aging==null?'n/a (not a primary zone)':z.aging?`Enabled &middot; no-refresh ${esc(z.noRef)}, refresh ${esc(z.refr)}`:'Disabled')
        +kv('Stale threshold',z.staleDays+' days'+(z.aging?'':' (default used for the report, aging is off)'))+(z.scavAvail?kv('Scavenging possible from',esc(z.scavAvail)):'')
        +kv('Zone transfers',(XFR[z.xfer]||esc(z.xfer))+(z.xferTo.length?'<div class="mut">'+esc(z.xferTo.join(', '))+'</div>':''))+kv('Notify',esc(z.notify)||'n/a')}
      ${z.masters.length&&!fw?kv('Master servers',esc(z.masters.join(', '))):''}
      ${z.type==='Secondary'||z.type==='Stub'?kv('Last SOA check',z.lastSoa?esc(z.lastSoa)+' ('+ago(dAge(z.lastSoa))+')':'<span class="tcrit">never</span>')+kv('Last zone transfer',z.lastXfr?esc(z.lastXfr)+' ('+ago(dAge(z.lastXfr))+')':'never')+kv('Last transfer result',z.xferRes===''?'n/a':z.xferRes==='0'?'Success':'<span class="twarn">'+esc(z.xferRes)+'</span>'):''}
      ${kv('DNSSEC',z.signed?'Signed':'Not signed')}</div>
      ${s?`<h3>SOA record</h3><div class="kv">${kv('Primary server',esc(s.primary))}${kv('Responsible person',esc(s.admin))}${kv('Serial number',esc(s.serial))}${kv('Refresh / retry',ttlF(s.refresh)+' / '+ttlF(s.retry))}${kv('Expire',ttlF(s.expire))}${kv('Minimum (negative) TTL',ttlF(s.minTtl))}</div>`:''}
      ${fw?'':`<h3>Records by type</h3><div class="kv">${Object.keys(z.c.types).sort((a,b)=>z.c.types[b]-z.c.types[a]).map(k=>kv(esc(k),fmt(z.c.types[k]))).join('')||'<div class="mut">No records</div>'}</div>`}`;
  }else if(t==='rec'){
    const F=[['All',()=>true],['A',r=>r.t==='A'],['AAAA',r=>r.t==='AAAA'],['CNAME',r=>r.t==='CNAME'],['PTR',r=>r.t==='PTR'],['MX',r=>r.t==='MX'],['SRV',r=>r.t==='SRV'],['NS / SOA',r=>r.t==='NS'||r.t==='SOA'],['TXT',r=>r.t==='TXT'],['Other',r=>!['A','AAAA','CNAME','PTR','MX','SRV','NS','SOA','TXT'].includes(r.t)],['Static',r=>!r.ts],['Dynamic',r=>!!r.ts],['Stale',r=>r.stale]];
    const V=F.map(f=>[f[0],f[1],z.records.filter(f[1]).length]).filter((f,i)=>i===0||f[2]||f[0]==='Stale');
    let cur=sub==='stale'?V.findIndex(f=>f[0]==='Stale'):0;
    T.innerHTML=`<div class="chips">${V.map((f,i)=>`<button data-i="${i}" class="${i===cur?'on':''}">${f[0]} ${badge(fmt(f[2]))}</button>`).join('')}</div><div class="gg"></div>
      <div class="mut hint">Stale = dynamic record not refreshed for more than ${z.staleDays} days${z.aging?' (no-refresh + refresh interval)':''}.${z.truncated?` Only the first ${fmt(z.records.length)} of ${fmt(z.total)} records are in the report.`:''}</div>`;
    const draw=(i,qq)=>makeGrid(T.querySelector('.gg'),[{k:'n',t:'Name',f:r=>esc(r.n)+(r.n==='@'?' <span class="mut">(same as zone)</span>':'')},{k:'t',t:'Type'},{k:'d',t:'Data',brk:1,sv:r=>r.t==='A'?ipN(r.d):lc(r.d)},{k:'ttl',t:'TTL',num:1,sv:r=>+r.ttl,f:r=>ttlF(r.ttl)},
      {k:'ts',t:'Timestamp',f:r=>r.ts?esc(r.ts)+` <span class="mut">(${ago(r.age)})</span>`:'<span class="mut">static</span>'},{k:'st',t:'State',sv:r=>r.ts?(r.stale?2:1):0,f:recState}],V[i][1]===undefined?[]:z.records.filter(V[i][1]),{empty:'No records',q:qq});
    T.querySelector('.chips').onclick=e=>{const b=e.target.closest('button');if(!b)return;e.stopPropagation();T.querySelectorAll('.chips button').forEach(x=>x.classList.toggle('on',x===b));draw(+b.dataset.i)};
    draw(cur,q);
  }else if(t==='prob'){
    T.innerHTML='<div class="gg"></div><div class="mut hint">Checks across all zones hosted on this server: names outside them are not verified. Missing PTR is checked only for addresses covered by a reverse zone hosted here.</div>';
    makeGrid(T.querySelector('.gg'),[{k:'sev',t:'Severity',sv:r=>SEV[r.sev],f:r=>`<span class="pill ${r.sev}">${SEVL[r.sev]}</span>`},{k:'kind',t:'Problem'},{k:'name',t:'Name / IP',brk:1},{k:'detail',t:'Details',f:r=>r.detail}],z.p,{empty:'No problems found'});
  }else if(t==='ns'){
    if(z.type==='Forwarder'){
      T.innerHTML=z.fwdTest.length?`<div class="wrap"><table><thead><tr><th>Server</th><th>Result</th><th class="num">Time</th><th>Answer / error</th></tr></thead><tbody>${z.fwdTest.map(x=>`<tr><td>${esc(x.ip)}</td><td>${res(x)}</td><td class="num">${x.ms} ms</td><td>${esc(x.res||x.err)}</td></tr>`).join('')}</tbody></table></div>`
        :`<div class="kv">${z.masters.map(m=>kv('Server',esc(m))).join('')}</div><div class="mut hint">Live tests were not run.</div>`;
    }else{
      const ref=z.soa?z.soa.serial:null;
      T.innerHTML=z.ns.length?`<div class="wrap"><table><thead><tr><th>Name server</th><th>IP</th><th>Result</th><th class="num">Time</th><th>SOA serial</th><th>Error</th></tr></thead><tbody>${z.ns.map(x=>`<tr><td><b>${esc(x.name)}</b></td><td>${esc(x.ip)||'<span class="mut">&ndash;</span>'}</td>
        <td>${x.tested?res(x):'<span class="mut">not tested</span>'}</td><td class="num">${x.tested&&x.ip?x.ms+' ms':''}</td>
        <td>${x.serial==null?'':x.serial===ref?'<span class="tok">'+x.serial+'</span>':'<span class="twarn">'+x.serial+'</span> <span class="mut">(here: '+ref+')</span>'}</td><td class="mut">${esc(x.err)}</td></tr>`).join('')}</tbody></table></div>
        <div class="mut hint">Each name server is asked for the zone's SOA record without recursion: it must answer, and with the same serial number as this server.</div>`:'<div class="mut">No NS records at the zone apex.</div>';
    }
  }else if(t==='live'){
    const sc=z.scan,c={live:0,dead:0};sc.ips.forEach(x=>c[x.cls]++);
    const tiles=sc.ips.slice().sort((a,b)=>ipN(a.ip)-ipN(b.ip)).map(x=>{const tip=[x.ip,'Names: '+x.names,'Kind: '+x.kind,x.ping!==''&&x.ping!=null?'Ping: '+x.ping+' ms':'',x.tcp?'TCP: '+x.tcp:'',x.mac?'MAC: '+x.mac:''].filter(Boolean).join('\n');
      return `<div class="t ${x.cls}" title="${esc(tip)}"><b>${esc(String(x.names).split(',')[0])}</b><span>${esc(x.ip)}${x.kind!=='static'?' &middot; stale':''}</span></div>`}).join('');
    T.innerHTML=`<div class="leg"><span><i class="live"></i>Responds ${c.live}</span><span><i class="dead"></i>No response ${c.dead}</span>
      <span class="mut">static A records and stale dynamic A records &middot; ping, TCP ports and ARP (local subnets only) &middot; hover a tile for details</span></div>
      <div class="map">${tiles}</div>${sc.total>sc.ips.length?`<div class="mut hint">${fmt(sc.total-sc.ips.length)} more addresses were not checked (limit reached).</div>`:''}
      <h3>No response: cleanup candidates</h3><div class="gg"></div>
      <div class="mut hint">No response = no evidence of a live host at the time of the test, not a guarantee: the device may be off or firewalled. Verify before deleting records.</div>`;
    makeGrid(T.querySelector('.gg'),[{k:'ip',t:'IP',sv:r=>ipN(r.ip)},{k:'names',t:'Names',brk:1},{k:'kind',t:'Kind',f:r=>r.kind==='static'?'<span class="pill">Static</span>':'<span class="pill warn">Stale</span>'}],sc.ips.filter(x=>x.cls==='dead'),{empty:'Every checked address responds'});
  }
}
function openZone(id,tab,q){
  $('#zones').classList.add('open');
  const sel=`tr.sc[data-id="${CSS.escape(id)}"]`;let tr=document.querySelector(sel);
  if(!tr){const z=D.zones.find(x=>x.name===id);const f=z&&z.auto?'auto':'all';document.querySelectorAll('[data-for="zf"] button').forEach(b=>b.classList.toggle('on',b.dataset.f===f));renderZones(f);tr=document.querySelector(sel)}
  if(!tr)return;
  const nx=tr.nextElementSibling;if(nx&&nx.classList.contains('det')){nx.remove();tr.classList.remove('exp')}
  toggleZone(tr,tab||'ov',q);tr.scrollIntoView({behavior:'smooth',block:'start'});
  tr.classList.add('flash');setTimeout(()=>tr.classList.remove('flash'),1500);
}

/* ---------- issues list ---------- */
function renderIssues(f){
  const L=I.filter(i=>f==='all'||i.sev===f).sort((a,b)=>SEV[a.sev]-SEV[b.sev]);
  $('#isl').innerHTML=L.length?L.map(i=>`<div class="iss ${i.sev}${i.zone?' lnk" data-zone="'+esc(i.zone)+'" data-tab="'+(i.tab||'ov')+'"':i.go?' lnk" data-go="'+i.go+'"':'"'}><span class="pill ${i.sev}">${SEVL[i.sev]}</span><span>${i.text}</span>${i.zone?'<span class="go">Open zone &rsaquo;</span>':i.go?'<span class="go">Open &rsaquo;</span>':''}</div>`).join('')
    :'<div class="iss ok"><span class="pill ok">OK</span><span>No issues found</span></div>';
}

/* ---------- global search ---------- */
function search(q){
  const R=$('#sres');q=q.trim().toLowerCase();if(q.length<2){R.innerHTML='';return}
  const out=[];
  D.zones.forEach(z=>{
    if(z.fq.includes(q))out.push({t:'Zone',n:z.name,rt:'',d:z.type,zn:z.name,tab:'ov'});
    z.records.forEach(r=>{if(out.length<2000&&(r.fq.includes(q)||String(r.d).toLowerCase().includes(q)))out.push({t:'Record',n:r.fq,rt:r.t,d:r.d,zn:z.name,tab:'rec',st:r})});
  });
  R.innerHTML=sec('sr','Search results',badge(fmt(out.length)+(out.length>=2000?'+':''),out.length?'ok':''),'<div class="gg"></div>',true);
  makeGrid(R.querySelector('.gg'),[{k:'t',t:'Kind'},{k:'n',t:'Name',brk:1},{k:'rt',t:'Type'},{k:'d',t:'Data',brk:1,sv:r=>ipN(r.d)>=0?ipN(r.d):lc(r.d)},{k:'zn',t:'Zone'},{k:'s',t:'State',f:r=>r.st?recState(r.st):''},
    {k:'go',t:'',f:r=>`<button data-zone="${esc(r.zn)}" data-tab="${r.tab}" data-q="${esc(q)}">Open &rsaquo;</button>`}],out,{search:false,empty:'No results',max:500});
}

/* ---------- page ---------- */
const real=D.zones.filter(z=>!z.auto);
const recTot=real.reduce((a,z)=>a+(+z.total||0),0),staleTot=real.reduce((a,z)=>a+z.c.stale,0),dynTot=real.reduce((a,z)=>a+z.c.dyn,0);
const tOk=D.tests.filter(t=>t.ok).length,fOk=D.forwarders.filter(f=>f.ok).length;
const zSt=z=>z.shutdown?'crit':z.sev;
$('#sub').innerHTML=`${esc(D.server)} &middot; ${esc(D.generated)}`;
if(D.demo)$('#demo').innerHTML='<span class="demo">DEMO DATA</span>';
$('#ft').innerHTML=`DNS Analyzer by <b>Starkark98</b> &middot; ${esc(D.server)} &middot; generated ${esc(D.generated)} &middot; read-only report`;

const scavCls=S.scavOn===false&&agingZ.length?'warn':S.scavOn==null?'info':'ok';
const K=[
  ['Zones',`${real.filter(z=>z.type==='Primary').length} primary / ${real.length}`,real.some(z=>zSt(z)==='crit')?'crit':'ok','zones'],
  ['Resource records',fmt(recTot),'ok','zones'],
  ['Stale records',`${fmt(staleTot)}${dynTot?' <small class="mut">('+pct(staleTot,dynTot)+'%)</small>':''}`,staleTot?(pct(staleTot,dynTot)>=20?'warn':'info'):'ok','zones'],
  ['Live tests',D.scanned?`${tOk} / ${D.tests.length} OK`:'not run',!D.scanned?'info':tOk<D.tests.length?'crit':'ok','res'],
  ['Forwarders',D.forwarders.length?`${fOk} / ${D.forwarders.length} answer`:S.fwdIps.length?String(S.fwdIps.length):'None',!D.forwarders.length?'info':fOk===0?'crit':fOk<D.forwarders.length?'warn':'ok','res'],
  ['Log problems (7 days)',LG?fmt(logProb):'n/a',!LG?'info':evCrit?'crit':evErr?'warn':logProb?'info':'ok','logs'],
  ['Scavenging',S.scavOn==null?'n/a':S.scavOn?'On':'Off',scavCls,'config'],
  ['Issues',I.length,nC?'crit':nW?'warn':'ok','issues']
];
let h='<div class="kpi">'+K.map(k=>`<div class="k ${k[2]}" data-go="${k[3]}"><span>${k[0]}</span><b class="${k[4]||''}">${k[1]}</b></div>`).join('')+'</div><div id="sres"></div>';

h+=sec('issues','Issues',badge(I.length,nC?'crit':nW?'warn':'ok'),
  chips('isf',[['all','All',I.length],['crit','Critical',nC],['warn','Warnings',nW],['info','Info',nI]])+'<div id="isl"></div>',I.length>0);

const zc=f=>D.zones.filter(ZF[f]).length;
h+=sec('zones','Zones',badge(real.length),
  chips('zf',[['all','All',zc('all')],['att','Needs attention',zc('att')],['fwd','Forward',zc('fwd')],['rev','Reverse',zc('rev')],['cf','Forwarders &amp; stubs',zc('cf')],['auto','Auto-created',zc('auto')]])+
  `<div class="wrap"><table><thead><tr><th></th><th>Zone</th><th>Type / storage</th><th>Dynamic updates</th><th class="num">Records</th><th>Stale</th><th>Aging</th><th>Zone transfers</th><th>Name servers</th></tr></thead><tbody id="zt"></tbody></table></div>
  <div class="mut hint">Click a zone to see its records, problems, name servers and liveness checks.</div>`,true);

function resBody(){
  const cf=D.zones.filter(z=>z.type==='Forwarder');
  let b=`<div class="kv">${kv('Recursion',yn(S.recursion,'Enabled','Disabled'))}${kv('Forwarders',S.fwdIps.length?esc(S.fwdIps.join(', ')):'None')}${kv('Use root hints if forwarders fail',yn(S.useRoot,'Yes','No'))}${kv('Forwarder timeout',S.fwdTimeout?S.fwdTimeout+' s':'n/a')}${kv('Root hints',S.rootN!=null?plural(S.rootN,'server'):'n/a')}${kv('Test name',esc(D.extName||''))}</div>`;
  b+='<h3>Live tests</h3>'+(D.scanned?(D.tests.length?`<div class="wrap"><table><thead><tr><th>Test</th><th>Query</th><th>Result</th><th class="num">Time</th><th>Answer / error</th></tr></thead><tbody>${D.tests.map(t=>`<tr><td><b>${esc(t.name)}</b></td><td>${esc(t.query)}</td><td>${res(t)}</td><td class="num">${t.ms} ms</td><td>${esc(t.res||t.err)}</td></tr>`).join('')}</tbody></table></div>`:'<div class="mut">No tests applicable.</div>')
    :'<div class="mut">Live tests were not run (option disabled or -SkipLiveTests).</div>');
  b+='<h3>Forwarders</h3>'+(D.forwarders.length?`<div class="wrap"><table><thead><tr><th>Forwarder</th><th>Result</th><th class="num">Time</th><th>Answer / error</th></tr></thead><tbody>${D.forwarders.map(f=>`<tr><td><b>${esc(f.ip)}</b></td><td>${res(f)}</td><td class="num ${f.ok&&f.ms>300?'twarn':''}">${f.ms} ms</td><td>${esc(f.res||f.err)}</td></tr>`).join('')}</tbody></table></div>`
    :`<div class="mut">${S.fwdIps.length?'Forwarders were not tested.':'No forwarders configured: external names are resolved through the root hints.'}</div>`);
  b+='<h3>Conditional forwarders</h3>'+(cf.length?`<div class="wrap"><table><thead><tr><th>Domain</th><th>Servers</th><th>Storage</th><th>Result</th></tr></thead><tbody>${cf.map(z=>`<tr><td><a data-zone="${esc(z.name)}" data-tab="ns">${esc(z.name)}</a></td><td>${esc(z.masters.join(', '))}</td><td>${store(z)}</td>
    <td>${z.fwdTest.length?z.fwdTest.map(t=>esc(t.ip)+' '+res(t)).join('<br>'):'<span class="mut">not tested</span>'}</td></tr>`).join('')}</tbody></table></div>`:'<div class="mut">No conditional forwarders.</div>');
  if(D.rootHints.length)b+=`<h3>Root hints</h3><div class="kv">${D.rootHints.map(r=>kv(esc(r.name),esc(r.ips)||'<span class="mut">no address</span>')).join('')}</div>`;
  return b;
}
const fwCls=!D.forwarders.length?'':fOk===0?'crit':fOk<D.forwarders.length?'warn':'ok';
const tCls=!D.scanned?'':tOk<D.tests.length?'crit':'ok';
h+=sec('res','Resolution and forwarders',badge(D.scanned?`${tOk+fOk} / ${D.tests.length+D.forwarders.length} OK`:'not tested',tCls==='crit'||fwCls==='crit'?'crit':fwCls==='warn'?'warn':D.scanned?'ok':''),resBody(),tCls==='crit'||fwCls==='crit'||fwCls==='warn');

const ADT={512:'Zone added',513:'Zone deleted',514:'Zone updated',515:'Record created',516:'Record deleted',517:'Record set deleted',518:'Node deleted',519:'Record created (dynamic)',520:'Record deleted (dynamic)',521:'Record scavenged'};
const CAT={manual:['Record change','warn'],zone:['Zone change','info'],server:['Server change','info']};
const LVL={1:['Critical','crit'],2:['Error','crit'],3:['Warning','warn']};
const EVH={404:'Port 53 could not be opened: another service may be using it, or a configured IP address is missing',407:'Port 53 could not be opened on an address: check the listening interfaces',408:'Port 53 could not be opened on an address: check the listening interfaces',
  4000:'The DNS server cannot open Active Directory: check AD DS on this DC (dcdiag, repadmin)',4004:'Zone enumeration in AD failed: check AD DS health',4007:'An AD-integrated zone could not be loaded: check AD DS and replication',
  4013:'Waiting for the initial AD synchronization: normal right after a reboot, a problem if it persists (check replication)',4015:'Critical error from Active Directory: check AD DS health and replication (dcdiag, repadmin /showrepl)',
  4016:'LDAP timeout talking to Active Directory',4510:'A record could not be written to Active Directory',4511:'A record could not be written to Active Directory',4512:'A zone could not be written to Active Directory',
  5501:'Malformed packet received: investigate if frequent from the same client',5504:'Invalid domain name in a received packet: usually a misbehaving client, investigate if frequent',
  6527:'A secondary or stub zone expired: check the master servers and zone transfers',6702:'The server could not update its own records on other DNS servers: check their reachability and permissions',
  7062:'A packet was sent to the server itself: check forwarders and delegations for loops'};
function logsBody(){
  if(!LG)return '<div class="mut">Logs were not collected.</div>';
  const C=[['dyn','Dynamic updates'],['manual','Record changes','warn'],['scav','Scavenged'],['zone','Zone changes','info'],['server','Server changes','info'],['err','Errors','crit'],['warn','Warnings','warn']];
  const td=(v,c,b)=>`<td class="num${c&&v?' t'+c:''}"${b?' style="font-weight:600"':''}>${v?fmt(v):'<span class="mut">0</span>'}</td>`;
  const note=[LG.auditErr?'Audit log could not be read: '+esc(LG.auditErr)+' (the change columns stay at 0).':'',LG.eventsErr?'DNS Server event log could not be read: '+esc(LG.eventsErr)+'.':'',LG.auditCapped?'Audit log: only the latest 20,000 entries were read.':''].filter(Boolean).map(x=>`<div class="mut">${x}</div>`).join('');
  return `<h3>Daily activity</h3><div class="wrap"><table><thead><tr><th>Day</th>${C.map(c=>`<th class="num">${c[1]}</th>`).join('')}</tr></thead><tbody>${LG.days.map(d=>`<tr><td><span class="mut" style="display:inline-block;width:34px">${wday(d.day)}</span>${esc(d.day)}</td>${C.map(c=>td(+d[c[0]]||0,c[2])).join('')}</tr>`).join('')}<tr><td><b>Total</b></td>${C.map(c=>td(lt[c[0]],c[2],1)).join('')}</tr></tbody></table></div>${note}
    <h3>Changes made by administrators (audit log)</h3><div id="lgr"></div>
    <h3>DNS Server event log &ndash; critical, errors and warnings</h3><div id="lge"></div>`;
}
h+=sec('logs','Logs and events',`${badge(fmt(logProb),evCrit?'crit':evErr?'warn':logProb?'':'ok')} <span class="mut">last 7 days</span>`,logsBody(),evErr>0);

function statsBody(){
  if(!ST)return '<div class="mut">Statistics could not be read.</div>';
  const C=ST.c,keys=Object.keys(C);
  const g=(...n)=>{for(const x of n){const k=keys.find(k=>k.split('.').pop().toLowerCase()===x.toLowerCase());if(k!=null)return +C[k]}return null};
  const tq=g('TotalQueries'),sel=[['Total queries',tq],['Total responses',g('TotalResponses')],['NXDOMAIN (name does not exist)',g('NxDomain'),1],['SERVFAIL (server failure)',g('ServFail'),1],['Refused',g('Refused'),1],
    ['Recursive queries',g('TotalQuestionsRecursed','QueriesRecursed')],['Recursion failures',g('RecursionFailure','RecursionFailures')],['Recursion timeouts',g('TimedoutQueries','RecursionTimeOut','FinalTimeout')],
    ['Dynamic updates received',g('DynamicUpdateReceived')],['Dynamic updates rejected',g('DynamicUpdateRejected')],['Zone transfer requests',g('TransferRequestReceived')],['Zone transfer failures',g('TransferFailures','FailedTransfers')]].filter(x=>x[1]!=null);
  const rows=keys.map(k=>({g:k.split('.').slice(0,-1).join('.'),n:k.split('.').pop(),v:+C[k]}));
  return `<div class="kv">${ST.start?kv('Counting since (service start)',esc(ST.start)+' ('+ago(dAge(ST.start))+')'):''}${sel.map(x=>kv(x[0],fmt(x[1])+(x[2]&&tq?` <span class="mut">(${pct(x[1],tq)}% of queries)</span>`:''))).join('')}</div>
    <h3>All counters</h3><div id="stg"></div>`;
}
h+=sec('stats','Statistics',ST&&ST.start?`<span class="mut">since ${esc(ST.start)}</span>`:'',statsBody(),false);

h+=sec('config','Server configuration','',
  `<div class="kv">${kv('DNS Server service',S.service?(S.service==='Running'?'Running':'<span class="tcrit">'+esc(S.service)+'</span>')+(S.startType?' &middot; '+esc(S.startType):''):'n/a')}
  ${kv('DNS server version',S.version?esc(S.version):'n/a')}${kv('Read-only domain controller',yn(S.rodc,'Yes','No'))}
  ${kv('Listening on',S.listen.length?esc(S.listen.join(', ')):'All IP addresses'+(S.allIps.length?'<div class="mut">'+esc(S.allIps.join(', '))+'</div>':''))}
  ${kv('Recursion',yn(S.recursion,'Enabled','Disabled')+(S.recTimeout?' &middot; timeout '+S.recTimeout+' s':''))}${kv('Secure responses',yn(S.secureResp,'Enabled','Disabled'))}
  ${kv('Scavenging',S.scavOn==null?'n/a':S.scavOn?'Enabled &middot; every '+esc(S.scavInt):'<span class="'+(agingZ.length?'twarn':'')+'">Disabled</span>')}
  ${kv('Last scavenging',S.lastScav?esc(S.lastScav)+' ('+ago(dAge(S.lastScav))+')':'never')}${kv('Default aging (new zones)',S.scavNoRef?'no-refresh '+esc(S.scavNoRef)+', refresh '+esc(S.scavRef):'n/a')}
  ${kv('Cache',S.cacheMaxKB==null?'n/a':(S.cacheMaxKB?fmt(S.cacheMaxKB)+' KB max':'No size limit')+(S.cacheMaxTtl?' &middot; max TTL '+esc(S.cacheMaxTtl):''))}
  ${kv('Cache pollution protection',yn(S.pollution,'Enabled','<span class="twarn">Disabled</span>'))}${kv('Cache locking',S.locking==null?'n/a':S.locking+'%')}
  ${kv('Global query block list',S.gqblOn==null?'n/a':S.gqblOn?'Enabled'+(S.gqbl?' &middot; '+esc(S.gqbl):''):'Disabled')}
  ${kv('Response rate limiting',esc(S.rrl)||'n/a')}${kv('Round robin',yn(S.roundRobin,'Enabled','Disabled'))}${kv('DNSSEC validation',yn(S.dnssec,'Enabled','Disabled'))}
  ${kv('Debug logging',S.debugLog==null?'n/a':S.debugLog?'<span class="twarn">Enabled</span>'+(S.debugPath?' &middot; '+esc(S.debugPath):''):'Disabled')}
  ${kv('Server-level plugin DLL',S.plugin?'<span class="tcrit">'+esc(S.plugin)+'</span>':'None')}</div>`,false);

$('#m').innerHTML=h;
renderIssues('all');renderZones('all');
if(LG&&$('#lgr'))makeGrid($('#lgr'),[{k:'time',t:'Time'},{k:'id',t:'Event',sv:r=>r.id,f:r=>{const c=CAT[r.cat]||['Change','mut'];return `<span class="pill ${c[1]}">${esc(ADT[r.id]||c[0])}</span> <span class="mut">${r.id}</span>`}},
  {k:'zone',t:'Zone',f:r=>r.zone&&D.zones.some(z=>z.name===r.zone)?`<a data-zone="${esc(r.zone)}">${esc(r.zone)}</a>`:esc(r.zone)},{k:'user',t:'User'},{k:'msg',t:'Details'}],LG.rows,{empty:LG.auditErr?'Audit log not available':'No manual changes in the last 7 days'});
if(LG&&$('#lge'))makeGrid($('#lge'),[{k:'level',t:'Level',sv:r=>r.level,f:r=>{const l=LVL[r.level]||['Info','mut'];return `<span class="pill ${l[1]}">${l[0]}</span>`}},{k:'id',t:'Event ID',sv:r=>r.id,num:1},
  {k:'count',t:'Count',sv:r=>r.count,num:1},{k:'first',t:'First'},{k:'last',t:'Last'},{k:'msg',t:'Message',f:r=>esc(r.msg)+(EVH[r.id]?`<div class="mut" style="margin-top:4px">&#9432; ${EVH[r.id]}</div>`:'')}],LG.events,{empty:LG.eventsErr?'Event log not available':'No errors or warnings in the last 7 days'});
if(ST&&$('#stg'))makeGrid($('#stg'),[{k:'g',t:'Group'},{k:'n',t:'Counter'},{k:'v',t:'Value',num:1,sv:r=>r.v,f:r=>fmt(r.v)}],Object.keys(ST.c).map(k=>({g:k.split('.').slice(0,-1).join('.'),n:k.split('.').pop(),v:+ST.c[k]})),{empty:'No counters'});

/* ---------- interactions ---------- */
document.addEventListener('click',e=>{
  let t;
  if((t=e.target.closest('.sec>h2'))){t.parentNode.classList.toggle('open');return}
  if((t=e.target.closest('[data-zone]'))){openZone(t.dataset.zone,t.dataset.tab,t.dataset.q);return}
  if((t=e.target.closest('[data-go]'))){const s=document.getElementById(t.dataset.go);s.classList.add('open');s.scrollIntoView({behavior:'smooth',block:'start'});return}
  if((t=e.target.closest('.chips[data-for] button'))){const p=t.parentNode;p.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b===t));(p.dataset.for==='isf'?renderIssues:renderZones)(t.dataset.f);return}
  if((t=e.target.closest('tr.sc'))){toggleZone(t)}
});
$('#bx').onclick=()=>document.querySelectorAll('.sec').forEach(s=>s.classList.add('open'));
$('#bc').onclick=()=>document.querySelectorAll('.sec').forEach(s=>s.classList.remove('open'));
let tmr;$('#q').oninput=e=>{clearTimeout(tmr);tmr=setTimeout(()=>search(e.target.value),250)};
document.addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();$('#q').focus()}});
</script></body></html>
'@

# =============================================================================
#  REPORT OUTPUT
# =============================================================================
# '<' only occurs inside JSON strings: \u003c keeps names like "</script>" or "<!--" from breaking the page.
# The CSP allows only this exact script: its SHA-256 is computed on the final page, with LF line ends as the browser
# sees it, and the placeholder is replaced only before the script (data can never reach it).
function Build-Html([string]$json) {
    $html = $Template.Replace('__ICON__', $IconPng).Replace('__DATA__', $json.Replace('<', '\u003c')).Replace("`r`n", "`n")
    $i = $html.IndexOf('<script>'); $j = $html.IndexOf('</script>', $i)
    $code = [Text.UTF8Encoding]::new($false).GetBytes($html.Substring($i + 8, $j - $i - 8))
    $hash = [Convert]::ToBase64String([Security.Cryptography.SHA256]::Create().ComputeHash($code))
    $html.Substring(0, $i).Replace('__SCRIPT_HASH__', $hash) + $html.Substring($i)
}
# Full path of the requested report. A folder (existing, or written with a trailing '\') means "default name in that folder"
function Resolve-OutHtml([string]$path) {
    if (-not $path) { return '' }
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path.Trim())
    if ($path.EndsWith('\') -or (Test-Path -LiteralPath $path -PathType Container)) { return $path.TrimEnd('\') + '\' }
    if ([IO.Path]::GetExtension($path) -notin '.html', '.htm') { throw "-OutHtml must be a folder or a file ending in .html or .htm: $path" }
    $path
}
function Save-Report([string]$json, [string]$server, [string]$path) {
    $name = "DnsReport_{0}_{1}.html" -f ($server -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd_HHmmss)
    $path = Resolve-OutHtml $path
    if (-not $path) { $path = Join-Path $env:TEMP $name }
    elseif ($path.EndsWith('\')) { $path = Join-Path $path $name }
    $dir = Split-Path $path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -Path $dir -ItemType Directory -Force) }
    [IO.File]::WriteAllText($path, (Build-Html $json), [Text.UTF8Encoding]::new($false))
    $path
}
function Find-Browser {
    $cands = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )
    foreach ($exe in 'msedge.exe', 'chrome.exe', 'firefox.exe') {
        try { $cands += (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exe" -ErrorAction Stop).'(default)' } catch { }
    }
    $cands | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
function Open-Report([string]$path) {
    $b = Find-Browser
    if (-not $b) { return $false }
    Start-Process -FilePath $b -ArgumentList "`"$path`""
    return $true
}
function Show-Message([string]$text, [string]$icon = 'Warning') {
    try { Add-Type -AssemblyName PresentationFramework; [void][Windows.MessageBox]::Show($text, 'DNS Analyzer', 'OK', $icon) }
    catch { Write-Warning $text }
}
# Last-resort handler: the launchers start PowerShell with a hidden console, so an unexpected error would otherwise vanish silently
trap {
    if ($NoGui) { break }
    Show-Message "$AppName stopped because of an unexpected error:`n$($_.Exception.Message)" 'Error'
    break
}
$NoBrowserMsg = "Report created, but no modern browser (Edge, Chrome or Firefox) was found on this PC: Internet Explorer cannot display the dashboard. Use 'Save as' or 'Show in folder' and open the file on a PC with Edge or Chrome, or run DNS Analyzer from your workstation with the RSAT DNS tools."

# =============================================================================
#  DEMO AND COMMAND-LINE MODES
# =============================================================================
if ($Demo) {
    try {
        $path = Save-Report ((New-DemoData) | ConvertTo-Json -Depth 8 -Compress) 'DEMO' $OutHtml
        Write-Host "Demo dashboard: $path" -ForegroundColor Green
        if ($NoOpen) { return }
        if (-not (Open-Report $path)) {
            try { Start-Process explorer.exe "/select,`"$path`"" } catch { }
            Show-Message "The demo dashboard was created, but no modern browser (Edge, Chrome or Firefox) was found on this PC. Internet Explorer cannot display it.`n`nThe file is now selected in File Explorer: copy it to a PC with Edge or Chrome and open it there.`n`n$path"
        }
    } catch { Show-Message "The demo could not be created:`n$($_.Exception.Message)" 'Error' }
    return
}

if ($NoGui) {
    while (-not $DnsServer) { $DnsServer = (Read-Host 'DNS server name').Trim() }
    $sync = [hashtable]::Synchronized(@{ Status = ''; Progress = 0; Done = $false; Error = $null; Json = $null })
    Write-Host "Analyzing $DnsServer..." -ForegroundColor Cyan
    & $Collector $DnsServer (-not $SkipLiveTests) $ExternalName $sync
    if ($sync.Error) { Write-Error $sync.Error; return }
    $path = Save-Report $sync.Json $DnsServer $OutHtml
    Write-Host "Dashboard: $path" -ForegroundColor Green
    if (-not $NoOpen -and -not (Open-Report $path)) { Write-Warning $NoBrowserMsg }
    return
}

# =============================================================================
#  GRAPHICAL INTERFACE
# =============================================================================
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
$relArgs = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`" -NoElevate"
if ($DnsServer) { $relArgs += " -DnsServer `"$DnsServer`"" }
if ($SkipLiveTests) { $relArgs += ' -SkipLiveTests' }
if ($PSBoundParameters.ContainsKey('ExternalName')) { $relArgs += " -ExternalName `"$ExternalName`"" }
# Resolved now: the elevated process starts in System32, where a relative path would point somewhere else
if ($OutHtml) { $OutHtml = Resolve-OutHtml $OutHtml; $relArgs += " -OutHtml `"$($OutHtml -replace '\\$', '\\')`"" }
if (-not $isAdmin -and -not $NoElevate) {
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $relArgs; return }
    catch { }   # UAC declined: continue without elevation
}
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Start-Process powershell.exe -ArgumentList $relArgs
    return
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DNS Analyzer - by Starkark98" Width="540" SizeToContent="Height" WindowStartupLocation="CenterScreen"
        ResizeMode="CanMinimize" Background="#F4F5F7" FontFamily="Segoe UI" FontSize="13">
  <Border Margin="16" Padding="24" Background="White" CornerRadius="10">
    <StackPanel>
      <Grid Margin="0,0,0,20">
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Image x:Name="ImgLogo" Width="68" Height="68" Margin="0,0,16,0" VerticalAlignment="Center" RenderOptions.BitmapScalingMode="HighQuality"/>
        <StackPanel Grid.Column="1" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="DNS Analyzer" FontSize="24" FontWeight="SemiBold" Foreground="#1F2328"/>
            <TextBlock Text="by Starkark98" FontSize="13" FontStyle="Italic" Foreground="#2563EB" VerticalAlignment="Bottom" Margin="8,0,0,5"/>
            <TextBlock x:Name="TxtVer" FontSize="11" Foreground="#9CA3AF" VerticalAlignment="Bottom" Margin="8,0,0,6"/>
          </StackPanel>
          <TextBlock Text="Read-only health check of zones, records, scavenging, zone transfers, forwarders and server settings."
                     Foreground="#6B7280" TextWrapping="Wrap" Margin="0,4,0,0"/>
        </StackPanel>
      </Grid>
      <TextBlock Text="DNS server" FontWeight="SemiBold" Foreground="#1F2328"/>
      <ComboBox x:Name="CmbServer" IsEditable="True" FontSize="15" Padding="6" Margin="0,6,0,14"/>
      <CheckBox x:Name="ChkScan" IsChecked="True" Foreground="#1F2328">
        <TextBlock TextWrapping="Wrap">Run live tests: name servers, forwarders, resolution, liveness of static and stale records (DNS queries, ping, ports)</TextBlock>
      </CheckBox>
      <TextBlock Text="Takes a few extra minutes. ARP works only for subnets this PC is connected to."
                 Foreground="#6B7280" FontSize="12" TextWrapping="Wrap" Margin="22,2,0,0"/>
      <Button x:Name="BtnRun" Content="Analyze" Height="40" Margin="0,22,0,0" FontSize="15" FontWeight="SemiBold"
              IsDefault="True" Background="#2563EB" Foreground="White" BorderThickness="0" Cursor="Hand"/>
      <Button x:Name="BtnDemo" Content="No server at hand? Try the demo with sample data" Margin="0,10,0,0" Padding="0,4"
              Background="Transparent" BorderThickness="0" Foreground="#2563EB" Cursor="Hand" HorizontalAlignment="Center"/>
      <ProgressBar x:Name="Bar" Height="8" Margin="0,14,0,0" Minimum="0" Maximum="100" Visibility="Collapsed" Foreground="#2563EB"/>
      <TextBox x:Name="TxtStatus" Margin="0,8,0,0" Foreground="#4B5563" TextWrapping="Wrap" IsReadOnly="True"
               BorderThickness="0" Background="Transparent" Padding="0"/>
      <WrapPanel x:Name="PnlDone" Margin="0,14,0,0" Visibility="Collapsed">
        <Button x:Name="BtnOpen" Content="Open dashboard" Padding="14,6" Margin="0,0,8,0" Cursor="Hand"/>
        <Button x:Name="BtnSave" Content="Save as..." Padding="14,6" Margin="0,0,8,0" Cursor="Hand"/>
        <Button x:Name="BtnFolder" Content="Show in folder" Padding="14,6" Cursor="Hand"/>
      </WrapPanel>
    </StackPanel>
  </Border>
</Window>
'@

try { $win = [Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($xaml)) }
catch { Show-Message "DNS Analyzer could not open its window:`n$($_.Exception.Message)" 'Error'; return }
$ui  = @{}
'CmbServer', 'ChkScan', 'BtnRun', 'BtnDemo', 'Bar', 'TxtStatus', 'PnlDone', 'BtnOpen', 'BtnSave', 'BtnFolder', 'TxtVer' | ForEach-Object { $ui[$_] = $win.FindName($_) }
$ui.TxtVer.Text = "v$AppVersion"
function ConvertTo-Image([string]$b64) {
    $bi = [Windows.Media.Imaging.BitmapImage]::new()
    $bi.BeginInit(); $bi.StreamSource = [IO.MemoryStream]::new([Convert]::FromBase64String($b64)); $bi.CacheOption = 'OnLoad'; $bi.EndInit(); $bi.Freeze()
    $bi
}
try { $win.Icon = ConvertTo-Image $IconPng; $win.FindName('ImgLogo').Source = ConvertTo-Image $LogoPng } catch { }   # cosmetic only

$cfgDir   = Join-Path $env:APPDATA 'DnsAnalyzer'
$lastFile = Join-Path $cfgDir 'last.txt'
$script:report = $null; $script:job = $null

function Set-Status([string]$text, [bool]$isError = $false) {
    $ui.TxtStatus.Text = $text
    $ui.TxtStatus.Foreground = if ($isError) { [Windows.Media.Brushes]::Firebrick } else { [Windows.Media.Brushes]::DimGray }
}
function Set-Busy([bool]$busy) {
    $ui.CmbServer.IsEnabled = -not $busy; $ui.ChkScan.IsEnabled = -not $busy
    $ui.BtnRun.IsEnabled = -not $busy; $ui.BtnDemo.IsEnabled = -not $busy
    $ui.Bar.Visibility = if ($busy) { 'Visible' } else { 'Collapsed' }
    if ($busy) { $ui.PnlDone.Visibility = 'Collapsed'; $ui.Bar.Value = 0 }
}
function Show-Report([string]$okText) {
    $ui.PnlDone.Visibility = 'Visible'
    if (Open-Report $script:report) { Set-Status $okText } else { Set-Status $NoBrowserMsg $true }
}

# Domain controllers of the current domain + DNS servers configured on this PC + last server used
$win.Add_ContentRendered({
    $names = [Collections.Generic.List[string]]::new()
    try { [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object { $names.Add("$($_.Name)") } } catch { }
    try { Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object { $_.ServerAddresses } | ForEach-Object { $names.Add("$_") } } catch { }
    $names | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { [void]$ui.CmbServer.Items.Add($_) }
    if (-not (Get-Module -ListAvailable DnsServer)) { Set-Status 'DnsServer module not found: install the RSAT "DNS Server Tools" to analyze a server. The demo works anyway.' $true }
})
if ($DnsServer) { $ui.CmbServer.Text = $DnsServer }
elseif (Test-Path -LiteralPath $lastFile) { try { $last = "$(Get-Content -LiteralPath $lastFile -Raw)".Trim(); if ($last -match '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,252}$') { $ui.CmbServer.Text = $last } } catch { } }
if ($SkipLiveTests) { $ui.ChkScan.IsChecked = $false }

$timer = [Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromMilliseconds(250)
$timer.Add_Tick({
    try {
        $ui.Bar.Value = $script:sync.Progress
        if ($script:sync.Status) { Set-Status $script:sync.Status }
        if (-not $script:sync.Done) { return }
        $timer.Stop()
        try { [void]$script:job.EndInvoke($script:handle) } catch { }
        $script:job.Dispose(); $script:job = $null
        Set-Busy $false
        if ($script:sync.Error) { Set-Status "Error: $($script:sync.Error)" $true; return }
        $script:report = Save-Report $script:sync.Json $script:srv $OutHtml
        Show-Report 'Analysis completed. Dashboard opened in your browser.'
    } catch { $timer.Stop(); Set-Busy $false; Set-Status "Error: $($_.Exception.Message)" $true }
})

$ui.BtnRun.Add_Click({
    try {
        $srv = "$($ui.CmbServer.Text)".Trim()
        if (-not $srv) { Set-Status 'Enter the DNS server name.' $true; return }
        if ($srv -notmatch '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,252}$') { Set-Status 'Invalid server name: use only letters, digits, dots, hyphens (or an IP address).' $true; return }
        try { if (-not (Test-Path $cfgDir)) { [void](New-Item $cfgDir -ItemType Directory) }; Set-Content $lastFile $srv } catch { }
        Set-Busy $true
        $script:srv    = $srv
        $script:sync   = [hashtable]::Synchronized(@{ Status = 'Starting analysis...'; Progress = 0; Done = $false; Error = $null; Json = $null })
        $script:job    = [powershell]::Create()
        [void]$script:job.AddScript($Collector.ToString()).AddArgument($srv).AddArgument([bool]$ui.ChkScan.IsChecked).AddArgument($ExternalName).AddArgument($script:sync)
        $script:handle = $script:job.BeginInvoke()
        $timer.Start()
    } catch { Set-Busy $false; Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnDemo.Add_Click({
    try {
        $script:report = Save-Report ((New-DemoData) | ConvertTo-Json -Depth 8 -Compress) 'DEMO' $null
        Show-Report 'Demo dashboard opened in your browser (fictitious data).'
    } catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnOpen.Add_Click({
    try { if ($script:report -and -not (Open-Report $script:report)) { Set-Status $NoBrowserMsg $true } }
    catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnFolder.Add_Click({
    try { if ($script:report) { Start-Process explorer.exe "/select,`"$script:report`"" } }
    catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnSave.Add_Click({
    try {
        if (-not $script:report) { return }
        $dlg = [Microsoft.Win32.SaveFileDialog]::new()
        $dlg.Filter = 'HTML dashboard (*.html)|*.html'; $dlg.FileName = [IO.Path]::GetFileName($script:report)
        if ($dlg.ShowDialog($win)) {
            if ($dlg.FileName -ne $script:report) { Copy-Item $script:report $dlg.FileName -Force }
            Set-Status "Saved to $($dlg.FileName)"
        }
    } catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$win.Add_Closing({ if ($script:job) { try { $script:job.Stop(); $script:job.Dispose() } catch { } } })

[void]$win.ShowDialog()
