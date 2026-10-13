# KQL Query Library

Every query used in this project, in the order you run them. Queries marked **(lab baseline)** come from the Cyber Range lab. Everything else is an extension written for this project.

Run all of them in Microsoft Sentinel → Logs (or Defender portal → Advanced hunting, where noted).

> Schema note: Threat intelligence moved to the `ThreatIntelIndicators` and `ThreatIntelObjects` tables. Older workspaces still have `ThreatIntelligenceIndicator`. If a column below is missing, run `ThreatIntelIndicators | take 1` and compare against your schema.

---

## Phase 1. Know what intelligence you actually have

### 1.1 What indicator types exist? (extension)

You cannot match what you have not inventoried. Always start here.

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(30d)
| summarize Indicators = dcount(ObservableValue), Active = countif(IsActive == true) by ObservableKey, SourceSystem
| order by Indicators desc
```

### 1.2 Built-in IPv4 indicators exist (lab baseline)

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(7d)
| where IsActive == true
| where ObservableKey == "network-traffic:src_ref.value"
| project TimeGenerated, SourceSystem, ObservableValue, ObservableKey, ValidUntil, Confidence
| order by TimeGenerated desc
```

Expected: rows from the Microsoft threat intelligence feed.

### 1.3 Built-in file hash indicators exist (extension)

The lab heading talks about file hashes but the lab queries only use IPs. This closes the gap.

```kql
ThreatIntelIndicators
| where TimeGenerated > ago(14d)
| where IsActive == true
| where ObservableKey has "hashes"
| summarize Count = dcount(ObservableValue) by ObservableKey, SourceSystem
```

Expected: keys such as `file:hashes.'SHA-256'`. Use the exact key you see in your tenant in later queries.

### 1.4 Indicator hygiene: duplicates and expiry (extension)

Sentinel stores every update to an indicator as a new row. Always collapse to the latest version, and never match expired intel.

```kql
let LatestIndicators = ThreatIntelIndicators
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now();
LatestIndicators
| summarize Active = count(), ExpiringIn7Days = countif(ValidUntil < now() + 7d) by SourceSystem
```

Why it matters: stale indicators are the number one cause of noisy TI rules. A residential IP that was a botnet node six months ago may belong to a real customer today.

---

## Phase 2. Find suspicious IPs in your own telemetry

### 2.1 Brute force sources (lab baseline)

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize Count = count() by RemoteIP, ActionType
| order by Count desc
```

### 2.2 Same query, but built to produce a defensible indicator (extension)

Adds volume, distinct targets, time span and a public-IP filter. An IP that failed 700 times against 9 different devices is far more convincing than one that failed 12 times against one.

```kql
let startTime = ago(7d);
DeviceLogonEvents
| where TimeGenerated > startTime
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| summarize
    FailedLogons = count(),
    DistinctDevices = dcount(DeviceName),
    DistinctAccounts = dcount(AccountName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP
| where FailedLogons >= 10
| order by FailedLogons desc
```

Export this result as CSV (`RemoteIP`, `Count` columns needed by the script, rename `FailedLogons` to `Count` or edit the CSV header) and feed it to `scripts/ti_indicator_builder.py`.

### 2.3 Did the attacker ever succeed? (extension, critical)

A brute force source is an annoyance. A brute force source that later logged in is an incident.

```kql
let Attackers = DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where ActionType == "LogonFailed" and isnotempty(RemoteIP)
| summarize Failed = count() by RemoteIP
| where Failed >= 10;
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where ActionType == "LogonSuccess"
| join kind=inner Attackers on RemoteIP
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, Failed
| order by TimeGenerated asc
```

Expected on a healthy range: zero rows. Any row here is escalated immediately.

---

## Phase 3. Create and verify the indicator

Create the indicator in the portal (see RUNBOOK.md Phase 3), name it starting with `MaliciousFlows`.

### 3.1 Confirm the indicator landed (lab baseline, corrected)

The source lab filters on `Data.name == "Malicious Behavior"` in one place and tells you to use `MaliciousFlows` in another. This version uses one convention everywhere.

```kql
ThreatIntelIndicators
| where tostring(Data.name) startswith "MaliciousFlows"
| summarize arg_max(TimeGenerated, *) by Id
| project ObservableValue, ObservableKey, IsActive, Confidence, ValidUntil, Name = tostring(Data.name)
```

Expected: one row per indicator you added. Ingestion can take a few minutes. If zero rows after 10 minutes, see TROUBLESHOOTING in RUNBOOK.md.

---

## Phase 4. Match indicators against telemetry

### 4.1 Against network traffic (lab baseline, hardened)

Requires NSG flow logs with Traffic Analytics enabled (that populates `NTANetAnalytics`).

```kql
let BadIPs = ThreatIntelIndicators
| where TimeGenerated > ago(365d)
| where tostring(Data.name) startswith "MaliciousFlows"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now()
| project BadIP = ObservableValue;
NTANetAnalytics
| where TimeGenerated > ago(7d)
| where isnotempty(SrcPublicIps)
| extend FoundIPs = extract_all(@"(\d{1,3}(?:\.\d{1,3}){3})", SrcPublicIps)
| mv-expand RemoteIP = FoundIPs to typeof(string)
| join kind=inner BadIPs on $left.RemoteIP == $right.BadIP
| project TimeGenerated, RemoteIP, SrcIp, DestIp, DestPort, FlowDirection, FlowType, AllowedInFlows, DeniedInFlows, SrcPublicIps
| order by TimeGenerated desc
```

What changed from the lab and why:

- In real data, `SrcPublicIps` looks like `80.94.95.83|717|740|740...`: an IP followed by pipe separated counters, and possibly more IPs after it. An exact match on the whole string never succeeds. The regex pulls out every IPv4 address and ignores the counters.
- The lab's `split(SrcPublicIps,"|")[0]` works for the first IP only. The regex covers all IPs in the field.
- The lab used `toscalar(... make_set())`. A dynamic set is capped at about 1 MB, which a real feed can exceed. A join scales and carries confidence and source along for alert enrichment.
- Expired indicators are excluded.
- `DeniedInFlows` is included so you can see blocked attempts as well as allowed ones. Add `| where AllowedInFlows > 0` to see only traffic that got through.

Always inspect the real field first: `NTANetAnalytics | where isnotempty(SrcPublicIps) | take 5`. That is how this format was found.

---

### 4.2 Against logins (lab baseline, hardened and enriched)

```kql
let BadIPs = ThreatIntelIndicators
| where TimeGenerated > ago(365d)
| where tostring(Data.name) startswith "MaliciousFlows"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now()
| project BadIP = ObservableValue, Confidence, Name = tostring(Data.name), ValidUntil;
DeviceLogonEvents
| where TimeGenerated > ago(7d)
| join kind=inner BadIPs on $left.RemoteIP == $right.BadIP
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteIP, Confidence, Name
| order by TimeGenerated desc
```

### 4.3 Against Entra ID sign-ins (extension)

Intelligence is only useful where the attacker can touch you. Cloud identity is the other front door.

```kql
let BadIPs = ThreatIntelIndicators
| where TimeGenerated > ago(365d)
| where ObservableKey == "network-traffic:src_ref.value" or ObservableKey == "ipv4-addr:value"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now()
| project BadIP = ObservableValue, Confidence;
SigninLogs
| where TimeGenerated > ago(7d)
| join kind=inner BadIPs on $left.IPAddress == $right.BadIP
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, Confidence
```

Only works if SigninLogs is connected. Skip if you did not enable the Entra ID connector.

### 4.4 Against endpoint network connections, outbound (extension)

Inbound brute force is noise. An internal host talking OUT to a known bad IP is a much stronger signal (possible C2).

```kql
let BadIPs = ThreatIntelIndicators
| where TimeGenerated > ago(30d)
| where ObservableKey == "network-traffic:src_ref.value" or ObservableKey == "ipv4-addr:value"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now()
| project BadIP = ObservableValue, Confidence;
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| join kind=inner BadIPs on $left.RemoteIP == $right.BadIP
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, Confidence
```

---

## Phase 5. File hash matching (the lab 1 heading, finally delivered)

### 5.1 Hash match against file events and antivirus detections, SHA-256 and SHA-1 (extension)

Two lessons from testing on a real onboarded VM, both worth stating in an interview:

1. When Defender blocks or deletes a file on arrival, the evidence is an `AntivirusDetection` row in `DeviceEvents`. No normal `DeviceFileEvents` row may exist.
2. Those antivirus rows carry the **SHA-1** and leave `SHA256` empty. A SHA-256 indicator never matches them. Matching must cover every hash type the telemetry provides, and you may need an indicator for each hash type.

```kql
let BadHashes = ThreatIntelIndicators
| where TimeGenerated > ago(30d)
| where ObservableKey has "hashes"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now()
| project Hash = tolower(ObservableValue), Confidence, Source = SourceSystem;
let FileHits = DeviceFileEvents
| where TimeGenerated > ago(1h)
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, SHA1, ActionType, Table = "DeviceFileEvents";
let AvHits = DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "AntivirusDetection"
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, SHA1, ActionType, Table = "DeviceEvents";
union FileHits, AvHits
| extend Hash = pack_array(tolower(SHA256), tolower(SHA1))
| mv-expand Hash to typeof(string)
| where isnotempty(Hash)
| join kind=inner BadHashes on Hash
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType, Table, Hash, Confidence, Source
| order by TimeGenerated desc
```

Normalize case with `tolower()` on both sides. When testing, widen both `ago(1h)` values to `ago(1d)`, and add `| where DeviceName startswith "<your vm>"` after the union to avoid showing other users' devices in a shared workspace.

### 5.2 Proving the rule works with a known test hash (extension)

Built-in hashes are real malware, so a clean lab has zero matches. Use the EICAR antivirus test file, which is harmless and universally recognized. Import both files from `test-indicators/` (SHA-256 and SHA-1), because antivirus events carry SHA-1:

```
SHA-256  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
SHA-1    3395856ce81f2b7382dee72602f798b642f14140
```

Then follow RUNBOOK.md Phase 5. Never paste the EICAR string itself into a document in this repo, because antivirus will quarantine the file.

---

## Phase 6. The "so what" queries (extension)

### 6.1 Retrohunt: was the attacker already here before we knew? (extension)

Intelligence arrives late. This looks back 90 days with today's indicators. It is the single most valuable use of a new indicator.

```kql
let BadIPs = ThreatIntelIndicators
| where tostring(Data.name) startswith "MaliciousFlows"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true
| project BadIP = ObservableValue;
DeviceLogonEvents
| where TimeGenerated > ago(90d)
| join kind=inner BadIPs on $left.RemoteIP == $right.BadIP
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Attempts = count(), Successes = countif(ActionType == "LogonSuccess")
            by RemoteIP, DeviceName
| order by Attempts desc
```

### 6.2 Indicator effectiveness: which sources earn their keep? (extension)

```kql
let Hits = SecurityAlert
| where TimeGenerated > ago(30d)
| where AlertName startswith "TI Map"
| summarize AlertCount = count();
ThreatIntelIndicators
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by Id
| summarize ActiveIndicators = countif(IsActive == true), AvgConfidence = avg(toreal(Confidence)) by SourceSystem
| extend Note = "Compare with alert counts per rule. A source with thousands of indicators and zero hits is cost, not value."
```

Adjust the alert name prefix to match your rule names.

### 6.3 Allowlist so you never alert on yourself (extension)

Create a Watchlist named `TI-Allowlist` with a single column `IPAddress` (your office egress IP, vulnerability scanner, partner IPs). Then add this to any matching rule:

```kql
let Allow = _GetWatchlist('TI-Allowlist') | project IPAddress;
// ... then in the match query:
| where RemoteIP !in (Allow)
```

---

## Analytics rule: final versions

### Rule A. TI Map IP to Device Logon (MaliciousFlows)

- Name: `TI Map IP Entity to DeviceLogonEvents - MaliciousFlows`
- Severity: Medium (raise to High through alert details override when Confidence >= 80)
- Run query every: 5 minutes. Lookup data from the last: 1 hour (covers ingestion delay).
- Tactics: Credential Access (T1110), Initial Access (T1078, T1133)

```kql
let Allow = _GetWatchlist('TI-Allowlist') | project IPAddress;
let BadIPs = ThreatIntelIndicators
| where TimeGenerated > ago(365d)
| where tostring(Data.name) startswith "MaliciousFlows"
| summarize arg_max(TimeGenerated, *) by Id
| where IsActive == true and ValidUntil > now()
| project BadIP = ObservableValue, Confidence, IndicatorName = tostring(Data.name), ValidUntil;
DeviceLogonEvents
| where TimeGenerated > ago(1h)
| where RemoteIP !in (Allow)
| join kind=inner BadIPs on $left.RemoteIP == $right.BadIP
| extend Outcome = iff(ActionType == "LogonSuccess", "SUCCESS after known bad", "Failed attempt")
| extend Severity = case(ActionType == "LogonSuccess", "High", Confidence >= 80, "High", Confidence >= 50, "Medium", "Low")
| project TimeGenerated, DeviceName, AccountName, RemoteIP, ActionType, Outcome, Confidence, IndicatorName, Severity
```

Entity mapping: IP → `RemoteIP`, Host → `DeviceName` (HostName), Account → `AccountName` (Name).
Alert details override: Alert name format `TI Match: {{RemoteIP}} on {{DeviceName}}`, severity from column `Severity`.
Event grouping: group all events into a single alert. Alert grouping into incidents: by IP entity, 24 hours.

### Rule B. TI Map File Hash to DeviceFileEvents

- Name: `TI Map SHA256 to DeviceFileEvents`
- Severity: High
- Run every 5 minutes, lookup 1 hour
- Tactics: Execution (T1204.002), Defense Evasion

Query: Section 5.1 (both tables, both hash types). Entity mapping: Host → `DeviceName`, File hash → `SHA256` (Algorithm SHA256), Account → `InitiatingProcessAccountName`.

### Rule C. TI Map IP to outbound connection (C2 hunting)

- Name: `TI Map IP Entity to DeviceNetworkEvents (outbound)`
- Severity: High
- Query: Section 4.4 with `TimeGenerated > ago(1h)`.
- Tactics: Command and Control (T1071)
