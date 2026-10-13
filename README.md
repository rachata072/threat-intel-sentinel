# Threat Intelligence in Microsoft Sentinel: From Raw Logs to Detection Rules

Turn Microsoft's built-in threat intelligence and your own telemetry into working, tuned Sentinel analytics rules. Built on the Cyber Range threat intelligence labs, then extended to show how threat intelligence is actually run in a SOC: lifecycle, confidence, expiry, allowlisting, retrohunting and measuring value.

**Author:** Rachata (Trey) Wichakkhapan | [LinkedIn](https://linkedin.com/in/treywcp) | [nexthophub.com](https://nexthophub.com)

## The problem

Security teams subscribe to threat feeds and then either ignore them or drown in alerts from them. Indicators go stale, shared IPs trigger false positives, nobody knows whether a feed ever caught anything, and when a new indicator arrives nobody checks whether the attacker was already inside last month.

## What this project does

| Capability | How |
|---|---|
| Inventory built-in intelligence | Queries 1.1 to 1.4 |
| Match global malware hashes and bad IPs to endpoint and network telemetry | Queries 1.2, 1.3, 4.1, 5.1 |
| Create first-party indicators from your own brute force telemetry | Queries 2.1, 2.2, portal or script |
| Automate indicator creation safely | `scripts/ti_indicator_builder.py` (validate, filter, score, STIX 2.1 output, audit CSV) |
| Prove a hash rule works in a clean environment | EICAR test hash (RUNBOOK Phase 5) |
| Detect if an attacker already succeeded | Query 2.3 |
| Look backward when new intelligence arrives | Retrohunt Query 6.1 |
| Alert in production-ready form | Three analytics rules with entity mapping, allowlist, dynamic severity |
| Measure value | Query 6.2 effectiveness |

## What I added beyond the lab

1. **Fixed lab inconsistencies.** The source lab names the indicator `MaliciousFlows` in one place and queries `Malicious Behavior` in another. This repo uses one naming convention.
2. **Delivered the file hash half of lab 1.** The lab heading says file hashes but its queries only use IPs.
3. **Hardened the matching logic.** Latest-version-only (`arg_max by Id`), expiry filtering, case-normalized hashes, and a join instead of a capped `make_set`.
4. **Checked all public IPs**, not only the first one in a multi-value field.
5. **Added a Python tool** that validates IPs, removes private and allow-listed addresses, scores confidence, optionally enriches from AbuseIPDB and outputs STIX 2.1 with TLP marking plus a review CSV for audit.
6. **Added the failed-then-succeeded check**, which separates annoyance from incident.
7. **Added outbound (C2) matching**, retrohunting and a TI effectiveness query.
8. **Documented the concepts** (Pyramid of Pain, TLP, confidence, lifecycle, STIX/TAXII) in TI-CONCEPTS.md.

## Architecture

```
 Microsoft TI feed (global) ─┐
                             ├─> ThreatIntelIndicators ──> KQL joins ──> Analytics rules ──> Incidents
 First-party indicators ─────┘         ^                      |
   (portal or STIX import)             |                      v
          ^                            |            DeviceLogonEvents, DeviceFileEvents,
          |                            |            DeviceNetworkEvents, NTANetAnalytics, SigninLogs
 ti_indicator_builder.py               |
          ^                            |
 Failed logon export <── Query 2.2 ────┘      Watchlist TI-Allowlist suppresses known good
```

## Repo contents

| File | Purpose |
|---|---|
| RUNBOOK.md | Step by step procedure, phases 0 to 7, with troubleshooting |
| KQL-QUERY-LIBRARY.md | Every query, plus final analytics rule definitions |
| TI-CONCEPTS.md | Threat intelligence concepts tied to this project |
| MITRE-MAPPING.md | ATT&CK mapping limited to what is actually detected |
| EVIDENCE.md | Screenshot checklist and results template |
| MEETING-SCRIPT.md | Stakeholder walkthrough: problem, fix, who is affected |
| scripts/ti_indicator_builder.py | Indicator builder (Python standard library only) |
| scripts/sample_failed_logons.csv | Sample input to test the script |

## Quick start

1. Confirm `ThreatIntelIndicators` returns rows in Sentinel.
2. Follow RUNBOOK.md Phase 0 through 7.
3. Test the script without any Azure access:

   ```
   python scripts/ti_indicator_builder.py --input scripts/sample_failed_logons.csv --allowlist scripts/allowlist.example.txt --outdir out
   ```

## Requirements and cost

- Azure/Sentinel/Defender for Endpoint environment from the Cyber Range course (the environment is the same one the original lab uses).
- Python 3.8+, no packages to install.
- AbuseIPDB free API key is optional.
- No additional cost beyond what the course environment already provides.

## Results

See EVIDENCE.md for screenshots and measured results.

## Limitations (stated honestly)

- This detects known-bad infrastructure. A new attacker with fresh IPs will not match. Pair with behavioral detections.
- The IPs in this lab come from internet background noise against exposed lab VMs, so they illustrate the method more than they represent a targeted adversary.
- Table names and portal screens change. Verify schema with `take 1` before assuming a column exists.
- The script handles IPv4 only in this version.

## Credits

Based on the Cyber Range threat intelligence labs (Josh Madakor's community). Extensions, tooling and documentation by the author.

## License

MIT
