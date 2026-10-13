# Threat Intelligence Concepts Applied in This Project

This is the "I understand it, not just clicked through it" document. Each concept is paired with the exact place in this project where it shows up. Use it to prepare for interviews.

## 1. Indicators are not intelligence

An indicator (an IP, hash, domain, URL) is raw data. Intelligence is data plus context: who, how confident, how fresh, how relevant to us, and what to do about it. This project adds context at every step (confidence, validity window, TLP, source, allowlist).

## 2. Types of threat intelligence

| Type | Audience | Example in this project |
|---|---|---|
| Strategic | Executives | Why brute force against exposed VMs matters to the business (meeting script) |
| Operational | SOC and hunters | Retrohunt query 6.1: was the attacker here before we knew |
| Tactical | Detection engineers | Analytics Rules A, B and C |
| Technical (IOCs) | Tools | The IPs and hashes themselves |

## 3. Third-party vs first-party intelligence

- Third-party: Microsoft's built-in feed (global, broad, mostly low match rate in a small environment).
- First-party: indicators you create from your own telemetry (high relevance, because the attacker has already touched you).

Lab 1 uses third-party. Lab 2 uses first-party. A mature program uses both. This is why a clean environment returns zero hits on global hash indicators: it is the expected, healthy outcome.

## 4. Pyramid of Pain

David Bianco's model: hashes are trivial for an attacker to change, IPs are easy, domains are annoying, tools and TTPs are painful. Implication for this project: hash and IP matching is useful for fast, cheap detection but expires quickly. That is why every indicator has a short `ValidUntil` and why the project also maps behavior to MITRE ATT&CK (MITRE-MAPPING.md).

## 5. Indicator lifecycle

Create → validate → enrich → deploy → monitor hit rate → expire or revoke. Query 1.4 and 6.2 implement the monitor and expire steps. An indicator without an expiry date becomes a false positive when the IP is reassigned to an innocent customer.

## 6. Confidence scoring

Confidence is the probability the indicator is truly malicious. This project's script uses a transparent rule: failure volume buckets, optionally blended with an external reputation score. Suggested interpretation:

| Confidence | Meaning | Rule behavior |
|---|---|---|
| 80 to 100 | Strong evidence | High severity incident |
| 50 to 79 | Probable | Medium severity |
| 1 to 49 | Weak, single source | Low severity or hunt only |

Confidence is different from severity. A low-confidence indicator that matches a successful logon on a domain controller is still urgent. Rule A reflects this: a successful logon raises severity regardless of confidence.

## 7. TLP (Traffic Light Protocol)

TLP says how far intelligence may be shared: RED (named recipients only), AMBER (your org and need-to-know partners), GREEN (community), CLEAR (public). Indicators generated from your own telemetry can reveal your environment, so the script marks them TLP:AMBER.

## 8. False positives and allowlisting

Shared infrastructure (cloud NAT, VPNs, security scanners, your own egress IP) can look malicious. The `TI-Allowlist` watchlist and the private-IP filter in the script prevent self-inflicted alerts. In an interview, say: "A TI rule that alerts on the CEO's home IP gets disabled within a week."

## 9. Ingestion delay and lookback windows

Logs arrive minutes after they are generated. A rule that runs every 5 minutes and looks back 5 minutes misses events that land late. Lookback of 1 hour with alert grouping is the standard compromise.

## 10. Retrohunting

New intelligence about old activity. Query 6.1 searches 90 days of history with today's indicators. This is how you discover that an attacker has been in the environment for weeks.

## 11. STIX and TAXII

STIX 2.1 is the standard JSON language for describing indicators. TAXII is the transport that servers use to share them. The script outputs STIX 2.1 so the indicators can move into any platform. Sentinel can also ingest from TAXII servers through its connectors (not used in this free lab, but you can describe how).

## 12. Detection coverage honesty

This project detects known-bad infrastructure. It does not detect a new attacker with fresh IPs. Pair it with behavioral detections (impossible travel, password spray analytics) for that. Saying so in an interview signals maturity.
