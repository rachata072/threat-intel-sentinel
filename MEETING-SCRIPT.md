# Meeting Script: Operationalizing Threat Intelligence in Sentinel

**Format:** 15 minute briefing with Q&A.
**Presenter:** Jordan (SOC Analyst)
**Audience:** Priya (Security Lead), Marcus (IT Manager), Dana (Service Desk Lead), optionally a Finance/Operations representative.

---

## 1. Opening (1 minute)

Jordan: "Thanks for the time. In 15 minutes I want to show how we turn threat intelligence from a subscription into a working defense, what problem it solves, who is affected, and what I need from you."

## 2. The problem (3 minutes)

Jordan: "Today, three things are true.

First, we have a threat intelligence feed from Microsoft inside Sentinel, but nobody has confirmed what it contains or whether it ever matches anything.

Second, our internet-facing lab and test servers get hammered by password guessing from outside IP addresses every day. We see the failures in the logs, but we have no rule that treats a repeat offender differently from a typo.

Third, when we learn that an IP or a file hash is bad, we have no way to check whether it already touched us last month. Knowing about an attacker after the fact is only useful if we can look back."

Priya: "So what is the actual risk?"

Jordan: "A password guessing campaign that eventually succeeds. Without a rule tied to known-bad addresses, a successful login from one of them looks like a normal login."

## 3. What I built (4 minutes)

Jordan: "Five pieces.

One, an inventory of the built-in intelligence, so we know what we have, from whom, and when it expires.

Two, our own indicators. I pulled the most aggressive attacker addresses from our own failed logons, filtered out private and trusted addresses, scored confidence, and created indicators with an expiry date. A small Python tool does this and writes an audit file explaining every skip.

Three, matching rules that compare those indicators to device logons, file events, outbound connections and network flows.

Four, a retrohunt. When a new indicator arrives we automatically ask: was this already here in the last 90 days?

Five, an allowlist so we never alert on our own office address or our scanners."

Marcus: "Does this block anything?"

Jordan: "Not automatically. It creates incidents for review. Blocking is a separate change I would bring through change control with a recommendation to add a network deny rule for confirmed addresses."

## 4. Results (2 minutes)

Jordan: "Results from the lab: built-in global hash indicators produced zero matches, which is what a clean environment should show. To prove the rule works, I used the harmless EICAR test file hash and the rule detected it within minutes. Our own indicators matched the logon activity as expected, and I confirmed whether any of those addresses ever logged in successfully. [state result from EVIDENCE.md]."

## 5. Who is affected (2 minutes)

| Group | Impact |
|---|---|
| Security team (Priya, Jordan) | New incidents to triage, with the indicator name, confidence and affected device already attached |
| IT Operations (Marcus) | Occasional request to block an address or reset a credential. Expected volume: low |
| Service Desk (Dana) | Possible user lockout follow-up if a successful bad logon is found. Runbook provided |
| End users | No change to daily work. If a true compromise is found, a password reset |
| Finance/Operations | No added cost in the lab. In production, Sentinel ingestion volume is the cost driver |

## 6. Risks and mitigations (1 minute)

- False positives from shared infrastructure: allowlist watchlist and expiry dates.
- Stale intelligence: every indicator expires in 30 days by default.
- Coverage: this catches known-bad infrastructure only. We still need behavioral detections.

## 7. Ask (1 minute)

Jordan: "I need three decisions. Approve the three analytics rules for the production workspace. Agree on a 30 day indicator lifetime as our default. Nominate an owner for the monthly indicator review."

## 8. Anticipated questions

**Q: Why not just buy a bigger feed?**
A: More indicators without relevance creates noise. Query 6.2 measures value per source so we can justify or cut a feed.

**Q: How do you stop false positives on a partner's IP?**
A: Allowlist watchlist, reviewed monthly, and confidence-based severity.

**Q: What if an attacker uses a new IP?**
A: Then this will not catch it. That is why we pair it with behavior-based rules and a retrohunt when new intelligence arrives.

**Q: Is the Python script safe to run on production data?**
A: It uses only the standard library, makes no changes in Azure, and writes a file for human review before import.

**Q: What does success look like in 90 days?**
A: Every active indicator has an owner and expiry, the allowlist is maintained, and we can report matches, false positives and time to triage per source.
