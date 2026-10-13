# RUNBOOK: Threat Intelligence in Microsoft Sentinel

Pure procedure. Follow the phases in order. Screenshot checkpoints are listed in EVIDENCE.md. All queries are in KQL-QUERY-LIBRARY.md (referenced by number, for example "Query 2.2").

**Environment:** the Cyber Range Azure environment (Sentinel workspace, Defender for Endpoint onboarded VMs, NSG flow logs). No extra cost beyond the course environment. The Python script and AbuseIPDB free tier cost nothing.

**Time:** about 4 to 6 hours across 2 sessions.

---

## Phase 0. Preflight (15 minutes)

1. Open Sentinel → your workspace → Logs. Run `ThreatIntelIndicators | take 5`.
   - Rows returned: continue.
   - "Failed to resolve table": the Threat Intelligence connector is not enabled. Go to Sentinel → Content hub → search "Threat Intelligence" → Install → open the data connector "Microsoft Defender Threat Intelligence" (and "Threat Intelligence Platforms" if listed) → Connect. Wait 15 to 30 minutes.
2. Run `DeviceLogonEvents | take 5`. If empty, confirm Defender XDR connector is connected with Device events enabled.
3. Run `NTANetAnalytics | take 5`. If empty, Traffic Analytics is not on. This is only needed for Query 4.1. You can skip 4.1 and still finish the project (note it in your write-up).
4. Create the allowlist: Sentinel → Watchlist → Add new → Name and alias `TI-Allowlist`, source type Local file, upload a CSV with header `IPAddress` and one row per trusted IP (your own public IP: search "what is my ip"). Search key: `IPAddress`.

Checkpoint: screenshot 01 (workspace + tables returning rows).

---

## Phase 1. Inventory the built-in intelligence (30 minutes)

1. Run Query 1.1. Note which `ObservableKey` values exist and which sources provide them.
2. Run Query 1.2 (IPv4 indicators). Expected: rows.
3. Run Query 1.3 (hash indicators). Note the exact `ObservableKey` string for SHA-256.
4. Run Query 1.4 (hygiene). Write down how many are active and how many expire within 7 days.
5. Run the second lab test (built-in IPs vs NTANetAnalytics). Expected on a clean range: zero rows. Zero is a good result, not a failure. Record it.

Checkpoint: screenshots 02 to 04.

**Why this phase exists:** a threat intel program starts with knowing what you own. Many teams turn on feeds and never look at them.

---

## Phase 2. Find your own suspicious IPs (30 minutes)

1. Run Query 2.1 (lab baseline). Write down the top 5 IPs.
2. Run Query 2.2 (enriched). Pick candidates with high `FailedLogons` AND more than one `DistinctDevices` if possible.
3. Run Query 2.3 (did they succeed?). Record the answer. If any row returns, STOP and treat it as an incident (see Phase 7 escalation note).
4. Export Query 2.2 results: Logs → Export → CSV. Open it, make sure the column headers are exactly `RemoteIP` and `Count` (rename `FailedLogons` to `Count`). Save as `failed_logons.csv`.
5. Optional but impressive: check two of the top IPs in a public reputation source (AbuseIPDB, GreyNoise community, Shodan). Record what each says. Note disagreements, that is normal and worth discussing in your interview.

Checkpoint: screenshots 05 to 07.

---

## Phase 3. Create indicators (45 minutes)

### Path A: portal, one at a time (lab method)

1. Go to Defender portal → Threat intelligence → Intel management (or Sentinel → Threat management → Threat intelligence).
2. **+ Add new** → **TI object** → Type: **Indicator**.
3. Fill in:
   - Name: `MaliciousFlows - Brute Force Source - <IP>`
   - Indicator type: IP address (IPv4)
   - Value: the bad IP
   - Confidence: the number you decide (see TI-CONCEPTS.md, confidence scoring)
   - Valid from: today. Valid until: 30 days out (never leave it open ended)
   - TLP: Amber (internal use)
   - Tags: `brute-force`, `lab`
4. Save. Repeat for 3 to 5 IPs.

### Path B: script and file import (the "I can automate this" method)

1. Install nothing. Python 3.8+ only.
2. Create `my_allowlist.txt` with your own egress IPs, one per line (copy `scripts/allowlist.example.txt`).
3. Run:

   ```
   python scripts/ti_indicator_builder.py --input failed_logons.csv --allowlist my_allowlist.txt --valid-days 30
   ```

4. Open `out/review.csv`. Every skipped row has a reason. This file is your audit trail.
5. Import `out/indicators.import.json` (the plain JSON array version, not the `.stix.json` bundle):
   1. Defender portal (security.microsoft.com) → **Microsoft Sentinel** → **Threat management** → **Threat intelligence**. In the Azure portal: Sentinel → your workspace → **Threat management** → **Threat intelligence**.
   2. Select **Import** → **Import using a file**.
   3. File format: **JSON**. (Select **Download template** once to see the expected layout.)
   4. Drag `indicators.import.json` into **Upload a file**.
   5. Source: type `MaliciousFlows-Lab`. This value is stamped on every indicator as `SourceSystem`, which makes them easy to find later.
   6. Choose how to handle invalid entries, then **Import**.
   7. Track it under **Import** → **Manage file imports**.
   8. If the import rejects the file, open the template and compare the layout. The template is the source of truth. The file must be a top-level array, with no comments and no trailing comma.
6. Optional: set `ABUSEIPDB_KEY` (free account) before running so confidence blends your volume score with a community score.

Checkpoint: screenshots 08 to 10.

---

## Phase 4. Confirm and match (45 minutes)

1. Wait up to 10 minutes, then run Query 3.1. Expected: one row per indicator.
2. Run Query 4.2 (logins). Expected: matches, because the IPs came from your own failed logons.
3. Run Query 4.1 (network flow) if NTANetAnalytics is populated.
4. Run Query 4.3 (sign-ins) and 4.4 (outbound) if those tables are connected. Zero rows is fine for 4.4 and is the expected healthy result.
5. Run Query 6.1 (retrohunt, 90 days). Record first seen, last seen, attempts, successes.

Checkpoint: screenshots 11 to 14.

---

## Phase 5. Prove the hash rule using EICAR (45 minutes)

Do this on a lab VM only, never on your daily machine.

1. Add an indicator: Type File, SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`, name `MaliciousFlows - TEST - EICAR`, valid 7 days, tag `test`.
2. On the lab VM, download the official EICAR test file from eicar.org (the project page lists the files and their hashes). Defender will probably quarantine it. That is fine. The file creation event is still recorded.
3. Wait 5 to 15 minutes. Run Query 5.1 with `ago(1d)` instead of `ago(1h)` while testing.
4. Expected: a row for the EICAR file on your VM.
5. Delete the EICAR indicator after the test (or let it expire in 7 days).

If no match: check that the stored hash case matches (Query 5.1 lowercases both sides), that Defender recorded `SHA256` in `DeviceFileEvents` (`DeviceFileEvents | where FileName has "eicar" | project SHA256`), and that the indicator's `ObservableKey` really contains "SHA-256" (Query 1.3 shows the exact string).

Checkpoint: screenshots 15 to 16.

---

## Phase 6. Build the analytics rules (60 minutes)

For each of Rules A, B and C in the KQL library:

1. Sentinel → Analytics → Create → **Scheduled query rule**.
2. General: name, description, tactics/techniques as listed, severity as listed.
3. Set rule logic: paste the query. Click **View query results** to test. Rule A should return your lab matches.
4. Query scheduling: every 5 minutes, lookup 1 hour. (Lookup must be at least as long as run interval plus expected ingestion delay, or you miss events.)
5. Alert threshold: greater than 0.
6. Entity mapping: as listed in the library.
7. Alert details: use the override for name and severity where listed.
8. Event grouping: single alert for all events.
9. Incident settings: enable incident creation. Alert grouping: by matching IP entity, 24 hour window.
10. Automated response: leave empty for now. Review and create.

Tip: because Rule A only looks back 1 hour, it will not fire on old test data. Trigger a fresh failed logon from an indicator IP (not possible for external IPs), so instead temporarily raise the lookup to 7 days to prove the rule, take the screenshot, then set it back to 1 hour. Document that you did this.

Checkpoint: screenshots 17 to 20.

---

## Phase 7. Operate it (30 minutes)

1. Open the incident the rule created. Review entities and the evidence.
2. Write the triage note using this template:
   - Indicator, source and confidence
   - What the indicator touched (devices, accounts)
   - Did any attempt succeed? (Query 2.3)
   - Verdict (true positive, benign, needs more data)
   - Action (block at NSG, reset password, close as expected)
3. **Escalation note:** a successful logon from a known bad IP is treated as a potential compromise. Disable the account, isolate the device, preserve logs, notify the security lead. In this lab there should be none.
4. Run Query 6.2 and 1.4 monthly. Remove or let expire indicators that never produce value.
5. Block action (optional lab exercise): add an NSG deny rule for the confirmed bad IP and document the change record.

Checkpoint: screenshots 21 to 22.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ThreatIntelIndicators` not found | Connector not enabled, or older schema | Enable connector. Older workspaces: try `ThreatIntelligenceIndicator` and map column names |
| Indicator created but Query 3.1 shows nothing | Ingestion delay, or name does not start with `MaliciousFlows` | Wait 10 minutes, check name spelling, confirm the indicator is saved in Intel management |
| Query 3.1 shows duplicate rows | Every edit creates a new row | The query already uses `arg_max(... ) by Id` |
| 4.1 returns zero but you expected a hit | `SrcPublicIps` separator differs, or IP is in `DestPublicIps` | Inspect with `take 5`, adjust the `split`, also check `DestPublicIps` for outbound |
| Hash rule never fires | Case mismatch, wrong `ObservableKey`, AV deleted file before event | Use Query 5.1 as written, verify key with Query 1.3, check `DeviceFileEvents` for the filename |
| Rule fires every 5 minutes with the same events | Lookup window longer than run interval | Use 1 hour lookup with event grouping, or dedupe with alert grouping |
| Rule fires on your own IP | IP was in your telemetry as a failed logon | Add to `TI-Allowlist` watchlist, remove the indicator |
| Import says file is invalid | Used the `.stix.json` bundle instead of the array file | Import `indicators.import.json`, compare with the downloaded template |
| Script says "Input needs columns" | CSV headers wrong | Rename to `RemoteIP` and `Count` |
| `Count` column is text | Export added quotes or commas | Open in a text editor and clean, or re-export |

---

## Cleanup

1. Delete or expire the lab indicators (set Valid until to a past date, or delete).
2. Disable analytics rules you do not want running (or leave them, they cost nothing extra to run in the course environment).
3. Delete any EICAR file remnants.
4. Do not commit `out/`, your `my_allowlist.txt` or real IPs of your employer to GitHub. The `.gitignore` already blocks these.
