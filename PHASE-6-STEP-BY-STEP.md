# Phase 6 Step by Step: Finish the Hash Test and Build Rule A

Use this after Phases 1 to 5 of RUNBOOK.md. Screenshot slot numbers refer to EVIDENCE.md.

## Part A. Finish the hash test (about 20 minutes)

1. Open `test-indicators/eicar-sha1.json` on your PC.
2. In the Defender portal, open Microsoft Sentinel → Threat management → Threat intelligence, then select Import → Import using a file.
3. File format: JSON. Source: `MaliciousFlows-Lab`. Drag the file in and select Import.
4. Open Import → Manage file imports and wait until the status shows imported.
5. In Advanced hunting (time range Last 24 hours or more), run:

   ```kql
   ThreatIntelIndicators
   | where tostring(Data.name) has "EICAR"
   | project TimeGenerated, ObservableKey, ObservableValue, IsActive, ValidUntil
   ```

   Expected: two rows, one SHA-256 and one SHA-1. Screenshot (slot 15).
6. Run Query 5.1 from KQL-QUERY-LIBRARY.md with both `ago(1h)` values changed to `ago(1d)`, and add `| where DeviceName startswith "threatintel-lab"` after the union line so only your own device appears. Expected: `eicar.com.txt` rows from the `DeviceEvents` table with confidence 90. Screenshot (slot 16).
7. If you get no rows, check step 5 first, then widen the time range picker.

If the dates inside the JSON files have expired, edit `valid_from` and `valid_until` before importing.

## Part B. Build Rule A (about 30 minutes)

1. Create the allowlist: edit `watchlist/TI-Allowlist.csv`, then Sentinel → Watchlist → Add new, name and alias `TI-Allowlist`, search key `IPAddress`. The rule fails if this watchlist does not exist.
2. Sentinel → Configuration → Analytics → Create → Scheduled query rule.
3. General tab:
   - Name: `TI Map IP Entity to DeviceLogonEvents - MaliciousFlows`
   - Description: Alerts when a device logon involves an IP from our MaliciousFlows threat intelligence indicators.
   - Severity: Medium
   - Tactics: Credential Access, Initial Access
   - Status: Enabled
4. Set rule logic tab: paste the Rule A query from KQL-QUERY-LIBRARY.md. Select View query results. For the test only, widen the `ago(1h)` on the logon table to `ago(7d)`.
5. Query scheduling: run every 5 minutes, look up data from the last 1 hour, alert threshold greater than 0.
6. Entity mapping:
   - IP → address → `RemoteIP`
   - Host → HostName → `DeviceName`
   - Account → Name → `AccountName`
7. Alert details: alert name format `TI Match: {{RemoteIP}} on {{DeviceName}}`, severity taken from the `Severity` column.
8. Event grouping: group all events into a single alert.
9. Incident settings: create incidents on. Alert grouping: group related alerts when the IP entity matches, within 24 hours.
10. Review and create, then Save. Screenshot the rule logic (slot 17) and entity mapping (slot 18).
11. If you widened the lookback for the test, edit the rule and set it back to 1 hour. Write down in EVIDENCE.md that you did this.
12. Repeat for Rule B (hash) and Rule C (outbound connections), using the queries and settings in KQL-QUERY-LIBRARY.md.
13. When a rule creates an incident, screenshot it (slot 20) and fill in the triage note from RUNBOOK.md Phase 7.
