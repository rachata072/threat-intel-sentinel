# MITRE ATT&CK Mapping

Mapped only to behaviors this project actually detects. Nothing is padded.

| Tactic | Technique | ID | Where in project |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | Source of the MaliciousFlows indicators (Query 2.1, 2.2) |
| Credential Access | Brute Force: Password Spraying | T1110.003 | Query 2.2 `DistinctAccounts` high with low failures per account suggests spraying |
| Initial Access | Valid Accounts | T1078 | Query 2.3 and Rule A success outcome |
| Initial Access | External Remote Services | T1133 | RDP/SSH exposed to the internet is what the brute force targets |
| Command and Control | Application Layer Protocol | T1071 | Rule C, outbound connection to a known bad IP |
| Execution | User Execution: Malicious File | T1204.002 | Rule B, known bad file hash written to disk |

Honest limits: hash and IP matching gives you the indicator, not the full technique chain. A match on its own does not prove which technique was used.
