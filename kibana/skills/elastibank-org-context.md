# Elastibank organizational context

Use this context whenever you triage, investigate, score or escalate security activity at Elastibank. It tells you which assets matter most, who we worry about, what normal looks like, and who must be told.

## Company

Elastibank is a mid-sized retail and corporate bank. Its SOC runs 24x7 on Elastic Security. Customer money moves through the core banking database and the SWIFT gateway; a compromise of either is a business-critical event, not just an IT incident.

## Asset tiers

| Host | Tier | Role |
|---|---|---|
| DC01 | Tier 0 | Domain controller |
| ADFS01 | Tier 0 | AD FS federation server |
| FIN-DB01 | Tier 1 | Core banking database |
| SWG01 | Tier 1 | SWIFT gateway |

Everything else is **Tier 2**: about 50 user workstations named `WS-<DEPT>-<NNN>`: `WS-FIN-` (Finance), `WS-OPS-` (Operations) and `WS-IT-` (IT). Tier 2 hosts are not valuable themselves; they matter for what they can reach.

Treat any path from a Tier 2 host toward a Tier 0 or Tier 1 host as a Tier 0/1 incident, whatever the starting point.

## Crown-jewel accounts

- `svc_findb`: service account for the core banking database. Interactive or network logons from a workstation are never normal.
- `adm.*`: named IT administrator accounts. Anything they do outside IT workstations deserves a second look.

## Threat actors of concern

- **APT29 (state-sponsored)**: patient and quiet, and interested in finance. TTPs to watch for:
  - spearphishing with ISO or LNK attachments (T1566.001);
  - encoded PowerShell (T1059.001, T1027);
  - scheduled task persistence (T1053.005);
  - LSASS credential dumping, for example `comsvcs.dll` MiniDump (T1003.001);
  - Active Directory discovery (T1482, T1069.002);
  - WMI lateral movement (T1047);
  - low-and-slow HTTPS command and control to look-alike CDN domains (T1071.001), with small, regular check-ins that no signature fires on.
- **Commodity ransomware**: fast and noisy. Watch for mass file changes, shadow-copy deletion and backup tampering.

## Known-benign activity

Do not escalate these on their own; still note them as context.

- IT's Configuration Manager (`ccmexec.exe`) runs encoded PowerShell inventory scripts and creates the `Elastibank\AgentUpdate` scheduled task on workstations.
- `svc_backup` makes regular network logons to FIN-DB01 from the IT backup workstation.
- Procurement receives monthly statements as `.iso` files from the known vendor `contoso.example`.
- Routine `net group "domain admins"` audits from the IT desk.
- Windows Update and the EDR cloud service check in on a fixed schedule.

## Risk scoring

Start from the alert's risk score (0–100), then weight it by the highest tier involved:

| Highest tier involved | Multiplier |
|---|---|
| Tier 0 | ×3 |
| Tier 1 | ×2 |
| Tier 2 | ×1 |

Cap the result at 100. Raise it further for a crown-jewel account, for several linked alerts across hosts, or for credential theft. Lower it only with a concrete benign explanation from the list above.

## Escalation

| Situation | Action | Time limit |
|---|---|---|
| Confirmed or suspected compromise of a Tier 0 or Tier 1 host, a crown-jewel account, or movement toward either | Email `ciso@elastibank.example` and `ir-oncall@elastibank.example`, and open a SOC case | Within 15 minutes |
| Tier 2 only | Open a SOC case. Severity follows the weighted score: low 1–21, medium 22–47, high 48–73, critical 74–100 | Same shift |
| Known-benign pattern | Close with a note, or tune the rule | None |

## How to work

- Cite evidence: name the host, user, time and event behind each claim.
- State the MITRE ATT&CK technique IDs you rely on.
- Separate what you observed from what you infer, and say what you would check next.
- Never take containment actions (isolating hosts, disabling accounts, blocking IPs) without human approval. Recommend them and wait.
