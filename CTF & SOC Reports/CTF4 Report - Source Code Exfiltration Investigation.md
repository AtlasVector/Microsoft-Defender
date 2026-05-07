## Report Details:

**Title**: MYDFIR CTF #4 – EmberForge Studios: Source Code Exfiltration Investigation

**Analyst**: YB

### MITRE ATT&CK:

- **Tactics:** [#Execution](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#Collection](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#Exfiltration](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#Persistence](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21)
    - **IDs:** [#TA0002](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#TA0009](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#TA0010](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#TA0003](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21)
- **Techniques:** [#PowerShell](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#Archive_Collected_Data](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#Transfer_to_Cloud_Account](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#Create_Domain_Account](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21)
    - **IDs:** [#T1059](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21).001 [#T1560](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21).001 [#T1537](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21) [#T1136](https://www.notion.so/MYDFIR-CTF-4-35960332707a80388913d2781002832e?pvs=21).002

### Report N: INC-CTF4-001

---

## Executive Summary

Between **2026-01-30 23:49** and **2026-01-31 00:38**, an attacker operating on the **EmberForge Studios** internal network conducted a targeted data theft operation against the company's unreleased game, **Neon Shadows**. Operating under **SYSTEM-level privileges**, the attacker used PowerShell to compress the entire `C:\\GameDev\\` source directory into an archive and exfiltrated it to **Mega cloud storage** using a pre-configured rclone tool tied to the attacker-controlled account `jwilson.vhr@proton.me`. To ensure continued access, the attacker created a new domain account (`svc_backup`) before concluding the session. The attack was executed in under **49 minutes** across at least two hosts within the `EMBERFORGE` domain. **The source code for Neon Shadows should be considered fully compromised and in the hands of an unknown third party.**

---

## Findings

- **AlertID**: Exfil-Alert #001 (MYDFIR CTF #4)
- Attack scope: **EmberForge Studios** (`emberforge.local` domain), **Neon Shadows** game source code targeted
- **SYSTEM-level** (`S-1-5-18`) command execution confirmed on `EC2AMAZ-16V3AU4.emberforge.local`
- **PowerShell** used to archive `C:\\GameDev\\` into `C:\\Users\\Public\\gamedev.zip` via `Compress-Archive`
- **Rclone** configured with attacker-controlled **Mega cloud credentials**:
    - Exfiltration account: `jwilson.vhr@proton.me`
    - Target endpoint: `bt5.api.mega.co.nz`
- **Domain persistence account created:**
    - Username: `svc_backup`
    - Password: `P@ssw0rd123!`
    - Added to domain via `net user /add /domain`
- **Affected Hosts:**
    - `EC2AMAZ-EEU3IA2.emberforge.local` — primary exfiltration host
    - `EC2AMAZ-16V3AU4.emberforge.local` — SYSTEM-level execution observed
- Log sources confirmed:
    - `MYDFIR_SecurityEvent_CL` (EventID **4103** – PowerShell module logging)
    - `MYDFIR_DeviceProcessEvents_CL`

---

## Investigation Summary

Sentinel telemetry from the `emberforge` lab environment, scoped to **2026-01-29 through 2026-02-02**, reveals a concise but complete attack chain focused on intellectual property theft. The attacker's earliest confirmed footprint is **2026-01-30 23:49:25**, where `conhost.exe` was spawned by `cmd.exe` running under the `SYSTEM` account (`S-1-5-18`) on `EC2AMAZ-16V3AU4.emberforge.local`. The use of SYSTEM context at this early stage indicates the attacker had already achieved full privilege escalation before the observed activity window begins.

Approximately **19 minutes later** on `EC2AMAZ-EEU3IA2.emberforge.local`, the attacker issued a PowerShell command to compress the entire `C:\\GameDev\\` directory — which contained the source code for **Neon Shadows**, EmberForge's upcoming cyberpunk RPG — into a zip archive at `C:\\Users\\Public\\gamedev.zip`. Staging the archive in `C:\\Users\\Public\\` is a deliberate choice: this path is world-readable and commonly used by attackers to temporarily stage data before exfiltration without requiring elevated write permissions at the destination.

Four minutes later (**00:12:54**), the attacker wrote a rclone configuration file (`C:\\Users\\Public\\rclone.conf`) containing credentials for the Mega cloud storage account `jwilson.vhr@proton.me`, targeting the endpoint `bt5.api.mega.co.nz`. Rclone is a legitimate open-source cloud sync tool that, in this context, was weaponized to transfer the staged archive to attacker-controlled cloud storage. The use of Mega is notable — Mega's end-to-end encryption makes it difficult for network-layer controls to inspect the transferred content, and the use of a dedicated exfiltration account (`jwilson.vhr@proton.me`) suggests the attacker pre-planned this operation.

The final observed action (**00:38:11**) was the creation of a new domain account — `svc_backup` with the password `P@ssw0rd123!` — using `net user /add /domain`. This is a classic persistence move: by creating a domain account with a plausible service-account name, the attacker ensures they can re-enter the environment even if the original access vector is remediated.

The entire chain from first SYSTEM execution to persistence account creation spans **49 minutes**, suggesting an attacker who knew exactly what they were after and executed with deliberate efficiency.

---

## The 5W – 1H

- **Who:** An unknown threat actor with pre-established SYSTEM-level access to the `EMBERFORGE` domain. The use of a dedicated Mega exfiltration account (`jwilson.vhr@proton.me`) and pre-configured rclone suggests this was a targeted, planned operation — not opportunistic.
- **What:** Complete exfiltration of the `C:\\GameDev\\` source directory (Neon Shadows game source code), followed by creation of a domain persistence account (`svc_backup`). The stolen data was transferred to Mega cloud storage under attacker-controlled credentials.
- **When:** Attack chain observed between **2026-01-30 23:49:25** and **2026-01-31 00:38:11** — approximately **49 minutes** from first footprint to persistence establishment.
- **Where:** Two hosts within the `EMBERFORGE` domain:
    - `EC2AMAZ-16V3AU4.emberforge.local` — initial SYSTEM-level execution
    - `EC2AMAZ-EEU3IA2.emberforge.local` — data collection and exfiltration
- **Why:** The target was specifically `C:\\GameDev\\` — the source code for **Neon Shadows**, an unreleased game with significant commercial value and an upcoming funding round. The attacker did not appear to broadly explore the environment, focusing exclusively on this high-value directory. The creation of `svc_backup` after exfiltration suggests the attacker intends to return.
- **How:** SYSTEM-level `cmd.exe` → PowerShell `Compress-Archive` to package `C:\\GameDev\\` → rclone configuration written with Mega credentials → data uploaded to `bt5.api.mega.co.nz` → `net user /add /domain` to establish `svc_backup` for persistent re-entry. The speed and precision of execution, combined with pre-staged tooling (rclone, Mega account), indicate the attacker had pre-planned this operation and likely conducted reconnaissance prior to this window.

---

## Commands (Exact as Logged)

**Stage 1 – Data collection:**

```
powershell.exe -c Compress-Archive -Path C:\\GameDev -DestinationPath C:\\Users\\Public\\gamedev.zip
```

**Stage 2 – Exfiltration configuration:**

```
cmd.exe /c "echo user = jwilson.vhr@proton.me>> C:\\Users\\Public\\rclone.conf"
```

**Stage 3 – Domain persistence:**

```
net user svc_backup P@ssw0rd123! /add /domain
```

**SYSTEM process chain:**

```
ProcessCommandLine: \\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1
InitiatingProcessFileName: C:\\Windows\\System32\\cmd.exe
```

---

## Attack Timeline

|Timestamp (UTC)|Host|Activity|Source|
|---|---|---|---|
|`2026-01-30 23:49:25`|`EC2AMAZ-16V3AU4.emberforge.local`|`conhost.exe` spawned by `cmd.exe` under SYSTEM (S-1-5-18)|`MYDFIR_DeviceProcessEvents_CL`|
|`2026-01-31 00:08:28`|`EC2AMAZ-EEU3IA2.emberforge.local`|PowerShell compressed `C:\\GameDev` → `C:\\Users\\Public\\gamedev.zip`|`MYDFIR_SecurityEvent_CL` (EventID 4103)|
|`2026-01-31 00:12:54`|`EC2AMAZ-EEU3IA2.emberforge.local`|Rclone config written with Mega account credentials targeting `bt5.api.mega.co.nz`|`MYDFIR_SecurityEvent_CL` (EventID 4103)|
|`2026-01-31 00:38:11`|`EC2AMAZ-EEU3IA2.emberforge.local`|Domain user `svc_backup` created with `P@ssw0rd123!` for persistent access|`MYDFIR_DeviceProcessEvents_CL`|

---

## Detection Query (KQL)

**Compress-Archive activity via PowerShell (EventID 4103):**

```
MYDFIR_SecurityEvent_CL
| where Lab == "emberforge"
| where Timestamp between (datetime(2026-01-29 12:11:00) .. datetime(2026-02-02))
| where EventID == 4103
| extend x = parse_xml(EventData)
| extend ContextInfo = tostring(x.Event.EventData.Data[0]["#text"])
| where ContextInfo has "Compress-Archive"
| project Timestamp, Computer, EventID, ContextInfo, EventData
| sort by Timestamp asc
```

---

## Indicators of Compromise

### Accounts

```
svc_backup                  (domain persistence account — created by attacker)
jwilson.vhr@proton.me       (attacker-controlled Mega exfiltration account)
```

### Exfiltration Infrastructure

```
bt5.api.mega.co.nz          (Mega cloud storage — exfiltration destination)
```

### Files & Paths

```
C:\\Users\\Public\\gamedev.zip     (compressed source code archive — staged for exfiltration)
C:\\Users\\Public\\rclone.conf     (rclone config containing attacker Mega credentials)
C:\\GameDev\\                     (exfiltrated source directory — Neon Shadows)
```

### Compromised Hosts

```
EC2AMAZ-EEU3IA2.emberforge.local
EC2AMAZ-16V3AU4.emberforge.local
```

### Process Context

```
AccountSid:    S-1-5-18        (SYSTEM)
AccountDomain: EMBERFORGE
AccountName:   EC2AMAZ-16V3AU4$
LogonId:       0x3e7
```

### Raw Event Identifiers

```
DeviceId:      8316098e3fa89a887a05c05525971225c0ad8ca5
ReportId:      167659
SourceSystem:  Splunk
Type:          MYDFIR_DeviceProcessEvents_CL
```

---

## MITRE ATT&CK Mapping

|Technique ID|Name|
|---|---|
|T1059.001|Command and Scripting Interpreter: PowerShell|
|T1560.001|Archive Collected Data: Archive via Utility|
|T1537|Transfer Data to Cloud Account|
|T1136.002|Create Account: Domain Account|

---

## Recommendations

### Immediate Response

- **Disable `svc_backup`** immediately and audit all recently created domain accounts — assume the account may have already been used for re-entry
- **Rotate all credentials** on `EC2AMAZ-EEU3IA2` and `EC2AMAZ-16V3AU4` — SYSTEM-level access was confirmed and the initial access vector is not yet identified
- **Delete staged files** — `C:\\Users\\Public\\gamedev.zip` and `C:\\Users\\Public\\rclone.conf`
- **Block outbound access to `bt5.api.mega.co.nz`** and Mega infrastructure at the perimeter; verify whether the upload completed
- **Notify legal and leadership** — source code for Neon Shadows is likely in the hands of a third party; this may constitute a data breach requiring notification depending on jurisdiction

### Detection & Hardening

- Implement alerting for:
    - `Compress-Archive` or `zip` operations targeting source code directories
    - Rclone, MEGAsync, or other cloud sync tool execution from non-standard paths
    - `net user /add /domain` executed outside approved change windows
    - `C:\\Users\\Public\\` used as a staging directory for large files
    - New domain accounts created outside of IT provisioning workflows
- Enforce **PowerShell Constrained Language Mode** and script block logging across the domain
- Review and restrict which accounts can execute PowerShell and run net commands with domain-level flags

### References

- [**MITRE ATT&CK T1537**](https://attack.mitre.org/techniques/T1537/) – Transfer Data to Cloud Account
- [**MITRE ATT&CK T1560.001**](https://attack.mitre.org/techniques/T1560/001/) – Archive Collected Data: Archive via Utility
- [**MITRE ATT&CK T1136.002**](https://attack.mitre.org/techniques/T1136/002/) – Create Account: Domain Account
- [**NIST SP 800-53 Rev 5 – AC-2**](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-53r5.pdf): Account Management