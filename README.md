# Microsoft Defender & Sentinel Lab
A personal collection of Microsoft Sentinel / Microsoft Defender lab content built during CTF participation and hands-on threat hunting practice. This repo documents real investigation workflows, KQL queries, Sentinel workbook development, and incident response reports - all built from live lab telemetry.
## What's Inside  

### Workbooks

Custom Sentinel workbooks built from scratch to visualize authentication abuse patterns and correlate security events:
- **[Auth Abuse Hunting Dashboard](./Workbooks/Microsoft%20Sentinel%20Workbook.md)** - A multi-panel Sentinel workbook combining Windows Security Events (`4625 failed logons`) and Entra ID Sign-in Logs to surface brute-force patterns, targeted accounts, and high-volume authentication failures. Built with KQL, workbook parameters, and dynamic highlighting to make hunting faster and more actionable.

  

### Incident & Threat Hunting Reports
Write-ups of investigations conducted in lab/CTF environments, modeled after real-world SOC reporting:

- **[Brute-Force Investigation - INC-001](./CTF%20&%20SOC%20Reports/001%20-%20Incident%20Report%20-%20Brute%20Investigation.md)** - Investigation of high-volume Event ID 4625 failures targeting privileged accounts (`admin`, `administrator`, `ADMIN`) across multiple hosts. Includes 5W-1H analysis, MITRE ATT&CK mapping (T1110 Brute Force), and hardening recommendations.

- **[Active C2 & Multi-Stage Malware - INC-KCD-001](./CTF%20&%20SOC%20Reports/Threat%20Hunting%20Report%20-%20Active%20C2%20Communication%20&%20Multi-Stage%20Malware%20Deployment.md)** - Full threat hunt uncovering a multi-stage malware deployment (HRSword.exe -> p2.exe -> client.exe) with C2 beaconing to `8.8.8.8`, registry persistence via Peer2Profit, and firewall evasion. Covers execution, persistence, defense evasion, and command & control tactics.


- **[Source Code Exfiltration - INC-CTF4-001](./CTF%20&%20SOC%20Reports/CTF4%20Report%20-%20Source%20Code%20Exfiltration%20Investigation.md)** - Investigation of Neon Shadows game source code theft via PowerShell `Compress-Archive`, **rclone-based** exfiltration to Mega cloud storage (`jwilson[.]vhr[@]proton[.]me`), and domain persistence account creation (`svc_backup`). Maps to MITRE ATT&CK *T1059.001*, *T1560.001*, *T1537*, *T1136.002*.

## Skills Demonstrated

- **KQL (Kusto Query Language)** - Writing actionable queries with threshold filtering, and multi-table correlation

- **Microsoft Sentinel Workbook Development** - Building interactive dashboards with parameters, dynamic text, and multi-panel layouts

- **Threat Hunting** - Proactive hunting across Windows Security Events, Entra ID Sign-in Logs, and process execution telemetry

- **Incident Response & Reporting** - Structured 5W-1H investigation write-ups, IOC extraction, and actionable recommendations

- **MITRE ATT&CK Mapping** - Technique and tactic alignment for every investigation

- **Detection Engineering** - Translating investigations into KQL detection queries and alerting logic

- **Digital Forensics** - Tracing multi-stage attack chains, persistence mechanisms, C2 infrastructure, and exfiltration paths

## Lab Environment

- **Platform:** Microsoft Sentinel + Microsoft Defender (lab tenant)
- **Data Sources:** Windows Security Events (`SecurityEvent_CL`), Entra ID Sign-in Logs (`SigninLogs_CL`), Defender for Endpoint (`DeviceProcessEvents_CL`)
- **Tools Used:** KQL, Sentinel Workbooks, Splunk (CTF contexts), rclone, Mega, NTLM Brute-Forcer
## Resources & References

- [Microsoft Certified: Security Operations Analyst Associate](https://learn.microsoft.com/en-us/credentials/certifications/security-operations-analyst/?practice-assessment-type=certification)
- [Azure Sentinel Community Repository](https://github.com/Azure/Azure-Sentinel)
- [MYDFIR Community](https://www.mydfir.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST SP 800-53 Rev 5](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-53r5.pdf)
- [NIST SP 800-63B](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)