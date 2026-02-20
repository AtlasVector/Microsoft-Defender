## Report Details:
**Title**: 30 Day MyDFIR Microsoft Challenge  - DAY 7 
Name: YB
#### MITRE ATT&CK: 
- **Tactics:** #Credential_Access **ID:** #TA0006
- **Techniques:** #Brute_Force  **ID:** #T1110 
#### Report N:  INC-001

## Findings
- AlertID: Brute-Force-Alert #001
- High volume of Windows **Event ID 4625 (Failed Logon)** detected.
- Total failed attempts mostly focused on high privileges access account
	- **Targeted Systems:**
		- `SHIR-Hive`
		- `SOC-FW-RDP`
	- **Targeted Accounts**
		- `admin`
		- `administrator`
		- `ADMIN`
		- `USER`
		- `TEST`
		- `SERVER`
- All attempts used **NTLM authentication**, which is considered not safe authentication methods
![4625 Activity Logs](./Resources/4625-Logs.png)
## Investigation Summary 
Over the past 24 hours, Sentinel telemetry from **Windows Security Event ID 4625 (Failed Logon)** shows a high volume authentication failure which might be an indicator for a brute force attempt against privileged  accounts. This attack is focused on two systems **SOC-FW-RDP** and **SHIR-Hive** with the highest target being **SOC-FW-RDP** for the account  **\ADMINISTRATOR** (**9,997** failed attempts). 

Additional attack  was observed against **\admin** (**1,988**), **\administrator** (**1,740**), and other account variants such as **\ADMIN**, **\USER**, and **\TEST**, indicating credential guessing against common administrative usernames. All observed attempts in this dataset used **NTLM** as the authentication package.
![[GitHub-Public/Microsoft-Defender/resources/brute_dash]]

## **The 5W - 1H**
#### **Who:**
- An unknown actor (internal vs. external not confirmed) generating repeated failed authentication attempts.
#### **What:**
- A high volume of failed login attempts (**Event ID 4625**) against multiple accounts.
#### **When:**
- **19 Feb 2026 ~08:06 AM** (based on available timestamps), with the activity appearing compressed into roughly **one minute**.
  Timestamp range: `2/19/2026, 8:06:29.412 AM `– `2/19/2026, 8:06:29.537 AM`
#### **Where:**
- Targeted hosts: **SOC-FW-RDP**, **SHIR-Hive**, **SOC-FW**, **SHIR-SAP**. 
#### **Why:**
- The attempts focused on common/privileged account names and were heaviest against **SOC-FW-RDP** and **SHIR-Hive**, suggesting an attempt to gain elevated access.
#### **How:**
- The high volume of attempts in a very short timeframe suggests the activity was automated, potentially using a script-based NTLM brute-force tool (for example, a Python **[NTLM Brute-Forcer](https://dhimasln.medium.com/ntlm-brute-force-attacks-a-practical-lab-simulation-detection-guide-365f5005dfea)**). The tool would repeatedly submit invalid credentials, generating Event ID 4625 (failed logon) entries and showing NTLM as the authentication package across the observed activity.

### **Recommendations**
#### Exposure & configuration recommendations
- Review the business need for RDP exposure (especially on `SOC-FW-RDP`): 
	- If required, restrict access (for example allow list, jump host, gateway, VPN), and activity monitoring .
	- if not required, remove exposure to reduce attack surface.
- Prioritize privileged account hardening as reduce use of default/admin-equivalent usernames, and ensure privileged accounts use stronger controls.
- Migrate to Kerberos and actively move applications and / or services from NTLM to Kerberos.

##### **References**
[**NIST SP 800-53 Rev 5** Control **AC-7**:](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-53r5.pdf#%5B%7B%22num%22%3A190%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C88%2C650%2C0%5D) Unsuccessful Logon Attempts (lockout/throttling concept).
**[NIST SP 800-63B-4:](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)** Digital Identity Guidelines: Authentication and Authenticator Management
