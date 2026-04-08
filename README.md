# cozy-bear-emulation
emualting apt29 tactics and customizing them for evasion against elastic edr + windows 11 defender

# cozy-bear-emulation

> Full adversary emulation of APT29 (Cozy Bear / NOBELIUM / Midnight Blizzard) 
> across a live Active Directory environment. Zero Elastic EDR + Windows Defender 
> detections as the operational goal.

## Overview

This repository documents a complete two-phase APT29 adversary emulation executed 
against a controlled Active Directory lab environment. Every technique is attributed 
to a real, publicly documented APT29 campaign but customized to evade modern defenses. 

The emulation uses Havoc C2 with a custom profile mimicking NOBELIUM HTTP traffic 
patterns, and targets zero detections across both Elastic EDR and Windows Defender.

**Fake target organization:** PolarWinds — a fictional DC-based policy 
research firm, the type of organization SVR routinely targets.

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux (WSL2) |
| C2 Framework | Havoc — custom APT29 C2 profile |
| Domain Controller | Windows Server 2019 — polar.local |
| Victim Workstation | Windows 11 Enterprise |
| EDR | Elastic Security Cloud + Windows Defender |

---

## Kill Chain

### Phase 1 — Initial Access
**Technique:** T1204.002 — User Execution: Malicious File  
**Source:** NCSC SVR Advisory (2024), NOBELIUM ClickFix campaigns  
ClickFix lure page served via Flask — victim pastes PowerShell stager into 
Windows Run dialog. Havoc beacon established over custom HTTPS profile mimicking 
Microsoft O365 authentication traffic.

### Phase 2 — Discovery  
**Techniques:** T1087.002, T1057, T1082, T1016  
**Source:** SolarWinds Compromise — MSTIC Solorigate deep dive (January 2021)  
LDAP domain account enumeration, running process list, system and network 
configuration discovery. All via PowerShell living-off-the-land — no binaries 
touching disk.

### Phase 3 — Local Privilege Escalation
**Technique:** T1068 — CVE-2021-36934 HiveNightmare  
**Source:** MITRE ATT&CK G0016 — APT29 documented exploitation  
Read SAM/SYSTEM/SECURITY registry hives via Volume Shadow Copy ACL misconfiguration. 
Extract local account hashes without touching LSASS.

### Phase 4 — Credential Access
**Technique:** T1003.001 — LSASS Memory via WMI  
**Source:** POSHSPY — Mandiant/FireEye (April 2017)  
Mimikatz executed entirely in-memory via WMI class. Credentials parsed, encoded, 
and stored in WMI class property. Never touches disk.

### Phase 5 — Defense Evasion
**Techniques:** T1562.002, T1070.006  
**Source:** SolarWinds — MSTIC (January 2021), POSHSPY — FireEye (2017)  
AUDITPOL subcategory manipulation to blind event logging. Timestomping artifacts 
to match System32 file timestamps.

### Phase 6 — Lateral Movement to DC
**Techniques:** T1021.006, T1021.002  
**Source:** SolarWinds — MSTIC Solorigate deep dive (January 2021)  
WinRM PowerShell remoting session to DC01 using stolen domain credentials. 
SMB admin share used for tool transfer.

### Phase 7 — Domain Privilege Escalation
**Technique:** T1003.006 — DCSync  
**Source:** SolarWinds — CrowdStrike StellarParticle (January 2022)  
DCSync via Mimikatz lsadump module to extract KRBTGT hash. No code executes 
on DC, no LSASS access — traffic mimics legitimate DC replication via MS-DRSR.

### Phase 8 — Persistence
**Techniques:** T1558.001, T1136.002  
**Source:** SolarWinds — MSTIC/Mandiant confirmed  
Golden Ticket forged using KRBTGT hash and domain SID. New domain admin account 
created for persistent access.

### Phase 9 — Cleanup
**Techniques:** T1070.004, T1562.002  
**Source:** FireEye No Easy Breach DerbyCon (2016), SolarWinds MSTIC (2021)  
Secure file deletion via SDelete pattern. AUDITPOL restored. Event logs cleared.

---

## ATT&CK Coverage

| Technique | ID | Campaign Reference |
|-----------|-----|-------------------|
| User Execution: Malicious File | T1204.002 | NOBELIUM 2023-2024 |
| Domain Account Discovery | T1087.002 | SolarWinds 2020 |
| Process Discovery | T1057 | SolarWinds 2020 |
| System Information Discovery | T1082 | SolarWinds 2020 |
| Network Config Discovery | T1016 | SolarWinds 2020 |
| Exploitation for PrivEsc | T1068 | APT29 CVE-2021-36934 |
| LSASS Memory | T1003.001 | POSHSPY 2017 |
| Disable Windows Event Logging | T1562.002 | SolarWinds 2020 |
| Timestomp | T1070.006 | POSHSPY 2017 |
| Windows Remote Management | T1021.006 | SolarWinds 2020 |
| SMB/Admin Shares | T1021.002 | SolarWinds 2020 |
| DCSync | T1003.006 | SolarWinds 2020 |
| Golden Ticket | T1558.001 | SolarWinds 2020 |
| Create Domain Account | T1136.002 | SolarWinds 2020 |
| File Deletion | T1070.004 | No Easy Breach 2016 |

## Primary Sources

- FireEye — [SUNBURST Backdoor Analysis](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html) (December 2020)
- MSTIC — [Deep Dive Solorigate](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/) (January 2021)
- CrowdStrike — [StellarParticle Campaign](https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/) (January 2022)
- Mandiant — [POSHSPY Analysis](https://www.mandiant.com/resources/blog/dissecting-one-of-apt29s-fileless-wmi-and-powershell-backdoors) (April 2017)
- FireEye — [No Easy Breach DerbyCon](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) (2016)
- NCSC/CISA — [SVR TTPs Advisory](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf) (May 2021)
- NCSC — [SVR Cloud Advisory](https://www.ncsc.gov.uk/files/Advisory-SVR-cloud-attacks.pdf) (February 2024)

---

## Evasion Stack

- **C2:** Custom Havoc profile mimicking NOBELIUM O365 authentication traffic
- **Execution:** Stomped PE headers, reflective loading, no disk writes
- **Memory:** Sleep masking, call stack spoofing, ETW patching
- **AMSI:** Load-time interception
- **Syscalls:** Direct syscalls for sensitive operations
- **Persistence:** Masqueraded scheduled tasks, WMI subscriptions
- **Credential Access:** Fileless only — WMI class property storage

---

## Disclaimer

This repository is for authorized security research and defensive education only. 
All techniques are documented against controlled lab infrastructure. 
Do not use against systems you do not own or have explicit written authorization to test.

Techniques are attributed to APT29 based on publicly available threat intelligence 
from FireEye/Mandiant, Microsoft, CrowdStrike, and government advisories.

---

## Author

**regulus** — Purdue University, BS Cybersecurity  
Founder, DiTM Security | 2x CVE | CRTO, CRTL  
[LinkedIn](https://linkedin.com/in/aryan-cybersecurity)
