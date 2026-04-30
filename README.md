# cozy-bear — APT29 Adversary Emulation

> Full adversary emulation of APT29 (Cozy Bear / NOBELIUM / SVR) against a hardened
> Active Directory environment. Every technique attributed to a named primary source report.
> Operational goal: zero Elastic EDR detections in block/prevent mode.

---

## Overview

This repository documents a complete APT29 adversary emulation executed against a 
controlled Active Directory lab environment with modern enterprise defenses enabled.

Every technique in the kill chain is directly attributed to a named, publicly 
documented APT29 campaign report. Where MITRE is the only available attribution, 
this is explicitly noted.

The emulation advances documented APT29 tradecraft to account for 2026 defensive 
capabilities — specifically Elastic Security 9.3 in full block/prevent mode,
Windows Defender with ASR rules, LSA Protection, PowerShell Constrained Language 
Mode, and AES-only Kerberos with NTLM disabled.

**No commercial post-ex frameworks used.** Every component is built from 
open source research and primary source attribution.

**Fictional target organization:** PolarWinds — a DC-based policy research firm.
SVR's documented targeting pattern includes think tanks, diplomatic entities, and 
policy organizations of exactly this type.

---

## Defensive Environment

| Defense | Configuration |
|---------|--------------|
| Elastic Security | v9.3 — all protections in **Prevent/Block** mode |
| Windows Defender | Real-time protection + all ASR rules enabled |
| LSA Protection | RunAsPPL enabled — standard Mimikatz fails |
| WDigest | Disabled — no cleartext credentials in LSASS |
| PowerShell CLM | Constrained Language Mode enforced |
| AppLocker | Script rules enforced — Windows/ProgramFiles paths only |
| NTLM | Disabled domain-wide — Kerberos only |
| Kerberos | AES-256/AES-128 only — RC4 disabled |
| SMB | v1 disabled, signing required |
| Protected Users | Domain admins in Protected Users security group |
| Fine-grained Password Policy | 16 char min, complexity, lockout after 5 attempts |
| Windows Firewall | Enabled on all profiles |
| Audit Logging | Full audit policy |
| PowerShell Logging | Script block + module logging enabled |

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Attacker | Kali Linux (WSL2), Havoc C2 |
| Domain Controller | Windows Server 2019 — polar.local |
| Victim Workstation | Windows 11 Enterprise — domain joined |
| EDR | Elastic Security 9.3 Cloud (block mode) + Windows Defender |
| Monitoring | Elastic Fleet — both endpoints enrolled |

---

## Loader Architecture

Custom loader built from scratch in C. No commercial frameworks.
Every evasion technique sourced from public open source research.

### Loader Evasion Stack

| Component | Implementation | Detection Defeated | Source |
|-----------|---------------|-------------------|--------|
| Indirect syscalls | RecycledGate — Hell's/Halo's Gate SSN resolution. Syscall executed from ntdll .text | NTDLL userland hooks | thefLink — [RecycledGate](https://github.com/thefLink/RecycledGate) |
| Sleep masking | Hook Sleep → encrypt all PE sections → RX→RW during sleep → restore on wake | Elastic memory scanner | C5pider — [Ekko](https://github.com/Cracked5pider/Ekko) |
| Call stack spoofing | Draugr — fake BaseThreadInitThunk+0x17 and RtlUserThreadStart+0x2c frames | ETW-TI call stack analysis | mgeeky — [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) |
| RWX elimination | Allocate RW, copy, decrypt, flip RX — never RWX | RWX memory alerts | Standard |
| Memory self-destruction | SecureZeroMemory on shellcode + loader image on exit | Memory forensics | FireEye SUNBURST [9] |

### APT29 Behavioral Checks

All behavioral checks implemented in loader before execution.
Loader silently terminates + zeroes memory if any check fails.

| Check | Behavior | Attribution |
|-------|----------|-------------|
| MAC address blocklist | Terminate if sandbox MAC detected (VMware/VBox prefixes) | MSTIC GoldMax [10] |
| Domain allowlist | Only execute if joined to `polar.local` | FireEye SUNBURST [9] |
| Domain blocklist | Terminate if security vendor domain detected | FireEye SUNBURST [9] |
| Activation delay | 24 hour delay before first execution | FireEye SUNBURST [9] |
| Working hours | Only execute weekdays 09:00-18:00 UTC+3 (Moscow hours) | MSTIC GoldMax [10] |
| Decoy traffic | 1-4 WinHTTP GET requests to legitimate domains before beacon | MSTIC GoldMax [10] |

### Memory Self-Destruction

If any behavioral check fails, or on clean exit:

```c
/* zero shellcode */
SecureZeroMemory(buf, shellcode_len);
NtFreeVirtualMemory(...);

/* zero loader image — memory forensics finds nothing */
BYTE *image_base = get_own_base();
SecureZeroMemory(image_base, image_size);
```

Attributed to SUNBURST [9] — FireEye documented APT29 cleaning its own memory on termination.

---

## Sandbox Evasion Validation

Loader submitted to public sandboxes to document behavioral check effectiveness.

| Sandbox | Result | Triggered By | Evidence |
|---------|--------|-------------|---------|
| any.run | 🔴 Pending | | |
| hybrid-analysis | 🔴 Pending | | |
| Joe Sandbox | 🔴 Pending | | |

*To be populated after loader completion.*

---

## Kill Chain — Primary Source Attribution

### Phase 1 — Initial Access
**Techniques:** T1566.001, T1027.006  
**Primary Source:** MSTIC — *NOBELIUM EnvyScout* (May 2021) [18][19]

EnvyScout HTML smuggler delivered via spearphishing. XOR-encoded ISO decoded and 
auto-downloaded by JavaScript. ISO contains LNK executing compiled binary stager.
PowerShell CLM enforced on VICTIM01 — PS-based stagers not viable.

### Phase 2 — C2 Establishment
**Technique:** T1071.001  
**Primary Sources:** FireEye SUNBURST [9], MSTIC GoldMax [10]

Custom Havoc C2 profile:
- Sleep: 30-60 minutes, 25% jitter
- Active hours: weekdays 09:00-18:00 UTC+3
- Activation delay: 24 hours
- Decoy traffic mixed with real C2
- Anti-sandbox MAC check
- Content-Type: application/json tasking, application/octet-stream exfil

### Phase 3 — Discovery
**Techniques:** T1087.002, T1057, T1082, T1016  
**Primary Sources:** MSTIC Solorigate [37], Mandiant [62]

PowerShell LOTL discovery. No binaries on disk. Native cmdlets + LDAP queries.

### Phase 4 — UAC Bypass
**Technique:** T1548.002  
**Attribution:** MITRE G0016 (no primary source documents specific method)

fodhelper.exe registry hijack — medium to high integrity.

### Phase 5 — Local Privilege Escalation
**Technique:** T1574.002  
**Primary Source:** Mandiant UNC2452 Merge [29]

DLL sideloading against intentionally vulnerable PolarHealthMonitor service.
Writable service directory, malicious DLL dropped to ServiceDll path.
Service runs as LocalSystem.

### Phase 6 — Credential Access
**Techniques:** T1003.001, T1047  
**Primary Sources:** Mandiant POSHSPY [55], MSTIC Solorigate [37]

In-memory LSASS dump via direct syscalls — no Mimikatz binary on disk.
Output stored in WMI class property (POSHSPY pattern).
LSA PPL bypass required.

### Phase 7 — Defense Evasion
**Techniques:** T1562.002, T1070.006  
**Primary Sources:** MSTIC Solorigate [37], Mandiant POSHSPY [55]

auditpol disables specific subcategories before sensitive operations.
Timestomping matches randomly selected System32 file timestamps.

### Phase 8 — Persistence (Three Layers)
**Primary Sources:** MSTIC [37], POSHSPY [55], MSTIC GoldMax [10], CrowdStrike StellarParticle [24]

**Layer 1 — Scheduled Task (T1053.005)**
Path: `\Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager`
rundll32 loading .sys-extension DLL from temp path.

**Layer 2 — WMI Event Subscription (T1546.003)**
Filter: `BfeOnServiceStartTypeChange`
Schedule: Mon/Tue/Thu/Fri/Sat 11:33 AM
ActiveScriptEventConsumer. Payload encrypted in WMI property.

**Layer 3 — Sibot (T1112, T1218.005)**
VBScript in registry, scheduled task calling mshta.exe.
Task path: `\Microsoft\Windows\WindowsUpdate\sibot`

### Phase 9 — Lateral Movement
**Techniques:** T1021.006, T1078  
**Primary Sources:** MSTIC Solorigate [37], CrowdStrike StellarParticle [24]

WinRM PowerShell remoting to DC using stolen Kerberos credentials.
Separate accounts for recon vs lateral movement (StellarParticle documented).
Tools transferred via SMB admin share, renamed to match legitimate Windows binaries.

### Phase 10 — Domain Privilege Escalation
**Technique:** T1003.006  
**Primary Source:** CrowdStrike StellarParticle [24]

DCSync via in-memory implementation — no Mimikatz binary.
MS-DRSR replication protocol. No LSASS access on DC.
Executed via remote WinRM session — no code on DC.

### Phase 11 — Domain Persistence
**Techniques:** T1558.001, T1136.002  
**Primary Sources:** MSTIC Solorigate [37], Mandiant confirmed

Golden Ticket from KRBTGT hash + domain SID.
New domain admin account (polarsvc) — documented APT29 pattern.

### Phase 12 — Cleanup
**Techniques:** T1070.001, T1070.004, T1562.002  
**Primary Sources:** Mandiant No Easy Breach [30], MSTIC Solorigate [37]

auditpol restored. Event logs cleared. Tools securely wiped via SDelete.
WMI persistence removed after objectives met.

---

## Post-Ex Toolkit

**No commercial frameworks. All custom.**

| Component | Technique | Status |
|-----------|-----------|--------|
| LSASS dumper | Direct syscalls, no binary on disk | 🔴 Planned |
| DCSync implementation | MS-DRSR in C | 🔴 Planned |
| POSHSPY 2026 | Original POSHSPY + modern evasion | 🔴 Planned |
| WMI persistence tool | COM-based, no PowerShell | 🔴 Planned |
| DLL sideload payload | Custom reflective DLL | 🔴 Planned |

### POSHSPY 2026

Mandiant published POSHSPY source in 2017 [55]. This project implements a modernized 
version with 2026 evasion additions:

**Original POSHSPY behavior (Mandiant attributed):**
- WMI class property payload storage
- WMI event subscription execution
- Filter name: `BfeOnServiceStartTypeChange`
- Schedule: Mon/Tue/Thu/Fri/Sat 11:33 AM

**Novel additions:**
- Payload AES-encrypted in WMI property (not plaintext)
- Indirect syscalls for WMI COM calls
- Sleep masking during execution windows
- Timestomping on any artifacts

---

## ATT&CK Coverage

| Technique | ID | Source |
|-----------|-----|--------|
| Spearphishing Attachment | T1566.001 | MSTIC NOBELIUM [18][19] |
| HTML Smuggling | T1027.006 | MSTIC NOBELIUM [18][19] |
| C2 Application Layer Protocol | T1071.001 | FireEye SUNBURST [9], MSTIC GoldMax [10] |
| Domain Account Discovery | T1087.002 | MSTIC Solorigate [37] |
| Process Discovery | T1057 | MSTIC Solorigate [37] |
| System Information Discovery | T1082 | MSTIC Solorigate [37] |
| Bypass UAC | T1548.002 | MITRE G0016 |
| DLL Side-Loading | T1574.002 | Mandiant UNC2452 [29] |
| LSASS Memory | T1003.001 | POSHSPY Mandiant [55] |
| WMI | T1047 | POSHSPY Mandiant [55] |
| Disable Event Logging | T1562.002 | MSTIC Solorigate [37] |
| Timestomp | T1070.006 | POSHSPY [55] |
| Scheduled Task | T1053.005 | MSTIC Solorigate [37] |
| WMI Event Subscription | T1546.003 | POSHSPY Mandiant [55] |
| Modify Registry | T1112 | MSTIC GoldMax [10] |
| Mshta | T1218.005 | MSTIC GoldMax [10] |
| WinRM | T1021.006 | MSTIC Solorigate [37] |
| Valid Accounts | T1078 | CrowdStrike StellarParticle [24] |
| DCSync | T1003.006 | CrowdStrike StellarParticle [24] |
| Golden Ticket | T1558.001 | MSTIC Solorigate [37] |
| Create Domain Account | T1136.002 | MSTIC Solorigate [37] |
| Clear Event Logs | T1070.001 | MSTIC Solorigate [37] |
| File Deletion | T1070.004 | No Easy Breach [30] |

---

## Detection Results

*To be populated as engagement progresses.*

| Phase | Technique | Elastic Alert | Defender Alert | Bypassed | Notes |
|-------|-----------|--------------|----------------|---------|-------|
| | | | | | |

---

## Primary Sources

| ID | Report | Author | Year |
|----|--------|--------|------|
| [9] | SUNBURST Backdoor Analysis | FireEye/Mandiant | 2020 |
| [10] | GoldMax, GoldFinder, Sibot | MSTIC | 2021 |
| [18][19] | NOBELIUM EnvyScout | MSTIC | 2021 |
| [24] | StellarParticle Campaign | CrowdStrike | 2022 |
| [29] | UNC2452 Merged into APT29 | Mandiant | 2022 |
| [30] | No Easy Breach DerbyCon | Mandiant | 2016 |
| [37] | Deep Dive into Solorigate | MSTIC | 2021 |
| [55] | POSHSPY Fileless WMI Backdoor | Mandiant | 2017 |
| [62] | Tracking APT29 Phishing | Mandiant | 2022 |

---

## Status

| Component | Status |
|-----------|--------|
| Lab environment | ✅ Complete |
| Havoc C2 profile | ✅ Complete |
| EnvyScout HTML smuggler | ✅ Complete |
| Loader — RecycledGate indirect syscalls | ✅ Complete |
| Loader — Ekko sleep masking | 🔴 In progress |
| Loader — Draugr call stack spoofing | 🔴 Pending |
| Loader — APT29 behavioral checks | 🔴 Pending |
| Loader — Memory self-destruction | 🔴 Pending |
| Sandbox evasion validation | 🔴 Pending loader completion |
| POSHSPY 2026 | 🔴 Planned |
| Post-ex toolkit | 🔴 Planned |
| Full kill chain execution | 🔴 Pending loader completion |
| Detection results table | 🔴 Pending engagement execution |

---

## Disclaimer

This repository is for authorized security research and defensive education only.
All techniques executed against controlled lab infrastructure owned by the author.
Do not use against systems you do not own or have explicit written authorization to test.

Techniques attributed to APT29 based on publicly available threat intelligence from
FireEye/Mandiant, Microsoft Threat Intelligence Center, CrowdStrike, and government
advisories (NCSC, CISA, NSA).

---

## Author

**61tiger** — Purdue University, BS Cybersecurity
CRTO | CRTL
[GitHub](https://github.com/61tiger) | [LinkedIn](https://linkedin.com/in/aryan-cybersecurity)
