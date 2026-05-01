# cozy-bear — APT29 Adversary Emulation

> Full adversary emulation of APT29 (Cozy Bear / NOBELIUM / SVR) against a hardened
> Active Directory environment. Every technique attributed to a named primary source report.
> Operational goal: zero Elastic EDR detections in block/prevent mode.

## Special Thanks

| Project | Author | Used For |
|---------|--------|---------|
| [Ekko](https://github.com/Cracked5pider/Ekko) | C5pider | Sleep masking implementation |
| [RecycledGate](https://github.com/thefLink/RecycledGate) | thefLink | Indirect syscall SSN resolution |
| [HellsGate](https://github.com/am0nsec/HellsGate) | am0nsec | Hell's Gate SSN resolution reference |
| [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) | mgeeky | Call stack spoofing research |
| [Havoc](https://github.com/HavocFramework/Havoc) | C5pider | C2 framework |
| [POSHSPY](https://github.com/matthewdunwoody/POSHSPY) | Matthew Dunwoody / Mandiant | Original POSHSPY PS1 source |

This project builds on the shoulders of public offensive security research. All implementations are cited inline in source code.

---

## Overview

This repository documents a complete APT29 adversary emulation executed against a 
controlled Active Directory lab environment with modern enterprise defenses enabled.

Every technique in the kill chain is directly attributed to a named, publicly 
documented APT29 campaign report. Where MITRE is the only available attribution, this is explicitly noted.

The emulation advances documented APT29 tradecraft to account for 2026 defensive 
capabilities — specifically Elastic Security 9.3 in full block/prevent mode, 
Windows Defender with ASR rules, LSA Protection, PowerShell Constrained Language 
Mode, and AES-only Kerberos with NTLM disabled.

**Fictional target organization:** PolarWinds — a DC-based policy research firm.
SVR's documented targeting pattern includes think tanks, diplomatic entities, and 
policy organizations of exactly this type.

**Every component is built from open source 
research with full primary source attribution.**

---

## Defensive Environment

| Defense | Configuration |
|---------|--------------|
| Elastic Security | v9.3 — all protections in **Prevent/Block** mode |
| Windows Defender | Real-time protection + all ASR rules enabled |
| LSA Protection | RunAsPPL enabled — standard Mimikatz fails |
| WDigest | Disabled — no cleartext credentials in LSASS |
| PowerShell CLM | Constrained Language Mode enforced via environment variable |
| AppLocker | Script rules enforced — Windows/ProgramFiles paths only |
| NTLM | Disabled domain-wide — Kerberos only |
| Kerberos | AES-256/AES-128 only — RC4 disabled |
| SMB | v1 disabled, signing required |
| Protected Users | Domain admins in Protected Users security group |
| Fine-grained Password Policy | 16 char min, complexity, lockout after 5 attempts |
| Windows Firewall | Enabled on all profiles |
| Audit Logging | Full audit policy — process creation, logon, DS access, credential validation |
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

## Kill Chain — Primary Source Attribution

Every phase cites the specific report where APT29 was documented using this technique.

---

### Phase 1 — Initial Access
**Techniques:** T1566.001, T1027.006  
**Primary Source:** MSTIC — *New sophisticated email-based attack from NOBELIUM* (May 2021) [18] and *Breaking down NOBELIUM's latest early-stage toolset* (May 2021) [19]

EnvyScout HTML smuggler delivered via spearphishing. The HTML file contains a 
XOR-encoded ISO file decoded and auto-downloaded by JavaScript using FileSaver.js. 
ISO mounts automatically on Windows 10+. ISO contains an LNK file executing a compiled binary stager that establishes the Havoc beacon.

Note: PowerShell CLM is enforced on VICTIM01 — PS-based stagers are not viable against the target environment.

MSTIC documented this exact delivery chain — NV.html, FileSaver.js, ISO delivery, 
LNK execution — used by NOBELIUM in May 2021 campaigns targeting diplomatic entities.

Additional documented NOBELIUM behaviors implemented:
- Web bug for victim tracking
- C: drive check to avoid sandbox execution
- iOS user-agent redirect to benign content
- NTLMv2 capture via file:// URI

**Current implementation:** EXE-based (disk artifact). DLL/fileless variant in progress.

---

### Phase 2 — C2 Establishment
**Technique:** T1071.001  
**Primary Sources:** FireEye — *SUNBURST Backdoor Analysis* (December 2020) [9][9b], MSTIC — *GoldMax, GoldFinder, and Sibot* (March 2021) [10]

Custom Havoc C2 profile implementing documented NOBELIUM behavioral parameters:
- **Sleep:** 30-60 minutes with 25% jitter
- **Active hours:** Weekdays only, 09:00-18:00 UTC+3 (Moscow business hours)
- **Activation delay:** 24 hours before first beacon (SUNBURST: 12-14 days)
- **Decoy traffic:** Legitimate-looking requests mixed with real C2 (GoldMax documented)
- **Anti-sandbox:** MAC address check — terminates on known sandbox OUI prefixes (GoldMax documented)
- **Content-Type:** application/json for tasking, application/octet-stream for exfil (SUNBURST documented)
- **URIs:** Mimic PolarWinds internal service endpoints

---

### Phase 3 — Discovery
**Techniques:** T1087.002, T1057, T1082, T1016  
**Primary Sources:** MSTIC — *Solorigate deep dive* (January 2021) [37], Mandiant — *Tracking APT29 Phishing Campaigns* (April 2022) [62]

PowerShell living-off-the-land discovery. MSTIC documented exact commands used 
post-SolarWinds compromise. Mandiant documented atypical LDAP queries including 
msPKI-CredentialRoamingTokens attribute queries against AD.

No binaries touch disk. All discovery via native PowerShell cmdlets and LDAP queries.

---

### Phase 4 — UAC Bypass
**Technique:** T1548.002  
**Attribution:** MITRE ATT&CK G0016 (technique attributed, specific method not documented in primary source reports)

fodhelper.exe registry hijack to elevate from medium to high integrity. T1548.002 
is mapped to APT29 in MITRE G0016. No primary source report documents APT29's 
specific UAC bypass implementation — this is noted explicitly.

---

### Phase 5 — Local Privilege Escalation
**Technique:** T1574.002  
**Primary Source:** Mandiant — *Assembling the Russian Nesting Doll: UNC2452 Merged into APT29* (April 2022) [29]

Mandiant documented APT29 (UNC2452) modifying "a legitimate Microsoft DLL to enable 
the DLL Side Loading of a malicious payload" and replacing "a legitimate binary with 
a malicious file of the same name."

Implemented against an intentionally vulnerable service (PolarHealthMonitor) with a 
writable service executable directory. Authenticated Users have full control over the 
directory. Malicious DLL dropped to the path specified in ServiceDll registry key. 
Service runs as LocalSystem — DLL executes as SYSTEM.

---

### Phase 6 — Credential Access
**Techniques:** T1003.001, T1047  
**Primary Source:** Mandiant — *POSHSPY Analysis* (April 2017) [55], MSTIC — *Solorigate* (January 2021) [37]

POSHSPY source code documents APT29 storing Mimikatz output inside a WMI class 
property (HiveUploadTask property of RacTask class). Mimikatz executed entirely 
in-memory via WMI. Credentials never touch disk.

LSASS dump attempted against LSA-protected process — requires advanced techniques 
to bypass RunAsPPL. Output encoded and stored in custom WMI class property.

---

### Phase 7 — Defense Evasion
**Techniques:** T1562.002, T1070.006  
**Primary Sources:** MSTIC — *Solorigate* (January 2021) [37], Mandiant — *POSHSPY* (2017) [55]

MSTIC explicitly documented APT29 using auditpol to disable specific audit 
subcategories before sensitive operations and restoring them afterward.

POSHSPY source code contains timestomping implementation filtering System32 files 
with LastWriteTime before 01/01/2013. Artifacts timestomped to match randomly 
selected System32 files.

---

### Phase 8 — Persistence (Three Layers)
**Primary Sources:** MSTIC [37], POSHSPY [55], MSTIC GoldMax [10], CrowdStrike StellarParticle [24]

**Layer 1 — Scheduled Task (T1053.005)**  
MSTIC documented exact task path: `\Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager`  
Task executes rundll32 loading a .sys-extension DLL from a temp path.

**Layer 2 — WMI Event Subscription (T1546.003)**  
POSHSPY documented exact filter name: `BfeOnServiceStartTypeChange`  
Schedule: Monday/Tuesday/Thursday/Friday/Saturday at 11:33 AM  
Advanced from CommandLineEventConsumer (documented) to ActiveScriptEventConsumer 
for improved evasion. Payload stored encrypted in WMI class property.

**Layer 3 — Sibot (T1112, T1218.005)**  
MSTIC GoldMax report documented Sibot exactly — VBScript stored in registry, 
scheduled task calling mshta.exe to execute it, task at 
`\Microsoft\Windows\WindowsUpdate\sibot`.

---

### Phase 9 — Lateral Movement
**Techniques:** T1021.006, T1078  
**Primary Sources:** MSTIC — *Solorigate* [37], CrowdStrike — *StellarParticle* [24]

WinRM PowerShell remoting to DC using stolen Kerberos credentials. MSTIC documented 
APT29 using WinRM for lateral movement. StellarParticle documented APT29 using 
separate accounts for reconnaissance vs lateral movement to limit exposure if 
one account was detected.

Temp file replacement technique documented in MSTIC [37] — tools transferred via 
SMB admin share, renamed to match legitimate Windows binaries.

---

### Phase 10 — Domain Privilege Escalation
**Technique:** T1003.006  
**Primary Source:** CrowdStrike — *StellarParticle Campaign* (January 2022) [24]

CrowdStrike documented APT29 performing DCSync to extract the KRBTGT hash in the 
StellarParticle campaign. DCSync via Mimikatz lsadump::dcsync executed in-memory 
via remote WinRM session. No code executes on DC, no LSASS access — traffic 
mimics legitimate MS-DRSR replication protocol.

---

### Phase 11 — Domain Persistence
**Techniques:** T1558.001, T1136.002  
**Primary Sources:** MSTIC — *Solorigate* [37], Mandiant confirmed

Golden Ticket forged using KRBTGT hash and domain SID. New domain admin account 
(polarsvc) created — documented APT29 pattern of creating persistent admin accounts.

---

### Phase 12 — Cleanup
**Techniques:** T1070.001, T1070.004, T1562.002  
**Primary Sources:** Mandiant — *No Easy Breach DerbyCon* (2016) [30], MSTIC — *Solorigate* [37]

No Easy Breach documented APT29's meticulous cleanup methodology. MSTIC documented 
tool removal, log clearing, and use of Microsoft SDelete for secure deletion.

AUDITPOL restored to pre-operation state. Windows event logs cleared (Security, 
System, PowerShell). All transferred tools securely wiped. WMI persistence removed 
after operational objectives met.

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
| DLL Side-Loading | T1574.002 | Mandiant UNC2452 Merge [29] |
| LSASS Memory | T1003.001 | POSHSPY Mandiant [55] |
| Windows Management Instrumentation | T1047 | POSHSPY Mandiant [55] |
| Disable Windows Event Logging | T1562.002 | MSTIC Solorigate [37] |
| Timestomp | T1070.006 | POSHSPY [55] |
| Scheduled Task | T1053.005 | MSTIC Solorigate [37] |
| WMI Event Subscription | T1546.003 | POSHSPY Mandiant [55] |
| Modify Registry | T1112 | MSTIC GoldMax [10] |
| Mshta | T1218.005 | MSTIC GoldMax [10] |
| Windows Remote Management | T1021.006 | MSTIC Solorigate [37] |
| Valid Accounts | T1078 | CrowdStrike StellarParticle [24] |
| DCSync | T1003.006 | CrowdStrike StellarParticle [24] |
| Golden Ticket | T1558.001 | MSTIC Solorigate [37] |
| Create Domain Account | T1136.002 | MSTIC Solorigate [37] |
| Clear Windows Event Logs | T1070.001 | MSTIC Solorigate [37] |
| File Deletion | T1070.004 | No Easy Breach [30] |

---

## Evasion Stack

Built using publicly documented open source research, ported to Havoc. All implemented as position-independent code compiled with mingw-w64.

| Component | Implementation | Detection Defeated | Source |
|-----------|---------------|-------------------|----|
| Sleep masking | Hook Sleep → RC4 encrypt beacon memory → RX→RW during sleep → restore on wake. Random key per sleep cycle via xorshift RNG | Elastic memory scanner | C5pider — [Ekko](https://github.com/Cracked5pider/Ekko) |
| Indirect syscalls | RecycledGate — Hell's/Halo's Gate SSN resolution. Syscall executed from NTDLL .text section | NTDLL userland hooks | thefLink — [RecycledGate](https://github.com/thefLink/RecycledGate) |
| Call stack spoofing | Draugr — fake BaseThreadInitThunk+0x17 and RtlUserThreadStart+0x2c frames. Gadget from dfshim.dll with preceding call instruction | ETW-TI call stack analysis | mgeeky — [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer) + WithSecure research |
| Static signature removal | XOR-masked payload delivery, Havoc string replacement | YARA / static AV | Public — [Havoc Binary block](https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD) |
| RWX elimination | Allocate RW → copy + decrypt shellcode → flip RX via indirect syscall | RWX memory alerts | Standard PE loader — Windows Internals |
| Memory cleanup | Loader zeroes shellcode buffer on exit. RtlExitUserProcess — exit code 0 | Post-execution forensics | FireEye SUNBURST [9] |
| CRT elimination | No windows.h, no stdlib. All types manual. strcmp replaced with my_strcmp. memcpy replaced with byte loop | Import table analysis | Standard OPSEC practice |

---

## APT29 Behavioral Checks

All checks implemented in loader before execution. Loader silently terminates and
zeroes its own memory if any check fails. Attributed to documented APT29 campaigns.

| Check | Behavior | Attribution |
|-------|----------|-------------|
| Domain allowlist | Only execute if joined to `polar.local` — abort otherwise | FireEye SUNBURST [9] |
| Domain blocklist | Terminate if security vendor domain detected | FireEye SUNBURST [9] |
| MAC address blocklist | Terminate if sandbox MAC OUI prefix detected (VMware/VBox/Hyper-V/KVM/Docker/AWS/GCP) | MSTIC GoldMax [10] |
| Activation delay | 24 hour delay before first execution | FireEye SUNBURST [9] |
| Working hours | Only execute weekdays 09:00-18:00 UTC+3 (Moscow hours) | MSTIC GoldMax [10] |
| Decoy traffic | 1-4 WinHTTP GET requests to legitimate domains before beacon | MSTIC GoldMax [10] |

---

## Memory Self-Destruction

On failed behavioral check or clean exit, loader zeroes its own memory.
Memory forensics finds nothing — no shellcode, no loader artifacts.
Attributed to FireEye SUNBURST [9] — documented APT29 cleaning own memory on termination.

---

## POSHSPY 2026

Mandiant published POSHSPY source in 2017 [55]. This project builds the missing server-side component and a modernized client with 2026 evasion layered on top.

**Status:** Skeleton public. Protocol implementation complete and validated. End-to-end testing and Elastic evasion integration in progress.

**What's implemented:**
- `crypto.py` — full VC class reimplementation: AES-CBC, RSA PKCS1v1.5, PKI encrypt/decrypt/sign/verify, file signature masking
- `protocol.py` — auth token handshake, 2048-byte chunked upload, ACK cookie generation
- `dga.py` — .NET System.Random reimplemented in Python, deterministic URL generation matching PS1 output exactly
- `server.py` — Flask C2 server: decoy GET, auth token issuance, payload delivery, chunk reassembly

**Original POSHSPY behavior preserved (Mandiant [55]):**
- WMI class property payload storage (HiveUploadTask / RacTask)
- WMI event subscription execution
- Filter name: `BfeOnServiceStartTypeChange`
- Schedule: Mon/Tue/Thu/Fri/Sat 11:33 AM

**Novel 2026 additions:**
- Payload AES-encrypted in WMI property — not plaintext
- Indirect syscalls for WMI COM calls
- Sleep masking during execution windows
- Timestomping on any artifacts

---

## Sandbox Evasion Validation

Loader submitted to public sandboxes after completion to document behavioral check effectiveness.

| Sandbox | Result | Triggered By | Evidence |
|---------|--------|-------------|---------|
| any.run | 🔴 Pending | | |
| hybrid-analysis | 🔴 Pending | | |
| Joe Sandbox | 🔴 Pending | | |

---

## Detection Results

| Phase | Technique | Elastic Alert | Defender Alert | Bypassed | Notes |
|-------|-----------|--------------|----------------|---------|-------|
| Initial Access | HTML Smuggling T1027.006 | 🔴 Pending | ✅ None | ✅ | ISO drops, mounts, LNK executes — 0 Defender alerts |
| Persistence | WMI Event Subscription T1546.003 | 🔴 Pending | ✅ None | ✅ | BfeOnServiceStartTypeChange — no alert on creation or persistence |
| Execution | Loader — indirect syscalls + Ekko sleep mask | 🔴 Pending | ✅ None | ✅ | 0 detections confirmed on latest Defender |

---

## Primary Sources

| ID | Report | Author | Year | Link |
|----|--------|--------|------|------|
| [9][9b] | SUNBURST Backdoor Analysis + Additional Details | FireEye/Mandiant | 2020 | [Link](https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor) |
| [10] | GoldMax, GoldFinder, and Sibot | MSTIC | 2021 | [Link](https://www.microsoft.com/en-us/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-multilayered-persistence/) |
| [18][19] | NOBELIUM EnvyScout toolset | MSTIC | 2021 | [Link](https://www.microsoft.com/en-us/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/) |
| [24] | StellarParticle Campaign | CrowdStrike | 2022 | [Link](https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/) |
| [29] | UNC2452 Merged into APT29 | Mandiant | 2022 | [Link](https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29) |
| [30] | No Easy Breach DerbyCon | Mandiant | 2016 | [Link](https://www.slideshare.net/MatthewDunwoody1/no-easy-breach-derby-con-2016) |
| [37] | Deep Dive into Solorigate | MSTIC | 2021 | [Link](https://www.microsoft.com/en-us/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/) |
| [55] | POSHSPY — APT29 Fileless WMI Backdoor | Mandiant | 2017 | [Link](https://www.mandiant.com/resources/blog/dissecting-one-of-apt29s-fileless-wmi-and-powershell-backdoors) |
| [62] | Tracking APT29 Phishing Campaigns | Mandiant | 2022 | [Link](https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns) |

---

## Status

| Component | Status |
|-----------|--------|
| Lab environment | ✅ Complete |
| Havoc C2 profile (apt29.yaotl) | ✅ Complete |
| EnvyScout HTML smuggler generator | ✅ Complete — EXE-based, DLL/fileless in progress |
| Loader — RecycledGate indirect syscalls | ✅ Complete |
| Loader — Ekko sleep masking | ✅ Complete |
| Loader — APT29 behavioral checks | ✅ Complete |
| Loader — Memory self-destruction | ✅ Complete |
| Loader — Draugr call stack spoofing | 🔴 Pending |
| POSHSPY 2026 server skeleton | 🟡 Public — testing in progress |
| Sandbox evasion validation | 🔴 Pending |
| Full kill chain execution | 🔴 Pending |
| Detection results table | 🟡 Partial — Defender results in, Elastic pending |

---

## AI Assistance Disclosure

Claude (Anthropic) was used in the development of this project to:
- Beautify and format code for readability
- Structure and format this README
- Aggregate primary source references into a single attribution table
- Debug implementation issues during development

All techniques, primary source attributions, tool design decisions, and security research are the author's own work.

---

## Disclaimer

This repository is for authorized security research and defensive education only.
All techniques were executed against controlled lab infrastructure owned by the author.
Do not use against systems you do not own or have explicit written authorization to test.

Techniques are attributed to APT29 based on publicly available threat intelligence 
from FireEye/Mandiant, Microsoft Threat Intelligence Center, CrowdStrike, and 
government advisories (NCSC, CISA, NSA).

---

## Author

**61tiger** — Purdue University, BS Cybersecurity  
CRTO | CRTL  
[GitHub](https://github.com/61tiger) | [LinkedIn](https://linkedin.com/in/aryan-cybersecurity)
