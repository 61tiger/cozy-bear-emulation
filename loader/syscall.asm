; syscall.asm
; RecycledGate technique — two stage syscall execution
;
; PrepareSyscall — stores SSN in r11, gate address in r10
; DoSyscall      — executes syscall from ntdll .text via gate
;
; usage in C:
;   PrepareSyscall(ssn, gate);
;   DoSyscall(arg1, arg2, ...);

section .text
global PrepareSyscall
global DoSyscall

PrepareSyscall:
    ; rcx = SSN, rdx = gate address
    xor r11, r11
    xor r10, r10
    mov r11, rcx    ; r11 = SSN — DoSyscall reads this
    mov r10, rdx    ; r10 = gate address — DoSyscall jumps here
    ret

DoSyscall:
    ; rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4, stack = arg5+
    push r10        ; push gate address onto stack as return address
    xor rax, rax
    mov r10, rcx    ; r10 = arg1 (Windows syscall ABI requires r10=rcx)
    mov eax, r11d   ; eax = SSN (kernel reads syscall number from here)
    ret             ; ret pops gate address — jumps to syscall;ret in ntdll