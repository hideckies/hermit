section .text
    global SysSample
    global SysSet
    global SysInvoke
    ;
    global SyscallPrepare
    global SyscallInvoke

SysSample:
    mov rax, rcx
    mov eax, [rax]
    add eax, [rax + 0x8]
    ret

SysSet:
    mov r11, rcx
    ret

SysInvoke:
    mov r10, rcx
    mov eax, [r11 + 0x8]
    jmp qword [r11]
    ret

; TEST
SyscallPrepare:
    nop
    xor r11, r11
    nop
    nop
    mov r11d, ecx
    ret

; TEST
SyscallInvoke:
    nop
    xor eax, eax
    mov r10, rcx
    nop
    mov eax, r11d
    nop
    syscall
    nop
    ret