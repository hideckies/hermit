section .text
    global SysSample
    global SysSet
    global SysInvoke

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