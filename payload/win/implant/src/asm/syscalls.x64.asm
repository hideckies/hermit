; Inspired:
;   https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/asm/Syscall.x64.asm#L1

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
