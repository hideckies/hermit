global SysSet
global SysInvoke

section .text

    SysSet:
        mov r11, rcx
        ret

    SysInvoke:
        mov r10, rcx
        mov eax, [r11 + 0x8]
        jmp qword [r11]
        ret
