; Inspired:
;   https://github.com/HavocFramework/Havoc/blob/ea3646e055eb1612dcc956130fd632029dbf0b86/payloads/Demon/src/asm/Syscall.x64.asm#L1

global SysSet
global SysInvoke

section .text

    SysSet:
        mov edx, [esp + 0x4]
        ret

    SysInvoke:
        mov ebx, [edx + 0x0]
        mov eax, [edx + 0x4]
        mov edx, esp
        sub edx, 0x4
        call DWORD ebx
        ret      
