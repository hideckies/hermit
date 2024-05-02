global _SysSet
global _SysInvoke

section .text

    _SysSet:
        mov edx, [esp + 0x4]
        ret

    _SysInvoke:
        mov ebx, [edx + 0x0]
        mov eax, [edx + 0x4]
        mov edx, esp
        sub edx, 0x4
        call DWORD ebx
        ret      
