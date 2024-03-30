section .data
    extern NtOpenProcessSSN
    extern NtOpenProcessAddr

section .text

    ; global SysSet
    ; global SysInvoke

    ; global SysNtOpenProcess
    ; global SysNtAllocateVirtualMemory
    ; global SysNtWriteVirtualMemory
    ; global SysNtCreateThreadEx
    ; global SysNtWaitForSingleObject
    ; global SysNtClose

    ; SysSet:
    ;     mov r11, rcx
    ;     ret

    ; SysInvoke:
    ;     mov r10, rcx
    ;     mov eax, [r11 + 0x8]
    ;     jmp qword [r11]
    ;     ret

    ; SysNtOpenProcess:
        mov r10, rcx
        mov eax, NtOpenProcessSSN
        jmp qword [NtOpenProcessAddr]
        ret

    ; SysNtAllocateVirtualMemory:
    ;     mov r10, rcx
    ;     mov eax, NtAllocateVirtualMemorySSN
    ;     jmp qword [NtAllocateVirtualMemorySyscall]
    ;     ret

    ; SysNtWriteVirtualMemory:
    ;     mov r10, rcx
    ;     mov eax, NtWriteVirtualMemorySSN
    ;     jmp qword [NtWriteVirtualMemorySyscall]
    ;     ret

    ; SysNtCreateThreadEx:
    ;     mov r10, rcx
    ;     mov eax, NtCreateThreadExSSN
    ;     jmp qword [NtCreateThreadExSyscall]
    ;     ret

    ; SysNtWaitForSingleObject:
    ;     mov r10, rcx
    ;     mov eax, NtWaitForSingleObjectSSN
    ;     jmp qword [NtWaitForSingleObjectSyscall]
    ;     ret

    ; SysNtClose:
    ;     mov r10, rcx
    ;     mov eax, NtCloseSSN
    ;     jmp qword [NtCloseSyscall]
    ;     ret
