section .data

extern NtOpenProcessSSN
extern NtOpenProcessSyscall

extern NtAllocateVirtualMemorySSN
extern NtAllocateVirtualMemorySyscall

extern NtWriteVirtualMemorySSN
extern NtWriteVirtualMemorySyscall

extern NtCreateThreadExSSN
extern NtCreateThreadExSyscall

extern NtWaitForSingleObjectSSN
extern NtWaitForSingleObjectSyscall

extern NtCloseSSN
extern NtCloseSyscall

section .text

global NtOpenProcess
NtOpenProcess:
    mov r10, rcx
    mov eax, [rel NtOpenProcessSSN]
    jmp qword [rel NtOpenProcessSyscall]
    ret

global NtAllocateVirtualMemory
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, [rel NtAllocateVirtualMemorySSN]
    jmp qword [rel NtAllocateVirtualMemorySyscall]
    ret

global NtWriteVirtualMemory
NtWriteVirtualMemory:
    mov r10, rcx
    mov eax, [rel NtWriteVirtualMemorySSN]
    jmp qword [rel NtWriteVirtualMemorySyscall]
    ret

global NtCreateThreadEx
NtCreateThreadEx:
    mov r10, rcx
    mov eax, [rel NtCreateThreadExSSN]
    jmp qword [rel NtCreateThreadExSyscall]
    ret

global NtWaitForSingleObject
NtWaitForSingleObject:
    mov r10, rcx
    mov eax, [rel NtWaitForSingleObjectSSN]
    jmp qword [rel NtWaitForSingleObjectSyscall]
    ret

global NtClose
NtClose:
    mov r10, rcx
    mov eax, [rel NtCloseSSN]
    jmp qword [rel NtCloseSyscall]
    ret
