section .text
global _start

_start:
    xor     rax, rax            ; Clear rax register
    push    rax                 ; Push NULL terminator onto the stack
    push    0x68732f6e69622f    ; Push "hs/nib/" onto the stack (reversed for little endian)
    push    0x63736d2e656d6f63  ; Push "csmo.em" onto the stack (reversed for little endian)
    mov     rcx, rsp            ; Move the address of "/csmo.em/nib/" to rcx (command string)
    xor     rdx, rdx            ; Clear rdx register (parameters)
    xor     r8, r8              ; Clear r8 register (parameters)
    xor     r9, r9              ; Clear r9 register (parameters)
    mov     al, 0x60            ; Load syscall number for NtAllocateVirtualMemory
    mov     dl, 0x4             ; Load the allocation type (MEM_COMMIT)
    mov     r8d, 0x40           ; Load the protection (PAGE_EXECUTE_READWRITE)
    lea     r9, [rcx+8]         ; Load the size of the memory block to allocate
    syscall                     ; Call NtAllocateVirtualMemory to allocate memory

    mov     rsi, rcx            ; Move the address of "/csmo.em/nib/" to rsi (command string)
    mov     rdx, rsp            ; Move the address of the NULL terminator to rdx (parameters)
    xor     rax, rax            ; Clear rax register
    mov     al, 0x70            ; Load syscall number for NtCreateThreadEx
    syscall                     ; Call NtCreateThreadEx to create a new thread

    xor     rax, rax            ; Clear rax register
    mov     al, 0x3c            ; Load syscall number for NtTerminateThread
    xor     rdi, rdi            ; Clear rdi register (exit code)
    syscall                     ; Call NtTerminateThread to terminate the thread
