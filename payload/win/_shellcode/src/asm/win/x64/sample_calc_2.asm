; main.asm: Execute calc.exe
section .text
    global _start

_start:
    ; WinExec("calc.exe", SW_SHOWNORMAL)
    mov rax, 1                ; SW_SHOWNORMAL = 1
    push rax
    mov rdx, calcStr          ; Load address to RDX register
    sub rsp, 32               ; Shadow space
    call WinExec              ; Call WinExec
    add rsp, 40               ; Clean up stack

    ; ExitProcess(0)
    xor rcx, rcx              ; Argument 0 (Exit Code)
    call ExitProcess          ; Call ExitProcess

section .data
    calcStr db 'calc.exe', 0  ; Null-terminated

section .idata
    ; Import directory for kernel32.dll
    import
    dd 0, 0, 0, Rva(kernel32Name), Rva(kernel32Imports)
    dd 0, 0, 0, 0, 0

    ; Import kernel32.dll functions
    kernel32Imports:
        WinExec dq Rva(_WinExec)
        ExitProcess dq Rva(_ExitProcess)
        dq 0

    ; Function names
    _WinExec db 'WinExec', 0
    _ExitProcess db 'ExitProcess', 0

    ; DLL
    kernel32Name db 'KERNEL32.DLL', 0

    align 4

    ; Relocation directory - not used for this sample
    relocations:
        dd 0, 0, 0

; It's required for creating the executable
section .reloc fixups data discardable
