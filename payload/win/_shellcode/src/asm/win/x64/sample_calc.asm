; nasm -f win32 -o tmp/shellcode.bin src/asm/x86/calc.asm
; python3 bin2shellcode tmp/shellcode.bin
section .data

section .bss

section .text
    global _start         ; must be declared for linker

_start:
    xor  ecx, ecx         ; zero out ecx
    push ecx              ; string terminator 0x00 for "calc.exe" string
    push 0x6578652e       ; exe. : 6578652e
    push 0x636c6163       ; clac : 636c6163

    mov  eax, esp         ; save pointer to "calc.exe" string in eax

    ; UINT WinExec([in] LPCSTR lpCmdLine, [in] UINT   uCmdShow);
    inc  ecx              ; uCmdShow = 1
    push ecx              ; uCmdShow *ptr to stack in 2nd position - LIFO
    push eax              ; lpcmdLine *ptr to stack in 1st position
    mov  ebx, 0x76f0e5fd  ; call WinExec() function addr in kernel32.dll
    call ebx

    ; void ExitProcess([in] UINT uExitCode);
    xor  eax, eax         ; zero out eax
    push eax              ; push NULL
    mov  eax, 0x76ed214f  ; call ExitProcess function addr in kernel32.dll
    jmp  eax              ; execute the ExitProcess function
