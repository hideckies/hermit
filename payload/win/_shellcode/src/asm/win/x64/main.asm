; main.asm: Call MessageBox
BITS 64

section .text
global _start

_start:
    ; Get the address of the kernel32.dll
    xor rax, rax                ; Avoid null bytes
    mov rax, [gs:rax + 0x60]    ; TEB->PEB
    mov rax, [rax + 0x18]       ; PEB->Ldr (PEB_LDR_DATA)
    mov rsi, [rax + 0x10]       ; Ldr->Ldr.InLoadOrderModuleList.Flink
    lodsq                       ; Move to the next element -> InMemoryOrderLinks of ntdll.dll (second module)
    xchg rax, rsi               ; Exchange rax and rsi
    lodsq                       ; Move to the next element -> InMemoryOrderLinks of kernel32.dll (third module)
    mov rax, [rax + 0x10]       ; The base address of kernel32.dll

    ; Parse the PE file and find the export directory

    ; Get addresses of LoadLibrary, GetProcAddress functions that are exported from kernel32.dll
    ; TODO

    ; Call desired functions with LoadLibrary, GetProcAddress functions
    ; TODO




    ; Set arguments of MessageBox
    xor r9d, r9d             ; uType = MB_OK
    lea r8, [rel msgCaption] ; lpCaption
    lea rdx, [rel msgText]   ; lpText
    xor rcx, rcx             ; hWnd = NULL

    ; Call MessageBoxA
    mov rax, 0x12345678      ; Placeholder for MessageBoxA. (It's required to resolve dynamatically when practice.)
    call rax

    ; Exit the program
    xor rcx, rcx             ; Parameters for ExitProcess's ExitCode
    mov rax, 0x87654321      ; Placeholdre for ExitProcess (Its' required to resolve dynamatically when practice.)
    call rax

section .data
msgText db 'Hello, World!', 0
msgCaption db 'Test', 0
