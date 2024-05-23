extern Entry

global AlignRSP
global ReflectiveCaller

section .text$A

     AlignRSP:
          push rsi
          mov rsi, rsp
          and rsp, 0x0FFFFFFFFFFFFFFF0
          sub rsp, 0x020
          call Entry
          mov rsp, rsi
          pop rsi
          ret

section .text$F

     ReflectiveCaller:
          call caller
          caller:
          pop rcx
               
     loop:
          xor rbx, rbx
          mov ebx, 0x5A4D
          inc rcx
          cmp bx,  [rcx]
          jne loop
          xor rax, rax
          mov ax,  [rcx + 0x3C]
          add rax, rcx
          xor rbx, rbx
          add bx,  0x4550
          cmp bx,  [rax]
          jne loop
          mov rax, rcx
          ret