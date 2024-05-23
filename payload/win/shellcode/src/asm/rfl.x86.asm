extern Entry

global AlignRSP
global ReflectiveCaller

section .text$A

     AlignRSP:
          push esi
          mov  esi, esp
          and  esp, 0x0FFFFFFF0
          sub  esp, 0x020
          call Entry
          mov  esp, esi
          pop  esi
          ret

section .text$F

     ReflectiveCaller:
          call caller
     caller:
          pop ecx
               
     loop:
          xor ebx, ebx
          mov ebx, 0x5A4D
          inc ecx
          cmp bx,  [ecx]
          jne loop
          xor eax, eax
          mov ax,  [rcx + 0x3C]
          add eax, ecx
          xor ebx, ebx
          add bx,  0x4550
          cmp bx,  [eax]
          jne loop
          mov eax, ecx
          ret