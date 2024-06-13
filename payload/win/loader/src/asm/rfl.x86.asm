global _ReflectiveCaller

section .text

     _ReflectiveCaller:
          call pop
          pop:
          pop ecx
               
     loop:
          xor ebx, ebx
          mov ebx, 0x5A4D
          dec ecx
          cmp bx,  word ds:[ecx]
          jne loop
          xor eax, eax
          mov ax,  [ecx + 0x3C]
          add eax, ecx
          xor ebx, ebx
          add bx,  0x4550
          cmp bx,  word ds:[eax]
          jne loop
          mov eax, ecx
          ret