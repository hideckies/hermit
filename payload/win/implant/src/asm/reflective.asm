section .text
     global ReflectiveCaller

ReflectiveCaller:
     call pop
     pop:
     pop rcx    
          
loop:
     xor rbx, rbx
     mov ebx, 0x5A4D
     dec rcx
     cmp bx,  word ds:[rcx]
     jne loop
     xor rax, rax
     mov ax,  [ rcx + 0x3C ]
     add rax, rcx
     xor rbx, rbx
     add bx,  0x4550
     cmp bx,  word ds:[rax]
     jne loop
     mov rax, rcx
     ret