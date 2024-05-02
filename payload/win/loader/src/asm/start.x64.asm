; Reference:
; https://github.com/SolomonSklash/netntlm/blob/master/asm/x64/start.asm
global GetRIP
global Leave

section .text$F

    GetRIP:
        call get_ret_ptr

    get_ret_ptr:
        pop rax
        sub rax, 5
        ret

    Leave:
        db 'O', 'S', 'H', 'I', 'M', 'A', 'I'