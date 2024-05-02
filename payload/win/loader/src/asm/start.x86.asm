; Reference:
; https://github.com/SolomonSklash/netntlm/blob/master/asm/x64/start.asm
global _GetRIP
global _Leave

section .text$F

    _GetRIP:
        call _get_ret_ptr

        _get_ret_ptr:
        pop eax
        sub eax, 5
        ret

    _Leave:
        db 'O', 'S', 'H', 'I', 'M', 'A', 'I'