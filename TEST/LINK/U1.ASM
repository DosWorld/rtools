bits 16
global unused
extern nothere
section .text
unused:
        call    nothere
        times 500 nop
        ret
