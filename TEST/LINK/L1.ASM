bits 16
global start
extern helper
section .text
start:
        call    helper
        mov     ax, 4C00h
        int     21h
