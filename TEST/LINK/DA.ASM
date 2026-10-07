bits 16
global start
extern dup
section .text
start:
        call    dup
        mov     ax, 4C00h
        int     21h
