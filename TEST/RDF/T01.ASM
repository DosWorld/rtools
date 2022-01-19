bits 16

global start
extern _main
; extern paramstr

section .text
        nop
start:
        call _main
        call b
        mov  ah,4ch
        int  21h
b:      ret
        dw start