bits 16

global start
extern _main

section .text
        nop
start:
        call far _main
        call b
        mov  ah,4ch
        int  21h
b:      ret
        dw start