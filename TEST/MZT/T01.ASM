bits 16

global start
extern _main

section .text
        nop
start:
        push cs
        pop  ds
        call _main
        call b
        mov  ah,4ch
        int  21h
b:      ret
section .data
