bits 32

global start
extern _main

section .text
start:
        call _main
        call b
        mov  ah,4ch
        int  21h
b:      ret

section .bss
 resb(128)