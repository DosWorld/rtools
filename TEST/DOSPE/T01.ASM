bits 32

global start
extern _main

section .text
start:
        mov  eax,[d]
        call eax
        call b
        mov  ah,4ch
        int  21h
b:      ret

d:   dd _main

section .bss
 resb(128)