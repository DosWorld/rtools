bits 16

global start
extern _main

section .text
        nop
start:
        mov  ax, seg ddd
        mov  ds, ax
        call _main
        call b
        mov  ah,4ch
        int  21h
b:      ret
section .data
ddd:   dw start