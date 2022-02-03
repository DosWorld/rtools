bits 32

global start
extern _main

section .text
        mov edx, hello2
        mov ah,9
        int 21h
start:
        mov  ax,901h
        int  31h
        cld
        call main
        mov  ah,4ch
        int  21h
main:
        mov edx, hello
        mov ah,9
        int 21h
        ret
hello: db 'Hello, world!$'
hello2: db 'False entry',10,13,'$'
