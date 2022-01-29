bits 32
global start
section .text
_main3:
        mov edx, hello
        mov ah, 9
        int 21h
        ret
start:
        mov  ebx, [call_addr]
        call ebx
        mov  ah,4ch
        int  21h
        ret
call_addr:
        dd _main3
hello:
        db 'Hello, world!$'
section .data
db 0