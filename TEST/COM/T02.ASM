bits 16

global _main
global _mdata

section .text
        nop
_main:
        mov dx, hello
        mov ah,9
        int 21h
        retn
section .data
hello:
        db 'Hello, world!$'
_mdata: