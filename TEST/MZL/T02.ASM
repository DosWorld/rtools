bits 16

global _main
global _mdata

section .text
        nop
_main:
        mov ax, seg hello
        mov ds, ax
        mov dx, hello
        mov ah,9
        int 21h
        retf
section .data
hello:
        db 'Hello, world!$'
_mdata: