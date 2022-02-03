bits 32

global _main

section .text
        nop
_main:
        mov edx, _mdata
        mov ah, 9
        int 21h

        ret
section .data
_mdata:
        db 'Hello, world!$'
db 0