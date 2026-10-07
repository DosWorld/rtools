bits 32

global start
extern dlladd

section .text
start:
        call    dlladd
        cmp     eax, 42
        jne     bad
        mov     edx, msg
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h
bad:
        mov     ax, 4C01h
        int     21h

section .data
msg:    db      'DosPE import OK', 13, 10, '$'
