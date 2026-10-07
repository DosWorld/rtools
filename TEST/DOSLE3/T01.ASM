bits 32

global start

section .text
start:
        mov     edx, [ptr]
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h
        times 4094 - ($ - $$) db 90h

section .data
ptr:    dd      msg
        times 70000 db 0
msg:    db      'LE fixup OK', 13, 10, '$'
