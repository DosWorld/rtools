        bits 16
        cpu 8086
        global  start
        global  HELLO

start:  retf    2

HELLO:  push    ds
        push    cs
        pop     ds
        mov     dx, msg
        mov     ah, 9
        int     21h
        pop     ds
        retf

msg:    db      'Hello, world!', 13, 10, '$'
