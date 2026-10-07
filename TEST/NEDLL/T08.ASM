        bits 16
        cpu 8086
        global  start
        global  hello
        segment .text
start:
        mov     ax, 1
        retf
hello:
        push    ds
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        pop     ds
        retf
        segment .data
msg:    db      'NE dll two', 13, 10, '$'
