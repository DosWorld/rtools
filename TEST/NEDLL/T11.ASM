        bits 16
        cpu 8086
        global  start
        extern  myhello
        extern  ord1
        segment .text
start:
        call    far myhello
        call    far ord1
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h
        segment .data
msg:    db      'NE test 11', 13, 10, '$'
