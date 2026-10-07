        bits 16
        cpu 8086
        global  start
        extern  KERNEL_INITTASK
        segment .text
start:
        call    far KERNEL_INITTASK
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h
        segment .data
msg:    db      'NE test 3', 13, 10, '$'
