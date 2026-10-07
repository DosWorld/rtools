        bits 16
        cpu 8086
        global  start
        extern  MYLIB_1
        extern  MYLIB2_1
        segment .text
start:
        call    far MYLIB_1
        call    far MYLIB2_1
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h
        segment .data
msg:    db      'NE test 9', 13, 10, '$'
