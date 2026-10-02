; Test for RLINK qlb: routine HELLO callable from QuickBASIC.
; start is the entry-point: Pascal style far procedure, QB start-up/shut-down calls it
; with the selector as parameter (it is also in CX), the procedure removes it with retf 2.
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
