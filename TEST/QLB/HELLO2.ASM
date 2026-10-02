; Test for RLINK qlb: data, bss and segment relocation inside a QuickLibrary.
        bits 16
        cpu 8086
        global  HELLO2
        global  COUNT

        segment .text

; prints message from the data segment
HELLO2: push    ds
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        pop     ds
        retf

; counts calls (bss), prints message by pointer from the data segment
COUNT:  push    ds
        mov     ax, seg counter
        mov     es, ax
        inc     word [es:counter]
        mov     ax, seg ptr
        mov     ds, ax
        mov     dx, [ptr]
        mov     ah, 9
        int     21h
        pop     ds
        retf

        segment .data

msg:    db      'Hello from data!', 13, 10, '$'
ptr:    dw      msg2
msg2:   db      'Counting...', 13, 10, '$'

        segment .bss

counter resw    1
