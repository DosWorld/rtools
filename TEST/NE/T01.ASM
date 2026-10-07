        bits 16
        cpu 8086
        global  start
        extern  say
        extern  var2
        segment .text
start:
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        call    far say
        call    far [ptr]
        mov     ax, seg var2
        mov     es, ax
        mov     ax, [es:var2]
        cmp     ax, 1234
        jne     bad
        mov     ax, seg counter
        mov     ds, ax
        mov     word [counter], 5
        mov     ax, seg okmsg
        mov     ds, ax
        mov     dx, okmsg
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h
bad:
        mov     ax, 4C01h
        int     21h
        segment .data
msg:    db      'NE test 1', 13, 10, '$'
okmsg:  db      'OK', 13, 10, '$'
ptr:    dw      say, seg say
        segment .bss
counter: resw   1
