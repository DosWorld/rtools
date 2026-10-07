        bits 16
        cpu 8086
        global  say
        global  var2
        segment .text
say:
        push    ds
        mov     ax, seg m2
        mov     ds, ax
        mov     dx, m2
        mov     ah, 9
        int     21h
        pop     ds
        retf
        segment .data
m2:     db      'NE test 2', 13, 10, '$'
var2:   dw      1234
