        bits 16
        cpu 8086
        global  start
        extern  say
        segment .text
start:
        call    say
        mov     ax, 4C00h
        int     21h
