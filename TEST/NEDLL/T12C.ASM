        bits 16
        cpu 8086
        global  unusedfn
        segment .text
unusedfn:
        mov     ax, 3
        times 200 nop
        retf
        segment .data
unused: times 100 db 7
