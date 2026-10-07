        bits 16
        cpu 8086
        global  start
        global  expfn
        extern  usedfn
        segment .text
start:
        mov     ax, 1
        retf
expfn:
        call far usedfn
        retf
