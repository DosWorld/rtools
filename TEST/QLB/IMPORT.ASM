        bits 16
        cpu 8086
        global  start
        global  _TWICE
        global  RAISE5
        global  SYMSEG
        extern  B$RUNERR
        extern  b_ULSymSeg

        segment .text

start:  retf    2

_TWICE: push    bp
        mov     bp, sp
        mov     bx, [bp+6]
        mov     ax, [bx]
        add     ax, ax
        pop     bp
        retf

RAISE5: mov     bx, 5
        call    far B$RUNERR
        retf

SYMSEG: push    ds
        mov     ax, seg b_ULSymSeg
        mov     ds, ax
        mov     ax, [b_ULSymSeg]
        pop     ds
        retf
