; Copyright (c) 2026 Viacheslav Komenda
;
; This is free and unencumbered software released into the public domain.
; See the file UNLICENSE or <https://unlicense.org>.

%define CLIENT32 0
%include "RDFLDRM.INC"

MAXMOD  equ     16
MODSZ   equ     148
M_HSEG  equ     0
M_HLEN  equ     2
M_CSEG  equ     4
M_DSEG  equ     6
M_CNUM  equ     8
M_DNUM  equ     10
M_BNUM  equ     12
M_DLEN  equ     14
M_CALI  equ     16
M_PATH  equ     18

pm_init:
        mov     cx, [fnlen]
.dir:
        test    cx, cx
        jz      .dirdone
        mov     bx, cx
        mov     al, [fname+bx-1]
        cmp     al, '\'
        je      .dirdone
        cmp     al, ':'
        je      .dirdone
        dec     cx
        jmp     .dir
.dirdone:
        mov     [dirlen], cx
        mov     dx, fname
        call    loadmod
        mov     [lkseg], ds
        mov     word [lkoff], start_name
        call    lookup
        jnc     .have
        mov     ax, [mods+M_CSEG]
        mov     [tseg], ax
        mov     word [toff], 0
.have:
        mov     bx, [tseg]
        mov     dx, [toff]
        mov     ax, [mods+M_DSEG]
        mov     cx, [pspsel]
        mov     di, termstub
        mov     ss, ax
        mov     sp, 0FFF0h
        push    cs
        push    di
        push    bx
        push    dx
        mov     ds, ax
        mov     es, cx
        xor     ax, ax
        xor     bx, bx
        xor     cx, cx
        xor     dx, dx
        xor     si, si
        xor     di, di
        xor     bp, bp
        retf

termstub:
        mov     ax, 4C00h
        int     21h

fail:
        push    dx
        mov     dx, msg_pre
        mov     ah, 9
        int     21h
        pop     dx
        mov     ah, 9
        int     21h
        mov     dx, msg_crlf
        mov     ah, 9
        int     21h
        mov     ax, 4C01h
        int     21h

e_open:
        mov     dx, m_open
        jmp     fail
e_read:
        mov     dx, m_read
        jmp     fail
e_mem:
        mov     dx, m_mem
        jmp     fail
e_fmt:
        mov     dx, m_fmt
        jmp     fail
e_seg:
        mov     dx, m_seg
        jmp     fail
e_many:
        mov     dx, m_many
        jmp     fail
e_rec:
        mov     dx, m_rec
        jmp     fail
e_near:
        mov     dx, m_near
        jmp     fail
e_big:
        mov     dx, m_big
        jmp     fail

mkblk:
        mov     [blksz], ax
        mov     [blksz+2], dx
        mov     [blkacc], cl
        mov     bx, dx
        mov     cx, ax
        mov     ax, 501h
        int     31h
        nc      e_mem
        mov     [m_base], cx
        mov     [m_base+2], bx
        mov     ax, [blksz]
        mov     dx, [blksz+2]
        sub     ax, 1
        sbb     dx, 0
        mov     [m_limit], ax
        mov     [m_limit+2], dx
mkdesc:
        call    newsel
        mov     [m_sel], ax
        mov     al, [blkacc]
        mov     [m_acc], al
        mov     byte [m_gran], 0
        call    mksel
        mov     ax, [m_sel]
        ret

mkalias:
        mov     byte [blkacc], 92h
        jmp     mkdesc

zerowords:
        push    es
        push    di
        mov     es, ax
        xor     di, di
        xor     ax, ax
        cld
        rep     stosw
        pop     di
        pop     es
        ret

readx:
        mov     bx, [fh]
        mov     ah, 3Fh
        push    cx
        int     21h
        pop     cx
        nc     e_read
        cmp     ax, cx
        nne     e_read
        ret

readseg:
        test    cx, cx
        jz      .z
        mov     bx, [fh]
        push    ds
        mov     ds, ax
        xor     dx, dx
        mov     ah, 3Fh
        push    cx
        int     21h
        pop     cx
        pop     ds
        nc     e_read
        cmp     ax, cx
        nne     e_read
.z:
        ret

skipx:
        xchg    cx, dx
        mov     ax, 4201h
        mov     bx, [fh]
        int     21h
        nc     e_read
        ret

nextseg:
        mov     dx, iobuf
        mov     cx, 10
        call    readx
        cmp     word [iobuf], 0
        ret

segbase:
        cmp     ax, [si+M_CNUM]
        jne     .d
        mov     ax, [si+M_CSEG]
        mov     [tseg], ax
        mov     word [toff], 0
        ret
.d:
        cmp     ax, [si+M_DNUM]
        jne     .b
        mov     ax, [si+M_DSEG]
        mov     [tseg], ax
        mov     word [toff], 0
        ret
.b:
        cmp     ax, [si+M_BNUM]
        nne     e_seg
        mov     ax, [si+M_DSEG]
        mov     [tseg], ax
        mov     ax, [si+M_DLEN]
        mov     [toff], ax
        ret

lookup:
        push    bx
        push    cx
        push    dx
        push    si
        push    di
        push    es
        mov     word [lkidx], 0
.mod:
        mov     ax, [lkidx]
        cmp     ax, [nmods]
        nae     .nf
        mov     cx, MODSZ
        mul     cx
        add     ax, mods
        mov     [lkmod], ax
        mov     si, ax
        mov     es, [si+M_HSEG]
        mov     ax, [si+M_HLEN]
        mov     [lkend], ax
        xor     bx, bx
.rec:
        cmp     bx, [lkend]
        nae     .nextmod
        mov     cl, [es:bx+1]
        xor     ch, ch
        cmp     byte [es:bx], 3
        jne     .adv
        mov     [lkrec], bx
        lea     di, [bx+8]
        mov     si, [lkoff]
        mov     ax, [lkseg]
        push    ds
        mov     ds, ax
.cmp:
        lodsb
        scasb
        jne     .no
        test    al, al
        jnz     .cmp
        pop     ds
        jmp     .yes
.no:
        pop     ds
        mov     bx, [lkrec]
.adv:
        add     bx, cx
        add     bx, 2
        jmp     .rec
.yes:
        mov     bx, [lkrec]
        mov     al, [es:bx+3]
        xor     ah, ah
        mov     dx, [es:bx+4]
        mov     si, [lkmod]
        push    dx
        call    segbase
        pop     dx
        add     [toff], dx
        clc
        jmp     .out
.nextmod:
        inc     word [lkidx]
        jmp     .mod
.nf:
        stc
.out:
        pop     es
        pop     di
        pop     si
        pop     dx
        pop     cx
        pop     bx
        ret

resolveimp:
        push    bx
        push    cx
        push    di
        mov     di, [si+M_HLEN]
        xor     bx, bx
.s:
        cmp     bx, di
        nae     .bad0
        mov     cl, [es:bx+1]
        xor     ch, ch
        cmp     byte [es:bx], 2
        jne     .n
        cmp     [es:bx+3], ax
        jne     .n
        lea     dx, [bx+5]
        mov     [lkoff], dx
        mov     [implast], dx
        mov     [lkseg], es
        call    lookup
        jc      .bad
        pop     di
        pop     cx
        pop     bx
        ret
.n:
        add     bx, cx
        add     bx, 2
        jmp     .s
.bad0:
        mov     byte [impname], '$'
        mov     dx, m_imp
        jmp     fail
.bad:
        mov     si, [implast]
        mov     di, impname
.c:
        mov     al, [es:si]
        mov     [di], al
        inc     si
        inc     di
        test    al, al
        jnz     .c
        mov     byte [di-1], '$'
        mov     dx, m_imp
        jmp     fail

loadlib:
        mov     di, path
        mov     si, fname
        mov     cx, [dirlen]
.dc:
        test    cx, cx
        jz      .dd
        mov     al, [si]
        mov     [di], al
        inc     si
        inc     di
        dec     cx
        jmp     .dc
.dd:
        xor     cx, cx
.n:
        mov     al, [es:bx]
        mov     [di], al
        inc     bx
        inc     di
        cmp     al, '.'
        jne     .nd
        mov     cx, 1
.nd:
        test    al, al
        jnz     .n
        test    cx, cx
        jnz     .have
        dec     di
        mov     byte [di], '.'
        mov     byte [di+1], 'R'
        mov     byte [di+2], 'D'
        mov     byte [di+3], 'F'
        mov     byte [di+4], 0
.have:
        xor     bx, bx
.chk:
        cmp     bx, [nmods]
        jae     .load
        mov     ax, MODSZ
        mul     bx
        lea     si, [mods+M_PATH]
        add     si, ax
        mov     di, path
.cc:
        mov     al, [si]
        cmp     al, [di]
        jne     .nx
        test    al, al
        jz      .done
        inc     si
        inc     di
        jmp     .cc
.nx:
        inc     bx
        jmp     .chk
.load:
        mov     dx, path
        call    loadmod
.done:
        ret

loadmod:
        push    bp
        mov     bp, sp
        sub     sp, 40
        mov     ax, [nmods]
        cmp     ax, MAXMOD
        nae     e_many
        mov     cx, MODSZ
        push    dx
        mul     cx
        pop     dx
        add     ax, mods
        mov     si, ax
        inc     word [nmods]
        mov     [bp-2], si
        lea     di, [si+M_PATH]
        mov     bx, dx
        mov     cx, 127
.pc:
        mov     al, [bx]
        mov     [di], al
        inc     bx
        inc     di
        test    al, al
        jz      .pdone
        loop    .pc
        mov     byte [di], 0
.pdone:
        lea     dx, [si+M_PATH]
        call    openf
        nc     e_open
        mov     [fh], ax
        mov     bx, ax
        mov     cx, [curbase+2]
        mov     dx, [curbase]
        mov     word [curbase], 0
        mov     word [curbase+2], 0
        mov     ax, 4200h
        int     21h
        nc     e_read
        mov     dx, iobuf
        mov     cx, 14
        call    readx
        cmp     word [iobuf], 'RD'
        nne     e_fmt
        cmp     word [iobuf+2], 'OF'
        nne     e_fmt
        cmp     word [iobuf+4], 'F2'
        nne     e_fmt
        cmp     word [iobuf+12], 0
        nne     e_big
        mov     ax, [iobuf+10]
        cmp     ax, 0F000h
        nae     e_big
        mov     [bp-4], ax
        mov     si, [bp-2]
        mov     [si+M_HLEN], ax
        add     ax, 16
        xor     dx, dx
        mov     cl, 92h
        call    mkblk
        mov     si, [bp-2]
        mov     [si+M_HSEG], ax
        mov     cx, [bp-4]
        call    readseg
        mov     es, [si+M_HSEG]
        xor     bx, bx
        mov     word [bp-8], 0
        mov     word [bp-6], 0
.p1:
        cmp     bx, [bp-4]
        jae     .p1done
        mov     cl, [es:bx+1]
        xor     ch, ch
        cmp     byte [es:bx], 5
        jne     .p1n
        mov     ax, [es:bx+2]
        add     [bp-8], ax
        mov     ax, [es:bx+4]
        adc     [bp-6], ax
.p1n:
        add     bx, cx
        add     bx, 2
        jmp     .p1
.p1done:
        xor     cx, cx
        xor     dx, dx
        mov     ax, 4201h
        mov     bx, [fh]
        int     21h
        mov     [bp-12], ax
        mov     [bp-10], dx
        mov     word [si+M_CNUM], 0FFFFh
        mov     word [si+M_DNUM], 0FFFFh
        mov     word [bp-16], 0
        mov     word [bp-14], 0
        mov     word [bp-20], 0
        mov     word [bp-18], 0
.s1:
        call    nextseg
        je      .s1done
        mov     ax, [iobuf]
        mov     cx, [iobuf+6]
        mov     dx, [iobuf+8]
        cmp     ax, 1
        jne     .s1d
        mov     [bp-16], cx
        mov     [bp-14], dx
        mov     ax, [iobuf+2]
        mov     [si+M_CNUM], ax
        jmp     .s1skip
.s1d:
        cmp     ax, 2
        jne     .s1skip
        mov     [bp-20], cx
        mov     [bp-18], dx
        mov     ax, [iobuf+2]
        mov     [si+M_DNUM], ax
.s1skip:
        call    skipx
        jmp     .s1
.s1done:
        mov     ax, [si+M_CNUM]
        cmp     ax, 0FFFFh
        jne     .hascs
        xor     ax, ax
        cmp     word [si+M_DNUM], 0
        jne     .setcs
        mov     ax, 1
.setcs:
        mov     [si+M_CNUM], ax
.hascs:
        mov     ax, [si+M_DNUM]
        cmp     ax, 0FFFFh
        jne     .hasds
        mov     ax, [si+M_CNUM]
        inc     ax
        mov     [si+M_DNUM], ax
.hasds:
        mov     ax, [si+M_CNUM]
        cmp     ax, [si+M_DNUM]
        jae     .bn
        mov     ax, [si+M_DNUM]
.bn:
        inc     ax
        mov     [si+M_BNUM], ax
        cmp     word [bp-14], 0
        nne     e_big
        cmp     word [bp-18], 0
        nne     e_big
        cmp     word [bp-6], 0
        nne     e_big
        mov     ax, [bp-20]
        cmp     ax, 0F000h
        nae     e_big
        inc     ax
        and     ax, 0FFFEh
        mov     [bp-24], ax
        add     ax, [bp-8]
        nc      e_big
        cmp     ax, 0F000h
        nae     e_big
        mov     ax, [bp-24]
        mov     [si+M_DLEN], ax
        mov     ax, [bp-16]
        xor     dx, dx
        add     ax, 16
        adc     dx, 0
        push    ax
        push    dx
        mov     cl, 9Ah
        call    mkblk
        mov     si, [bp-2]
        mov     [si+M_CSEG], ax
        call    mkalias
        mov     si, [bp-2]
        mov     [si+M_CALI], ax
        pop     dx
        pop     cx
        shr     dx, 1
        rcr     cx, 1
        call    zerowords
        mov     si, [bp-2]
        cmp     si, mods
        jne     .exact
        mov     dx, 1
        xor     ax, ax
        jmp     .size
.exact:
        mov     ax, [bp-24]
        add     ax, [bp-8]
        add     ax, 16
        xor     dx, dx
.size:
        push    ax
        push    dx
        mov     cl, 92h
        call    mkblk
        mov     si, [bp-2]
        mov     [si+M_DSEG], ax
        pop     dx
        pop     cx
        shr     dx, 1
        rcr     cx, 1
        call    zerowords
        mov     dx, [bp-12]
        mov     cx, [bp-10]
        mov     bx, [fh]
        mov     ax, 4200h
        int     21h
.s2:
        mov     si, [bp-2]
        call    nextseg
        je      .s2done
        mov     ax, [iobuf]
        mov     cx, [iobuf+6]
        cmp     ax, 1
        jne     .s2d
        mov     ax, [si+M_CALI]
        call    readseg
        jmp     .s2
.s2d:
        cmp     ax, 2
        jne     .s2skip
        mov     ax, [si+M_DSEG]
        call    readseg
        jmp     .s2
.s2skip:
        mov     cx, [iobuf+6]
        mov     dx, [iobuf+8]
        call    skipx
        jmp     .s2
.s2done:
        mov     ah, 3Eh
        mov     bx, [fh]
        int     21h
        mov     si, [bp-2]
        mov     es, [si+M_HSEG]
        xor     bx, bx
.p3:
        cmp     bx, [bp-4]
        jae     .p3done
        mov     cl, [es:bx+1]
        xor     ch, ch
        cmp     byte [es:bx], 4
        jne     .p3n
        push    bx
        push    cx
        push    es
        add     bx, 2
        call    loadlib
        pop     es
        pop     cx
        pop     bx
        mov     si, [bp-2]
.p3n:
        add     bx, cx
        add     bx, 2
        jmp     .p3
.p3done:
        xor     bx, bx
.p4:
        cmp     bx, [bp-4]
        nae     .p4done
        mov     cl, [es:bx+1]
        xor     ch, ch
        mov     al, [es:bx]
        xor     ah, ah
        cmp     ax, 1
        je      .reloc
        cmp     ax, 6
        je      .reloc
        cmp     ax, 7
        ne     e_rec
.p4n:
        add     bx, cx
        add     bx, 2
        jmp     .p4
.reloc:
        push    bx
        push    cx
        mov     [bp-26], ax
        mov     dl, [es:bx+2]
        xor     dh, dh
        mov     [bp-28], dx
        and     dx, 3Fh
        mov     ax, dx
        cmp     ax, [si+M_CNUM]
        jne     .pd
        mov     ax, [si+M_CALI]
        mov     [bp-36], ax
        mov     ax, [si+M_CSEG]
        jmp     .pgot
.pd:
        cmp     ax, [si+M_DNUM]
        nne     e_seg
        mov     ax, [si+M_DSEG]
        mov     [bp-36], ax
.pgot:
        mov     [bp-30], ax
        mov     ax, [es:bx+3]
        mov     [bp-32], ax
        mov     al, [es:bx+7]
        xor     ah, ah
        mov     [bp-34], ax
        mov     ax, [es:bx+8]
        cmp     ax, [si+M_CNUM]
        je      .tseg
        cmp     ax, [si+M_DNUM]
        je      .tseg
        cmp     ax, [si+M_BNUM]
        je      .tseg
        call    resolveimp
        jmp     .tgot
.tseg:
        call    segbase
.tgot:
        mov     di, [bp-32]
        mov     ax, [toff]
        mov     dx, [tseg]
        cmp     word [bp-26], 6
        je      .segrel
        test    byte [bp-28], 40h
        jz      .abs
        cmp     dx, [bp-30]
        nne     e_near
.abs:
        mov     cx, [bp-34]
        mov     bx, [bp-36]
        push    ds
        mov     ds, bx
        cmp     cx, 1
        je      .w1
        cmp     cx, 2
        je      .w2
        add     [di], ax
        adc     word [di+2], 0
        jmp     .pdone2
.w1:
        add     [di], al
        jmp     .pdone2
.w2:
        add     [di], ax
        jmp     .pdone2
.segrel:
        mov     bx, [bp-36]
        push    ds
        mov     ds, bx
        add     [di], dx
.pdone2:
        pop     ds
.rdone:
        pop     cx
        pop     bx
        mov     si, [bp-2]
        jmp     .p4n
.p4done:
        mov     sp, bp
        pop     bp
        ret
hostname db     'HDPMI16.EXE', 0
msg_usage db    'RDFLD16 - RDOFF2 loader (16-bit DPMI). usage: RDFLD16 file.rdf [arguments]', 13, 10, '$'
msg_nohost db   'RDFLD16: no DPMI host and HDPMI16.EXE was not found.', 13, 10, '$'
msg_init db     'RDFLD16: cannot enter protected mode.', 13, 10, '$'
msg_pre db      'RDFLD16: ', '$'
msg_crlf db     13, 10, '$'
m_open  db      'cannot open file.$'
m_read  db      'read error.$'
m_mem   db      'not enough memory.$'
m_fmt   db      'not an RDOFF2 file.$'
m_seg   db      'bad segment number in a record.$'
m_imp   db      'unresolved import: '
impname times 64 db 0
        db      '$'
m_many  db      'too many modules.$'
m_rec   db      'unsupported record.$'
m_near  db      'near reference to another segment.$'
m_big   db      'code or data larger than 64 KB.$'
start_name db   'start', 0

tseg    dw      0
toff    dw      0
dirlen  dw      0
fh      dw      0
nmods   dw      0
lkseg   dw      0
lkoff   dw      0
lkidx   dw      0
lkmod   dw      0
lkrec   dw      0
lkend   dw      0
implast dw      0
blksz   dd      0
blkacc  db      0
        section .bss
        commonbss
iobuf   resb    16
path    resb    262
mods    resb    MAXMOD*MODSZ
