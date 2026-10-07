; Copyright (c) 2026 Viacheslav Komenda
;
; This is free and unencumbered software released into the public domain.
; See the file UNLICENSE or <https://unlicense.org>.


MAXMOD  equ     16
MODSZ   equ     160
IOSZ    equ     4096
M_CODE  equ     0
M_DATA  equ     4
M_BSS   equ     8
M_HDR   equ     12
M_HLEN  equ     16
M_CNUM  equ     20
M_DNUM  equ     22
M_BNUM  equ     24
M_PATH  equ     32

%define CLIENT32 1
%include "RDFLDRM.INC"

pm_init:
        call    newsel
        mov     [sel_lc], ax
        call    newsel
        mov     [sel_ld], ax
        call    newsel
        mov     [sel_uc], ax
        call    newsel
        mov     [sel_ud], ax
        mov     eax, [loadbase]
        mov     [m_base], eax
        mov     dword [m_limit], 0FFFFFFFFh
        mov     byte [m_gran], 0C0h
        mov     ax, [sel_lc]
        mov     [m_sel], ax
        mov     byte [m_acc], 9Ah
        call    mksel
        mov     ax, [sel_ld]
        mov     [m_sel], ax
        mov     byte [m_acc], 92h
        call    mksel
        mov     dword [m_base], 0
        mov     ax, [sel_uc]
        mov     [m_sel], ax
        mov     byte [m_acc], 9Ah
        call    mksel
        mov     ax, [sel_ud]
        mov     [m_sel], ax
        mov     byte [m_acc], 92h
        call    mksel
        mov     ax, [sel_lc]
        mov     [farptr+4], ax
        mov     dword [farptr], start32
        db      66h, 0FFh, 2Eh
        dw      farptr

        bits    32

start32:
        mov     ax, [sel_ld]
        mov     ds, ax
        mov     es, ax
        mov     ss, ax
        mov     esp, stktop
        mov     ax, [sel_ud]
        mov     fs, ax
        xor     ax, ax
        mov     gs, ax
        mov     ecx, [fnlen]
.dir:
        test    ecx, ecx
        jz      .dirdone
        mov     al, [fname+ecx-1]
        cmp     al, '\'
        je      .dirdone
        cmp     al, ':'
        je      .dirdone
        dec     ecx
        jmp     .dir
.dirdone:
        mov     [dirlen], ecx
        movzx   eax, word [dosseg]
        shl     eax, 4
        mov     [dosl], eax
        mov     edx, fname
        call    loadmod
        mov     esi, [mods+M_CODE]
        mov     eax, start_name
        add     eax, [loadbase]
        mov     [lkname], eax
        call    lookup
        jnc     .have
        mov     eax, [mods+M_CODE]
.have:
        mov     [entry], eax
        mov     ecx, 65536
        call    alloc
        add     eax, 65536 - 16
        mov     [ustack], eax
        mov     ebx, [psplin]
        mov     eax, termstub
        add     eax, [loadbase]
        mov     edx, [ustack]
        sub     edx, 4
        mov     [fs:edx], eax
        mov     eax, [entry]
        mov     [farptr2], eax
        mov     ax, [sel_uc]
        mov     [farptr2+4], ax
        mov     esi, [mods+M_CODE]
        mov     ax, [sel_ud]
        mov     ds, ax
        mov     es, ax
        mov     ss, ax
        mov     esp, edx
        xor     ax, ax
        mov     fs, ax
        mov     gs, ax
        mov     eax, esi
        xor     ecx, ecx
        xor     edx, edx
        xor     esi, esi
        xor     edi, edi
        xor     ebp, ebp
        jmp     far [cs:farptr2]

dosp:
        pushad
        push    es
        push    ds
        mov     [dosfn], ah
        mov     [rmr+28], eax
        mov     [rmr+16], ebx
        mov     [rmr+24], ecx
        mov     [rmr+20], edx
        mov     [dosedx], edx
        mov     [rmr+4], esi
        mov     dword [rmr], 0
        mov     dword [rmr+8], 0
        mov     dword [rmr+12], 0
        mov     esi, [rmr+4]
        mov     dword [rmr+4], 0
        mov     word [rmr+32], 0
        mov     dword [rmr+38], 0
        mov     dword [rmr+42], 0
        mov     dword [rmr+46], 0
        cmp     word [rmr+28], 716Ch
        je      .skipdx
        mov     word [rmr+20], 0
.skipdx:
        mov     ax, [dosseg]
        mov     [rmr+34], ax
        mov     [rmr+36], ax
        cmp     word [rmr+28], 716Ch
        je      .lfn
        mov     esi, edx
.lfn:
        mov     edi, [dosl]
        mov     es, [sel_ud]
        cmp     word [rmr+28], 716Ch
        je      .str0
        cmp     byte [rmr+29], 3Dh
        je      .str0
        cmp     byte [rmr+29], 9
        je      .strd
        jmp     .go
.str0:
        lodsb
        stosb
        test    al, al
        jnz     .str0
        jmp     .go
.strd:
        lodsb
        stosb
        cmp     al, '$'
        jne     .strd
.go:
        mov     ax, 300h
        mov     bx, 21h
        xor     cx, cx
        push    ds
        pop     es
        mov     edi, rmr
        int     31h
        cmp     byte [dosfn], 3Fh
        jne     .done
        test    byte [rmr+32], 1
        jnz     .done
        movzx   ecx, word [rmr+28]
        mov     edi, [dosedx]
        mov     esi, [dosl]
        push    ds
        pop     es
        mov     ds, [sel_ud]
        rep     movsb
.done:
        pop     ds
        pop     es
        popad
        mov     ax, [rmr+28]
        bt      word [rmr+32], 0
        ret

openf32:
        push    esi
        push    edx
        mov     esi, edx
        mov     ax, 716Ch
        xor     ebx, ebx
        xor     ecx, ecx
        mov     edx, 1
        call    dosp
        pop     edx
        pop     esi
        jnc     .r
        mov     ax, 3D00h
        call    dosp
.r:
        ret

termstub:
        mov     ax, 4C00h
        int     21h

fail:
        push    edx
        mov     edx, msg_pre
        mov     ah, 9
        call    dosp
        pop     edx
        mov     ah, 9
        call    dosp
        mov     edx, msg_crlf
        mov     ah, 9
        call    dosp
        mov     ax, 4C01h
        int     21h

err_open:
        mov     edx, e_open
        jmp     fail
err_read:
        mov     edx, e_read
        jmp     fail
err_mem:
        mov     edx, e_mem
        jmp     fail
err_fmt:
        mov     edx, e_fmt
        jmp     fail
err_seg:
        mov     edx, e_seg
        jmp     fail
err_imp:
        mov     edx, e_imp
        jmp     fail
err_many:
        mov     edx, e_many
        jmp     fail
err_rec:
        mov     edx, e_rec
        jmp     fail

alloc:
        push    ebx
        push    esi
        push    edi
        mov     ebx, ecx
        shr     ebx, 16
        mov     ax, 501h
        int     31h
        jc      near err_mem
        shl     ebx, 16
        mov     bx, cx
        mov     eax, ebx
        pop     edi
        pop     esi
        pop     ebx
        ret

readx:
        push    ecx
        mov     ah, 3Fh
        mov     bx, [fh]
        call    dosp
        pop     ecx
        jc      near err_read
        cmp     ax, cx
        jne     near err_read
        ret

readfar:
        push    es
        mov     ax, [sel_ud]
        mov     es, ax
.next:
        test    ecx, ecx
        jz      .end
        mov     edx, ecx
        cmp     edx, IOSZ
        jbe     .size
        mov     edx, IOSZ
.size:
        push    ecx
        push    edx
        mov     ecx, edx
        mov     edx, iobuf
        call    readx
        pop     edx
        pop     ecx
        mov     esi, iobuf
        push    ecx
        mov     ecx, edx
        rep     movsb
        pop     ecx
        sub     ecx, edx
        jmp     .next
.end:
        pop     es
        ret

skipx:
        mov     edx, ecx
        shr     ecx, 16
        mov     ax, 4201h
        mov     bx, [fh]
        int     21h
        jc      near err_read
        ret

tellx:
        xor     ecx, ecx
        xor     edx, edx
        mov     ax, 4201h
        mov     bx, [fh]
        int     21h
        jc      near err_read
        shl     edx, 16
        mov     dx, ax
        ret

seekx:
        mov     ecx, edx
        shr     ecx, 16
        mov     ax, 4200h
        mov     bx, [fh]
        int     21h
        jc      near err_read
        ret

nextseg:
        mov     edx, iobuf
        mov     ecx, 10
        call    readx
        cmp     word [iobuf], 0
        ret

segbase:
        cmp     ax, [esi+M_CNUM]
        jne     .d
        mov     eax, [esi+M_CODE]
        ret
.d:
        cmp     ax, [esi+M_DNUM]
        jne     .b
        mov     eax, [esi+M_DATA]
        ret
.b:
        cmp     ax, [esi+M_BNUM]
        jne      near err_seg
        mov     eax, [esi+M_BSS]
        ret

lookup:
        push    ebx
        push    esi
        push    edi
        push    ebp
        xor     ebp, ebp
.mod:
        cmp     ebp, [nmods]
        jae     .nf
        imul    esi, ebp, MODSZ
        add     esi, mods
        mov     ebx, [esi+M_HDR]
        mov     edi, ebx
        add     edi, [esi+M_HLEN]
.rec:
        cmp     ebx, edi
        jae     .nextmod
        movzx   ecx, byte [fs:ebx+1]
        cmp     byte [fs:ebx], 3
        jne     .adv
        push    ebx
        push    ecx
        lea     edx, [ebx+8]
        mov     eax, [lkname]
.cmp:
        mov     cl, [fs:edx]
        cmp     cl, [fs:eax]
        jne     .no
        test    cl, cl
        jz      .yes
        inc     edx
        inc     eax
        jmp     .cmp
.no:
        pop     ecx
        pop     ebx
.adv:
        lea     ebx, [ebx+ecx+2]
        jmp     .rec
.yes:
        pop     ecx
        pop     ebx
        movzx   eax, byte [fs:ebx+3]
        push    dword [fs:ebx+4]
        call    segbase
        pop     ecx
        add     eax, ecx
        clc
        jmp     .out
.nextmod:
        inc     ebp
        jmp     .mod
.nf:
        stc
.out:
        pop     ebp
        pop     edi
        pop     esi
        pop     ebx
        ret

loadmod:
        push    ebp
        mov     ebp, esp
        sub     esp, 32
        mov     eax, [nmods]
        cmp     eax, MAXMOD
        jae      near err_many
        imul    esi, eax, MODSZ
        add     esi, mods
        inc     dword [nmods]
        mov     [ebp-4], esi
        lea     edi, [esi+M_PATH]
        mov     ecx, 127
.pc:
        mov     al, [edx]
        mov     [edi], al
        inc     edx
        inc     edi
        test    al, al
        jz      .pdone
        loop    .pc
        mov     byte [edi], 0
.pdone:
        lea     edx, [esi+M_PATH]
        call    openf32
        jc      near err_open
        mov     [fh], ax
        mov     edx, [curbase]
        mov     dword [curbase], 0
        call    seekx
        mov     edx, iobuf
        mov     ecx, 14
        call    readx
        cmp     dword [iobuf], 'RDOF'
        jne      near err_fmt
        cmp     word [iobuf+4], 'F2'
        jne      near err_fmt
        mov     ecx, [iobuf+10]
        mov     [ebp-8], ecx
        add     ecx, 16
        call    alloc
        mov     esi, [ebp-4]
        mov     [esi+M_HDR], eax
        mov     ecx, [ebp-8]
        mov     [esi+M_HLEN], ecx
        mov     edi, eax
        call    readfar
        mov     esi, [ebp-4]
        xor     edx, edx
        mov     [ebp-12], edx
        mov     ebx, [esi+M_HDR]
        mov     edi, ebx
        add     edi, [esi+M_HLEN]
.p1:
        cmp     ebx, edi
        jae     .p1done
        movzx   ecx, byte [fs:ebx+1]
        cmp     byte [fs:ebx], 5
        jne     .p1next
        mov     eax, [fs:ebx+2]
        add     [ebp-12], eax
.p1next:
        lea     ebx, [ebx+ecx+2]
        jmp     .p1
.p1done:
        call    tellx
        mov     [ebp-16], edx
        mov     word [esi+M_CNUM], 0FFFFh
        mov     word [esi+M_DNUM], 0FFFFh
        mov     dword [ebp-20], 0
        mov     dword [ebp-24], 0
.s1:
        call    nextseg
        je      .s1done
        movzx   eax, word [iobuf]
        mov     ecx, [iobuf+6]
        cmp     eax, 1
        jne     .s1d
        mov     [ebp-20], ecx
        mov     ax, [iobuf+2]
        mov     [esi+M_CNUM], ax
        jmp     .s1skip
.s1d:
        cmp     eax, 2
        jne     .s1skip
        mov     [ebp-24], ecx
        mov     ax, [iobuf+2]
        mov     [esi+M_DNUM], ax
.s1skip:
        call    skipx
        jmp     .s1
.s1done:
        mov     ax, [esi+M_CNUM]
        cmp     ax, 0FFFFh
        jne     .hascs
        xor     ax, ax
        cmp     word [esi+M_DNUM], 0
        jne     .setcs
        mov     ax, 1
.setcs:
        mov     [esi+M_CNUM], ax
.hascs:
        mov     ax, [esi+M_DNUM]
        cmp     ax, 0FFFFh
        jne     .hasds
        mov     ax, [esi+M_CNUM]
        inc     ax
        mov     [esi+M_DNUM], ax
.hasds:
        mov     ax, [esi+M_CNUM]
        cmp     ax, [esi+M_DNUM]
        jae     .bn
        mov     ax, [esi+M_DNUM]
.bn:
        inc     ax
        mov     [esi+M_BNUM], ax
        mov     ecx, [ebp-20]
        add     ecx, 15
        and     ecx, -16
        mov     [ebp-28], ecx
        mov     eax, [ebp-24]
        add     eax, 15
        and     eax, -16
        mov     [ebp-32], eax
        add     ecx, eax
        add     ecx, [ebp-12]
        add     ecx, 32
        call    alloc
        mov     esi, [ebp-4]
        mov     [esi+M_CODE], eax
        add     eax, [ebp-28]
        mov     [esi+M_DATA], eax
        add     eax, [ebp-32]
        mov     [esi+M_BSS], eax
        mov     edi, [esi+M_CODE]
        mov     ecx, [ebp-28]
        add     ecx, [ebp-32]
        add     ecx, [ebp-12]
        add     ecx, 35
        push    es
        mov     ax, [sel_ud]
        mov     es, ax
        xor     eax, eax
        shr     ecx, 2
        rep     stosd
        pop     es
        mov     edx, [ebp-16]
        call    seekx
.s2:
        mov     esi, [ebp-4]
        call    nextseg
        je      .s2done
        movzx   eax, word [iobuf]
        mov     ecx, [iobuf+6]
        cmp     eax, 1
        jne     .s2d
        mov     edi, [esi+M_CODE]
        call    readfar
        jmp     .s2
.s2d:
        cmp     eax, 2
        jne     .s2skip
        mov     edi, [esi+M_DATA]
        call    readfar
        jmp     .s2
.s2skip:
        call    skipx
        jmp     .s2
.s2done:
        mov     ah, 3Eh
        mov     bx, [fh]
        int     21h
        mov     esi, [ebp-4]
        mov     ebx, [esi+M_HDR]
        mov     edi, ebx
        add     edi, [esi+M_HLEN]
.p3:
        cmp     ebx, edi
        jae     .p3done
        movzx   ecx, byte [fs:ebx+1]
        cmp     byte [fs:ebx], 4
        jne     .p3next
        push    ebx
        push    edi
        push    ecx
        lea     edx, [ebx+2]
        call    loadlib
        pop     ecx
        pop     edi
        pop     ebx
        mov     esi, [ebp-4]
.p3next:
        lea     ebx, [ebx+ecx+2]
        jmp     .p3
.p3done:
        mov     ebx, [esi+M_HDR]
        mov     edi, ebx
        add     edi, [esi+M_HLEN]
.p4:
        cmp     ebx, edi
        jae     near .p4done
        movzx   ecx, byte [fs:ebx+1]
        movzx   eax, byte [fs:ebx]
        cmp     eax, 1
        je      .reloc
        cmp     eax, 6
        je      near err_rec
        cmp     eax, 7
        je      near err_rec
.p4next:
        lea     ebx, [ebx+ecx+2]
        jmp     .p4
.reloc:
        push    ebx
        push    edi
        push    ecx
        movzx   edx, byte [fs:ebx+2]
        mov     [ebp-8], edx
        and     edx, 3Fh
        mov     eax, edx
        call    segbase
        mov     [ebp-12], eax
        add     eax, [fs:ebx+3]
        mov     [ebp-16], eax
        movzx   eax, word [fs:ebx+8]
        cmp     ax, [esi+M_CNUM]
        je      .tseg
        cmp     ax, [esi+M_DNUM]
        je      .tseg
        cmp     ax, [esi+M_BNUM]
        je      .tseg
        call    resolveimp
        jmp     .tgot
.tseg:
        call    segbase
.tgot:
        test    byte [ebp-8], 40h
        jz      .abs
        sub     eax, [ebp-12]
.abs:
        mov     edx, [ebp-16]
        movzx   ecx, byte [fs:ebx+7]
        cmp     ecx, 1
        je      .w1
        cmp     ecx, 2
        je      .w2
        add     [fs:edx], eax
        jmp     .rdone
.w1:
        add     [fs:edx], al
        jmp     .rdone
.w2:
        add     [fs:edx], ax
.rdone:
        pop     ecx
        pop     edi
        pop     ebx
        jmp     .p4next
.p4done:
        mov     esp, ebp
        pop     ebp
        ret

resolveimp:
        push    ebx
        push    edi
        push    ecx
        mov     ecx, [esi+M_HDR]
        mov     edi, ecx
        add     edi, [esi+M_HLEN]
.s:
        cmp     ecx, edi
        jae      near err_imp
        movzx   ebx, byte [fs:ecx+1]
        cmp     byte [fs:ecx], 2
        jne     .n
        cmp     [fs:ecx+3], ax
        jne     .n
        lea     eax, [ecx+5]
        mov     [lkname], eax
        mov     [implast], eax
        call    lookup
        jc      .bad
        pop     ecx
        pop     edi
        pop     ebx
        ret
.n:
        lea     ecx, [ecx+ebx+2]
        jmp     .s
.bad:
        mov     edi, [implast]
        mov     esi, impname
.c:
        mov     al, [fs:edi]
        mov     [esi], al
        inc     edi
        inc     esi
        test    al, al
        jnz     .c
        mov     byte [esi-1], '$'
        mov     edx, e_imp
        jmp     fail

loadlib:
        push    ebp
        mov     ebp, esp
        mov     edi, path
        mov     esi, fname
        mov     ecx, [dirlen]
        rep     movsb
        mov     ebx, edi
        xor     ecx, ecx
.n:
        mov     al, [fs:edx]
        mov     [edi], al
        inc     edx
        inc     edi
        cmp     al, '.'
        jne     .nd
        mov     ecx, 1
.nd:
        test    al, al
        jnz     .n
        test    ecx, ecx
        jnz     .have
        dec     edi
        mov     byte [edi], '.'
        mov     byte [edi+1], 'R'
        mov     byte [edi+2], 'D'
        mov     byte [edi+3], 'F'
        mov     byte [edi+4], 0
.have:
        xor     ebx, ebx
.chk:
        cmp     ebx, [nmods]
        jae     .load
        imul    esi, ebx, MODSZ
        lea     esi, [esi+mods+M_PATH]
        mov     edi, path
.cc:
        mov     al, [esi]
        cmp     al, [edi]
        jne     .nx
        test    al, al
        jz      .done
        inc     esi
        inc     edi
        jmp     .cc
.nx:
        inc     ebx
        jmp     .chk
.load:
        mov     edx, path
        call    loadmod
.done:
        mov     esp, ebp
        pop     ebp
        ret

        bits    16
dosl    dd      0
dosedx  dd      0
dosfn   db      0
hostname db     'HDPMI32.EXE', 0
msg_usage db    'RDFLD32 - RDOFF2 loader (32-bit DPMI). usage: RDFLD32 file.rdf [arguments]', 13, 10, '$'
msg_nohost db   'RDFLD32: no 32-bit DPMI host and HDPMI32.EXE was not found.', 13, 10, '$'
msg_init db     'RDFLD32: cannot enter protected mode.', 13, 10, '$'
msg_pre db      'RDFLD32: ', '$'
msg_crlf db     13, 10, '$'
e_open  db      'cannot open file.$'
e_read  db      'read error.$'
e_mem   db      'not enough memory.$'
e_fmt   db      'not an RDOFF2 file.$'
e_seg   db      'bad segment number in a record.$'
e_imp   db      'unresolved import: '
impname times 64 db 0
        db      '$'
e_many  db      'too many modules.$'
e_rec   db      'unsupported record (segment relocation or far import).$'
start_name db   'start', 0

sel_lc  dw      0
sel_ld  dw      0
sel_uc  dw      0
sel_ud  dw      0
dirlen  dd      0
fh      dw      0
nmods   dd      0
lkname  dd      0
implast dd      0
entry   dd      0
ustack  dd      0
        section .bss
        commonbss
rmr     resb    50
farptr  resb    6
farptr2 resb    6
path    resb    260
mods    resb    MAXMOD*MODSZ
iobuf   resb    IOSZ
        resb    2048
stktop:
