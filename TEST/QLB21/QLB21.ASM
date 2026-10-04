        bits 16
        cpu 8086
        global  start

%define HDRBYTES 0x0400
%define IMAGEOFF 0x0402
%define SYMOFF   8
%define MAGICOFF 6

%macro AFTEREXEC 0
        mov     [cs:ax_], ax
        sbb     ax, ax
        mov     [cs:cf_], ax
        mov     ax, cs
        mov     ds, ax
        mov     es, ax
        mov     ss, [cs:savess]
        mov     sp, [cs:savesp]
        cmp     byte [unloading], 0
        je      %%first
        jmp     unloaded
%%first:
        cmp     word [cf_], 0
%endmacro

section .text

start:
        mov     ax, cs
        mov     ds, ax
        mov     es, ax
        mov     ah, 51h
        int     21h
        mov     [psp], bx

        mov     es, bx
        mov     si, 81h
.skip:  mov     al, [es:si]
        cmp     al, ' '
        jne     .nsp
        inc     si
        jmp     .skip
.nsp:   cmp     al, 13
        je      .defname
        mov     di, fname
.cp:    mov     al, [es:si]
        inc     si
        cmp     al, 13
        je      .cpd
        cmp     al, ' '
        je      .cpd
        mov     [di], al
        inc     di
        jmp     .cp
.cpd:   mov     byte [di], 0
        jmp     .named
.defname:
        mov     si, defname
        mov     di, fname
.dn:    mov     al, [si]
        mov     [di], al
        inc     si
        inc     di
        test    al, al
        jnz     .dn
.named:
        mov     ax, cs
        mov     es, ax

        mov     dx, m_banner
        call    puts
        mov     dx, m_file
        call    puts
        mov     dx, fname
        call    puts
        call    crlf

        mov     dx, l_free0
        call    freemem

        mov     ax, cs
        mov     [par+4], ax
        mov     [par+8], ax
        mov     [par+12], ax
        mov     word [par+2], tail
        mov     word [par+6], fcb
        mov     word [par+10], fcb

        mov     dx, m_try1
        call    puts
        mov     [savess], ss
        mov     [savesp], sp
        mov     dx, fname
        mov     bx, par
        mov     ax, 4B01h
        int     21h
ret1:
        AFTEREXEC
        jnz     r1bad
        jmp     loaded
r1bad:
        mov     dx, l_ax
        mov     ax, [ax_]
        call    kv
        cmp     word [ax_], 8
        je      patch
        jmp     failed

patch:
        mov     dx, m_patch
        call    puts
        call    mktmp
        jnc     patch_go
        jmp     failed
patch_go:
        mov     byte [usedtmp], 1
        mov     [savess], ss
        mov     [savesp], sp
        mov     dx, tmpname
        mov     bx, par
        mov     ax, 4B01h
        int     21h
ret2:
        AFTEREXEC
        jnz     r2bad
        jmp     loaded
r2bad:
        mov     dx, l_ax
        mov     ax, [ax_]
        call    kv
        jmp     failed

failed:
        mov     dx, m_bad
        call    puts
        call    deltmp
        mov     ax, 4C01h
        int     21h

loaded:
        call    deltmp
        mov     ah, 62h
        int     21h
        mov     [chpsp], bx
        mov     ah, 50h
        mov     bx, [psp]
        int     21h
        mov     ax, [chpsp]
        add     ax, 10h
        mov     [bseg], ax

        mov     dx, m_ok
        call    puts
        mov     ax, [chpsp]
        mov     dx, l_cpsp
        call    kv
        mov     ax, [bseg]
        mov     dx, l_bseg
        call    kv
        mov     ax, [par+20]
        mov     dx, l_cs
        call    kv
        mov     ax, [par+18]
        mov     dx, l_ip
        call    kv
        mov     ax, [par+16]
        mov     dx, l_ss
        call    kv
        mov     ax, [par+14]
        mov     dx, l_sp
        call    kv
        mov     ax, [chpsp]
        dec     ax
        mov     es, ax
        mov     ax, [es:3]
        mov     dx, l_mcb
        call    kv
        mov     ax, cs
        mov     es, ax
        mov     dx, l_free1
        call    freemem

        call    readhdr
        jnc     rd_ok
        mov     dx, m_rderr
        call    puts
        jmp     unload
rd_ok:
        mov     dx, m_dos
        call    puts
        mov     byte [probemode], 0
        call    probe
        call    fixup
        mov     dx, m_fixed
        call    puts
        mov     byte [probemode], 1
        call    probe
        call    verify
        call    crlf

        call    findhdr
        jnc     hdr_ok
        mov     dx, m_nohdr
        call    puts
        jmp     unload
hdr_ok:
        call    findsym
        jnc     sym_ok
        mov     dx, m_nosym
        call    puts
        jmp     unload
sym_ok:
        mov     dx, m_call
        call    puts
        call    callint86
        call    crlf

unload:
        mov     dx, m_unl
        call    puts
        mov     byte [unloading], 1
        mov     [savess], ss
        mov     [savesp], sp
        mov     ah, 50h
        mov     bx, [chpsp]
        int     21h
        mov     ax, 4C00h
        int     21h
        jmp     $

unloaded:
        mov     dx, m_unl2
        call    puts
        mov     ah, 4Dh
        int     21h
        mov     dx, l_exit
        call    kv
        mov     dx, l_free2
        call    freemem
        mov     dx, m_bye
        call    puts
        mov     ax, 4C00h
        int     21h

readhdr:
        mov     dx, fname
        mov     ax, 3D00h
        int     21h
        jc      .bad
        mov     bx, ax
        mov     cx, HDRBYTES
        mov     dx, hdr
        mov     ah, 3Fh
        int     21h
        jc      .bad
        mov     ax, 4202h
        xor     cx, cx
        xor     dx, dx
        int     21h
        jc      .bad
        mov     [fsize], ax
        mov     [fsize+2], dx
        mov     ah, 3Eh
        int     21h
        clc
        ret
.bad:   stc
        ret

fixup:
        mov     ax, [bseg]
        mov     [tseg], ax
        mov     [tval], ax
        mov     cx, 0
        call    reloc_pass
        mov     ax, [fsize]
        mov     dx, [fsize+2]
        sub     ax, IMAGEOFF
        sbb     dx, 0
        mov     [remlo], ax
        mov     [remhi], dx
        mov     ax, [bseg]
        mov     [cseg], ax
.chunk: mov     ax, [remhi]
        test    ax, ax
        jnz     .full
        mov     cx, [remlo]
        cmp     cx, 0x8000
        jbe     .go
.full:  mov     cx, 0x8000
.go:    test    cx, cx
        jz      .done
        mov     ax, [cseg]
        mov     ds, ax
        mov     es, ax
        mov     si, 2
        xor     di, di
        cld
        rep     movsb
        mov     ax, cs
        mov     ds, ax
        mov     es, ax
        sub     word [remlo], 0x8000
        sbb     word [remhi], 0
        jc      .done
        add     word [cseg], 0x0800
        jmp     .chunk
.done:  mov     ax, cs
        mov     ds, ax
        mov     es, ax
        mov     cx, 1
        call    reloc_pass
        ret

verify:
        mov     ax, [fsize]
        mov     dx, [fsize+2]
        sub     ax, IMAGEOFF
        sbb     dx, 0
        add     ax, 15
        adc     dx, 0
        mov     cx, 4
.sh:    shr     dx, 1
        rcr     ax, 1
        loop    .sh
        inc     ax
        mov     bx, ax
        mov     ah, 48h
        int     21h
        jnc     .have
        mov     dx, m_vnomem
        call    puts
        ret
.have:  mov     [vseg], ax
        mov     dx, fname
        mov     ax, 3D00h
        int     21h
        jnc     .vo1
        jmp     .vbad
.vo1:   mov     [h_in], ax
        mov     bx, ax
        mov     ax, 4200h
        xor     cx, cx
        mov     dx, IMAGEOFF
        int     21h
        mov     ax, [vseg]
        mov     [cseg], ax
.rd:    mov     bx, [h_in]
        mov     ax, [cseg]
        mov     ds, ax
        xor     dx, dx
        mov     cx, 0x8000
        mov     ah, 3Fh
        int     21h
        mov     bx, cs
        mov     ds, bx
        jnc     .vo2
        jmp     .vbad
.vo2:   cmp     ax, 0x8000
        jne     .rdone
        add     word [cseg], 0x0800
        jmp     .rd
.rdone: mov     bx, [h_in]
        mov     ah, 3Eh
        int     21h
        mov     ax, [vseg]
        mov     [tseg], ax
        mov     ax, [bseg]
        mov     [tval], ax
        mov     cx, 1
        call    reloc_pass
        mov     ax, [fsize]
        mov     dx, [fsize+2]
        sub     ax, IMAGEOFF
        sbb     dx, 0
        mov     [remlo], ax
        mov     [remhi], dx
        mov     ax, [bseg]
        mov     [cseg], ax
        mov     ax, [vseg]
        mov     [cseg2], ax
        mov     word [vbad], 0
.cc:    mov     ax, [remhi]
        test    ax, ax
        jnz     .vfull
        mov     cx, [remlo]
        cmp     cx, 0x8000
        jbe     .vgo
.vfull: mov     cx, 0x8000
.vgo:   test    cx, cx
        jz      .vdone
        mov     ax, [cseg2]
        mov     es, ax
        mov     ax, [cseg]
        mov     ds, ax
        xor     si, si
        xor     di, di
        cld
        repe    cmpsb
        jz      .eq
        dec     si
        dec     di
        mov     al, [si]
        mov     ah, [es:di]
        mov     [cs:dbgb], ax
        mov     [cs:dbgo], si
        mov     ax, cs
        mov     ds, ax
        mov     es, ax
        cmp     word [vbad], 0
        jne     .cnt
        mov     ax, [cseg]
        sub     ax, [bseg]
        mov     dx, l_vseg
        call    kv
        mov     ax, [dbgo]
        mov     dx, l_voff
        call    kv
        mov     ax, [dbgb]
        mov     dx, l_vbyt
        call    kv
.cnt:   inc     word [vbad]
        jmp     .same
.eq:    mov     ax, cs
        mov     ds, ax
        mov     es, ax
.same:  sub     word [remlo], 0x8000
        sbb     word [remhi], 0
        jc      .vdone
        add     word [cseg], 0x0800
        add     word [cseg2], 0x0800
        jmp     .cc
.vdone: mov     es, [vseg]
        mov     ah, 49h
        int     21h
        mov     ax, cs
        mov     es, ax
        cmp     word [vbad], 0
        jne     .differ
        mov     dx, m_vsame
        call    puts
        ret
.differ:mov     dx, m_vdiff
        call    puts
        ret
.vbad:  mov     ax, cs
        mov     ds, ax
        mov     es, ax
        mov     dx, m_vfail
        call    puts
        ret

reloc_pass:
        mov     bp, cx
        mov     dx, [tval]
        mov     si, [hdr+0x18]
        mov     bx, [hdr+0x06]
        add     si, hdr
        test    bx, bx
        jz      .done
.loop:  mov     di, [si]
        mov     ax, [si+2]
        add     ax, [tseg]
        mov     es, ax
        add     si, 4
        test    bp, bp
        jnz     .add
        sub     [es:di], dx
        jmp     .next
.add:   add     [es:di], dx
.next:  dec     bx
        jnz     .loop
.done:  mov     ax, cs
        mov     es, ax
        ret

probe:
        mov     cx, [hdr+0x06]
        test    cx, cx
        jz      .out
        mov     si, [hdr+0x18]
        add     si, hdr
        mov     ax, [si+2]
        add     ax, [bseg]
        mov     es, ax
        mov     bx, [si]
        cmp     byte [probemode], 0
        jne     .after
        mov     ax, [es:bx]
        call    puthexw
        mov     al, ' '
        call    putchar
        mov     ax, [es:bx+2]
        call    puthexw
        jmp     .nl
.after: mov     ax, [es:bx-2]
        call    puthexw
        mov     al, ' '
        call    putchar
        mov     ax, [es:bx]
        call    puthexw
.nl:    call    crlf
.out:   mov     ax, cs
        mov     es, ax
        ret

findhdr:
        mov     ax, [par+20]
        sub     ax, [bseg]
        mov     dx, [par+18]
        sub     dx, 2
        jnc     .nb
        add     dx, 16
        dec     ax
.nb:    add     ax, [bseg]
        mov     [hseg], ax
        mov     [hoff], dx
        mov     es, ax
        mov     bx, dx
        cmp     word [es:bx+MAGICOFF], 0x6C75
        mov     ax, cs
        mov     es, ax
        jne     .bad
        mov     ax, [hseg]
        mov     dx, l_hseg
        call    kv
        mov     ax, [hoff]
        mov     dx, l_hoff
        call    kv
        clc
        ret
.bad:   stc
        ret

findsym:
        mov     es, [hseg]
        mov     bx, [hoff]
        mov     si, [es:bx+SYMOFF]
        add     si, bx
        mov     word [nsym], 0
.next:  mov     ax, [es:si]
        test    ax, ax
        jz      .end
        inc     word [nsym]
        mov     di, [es:si+2]
        add     di, bx
        push    si
        mov     si, sname
.cmp:   mov     al, [si]
        cmp     al, [es:di]
        jne     .no
        test    al, al
        jz      .yes
        inc     si
        inc     di
        jmp     .cmp
.yes:   pop     si
        mov     ax, [es:si+4]
        mov     [qoff], ax
        mov     ax, [es:si+6]
        mov     [qsegr], ax
        mov     ax, cs
        mov     es, ax
        mov     ax, [nsym]
        mov     dx, l_nsym
        call    kv
        mov     ax, [qsegr]
        mov     dx, l_qseg
        call    kv
        mov     ax, [qoff]
        mov     dx, l_qoff
        call    kv
        clc
        ret
.no:    pop     si
        add     si, 8
        jmp     .next
.end:   mov     ax, cs
        mov     es, ax
        mov     ax, [nsym]
        mov     dx, l_nsym
        call    kv
        stc
        ret

callint86:
        mov     word [inregs+0],  0x0200
        mov     word [inregs+2],  0
        mov     word [inregs+4],  0
        mov     word [inregs+6],  0x0051
        mov     word [inregs+8],  0
        mov     word [inregs+10], 0
        mov     word [inregs+12], 0
        mov     word [inregs+14], 0x0202
        mov     word [intnum], 0x21
        mov     ax, cs
        mov     [indesc+0], word inregs
        mov     [indesc+2], ax
        mov     [outdesc+0], word outregs
        mov     [outdesc+2], ax
        mov     ax, [qoff]
        mov     [qentry+0], ax
        mov     ax, [bseg]
        add     ax, [qsegr]
        mov     [qentry+2], ax
        mov     ax, intnum
        push    ax
        mov     ax, indesc
        push    ax
        mov     ax, outdesc
        push    ax
        call    far [qentry]
        mov     ax, cs
        mov     ds, ax
        mov     es, ax
        mov     dx, l_outax
        mov     ax, [outregs+0]
        call    kv
        ret

mktmp:
        mov     dx, fname
        mov     ax, 3D00h
        int     21h
        jc      .bad
        mov     [h_in], ax
        mov     dx, tmpname
        xor     cx, cx
        mov     ah, 3Ch
        int     21h
        jc      .bad
        mov     [h_out], ax
        mov     byte [first], 1
.rd:    mov     bx, [h_in]
        mov     cx, 512
        mov     dx, iobuf
        mov     ah, 3Fh
        int     21h
        jc      .bad
        test    ax, ax
        jz      .done
        mov     cx, ax
        cmp     byte [first], 0
        je      .wr
        mov     byte [first], 0
        cmp     cx, 14
        jb      .wr
        mov     word [iobuf+10], 0x0010
        mov     word [iobuf+12], 0x0010
.wr:    mov     bx, [h_out]
        mov     dx, iobuf
        mov     ah, 40h
        int     21h
        jc      .bad
        jmp     .rd
.done:  mov     bx, [h_in]
        mov     ah, 3Eh
        int     21h
        mov     bx, [h_out]
        mov     ah, 3Eh
        int     21h
        clc
        ret
.bad:   stc
        ret

deltmp:
        cmp     byte [usedtmp], 0
        je      .out
        mov     dx, tmpname
        mov     ah, 41h
        int     21h
        mov     byte [usedtmp], 0
.out:   ret

freemem:
        push    dx
        mov     bx, 0FFFFh
        mov     ah, 48h
        int     21h
        pop     dx
        mov     ax, bx
        call    kv
        ret

puts:   push    ax
        push    bx
        push    cx
        push    dx
        push    si
        mov     si, dx
        xor     cx, cx
.len:   cmp     byte [si], 0
        je      .go
        inc     si
        inc     cx
        jmp     .len
.go:    test    cx, cx
        jz      .out
        mov     bx, 1
        mov     ah, 40h
        int     21h
.out:   pop     si
        pop     dx
        pop     cx
        pop     bx
        pop     ax
        ret

crlf:   mov     dx, nl
        call    puts
        ret

putchar:
        push    ax
        push    dx
        mov     dl, al
        mov     ah, 2
        int     21h
        pop     dx
        pop     ax
        ret

kv:     push    ax
        call    puts
        pop     ax
        call    puthexw
        call    crlf
        ret

puthexw:
        push    ax
        push    bx
        push    cx
        push    dx
        mov     bx, ax
        mov     cx, 4
.l:     rol     bx, 1
        rol     bx, 1
        rol     bx, 1
        rol     bx, 1
        mov     dl, bl
        and     dl, 0Fh
        add     dl, '0'
        cmp     dl, '9'
        jbe     .p
        add     dl, 7
.p:     mov     ah, 2
        int     21h
        loop    .l
        pop     dx
        pop     cx
        pop     bx
        pop     ax
        ret

psp         dw 0
chpsp       dw 0
bseg        dw 0
hseg        dw 0
hoff        dw 0
qoff        dw 0
qsegr       dw 0
nsym        dw 0
cf_         dw 0
ax_         dw 0
savess      dw 0
savesp      dw 0
fsize       dw 0, 0
tseg        dw 0
tval        dw 0
vseg        dw 0
cseg2       dw 0
vbad        dw 0
dbgb        dw 0
dbgo        dw 0
remlo       dw 0
remhi       dw 0
cseg        dw 0
h_in        dw 0
h_out       dw 0
unloading   db 0
usedtmp     db 0
probemode   db 0
first       db 0
qentry      dw 0, 0
intnum      dw 0
indesc      dw 0, 0
outdesc     dw 0, 0
inregs      times 8 dw 0
outregs     times 10 dw 0
par         times 22 db 0
tail        db 0, 13
fcb         times 20 db 0
fname       times 80 db 0
iobuf       times 512 db 0
hdr         times HDRBYTES db 0

defname     db 'QB.QLB', 0
tmpname     db 'QLB21.TMP', 0
sname       db 'INT86OLD', 0
nl          db 13, 10, 0
m_banner    db 'QLB21 -- a QuickLibrary loaded with '
            db 'INT 21h AH=4Bh AL=01h'
            db 13, 10, 13, 10, 0
m_file      db 'library       ', 0
m_try1      db 'EXEC AL=01h on the file as it is', 13, 10, 0
m_patch     db 'the header declares e_minalloc = '
            db 'e_maxalloc = FFFF: loading a copy '
            db 'with both patched'
            db 13, 10, 0
m_bad       db 'could not load the library', 13, 10, 0
m_ok        db 13, 10, 'loaded; DOS reports', 13, 10, 0
m_rderr     db 'cannot read the file header', 13, 10, 0
m_dos       db 13, 10
            db 'first relocation entry: offset half,'
            db ' segment half, as DOS left them:'
            db 13, 10, 0
m_vnomem   db 'verify: no memory for a second copy', 13, 10, 0
m_vsame     db 'verify: the repaired image is byte '
            db 'for byte the one a hand loader '
            db 'builds'
            db 13, 10, 0
m_vdiff     db 'verify: THE IMAGE DIFFERS from a '
            db 'hand-loaded one'
            db 13, 10, 0
m_vfail     db 'verify: cannot read the file', 13, 10, 0
m_fixed     db 'after undo / shift / redo (same far '
            db 'pointer):'
            db 13, 10, 0
m_nohdr     db 'no QB header (magic 6C75) at the '
            db 'place CS:IP names'
            db 13, 10, 0
m_nosym     db 'INT86OLD is not in the CODE table '
            db '(not QB.QLB, or an RLINK library)'
            db 13, 10, 0
m_call      db 'far call INT86OLD  (INT 21h AH=02h DL=Q) -> ', 0
m_unl       db 13, 10
            db 'unloading: terminate the child '
            db 'process'
            db 13, 10, 0
m_unl2      db 'DOS resumed the parent a second '
            db 'time, at the instruction after INT '
            db '21h AH=4Bh'
            db 13, 10, 0
m_bye       db 'done', 13, 10, 0
l_free0     db 'largest free block before loading   ', 0
l_free1     db 'largest free block with the library ', 0
l_free2     db 'largest free block after unloading  ', 0
l_ax        db 'AX          ', 0
l_cpsp      db 'child PSP   ', 0
l_bseg      db 'image at    ', 0
l_cs        db 'CS          ', 0
l_ip        db 'IP          ', 0
l_ss        db 'SS          ', 0
l_sp        db 'SP          ', 0
l_mcb       db 'block paras ', 0
l_hseg      db 'QB header   seg ', 0
l_hoff      db '            off ', 0
l_nsym      db 'CODE table entries ', 0
l_qseg      db 'INT86OLD  seg ', 0
l_qoff      db '          off ', 0
l_outax     db 'out-array ax ', 0
l_vseg     db 'mismatch chunk (seg offset) ', 0
l_voff      db 'mismatch offset in chunk  ', 0
l_vbyt      db 'mismatch bytes (ref,fixed)  ', 0
l_exit      db 'child exit code ', 0
