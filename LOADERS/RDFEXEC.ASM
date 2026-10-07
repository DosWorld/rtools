; Copyright (c) 2026 Viacheslav Komenda
;
; This is free and unencumbered software released into the public domain.
; See the file UNLICENSE or <https://unlicense.org>.

        cpu     8086
        bits    16

%macro jcn 1
        jnc     %%s
        jmp     %1
%%s:
%endmacro
%macro jen 1
        jne     %%s
        jmp     %1
%%s:
%endmacro

        global  start
hook:
        jmp     short hk1
sig     db      'RDFEXEC', 0
hk1:
        cmp     ax, 4B00h
        je      hk2
hk0:
        jmp     far [cs:oldint]
hk2:
        push    bx
        push    cx
        push    dx
        push    si
        push    di
        push    bp
        push    ds
        push    es
        mov     bp, sp
        cld
        mov     [cs:nameofs], dx
        mov     [cs:nameseg], ds
        mov     [cs:pbofs], bx
        mov     [cs:pbseg], es
        mov     ax, 3D00h
        call    dos
        jcn     pass
        mov     bx, ax
        push    cs
        pop     ds
        mov     dx, hdr
        mov     cx, 6
        mov     ah, 3Fh
        call    dos
        mov     byte [isrdf], 0
        jc      .cl
        cmp     ax, 6
        jne     .cl
        cmp     word [hdr], 'RD'
        jne     .cl
        cmp     word [hdr+2], 'OF'
        jne     .cl
        cmp     word [hdr+4], 'F2'
        jne     .cl
        mov     byte [isrdf], 1
.cl:
        mov     ah, 3Eh
        call    dos
        cmp     byte [isrdf], 0
        jen     pass
        push    cs
        pop     es
        mov     di, pblock
        lds     si, [cs:pbofs]
        mov     cx, 7
        rep     movsw
        push    cs
        pop     ds
        lds     si, [pblock+2]
        mov     al, [si]
        xor     ah, ah
        mov     [cs:otlen], ax
        inc     si
        mov     [cs:otofs], si
        mov     [cs:otseg], ds
        push    cs
        pop     ds
        mov     di, tail+1
        mov     al, ' '
        stosb
        mov     al, '"'
        stosb
        lds     si, [cs:nameofs]
.nm:
        lodsb
        test    al, al
        jz      .nmend
        stosb
        cmp     di, tail+1+100
        jb      .nm
        jmp     pass
.nmend:
        mov     al, '"'
        stosb
        mov     cx, [cs:otlen]
        mov     ax, di
        sub     ax, tail+1
        add     ax, cx
        cmp     ax, 126
        jbe     .fit
        jmp     pass
.fit:
        lds     si, [cs:otofs]
        rep     movsb
        mov     al, 13
        stosb
        mov     ax, di
        sub     ax, tail+2
        mov     [es:tail], al
        push    cs
        pop     ds
        mov     word [pblock+2], tail
        mov     [pblock+4], cs
        mov     bx, [depth]
        cmp     bx, 32
        jb      .room
        jmp     pass
.room:
        mov     [sptab+bx], sp
        mov     [sptab+bx+2], ss
        add     bx, 4
        mov     [depth], bx
        mov     dx, ldrpath
        mov     bx, pblock
        mov     ax, 4B00h
        pushf
        call    far [cs:oldint]
        mov     [cs:res], ax
        mov     ax, 0
        jnc     .z
        inc     ax
.z:
        mov     [cs:resfl], ax
        mov     bx, [cs:depth]
        sub     bx, 4
        mov     [cs:depth], bx
        mov     ss, [cs:bx+sptab+2]
        mov     sp, [cs:bx+sptab]
        mov     bp, sp
        and     word [bp+20], 0FFFEh
        cmp     word [cs:resfl], 0
        je      .nc
        or      word [bp+20], 1
.nc:
        pop     es
        pop     ds
        pop     bp
        pop     di
        pop     si
        pop     dx
        pop     cx
        pop     bx
        mov     ax, [cs:res]
        iret

pass:
        mov     sp, bp
        pop     es
        pop     ds
        pop     bp
        pop     di
        pop     si
        pop     dx
        pop     cx
        pop     bx
        mov     ax, 4B00h
        jmp     far [cs:oldint]

dos:
        pushf
        call    far [cs:oldint]
        ret

oldint  dd      0
nameofs dw      0
nameseg dw      0
pbofs   dw      0
pbseg   dw      0
otofs   dw      0
otseg   dw      0
otlen   dw      0
isrdf   db      0
res     dw      0
resfl   dw      0
depth   dw      0
pspseg  dw      0
quiet   db      0
uninst  db      0
defname db      'RDFLDR.EXE', 0

m_usage db      'RDFEXEC - resident RDOFF2 loader. usage: RDFEXEC [-q] [-u] [loader.exe]', 13, 10
        db      'loader is RDFLDR.EXE (default), RDFLD16.EXE or RDFLD32.EXE.', 13, 10, '$'
m_ok    db      'RDFEXEC installed, loader: ', 0
m_crlf  db      13, 10, 0
m_already db    'RDFEXEC is already installed.', 13, 10, '$'
m_noload db     'RDFEXEC: loader not found.', 13, 10, '$'
m_notinst db    'RDFEXEC is not installed (or another program hooked INT 21h after it).', 13, 10, '$'
m_removed db    'RDFEXEC uninstalled.', 13, 10, '$'

start:
        cld
        mov     [pspseg], es
        mov     byte [argbuf], 0
        mov     si, 81h
.arg:
        mov     al, [es:si]
        inc     si
        cmp     al, ' '
        je      .arg
        cmp     al, 9
        je      .arg
        cmp     al, 13
        je      .parsed
        cmp     al, '-'
        je      .opt
        cmp     al, '/'
        je      .opt
        mov     di, argbuf
        dec     si
.cp:
        mov     al, [es:si]
        cmp     al, 33
        jb      .cpend
        mov     [di], al
        inc     si
        inc     di
        jmp     .cp
.cpend:
        mov     byte [di], 0
        jmp     .arg
.opt:
        mov     al, [es:si]
        inc     si
        or      al, 20h
        cmp     al, 'q'
        jne     .o2
        mov     byte [quiet], 1
        jmp     .arg
.o2:
        cmp     al, 'u'
        jne     .usage
        mov     byte [uninst], 1
        jmp     .arg
.usage:
        mov     dx, m_usage
        jmp     die
.parsed:
        mov     ax, 3521h
        int     21h
        mov     di, bx
        add     di, 2
        mov     si, sig
        mov     cx, 8
        repe    cmpsb
        mov     al, 0
        jne     .notours
        mov     al, 1
.notours:
        cmp     byte [uninst], 0
        jne     .un
        test    al, al
        jz      .inst
        mov     dx, m_already
        jmp     die
.un:
        test    al, al
        jz      .ni
        cmp     bx, hook
        je      .rm
.ni:
        mov     dx, m_notinst
        jmp     die
.rm:
        push    ds
        lds     dx, [es:oldint]
        mov     ax, 2521h
        int     21h
        pop     ds
        mov     es, [es:pspseg]
        mov     ah, 49h
        int     21h
        mov     dx, m_removed
        jmp     bye
.inst:
        mov     es, [pspseg]
        mov     es, [es:2Ch]
        xor     di, di
.env:
        cmp     word [es:di], 0
        je      .envend
        inc     di
        jmp     .env
.envend:
        add     di, 4
        mov     bx, ownbuf
.oc:
        mov     al, [es:di]
        mov     [bx], al
        inc     di
        inc     bx
        test    al, al
        jnz     .oc
.ob:
        dec     bx
        cmp     bx, ownbuf
        jb      .od
        cmp     byte [bx], '\'
        je      .od
        cmp     byte [bx], ':'
        je      .od
        jmp     .ob
.od:
        inc     bx
        mov     byte [bx], 0
        cmp     byte [argbuf], 0
        je      .usedef
        mov     si, argbuf
.hs:
        mov     al, [si]
        test    al, al
        jz      .nosep
        cmp     al, '\'
        je      .full
        cmp     al, ':'
        je      .full
        cmp     al, '/'
        je      .full
        inc     si
        jmp     .hs
.full:
        mov     di, work
        mov     si, argbuf
        call    strcat
        jmp     .tn
.nosep:
        mov     di, work
        mov     si, ownbuf
        call    strcat
        mov     si, argbuf
        call    strcat
        jmp     .tn
.usedef:
        mov     di, work
        mov     si, ownbuf
        call    strcat
        mov     si, defname
        call    strcat
.tn:
        push    ds
        pop     es
        mov     si, work
        mov     di, ldrpath
        mov     ah, 60h
        int     21h
        jnc     .tnok
        mov     di, ldrpath
        mov     si, work
        call    strcat
.tnok:
        mov     dx, ldrpath
        mov     ax, 3D00h
        int     21h
        jnc     .have
        mov     dx, m_noload
        jmp     die
.have:
        mov     bx, ax
        mov     ah, 3Eh
        int     21h
        mov     ax, 3521h
        int     21h
        mov     [oldint], bx
        mov     [oldint+2], es
        mov     dx, hook
        mov     ax, 2521h
        int     21h
        cmp     byte [quiet], 0
        jne     .quiet
        mov     si, m_ok
        call    puts
        mov     si, ldrpath
        call    puts
        mov     si, m_crlf
        call    puts
.quiet:
        mov     es, [pspseg]
        xor     bx, bx
        xchg    bx, [es:2Ch]
        mov     es, bx
        mov     ah, 49h
        int     21h
        mov     ax, cs
        sub     ax, [pspseg]
        mov     dx, bssend
        add     dx, 15
        mov     cl, 4
        shr     dx, cl
        add     dx, ax
        mov     ax, 3100h
        int     21h

strcat:
        mov     al, [si]
        mov     [di], al
        test    al, al
        jz      .e
        inc     si
        inc     di
        jmp     strcat
.e:
        ret

puts:
        mov     al, [si]
        inc     si
        test    al, al
        jz      .e
        mov     dl, al
        mov     ah, 2
        int     21h
        jmp     puts
.e:
        ret

die:
        mov     ah, 9
        int     21h
        mov     ax, 4C01h
        int     21h
bye:
        mov     ah, 9
        int     21h
        mov     ax, 4C00h
        int     21h

        section .bss
hdr     resb    6
pblock  resb    14
tail    resb    130
sptab   resb    32
ldrpath resb    130
ownbuf  resb    130
argbuf  resb    130
work    resb    260
bssend  resb    1
