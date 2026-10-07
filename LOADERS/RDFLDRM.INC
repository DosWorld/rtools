; Copyright (c) 2026 Viacheslav Komenda
;
; This is free and unencumbered software released into the public domain.
; See the file UNLICENSE or <https://unlicense.org>.


%if CLIENT32
        cpu     386
%else
        cpu     286
%endif
        bits    16
%macro nae 1
        jb      %%s
        jmp     %1
%%s:
%endmacro
%macro nb 1
        jae      %%s
        jmp     %1
%%s:
%endmacro
%macro nbe 1
        ja      %%s
        jmp     %1
%%s:
%endmacro
%macro nc 1
        jnc      %%s
        jmp     %1
%%s:
%endmacro
%macro ne 1
        jne      %%s
        jmp     %1
%%s:
%endmacro
%macro nne 1
        je      %%s
        jmp     %1
%%s:
%endmacro

        global  start
start:
        cld
        mov     [pspseg], cs
        mov     ah, 4Ah
        mov     bx, 1000h
        int     21h
        nc     rm_dos
%if CLIENT32
        mov     ah, 48h
        mov     bx, 120h
        int     21h
        nc     rm_dos
        mov     [dosseg], ax
%endif
        call    selfinfo
        jnc     .named
        mov     si, 81h
.skip:
        mov     al, [si]
        inc     si
        cmp     al, ' '
        je      .skip
        cmp     al, 9
        je      .skip
        cmp     al, 13
        ne     rm_usage
        dec     si
        mov     di, fname
        cmp     byte [si], '"'
        je      .quoted
.copy:
        mov     al, [si]
        cmp     al, 33
        jb      .done
        mov     [di], al
        inc     si
        inc     di
        jmp     .copy
.quoted:
        inc     si
.qcopy:
        mov     al, [si]
        cmp     al, 13
        je      .done
        cmp     al, '"'
        je      .done
        mov     [di], al
        inc     si
        inc     di
        jmp     .qcopy
.done:
        mov     byte [di], 0
        sub     di, fname
        mov     [fnlen], di
        mov     word [fnlen+2], 0
.named:
        mov     [parm+4], cs
        mov     [parm+8], cs
        mov     [parm+12], cs
        call    detect
        jnc     .have
        call    findhost
        nc     rm_nohost
        call    detect
        nc     rm_nohost
.have:
        mov     bx, [dpmimem]
        test    bx, bx
        jz      .noalloc
        mov     ah, 48h
        int     21h
        nc     rm_dos
        mov     es, ax
.noalloc:
        mov     ax, CLIENT32
        call    far [dpmient]
        nc     rm_init
        mov     [pspsel], es
        mov     ax, 6
        mov     bx, es
        int     31h
        mov     [psplin], dx
        mov     [psplin+2], cx
        mov     ax, 6
        mov     bx, cs
        int     31h
        mov     [loadbase], dx
        mov     [loadbase+2], cx
        mov     ax, cs
        lar     ax, ax
        mov     al, ah
        and     al, 60h
        mov     [dpl], al
        mov     ax, 3
        int     31h
        mov     [seladd], ax
        jmp     pm_init

openf:
        push    dx
        push    si
        mov     si, dx
        mov     ax, 716Ch
        xor     bx, bx
        xor     cx, cx
        mov     dx, 1
        stc
        int     21h
        pop     si
        pop     dx
        jnc     .r
        mov     ax, 3D00h
        int     21h
.r:
        ret

selfinfo:
        mov     es, [2Ch]
        xor     di, di
.env:
        cmp     word [es:di], 0
        je      .path
        inc     di
        jmp     .env
.path:
        add     di, 4
        mov     si, di
        mov     dx, hdrbuf
        push    ds
        push    es
        pop     ds
        mov     dx, si
        call    openf
        pop     ds
        jc      .no
        mov     bx, ax
        mov     dx, hdrbuf
        mov     cx, 28
        mov     ah, 3Fh
        int     21h
        jc      .close
        cmp     ax, 28
        jne     .close
        cmp     word [hdrbuf], 'MZ'
        jne     .close
        mov     ax, [hdrbuf+4]
        dec     ax
        mov     dx, 512
        mul     dx
        mov     cx, [hdrbuf+2]
        test    cx, cx
        jnz     .last
        mov     cx, 512
.last:
        add     ax, cx
        adc     dx, 0
        mov     [curbase], ax
        mov     [curbase+2], dx
        xor     cx, cx
        xor     dx, dx
        mov     ax, 4202h
        int     21h
        jc      .close
        cmp     dx, [curbase+2]
        jb      .close
        ja      .emb
        cmp     ax, [curbase]
        jbe     .close
.emb:
        mov     ah, 3Eh
        int     21h
        push    es
        pop     ds
        mov     si, di
        push    cs
        pop     es
        mov     di, fname
.cp:
        lodsb
        stosb
        test    al, al
        jnz     .cp
        push    cs
        pop     ds
        dec     di
        sub     di, fname
        mov     [fnlen], di
        mov     word [fnlen+2], 0
        clc
        ret
.close:
        mov     ah, 3Eh
        int     21h
.no:
        mov     word [curbase], 0
        mov     word [curbase+2], 0
        push    cs
        pop     es
        stc
        ret

detect:
        mov     ax, 1687h
        int     2Fh
        test    ax, ax
        jnz     .no
%if CLIENT32
        test    bl, 1
        jz      .no
%endif
        mov     [dpmient], di
        mov     [dpmient+2], es
        mov     [dpmimem], si
        clc
        ret
.no:
        stc
        ret

tryexec:
        push    ds
        push    es
        mov     [sv_ss], ss
        mov     [sv_sp], sp
        mov     ax, cs
        mov     es, ax
        mov     bx, parm
        mov     ax, 4B00h
        int     21h
        mov     ss, [cs:sv_ss]
        mov     sp, [cs:sv_sp]
        pop     es
        pop     ds
        ret

findhost:
        mov     es, [pspseg]
        mov     es, [es:2Ch]
        xor     di, di
        xor     al, al
.s:
        mov     cx, 0FFFFh
        repne   scasb
        cmp     byte [es:di], 0
        jne     .s
        add     di, 3
        mov     bx, hostbuf
.c:
        mov     al, [es:di]
        mov     [bx], al
        inc     di
        inc     bx
        test    al, al
        jnz     .c
.b:
        dec     bx
        cmp     bx, hostbuf
        jb      .nodir
        cmp     byte [bx], '\'
        je      .gotdir
        cmp     byte [bx], ':'
        je      .gotdir
        jmp     .b
.nodir:
        mov     bx, hostbuf
        dec     bx
.gotdir:
        inc     bx
        call    addname
        mov     dx, hostbuf
        call    tryexec
        jnc     .ok
        mov     es, [pspseg]
        mov     es, [es:2Ch]
        xor     di, di
.e:
        cmp     byte [es:di], 0
        je      .none
        cmp     word [es:di], 'PA'
        jne     .nextenv
        cmp     word [es:di+2], 'TH'
        jne     .nextenv
        cmp     byte [es:di+4], '='
        je      .path
.nextenv:
        xor     al, al
        mov     cx, 0FFFFh
        repne   scasb
        jmp     .e
.path:
        add     di, 5
.dir:
        mov     bx, hostbuf
.d:
        mov     al, [es:di]
        test    al, al
        jz      .dend
        cmp     al, ';'
        je      .dend
        mov     [bx], al
        inc     bx
        inc     di
        jmp     .d
.dend:
        cmp     bx, hostbuf
        je      .skipdir
        mov     al, [bx-1]
        cmp     al, '\'
        je      .app
        cmp     al, ':'
        je      .app
        mov     byte [bx], '\'
        inc     bx
.app:
        call    addname
        push    es
        push    di
        mov     dx, hostbuf
        call    tryexec
        pop     di
        pop     es
        jnc     .ok
.skipdir:
        cmp     byte [es:di], 0
        je      .none
        inc     di
        jmp     .dir
.none:
        stc
        ret
.ok:
        clc
        ret

addname:
        mov     si, hostname
.a:
        mov     al, [si]
        mov     [bx], al
        inc     si
        inc     bx
        test    al, al
        jnz     .a
        ret

rm_dos:
        mov     dx, msg_dos
        jmp     rm_exit
rm_nohost:
        mov     dx, msg_nohost
        jmp     rm_exit
rm_init:
        mov     dx, msg_init
        jmp     rm_exit
rm_usage:
        mov     dx, msg_usage
rm_exit:
        mov     ah, 9
        int     21h
        mov     ax, 4C01h
        int     21h

mksel:
        mov     bx, [m_sel]
        mov     ax, 7
        mov     cx, [m_base+2]
        mov     dx, [m_base]
        int     31h
        mov     ax, 8
        mov     cx, [m_limit+2]
        mov     dx, [m_limit]
        int     31h
        mov     ax, 9
        mov     cl, [m_acc]
        or      cl, [dpl]
        mov     ch, [m_gran]
        int     31h
        ret

newsel:
        xor     ax, ax
        mov     cx, 1
        int     31h
        nc     rm_init
        ret

msg_dos db      'RDFLD: DOS memory error.', 13, 10, '$'

pspseg  dw      0
dosseg  dw      0
pspsel  dw      0
psplin  dd      0
loadbase dd     0
dpl     db      0
seladd  dw      0
dpmient dd      0
dpmimem dw      0
fnlen   dd      0
curbase dd      0
sv_ss   dw      0
sv_sp   dw      0
m_sel   dw      0
m_base  dd      0
m_limit dd      0
m_acc   db      0
m_gran  db      0
parm    dw      0, nulltail, 0, fcbarea, 0, fcbarea, 0
nulltail db     0, 13
%macro commonbss 0
hdrbuf  resb    28
fcbarea resb    16
hostbuf resb    144
fname   resb    262
%endmacro
