{
 MIT License

Copyright (c) 2022 Viacheslav Komenda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

https://github.com/DosWorld/rtools

}
{$I+,A+,R-,S-,O-,F-,D-,L-,Q-,F-,G-}
{$M 16000, 500000, 650000}
USES utils, rldutil, dos;

CONST

SEG_SIZE = 65500;
RELOC_WIDTH = 2;

PROCEDURE Help(VAR ctx : RLCTX);
BEGIN
        WriteLn('usage: RLINK [/H] [/E name] [/O out] [/A nn] [/T] [/V] file1.rdf [..file2.rdf]');
        WriteLn;
        WriteLn('/E name - Set symbol name for entry point (default is "start")');
        WriteLn('/O out  - Set output file name');
        WriteLn('/A nn   - Align segments to nn (2, 4, 8, 16, 32)');
        WriteLn('/T      - Merge code, data into one segment');
        WriteLn('/V      - Verbose output');
        WriteLn('/H      - Show this help');
        WriteLn;
        Write('Use environment variable RLIB as library search path.');
        IF Length(ctx.rlib) <> 0 THEN BEGIN
                WriteLn;
                WriteLn('RLIB=', ctx.rlib);
        END ELSE WriteLn(' RLIB is empty');
        WriteLn;
        WriteLn('Use @MYLIB.TXT as input file name, if you need list from a text file.');
        Halt(1);
END;

PROCEDURE save_rdf(VAR ctx : RLCTX);
VAR o          : FILE;
    p0, p1, p2 : DWORD;
    i          : INTEGER;
BEGIN
        IF ctx.err THEN EXIT;
        Assign(o, ctx.outname);
        {$I-}
        Rewrite(o, 1);
        i := IOResult;
        {$I+}
        IF i <> 0 THEN BEGIN
                mkerr(ctx, 'Could not write ' + ctx.outname);
                EXIT;
        END;
        BlockWrite(o, RDOFF2_SIGN[1], Length(RDOFF2_SIGN));
        p0 := FilePos(o);
        write_dword(o, 0);
        p1 := FilePos(o);
        write_dword(o, ctx.outrdf^.hdr_size);
        IF ctx.outrdf^.hdr_size <> 0 THEN BlockWrite(o, ctx.outrdf^.hdr[0], ctx.outrdf^.hdr_size);

        write_word(o, CSEG);
        write_word(o, ctx.outrdf^.code_segnum);
        write_word(o, 0);
        write_dword(o, ctx.outrdf^.code_size);
        IF ctx.outrdf^.code_size <> 0 THEN BlockWrite(o, ctx.outrdf^.code[0], ctx.outrdf^.code_size);

        write_word(o, DSEG);
        write_word(o, ctx.outrdf^.data_segnum);
        write_word(o, 0);
        write_dword(o, ctx.outrdf^.data_size);
        IF ctx.outrdf^.data_size <> 0 THEN BlockWrite(o, ctx.outrdf^.data[0], ctx.outrdf^.data_size);
        
        write_word(o, 0);
        write_word(o, 0);
        write_word(o, 0);
        write_dword(o, 0);

        p2 := FilePos(o);

        Seek(o, p0);
        write_dword(o, p2 - p1);
        Close(o);
END;

PROCEDURE remove_unused_imports(r : PRDF);
VAR data     : PCHAR;
    p        : WORD;
    ldata    : WORD;
    rtype    : CHAR;
    rlen     : WORD;
    find     : BOOLEAN;
    rsegnum  : WORD;
    p1       : WORD;
    rtype1   : CHAR;
    rlen1    : WORD;
    rseg1    : WORD;
BEGIN
        data := r^.hdr;
        p := 0;
        ldata := r^.hdr_size;
        r^.bss_size := 0;
        WHILE p < ldata DO BEGIN
                rtype := data[p];
                rlen := ORD(data[p + 1]);
                IF rtype = RREC_IMPORT THEN BEGIN
                        rsegnum := get_word(@data[p + 3]);
                        find := FALSE;
                        p1 := 0;
                        WHILE (p1 < ldata) AND (NOT find) DO BEGIN
                                rtype1 := data[p1];
                                rlen1 := ORD(data[p1 + 1]);
                                IF rtype1 = RREC_RELOC THEN BEGIN
                                        rseg1 := get_word(@data[p1 + 8]);
                                        find := rseg1 = rsegnum;
                                END;
                                Inc(p1, rlen1 + 2);
                        END;
                        IF NOT find THEN BEGIN
                                data[p] := RREC_COMMENT;
                        END;
                END ELSE IF rtype = RREC_BSS THEN BEGIN
                        Inc(r^.bss_size, get_dword(@data[p + 2]));
                END;
                Inc(p, rlen + 2);
        END;
END;

PROCEDURE load_rdf(VAR ctx : RLCTX; VAR f : FILE; VAR fname : STRING);
VAR
    modsize  : DWORD;
    hdrsize  : DWORD;
    r        : PRDF;
    segtype : WORD;
    segnum  : WORD;
    reserv  : WORD;
    seglen  : DWORD;
BEGIN
        Seek(f, FilePos(f) + 6);
        modsize := read_dword(f);
        hdrsize := read_dword(f);
        IF hdrsize > 65000 THEN BEGIN
                mkerr(ctx, 'Too big headers into rdf.');
                EXIT;
        END;
        r := rdf_create;
        r^.next := ctx.rdfs;
        ctx.rdfs := r;
        r^.fname := fname;
        r^.hdr_alloc := hdrsize;
        r^.hdr_size := hdrsize;
        GetMem(r^.hdr, r^.hdr_size);
        BlockRead(f, r^.hdr[0], r^.hdr_size);
        WHILE (NOT EOF(f)) AND (NOT ctx.err) DO BEGIN
                segtype := read_word(f);
                segnum := read_word(f);
                reserv := read_word(f);
                seglen := read_dword(f);
                IF segtype = 0 THEN BREAK;
                IF seglen > 65535 THEN BEGIN
                        mkerr(ctx, 'Too big segment.');
                        EXIT;
                END;
                IF segtype = CSEG THEN BEGIN
                        IF r^.code_size <> 0 THEN BEGIN
                                mkerr(ctx, 'Multiple code-segment.');
                                EXIT;
                        END;
                        r^.code_size := seglen;
                        r^.code_segnum := segnum;
                        r^.file_code_ofs := FilePos(f);
                END ELSE IF segtype = DSEG THEN BEGIN
                        IF r^.data_size <> 0 THEN BEGIN
                                mkerr(ctx, 'Multiple data-segment.');
                                EXIT;
                        END;
                        r^.data_size := seglen;
                        r^.data_segnum := segnum;
                        r^.file_data_ofs := FilePos(f);
                END ELSE BEGIN
                        mkerr(ctx, 'Unknown type of segment.');
                        EXIT;
                END;
                Seek(f, FilePos(f) + seglen);
        END;
        remove_unused_imports(r);
        r^.bss_segnum := r^.data_segnum;
        IF r^.bss_segnum < r^.code_segnum THEN r^.bss_segnum := r^.code_segnum;
        Inc(r^.bss_segnum);
END;

PROCEDURE load_rdl(VAR ctx : RLCTX; fname : STRING);
VAR f : FILE;
    i : INTEGER;
    sign1    : STRING[12];
    sign2    : STRING[12];
    p        : DWORD;
    modsize  : DWORD;
    modstart : DWORD;
    modname  : STRING;
BEGIN
        IF ctx.err THEN EXIT;
        Assign(f, fname);
        {$I-}
        Reset(f, 1);
        i := IOResult;
        {$I+}
        IF i <> 0 THEN BEGIN
                mkerr(ctx, 'Could not read ' + fname);
                EXIT;
        END;
        BlockRead(f, sign1[1], 6);
        sign1[0] := #6;
        sign2 := sign1;
        sign2[0] := #5;
        Seek(f, 0);
        IF sign1 = RDOFF2_SIGN THEN BEGIN
                load_rdf(ctx, f, fname);
        END ELSE IF sign2 = RLIB_SIGN1 THEN BEGIN
                WHILE (NOT EOF(f)) AND (NOT ctx.err) DO BEGIN
                        p := FilePos(f);
                        BlockRead(f, modname[1], 255, i);
                        modname := strc2pas(@modname[1]);
                        Inc(p, Length(modname) + 1);
                        Seek(f, p);
                        BlockRead(f, sign1[1], 6);
                        sign1[0] := #6;
                        modsize := read_dword(f);
                        modstart := FilePos(f);
                        IF modname[1] <> '.' THEN BEGIN
                                IF sign1 = RDOFF2_SIGN THEN BEGIN
                                        Seek(f, p);
                                        load_rdf(ctx, f, fname);
                                END ELSE BEGIN
                                        mkerr(ctx, 'Unknown file format ' + fname);
                                        BREAK;
                                END;
                        END;
                        Seek(f, modstart + modsize);
                END;
        END ELSE BEGIN
                mkerr(ctx, 'Unknown file format ' + fname);
        END;
        Close(f);
END;

PROCEDURE load_rlib_rdl(VAR ctx : RLCTX; fname : STRING);
VAR msg     : STRING;
    i, t, l : INTEGER;
    path    : STRING;
BEGIN
        IF ctx.err THEN EXIT;
        load_rdl(ctx, fname);
        IF NOT ctx.err THEN EXIT;
        l := Length(ctx.rlib);
        IF l = 0 THEN EXIT;
        msg := ctx.errMsg;
        ctx.errMsg := '';
        fname := basename(fname);
        i := 1;
        WHILE i < l DO BEGIN
                path := '';
                t := i;
                WHILE (t <= l) AND (ctx.rlib[t] <> ';') DO BEGIN
                        path := path + ctx.rlib[t];
                        Inc(t);
                END;
                i := t + 1;
                IF Length(path) > 0 THEN BEGIN
                        ctx.err := FALSE;
                        IF NOT (path[Length(path)] IN ['\', '/']) THEN path := path + '\';
                        load_rdl(ctx, path + fname);
                END;
                IF NOT ctx.err THEN BREAK;
        END;
        IF ctx.err THEN BEGIN
                ctx.err := TRUE;
                ctx.errMsg := msg;
        END;
END;

PROCEDURE load_meta_rdl(VAR ctx : RLCTX; fname : STRING);
VAR t : TEXT;
    i : INTEGER;
BEGIN
        IF ctx.err THEN EXIT;
        IF fname[1] <> '@' THEN BEGIN
                load_rlib_rdl(ctx, fname);
                EXIT;
        END;
        fname := Copy(fname, 2, Length(fname));
        Assign(t, fname);
        {$I-}
        Reset(t);
        i := IOResult;
        {$I+}
        IF i <> 0 THEN BEGIN
                mkerr(ctx, 'Could not read ' + fname);
                EXIT;
        END;
        WHILE (NOT EOF(t)) AND (NOT ctx.err) DO BEGIN
                ReadLn(t, fname);
                IF fname[0] <> #0 THEN load_rlib_rdl(ctx, fname);
        END;
        Close(t);
END;

PROCEDURE load_segments(VAR ctx : RLCTX; code , data : PCHAR);
VAR
    rdf      : PRDF;
    f        : FILE;
    i        : INTEGER;
BEGIN
        IF ctx.err THEN EXIT;
        rdf := ctx.rdfs;
        WHILE rdf <> NIL DO BEGIN
                IF (rdf^.linked) AND ((rdf^.code_size + rdf^.data_size) <> 0) THEN BEGIN
                        Assign(f, rdf^.fname);
                        {$I-}
                        Reset(f, 1);
                        i := IOResult;
                        {$I+}
                        IF i <> 0 THEN BEGIN
                                mkerr(ctx, 'Could not read ' + rdf^.fname);
                                EXIT;
                        END;
                        IF rdf^.code_size <> 0 THEN BEGIN
                                Seek(f, rdf^.file_code_ofs);
                                BlockRead(f, code[rdf^.link_code_ofs], rdf^.code_size);
                        END;
                        IF rdf^.data_size <> 0 THEN BEGIN
                                Seek(f, rdf^.file_data_ofs);
                                BlockRead(f, data[rdf^.link_data_ofs], rdf^.data_size);
                        END;
                        Close(f);
                END;
                rdf := rdf^.next;
        END;
END;

PROCEDURE link_sym(VAR ctx : RLCTX; sym : PSYMTAB; code, data : PCHAR; code_segnum, data_segnum, bss_segnum : WORD);
VAR  rdf : PRDF;
BEGIN
        rdf := sym^.rdf;
        IF sym^.segnum = rdf^.code_segnum THEN BEGIN
                sym^.linked_seg := code_segnum;
                Inc(sym^.linked_ofs, rdf^.link_code_ofs);
        END ELSE IF sym^.segnum = rdf^.data_segnum THEN BEGIN
                sym^.linked_seg := data_segnum;
                Inc(sym^.linked_ofs, rdf^.link_data_ofs);
        END ELSE IF sym^.segnum = rdf^.bss_segnum THEN BEGIN
                sym^.linked_seg := bss_segnum;
                Inc(sym^.linked_ofs, rdf^.link_bss_ofs);
        END;
END;

PROCEDURE link_relocs(VAR ctx : RLCTX; rdf : PRDF; code, data : PCHAR; code_segnum, data_segnum, bss_segnum : WORD);
VAR
d     : PCHAR;
p     : WORD;
len   : WORD;
rtype : CHAR;
rlen  : WORD;
rdf_relo_seg   : BYTE;
rdf_relo_ofs   : DWORD;
rdf_relo_width : BYTE;
rdf_relo_rseg  : WORD;
rec            : STRING;
out_relo_seg   : BYTE;
out_relo_ofs   : DWORD;
out_relo_width : BYTE;
out_relo_rseg  : WORD;
need_add       : BOOLEAN;
name           : PCHAR;
dst_rdf        : PRDF;
dst_sym        : PSYMTAB;
self_rel       : BOOLEAN;
fix            : WORD;
BEGIN
        p := 0;
        d := rdf^.hdr;
        need_add := FALSE;
        len := rdf^.hdr_size;
        WHILE (p < len) AND (NOT ctx.err) DO BEGIN
                rtype := d[p];
                rlen  := ORD(d[p + 1]);
                IF NOT (rtype IN [RREC_RELOC, RREC_SEGRELO]) THEN BEGIN
                        Inc(p, rlen + 2);
                        CONTINUE;
                END;
                rdf_relo_seg := ORD(d[p + 2]);
                rdf_relo_ofs := get_dword(@d[p + 3]);
                rdf_relo_width := ORD(d[p + 7]);
                rdf_relo_rseg := get_word(@d[p + 8]);
                self_rel := (rdf_relo_seg AND $40) <> 0;
                fix := 0;
                rdf_relo_seg := rdf_relo_seg AND $3F;
                IF rdf_relo_width <> RELOC_WIDTH THEN mkerr(ctx, 'Invalid reloc width.');
                IF rdf_relo_seg = rdf^.code_segnum THEN BEGIN
                        Inc(rdf_relo_ofs, rdf^.link_code_ofs);
                        rdf_relo_seg := code_segnum;
                        IF self_rel THEN fix := -rdf^.link_code_ofs;
                END ELSE IF rdf_relo_seg = rdf^.data_segnum THEN BEGIN
                        Inc(rdf_relo_ofs, rdf^.link_data_ofs);
                        rdf_relo_seg := data_segnum;
                        IF self_rel THEN fix := -rdf^.link_data_ofs;
                END;
                IF rtype = RREC_RELOC THEN BEGIN
                        IF rdf_relo_rseg = rdf^.code_segnum THEN BEGIN
                                rdf_relo_rseg := code_segnum;
                                need_add := TRUE;
                        END ELSE IF rdf_relo_rseg = rdf^.data_segnum THEN BEGIN
                                rdf_relo_rseg := data_segnum;
                                need_add := TRUE;
                        END ELSE IF rdf_relo_rseg = rdf^.bss_segnum THEN BEGIN
                                rdf_relo_rseg := bss_segnum;
                                need_add := TRUE;
                        END ELSE BEGIN
                                name := get_import_name_by_segnum(rdf, rdf_relo_rseg);
                                dst_sym := lookup_gsymtab(ctx, name);
                                IF dst_sym <> NIL THEN BEGIN
                                        rdf_relo_rseg := dst_sym^.linked_seg;
                                        fix := dst_sym^.linked_ofs;
                                        need_add := TRUE;
                                END ELSE BEGIN
                                        mkerr(ctx, 'Could not resolve seg ' + itoa(rdf_relo_rseg));
                                END;
                        END;
                        IF need_add THEN BEGIN
                                IF rdf_relo_seg = code_segnum THEN BEGIN
                                        set_word(@code[rdf_relo_ofs], get_word(@code[rdf_relo_ofs]) + fix);
                                END ELSE IF rdf_relo_seg = data_segnum THEN BEGIN
                                        set_word(@data[rdf_relo_ofs], get_word(@data[rdf_relo_ofs]) + fix);
                                END;
                        END;

                        out_relo_seg := rdf_relo_seg;
                        out_relo_ofs := rdf_relo_ofs;
                        out_relo_width := rdf_relo_width;
                        out_relo_rseg := rdf_relo_rseg;
                END ELSE IF rtype = RREC_SEGRELO THEN BEGIN
                        IF rdf_relo_rseg = rdf^.code_segnum THEN BEGIN
                                rdf_relo_rseg := code_segnum;
                                need_add := TRUE;
                        END ELSE IF rdf_relo_rseg = rdf^.data_segnum THEN BEGIN
                                rdf_relo_rseg := data_segnum;
                                need_add := TRUE;
                        END ELSE IF rdf_relo_rseg = rdf^.bss_segnum THEN BEGIN
                                rdf_relo_rseg := bss_segnum;
                                need_add := TRUE;
                        END ELSE BEGIN
                                name := get_import_name_by_segnum(rdf, rdf_relo_rseg);
                                dst_sym := lookup_gsymtab(ctx, name);
                                IF dst_sym <> NIL THEN BEGIN
                                        rdf_relo_rseg := dst_sym^.linked_seg;
                                        need_add := TRUE;
                                END ELSE BEGIN
                                        mkerr(ctx, 'Could not resolve seg ' + itoa(rdf_relo_rseg));
                                END;
                        END;
                        out_relo_seg := rdf_relo_seg;
                        out_relo_ofs := rdf_relo_ofs;
                        out_relo_width := rdf_relo_width;
                        out_relo_rseg := rdf_relo_rseg;
                END;
                IF need_add THEN BEGIN
                        rec := CHR(out_relo_seg)
                                + bin_dword(out_relo_ofs)
                                + CHR(out_relo_width)
                                + bin_word(out_relo_rseg);
                        ctx.outrdf^.recs := rdfrec_add(ctx.outrdf^.recs, rtype, rec);
                        need_add := FALSE;
                END;
                Inc(p, rlen + 2);
        END;
END;

PROCEDURE link_rdf(VAR ctx : RLCTX);
VAR recs     : PRDFREC;
    rec      : STRING;
    startRdf : PRDF;
    rdf      : PRDF;
    entry    : STRING;
    sym      : PSYMTAB;

    code_ofs : WORD;
    data_ofs : WORD;
    bss_ofs  : WORD;
    code     : PCHAR;
    data     : PCHAR;

    code_segnum : WORD;
    data_segnum : WORD;
    bss_segnum  : WORD;
BEGIN
        IF ctx.err THEN EXIT;
        recs := NIL;
        entry := ctx.entry_name + #0;
        startRdf := lookup_export(ctx.rdfs, @entry[1]);
        IF startRdf = NIL THEN BEGIN
                mkerr(ctx, 'Could not resolve ' + ctx.entry_name);
                EXIT;
        END;
        resolve(ctx, startRdf);
        IF ctx.err THEN EXIT;
        ctx.rdfs := rdf_free_list(ctx.rdfs, FALSE);
        rdf_reorder(ctx, startRdf);
        IF ctx.rdfs <> startRdf THEN mkerr(ctx, 'Wrong reorder!!');
        IF ctx.err THEN EXIT;
        code_ofs := 0;
        data_ofs := 0;
        bss_ofs := 0;
        rdf := ctx.rdfs;
        code_segnum := 0;
        data_segnum := 1;
        bss_segnum  := 2;
        WHILE rdf <> NIL DO BEGIN
                rdf^.link_code_ofs := code_ofs;
                Inc(code_ofs, rdf^.code_size);
                WHILE (code_ofs AND ctx.align_segment) <> 0 DO Inc(code_ofs);

                rdf^.link_data_ofs := data_ofs;
                Inc(data_ofs, rdf^.data_size);
                WHILE (data_ofs AND ctx.align_segment) <> 0 DO Inc(data_ofs);

                rdf^.link_bss_ofs := bss_ofs;
                Inc(bss_ofs, rdf^.bss_size);
                WHILE (bss_ofs AND ctx.align_segment) <> 0 DO Inc(bss_ofs);

                rdf := rdf^.next;
        END;
        ctx.outrdf^.code_size := code_ofs;
        ctx.outrdf^.data_size := data_ofs;
        ctx.outrdf^.bss_size := bss_ofs;
        code := ctx.outrdf^.code;
        data := ctx.outrdf^.data;
        IF ctx.single_segment THEN BEGIN
                rdf := ctx.rdfs;
                WHILE rdf <> NIL DO BEGIN
                        Inc(rdf^.link_data_ofs, code_ofs);
                        rdf := rdf^.next;
                END;
                data_segnum := code_segnum;
                data := code;
        END;
        build_gsymtab(ctx);
        IF ctx.err THEN EXIT;
        load_segments(ctx, code, data);
        IF ctx.err THEN EXIT;
        ctx.outrdf^.recs := NIL;
        sym := ctx.symtab;
        WHILE sym <> NIL DO BEGIN
                link_sym(ctx, sym, code, data, code_segnum, data_segnum, bss_segnum);
                sym := sym^.next;
        END;
        rdf := ctx.rdfs;
        WHILE (rdf <> NIL) AND (NOT ctx.err) DO BEGIN
                link_relocs(ctx, rdf, code, data, code_segnum, data_segnum, bss_segnum);
                rdf := rdf^.next;
        END;
        IF ctx.err THEN EXIT;
        rec := bin_dword(ctx.outrdf^.bss_size);
        ctx.outrdf^.recs := rdfrec_add(ctx.outrdf^.recs, RREC_BSS, rec);
        ctx.outrdf^.recs := export_gsymtab(ctx, ctx.outrdf^.recs);
        rdfrec_implode(ctx.outrdf^.recs, ctx.outrdf^.hdr, ctx.outrdf^.hdr_size);
        ctx.outrdf^.hdr_alloc := ctx.outrdf^.hdr_size;

        IF ctx.single_segment THEN ctx.outrdf^.data_size := 0;
END;

PROCEDURE init(VAR ctx : RLCTX);
BEGIN
        FillChar(ctx, SizeOf(RLCTX), #0);
        ctx.outrdf := rdf_create;
        GetMem(ctx.outrdf^.code, SEG_SIZE);
        ctx.outrdf^.code_alloc := SEG_SIZE;
        GetMem(ctx.outrdf^.data, SEG_SIZE);
        ctx.outrdf^.data_alloc := SEG_SIZE;
        ctx.rdfs := NIL;
        ctx.rlib := getEnv('RLIB');
        ctx.outrdf^.code_segnum := 0;
        ctx.outrdf^.data_segnum := 1;
        ctx.outrdf^.bss_segnum := 2;
END;

PROCEDURE read_params(VAR ctx : RLCTX);
VAR c               : CHAR;
    pc, asegm, i    : INTEGER;
    str             : STRING;
BEGIN
        ctx.entry_name := 'start';
        ctx.align_segment := 2;
        i := 1;
        pc := ParamCount;
        WHILE (i <= ParamCount) AND (NOT ctx.err) DO BEGIN
                str := ParamStr(i);
                c := str[1];
                IF (c IN ['-', '/']) AND (str[0] = #2) THEN BEGIN
                        c := upCase(str[2]);
                        Inc(i);
                        IF c IN ['H', '?'] THEN Help(ctx)
                        ELSE IF c = 'V' THEN ctx.verbose := TRUE
                        ELSE IF c = 'T' THEN BEGIN
                                ctx.single_segment := TRUE;
                        END ELSE IF (c = 'A') AND (i <= pc) THEN BEGIN
                                asegm := atoi(ParamStr(i), 16);
                                IF NOT (asegm IN [2, 4, 8, 16, 32]) THEN BEGIN
                                        mkerr(ctx, 'Invalid segment align value');
                                        EXIT;
                                END;
                                ctx.align_segment := asegm;
                        END ELSE IF (c = 'E') AND (i <= pc) THEN BEGIN
                                ctx.entry_name := ParamStr(i);
                                Inc(i);
                        END ELSE IF (c = 'O') AND (i <= pc) THEN BEGIN
                                ctx.outname := ParamStr(i);
                                Inc(i);
                        END ELSE BEGIN
                                mkerr(ctx, 'Unknown option /' + c);
                                EXIT;
                        END;
                END ELSE BEGIN
                        load_meta_rdl(ctx, str);
                        Inc(i);
                END;
        END;
        IF ctx.rdfs = NIL THEN mkerr(ctx, 'No input files.');
        IF Length(ctx.outname) = 0 THEN mkerr(ctx, 'No output file.');
        IF Length(ctx.entry_name) = 0 THEN mkerr(ctx, 'Empty entry-point symbol name.');
        Dec(ctx.align_segment);
END;

VAR ctx : RLCTX;
BEGIN
        init(ctx);
        read_params(ctx);
        link_rdf(ctx);
        save_rdf(ctx);
        rdf_free(ctx.outrdf);
        rdf_free_list(ctx.rdfs, TRUE);
        IF ctx.err THEN BEGIN
                WriteLn(ctx.errMsg);
                WriteLn('  use /H for help');
                Halt(1);
        END;
END.
