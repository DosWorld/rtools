{ MIT License

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

https://github.com/DosWorld/rtools }
{$I+,A+,R-,S-,O-,F-,D-,L-,Q-,F-,G-}
UNIT rldutil;

INTERFACE

USES utils;

CONST

CSEG         = 1;
DSEG         = 2;
BSEG         = 3;

RREC_COMMENT = #0;
RREC_RELOC   = #1;
RREC_IMPORT  = #2;
RREC_GLOBAL  = #3;
RREC_BSS     = #5;
RREC_SEGRELO = #6;

RDOFF2_SIGN : STRING[6] = 'RDOFF2';
RLIB_SIGN1  : STRING[6] = '.sig'+#0;

TYPE

PRDFREC = ^TRDFREC;
TRDFREC = RECORD
        rtype : CHAR;
        rec   : STRING[64];
        next  : PRDFREC;
END;

PRDF=^TRDF;
TRDF=RECORD
        code, data  : PCHAR;
        hdr         : PCHAR;
        code_size   : WORD;
        code_segnum : WORD;
        code_alloc  : WORD;
        data_size   : WORD;
        data_segnum : WORD;
        data_alloc  : WORD;
        bss_size    : WORD;
        bss_segnum  : WORD;
        hdr_size    : WORD;
        hdr_alloc   : WORD;
        linked      : BOOLEAN;
        link_code_ofs : WORD;
        link_data_ofs : WORD;
        link_bss_ofs  : WORD;
        file_code_ofs : DWORD;
        file_data_ofs : DWORD;
        recs       : PRDFREC;
        fname      : STRING;
        next       : PRDF;
END;

PSYMTAB = ^TSYMTAB;
TSYMTAB = RECORD
        name       : PCHAR;
        rdf        : PRDF;
        ofs        : WORD;
        linked_ofs : WORD;
        linked_seg : BYTE;
        segnum     : WORD;
        segtype    : BYTE;
        next       : PSYMTAB;
END;

RLCTX = RECORD
        outrdf         : PRDF;
        outreloc       : PRDFREC;
        outname        : STRING;
        entry_name     : STRING;
        single_segment : BOOLEAN;
        align_segment  : WORD;
        rdfs           : PRDF;
        symtab         : PSYMTAB;
        verbose        : BOOLEAN;
        err            : BOOLEAN;
        errMsg         : STRING;
        rlib           : STRING;
END;

PROCEDURE mkerr(VAR ctx : RLCTX; str : STRING);
FUNCTION bin_word(w : WORD) : STRING;
FUNCTION bin_dword(w : DWORD) : STRING;
FUNCTION rdfrec_explode(data : PCHAR; len : WORD):PRDFREC;
FUNCTION rdfrec_add(r : PRDFREC; rtype : CHAR; VAR rec : STRING):PRDFREC;
PROCEDURE rdfrec_implode(r : PRDFREC; VAR data : PCHAR; VAR len : WORD);
FUNCTION rdf_create:PRDF;
PROCEDURE rdf_free(r : PRDF);
FUNCTION rdf_free_list(rdf : PRDF; all : BOOLEAN) : PRDF;

FUNCTION lookup_export(rdf : PRDF; name : PCHAR) : PRDF;
PROCEDURE resolve(VAR ctx : RLCTX; rdf : PRDF);
PROCEDURE rdf_reorder(VAR ctx : RLCTX; main : PRDF);

PROCEDURE build_gsymtab(VAR ctx : RLCTX);
FUNCTION export_gsymtab(VAR ctx : RLCTX; root : PRDFREC):PRDFREC;
FUNCTION get_import_name_by_segnum(rdf : PRDF; segnum : WORD):PCHAR;

FUNCTION lookup_gsymtab(VAR ctx : RLCTX; name : PCHAR) : PSYMTAB;

FUNCTION basename(s : STRING) : STRING;

IMPLEMENTATION

PROCEDURE mkerr(VAR ctx : RLCTX; str : STRING);
BEGIN
        IF ctx.err THEN EXIT;
        ctx.err := TRUE;
        ctx.errMsg := str;
END;

FUNCTION bin_word(w : WORD) : STRING;
BEGIN
        bin_word := CHR(w AND $FF) + CHR((w SHR 8) AND $FF);
END;

FUNCTION bin_dword(w : DWORD) : STRING;
BEGIN
        bin_dword := CHR(w AND $FF) + CHR((w SHR 8) AND $FF) + CHR((w SHR 16) AND $FF) + CHR((w SHR 24) AND $FF);
END;

FUNCTION rdfrec_explode(data : PCHAR; len : WORD):PRDFREC;
VAR     r, n : PRDFREC;
        p    : WORD;
        rlen : INTEGER;
BEGIN
        r := NIL;
        p := 0;
        WHILE p < len DO BEGIN
                GetMem(n, SizeOf(TRDFREC));
                n^.next := r;
                r := n;
                r^.rtype := data[p];
                Inc(p);
                rlen := ORD(data[p]);
                r^.rec[0] := CHR(rlen);
                Inc(p);
                Move(data[p], r^.rec[1], rlen);
                Inc(p, rlen);
        END;
        rdfrec_explode := r;
END;

FUNCTION rdfrec_add(r : PRDFREC; rtype : CHAR; VAR rec : STRING):PRDFREC;
VAR     n : PRDFREC;
BEGIN
        GetMem(n, SizeOf(TRDFREC));
        n^.rtype := rtype;
        n^.rec := rec;
        n^.next := r;
        rdfrec_add := n;
END;

PROCEDURE rdfrec_implode(r : PRDFREC; VAR data : PCHAR; VAR len : WORD);
VAR     n    : PRDFREC;
        p    : WORD;
        rlen : INTEGER;
BEGIN
        len := 0;
        data := NIL;
        n := r;
        WHILE n <> NIL DO BEGIN
                Inc(len, Length(n^.rec) + 2);
                n := n^.next;
        END;
        GetMem(data, len);
        n := r;
        p := 0;
        WHILE n <> NIL DO BEGIN
                data[p] := n^.rtype;
                Inc(p);
                rlen := Length(n^.rec) + 1;
                Move(n^.rec[0], data[p], rlen);
                Inc(p, rlen);
                n := n^.next;
        END;
END;

FUNCTION rdf_create:PRDF;
VAR     r : PRDF;
BEGIN
        GetMem(r, SizeOf(TRDF));
        FillChar(r^, SizeOf(TRDF), #0);
        rdf_create := r;
END;

PROCEDURE rdf_free(r : PRDF);
VAR     recs : PRDFREC;
BEGIN
        IF r = NIL THEN EXIT;
        IF r^.code_alloc <> 0 THEN FreeMem(r^.code, r^.code_alloc);
        IF r^.data_alloc <> 0 THEN FreeMem(r^.data, r^.data_alloc);
        IF r^.hdr_alloc <> 0 THEN FreeMem(r^.hdr, r^.hdr_alloc);
        WHILE r^.recs <> NIL DO BEGIN
                recs := r^.recs;
                r^.recs := r^.recs^.next;
                FreeMem(recs, SizeOf(TRDFREC));
        END;
        FreeMem(r, SizeOf(TRDF));
END;

FUNCTION rdf_free_list(rdf : PRDF; all : BOOLEAN) : PRDF;
VAR     r, n : PRDF;
BEGIN
        r := NIL;
        WHILE rdf <> NIL DO BEGIN
                n := rdf;
                rdf := rdf^.next;
                IF (NOT n^.linked) OR all THEN BEGIN
                        rdf_free(n);
                END ELSE BEGIN
                        n^.next := r;
                        r := n;
                END;
        END;
        rdf_free_list := r;
END;

FUNCTION basename(s : STRING) : STRING;
VAR     i : INTEGER;
BEGIN
        i := Length(s);
        WHILE i > 0 DO BEGIN
                IF s[i] IN [':','\','/'] THEN BREAK;
                Dec(i);
        END;
        IF i <> 0 THEN s := Copy(s, i + 1, Length(s) - i);
        basename := s;
END;

FUNCTION lookup_export(rdf : PRDF; name : PCHAR) : PRDF;
VAR     data  : PCHAR;
        p     : WORD;
        len   : WORD;
        rtype : CHAR;
        rlen  : WORD;
        r     : PRDF;
BEGIN
        r := NIL;
        IF name <> NIL THEN
                WHILE (rdf <> NIL) AND (r = NIL) DO BEGIN
                        p := 0;
                        data := rdf^.hdr;
                        len := rdf^.hdr_size;
                        WHILE p < len DO BEGIN
                                rtype := data[p];
                                rlen  := ORD(data[p + 1]);
                                IF rtype = RREC_GLOBAL THEN BEGIN
                                        IF strcmp(@data[p + 8], name) THEN r := rdf;
                                END;
                                Inc(p, rlen + 2);
                        END;
                        rdf := rdf^.next;
                END;
        lookup_export := r;
END;

PROCEDURE resolve(VAR ctx : RLCTX; rdf : PRDF);
VAR     data  : PCHAR;
        p     : WORD;
        len   : WORD;
        rtype : CHAR;
        rlen  : WORD;
        r     : PRDF;
        exp   : PRDF;
BEGIN
        IF ctx.err THEN EXIT;
        IF rdf = NIL THEN EXIT;
        IF rdf^.linked THEN EXIT;
        rdf^.linked := TRUE;
        p := 0;
        data := rdf^.hdr;
        len := rdf^.hdr_size;
        WHILE (p < len) AND (NOT ctx.err) DO BEGIN
                rtype := data[p];
                rlen  := ORD(data[p + 1]);
                IF rtype = RREC_IMPORT THEN BEGIN
                        exp := lookup_export(ctx.rdfs, @data[p + 5]);
                        IF exp <> NIL THEN BEGIN
                                resolve(ctx, exp);
                        END ELSE BEGIN
                                mkerr(ctx, 'Could not resolve symbol ' + strc2pas(@data[p + 5]));
                                EXIT;
                        END;
                END;
                Inc(p, rlen + 2);
        END;
END;

PROCEDURE build_gsymtab(VAR ctx : RLCTX);
VAR     sym   : PSYMTAB;
        rdf   : PRDF;
        data  : PCHAR;
        p     : WORD;
        len   : WORD;
        rtype : CHAR;
        rlen  : WORD;
BEGIN
        IF ctx.err THEN EXIT;
        rdf := ctx.rdfs;
        WHILE rdf <> NIL DO BEGIN
                p := 0;
                data := rdf^.hdr;
                len := rdf^.hdr_size;
                WHILE (p < len) AND (NOT ctx.err) DO BEGIN
                        rtype := data[p];
                        rlen  := ORD(data[p + 1]);
                        IF rtype = RREC_GLOBAL THEN BEGIN
                                GetMem(sym, SizeOf(TSYMTAB));
                                sym^.next := ctx.symtab;
                                sym^.rdf := rdf;
                                ctx.symtab := sym;
                                sym^.name := @data[p + 8];
                                sym^.ofs := get_dword(@data[p + 4]);
                                sym^.linked_ofs := sym^.ofs;
                                sym^.segnum := ORD(data[p + 3]);
                                sym^.linked_seg := 0;
                                IF sym^.segnum = rdf^.code_segnum THEN
                                        sym^.segtype := CSEG
                                ELSE IF sym^.segnum = rdf^.data_segnum THEN
                                        sym^.segtype := DSEG
                                ELSE IF sym^.segnum = rdf^.bss_segnum THEN
                                        sym^.segtype := BSEG
                                ELSE BEGIN
                                        mkerr(ctx, 'Bad export');
                                        EXIT;
                                END;
                        END;
                        Inc(p, rlen + 2);
                END;
                rdf := rdf^.next;
        END;
END;

FUNCTION export_gsymtab(VAR ctx : RLCTX; root : PRDFREC):PRDFREC;
VAR     str  : STRING;
        sym  : PSYMTAB;
        name : STRING;
BEGIN
        sym := ctx.symtab;
        WHILE sym <> NIL DO BEGIN
                name := strc2pas(sym^.name);
                str := #0 + CHR(sym^.linked_seg) + bin_dword(sym^.linked_ofs);
                str := str + name + #0;
                root := rdfrec_add(root, RREC_GLOBAL, str);
                sym := sym^.next;
        END;
        export_gsymtab := root;
END;

PROCEDURE rdf_reorder(VAR ctx : RLCTX; main : PRDF);
VAR     r, rdf, root : PRDF;
BEGIN
        root := NIL;
        r := ctx.rdfs;
        WHILE r <> NIL DO BEGIN
                rdf := r;
                r := r^.next;
                IF rdf <> main THEN BEGIN
                        rdf^.next := root;
                        root := rdf;
                END;
        END;
        main^.next := root;
        ctx.rdfs := main;
END;

FUNCTION get_import_name_by_segnum(rdf : PRDF; segnum : WORD):PCHAR;
VAR     data  : PCHAR;
        p     : WORD;
        len   : WORD;
        rtype : CHAR;
        rlen  : WORD;
        r     : PCHAR;
BEGIN
        r := NIL;
        p := 0;
        data := rdf^.hdr;
        len := rdf^.hdr_size;
        WHILE p < len DO BEGIN
                rtype := data[p];
                rlen  := ORD(data[p + 1]);
                IF rtype = RREC_IMPORT THEN BEGIN
                        IF get_word(@data[p + 3]) = segnum THEN BEGIN
                                r := @data[p + 5];
                                BREAK;
                        END;
                END;
                Inc(p, rlen + 2);
        END;
        get_import_name_by_segnum := r;
END;

FUNCTION lookup_gsymtab(VAR ctx : RLCTX; name : PCHAR) : PSYMTAB;
VAR     r : PSYMTAB;
BEGIN
        IF name <> NIL THEN BEGIN
                r := ctx.symtab;
                WHILE r <> NIL DO BEGIN
                        IF strcmp(name, r^.name) THEN BREAK;
                        r := r^.next;
                END;
        END ELSE BEGIN
                r := NIL;
        END;
        lookup_gsymtab := r;
END;

END.
