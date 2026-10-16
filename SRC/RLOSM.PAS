{ MIT License

Copyright (c) 2022 Viacheslav Komenda

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

https://github.com/DosWorld/rtools }
{$A+,I+,S-,R-,D-,L-,Q-,F-,G-}
UNIT RloSm;
INTERFACE
USES System2, RdfFmt, Rlo;
FUNCTION LinkSmallModel(VAR build_plan: IMAGE_BUILD_PLAN):
    BOOLEAN;
IMPLEMENTATION
FUNCTION LinkSmallModel(VAR build_plan : IMAGE_BUILD_PLAN) :
    BOOLEAN;
VAR     err : BOOLEAN;
    i, new_headers, code, data : BFILE;
    code_segnum, data_segnum, bss_segnum : BYTE;
    r         : PRDFMETA;
    bss_size  : DWORD;
    cbss_size : DWORD;
    import    : PLINK_IMPORT;
    fix       : DWORD;
    s         : STRING;
    rt        : CHAR;
    rrec      : RRELOC_REC;
    selfr     : BOOLEAN;
    exports   : PEXPORTS;
    p         : INTEGER;
    lk        : INTEGER;
    tk        : INTEGER;
    grec      : REXP_REC;
BEGIN
    code_segnum := 0;
    data_segnum := 1;
    bss_segnum := 2;
    bss_size := 0;

    ReWriteTemp(code);
    ReWriteTemp(data);
    ReWriteTemp(new_headers);
    err := NOT (IsOpen(code) AND IsOpen(data) AND IsOpen(
        new_headers));

    r := build_plan.rdfs;
    WHILE (r <> NIL) AND (NOT err) DO BEGIN
        Assign(i, r^.filename^);
        Reset(i);
        err := NOT IsOpen(i);
        IF err THEN BREAK;

        r^.linker.smz_bss_ofs := bss_size;
        cbss_size := 0;
        Seek(i, r^.file_code);
        r^.linker.smz_code_ofs := FilePos(code);
        BlockCopy(i, code, r^.code_size);
        WHILE (FilePos(code) AND 15) <> 0 DO WriteByte(code,
            $90);

        Seek(i, r^.file_data);
        r^.linker.smz_data_ofs := FilePos(data);
        BlockCopy(i, data, r^.data_size);
        FilePosAlign(data, 4);

        Close(i);
        Seek(build_plan.hdr, r^.hdr_ofs);
        WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr,
            r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
            GET_BSS(s, cbss_size);
        END;
        Seek(build_plan.hdr, r^.hdr_ofs);
        IF RDF_NLOOKUPREC(build_plan.hdr,
            r^.hdr_ofs + r^.hdr_size,
            RREC_SEGRELO, s) THEN BEGIN
            System.Writeln(
            'Segment fixup requires MZS, MZL, NE or QLB.');
            err := TRUE;
        END;
        Seek(build_plan.hdr, r^.hdr_ofs);
        WHILE FilePos(build_plan.hdr) <
            r^.hdr_ofs + r^.hdr_size DO BEGIN
            RDF_READ_REC(build_plan.hdr, rt, s);
            IF rt IN [RREC_DLL, RREC_MODNAME,
                RREC_COMMENT] THEN
                RDF_WRITE_REC(new_headers, rt, s);
        END;
        IF cbss_size > $7FFFFFFC - bss_size THEN BEGIN
            System.Writeln('Combined BSS size overflows.');
            err := TRUE;
        END ELSE BEGIN
            cbss_size := AlignValue(cbss_size, 4);
            Inc(bss_size, cbss_size);
        END;
        r := r^.next;
    END;

        { write exports and recalculate offsets }
    r := build_plan.rdfs;
    WHILE (r <> NIL) AND (NOT err) DO BEGIN
        exports := r^.linker.export;
        WHILE exports <> NIL DO BEGIN
            p := 1;
            WHILE p <= exports^.export_count DO BEGIN
                IF exports^.export[p].rec.seg =
                exports^.export[p].rdf^.code_segnum THEN BEGIN
                    Inc(exports^.export[p].rec.offset,
                r^.linker.smz_code_ofs);
                    exports^.export[p].rec.seg := code_segnum;
                END ELSE IF exports^.export[p].rec.seg =
                exports^.export[p].rdf^.data_segnum THEN BEGIN
                    Inc(exports^.export[p].rec.offset,
                r^.linker.smz_data_ofs);
                    exports^.export[p].rec.seg := data_segnum;
                END ELSE IF exports^.export[p].rec.seg =
                exports^.export[p].rdf^.bss_segnum THEN BEGIN
                    Inc(exports^.export[p].rec.offset,
                r^.linker.smz_bss_ofs);
                    exports^.export[p].rec.seg := bss_segnum;
                END;
                grec.flags := exports^.export[p].rec.flags;
                grec.seg := exports^.export[p].rec.seg;
                grec.offset := exports^.export[p].rec.offset;
                grec.name := SymName(
                exports^.export[p].rec.sym)^;
                grec.next := NIL;
                SET_EXPORT_REC(grec, s);
                RDF_WRITE_REC(new_headers, RREC_GLOBAL, s);
                Inc(p);
            END;
            exports := exports^.next;
        END;
        r := r^.next;
    END;

        { resolve relo }
    r := build_plan.rdfs;
    WHILE (r <> NIL) AND (NOT err) DO BEGIN
        Seek(build_plan.hdr, r^.hdr_ofs);
        WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr,
            r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
            GET_RELOC_REC(s, rrec);
            selfr := (rrec.seg AND $40) <> 0;
            fix := 0;
            rrec.seg := rrec.seg AND $3F;
            lk := 3;
            tk := 3;
            IF rrec.seg = r^.code_segnum THEN lk := 0
            ELSE IF rrec.seg = r^.data_segnum THEN lk := 1;
            IF rrec.seg = r^.code_segnum THEN BEGIN
                rrec.seg := code_segnum;
                Inc(rrec.offset, r^.linker.smz_code_ofs);
            END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                rrec.seg := data_segnum;
                Inc(rrec.offset, r^.linker.smz_data_ofs);
            END;
            IF rrec.rseg = r^.code_segnum THEN BEGIN
                tk := 0; rrec.rseg := code_segnum;
                IF NOT selfr THEN Inc(fix,
                r^.linker.smz_code_ofs);
            END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                tk := 1; rrec.rseg := data_segnum;
                IF NOT selfr THEN Inc(fix,
                r^.linker.smz_data_ofs);
            END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                tk := 2; rrec.rseg := bss_segnum;
                IF NOT selfr THEN Inc(fix,
                r^.linker.smz_bss_ofs);
            END ELSE BEGIN
                import := LookupImportByRSeg(r, rrec.rseg);
                IF (import = NIL) OR (import^.export = NIL) THEN
                BEGIN
                    System.Writeln(r^.filename^,
                ': unresolved import.');
                    err := TRUE;
                    BREAK;
                END;
                IF import^.export^.rec.seg <= 2 THEN tk :=
                import^.export^.rec.seg;
                IF import^.export^.rec.seg = code_segnum THEN
                BEGIN
                    rrec.rseg := code_segnum;
                    IF selfr THEN fix := -r^.linker.smz_code_ofs;
                END ELSE IF import^.export^.rec.seg =
                data_segnum THEN BEGIN
                    rrec.rseg := data_segnum;
                    IF selfr THEN fix := -r^.linker.smz_data_ofs;
                END ELSE IF import^.export^.rec.seg = bss_segnum
                THEN BEGIN
                    rrec.rseg := bss_segnum;
                    IF selfr THEN fix := -r^.linker.smz_bss_ofs;
                END;
                Inc(fix, import^.export^.rec.offset);
            END;
            IF selfr AND (lk <> tk) THEN BEGIN
                System.Writeln(r^.filename^,
                ': near relative reference to another segment.');
                err := TRUE;
                BREAK;
            END;
            IF rrec.seg = code_segnum THEN BEGIN
                IncMem(code, rrec.width
                    , rrec.offset
                    , fix);
            END ELSE IF rrec.seg = data_segnum THEN BEGIN
                IncMem(data, rrec.width
                    , rrec.offset
                    , fix);
            END;
            IF NOT selfr THEN BEGIN
                SET_RELOC_REC(rrec, s);
                RDF_WRITE_REC(new_headers, RREC_RELOC, s);
            END;
        END;
        r := r^.next;
    END;

    IF NOT err THEN BEGIN
        LayCode := FileSize(code);
        LayData := FileSize(data);
        LayBss := bss_size;
        SET_BSS(bss_size, s);
        RDF_WRITE_REC(new_headers, RREC_BSS, s);
        WRITE_RDF(new_headers, code_segnum, code, data_segnum,
            data, build_plan.linked_out);
    END;
    IF NOT err THEN BEGIN
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
            r^.code_segnum := code_segnum;
            r^.data_segnum := data_segnum;
            r^.bss_segnum := bss_segnum;
            r := r^.next;
        END;
    END;
    Close(new_headers);
    Close(code);
    Close(data);
    LinkSmallModel := err;
END;

END.
