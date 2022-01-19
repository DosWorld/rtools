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
{$A+,I+,S-,R-,D-,L-,Q-,F-,G-}
USES dos, system2, args, StrBin, rdffmt, rlinkout;

{$DEFINE DEBUG}

FUNCTION basename(s : STRING) : STRING;
VAR     i : INTEGER;
BEGIN
        i := Length(s);
        WHILE i > 0 DO BEGIN
                IF s[i] IN [':','\','/'] THEN BEGIN Delete(s, 1, i); BREAK;
                END;
                Dec(i);
        END;
        basename := s;
END;

FUNCTION GetRdfMetaInfo(root : PRDFMETA; VAR src : BFILE; VAR hdr : BFILE):PRDFMETA;
VAR     r        : PRDFMETA;
        mod_size : DWORD;
        hdr_size : DWORD;
        rec      : RDF_SEG;
BEGIN
        Seek(src, FilePos(src) + 6);
        mod_size := ReadDWord(src);
        hdr_size := ReadDWord(src);
        GetMem(r, SizeOf(TRDFMETA));
        FillChar(r^, SizeOf(TRDFMETA), #0);
        r^.filename := src.filename;
        r^.hdr_size := hdr_size;
        r^.bhdr_ofs := FilePos(hdr);
        r^.next := root;
        root := r;
        BlockCopy(src, hdr, hdr_size);
        WHILE READ_SEG_REC(src, rec) DO BEGIN
                IF rec.segtype = RDFCS THEN BEGIN
                        r^.file_code := FilePos(src);
                        r^.code_size := rec.seglen;
                        r^.code_segnum := rec.segnum;
                        Seek(src, FilePos(src) + rec.seglen);
                END ELSE IF rec.segtype = RDFDS THEN BEGIN
                        r^.file_data := FilePos(src);
                        r^.data_size := rec.seglen;
                        r^.data_segnum := rec.segnum;
                        Seek(src, FilePos(src) + rec.seglen);
                END;
        END;
        r^.bss_segnum := r^.code_segnum;
        IF r^.bss_segnum < r^.data_segnum THEN r^.bss_segnum := r^.data_segnum;
        Inc(r^.bss_segnum);
        GetRdfMetaInfo := root;
END;

FUNCTION GetRdlMetaInfo(root : PRDFMETA; fname : STRING; VAR hdr : BFILE; VAR err : BOOLEAN):PRDFMETA;
VAR     ft       : RDF_FILE_TYPE;
        i        : BFILE;
        mod_name : STRING;
BEGIN
        Assign(i, fname);
        Reset(i);
        ft := GET_FILE_TYPE(i);
        IF ft = FILE_RDF THEN BEGIN
                root := GetRdfMetaInfo(root, i, hdr);
        END ELSE IF ft = FILE_RDL THEN BEGIN
                WHILE RDL_NEXT_MODULE(i, mod_name) DO BEGIN
                        root := GetRdfMetaInfo(root, i, hdr);
                END;
        END ELSE err := TRUE;
        Close(i);
        GetRdlMetaInfo := root;
END;

FUNCTION FindFileInRlib(VAR rlib : STRING; fname : STRING) : STRING;
VAR
        l, i, t : INTEGER;
        path    : STRING;
        bname   : STRING;
        nname   : STRING;
BEGIN
        IF NOT FileExists(fname) THEN BEGIN
                l := Length(rlib);
                bname := basename(fname);
                fname := '';
                i := 1;
                IF FileExists(bname) THEN BEGIN
                        fname := bname;
                END ELSE WHILE i < l DO BEGIN
                        path := '';
                        t := i;
                        WHILE (t <= l) AND (rlib[t] <> ';') DO BEGIN
                                Inc(path[0]);
                                path[ORD(path[0])] := rlib[t];
                                Inc(t);
                        END;
                        i := t + 1;
                        IF Length(path) > 0 THEN BEGIN
                                IF NOT (path[Length(path)] IN ['\', '/']) THEN path := path + '\';
                                nname := path + bname;
                                IF FileExists(nname) THEN BEGIN
                                        fname := nname;
                                        BREAK;
                                END;
                        END;
                END;
        END;
        {$IFDEF DEBUG}
        System.Writeln('Load ', fname);
        {$ENDIF}
        FindFileInRlib := fname;
END;

FUNCTION GetRlibMetaInfo(VAR rlib : STRING; root : PRDFMETA; fname : STRING; VAR hdr : BFILE; VAR err : BOOLEAN):PRDFMETA;
VAR     i        : BFILE;
BEGIN
        IF (fname[0] > #1) AND (fname[1] = '@') THEN BEGIN
                delete(fname, 1, 1);
                Assign(i, fname);
                Reset(i);
                err := err OR (NOT IsOpen(i));
                WHILE (NOT EOF(i)) AND (NOT err) DO BEGIN
                        ReadLn(i, fname);
                        IF Length(fname) <> 0 THEN IF fname[1] <> '@' THEN
                                root := GetRlibMetaInfo(rlib, root, fname, hdr, err);
                END;
                Close(i);
        END ELSE BEGIN
                fname := FindFileInRlib(rlib, fname);
                IF Length(fname) = 0 THEN BEGIN
                        System.Writeln('File ', fname, ' does not exists.');
                        err := TRUE;
                END ELSE root := GetRdlMetaInfo(root, fname, hdr, err)
        END;
        GetRlibMetaInfo := root;
END;

FUNCTION FindImportInBuildPlan(import : PIMPORTS; name : RDFNAME; segnum : WORD) : BOOLEAN;
VAR     r : BOOLEAN;
        i : INTEGER;
BEGIN
        r := FALSE;
        WHILE (import <> NIL) AND (NOT r) DO BEGIN
                i := 1;
                WHILE i <= import^.import_count DO BEGIN
                        IF import^.import[i].rec.seg = segnum THEN BEGIN
                                r := TRUE;
                                BREAK;
                        END ELSE IF import^.import[i].rec.name[0] = name[0] THEN
                                IF import^.import[i].rec.name = name THEN BEGIN
                                        r := TRUE;
                                        BREAK;
                                END;
                        Inc(i);
                END;
                import := import^.next;
        END;
        FindImportInBuildPlan := r;
END;

FUNCTION FindExportRdf(VAR build_plan : IMAGE_BUILD_PLAN; VAR name : RDFNAME) : PLINK_EXPORT;
VAR     export   : PLINK_EXPORT;
        exports  : PEXPORTS;
        r        : PRDFMETA;
        i        : INTEGER;
BEGIN
        export := NIL;
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (export = NIL) DO BEGIN
                exports := r^.linker.export;
                WHILE (exports <> NIL) AND (export = NIL) DO BEGIN
                        i := 1;
                        WHILE i <= r^.linker.export^.export_count DO BEGIN
                                IF r^.linker.export^.export[i].rec.name[0] = name[0] THEN
                                        IF r^.linker.export^.export[i].rec.name = name THEN BEGIN
                                                export := @r^.linker.export^.export[i];
                                                BREAK;
                                        END;
                                Inc(i);
                        END;
                        exports := exports^.next;
                END;
                r := r^.next;
        END;
        FindExportRdf := export;
END;

FUNCTION ResolveImports(VAR build_plan : IMAGE_BUILD_PLAN; rdf : PRDFMETA) : BOOLEAN;
VAR     err      : BOOLEAN;
        r        : PRDFMETA;
        import   : PIMPORTS;
        export   : PLINK_EXPORT;
        i : INTEGER;
BEGIN
        err := FALSE;
        IF NOT rdf^.linker.linked THEN BEGIN
                rdf^.linker.linked := TRUE;
                import := rdf^.linker.import;
                WHILE (NOT err) AND (import <> NIL) DO BEGIN
                        i := 1;
                        WHILE (NOT err) AND (i <= import^.import_count) DO BEGIN
                                export := FindExportRdf(build_plan, import^.import[i].rec.name);
                                import^.import[i].export := export;
                                err := export = NIL;
                                IF err THEN BEGIN
                                        System.Writeln('Could not resolve ', import^.import[i].rec.name);
                                END ELSE IF NOT export^.rdf^.linker.linked THEN BEGIN
                                        err := ResolveImports(build_plan, export^.rdf);
                                END;
                                Inc(i);
                        END;
                        import := import^.next;
                END;
        END;
        ResolveImports := err;
END;

FUNCTION CreateBuildPlan(VAR build_plan : IMAGE_BUILD_PLAN; entry_name : RDFNAME; strict_import : BOOLEAN) : BOOLEAN;
VAR     err      : BOOLEAN;
        r        : PRDFMETA;
        startRdf : PRDFMETA;
        s        : STRING;
        grec     : REXP_REC;
        irec     : RIMP_REC;
        rrec     : RRELOC_REC;
        export   : PEXPORTS;
        import   : PIMPORTS;
        p        : DWORD;
        find     : BOOLEAN;
BEGIN
        err := build_plan.rdfs = NIL;
        startRdf := NIL;

        { build export tables and lookup entry point }
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_GLOBAL, s) DO BEGIN
                        GET_EXPORT_REC(s, grec);
                        IF r^.linker.export = NIL THEN BEGIN
                                GetMem(export, SizeOf(TEXPORTS));
                                FillChar(export^, SizeOf(TEXPORTS), #0);
                                r^.linker.export := export;
                        END;
                        IF r^.linker.export^.export_count = REC_IN_PLAN THEN BEGIN
                                GetMem(export, SizeOf(TEXPORTS));
                                FillChar(export^, SizeOf(TEXPORTS), #0);
                                export^.next := r^.linker.export;
                                r^.linker.export := export;
                        END;
                        Inc(r^.linker.export^.export_count);
                        r^.linker.export^.export[r^.linker.export^.export_count].rec := grec;
                        r^.linker.export^.export[r^.linker.export^.export_count].rdf := r;
                        IF grec.name = entry_name THEN startRdf := r;
                END;
                r := r^.next;
        END;
        IF startRdf = NIL THEN System.Writeln('Entry point ', entry_name, ' not found.');
        err := err OR (startRdf = NIL);

        { build import tables }
        r := build_plan.rdfs;
        WHILE (NOT err) AND (r <> NIL) DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.rseg <= r^.bss_segnum THEN CONTINUE;
                        IF FindImportInBuildPlan(r^.linker.import, '', rrec.rseg) THEN CONTINUE;
                        p := FilePos(build_plan.hdr);
                        find := FALSE;
                        Seek(build_plan.hdr, r^.bhdr_ofs);
                        WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_IMPORT, s) DO BEGIN
                                GET_IMPORT_REC(s, irec);
                                IF irec.seg = rrec.rseg THEN BEGIN
                                        find := TRUE;
                                        BREAK;
                                END;
                        END;
                        IF NOT find THEN BEGIN
                                System.Writeln(
                                'Invalid relocation record - links to non-exists import ', rrec.rseg);
                                err := TRUE;
                        END;
                        IF r^.linker.import = NIL THEN BEGIN
                                GetMem(import, SizeOf(TIMPORTS));
                                FillChar(import^, SizeOf(TIMPORTS), #0);
                                r^.linker.import := import;
                        END;
                        IF r^.linker.import^.import_count = REC_IN_PLAN THEN BEGIN
                                GetMem(import, SizeOf(TIMPORTS));
                                FillChar(import^, SizeOf(TIMPORTS), #0);
                                import^.next := r^.linker.import;
                                r^.linker.import := import;
                        END;
                        Inc(r^.linker.import^.import_count);
                        r^.linker.import^.import[r^.linker.import^.import_count].rec := irec;
                        Seek(build_plan.hdr, p);
                END;
                r := r^.next;
        END;
        { resolve imports }
        IF NOT err THEN err := ResolveImports(build_plan, startRdf);
        CreateBuildPlan := err;
END;

FUNCTION LookupImportByRSeg(r : PRDFMETA; rseg : WORD) : PLINK_IMPORT;
VAR     import  : PLINK_IMPORT;
        imports : PIMPORTS;
        p       : INTEGER;
BEGIN
        imports := r^.linker.import;
        import := NIL;
        WHILE (imports <> NIL) AND (import = NIL) DO BEGIN
                p := 1;
                WHILE (p <= imports^.import_count) AND (import = NIL) DO BEGIN
                        IF imports^.import[p].rec.seg = rseg THEN BEGIN
                                import := @imports^.import[p];
                        END;
                        Inc(p);
                END;
                imports := imports^.next;
        END;
        LookupImportByRSeg := import;
END;

FUNCTION LinkSmallModel(VAR build_plan : IMAGE_BUILD_PLAN) : BOOLEAN;
VAR     err : BOOLEAN;
        i, new_headers, code, data : BFILE;
        code_segnum, data_segnum, bss_segnum : BYTE;
        r         : PRDFMETA;
        bss_size  : DWORD;
        cbss_size : DWORD;
        import    : PLINK_IMPORT;
        fix       : DWORD;
        s         : STRING;
        rrec      : RRELOC_REC;
        selfr     : BOOLEAN;
        exports   : PEXPORTS;
        p         : INTEGER;
BEGIN
        code_segnum := 0;
        data_segnum := 1;
        bss_segnum := 2;
        bss_size := 0;
        ReWriteMemFile(code);
        ReWriteMemFile(data);
        ReWriteMemFile(new_headers);
        err := NOT (IsOpen(code) AND IsOpen(data) AND IsOpen(new_headers));

        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Assign(i, r^.filename);
                Reset(i);
                err := NOT IsOpen(i) ;
                IF err THEN BREAK;

                r^.linker.smz_bss_ofs := bss_size;
                cbss_size := 0;
                Seek(i, r^.file_code);
                r^.linker.smz_code_ofs := FilePos(code);
                BlockCopy(i, code, r^.code_size);
                WHILE (r^.code_size AND 3) <> 0 DO BEGIN
                        WriteByte(code, $90);
                        Inc(r^.code_size);
                END;

                Seek(i, r^.file_data);
                r^.linker.smz_data_ofs := FilePos(data);
                BlockCopy(i, data, r^.data_size);
                FilePosAlign(data, 4);

                Close(i);
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, cbss_size);
                END;
                cbss_size := AlignValue(cbss_size, 4);
                Inc(bss_size, cbss_size);
                r := r^.next;
        END;

        { write exports and recalculate offsets }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                exports := r^.linker.export;
                WHILE exports <> NIL DO BEGIN
                        p := 1;
                        WHILE p <= exports^.export_count DO BEGIN
                                IF exports^.export[p].rec.seg = exports^.export[p].rdf^.code_segnum THEN BEGIN
                                        Inc(exports^.export[p].rec.offset, r^.linker.smz_code_ofs);
                                        exports^.export[p].rec.seg := code_segnum;
                                END ELSE IF exports^.export[p].rec.seg = exports^.export[p].rdf^.data_segnum THEN BEGIN
                                        Inc(exports^.export[p].rec.offset, r^.linker.smz_data_ofs);
                                        exports^.export[p].rec.seg := data_segnum;
                                END ELSE IF exports^.export[p].rec.seg = exports^.export[p].rdf^.bss_segnum THEN BEGIN
                                        Inc(exports^.export[p].rec.offset, r^.linker.smz_bss_ofs);
                                        exports^.export[p].rec.seg := bss_segnum;
                                END;
                                SET_EXPORT_REC(exports^.export[p].rec, s);
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
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        selfr := (rrec.seg AND $40) <> 0;
                        fix := 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                rrec.seg := code_segnum;
                                Inc(rrec.offset, r^.linker.smz_code_ofs);
                                IF selfr THEN fix := -r^.linker.smz_code_ofs
                                ELSE fix := r^.linker.smz_code_ofs;
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                rrec.seg := data_segnum;
                                Inc(rrec.offset, r^.linker.smz_data_ofs);
                                IF selfr THEN fix := -r^.linker.smz_data_ofs
                                ELSE fix := r^.linker.smz_data_ofs;
                        END;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                Inc(fix, import^.export^.rec.offset);
                                IF import^.export^.rec.seg
                                        = code_segnum THEN BEGIN
                                        rrec.rseg := code_segnum;
                                END ELSE IF import^.export^.rec.seg
                                        = data_segnum THEN BEGIN
                                        rrec.rseg := data_segnum;
                                END ELSE IF import^.export^.rec.seg
                                        = bss_segnum THEN BEGIN
                                        rrec.rseg := bss_segnum;
                                END;
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
                SET_BSS(bss_size, s);
                RDF_WRITE_REC(new_headers, RREC_BSS, s);
                WRITE_RDF(new_headers, code_segnum, code, data_segnum, data, build_plan.linked_out);
        END;
        Close(new_headers);
        Close(code);
        Close(data);
        LinkSmallModel := err;
END;

FUNCTION LinkAndGenMZH(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;

VAR     err      : BOOLEAN;
        i, o     : BFIle;
        hdr      : MZ_HEADER;
        header_paragraphs : WORD;
        code     : BFile;
        stack_ss : WORD;
        r        : PRDFMETA;
        start    : PLINK_EXPORT;
        export   : PLINK_EXPORT;
        import   : PLINK_IMPORT;
        bss_size : DWORD;
        s        : STRING;
        rrec     : RRELOC_REC;
        mzr      : MZ_RELOC;
        fix      : WORD;
        p        : INTEGER;
        find     : BOOLEAN;
        selfr    : BOOLEAN;
BEGIN
        err := FALSE;
        Assign(o, outfname);
        ReWrite(o);
        err := NOT IsOpen(o);
        start := NIL;
        FillChar(hdr, SizeOf(MZ_HEADER), #0);
        BlockWrite(o, hdr, SizeOf(MZ_HEADER));

        ReWriteMemFile(code);
        err := err OR (NOT IsOpen(code));
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Assign(i, r^.filename);
                Reset(i);

                err := NOT IsOpen(i) ;
                IF NOT err THEN BEGIN
                        Seek(i, r^.file_code);
                        r^.linker.hmz_code_seg := FilePos(code) SHR 4;
                        BlockCopy(i, code, r^.code_size);
                        FilePosAlign(code, $10);
        
                        Seek(i, r^.file_data);
                        r^.linker.hmz_data_seg := FilePos(code) SHR 4;
                        BlockCopy(i, code, r^.data_size);
                        FilePosAlign(code, $10);
        
                        Close(i);
                END;
                r := r^.next;
        END;
        IF NOT err THEN start := FindExportRdf(build_plan, entry_name);
        err := err OR (start = NIL);
        IF NOT err THEN BEGIN
                hdr.cs := start^.rdf^.linker.hmz_code_seg;
                hdr.ip := start^.rec.offset;
        END;

        { calculate bss seg's and SS }
        IF NOT err THEN hdr.ss := FileSize(code) SHR 4;
        hdr.min_extra_paragraphs := hdr.ss;
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                bss_size := 0;
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
                bss_size := AlignValue(bss_size, $10);
                r^.linker.hmz_bss_seg := hdr.ss;
                Inc(hdr.ss, bss_size SHR 4);
                r := r^.next;
        END;

        { resolve segrelo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_SEGRELO, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                                fix := r^.linker.hmz_code_seg;
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                fix := r^.linker.hmz_data_seg;
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                fix := r^.linker.hmz_bss_seg;
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import^.export^.rec.seg
                                        = import^.export^.rdf^.code_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_code_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.data_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_data_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.bss_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_bss_seg;
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_code_seg SHL 4) + rrec.offset
                                        , fix);
                                mzr.seg := r^.linker.hmz_code_seg;
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_data_seg SHL 4) + rrec.offset
                                        , fix);
                                mzr.seg := r^.linker.hmz_data_seg;
                        END;
                        mzr.ofs := rrec.offset;
                        BlockWrite(o, mzr, SizeOf(MZ_RELOC));
                        Inc(hdr.num_relocs);
                END;
                r := r^.next;
        END;

        { resolve relo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        selfr := (rrec.seg AND $40) <> 0;
                        fix := 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                fix := import^.export^.rec.offset;
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_code_seg SHL 4) + rrec.offset
                                        , fix);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_data_seg SHL 4) + rrec.offset
                                        , fix);
                        END;
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                FilePosAlign(o, $10);
                Seek(code, 0);
                hdr.signature := MZ_SIGN;
                hdr.header_paragraphs := FilePos(o) SHR 4;
                BlockCopy(code, o, FileSize(code));
                hdr.blocks_in_file := (FileSize(code) SHR 9) + 1;
                hdr.bytes_in_last_block := (FileSize(code) AND $1FF);
                hdr.reloc_table_offset := SizeOf(MZ_HEADER);
                hdr.min_extra_paragraphs :=
                        (hdr.ss - hdr.min_extra_paragraphs)
                        + (stack_size SHR 4) + 1;
                hdr.max_extra_paragraphs := hdr.min_extra_paragraphs;
                hdr.sp := stack_size;
                Seek(o, 0);
                BlockWrite(o, hdr, SizeOf(MZ_HEADER));
        END;
        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(code);
        Close(o);
        LinkAndGenMZH := err;
END;


FUNCTION LinkAndGenMZS(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;

VAR     err      : BOOLEAN;
        i, o     : BFIle;
        hdr      : MZ_HEADER;
        header_paragraphs : WORD;
        code     : BFile;
        data     : BFile;
        stack_ss : WORD;
        r        : PRDFMETA;
        start    : PLINK_EXPORT;
        export   : PLINK_EXPORT;
        import   : PLINK_IMPORT;
        bss_size : DWORD;
        s        : STRING;
        rrec     : RRELOC_REC;
        mzr      : MZ_RELOC;
        fix      : WORD;
        p        : INTEGER;
        find     : BOOLEAN;
        selfr    : BOOLEAN;
        smz_code_seg  : WORD;
        smz_data_seg  : WORD;
        smz_bss_seg   : WORD;
BEGIN
        err := FALSE;
        Assign(o, outfname);
        ReWrite(o);
        err := NOT IsOpen(o);
        start := NIL;
        FillChar(hdr, SizeOf(MZ_HEADER), #0);
        BlockWrite(o, hdr, SizeOf(MZ_HEADER));

        ReWriteMemFile(code);
        ReWriteMemFile(data);
        err := err OR (NOT (IsOpen(code) AND IsOpen(data)));
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Assign(i, r^.filename);
                Reset(i);

                err := NOT IsOpen(i) ;
                IF NOT err THEN BEGIN
                        Seek(i, r^.file_code);
                        r^.linker.smz_code_ofs := FilePos(code);
                        BlockCopy(i, code, r^.code_size);
                        FilePosAlign(code, 4);
        
                        Seek(i, r^.file_data);
                        r^.linker.smz_data_ofs := FilePos(data);
                        BlockCopy(i, data, r^.data_size);
                        FilePosAlign(data, 4);
        
                        Close(i);
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                FilePosAlign(code, $10);
                FilePosAlign(data, $10);
                smz_code_seg  := 0;
                smz_data_seg  := FileSize(code) SHR 4;
                smz_bss_seg   := smz_data_seg + FileSize(data) SHR 4;
        END;
        IF NOT err THEN start := FindExportRdf(build_plan, entry_name);
        err := err OR (start = NIL);
        IF NOT err THEN BEGIN
                hdr.cs := smz_code_seg;
                hdr.ip := start^.rec.offset + start^.rdf^.linker.smz_code_ofs;
        END;

        { calculate bss seg's and SS }
        IF NOT err THEN hdr.ss := smz_bss_seg;
        bss_size := 0;
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                r^.linker.smz_bss_ofs := bss_size;
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
                bss_size := AlignValue(bss_size, 2);
                r := r^.next;
        END;
        bss_size := AlignValue(bss_size, $10);
        hdr.ss := smz_bss_seg + (bss_size SHR 4);

        { resolve segrelo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_SEGRELO, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                                fix := smz_code_seg;
                                Inc(rrec.offset, r^.linker.smz_code_ofs);
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                fix := smz_data_seg;
                                Inc(rrec.offset, r^.linker.smz_data_ofs);
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                fix := smz_bss_seg;
                                Inc(rrec.offset, r^.linker.smz_bss_ofs);
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import^.export^.rec.seg
                                        = import^.export^.rdf^.code_segnum THEN
                                        fix := smz_code_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.data_segnum THEN
                                        fix := smz_data_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.bss_segnum THEN
                                        fix := smz_bss_seg;
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , rrec.offset
                                        , fix);
                                mzr.seg := smz_code_seg;
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                SetMem(data, RWIDTH16
                                        , rrec.offset
                                        , fix);
                                mzr.seg := smz_data_seg;
                        END;
                        mzr.ofs := rrec.offset;
                        BlockWrite(o, mzr, SizeOf(MZ_RELOC));
                        Inc(hdr.num_relocs);
                END;
                r := r^.next;
        END;

        { resolve relo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.bhdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.bhdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        selfr := (rrec.seg AND $40) <> 0;
                        fix := 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                Inc(rrec.offset, r^.linker.smz_code_ofs);
                                IF selfr THEN Dec(fix, r^.linker.smz_code_ofs);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                Inc(rrec.offset, r^.linker.smz_data_ofs);
                                IF selfr THEN Dec(fix, r^.linker.smz_data_ofs);
                        END;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                Inc(fix, import^.export^.rec.offset);
                                IF import^.export^.rec.seg = import^.export^.rdf^.code_segnum THEN BEGIN
                                        Inc(fix, import^.export^.rdf^.linker.smz_code_ofs);
                                END ELSE IF import^.export^.rec.seg = import^.export^.rdf^.data_segnum THEN BEGIN
                                        Inc(fix, import^.export^.rdf^.linker.smz_data_ofs);
                                END ELSE IF import^.export^.rec.seg = import^.export^.rdf^.bss_segnum THEN BEGIN
                                        Inc(fix, import^.export^.rdf^.linker.smz_bss_ofs);
                                END;
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                IncMem(code, rrec.width
                                        , rrec.offset
                                        , fix);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                IncMem(data, rrec.width
                                        , rrec.offset
                                        , fix);
                        END;
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                FilePosAlign(o, $10);
                hdr.signature := MZ_SIGN;
                hdr.header_paragraphs := FilePos(o) SHR 4;
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));
                Seek(data, 0);
                BlockCopy(data, o, FileSize(data));
                hdr.blocks_in_file := ((FileSize(code) + FileSize(data)) SHR 9) + 1;
                hdr.bytes_in_last_block := ((FileSize(code) + FileSize(data)) AND $1FF);
                hdr.reloc_table_offset := SizeOf(MZ_HEADER);
                hdr.min_extra_paragraphs :=
                        (hdr.ss - smz_bss_seg)
                        + (stack_size SHR 4) + 1;
                hdr.max_extra_paragraphs := hdr.min_extra_paragraphs;
                hdr.sp := stack_size;
                Seek(o, 0);
                BlockWrite(o, hdr, SizeOf(MZ_HEADER));
        END;
        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(code);
        Close(o);
        LinkAndGenMZS := err;
END;

PROCEDURE FreeOutOfPlan(VAR build_plan : IMAGE_BUILD_PLAN);
VAR     r        : PRDFMETA;
        export   : PEXPORTS;
        import   : PIMPORTS;
BEGIN
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                IF NOT r^.linker.linked THEN BEGIN
                        WHILE r^.linker.export <> NIL DO BEGIN
                                export := r^.linker.export;
                                r^.linker.export := r^.linker.export^.next;
                                FreeMem(export, SizeOf(TEXPORTS));
                        END;
                        WHILE r^.linker.import <> NIL DO BEGIN
                                import := r^.linker.import;
                                r^.linker.import := r^.linker.import^.next;
                                FreeMem(import, SizeOf(TIMPORTS));
                        END;
                END;
                r := r^.next;
        END;
END;

PROCEDURE DestroyPlan(VAR build_plan : IMAGE_BUILD_PLAN);
VAR     r        : PRDFMETA;
        export   : PEXPORTS;
        import   : PIMPORTS;
BEGIN
        WHILE build_plan.rdfs <> NIL DO BEGIN
                r := build_plan.rdfs;
                build_plan.rdfs := build_plan.rdfs^.next;
                WHILE r^.linker.export <> NIL DO BEGIN
                        export := r^.linker.export;
                        r^.linker.export := r^.linker.export^.next;
                        FreeMem(export, SizeOf(TEXPORTS));
                END;
                WHILE r^.linker.import <> NIL DO BEGIN
                        import := r^.linker.import;
                        r^.linker.import := r^.linker.import^.next;
                        FreeMem(import, SizeOf(TIMPORTS));
                END;
                FreeMem(r, SizeOf(TRDFMETA));
        END;
        Close(build_plan.hdr);
END;

CONST
ARG_OUTPUT = 'o';
ARG_ENTRY  = 'entry';
ARG_ORG    = 'org';
ARG_BSS    = 'bss';
ARG_RDF    = 'rdf';
ARG_NOEMEM = 'noextmem';
ARG_COM    = 'com';
ARG_MZH    = 'mzh';
ARG_MZS    = 'mzs';
ARG_DOSPE  = 'dospe';
ARG_WINPE  = 'winpe';
ARG_STACK  = 's';
LIB_ENV    = 'RLIB';

OPTIONS_DESC : ARRAY[0..10] OF TOPT = (
(name: ARG_OUTPUT; otype: OPTSTR;  help: 'Set output file name.'),
(name: ARG_ORG;    otype: OPTSTR;  help: 'Set code start offset for COM output.'; default:'0x0100'),
(name: ARG_ENTRY;  otype: OPTSTR;  help: 'Set entry-point name.'; default:'start'),
(name: ARG_STACK;  otype: OPTSTR;  help: 'Set stack size in KB.'; default:'8'),
(name: ARG_BSS;    otype: OPTBOOL; help: 'Reserve BSS-memory for COM/RDF output.'),
(name: ARG_NOEMEM; otype: OPTBOOL; help: 'Use temporary files instead EMS/XMS memory.'),
(name: ARG_RDF;    otype: OPTCMD;  help: 'Link RDF file. Merge all segments into one code segment.'),
(name: ARG_COM;    otype: OPTCMD;  help: 'Link COM file, tiny memory model.'),
(name: ARG_MZS;    otype: OPTCMD;  help: 'Link MZ file, small memory model.'),
(name: ARG_MZH;    otype: OPTCMD;  help: 'Link MZ file, huge memory model.'),
(name: ARG_DOSPE;  otype: OPTCMD;  help: 'Link DOS-PE file (PE without imports).') {,
(name: ARG_WINPE;  otype: OPTCMD;  help: 'Link Win32-PE file.')}
);

VAR     myArgs        : TARGSTATE;
        bin_org       : LONGINT;
        str_org       : STRING;
        bin_ss        : LONGINT;
        str_ss        : STRING;
        cmd           : STRING;
        outfname      : STRING;
        entry_name    : RDFNAME;
        build_plan    : IMAGE_BUILD_PLAN;
        i, arg_count  : INTEGER;
        err           : BOOLEAN;
        strict_import : BOOLEAN;
        rlib          : STRING;
BEGIN
        ArgsParse(myArgs, OPTIONS_DESC);

        outfname := GetOptStr(myArgs, ARG_OUTPUT);
        entry_name := GetOptStr(myArgs, ARG_ENTRY);
        str_org := GetOptStr(myArgs, ARG_ORG);
        str_ss := GetOptStr(myArgs, ARG_STACK);

        IF ArgsCount(myArgs) = 0 THEN SetArgsErr(myArgs, 'No input files.');
        IF Length(outfname) = 0 THEN SetArgsErr(myArgs, 'No output file.');
        IF Length(entry_name) = 0 THEN SetArgsErr(myArgs, 'No entry point.');
        IF NOT StrAsLong(str_org, bin_org) THEN SetArgsErr(myArgs, 'Bad code offset.');
        IF NOT StrAsLong(str_ss, bin_ss) THEN SetArgsErr(myArgs, 'Bad stack size.');

        WriteArgsErrors(myArgs);
        IF ArgsError(myArgs) THEN Halt(1);

        rlib := getEnv(LIB_ENV);
        {$IFDEF DEBUG}
        System.Writeln('RLIB=', rlib);
        {$ENDIF}
        IF GetOptBool(myArgs, ARG_NOEMEM) THEN SetDefaultCacheSize(0);
        SetUseTempFiles(TRUE);

        cmd := GetCmd(myArgs);
        bin_ss := bin_ss * 1024;

        FillChar(build_plan, SizeOf(IMAGE_BUILD_PLAN), #0);
        ReWriteMemFile(build_plan.hdr);
        err := FALSE;
        arg_count := ArgsCount(myArgs);
        i := 1;
        WHILE (i <= arg_count) AND (NOT err) DO BEGIN
                build_plan.rdfs :=
                        GetRlibMetaInfo(rlib, build_plan.rdfs
                                , GetArgsStr(myArgs, i)
                                , build_plan.hdr, err);
                Inc(i);
        END;
        IF cmd = ARG_DOSPE THEN strict_import := FALSE ELSE strict_import := TRUE;
        IF NOT err THEN err := CreateBuildPlan(build_plan, entry_name, strict_import);
        {$IFDEF DEBUG}
        Assign(build_plan.linked_out, 'int.rdf');
        ReWrite(build_plan.linked_out);
        {$ENDIF}
        {$IFNDEF DEBUG}
        ReWriteMemFile(build_plan.linked_out);
        {$ENDIF}
        FreeOutOfPlan(build_plan);
        IF (NOT err) AND (cmd = ARG_MZH) THEN BEGIN
                err := LinkAndGenMZH(build_plan, entry_name, outfname, bin_ss);
                DestroyPlan(build_plan);
        END ELSE IF (NOT err) AND (cmd = ARG_COM) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenCOM(build_plan.linked_out
                        , bin_org
                        , entry_name
                        , outfname
                        , GetOptBool(myArgs, ARG_BSS));
        END ELSE IF (NOT err) AND (cmd = ARG_MZS) THEN BEGIN
                err := LinkAndGenMZS(build_plan
                        , entry_name
                        , outfname
                        , bin_ss);
                DestroyPlan(build_plan);
        END ELSE IF (NOT err) AND (cmd = ARG_RDF) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenRDF(build_plan.linked_out
                        , outfname
                        , GetOptBool(myArgs, ARG_BSS));
        END ELSE IF (NOT err) AND (cmd = ARG_DOSPE) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenDosPE(build_plan.linked_out
                        , entry_name
                        , outfname
                        , bin_ss);
        END ELSE DestroyPlan(build_plan);
        Close(build_plan.linked_out);
        IF err THEN Halt(1);
END.