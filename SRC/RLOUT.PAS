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
UNIT rlout;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt;

CONST
REC_IN_PLAN = 64;

TYPE
PRDFMETA = ^TRDFMETA;

PLINK_EXPORT = ^TLINK_EXPORT;
TLINK_EXPORT = RECORD
        rec : REXP_REC;
        rdf : PRDFMETA;
END;

PEXPORTS = ^TEXPORTS;
TEXPORTS = RECORD
        export       : ARRAY [1..REC_IN_PLAN] OF TLINK_EXPORT;
        export_count : WORD;
        next         : PEXPORTS;
END;

PLINK_IMPORT = ^TLINK_IMPORT;
TLINK_IMPORT = RECORD
        rec     : RIMP_REC;
        export  : PLINK_EXPORT;
        newrseg : WORD;
        resolv  : BOOLEAN;
END;

PIMPORTS = ^TIMPORTS;
TIMPORTS = RECORD
        import       : ARRAY [1..REC_IN_PLAN] OF TLINK_IMPORT;
        import_count : WORD;
        next         : PIMPORTS;
END;

TLINKDATA = RECORD
        linked   : BOOLEAN;
        export   : PEXPORTS;
        import   : PIMPORTS;

        smz_bss_size  : WORD;

        smz_code_ofs  : DWORD;
        smz_data_ofs  : DWORD;
        smz_bss_ofs   : DWORD;

        hmz_code_seg  : WORD;
        hmz_code_size : WORD;
        hmz_data_seg  : WORD;
        hmz_data_size : WORD;
        hmz_bss_seg   : WORD;
        hmz_bss_size  : WORD;
END;

TRDFMETA = RECORD
        filename    : STRING;
        file_code   : DWORD;
        file_data   : DWORD;
        code_size   : DWORD;
        data_size   : DWORD;

        data_segnum : WORD;
        bss_segnum  : WORD;
        code_segnum : WORD;

        hdr_size    : DWORD;
        hdr_ofs     : DWORD;
        linker      : TLINKDATA;
        next        : PRDFMETA;
END;

IMAGE_BUILD_PLAN = RECORD
        rdfs        : PRDFMETA;
        hdr         : BFILE;
        linked_out  : BFILE;
END;

CONST
MZ_SIGN = $5A4D;

TYPE
MZ_HEADER = RECORD
        signature
        , bytes_in_last_block
        , blocks_in_file
        , num_relocs
        , header_paragraphs
        , min_extra_paragraphs
        , max_extra_paragraphs
        , ss, sp
        , checksum
        , ip, cs
        , reloc_table_offset
        , overlay_number : WORD;
END;

MZ_RELOC = RECORD
        ofs : WORD;
        seg : WORD;
END;

FUNCTION AlignValue(value : DWORD; align : DWORD) : DWORD;
FUNCTION ReadRDF(VAR src, dst_headers, dst_code, dst_data : BFILE; VAR code_segnum, data_segnum, bss_segnum : WORD) : BOOLEAN;
FUNCTION FindEntryPoint(hdr : BFILE; hdr_size : DWORD; VAR name : RDFNAME; VAR ip : DWORD) : BOOLEAN;
FUNCTION DisableRecs(VAR hdr : BFILE; rtype : CHAR) : BOOLEAN;
FUNCTION DisableRelocsWidth(VAR hdr : BFILE; width : BYTE) : BOOLEAN;
PROCEDURE IncMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
PROCEDURE SetMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
FUNCTION MergeCodeDataBss(VAR src, dst : BFile; merge_bss : BOOLEAN) : BOOLEAN;

FUNCTION FindImportInBuildPlan(import : PIMPORTS; name : RDFNAME; segnum : WORD) : BOOLEAN;
FUNCTION FindExportRdf(VAR build_plan : IMAGE_BUILD_PLAN; VAR name : RDFNAME) : PLINK_EXPORT;
FUNCTION ResolveImports(VAR build_plan : IMAGE_BUILD_PLAN; rdf : PRDFMETA) : BOOLEAN;
FUNCTION LookupImportByRSeg(r : PRDFMETA; rseg : WORD) : PLINK_IMPORT;

FUNCTION CreateBuildPlan(VAR build_plan : IMAGE_BUILD_PLAN; entry_name : RDFNAME; strict_import : BOOLEAN) : BOOLEAN;
PROCEDURE FreeOutOfPlan(VAR build_plan : IMAGE_BUILD_PLAN);
PROCEDURE DestroyPlan(VAR build_plan : IMAGE_BUILD_PLAN);

FUNCTION LinkSmallModel(VAR build_plan : IMAGE_BUILD_PLAN) : BOOLEAN;

IMPLEMENTATION

FUNCTION AlignValue(value : DWORD; align : DWORD) : DWORD;
VAR     n : DWORD;
BEGIN
        n := value DIV align;
        IF value MOD align <> 0 THEN Inc(n);
        AlignValue := n * align;
END;

FUNCTION ReadRDF(VAR src, dst_headers, dst_code, dst_data : BFILE; VAR code_segnum, data_segnum, bss_segnum : WORD) : BOOLEAN;
VAR     modsize : DWORD;
        hdrsize : DWORD;
        rec     : RDF_SEG;
        err     : BOOLEAN;
BEGIN
        err := FALSE;
        Seek(src, 0);
        IF GET_FILE_TYPE(src) = FILE_RDF THEN BEGIN
                Seek(src, 6);
                modsize := ReadDWord(src);
                hdrsize := ReadDWord(src);
                IF IsOpen(dst_headers) THEN BlockCopy(src, dst_headers, hdrsize)
        END ELSE BEGIN
                System.writeln('WRONG FILE TYPE');
                err := TRUE;
        END;
        WHILE READ_SEG_REC(src, rec) AND (NOT err) DO BEGIN
                IF (rec.segtype = RDFCS) AND (FileSize(dst_code) = 0) THEN BEGIN
                        BlockCopy(src, dst_code, rec.seglen);
                        code_segnum := rec.segnum;
                END ELSE IF (rec.segtype = RDFDS) AND (FileSize(dst_data) = 0) THEN BEGIN
                        BlockCopy(src, dst_data, rec.seglen);
                        data_segnum := rec.segnum;
                END ELSE BEGIN
                        err := TRUE;
                END;
        END;
        bss_segnum := code_segnum;
        IF bss_segnum < data_segnum THEN bss_segnum := data_segnum;
        Inc(bss_segnum);
        ReadRDF := NOT err;
END;

FUNCTION FindEntryPoint(hdr : BFILE; hdr_size : DWORD; VAR name : RDFNAME; VAR ip : DWORD) : BOOLEAN;
VAR     str   : STRING;
        rec   : REXP_REC;
        find  : BOOLEAN;
        pos   : DWORD;
BEGIN
        find := FALSE;
        ip := 0;
        pos := FilePos(hdr) + hdr_size;
        WHILE (RDF_NLOOKUPREC(hdr, pos, RREC_GLOBAL, str)) AND (NOT find) DO BEGIN
                GET_EXPORT_REC(str, rec);
                IF rec.name = name THEN BEGIN
                        ip := rec.offset;
                        find := TRUE;
                END;
        END;
        FindEntryPoint := find;
END;

FUNCTION DisableRecs(VAR hdr : BFILE; rtype : CHAR) : BOOLEAN;
VAR     str   : STRING;
        err   : BOOLEAN;
BEGIN
        err := FALSE;
        Seek(hdr, 0);
        IF RDF_LOOKUPREC(hdr, rtype, str) THEN BEGIN
                err := TRUE;
                system.writeln('Unsupported record type ' + CHR(ORD(rtype) + ORD('0')));
        END;
        DisableRecs := err;
END;

FUNCTION DisableRelocsWidth(VAR hdr : BFILE; width : BYTE) : BOOLEAN;
VAR     rtype : CHAR;
        c     : STRING;
        rec   : RRELOC_REC;
        err   : BOOLEAN;
BEGIN
        err := FALSE;
        Seek(hdr, 0);
        WHILE NOT EOF(hdr) DO BEGIN
                RDF_READ_REC(hdr, rtype, c);
                IF rtype IN [RREC_SEGRELO, RREC_RELOC] THEN BEGIN
                        GET_RELOC_REC(c, rec);
                        IF rec.width > width THEN BEGIN
                                system.writeln('Invalid relocation width for output format.');
                                err := TRUE;
                                BREAK;
                        END;
                END;
        END;
        DisableRelocsWidth := err;
END;

PROCEDURE IncMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
BEGIN
        CASE width OF
        RWIDTH8:   IncByte(f, ofs, value AND $FF);
        RWIDTH16:  IncWord(f, ofs, value AND $FFFF);
        RWIDTH32:  IncDWord(f, ofs, value);
        END;
END;

PROCEDURE SetMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
BEGIN
        CASE width OF
        RWIDTH8:   SetByte(f, ofs, value AND $FF);
        RWIDTH16:  SetWord(f, ofs, value AND $FFFF);
        RWIDTH32:  SetDWord(f, ofs, value);
        END;
END;

FUNCTION MergeCodeDataBss(VAR src, dst : BFile; merge_bss : BOOLEAN) : BOOLEAN;
VAR     new_headers : BFile;
        c           : STRING;
        rec         : RRELOC_REC;
        grec        : REXP_REC;
        irec        : RIMP_REC;
        nrec        : RNAME_REC;
        err         : BOOLEAN;

        code        : BFILE;
        data        : BFILE;
        hdr         : BFILE;

        code_ofs    : DWORD;
        code_size   : DWORD;
        data_ofs    : DWORD;
        data_size   : DWORD;
        bss_ofs     : DWORD;
        bss_size    : DWORD;

        code_segnum : WORD;
        data_segnum : WORD;
        bss_segnum  : WORD;

        fix         : DWORD;
BEGIN
        FillChar(hdr, SizeOf(BFile), #0);
        FillChar(code, SizeOf(BFile), #0);
        FillChar(data, SizeOf(BFile), #0);
        FillChar(new_headers, SizeOf(BFile), #0);

        err := NOT (IsOpen(src) AND IsOpen(dst));
        IF NOT err THEN BEGIN
                ReWriteMemFile(hdr);
                ReWriteMemFile(code);
                ReWriteMemFile(data);
        END;
        err := err OR (NOT ReadRDF(src, hdr, code, data, code_segnum, data_segnum, bss_segnum));

        IF NOT err THEN BEGIN
                FilePosAlign(code, 2);
                FilePosAlign(data, 2);

                code_ofs := 0;
                code_size := FileSize(code);
                data_ofs := code_ofs + code_size;
                data_size := FileSize(data);
                bss_ofs := data_ofs + data_size;

                ReWriteMemFile(new_headers);
                err := err OR (NOT IsOpen(new_headers));
        END;

{ copy bss recs }
        IF NOT err THEN BEGIN
                bss_size := 0;
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_BSS, c) DO BEGIN
                        IF merge_bss THEN
                                GET_BSS(c, bss_size)
                        ELSE RDF_WRITE_REC(new_headers, RREC_BSS, c);
                END;
        END;
{ copy export recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_GLOBAL, c) AND (NOT err) DO BEGIN
                        GET_EXPORT_REC(c, grec);
                        IF grec.seg = data_segnum THEN BEGIN
                                grec.seg := code_segnum;
                                Inc(grec.offset, data_ofs);
                        END ELSE IF merge_bss AND (grec.seg = bss_segnum) THEN BEGIN
                                grec.seg := code_segnum;
                                Inc(grec.offset, bss_ofs);
                        END;
                        SET_EXPORT_REC(grec, c);
                        RDF_WRITE_REC(new_headers, RREC_GLOBAL, c);
                END;
        END;
{ copy import recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_IMPORT, c) AND (NOT err) DO BEGIN
                        GET_IMPORT_REC(c, irec);
                        IF irec.seg = data_segnum THEN BEGIN
                                irec.seg := code_segnum;
                        END;
                        SET_IMPORT_REC(irec, c);
                        RDF_WRITE_REC(new_headers, RREC_IMPORT, c);
                END;
        END;
{ copy relocation recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_RELOC, c) AND (NOT err) DO BEGIN
                        GET_RELOC_REC(c, rec);
                        rec.seg := rec.seg AND $3F;

                        IF rec.seg = code_segnum THEN BEGIN
                                fix := 0;
                                IF rec.rseg = data_segnum THEN
                                        fix := data_ofs
                                ELSE IF merge_bss AND (rec.rseg = bss_segnum) THEN
                                        fix := bss_ofs;
                                IncMem(code, rec.width, rec.offset, fix);
                        END ELSE IF rec.seg = data_segnum THEN BEGIN
                                fix := 0;
                                IF rec.rseg = code_segnum THEN
                                        fix := code_ofs - data_ofs
                                ELSE IF rec.rseg = data_segnum THEN
                                        fix := data_ofs
                                ELSE IF merge_bss AND (rec.rseg = bss_segnum) THEN
                                        fix := bss_ofs - data_ofs;
                                IncMem(data, rec.width, rec.offset, fix);
                                Inc(rec.offset, data_ofs);
                                rec.seg := code_segnum;
                        END;
                        IF (rec.rseg = data_segnum)
                                OR ((rec.rseg = bss_segnum) AND merge_bss)
                                THEN rec.rseg := code_segnum;
                        SET_RELOC_REC(rec, c);
                        RDF_WRITE_REC(new_headers, RREC_RELOC, c);
                END;
                Close(hdr);
        END;
{ copy seg-relocation recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_SEGRELO, c) AND (NOT err) DO BEGIN
                        GET_RELOC_REC(c, rec);
                        IF rec.seg = data_segnum THEN BEGIN
                                IncMem(data, rec.width, rec.offset, -data_ofs);
                                Inc(rec.offset, data_ofs);
                                rec.seg := code_segnum;
                        END;
                        IF (rec.rseg = data_segnum) THEN rec.rseg := code_segnum;
                        IF (rec.rseg = bss_segnum) AND merge_bss THEN rec.rseg := code_segnum;
                        SET_RELOC_REC(rec, c);
                        RDF_WRITE_REC(new_headers, RREC_SEGRELO, c);
                END;
        END;
{ copy DLL recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_DLL, c) AND (NOT err) DO BEGIN
                        RDF_WRITE_REC(new_headers, RREC_DLL, c);
                END;
        END;
{ copy RREC_MODNAME recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_MODNAME, c) AND (NOT err) DO BEGIN
                        RDF_WRITE_REC(new_headers, RREC_MODNAME, c);
                END;
        END;

        IF NOT err THEN BEGIN
                Seek(dst, 0);
                Seek(data, 0);
                Seek(code, FileSize(code));
                BlockCopy(data, code, FileSize(data));
                IF merge_bss THEN WHILE bss_size > 0 DO BEGIN
                                WriteByte(code, 0);
                                Dec(bss_size);
                        END;
                Seek(data, 0);
                Truncate(data);
                WRITE_RDF(new_headers, code_segnum, code, data_segnum, data, dst);
                Truncate(dst);
                Seek(dst, 0);
        END;
        Close(new_headers);
        Close(hdr);
        Close(code);
        Close(data);
        MergeCodeDataBss := err;
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
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_GLOBAL, s) DO BEGIN
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
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.rseg <= r^.bss_segnum THEN CONTINUE;
                        IF FindImportInBuildPlan(r^.linker.import, '', rrec.rseg) THEN CONTINUE;
                        p := FilePos(build_plan.hdr);
                        find := FALSE;
                        Seek(build_plan.hdr, r^.hdr_ofs);
                        WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_IMPORT, s) DO BEGIN
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
                err := NOT IsOpen(i);
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
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
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
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
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
                                fix := import^.export^.rec.offset;
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

END.