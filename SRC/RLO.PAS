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
UNIT rlo;

INTERFACE

USES system2, rdffmt;

CONST
REC_IN_PLAN = 64;
EXP_MAX     = 3000;
IMP_MAX     = 4000;
SYM_PAGE    = 256;
SYM_BUCKETS = 4096;

TYPE
PRDFMETA = ^TRDFMETA;

PNAME = ^RDFNAME;
PFNAME = ^STRING;

TSYM_EXP = RECORD
        flags  : BYTE;
        seg    : BYTE;
        offset : DWORD;
        sym    : WORD;
END;

TSYM_IMP = RECORD
        flags : BYTE;
        seg   : WORD;
        sym   : WORD;
END;

PLINK_EXPORT = ^TLINK_EXPORT;
TLINK_EXPORT = RECORD
        rec   : TSYM_EXP;
        rdf   : PRDFMETA;
        hnext : PLINK_EXPORT;
END;

PSYMNODE = ^TSYMNODE;
TSYMNODE = RECORD
        hash : WORD;
        next : WORD;
        name : PNAME;
        exp  : PLINK_EXPORT;
END;

PSYMPAGE = ^TSYMPAGE;
TSYMPAGE = ARRAY [0..SYM_PAGE - 1] OF TSYMNODE;
PSYMBUCK = ^TSYMBUCK;
TSYMBUCK = ARRAY [0..SYM_BUCKETS - 1] OF WORD;

PEXPORTS = ^TEXPORTS;
TEXPORTS = RECORD
        export_count : WORD;
        cap          : WORD;
        next         : PEXPORTS;
        export       : ARRAY [1..EXP_MAX] OF TLINK_EXPORT;
END;

PLINK_IMPORT = ^TLINK_IMPORT;
TLINK_IMPORT = RECORD
        rec     : TSYM_IMP;
        export  : PLINK_EXPORT;
        ext     : BOOLEAN;
END;

PIMPORTS = ^TIMPORTS;
TIMPORTS = RECORD
        import_count : WORD;
        cap          : WORD;
        next         : PIMPORTS;
        import       : ARRAY [1..IMP_MAX] OF TLINK_IMPORT;
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
        map_seg       : ARRAY [0..2] OF DWORD;
        map_ofs       : ARRAY [0..2] OF DWORD;
END;

TEXTIMPORT = FUNCTION(VAR name : RDFNAME) : BOOLEAN;

TRDFMETA = RECORD
        filename    : PFNAME;
        modname     : PNAME;
        file_code   : DWORD;
        file_data   : DWORD;
        code_size   : DWORD;
        data_size   : DWORD;

        data_segnum : WORD;
        bss_segnum  : WORD;
        code_segnum : WORD;

        seq         : WORD;
        hdr_size    : DWORD;
        hdr_ofs     : DWORD;
        qbimp       : BOOLEAN;
        linker      : TLINKDATA;
        next        : PRDFMETA;
END;

IMAGE_BUILD_PLAN = RECORD
        rdfs        : PRDFMETA;
        hdr         : BFILE;
        linked_out  : BFILE;
END;

CONST
MAP_FLAT = 0;
MAP_SEG  = 1;

VAR
SymPages   : ARRAY [0..255] OF PSYMPAGE;
SymCount   : WORD;
SymBuck    : PSYMBUCK;
ExtImport   : TEXTIMPORT;
ExtImportOn : BOOLEAN;
LayCode    : DWORD;
LayData    : DWORD;
LayBss     : DWORD;
MapKind    : BYTE;
MapBase    : ARRAY [0..2] OF DWORD;
MapImage   : DWORD;
MapSegNo   : ARRAY [0..2] OF LONGINT;
MapDigits  : BYTE;

FUNCTION AlignValue(value : DWORD; align : DWORD) : DWORD;
FUNCTION AllocZero(size : WORD) : POINTER;
FUNCTION NewFileName(VAR s : STRING) : PFNAME;
FUNCTION NewName(VAR name : RDFNAME) : PNAME;
FUNCTION NameHash(VAR name : RDFNAME) : WORD;
FUNCTION SymFind(VAR name : RDFNAME) : WORD;
FUNCTION SymAdd(VAR name : RDFNAME) : WORD;
FUNCTION SymName(id : WORD) : PNAME;
FUNCTION ModLabel(r : PRDFMETA) : STRING;
FUNCTION ReadRDF(VAR src, dst_headers, dst_code, dst_data : BFILE; VAR code_segnum, data_segnum, bss_segnum : WORD) : BOOLEAN;
FUNCTION FindEntryPoint(VAR hdr : BFILE; hdr_size : DWORD; VAR name : RDFNAME; VAR ip : DWORD) : BOOLEAN;
FUNCTION DisableRecs(VAR hdr : BFILE; rtype : CHAR) : BOOLEAN;
FUNCTION DisableRelocsWidth(VAR hdr : BFILE; width : BYTE) : BOOLEAN;
PROCEDURE IncMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
PROCEDURE SetMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
FUNCTION MergeCodeDataBss(VAR src, dst : BFile; merge_bss : BOOLEAN) : BOOLEAN;

FUNCTION FindImportInBuildPlan(import : PIMPORTS; sym : WORD; segnum : WORD) : BOOLEAN;
FUNCTION FindExportRdf(VAR build_plan : IMAGE_BUILD_PLAN; VAR name : RDFNAME) : PLINK_EXPORT;
FUNCTION ResolveImports(VAR build_plan : IMAGE_BUILD_PLAN; rdf : PRDFMETA) : BOOLEAN;
FUNCTION LookupImportByRSeg(r : PRDFMETA; rseg : WORD) : PLINK_IMPORT;
FUNCTION AreaKind(r : PRDFMETA; seg : WORD) : INTEGER;
FUNCTION HmzSegOf(r : PRDFMETA; k : INTEGER) : WORD;
FUNCTION ResolveKind(r : PRDFMETA; rseg : WORD; VAR er : PRDFMETA; VAR k : INTEGER) : BOOLEAN;
PROCEDURE DropFile(VAR f : BFILE);
PROCEDURE AbortGen(VAR o, f1, f2, f3, f4 : BFILE);

FUNCTION CreateBuildPlan(VAR build_plan : IMAGE_BUILD_PLAN; entry_name : RDFNAME) : BOOLEAN;
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

FUNCTION AllocZero(size : WORD) : POINTER;
VAR     p : POINTER;
BEGIN
        IF MaxAvail < size THEN BEGIN
                System.Writeln('Not enough memory.');
                Halt(1);
        END;
        GetMem(p, size);
        FillChar(p^, size, #0);
        AllocZero := p;
END;

FUNCTION NewFileName(VAR s : STRING) : PFNAME;
VAR     p : PFNAME;
BEGIN
        p := PFNAME(AllocZero(Length(s) + 1));
        Move(s, p^, Length(s) + 1);
        NewFileName := p;
END;

FUNCTION NewName(VAR name : RDFNAME) : PNAME;
VAR     p : PNAME;
BEGIN
        p := PNAME(AllocZero(Length(name) + 1));
        Move(name, p^, Length(name) + 1);
        NewName := p;
END;

FUNCTION NameHash(VAR name : RDFNAME) : WORD;
VAR     h : WORD;
        i : INTEGER;
BEGIN
        h := 5381;
        FOR i := 1 TO Length(name) DO h := (h * 33) XOR ORD(name[i]);
        NameHash := h;
END;

FUNCTION SymNode(id : WORD) : PSYMNODE;
BEGIN
        SymNode := @SymPages[id SHR 8]^[id AND (SYM_PAGE - 1)];
END;

FUNCTION SymFind(VAR name : RDFNAME) : WORD;
VAR     h  : WORD;
        id : WORD;
        n  : PSYMNODE;
BEGIN
        SymFind := 0;
        IF SymBuck = NIL THEN EXIT;
        h := NameHash(name);
        id := SymBuck^[h AND (SYM_BUCKETS - 1)];
        WHILE id <> 0 DO BEGIN
                n := SymNode(id);
                IF (n^.hash = h) AND (n^.name^ = name) THEN BEGIN
                        SymFind := id;
                        EXIT;
                END;
                id := n^.next;
        END;
END;

FUNCTION SymAdd(VAR name : RDFNAME) : WORD;
VAR     id : WORD;
        n  : PSYMNODE;
        b  : WORD;
BEGIN
        id := SymFind(name);
        IF id = 0 THEN BEGIN
                IF SymBuck = NIL THEN SymBuck := PSYMBUCK(AllocZero(SizeOf(TSYMBUCK)));
                IF SymCount = $FFFF THEN BEGIN
                        System.Writeln('Too many symbols.');
                        Halt(1);
                END;
                Inc(SymCount);
                id := SymCount;
                IF SymPages[id SHR 8] = NIL THEN SymPages[id SHR 8] := PSYMPAGE(AllocZero(SizeOf(TSYMPAGE)));
                n := SymNode(id);
                n^.hash := NameHash(name);
                n^.name := NewName(name);
                b := n^.hash AND (SYM_BUCKETS - 1);
                n^.next := SymBuck^[b];
                SymBuck^[b] := id;
        END;
        SymAdd := id;
END;

FUNCTION SymName(id : WORD) : PNAME;
BEGIN
        SymName := SymNode(id)^.name;
END;

PROCEDURE SymFree;
VAR     i : WORD;
BEGIN
        FOR i := 1 TO SymCount DO FreeMem(SymNode(i)^.name, Length(SymNode(i)^.name^) + 1);
        FOR i := 0 TO 255 DO IF SymPages[i] <> NIL THEN BEGIN
                FreeMem(SymPages[i], SizeOf(TSYMPAGE));
                SymPages[i] := NIL;
        END;
        IF SymBuck <> NIL THEN FreeMem(SymBuck, SizeOf(TSYMBUCK));
        SymBuck := NIL;
        SymCount := 0;
END;

FUNCTION ModLabel(r : PRDFMETA) : STRING;
BEGIN
        IF r^.modname <> NIL THEN ModLabel := r^.filename^ + '(' + r^.modname^ + ')'
        ELSE ModLabel := r^.filename^;
END;

PROCEDURE HashAdd(e : PLINK_EXPORT);
VAR     n : PSYMNODE;
BEGIN
        n := SymNode(e^.rec.sym);
        e^.hnext := n^.exp;
        n^.exp := e;
END;

PROCEDURE HashRebuild(VAR build_plan : IMAGE_BUILD_PLAN);
VAR     r       : PRDFMETA;
        exports : PEXPORTS;
        i       : INTEGER;
        id      : WORD;
BEGIN
        FOR id := 1 TO SymCount DO SymNode(id)^.exp := NIL;
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                exports := r^.linker.export;
                WHILE exports <> NIL DO BEGIN
                        FOR i := 1 TO exports^.export_count DO HashAdd(@exports^.export[i]);
                        exports := exports^.next;
                END;
                r := r^.next;
        END;
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

FUNCTION FindEntryPoint(VAR hdr : BFILE; hdr_size : DWORD; VAR name : RDFNAME; VAR ip : DWORD) : BOOLEAN;
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
                ReWriteTemp(hdr);
                ReWriteTemp(code);
                ReWriteTemp(data);
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

                ReWriteTemp(new_headers);
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

FUNCTION FindImportInBuildPlan(import : PIMPORTS; sym : WORD; segnum : WORD) : BOOLEAN;
VAR     r : BOOLEAN;
        i : INTEGER;
BEGIN
        r := FALSE;
        WHILE (import <> NIL) AND (NOT r) DO BEGIN
                i := 1;
                WHILE i <= import^.import_count DO BEGIN
                        IF (import^.import[i].rec.seg = segnum)
                                OR ((sym <> 0) AND (import^.import[i].rec.sym = sym)) THEN BEGIN
                                r := TRUE;
                                BREAK;
                        END;
                        Inc(i);
                END;
                import := import^.next;
        END;
        FindImportInBuildPlan := r;
END;

FUNCTION FindExportSym(id : WORD) : PLINK_EXPORT;
VAR     found : PLINK_EXPORT;
        e     : PLINK_EXPORT;
BEGIN
        found := NIL;
        IF id <> 0 THEN e := SymNode(id)^.exp ELSE e := NIL;
        WHILE e <> NIL DO BEGIN
                IF (found = NIL) OR (e^.rdf^.seq > found^.rdf^.seq) THEN found := e;
                e := e^.hnext;
        END;
        FindExportSym := found;
END;

FUNCTION FindExportRdf(VAR build_plan : IMAGE_BUILD_PLAN; VAR name : RDFNAME) : PLINK_EXPORT;
BEGIN
        FindExportRdf := FindExportSym(SymFind(name));
END;

FUNCTION CountExports(id : WORD) : INTEGER;
VAR     n : INTEGER;
        e : PLINK_EXPORT;
BEGIN
        n := 0;
        IF id <> 0 THEN e := SymNode(id)^.exp ELSE e := NIL;
        WHILE e <> NIL DO BEGIN
                Inc(n);
                e := e^.hnext;
        END;
        CountExports := n;
END;

FUNCTION ResolveImports(VAR build_plan : IMAGE_BUILD_PLAN; rdf : PRDFMETA) : BOOLEAN;
VAR     err      : BOOLEAN;
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
                                export := FindExportSym(import^.import[i].rec.sym);
                                import^.import[i].export := export;
                                import^.import[i].ext := FALSE;
                                IF (export = NIL) AND ExtImportOn THEN
                                        import^.import[i].ext := ExtImport(SymName(import^.import[i].rec.sym)^);
                                err := (export = NIL) AND (NOT import^.import[i].ext);
                                IF err THEN BEGIN
                                        System.Writeln('Could not resolve ', SymName(import^.import[i].rec.sym)^);
                                END ELSE IF (export <> NIL)
                                        AND (CountExports(import^.import[i].rec.sym) > 1) THEN BEGIN
                                        System.Writeln('Warning: symbol ', SymName(import^.import[i].rec.sym)^
                                                , ' is defined more than once, using ', ModLabel(export^.rdf));
                                END;
                                IF (NOT err) AND (export <> NIL) AND (NOT export^.rdf^.linker.linked) THEN BEGIN
                                        err := ResolveImports(build_plan, export^.rdf);
                                END;
                                Inc(i);
                        END;
                        import := import^.next;
                END;
        END;
        ResolveImports := err;
END;

FUNCTION ExpChunkSize(n : WORD) : WORD;
BEGIN
        ExpChunkSize := SizeOf(TEXPORTS) - (EXP_MAX - n) * SizeOf(TLINK_EXPORT);
END;

FUNCTION ImpChunkSize(n : WORD) : WORD;
BEGIN
        ImpChunkSize := SizeOf(TIMPORTS) - (IMP_MAX - n) * SizeOf(TLINK_IMPORT);
END;

FUNCTION CountRecs(VAR build_plan : IMAGE_BUILD_PLAN; r : PRDFMETA; rtype : CHAR) : WORD;
VAR     s : STRING;
        n : WORD;
BEGIN
        n := 0;
        Seek(build_plan.hdr, r^.hdr_ofs);
        WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, rtype, s) DO Inc(n);
        CountRecs := n;
END;

FUNCTION CreateBuildPlan(VAR build_plan : IMAGE_BUILD_PLAN; entry_name : RDFNAME) : BOOLEAN;
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
        rtype    : CHAR;
        slot     : PLINK_EXPORT;
        islot    : PLINK_IMPORT;
        entry    : PLINK_EXPORT;
        nexp     : WORD;
        ncap     : WORD;
        nimp     : WORD;
        nfull    : BOOLEAN;
        seq      : WORD;
BEGIN
        err := build_plan.rdfs = NIL;
        startRdf := NIL;
        seq := 0;

        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                Inc(seq);
                r^.seq := seq;
                nexp := CountRecs(build_plan, r, RREC_GLOBAL);
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_GLOBAL, s) DO BEGIN
                        GET_EXPORT_REC(s, grec);
                        nfull := r^.linker.export = NIL;
                        IF NOT nfull THEN nfull := r^.linker.export^.export_count = r^.linker.export^.cap;
                        IF nfull THEN BEGIN
                                IF nexp > EXP_MAX THEN ncap := EXP_MAX ELSE ncap := nexp;
                                export := PEXPORTS(AllocZero(ExpChunkSize(ncap)));
                                export^.cap := ncap;
                                export^.next := r^.linker.export;
                                r^.linker.export := export;
                        END;
                        Inc(r^.linker.export^.export_count);
                        slot := @r^.linker.export^.export[r^.linker.export^.export_count];
                        slot^.rec.flags := grec.flags;
                        slot^.rec.seg := grec.seg;
                        slot^.rec.offset := grec.offset;
                        slot^.rec.sym := SymAdd(grec.name);
                        slot^.rdf := r;
                        HashAdd(slot);
                        Dec(nexp);
                END;
                r := r^.next;
        END;
        entry := FindExportRdf(build_plan, entry_name);
        IF entry = NIL THEN System.Writeln('Entry point ', entry_name, ' not found.')
        ELSE IF entry^.rec.seg <> entry^.rdf^.code_segnum THEN BEGIN
                System.Writeln('Entry point ', entry_name, ' is not in the code segment.');
                entry := NIL;
        END;
        err := err OR (entry = NIL);
        IF entry <> NIL THEN startRdf := entry^.rdf;

        { build import tables }
        r := build_plan.rdfs;
        WHILE (NOT err) AND (r <> NIL) DO BEGIN
                rtype := RREC_RELOC;
                REPEAT
                        Seek(build_plan.hdr, r^.hdr_ofs);
                        WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, rtype, s) DO BEGIN
                                GET_RELOC_REC(s, rrec);
                                IF rrec.rseg <= r^.bss_segnum THEN CONTINUE;
                                IF FindImportInBuildPlan(r^.linker.import, 0, rrec.rseg) THEN CONTINUE;
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
                                        CONTINUE;
                                END;
                                nfull := r^.linker.import = NIL;
                                IF NOT nfull THEN nfull := r^.linker.import^.import_count = r^.linker.import^.cap;
                                IF nfull THEN BEGIN
                                        nimp := CountRecs(build_plan, r, RREC_IMPORT);
                                        IF nimp > IMP_MAX THEN nimp := IMP_MAX;
                                        import := PIMPORTS(AllocZero(ImpChunkSize(nimp)));
                                        import^.cap := nimp;
                                        import^.next := r^.linker.import;
                                        r^.linker.import := import;
                                END;
                                Inc(r^.linker.import^.import_count);
                                islot := @r^.linker.import^.import[r^.linker.import^.import_count];
                                islot^.rec.flags := irec.flags;
                                islot^.rec.seg := irec.seg;
                                islot^.rec.sym := SymAdd(irec.name);
                                Seek(build_plan.hdr, p);
                        END;
                        IF rtype = RREC_RELOC THEN rtype := RREC_SEGRELO ELSE rtype := #0;
                UNTIL rtype = #0;
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

FUNCTION AreaKind(r : PRDFMETA; seg : WORD) : INTEGER;
BEGIN
        IF seg = r^.code_segnum THEN AreaKind := 0
        ELSE IF seg = r^.data_segnum THEN AreaKind := 1
        ELSE IF seg = r^.bss_segnum THEN AreaKind := 2
        ELSE AreaKind := 3;
END;

FUNCTION HmzSegOf(r : PRDFMETA; k : INTEGER) : WORD;
BEGIN
        CASE k OF
        0 : HmzSegOf := r^.linker.hmz_code_seg;
        1 : HmzSegOf := r^.linker.hmz_data_seg;
        2 : HmzSegOf := r^.linker.hmz_bss_seg;
        ELSE HmzSegOf := 0;
        END;
END;

FUNCTION ResolveKind(r : PRDFMETA; rseg : WORD; VAR er : PRDFMETA; VAR k : INTEGER) : BOOLEAN;
VAR     import : PLINK_IMPORT;
BEGIN
        er := r;
        k := AreaKind(r, rseg);
        ResolveKind := TRUE;
        IF k <= 2 THEN EXIT;
        import := LookupImportByRSeg(r, rseg);
        IF (import = NIL) OR (import^.export = NIL) THEN BEGIN
                System.Writeln(r^.filename^, ': unresolved import.');
                ResolveKind := FALSE;
                EXIT;
        END;
        er := import^.export^.rdf;
        k := AreaKind(er, import^.export^.rec.seg);
END;

PROCEDURE DropFile(VAR f : BFILE);
BEGIN
        IF IsOpen(f) THEN Close(f);
END;

PROCEDURE AbortGen(VAR o, f1, f2, f3, f4 : BFILE);
BEGIN
        IF IsOpen(o) THEN BEGIN
                SetDeleteOnClose(o, TRUE);
                Close(o);
        END;
        DropFile(f1);
        DropFile(f2);
        DropFile(f3);
        DropFile(f4);
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
        err := NOT (IsOpen(code) AND IsOpen(data) AND IsOpen(new_headers));

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
                WHILE (FilePos(code) AND 15) <> 0 DO WriteByte(code, $90);

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
                                grec.flags := exports^.export[p].rec.flags;
                                grec.seg := exports^.export[p].rec.seg;
                                grec.offset := exports^.export[p].rec.offset;
                                grec.name := SymName(exports^.export[p].rec.sym)^;
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
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
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
                                tk := 0;
                                IF NOT selfr THEN Inc(fix, r^.linker.smz_code_ofs);
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                tk := 1;
                                IF NOT selfr THEN Inc(fix, r^.linker.smz_data_ofs);
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                tk := 2;
                                IF NOT selfr THEN Inc(fix, r^.linker.smz_bss_ofs);
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF (import = NIL) OR (import^.export = NIL) THEN BEGIN
                                        System.Writeln(r^.filename^, ': unresolved import.');
                                        err := TRUE;
                                        BREAK;
                                END;
                                IF import^.export^.rec.seg <= 2 THEN tk := import^.export^.rec.seg;
                                IF import^.export^.rec.seg = code_segnum THEN BEGIN
                                        rrec.rseg := code_segnum;
                                        IF selfr THEN fix := -r^.linker.smz_code_ofs;
                                END ELSE IF import^.export^.rec.seg = data_segnum THEN BEGIN
                                        rrec.rseg := data_segnum;
                                        IF selfr THEN fix := -r^.linker.smz_data_ofs;
                                END ELSE IF import^.export^.rec.seg = bss_segnum THEN BEGIN
                                        rrec.rseg := bss_segnum;
                                        IF selfr THEN fix := -r^.linker.smz_bss_ofs;
                                END;
                                Inc(fix, import^.export^.rec.offset);
                        END;
                        IF selfr AND (lk <> tk) THEN BEGIN
                                System.Writeln(r^.filename^, ': near relative reference to another segment.');
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
                WRITE_RDF(new_headers, code_segnum, code, data_segnum, data, build_plan.linked_out);
        END;
        Close(new_headers);
        Close(code);
        Close(data);
        LinkSmallModel := err;
END;

PROCEDURE FreeMeta(r : PRDFMETA);
VAR     export   : PEXPORTS;
        import   : PIMPORTS;
BEGIN
        WHILE r^.linker.export <> NIL DO BEGIN
                export := r^.linker.export;
                r^.linker.export := r^.linker.export^.next;
                FreeMem(export, ExpChunkSize(export^.cap));
        END;
        WHILE r^.linker.import <> NIL DO BEGIN
                import := r^.linker.import;
                r^.linker.import := r^.linker.import^.next;
                FreeMem(import, ImpChunkSize(import^.cap));
        END;
        IF r^.modname <> NIL THEN FreeMem(r^.modname, Length(r^.modname^) + 1);
        FreeMem(r, SizeOf(TRDFMETA));
END;

PROCEDURE FreeOutOfPlan(VAR build_plan : IMAGE_BUILD_PLAN);
VAR     r        : PRDFMETA;
        prev     : PRDFMETA;
        nxt      : PRDFMETA;
BEGIN
        prev := NIL;
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                nxt := r^.next;
                IF NOT r^.linker.linked THEN BEGIN
                        IF prev = NIL THEN build_plan.rdfs := nxt ELSE prev^.next := nxt;
                        FreeMeta(r);
                END ELSE prev := r;
                r := nxt;
        END;
        HashRebuild(build_plan);
END;

PROCEDURE DestroyPlan(VAR build_plan : IMAGE_BUILD_PLAN);
VAR     r        : PRDFMETA;
BEGIN
        WHILE build_plan.rdfs <> NIL DO BEGIN
                r := build_plan.rdfs;
                build_plan.rdfs := build_plan.rdfs^.next;
                FreeMeta(r);
        END;
        SymFree;
        Close(build_plan.hdr);
END;

BEGIN
        ExtImportOn := FALSE;
        LayCode := 0;
        LayData := 0;
        LayBss := 0;
        MapKind := MAP_FLAT;
        FillChar(MapBase, SizeOf(MapBase), #0);
        MapImage := 0;
        MapSegNo[0] := -1;
        MapSegNo[1] := -1;
        MapSegNo[2] := -1;
        MapDigits := 8;
END.
