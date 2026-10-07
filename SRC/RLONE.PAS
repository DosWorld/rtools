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
UNIT rlone;

INTERFACE

USES system2, rdffmt, rlo, rlodef;

FUNCTION NeSetup(def_file : STRING) : BOOLEAN;

FUNCTION LinkAndGenNE(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname   : STRING;
        stack_size : LONGINT;
        res_name   : STRING) : BOOLEAN;

IMPLEMENTATION

USES exe;

CONST
MAX_SEGS     = 250;
MAX_RELOCS   = 8000;
MAX_IMPN     = 160;
MAX_MODS     = 16;
MAX_RES      = 200;
SECTOR_SHIFT = 8;
SECTOR_SIZE  = 256;
KIND_CODE    = 0;
KIND_DATA    = 1;
KIND_BSS     = 2;


TYPE
TSEGINFO = RECORD
        r        : PRDFMETA;
        kind     : BYTE;
        blob_ofs : DWORD;
        len      : DWORD;
        alloc    : DWORD;
        rel_ofs  : DWORD;
        rel_cnt  : WORD;
        sector   : DWORD;
        has_ovr  : BOOLEAN;
        attr_ovr : WORD;
END;

PSEGARR = ^TSEGARR;
TSEGARR = ARRAY [1..MAX_SEGS + 1] OF TSEGINFO;

TRESREC = RECORD
        tstr_on  : BOOLEAN;
        nstr_on  : BOOLEAN;
        tid      : WORD;
        nid      : WORD;
        tstr     : STRING[32];
        nstr     : STRING[32];
        tval     : WORD;
        nval     : WORD;
        flags    : WORD;
        size     : DWORD;
        pos      : DWORD;
        fpos     : DWORD;
END;

PRESARR = ^TRESARR;
TRESARR = ARRAY [1..MAX_RES] OF TRESREC;

PORDARR = ^TORDARR;
TORDARR = ARRAY [1..MAX_RES] OF INTEGER;

TSTRREC = RECORD
        s        : STRING[32];
        ofs      : WORD;
END;

PSTRARR = ^TSTRARR;
TSTRARR = ARRAY [1..MAX_RES * 2] OF TSTRREC;

PENTBUF = ^TENTBUF;
TENTBUF = ARRAY [0..8191] OF BYTE;

PRELARR = ^TRELARR;
TRELARR = ARRAY [0..MAX_RELOCS - 1] OF NE_RELOC;

VAR
segs      : PSEGARR;
rl        : PRELARR;
rn        : INTEGER;
nseg      : INTEGER;
dgroup    : INTEGER;
blob      : BFILE;
relf      : BFILE;
ext_mods  : ARRAY [1..MAX_MODS] OF STRING[32];
ext_ofs   : ARRAY [1..MAX_MODS] OF WORD;
ext_count : INTEGER;
imp_tab   : ARRAY [1..MAX_IMPN] OF STRING[64];
imp_tofs  : ARRAY [1..MAX_IMPN] OF WORD;
imp_tcnt  : INTEGER;
imp_size  : WORD;
ress      : PRESARR;
res_count : INTEGER;
res_types : INTEGER;
res_tsize : WORD;
order     : PORDARR;
strs      : PSTRARR;
str_count : INTEGER;
str_size  : WORD;
entbuf    : PENTBUF;
res_file  : BFILE;
res_open  : BOOLEAN;

FUNCTION AddImpName(s : STRING) : WORD;
VAR     i : INTEGER;
BEGIN
        FOR i := 1 TO imp_tcnt DO IF imp_tab[i] = s THEN BEGIN
                AddImpName := imp_tofs[i];
                EXIT;
        END;
        IF imp_tcnt >= MAX_IMPN THEN BEGIN
                AddImpName := 0;
                EXIT;
        END;
        Inc(imp_tcnt);
        imp_tab[imp_tcnt] := s;
        imp_tofs[imp_tcnt] := imp_size;
        AddImpName := imp_size;
        Inc(imp_size, 1 + Length(s));
END;

FUNCTION ParseExt(VAR name : RDFNAME; VAR modname : STRING; VAR ordnum : WORD; VAR procname : STRING) : BOOLEAN;
BEGIN
        ParseExt := FALSE;
        procname := '';
        IF FindDefImport(name, modname, ordnum, procname) THEN BEGIN
                ParseExt := TRUE;
                EXIT;
        END;
        IF UpStr(name) = 'KERNEL_INITTASK' THEN BEGIN
                modname := 'KERNEL';
                ordnum := 91;
                ParseExt := TRUE;
        END;
END;

{$F+}
FUNCTION NeIsExt(VAR name : RDFNAME) : BOOLEAN;
VAR     m : STRING;
        o : WORD;
        p : STRING;
BEGIN
        NeIsExt := ParseExt(name, m, o, p);
END;
{$F-}

FUNCTION ModIndex(VAR m : STRING) : INTEGER;
VAR     i : INTEGER;
BEGIN
        ModIndex := 0;
        FOR i := 1 TO ext_count DO IF ext_mods[i] = m THEN BEGIN
                ModIndex := i;
                EXIT;
        END;
        IF ext_count < MAX_MODS THEN BEGIN
                Inc(ext_count);
                ext_mods[ext_count] := m;
                ext_ofs[ext_count] := AddImpName(m);
                ModIndex := ext_count;
        END;
END;

FUNCTION ResolveRef(r : PRDFMETA; rseg : WORD
        ; VAR tidx, tbase : WORD
        ; VAR ext : BOOLEAN; VAR eflag : BYTE; VAR emod, eord : WORD) : BOOLEAN;
VAR     imp : PLINK_IMPORT;
        er  : PRDFMETA;
        mn  : STRING;
        pn  : STRING;
        k   : INTEGER;
BEGIN
        ResolveRef := FALSE;
        ext := FALSE;
        tidx := 0;
        tbase := 0;
        IF rseg = r^.code_segnum THEN BEGIN
                tidx := r^.linker.hmz_code_seg;
        END ELSE IF rseg = r^.data_segnum THEN BEGIN
                tidx := r^.linker.hmz_data_seg;
        END ELSE IF rseg = r^.bss_segnum THEN BEGIN
                tidx := dgroup;
                tbase := r^.linker.hmz_bss_seg;
        END ELSE BEGIN
                imp := LookupImportByRSeg(r, rseg);
                IF imp = NIL THEN BEGIN
                        System.Writeln(r^.filename, ': relocation to unknown import.');
                        EXIT;
                END;
                IF imp^.ext THEN BEGIN
                        IF NOT ParseExt(imp^.rec.name, mn, eord, pn) THEN EXIT;
                        k := ModIndex(mn);
                        IF k = 0 THEN BEGIN
                                System.Writeln('Too many imported modules.');
                                EXIT;
                        END;
                        emod := k;
                        IF Length(pn) = 0 THEN eflag := NE_REL_ORDINAL
                        ELSE BEGIN
                                eflag := NE_REL_NAME;
                                eord := AddImpName(pn);
                                IF eord = 0 THEN BEGIN
                                        System.Writeln('Too many imported names.');
                                        EXIT;
                                END;
                        END;
                        ext := TRUE;
                        ResolveRef := TRUE;
                        EXIT;
                END;
                er := imp^.export^.rdf;
                tbase := imp^.export^.rec.offset;
                IF imp^.export^.rec.seg = er^.code_segnum THEN BEGIN
                        tidx := er^.linker.hmz_code_seg;
                END ELSE IF imp^.export^.rec.seg = er^.data_segnum THEN BEGIN
                        tidx := er^.linker.hmz_data_seg;
                END ELSE IF imp^.export^.rec.seg = er^.bss_segnum THEN BEGIN
                        tidx := dgroup;
                        Inc(tbase, er^.linker.hmz_bss_seg);
                END;
        END;
        IF tidx = 0 THEN BEGIN
                System.Writeln(r^.filename, ': relocation to empty segment.');
                EXIT;
        END;
        ResolveRef := TRUE;
END;

FUNCTION AddRel(rt, fl : BYTE; ofs, tseg, tofs : WORD) : BOOLEAN;
BEGIN
        AddRel := FALSE;
        IF rn >= MAX_RELOCS THEN BEGIN
                System.Writeln('Too many relocations in one segment.');
                EXIT;
        END;
        rl^[rn].rtype := rt;
        rl^[rn].flags := fl;
        rl^[rn].ofs := ofs;
        rl^[rn].tseg := tseg;
        rl^[rn].tofs := tofs;
        Inc(rn);
        AddRel := TRUE;
END;

FUNCTION FindOffsAt(ofs : WORD) : INTEGER;
VAR     i : INTEGER;
BEGIN
        FindOffsAt := -1;
        i := rn - 1;
        WHILE i >= 0 DO BEGIN
                IF (rl^[i].ofs = ofs) AND (rl^[i].rtype = NE_REL_OFFS) THEN BEGIN
                        FindOffsAt := i;
                        EXIT;
                END;
                Dec(i);
        END;
END;

FUNCTION ProcessSegment(VAR build_plan : IMAGE_BUILD_PLAN; si : INTEGER) : BOOLEAN;
VAR     r        : PRDFMETA;
        psn      : WORD;
        rtype    : CHAR;
        s        : STRING;
        rrec     : RRELOC_REC;
        rel      : BOOLEAN;
        base     : DWORD;
        w, nw    : WORD;
        tidx     : WORD;
        tbase    : WORD;
        ext      : BOOLEAN;
        eflag    : BYTE;
        emod     : WORD;
        eord     : WORD;
        k        : INTEGER;
        pass     : INTEGER;
        err      : BOOLEAN;
BEGIN
        err := FALSE;
        r := segs^[si].r;
        IF segs^[si].kind = KIND_CODE THEN psn := r^.code_segnum ELSE psn := r^.data_segnum;
        base := segs^[si].blob_ofs;
        rn := 0;
        FOR pass := 0 TO 1 DO BEGIN
                IF pass = 0 THEN rtype := RREC_RELOC ELSE rtype := RREC_SEGRELO;
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, rtype, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        rel := (rrec.seg AND $40) <> 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.seg <> psn THEN CONTINUE;
                        IF rrec.width <> RWIDTH16 THEN BEGIN
                                System.Writeln(r^.filename, ': only 16-bit relocations are supported in NE.');
                                err := TRUE;
                                BREAK;
                        END;
                        IF rrec.offset + 2 > segs^[si].len THEN BEGIN
                                System.Writeln(r^.filename, ': relocation is outside of segment.');
                                err := TRUE;
                                BREAK;
                        END;
                        IF NOT ResolveRef(r, rrec.rseg, tidx, tbase, ext, eflag, emod, eord) THEN BEGIN
                                err := TRUE;
                                BREAK;
                        END;
                        w := GetWord(blob, base + rrec.offset);
                        IF pass = 0 THEN BEGIN
                                IF rel THEN BEGIN
                                        IF ext OR (tidx <> si) THEN BEGIN
                                                System.Writeln(r^.filename
                                                        , ': near relative reference to another segment.');
                                                err := TRUE;
                                        END ELSE IF rrec.rseg <> psn THEN BEGIN
                                                nw := w + tbase;
                                                SetWord(blob, base + rrec.offset, nw);
                                        END;
                                END ELSE IF ext THEN BEGIN
                                        SetWord(blob, base + rrec.offset, $FFFF);
                                        err := NOT AddRel(NE_REL_OFFS, eflag, rrec.offset, emod, eord);
                                END ELSE BEGIN
                                        nw := w + tbase;
                                        SetWord(blob, base + rrec.offset, $FFFF);
                                        err := NOT AddRel(NE_REL_OFFS, NE_REL_INTERNAL, rrec.offset, tidx, nw);
                                END;
                        END ELSE BEGIN
                                IF rel THEN BEGIN
                                        System.Writeln(r^.filename, ': relative segment reference.');
                                        err := TRUE;
                                        BREAK;
                                END;
                                k := -1;
                                IF rrec.offset >= 2 THEN k := FindOffsAt(rrec.offset - 2);
                                IF ext THEN BEGIN
                                        IF (k < 0) OR (rl^[k].flags <> eflag)
                                                OR (rl^[k].tseg <> emod) OR (rl^[k].tofs <> eord) THEN BEGIN
                                                System.Writeln(r^.filename
                                                        , ': segment of imported symbol is not supported.');
                                                err := TRUE;
                                                BREAK;
                                        END;
                                        rl^[k].rtype := NE_REL_PTR;
                                        SetWord(blob, base + rrec.offset, 0);
                                END ELSE IF (k >= 0) AND (rl^[k].flags = NE_REL_INTERNAL)
                                        AND (rl^[k].tseg = tidx) THEN BEGIN
                                        rl^[k].rtype := NE_REL_PTR;
                                        SetWord(blob, base + rrec.offset, 0);
                                END ELSE BEGIN
                                        SetWord(blob, base + rrec.offset, $FFFF);
                                        err := NOT AddRel(NE_REL_BASE, NE_REL_INTERNAL, rrec.offset, tidx, 0);
                                END;
                        END;
                END;
        END;
        IF NOT err THEN BEGIN
                segs^[si].rel_ofs := FilePos(relf);
                segs^[si].rel_cnt := rn;
                IF rn > 0 THEN BlockWrite(relf, rl^, rn * SizeOf(NE_RELOC));
        END;
        ProcessSegment := NOT err;
END;


PROCEDURE WriteCountedName(VAR o : BFILE; s : STRING);
VAR     i : INTEGER;
BEGIN
        WriteByte(o, Length(s));
        FOR i := 1 TO Length(s) DO WriteByte(o, ORD(s[i]));
END;

FUNCTION SegAttr(VAR sg : TSEGINFO) : WORD;
VAR     a : WORD;
BEGIN
        IF sg.has_ovr THEN a := sg.attr_ovr
        ELSE IF sg.kind = KIND_CODE THEN a := code_attr
        ELSE a := data_attr;
        IF sg.rel_cnt > 0 THEN a := a OR NE_SEG_HASRELOC;
        SegAttr := a;
END;

FUNCTION NeSetup(def_file : STRING) : BOOLEAN;
BEGIN
        DefInit;
        ext_count := 0;
        imp_tcnt := 0;
        imp_size := 1;
        ExtImport := NeIsExt;
        ExtImportOn := TRUE;
        NeSetup := FALSE;
        IF Length(def_file) > 0 THEN NeSetup := ParseDef(def_file);
END;

FUNCTION FindByOrd(o : WORD) : INTEGER;
VAR     i : INTEGER;
BEGIN
        FindByOrd := 0;
        FOR i := 1 TO exp_count DO IF exps^[i].ordinal = o THEN BEGIN
                FindByOrd := i;
                EXIT;
        END;
END;

FUNCTION ResolveExports(VAR build_plan : IMAGE_BUILD_PLAN) : BOOLEAN;
VAR     i, j : INTEGER;
        e    : PLINK_EXPORT;
        o    : WORD;
BEGIN
        ResolveExports := TRUE;
        FOR i := 1 TO exp_count DO BEGIN
                e := FindExportRdf(build_plan, exps^[i].sym);
                IF e = NIL THEN BEGIN
                        System.Writeln('Exported symbol ', exps^[i].sym, ' not found.');
                        EXIT;
                END;
                IF (e^.rec.seg <> e^.rdf^.code_segnum) OR (e^.rdf^.linker.hmz_code_seg = 0) THEN BEGIN
                        System.Writeln('Exported symbol ', exps^[i].sym, ' is not in code segment.');
                        EXIT;
                END;
                exps^[i].seg := e^.rdf^.linker.hmz_code_seg;
                exps^[i].ofs := e^.rec.offset;
                FOR j := 1 TO i - 1 DO IF exps^[j].name = exps^[i].name THEN BEGIN
                        System.Writeln('Duplicate export ', exps^[i].name, '.');
                        EXIT;
                END;
                IF (exps^[i].ordinal <> 0) AND (FindByOrd(exps^[i].ordinal) <> i) THEN BEGIN
                        System.Writeln('Duplicate ordinal ', exps^[i].ordinal, '.');
                        EXIT;
                END;
        END;
        o := 1;
        FOR i := 1 TO exp_count DO IF exps^[i].ordinal = 0 THEN BEGIN
                WHILE FindByOrd(o) <> 0 DO Inc(o);
                IF o > MAX_ORD THEN BEGIN
                        System.Writeln('Too many exports.');
                        EXIT;
                END;
                exps^[i].ordinal := o;
        END;
        ResolveExports := FALSE;
END;

FUNCTION BuildEntries(single : BOOLEAN; VAR movcnt : WORD) : WORD;
VAR     pos, h, n, k : INTEGER;
        o, maxo      : WORD;
        fl           : BYTE;
BEGIN
        maxo := 0;
        FOR k := 1 TO exp_count DO IF exps^[k].ordinal > maxo THEN maxo := exps^[k].ordinal;
        pos := 0;
        movcnt := 0;
        o := 1;
        WHILE o <= maxo DO BEGIN
                IF FindByOrd(o) = 0 THEN BEGIN
                        n := 0;
                        WHILE (o + n <= maxo) AND (n < 255) AND (FindByOrd(o + n) = 0) DO Inc(n);
                        entbuf^[pos] := n;
                        entbuf^[pos + 1] := 0;
                        Inc(pos, 2);
                END ELSE BEGIN
                        h := pos;
                        Inc(pos, 2);
                        n := 0;
                        WHILE (o + n <= maxo) AND (n < 255) AND (FindByOrd(o + n) <> 0) DO BEGIN
                                k := FindByOrd(o + n);
                                fl := NE_ENT_EXPORTED;
                                IF single AND (NOT exps^[k].nodata) THEN fl := fl OR NE_ENT_SINGLE;
                                fl := fl OR (exps^[k].parms SHL 3);
                                entbuf^[pos] := fl;
                                entbuf^[pos + 1] := $CD;
                                entbuf^[pos + 2] := $3F;
                                entbuf^[pos + 3] := exps^[k].seg;
                                entbuf^[pos + 4] := exps^[k].ofs AND $FF;
                                entbuf^[pos + 5] := exps^[k].ofs SHR 8;
                                Inc(pos, 6);
                                Inc(n);
                                Inc(movcnt);
                        END;
                        entbuf^[h] := n;
                        entbuf^[h + 1] := $FF;
                END;
                Inc(o, n);
        END;
        entbuf^[pos] := 0;
        BuildEntries := pos + 1;
END;

FUNCTION ReadResId(VAR f : BFILE; VAR isstr : BOOLEAN; VAR id : WORD; VAR str : STRING) : BOOLEAN;
VAR     b : BYTE;
BEGIN
        ReadResId := FALSE;
        b := ReadByte(f);
        IF b = $FF THEN BEGIN
                isstr := FALSE;
                id := ReadWord(f);
        END ELSE BEGIN
                isstr := TRUE;
                str := '';
                WHILE b <> 0 DO BEGIN
                        IF Length(str) >= 32 THEN EXIT;
                        str := str + UpCase(CHR(b));
                        IF Eof(f) THEN EXIT;
                        b := ReadByte(f);
                END;
        END;
        ReadResId := TRUE;
END;

FUNCTION ParseRes(fname : STRING) : BOOLEAN;
VAR     hd   : DWORD;
        sz   : DWORD;
        err  : BOOLEAN;
        ts   : STRING;
        ns   : STRING;
BEGIN
        ParseRes := TRUE;
        Assign(res_file, fname);
        Reset(res_file);
        IF NOT IsOpen(res_file) THEN BEGIN
                System.Writeln('Could not open ', fname, '.');
                EXIT;
        END;
        res_open := TRUE;
        IF FileSize(res_file) >= 8 THEN BEGIN
                hd := ReadDWord(res_file);
                IF (hd = 0) AND (ReadDWord(res_file) = $20) THEN BEGIN
                        System.Writeln(fname, ': 32-bit .RES files are not supported.');
                        EXIT;
                END;
                Seek(res_file, 0);
        END;
        err := FALSE;
        WHILE (NOT err) AND (FilePos(res_file) < FileSize(res_file)) DO BEGIN
                IF res_count >= MAX_RES THEN BEGIN
                        System.Writeln('Too many resources.');
                        EXIT;
                END;
                Inc(res_count);
                FillChar(ress^[res_count], SizeOf(TRESREC), #0);
                IF NOT ReadResId(res_file, ress^[res_count].tstr_on, ress^[res_count].tid, ts) THEN err := TRUE
                ELSE IF NOT ReadResId(res_file, ress^[res_count].nstr_on, ress^[res_count].nid, ns) THEN err := TRUE;
                ress^[res_count].tstr := ts;
                ress^[res_count].nstr := ns;
                IF err THEN BEGIN
                        System.Writeln(fname, ': bad .RES file.');
                        EXIT;
                END;
                ress^[res_count].flags := ReadWord(res_file);
                sz := ReadDWord(res_file);
                ress^[res_count].size := sz;
                ress^[res_count].pos := FilePos(res_file);
                IF (sz > $FF00) OR (FilePos(res_file) + sz > FileSize(res_file)) THEN BEGIN
                        System.Writeln(fname, ': bad .RES file (resource size).');
                        EXIT;
                END;
                Seek(res_file, FilePos(res_file) + sz);
        END;
        ParseRes := FALSE;
END;

FUNCTION SameType(VAR a, b : TRESREC) : BOOLEAN;
BEGIN
        IF a.tstr_on <> b.tstr_on THEN SameType := FALSE
        ELSE IF a.tstr_on THEN SameType := a.tstr = b.tstr
        ELSE SameType := a.tid = b.tid;
END;

FUNCTION StrOfs(s : STRING) : WORD;
VAR     i : INTEGER;
BEGIN
        FOR i := 1 TO str_count DO IF strs^[i].s = s THEN BEGIN
                StrOfs := strs^[i].ofs;
                EXIT;
        END;
        Inc(str_count);
        strs^[str_count].s := s;
        strs^[str_count].ofs := str_size;
        StrOfs := str_size;
        Inc(str_size, 1 + Length(s));
END;

PROCEDURE PrepareRes;
VAR     i, j, n : INTEGER;
        used    : ARRAY [1..MAX_RES] OF BOOLEAN;
        types   : INTEGER;
BEGIN
        FillChar(used, SizeOf(used), #0);
        n := 0;
        types := 0;
        FOR i := 1 TO res_count DO IF NOT used[i] THEN BEGIN
                Inc(types);
                FOR j := i TO res_count DO IF (NOT used[j]) AND SameType(ress^[i], ress^[j]) THEN BEGIN
                        used[j] := TRUE;
                        Inc(n);
                        order^[n] := j;
                END;
        END;
        res_types := types;
        str_count := 0;
        str_size := 0;
        res_tsize := 2 + 2 + (types * 8) + (res_count * 12);
        FOR i := 1 TO res_count DO BEGIN
                IF ress^[i].tstr_on THEN ress^[i].tval := StrOfs(ress^[i].tstr)
                ELSE ress^[i].tval := $8000 OR ress^[i].tid;
                IF ress^[i].nstr_on THEN ress^[i].nval := StrOfs(ress^[i].nstr)
                ELSE ress^[i].nval := $8000 OR ress^[i].nid;
        END;
        res_tsize := res_tsize + str_size + 1;
END;

PROCEDURE WriteResTable(VAR o : BFILE);
VAR     i, j  : INTEGER;
        cnt   : INTEGER;
        base  : WORD;
        k     : INTEGER;
BEGIN
        base := 2 + 2 + (res_types * 8) + (res_count * 12);
        WriteWord(o, SECTOR_SHIFT);
        i := 1;
        WHILE i <= res_count DO BEGIN
                cnt := 1;
                WHILE (i + cnt <= res_count) AND SameType(ress^[order^[i]], ress^[order^[i + cnt]]) DO Inc(cnt);
                k := order^[i];
                IF ress^[k].tstr_on THEN WriteWord(o, base + ress^[k].tval)
                ELSE WriteWord(o, ress^[k].tval);
                WriteWord(o, cnt);
                WriteDWord(o, 0);
                FOR j := i TO i + cnt - 1 DO BEGIN
                        k := order^[j];
                        WriteWord(o, ress^[k].fpos DIV SECTOR_SIZE);
                        WriteWord(o, (ress^[k].size + SECTOR_SIZE - 1) DIV SECTOR_SIZE);
                        WriteWord(o, ress^[k].flags);
                        IF ress^[k].nstr_on THEN WriteWord(o, base + ress^[k].nval)
                        ELSE WriteWord(o, ress^[k].nval);
                        WriteDWord(o, 0);
                END;
                Inc(i, cnt);
        END;
        WriteWord(o, 0);
        FOR i := 1 TO str_count DO WriteCountedName(o, strs^[i].s);
        WriteByte(o, 0);
END;

FUNCTION StemOf(fn : STRING) : STRING;
VAR     p : INTEGER;
BEGIN
        FOR p := Length(fn) DOWNTO 1 DO IF fn[p] IN [':', '\', '/'] THEN BEGIN
                Delete(fn, 1, p);
                BREAK;
        END;
        p := Pos('.', fn);
        IF p > 0 THEN fn[0] := CHR(p - 1);
        StemOf := UpStr(fn);
END;

FUNCTION LinkAndGenNE(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname   : STRING;
        stack_size : LONGINT;
        res_name   : STRING) : BOOLEAN;
VAR     err      : BOOLEAN;
        r        : PRDFMETA;
        i        : BFILE;
        o        : BFILE;
        stubf    : BFILE;
        s        : STRING;
        bss_size : DWORD;
        bss_total: DWORD;
        n, m     : INTEGER;
        start    : PLINK_EXPORT;
        hdr      : NE_HEADER;
        sg       : NE_SEGMENT;
        stem     : STRING;
        nrname   : STRING;
        p        : INTEGER;
        segtab   : WORD;
        restab   : WORD;
        resnames : WORD;
        resident : WORD;
        modref   : WORD;
        impnames : WORD;
        enttab   : WORD;
        entlen   : WORD;
        movcnt   : WORD;
        nonres   : DWORD;
        nrlen    : WORD;
        seg_start: DWORD;
        total    : INTEGER;
        sec      : DWORD;
        mem_ok   : BOOLEAN;
        resbytes : WORD;
        stub_size: DWORD;
        stub_ok  : BOOLEAN;
        dg       : INTEGER;
BEGIN
        err := FALSE;
        mem_ok := FALSE;
        stub_ok := FALSE;
        segs := NIL;
        rl := NIL;
        ress := NIL;
        order := NIL;
        strs := NIL;
        entbuf := NIL;
        nseg := 0;
        res_count := 0;
        res_open := FALSE;
        bss_total := 0;
        stub_size := SizeOf(NE_EXE_STUB);
        FillChar(blob, SizeOf(BFILE), #0);
        FillChar(relf, SizeOf(BFILE), #0);
        FillChar(o, SizeOf(BFILE), #0);
        FillChar(stubf, SizeOf(BFILE), #0);
        FillChar(res_file, SizeOf(BFILE), #0);

        IF (MaxAvail < 150000) THEN BEGIN
                System.Writeln('Not enough memory.');
                LinkAndGenNE := TRUE;
                EXIT;
        END;
        GetMem(segs, SizeOf(TSEGARR));
        GetMem(rl, SizeOf(TRELARR));
        GetMem(ress, SizeOf(TRESARR));
        GetMem(order, SizeOf(TORDARR));
        GetMem(strs, SizeOf(TSTRARR));
        GetMem(entbuf, SizeOf(TENTBUF));
        mem_ok := TRUE;
        FillChar(segs^, SizeOf(TSEGARR), #0);

        IF Length(def_stub) > 0 THEN BEGIN
                Assign(stubf, def_stub);
                Reset(stubf);
                stub_ok := IsOpen(stubf);
                IF stub_ok THEN BEGIN
                        IF (FileSize(stubf) < 64) OR (FileSize(stubf) > $F000) OR (GetWord(stubf, 0) <> MZ_SIGN) THEN BEGIN
                                System.Writeln(def_stub, ': bad STUB file.');
                                err := TRUE;
                        END ELSE stub_size := AlignValue(FileSize(stubf), 16);
                END ELSE BEGIN
                        System.Writeln('Could not open ', def_stub, '.');
                        err := TRUE;
                END;
        END;
        IF (NOT err) AND (Length(res_name) > 0) THEN err := ParseRes(res_name);

        ReWriteTemp(blob);
        ReWriteTemp(relf);
        err := err OR (NOT (IsOpen(blob) AND IsOpen(relf)));

        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                IF (r^.code_size > $FFFF) OR (r^.data_size > $FFFF) THEN BEGIN
                        System.Writeln(r^.filename, ': code or data segment is larger than 64K.');
                        err := TRUE;
                        BREAK;
                END;
                r^.linker.hmz_code_seg := 0;
                r^.linker.hmz_data_seg := 0;
                IF r^.code_size > 0 THEN BEGIN
                        Inc(nseg);
                        IF nseg > MAX_SEGS THEN BEGIN
                                System.Writeln('Too many segments.');
                                err := TRUE;
                                BREAK;
                        END;
                        segs^[nseg].r := r;
                        segs^[nseg].kind := KIND_CODE;
                        segs^[nseg].len := r^.code_size;
                        segs^[nseg].alloc := r^.code_size;
                        r^.linker.hmz_code_seg := nseg;
                END;
                IF r^.data_size > 0 THEN BEGIN
                        Inc(nseg);
                        IF nseg > MAX_SEGS THEN BEGIN
                                System.Writeln('Too many segments.');
                                err := TRUE;
                                BREAK;
                        END;
                        segs^[nseg].r := r;
                        segs^[nseg].kind := KIND_DATA;
                        segs^[nseg].len := r^.data_size;
                        segs^[nseg].alloc := r^.data_size;
                        r^.linker.hmz_data_seg := nseg;
                END;
                Seek(build_plan.hdr, r^.hdr_ofs);
                bss_size := 0;
                WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
                bss_size := AlignValue(bss_size, 2);
                IF bss_total + bss_size > $FFFF THEN BEGIN
                        System.Writeln('bss is too large for NE format.');
                        err := TRUE;
                        BREAK;
                END;
                r^.linker.hmz_bss_seg := bss_total;
                Inc(bss_total, bss_size);
                r := r^.next;
        END;
        IF def_stack >= 0 THEN stack_size := def_stack;
        IF is_dll THEN stack_size := 0;
        IF NOT err THEN BEGIN
                IF nseg = 0 THEN BEGIN
                        System.Writeln('Nothing to link.');
                        err := TRUE;
                END ELSE IF bss_total + stack_size + def_heap + 2 > $FFFF THEN BEGIN
                        System.Writeln('bss, stack and heap are too large for NE format.');
                        err := TRUE;
                END;
        END;
        dgroup := nseg + 1;
        IF NOT err THEN BEGIN
                segs^[dgroup].r := NIL;
                segs^[dgroup].kind := KIND_BSS;
                segs^[dgroup].len := 0;
                segs^[dgroup].alloc := bss_total + stack_size + def_heap;
                IF segs^[dgroup].alloc = 0 THEN segs^[dgroup].alloc := 2;
                FOR n := 1 TO nseg DO FOR m := 1 TO segdef_count DO BEGIN
                        IF (segdefs[m].stem = StemOf(segs^[n].r^.filename))
                                AND (segdefs[m].isdata = (segs^[n].kind = KIND_DATA)) THEN BEGIN
                                segs^[n].has_ovr := TRUE;
                                segs^[n].attr_ovr := segdefs[m].attr;
                        END;
                END;
        END;

        n := 1;
        WHILE (n <= nseg) AND (NOT err) DO BEGIN
                r := segs^[n].r;
                Assign(i, r^.filename);
                Reset(i);
                IF NOT IsOpen(i) THEN BEGIN
                        err := TRUE;
                        BREAK;
                END;
                segs^[n].blob_ofs := FilePos(blob);
                IF segs^[n].kind = KIND_CODE THEN Seek(i, r^.file_code) ELSE Seek(i, r^.file_data);
                BlockCopy(i, blob, segs^[n].len);
                Close(i);
                Inc(n);
        END;

        start := NIL;
        IF NOT err THEN start := FindExportRdf(build_plan, entry_name);
        IF (NOT err) AND (start = NIL) THEN err := TRUE;
        IF (NOT err) AND (start^.rec.seg <> start^.rdf^.code_segnum) THEN BEGIN
                System.Writeln('Entry point ', entry_name, ' is not in code segment.');
                err := TRUE;
        END;

        n := 1;
        WHILE (n <= nseg) AND (NOT err) DO BEGIN
                err := NOT ProcessSegment(build_plan, n);
                Inc(n);
        END;
        IF NOT err THEN err := ResolveExports(build_plan);

        total := nseg + 1;
        stem := StemOf(outfname);
        IF Length(stem) > 8 THEN stem[0] := #8;
        IF Length(stem) = 0 THEN stem := 'A';
        nrname := stem + '.EXE';
        IF Length(def_name) > 0 THEN stem := def_name;
        IF Length(def_descr) > 0 THEN nrname := def_descr;
        dg := def_dgrp;
        IF dg < 0 THEN BEGIN
                IF is_dll THEN dg := 1 ELSE dg := 2;
        END;

        IF NOT err THEN BEGIN
                IF exp_count > 0 THEN entlen := BuildEntries(dg = 1, movcnt)
                ELSE BEGIN
                        FillChar(entbuf^, 4, #0);
                        entlen := 4;
                        movcnt := 0;
                END;
                IF res_count > 0 THEN BEGIN
                        PrepareRes;
                        resbytes := res_tsize;
                END ELSE resbytes := 4;
                segtab := SizeOf(NE_HEADER);
                restab := segtab + (total * SizeOf(NE_SEGMENT));
                resnames := restab + resbytes;
                resident := 1 + Length(stem) + 2 + 1;
                nrlen := 1 + Length(nrname) + 2 + 1;
                FOR p := 1 TO exp_count DO IF NOT exps^[p].noname THEN BEGIN
                        IF exps^[p].resident THEN Inc(resident, 1 + Length(exps^[p].name) + 2)
                        ELSE Inc(nrlen, 1 + Length(exps^[p].name) + 2);
                END;
                modref := resnames + resident;
                impnames := modref + (ext_count * 2);
                enttab := impnames + imp_size;
                nonres := stub_size + enttab + entlen;
                seg_start := AlignValue(nonres + nrlen, SECTOR_SIZE);
                sec := seg_start;
                FOR n := 1 TO nseg DO BEGIN
                        segs^[n].sector := sec;
                        sec := AlignValue(sec + segs^[n].len
                                + segs^[n].rel_cnt * SizeOf(NE_RELOC)
                                + 2 * ORD(segs^[n].rel_cnt > 0), SECTOR_SIZE);
                END;
                FOR n := 1 TO res_count DO BEGIN
                        ress^[order^[n]].fpos := sec;
                        sec := AlignValue(sec + ress^[order^[n]].size, SECTOR_SIZE);
                END;

                FillChar(hdr, SizeOf(NE_HEADER), #0);
                hdr.sign := NE_SIGN;
                hdr.link_major := 6;
                hdr.link_minor := 1;
                hdr.entry_ofs := enttab;
                hdr.entry_len := entlen;
                hdr.prog_flags := dg;
                IF def_prot THEN hdr.prog_flags := hdr.prog_flags OR NE_PROG_PROTMODE;
                IF def_initg THEN hdr.prog_flags := hdr.prog_flags OR NE_PROG_GLOBALINIT;
                hdr.app_flags := def_apptype;
                IF is_dll THEN hdr.app_flags := hdr.app_flags OR NE_APP_DLL;
                hdr.auto_data := dgroup;
                hdr.heap_size := def_heap;
                hdr.ip := start^.rec.offset;
                hdr.cs := start^.rdf^.linker.hmz_code_seg;
                IF is_dll THEN hdr.sp := 0 ELSE hdr.sp := bss_total + stack_size - 2;
                hdr.ss := dgroup;
                hdr.seg_count := total;
                hdr.mod_count := ext_count;
                hdr.nonres_len := nrlen;
                hdr.seg_ofs := segtab;
                hdr.res_ofs := restab;
                hdr.resname_ofs := resnames;
                hdr.modref_ofs := modref;
                hdr.impname_ofs := impnames;
                hdr.nonres_ofs := nonres;
                hdr.mov_entries := movcnt;
                hdr.align_shift := SECTOR_SHIFT;
                IF res_count > 0 THEN hdr.res_count := res_types;
                hdr.target_os := def_os;
                hdr.win_version := def_ver;

                Assign(o, outfname);
                ReWrite(o);
                err := NOT IsOpen(o);
        END;
        IF NOT err THEN BEGIN
                IF stub_ok THEN BEGIN
                        Seek(stubf, 0);
                        BlockCopy(stubf, o, FileSize(stubf));
                        WHILE FilePos(o) < stub_size DO WriteByte(o, 0);
                END ELSE BlockWrite(o, NE_EXE_STUB, SizeOf(NE_EXE_STUB));
                SetDWord(o, $3C, stub_size);
                Seek(o, stub_size);
                BlockWrite(o, hdr, SizeOf(NE_HEADER));
                FOR n := 1 TO total DO BEGIN
                        IF n <= nseg THEN BEGIN
                                sg.sector := segs^[n].sector DIV SECTOR_SIZE;
                                sg.length := segs^[n].len;
                        END ELSE BEGIN
                                sg.sector := 0;
                                sg.length := 0;
                        END;
                        IF n = total THEN sg.attr := data_attr
                        ELSE sg.attr := SegAttr(segs^[n]);
                        sg.alloc := segs^[n].alloc;
                        BlockWrite(o, sg, SizeOf(NE_SEGMENT));
                END;
                IF res_count > 0 THEN WriteResTable(o)
                ELSE BEGIN
                        WriteWord(o, SECTOR_SHIFT);
                        WriteWord(o, 0);
                END;
                WriteCountedName(o, stem);
                WriteWord(o, 0);
                FOR p := 1 TO exp_count DO IF exps^[p].resident AND (NOT exps^[p].noname) THEN BEGIN
                        WriteCountedName(o, exps^[p].name);
                        WriteWord(o, exps^[p].ordinal);
                END;
                WriteByte(o, 0);
                FOR p := 1 TO ext_count DO WriteWord(o, ext_ofs[p]);
                WriteByte(o, 0);
                FOR p := 1 TO imp_tcnt DO WriteCountedName(o, imp_tab[p]);
                BlockWrite(o, entbuf^, entlen);
                WriteCountedName(o, nrname);
                WriteWord(o, 0);
                FOR p := 1 TO exp_count DO IF (NOT exps^[p].resident) AND (NOT exps^[p].noname) THEN BEGIN
                        WriteCountedName(o, exps^[p].name);
                        WriteWord(o, exps^[p].ordinal);
                END;
                WriteByte(o, 0);
                WHILE FilePos(o) < seg_start DO WriteByte(o, 0);
                FOR n := 1 TO nseg DO BEGIN
                        Seek(blob, segs^[n].blob_ofs);
                        BlockCopy(blob, o, segs^[n].len);
                        IF segs^[n].rel_cnt > 0 THEN BEGIN
                                WriteWord(o, segs^[n].rel_cnt);
                                Seek(relf, segs^[n].rel_ofs);
                                BlockCopy(relf, o, segs^[n].rel_cnt * SizeOf(NE_RELOC));
                        END;
                        FilePosAlign(o, SECTOR_SIZE);
                END;
                FOR n := 1 TO res_count DO BEGIN
                        Seek(res_file, ress^[order^[n]].pos);
                        BlockCopy(res_file, o, ress^[order^[n]].size);
                        FilePosAlign(o, SECTOR_SIZE);
                END;
        END;
        IF IsOpen(o) THEN BEGIN
                IF err THEN SetDeleteOnClose(o, TRUE);
                Close(o);
        END;
        IF IsOpen(blob) THEN Close(blob);
        IF IsOpen(relf) THEN Close(relf);
        IF IsOpen(stubf) THEN Close(stubf);
        IF res_open THEN Close(res_file);
        IF mem_ok THEN BEGIN
                FreeMem(segs, SizeOf(TSEGARR));
                FreeMem(rl, SizeOf(TRELARR));
                FreeMem(ress, SizeOf(TRESARR));
                FreeMem(order, SizeOf(TORDARR));
                FreeMem(strs, SizeOf(TSTRARR));
                FreeMem(entbuf, SizeOf(TENTBUF));
        END;
        DefDone;
        LinkAndGenNE := err;
END;

END.
