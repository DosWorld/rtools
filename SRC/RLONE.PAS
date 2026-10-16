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

USES exe, rstore;

CONST
MAX_SEGS     = 250;
MAX_RELOCS   = 32766;
MAX_IMPN     = 32766;
MAX_MODS     = 32766;
MAX_RES      = 32766;
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

PSegInfo = ^TSEGINFO;

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

PResInfo = ^TRESREC;



TSTRREC = RECORD
    s        : STRING[32];
    ofs      : WORD;
END;

PStrInfo = ^TSTRREC;



PRelInfo = ^NE_RELOC;
TImpName = RECORD
  s: STRING[64];
  ofs: WORD;
END;
PImpName = ^TImpName;

VAR
segs      : TStore;
rl        : TStore;
rn        : INTEGER;
nseg      : INTEGER;
dgroup    : INTEGER;
blob      : BFILE;
relf      : BFILE;
ext_names : TStore;
ext_count : INTEGER;
imp_names : TStore;
imp_tcnt  : INTEGER;
imp_size  : WORD;
ress      : TStore;
res_count : INTEGER;
res_types : INTEGER;
res_tsize : DWORD;
order     : TStore;
strs      : TStore;
str_count : INTEGER;
str_size  : DWORD;
entbuf    : TStore;
res_file  : BFILE;
res_open  : BOOLEAN;

FUNCTION SegAt(i: INTEGER): PSegInfo;
BEGIN SegAt := PSegInfo(StoreAt(segs, i)); END;
FUNCTION RelAt(i: INTEGER): PRelInfo;
BEGIN RelAt := PRelInfo(StoreAt(rl, i + 1)); END;
FUNCTION ResAt(i: INTEGER): PResInfo;
BEGIN ResAt := PResInfo(StoreAt(ress, i)); END;
FUNCTION OrderAt(i: INTEGER): PStoreInt;
BEGIN OrderAt := PStoreInt(StoreAt(order, i)); END;
FUNCTION StrAt(i: INTEGER): PStrInfo;
BEGIN StrAt := PStrInfo(StoreAt(strs, i)); END;
FUNCTION EntryAt(i: WORD): PStoreByte;
BEGIN EntryAt := PStoreByte(StoreAt(entbuf, i + 1)); END;
FUNCTION ExtNameAt(i: INTEGER): PImpName;
BEGIN ExtNameAt := PImpName(StoreAt(ext_names, i)); END;
FUNCTION ImpNameAt(i: INTEGER): PImpName;
BEGIN ImpNameAt := PImpName(StoreAt(imp_names, i)); END;

FUNCTION AddImpName(s : STRING) : WORD;
VAR     i : INTEGER;
BEGIN
    FOR i := 1 TO imp_tcnt DO IF ImpNameAt(i)^.s = s THEN BEGIN
        AddImpName := ImpNameAt(i)^.ofs;
        EXIT;
    END;
    IF (imp_tcnt >= MAX_IMPN) OR
        (LONGINT(imp_size) + Length(s) + 1 > $FFFF) THEN BEGIN
        AddImpName := 0;
        EXIT;
    END;
    Inc(imp_tcnt);
    ImpNameAt(imp_tcnt)^.s := s;
    ImpNameAt(imp_tcnt)^.ofs := imp_size;
    AddImpName := imp_size;
    Inc(imp_size, 1 + Length(s));
END;

FUNCTION ParseExt(VAR name : RDFNAME; VAR modname : STRING; VAR
    ordnum : WORD; VAR procname : STRING) : BOOLEAN;
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
    FOR i := 1 TO ext_count DO IF ExtNameAt(i)^.s = m THEN BEGIN
        ModIndex := i;
        EXIT;
    END;
    IF ext_count < MAX_MODS THEN BEGIN
        Inc(ext_count);
        ExtNameAt(ext_count)^.s := m;
        ExtNameAt(ext_count)^.ofs := AddImpName(m);
        IF ExtNameAt(ext_count)^.ofs = 0 THEN BEGIN
            Dec(ext_count); EXIT;
        END;
        ModIndex := ext_count;
    END;
END;

FUNCTION ResolveRef(r : PRDFMETA; rseg : WORD
    ; VAR tidx, tbase : WORD
    ; VAR ext : BOOLEAN; VAR eflag : BYTE; VAR emod, eord :
        WORD) : BOOLEAN;
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
            System.Writeln(r^.filename^,
                ': relocation to unknown import.');
            EXIT;
        END;
        IF imp^.ext THEN BEGIN
            IF NOT ParseExt(SymName(imp^.rec.sym)^, mn, eord,
                pn) THEN EXIT;
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
        END ELSE IF imp^.export^.rec.seg = er^.data_segnum THEN
            BEGIN
            tidx := er^.linker.hmz_data_seg;
        END ELSE IF imp^.export^.rec.seg = er^.bss_segnum THEN
            BEGIN
            tidx := dgroup;
            Inc(tbase, er^.linker.hmz_bss_seg);
        END;
    END;
    IF tidx = 0 THEN BEGIN
        System.Writeln(r^.filename^,
            ': relocation to empty segment.');
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
    RelAt(rn)^.rtype := rt;
    RelAt(rn)^.flags := fl;
    RelAt(rn)^.ofs := ofs;
    RelAt(rn)^.tseg := tseg;
    RelAt(rn)^.tofs := tofs;
    Inc(rn);
    AddRel := TRUE;
END;

FUNCTION FindOffsAt(ofs : WORD) : INTEGER;
VAR     i : INTEGER;
BEGIN
    FindOffsAt := -1;
    i := rn - 1;
    WHILE i >= 0 DO BEGIN
        IF (RelAt(i)^.ofs = ofs) AND (RelAt(i)^.rtype =
            NE_REL_OFFS) THEN BEGIN
            FindOffsAt := i;
            EXIT;
        END;
        Dec(i);
    END;
END;

FUNCTION ProcessSegment(VAR build_plan : IMAGE_BUILD_PLAN; si :
    INTEGER) : BOOLEAN;
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
    r := SegAt(si)^.r;
    IF SegAt(si)^.kind = KIND_CODE THEN psn := r^.code_segnum
        ELSE psn := r^.data_segnum;
    base := SegAt(si)^.blob_ofs;
    rn := 0;
    FOR pass := 0 TO 1 DO BEGIN
        IF pass = 0 THEN rtype := RREC_RELOC ELSE rtype :=
            RREC_SEGRELO;
        Seek(build_plan.hdr, r^.hdr_ofs);
        WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr,
            r^.hdr_ofs + r^.hdr_size, rtype, s) DO BEGIN
            GET_RELOC_REC(s, rrec);
            rel := (rrec.seg AND $40) <> 0;
            rrec.seg := rrec.seg AND $3F;
            IF rrec.seg <> psn THEN CONTINUE;
            IF rrec.width <> RWIDTH16 THEN BEGIN
                System.Writeln(r^.filename^,
': only 16-bit relocations are supported in NE.');
                err := TRUE;
                BREAK;
            END;
            IF rrec.offset + 2 > SegAt(si)^.len THEN BEGIN
                System.Writeln(r^.filename^,
                ': relocation is outside of segment.');
                err := TRUE;
                BREAK;
            END;
            IF NOT ResolveRef(r, rrec.rseg, tidx, tbase, ext,
                eflag, emod, eord) THEN BEGIN
                err := TRUE;
                BREAK;
            END;
            w := GetWord(blob, base + rrec.offset);
            IF pass = 0 THEN BEGIN
                IF rel THEN BEGIN
                    IF ext OR (tidx <> si) THEN BEGIN
                        System.Writeln(r^.filename^
                            ,
                ': near relative reference to another segment.');
                        err := TRUE;
                    END ELSE IF rrec.rseg <> psn THEN BEGIN
                        nw := w + tbase;
                        SetWord(blob, base + rrec.offset, nw);
                    END;
                END ELSE IF ext THEN BEGIN
                    SetWord(blob, base + rrec.offset, $FFFF);
                    err := NOT AddRel(NE_REL_OFFS, eflag,
                rrec.offset, emod, eord);
                END ELSE BEGIN
                    nw := w + tbase;
                    SetWord(blob, base + rrec.offset, $FFFF);
                    err := NOT AddRel(NE_REL_OFFS,
                NE_REL_INTERNAL, rrec.offset, tidx, nw);
                END;
            END ELSE BEGIN
                IF rel THEN BEGIN
                    System.Writeln(r^.filename^,
                ': relative segment reference.');
                    err := TRUE;
                    BREAK;
                END;
                k := -1;
                IF rrec.offset >= 2 THEN k := FindOffsAt(
                rrec.offset - 2);
                IF ext THEN BEGIN
                    IF (k < 0) OR (RelAt(k)^.flags <> eflag)
                        OR (RelAt(k)^.tseg <> emod) OR (RelAt(
                k)^.tofs <> eord) THEN BEGIN
                        System.Writeln(r^.filename^
                            ,
': segment of imported symbol is not supported.');
                        err := TRUE;
                        BREAK;
                    END;
                    RelAt(k)^.rtype := NE_REL_PTR;
                    SetWord(blob, base + rrec.offset, 0);
                END ELSE IF (k >= 0) AND (RelAt(k)^.flags =
                NE_REL_INTERNAL)
                    AND (RelAt(k)^.tseg = tidx) THEN BEGIN
                    RelAt(k)^.rtype := NE_REL_PTR;
                    SetWord(blob, base + rrec.offset, 0);
                END ELSE BEGIN
                    SetWord(blob, base + rrec.offset, $FFFF);
                    err := NOT AddRel(NE_REL_BASE,
                NE_REL_INTERNAL, rrec.offset, tidx, 0);
                END;
            END;
        END;
    END;
    IF NOT err THEN BEGIN
        SegAt(si)^.rel_ofs := FilePos(relf);
        SegAt(si)^.rel_cnt := rn;
        IF rn > 0 THEN StoreWrite(rl, relf, rn);
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
    FOR i := 1 TO exp_count DO IF ExpAt(i)^.ordinal = o THEN
        BEGIN
        FindByOrd := i;
        EXIT;
    END;
END;

FUNCTION ResolveExports(VAR build_plan : IMAGE_BUILD_PLAN) :
    BOOLEAN;
VAR     i, j : INTEGER;
    e    : PLINK_EXPORT;
    o    : WORD;
BEGIN
    ResolveExports := TRUE;
    FOR i := 1 TO exp_count DO BEGIN
        e := FindExportRdf(build_plan, ExpAt(i)^.sym);
        IF e = NIL THEN BEGIN
            System.Writeln('Exported symbol ', ExpAt(i)^.sym,
                ' not found.');
            EXIT;
        END;
        IF (e^.rec.seg <> e^.rdf^.code_segnum) OR (
            e^.rdf^.linker.hmz_code_seg = 0) THEN BEGIN
            System.Writeln('Exported symbol ', ExpAt(i)^.sym,
                ' is not in code segment.');
            EXIT;
        END;
        ExpAt(i)^.seg := e^.rdf^.linker.hmz_code_seg;
        ExpAt(i)^.ofs := e^.rec.offset;
        FOR j := 1 TO i - 1 DO IF ExpAt(j)^.name = ExpAt(
            i)^.name THEN BEGIN
            System.Writeln('Duplicate export ', ExpAt(i)^.name,
                '.');
            EXIT;
        END;
        IF (ExpAt(i)^.ordinal <> 0) AND (FindByOrd(ExpAt(
            i)^.ordinal) <> i) THEN BEGIN
            System.Writeln('Duplicate ordinal ', ExpAt(
                i)^.ordinal, '.');
            EXIT;
        END;
    END;
    o := 1;
    FOR i := 1 TO exp_count DO IF ExpAt(i)^.ordinal = 0 THEN
        BEGIN
        WHILE FindByOrd(o) <> 0 DO Inc(o);
        IF o > MAX_ORD THEN BEGIN
            System.Writeln('Too many exports.');
            EXIT;
        END;
        ExpAt(i)^.ordinal := o;
    END;
    ResolveExports := FALSE;
END;

FUNCTION BuildEntries(single : BOOLEAN; VAR movcnt : WORD) :
    WORD;
VAR     pos, h: LONGINT;
    n, k: INTEGER;
    o, maxo      : LONGINT;
    fl           : BYTE;
BEGIN
    maxo := 0;
    FOR k := 1 TO exp_count DO IF ExpAt(k)^.ordinal > maxo THEN
        maxo := ExpAt(k)^.ordinal;
    BuildEntries := 0;
    pos := 0;
    movcnt := 0;
    o := 1;
    WHILE o <= maxo DO BEGIN
        IF pos > $FFF0 THEN BEGIN
            System.Writeln('NE entry table exceeds 64K.'); EXIT;
        END;
        IF FindByOrd(o) = 0 THEN BEGIN
            n := 0;
            WHILE (o + n <= maxo) AND (n < 255) AND (FindByOrd(o
                + n) = 0) DO Inc(n);
            EntryAt(pos)^ := n;
            EntryAt(pos + 1)^ := 0;
            Inc(pos, 2);
        END ELSE BEGIN
            h := pos;
            Inc(pos, 2);
            n := 0;
            WHILE (o + n <= maxo) AND (n < 255) AND (FindByOrd(o
                + n) <> 0) DO BEGIN
                IF pos > $FFF8 THEN BEGIN
                    System.Writeln(
                'NE entry table exceeds 64K.');
                    EXIT;
                END;
                k := FindByOrd(o + n);
                fl := NE_ENT_EXPORTED;
                IF single AND (NOT ExpAt(k)^.nodata) THEN fl :=
                fl OR NE_ENT_SINGLE;
                fl := fl OR (ExpAt(k)^.parms SHL 3);
                EntryAt(pos)^ := fl;
                EntryAt(pos + 1)^ := $CD;
                EntryAt(pos + 2)^ := $3F;
                EntryAt(pos + 3)^ := ExpAt(k)^.seg;
                EntryAt(pos + 4)^ := ExpAt(k)^.ofs AND $FF;
                EntryAt(pos + 5)^ := ExpAt(k)^.ofs SHR 8;
                Inc(pos, 6);
                Inc(n);
                Inc(movcnt);
            END;
            EntryAt(h)^ := n;
            EntryAt(h + 1)^ := $FF;
        END;
        Inc(o, n);
    END;
    EntryAt(pos)^ := 0;
    BuildEntries := pos + 1;
END;

FUNCTION ReadResId(VAR f : BFILE; VAR isstr : BOOLEAN; VAR id :
    WORD; VAR str : STRING) : BOOLEAN;
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
            System.Writeln(fname,
                ': 32-bit .RES files are not supported.');
            EXIT;
        END;
        Seek(res_file, 0);
    END;
    err := FALSE;
    WHILE (NOT err) AND (FilePos(res_file) < FileSize(res_file))
        DO BEGIN
        IF res_count >= MAX_RES THEN BEGIN
            System.Writeln('Too many resources.');
            EXIT;
        END;
        Inc(res_count);
        FillChar(ResAt(res_count)^, SizeOf(TRESREC), #0);
        IF NOT ReadResId(res_file, ResAt(res_count)^.tstr_on,
            ResAt(res_count)^.tid, ts) THEN err := TRUE
        ELSE IF NOT ReadResId(res_file, ResAt(
            res_count)^.nstr_on, ResAt(res_count)^.nid, ns) THEN
            err := TRUE;
        ResAt(res_count)^.tstr := ts;
        ResAt(res_count)^.nstr := ns;
        IF err THEN BEGIN
            System.Writeln(fname, ': bad .RES file.');
            EXIT;
        END;
        IF FileSize(res_file) - FilePos(res_file) < 6 THEN BEGIN
            System.Writeln(fname,
                ': truncated resource header.');
            EXIT;
        END;
        ResAt(res_count)^.flags := ReadWord(res_file);
        sz := ReadDWord(res_file);
        ResAt(res_count)^.size := sz;
        ResAt(res_count)^.pos := FilePos(res_file);
        IF (sz < 0) OR (sz > $FF00) OR
            (sz > FileSize(res_file) - FilePos(res_file)) THEN
                BEGIN
            System.Writeln(fname,
                ': bad .RES file (resource size).');
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
    FOR i := 1 TO str_count DO IF StrAt(i)^.s = s THEN BEGIN
        StrOfs := StrAt(i)^.ofs;
        EXIT;
    END;
    Inc(str_count);
    StrAt(str_count)^.s := s;
    StrAt(str_count)^.ofs := str_size;
    StrOfs := str_size;
    Inc(str_size, 1 + Length(s));
END;

PROCEDURE PrepareRes;
VAR     i, j, n : INTEGER;
    used    : TStore;
    types   : INTEGER;
FUNCTION UsedAt(i: INTEGER): PStoreByte;
BEGIN UsedAt := StoreByte(used, i); END;
BEGIN
    StoreInit(used, 1);
    n := 0;
    types := 0;
    FOR i := 1 TO res_count DO IF (UsedAt(i)^ = 0) THEN BEGIN
        Inc(types);
        FOR j := i TO res_count DO IF ((UsedAt(j)^ = 0)) AND
            SameType(ResAt(i)^, ResAt(j)^) THEN BEGIN
            UsedAt(j)^ := 1;
            Inc(n);
            OrderAt(n)^ := j;
        END;
    END;
    res_types := types;
    str_count := 0;
    str_size := 0;
    res_tsize := 2 + 2 + (LONGINT(types) * 8) + (LONGINT(
        res_count) * 12);
    FOR i := 1 TO res_count DO BEGIN
        IF ResAt(i)^.tstr_on THEN ResAt(i)^.tval := StrOfs(ResAt(
            i)^.tstr)
        ELSE ResAt(i)^.tval := $8000 OR ResAt(i)^.tid;
        IF ResAt(i)^.nstr_on THEN ResAt(i)^.nval := StrOfs(ResAt(
            i)^.nstr)
        ELSE ResAt(i)^.nval := $8000 OR ResAt(i)^.nid;
    END;
    res_tsize := res_tsize + str_size + 1;
StoreFree(used);
END;

PROCEDURE WriteResTable(VAR o : BFILE);
VAR     i, j  : INTEGER;
    cnt   : INTEGER;
    base  : WORD;
    k     : INTEGER;
BEGIN
    base := 2 + 2 + (LONGINT(res_types) * 8)
        + (LONGINT(res_count) * 12);
    WriteWord(o, SECTOR_SHIFT);
    i := 1;
    WHILE i <= res_count DO BEGIN
        cnt := 1;
        WHILE (i + cnt <= res_count) AND SameType(ResAt(OrderAt(
            i)^)^, ResAt(OrderAt(i + cnt)^)^) DO Inc(cnt);
        k := OrderAt(i)^;
        IF ResAt(k)^.tstr_on THEN WriteWord(o, base + ResAt(
            k)^.tval)
        ELSE WriteWord(o, ResAt(k)^.tval);
        WriteWord(o, cnt);
        WriteDWord(o, 0);
        FOR j := i TO i + cnt - 1 DO BEGIN
            k := OrderAt(j)^;
            WriteWord(o, ResAt(k)^.fpos DIV SECTOR_SIZE);
            WriteWord(o, (ResAt(k)^.size + SECTOR_SIZE - 1) DIV
                SECTOR_SIZE);
            WriteWord(o, ResAt(k)^.flags);
            IF ResAt(k)^.nstr_on THEN WriteWord(o, base + ResAt(
                k)^.nval)
            ELSE WriteWord(o, ResAt(k)^.nval);
            WriteDWord(o, 0);
        END;
        Inc(i, cnt);
    END;
    WriteWord(o, 0);
    FOR i := 1 TO str_count DO WriteCountedName(o, StrAt(i)^.s);
    WriteByte(o, 0);
END;

FUNCTION StemOf(fn : STRING) : STRING;
VAR     p : INTEGER;
BEGIN
    FOR p := Length(fn) DOWNTO 1 DO IF fn[p] IN [':', '\', '/']
        THEN BEGIN
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
    segtab   : DWORD;
    restab   : DWORD;
    resnames : DWORD;
    resident : DWORD;
    modref   : DWORD;
    impnames : DWORD;
    enttab   : DWORD;
    entlen   : WORD;
    movcnt   : WORD;
    nonres   : DWORD;
    nrlen    : DWORD;
    seg_start: DWORD;
    total    : INTEGER;
    sec      : DWORD;
    mem_ok   : BOOLEAN;
    resbytes : DWORD;
    stub_size: DWORD;
    stub_ok  : BOOLEAN;
    dg       : INTEGER;
BEGIN
    err := FALSE;
    mem_ok := FALSE;
    stub_ok := FALSE;
    FillChar(segs, SizeOf(segs), 0);
    FillChar(rl, SizeOf(rl), 0);
    FillChar(ress, SizeOf(ress), 0);
    FillChar(order, SizeOf(order), 0);
    FillChar(strs, SizeOf(strs), 0);
    FillChar(entbuf, SizeOf(entbuf), 0);
    nseg := 0;
    res_count := 0;
    str_count := 0;
    res_open := FALSE;
    bss_total := 0;
    stub_size := SizeOf(NE_EXE_STUB);
    FillChar(blob, SizeOf(BFILE), #0);
    FillChar(relf, SizeOf(BFILE), #0);
    FillChar(o, SizeOf(BFILE), #0);
    FillChar(stubf, SizeOf(BFILE), #0);
    FillChar(res_file, SizeOf(BFILE), #0);

    StoreInit(segs, SizeOf(TSEGINFO));
    StoreInit(rl, SizeOf(NE_RELOC));
    StoreInit(ress, SizeOf(TRESREC));
    StoreInit(order, SizeOf(INTEGER));
    StoreInit(strs, SizeOf(TSTRREC));
    StoreInit(entbuf, SizeOf(BYTE));
    mem_ok := TRUE;
    StoreInit(ext_names, SizeOf(TImpName));
    StoreInit(imp_names, SizeOf(TImpName));

    IF Length(def_stub) > 0 THEN BEGIN
        Assign(stubf, def_stub);
        Reset(stubf);
        stub_ok := IsOpen(stubf);
        IF stub_ok THEN BEGIN
            IF (FileSize(stubf) < 64) OR (FileSize(stubf) >
                $F000) OR (GetWord(stubf, 0) <> MZ_SIGN) THEN
                BEGIN
                System.Writeln(def_stub, ': bad STUB file.');
                err := TRUE;
            END ELSE stub_size := AlignValue(FileSize(stubf),
                16);
        END ELSE BEGIN
            System.Writeln('Could not open ', def_stub, '.');
            err := TRUE;
        END;
    END;
    IF (NOT err) AND (Length(res_name) > 0) THEN err := ParseRes(
        res_name);

    ReWriteTemp(blob);
    ReWriteTemp(relf);
    err := err OR (NOT (IsOpen(blob) AND IsOpen(relf)));

    r := build_plan.rdfs;
    WHILE (r <> NIL) AND (NOT err) DO BEGIN
        IF (r^.code_size > $FFFF) OR (r^.data_size > $FFFF) THEN
            BEGIN
            System.Writeln(r^.filename^,
                ': code or data segment is larger than 64K.');
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
            SegAt(nseg)^.r := r;
            SegAt(nseg)^.kind := KIND_CODE;
            SegAt(nseg)^.len := r^.code_size;
            SegAt(nseg)^.alloc := r^.code_size;
            r^.linker.hmz_code_seg := nseg;
        END;
        IF r^.data_size > 0 THEN BEGIN
            Inc(nseg);
            IF nseg > MAX_SEGS THEN BEGIN
                System.Writeln('Too many segments.');
                err := TRUE;
                BREAK;
            END;
            SegAt(nseg)^.r := r;
            SegAt(nseg)^.kind := KIND_DATA;
            SegAt(nseg)^.len := r^.data_size;
            SegAt(nseg)^.alloc := r^.data_size;
            r^.linker.hmz_data_seg := nseg;
        END;
        Seek(build_plan.hdr, r^.hdr_ofs);
        bss_size := 0;
        WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs +
            r^.hdr_size, RREC_BSS, s) DO BEGIN
            GET_BSS(s, bss_size);
        END;
        IF bss_size > $FFFF - bss_total THEN BEGIN
            System.Writeln('BSS exceeds NE segment limit.');
            err := TRUE; BREAK;
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
        END ELSE IF bss_total + stack_size + def_heap + 2 >
            $FFFF THEN BEGIN
            System.Writeln(
'bss, stack and heap are too large for NE format.');
            err := TRUE;
        END;
    END;
    dgroup := nseg + 1;
    MapKind := MAP_SEG;
    MapDigits := 4;
    r := build_plan.rdfs;
    WHILE r <> NIL DO BEGIN
        FillChar(r^.linker.map_ofs, SizeOf(r^.linker.map_ofs),
            #0);
        r^.linker.map_seg[0] := r^.linker.hmz_code_seg;
        r^.linker.map_seg[1] := r^.linker.hmz_data_seg;
        r^.linker.map_seg[2] := dgroup;
        r^.linker.map_ofs[2] := r^.linker.hmz_bss_seg;
        r := r^.next;
    END;
    IF NOT err THEN BEGIN
        SegAt(dgroup)^.r := NIL;
        SegAt(dgroup)^.kind := KIND_BSS;
        SegAt(dgroup)^.len := 0;
        SegAt(dgroup)^.alloc := bss_total + stack_size +
            def_heap;
        IF SegAt(dgroup)^.alloc = 0 THEN SegAt(dgroup)^.alloc :=
            2;
        FOR n := 1 TO nseg DO FOR m := 1 TO segdef_count DO BEGIN
            IF (DefSegAt(m)^.stem = StemOf(SegAt(
                n)^.r^.filename^))
                AND (DefSegAt(m)^.isdata = (SegAt(n)^.kind =
                KIND_DATA)) THEN BEGIN
                SegAt(n)^.has_ovr := TRUE;
                SegAt(n)^.attr_ovr := DefSegAt(m)^.attr;
            END;
        END;
    END;

    n := 1;
    WHILE (n <= nseg) AND (NOT err) DO BEGIN
        r := SegAt(n)^.r;
        Assign(i, r^.filename^);
        Reset(i);
        IF NOT IsOpen(i) THEN BEGIN
            err := TRUE;
            BREAK;
        END;
        SegAt(n)^.blob_ofs := FilePos(blob);
        IF SegAt(n)^.kind = KIND_CODE THEN Seek(i, r^.file_code)
            ELSE Seek(i, r^.file_data);
        BlockCopy(i, blob, SegAt(n)^.len);
        Close(i);
        Inc(n);
    END;

    start := NIL;
    IF NOT err THEN start := FindExportRdf(build_plan,
        entry_name);
    IF (NOT err) AND (start = NIL) THEN err := TRUE;
    IF (NOT err) AND (start^.rec.seg <> start^.rdf^.code_segnum)
        THEN BEGIN
        System.Writeln('Entry point ', entry_name,
            ' is not in code segment.');
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
        IF exp_count > 0 THEN entlen := BuildEntries(dg = 1,
            movcnt)
        ELSE BEGIN
            FOR n := 0 TO 3 DO EntryAt(n)^ := 0;
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
        FOR p := 1 TO exp_count DO IF NOT ExpAt(p)^.noname THEN
            BEGIN
            IF ExpAt(p)^.resident THEN Inc(resident, 1 + Length(
                ExpAt(p)^.name) + 2)
            ELSE Inc(nrlen, 1 + Length(ExpAt(p)^.name) + 2);
        END;
        modref := resnames + resident;
        impnames := modref + (LONGINT(ext_count) * 2);
        enttab := impnames + imp_size;
        IF (entlen = 0) OR (enttab + entlen > $FFFF)
            OR (nrlen > $FFFF) OR (resbytes > $FFFF)
            OR ((str_count > 0) AND (resbytes > $8000))
            THEN BEGIN
            System.Writeln(
                'NE loader tables exceed format limits.');
            err := TRUE;
        END;
        nonres := stub_size + enttab + entlen;
        seg_start := AlignValue(nonres + nrlen, SECTOR_SIZE);
        sec := seg_start;
        FOR n := 1 TO nseg DO BEGIN
            SegAt(n)^.sector := sec;
            sec := AlignValue(sec + SegAt(n)^.len
                + LONGINT(SegAt(n)^.rel_cnt) * SizeOf(NE_RELOC)
                + 2 * ORD(SegAt(n)^.rel_cnt > 0), SECTOR_SIZE);
        END;
        FOR n := 1 TO res_count DO BEGIN
            ResAt(OrderAt(n)^)^.fpos := sec;
            sec := AlignValue(sec + ResAt(OrderAt(n)^)^.size,
                SECTOR_SIZE);
        END;

        FillChar(hdr, SizeOf(NE_HEADER), #0);
        hdr.sign := NE_SIGN;
        hdr.link_major := 6;
        hdr.link_minor := 1;
        hdr.entry_ofs := enttab;
        hdr.entry_len := entlen;
        hdr.prog_flags := dg;
        IF def_prot THEN hdr.prog_flags := hdr.prog_flags OR
            NE_PROG_PROTMODE;
        IF def_initg THEN hdr.prog_flags := hdr.prog_flags OR
            NE_PROG_GLOBALINIT;
        hdr.app_flags := def_apptype;
        IF is_dll THEN hdr.app_flags := hdr.app_flags OR
            NE_APP_DLL;
        hdr.auto_data := dgroup;
        hdr.heap_size := def_heap;
        hdr.ip := start^.rec.offset;
        hdr.cs := start^.rdf^.linker.hmz_code_seg;
        IF is_dll THEN hdr.sp := 0 ELSE hdr.sp := bss_total +
            stack_size - 2;
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
                sg.sector := SegAt(n)^.sector DIV SECTOR_SIZE;
                sg.length := SegAt(n)^.len;
            END ELSE BEGIN
                sg.sector := 0;
                sg.length := 0;
            END;
            IF n = total THEN sg.attr := data_attr
            ELSE sg.attr := SegAttr(SegAt(n)^);
            sg.alloc := SegAt(n)^.alloc;
            BlockWrite(o, sg, SizeOf(NE_SEGMENT));
        END;
        IF res_count > 0 THEN WriteResTable(o)
        ELSE BEGIN
            WriteWord(o, SECTOR_SHIFT);
            WriteWord(o, 0);
        END;
        WriteCountedName(o, stem);
        WriteWord(o, 0);
        FOR p := 1 TO exp_count DO IF ExpAt(p)^.resident AND (
            NOT ExpAt(p)^.noname) THEN BEGIN
            WriteCountedName(o, ExpAt(p)^.name);
            WriteWord(o, ExpAt(p)^.ordinal);
        END;
        WriteByte(o, 0);
        FOR p := 1 TO ext_count DO WriteWord(o, ExtNameAt(
            p)^.ofs);
        WriteByte(o, 0);
        FOR p := 1 TO imp_tcnt DO WriteCountedName(o, ImpNameAt(
            p)^.s);
        StoreWrite(entbuf, o, entlen);
        WriteCountedName(o, nrname);
        WriteWord(o, 0);
        FOR p := 1 TO exp_count DO IF (NOT ExpAt(p)^.resident)
            AND (NOT ExpAt(p)^.noname) THEN BEGIN
            WriteCountedName(o, ExpAt(p)^.name);
            WriteWord(o, ExpAt(p)^.ordinal);
        END;
        WriteByte(o, 0);
        WHILE FilePos(o) < seg_start DO WriteByte(o, 0);
        FOR n := 1 TO nseg DO BEGIN
            Seek(blob, SegAt(n)^.blob_ofs);
            BlockCopy(blob, o, SegAt(n)^.len);
            IF SegAt(n)^.rel_cnt > 0 THEN BEGIN
                WriteWord(o, SegAt(n)^.rel_cnt);
                Seek(relf, SegAt(n)^.rel_ofs);
                BlockCopy(relf, o, LONGINT(SegAt(n)^.rel_cnt)
                    * SizeOf(NE_RELOC));
            END;
            FilePosAlign(o, SECTOR_SIZE);
        END;
        FOR n := 1 TO res_count DO BEGIN
            Seek(res_file, ResAt(OrderAt(n)^)^.pos);
            BlockCopy(res_file, o, ResAt(OrderAt(n)^)^.size);
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
        StoreFree(segs);
        StoreFree(rl);
        StoreFree(ress);
        StoreFree(order);
        StoreFree(strs);
        StoreFree(entbuf);
        StoreFree(ext_names); StoreFree(imp_names);
    END;
    DefDone;
    LinkAndGenNE := err;
END;

END.
