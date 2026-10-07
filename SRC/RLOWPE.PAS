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
UNIT rlowpe;

INTERFACE

USES system2, rdffmt, rlo, rlodef;

FUNCTION WpSetup(def_file : STRING) : BOOLEAN;

FUNCTION WpBuildImports(VAR rdf : BFILE; VAR err : BOOLEAN) : BOOLEAN;

FUNCTION LinkAndGenWinPE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname   : STRING;
        stack_size : LONGINT;
        res_name   : STRING;
        hx_stub    : BOOLEAN;
        win_stub   : BOOLEAN) : BOOLEAN;

IMPLEMENTATION

USES exe;

CONST
PE_FILE_ALIGN     = $200;
IMAGE_BASE_EXE    = $400000;
IMAGE_BASE_DLL    = $10000000;
IMAGE_CODE_OFFSET = $1000;
SECTION_ALIGN     = $1000;
IMAGE_FILE_DLL    = $2000;
THUNK_SIZE        = 6;
MAX_RSRC          = 200;
MAX_RSTR          = 400;

CODE_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_CODE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

DATA_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

BSS_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_UNINITIALIZED_DATA;

IDATA_SEG_ATTR : DWORD = IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

WCODE_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_CODE;

WDATA_SEG_ATTR : DWORD = IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

WBSS_SEG_ATTR : DWORD = IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_UNINITIALIZED_DATA;

RDATA_SEG_ATTR : DWORD = IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

RELO_SEG_ATTR : DWORD = IMAGE_SCN_MEM_DISCARDABLE
                OR IMAGE_SCN_MEM_SHARED
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

TYPE
PPE_RELOC_ITEM = ^PE_RELOC_ITEM;
PE_RELOC_ITEM = RECORD
        reloc       : ARRAY[1..REC_IN_PLAN] OF WORD;
        reloc_count : BYTE;
        next        : PPE_RELOC_ITEM;
END;

PPE_RELOC_TABLE = ^PE_RELOC_TABLE;
PE_RELOC_TABLE = RECORD
        page        : DWORD;
        items       : PPE_RELOC_ITEM;
        next        : PPE_RELOC_TABLE;
END;

TRSRC = RECORD
        tstr_on  : BOOLEAN;
        nstr_on  : BOOLEAN;
        tid      : WORD;
        nid      : WORD;
        lang     : WORD;
        tstr     : STRING[32];
        nstr     : STRING[32];
        size     : DWORD;
        pos      : DWORD;
        doff     : DWORD;
        soff_t   : DWORD;
        soff_n   : DWORD;
END;
PRSRCARR = ^TRSRCARR;
TRSRCARR = ARRAY [1..MAX_RSRC] OF TRSRC;
PRSRCORD = ^TRSRCORD;
TRSRCORD = ARRAY [1..MAX_RSRC] OF INTEGER;

VAR
slotofs   : ARRAY [1..MAX_IMPDEF] OF DWORD;
rs        : PRSRCARR;
rsord     : PRSRCORD;
rs_count  : INTEGER;
res_file  : BFILE;
res_open  : BOOLEAN;

PROCEDURE SetPeSectName(VAR sect : PE32_SECTION; name : STRING);
VAR     l : INTEGER;
BEGIN
        l := length(name);
        IF l > 8 THEN l := 8;
        Move(name[1], sect.name[1], l);
END;

FUNCTION AddReloc(root : PPE_RELOC_TABLE; r : DWORD) : PPE_RELOC_TABLE;
VAR     page : DWORD;
        ofs  : WORD;
        item : PPE_RELOC_ITEM;
        tbl  : PPE_RELOC_TABLE;
BEGIN
        item := NIL;
        tbl := root;
        page := r AND $FFFFF000;
        ofs := (r AND $0FFF) OR $3000;
        WHILE tbl <> NIL DO BEGIN
                IF tbl^.page = page THEN BREAK;
                tbl := tbl^.next;
        END;
        IF tbl = NIL THEN BEGIN
                GetMem(tbl, SizeOf(PE_RELOC_TABLE));
                FillChar(tbl^, SizeOf(PE_RELOC_TABLE), #0);
                tbl^.page := page;
                tbl^.next := root;
                root := tbl;
        END;
        IF tbl^.items = NIL THEN BEGIN
                GetMem(tbl^.items, SizeOf(PE_RELOC_ITEM));
                FillChar(tbl^.items^, SizeOf(PE_RELOC_ITEM), #0);
        END;
        IF tbl^.items^.reloc_count = REC_IN_PLAN THEN BEGIN
                GetMem(item, SizeOf(PE_RELOC_ITEM));
                FillChar(item^, SizeOf(PE_RELOC_ITEM), #0);
                item^.next := tbl^.items;
                tbl^.items := item;
        END;
        Inc(tbl^.items^.reloc_count);
        tbl^.items^.reloc[tbl^.items^.reloc_count] := ofs;
        AddReloc := root;
END;

PROCEDURE SaveRelocs(VAR o : BFILE; root : PPE_RELOC_TABLE);
VAR     t    : PPE_RELOC_TABLE;
        p    : DWORD;
        item : PPE_RELOC_ITEM;
        i    : DWORD;
BEGIN
        WHILE root <> NIL DO BEGIN
                t := root;
                root := root^.next;
                i := 0;
                WriteDWord(o, t^.page);
                p := FilePos(o);
                WriteDWord(o, 0);
                WHILE t^.items <> NIL DO BEGIN
                        item := t^.items;
                        t^.items := t^.items^.next;
                        BlockWrite(o, item^.reloc, item^.reloc_count SHL 1);
                        Inc(i, item^.reloc_count);
                        FreeMem(item, SizeOf(PE_RELOC_ITEM));
                END;
                IF (i AND 1) <> 0 THEN BEGIN Inc(i); WriteWord(o, 0); END;
                SetDWord(o, p, 8 + (i shl 1));
                Seek(o, FileSize(o));
                FreeMem(t, SizeOf(PE_RELOC_TABLE));
        END;
END;

FUNCTION WpSetup(def_file : STRING) : BOOLEAN;
VAR     i, k, p : INTEGER;
        fn      : STRING;
        v       : LONGINT;
        code    : INTEGER;
        perr    : BOOLEAN;
BEGIN
        DefInit;
        WpSetup := FALSE;
        IF Length(def_file) > 0 THEN BEGIN
                perr := ParseDef(def_file);
                WpSetup := perr;
                IF perr THEN EXIT;
        END;
        FOR i := 1 TO exp_count DO BEGIN
                p := 0;
                FOR k := 1 TO Length(exps^[i].sym) DO IF exps^[i].sym[k] = '.' THEN p := k;
                IF p = 0 THEN CONTINUE;
                IF (imp_count >= MAX_IMPDEF) OR (Length(exps^[i].name) > 58) OR (p = 1)
                        OR (p = Length(exps^[i].sym)) THEN BEGIN
                        System.Writeln('Bad forwarder export ', exps^[i].name, '.');
                        WpSetup := TRUE;
                        EXIT;
                END;
                Inc(imp_count);
                FillChar(imps^[imp_count], SizeOf(TIMPDEF), #0);
                imps^[imp_count].sym := '__fwd_' + exps^[i].name;
                imps^[imp_count].modname := UpStr(Copy(exps^[i].sym, 1, p - 1));
                fn := Copy(exps^[i].sym, p + 1, 255);
                IF fn[1] = '#' THEN BEGIN
                        Val(Copy(fn, 2, 255), v, code);
                        IF (code <> 0) OR (v < 1) OR (v > 65535) THEN BEGIN
                                System.Writeln('Bad forwarder export ', exps^[i].name, '.');
                                WpSetup := TRUE;
                                EXIT;
                        END;
                        imps^[imp_count].ordinal := v;
                END ELSE imps^[imp_count].procname := fn;
                exps^[i].sym := imps^[imp_count].sym;
        END;
END;

FUNCTION WpBuildImports(VAR rdf : BFILE; VAR err : BOOLEAN) : BOOLEAN;
VAR     code, data, hdr : BFILE;
        erec  : REXP_REC;
        rrec  : RRELOC_REC;
        s     : STRING;
        i, j  : INTEGER;
        dpos  : DWORD;
        done  : ARRAY [1..MAX_IMPDEF] OF BOOLEAN;
BEGIN
        WpBuildImports := FALSE;
        IF imp_count = 0 THEN EXIT;
        FillChar(code, SizeOf(BFILE), #0);
        FillChar(data, SizeOf(BFILE), #0);
        FillChar(hdr, SizeOf(BFILE), #0);
        ReWriteTemp(code);
        ReWriteTemp(data);
        ReWriteTemp(hdr);
        ReWriteTemp(rdf);
        IF NOT (IsOpen(code) AND IsOpen(data) AND IsOpen(hdr) AND IsOpen(rdf)) THEN BEGIN
                System.Writeln('Could not create temporary file (check TMP/TEMP).');
                err := TRUE;
                EXIT;
        END;
        FillChar(done, SizeOf(done), #0);
        dpos := 0;
        FOR i := 1 TO imp_count DO IF NOT done[i] THEN BEGIN
                FOR j := i TO imp_count DO IF (NOT done[j]) AND (imps^[j].modname = imps^[i].modname) THEN BEGIN
                        done[j] := TRUE;
                        slotofs[j] := dpos;
                        Inc(dpos, 4);
                END;
                Inc(dpos, 4);
        END;
        FOR i := 1 TO dpos DO WriteByte(data, 0);
        FOR i := 1 TO imp_count DO BEGIN
                FillChar(erec, SizeOf(erec), #0);
                erec.name := imps^[i].sym;
                erec.seg := 0;
                erec.offset := FilePos(code);
                SET_EXPORT_REC(erec, s);
                RDF_WRITE_REC(hdr, RREC_GLOBAL, s);
                FillChar(erec, SizeOf(erec), #0);
                erec.name := '__imp_' + imps^[i].sym;
                erec.seg := 1;
                erec.offset := slotofs[i];
                SET_EXPORT_REC(erec, s);
                RDF_WRITE_REC(hdr, RREC_GLOBAL, s);
                FillChar(rrec, SizeOf(rrec), #0);
                rrec.seg := 0;
                rrec.offset := FilePos(code) + 2;
                rrec.width := RWIDTH32;
                rrec.rseg := 1;
                SET_RELOC_REC(rrec, s);
                RDF_WRITE_REC(hdr, RREC_RELOC, s);
                WriteByte(code, $FF);
                WriteByte(code, $25);
                WriteDWord(code, slotofs[i]);
        END;
        WRITE_RDF(hdr, 0, code, 1, data, rdf);
        Flush(rdf);
        Close(hdr);
        Close(data);
        Close(code);
        WpBuildImports := TRUE;
END;

PROCEDURE WriteAsciiz(VAR o : BFILE; s : STRING);
VAR     i : INTEGER;
BEGIN
        FOR i := 1 TO Length(s) DO WriteByte(o, ORD(s[i]));
        WriteByte(o, 0);
END;

PROCEDURE PadTo(VAR o : BFILE; align : DWORD);
BEGIN
        WHILE (FilePos(o) MOD align) <> 0 DO WriteByte(o, 0);
END;

FUNCTION FindGlobal(VAR hdr : BFILE; VAR name : RDFNAME; VAR rec : REXP_REC) : BOOLEAN;
VAR     s : STRING;
BEGIN
        FindGlobal := FALSE;
        Seek(hdr, 0);
        WHILE RDF_LOOKUPREC(hdr, RREC_GLOBAL, s) DO BEGIN
                GET_EXPORT_REC(s, rec);
                IF rec.name = name THEN BEGIN
                        FindGlobal := TRUE;
                        EXIT;
                END;
        END;
END;

FUNCTION SymRva(VAR hdr : BFILE; VAR name : RDFNAME; code_ofs, data_ofs, bss_ofs : DWORD; VAR rva : DWORD) : BOOLEAN;
VAR     rec : REXP_REC;
BEGIN
        SymRva := FALSE;
        IF NOT FindGlobal(hdr, name, rec) THEN EXIT;
        IF rec.seg = 0 THEN rva := code_ofs + rec.offset
        ELSE IF rec.seg = 1 THEN rva := data_ofs + rec.offset
        ELSE rva := bss_ofs + rec.offset;
        SymRva := TRUE;
END;

FUNCTION BuildImports(VAR hdr : BFILE; VAR o : BFILE; rva : DWORD
        ; code_ofs, data_ofs, bss_ofs : DWORD; VAR dirsize, iat_rva, iat_size : DWORD) : BOOLEAN;
VAR     i, j, m  : INTEGER;
        nmods    : INTEGER;
        mods     : ARRAY [1..MAX_IMPDEF] OF INTEGER;
        have     : ARRAY [1..MAX_IMPDEF] OF BOOLEAN;
        slot     : ARRAY [1..MAX_IMPDEF] OF DWORD;
        nm       : RDFNAME;
        dll      : STRING;
        ilt_rva  : ARRAY [1..MAX_IMPDEF] OF DWORD;
        name_rva : ARRAY [1..MAX_IMPDEF] OF DWORD;
        dll_rva  : ARRAY [1..MAX_IMPDEF] OF DWORD;
        pos      : DWORD;
        cnt      : INTEGER;
        used     : BOOLEAN;
BEGIN
        BuildImports := FALSE;
        dirsize := 0;
        iat_rva := 0;
        iat_size := 0;
        nmods := 0;
        FOR i := 1 TO imp_count DO BEGIN
                nm := '__imp_' + imps^[i].sym;
                have[i] := SymRva(hdr, nm, code_ofs, data_ofs, bss_ofs, slot[i]);
        END;
        FOR i := 1 TO imp_count DO IF have[i] THEN BEGIN
                used := FALSE;
                FOR j := 1 TO nmods DO IF imps^[mods[j]].modname = imps^[i].modname THEN used := TRUE;
                IF NOT used THEN BEGIN
                        Inc(nmods);
                        mods[nmods] := i;
                END;
        END;
        IF nmods = 0 THEN EXIT;
        iat_rva := $FFFFFFF;
        FOR i := 1 TO imp_count DO IF have[i] THEN BEGIN
                IF slot[i] < iat_rva THEN iat_rva := slot[i];
                IF slot[i] + 8 > iat_size THEN iat_size := slot[i] + 8;
        END;
        iat_size := iat_size - iat_rva;
        pos := (nmods + 1) * 20;
        FOR m := 1 TO nmods DO BEGIN
                cnt := 0;
                FOR i := 1 TO imp_count DO IF have[i] AND (imps^[i].modname = imps^[mods[m]].modname) THEN Inc(cnt);
                ilt_rva[m] := rva + pos;
                Inc(pos, (cnt + 1) * 4);
        END;
        FOR i := 1 TO imp_count DO IF have[i] AND (Length(imps^[i].procname) > 0) THEN BEGIN
                name_rva[i] := rva + pos;
                Inc(pos, 2 + Length(imps^[i].procname) + 1);
                IF (pos AND 1) <> 0 THEN Inc(pos);
        END;
        FOR m := 1 TO nmods DO BEGIN
                dll_rva[m] := rva + pos;
                Inc(pos, Length(imps^[mods[m]].modname) + 5);
        END;
        FOR m := 1 TO nmods DO BEGIN
                WriteDWord(o, ilt_rva[m]);
                WriteDWord(o, 0);
                WriteDWord(o, 0);
                WriteDWord(o, dll_rva[m]);
                WriteDWord(o, slot[mods[m]]);
        END;
        FOR i := 1 TO 5 DO WriteDWord(o, 0);
        dirsize := (nmods + 1) * 20;
        FOR m := 1 TO nmods DO BEGIN
                FOR i := 1 TO imp_count DO IF have[i] AND (imps^[i].modname = imps^[mods[m]].modname) THEN BEGIN
                        IF Length(imps^[i].procname) > 0 THEN WriteDWord(o, name_rva[i])
                        ELSE WriteDWord(o, $80000000 OR imps^[i].ordinal);
                END;
                WriteDWord(o, 0);
        END;
        FOR i := 1 TO imp_count DO IF have[i] AND (Length(imps^[i].procname) > 0) THEN BEGIN
                WriteWord(o, 0);
                WriteAsciiz(o, imps^[i].procname);
                PadTo(o, 2);
        END;
        FOR m := 1 TO nmods DO BEGIN
                WriteAsciiz(o, imps^[mods[m]].modname + '.DLL');
        END;
        BuildImports := TRUE;
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

FUNCTION BuildExports(VAR hdr : BFILE; VAR o : BFILE; rva : DWORD
        ; code_ofs, data_ofs, bss_ofs : DWORD; modname : STRING; VAR dirsize : DWORD) : BOOLEAN;
VAR     i, j, k   : INTEGER;
        ordr      : ARRAY [1..MAX_EXPORTS] OF INTEGER;
        nn        : INTEGER;
        t         : INTEGER;
        base, top : WORD;
        nfunc     : DWORD;
        pos       : DWORD;
        funcs     : DWORD;
        names     : DWORD;
        ords      : DWORD;
        strs      : DWORD;
        erva      : DWORD;
        ok        : BOOLEAN;
        orda      : WORD;
        nm        : RDFNAME;
        name_rva  : ARRAY [1..MAX_EXPORTS] OF DWORD;
BEGIN
        BuildExports := FALSE;
        dirsize := 0;
        ok := TRUE;
        FOR i := 1 TO exp_count DO BEGIN
                nm := exps^[i].sym;
                IF NOT SymRva(hdr, nm, code_ofs, data_ofs, bss_ofs, erva) THEN BEGIN
                        System.Writeln('Exported symbol ', exps^[i].sym, ' not found.');
                        EXIT;
                END;
                FOR j := 1 TO i - 1 DO IF exps^[j].name = exps^[i].name THEN BEGIN
                        System.Writeln('Duplicate export ', exps^[i].name, '.');
                        EXIT;
                END;
                IF (exps^[i].ordinal <> 0) AND (FindByOrd(exps^[i].ordinal) <> i) THEN BEGIN
                        System.Writeln('Duplicate ordinal ', exps^[i].ordinal, '.');
                        EXIT;
                END;
        END;
        orda := 1;
        FOR i := 1 TO exp_count DO IF exps^[i].ordinal = 0 THEN BEGIN
                WHILE FindByOrd(orda) <> 0 DO Inc(orda);
                exps^[i].ordinal := orda;
        END;
        base := 65535;
        top := 0;
        FOR i := 1 TO exp_count DO BEGIN
                IF exps^[i].ordinal < base THEN base := exps^[i].ordinal;
                IF exps^[i].ordinal > top THEN top := exps^[i].ordinal;
        END;
        nfunc := top - base + 1;
        nn := 0;
        FOR i := 1 TO exp_count DO IF NOT exps^[i].noname THEN BEGIN
                Inc(nn);
                ordr[nn] := i;
        END;
        FOR i := 1 TO nn - 1 DO FOR j := i + 1 TO nn DO
                IF exps^[ordr[j]].name < exps^[ordr[i]].name THEN BEGIN
                        t := ordr[i];
                        ordr[i] := ordr[j];
                        ordr[j] := t;
                END;
        funcs := rva + 40;
        names := funcs + (nfunc * 4);
        ords := names + (nn * 4);
        strs := ords + (nn * 2);
        pos := strs;
        FOR k := 1 TO nn DO BEGIN
                name_rva[k] := pos;
                Inc(pos, Length(exps^[ordr[k]].name) + 1);
        END;
        WriteDWord(o, 0);
        WriteDWord(o, 0);
        WriteDWord(o, 0);
        WriteDWord(o, pos);
        WriteDWord(o, base);
        WriteDWord(o, nfunc);
        WriteDWord(o, nn);
        WriteDWord(o, funcs);
        WriteDWord(o, names);
        WriteDWord(o, ords);
        FOR k := 0 TO nfunc - 1 DO BEGIN
                j := FindByOrd(base + k);
                IF j = 0 THEN WriteDWord(o, 0)
                ELSE BEGIN
                        nm := exps^[j].sym;
                        SymRva(hdr, nm, code_ofs, data_ofs, bss_ofs, erva);
                        WriteDWord(o, erva);
                END;
        END;
        FOR k := 1 TO nn DO WriteDWord(o, name_rva[k]);
        FOR k := 1 TO nn DO WriteWord(o, exps^[ordr[k]].ordinal - base);
        FOR k := 1 TO nn DO WriteAsciiz(o, exps^[ordr[k]].name);
        WriteAsciiz(o, modname);
        dirsize := FilePos(o);
        BuildExports := ok;
END;

FUNCTION RsrcCmp(a, b : INTEGER) : INTEGER;
VAR     x, y : TRSRC;
        res  : INTEGER;
BEGIN
        x := rs^[a];
        y := rs^[b];
        res := 0;
        IF x.tstr_on <> y.tstr_on THEN BEGIN
                IF x.tstr_on THEN res := -1 ELSE res := 1;
        END ELSE IF x.tstr_on THEN BEGIN
                IF x.tstr < y.tstr THEN res := -1 ELSE IF x.tstr > y.tstr THEN res := 1;
        END ELSE IF x.tid <> y.tid THEN BEGIN
                IF x.tid < y.tid THEN res := -1 ELSE res := 1;
        END;
        IF res <> 0 THEN BEGIN RsrcCmp := res; EXIT; END;
        IF x.nstr_on <> y.nstr_on THEN BEGIN
                IF x.nstr_on THEN res := -1 ELSE res := 1;
        END ELSE IF x.nstr_on THEN BEGIN
                IF x.nstr < y.nstr THEN res := -1 ELSE IF x.nstr > y.nstr THEN res := 1;
        END ELSE IF x.nid <> y.nid THEN BEGIN
                IF x.nid < y.nid THEN res := -1 ELSE res := 1;
        END;
        IF res <> 0 THEN BEGIN RsrcCmp := res; EXIT; END;
        IF x.lang < y.lang THEN res := -1 ELSE IF x.lang > y.lang THEN res := 1;
        RsrcCmp := res;
END;

FUNCTION SameT(a, b : INTEGER) : BOOLEAN;
BEGIN
        IF rs^[a].tstr_on <> rs^[b].tstr_on THEN SameT := FALSE
        ELSE IF rs^[a].tstr_on THEN SameT := rs^[a].tstr = rs^[b].tstr
        ELSE SameT := rs^[a].tid = rs^[b].tid;
END;

FUNCTION SameN(a, b : INTEGER) : BOOLEAN;
BEGIN
        IF NOT SameT(a, b) THEN SameN := FALSE
        ELSE IF rs^[a].nstr_on <> rs^[b].nstr_on THEN SameN := FALSE
        ELSE IF rs^[a].nstr_on THEN SameN := rs^[a].nstr = rs^[b].nstr
        ELSE SameN := rs^[a].nid = rs^[b].nid;
END;

FUNCTION ReadWideStr(VAR f : BFILE; first : WORD; VAR s : STRING) : BOOLEAN;
VAR     w : WORD;
BEGIN
        ReadWideStr := FALSE;
        s := '';
        w := first;
        WHILE w <> 0 DO BEGIN
                IF Length(s) >= 32 THEN EXIT;
                s := s + UpCase(CHR(w AND $FF));
                IF Eof(f) THEN EXIT;
                w := ReadWord(f);
        END;
        ReadWideStr := TRUE;
END;

FUNCTION ParseRes32(fname : STRING) : BOOLEAN;
VAR     start, dsize, hsize : DWORD;
        w     : WORD;
        ts    : STRING;
        ns    : STRING;
        t, n  : BOOLEAN;
        tid, nid : WORD;
        r     : INTEGER;
        p     : DWORD;
BEGIN
        ParseRes32 := TRUE;
        Assign(res_file, fname);
        Reset(res_file);
        IF NOT IsOpen(res_file) THEN BEGIN
                System.Writeln('Could not open ', fname, '.');
                EXIT;
        END;
        res_open := TRUE;
        WHILE FilePos(res_file) + 16 <= FileSize(res_file) DO BEGIN
                start := FilePos(res_file);
                dsize := ReadDWord(res_file);
                hsize := ReadDWord(res_file);
                IF (hsize < 24) OR (start + hsize + dsize > FileSize(res_file)) THEN BEGIN
                        System.Writeln(fname, ': bad .RES file (only 32-bit .RES files are supported).');
                        EXIT;
                END;
                w := ReadWord(res_file);
                tid := 0;
                nid := 0;
                ts := '';
                ns := '';
                IF w = $FFFF THEN BEGIN
                        t := FALSE;
                        tid := ReadWord(res_file);
                END ELSE BEGIN
                        t := TRUE;
                        IF NOT ReadWideStr(res_file, w, ts) THEN EXIT;
                END;
                w := ReadWord(res_file);
                IF w = $FFFF THEN BEGIN
                        n := FALSE;
                        nid := ReadWord(res_file);
                END ELSE BEGIN
                        n := TRUE;
                        IF NOT ReadWideStr(res_file, w, ns) THEN EXIT;
                END;
                p := FilePos(res_file);
                IF ((p - start) AND 3) <> 0 THEN p := start + (((p - start) + 3) AND $FFFFFFFC);
                Seek(res_file, p + 4);
                w := ReadWord(res_file);
                r := ReadWord(res_file);
                IF NOT ((dsize = 0) AND (NOT t) AND (tid = 0)) THEN BEGIN
                        IF rs_count >= MAX_RSRC THEN BEGIN
                                System.Writeln('Too many resources.');
                                EXIT;
                        END;
                        Inc(rs_count);
                        FillChar(rs^[rs_count], SizeOf(TRSRC), #0);
                        rs^[rs_count].tstr_on := t;
                        rs^[rs_count].nstr_on := n;
                        rs^[rs_count].tid := tid;
                        rs^[rs_count].nid := nid;
                        rs^[rs_count].tstr := ts;
                        rs^[rs_count].nstr := ns;
                        rs^[rs_count].lang := r;
                        rs^[rs_count].size := dsize;
                        rs^[rs_count].pos := start + hsize;
                END;
                Seek(res_file, start + hsize + dsize);
                p := FilePos(res_file);
                IF (p AND 3) <> 0 THEN Seek(res_file, (p + 3) AND $FFFFFFFC);
        END;
        ParseRes32 := FALSE;
END;

PROCEDURE WriteWide(VAR o : BFILE; s : STRING);
VAR     i : INTEGER;
BEGIN
        WriteWord(o, Length(s));
        FOR i := 1 TO Length(s) DO WriteWord(o, ORD(s[i]));
END;

PROCEDURE WriteDirHdr(VAR o : BFILE; named, ided : WORD);
BEGIN
        WriteDWord(o, 0);
        WriteDWord(o, 0);
        WriteWord(o, 0);
        WriteWord(o, 0);
        WriteWord(o, named);
        WriteWord(o, ided);
END;

PROCEDURE BuildRsrc(VAR o : BFILE; rva : DWORD);
VAR     i, j, k, n : INTEGER;
        t          : INTEGER;
        ntypes     : INTEGER;
        nnames     : INTEGER;
        l2_base    : DWORD;
        l3_base    : DWORD;
        de_base    : DWORD;
        str_base   : DWORD;
        dat_base   : DWORD;
        cur        : DWORD;
        c2, c3     : DWORD;
        named, ided: INTEGER;
        cnt        : INTEGER;
        pos        : DWORD;
        l2off      : ARRAY [1..MAX_RSRC] OF DWORD;
        l3off      : ARRAY [1..MAX_RSRC] OF DWORD;
        newt, newn : ARRAY [1..MAX_RSRC] OF BOOLEAN;
        sp         : DWORD;
        first      : INTEGER;
        a, b       : INTEGER;
BEGIN
        n := rs_count;
        FOR i := 1 TO n DO rsord^[i] := i;
        FOR i := 1 TO n - 1 DO FOR j := i + 1 TO n DO
                IF RsrcCmp(rsord^[j], rsord^[i]) < 0 THEN BEGIN
                        t := rsord^[i];
                        rsord^[i] := rsord^[j];
                        rsord^[j] := t;
                END;
        ntypes := 0;
        nnames := 0;
        FOR i := 1 TO n DO BEGIN
                newt[i] := (i = 1) OR (NOT SameT(rsord^[i - 1], rsord^[i]));
                newn[i] := (i = 1) OR (NOT SameN(rsord^[i - 1], rsord^[i]));
                IF newt[i] THEN Inc(ntypes);
                IF newn[i] THEN Inc(nnames);
        END;
        l2_base := 16 + (8 * ntypes);
        l3_base := l2_base + (16 * ntypes) + (8 * nnames);
        de_base := l3_base + (16 * nnames) + (8 * n);
        str_base := de_base + (16 * n);
        sp := str_base;
        FOR i := 1 TO n DO BEGIN
                k := rsord^[i];
                IF rs^[k].tstr_on THEN BEGIN
                        rs^[k].soff_t := sp;
                        Inc(sp, 2 + 2 * Length(rs^[k].tstr));
                END;
                IF rs^[k].nstr_on THEN BEGIN
                        rs^[k].soff_n := sp;
                        Inc(sp, 2 + 2 * Length(rs^[k].nstr));
                END;
        END;
        dat_base := (sp + 3) AND $FFFFFFFC;
        pos := dat_base;
        FOR i := 1 TO n DO BEGIN
                rs^[rsord^[i]].doff := pos;
                pos := (pos + rs^[rsord^[i]].size + 3) AND $FFFFFFFC;
        END;

        c2 := l2_base;
        c3 := l3_base;
        i := 1;
        named := 0;
        ided := 0;
        FOR k := 1 TO n DO IF newt[k] THEN BEGIN
                IF rs^[rsord^[k]].tstr_on THEN Inc(named) ELSE Inc(ided);
        END;
        WriteDirHdr(o, named, ided);
        FOR k := 1 TO n DO IF newt[k] THEN BEGIN
                l2off[k] := c2;
                cnt := 0;
                FOR j := k TO n DO BEGIN
                        IF (j > k) AND newt[j] THEN BREAK;
                        IF newn[j] THEN Inc(cnt);
                END;
                Inc(c2, 16 + (8 * cnt));
                IF rs^[rsord^[k]].tstr_on THEN WriteDWord(o, $80000000 OR rs^[rsord^[k]].soff_t)
                ELSE WriteDWord(o, rs^[rsord^[k]].tid);
                WriteDWord(o, $80000000 OR l2off[k]);
        END;
        FOR k := 1 TO n DO IF newt[k] THEN BEGIN
                named := 0;
                ided := 0;
                FOR j := k TO n DO BEGIN
                        IF (j > k) AND newt[j] THEN BREAK;
                        IF newn[j] THEN BEGIN
                                IF rs^[rsord^[j]].nstr_on THEN Inc(named) ELSE Inc(ided);
                        END;
                END;
                WriteDirHdr(o, named, ided);
                FOR j := k TO n DO BEGIN
                        IF (j > k) AND newt[j] THEN BREAK;
                        IF newn[j] THEN BEGIN
                                l3off[j] := c3;
                                cnt := 0;
                                FOR a := j TO n DO BEGIN
                                        IF (a > j) AND newn[a] THEN BREAK;
                                        Inc(cnt);
                                END;
                                Inc(c3, 16 + (8 * cnt));
                                IF rs^[rsord^[j]].nstr_on THEN WriteDWord(o, $80000000 OR rs^[rsord^[j]].soff_n)
                                ELSE WriteDWord(o, rs^[rsord^[j]].nid);
                                WriteDWord(o, $80000000 OR l3off[j]);
                        END;
                END;
        END;
        FOR k := 1 TO n DO IF newn[k] THEN BEGIN
                cnt := 0;
                FOR a := k TO n DO BEGIN
                        IF (a > k) AND newn[a] THEN BREAK;
                        Inc(cnt);
                END;
                WriteDirHdr(o, 0, cnt);
                FOR a := k TO k + cnt - 1 DO BEGIN
                        WriteDWord(o, rs^[rsord^[a]].lang);
                        WriteDWord(o, de_base + (16 * (a - 1)));
                END;
        END;
        FOR i := 1 TO n DO BEGIN
                WriteDWord(o, rva + rs^[rsord^[i]].doff);
                WriteDWord(o, rs^[rsord^[i]].size);
                WriteDWord(o, 0);
                WriteDWord(o, 0);
        END;
        FOR i := 1 TO n DO BEGIN
                k := rsord^[i];
                IF rs^[k].tstr_on THEN WriteWide(o, rs^[k].tstr);
                IF rs^[k].nstr_on THEN WriteWide(o, rs^[k].nstr);
        END;
        PadTo(o, 4);
        FOR i := 1 TO n DO BEGIN
                k := rsord^[i];
                Seek(res_file, rs^[k].pos);
                BlockCopy(res_file, o, rs^[k].size);
                PadTo(o, 4);
        END;
END;

FUNCTION LinkAndGenWinPE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname   : STRING;
        stack_size : LONGINT;
        res_name   : STRING;
        hx_stub    : BOOLEAN;
        win_stub   : BOOLEAN) : BOOLEAN;
VAR     err           : BOOLEAN;
        code, data    : BFILE;
        hdr, o        : BFILE;
        idata, edata  : BFILE;
        rsrc          : BFILE;
        hdr_pe        : PE32_FULL_HEADER;
        sects         : ARRAY [1..8] OF PE32_SECTION;
        nsect         : INTEGER;
        code_ofs, data_ofs, bss_ofs : DWORD;
        idata_ofs, edata_ofs, rsrc_ofs, relocs_ofs : DWORD;
        code_size, data_size, bss_size : DWORD;
        idata_dir, edata_dir : DWORD;
        iat_rva, iat_size : DWORD;
        code_segnum, data_segnum, bss_segnum : WORD;
        pe_start, ip, base, img_base : DWORD;
        s             : STRING;
        rrec          : RRELOC_REC;
        rtable        : PPE_RELOC_TABLE;
        selfr         : BOOLEAN;
        fix           : DWORD;
        i             : INTEGER;
        modname       : STRING;
        stem          : STRING;
        have_entry    : BOOLEAN;
        have_idata, have_edata, have_rsrc : BOOLEAN;
        rec           : REXP_REC;
        sub           : WORD;
        k             : INTEGER;
        nm            : RDFNAME;
        mem_ok        : BOOLEAN;
        vsz           : DWORD;
BEGIN
        err := NOT IsOpen(input);
        rtable := NIL;
        rs := NIL;
        rsord := NIL;
        rs_count := 0;
        res_open := FALSE;
        mem_ok := FALSE;
        FillChar(hdr, SizeOf(hdr), #0);
        FillChar(code, SizeOf(BFILE), #0);
        FillChar(data, SizeOf(BFILE), #0);
        FillChar(idata, SizeOf(BFILE), #0);
        FillChar(edata, SizeOf(BFILE), #0);
        FillChar(rsrc, SizeOf(BFILE), #0);
        FillChar(o, SizeOf(o), #0);
        FillChar(res_file, SizeOf(BFILE), #0);
        have_idata := FALSE;
        have_edata := FALSE;
        have_rsrc := FALSE;
        nsect := 0;

        IF is_dll THEN img_base := IMAGE_BASE_DLL ELSE img_base := IMAGE_BASE_EXE;
        IF def_stack >= 0 THEN stack_size := def_stack;

        IF NOT err THEN BEGIN
                GetMem(rs, SizeOf(TRSRCARR));
                GetMem(rsord, SizeOf(TRSRCORD));
                mem_ok := TRUE;
                IF Length(res_name) > 0 THEN err := ParseRes32(res_name);
        END;
        IF NOT err THEN BEGIN
                Assign(o, outfname);
                ReWrite(o);
        END;
        err := err OR (NOT (IsOpen(input) AND IsOpen(o)));
        IF NOT err THEN BEGIN
                ReWriteTemp(hdr);
                ReWriteTemp(code);
                ReWriteTemp(data);
                ReWriteTemp(idata);
                ReWriteTemp(edata);
                ReWriteTemp(rsrc);
                err := NOT (IsOpen(hdr) AND IsOpen(code) AND IsOpen(data) AND IsOpen(idata)
                        AND IsOpen(edata) AND IsOpen(rsrc));
        END;
        IF NOT err THEN BEGIN
                Seek(input, 0);
                err := NOT ReadRDF(input, hdr, code, data, code_segnum, data_segnum, bss_segnum);
        END;

        code_size := FileSize(code);
        data_size := FileSize(data);
        bss_size := 0;
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
        END;
        code_ofs := IMAGE_CODE_OFFSET;
        IF code_size = 0 THEN code_size := SECTION_ALIGN;
        data_ofs := AlignValue(code_ofs + code_size, SECTION_ALIGN);
        IF data_size = 0 THEN data_size := SECTION_ALIGN;
        bss_ofs := AlignValue(data_ofs + data_size, SECTION_ALIGN);
        IF bss_size = 0 THEN bss_size := SECTION_ALIGN;

        ip := 0;
        have_entry := FALSE;
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                have_entry := FindEntryPoint(hdr, FileSize(hdr), entry_name, ip);
                IF (NOT have_entry) AND (NOT is_dll) THEN BEGIN
                        System.Writeln('Entry point ', entry_name, ' not found.');
                        err := TRUE;
                END;
        END;

        stem := '';
        modname := def_name;
        IF Length(modname) = 0 THEN BEGIN
                modname := outfname;
                FOR k := Length(modname) DOWNTO 1 DO IF modname[k] IN [':', '\', '/'] THEN BEGIN
                        Delete(modname, 1, k);
                        BREAK;
                END;
        END ELSE modname := modname + '.DLL';

        IF NOT err THEN Seek(hdr, 0);
        WHILE (NOT err) AND RDF_LOOKUPREC(hdr, RREC_RELOC, s) DO BEGIN
                GET_RELOC_REC(s, rrec);
                selfr := (rrec.seg AND $40) <> 0;
                rrec.seg := rrec.seg AND $3F;
                IF NOT (rrec.seg IN [code_segnum, data_segnum]) THEN BEGIN
                        System.Writeln('Invalid relocation.');
                        err := TRUE;
                        BREAK;
                END;
                IF (NOT selfr) AND (rrec.width <> RWIDTH32) THEN BEGIN
                        System.Writeln('Only 32-bit absolute relocations are supported in PE.');
                        err := TRUE;
                        BREAK;
                END;
                fix := img_base;
                IF NOT selfr THEN BEGIN
                        IF rrec.rseg = code_segnum THEN Inc(fix, code_ofs)
                        ELSE IF rrec.rseg = data_segnum THEN Inc(fix, data_ofs)
                        ELSE IF rrec.rseg = bss_segnum THEN Inc(fix, bss_ofs);
                END;
                IF rrec.width = RWIDTH8 THEN BEGIN
                        IF rrec.seg = code_segnum THEN IncByte(code, rrec.offset, fix AND $FF)
                        ELSE IncByte(data, rrec.offset, fix AND $FF);
                END ELSE IF rrec.width = RWIDTH16 THEN BEGIN
                        IF rrec.seg = code_segnum THEN IncWord(code, rrec.offset, fix AND $FFFF)
                        ELSE IncWord(data, rrec.offset, fix AND $FFFF);
                END ELSE IF rrec.width = RWIDTH32 THEN BEGIN
                        IF rrec.seg = code_segnum THEN IncDWord(code, rrec.offset, fix)
                        ELSE IncDWord(data, rrec.offset, fix);
                END;
                IF rrec.seg = code_segnum THEN Inc(rrec.offset, code_ofs)
                ELSE Inc(rrec.offset, data_ofs);
                IF (NOT selfr) AND (rrec.width = RWIDTH32) THEN rtable := AddReloc(rtable, rrec.offset);
        END;

        idata_ofs := AlignValue(bss_ofs + bss_size, SECTION_ALIGN);
        idata_dir := 0;
        IF NOT err THEN
                have_idata := BuildImports(hdr, idata, idata_ofs, code_ofs, data_ofs, bss_ofs
                        , idata_dir, iat_rva, iat_size);
        IF have_idata THEN edata_ofs := AlignValue(idata_ofs + FileSize(idata), SECTION_ALIGN)
        ELSE edata_ofs := idata_ofs;
        edata_dir := 0;
        IF (NOT err) AND (exp_count > 0) THEN BEGIN
                err := NOT BuildExports(hdr, edata, edata_ofs, code_ofs, data_ofs, bss_ofs, modname, edata_dir);
                have_edata := NOT err;
        END;
        IF have_edata THEN rsrc_ofs := AlignValue(edata_ofs + FileSize(edata), SECTION_ALIGN)
        ELSE rsrc_ofs := edata_ofs;
        IF (NOT err) AND (rs_count > 0) THEN BEGIN
                BuildRsrc(rsrc, rsrc_ofs);
                have_rsrc := TRUE;
        END;
        IF have_rsrc THEN relocs_ofs := AlignValue(rsrc_ofs + FileSize(rsrc), SECTION_ALIGN)
        ELSE relocs_ofs := rsrc_ofs;

        IF NOT err THEN BEGIN
                IF win_stub THEN BlockWrite(o, WIN_EXE_STUB, SizeOf(WIN_EXE_STUB))
                ELSE IF hx_stub THEN BlockWrite(o, HX_EXE_STUB, SizeOf(HX_EXE_STUB))
                ELSE BlockWrite(o, SIMPLE_EXE_STUB, SizeOf(SIMPLE_EXE_STUB));
                FilePosAlign(o, $10);
                pe_start := FilePos(o);
                SetWord(o, $003C, pe_start);
                Seek(o, pe_start);

                FillChar(sects, SizeOf(sects), #0);
                nsect := 3;
                IF win_stub THEN SetPeSectName(sects[1], '.text') ELSE SetPeSectName(sects[1], 'CODE');
                sects[1].vaddr := code_ofs;
                sects[1].vsize := AlignValue(code_size, SECTION_ALIGN);
                sects[1].rawSize := AlignValue(FileSize(code), PE_FILE_ALIGN);
                IF win_stub THEN sects[1].chars := WCODE_SEG_ATTR ELSE sects[1].chars := CODE_SEG_ATTR;
                IF win_stub THEN SetPeSectName(sects[2], '.data') ELSE SetPeSectName(sects[2], 'DATA');
                sects[2].vaddr := data_ofs;
                sects[2].vsize := AlignValue(data_size, SECTION_ALIGN);
                sects[2].rawSize := AlignValue(FileSize(data), PE_FILE_ALIGN);
                IF win_stub THEN sects[2].chars := WDATA_SEG_ATTR ELSE sects[2].chars := DATA_SEG_ATTR;
                IF win_stub THEN SetPeSectName(sects[3], '.bss') ELSE SetPeSectName(sects[3], 'BSS');
                sects[3].vaddr := bss_ofs;
                sects[3].vsize := bss_size;
                IF win_stub THEN sects[3].chars := WBSS_SEG_ATTR ELSE sects[3].chars := BSS_SEG_ATTR;
                IF have_idata THEN BEGIN
                        Inc(nsect);
                        SetPeSectName(sects[nsect], '.idata');
                        sects[nsect].vaddr := idata_ofs;
                        sects[nsect].rawSize := AlignValue(FileSize(idata), PE_FILE_ALIGN);
                        sects[nsect].vsize := AlignValue(FileSize(idata), SECTION_ALIGN);
                        sects[nsect].chars := IDATA_SEG_ATTR;
                END;
                IF have_edata THEN BEGIN
                        Inc(nsect);
                        SetPeSectName(sects[nsect], '.edata');
                        sects[nsect].vaddr := edata_ofs;
                        sects[nsect].rawSize := AlignValue(FileSize(edata), PE_FILE_ALIGN);
                        sects[nsect].vsize := AlignValue(FileSize(edata), SECTION_ALIGN);
                        sects[nsect].chars := RDATA_SEG_ATTR;
                END;
                IF have_rsrc THEN BEGIN
                        Inc(nsect);
                        SetPeSectName(sects[nsect], '.rsrc');
                        sects[nsect].vaddr := rsrc_ofs;
                        sects[nsect].rawSize := AlignValue(FileSize(rsrc), PE_FILE_ALIGN);
                        sects[nsect].vsize := AlignValue(FileSize(rsrc), SECTION_ALIGN);
                        sects[nsect].chars := RDATA_SEG_ATTR;
                END;
                Inc(nsect);
                SetPeSectName(sects[nsect], '.reloc');
                sects[nsect].vaddr := relocs_ofs;
                sects[nsect].chars := RELO_SEG_ATTR;

                FillChar(hdr_pe, SizeOf(PE32_FULL_HEADER), #0);
                hdr_pe.sign                     := PE_MAGIC;
                hdr_pe.fileHeader.machine       := IMAGE_FILE_MACHINE_I386;
                hdr_pe.fileHeader.numberOfSects := nsect;
                hdr_pe.fileHeader.optHeaderSize := SizeOf(PE32_OPTIONAL_HEADER);
                hdr_pe.fileHeader.chars         := IMAGE_SYM_CLASS_END_OF_STRUCT;
                IF is_dll THEN hdr_pe.fileHeader.chars := hdr_pe.fileHeader.chars OR IMAGE_FILE_DLL;
                hdr_pe.optHeader.magic          := HEADER_MAGIC_PE32;
                hdr_pe.optHeader.textSize       := code_size;
                hdr_pe.optHeader.dataSize       := data_size;
                hdr_pe.optHeader.bssSize        := bss_size;
                IF have_entry THEN hdr_pe.optHeader.entry := ip + code_ofs;
                hdr_pe.optHeader.imageBase      := img_base;
                hdr_pe.optHeader.secAlign       := SECTION_ALIGN;
                hdr_pe.optHeader.filAlign       := PE_FILE_ALIGN;
                hdr_pe.optHeader.hiOsVer        := 1;
                hdr_pe.optHeader.hiSubSysVer    := 4;
                IF def_apptype_set AND (def_apptype = 3) THEN sub := PE_SUBSYS_WIN_GUI
                ELSE sub := PE_SUBSYS_WIN_CUI;
                hdr_pe.optHeader.subsystem      := sub;
                hdr_pe.optHeader.sizeOfStackRes := stack_size;
                hdr_pe.optHeader.sizeOfStackCom := stack_size;
                IF def_heap > 0 THEN hdr_pe.optHeader.sizeOfHeapRes := def_heap
                ELSE hdr_pe.optHeader.sizeOfHeapRes := $100000;
                hdr_pe.optHeader.sizeOfHeapCom  := $1000;
                hdr_pe.optHeader.numRvaAndSizes := 16;
                IF have_edata THEN BEGIN
                        hdr_pe.optHeader.directory[1].vaddr := edata_ofs;
                        hdr_pe.optHeader.directory[1].size := edata_dir;
                END;
                IF have_idata THEN BEGIN
                        hdr_pe.optHeader.directory[2].vaddr := idata_ofs;
                        hdr_pe.optHeader.directory[2].size := idata_dir;
                        hdr_pe.optHeader.directory[13].vaddr := iat_rva;
                        hdr_pe.optHeader.directory[13].size := iat_size;
                END;
                IF have_rsrc THEN BEGIN
                        hdr_pe.optHeader.directory[3].vaddr := rsrc_ofs;
                        hdr_pe.optHeader.directory[3].size := FileSize(rsrc);
                END;
                hdr_pe.optHeader.directory[6].vaddr := relocs_ofs;
                BlockWrite(o, hdr_pe, SizeOf(PE32_FULL_HEADER));
                FOR k := 1 TO nsect DO BlockWrite(o, sects[k], SizeOf(PE32_SECTION));
                FilePosAlign(o, PE_FILE_ALIGN);
                hdr_pe.optHeader.sizeOfHeaders := FilePos(o);

                IF FileSize(code) > 0 THEN sects[1].ptrRaw := FilePos(o);
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));
                FilePosAlign(o, PE_FILE_ALIGN);
                IF FileSize(data) > 0 THEN sects[2].ptrRaw := FilePos(o);
                Seek(data, 0);
                BlockCopy(data, o, FileSize(data));
                FilePosAlign(o, PE_FILE_ALIGN);
                k := 4;
                IF have_idata THEN BEGIN
                        sects[k].ptrRaw := FilePos(o);
                        Seek(idata, 0);
                        BlockCopy(idata, o, FileSize(idata));
                        FilePosAlign(o, PE_FILE_ALIGN);
                        Inc(k);
                END;
                IF have_edata THEN BEGIN
                        sects[k].ptrRaw := FilePos(o);
                        Seek(edata, 0);
                        BlockCopy(edata, o, FileSize(edata));
                        FilePosAlign(o, PE_FILE_ALIGN);
                        Inc(k);
                END;
                IF have_rsrc THEN BEGIN
                        sects[k].ptrRaw := FilePos(o);
                        Seek(rsrc, 0);
                        BlockCopy(rsrc, o, FileSize(rsrc));
                        FilePosAlign(o, PE_FILE_ALIGN);
                        Inc(k);
                END;
                sects[k].ptrRaw := FilePos(o);
                SaveRelocs(o, rtable);
                hdr_pe.optHeader.directory[6].size := FilePos(o) - sects[k].ptrRaw;
                sects[k].rawSize := AlignValue(FilePos(o) - sects[k].ptrRaw, PE_FILE_ALIGN);
                vsz := AlignValue(sects[k].rawSize, SECTION_ALIGN);
                IF vsz = 0 THEN vsz := SECTION_ALIGN;
                sects[k].vsize := vsz;
                hdr_pe.optHeader.sizeOfImage := AlignValue(relocs_ofs + vsz, SECTION_ALIGN);
                FilePosAlign(o, PE_FILE_ALIGN);
                Seek(o, pe_start);
                BlockWrite(o, hdr_pe, SizeOf(PE32_FULL_HEADER));
                FOR k := 1 TO nsect DO BlockWrite(o, sects[k], SizeOf(PE32_SECTION));
        END;
        Close(hdr);
        Close(code);
        Close(data);
        Close(idata);
        Close(edata);
        Close(rsrc);
        IF res_open THEN Close(res_file);
        IF mem_ok THEN BEGIN
                FreeMem(rs, SizeOf(TRSRCARR));
                FreeMem(rsord, SizeOf(TRSRCORD));
        END;
        IF IsOpen(o) THEN BEGIN
                IF err THEN SetDeleteOnClose(o, TRUE);
                Close(o);
        END;
        DefDone;
        LinkAndGenWinPE := err;
END;

END.
