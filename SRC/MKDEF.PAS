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
USES system2, args, exe;

CONST
MAX_ORD = 1500;

TYPE
TNAME = STRING[40];
PNAMES = ^TNAMES;
TNAMES = ARRAY [1..MAX_ORD] OF TNAME;
PFLAGS = ^TFLAGS;
TFLAGS = ARRAY [1..MAX_ORD] OF BYTE;

VAR     names    : PNAMES;
        resident : PFLAGS;
        eflags   : PFLAGS;
        used     : PFLAGS;
        top_ord  : INTEGER;
        o        : BFILE;
        o_open   : BOOLEAN;

PROCEDURE Emit(s : STRING);
BEGIN
        IF o_open THEN WriteLn(o, s) ELSE System.Writeln(s);
END;

FUNCTION Num(v : LONGINT) : STRING;
VAR     s : STRING;
BEGIN
        Str(v, s);
        Num := s;
END;

PROCEDURE ReadNames(VAR f : BFILE; pos, size : DWORD; is_res : BOOLEAN; VAR first : STRING);
VAR     fin  : DWORD;
        len  : BYTE;
        s    : STRING;
        ord  : WORD;
        i    : INTEGER;
        n    : INTEGER;
BEGIN
        fin := pos + size;
        Seek(f, pos);
        n := 0;
        WHILE FilePos(f) < fin DO BEGIN
                len := ReadByte(f);
                IF len = 0 THEN BREAK;
                s := '';
                FOR i := 1 TO len DO s := s + CHR(ReadByte(f));
                ord := ReadWord(f);
                Inc(n);
                IF n = 1 THEN BEGIN
                        first := s;
                END ELSE IF (ord >= 1) AND (ord <= MAX_ORD) THEN BEGIN
                        IF Length(s) > 40 THEN s[0] := #40;
                        names^[ord] := s;
                        IF is_res THEN resident^[ord] := 1;
                END ELSE IF ord > MAX_ORD THEN
                        System.Writeln('Ordinal ', ord, ' is skipped (too large).');
        END;
END;

PROCEDURE ReadEntries(VAR f : BFILE; pos : DWORD; len : WORD);
VAR     fin   : DWORD;
        count : BYTE;
        seg   : BYTE;
        i     : INTEGER;
        ord   : INTEGER;
        fl    : BYTE;
        w     : WORD;
BEGIN
        fin := pos + len;
        Seek(f, pos);
        ord := 1;
        WHILE FilePos(f) < fin DO BEGIN
                count := ReadByte(f);
                IF count = 0 THEN BREAK;
                seg := ReadByte(f);
                FOR i := 1 TO count DO BEGIN
                        IF seg <> 0 THEN BEGIN
                                fl := ReadByte(f);
                                IF seg = $FF THEN BEGIN
                                        w := ReadWord(f);
                                        w := ReadByte(f);
                                        w := ReadWord(f);
                                END ELSE w := ReadWord(f);
                                IF (ord <= MAX_ORD) AND ((fl AND 1) <> 0) THEN BEGIN
                                        used^[ord] := 1;
                                        eflags^[ord] := fl;
                                END;
                        END;
                        Inc(ord);
                END;
        END;
        top_ord := ord - 1;
        IF top_ord > MAX_ORD THEN top_ord := MAX_ORD;
END;

PROCEDURE MkDefNe(VAR f : BFILE; lf : DWORD; imports : BOOLEAN);
VAR     h       : NE_HEADER;
        modname : STRING;
        descr   : STRING;
        dll     : BOOLEAN;
        dg      : BYTE;
        i       : INTEGER;
        s       : STRING;
        ver     : WORD;
BEGIN
        Seek(f, lf);
        BlockRead(f, h, SizeOf(NE_HEADER));
        dll := (h.app_flags AND NE_APP_DLL) <> 0;
        dg := h.prog_flags AND 3;
        GetMem(names, SizeOf(TNAMES));
        GetMem(resident, SizeOf(TFLAGS));
        GetMem(eflags, SizeOf(TFLAGS));
        GetMem(used, SizeOf(TFLAGS));
        FillChar(names^, SizeOf(TNAMES), #0);
        FillChar(resident^, SizeOf(TFLAGS), #0);
        FillChar(eflags^, SizeOf(TFLAGS), #0);
        FillChar(used^, SizeOf(TFLAGS), #0);
        modname := '';
        descr := '';
        ReadNames(f, lf + h.resname_ofs, h.modref_ofs - h.resname_ofs, TRUE, modname);
        IF h.nonres_len > 0 THEN ReadNames(f, h.nonres_ofs, h.nonres_len, FALSE, descr);
        ReadEntries(f, lf + h.entry_ofs, h.entry_len);
        IF Length(modname) = 0 THEN modname := 'NONAME';
        IF imports THEN BEGIN
                Emit('IMPORTS');
        END ELSE BEGIN
                IF dll THEN BEGIN
                        s := 'LIBRARY ' + modname;
                        IF (h.prog_flags AND NE_PROG_GLOBALINIT) <> 0 THEN s := s + ' INITGLOBAL';
                        Emit(s);
                END ELSE BEGIN
                        s := 'NAME ' + modname;
                        CASE h.app_flags AND 7 OF
                        1: s := s + ' NOTWINDOWCOMPAT';
                        2: s := s + ' WINDOWCOMPAT';
                        3: s := s + ' WINDOWAPI';
                        END;
                        Emit(s);
                END;
                IF Length(descr) > 0 THEN Emit('DESCRIPTION ''' + descr + '''');
                CASE h.target_os OF
                1: s := 'EXETYPE OS2';
                2: s := 'EXETYPE WINDOWS';
                3: s := 'EXETYPE DOS4';
                ELSE s := '';
                END;
                IF Length(s) > 0 THEN BEGIN
                        ver := h.win_version;
                        IF ver <> 0 THEN s := s + ' ' + Num(ver SHR 8) + '.' + Num(ver AND $FF);
                        Emit(s);
                END;
                CASE dg OF
                0: Emit('DATA NONE');
                1: Emit('DATA SINGLE');
                2: Emit('DATA MULTIPLE');
                END;
                IF h.heap_size <> 0 THEN Emit('HEAPSIZE ' + Num(h.heap_size));
                IF h.stack_size <> 0 THEN Emit('STACKSIZE ' + Num(h.stack_size));
                Emit('EXPORTS');
        END;
        FOR i := 1 TO top_ord DO IF used^[i] <> 0 THEN BEGIN
                IF imports THEN BEGIN
                        IF Length(names^[i]) > 0 THEN Emit(modname + '.' + names^[i])
                        ELSE Emit('ORD' + Num(i) + '=' + modname + '.' + Num(i));
                END ELSE BEGIN
                        IF Length(names^[i]) > 0 THEN s := names^[i] ELSE s := 'ORD' + Num(i);
                        s := s + ' @' + Num(i);
                        IF Length(names^[i]) = 0 THEN s := s + ' NONAME'
                        ELSE IF resident^[i] <> 0 THEN s := s + ' RESIDENTNAME';
                        IF (dg = 1) AND ((eflags^[i] AND NE_ENT_SINGLE) = 0) THEN s := s + ' NODATA';
                        IF (eflags^[i] SHR 3) <> 0 THEN s := s + ' ' + Num(eflags^[i] SHR 3);
                        Emit(s);
                END;
        END;
        FreeMem(names, SizeOf(TNAMES));
        FreeMem(resident, SizeOf(TFLAGS));
        FreeMem(eflags, SizeOf(TFLAGS));
        FreeMem(used, SizeOf(TFLAGS));
END;


FUNCTION StripExt(s : STRING) : STRING;
VAR     i : INTEGER;
BEGIN
        FOR i := Length(s) DOWNTO 1 DO IF s[i] = '.' THEN BEGIN
                s[0] := CHR(i - 1);
                BREAK;
        END;
        StripExt := s;
END;

FUNCTION StemOf(fn : STRING) : STRING;
VAR     p : INTEGER;
BEGIN
        FOR p := Length(fn) DOWNTO 1 DO IF fn[p] IN [':', '\', '/'] THEN BEGIN
                Delete(fn, 1, p);
                BREAK;
        END;
        StemOf := StripExt(fn);
END;

VAR
psec    : ARRAY [1..96] OF PE32_SECTION;
pnsec   : INTEGER;

FUNCTION Rva2Off(rva : DWORD) : DWORD;
VAR     i : INTEGER;
        sz : DWORD;
BEGIN
        Rva2Off := 0;
        FOR i := 1 TO pnsec DO BEGIN
                sz := psec[i].vsize;
                IF psec[i].rawSize > sz THEN sz := psec[i].rawSize;
                IF (rva >= psec[i].vaddr) AND (rva < psec[i].vaddr + sz) THEN BEGIN
                        Rva2Off := rva - psec[i].vaddr + psec[i].ptrRaw;
                        EXIT;
                END;
        END;
END;

FUNCTION ReadAsciiz(VAR f : BFILE; ofs : DWORD) : STRING;
VAR     s : STRING;
        b : BYTE;
BEGIN
        s := '';
        IF ofs <> 0 THEN BEGIN
                Seek(f, ofs);
                b := ReadByte(f);
                WHILE (b <> 0) AND (Length(s) < 60) AND (NOT Eof(f)) DO BEGIN
                        s := s + CHR(b);
                        b := ReadByte(f);
                END;
        END;
        ReadAsciiz := s;
END;

PROCEDURE MkDefPe(VAR f : BFILE; lf : DWORD; imports : BOOLEAN; fname : STRING);
VAR     i        : INTEGER;
        magic    : WORD;
        optsz    : WORD;
        opt      : DWORD;
        dirs     : DWORD;
        psz      : DWORD;
        subsys   : WORD;
        stackres : DWORD;
        heapres  : DWORD;
        ehi      : DWORD;
        ibase    : DWORD;
        isize    : DWORD;
        dll      : BOOLEAN;
        modname  : STRING;
        s        : STRING;
        eo       : DWORD;
        erva     : DWORD;
        esize    : DWORD;
        base     : DWORD;
        nfunc    : DWORD;
        nnames   : DWORD;
        funcs    : DWORD;
        nametab  : DWORD;
        ordtab   : DWORD;
        fr       : DWORD;
        k        : DWORD;
        ordn     : DWORD;
        idx      : WORD;
        no       : DWORD;
        io       : DWORD;
        dn       : STRING;
        mn       : STRING;
        ilt      : DWORD;
        ent      : DWORD;
        p        : DWORD;
        nm       : STRING;
        have_imp : BOOLEAN;
BEGIN
        opt := lf + 4 + SizeOf(PE32_FILE_HEADER);
        magic := GetWord(f, opt);
        IF (magic <> HEADER_MAGIC_PE32) AND (magic <> HEADER_MAGIC_PE32PLUS) THEN BEGIN
                System.Writeln(fname, ': unknown PE optional header.');
                Halt(1);
        END;
        pnsec := GetWord(f, lf + 6);
        optsz := GetWord(f, lf + 20);
        IF pnsec > 96 THEN pnsec := 96;
        Seek(f, opt + optsz);
        FOR i := 1 TO pnsec DO BlockRead(f, psec[i], SizeOf(PE32_SECTION));
        dll := (GetWord(f, lf + 22) AND $2000) <> 0;
        subsys := GetWord(f, opt + 68);
        IF magic = HEADER_MAGIC_PE32 THEN BEGIN
                psz := 4;
                dirs := opt + 96;
                stackres := GetDWord(f, opt + 72);
                heapres := GetDWord(f, opt + 80);
        END ELSE BEGIN
                psz := 8;
                dirs := opt + 112;
                stackres := GetDWord(f, opt + 72);
                heapres := GetDWord(f, opt + 88);
        END;
        ibase := GetDWord(f, dirs + 8);
        isize := GetDWord(f, dirs + 12);
        GetMem(names, SizeOf(TNAMES));
        GetMem(resident, SizeOf(TFLAGS));
        GetMem(eflags, SizeOf(TFLAGS));
        GetMem(used, SizeOf(TFLAGS));
        FillChar(names^, SizeOf(TNAMES), #0);
        FillChar(resident^, SizeOf(TFLAGS), #0);
        FillChar(eflags^, SizeOf(TFLAGS), #0);
        FillChar(used^, SizeOf(TFLAGS), #0);
        top_ord := 0;
        modname := StemOf(fname);
        erva := GetDWord(f, dirs);
        esize := GetDWord(f, dirs + 4);
        eo := 0;
        IF erva <> 0 THEN eo := Rva2Off(erva);
        IF eo <> 0 THEN BEGIN
                Seek(f, eo);
                ReadDWord(f);
                ReadDWord(f);
                ReadDWord(f);
                no := ReadDWord(f);
                base := ReadDWord(f);
                nfunc := ReadDWord(f);
                nnames := ReadDWord(f);
                funcs := ReadDWord(f);
                nametab := ReadDWord(f);
                ordtab := ReadDWord(f);
                s := ReadAsciiz(f, Rva2Off(no));
                IF Length(s) > 0 THEN modname := StripExt(s);
                IF (nfunc > 65536) OR (nnames > 65536) OR (Rva2Off(funcs) = 0) OR (Rva2Off(nametab) = 0)
                        OR (Rva2Off(ordtab) = 0) THEN BEGIN
                        System.Writeln(fname, ': damaged export table.');
                        nfunc := 0;
                        nnames := 0;
                END;
                FOR k := 0 TO nfunc - 1 DO BEGIN
                        ordn := base + k;
                        Seek(f, Rva2Off(funcs) + (k * 4));
                        fr := ReadDWord(f);
                        IF fr <> 0 THEN BEGIN
                                IF (fr >= erva) AND (fr < erva + esize) THEN
                                        System.Writeln('Forwarder ', ordn, ' is skipped.')
                                ELSE IF (ordn >= 1) AND (ordn <= MAX_ORD) THEN BEGIN
                                        used^[ordn] := 1;
                                        IF ordn > top_ord THEN top_ord := ordn;
                                END ELSE System.Writeln('Ordinal ', ordn, ' is skipped (too large).');
                        END;
                END;
                FOR k := 0 TO nnames - 1 DO BEGIN
                        Seek(f, Rva2Off(ordtab) + (k * 2));
                        idx := ReadWord(f);
                        Seek(f, Rva2Off(nametab) + (k * 4));
                        fr := ReadDWord(f);
                        s := ReadAsciiz(f, Rva2Off(fr));
                        ordn := base + idx;
                        IF (ordn >= 1) AND (ordn <= MAX_ORD) THEN BEGIN
                                IF Length(s) > 40 THEN s[0] := #40;
                                names^[ordn] := s;
                        END;
                END;
        END;
        IF imports THEN Emit('IMPORTS')
        ELSE BEGIN
                IF dll THEN Emit('LIBRARY ' + modname)
                ELSE IF subsys = PE_SUBSYS_WIN_GUI THEN Emit('NAME ' + modname + ' WINDOWAPI')
                ELSE Emit('NAME ' + modname);
                IF heapres <> $100000 THEN Emit('HEAPSIZE ' + Num(heapres));
                IF (NOT dll) AND (stackres <> 8192) THEN Emit('STACKSIZE ' + Num(stackres));
                IF top_ord > 0 THEN Emit('EXPORTS');
        END;
        FOR i := 1 TO top_ord DO IF used^[i] <> 0 THEN BEGIN
                IF imports THEN BEGIN
                        IF Length(names^[i]) > 0 THEN Emit(modname + '.' + names^[i])
                        ELSE Emit('ORD' + Num(i) + '=' + modname + '.' + Num(i));
                END ELSE BEGIN
                        IF Length(names^[i]) > 0 THEN s := names^[i] + ' @' + Num(i)
                        ELSE s := 'ORD' + Num(i) + ' @' + Num(i) + ' NONAME';
                        Emit(s);
                END;
        END;
        IF NOT imports THEN BEGIN
                io := 0;
                IF ibase <> 0 THEN io := Rva2Off(ibase);
                have_imp := FALSE;
                WHILE io <> 0 DO BEGIN
                        Seek(f, io);
                        ilt := ReadDWord(f);
                        ReadDWord(f);
                        ReadDWord(f);
                        no := ReadDWord(f);
                        p := ReadDWord(f);
                        IF no = 0 THEN BREAK;
                        IF ilt = 0 THEN ilt := p;
                        dn := ReadAsciiz(f, Rva2Off(no));
                        mn := StripExt(dn);
                        IF NOT have_imp THEN BEGIN
                                Emit('IMPORTS');
                                have_imp := TRUE;
                        END;
                        k := 0;
                        WHILE (Rva2Off(ilt) <> 0) AND (k < 4096) DO BEGIN
                                Seek(f, Rva2Off(ilt) + (k * psz));
                                ent := ReadDWord(f);
                                ehi := 0;
                                IF psz = 8 THEN ehi := ReadDWord(f);
                                IF (ent = 0) AND (ehi = 0) THEN BREAK;
                                IF (psz = 4) AND ((ent AND $80000000) <> 0) THEN BEGIN
                                        ehi := $80000000;
                                END ELSE IF psz = 4 THEN ehi := 0;
                                IF (ehi AND $80000000) <> 0 THEN
                                        Emit(mn + '_' + Num(ent AND $FFFF) + '=' + mn + '.' + Num(ent AND $FFFF))
                                ELSE BEGIN
                                        nm := '';
                                        IF Rva2Off(ent) <> 0 THEN nm := ReadAsciiz(f, Rva2Off(ent) + 2);
                                        IF Length(nm) > 0 THEN Emit(mn + '.' + nm);
                                END;
                                Inc(k);
                        END;
                        Inc(io, 20);
                END;
        END;
        FreeMem(names, SizeOf(TNAMES));
        FreeMem(resident, SizeOf(TFLAGS));
        FreeMem(eflags, SizeOf(TFLAGS));
        FreeMem(used, SizeOf(TFLAGS));
END;

PROCEDURE MkDef(fname : STRING; imports : BOOLEAN);
VAR     f       : BFILE;
        lf      : DWORD;
BEGIN
        Assign(f, fname);
        Reset(f);
        IF NOT IsOpen(f) THEN BEGIN
                System.Writeln('Could not open ', fname, '.');
                Halt(1);
        END;
        IF (FileSize(f) < $40) OR (GetWord(f, 0) <> MZ_SIGN) THEN BEGIN
                System.Writeln(fname, ' is not NE or PE file.');
                Halt(1);
        END;
        lf := GetDWord(f, $3C);
        IF lf + 4 > FileSize(f) THEN BEGIN
                System.Writeln(fname, ' is not NE or PE file.');
                Halt(1);
        END;
        IF GetDWord(f, lf) = PE_MAGIC THEN MkDefPe(f, lf, imports, fname)
        ELSE IF GetWord(f, lf) = NE_SIGN THEN MkDefNe(f, lf, imports)
        ELSE BEGIN
                System.Writeln(fname, ' is not NE or PE file.');
                Halt(1);
        END;
        Close(f);
END;

CONST
ARG_OUTPUT  = 'o';
ARG_IMPORTS = 'imp';

OPTIONS_DESC : ARRAY[0..1] OF TOPT = (
(name: ARG_OUTPUT;  otype: OPTSTR;  help: 'Set output def-file name (default: console).'),
(name: ARG_IMPORTS; otype: OPTBOOL; help: 'Write IMPORTS section (for linking with this dll) instead of EXPORTS.')
);

VAR     myArgs   : TARGSTATE;
        outfname : STRING;
BEGIN
        ArgsParse(myArgs, OPTIONS_DESC);
        outfname := GetOptStr(myArgs, ARG_OUTPUT);
        IF ArgsCount(myArgs) <> 1 THEN SetArgsErr(myArgs, 'No input file.');
        WriteArgsErrors(myArgs);
        IF ArgsError(myArgs) THEN Halt(1);
        o_open := FALSE;
        IF Length(outfname) > 0 THEN BEGIN
                Assign(o, outfname);
                ReWrite(o);
                o_open := IsOpen(o);
                IF NOT o_open THEN BEGIN
                        System.Writeln('Could not create ', outfname, '.');
                        Halt(1);
                END;
        END;
        MkDef(GetArgsStr(myArgs, 1), GetOptBool(myArgs, ARG_IMPORTS));
        IF o_open THEN Close(o);
END.
