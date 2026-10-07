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
UNIT rlodef;

INTERFACE

USES system2, rdffmt, exe;

CONST
MAX_EXPORTS  = 200;
MAX_IMPDEF   = 100;
MAX_SEGDEF   = 32;
MAX_ORD      = 2048;
ATTR_PRELOAD = $0040;
ATTR_MOVE    = $0010;
ATTR_DISCARD = $1000;
ATTR_SHARED  = $0020;
ATTR_RO      = $0080;
ATTR_IOPL    = $0400;
ATTR_CONFORM = $0200;

TYPE
TEXPORT = RECORD
        name     : RDFNAME;
        sym      : RDFNAME;
        ordinal  : WORD;
        seg      : WORD;
        ofs      : WORD;
        resident : BOOLEAN;
        noname   : BOOLEAN;
        nodata   : BOOLEAN;
        parms    : BYTE;
END;

PEXPARR = ^TEXPARR;
TEXPARR = ARRAY [1..MAX_EXPORTS] OF TEXPORT;

TIMPDEF = RECORD
        sym      : RDFNAME;
        modname  : STRING[32];
        procname : STRING[64];
        ordinal  : WORD;
END;

PIMPARR = ^TIMPARR;
TIMPARR = ARRAY [1..MAX_IMPDEF] OF TIMPDEF;

TSEGDEF = RECORD
        stem     : STRING[16];
        isdata   : BOOLEAN;
        attr     : WORD;
END;

VAR
exps      : PEXPARR;
exp_count : INTEGER;
imps      : PIMPARR;
imp_count : INTEGER;
segdefs   : ARRAY [1..MAX_SEGDEF] OF TSEGDEF;
segdef_count : INTEGER;
def_name  : STRING;
def_descr : STRING;
def_stub  : STRING;
is_dll    : BOOLEAN;
def_apptype : BYTE;
def_apptype_set : BOOLEAN;
def_initg : BOOLEAN;
def_os    : BYTE;
def_ver   : WORD;
def_prot  : BOOLEAN;
def_heap  : LONGINT;
def_stack : LONGINT;
def_dgrp  : INTEGER;
code_attr : WORD;
data_attr : WORD;

FUNCTION UpStr(s : STRING) : STRING;
PROCEDURE DefInit;
PROCEDURE DefDone;
FUNCTION ParseDef(fname : STRING) : BOOLEAN;
FUNCTION FindDefImport(VAR name : RDFNAME; VAR modname : STRING; VAR ordnum : WORD; VAR procname : STRING) : BOOLEAN;

IMPLEMENTATION

FUNCTION UpStr(s : STRING) : STRING;
VAR     i : INTEGER;
BEGIN
        FOR i := 1 TO Length(s) DO s[i] := UpCase(s[i]);
        UpStr := s;
END;

FUNCTION Trim(s : STRING) : STRING;
BEGIN
        WHILE (Length(s) > 0) AND (s[1] IN [' ', #9]) DO Delete(s, 1, 1);
        WHILE (Length(s) > 0) AND (s[Length(s)] IN [' ', #9, #13, #10]) DO Dec(s[0]);
        Trim := s;
END;

FUNCTION NextWord(VAR s : STRING) : STRING;
VAR     p : INTEGER;
BEGIN
        s := Trim(s);
        p := 1;
        WHILE (p <= Length(s)) AND (NOT (s[p] IN [' ', #9])) DO Inc(p);
        NextWord := Copy(s, 1, p - 1);
        Delete(s, 1, p - 1);
        s := Trim(s);
END;

FUNCTION ParseNum(s : STRING; VAR v : LONGINT) : BOOLEAN;
VAR     code : INTEGER;
BEGIN
        s := UpStr(s);
        IF Copy(s, 1, 2) = '0X' THEN s := '$' + Copy(s, 3, 255);
        Val(s, v, code);
        ParseNum := (code = 0) AND (v >= 0);
END;

FUNCTION AttrKw(VAR a : WORD; w : STRING) : BOOLEAN;
BEGIN
        AttrKw := TRUE;
        w := UpStr(w);
        IF w = 'PRELOAD' THEN a := a OR ATTR_PRELOAD
        ELSE IF w = 'LOADONCALL' THEN a := a AND $FFBF
        ELSE IF w = 'MOVEABLE' THEN a := a OR ATTR_MOVE
        ELSE IF w = 'FIXED' THEN a := a AND $FFEF
        ELSE IF w = 'DISCARDABLE' THEN a := a OR ATTR_DISCARD
        ELSE IF w = 'NONDISCARDABLE' THEN a := a AND $EFFF
        ELSE IF (w = 'SHARED') OR (w = 'PURE') THEN a := a OR ATTR_SHARED
        ELSE IF (w = 'NONSHARED') OR (w = 'IMPURE') THEN a := a AND $FFDF
        ELSE IF (w = 'EXECUTEONLY') OR (w = 'READONLY') THEN a := a OR ATTR_RO
        ELSE IF (w = 'EXECUTEREAD') OR (w = 'READWRITE') THEN a := a AND $FF7F
        ELSE IF w = 'IOPL' THEN a := a OR ATTR_IOPL
        ELSE IF w = 'NOIOPL' THEN a := a AND $FBFF
        ELSE IF w = 'CONFORMING' THEN a := a OR ATTR_CONFORM
        ELSE IF w = 'NONCONFORMING' THEN a := a AND $FDFF
        ELSE AttrKw := FALSE;
END;

FUNCTION Unquote(s : STRING) : STRING;
BEGIN
        s := Trim(s);
        IF (Length(s) > 1) AND (s[1] IN ['''', '"']) AND (s[Length(s)] = s[1]) THEN BEGIN
                Delete(s, 1, 1);
                Dec(s[0]);
        END;
        Unquote := s;
END;

FUNCTION ParseExportLine(fname : STRING; w, s : STRING) : BOOLEAN;
VAR     p    : INTEGER;
        v    : LONGINT;
        u    : STRING;
        ex   : ^TEXPORT;
BEGIN
        ParseExportLine := TRUE;
        IF exp_count >= MAX_EXPORTS THEN BEGIN
                System.Writeln('Too many exports.');
                EXIT;
        END;
        Inc(exp_count);
        ex := @exps^[exp_count];
        FillChar(ex^, SizeOf(TEXPORT), #0);
        p := Pos('=', w);
        IF p > 0 THEN BEGIN
                ex^.name := Copy(w, 1, p - 1);
                ex^.sym := Copy(w, p + 1, 255);
        END ELSE BEGIN
                ex^.name := w;
                ex^.sym := w;
        END;
        WHILE Length(s) > 0 DO BEGIN
                w := NextWord(s);
                u := UpStr(w);
                IF u = 'RESIDENTNAME' THEN ex^.resident := TRUE
                ELSE IF u = 'NONAME' THEN ex^.noname := TRUE
                ELSE IF u = 'NODATA' THEN ex^.nodata := TRUE
                ELSE IF (u = 'PRIVATE') OR (u = 'DATA') OR (u = 'CONSTANT') THEN BEGIN
                END ELSE IF (w[1] = '@') AND ParseNum(Copy(w, 2, 255), v) AND (v >= 1) AND (v <= MAX_ORD) THEN
                        ex^.ordinal := v
                ELSE IF ParseNum(w, v) AND (v <= 31) THEN ex^.parms := v
                ELSE BEGIN
                        System.Writeln(fname, ': bad export attribute ', w);
                        EXIT;
                END;
        END;
        IF ex^.noname AND (ex^.ordinal = 0) THEN BEGIN
                System.Writeln(fname, ': NONAME export ', ex^.name, ' needs an ordinal.');
                EXIT;
        END;
        ParseExportLine := FALSE;
END;

FUNCTION ParseImportLine(fname : STRING; w : STRING) : BOOLEAN;
VAR     i    : INTEGER;
        p    : INTEGER;
        v    : LONGINT;
        sym  : STRING;
        rest : STRING;
BEGIN
        ParseImportLine := TRUE;
        IF imp_count >= MAX_IMPDEF THEN BEGIN
                System.Writeln('Too many imports.');
                EXIT;
        END;
        sym := '';
        p := Pos('=', w);
        IF p > 0 THEN BEGIN
                sym := Copy(w, 1, p - 1);
                w := Copy(w, p + 1, 255);
        END;
        p := 0;
        FOR i := 1 TO Length(w) DO IF w[i] = '.' THEN p := i;
        IF (p < 2) OR (p = Length(w)) THEN BEGIN
                System.Writeln(fname, ': bad import ', w);
                EXIT;
        END;
        rest := Copy(w, p + 1, 255);
        w := Copy(w, 1, p - 1);
        IF (Length(w) > 4) AND (UpStr(Copy(w, Length(w) - 3, 4)) = '.DLL') THEN w[0] := CHR(Length(w) - 4);
        Inc(imp_count);
        FillChar(imps^[imp_count], SizeOf(TIMPDEF), #0);
        imps^[imp_count].modname := UpStr(w);
        IF ParseNum(rest, v) THEN BEGIN
                IF (v < 1) OR (v > 65535) THEN BEGIN
                        System.Writeln(fname, ': bad ordinal in ', w);
                        EXIT;
                END;
                imps^[imp_count].ordinal := v;
                IF Length(sym) = 0 THEN BEGIN
                        System.Writeln(fname, ': import ', w, ' needs an internal name.');
                        EXIT;
                END;
        END ELSE BEGIN
                imps^[imp_count].procname := rest;
                IF Length(sym) = 0 THEN sym := rest;
        END;
        imps^[imp_count].sym := sym;
        ParseImportLine := FALSE;
END;

FUNCTION ParseSegLine(fname : STRING; w, s : STRING) : BOOLEAN;
VAR     a      : WORD;
        isdata : BOOLEAN;
        u      : STRING;
BEGIN
        ParseSegLine := TRUE;
        IF segdef_count >= MAX_SEGDEF THEN BEGIN
                System.Writeln('Too many SEGMENTS entries.');
                EXIT;
        END;
        isdata := FALSE;
        a := 0;
        WHILE Length(s) > 0 DO BEGIN
                u := UpStr(NextWord(s));
                IF u = 'CLASS' THEN BEGIN
                        u := UpStr(Unquote(NextWord(s)));
                        isdata := Pos('DATA', u) > 0;
                END ELSE IF a = 0 THEN BEGIN
                        IF isdata THEN a := data_attr ELSE a := code_attr;
                        IF NOT AttrKw(a, u) THEN BEGIN
                                System.Writeln(fname, ': bad segment attribute ', u);
                                EXIT;
                        END;
                END ELSE IF NOT AttrKw(a, u) THEN BEGIN
                        System.Writeln(fname, ': bad segment attribute ', u);
                        EXIT;
                END;
        END;
        IF a = 0 THEN BEGIN
                IF isdata THEN a := data_attr ELSE a := code_attr;
        END;
        Inc(segdef_count);
        segdefs[segdef_count].stem := UpStr(w);
        segdefs[segdef_count].isdata := isdata;
        segdefs[segdef_count].attr := a;
        ParseSegLine := FALSE;
END;

FUNCTION ParseDef(fname : STRING) : BOOLEAN;
VAR     f       : BFILE;
        s, w, u : STRING;
        mode    : INTEGER;
        v       : LONGINT;
        p       : INTEGER;
        err     : BOOLEAN;
        got_nm  : BOOLEAN;
        d1, d2  : LONGINT;
BEGIN
        err := FALSE;
        mode := 0;
        Assign(f, fname);
        Reset(f);
        IF NOT IsOpen(f) THEN BEGIN
                System.Writeln('Could not open ', fname, '.');
                ParseDef := TRUE;
                EXIT;
        END;
        WHILE (NOT err) AND (NOT Eof(f)) DO BEGIN
                ReadLn(f, s);
                s := Trim(s);
                IF Length(s) = 0 THEN CONTINUE;
                w := NextWord(s);
                u := UpStr(w);
                IF u <> 'DESCRIPTION' THEN BEGIN
                        p := Pos(';', s);
                        IF p > 0 THEN s := Trim(Copy(s, 1, p - 1));
                        IF w[1] = ';' THEN CONTINUE;
                END;
                IF u = 'DESCRIPTION' THEN BEGIN
                        mode := 0;
                        def_descr := Unquote(s);
                END ELSE IF (u = 'NAME') OR (u = 'LIBRARY') THEN BEGIN
                        mode := 0;
                        is_dll := u = 'LIBRARY';
                        got_nm := FALSE;
                        WHILE Length(s) > 0 DO BEGIN
                                w := NextWord(s);
                                u := UpStr(w);
                                IF u = 'WINDOWAPI' THEN BEGIN def_apptype := 3; def_apptype_set := TRUE; END
                                ELSE IF u = 'WINDOWCOMPAT' THEN BEGIN def_apptype := 2; def_apptype_set := TRUE; END
                                ELSE IF u = 'NOTWINDOWCOMPAT' THEN BEGIN def_apptype := 1; def_apptype_set := TRUE; END
                                ELSE IF u = 'INITGLOBAL' THEN def_initg := TRUE
                                ELSE IF u = 'INITINSTANCE' THEN def_initg := FALSE
                                ELSE IF NOT got_nm THEN BEGIN
                                        def_name := u;
                                        got_nm := TRUE;
                                END ELSE BEGIN
                                        System.Writeln(fname, ': unknown option ', w);
                                        err := TRUE;
                                END;
                        END;
                END ELSE IF u = 'EXPORTS' THEN BEGIN
                        mode := 1;
                        IF Length(s) > 0 THEN BEGIN
                                w := NextWord(s);
                                err := ParseExportLine(fname, w, s);
                        END;
                END ELSE IF u = 'IMPORTS' THEN BEGIN
                        mode := 2;
                        IF Length(s) > 0 THEN BEGIN
                                w := NextWord(s);
                                err := ParseImportLine(fname, w);
                        END;
                END ELSE IF u = 'SEGMENTS' THEN BEGIN
                        mode := 3;
                        IF Length(s) > 0 THEN BEGIN
                                w := NextWord(s);
                                err := ParseSegLine(fname, w, s);
                        END;
                END ELSE IF u = 'CODE' THEN BEGIN
                        mode := 0;
                        WHILE (Length(s) > 0) AND (NOT err) DO BEGIN
                                w := NextWord(s);
                                IF NOT AttrKw(code_attr, w) THEN BEGIN
                                        System.Writeln(fname, ': bad CODE attribute ', w);
                                        err := TRUE;
                                END;
                        END;
                END ELSE IF u = 'DATA' THEN BEGIN
                        mode := 0;
                        WHILE (Length(s) > 0) AND (NOT err) DO BEGIN
                                w := NextWord(s);
                                u := UpStr(w);
                                IF u = 'NONE' THEN def_dgrp := 0
                                ELSE IF u = 'SINGLE' THEN def_dgrp := 1
                                ELSE IF u = 'MULTIPLE' THEN def_dgrp := 2
                                ELSE IF NOT AttrKw(data_attr, w) THEN BEGIN
                                        System.Writeln(fname, ': bad DATA attribute ', w);
                                        err := TRUE;
                                END;
                        END;
                END ELSE IF u = 'STUB' THEN BEGIN
                        mode := 0;
                        def_stub := Unquote(s);
                        IF UpStr(def_stub) = 'NONE' THEN BEGIN
                                System.Writeln(fname, ': STUB NONE is not supported.');
                                err := TRUE;
                        END;
                END ELSE IF u = 'EXETYPE' THEN BEGIN
                        mode := 0;
                        w := UpStr(NextWord(s));
                        IF w = 'WINDOWS' THEN def_os := 2
                        ELSE IF w = 'OS2' THEN def_os := 1
                        ELSE IF w = 'DOS4' THEN def_os := 3
                        ELSE IF w = 'UNKNOWN' THEN def_os := 0
                        ELSE BEGIN
                                System.Writeln(fname, ': unknown EXETYPE ', w);
                                err := TRUE;
                        END;
                        w := NextWord(s);
                        IF (NOT err) AND (Length(w) > 0) THEN BEGIN
                                p := Pos('.', w);
                                IF (p = 0) OR (NOT ParseNum(Copy(w, 1, p - 1), d1))
                                        OR (NOT ParseNum(Copy(w, p + 1, 255), d2)) OR (d1 > 255) OR (d2 > 255) THEN BEGIN
                                        System.Writeln(fname, ': bad EXETYPE version ', w);
                                        err := TRUE;
                                END ELSE def_ver := (d1 SHL 8) OR d2;
                        END;
                END ELSE IF u = 'PROTMODE' THEN BEGIN
                        mode := 0;
                        def_prot := TRUE;
                END ELSE IF u = 'REALMODE' THEN BEGIN
                        mode := 0;
                        def_prot := FALSE;
                END ELSE IF (u = 'HEAPSIZE') OR (u = 'STACKSIZE') THEN BEGIN
                        mode := 0;
                        w := NextWord(s);
                        p := Pos(',', w);
                        IF p > 0 THEN w := Copy(w, 1, p - 1);
                        IF (NOT ParseNum(w, v)) OR (v > $FFFF) THEN BEGIN
                                System.Writeln(fname, ': bad size ', w);
                                err := TRUE;
                        END ELSE IF u = 'HEAPSIZE' THEN def_heap := v
                        ELSE def_stack := v;
                END ELSE IF u = 'OLD' THEN BEGIN
                        mode := 0;
                END ELSE IF mode = 1 THEN BEGIN
                        err := ParseExportLine(fname, w, s);
                END ELSE IF mode = 2 THEN BEGIN
                        err := ParseImportLine(fname, w);
                END ELSE IF mode = 3 THEN BEGIN
                        err := ParseSegLine(fname, w, s);
                END ELSE BEGIN
                        System.Writeln(fname, ': unknown statement ', w);
                        err := TRUE;
                END;
        END;
        Close(f);
        ParseDef := err;
END;

PROCEDURE DefInit;
BEGIN
        IF exps <> NIL THEN DefDone;
        exp_count := 0;
        imp_count := 0;
        segdef_count := 0;
        def_name := '';
        def_descr := '';
        def_stub := '';
        is_dll := FALSE;
        def_apptype := 3;
        def_apptype_set := FALSE;
        def_initg := FALSE;
        def_os := NE_OS_OS2;
        def_ver := $0300;
        def_prot := TRUE;
        def_heap := 0;
        def_stack := -1;
        def_dgrp := -1;
        code_attr := NE_SEG_MOVEABLE OR NE_SEG_DISCARD OR NE_SEG_DPL3;
        data_attr := NE_SEG_DATA OR NE_SEG_PRELOAD OR NE_SEG_DPL3;
        GetMem(exps, SizeOf(TEXPARR));
        GetMem(imps, SizeOf(TIMPARR));
END;

PROCEDURE DefDone;
BEGIN
        IF exps <> NIL THEN FreeMem(exps, SizeOf(TEXPARR));
        IF imps <> NIL THEN FreeMem(imps, SizeOf(TIMPARR));
        exps := NIL;
        imps := NIL;
END;

FUNCTION FindDefImport(VAR name : RDFNAME; VAR modname : STRING; VAR ordnum : WORD; VAR procname : STRING) : BOOLEAN;
VAR     i : INTEGER;
BEGIN
        FindDefImport := FALSE;
        procname := '';
        FOR i := 1 TO imp_count DO IF imps^[i].sym = name THEN BEGIN
                modname := imps^[i].modname;
                ordnum := imps^[i].ordinal;
                procname := imps^[i].procname;
                FindDefImport := TRUE;
                EXIT;
        END;
END;

BEGIN
        exps := NIL;
        imps := NIL;
END.
