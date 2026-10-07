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
UNIT rlomap;

INTERFACE

USES system2, rdffmt, rlo;

FUNCTION MapNameFor(out_name : STRING) : STRING;
FUNCTION MapWrite(VAR build_plan : IMAGE_BUILD_PLAN;
        map_name   : STRING;
        out_name   : STRING;
        fmt        : STRING;
        entry_name : RDFNAME) : BOOLEAN;

IMPLEMENTATION

CONST
MAX_SORT = 8000;

TYPE
PSORTEXP = ^TSORTEXP;
TSORTEXP = ARRAY [1..MAX_SORT] OF PLINK_EXPORT;
PSORTKEY = ^TSORTKEY;
TSORTKEY = ARRAY [1..MAX_SORT] OF LONGINT;

FUNCTION Hex(v : DWORD; n : INTEGER) : STRING;
CONST HEXD : STRING[16] = '0123456789ABCDEF';
VAR     s : STRING;
        i : INTEGER;
BEGIN
        s := '';
        FOR i := n DOWNTO 1 DO
                s := s + HEXD[((v SHR ((i - 1) * 4)) AND 15) + 1];
        Hex := s;
END;

FUNCTION PadR(s : STRING; n : INTEGER) : STRING;
BEGIN
        WHILE Length(s) < n DO s := s + ' ';
        PadR := s;
END;

FUNCTION MapNameFor(out_name : STRING) : STRING;
VAR     i, p : INTEGER;
BEGIN
        p := 0;
        FOR i := 1 TO Length(out_name) DO BEGIN
                IF out_name[i] = '.' THEN p := i
                ELSE IF out_name[i] IN ['\', '/', ':'] THEN p := 0;
        END;
        IF p = 0 THEN MapNameFor := out_name + '.MAP'
        ELSE MapNameFor := Copy(out_name, 1, p - 1) + '.MAP';
END;

FUNCTION AreaName(k : INTEGER) : STRING;
BEGIN
        CASE k OF
        0 : AreaName := 'CODE';
        1 : AreaName := 'DATA';
        ELSE AreaName := 'BSS';
        END;
END;

FUNCTION BssSize(VAR build_plan : IMAGE_BUILD_PLAN; r : PRDFMETA) : DWORD;
VAR     s : STRING;
        n : DWORD;
BEGIN
        n := 0;
        Seek(build_plan.hdr, r^.hdr_ofs);
        WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO GET_BSS(s, n);
        BssSize := n;
END;

FUNCTION AreaOfs(r : PRDFMETA; k : INTEGER) : DWORD;
BEGIN
        AreaOfs := 0;
        IF MapKind = MAP_FLAT THEN BEGIN
                CASE k OF
                0 : AreaOfs := r^.linker.smz_code_ofs;
                1 : AreaOfs := r^.linker.smz_data_ofs;
                ELSE AreaOfs := r^.linker.smz_bss_ofs;
                END;
        END;
END;

FUNCTION AreaAddr(r : PRDFMETA; k : INTEGER; ofs : DWORD; VAR key : LONGINT) : STRING;
VAR     seg : DWORD;
        o   : DWORD;
BEGIN
        IF MapKind = MAP_SEG THEN BEGIN
                seg := r^.linker.map_seg[k];
                o := r^.linker.map_ofs[k] + ofs;
                key := (seg * 65536 + o) XOR $80000000;
                AreaAddr := Hex(seg, 4) + ':' + Hex(o, MapDigits);
        END ELSE BEGIN
                o := MapBase[k] + ofs;
                IF MapSegNo[k] >= 0 THEN BEGIN
                        key := MapSegNo[k] * 16777216 + o;
                        AreaAddr := Hex(MapSegNo[k], 4) + ':' + Hex(o, MapDigits);
                END ELSE BEGIN
                        key := MapImage + o;
                        AreaAddr := Hex(MapImage + o, MapDigits);
                END;
        END;
END;

FUNCTION ExpArea(e : PLINK_EXPORT) : INTEGER;
VAR     r : PRDFMETA;
        a : INTEGER;
BEGIN
        ExpArea := -1;
        r := e^.rdf;
        IF MapKind = MAP_FLAT THEN BEGIN
                IF e^.rec.seg <= 2 THEN ExpArea := e^.rec.seg;
        END ELSE BEGIN
                a := AreaKind(r, e^.rec.seg);
                IF a <= 2 THEN ExpArea := a;
        END;
END;

PROCEDURE WriteModule(VAR o : BFILE; VAR build_plan : IMAGE_BUILD_PLAN; r : PRDFMETA);
VAR     sizes  : ARRAY [0..2] OF DWORD;
        k, n   : INTEGER;
        i, j   : INTEGER;
        key    : LONGINT;
        exps   : PEXPORTS;
        arr    : PSORTEXP;
        keys   : PSORTKEY;
        a      : INTEGER;
        cap    : INTEGER;
BEGIN
        sizes[0] := r^.code_size;
        sizes[1] := r^.data_size;
        sizes[2] := BssSize(build_plan, r);
        WriteLn(o, '');
        WriteLn(o, ModLabel(r));
        FOR k := 0 TO 2 DO IF sizes[k] > 0 THEN
                WriteLn(o, '  ' + PadR(AreaName(k), 6) + AreaAddr(r, k, AreaOfs(r, k), key)
                        + '  size ' + Hex(sizes[k], 8));
        n := 0;
        exps := r^.linker.export;
        WHILE exps <> NIL DO BEGIN
                Inc(n, exps^.export_count);
                exps := exps^.next;
        END;
        IF n = 0 THEN EXIT;
        IF n > MAX_SORT THEN n := MAX_SORT;
        cap := n;
        arr := PSORTEXP(AllocZero(cap * SizeOf(PLINK_EXPORT)));
        keys := PSORTKEY(AllocZero(cap * SizeOf(LONGINT)));
        n := 0;
        exps := r^.linker.export;
        WHILE exps <> NIL DO BEGIN
                FOR i := 1 TO exps^.export_count DO BEGIN
                        IF n >= MAX_SORT THEN BREAK;
                        a := ExpArea(@exps^.export[i]);
                        IF a < 0 THEN CONTINUE;
                        AreaAddr(r, a, exps^.export[i].rec.offset, key);
                        j := n;
                        WHILE (j >= 1) AND (keys^[j] > key) DO BEGIN
                                arr^[j + 1] := arr^[j];
                                keys^[j + 1] := keys^[j];
                                Dec(j);
                        END;
                        arr^[j + 1] := @exps^.export[i];
                        keys^[j + 1] := key;
                        Inc(n);
                END;
                exps := exps^.next;
        END;
        FOR i := 1 TO n DO BEGIN
                a := ExpArea(arr^[i]);
                WriteLn(o, '    ' + AreaAddr(r, a, arr^[i]^.rec.offset, key) + '  '
                        + PadR(AreaName(a), 5) + SymName(arr^[i]^.rec.sym)^);
        END;
        FreeMem(arr, cap * SizeOf(PLINK_EXPORT));
        FreeMem(keys, cap * SizeOf(LONGINT));
END;

FUNCTION MapWrite(VAR build_plan : IMAGE_BUILD_PLAN;
        map_name   : STRING;
        out_name   : STRING;
        fmt        : STRING;
        entry_name : RDFNAME) : BOOLEAN;
VAR     o     : BFILE;
        r     : PRDFMETA;
        start : PLINK_EXPORT;
        a     : INTEGER;
        key   : LONGINT;
BEGIN
        Assign(o, map_name);
        ReWrite(o);
        IF NOT IsOpen(o) THEN BEGIN
                System.Writeln('Could not create ', map_name, '.');
                MapWrite := TRUE;
                EXIT;
        END;
        WriteLn(o, 'Output : ' + out_name);
        WriteLn(o, 'Format : ' + fmt);
        start := FindExportRdf(build_plan, entry_name);
        IF start <> NIL THEN BEGIN
                a := ExpArea(start);
                IF a >= 0 THEN
                        WriteLn(o, 'Entry  : ' + entry_name + ' = '
                                + AreaAddr(start^.rdf, a, start^.rec.offset, key));
        END;
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                IF r^.qbimp THEN BEGIN
                        WriteLn(o, '');
                        WriteLn(o, '(generated imports)');
                END ELSE WriteModule(o, build_plan, r);
                r := r^.next;
        END;
        Close(o);
        MapWrite := FALSE;
END;

END.
