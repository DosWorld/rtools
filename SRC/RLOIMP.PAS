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
UNIT RloImp;
INTERFACE
USES System2, RdfFmt, Rlo, RloDef;
FUNCTION WpIsImport(VAR name: RDFNAME): BOOLEAN;
FUNCTION WpBuildImports(VAR rdf: BFILE;
  VAR err: BOOLEAN): BOOLEAN;
FUNCTION FindGlobal(VAR hdr: BFILE; VAR name: RDFNAME;
  VAR rec: REXP_REC): BOOLEAN;
FUNCTION SymRva(VAR hdr: BFILE; VAR name: RDFNAME;
  co, da, bs: DWORD; VAR rva: DWORD): BOOLEAN;
FUNCTION BuildImports(VAR hdr, o: BFILE; rva, co, da,
  bs: DWORD; VAR dirsize, iat_rva, iat_size: DWORD): BOOLEAN;
PROCEDURE WriteAsciiz(VAR o: BFILE; s: STRING);
PROCEDURE PadTo(VAR o: BFILE; align: DWORD);
IMPLEMENTATION

PROCEDURE WriteAsciiz(VAR o: BFILE; s: STRING);
BEGIN Write(o, s + #0); END;
PROCEDURE PadTo(VAR o: BFILE; align: DWORD);
BEGIN
  WHILE (FilePos(o) MOD align) <> 0 DO WriteByte(o, 0);
END;

FUNCTION WpIsImport(VAR name: RDFNAME): BOOLEAN;
VAR i: INTEGER;
BEGIN
  WpIsImport := FALSE;
  FOR i := 1 TO imp_count DO
    IF (name = ImpAt(i)^.sym) OR
      (name = '__imp_' + ImpAt(i)^.sym) THEN BEGIN
      ImpAt(i)^.used := TRUE;
      WpIsImport := TRUE; EXIT;
    END;
END;

FUNCTION WpBuildImports(VAR rdf: BFILE;
  VAR err: BOOLEAN): BOOLEAN;
VAR code, data, hdr: BFILE; er: REXP_REC; rr: RRELOC_REC;
  s: STRING; i, j, live: INTEGER; pos: DWORD;
BEGIN
  WpBuildImports := FALSE; live := 0;
  FOR i := 1 TO imp_count DO BEGIN
    ImpAt(i)^.firstmod := 0;
    IF ImpAt(i)^.used THEN BEGIN
      Inc(live);
      IF Length(ImpAt(i)^.sym) > 58 THEN BEGIN
        System.Writeln('PE import alias exceeds 58 bytes.');
        err := TRUE; EXIT;
      END;
    END;
  END;
  IF live = 0 THEN EXIT;
  FillChar(code, SizeOf(code), 0);
  FillChar(data, SizeOf(data), 0);
  FillChar(hdr, SizeOf(hdr), 0);
  ReWriteTemp(code); ReWriteTemp(data);
  ReWriteTemp(hdr); ReWriteTemp(rdf);
  err := NOT (IsOpen(code) AND IsOpen(data)
    AND IsOpen(hdr) AND IsOpen(rdf));
  IF NOT err THEN BEGIN
    pos := 0;
    FOR i := 1 TO imp_count DO
      IF ImpAt(i)^.used AND
        (ImpAt(i)^.firstmod = 0) THEN BEGIN
        FOR j := i TO imp_count DO
          IF ImpAt(j)^.used AND
            (ImpAt(j)^.modname = ImpAt(i)^.modname)
            THEN BEGIN
            ImpAt(j)^.firstmod := i;
            ImpAt(j)^.slotofs := pos;
            Inc(pos, 4);
          END;
        Inc(pos, 4);
      END;
    WHILE FilePos(data) < pos DO WriteDWord(data, 0);
    FOR i := 1 TO imp_count DO IF ImpAt(i)^.used THEN BEGIN
      FillChar(er, SizeOf(er), 0);
      er.name := ImpAt(i)^.sym;
      er.offset := FilePos(code);
      SET_EXPORT_REC(er, s);
      RDF_WRITE_REC(hdr, RREC_GLOBAL, s);
      er.name := '__imp_' + ImpAt(i)^.sym;
      er.seg := 1; er.offset := ImpAt(i)^.slotofs;
      SET_EXPORT_REC(er, s);
      RDF_WRITE_REC(hdr, RREC_GLOBAL, s);
      FillChar(rr, SizeOf(rr), 0);
      rr.offset := FilePos(code) + 2;
      rr.width := 4; rr.rseg := 1;
      SET_RELOC_REC(rr, s);
      RDF_WRITE_REC(hdr, RREC_RELOC, s);
      WriteByte(code, $FF); WriteByte(code, $25);
      WriteDWord(code, ImpAt(i)^.slotofs);
    END;
    WRITE_RDF(hdr, 0, code, 1, data, rdf);
    Flush(rdf);
    err := (code.werror <> 0) OR (data.werror <> 0)
      OR (hdr.werror <> 0) OR (rdf.werror <> 0);
  END;
  Close(hdr); Close(data); Close(code);
  IF err THEN BEGIN
    IF IsOpen(rdf) THEN Close(rdf);
    System.Writeln('Could not build PE imports.');
  END;
  WpBuildImports := NOT err;
END;

FUNCTION FindGlobal(VAR hdr: BFILE; VAR name: RDFNAME;
  VAR rec: REXP_REC): BOOLEAN;
VAR s: STRING;
BEGIN
  FindGlobal := FALSE; Seek(hdr, 0);
  WHILE RDF_LOOKUPREC(hdr, RREC_GLOBAL, s) DO BEGIN
    GET_EXPORT_REC(s, rec);
    IF rec.name = name THEN BEGIN
      FindGlobal := TRUE; EXIT;
    END;
  END;
END;

FUNCTION SymRva(VAR hdr: BFILE; VAR name: RDFNAME;
  co, da, bs: DWORD; VAR rva: DWORD): BOOLEAN;
VAR rec: REXP_REC;
BEGIN
  SymRva := FALSE;
  IF NOT FindGlobal(hdr, name, rec) THEN EXIT;
  CASE rec.seg OF
  0: rva := co + rec.offset;
  1: rva := da + rec.offset;
  2: rva := bs + rec.offset;
  ELSE EXIT;
  END;
  SymRva := TRUE;
END;

FUNCTION BuildImports(VAR hdr, o: BFILE; rva, co, da,
  bs: DWORD; VAR dirsize, iat_rva, iat_size: DWORD): BOOLEAN;
VAR i, j, nmods, cnt: INTEGER; pos: DWORD; nm: RDFNAME;
BEGIN
  BuildImports := FALSE; dirsize := 0;
  iat_rva := 0; iat_size := 0; nmods := 0;
  FOR i := 1 TO imp_count DO IF ImpAt(i)^.used THEN BEGIN
    nm := '__imp_' + ImpAt(i)^.sym;
    IF NOT SymRva(hdr, nm, co, da, bs,
      ImpAt(i)^.slotrva) THEN EXIT;
    IF ImpAt(i)^.firstmod = i THEN Inc(nmods);
  END;
  IF nmods = 0 THEN EXIT;
  iat_rva := $7FFFFFFF;
  FOR i := 1 TO imp_count DO IF ImpAt(i)^.used THEN BEGIN
    IF ImpAt(i)^.slotrva < iat_rva THEN
      iat_rva := ImpAt(i)^.slotrva;
    IF ImpAt(i)^.slotrva + 8 > iat_size THEN
      iat_size := ImpAt(i)^.slotrva + 8;
  END;
  iat_size := iat_size - iat_rva;
  pos := (LONGINT(nmods) + 1) * 20;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.firstmod = i) THEN
      BEGIN
      cnt := 0;
      FOR j := 1 TO imp_count DO
        IF ImpAt(j)^.used AND
          (ImpAt(j)^.firstmod = i) THEN Inc(cnt);
      ImpAt(i)^.iltrva := rva + pos;
      Inc(pos, (LONGINT(cnt) + 1) * 4);
    END;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.procname <> '') THEN
      BEGIN
      ImpAt(i)^.namerva := rva + pos;
      Inc(pos, 3 + Length(ImpAt(i)^.procname));
      IF (pos AND 1) <> 0 THEN Inc(pos);
    END;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.firstmod = i) THEN
      BEGIN
      ImpAt(i)^.dllrva := rva + pos;
      Inc(pos, Length(ImpAt(i)^.modname) + 5);
    END;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.firstmod = i) THEN
      BEGIN
      WriteDWord(o, ImpAt(i)^.iltrva);
      WriteDWord(o, 0); WriteDWord(o, 0);
      WriteDWord(o, ImpAt(i)^.dllrva);
      WriteDWord(o, ImpAt(i)^.slotrva);
    END;
  FOR i := 1 TO 5 DO WriteDWord(o, 0);
  dirsize := (LONGINT(nmods) + 1) * 20;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.firstmod = i) THEN
      BEGIN
      FOR j := 1 TO imp_count DO
        IF ImpAt(j)^.used AND
          (ImpAt(j)^.firstmod = i) THEN BEGIN
          IF ImpAt(j)^.procname <> '' THEN
            WriteDWord(o, ImpAt(j)^.namerva)
          ELSE WriteDWord(o,
            $80000000 OR ImpAt(j)^.ordinal);
        END;
      WriteDWord(o, 0);
    END;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.procname <> '') THEN
      BEGIN
      WriteWord(o, 0);
      WriteAsciiz(o, ImpAt(i)^.procname); PadTo(o, 2);
    END;
  FOR i := 1 TO imp_count DO
    IF ImpAt(i)^.used AND (ImpAt(i)^.firstmod = i) THEN
      WriteAsciiz(o, ImpAt(i)^.modname + '.DLL');
  BuildImports := o.werror = 0;
END;
END.
