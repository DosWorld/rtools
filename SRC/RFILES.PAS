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
UNIT RFiles;
INTERFACE
USES Dos, System2;
FUNCTION SameFile(a, b: STRING): BOOLEAN;
FUNCTION StartOutput(VAR f: BFILE; name: STRING): BOOLEAN;
FUNCTION CommitOutput(VAR f: BFILE; name: STRING): BOOLEAN;
PROCEDURE CancelOutput(VAR f: BFILE);
FUNCTION CloseChecked(VAR f: BFILE): BOOLEAN;
IMPLEMENTATION
USES ExCache;

FUNCTION CloseChecked(VAR f: BFILE): BOOLEAN;
VAR r: Registers; err: INTEGER; remove: BOOLEAN;
  name: STRING;
BEGIN
  CloseChecked := TRUE;
  IF NOT IsOpen(f) THEN EXIT;
  Flush(f); err := f.ioresult;
  remove := f.delonclose; name := f.filename;
  r.AH := $3E; r.BX := f.f;
  Intr($21, r);
  IF (r.Flags AND FCarry) <> 0 THEN err := r.AX;
{$IFNDEF DPMI}
{$IFNDEF WINDOWS}
{$IFNDEF LINUX}
{$IFNDEF OS2}
  excache_free(PEXCACHE(f.rcache));
  excache_free(PEXCACHE(f.wcache));
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
  IF f.buf <> NIL THEN FreeMem(f.buf, SizeOf(BFILE_BUF));
  FillChar(f, SizeOf(f), 0);
  IF remove THEN BEGIN Assign(f, name); Erase(f); END;
  f.ioresult := err;
  CloseChecked := err = 0;
END;

FUNCTION Canonical(name: STRING): STRING;
VAR r: Registers; src, dst: ARRAY[0..259] OF CHAR;
  s: STRING; i: INTEGER;
BEGIN
  FillChar(src, SizeOf(src), 0);
  FillChar(dst, SizeOf(dst), 0);
  Move(name[1], src, Length(name));
  FillChar(r, SizeOf(r), 0);
  r.AX := $7160; r.CX := 1;
  r.DS := Seg(src); r.SI := Ofs(src);
  r.ES := Seg(dst); r.DI := Ofs(dst);
  r.Flags := FCarry;
  Intr($21, r);
  IF (r.Flags AND FCarry) <> 0 THEN BEGIN
    r.AX := $6000;
    r.DS := Seg(src); r.SI := Ofs(src);
    r.ES := Seg(dst); r.DI := Ofs(dst);
    Intr($21, r);
  END;
  s := '';
  IF (r.Flags AND FCarry) = 0 THEN BEGIN
    i := 0;
    WHILE (i < 255) AND (dst[i] <> #0) DO BEGIN
      s := s + UpCase(dst[i]); Inc(i);
    END;
  END ELSE s := FExpand(name);
  FOR i := 1 TO Length(s) DO BEGIN
    IF s[i] = '/' THEN s[i] := '\';
    s[i] := UpCase(s[i]);
  END;
  Canonical := s;
END;

FUNCTION SameFile(a, b: STRING): BOOLEAN;
BEGIN
  SameFile := Canonical(a) = Canonical(b);
END;

FUNCTION SpareName(name: STRING): STRING;
CONST hex: STRING[16] = '0123456789ABCDEF';
VAR dir_, candidate: STRING; i, j: INTEGER; n: WORD;
BEGIN
  i := Length(name);
  WHILE (i > 0) AND (NOT (name[i] IN [':','\','/'])) DO
    Dec(i);
  dir_ := Copy(name, 1, i);
  IF Length(dir_) > 244 THEN BEGIN
    SpareName := ''; EXIT;
  END;
  n := 0;
  REPEAT
    candidate := dir_ + '_RT0000.TMP';
    FOR j := 0 TO 3 DO
      candidate[Length(dir_) + 7 - j] :=
        hex[((n SHR (j * 4)) AND 15) + 1];
    IF NOT FileExists(candidate) THEN BEGIN
      SpareName := candidate; EXIT;
    END;
    Inc(n);
  UNTIL n = 0;
  SpareName := '';
END;

FUNCTION StartOutput(VAR f: BFILE; name: STRING): BOOLEAN;
VAR work: STRING;
BEGIN
  FillChar(f, SizeOf(f), 0);
  work := SpareName(name);
  StartOutput := FALSE;
  IF work = '' THEN EXIT;
  Assign(f, work); ReWrite(f);
  StartOutput := IsOpen(f);
  IF IsOpen(f) THEN SetDeleteOnClose(f, TRUE);
END;

PROCEDURE DeleteName(name: STRING);
VAR f: BFILE;
BEGIN
  Assign(f, name); Erase(f);
END;

PROCEDURE CancelOutput(VAR f: BFILE);
BEGIN
  IF IsOpen(f) THEN BEGIN
    SetDeleteOnClose(f, TRUE); Close(f);
  END;
END;

FUNCTION CommitOutput(VAR f: BFILE; name: STRING): BOOLEAN;
VAR work, backup: STRING; moving: BFILE; had_old: BOOLEAN;
BEGIN
  CommitOutput := FALSE;
  IF NOT IsOpen(f) THEN EXIT;
  work := f.filename;
  Flush(f);
  IF f.ioresult <> 0 THEN BEGIN
    CancelOutput(f); EXIT;
  END;
  SetDeleteOnClose(f, FALSE);
  IF NOT CloseChecked(f) THEN BEGIN
    DeleteName(work); EXIT;
  END;
  had_old := FileExists(name);
  backup := '';
  IF had_old THEN BEGIN
    backup := SpareName(name);
    IF backup = '' THEN BEGIN
      DeleteName(work); EXIT;
    END;
    Assign(moving, name); Rename(moving, backup);
    IF moving.ioresult <> 0 THEN BEGIN
      DeleteName(work); EXIT;
    END;
  END;
  Assign(moving, work); Rename(moving, name);
  IF moving.ioresult <> 0 THEN BEGIN
    IF had_old THEN BEGIN
      Assign(moving, backup); Rename(moving, name);
    END;
    DeleteName(work); EXIT;
  END;
  IF had_old THEN DeleteName(backup);
  CommitOutput := TRUE;
END;
END.
