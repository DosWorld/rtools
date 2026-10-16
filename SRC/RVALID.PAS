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
UNIT RValid;
INTERFACE
USES System2, RdfFmt;
TYPE
  TRdfInfo = RECORD
    finish, hdr_ofs, hdr_size: DWORD;
    code_ofs, data_ofs, code_size, data_size: DWORD;
    bss_size: DWORD;
    cs, ds, bs: WORD;
  END;
FUNCTION CheckRdf(VAR f: BFILE; limit: DWORD;
  VAR info: TRdfInfo): BOOLEAN;
IMPLEMENTATION
TYPE
  PBits = ^TBits;
  TBits = ARRAY[0..8191] OF BYTE;

FUNCTION NameOk(VAR s: STRING; first, maxlen: INTEGER): BOOLEAN;
VAR i: INTEGER;
BEGIN
  NameOk := FALSE;
  IF Length(s) <= first THEN EXIT;
  i := first;
  WHILE (i <= Length(s)) AND (s[i] <> #0) DO Inc(i);
  NameOk := (i = Length(s)) AND (i - first <= maxlen);
END;

FUNCTION Records(VAR f: BFILE; VAR info: TRdfInfo;
  imports: PBits; check_refs: BOOLEAN): BOOLEAN;
VAR rt: CHAR; s: STRING; rr: RRELOC_REC;
  er: REXP_REC; ir: RIMP_REC;
  stop, pos, n, size_: DWORD; id, k: WORD;
BEGIN
  Records := FALSE;
  stop := info.hdr_ofs + info.hdr_size;
  Seek(f, info.hdr_ofs);
  WHILE FilePos(f) < stop DO BEGIN
    pos := FilePos(f);
    IF stop - pos < 2 THEN EXIT;
    rt := Chr(ReadByte(f)); n := ReadByte(f);
    IF n > stop - FilePos(f) THEN EXIT;
    s[0] := Chr(n);
    IF BlockRead(f, s[1], n) <> n THEN EXIT;
    CASE rt OF
    RREC_RELOC, RREC_SEGRELO: BEGIN
      IF n <> 8 THEN EXIT;
      GET_RELOC_REC(s, rr);
      IF NOT (rr.width IN [1,2,4]) THEN EXIT;
      IF (rr.seg AND $80) <> 0 THEN EXIT;
      IF rt = RREC_SEGRELO THEN
        IF (rr.width <> 2) OR
          ((rr.seg AND $40) <> 0) THEN EXIT;
      IF check_refs THEN BEGIN
        k := rr.seg AND $3F;
        IF k = info.cs THEN size_ := info.code_size
        ELSE IF k = info.ds THEN
          size_ := info.data_size
        ELSE EXIT;
        IF (rr.offset < 0) OR
          (size_ < rr.width) THEN EXIT;
        IF rr.offset > size_ - rr.width THEN EXIT;
        id := rr.rseg;
        IF (id <> info.cs) AND (id <> info.ds)
          AND (id <> info.bs) THEN
          IF (imports^[id SHR 3] AND
            (1 SHL (id AND 7))) = 0 THEN EXIT;
      END;
    END;
    RREC_IMPORT, RREC_FARIMPORT: BEGIN
      IF NOT NameOk(s, 4, 64) THEN EXIT;
      GET_IMPORT_REC(s, ir);
      IF NOT check_refs THEN BEGIN
        id := ir.seg;
        IF (imports^[id SHR 3] AND
          (1 SHL (id AND 7))) <> 0 THEN EXIT;
        imports^[id SHR 3] := imports^[id SHR 3]
          OR (1 SHL (id AND 7));
      END ELSE IF (ir.seg = info.cs)
        OR (ir.seg = info.ds)
        OR (ir.seg = info.bs) THEN EXIT;
    END;
    RREC_GLOBAL: BEGIN
      IF NOT NameOk(s, 7, 64) THEN EXIT;
      IF check_refs THEN BEGIN
        GET_EXPORT_REC(s, er);
        IF er.seg = info.cs THEN
          size_ := info.code_size
        ELSE IF er.seg = info.ds THEN
          size_ := info.data_size
        ELSE IF er.seg = info.bs THEN
          size_ := info.bss_size
        ELSE EXIT;
        IF (er.offset < 0) OR
          (er.offset > size_) THEN EXIT;
      END;
    END;
    RREC_BSS: BEGIN
      IF n <> 4 THEN EXIT;
      IF NOT check_refs THEN BEGIN
        size_ := 0; GET_BSS(s, size_);
        IF (size_ < 0) OR
          (size_ > $7FFFFFFF - info.bss_size)
          THEN EXIT;
        Inc(info.bss_size, size_);
      END;
    END;
    RREC_DLL, RREC_MODNAME:
      IF NOT NameOk(s, 1, 254) THEN EXIT;
    RREC_COMMENT: BEGIN END;
    ELSE EXIT;
    END;
  END;
  Records := FilePos(f) = stop;
END;

FUNCTION CheckRdf(VAR f: BFILE; limit: DWORD;
  VAR info: TRdfInfo): BOOLEAN;
VAR start, size_, stop: DWORD; sig: STRING[6];
  rec: RDF_SEG; have_cs, have_ds, ok, ended: BOOLEAN;
  imports: PBits;
BEGIN
  CheckRdf := FALSE;
  FillChar(info, SizeOf(info), 0);
  start := FilePos(f);
  IF (limit < start) OR (limit > FileSize(f)) THEN EXIT;
  IF limit - start < 24 THEN EXIT;
  IF BlockRead(f, sig[1], 6) <> 6 THEN EXIT;
  sig[0] := #6;
  IF sig <> RDOFF2_SIGN THEN EXIT;
  size_ := ReadDWord(f);
  IF (size_ < 14) OR (size_ > limit - start - 10)
    THEN EXIT;
  info.finish := start + 10 + size_;
  info.hdr_size := ReadDWord(f);
  info.hdr_ofs := FilePos(f);
  IF (info.hdr_size < 0) OR
    (info.hdr_size > info.finish - info.hdr_ofs - 10)
    THEN EXIT;
  IF MaxAvail < SizeOf(TBits) THEN BEGIN
    System.Writeln('Not enough memory.'); EXIT;
  END;
  GetMem(imports, SizeOf(TBits));
  FillChar(imports^, SizeOf(TBits), 0);
  ok := Records(f, info, imports, FALSE);
  have_cs := FALSE; have_ds := FALSE; ended := FALSE;
  Seek(f, info.hdr_ofs + info.hdr_size);
  WHILE ok AND (FilePos(f) < info.finish) DO BEGIN
    IF info.finish - FilePos(f) < 10 THEN BREAK;
    rec.segtype := ReadWord(f);
    rec.segnum := ReadWord(f);
    size_ := ReadWord(f);
    rec.seglen := ReadDWord(f);
    IF (size_ <> 0) OR (rec.seglen < 0) OR
      (rec.seglen > info.finish - FilePos(f)) THEN
      BEGIN ok := FALSE; BREAK; END;
    CASE rec.segtype OF
    0: BEGIN
      ended := (rec.segnum = 0) AND (rec.seglen = 0)
        AND (FilePos(f) = info.finish);
      BREAK;
    END;
    RDFCS: BEGIN
      IF have_cs OR (rec.segnum > 63) THEN
        BEGIN ok := FALSE; BREAK; END;
      have_cs := TRUE; info.cs := rec.segnum;
      info.code_ofs := FilePos(f);
      info.code_size := rec.seglen;
    END;
    RDFDS: BEGIN
      IF have_ds OR (rec.segnum > 63) THEN
        BEGIN ok := FALSE; BREAK; END;
      have_ds := TRUE; info.ds := rec.segnum;
      info.data_ofs := FilePos(f);
      info.data_size := rec.seglen;
    END;
    ELSE BEGIN ok := FALSE; BREAK; END;
    END;
    Seek(f, FilePos(f) + rec.seglen);
  END;
  IF NOT have_cs THEN BEGIN
    IF info.ds = 0 THEN info.cs := 1 ELSE info.cs := 0;
  END;
  IF NOT have_ds THEN info.ds := info.cs + 1;
  info.bs := info.cs;
  IF info.ds > info.bs THEN info.bs := info.ds;
  Inc(info.bs);
  ok := ok AND ended AND (info.cs <> info.ds);
  IF ok THEN ok := Records(f, info, imports, TRUE);
  FreeMem(imports, SizeOf(TBits));
  Seek(f, start);
  CheckRdf := ok;
END;
END.
