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
UNIT RStore;
INTERFACE
USES System2;
CONST STORE_BYTES = 8184;
TYPE
  PStoreInt = ^INTEGER;
  PStoreLong = ^LONGINT;
  PStoreByte = ^BYTE;
  PChunk = ^TChunk;
  TChunk = RECORD
    next: PChunk;
    used: WORD;
    data: ARRAY[0..STORE_BYTES - 1] OF BYTE;
  END;
  TStore = RECORD
    first, last, cache: PChunk;
    count, item_size, per_chunk, cache_base: WORD;
  END;
PROCEDURE StoreInit(VAR s: TStore; item_size: WORD);
FUNCTION StoreAt(VAR s: TStore; index: WORD): POINTER;
FUNCTION StoreTryAt(VAR s: TStore; index: WORD): POINTER;
PROCEDURE StoreFree(VAR s: TStore);
FUNCTION StoreInt(VAR s: TStore; i: WORD): PStoreInt;
FUNCTION StoreLong(VAR s: TStore; i: WORD): PStoreLong;
FUNCTION StoreByte(VAR s: TStore; i: WORD): PStoreByte;
PROCEDURE StoreWrite(VAR s: TStore; VAR f: BFILE; n: WORD);
IMPLEMENTATION
PROCEDURE StoreInit(VAR s: TStore; item_size: WORD);
BEGIN
  FillChar(s, SizeOf(s), 0);
  IF (item_size = 0) OR (item_size > STORE_BYTES) THEN BEGIN
    System.Writeln('Invalid record size.'); Halt(1);
  END;
  s.item_size := item_size;
  s.per_chunk := STORE_BYTES DIV item_size;
END;

FUNCTION StoreTryAt(VAR s: TStore; index: WORD): POINTER;
VAR c: PChunk; base: WORD;
BEGIN
  StoreTryAt := NIL;
  IF (index = 0) OR (s.item_size = 0) THEN BEGIN
    EXIT;
  END;
  WHILE s.count < index DO BEGIN
    IF s.last <> NIL THEN c := s.last ELSE c := NIL;
    IF c <> NIL THEN
      IF c^.used = s.per_chunk THEN c := NIL;
    IF c = NIL THEN BEGIN
      IF MaxAvail < SizeOf(TChunk) THEN BEGIN
        EXIT;
      END;
      GetMem(c, SizeOf(TChunk));
      FillChar(c^, SizeOf(TChunk), 0);
      IF s.last = NIL THEN s.first := c
      ELSE s.last^.next := c;
      s.last := c;
    END;
    Inc(c^.used); Inc(s.count);
  END;
  IF (s.cache <> NIL) AND (index >= s.cache_base) THEN BEGIN
    c := s.cache; base := s.cache_base;
  END ELSE BEGIN
    c := s.first; base := 1;
  END;
  WHILE index - base >= c^.used DO BEGIN
    Inc(base, c^.used); c := c^.next;
  END;
  s.cache := c; s.cache_base := base;
  StoreTryAt := Ptr(Seg(c^.data), Ofs(c^.data)
    + (index - base) * s.item_size);
END;

FUNCTION StoreAt(VAR s: TStore; index: WORD): POINTER;
VAR p: POINTER;
BEGIN
  p := StoreTryAt(s, index);
  IF p = NIL THEN BEGIN
    System.Writeln('Record allocation failed.'); Halt(1);
  END;
  StoreAt := p;
END;

PROCEDURE StoreFree(VAR s: TStore);
VAR c: PChunk;
BEGIN
  WHILE s.first <> NIL DO BEGIN
    c := s.first; s.first := c^.next;
    FreeMem(c, SizeOf(TChunk));
  END;
  FillChar(s, SizeOf(s), 0);
END;
FUNCTION StoreInt(VAR s: TStore; i: WORD): PStoreInt;
BEGIN StoreInt := PStoreInt(StoreAt(s, i)); END;
FUNCTION StoreLong(VAR s: TStore; i: WORD): PStoreLong;
BEGIN StoreLong := PStoreLong(StoreAt(s, i)); END;
FUNCTION StoreByte(VAR s: TStore; i: WORD): PStoreByte;
BEGIN StoreByte := PStoreByte(StoreAt(s, i)); END;
PROCEDURE StoreWrite(VAR s: TStore; VAR f: BFILE; n: WORD);
VAR c: PChunk; take: WORD;
BEGIN
  c := s.first;
  WHILE (n <> 0) AND (c <> NIL) DO BEGIN
    take := c^.used;
    IF take > n THEN take := n;
    BlockWrite(f, c^.data, take * s.item_size);
    Dec(n, take); c := c^.next;
  END;
END;
END.
