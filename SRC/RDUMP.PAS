{
 MIT License

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

https://github.com/DosWorld/rtools
}
{$A+,I+,S-,R-,D-,L-,Q-,F-,G-}
USES utils;

CONST

a : STRING[16] = '0123456789ABCDEF';

FUNCTION hexb(b : BYTE) : STRING;
BEGIN
        hexb := a[((b SHR 4) AND $0f) + 1] + a[(b AND $0f) + 1];
END;

FUNCTION hexw(w : WORD):STRING;
BEGIN
        hexw := hexb(hi(w)) + hexb(lo(w));
END;

FUNCTION hexdw(dw : LONGINT):STRING;
BEGIN
        hexdw := hexw((dw SHR 16) AND $ffff) + hexw(dw AND $ffff);
END;

PROCEDURE WriteRelo(VAR rdata:STRING);
BEGIN
        Write('SEG: ', hexb(ORD(rdata[1])));
        Write(', OFS: ', hexdw(PDWORD(@rdata[2])^));
        Write(', LEN: ', hexb(ORD(rdata[6])));
        Write(', RSEG: ', hexw(PWORD(@rdata[7])^));
END;

PROCEDURE WriteImport(VAR rdata:STRING);
BEGIN
        Write('FLG: ', hexb(ORD(rdata[1])));
        Write(', SEG: ', hexw(PWORD(@rdata[2])^));
        Write(', ');
        Write(strc2pas(@rdata[4]));
END;

PROCEDURE WriteGlobal(VAR rdata:STRING);
VAR
        i : INTEGER;
BEGIN
        Write('FLG: ', hexb(ORD(rdata[1])));
        Write(', SEG: ', hexb(ORD(rdata[2])));
        Write(', OFS: ', hexdw(PDWORD(@rdata[3])^));
        Write(', ');
        Write(strc2pas(@rdata[7]));
END;

PROCEDURE WriteBSS(VAR rdata:STRING);
BEGIN
        Write(hexdw(PDWORD(@rdata[1])^));
END;

PROCEDURE WriteName(VAR rdata:STRING);
BEGIN
        Write(rdata);
END;

PROCEDURE WriteDefault(VAR rdata:STRING);
VAR
        i, l : INTEGER;
BEGIN
        l := Length(rdata);
        IF l > 16 THEN l := 16;
        FOR i := 1 TO l DO Write(hexb(ORD(rdata[i])), ' ');
END;

PROCEDURE DumpRec(rtype : BYTE; VAR rdata : STRING);
BEGIN
        CASE rtype OF
        1: BEGIN
                { reloc }
                Write('RELO      ');
                WriteRelo(rdata);
        END;
        2: BEGIN
                { import }
                Write('IMPORT    ');
                WriteImport(rdata);
        END;
        3: BEGIN
                { global }
                Write('GLOBAL    ');
                WriteGlobal(rdata);
        END;
        4: BEGIN
                { dll }
                Write('DLL       ');
                WriteName(rdata);
        END;
        5: BEGIN
                { bss }
                Write('BSS       ');
                WriteBSS(rdata);
        END;
        6: BEGIN
                { seg relo }
                Write('SEGRELO   ');
                WriteRelo(rdata);
        END;
        7: BEGIN
                { far import }
                Write('FARIMPORT ');
                WriteImport(rdata);
        END;
        8: BEGIN
                { mod name }
                Write('MODNAME   ');
                WriteName(rdata);
        END ELSE BEGIN
                Write('???    ');
                WriteDefault(rdata);
        END;
        END;
END;

PROCEDURE DumpSegs(VAR f : FILE; modlen : LONGINT);
VAR
        segtype  : WORD;
        segnum   : WORD;
        reserv   : WORD;
        seglen   : LONGINT;
BEGIN
        WHILE NOT eof(f) DO BEGIN
                BlockRead(f, segtype, SizeOf(segtype));
                BlockRead(f, segnum, SizeOf(segnum));
                BlockRead(f, reserv, SizeOf(reserv));
                BlockRead(f, seglen, SizeOf(seglen));
                Write(hexdw(FilePos(f)), ' ');
                Write(hexdw(seglen), ' ');
                Write(hexb(segtype), '-');
                IF segtype = 1 THEN Write('CODE     ')
                ELSE IF segtype = 2 THEN Write('DATA     ')
                ELSE Write('??       ');
                Write(' NUM: ',hexw(segnum), ' ');
                Write(' RES: ',hexw(reserv));
                Writeln;
                IF segtype = 0 THEN BREAK;
                Seek(f, FilePos(f) + seglen);
        END;
END;

VAR
        f : FILE;
        sign    : STRING;
        fullen  : LONGINT;
        modlen  : LONGINT;
        hdrlen  : LONGINT;
        rtype   : BYTE;
        rdata   : STRING;
BEGIN
        Writeln('RDFDUMP for NASM-0.98.39  (c) 2020 by DosWorld.  MIT License');
        Writeln;
        IF PARAMCOUNT <> 1 THEN BEGIN
                Writeln('usage: RDUMP filename.rdf');
                Halt(1);
        END;
        Assign(f, ParamStr(1));
        Reset(f, 1);
        fullen := FileSize(f);
        BlockRead(f, sign[1], 6);
        BlockRead(f, modlen, SizeOf(LONGINT));
        BlockRead(f, hdrlen, SizeOf(LONGINT));
        sign[0] := #6;
        Writeln('File name:   ', ParamStr(1));
        Writeln('File size:   ', hexdw(fullen), ' ', fullen);
        WriteLn('Signature:   ', sign);
        WriteLn('Module size: ', hexdw(modlen), ' ', modlen);
        WriteLn('Header size: ', hexdw(hdrlen), ' ', hdrlen);
        WriteLn;
        WriteLn('Header record(s)');
        WriteLn;
        WHILE hdrlen <> 0 DO BEGIN
                Write(hexdw(FilePos(f)), ' ');
                BlockRead(f, rtype, 1);
                BlockRead(f, rdata[0], 1);
                Dec(hdrlen, 2);
                BlockRead(f, rdata[1], ORD(rdata[0]));
                Dec(hdrlen, ORD(rdata[0]));
                Write(hexb(ORD(rdata[0])), ' ', hexb(rtype), '-');
                DumpRec(rtype, rdata);
                Writeln;
        END;
        WriteLn;
        WriteLn('Segment(s)');
        WriteLn;
        DumpSegs(f, modlen);
        Close(f);
END.