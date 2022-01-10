{  MIT License

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
USES utils, system2, rdfconst;

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
        System.Write('SEG: ', hexb(ORD(rdata[1])));
        System.Write(', OFS: ', hexdw(PDWORD(@rdata[2])^));
        System.Write(', LEN: ', hexb(ORD(rdata[6])));
        System.Write(', RSEG: ', hexw(PWORD(@rdata[7])^));
END;

PROCEDURE WriteImport(VAR rdata:STRING);
BEGIN
        System.Write('FLG: ', hexb(ORD(rdata[1])));
        System.Write(', SEG: ', hexw(PWORD(@rdata[2])^));
        System.Write(', ');
        System.Write(strc2pas(@rdata[4]));
END;

PROCEDURE WriteGlobal(VAR rdata:STRING);
BEGIN
        System.Write('FLG: ', hexb(ORD(rdata[1])));
        System.Write(', SEG: ', hexb(ORD(rdata[2])));
        System.Write(', OFS: ', hexdw(PDWORD(@rdata[3])^));
        System.Write(', ');
        System.Write(strc2pas(@rdata[7]));
END;

PROCEDURE WriteBSS(VAR rdata:STRING);
BEGIN
        System.Write(hexdw(PDWORD(@rdata[1])^));
END;

PROCEDURE WriteName(VAR rdata:STRING);
BEGIN
        System.Write(rdata);
END;

PROCEDURE WriteDefault(VAR rdata:STRING);
VAR
        i, l : INTEGER;
BEGIN
        l := Length(rdata);
        IF l > 16 THEN l := 16;
        FOR i := 1 TO l DO System.Write(hexb(ORD(rdata[i])), ' ');
END;

PROCEDURE DumpRec(rtype : CHAR; VAR rdata : STRING);
BEGIN
        CASE rtype OF
        RREC_RELOC: BEGIN
                { reloc }
                System.Write('RELO      ');
                WriteRelo(rdata);
        END;
        RREC_IMPORT: BEGIN
                { import }
                System.Write('IMPORT    ');
                WriteImport(rdata);
        END;
        RREC_GLOBAL: BEGIN
                { global }
                System.Write('GLOBAL    ');
                WriteGlobal(rdata);
        END;
        RREC_DLL: BEGIN
                { dll }
                System.Write('DLL       ');
                WriteName(rdata);
        END;
        RREC_BSS: BEGIN
                { bss }
                System.Write('BSS       ');
                WriteBSS(rdata);
        END;
        RREC_SEGRELO: BEGIN
                { seg relo }
                System.Write('SEGRELO   ');
                WriteRelo(rdata);
        END;
        RREC_FARIMPORT: BEGIN
                { far import }
                System.Write('FARIMPORT ');
                WriteImport(rdata);
        END;
        RREC_MODNAME: BEGIN
                { mod name }
                System.Write('MODNAME   ');
                WriteName(rdata);
        END ELSE BEGIN
                System.Write('???    ');
                WriteDefault(rdata);
        END;
        END;
END;

PROCEDURE DumpSegs(VAR f : BFILE; modlen : LONGINT);
VAR     segtype : WORD;
        segnum  : WORD;
        reserv  : WORD;
        seglen  : LONGINT;
BEGIN
        WHILE NOT eof(f) DO BEGIN
                segtype := ReadWord(f);
                segnum := ReadWord(f);
                reserv := ReadWord(f);
                seglen := ReadDWord(f);
                System.Write(hexdw(FilePos(f)), ' ');
                System.Write(hexdw(seglen), ' ');
                System.Write(hexb(segtype), '-');
                IF segtype = 1 THEN System.Write('CODE     ')
                ELSE IF segtype = 2 THEN System.Write('DATA     ')
                ELSE System.Write('??       ');
                System.Write(' NUM: ',hexw(segnum), ' ');
                System.Write(' RES: ',hexw(reserv));
                System.Writeln;
                IF segtype = 0 THEN BREAK;
                Seek(f, FilePos(f) + seglen);
        END;
END;

VAR     f      : BFILE;
        sign   : STRING;
        fullen : LONGINT;
        modlen : LONGINT;
        hdrlen : LONGINT;
        rtype  : CHAR;
        rdata  : STRING;
BEGIN
        System.Writeln('RDFDUMP for NASM-0.98.39  (c) 2022 by DosWorld.  MIT License');
        System.Writeln;
        IF PARAMCOUNT <> 1 THEN BEGIN
                WriteLnErr('usage: RDUMP filename.rdf');
                Halt(1);
        END;
        Assign(f, ParamStr(1));
        Reset(f);
        IF f.ioresult <> 0 THEN BEGIN
                WriteLnErr('Could not open ' + ParamStr(1));
                Halt(1);
        END;
        fullen := FileSize(f);
        BlockRead(f, sign[1], 6);
        BlockRead(f, modlen, SizeOf(LONGINT));
        BlockRead(f, hdrlen, SizeOf(LONGINT));
        sign[0] := #6;
        System.Writeln('File name:   ', ParamStr(1));
        System.Writeln('File size:   ', hexdw(fullen), ' ', fullen);
        System.WriteLn('Signature:   ', sign);
        System.WriteLn('Module size: ', hexdw(modlen), ' ', modlen);
        System.WriteLn('Header size: ', hexdw(hdrlen), ' ', hdrlen);
        System.WriteLn;
        System.WriteLn('Header record(s)');
        System.WriteLn;
        WHILE hdrlen <> 0 DO BEGIN
                System.Write(hexdw(FilePos(f)), ' ');
                BlockRead(f, rtype, 1);
                BlockRead(f, rdata[0], 1);
                Dec(hdrlen, 2);
                BlockRead(f, rdata[1], ORD(rdata[0]));
                Dec(hdrlen, ORD(rdata[0]));
                System.Write(hexb(ORD(rdata[0])), ' ', hexb(ORD(rtype)), '-');
                DumpRec(rtype, rdata);
                System.Writeln;
        END;
        System.WriteLn;
        System.WriteLn('Segment(s)');
        System.WriteLn;
        DumpSegs(f, modlen);
        Close(f);
END.
