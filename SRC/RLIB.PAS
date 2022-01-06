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
{$I+,A+,R-,S-,O-,F-,D-,L-,Q-,F-,G-}
{$M 64000, 128000,128000}
USES utils;

CONST

RLIB_SIGN1  : STRING[6] = '.sig'+#0;
RLIB_SIGN2  : STRING[6] = 'RDLIB2';
RDOFF2_SIGN : STRING[6] = 'RDOFF2';

BUF_SIZE = 8 * 1024;

PROCEDURE Help;
BEGIN
        WriteLn('usage: RLIB cmd lib.rdl [file.rdf modulename]');
        WriteLn;
        WriteLn('where CMD is:');
        WriteLn('/C  - Create empty lib.rdl (or overwrite)');
        WriteLn('/A  - Add to lib.rdl module modulename from file file.rdf');
        WriteLn('/L  - Show module names from lib.rdl');
        WriteLn('/H  - Show this help');
        Halt(1);
END;

PROCEDURE err_exit;
BEGIN
        WriteLn('  use /H for help');
        Halt(1);
END;

PROCEDURE file_err(VAR fname : STRING; i : INTEGER);
BEGIN
        Write(i, ':');
        CASE i OF
        2: Write('File not found');
        3: Write('Path not found');
        4: Write('Too many open files');
        5: Write('File access denied');
        6: Write('Invalid file handle');
        12: Write('Invalid file access code');
        15: Write('Invalid drive number');
        100: Write('Disk read error');
        101: Write('Disk write error');
        102: Write('File not assigned');
        103: Write('File not open');
        104: Write('File not open for input');
        105: Write('File not open for output');
        150: Write('Disk is write-protected');
        ELSE Write('Unknown error');
        END;
        WriteLn(':', fname);
        err_exit;
END;

PROCEDURE rlib_create(VAR libname : STRING);
VAR     f : FILE;
        i : INTEGER;
BEGIN
        Assign(f, libname);
        {$I-}
        ReWrite(f, 1);
        i := ioResult;
        {$I+}
        IF i <> 0 THEN file_err(libname, i);
        BlockWrite(f, RLIB_SIGN1[1], Length(RLIB_SIGN1));
        BlockWrite(f, RLIB_SIGN2[1], Length(RLIB_SIGN2));
        write_dword(f, SizeOf(DWORD));
        write_dword(f, 0);
        Truncate(f);
        Close(f);
END;


PROCEDURE rlib_add(VAR libname, filename, modname : STRING);
VAR     f, o  : FILE;
        i     : INTEGER;
        l     : LONGINT;
        buf   : ARRAY[1..BUF_SIZE] OF BYTE;
        inbuf : WORD;
BEGIN
        IF Length(modname) > 63 THEN modname[0] := #63;
        Assign(f, libname);
        {$I-}
        Reset(f, 1);
        i := ioResult;
        {$I+}
        IF i <> 0 THEN file_err(libname, i);
        Assign(o, filename);
        {$I-}
        Reset(o, 1);
        i := ioResult;
        {$I+}
        IF i <> 0 THEN BEGIN
                Close(f);
                file_err(filename, i);
        END;
        Seek(f, FileSize(f));
        modname := modname + #0;
        BlockWrite(f, modname[1], Length(modname));
        WHILE NOT EOF(o) DO BEGIN
                BlockRead(o, buf, BUF_SIZE, inbuf);
                BlockWrite(f, buf, inbuf);
                IF inbuf = 0 THEN BREAK;
        END;
        Close(o);
        Close(f);
END;

PROCEDURE rlib_list(VAR libname : STRING);
VAR     f        : FILE;
        i        : INTEGER;
        p        : DWORD;
        modsize  : DWORD;
        modstart : DWORD;
        modname  : STRING;
        s        : STRING;
BEGIN
        Assign(f, libname);
        {$I-}
        Reset(f, 1);
        i := ioResult;
        {$I+}
        IF i <> 0 THEN file_err(libname, i);
        WriteLn('Offset' : 8, ' ', 'Size' : 8, ' Module');
        WHILE NOT EOF(f) DO BEGIN
                p := FilePos(f);
                BlockRead(f, modname[1], 255, i);
                i := 1;
                WHILE i < 255 DO BEGIN
                        IF modname[i] = #0 THEN BEGIN
                                modname[0] := CHR(i - 1);
                                BREAK;
                        END;
                        INC(i);
                        INC(p);
                END;
                modstart := p + 1;
                Seek(f, modstart);
                BlockRead(f, s[1], 6);
                s[0] := #6;
                IF modname[1] <> '.' THEN BEGIN
                        IF s <> RDOFF2_SIGN THEN BEGIN
                                WriteLn('Module ', modname, ' has invalid format ', s);
                                BREAK;
                        END;
                END;
                modsize := read_dword(f);
                IF modname[1] <> '.' THEN BEGIN
                        WriteLn(modstart : 8, ' ', modsize : 8, ' ', modname);
                END;
                Seek(f, FilePos(f) + modsize);
        END;
        Close(f);
END;

VAR     cmd      : STRING;
        libname  : STRING;
        filename : STRING;
        modname  : STRING;
        pcount   : INTEGER;
        cmdc     : CHAR;

BEGIN
        cmd := '';
        libname := '';
        filename := '';
        modname := '';
        pcount := ParamCount;
        IF pcount > 0 THEN cmd := ParamStr(1);
        IF pcount > 1 THEN libname := ParamStr(2);
        IF pcount > 2 THEN filename := ParamStr(3);
        IF pcount > 3 THEN modname := ParamStr(4);
        cmdc := #0;
        IF Length(cmd) > 1 THEN IF cmd[1] IN ['/', '-'] THEN cmdc := UPCASE(cmd[2]);
        IF (cmdc = 'C') AND (pcount = 2) THEN rlib_create(libname)
        ELSE IF (cmdc = 'A') AND (pcount = 4) THEN rlib_add(libname, filename, modname)
        ELSE IF (cmdc = 'L') AND (pcount = 2) THEN rlib_list(libname)
        ELSE IF cmdc IN ['H', '?'] THEN Help
        ELSE err_exit;
END.
