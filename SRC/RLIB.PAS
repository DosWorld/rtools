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
USES utils, system2, rdfconst;

CONST

RLIB_SIGN1  : STRING[6] = '.sig'+#0;
RLIB_SIGN2  : STRING[6] = 'RDLIB2';

PROCEDURE Help;
BEGIN
        System.WriteLn('usage: RLIB cmd lib.rdl [file.rdf modulename]');
        System.WriteLn;
        System.WriteLn('where CMD is:');
        System.WriteLn('/C  - Create empty lib.rdl (or overwrite)');
        System.WriteLn('/A  - Add to lib.rdl module modulename from file file.rdf');
        System.WriteLn('/L  - Show module names from lib.rdl');
        System.WriteLn('/H  - Show this help');
        Halt(1);
END;

PROCEDURE err_exit;
BEGIN
        System.WriteLn('  use /H for help');
        Halt(1);
END;

PROCEDURE file_err(VAR fname : STRING; i : INTEGER);
VAR     msg : STRING;
BEGIN
        CASE i OF
        2: msg := 'File not found';
        3: msg := 'Path not found';
        4: msg := 'Too many open files';
        5: msg := 'File access denied';
        6: msg := 'Invalid file handle';
        12: msg := 'Invalid file access code';
        15: msg := 'Invalid drive number';
        100: msg := 'Disk read error';
        101: msg := 'Disk write error';
        102: msg := 'File not assigned';
        103: msg := 'File not open';
        104: msg := 'File not open for input';
        105: msg := 'File not open for output';
        150: msg := 'Disk is write-protected';
        ELSE msg := 'Error';
        END;
        WriteLnErr(msg + ':' + fname);
        err_exit;
END;

PROCEDURE rlib_create(VAR libname : STRING);
VAR     f : BFILE;
        i : INTEGER;
BEGIN
        Assign(f, libname);
        ReWrite(f);
        IF f.ioResult <> 0 THEN file_err(libname, i);
        BlockWrite(f, RLIB_SIGN1[1], Length(RLIB_SIGN1));
        BlockWrite(f, RLIB_SIGN2[1], Length(RLIB_SIGN2));
        WriteDWord(f, SizeOf(DWORD));
        WriteDWord(f, 0);
        Truncate(f);
        Close(f);
END;


PROCEDURE rlib_add(VAR libname, filename, modname : STRING);
VAR     f, o  : BFILE;
BEGIN
        IF Length(modname) > 63 THEN modname[0] := #63;
        Assign(f, libname);
        Reset(f);
        IF f.ioResult <> 0 THEN file_err(libname, f.ioResult);
        Assign(o, filename);
        Reset(o);
        IF NOT IsOpen(o) THEN BEGIN
                Close(f);
                file_err(filename, o.ioResult);
        END;
        Seek(f, FileSize(f));
        modname := modname + #0;
        Write(f, modname);
        BlockCopy(o, f, FileSize(o));
        Close(o);
        Close(f);
END;

PROCEDURE rlib_list(VAR libname : STRING);
VAR     f        : BFILE;
        i        : INTEGER;
        p        : DWORD;
        modsize  : DWORD;
        modstart : DWORD;
        modname  : STRING;
        s        : STRING;
BEGIN
        Assign(f, libname);
        Reset(f);
        IF f.ioResult <> 0 THEN file_err(libname, f.ioResult);
        System.WriteLn('Offset' : 8, ' ', 'Size' : 8, ' Module');
        WHILE NOT EOF(f) DO BEGIN
                p := FilePos(f);
                BlockRead(f, modname[1], 255);
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
                                System.WriteLn('Module ', modname, ' has invalid format ', s);
                                BREAK;
                        END;
                END;
                modsize := ReadDword(f);
                IF modname[1] <> '.' THEN BEGIN
                        System.WriteLn(modstart : 8, ' ', modsize : 8, ' ', modname);
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
