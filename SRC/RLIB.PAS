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
USES system2, args, RdfFmt;

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
END;

PROCEDURE rlib_create(VAR libname : STRING);
VAR     f : BFILE;
        i : INTEGER;
BEGIN
        Assign(f, libname);
        ReWrite(f);
        IF IsOpen(f) THEN BEGIN
                RDL_CREATE(f);
                Close(f);
        END;
END;


PROCEDURE rlib_add(VAR libname, filename, modname : STRING);
VAR     f, o  : BFILE;
BEGIN
        IF Length(modname) > 63 THEN modname[0] := #63;
        Assign(f, libname);
        Reset(f);
        IF GET_FILE_TYPE(f) <> FILE_RDL THEN BEGIN
                System.writeln(libname, ' is not rdl');
                Close(f);
        END;
        Assign(o, filename);
        Reset(o);
        IF GET_FILE_TYPE(o) <> FILE_RDF THEN BEGIN
                System.writeln(filename, ' is not rdf');
                Close(o);
        END;
        IF IsOpen(f) AND IsOpen(o) THEN BEGIN
                RDL_APPEND_MODULE(f, modname);
                Seek(o, 0);
                BlockCopy(o, f, FileSize(o));
        END;
        IF IsOpen(f) THEN Close(f);
        IF IsOpen(o) THEN Close(o);
END;

PROCEDURE rlib_list(VAR libname : STRING);
VAR     f        : BFILE;
        modsize  : DWORD;
        modstart : DWORD;
        modname  : STRING;
        s        : STRING;
BEGIN
        Assign(f, libname);
        Reset(f);
        IF NOT IsOpen(f) THEN file_err(libname, f.ioResult);
        System.WriteLn('Offset' : 8, ' ', 'Size' : 8, ' Module');
        WHILE RDL_NEXT_MODULE(f, modname) DO BEGIN
                modstart := FilePos(f);
                Seek(f, modstart + Length(RDOFF2_SIGN));
                modsize := ReadDword(f);
                System.WriteLn(modstart : 8, ' ', modsize : 8, ' ', modname);
                Seek(f, FilePos(f) + modsize);
        END;
        Close(f);
END;

CONST
ARG_CMD_CREATE = 'c';
ARG_CMD_ADD    = 'a';
ARG_CMD_LIST   = 'l';

OPTIONS_DESC : ARRAY[0..2] OF TOPT = (
(name: ARG_CMD_CREATE; otype: OPTCMD;  help: 'Create empty library arg0 (or overwrite it)'),
(name: ARG_CMD_ADD;    otype: OPTCMD;  help: 'Add to library arg0 module from file arg1 with name arg2'),
(name: ARG_CMD_LIST;   otype: OPTCMD;  help: 'Show module names from library arg0')
);

VAR     myArgs   : TARGSTATE;
        cmd      : STRING;
        libname  : STRING;
        filename : STRING;
        modname  : STRING;
        pcount   : INTEGER;
BEGIN
        ArgsParse(myArgs, OPTIONS_DESC);

        libname := GetArgsStr(myArgs, 1);
        filename := GetArgsStr(myArgs, 2);
        modname := GetArgsStr(myArgs, 3);

        cmd := GetCmd(myArgs);
        pcount := ArgsCount(myArgs);

        IF (cmd = ARG_CMD_CREATE) AND (pcount <> 1) THEN
                SetArgsErr(myArgs, 'Required parameters: library.rdl');
        IF (cmd = ARG_CMD_ADD) AND (pcount <> 3) THEN
                SetArgsErr(myArgs, 'Required parameters: library.rdl file.rdf module_name');
        IF (cmd = ARG_CMD_LIST) AND (pcount <> 1) THEN
                SetArgsErr(myArgs, 'Required parameters: library.rdl');

        WriteArgsErrors(myArgs);
        IF ArgsError(myArgs) THEN Halt(1);

        IF cmd = ARG_CMD_CREATE THEN rlib_create(libname)
        ELSE IF cmd = ARG_CMD_ADD THEN rlib_add(libname, filename, modname)
        ELSE IF cmd = ARG_CMD_LIST THEN rlib_list(libname);
END.