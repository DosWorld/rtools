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

FUNCTION rlib_create(VAR libname : STRING) : BOOLEAN;
VAR     f : BFILE;
BEGIN
        Assign(f, libname);
        ReWrite(f);
        IF IsOpen(f) THEN BEGIN
                RDL_CREATE(f);
                Close(f);
                rlib_create := FALSE;
        END ELSE BEGIN
                file_err(libname, f.ioResult);
                rlib_create := TRUE;
        END;
END;

FUNCTION rdl_find(VAR f : BFILE; VAR modname : STRING; VAR start, total : DWORD) : BOOLEAN;
VAR     n : STRING;
BEGIN
        rdl_find := FALSE;
        IF GET_FILE_TYPE(f) <> FILE_RDL THEN EXIT;
        WHILE RDL_NEXT_MODULE(f, n) DO BEGIN
                start := FilePos(f);
                Seek(f, start + Length(RDOFF2_SIGN));
                total := ReadDWord(f) + Length(RDOFF2_SIGN) + SizeOf(DWORD);
                IF n = modname THEN BEGIN
                        Seek(f, start);
                        rdl_find := TRUE;
                        EXIT;
                END;
                Seek(f, start + total);
        END;
END;

FUNCTION rlib_add(VAR libname, filename, modname : STRING) : BOOLEAN;
VAR     f, o  : BFILE;
        err   : BOOLEAN;
        st    : DWORD;
        tot   : DWORD;
BEGIN
        err := FALSE;
        IF (Length(modname) = 0) OR (modname[1] = '.') OR (Length(modname) > 63) THEN BEGIN
                System.writeln('Bad module name (1..63 characters, not starting with dot): ', modname);
                err := TRUE;
        END;
        IF NOT err THEN BEGIN
                Assign(f, libname);
                Reset(f);
                IF NOT IsOpen(f) THEN BEGIN
                        file_err(libname, f.ioResult);
                        err := TRUE;
                END ELSE IF GET_FILE_TYPE(f) <> FILE_RDL THEN BEGIN
                        System.writeln(libname, ' is not rdl');
                        err := TRUE;
                END;
        END;
        IF NOT err THEN BEGIN
                Assign(o, filename);
                Reset(o);
                IF NOT IsOpen(o) THEN BEGIN
                        file_err(filename, o.ioResult);
                        err := TRUE;
                END ELSE IF GET_FILE_TYPE(o) <> FILE_RDF THEN BEGIN
                        System.writeln(filename, ' is not rdf');
                        err := TRUE;
                END;
        END;
        IF (NOT err) AND (FileSize(o) < 10) THEN BEGIN
                System.writeln(filename, ' is damaged');
                err := TRUE;
        END;
        IF NOT err THEN BEGIN
                Seek(o, 6);
                IF ReadDWord(o) + 10 <> FileSize(o) THEN BEGIN
                        System.writeln(filename, ' is damaged');
                        err := TRUE;
                END;
        END;
        IF NOT err THEN BEGIN
                IF rdl_find(f, modname, st, tot) THEN BEGIN
                        System.writeln('Module ', modname, ' is already in ', libname);
                        err := TRUE;
                END;
        END;
        IF NOT err THEN BEGIN
                RDL_APPEND_MODULE(f, modname);
                Seek(o, 0);
                BlockCopy(o, f, FileSize(o));
        END;
        IF IsOpen(f) THEN Close(f);
        IF IsOpen(o) THEN Close(o);
        rlib_add := err;
END;

FUNCTION rlib_list(VAR libname : STRING) : BOOLEAN;
VAR     f        : BFILE;
        modsize  : DWORD;
        modstart : DWORD;
        modname  : STRING;
        err      : BOOLEAN;
BEGIN
        err := FALSE;
        Assign(f, libname);
        Reset(f);
        IF NOT IsOpen(f) THEN BEGIN
                file_err(libname, f.ioResult);
                err := TRUE;
        END ELSE BEGIN
                IF GET_FILE_TYPE(f) = FILE_RDL THEN BEGIN
                        System.WriteLn('Offset' : 8, ' ', 'Size' : 8, ' Module');
                        WHILE RDL_NEXT_MODULE(f, modname) DO BEGIN
                                modstart := FilePos(f);
                                Seek(f, FilePos(f) + Length(RDOFF2_SIGN));
                                modsize := ReadDword(f);
                                System.WriteLn(modstart : 8, ' ', modsize : 8, ' ', modname);
                                Seek(f, FilePos(f) + modsize);
                        END;
                END ELSE BEGIN
                        System.writeln(libname, ' is not rdl');
                        err := TRUE;
                END;
                Close(f);
        END;
        rlib_list := err;
END;

FUNCTION rlib_delete(VAR libname, modname : STRING) : BOOLEAN;
VAR     f, t  : BFILE;
        n     : STRING;
        st    : DWORD;
        tot   : DWORD;
        found : BOOLEAN;
        err   : BOOLEAN;
BEGIN
        err := FALSE;
        found := FALSE;
        Assign(f, libname);
        Reset(f);
        IF NOT IsOpen(f) THEN BEGIN
                file_err(libname, f.ioResult);
                rlib_delete := TRUE;
                EXIT;
        END;
        IF GET_FILE_TYPE(f) <> FILE_RDL THEN BEGIN
                System.writeln(libname, ' is not rdl');
                Close(f);
                rlib_delete := TRUE;
                EXIT;
        END;
        ReWriteTemp(t);
        IF NOT IsOpen(t) THEN BEGIN
                System.writeln('Could not create temporary file (check TMP/TEMP).');
                Close(f);
                rlib_delete := TRUE;
                EXIT;
        END;
        RDL_CREATE(t);
        Seek(t, FileSize(t));
        WHILE RDL_NEXT_MODULE(f, n) DO BEGIN
                st := FilePos(f);
                Seek(f, st + Length(RDOFF2_SIGN));
                tot := ReadDWord(f) + Length(RDOFF2_SIGN) + SizeOf(DWORD);
                Seek(f, st);
                IF n = modname THEN found := TRUE
                ELSE BEGIN
                        RDL_APPEND_MODULE(t, n);
                        BlockCopy(f, t, tot);
                END;
                Seek(f, st + tot);
        END;
        IF NOT found THEN BEGIN
                System.writeln('Module ', modname, ' is not in ', libname);
                err := TRUE;
        END ELSE BEGIN
                Seek(f, 0);
                Seek(t, 0);
                BlockCopy(t, f, FileSize(t));
                Truncate(f);
        END;
        Close(t);
        Close(f);
        rlib_delete := err;
END;

FUNCTION rlib_extract(VAR libname, modname, outname : STRING) : BOOLEAN;
VAR     f, o  : BFILE;
        st    : DWORD;
        tot   : DWORD;
        err   : BOOLEAN;
BEGIN
        err := FALSE;
        Assign(f, libname);
        Reset(f);
        IF NOT IsOpen(f) THEN BEGIN
                file_err(libname, f.ioResult);
                rlib_extract := TRUE;
                EXIT;
        END;
        IF NOT rdl_find(f, modname, st, tot) THEN BEGIN
                System.writeln('Module ', modname, ' is not in ', libname, ' (or it is not rdl)');
                Close(f);
                rlib_extract := TRUE;
                EXIT;
        END;
        Assign(o, outname);
        ReWrite(o);
        IF NOT IsOpen(o) THEN BEGIN
                file_err(outname, o.ioResult);
                err := TRUE;
        END ELSE BEGIN
                BlockCopy(f, o, tot);
                Close(o);
        END;
        Close(f);
        rlib_extract := err;
END;

CONST
ARG_CMD_CREATE = 'c';
ARG_CMD_ADD    = 'a';
ARG_CMD_LIST   = 'l';
ARG_CMD_DEL    = 'd';
ARG_CMD_EXT    = 'x';

OPTIONS_DESC : ARRAY[0..4] OF TOPT = (
(name: ARG_CMD_CREATE; otype: OPTCMD;  help: 'Create empty library arg0 (or overwrite it)'),
(name: ARG_CMD_ADD;    otype: OPTCMD;  help: 'Add to library arg0 module from file arg1 with name arg2'),
(name: ARG_CMD_LIST;   otype: OPTCMD;  help: 'Show module names from library arg0'),
(name: ARG_CMD_DEL;    otype: OPTCMD;  help: 'Delete module arg1 from library arg0'),
(name: ARG_CMD_EXT;    otype: OPTCMD;  help: 'Extract module arg1 from library arg0 into file arg2')
);

VAR     myArgs   : TARGSTATE;
        cmd      : STRING;
        libname  : STRING;
        filename : STRING;
        modname  : STRING;
        pcount   : INTEGER;
        err      : BOOLEAN;
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

        IF (cmd = ARG_CMD_DEL) AND (pcount <> 2) THEN
                SetArgsErr(myArgs, 'Required parameters: library.rdl module_name');
        IF (cmd = ARG_CMD_EXT) AND (pcount <> 3) THEN
                SetArgsErr(myArgs, 'Required parameters: library.rdl module_name file.rdf');

        WriteArgsErrors(myArgs);
        IF ArgsError(myArgs) THEN Halt(1);

        err := FALSE;
        IF cmd = ARG_CMD_CREATE THEN err := rlib_create(libname)
        ELSE IF cmd = ARG_CMD_ADD THEN err := rlib_add(libname, filename, modname)
        ELSE IF cmd = ARG_CMD_LIST THEN err := rlib_list(libname)
        ELSE IF cmd = ARG_CMD_DEL THEN err := rlib_delete(libname, filename)
        ELSE IF cmd = ARG_CMD_EXT THEN err := rlib_extract(libname, filename, modname);
        IF err THEN Halt(1);
END.