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
{$A+,I+,S-,R-,D-,L-,Q-,F-,G-}
USES system2, args, rdffmt;

PROCEDURE bin2rdf(inp : STRING; VAR out : STRING; VAR name : RDFNAME; is_code : BOOLEAN);
VAR     i, o            : BFile;
        code, data, hdr : BFile;
        rec             : REXP_REC;
        str             : STRING;
BEGIN
        Assign(i, inp);
        Reset(i);
        Assign(o, out);
        Rewrite(o);
        ReWriteMemFile(hdr);
        ReWriteMemFile(code);
        ReWriteMemFile(data);

        IF IsOpen(i) AND IsOpen(o) AND IsOpen(hdr) AND IsOpen(code) AND IsOpen(data) THEN BEGIN
                IF is_code THEN BlockCopy(i, code, FileSize(i))
                ELSE BlockCopy(i, code, FileSize(i));

                FillChar(rec, SizeOf(rec), #0);
                rec.name := name;
                IF is_code THEN rec.seg := 0 ELSE rec.seg := 1;
                SET_EXPORT_REC(rec, str);
                RDF_WRITE_REC(hdr, RREC_GLOBAL, str);

                FillChar(rec, SizeOf(rec), #0);
                rec.name := name + '_SIZE';
                rec.seg := 1;
                rec.offset := FilePos(data);
                SET_EXPORT_REC(rec, str);
                RDF_WRITE_REC(hdr, RREC_GLOBAL, str);
                WriteDWord(data, FileSize(i));

                WRITE_RDF(hdr, 0, code, 1, data, o);
        END ELSE SetDeleteOnClose(o, TRUE);

        Close(hdr);
        Close(code);
        Close(data);
        Close(i);
        Close(o);
END;

CONST
ARG_OUTPUT = 'o';
ARG_ENTRY  = 'name';
ARG_CODE   = 'code';

OPTIONS_DESC : ARRAY[0..2] OF TOPT = (
(name: ARG_OUTPUT; otype: OPTSTR;  help: 'Set output rdf-file name.'),
(name: ARG_ENTRY;  otype: OPTSTR;  help: 'Set rdf-symbol name.'),
(name: ARG_CODE;   otype: OPTBOOL; help: 'Put binary blob into CODE segment (instead DATA).')
);

VAR     myArgs     : TARGSTATE;
        is_code    : BOOLEAN;
        outfname   : STRING;
        entry_name : RDFNAME;
        arg_count  : INTEGER;
BEGIN
        ArgsParse(myArgs, OPTIONS_DESC);

        outfname := GetOptStr(myArgs, ARG_OUTPUT);
        entry_name := GetOptStr(myArgs, ARG_ENTRY);
        is_code := GetOptBool(myArgs, ARG_CODE);

        IF Length(outfname) = 0 THEN SetArgsErr(myArgs, 'No output file.');
        IF Length(entry_name) = 0 THEN SetArgsErr(myArgs, 'No symbol name.');
        IF ArgsCount(myArgs) <> 1 THEN SetArgsErr(myArgs, 'No input file.');

        WriteArgsErrors(myArgs);
        IF ArgsError(myArgs) THEN Halt(1);

        SetUseTempFiles(TRUE);
        arg_count := ArgsCount(myArgs);
        bin2rdf(GetArgsStr(myArgs, 1), outfname, entry_name, is_code);
END.