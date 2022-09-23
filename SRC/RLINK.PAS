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
USES Dos, System2, Args, StrBin, rdffmt, rlo
        , rlocom
        , rlordf
        , rlomz
        , rloadam
        , rlole
        , rlope;

{$DEFINE DEBUG1}

FUNCTION basename(s : STRING) : STRING;
VAR     i : INTEGER;
BEGIN
        i := Length(s);
        WHILE i > 0 DO BEGIN
                IF s[i] IN [':','\','/'] THEN BEGIN Delete(s, 1, i); BREAK;
                END;
                Dec(i);
        END;
        basename := s;
END;

FUNCTION GetRdfMetaInfo(root : PRDFMETA; VAR src : BFILE; VAR hdr : BFILE):PRDFMETA;
VAR     r        : PRDFMETA;
        mod_size : DWORD;
        hdr_size : DWORD;
        rec      : RDF_SEG;
BEGIN
        Seek(src, FilePos(src) + 6);
        mod_size := ReadDWord(src);
        hdr_size := ReadDWord(src);
        GetMem(r, SizeOf(TRDFMETA));
        FillChar(r^, SizeOf(TRDFMETA), #0);
        r^.filename := src.filename;
        r^.hdr_size := hdr_size;
        r^.hdr_ofs := FilePos(hdr);
        r^.next := root;
        root := r;
        BlockCopy(src, hdr, hdr_size);
        WHILE READ_SEG_REC(src, rec) DO BEGIN
                IF rec.segtype = RDFCS THEN BEGIN
                        r^.file_code := FilePos(src);
                        r^.code_size := rec.seglen;
                        r^.code_segnum := rec.segnum;
                        Seek(src, FilePos(src) + rec.seglen);
                END ELSE IF rec.segtype = RDFDS THEN BEGIN
                        r^.file_data := FilePos(src);
                        r^.data_size := rec.seglen;
                        r^.data_segnum := rec.segnum;
                        Seek(src, FilePos(src) + rec.seglen);
                END;
        END;
        r^.bss_segnum := r^.code_segnum;
        IF r^.bss_segnum < r^.data_segnum THEN r^.bss_segnum := r^.data_segnum;
        Inc(r^.bss_segnum);
        GetRdfMetaInfo := root;
END;

FUNCTION GetRdlMetaInfo(root : PRDFMETA; fname : STRING; VAR hdr : BFILE; VAR err : BOOLEAN):PRDFMETA;
VAR     ft       : RDF_FILE_TYPE;
        i        : BFILE;
        mod_name : STRING;
BEGIN
        Assign(i, fname);
        Reset(i);
        ft := GET_FILE_TYPE(i);
        IF ft = FILE_RDF THEN BEGIN
                root := GetRdfMetaInfo(root, i, hdr);
        END ELSE IF ft = FILE_RDL THEN BEGIN
                WHILE RDL_NEXT_MODULE(i, mod_name) DO BEGIN
                        root := GetRdfMetaInfo(root, i, hdr);
                END;
        END ELSE err := TRUE;
        Close(i);
        GetRdlMetaInfo := root;
END;

FUNCTION FindFileInRlib(VAR rlib : STRING; fname : STRING) : STRING;
VAR
        l, i, t : INTEGER;
        path    : STRING;
        bname   : STRING;
        nname   : STRING;
BEGIN
        IF NOT FileExists(fname) THEN BEGIN
                l := Length(rlib);
                bname := basename(fname);
                fname := '';
                i := 1;
                IF FileExists(bname) THEN BEGIN
                        fname := bname;
                END ELSE WHILE i < l DO BEGIN
                        path := '';
                        t := i;
                        WHILE (t <= l) AND (rlib[t] <> ';') DO BEGIN
                                Inc(path[0]);
                                path[ORD(path[0])] := rlib[t];
                                Inc(t);
                        END;
                        i := t + 1;
                        IF Length(path) > 0 THEN BEGIN
                                IF NOT (path[Length(path)] IN ['\', '/']) THEN path := path + '\';
                                nname := path + bname;
                                IF FileExists(nname) THEN BEGIN
                                        fname := nname;
                                        BREAK;
                                END;
                        END;
                END;
        END;
        {$IFDEF DEBUG}
        System.Writeln('Load ', fname);
        {$ENDIF}
        FindFileInRlib := fname;
END;

FUNCTION GetRlibMetaInfo(VAR rlib : STRING; root : PRDFMETA; fname : STRING; VAR hdr : BFILE; VAR err : BOOLEAN):PRDFMETA;
VAR     i        : BFILE;
        nname    : STRING;
BEGIN
        IF (fname[0] > #1) AND (fname[1] = '@') THEN BEGIN
                delete(fname, 1, 1);
                Assign(i, fname);
                Reset(i);
                err := err OR (NOT IsOpen(i));
                WHILE (NOT EOF(i)) AND (NOT err) DO BEGIN
                        ReadLn(i, fname);
                        IF Length(fname) <> 0 THEN IF fname[1] <> '@' THEN
                                root := GetRlibMetaInfo(rlib, root, fname, hdr, err);
                END;
                Close(i);
        END ELSE BEGIN
                nname := FindFileInRlib(rlib, fname);
                IF Length(nname) = 0 THEN BEGIN
                        System.Writeln('File ', fname, ' does not exists.');
                        err := TRUE;
                END ELSE root := GetRdlMetaInfo(root, nname, hdr, err)
        END;
        GetRlibMetaInfo := root;
END;

CONST
ARG_OUTPUT = 'o';
ARG_ENTRY  = 'entry';
ARG_ORG    = 'org';
ARG_BSS    = 'bss';
ARG_RDF    = 'rdf';
ARG_EMEM   = 'emem';
ARG_COM    = 'com';
ARG_MZL    = 'mzl';
ARG_MZS    = 'mzs';
ARG_DOSPE  = 'dospe';
ARG_ADAM   = 'adam';
ARG_LE     = 'le';
ARG_ZRDX   = 'zrdx';
ARG_HX     = 'hx';
ARG_WINPE  = 'winpe';
ARG_STACK  = 's';
LIB_ENV    = 'RLIB';

OPTIONS_DESC : ARRAY[0..13] OF TOPT = (
(name: ARG_OUTPUT; otype: OPTSTR;  help: 'Set output file name.'),
(name: ARG_ORG;    otype: OPTSTR;  help: 'Set code start offset for COM output.'; default:'0x0100'),
(name: ARG_ENTRY;  otype: OPTSTR;  help: 'Set entry-point name.'; default:'start'),
(name: ARG_STACK;  otype: OPTSTR;  help: 'Set stack size in KB.'; default:'8'),
(name: ARG_BSS;    otype: OPTBOOL; help: 'Reserve BSS-memory for COM/RDF output.'),
(name: ARG_ZRDX;   otype: OPTBOOL; help: 'Bind ZRDX Dos-Extender to LE file.'),
(name: ARG_HX;     otype: OPTBOOL; help: 'Bind HX Dos-Extender stub to PE file.'),
(name: ARG_RDF;    otype: OPTCMD;  help: 'Link RDF file. Merge all segments into one code segment.'),
(name: ARG_COM;    otype: OPTCMD;  help: 'Link COM file, tiny memory model.'),
(name: ARG_MZS;    otype: OPTCMD;  help: 'Link MZ file, small memory model.'),
(name: ARG_MZL;    otype: OPTCMD;  help: 'Link MZ file, large memory model.'),
(name: ARG_ADAM;   otype: OPTCMD;  help: 'Link ADAM file (DOS32 Dos-Extender).'),
(name: ARG_LE;     otype: OPTCMD;  help: 'Link LE file (old-style DPMI executable).'),
(name: ARG_DOSPE;  otype: OPTCMD;  help: 'Link DOS-PE file (PE without imports).') {,
(name: ARG_WINPE;  otype: OPTCMD;  help: 'Link Win32-PE file.')}
);

VAR     myArgs        : TARGSTATE;
        bin_org       : LONGINT;
        str_org       : STRING;
        bin_ss        : LONGINT;
        str_ss        : STRING;
        cmd           : STRING;
        outfname      : STRING;
        entry_name    : RDFNAME;
        build_plan    : IMAGE_BUILD_PLAN;
        i, arg_count  : INTEGER;
        err           : BOOLEAN;
        strict_import : BOOLEAN;
        rlib          : STRING;
BEGIN
        ArgsParse(myArgs, OPTIONS_DESC);

        outfname := GetOptStr(myArgs, ARG_OUTPUT);
        entry_name := GetOptStr(myArgs, ARG_ENTRY);
        str_org := GetOptStr(myArgs, ARG_ORG);
        str_ss := GetOptStr(myArgs, ARG_STACK);

        IF ArgsCount(myArgs) = 0 THEN SetArgsErr(myArgs, 'No input files.');
        IF Length(outfname) = 0 THEN SetArgsErr(myArgs, 'No output file.');
        IF Length(entry_name) = 0 THEN SetArgsErr(myArgs, 'No entry point.');
        IF NOT StrAsLong(str_org, bin_org) THEN SetArgsErr(myArgs, 'Bad code offset.');
        IF NOT StrAsLong(str_ss, bin_ss) THEN SetArgsErr(myArgs, 'Bad stack size.');

        WriteArgsErrors(myArgs);
        IF ArgsError(myArgs) THEN Halt(1);

        rlib := getEnv(LIB_ENV);
        {$IFDEF DEBUG}
        System.Writeln('RLIB=', rlib);
        {$ENDIF}

        cmd := GetCmd(myArgs);
        bin_ss := bin_ss * 1024;

        FillChar(build_plan, SizeOf(IMAGE_BUILD_PLAN), #0);
        ReWriteTemp(build_plan.hdr);
        err := FALSE;
        arg_count := ArgsCount(myArgs);
        i := 1;
        WHILE (i <= arg_count) AND (NOT err) DO BEGIN
                build_plan.rdfs :=
                        GetRlibMetaInfo(rlib, build_plan.rdfs
                                , GetArgsStr(myArgs, i)
                                , build_plan.hdr, err);
                Inc(i);
        END;
        IF cmd = ARG_DOSPE THEN strict_import := FALSE ELSE strict_import := TRUE;
        IF NOT err THEN err := CreateBuildPlan(build_plan, entry_name, strict_import);
        {$IFDEF DEBUG}
        Assign(build_plan.linked_out, 'small.rdf');
        ReWrite(build_plan.linked_out);
        {$ENDIF}
        {$IFNDEF DEBUG}
        ReWriteTemp(build_plan.linked_out);
        {$ENDIF}
        FreeOutOfPlan(build_plan);
        IF (NOT err) AND (cmd = ARG_MZL) THEN BEGIN
                err := LinkAndGenMZL(build_plan, entry_name, outfname, bin_ss);
                DestroyPlan(build_plan);
        END ELSE IF (NOT err) AND (cmd = ARG_COM) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenCOM(build_plan.linked_out
                        , bin_org
                        , entry_name
                        , outfname
                        , GetOptBool(myArgs, ARG_BSS));
        END ELSE IF (NOT err) AND (cmd = ARG_MZS) THEN BEGIN
                err := LinkAndGenMZS(build_plan
                        , entry_name
                        , outfname
                        , bin_ss);
                DestroyPlan(build_plan);
        END ELSE IF (NOT err) AND (cmd = ARG_RDF) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenRDF(build_plan.linked_out
                        , outfname
                        , GetOptBool(myArgs, ARG_BSS));
        END ELSE IF (NOT err) AND (cmd = ARG_ADAM) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenAdam(build_plan.linked_out
                        , entry_name
                        , outfname
                        , bin_ss);
        END ELSE IF (NOT err) AND (cmd = ARG_LE) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenLE(build_plan.linked_out
                        , entry_name
                        , outfname
                        , bin_ss, GetOptBool(myArgs, ARG_ZRDX));
        END ELSE IF (NOT err) AND (cmd = ARG_DOSPE) THEN BEGIN
                err := LinkSmallModel(build_plan);
                DestroyPlan(build_plan);
                IF NOT err THEN err := LinkAndGenDosPE(build_plan.linked_out
                        , entry_name
                        , outfname
                        , bin_ss, GetOptBool(myArgs, ARG_HX));
        END ELSE DestroyPlan(build_plan);
        Close(build_plan.linked_out);
        IF err THEN Halt(1);
END.
