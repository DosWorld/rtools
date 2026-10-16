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
USES Dos, System2, Args, StrBin, rdffmt, rlo, rvalid
    , rlocom
    , rlordf
    , rlomz
    , rloadam
    , rlole
    , rlomap
    , rloqbe
    , rlodef
    , rlone
    , rlowpe, rloimp, rlosm;

FUNCTION basename(s : STRING) : STRING;
VAR     i : INTEGER;
BEGIN
    i := Length(s);
    WHILE i > 0 DO BEGIN
        IF s[i] IN [':','\','/'] THEN BEGIN Delete(s, 1, i);
            BREAK;
        END;
        Dec(i);
    END;
    basename := s;
END;

VAR
LastFile : PFNAME;

FUNCTION GetRdfMetaInfo(root : PRDFMETA; VAR src : BFILE; VAR
    hdr : BFILE; VAR err : BOOLEAN):PRDFMETA;
VAR     r: PRDFMETA;
    info: TRdfInfo;
BEGIN
    GetRdfMetaInfo := root;
    IF NOT CheckRdf(src, FileSize(src), info) THEN BEGIN
        System.Writeln(src.filename, ': invalid RDF.');
        err := TRUE;
        EXIT;
    END;
    r := NewMeta;
    IF (LastFile = NIL) OR
        (LastFile^ <> src.filename) THEN
        LastFile := NewFileName(src.filename);
    r^.filename := LastFile;
    r^.hdr_size := info.hdr_size;
    r^.hdr_ofs := FilePos(hdr);
    r^.next := root;
    r^.file_code := info.code_ofs;
    r^.file_data := info.data_ofs;
    r^.code_size := info.code_size;
    r^.data_size := info.data_size;
    r^.code_segnum := info.cs;
    r^.data_segnum := info.ds;
    r^.bss_segnum := info.bs;
    Seek(src, info.hdr_ofs);
    IF BlockCopy(src, hdr, info.hdr_size) <>
        info.hdr_size THEN err := TRUE;
    Seek(src, info.finish);
    GetRdfMetaInfo := r;
END;

FUNCTION GetRdlMetaInfo(root : PRDFMETA; fname : STRING; VAR hdr
    : BFILE; VAR err : BOOLEAN):PRDFMETA;
VAR     ft       : RDF_FILE_TYPE;
    i        : BFILE;
    mod_name : STRING;
    mnm      : RDFNAME;
BEGIN
    Assign(i, fname);
    Reset(i);
    IF NOT IsOpen(i) THEN BEGIN
        System.Writeln('Could not open ', fname, '.');
        err := TRUE;
        GetRdlMetaInfo := root;
        EXIT;
    END;
    ft := GET_FILE_TYPE(i);
    IF ft = FILE_RDF THEN BEGIN
        root := GetRdfMetaInfo(root, i, hdr, err);
            IF FilePos(i) <> FileSize(i) THEN BEGIN
            System.Writeln(fname, ': trailing RDF data.');
            err := TRUE;
        END;
    END ELSE IF ft = FILE_RDL THEN BEGIN
        WHILE (NOT err) AND RDL_NEXT_MODULE(i, mod_name) DO BEGIN
            root := GetRdfMetaInfo(root, i, hdr, err);
            IF NOT err THEN BEGIN
                mnm := mod_name;
                root^.modname := NewName(mnm);
            END;
        END;
    END ELSE BEGIN
        System.Writeln(fname, ' is not rdf or rdl.');
        err := TRUE;
    END;
    err := err OR RDF_ERROR;
    Close(i);
    GetRdlMetaInfo := root;
END;

FUNCTION FindFileInRlib(VAR rlib : STRING; fname : STRING) :
    STRING;
VAR
    l, i, t : INTEGER;
    path    : STRING;
    bname   : STRING;
    nname   : STRING;
BEGIN
    IF NOT FileExists(fname) THEN BEGIN
        l := Length(rlib);
        bname := basename(fname);
        IF bname <> fname THEN l := 0;
        fname := '';
        i := 1;
        WHILE i <= l DO BEGIN
            path := '';
            t := i;
            WHILE (t <= l) AND (rlib[t] <> ';') DO BEGIN
                Inc(path[0]);
                path[ORD(path[0])] := rlib[t];
                Inc(t);
            END;
            i := t + 1;
            IF Length(path) > 0 THEN BEGIN
                IF NOT (path[Length(path)] IN ['\', '/']) THEN
                path := path + '\';
                nname := path + bname;
                IF FileExists(nname) THEN BEGIN
                    fname := nname;
                    BREAK;
                END;
            END;
        END;
    END;
    FindFileInRlib := fname;
END;

FUNCTION GetRlibMetaInfo(VAR rlib : STRING; root : PRDFMETA;
    fname : STRING; VAR hdr : BFILE; VAR err : BOOLEAN):PRDFMETA;
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
                root := GetRlibMetaInfo(rlib, root, fname, hdr,
                err);
        END;
        Close(i);
    END ELSE BEGIN
        nname := FindFileInRlib(rlib, fname);
        IF Length(nname) = 0 THEN BEGIN
            System.Writeln('File ', fname, ' does not exist.');
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
ARG_COM    = 'com';
ARG_MZL    = 'mzl';
ARG_MZS    = 'mzs';
ARG_MZT    = 'mzt';
ARG_DOSPE  = 'dospe';
ARG_ADAM   = 'adam';
ARG_LE     = 'le';
ARG_QLB    = 'qlb';
ARG_NE     = 'ne';
ARG_DEF    = 'def';
ARG_RES    = 'res';
ARG_ZRDX   = 'zrdx';
ARG_HX     = 'hx';
ARG_WINPE  = 'winpe';
ARG_STACK  = 's';
ARG_NONAMES = 'nonames';
ARG_MAP     = 'map';
LIB_ENV    = 'RLIB';

OPTIONS_DESC : ARRAY[0..21] OF TOPT = (
(name: ARG_OUTPUT; otype: OPTSTR;  help:
    'Set output file name.'),
(name: ARG_ORG;    otype: OPTSTR;  help:
    'Set code start offset for COM output.'; default:'0x0100'),
(name: ARG_ENTRY;  otype: OPTSTR;  help:
    'Set entry-point name.'; default:'start'),
(name: ARG_STACK;  otype: OPTSTR;  help:
    'Set stack size in KB.'; default:'8'),
(name: ARG_BSS;    otype: OPTBOOL; help:
    'Reserve BSS-memory for COM/RDF output.'),
(name: ARG_DEF;    otype: OPTSTR;  help:
    'NE, WINPE: module definition file (NAME, LIBRARY,.'),
(name: ARG_RES;    otype: OPTSTR;  help:
    'NE: 16-bit .RES file, WINPE: 32-bit .RES file.'),
(name: ARG_NONAMES; otype: OPTBOOL; help:
    'QLB: leave the CODE table empty.'),
(name: ARG_MAP;     otype: OPTBOOL; help:
    'Write map file (output name with .MAP extension).'),
(name: ARG_ZRDX;   otype: OPTBOOL; help:
    'Bind ZRDX Dos-Extender to LE file.'),
(name: ARG_HX;     otype: OPTBOOL; help:
    'dospe: bind HX Dos-Extender stub to PE file.'),
(name: ARG_RDF;    otype: OPTCMD;  help:
    'Link RDF file. Merge all segments into one code segment.'),
(name: ARG_COM;    otype: OPTCMD;  help:
    'Link COM file, tiny memory model.'),
(name: ARG_MZS;    otype: OPTCMD;  help:
    'Link MZ file, small memory model.'),
(name: ARG_MZT;    otype: OPTCMD;  help:
    'Link MZ file, tiny memory model (like COM, with MZ.'),
(name: ARG_MZL;    otype: OPTCMD;  help:
    'Link MZ file, large memory model.'),
(name: ARG_ADAM;   otype: OPTCMD;  help:
    'Link ADAM file (DOS32 Dos-Extender).'),
(name: ARG_LE;     otype: OPTCMD;  help:
    'Link LE file (old-style DPMI executable).'),
(name: ARG_DOSPE;  otype: OPTCMD;  help:
    'Link DOS-PE file (DOS style PE32, imports, exports and.'),
(name: ARG_NE;     otype: OPTCMD;  help:
    'Link NE file (16-bit DPMI executable, one segment per.'),
(name: ARG_WINPE;  otype: OPTCMD;  help:
    'Link Win32-PE file (exe or dll) with imports, exports.'),
(name: ARG_QLB;    otype: OPTCMD;  help:
    'Link QuickBASIC QuickLibrary (QLB). Entry-point is.')
);

FUNCTION LinkRoots(VAR build_plan: IMAGE_BUILD_PLAN;
    entry_name: RDFNAME; cmd: STRING): BOOLEAN;
VAR err, use_wpe: BOOLEAN; i: INTEGER;
    ex: PLINK_EXPORT; r: PRDFMETA;
BEGIN
    use_wpe := (cmd = ARG_WINPE) OR (cmd = ARG_DOSPE);
    err := CreateBuildPlan(build_plan, entry_name);
    IF (NOT err) AND ((cmd = ARG_QLB) OR (use_wpe AND (is_dll OR
        (exp_count > 0)))
        OR ((cmd = ARG_NE) AND (is_dll OR (exp_count > 0))))
            THEN BEGIN
        IF (cmd <> ARG_QLB) AND (exp_count > 0) THEN BEGIN
            i := 1;
            WHILE (i <= exp_count) AND (NOT err) DO BEGIN
                ex := FindExportRdf(build_plan, ExpAt(i)^.sym);
                IF ex <> NIL THEN err := ResolveImports(
                build_plan, ex^.rdf);
                Inc(i);
            END;
        END ELSE BEGIN
            r := build_plan.rdfs;
            WHILE (r <> NIL) AND (NOT err) DO BEGIN
                err := ResolveImports(build_plan, r);
                r := r^.next;
            END;
        END;
    END;
    LinkRoots := err;
END;

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
    rlib          : STRING;
    r             : PRDFMETA;
    ex            : PLINK_EXPORT;
    qbi           : BFILE;
    qbi_open      : BOOLEAN;
    use_wpe       : BOOLEAN;
BEGIN
    ArgsParse(myArgs, OPTIONS_DESC);

    outfname := GetOptStr(myArgs, ARG_OUTPUT);
    entry_name := GetOptStr(myArgs, ARG_ENTRY);
    str_org := GetOptStr(myArgs, ARG_ORG);
    str_ss := GetOptStr(myArgs, ARG_STACK);

    IF ArgsCount(myArgs) = 0 THEN SetArgsErr(myArgs,
        'No input files.');
    IF Length(outfname) = 0 THEN SetArgsErr(myArgs,
        'No output file.');
    IF Length(entry_name) = 0 THEN SetArgsErr(myArgs,
        'No entry point.');
    IF NOT StrAsLong(str_org, bin_org) THEN SetArgsErr(myArgs,
        'Bad code offset.');
    IF NOT StrAsLong(str_ss, bin_ss) THEN SetArgsErr(myArgs,
        'Bad stack size.');

    WriteArgsErrors(myArgs);
    IF ArgsError(myArgs) THEN Halt(1);

    rlib := getEnv(LIB_ENV);

    cmd := GetCmd(myArgs);
    use_wpe := (cmd = ARG_WINPE) OR (cmd = ARG_DOSPE);
    IF (cmd = ARG_WINPE) AND GetOptBool(myArgs, ARG_HX) THEN
        BEGIN
        System.Writeln(
'/hx is for dospe, winpe writes the standard Windows stub.');
        Halt(1);
    END;
    IF (bin_org < 0) OR (bin_org > $FFFF) THEN BEGIN
        System.Writeln('Bad code offset.');
        Halt(1);
    END;
    IF (bin_ss < 0) OR (bin_ss > 2097151) OR (((cmd = ARG_COM)
        OR (cmd = ARG_MZT) OR (cmd = ARG_MZS) OR (cmd = ARG_MZL)
        OR (cmd = ARG_NE)) AND (bin_ss > 64)) THEN BEGIN
        System.Writeln('Bad stack size (COM, MZ: 0..64 Kb).');
        Halt(1);
    END;
    IF ((cmd = ARG_MZS) OR (cmd = ARG_MZL)) AND (bin_ss = 0)
        THEN BEGIN
        System.Writeln('Bad stack size (MZ: 1..64 Kb).');
        Halt(1);
    END;
    IF GetOptBool(myArgs, ARG_MAP) AND (UpStr(MapNameFor(
        outfname)) = UpStr(outfname)) THEN BEGIN
        System.Writeln(
'Map file name is the same as the output file name.');
        Halt(1);
    END;
    bin_ss := bin_ss * 1024;

    FillChar(build_plan, SizeOf(IMAGE_BUILD_PLAN), #0);
    ReWriteTemp(build_plan.hdr);
    err := NOT IsOpen(build_plan.hdr);
    IF err THEN System.Writeln(
        'Could not create temporary file (check TMP/TEMP).');
    arg_count := ArgsCount(myArgs);
    i := 1;
    WHILE (i <= arg_count) AND (NOT err) DO BEGIN
        build_plan.rdfs :=
            GetRlibMetaInfo(rlib, build_plan.rdfs
                , GetArgsStr(myArgs, i)
                , build_plan.hdr, err);
        Inc(i);
    END;
    qbi_open := FALSE;
    IF (NOT err) AND (cmd = ARG_QLB) THEN BEGIN
        QbeOptNames := NOT GetOptBool(myArgs, ARG_NONAMES);
        IF QbeBuildImports(build_plan, qbi, err) THEN BEGIN
            qbi_open := TRUE;
            IF GET_FILE_TYPE(qbi) = FILE_RDF THEN BEGIN
                build_plan.rdfs := GetRdfMetaInfo(
                build_plan.rdfs, qbi, build_plan.hdr, err);
                IF NOT err THEN
                    build_plan.rdfs^.qbimp := TRUE;
            END ELSE err := TRUE;
        END;
    END;
    IF (NOT err) AND (cmd = ARG_NE) THEN err := NeSetup(
        GetOptStr(myArgs, ARG_DEF));
    IF (NOT err) AND use_wpe THEN BEGIN
        err := WpSetup(GetOptStr(myArgs, ARG_DEF));
    END;
    IF NOT err THEN
        err := LinkRoots(build_plan, entry_name, cmd);
    IF (NOT err) AND use_wpe THEN BEGIN
        IF WpBuildImports(qbi, err) THEN BEGIN
            qbi_open := TRUE;
            Seek(qbi, 0);
            build_plan.rdfs := GetRdfMetaInfo(
                build_plan.rdfs, qbi,
                build_plan.hdr, err);
            IF NOT err THEN BEGIN
                IF NOT err THEN
                    build_plan.rdfs^.qbimp := TRUE;
                ClearLinks(build_plan);
                ExtImportOn := FALSE;
                err := LinkRoots(build_plan,
                    entry_name, cmd);
            END;
        END;
    END;
    ReWriteTemp(build_plan.linked_out);
    IF NOT IsOpen(build_plan.linked_out) THEN BEGIN
        System.Writeln(
            'Could not create temporary file (check TMP/TEMP).');
        err := TRUE;
    END;
    FreeOutOfPlan(build_plan);
    IF (NOT err) AND (cmd = ARG_MZL) THEN BEGIN
        err := LinkAndGenMZL(build_plan, entry_name, outfname,
            bin_ss);
    END ELSE IF (NOT err) AND ((cmd = ARG_COM) OR (cmd =
        ARG_MZT)) THEN BEGIN
        err := LinkSmallModel(build_plan);
        IF NOT err THEN err := LinkAndGenCOM(
            build_plan.linked_out
            , bin_org
            , entry_name
            , outfname
            , GetOptBool(myArgs, ARG_BSS)
            , cmd = ARG_MZT
            , bin_ss);
    END ELSE IF (NOT err) AND (cmd = ARG_MZS) THEN BEGIN
        err := LinkAndGenMZS(build_plan
            , entry_name
            , outfname
            , bin_ss);
    END ELSE IF (NOT err) AND (cmd = ARG_RDF) THEN BEGIN
        err := LinkSmallModel(build_plan);
        IF NOT err THEN err := LinkAndGenRDF(
            build_plan.linked_out
            , outfname
            , GetOptBool(myArgs, ARG_BSS));
    END ELSE IF (NOT err) AND (cmd = ARG_ADAM) THEN BEGIN
        err := LinkSmallModel(build_plan);
        IF NOT err THEN err := LinkAndGenAdam(
            build_plan.linked_out
            , entry_name
            , outfname
            , bin_ss);
    END ELSE IF (NOT err) AND (cmd = ARG_LE) THEN BEGIN
        err := LinkSmallModel(build_plan);
        IF NOT err THEN err := LinkAndGenLE(build_plan.linked_out
            , entry_name
            , outfname
            , bin_ss, GetOptBool(myArgs, ARG_ZRDX));
    END ELSE IF (NOT err) AND (cmd = ARG_NE) THEN BEGIN
        err := LinkAndGenNE(build_plan
            , entry_name
            , outfname
            , bin_ss
            , GetOptStr(myArgs, ARG_RES));
    END ELSE IF (NOT err) AND use_wpe THEN BEGIN
        err := LinkSmallModel(build_plan);
        IF NOT err THEN err := LinkAndGenWinPE(
            build_plan.linked_out
            , entry_name
            , outfname
            , bin_ss
            , GetOptStr(myArgs, ARG_RES)
            , GetOptBool(myArgs, ARG_HX)
            , cmd = ARG_WINPE);
    END ELSE IF (NOT err) AND (cmd = ARG_QLB) THEN BEGIN
        err := LinkAndGenQBE(build_plan
            , entry_name
            , outfname);
    END;
    IF (NOT err) AND GetOptBool(myArgs, ARG_MAP) THEN
        err := MapWrite(build_plan, MapNameFor(outfname),
            outfname, cmd, entry_name);
    DestroyPlan(build_plan);
    IF use_wpe OR (cmd = ARG_NE) THEN DefDone;
    Close(build_plan.linked_out);
    IF qbi_open THEN Close(qbi);
    IF err THEN Halt(1);
END.
