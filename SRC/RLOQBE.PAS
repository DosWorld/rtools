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
UNIT rloqbe;

{$DEFINE DEBUG1}


INTERFACE

USES system2, rdffmt, rlo;

CONST
QB_HDR_PAR     = $40;
QB_DATA_BASE   = $3360;
QB_ULVARS_SIZE = $20;
QB_MAGIC       = $6C75;
QB_BLOCK_HDR   = 34;
QB_NAME_ULVARS = 'b_ULVars';


QB_RT_SIZE     = 281;
QB_RT_EP       = $00;
QB_RT_MASK     = $04;
QB_RT_DISP     = $06;
QB_RT_STUB     = $21;

QB_RT : ARRAY [0..QB_RT_SIZE - 1] OF BYTE = (
        $00, $00, $00, $00, $00, $00, $80, $F9, $0A, $74, $20, $80,
        $F9, $10, $74, $12, $51, $51, $2E, $FF, $1E, $00, $00, $59,
        $80, $F9, $08, $72, $03, $CA, $02, $00, $CB, $CB, $31, $C0,
        $31, $DB, $31, $D2, $CA, $02, $00, $55, $89, $E5, $56, $57,
        $06, $50, $50, $FC, $8B, $5E, $06, $8B, $0F, $8B, $77, $02,
        $09, $D2, $74, $02, $B2, $01, $30, $F6, $0E, $07, $51, $56,
        $B8, $05, $15, $08, $D2, $74, $03, $B8, $04, $B6, $E3, $1D,
        $89, $C7, $AC, $E8, $AA, $00, $30, $E4, $89, $C3, $89, $F8,
        $D1, $E0, $D1, $E0, $D1, $E0, $D1, $E0, $D1, $E0, $01, $F8,
        $01, $D8, $49, $EB, $E1, $5E, $59, $89, $C7, $0D, $00, $80,
        $89, $46, $F8, $2E, $8B, $1E, $04, $00, $21, $DF, $D1, $E7,
        $D1, $E7, $89, $7E, $F6, $8B, $7E, $F6, $2E, $8B, $85, $19,
        $01, $09, $C0, $74, $52, $3B, $46, $F8, $75, $32, $2E, $8B,
        $9D, $1B, $01, $8D, $7F, $04, $08, $D2, $74, $07, $26, $80,
        $3D, $5F, $75, $20, $47, $51, $56, $E3, $0A, $AC, $E8, $4F,
        $00, $AE, $75, $07, $49, $EB, $F4, $26, $80, $3D, $00, $5E,
        $59, $75, $09, $26, $8B, $07, $26, $8B, $57, $02, $EB, $1F,
        $2E, $8B, $1E, $04, $00, $D1, $E3, $D1, $E3, $81, $CB, $03,
        $00, $8B, $7E, $F6, $81, $C7, $04, $00, $21, $DF, $89, $7E,
        $F6, $EB, $A2, $31, $C0, $31, $D2, $81, $C4, $04, $00, $50,
        $52, $8B, $5E, $06, $BF, $1A, $00, $FF, $1E, $C2, $00, $5A,
        $58, $07, $5F, $5E, $5D, $CA, $02, $00, $08, $D2, $74, $06,
        $3C, $2E, $75, $02, $B0, $5F, $3C, $61, $72, $06, $3C, $7A,
        $77, $02, $2C, $20, $C3
);

TYPE
TQBEEXP = RECORD
        name : RDFNAME;
        ofs  : WORD;
        seg  : WORD;
END;

VAR
QbeOptNames : BOOLEAN;

FUNCTION QbeRuntimeParas(n_code, names_size : DWORD) : DWORD;

FUNCTION QbeFinish(VAR code, tail, relocs, exports : BFILE;
        n_rel, n_code, n_names, w2_code : DWORD;
        entry_ofs, entry_seg : WORD;
        outfname : STRING) : BOOLEAN;

FUNCTION QbeBuildImports(VAR build_plan : IMAGE_BUILD_PLAN;
        VAR rdf : BFILE; VAR err : BOOLEAN) : BOOLEAN;

FUNCTION LinkAndGenQBE(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname   : STRING) : BOOLEAN;

IMPLEMENTATION

USES exe;

PROCEDURE AddReloc(VAR relocs : BFILE; VAR n_rel : DWORD; ofs, seg : WORD);
BEGIN
        WriteWord(relocs, ofs);
        WriteWord(relocs, seg);
        Inc(n_rel);
END;

PROCEDURE WriteName(VAR f : BFILE; name : STRING);
VAR     i : INTEGER;
BEGIN
        FOR i := 1 TO Length(name) DO WriteByte(f, ORD(name[i]));
        WriteByte(f, 0);
END;

PROCEDURE WriteEntry(VAR f, relocs : BFILE; VAR n_rel : DWORD;
        w3, flags, nameofs, ofs, seg : WORD);
BEGIN
        AddReloc(relocs, n_rel, FilePos(f) + 6, w3);
        WriteWord(f, flags);
        WriteWord(f, nameofs);
        WriteWord(f, ofs);
        WriteWord(f, seg);
END;

PROCEDURE WriteZeros(VAR f : BFILE; count : DWORD);
BEGIN
        WHILE count > 0 DO BEGIN
                WriteByte(f, 0);
                Dec(count);
        END;
END;

FUNCTION QbHash(VAR name : RDFNAME) : WORD;
VAR     h : DWORD;
        i : INTEGER;
BEGIN
        h := $1505;
        FOR i := 1 TO Length(name) DO
                h := (h * 33 + ORD(UpCase(name[i]))) AND $FFFF;
        QbHash := h;
END;

FUNCTION HashSlots(n_code : DWORD) : DWORD;
VAR     slots : DWORD;
BEGIN
        slots := 4;
        WHILE slots < (n_code * 2) DO slots := slots SHL 1;
        HashSlots := slots;
END;

FUNCTION QbeRuntimeParas(n_code, names_size : DWORD) : DWORD;
BEGIN
        QbeRuntimeParas := (QB_RT_SIZE + (HashSlots(n_code) * 4) + names_size + $0F) SHR 4;
END;

CONST
QBI_PROC  = 0;
QBI_FAR   = 1;
QBI_ERR   = 2;
QBI_VAR   = 3;
QBI_COUNT = 122;

TYPE
TQBIMP = RECORD
        name : STRING[20];
        kind : BYTE;
        val  : WORD;
END;

CONST
QBI : ARRAY [1..QBI_COUNT] OF TQBIMP = (
        (name: 'B$BREAK_CHK';    kind: QBI_PROC; val: 0),
        (name: 'B$FOUTBX';       kind: QBI_PROC; val: 2),
        (name: 'B$LHLOCFDB';     kind: QBI_PROC; val: 4),
        (name: 'B$RES_SETUP';    kind: QBI_PROC; val: 6),
        (name: 'B$TYPUI';        kind: QBI_PROC; val: 8),
        (name: 'B$LHFDBLOC';     kind: QBI_PROC; val: 10),
        (name: 'B$$WCLF';        kind: QBI_PROC; val: 12),
        (name: 'B$$RCH';         kind: QBI_PROC; val: 14),
        (name: 'B$$TCR';         kind: QBI_PROC; val: 16),
        (name: 'B$$WCH';         kind: QBI_PROC; val: 18),
        (name: 'B$STALCTMP';     kind: QBI_PROC; val: 20),
        (name: 'B$TTY_SOUT';     kind: QBI_PROC; val: 22),
        (name: 'B$STDALC';       kind: QBI_PROC; val: 24),
        (name: 'B$STDALCTMP';    kind: QBI_PROC; val: 26),
        (name: 'B$STDALCALLTMP'; kind: QBI_PROC; val: 28),
        (name: 'B$PUTNUM';       kind: QBI_PROC; val: 30),
        (name: '__BRUNERR';      kind: QBI_PROC; val: 32),
        (name: 'B$RUNERR';       kind: QBI_PROC; val: 34),
        (name: 'B$FHHighAlloc';  kind: QBI_PROC; val: 36),
        (name: 'B$FHHighDealloc'; kind: QBI_PROC; val: 38),
        (name: 'B$IFHAlloc';     kind: QBI_PROC; val: 40),
        (name: 'B$FHDealloc';    kind: QBI_PROC; val: 42),
        (name: 'B$ULReload';     kind: QBI_FAR;  val: 0),
        (name: 'B$IStop';        kind: QBI_FAR;  val: 4),
        (name: 'B$END';          kind: QBI_FAR;  val: 8),
        (name: 'B$GetNmalloc';   kind: QBI_FAR;  val: 12),
        (name: 'B$IEND';         kind: QBI_FAR;  val: 16),
        (name: 'B$SetUEvent';    kind: QBI_FAR;  val: 20),
        (name: 'B$ERR_BFM';      kind: QBI_ERR;  val: 54),
        (name: 'B$ERR_IFN';      kind: QBI_ERR;  val: 52),
        (name: 'B$ERR_DV0';      kind: QBI_ERR;  val: 11),
        (name: 'B$ERR_FC';       kind: QBI_ERR;  val: 5),
        (name: 'B$ERR_RG';       kind: QBI_ERR;  val: 3),
        (name: 'B$ERR_OM';       kind: QBI_ERR;  val: 7),
        (name: 'B$ERR_AFE';      kind: QBI_ERR;  val: 73),
        (name: 'B$ERR_OV';       kind: QBI_ERR;  val: 6),
        (name: 'B$ERR_NOL';      kind: QBI_ERR;  val: $9400),
        (name: 'B$ERR_OSS';      kind: QBI_ERR;  val: $9007),
        (name: '__osversion'; kind: QBI_VAR; val: $007F),
        (name: '__aexit_rtn'; kind: QBI_VAR; val: $000A),
        (name: 'STKHQQ'; kind: QBI_VAR; val: $0000),
        (name: 'b$nmalloc_end'; kind: QBI_VAR; val: $00BC),
        (name: '_errno'; kind: QBI_VAR; val: $0077),
        (name: 'b$ULDataStart'; kind: QBI_VAR; val: $00D7),
        (name: 'b$pULtoRTNear'; kind: QBI_VAR; val: $00C2),
        (name: '__aaltstkovr'; kind: QBI_VAR; val: $0002),
        (name: 'b$FHDULFarData'; kind: QBI_VAR; val: $00E1),
        (name: 'b$ULDataLength'; kind: QBI_VAR; val: $00D5),
        (name: 'b$LPTFDB'; kind: QBI_VAR; val: $00F8),
        (name: '__child'; kind: QBI_VAR; val: $00A0),
        (name: 'b$erradr'; kind: QBI_VAR; val: $0102),
        (name: 'b$cCSubs'; kind: QBI_VAR; val: $0113),
        (name: '__nfile'; kind: QBI_VAR; val: $0084),
        (name: '__abrkp'; kind: QBI_VAR; val: $005C),
        (name: 'b$errmod'; kind: QBI_VAR; val: $0106),
        (name: 'b$errlin'; kind: QBI_VAR; val: $010C),
        (name: 'b$PTRFIL'; kind: QBI_VAR; val: $010F),
        (name: '___argc'; kind: QBI_VAR; val: $009A),
        (name: 'b$errnum'; kind: QBI_VAR; val: $010A),
        (name: 'B$VALTYP'; kind: QBI_VAR; val: $00F6),
        (name: '__intno'; kind: QBI_VAR; val: $00AF),
        (name: '__dosvermajor'; kind: QBI_VAR; val: $007F),
        (name: '__oserr'; kind: QBI_VAR; val: $0082),
        (name: '___argv'; kind: QBI_VAR; val: $009C),
        (name: '__dosverminor'; kind: QBI_VAR; val: $0080),
        (name: 'b$FHDULNearData'; kind: QBI_VAR; val: $00D9),
        (name: 'b$chaindata_len'; kind: QBI_VAR; val: $00C7),
        (name: 'b_erradr'; kind: QBI_VAR; val: $0102),
        (name: 'b$pendchk'; kind: QBI_VAR; val: $00B6),
        (name: 'b_errmod'; kind: QBI_VAR; val: $0106),
        (name: 'b$cNonQBIFrames'; kind: QBI_VAR; val: $0115),
        (name: '$AC'; kind: QBI_VAR; val: $00CB),
        (name: 'b_errlin'; kind: QBI_VAR; val: $010C),
        (name: '__acmdln'; kind: QBI_VAR; val: $00A8),
        (name: 'b$pBC_SAB'; kind: QBI_VAR; val: $00B8),
        (name: '__abrktb'; kind: QBI_VAR; val: $000C),
        (name: '__aseglo'; kind: QBI_VAR; val: $0117),
        (name: 'b_errnum'; kind: QBI_VAR; val: $010A),
        (name: '_environ'; kind: QBI_VAR; val: $009E),
        (name: '__osfile'; kind: QBI_VAR; val: $0086),
        (name: 'b$inonerr'; kind: QBI_VAR; val: $010E),
        (name: '__osmode'; kind: QBI_VAR; val: $0081),
        (name: '__pspadr'; kind: QBI_VAR; val: $007B),
        (name: '__asizds'; kind: QBI_VAR; val: $0006),
        (name: '__ovlvec'; kind: QBI_VAR; val: $00B0),
        (name: '__atopsp'; kind: QBI_VAR; val: $0008),
        (name: 'b$EVTRETV'; kind: QBI_VAR; val: $00F2),
        (name: 'b$nmalloc_start'; kind: QBI_VAR; val: $00BA),
        (name: '__pgmptr'; kind: QBI_VAR; val: $00A2),
        (name: 'b$Chaining'; kind: QBI_VAR; val: $00C6),
        (name: 'B$AC'; kind: QBI_VAR; val: $00CF),
        (name: '$DAC'; kind: QBI_VAR; val: $00CB),
        (name: '__acmdseg'; kind: QBI_VAR; val: $00AA),
        (name: '__acfinfo'; kind: QBI_VAR; val: $005E),
        (name: '__abrktbe'; kind: QBI_VAR; val: $005C),
        (name: 'b$curframe'; kind: QBI_VAR; val: $00EE),
        (name: '__aenvseg'; kind: QBI_VAR; val: $00AC),
        (name: 'b$curlevel'; kind: QBI_VAR; val: $00F0),
        (name: '__ovlflag'; kind: QBI_VAR; val: $00AE),
        (name: '__aintdiv'; kind: QBI_VAR; val: $006B),
        (name: '__osmajor'; kind: QBI_VAR; val: $007F),
        (name: 'b$ULSymSeg'; kind: QBI_VAR; val: $00D3),
        (name: '__osminor'; kind: QBI_VAR; val: $0080),
        (name: 'B$DAC'; kind: QBI_VAR; val: $00CB),
        (name: 'b$mainframe'; kind: QBI_VAR; val: $00EC),
        (name: 'b$CtrlFlags'; kind: QBI_VAR; val: $00E9),
        (name: 'b$seg'; kind: QBI_VAR; val: $00C9),
        (name: '__bpBC_SAB'; kind: QBI_VAR; val: $00B8),
        (name: 'b$userflags'; kind: QBI_VAR; val: $00EA),
        (name: 'b_ULSymSeg'; kind: QBI_VAR; val: $00D3),
        (name: '__umaskval'; kind: QBI_VAR; val: $0079),
        (name: '__doserrno'; kind: QBI_VAR; val: $0082),
        (name: 'b$RTMOverlayStart'; kind: QBI_VAR; val: $00C6),
        (name: '__fac'; kind: QBI_VAR; val: $006F),
        (name: 'b$pend'; kind: QBI_VAR; val: $00B4),
        (name: 'b$PUDS'; kind: QBI_VAR; val: $00FE),
        (name: '__psp'; kind: QBI_VAR; val: $007D),
        (name: '__anullsize'; kind: QBI_VAR; val: $0000),
        (name: 'b$pULtoRTFar'; kind: QBI_VAR; val: $00BE),
        (name: 'b$TTYP'; kind: QBI_VAR; val: $00F7),
        (name: 'b$VTYP'; kind: QBI_VAR; val: $00F6),
        (name: 'b$cfilex'; kind: QBI_VAR; val: $006A)
);

FUNCTION QbiFind(VAR name : RDFNAME) : INTEGER;
VAR     i, j : INTEGER;
        ok   : BOOLEAN;
BEGIN
        QbiFind := 0;
        FOR i := 1 TO QBI_COUNT DO BEGIN
                IF Length(QBI[i].name) = Length(name) THEN BEGIN
                        ok := TRUE;
                        FOR j := 1 TO Length(name) DO
                                IF UpCase(QBI[i].name[j]) <> UpCase(name[j]) THEN BEGIN
                                        ok := FALSE;
                                        BREAK;
                                END;
                        IF ok THEN BEGIN
                                QbiFind := i;
                                EXIT;
                        END;
                END;
        END;
END;

PROCEDURE QbiThunk(VAR code : BFILE; kind : BYTE; val : WORD);
BEGIN
        CASE kind OF
        QBI_PROC: BEGIN
                WriteByte(code, $57);
                WriteByte(code, $BF);
                WriteWord(code, val);
                WriteByte(code, $FF);
                WriteByte(code, $1E);
                WriteWord(code, $00C2);
                WriteByte(code, $5F);
                WriteByte(code, $CB);
        END;
        QBI_FAR: BEGIN
                WriteByte(code, $BB);
                WriteWord(code, val);
                WriteByte(code, $FF);
                WriteByte(code, $2E);
                WriteWord(code, $00BE);
        END;
        QBI_ERR: BEGIN
                WriteByte(code, $BB);
                WriteWord(code, val);
                WriteByte(code, $57);
                WriteByte(code, $BF);
                WriteWord(code, 34);
                WriteByte(code, $FF);
                WriteByte(code, $1E);
                WriteWord(code, $00C2);
                WriteByte(code, $5F);
                WriteByte(code, $CB);
        END;
        END;
END;

FUNCTION QbeBuildImports(VAR build_plan : IMAGE_BUILD_PLAN;
        VAR rdf : BFILE; VAR err : BOOLEAN) : BOOLEAN;
VAR     r     : PRDFMETA;
        s     : STRING;
        irec  : RIMP_REC;
        erec  : REXP_REC;
        used  : ARRAY [1..QBI_COUNT] OF BOOLEAN;
        i, k  : INTEGER;
        any   : BOOLEAN;
        code  : BFILE;
        data  : BFILE;
        hdr   : BFILE;
BEGIN
        QbeBuildImports := FALSE;
        FillChar(used, SizeOf(used), #0);
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_IMPORT, s) DO BEGIN
                        GET_IMPORT_REC(s, irec);
                        k := QbiFind(irec.name);
                        IF k > 0 THEN used[k] := TRUE;
                END;
                r := r^.next;
        END;
        r := build_plan.rdfs;
        WHILE r <> NIL DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_GLOBAL, s) DO BEGIN
                        GET_EXPORT_REC(s, erec);
                        k := QbiFind(erec.name);
                        IF k > 0 THEN used[k] := FALSE;
                END;
                r := r^.next;
        END;
        any := FALSE;
        FOR i := 1 TO QBI_COUNT DO IF used[i] THEN any := TRUE;
        IF NOT any THEN EXIT;

        FillChar(code, SizeOf(BFILE), #0);
        FillChar(data, SizeOf(BFILE), #0);
        FillChar(hdr, SizeOf(BFILE), #0);
        ReWriteTemp(code);
        ReWriteTemp(data);
        ReWriteTemp(hdr);
        ReWriteTemp(rdf);
        IF NOT (IsOpen(code) AND IsOpen(data) AND IsOpen(hdr) AND IsOpen(rdf)) THEN BEGIN
                System.Writeln('Could not create temporary file (check TMP/TEMP).');
                err := TRUE;
        END ELSE BEGIN
                FOR i := 1 TO QBI_COUNT DO IF used[i] THEN BEGIN
                        FillChar(erec, SizeOf(erec), #0);
                        erec.name := QBI[i].name;
                        IF QBI[i].kind = QBI_VAR THEN BEGIN
                                erec.seg := 1;
                                erec.offset := QBI[i].val;
                        END ELSE BEGIN
                                erec.seg := 0;
                                erec.offset := FilePos(code);
                                QbiThunk(code, QBI[i].kind, QBI[i].val);
                        END;
                        SET_EXPORT_REC(erec, s);
                        RDF_WRITE_REC(hdr, RREC_GLOBAL, s);
                END;
                WRITE_RDF(hdr, 0, code, 1, data, rdf);
                Flush(rdf);
                QbeBuildImports := TRUE;
        END;
        Close(hdr);
        Close(data);
        Close(code);
END;

FUNCTION QbeFinish(VAR code, tail, relocs, exports : BFILE;
        n_rel, n_code, n_names, w2_code : DWORD;
        entry_ofs, entry_seg : WORD;
        outfname : STRING) : BOOLEAN;
VAR     err        : BOOLEAN;
        o          : BFILE;
        scr        : BFILE;
        blk        : BFILE;
        rel2       : BFILE;
        htab       : BFILE;
        ents       : BFILE;
        hdr        : MZ_HEADER;
        ex         : TQBEEXP;
        ename      : RDFNAME;
        ent_ofs    : DWORD;
        ci         : INTEGER;
        w2         : DWORD;
        w3         : DWORD;
        w4         : DWORD;
        rt_seg     : DWORD;
        data_par   : DWORD;
        hdr_par    : DWORD;
        total      : DWORD;
        pool_ofs   : DWORD;
        name_ofs   : DWORD;
        sym_ofs    : DWORD;
        dat_ofs    : DWORD;
        seg_ofs    : DWORD;
        q_ofs      : DWORD;
        slots      : DWORD;
        idx        : DWORD;
        hv         : WORD;
        k          : DWORD;
        n_all      : DWORD;
        cn_ofs     : DWORD;
BEGIN
        err := n_code = 0;
        n_all := 0;
        FillChar(hdr, SizeOf(MZ_HEADER), #0);
        FillChar(o, SizeOf(BFILE), #0);
        FillChar(scr, SizeOf(BFILE), #0);
        FillChar(blk, SizeOf(BFILE), #0);
        FillChar(rel2, SizeOf(BFILE), #0);
        FillChar(htab, SizeOf(BFILE), #0);
        FillChar(ents, SizeOf(BFILE), #0);
        IF NOT err THEN BEGIN
                Assign(o, outfname);
                ReWrite(o);
                ReWriteTemp(scr);
                ReWriteTemp(blk);
                ReWriteTemp(rel2);
                ReWriteTemp(htab);
                ReWriteTemp(ents);
                err := NOT (IsOpen(o) AND IsOpen(scr) AND IsOpen(blk)
                        AND IsOpen(rel2) AND IsOpen(htab) AND IsOpen(ents));
        END;

        IF NOT err THEN BEGIN
                Seek(code, FileSize(code));
                FilePosAlign(code, $10);
                rt_seg := FilePos(code) SHR 4;
                Seek(relocs, 0);
                BlockCopy(relocs, rel2, FileSize(relocs));
                n_all := n_rel;
        END;

        IF NOT err THEN BEGIN
                slots := HashSlots(n_code);
                WriteZeros(htab, slots * 4);
                ent_ofs := QB_RT_SIZE + (slots * 4);
                Seek(exports, 0);
                k := 0;
                WHILE k < n_code DO BEGIN
                        BlockRead(exports, ex, SizeOf(TQBEEXP));
                        hv := QbHash(ex.name);
                        idx := hv AND (slots - 1);
                        WHILE GetWord(htab, idx * 4) <> 0 DO
                                idx := (idx + 1) AND (slots - 1);
                        SetWord(htab, idx * 4, hv OR $8000);
                        SetWord(htab, (idx * 4) + 2, ent_ofs + FileSize(ents));
                        AddReloc(rel2, n_all, ent_ofs + FileSize(ents) + 2, rt_seg);
                        WriteWord(ents, ex.ofs);
                        WriteWord(ents, ex.seg);
                        ename := ex.name;
                        FOR ci := 1 TO Length(ename) DO ename[ci] := UpCase(ename[ci]);
                        WriteName(ents, ename);
                        Inc(k);
                END;
                IF ent_ofs + FileSize(ents) > $FFFF THEN BEGIN
                        System.Writeln('Too many symbols.');
                        err := TRUE;
                END;
        END;

        IF NOT err THEN BEGIN
                BlockWrite(code, QB_RT, QB_RT_SIZE);
                Seek(htab, 0);
                BlockCopy(htab, code, FileSize(htab));
                Seek(ents, 0);
                BlockCopy(ents, code, FileSize(ents));
                FilePosAlign(code, $10);
                SetWord(code, (rt_seg SHL 4) + QB_RT_EP, entry_ofs);
                SetWord(code, (rt_seg SHL 4) + QB_RT_EP + 2, entry_seg);
                SetWord(code, (rt_seg SHL 4) + QB_RT_MASK, slots - 1);
                w2 := FileSize(code) SHR 4;
                data_par := QB_DATA_BASE SHR 4;
                IF w2 <> w2_code THEN BEGIN
                        System.Writeln('Internal error: size of runtime.');
                        err := TRUE;
                END;
                w3 := w2 + ((QB_DATA_BASE + QB_ULVARS_SIZE + FileSize(tail)) SHR 4);
                IF w3 > $FFFF THEN BEGIN
                        System.Writeln('Library is too large for QuickBASIC.');
                        err := TRUE;
                END;
        END;

        IF NOT err THEN BEGIN
                AddReloc(rel2, n_all, QB_RT_EP + 2, rt_seg);
                AddReloc(rel2, n_all, $02, w2 + data_par);
                AddReloc(rel2, n_all, $06, w2 + data_par);
                AddReloc(rel2, n_all, $0A, w2 + data_par);

                WriteZeros(scr, QB_ULVARS_SIZE);
                SetWord(scr, $00, QB_RT_DISP);
                SetWord(scr, $02, rt_seg);
                SetWord(scr, $04, QB_RT_STUB);
                SetWord(scr, $06, rt_seg);
                SetWord(scr, $08, QB_RT_STUB);
                SetWord(scr, $0A, rt_seg);
                SetWord(scr, $0E, $13);
        END;

        IF NOT err THEN BEGIN
                sym_ofs := QB_BLOCK_HDR;
                dat_ofs := sym_ofs + (n_names * 8) + 2;
                seg_ofs := dat_ofs + 8 + 2;
                pool_ofs := seg_ofs + (5 * 8) + 2;

                WriteByte(blk, $EA);
                WriteWord(blk, entry_ofs);
                WriteWord(blk, entry_seg);
                AddReloc(rel2, n_all, 3, w3);
                WriteByte(blk, 2);
                WriteWord(blk, QB_MAGIC);
                WriteWord(blk, sym_ofs);
                WriteWord(blk, dat_ofs);
                WriteWord(blk, seg_ofs);
                WriteWord(blk, 0);
                WriteWord(blk, w2);
                WriteWord(blk, w3);
                WriteWord(blk, 0);
                WriteWord(blk, w2);
                WriteWord(blk, 0);
                WriteWord(blk, 0);
                WriteWord(blk, w2);
                WriteWord(blk, 0);
                WriteWord(blk, 0);
                AddReloc(rel2, n_all, 14, w3);
                AddReloc(rel2, n_all, 16, w3);
                AddReloc(rel2, n_all, 18, w3);
                AddReloc(rel2, n_all, 22, w3);
                AddReloc(rel2, n_all, 28, w3);

                cn_ofs := pool_ofs + (Length(QB_NAME_ULVARS) + 1) + 5 + 6 + 7 + 6 + 7;
                IF n_names > 0 THEN BEGIN
                        Seek(exports, 0);
                        k := 0;
                        WHILE k < n_code DO BEGIN
                                BlockRead(exports, ex, SizeOf(TQBEEXP));
                                WriteEntry(blk, rel2, n_all, w3, 1, cn_ofs, ex.ofs, ex.seg);
                                Inc(cn_ofs, Length(ex.name) + 1);
                                Inc(k);
                        END;
                END;
                WriteWord(blk, 0);

                name_ofs := pool_ofs;
                WriteEntry(blk, rel2, n_all, w3, 2, name_ofs, QB_DATA_BASE, w2);
                Inc(name_ofs, Length(QB_NAME_ULVARS) + 1);
                WriteWord(blk, 0);

                WriteEntry(blk, rel2, n_all, w3, 3, name_ofs, 0, w2);
                Inc(name_ofs, 5);
                WriteEntry(blk, rel2, n_all, w3, 3, name_ofs, 0, w2 + data_par);
                Inc(name_ofs, 6);
                WriteEntry(blk, rel2, n_all, w3, 3, name_ofs, $10, w2 + data_par);
                Inc(name_ofs, 7);
                WriteEntry(blk, rel2, n_all, w3, 3, name_ofs, 0, w3);
                Inc(name_ofs, 6);
                WriteEntry(blk, rel2, n_all, w3, 3, name_ofs, 0, w3);
                WriteWord(blk, 0);

                WriteName(blk, QB_NAME_ULVARS);
                WriteName(blk, 'NULL');
                WriteName(blk, '_DATA');
                WriteName(blk, 'BC_SAB');
                WriteName(blk, 'STACK');
                WriteName(blk, 'SYMBOL');
                IF n_names > 0 THEN BEGIN
                        Seek(exports, 0);
                        k := 0;
                        WHILE k < n_code DO BEGIN
                                BlockRead(exports, ex, SizeOf(TQBEEXP));
                                WriteName(blk, ex.name);
                                Inc(k);
                        END;
                END;
                WriteByte(blk, 0);
                w4 := FileSize(blk);
                IF w4 > $FFF0 THEN BEGIN
                        System.Writeln('Too many symbols (symbol table is larger than 64K).');
                        err := TRUE;
                END;
                IF n_all > $FFFF THEN BEGIN
                        System.Writeln('Too many relocations.');
                        err := TRUE;
                END;
                SetWord(blk, 20, w4);
        END;

        IF NOT err THEN BEGIN
                hdr_par := (($1E + (n_all * 4)) + $0F) SHR 4;
                IF hdr_par < QB_HDR_PAR THEN hdr_par := QB_HDR_PAR;
                q_ofs := (hdr_par SHL 4) + 2 + (w2 SHL 4) + 2
                        + QB_ULVARS_SIZE + FileSize(tail);
                total := (hdr_par SHL 4) + (w3 SHL 4) + w4;

                hdr.sign := MZ_SIGN;
                hdr.lblk_size := total AND $1FF;
                hdr.blk_count := (total + $1FF) SHR 9;
                hdr.relocs_count := n_all;
                hdr.header_par := hdr_par;
                hdr.min_ext_par := $FFFF;
                hdr.max_ext_par := $FFFF;
                hdr.ss := w3;
                hdr.sp := 0;
                hdr.ip := (q_ofs - (hdr_par SHL 4)) AND $0F;
                hdr.cs := (q_ofs - (hdr_par SHL 4)) SHR 4;
                hdr.relocs_ofs := $1E;

                BlockWrite(o, hdr, SizeOf(MZ_HEADER));
                WriteWord(o, 0);
                Seek(rel2, 0);
                BlockCopy(rel2, o, FileSize(rel2));
                FilePosAlign(o, hdr_par SHL 4);
                WriteWord(o, 0);
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));
                WriteWord(o, QB_DATA_BASE);
                Seek(scr, 0);
                BlockCopy(scr, o, FileSize(scr));
                Seek(tail, 0);
                BlockCopy(tail, o, FileSize(tail));
                Seek(blk, 0);
                BlockCopy(blk, o, FileSize(blk));
        END;
        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(ents);
        Close(htab);
        Close(rel2);
        Close(blk);
        Close(scr);
        Close(o);
        QbeFinish := err;
END;

FUNCTION LinkAndGenQBE(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname   : STRING) : BOOLEAN;
VAR     err        : BOOLEAN;
        i          : BFILE;
        code       : BFILE;
        tail       : BFILE;
        relocs     : BFILE;
        exports    : BFILE;
        ex         : TQBEEXP;
        r          : PRDFMETA;
        start      : PLINK_EXPORT;
        import     : PLINK_IMPORT;
        expl       : PEXPORTS;
        s          : STRING;
        rrec       : RRELOC_REC;
        selfr      : BOOLEAN;
        bss_size   : DWORD;
        w2         : DWORD;
        n_rel      : DWORD;
        n_code     : DWORD;
        n_names    : DWORD;
        names_size : DWORD;
        names_real : DWORD;
        fix        : WORD;
        p          : INTEGER;

BEGIN
        err := FALSE;
        n_rel := 0;
        n_code := 0;
        names_size := 0;
        names_real := 0;
        start := NIL;
        FillChar(i, SizeOf(BFILE), #0);
        FillChar(code, SizeOf(BFILE), #0);
        FillChar(tail, SizeOf(BFILE), #0);
        FillChar(relocs, SizeOf(BFILE), #0);
        FillChar(exports, SizeOf(BFILE), #0);

        ReWriteTemp(code);
        ReWriteTemp(tail);
        ReWriteTemp(relocs);
        ReWriteTemp(exports);
        err := NOT (IsOpen(code) AND IsOpen(tail)
                AND IsOpen(relocs) AND IsOpen(exports));

        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Assign(i, r^.filename);
                Reset(i);
                err := NOT IsOpen(i);
                IF (NOT err) AND (r^.code_size > $10000) THEN BEGIN
                        System.Writeln(r^.filename, ': code segment is larger than 64K.');
                        Close(i);
                        err := TRUE;
                END;
                IF NOT err THEN BEGIN
                        Seek(i, r^.file_code);
                        r^.linker.hmz_code_seg := FilePos(code) SHR 4;
                        BlockCopy(i, code, r^.code_size);
                        FilePosAlign(code, $10);
                        Close(i);
                END;
                r := r^.next;
        END;

        IF NOT err THEN start := FindExportRdf(build_plan, entry_name);
        IF NOT err THEN BEGIN
                IF start = NIL THEN err := TRUE
                ELSE IF start^.rec.seg <> start^.rdf^.code_segnum THEN BEGIN
                        System.Writeln('Entry point ', entry_name, ' is not in the code segment.');
                        err := TRUE;
                END;
        END;

        IF NOT err THEN BEGIN
                r := build_plan.rdfs;
                WHILE r <> NIL DO BEGIN
                        IF NOT r^.qbimp THEN BEGIN
                                expl := r^.linker.export;
                                WHILE expl <> NIL DO BEGIN
                                        FOR p := 1 TO expl^.export_count DO
                                                IF expl^.export[p].rec.seg = r^.code_segnum THEN BEGIN
                                                        ex.name := expl^.export[p].rec.name;
                                                        ex.ofs := expl^.export[p].rec.offset;
                                                        ex.seg := r^.linker.hmz_code_seg;
                                                        BlockWrite(exports, ex, SizeOf(TQBEEXP));
                                                        Inc(n_code);
                                                        Inc(names_size, Length(ex.name) + 5);
                                                        Inc(names_real, Length(ex.name) + 1);
                                                END;
                                        expl := expl^.next;
                                END;
                        END;
                        r := r^.next;
                END;
                IF n_code = 0 THEN BEGIN
                        System.Writeln('No exported code symbols.');
                        err := TRUE;
                END;
        END;
        IF NOT err THEN w2 := (FileSize(code) SHR 4) + QbeRuntimeParas(n_code, names_size);

        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                IF r^.qbimp THEN BEGIN
                        r^.linker.smz_data_ofs := 0;
                        r^.linker.hmz_data_seg := w2;
                        r^.linker.hmz_bss_seg := w2;
                        r := r^.next;
                        CONTINUE;
                END;
                Assign(i, r^.filename);
                Reset(i);
                err := NOT IsOpen(i);
                IF (NOT err) AND (r^.data_size > $10000) THEN BEGIN
                        System.Writeln(r^.filename, ': data segment is larger than 64K.');
                        Close(i);
                        err := TRUE;
                END;
                IF NOT err THEN BEGIN
                        Seek(i, r^.file_data);
                        r^.linker.smz_data_ofs := FilePos(tail);
                        r^.linker.hmz_data_seg := w2
                                + ((QB_DATA_BASE + QB_ULVARS_SIZE + FilePos(tail)) SHR 4);
                        BlockCopy(i, tail, r^.data_size);
                        FilePosAlign(tail, $10);
                        Close(i);

                        Seek(build_plan.hdr, r^.hdr_ofs);
                        bss_size := 0;
                        WHILE RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                                GET_BSS(s, bss_size);
                        END;
                        IF bss_size > $10000 THEN BEGIN
                                System.Writeln(r^.filename, ': bss segment is larger than 64K.');
                                err := TRUE;
                        END;
                        bss_size := AlignValue(bss_size, $10);
                        r^.linker.hmz_bss_seg := w2
                                + ((QB_DATA_BASE + QB_ULVARS_SIZE + FilePos(tail)) SHR 4);
                        IF NOT err THEN WriteZeros(tail, bss_size);
                END;
                r := r^.next;
        END;

        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_SEGRELO, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.width <> RWIDTH16 THEN BEGIN
                                System.Writeln(r^.filename, ': only 16-bit segment relocations are supported.');
                                err := TRUE;
                                BREAK;
                        END;
                        fix := 0;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                                fix := r^.linker.hmz_code_seg;
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                fix := r^.linker.hmz_data_seg;
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                fix := r^.linker.hmz_bss_seg;
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import = NIL THEN BEGIN
                                        System.Writeln(r^.filename, ': unresolved import ', rrec.rseg, '.');
                                        err := TRUE;
                                END ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.code_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_code_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.data_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_data_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.bss_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_bss_seg;
                        END;
                        IF err THEN BREAK;
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_code_seg SHL 4) + rrec.offset
                                        , fix);
                                AddReloc(relocs, n_rel, rrec.offset, r^.linker.hmz_code_seg);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                SetMem(tail, RWIDTH16
                                        , r^.linker.smz_data_ofs + rrec.offset
                                        , fix);
                                AddReloc(relocs, n_rel, rrec.offset, r^.linker.hmz_data_seg);
                        END;
                END;
                r := r^.next;
        END;

        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        fix := 0;
                        selfr := (rrec.seg AND $40) <> 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.width <> RWIDTH16 THEN BEGIN
                                System.Writeln(r^.filename, ': only 16-bit relocations are supported.');
                                err := TRUE;
                                BREAK;
                        END;
                        IF selfr AND (rrec.rseg <> rrec.seg) THEN BEGIN
                                System.Writeln(r^.filename, ': self-relative relocation to another segment or import.');
                                err := TRUE;
                                BREAK;
                        END;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import = NIL THEN BEGIN
                                        System.Writeln(r^.filename, ': unresolved import ', rrec.rseg, '.');
                                        err := TRUE;
                                END ELSE Inc(fix, import^.export^.rec.offset);
                        END;
                        IF err THEN BREAK;
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                IncMem(code, RWIDTH16
                                        , (r^.linker.hmz_code_seg SHL 4) + rrec.offset
                                        , fix);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                IncMem(tail, RWIDTH16
                                        , r^.linker.smz_data_ofs + rrec.offset
                                        , fix);
                        END;
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                n_names := n_code;
                IF NOT QbeOptNames THEN n_names := 0;
                IF (n_names > 0)
                        AND (QB_BLOCK_HDR + (n_names * 8) + 2 + 10 + 42 + 40 + names_real + 1 > $FFF0) THEN BEGIN
                        System.Writeln('Warning: too many names for the CODE table, it is left empty.');
                        n_names := 0;
                END;
                err := QbeFinish(code, tail, relocs, exports
                        , n_rel, n_code, n_names, w2
                        , start^.rec.offset, start^.rdf^.linker.hmz_code_seg
                        , outfname);
        END;
        Close(exports);
        Close(relocs);
        Close(tail);
        Close(code);
        LinkAndGenQBE := err;
END;

BEGIN
        QbeOptNames := TRUE;
END.
