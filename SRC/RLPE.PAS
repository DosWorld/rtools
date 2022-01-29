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
UNIT rlpe;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt, rlout;

FUNCTION LinkAndGenDosPE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;

IMPLEMENTATION

CONST
        SECT_ALIGN = $1000;

TYPE
PE_FILE_HDR = RECORD
        machine         : WORD;
        numberOfSects   : WORD;
        timeDate        : DWORD;
        symTab          : DWORD;
        symNum          : DWORD;
        optHeaderSize   : WORD;
        chars           : WORD;
END;

PE_DIR = RECORD
        vaddr : DWORD;
        size  : DWORD;
END;

PE_OPT_HDR = RECORD
        magic          : WORD;
        hiLinkVer      : BYTE;
        loLinkVer      : BYTE;
        textSize       : DWORD;
        dataSize       : DWORD;
        bssSize        : DWORD;
        entry          : DWORD;
        textBase       : DWORD;
        dataBase       : DWORD;
        imageBase      : DWORD;
        secAlign       : DWORD;
        filAlign       : DWORD;
        hiOsVer        : WORD;
        loOsVer        : WORD;
        hiImgVer       : WORD;
        loImgVer       : WORD;
        hiSubSysVer    : WORD;
        loSubSysVer    : WORD;
        res1           : DWORD;
        sizeOfImage    : DWORD;
        sizeOfHeaders  : DWORD;
        chkSum         : DWORD;
        subsystem      : WORD;
        dllChars       : WORD;
        sizeOfStackRes : DWORD;
        sizeOfStackCom : DWORD;
        sizeOfHeapRes  : DWORD;
        sizeOfHeapCom  : DWORD;
        loaderFlags    : DWORD;
        numRvaAndSizes : DWORD;
        directory      : ARRAY[1..16] OF PE_DIR;
END;

PE_SECT = RECORD
        name      : ARRAY[1..8] OF CHAR;
        vsize     : DWORD;
        vaddr     : DWORD;
        rawSize   : DWORD;
        ptrRaw    : DWORD;
        ptrRelo   : DWORD;
        ptrLn     : DWORD;
        reloCount : WORD;
        lnCount   : WORD;
        chars     : DWORD;
END;

PE_HEADER = RECORD
        sign       : DWORD;
        fileHeader : PE_FILE_HDR;
        optHeader  : PE_OPT_HDR;
END;

PPE_RELOC_ITEM = ^PE_RELOC_ITEM;
PE_RELOC_ITEM = RECORD
        reloc       : ARRAY[1..REC_IN_PLAN] OF WORD;
        reloc_count : BYTE;
        next        : PPE_RELOC_ITEM;
END;

PPE_RELOC_TABLE = ^PE_RELOC_TABLE;
PE_RELOC_TABLE = RECORD
        page        : DWORD;
        items       : PPE_RELOC_ITEM;
        next        : PPE_RELOC_TABLE;
END;

CONST
PE_FILE_ALIGN = $200;

PE_WIN_GUI   = 2;
PE_WIN_CUI   = 3;
PE_OS2_CUI   = 5;
PE_POSIX_CUI = 7;

IMAGE_SCN_CNT_CODE               : DWORD = $00000020;
IMAGE_SCN_MEM_EXECUTE            : DWORD = $20000000;
IMAGE_SCN_MEM_READ               : DWORD = $40000000;
IMAGE_SCN_MEM_WRITE              : DWORD = $80000000;
IMAGE_SCN_CNT_INITIALIZED_DATA   : DWORD = $00000040;
IMAGE_SCN_CNT_UNINITIALIZED_DATA : DWORD = $00000080;

{ ==============
  DPMIST32.BIN - HX DOS Extender,
  Included with Japheth's permit:
  https://www.bttr-software.de/forum/board_entry.php?id=18630&category=8
  ============== }

CONST   MZEXE_STUB : ARRAY[0..511] OF BYTE = (
$4D, $5A, $00, $00, $01, $00, $00, $00, $04, $00, $14, $06, $FF, $FF, $00, $00,
$00, $00, $00, $00, $D5, $00, $00, $00, $40, $00, $00, $00, $00, $00, $00, $00,
$00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
$00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
$33, $D2, $B1, $20, $B4, $3F, $CD, $21, $72, $78, $33, $F6, $AD, $3D, $4D, $5A,
$75, $6B, $83, $C6, $04, $AD, $8B, $F8, $23, $C0, $74, $1D, $50, $33, $C9, $8B,
$54, $10, $B8, $00, $42, $CD, $21, $59, $C1, $E1, $02, $2B, $E1, $8B, $D4, $1E,
$16, $1F, $B4, $3F, $CD, $21, $1F, $72, $44, $AD, $C1, $E0, $04, $8B, $D0, $33,
$C9, $B8, $00, $42, $CD, $21, $33, $D2, $B4, $3F, $B9, $00, $60, $CD, $21, $72,
$31, $3B, $C1, $73, $28, $B4, $3E, $CD, $21, $8B, $CF, $E3, $17, $8B, $FC, $8C,
$D8, $36, $8B, $5D, $02, $C1, $E3, $04, $36, $03, $1D, $01, $07, $83, $C7, $04,
$E2, $EF, $8B, $E7, $8B, $DC, $1E, $52, $8B, $D5, $16, $1F, $CB, $BA, $C3, $00,
$EB, $03, $BA, $B6, $00, $0E, $1F, $E8, $0B, $00, $BA, $9A, $00, $E8, $05, $00,
$B8, $F0, $4C, $CD, $21, $B4, $09, $CD, $21, $C3, $0D, $0A, $70, $72, $6F, $67,
$72, $61, $6D, $20, $6C, $6F, $61, $64, $69, $6E, $67, $20, $61, $62, $6F, $72,
$74, $65, $64, $0D, $0A, $24, $0D, $0A, $72, $65, $61, $64, $20, $65, $72, $72,
$6F, $72, $24, $0D, $0A, $62, $61, $64, $20, $6C, $6F, $61, $64, $65, $72, $20,
$66, $69, $6C, $65, $24, $FC, $A1, $02, $00, $83, $E8, $30, $8E, $D0, $BC, $B0,
$02, $8B, $EC, $83, $EC, $50, $8B, $F4, $06, $26, $8E, $06, $2C, $00, $E8, $23,
$00, $0E, $1F, $E8, $39, $00, $8B, $F7, $16, $1F, $E8, $4C, $00, $BA, $95, $01,
$72, $83, $B9, $D5, $00, $16, $07, $33, $FF, $33, $F6, $2E, $F3, $A4, $07, $1E,
$51, $0E, $1F, $CB, $2B, $FF, $B0, $00, $B9, $FF, $FF, $F2, $AE, $AE, $75, $FB,
$47, $47, $26, $8A, $05, $36, $88, $04, $46, $47, $22, $C0, $75, $F4, $C3, $2B,
$FF, $BE, $90, $01, $B9, $05, $00, $F3, $A6, $74, $0D, $B0, $00, $B5, $7F, $F2,
$AE, $26, $3A, $05, $75, $EB, $2B, $FF, $C3, $8D, $7E, $00, $8B, $D7, $56, $BE,
$AA, $01, $B9, $0C, $00, $2E, $AC, $88, $05, $47, $E2, $F9, $88, $0D, $B8, $20,
$3D, $CD, $21, $5E, $73, $28, $23, $F6, $F9, $74, $24, $8B, $FA, $B9, $44, $00,
$26, $8A, $04, $88, $05, $46, $47, $3C, $3B, $74, $06, $3C, $00, $E0, $F1, $33,
$F6, $4F, $80, $7D, $FF, $5C, $74, $C6, $C6, $05, $5C, $47, $EB, $C0, $93, $C3,
$50, $41, $54, $48, $3D, $0D, $0A, $63, $61, $6E, $6E, $6F, $74, $20, $66, $69,
$6E, $64, $20, $6C, $6F, $61, $64, $65, $72, $20, $44, $50, $4D, $49, $4C, $44,
$33, $32, $2E, $45, $58, $45, $24, $00, $00, $00, $00, $00, $00, $00, $00, $00);
{
MZEXE_STUB : array[0..63] of byte = (
$4D, $5A, $3C, $00, $01, $00, $00, $00, $02, $00, $94, $00, $94, $00, $F0, $FF,
$40, $09, $00, $00, $00, $01, $F0, $FF, $40, $00, $00, $00, $00, $00, $00, $00,
$FC, $31, $C0, $50, $BA, $0C, $01, $B4, $09, $CD, $21, $C3, $54, $68, $69, $73,
$20, $69, $73, $20, $57, $69, $6E, $50, $45, $2E, $24, $00, $40, $00, $00, $00);
}

PROCEDURE SetPeSectName(VAR sect : PE_SECT; name : STRING);
VAR     i, l : integer;
BEGIN
        l := length(name);
        IF l > 8 THEN l := 8;
        Move(name[1], sect.name[1], l);
END;

FUNCTION AddReloc(root : PPE_RELOC_TABLE; r : DWORD) : PPE_RELOC_TABLE;
VAR     page : DWORD;
        ofs  : WORD;
        item : PPE_RELOC_ITEM;
        tbl  : PPE_RELOC_TABLE;
BEGIN
        item := NIL;
        tbl := root;
        page := r AND $FFFFF000;
        ofs := (r AND $0FFF) OR $3000;
        WHILE tbl <> NIL DO BEGIN
                IF tbl^.page = page THEN BREAK;
                tbl := tbl^.next;
        END;
        IF tbl = NIL THEN BEGIN
                GetMem(tbl, SizeOf(PE_RELOC_TABLE));
                FillChar(tbl^, SizeOf(PE_RELOC_TABLE), #0);
                tbl^.page := page;
                tbl^.next := root;
                root := tbl;
        END;
        IF tbl^.items = NIL THEN BEGIN
                GetMem(tbl^.items, SizeOf(PE_RELOC_ITEM));
                FillChar(tbl^.items^, SizeOf(PE_RELOC_ITEM), #0);
        END;
        IF tbl^.items^.reloc_count = REC_IN_PLAN THEN BEGIN
                GetMem(item, SizeOf(PE_RELOC_ITEM));
                FillChar(item^, SizeOf(PE_RELOC_ITEM), #0);
                item^.next := tbl^.items;
                tbl^.items := item;
        END;
        Inc(tbl^.items^.reloc_count);
        tbl^.items^.reloc[tbl^.items^.reloc_count] := ofs;
        AddReloc := root;
END;

PROCEDURE SaveRelocs(VAR o : BFILE; root : PPE_RELOC_TABLE);
VAR     t    : PPE_RELOC_TABLE;
        p    : DWORD;
        item : PPE_RELOC_ITEM;
        i    : DWORD;
BEGIN
        WHILE root <> NIL DO BEGIN
                t := root;
                root := root^.next;
                i := 0;
                WriteDWord(o, t^.page);
                p := FilePos(o);
                WriteDWord(o, 0);
                WHILE t^.items <> NIL DO BEGIN
                        item := t^.items;
                        t^.items := t^.items^.next;
                        BlockWrite(o, item^.reloc, item^.reloc_count SHL 1);
                        Inc(i, item^.reloc_count);
                        FreeMem(item, SizeOf(PE_RELOC_ITEM));
                END;
                IF (i AND 1) <> 0 THEN BEGIN Inc(i); WriteWord(o, 0); END;
                SetDWord(o, p, 8 + (i shl 1));
                Seek(o, FileSize(o));
                FreeMem(t, SizeOf(PE_RELOC_TABLE));
        END;
END;

FUNCTION LinkAndGenDosPE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;
VAR     err          : BOOLEAN;

        code, data    : BFILE;
        hdr, o        : BFILE;

        image_base    : DWORD;
        hdr_pe        : PE_HEADER;

        code_ofs      : DWORD;
        data_ofs      : DWORD;
        bss_ofs       : DWORD;

        code_size     : DWORD;
        data_size     : DWORD;
        bss_size      : DWORD;

        sectCode      : PE_SECT;
        sectData      : PE_SECT;
        sectBss       : PE_SECT;
        sectRelo      : PE_SECT;

        code_segnum   : WORD;
        data_segnum   : WORD;
        bss_segnum    : WORD;

        pe_start      : DWORD;
        ip            : DWORD;
        imageSize     : DWORD;
        i             : WORD;
        relocs_ofs    : DWORD;
        cr_pos        : DWORD;
        crb_pos       : DWORD;
        cr_page       : DWORD;
        s             : STRING;
        rrec          : RRELOC_REC;
        rtable        : PPE_RELOC_TABLE;
        selfr         : BOOLEAN;
        fix           : DWORD;
BEGIN
        err := NOT IsOpen(input);
        rtable := NIL;
        FillChar(hdr, SizeOf(hdr), #0);
        FillChar(code, SizeOf(hdr), #0);
        FillChar(data, SizeOf(hdr), #0);
        FillChar(o, SizeOf(o), #0);

        IF NOT err THEN BEGIN
                Assign(o, outfname);
                ReWrite(o);
        END;

        err := err OR (NOT (IsOpen(input) AND IsOpen(o)));
        IF NOT err THEN BEGIN        
                ReWriteMemFile(hdr);
                ReWriteMemFile(code);
                ReWriteMemFile(data);
                err := NOT (IsOpen(hdr) AND IsOpen(code) AND IsOpen(data))
        END;

        IF NOT err THEN BEGIN
                Seek(input, 0);
                err := NOT ReadRDF(input, hdr, code, data, code_segnum, data_segnum, bss_segnum);
        END;

        code_size := FileSize(code);
        data_size := FileSize(data);

        bss_size := 0;
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
        END;
        image_base := $400000;

        code_ofs := $1000;
        IF code_size = 0 THEN code_size := SECT_ALIGN;

        data_ofs := AlignValue(code_ofs + code_size, SECT_ALIGN);
        IF data_size = 0 THEN data_size := SECT_ALIGN;

        bss_ofs := AlignValue(data_ofs + data_size, SECT_ALIGN);
        IF bss_size = 0 THEN bss_size := SECT_ALIGN;

        relocs_ofs := AlignValue(bss_ofs + bss_size, SECT_ALIGN);

        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                err := NOT FindEntryPoint(hdr, FileSize(hdr), entry_name, ip);
        END;

        BlockWrite(o, MZEXE_STUB, SizeOf(MZEXE_STUB));
        FilePosAlign(o, $10);
        pe_start := FilePos(o);
        SetWord(o, $003C, pe_start);
        Seek(o, pe_start);

        FillChar(hdr_pe, SizeOf(PE_HEADER), #0);
        hdr_pe.sign                     := $4550;
        hdr_pe.fileHeader.machine       := $014c;
        hdr_pe.fileHeader.numberOfSects := 4;
        hdr_pe.fileHeader.optHeaderSize := 224;
        hdr_pe.fileHeader.chars         := $102;
        hdr_pe.optHeader.magic          := $010B;
        hdr_pe.optHeader.textSize       := code_size;
        hdr_pe.optHeader.dataSize       := data_size;
        hdr_pe.optHeader.bssSize        := bss_size;
        hdr_pe.optHeader.entry          := ip + code_ofs;
        hdr_pe.optHeader.textBase       := 0;
        hdr_pe.optHeader.dataBase       := 0;
        hdr_pe.optHeader.imageBase      := image_base;
        hdr_pe.optHeader.secAlign       := SECT_ALIGN;
        hdr_pe.optHeader.filAlign       := PE_FILE_ALIGN;
        hdr_pe.optHeader.hiOsVer        := 1;
        hdr_pe.optHeader.hiSubSysVer    := 4;
        hdr_pe.optHeader.loSubSysVer    := 0;
        hdr_pe.optHeader.sizeOfImage    := imageSize;
        hdr_pe.optHeader.subsystem      := PE_WIN_CUI;
        hdr_pe.optHeader.sizeOfStackRes := stack_size;
        hdr_pe.optHeader.sizeOfStackCom := stack_size;
        hdr_pe.optHeader.numRvaAndSizes := 16;
        hdr_pe.optHeader.directory[6].vaddr := relocs_ofs;
        BlockWrite(o, hdr_pe, SizeOf(PE_HEADER));

        FillChar(sectCode, SizeOf(sectCode), #0);
        SetPeSectName(sectCode, 'CODE');
        sectCode.vaddr := code_ofs;
        sectCode.vsize := AlignValue(code_size, SECT_ALIGN);
        sectCode.rawSize := code_size;
        sectCode.chars := IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_CODE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;
        BlockWrite(o, sectCode, SizeOf(sectCode));

        FillChar(sectData, SizeOf(sectData), #0);
        SetPeSectName(sectData, 'DATA');
        sectData.vaddr := data_ofs;
        sectData.vsize := AlignValue(data_size, SECT_ALIGN);
        sectData.rawSize := data_size;
        sectData.chars := IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;
        BlockWrite(o, sectData, SizeOf(sectData));

        FillChar(sectBss, SizeOf(sectBss), #0);
        SetPeSectName(sectBss, 'BSS');
        sectBss.vaddr := bss_ofs;
        sectBss.vsize := bss_size;
        sectBss.chars := IMAGE_SCN_CNT_UNINITIALIZED_DATA
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_WRITE;
        BlockWrite(o, sectBss, SizeOf(sectBss));

        FillChar(sectRelo, SizeOf(sectRelo), #0);
        SetPeSectName(sectRelo, 'relocs');
        sectRelo.vaddr := relocs_ofs;
        sectRelo.chars := $52000040;
        BlockWrite(o, sectRelo, SizeOf(sectRelo));

        hdr_pe.optHeader.sizeOfHeaders := FilePos(o);

        FilePosAlign(o, PE_FILE_ALIGN);

        IF NOT err THEN Seek(hdr, 0);
        WHILE (NOT err) AND RDF_LOOKUPREC(hdr, RREC_RELOC, s) DO BEGIN
                GET_RELOC_REC(s, rrec);
                selfr := (rrec.seg AND $40) <> 0;
                rrec.seg := rrec.seg AND $3F;
                IF NOT (rrec.seg IN [code_segnum, data_segnum]) THEN BEGIN
                        System.writeln('Invalid relocation.'); err := TRUE; BREAK;
                END;
                fix := image_base;
                IF NOT selfr THEN BEGIN
                        IF rrec.rseg = code_segnum THEN Inc(fix, code_ofs)
                        ELSE IF rrec.rseg = data_segnum THEN Inc(fix, data_ofs)
                        ELSE IF rrec.rseg = bss_segnum THEN Inc(fix, bss_ofs);
                END;
                IF selfr THEN BEGIN
                        IF rrec.seg = code_segnum THEN Dec(fix, code_ofs)
                        ELSE IF rrec.seg = data_segnum THEN Dec(fix, data_ofs);
                END;

                IF rrec.width = RWIDTH8 THEN BEGIN
                        IF rrec.seg = code_segnum THEN
                                IncByte(code, rrec.offset, fix AND $FF)
                        ELSE IF rrec.seg = data_segnum THEN
                                IncByte(data, rrec.offset, fix AND $FF);
                END ELSE IF rrec.width = RWIDTH16 THEN BEGIN
                        IF rrec.seg = code_segnum THEN
                                IncWord(code, rrec.offset, fix AND $FFFF)
                        ELSE IF rrec.seg = data_segnum THEN
                                IncWord(data, rrec.offset, fix AND $FFFF);
                END ELSE IF rrec.width = RWIDTH32 THEN BEGIN
                        IF rrec.seg = code_segnum THEN
                                IncDWord(code, rrec.offset, fix)
                        ELSE IF rrec.seg = data_segnum THEN
                                IncDWord(data, rrec.offset, fix);
                END;
                IF rrec.seg = code_segnum THEN
                        Inc(rrec.offset, code_ofs)
                ELSE IF rrec.seg = data_segnum THEN
                        Inc(rrec.offset, data_ofs);

                IF NOT selfr THEN rtable := AddReloc(rtable, rrec.offset);
        END;

        sectRelo.ptrRaw := FilePos(o);
        IF NOT err THEN SaveRelocs(o, rtable);
        sectRelo.rawSize := FilePos(o) - sectRelo.ptrRaw;
        sectRelo.vsize := AlignValue(sectRelo.rawSize, SECT_ALIGN);
        IF sectRelo.vsize = 0 THEN sectRelo.vsize := SECT_ALIGN;

        hdr_pe.optHeader.directory[6].size := sectRelo.rawSize;
        hdr_pe.optHeader.sizeOfImage := AlignValue(relocs_ofs + sectRelo.vsize, SECT_ALIGN);
        IF NOT err THEN BEGIN
                FilePosAlign(o, PE_FILE_ALIGN);
                sectCode.ptrRaw := FilePos(o);
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));
        
                FilePosAlign(o, PE_FILE_ALIGN);
                sectData.ptrRaw := FilePos(o);
                Seek(data, 0);
                BlockCopy(data, o, FileSize(data));

                Seek(o, pe_start);
                BlockWrite(o, hdr_pe, SizeOf(PE_HEADER));
                BlockWrite(o, sectCode, SizeOf(sectCode));
                BlockWrite(o, sectData, SizeOf(sectData));
                BlockWrite(o, sectBss, SizeOf(sectBss));
                BlockWrite(o, sectRelo, SizeOf(sectRelo));
        END;
        Close(hdr);
        Close(code);
        Close(data);

        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(o);
        LinkAndGenDosPE := err;
END;

END.