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
UNIT rlope;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt, rlo;

FUNCTION LinkAndGenDosPE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT;
        hx_stub : BOOLEAN) : BOOLEAN;

IMPLEMENTATION

USES exe;

{ ====================================================
  PE32-Image settings
  ==================================================== }

CONST
PE_FILE_ALIGN     = $200;
PE_IMAGE_TYPE     = PE_SUBSYS_WIN_CUI;

IMAGE_BASE        = $400000;
IMAGE_CODE_OFFSET = $1000;
SECTION_ALIGN     = $1000;

CODE_SEG_NAME     = 'CODE';
DATA_SEG_NAME     = 'DATA';
BSS_SEG_NAME      = 'BSS';
RELO_SEG_NAME     = 'relocs';

CODE_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_CODE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

DATA_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

BSS_SEG_ATTR : DWORD = IMAGE_SCN_MEM_EXECUTE
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_MEM_WRITE
                OR IMAGE_SCN_CNT_UNINITIALIZED_DATA;

RELO_SEG_ATTR : DWORD = IMAGE_SCN_MEM_DISCARDABLE
                OR IMAGE_SCN_MEM_SHARED
                OR IMAGE_SCN_MEM_READ
                OR IMAGE_SCN_CNT_INITIALIZED_DATA;

{ ====================================================
  Here is tables, which help me collect relocs.
  This is non pe file format data structures.
  ==================================================== }

TYPE
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

PROCEDURE SetPeSectName(VAR sect : PE32_SECTION; name : STRING);
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
        stack_size: LONGINT;
        hx_stub : BOOLEAN) : BOOLEAN;

VAR     err           : BOOLEAN;

        code, data    : BFILE;
        hdr, o        : BFILE;
        t             : BFILE;

        hdr_pe        : PE32_FULL_HEADER;
        sectCode      : PE32_SECTION;
        sectData      : PE32_SECTION;
        sectBss       : PE32_SECTION;
        sectRelo      : PE32_SECTION;

        code_ofs      : DWORD;
        data_ofs      : DWORD;
        bss_ofs       : DWORD;

        code_size     : DWORD;
        data_size     : DWORD;
        bss_size      : DWORD;

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

        code_ofs := IMAGE_CODE_OFFSET;
        IF code_size = 0 THEN code_size := SECTION_ALIGN;

        data_ofs := AlignValue(code_ofs + code_size, SECTION_ALIGN);
        IF data_size = 0 THEN data_size := SECTION_ALIGN;

        bss_ofs := AlignValue(data_ofs + data_size, SECTION_ALIGN);
        IF bss_size = 0 THEN bss_size := SECTION_ALIGN;

        relocs_ofs := AlignValue(bss_ofs + bss_size, SECTION_ALIGN);

        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                err := NOT FindEntryPoint(hdr, FileSize(hdr), entry_name, ip);
        END;

        IF hx_stub THEN BlockWrite(o, HX_EXE_STUB, SizeOf(HX_EXE_STUB))
        ELSE BlockWrite(o, SIMPLE_EXE_STUB, SizeOf(SIMPLE_EXE_STUB));

        FilePosAlign(o, $10);
        pe_start := FilePos(o);
        SetWord(o, $003C, pe_start);
        Seek(o, pe_start);

        FillChar(hdr_pe, SizeOf(PE32_FULL_HEADER), #0);
        hdr_pe.sign                     := PE_MAGIC;
        hdr_pe.fileHeader.machine       := IMAGE_FILE_MACHINE_I386;
        hdr_pe.fileHeader.numberOfSects := 4;
        hdr_pe.fileHeader.optHeaderSize := SizeOf(PE32_OPTIONAL_HEADER);
        hdr_pe.fileHeader.chars         := IMAGE_SYM_CLASS_END_OF_STRUCT;
        hdr_pe.optHeader.magic          := HEADER_MAGIC_PE32;
        hdr_pe.optHeader.textSize       := code_size;
        hdr_pe.optHeader.dataSize       := data_size;
        hdr_pe.optHeader.bssSize        := bss_size;
        hdr_pe.optHeader.entry          := ip + code_ofs;
        hdr_pe.optHeader.textBase       := 0;
        hdr_pe.optHeader.dataBase       := 0;
        hdr_pe.optHeader.imageBase      := IMAGE_BASE;
        hdr_pe.optHeader.secAlign       := SECTION_ALIGN;
        hdr_pe.optHeader.filAlign       := PE_FILE_ALIGN;
        hdr_pe.optHeader.hiOsVer        := 1;
        hdr_pe.optHeader.hiSubSysVer    := 4;
        hdr_pe.optHeader.loSubSysVer    := 0;
        hdr_pe.optHeader.sizeOfImage    := imageSize;
        hdr_pe.optHeader.subsystem      := PE_IMAGE_TYPE;
        hdr_pe.optHeader.sizeOfStackRes := stack_size;
        hdr_pe.optHeader.sizeOfStackCom := stack_size;
        hdr_pe.optHeader.numRvaAndSizes := 16;
        hdr_pe.optHeader.directory[6].vaddr := relocs_ofs;
        BlockWrite(o, hdr_pe, SizeOf(PE32_FULL_HEADER));

        FillChar(sectCode, SizeOf(sectCode), #0);
        SetPeSectName(sectCode, CODE_SEG_NAME);
        sectCode.vaddr := code_ofs;
        sectCode.vsize := AlignValue(code_size, SECTION_ALIGN);
        sectCode.rawSize := code_size;
        sectCode.chars := CODE_SEG_ATTR;
        BlockWrite(o, sectCode, SizeOf(sectCode));

        FillChar(sectData, SizeOf(sectData), #0);
        SetPeSectName(sectData, DATA_SEG_NAME);
        sectData.vaddr := data_ofs;
        sectData.vsize := AlignValue(data_size, SECTION_ALIGN);
        sectData.rawSize := data_size;
        sectData.chars := DATA_SEG_ATTR;
        BlockWrite(o, sectData, SizeOf(sectData));

        FillChar(sectBss, SizeOf(sectBss), #0);
        SetPeSectName(sectBss, BSS_SEG_NAME);
        sectBss.vaddr := bss_ofs;
        sectBss.vsize := bss_size;
        sectBss.chars := BSS_SEG_ATTR;
        BlockWrite(o, sectBss, SizeOf(sectBss));

        FillChar(sectRelo, SizeOf(sectRelo), #0);
        SetPeSectName(sectRelo, RELO_SEG_NAME);
        sectRelo.vaddr := relocs_ofs;
        sectRelo.chars := RELO_SEG_ATTR;
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
                fix := IMAGE_BASE;
                IF NOT selfr THEN BEGIN
                        IF rrec.rseg = code_segnum THEN Inc(fix, code_ofs)
                        ELSE IF rrec.rseg = data_segnum THEN Inc(fix, data_ofs)
                        ELSE IF rrec.rseg = bss_segnum THEN Inc(fix, bss_ofs);
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
        sectRelo.vsize := AlignValue(sectRelo.rawSize, SECTION_ALIGN);
        IF sectRelo.vsize = 0 THEN sectRelo.vsize := SECTION_ALIGN;

        hdr_pe.optHeader.directory[6].size := sectRelo.rawSize;
        hdr_pe.optHeader.sizeOfImage := AlignValue(relocs_ofs + sectRelo.vsize, SECTION_ALIGN);
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
                BlockWrite(o, hdr_pe, SizeOf(PE32_FULL_HEADER));
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