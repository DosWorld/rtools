{  MIT License

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
USES rutils, utils, system2, rdfconst;

TYPE

OUTFMT = (OCOM, OMZ, OPE);

MZ_HEADER = ARRAY[0..15] OF WORD;
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
        ptrRar    : DWORD;
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

IMAGE = RECORD
        i, o        : BFILE;
        code        : BFILE;
        data        : BFILE;
        hdr         : BFILE;
        pe_relocs   : BFILE;
        image_base  : DWORD;
        code_size   : DWORD;
        code_segnum : WORD;
        code_ofs    : DWORD;
        data_size   : DWORD;
        data_segnum : WORD;
        data_ofs    : DWORD;
        bss_size    : DWORD;
        bss_segnum  : WORD;
        bss_ofs     : DWORD;
        ip          : DWORD;
        reloc_cnt   : DWORD;
        sreloc_cnt  : DWORD;
        err         : BOOLEAN;
        errMsg      : STRING;
        entry_name  : STRING;
        infname     : STRING;
        outfname    : STRING;
        stack_size  : DWORD;
        verbose     : BOOLEAN;
        seg_align   : INTEGER;
        format      : OUTFMT;
        fext        : STRING[3];
END;

PE_RELOC = RECORD
        page    : DWORD;
        offset  : WORD;
        writed  : BOOLEAN;
END;

CONST
MZEXE_STUB : ARRAY[0..26] OF BYTE = ($BA,$09,$01,$B4,$09,$CD,$21,$CD,$20,
$54,$68,$69,$73,$20,$69,$73,$20,$44,$50,$4D,$49,$20,$2E,$65,$78,$65,$24);

PE_FILE_ALIGN = $10;

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

PROCEDURE mkerr(VAR img : IMAGE; str : STRING);
BEGIN
        IF img.err THEN EXIT;
        img.err := TRUE;
        img.errMsg := str;
        SetDeleteOnClose(img.o, TRUE);
END;

PROCEDURE Help;
BEGIN
        System.WriteLn('usage: REXE [/H] [/S nnnn] [/E name] [/F fmt] [/V] [/O name] file.rdf');
        System.WriteLn;
        System.WriteLn('/S nnnn - Set stack size (in KB)');
        System.WriteLn('/E name - Set symbol name for entry point (default is "start")');
        System.WriteLn('/F fmt  - Output format {COM|MZ|PE}');
        System.WriteLn('/O name - Output file name');
        System.WriteLn('/V      - Verbose output');
        System.WriteLn('/H      - Show this help');
        Halt(1);
END;

PROCEDURE SetPeSectName(VAR sect : PE_SECT; name : STRING);
VAR i, l : integer;
BEGIN
        l := length(name);
        IF l > 8 THEN l := 8;
        Move(name[1], sect.name[1], l);
END;

FUNCTION AlignValue(value : DWORD; align : DWORD) : DWORD;
VAR  n : DWORD;
BEGIN
        n := value DIV align;
        IF value MOD align <> 0 THEN Inc(n);
        AlignValue := n * align;
END;

FUNCTION ReadHeaders(VAR img : IMAGE) : BOOLEAN;
VAR     sign    : STRING[6];
        modsize : DWORD;
        hdrsize : DWORD;
BEGIN
        BlockRead(img.i, sign[1], 6);
        sign[0] := #6;
        IF sign = 'RDOFF2' THEN BEGIN
                modsize := ReadDWord(img.i);
                hdrsize := ReadDWord(img.i);
                ReWriteMemFile(img.hdr, hdrsize);
                IF IsOpen(img.hdr) THEN BlockCopy(img.i, img.hdr, hdrsize)
                ELSE mkerr(img, 'No memory.');
        END ELSE mkerr(img, 'Input file is not RDOFF2.');
        ReadHeaders := NOT img.err;
END;

FUNCTION ReadSegments(VAR img : IMAGE) : BOOLEAN;
VAR     segtype : WORD;
        segnum  : WORD;
        reserv  : WORD;
        seglen  : DWORD;
BEGIN        
        WHILE (NOT EOF(img.i)) AND (NOT img.err) DO BEGIN
                segtype := ReadWord(img.i);
                segnum := ReadWord(img.i);
                reserv := ReadWord(img.i);
                seglen := ReadDWord(img.i);
                IF segtype = 0 THEN BREAK
                ELSE IF NOT (segtype IN[RDFCS, RDFDS]) THEN mkerr(img, 'Unknown type of segment.')
                ELSE IF segtype = RDFCS THEN BEGIN
                        IF NOT IsOpen(img.code) THEN BEGIN
                                ReWriteMemFile(img.code, seglen + img.seg_align);
                                IF IsOpen(img.code) THEN BEGIN
                                        BlockCopy(img.i, img.code, seglen);
                                        FilePosAlign(img.code, img.seg_align);
                                        img.code_size := FilePos(img.code);
                                        img.code_segnum := segnum;
                                END ELSE mkerr(img, 'No memory.');
                        END ELSE mkerr(img, 'Multiple code segments.');
                END ELSE IF segtype = RDFDS THEN BEGIN
                        IF NOT IsOpen(img.data) THEN BEGIN
                                ReWriteMemFile(img.data, seglen + img.seg_align);
                                IF IsOpen(img.data) THEN BEGIN
                                        BlockCopy(img.i, img.data, seglen);
                                        FilePosAlign(img.data, img.seg_align);
                                        img.data_size := FilePos(img.data);
                                        img.data_segnum := segnum;
                                END ELSE mkerr(img, 'No memory.');
                        END ELSE mkerr(img, 'Multiple data segments.');
                END;
        END;
        IF NOT NOT img.err THEN BEGIN
                IF NOT IsOpen(img.code) THEN mkerr(img, 'No code segment.');
                img.bss_segnum := img.code_segnum;
                IF img.bss_segnum < img.data_segnum THEN img.bss_segnum := img.data_segnum;
                Inc(img.bss_segnum);
        END;
        ReadSegments := NOT img.err;
END;

FUNCTION FindEntryPoint(VAR img : IMAGE) : BOOLEAN;
VAR     rtype : CHAR;
        str   : STRING;
        rec   : REXP_REC;
        find  : BOOLEAN;
BEGIN
        find := FALSE;
        Seek(img.hdr, 0);
        WHILE NOT EOF(img.hdr) DO BEGIN
                RDF_READ_REC(img.hdr, rtype, str);
                IF rtype = RREC_GLOBAL THEN BEGIN
                        GET_EXPORT_REC(str, rec, TRUE);
                        IF rec.name = img.entry_name THEN BEGIN
                                img.ip := img.code_ofs + rec.offset;
                                find := TRUE;
                                BREAK;
                        END;
                END;
        END;
        IF NOT find THEN mkerr(img, 'Entry point not found.');
        FindEntryPoint := find;
END;

FUNCTION DisableSegRelocs(VAR img : IMAGE) : BOOLEAN;
VAR     rtype : CHAR;
        str   : STRING;
        find  : BOOLEAN;
BEGIN
        find := FALSE;
        Seek(img.hdr, 0);
        WHILE NOT EOF(img.hdr) DO BEGIN
                RDF_READ_REC(img.hdr, rtype, str);
                IF rtype = RREC_SEGRELO THEN BEGIN
                            mkerr(img, 'Output format does not support segment relocations.');
                            find := TRUE;
                            BREAK;
                END;
        END;
        DisableSegRelocs := find;
END;

FUNCTION DisableRelocsWidth(VAR img : IMAGE; width : BYTE) : BOOLEAN;
VAR     rtype : CHAR;
        c     : STRING;
        rec   : RRELOC_REC;
        find  : BOOLEAN;
BEGIN
        find := FALSE;
        Seek(img.hdr, 0);
        WHILE NOT EOF(img.hdr) DO BEGIN
                RDF_READ_REC(img.hdr, rtype, c);
                IF rtype IN [RREC_SEGRELO, RREC_RELOC] THEN BEGIN
                        GET_RELOC_REC(c, rec);
                        IF rec.width > width THEN BEGIN
                                mkerr(img, 'Invalid relocation width for output format.');
                                find := TRUE;
                                BREAK;
                        END;
                END;
        END;
        DisableRelocsWidth := find;
END;

FUNCTION ApplyMZRelocs(VAR img : IMAGE; VAR header : MZ_HEADER) : BOOLEAN;
VAR     er_seg   : WORD;
        er_ofs   : DWORD;
        c        : STRING;
        dst      : ^BFILE;
        rtype    : CHAR;
        rec      : RRELOC_REC;
BEGIN
        Seek(img.hdr, 0);
        WHILE NOT EOF(img.hdr) DO BEGIN
                RDF_READ_REC(img.hdr, rtype, c);
                IF rtype = RREC_SEGRELO THEN BEGIN
                        GET_RELOC_REC(c, rec);
                        IF NOT (rec.seg IN [img.code_segnum, img.data_segnum]) THEN BEGIN
                                mkerr(img, 'Invalid segment relocation.');
                                BREAK;
                        END;
                        IF rec.rseg = img.bss_segnum THEN BEGIN
                                rec.rseg := img.data_segnum;
                        END;
                        IF NOT (rec.rseg IN [img.code_segnum, img.data_segnum]) THEN BEGIN
                                mkerr(img, 'Invalid segment ref relocation.');
                                BREAK;
                        END;
                        IF rec.width <> RWIDTH16 THEN BEGIN
                                mkerr(img, 'Invalid segment relocation bit-width.');
                                BREAK;
                        END;
                        er_seg := 0;
                        IF rec.seg <> img.code_segnum THEN er_seg := img.code_size SHR 4;
                        er_ofs := rec.offset;
                        IF rec.rseg = img.code_segnum THEN rec.rseg := 0
                        ELSE rec.rseg := img.code_size SHR 4;

                        IF rec.seg = 0 THEN BEGIN
                                SetWord(img.code, er_ofs, rec.rseg);
                        END ELSE BEGIN
                                SetWord(img.data, er_ofs, rec.rseg);
                        END;
                        WriteWord(img.o, er_ofs);
                        WriteWord(img.o, er_seg);
                        Inc(header[3]);
                END;
        END;
        ApplyMZRelocs := NOT img.err;
END;

PROCEDURE EvalBssSize(VAR img : IMAGE);
VAR     rtype : CHAR;
        str   : STRING;
BEGIN
        img.bss_size := 0;
        img.reloc_cnt := 0;
        img.sreloc_cnt := 0;
        Seek(img.hdr, 0);
        WHILE NOT EOF(img.hdr) DO BEGIN
                RDF_READ_REC(img.hdr, rtype, str);
                IF rtype = RREC_BSS THEN GET_BSS(str, img.bss_size)
                ELSE IF rtype = RREC_RELOC THEN Inc(img.reloc_cnt)
                ELSE IF rtype = RREC_SEGRELO THEN Inc(img.sreloc_cnt);
        END;
END;

FUNCTION ApplyRelocs(VAR img : IMAGE) : BOOLEAN;
VAR     dst_ofs : DWORD;
        c       : STRING;
        dst     : ^BFILE;
        rtype   : CHAR;
        rec     : RRELOC_REC;
        sreloc  : PE_RELOC;
BEGIN
        FillChar(sreloc, SizeOf(PE_RELOC), #0);
        Seek(img.hdr, 0);
        WHILE (NOT EOF(img.hdr)) AND (NOT img.err) DO BEGIN
                RDF_READ_REC(img.hdr, rtype, c);
                CASE rtype OF
                RREC_RELOC: BEGIN
                        GET_RELOC_REC(c, rec);
                        
                        IF rec.seg = img.code_segnum THEN dst := @img.code
                        ELSE IF rec.seg = img.data_segnum THEN dst := @img.data
                        ELSE BEGIN
                            mkerr(img, 'Invalid relocation.');
                            BREAK;
                        END;
                        
                        IF rec.rseg = img.code_segnum THEN
                                dst_ofs := img.image_base + img.code_ofs
                        ELSE IF rec.rseg = img.data_segnum THEN
                                dst_ofs := img.image_base + img.data_ofs
                        ELSE IF rec.rseg = img.bss_segnum THEN
                                dst_ofs := img.image_base + img.bss_ofs;

                        IF IsOpen(img.pe_relocs) THEN BEGIN
                                sreloc.page := img.code_ofs + rec.offset;
                                sreloc.offset := sreloc.page AND $0FFF;
                                sreloc.page := (sreloc.page SHR 12) SHL 12;
                                BlockWrite(img.pe_relocs, sreloc, SizeOf(PE_RELOC));
                                IF rec.width <> RWIDTH32 THEN mkerr(img, 'Invalid relocation width.');
                        END;

                        IF rec.width = RWIDTH8 THEN
                                IncByte(dst^, rec.offset, dst_ofs AND $FF)
                        ELSE IF rec.width = RWIDTH16 THEN
                                IncWord(dst^, rec.offset, dst_ofs AND $FFFF)
                        ELSE IF rec.width = RWIDTH32 THEN
                                IncDWord(dst^, rec.offset, dst_ofs);
                END;
                RREC_IMPORT:  mkerr(img, 'Non-resolved import found.');
                END;
        END;
        ApplyRelocs := NOT img.err;
END;

PROCEDURE GenCOM(VAR img : IMAGE);
VAR     alloc_size : WORD;
        jmp_instr  : ARRAY[0..3] OF BYTE;
        jmp_addr   : WORD;
BEGIN
        IF DisableSegRelocs(img) THEN EXIT;
        IF DisableRelocsWidth(img, RWIDTH16) THEN EXIT;

        img.data_ofs := img.code_ofs + img.code_size;
        img.bss_ofs := img.data_ofs + img.data_size;

        IF NOT FindEntryPoint(img) THEN EXIT;

        IF img.ip <> img.code_ofs THEN BEGIN
                Inc(img.ip, SizeOf(jmp_instr));
                Inc(img.code_ofs, SizeOf(jmp_instr));
                Inc(img.data_ofs, SizeOf(jmp_instr));
                Inc(img.bss_ofs, SizeOf(jmp_instr));
        END;

        IF NOT ApplyRelocs(img) THEN EXIT;

        IF img.ip <> img.code_ofs THEN BEGIN
                jmp_addr := img.ip;
                jmp_addr := jmp_addr - $103;
                jmp_instr[0] := $e9;
                jmp_instr[1] := jmp_addr AND $FF;
                jmp_instr[2] := (jmp_addr SHR 8) AND $FF;
                jmp_instr[3] := $90;
                BlockWrite(img.o, jmp_instr, SizeOf(jmp_instr));
        END;
        Seek(img.code, 0);
        BlockCopy(img.code, img.o, img.code_size);
        IF IsOpen(img.data) THEN BEGIN
                Seek(img.data, 0);
                BlockCopy(img.data, img.o, img.data_size);
        END;
END;

PROCEDURE GenMZ(VAR img : IMAGE);
VAR     alloc_size : WORD;
        img_size   : DWORD;
        header     : MZ_HEADER;
BEGIN
        IF DisableRelocsWidth(img, RWIDTH16) THEN EXIT;

        img.bss_ofs := img.data_ofs + img.data_size;

        FillChar(header, SizeOf(header), #0);
        BlockWrite(img.o, header, SizeOf(header));

        IF NOT FindEntryPoint(img) THEN EXIT;
        EvalBssSize(img);
        IF NOT ApplyRelocs(img) THEN EXIT;
        IF NOT ApplyMZRelocs(img, header) THEN EXIT;

        FilePosAlign(img.o, 16);
        header[4] := (FilePos(img.o) SHR 4);

        Seek(img.code, 0);
        BlockCopy(img.code, img.o, img.code_size);
        IF IsOpen(img.data) THEN BEGIN
                Seek(img.data, 0);
                BlockCopy(img.data, img.o, img.data_size);
        END;
        img_size := img.code_size + img.data_size;
        header[0] := $5a4d;
        header[1] := img_size AND $1ff;
        header[2] := img_size SHR 9;
        alloc_size := img.bss_size + img.stack_size;
        header[5] := alloc_size SHR 4;
        IF (alloc_size AND $0f) <> 0 THEN Inc(header[5]);
        header[6] := header[5];
        header[7] := img.code_size SHR 4;
        header[8] := img.data_size + img.bss_size + img.stack_size;
        header[10] := img.ip AND $FFFF;
        header[12] := 32;
        Seek(img.o, 0);
        BlockWrite(img.o, header, SizeOf(header));
        IF (img.verbose) AND (NOT img.err) THEN BEGIN
                System.WriteLn('Seg relocs:  ', header[3]);
        END;
END;

PROCEDURE GenPE(VAR img : IMAGE);
CONST
SECT_ALIGN = $1000;
VAR     alloc_size    : WORD;
        hdr_pe        : PE_HEADER;
        pe_seg_start  : DWORD;
        pe_code_start : DWORD;
        sectCode      : PE_SECT;
        sectBss       : PE_SECT;
        sectRelo      : PE_SECT;
        hdr_mz        : MZ_HEADER;
        pe_start      : DWORD;
        imageSize     : DWORD;
        i             : WORD;
        relocs_ofs    : DWORD;
        cr_pos        : DWORD;
        crb_pos       : DWORD;
        cr_page       : DWORD;
        sreloc        : PE_RELOC;

BEGIN
        IF DisableSegRelocs(img) THEN EXIT;

        img.image_base := $400000;

        img.code_ofs := SECT_ALIGN;
        img.data_ofs := img.code_ofs + img.code_size;
        img.bss_ofs := AlignValue(img.data_ofs + img.data_size, SECT_ALIGN);
        EvalBssSize(img);
        relocs_ofs := AlignValue(img.bss_ofs + img.bss_size, SECT_ALIGN);
        IF relocs_ofs = img.bss_ofs THEN Inc(relocs_ofs, SECT_ALIGN);

        ReWriteMemFile(img.pe_relocs, img.reloc_cnt * SizeOf(PE_RELOC));

        IF NOT FindEntryPoint(img) THEN EXIT;
        IF NOT ApplyRelocs(img) THEN EXIT;

        imageSize := AlignValue(relocs_ofs + FileSize(img.pe_relocs), SECT_ALIGN);
        IF imageSize = relocs_ofs THEN Inc(imageSize, SECT_ALIGN);

        FillChar(hdr_mz, SizeOf(MZ_HEADER), #0);
        hdr_mz[0] := $5a4d;
        hdr_mz[1] := SizeOf(MZEXE_STUB) AND $1ff;
        hdr_mz[4] := 4;
        hdr_mz[5] := $4;
        hdr_mz[6] := $4;
        hdr_mz[7] := $FFF0;
        hdr_mz[8] := $0100 + (AlignValue(SizeOf(MZEXE_STUB), 16) AND $1ff) + 64;
        hdr_mz[10] := $0100;
        hdr_mz[11] := $FFF0;
        BlockWrite(img.o, hdr_mz, SizeOf(MZ_HEADER));
        FilePosAlign(img.o, $40);

        BlockWrite(img.o, MZEXE_STUB, SizeOf(MZEXE_STUB) AND $1ff);
        FilePosAlign(img.o, $10);

        pe_start := FilePos(img.o);
        SetWord(img.o, $003C, pe_start);
        Seek(img.o, pe_start);

        FillChar(hdr_pe, SizeOf(PE_HEADER), #0);
        hdr_pe.sign                     := $4550;
        hdr_pe.fileHeader.machine       := $014c;
        hdr_pe.fileHeader.numberOfSects := 3;
        hdr_pe.fileHeader.optHeaderSize := 224;
        hdr_pe.fileHeader.chars         := $102;
        hdr_pe.optHeader.magic          := $010B;
        hdr_pe.optHeader.textSize       := imageSize;
        hdr_pe.optHeader.dataSize       := 0;
        hdr_pe.optHeader.bssSize        := img.bss_size;
        hdr_pe.optHeader.entry          := img.ip;
        hdr_pe.optHeader.textBase       := 0;
        hdr_pe.optHeader.dataBase       := 0;
        hdr_pe.optHeader.imageBase      := img.image_base;
        hdr_pe.optHeader.secAlign       := SECT_ALIGN;
        hdr_pe.optHeader.filAlign       := PE_FILE_ALIGN;
        hdr_pe.optHeader.hiOsVer        := 1;
        hdr_pe.optHeader.hiSubSysVer    := 3;
        hdr_pe.optHeader.loSubSysVer    := 10;
        hdr_pe.optHeader.sizeOfImage    := imageSize;
        hdr_pe.optHeader.subsystem      := PE_WIN_CUI;
        hdr_pe.optHeader.sizeOfStackRes := img.stack_size;
        hdr_pe.optHeader.sizeOfStackCom := img.stack_size;
        hdr_pe.optHeader.numRvaAndSizes := 16;
        hdr_pe.optHeader.directory[6].vaddr := relocs_ofs;
        BlockWrite(img.o, hdr_pe, SizeOf(PE_HEADER));

        FillChar(sectCode, SizeOf(sectCode), #0);
        SetPeSectName(sectCode, 'CODE');
        sectCode.vaddr := img.code_ofs;
        sectCode.vsize := AlignValue(img.code_size + img.data_size, SECT_ALIGN);
        sectCode.rawSize := img.code_size + img.data_size;
        sectCode.chars := IMAGE_SCN_CNT_CODE OR IMAGE_SCN_MEM_EXECUTE OR IMAGE_SCN_MEM_READ OR IMAGE_SCN_MEM_WRITE;
        BlockWrite(img.o, sectCode, SizeOf(sectCode));

        FillChar(sectBss, SizeOf(sectBss), #0);
        SetPeSectName(sectBss, 'BSS');
        sectBss.vaddr := img.bss_ofs;
        sectBss.vsize := img.bss_size;
        sectBss.chars := IMAGE_SCN_CNT_UNINITIALIZED_DATA OR IMAGE_SCN_MEM_READ OR IMAGE_SCN_MEM_WRITE;
        BlockWrite(img.o, sectBss, SizeOf(sectBss));

        FillChar(sectRelo, SizeOf(sectRelo), #0);
        SetPeSectName(sectRelo, 'RELOCS');
        sectRelo.vaddr := relocs_ofs;
        sectRelo.chars := $52000040;
        BlockWrite(img.o, sectRelo, SizeOf(sectRelo));

        hdr_pe.optHeader.sizeOfHeaders := FilePos(img.o);

        FilePosAlign(img.o, PE_FILE_ALIGN);
        sectRelo.ptrRar := FilePos(img.o);

        Seek(img.pe_relocs, 0);
        WHILE NOT EOF(img.pe_relocs) DO BEGIN
                BlockRead(img.pe_relocs, sreloc, SizeOf(PE_RELOC));
                IF NOT sreloc.writed THEN BEGIN
                        crb_pos := FilePos(img.pe_relocs);
                        cr_page := sreloc.page;
System.writeln('Process page ', cr_page);
                        WriteDWord(img.o, cr_page);
                        cr_pos := FilePos(img.o);
                        WriteDWord(img.o, 0);
                        Seek(img.pe_relocs, FilePos(img.pe_relocs) - SizeOf(PE_RELOC));
                        WHILE NOT EOF(img.pe_relocs) DO BEGIN
                                BlockRead(img.pe_relocs, sreloc, SizeOf(PE_RELOC));
                                IF (NOT sreloc.writed) AND (sreloc.page = cr_page) THEN BEGIN
                                        WriteWord(img.o, sreloc.offset OR $3000);
                                        sreloc.writed := TRUE;
System.writeln('Process page ', cr_page, ', add ofs ', sreloc.offset);
                                        Seek(img.pe_relocs, FilePos(img.pe_relocs) - SizeOf(PE_RELOC));
                                        BlockWrite(img.pe_relocs, sreloc, SizeOf(PE_RELOC));
                                END;
                        END;

                        IF (FileSize(img.o) AND 3) <> 0 THEN WriteWord(img.o, 0);
System.writeln('Process page ', cr_page, ', size = ', FileSize(img.o) - cr_pos + 4);
                        IncDWord(img.o, cr_pos, FileSize(img.o) - cr_pos + 4);
                        Seek(img.o, FileSize(img.o));
                        Seek(img.pe_relocs, crb_pos);
                END;
        END;
        sectRelo.rawSize := FilePos(img.o) - sectRelo.ptrRar;
        sectRelo.vsize := sectRelo.rawSize;
        hdr_pe.optHeader.directory[6].size := sectRelo.rawSize;
        hdr_pe.optHeader.sizeOfImage := AlignValue(relocs_ofs + sectRelo.vsize, SECT_ALIGN);
System.writeln('Reloc size: ', sectRelo.rawSize);

        FilePosAlign(img.o, PE_FILE_ALIGN);
        sectCode.ptrRar := FilePos(img.o);
        Seek(img.code, 0);
        BlockCopy(img.code, img.o, img.code_size);
        IF IsOpen(img.data) THEN BEGIN
                Seek(img.data, 0);
                BlockCopy(img.data, img.o, img.data_size);
        END;

        Seek(img.o, pe_start);
        BlockWrite(img.o, hdr_pe, SizeOf(PE_HEADER));
        BlockWrite(img.o, sectCode, SizeOf(sectCode));
        BlockWrite(img.o, sectBss, SizeOf(sectBss));
        BlockWrite(img.o, sectRelo, SizeOf(sectRelo));
END;

PROCEDURE parse_args(VAR img : IMAGE);
VAR     c       : CHAR;
        pc, pos : INTEGER;
        len, i  : INTEGER;
        str     : STRING;
BEGIN
        i := 1;
        pc := ParamCount;
        WHILE (i <= pc) AND (NOT img.err) DO BEGIN
                str := ParamStr(i);
                c := str[1];
                IF (c IN ['-', '/']) AND (str[0] = #2) THEN BEGIN
                        c := upCase(str[2]);
                        Inc(i);
                        IF (c = 'S') AND (i <= pc) THEN BEGIN
                                img.stack_size := atoi(ParamStr(i), 8) SHL 12;
                                Inc(i);
                        END ELSE IF (c = 'F') AND (i <= pc) THEN BEGIN
                                str := ParamStr(i);
                                upstr(str);
                                IF str = 'COM' THEN BEGIN
                                        img.format := OCOM;
                                        img.fext := 'COM';
                                END ELSE IF str = 'MZ' THEN BEGIN
                                        img.format := OMZ;
                                        img.fext := 'EXE';
                                END ELSE IF str = 'PE' THEN BEGIN
                                        img.format := OPE;
                                        img.fext := 'EXE';
                                END ELSE BEGIN
                                        mkerr(img, 'Unknown output format option /F ???');
                                        EXIT;
                                END;
                                Inc(i);
                        END ELSE IF c = 'V' THEN BEGIN
                                img.verbose := TRUE;
                        END ELSE IF c IN ['H', '?'] THEN Help
                        ELSE IF (c = 'O') AND (i <= pc) THEN BEGIN
                                img.outfname := ParamStr(i);
                                Inc(i);
                        END ELSE IF (c = 'E') AND (i <= pc) THEN BEGIN
                                img.entry_name := ParamStr(i);
                                Inc(i);
                        END ELSE BEGIN
                                mkerr(img, 'Unknown option.');
                                EXIT;
                        END;
                END ELSE BEGIN
                        IF Length(img.infname) <> 0 THEN BEGIN
                                mkerr(img, 'Too many input files.');
                                EXIT;
                        END;
                        img.infname := str;
                        Inc(i);
                END;
        END;

        IF Length(img.infname) = 0 THEN mkerr(img, 'No input file.');
        IF Length(img.entry_name) = 0 THEN mkerr(img, 'No entry name.');
        IF (img.stack_size AND $0f) <> 0 THEN img.stack_size := (img.stack_size AND $FFF0) + $10;
        IF img.stack_size < 512 THEN mkerr(img, 'Too small stack.');

        IF img.err THEN EXIT;

        len := Length(img.outfname);
        IF len = 0 THEN BEGIN
                img.outfname := img.infname;
                len := Length(img.outfname);
                pos := len;
                WHILE pos > 0 DO BEGIN
                        c := img.outfname[pos];
                        IF c = '.' THEN BREAK
                        ELSE IF c IN [':', '/', '\'] THEN BEGIN
                                pos := -1;
                                BREAK;
                        END;
                        Dec(pos);
                END;

                IF pos < 1 THEN img.outfname := img.outfname + '.'
                ELSE img.outfname := Copy(img.outfname, 1, pos);

                img.outfname := img.outfname + img.fext;
        END;
        IF img.format = OCOM THEN BEGIN
                img.seg_align := 2;
                img.code_ofs := $100;
        END ELSE IF img.format = OMZ THEN BEGIN
                img.seg_align := $10;
        END ELSE IF img.format = OPE THEN BEGIN
                img.seg_align := $10;
                img.code_ofs := $10000;
        END ELSE BEGIN
                img.seg_align := $10;
        END;
        IF Length(img.outfname) = 0 THEN mkerr(img, 'No output file.');
END;

VAR     img : IMAGE;

BEGIN
        FillChar(img, sizeof(IMAGE), #0);

        img.stack_size := 8 * 1024;
        img.entry_name := 'start';
        img.format := OMZ;

        parse_args(img);

        IF img.err THEN BEGIN
                WriteLnErr(img.errMsg);
                System.WriteLn('  use /H for help');
                Halt(1);
        END;

        Assign(img.i, img.infname);
        Reset(img.i);
        IF NOT IsOpen(img.i) THEN mkerr(img, 'Could not open input file');

        Assign(img.o, img.outfname);
        ReWrite(img.o);
        IF NOT IsOpen(img.o) THEN mkerr(img, 'Could not write output file');

        IF (img.verbose) AND (NOT img.err) THEN BEGIN
                System.WriteLn('Input file:  ', img.infname);
                System.WriteLn('Output file: ', img.outfname);
                System.WriteLn('Stack size:  ', img.stack_size);
                System.WriteLn('Entry name:  ', img.entry_name);
        END;
        IF NOT img.err THEN BEGIN
                IF ReadHeaders(img) THEN IF ReadSegments(img) THEN BEGIN
                        IF img.format = OCOM THEN GenCOM(img)
                        ELSE IF img.format = OMZ THEN GenMZ(img)
                        ELSE IF img.format = OPE THEN GenPE(img);
                END;
        END;
        IF (img.verbose) AND (NOT img.err) THEN BEGIN
                System.WriteLn('Code size:   ', img.code_size);
                System.WriteLn('Data size:   ', img.data_size);
                System.WriteLn('BSS size:    ', img.bss_size);
        END;

        IF IsOpen(img.pe_relocs) THEN Close(img.pe_relocs);
        IF IsOpen(img.i) THEN Close(img.i);
        IF IsOpen(img.o) THEN Close(img.o);
        IF IsOpen(img.code) THEN Close(img.code);
        IF IsOpen(img.data) THEN Close(img.data); 
        IF IsOpen(img.hdr) THEN Close(img.hdr);
        IF img.err THEN BEGIN
                WriteLnErr(img.errMsg);
                System.WriteLn('  use /H for help');
                Halt(1);
        END;
END.
