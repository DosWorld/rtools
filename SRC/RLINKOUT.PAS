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
UNIT rlinkout;

{$DEFINE DEBUG1}

INTERFACE

USES rdffmt, system2;

CONST
REC_IN_PLAN = 64;

TYPE
PRDFMETA = ^TRDFMETA;

PLINK_EXPORT = ^TLINK_EXPORT;
TLINK_EXPORT = RECORD
        rec : REXP_REC;
        rdf : PRDFMETA;
END;

PEXPORTS = ^TEXPORTS;
TEXPORTS = RECORD
        export       : ARRAY [1..REC_IN_PLAN] OF TLINK_EXPORT;
        export_count : WORD;
        next         : PEXPORTS;
END;

PLINK_IMPORT = ^TLINK_IMPORT;
TLINK_IMPORT = RECORD
        rec     : RIMP_REC;
        export  : PLINK_EXPORT;
        newrseg : WORD;
        resolv  : BOOLEAN;
END;

PIMPORTS = ^TIMPORTS;
TIMPORTS = RECORD
        import       : ARRAY [1..REC_IN_PLAN] OF TLINK_IMPORT;
        import_count : WORD;
        next         : PIMPORTS;
END;

TLINKDATA = RECORD
        linked   : BOOLEAN;
        export   : PEXPORTS;
        import   : PIMPORTS;

        smz_bss_size  : WORD;

        smz_code_ofs  : DWORD;
        smz_data_ofs  : DWORD;
        smz_bss_ofs   : DWORD;

        hmz_code_seg  : WORD;
        hmz_code_size : WORD;
        hmz_data_seg  : WORD;
        hmz_data_size : WORD;
        hmz_bss_seg   : WORD;
        hmz_bss_size  : WORD;
END;

TRDFMETA = RECORD
        filename    : STRING;
        file_code   : DWORD;
        file_data   : DWORD;
        code_size   : DWORD;
        data_size   : DWORD;

        data_segnum : WORD;
        bss_segnum  : WORD;
        code_segnum : WORD;

        hdr_size    : DWORD;
        hdr_ofs     : DWORD;
        linker      : TLINKDATA;
        next        : PRDFMETA;
END;

IMAGE_BUILD_PLAN = RECORD
        rdfs        : PRDFMETA;
        hdr         : BFILE;
        linked_out  : BFILE;
END;

CONST
MZ_SIGN = $5A4D;

TYPE
MZ_HEADER = RECORD
        signature
        , bytes_in_last_block
        , blocks_in_file
        , num_relocs
        , header_paragraphs
        , min_extra_paragraphs
        , max_extra_paragraphs
        , ss, sp
        , checksum
        , ip, cs
        , reloc_table_offset
        , overlay_number : WORD;
END;

MZ_RELOC = RECORD
        ofs : WORD;
        seg : WORD;
END;

FUNCTION AlignValue(value : DWORD; align : DWORD) : DWORD;
FUNCTION ReadRDF(VAR src, dst_headers, dst_code, dst_data : BFILE; VAR code_segnum, data_segnum, bss_segnum : WORD) : BOOLEAN;
FUNCTION FindEntryPoint(hdr : BFILE; hdr_size : DWORD; VAR name : RDFNAME; VAR ip : DWORD) : BOOLEAN;
PROCEDURE IncMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
PROCEDURE SetMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
FUNCTION LinkAndGenRDF(VAR input : BFILE; outfname : STRING; reserv_bss : BOOLEAN) : BOOLEAN;
FUNCTION LinkAndGenCOM(VAR input : BFILE;
        code_ofs : DWORD;
        entry_name : RDFNAME;
        outfname : STRING;
        reserv_bss : BOOLEAN) : BOOLEAN;
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
FUNCTION AlignValue(value : DWORD; align : DWORD) : DWORD;
VAR     n : DWORD;
BEGIN
        n := value DIV align;
        IF value MOD align <> 0 THEN Inc(n);
        AlignValue := n * align;
END;

FUNCTION ReadRDF(VAR src, dst_headers, dst_code, dst_data : BFILE; VAR code_segnum, data_segnum, bss_segnum : WORD) : BOOLEAN;
VAR     modsize : DWORD;
        hdrsize : DWORD;
        rec     : RDF_SEG;
        err     : BOOLEAN;
BEGIN
        err := FALSE;
        Seek(src, 0);
        IF GET_FILE_TYPE(src) = FILE_RDF THEN BEGIN
                Seek(src, 6);
                modsize := ReadDWord(src);
                hdrsize := ReadDWord(src);
                IF IsOpen(dst_headers) THEN BlockCopy(src, dst_headers, hdrsize)
        END ELSE BEGIN
                System.writeln('WRONG FILE TYPE');
                err := TRUE;
        END;
        WHILE READ_SEG_REC(src, rec) AND (NOT err) DO BEGIN
                IF (rec.segtype = RDFCS) AND (FileSize(dst_code) = 0) THEN BEGIN
                        BlockCopy(src, dst_code, rec.seglen);
                        code_segnum := rec.segnum;
                END ELSE IF (rec.segtype = RDFDS) AND (FileSize(dst_data) = 0) THEN BEGIN
                        BlockCopy(src, dst_data, rec.seglen);
                        data_segnum := rec.segnum;
                END ELSE BEGIN
                        err := TRUE;
                END;
        END;
        bss_segnum := code_segnum;
        IF bss_segnum < data_segnum THEN bss_segnum := data_segnum;
        Inc(bss_segnum);
        ReadRDF := NOT err;
END;

FUNCTION FindEntryPoint(hdr : BFILE; hdr_size : DWORD; VAR name : RDFNAME; VAR ip : DWORD) : BOOLEAN;
VAR     str   : STRING;
        rec   : REXP_REC;
        find  : BOOLEAN;
        pos   : DWORD;
BEGIN
        find := FALSE;
        ip := 0;
        pos := FilePos(hdr) + hdr_size;
        WHILE (RDF_NLOOKUPREC(hdr, pos, RREC_GLOBAL, str)) AND (NOT find) DO BEGIN
                GET_EXPORT_REC(str, rec);
                IF rec.name = name THEN BEGIN
                        ip := rec.offset;
                        find := TRUE;
                END;
        END;
        FindEntryPoint := find;
END;

FUNCTION DisableRecs(VAR hdr : BFILE; rtype : CHAR) : BOOLEAN;
VAR     str   : STRING;
        err   : BOOLEAN;
BEGIN
        err := FALSE;
        Seek(hdr, 0);
        IF RDF_LOOKUPREC(hdr, rtype, str) THEN BEGIN
                err := TRUE;
                system.writeln('Unsupported record type ' + CHR(ORD(rtype) + ORD('0')));
        END;
        DisableRecs := err;
END;

FUNCTION DisableRelocsWidth(VAR hdr : BFILE; width : BYTE) : BOOLEAN;
VAR     rtype : CHAR;
        c     : STRING;
        rec   : RRELOC_REC;
        err   : BOOLEAN;
BEGIN
        err := FALSE;
        Seek(hdr, 0);
        WHILE NOT EOF(hdr) DO BEGIN
                RDF_READ_REC(hdr, rtype, c);
                IF rtype IN [RREC_SEGRELO, RREC_RELOC] THEN BEGIN
                        GET_RELOC_REC(c, rec);
                        IF rec.width > width THEN BEGIN
                                system.writeln('Invalid relocation width for output format.');
                                err := TRUE;
                                BREAK;
                        END;
                END;
        END;
        DisableRelocsWidth := err;
END;

PROCEDURE IncMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
BEGIN
        CASE width OF
        RWIDTH8:   IncByte(f, ofs, value AND $FF);
        RWIDTH16:  IncWord(f, ofs, value AND $FFFF);
        RWIDTH32:  IncDWord(f, ofs, value);
        END;
END;

PROCEDURE SetMem(VAR f : BFile; width : BYTE; ofs, value : DWORD);
BEGIN
        CASE width OF
        RWIDTH8:   SetByte(f, ofs, value AND $FF);
        RWIDTH16:  SetWord(f, ofs, value AND $FFFF);
        RWIDTH32:  SetDWord(f, ofs, value);
        END;
END;

FUNCTION MergeCodeDataBss(VAR src, dst : BFile; merge_bss : BOOLEAN) : BOOLEAN;
VAR     new_headers : BFile;
        c           : STRING;
        rec         : RRELOC_REC;
        grec        : REXP_REC;
        irec        : RIMP_REC;
        nrec        : RNAME_REC;
        err         : BOOLEAN;

        code        : BFILE;
        data        : BFILE;
        hdr         : BFILE;

        code_ofs    : DWORD;
        code_size   : DWORD;
        data_ofs    : DWORD;
        data_size   : DWORD;
        bss_ofs     : DWORD;
        bss_size    : DWORD;

        code_segnum : WORD;
        data_segnum : WORD;
        bss_segnum  : WORD;

        fix         : DWORD;
BEGIN
        FillChar(hdr, SizeOf(BFile), #0);
        FillChar(code, SizeOf(BFile), #0);
        FillChar(data, SizeOf(BFile), #0);
        FillChar(new_headers, SizeOf(BFile), #0);

        err := NOT (IsOpen(src) AND IsOpen(dst));
        IF NOT err THEN BEGIN
                ReWriteMemFile(hdr);
                ReWriteMemFile(code);
                ReWriteMemFile(data);
        END;
        err := err OR (NOT ReadRDF(src, hdr, code, data, code_segnum, data_segnum, bss_segnum));

        IF NOT err THEN BEGIN
                FilePosAlign(code, 2);
                FilePosAlign(data, 2);

                code_ofs := 0;
                code_size := FileSize(code);
                data_ofs := code_ofs + code_size;
                data_size := FileSize(data);
                bss_ofs := data_ofs + data_size;

                ReWriteMemFile(new_headers);
                err := err OR (NOT IsOpen(new_headers));
        END;

{ copy bss recs }
        IF NOT err THEN BEGIN
                bss_size := 0;
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_BSS, c) DO BEGIN
                        IF merge_bss THEN
                                GET_BSS(c, bss_size)
                        ELSE RDF_WRITE_REC(new_headers, RREC_BSS, c);
                END;
        END;
{ copy export recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_GLOBAL, c) AND (NOT err) DO BEGIN
                        GET_EXPORT_REC(c, grec);
                        IF grec.seg = data_segnum THEN BEGIN
                                grec.seg := code_segnum;
                                Inc(grec.offset, data_ofs);
                        END ELSE IF merge_bss AND (grec.seg = bss_segnum) THEN BEGIN
                                grec.seg := code_segnum;
                                Inc(grec.offset, bss_ofs);
                        END;
                        SET_EXPORT_REC(grec, c);
                        RDF_WRITE_REC(new_headers, RREC_GLOBAL, c);
                END;
        END;
{ copy import recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_IMPORT, c) AND (NOT err) DO BEGIN
                        GET_IMPORT_REC(c, irec);
                        IF irec.seg = data_segnum THEN BEGIN
                                irec.seg := code_segnum;
                        END;
                        SET_IMPORT_REC(irec, c);
                        RDF_WRITE_REC(new_headers, RREC_IMPORT, c);
                END;
        END;
{ copy relocation recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_RELOC, c) AND (NOT err) DO BEGIN
                        GET_RELOC_REC(c, rec);
                        rec.seg := rec.seg AND $3F;

                        IF rec.seg = code_segnum THEN BEGIN
                                fix := 0;
                                IF rec.rseg = data_segnum THEN
                                        fix := data_ofs
                                ELSE IF merge_bss AND (rec.rseg = bss_segnum) THEN
                                        fix := bss_ofs;
                                IncMem(code, rec.width, rec.offset, fix);
                        END ELSE IF rec.seg = data_segnum THEN BEGIN
                                fix := 0;
                                IF rec.rseg = code_segnum THEN
                                        fix := code_ofs - data_ofs
                                ELSE IF rec.rseg = data_segnum THEN
                                        fix := data_ofs
                                ELSE IF merge_bss AND (rec.rseg = bss_segnum) THEN
                                        fix := bss_ofs - data_ofs;
                                IncMem(data, rec.width, rec.offset, fix);
                                Inc(rec.offset, data_ofs);
                                rec.seg := code_segnum;
                        END;
                        IF (rec.rseg = data_segnum)
                                OR ((rec.rseg = bss_segnum) AND merge_bss)
                                THEN rec.rseg := code_segnum;
                        SET_RELOC_REC(rec, c);
                        RDF_WRITE_REC(new_headers, RREC_RELOC, c);
                END;
                Close(hdr);
        END;
{ copy seg-relocation recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_SEGRELO, c) AND (NOT err) DO BEGIN
                        GET_RELOC_REC(c, rec);
                        IF rec.seg = data_segnum THEN BEGIN
                                IncMem(data, rec.width, rec.offset, -data_ofs);
                                Inc(rec.offset, data_ofs);
                                rec.seg := code_segnum;
                        END;
                        IF (rec.rseg = data_segnum) THEN rec.rseg := code_segnum;
                        IF (rec.rseg = bss_segnum) AND merge_bss THEN rec.rseg := code_segnum;
                        SET_RELOC_REC(rec, c);
                        RDF_WRITE_REC(new_headers, RREC_SEGRELO, c);
                END;
        END;
{ copy DLL recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_DLL, c) AND (NOT err) DO BEGIN
                        RDF_WRITE_REC(new_headers, RREC_DLL, c);
                END;
        END;
{ copy RREC_MODNAME recs }
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_MODNAME, c) AND (NOT err) DO BEGIN
                        RDF_WRITE_REC(new_headers, RREC_MODNAME, c);
                END;
        END;

        IF NOT err THEN BEGIN
                Seek(dst, 0);
                Seek(data, 0);
                Seek(code, FileSize(code));
                BlockCopy(data, code, FileSize(data));
                IF merge_bss THEN WHILE bss_size > 0 DO BEGIN
                                WriteByte(code, 0);
                                Dec(bss_size);
                        END;
                Seek(data, 0);
                Truncate(data);
                WRITE_RDF(new_headers, code_segnum, code, data_segnum, data, dst);
                Truncate(dst);
                Seek(dst, 0);
        END;
        Close(new_headers);
        Close(hdr);
        Close(code);
        Close(data);
        MergeCodeDataBss := err;
END;

FUNCTION LinkAndGenRDF(VAR input : BFILE; outfname : STRING; reserv_bss : BOOLEAN) : BOOLEAN;
VAR     o           : BFILE;
        err         : BOOLEAN;
BEGIN
        err := FALSE;
        Assign(o, outfname);
        Rewrite(o);
        err := err OR (NOT IsOpen(o));
        IF NOT err THEN BEGIN
                err := MergeCodeDataBss(input, o, reserv_bss);
        END;
{$IFNDEF DEBUG}
        IF err THEN SetDeleteOnClose(o, TRUE);
{$ENDIF}
        Close(o);
        LinkAndGenRDF := err;
END;

FUNCTION LinkAndGenCOM(VAR input : BFILE;
        code_ofs    : DWORD;
        entry_name  : RDFNAME;
        outfname    : STRING;
        reserv_bss  : BOOLEAN) : BOOLEAN;
VAR     dst_ofs     : DWORD;
        c           : STRING;
        rec         : RRELOC_REC;
        alloc_size  : WORD;
        jmp_instr   : ARRAY[0..3] OF BYTE;
        jmp_addr    : WORD;

        err         : BOOLEAN;

        i, o        : BFILE;

        code        : BFILE;
        data        : BFILE;
        hdr         : BFILE;

        code_size   : DWORD;
        data_ofs    : DWORD;
        data_size   : DWORD;
        bss_ofs     : DWORD;

        ip          : DWORD;

        code_segnum : WORD;
        data_segnum : WORD;
        bss_segnum  : WORD;
        self        : BOOLEAN;
BEGIN
        FillChar(i, SizeOf(BFile), #0);
        FillChar(hdr, SizeOf(BFile), #0);
        FillChar(code, SizeOf(BFile), #0);
        FillChar(data, SizeOf(BFile), #0);

        err := FALSE;

        Assign(o, outfname);
        ReWrite(o);
        err := err OR (NOT (IsOpen(input) AND IsOpen(o)));

        IF NOT err THEN BEGIN
                ReWriteMemFile(hdr);
                ReWriteMemFile(code);
                ReWriteMemFile(data);
                {$IFNDEF DEBUG}
                ReWriteMemFile(i);
                {$ENDIF}
                {$IFDEF DEBUG}
                Assign(i, 'merge.rdf');
                ReWrite(i);
                {$ENDIF}
        END;

        IF NOT err THEN err := err OR MergeCodeDataBss(input, i, reserv_bss);

        Seek(i, 0);
        err := err OR (NOT ReadRDF(i, hdr, code, data, code_segnum, data_segnum, bss_segnum));

        FilePosAlign(code, 2);
        FilePosAlign(data, 2);

        err := err OR DisableRecs(hdr, RREC_SEGRELO);
        err := err OR DisableRecs(hdr, RREC_IMPORT);
        err := err OR DisableRecs(hdr, RREC_FARIMPORT);
        err := err OR DisableRelocsWidth(hdr, RWIDTH16);
        code_ofs := $100;
        code_size := FileSize(code);
        bss_ofs := code_ofs + code_size;

        Seek(hdr, 0);
        err := err OR (NOT FindEntryPoint(hdr, FileSize(hdr), entry_name, ip));
        Inc(ip, code_ofs);

        IF ip <> code_ofs THEN BEGIN
                Inc(ip, SizeOf(jmp_instr));
                Inc(code_ofs, SizeOf(jmp_instr));
                Inc(bss_ofs, SizeOf(jmp_instr));
        END;

        Seek(hdr, 0);
        WHILE RDF_NLOOKUPREC(hdr, FileSize(hdr), RREC_RELOC, c) AND (NOT err) DO BEGIN
                GET_RELOC_REC(c, rec);
                
                self := (rec.seg AND $40) <> 0;
                dst_ofs := 0;                
                IF rec.rseg = code_segnum THEN
                        dst_ofs := code_ofs
                ELSE IF rec.rseg = bss_segnum THEN
                        dst_ofs := bss_ofs
                ELSE CONTINUE;
                IF self THEN Dec(dst_ofs, code_ofs);
                IncMem(code, rec.width, rec.offset, dst_ofs);
        END;

        IF NOT err THEN BEGIN
                IF ip <> code_ofs THEN BEGIN
                        jmp_addr := ip;
                        jmp_addr := jmp_addr - $103;
                        jmp_instr[0] := $e9;
                        jmp_instr[1] := jmp_addr AND $FF;
                        jmp_instr[2] := (jmp_addr SHR 8) AND $FF;
                        jmp_instr[3] := $90;
                        BlockWrite(o, jmp_instr, SizeOf(jmp_instr));
                END;
        
                Seek(code, 0);
                BlockCopy(code, o, code_size);
        END;
        IF err THEN SetDeleteOnClose(o, TRUE);

        Close(code);
        Close(data);
        Close(hdr);
        Close(i);
        Close(o);
        LinkAndGenCOM := err;
END;

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