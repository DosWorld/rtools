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
UNIT rlole;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt, rlo;

FUNCTION LinkAndGenLE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT;
        bind_zrdx : BOOLEAN) : BOOLEAN;

IMPLEMENTATION

USES Exe;

CONST
SECTION_ALIGN = $10000;
IMAGE_BASE = $10000;

FUNCTION LinkAndGenLE(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT;
        bind_zrdx : BOOLEAN) : BOOLEAN;
VAR     err           : BOOLEAN;

        inp           : BFILE;
        code, data    : BFILE;
        hdr, o        : BFILE;
        relocs        : BFILE;

        hdr_le        : LE_HEADER;

        code_ofs      : DWORD;
        data_ofs      : DWORD;
        bss_ofs       : DWORD;

        code_size     : DWORD;
        data_size     : DWORD;
        bss_size      : DWORD;

        code_segnum   : WORD;
        data_segnum   : WORD;
        bss_segnum    : WORD;

        le_start      : DWORD;
        ip            : DWORD;
        imageSize     : DWORD;
        i             : DWORD;
        relocs_ofs    : DWORD;
        cr_pos        : DWORD;
        crb_pos       : DWORD;
        cr_page       : DWORD;
        s             : STRING;
        rrec          : RRELOC_REC;
        selfr         : BOOLEAN;
        fix           : DWORD;
        ot1, ot2      : LE_OBJECT_TABLE_ENTRY;
        pTable        : LE_OBJECT_PAGE_TABLE_ENTRY;
        rwidth        : BYTE;
        rval, rofs    : DWORD;
        rpage         : DWORD;
        psize, rsize  : DWORD;
BEGIN
        err := NOT IsOpen(input);
        FillChar(hdr, SizeOf(hdr), #0);
        FillChar(code, SizeOf(hdr), #0);
        FillChar(data, SizeOf(hdr), #0);
        FillChar(o, SizeOf(o), #0);
        FillChar(relocs, SizeOf(o), #0);

        IF NOT err THEN BEGIN
                Assign(o, outfname);
                ReWrite(o);
        END;

        err := err OR (NOT (IsOpen(input) AND IsOpen(o)));
        IF NOT err THEN BEGIN        
                ReWriteTemp(hdr);
                ReWriteTemp(code);
                ReWriteTemp(data);
                ReWriteTemp(inp);
                ReWriteTemp(relocs);
                err := NOT (IsOpen(hdr) AND IsOpen(code) AND IsOpen(data) AND IsOpen(inp) AND IsOpen(relocs));
        END;

        IF NOT err THEN err := err OR MergeCodeDataBss(input, inp, FALSE);

        IF NOT err THEN BEGIN
                Seek(input, 0);
                err := NOT ReadRDF(inp, hdr, code, data, code_segnum, data_segnum, bss_segnum);
                IF NOT err THEN BEGIN
                        Seek(o, FileSize(o));
                        FilePosAlign(o, $10);
                END;
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

        code_ofs := 0;
        bss_ofs := code_ofs + code_size;

        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                err := NOT FindEntryPoint(hdr, FileSize(hdr), entry_name, ip);
        END;

        Inc(ip, code_ofs);

        IF bind_zrdx THEN BlockWrite(o, ZRDX_EXE_STUB, SizeOf(ZRDX_EXE_STUB))
        ELSE BlockWrite(o, SIMPLE_EXE_STUB, SizeOf(SIMPLE_EXE_STUB));

        FilePosAlign(o, $10);
        le_start := FilePos(o);
        SetWord(o, $3C, le_start);
        Seek(o, le_start);

        FillChar(hdr_le, SizeOf(LE_HEADER), #0);
        hdr_le.sign := LE_MAGIC;

        hdr_le.cpuType := LE_CPU_I386;
        hdr_le.osType := LE_OS2;
        hdr_le.moduleFlags := $200;
        hdr_le.pageSize := $1000;
        hdr_le.moduleNumPages := (FileSize(code) div hdr_le.pageSize) + 1;
        hdr_le.eipObject := 1;
        hdr_le.eip := ip;
        hdr_le.espObject := 2;
        hdr_le.esp := stack_size;
        hdr_le.lPageSize := FileSize(code) mod hdr_le.pageSize;
        hdr_le.objectTblOfs := SizeOf(LE_HEADER);
        hdr_le.moduleNumObjects := 2;
        hdr_le.autoDsObjectNum := 2;

        BlockWrite(o, hdr_le, SizeOf(LE_HEADER));

        FillChar(ot1, SizeOf(LE_OBJECT_TABLE_ENTRY), #0);
        ot1.relocBaseAddr := code_ofs;
        ot1.virtualSize := FileSize(code) + bss_size;
        ot1.objectFlags := $2045;
        ot1.pageTblIndex := 1;
        ot1.numPageTblEntries := hdr_le.moduleNumPages;
        BlockWrite(o, ot1, SizeOf(LE_OBJECT_TABLE_ENTRY));

        FillChar(ot2, SizeOf(LE_OBJECT_TABLE_ENTRY), #0);
        ot2.relocBaseAddr := ot1.relocBaseAddr + AlignValue(ot1.virtualSize, SECTION_ALIGN);
        ot2.virtualSize := stack_size;
        ot2.objectFlags := $2043;
        ot2.pageTblIndex := 2;
        BlockWrite(o, ot2, SizeOf(LE_OBJECT_TABLE_ENTRY));

        hdr_le.objectPageTblOfs := FilePos(o) - le_start;
        FillChar(pTable, SizeOf(LE_OBJECT_PAGE_TABLE_ENTRY), #0);
        FOR i := 1 TO hdr_le.moduleNumPages DO BEGIN
                pTable.pnumLo := i AND $FF;
                pTable.pnumHi := i SHR 8;
                pTable.pnumHi := (pTable.pnumHi SHL 8) OR (pTable.pnumHi SHR 8);
                BlockWrite(o, pTable, SizeOf(LE_OBJECT_PAGE_TABLE_ENTRY));
        END;

        hdr_le.resourceTblOfs := FilePos(o) - le_start;
        hdr_le.residentNameTblOfs := hdr_le.resourceTblOfs;
        BlockWrite(o, outfname[0], ORD(outfname[0]) + 1);
        WriteWord(o, 0);
        WriteByte(o, 0);
        hdr_le.entryTblOfs := FilePos(o) - le_start;
        WriteByte(o, 0);

        hdr_le.fixupPageTblOfs := FilePos(o) - le_start;
        FOR i := 1 TO hdr_le.moduleNumPages + 1 DO BEGIN
                WriteDword(o, 0);
        END;
        
        IF NOT err THEN Seek(hdr, 0);
        WHILE (NOT err) AND RDF_LOOKUPREC(hdr, RREC_RELOC, s) DO BEGIN
                GET_RELOC_REC(s, rrec);
                selfr := (rrec.seg AND $40) <> 0;
                rrec.seg := rrec.seg AND $3F;
                IF rrec.seg <> code_segnum THEN BEGIN
                        System.writeln('Invalid relocation.'); err := TRUE; BREAK;
                END;
                fix := code_ofs;
                IF NOT selfr THEN BEGIN
                        IF rrec.rseg = code_segnum THEN Inc(fix, code_ofs)
                        ELSE IF rrec.rseg = data_segnum THEN Inc(fix, data_ofs)
                        ELSE IF rrec.rseg = bss_segnum THEN Inc(fix, bss_ofs);
                END;

                IF rrec.width = RWIDTH8 THEN BEGIN
                        IF rrec.seg = code_segnum THEN
                                IncByte(code, rrec.offset, fix AND $FF);
                END ELSE IF rrec.width = RWIDTH16 THEN BEGIN
                        IF rrec.seg = code_segnum THEN
                                IncWord(code, rrec.offset, fix AND $FFFF);
                END ELSE IF rrec.width = RWIDTH32 THEN BEGIN
                        IF rrec.seg = code_segnum THEN
                                IncDWord(code, rrec.offset, fix);
                END;
                IF rrec.seg = code_segnum THEN BEGIN
                        WriteDword(relocs, rrec.offset div hdr_le.pageSize);
                        WriteDword(relocs, rrec.offset mod hdr_le.pageSize);
                        WriteDword(relocs, GetDWord(code, rrec.offset));
                END;
        END;

        hdr_le.fixupRecordTblOfs := FilePos(o) - le_start;
        psize := 0;
        FOR i := 1 TO hdr_le.moduleNumPages DO BEGIN
                Seek(relocs, 0);
                rsize := FilePos(o);
                WHILE NOT EOF(relocs) DO BEGIN
                        rpage := ReadDWord(relocs);
                        rofs := ReadDWord(relocs);
                        rval := ReadDWord(relocs);
                        IF rpage = (i - 1) THEN BEGIN
                                WriteByte(o, 7);
                                IF rofs < $10000 THEN BEGIN
                                        WriteByte(o, 0);
                                        WriteWord(o, rofs);
                                        WriteByte(o, 1);
                                        WriteWord(o, rval);
                                END ELSE BEGIN
                                        WriteByte(o, $10);
                                        WriteWord(o, rofs);
                                        WriteByte(o, 1);
                                        WriteDword(o, rval);
                                END;
                        END;
                END;
                rsize := FilePos(o) - rsize + psize;
                SetDword(o, le_start + hdr_le.fixupPageTblOfs + ((i - 1) SHL 2), psize);
                psize := rsize;
                Seek(o, FileSize(o));
        END;
        Close(relocs);
        SetDword(o, le_start + hdr_le.fixupPageTblOfs + (hdr_le.moduleNumPages SHL 2), psize);
        Seek(o, FileSize(o));

        hdr_le.importModuleTblOfs := FilePos(o) - le_start;
        hdr_le.importProcTblOfs := hdr_le.importModuleTblOfs;
        WriteByte(o, 0);
        hdr_le.fixupSectionSize :=  FilePos(o) - le_start - hdr_le.fixupPageTblOfs;

        hdr_le.loaderSectionSize := FilePos(o) - le_start - SizeOf(LE_HEADER);

        IF NOT err THEN BEGIN
                FilePosAlign(o, $10);
                hdr_le.dataPagesOfs := FilePos(o);
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));

                Seek(o, le_start);
                BlockWrite(o, hdr_le, SizeOf(LE_HEADER));
                BlockWrite(o, ot1, SizeOf(LE_OBJECT_TABLE_ENTRY));
                BlockWrite(o, ot2, SizeOf(LE_OBJECT_TABLE_ENTRY));

        END;
        Close(hdr);
        Close(code);
        Close(data);
        Close(inp);

        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(o);
        LinkAndGenLE := err;
END;

END.
