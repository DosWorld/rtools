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
UNIT rloadam;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt, rlo;

FUNCTION LinkAndGenAdam(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;

IMPLEMENTATION

USES exe;

FUNCTION LinkAndGenAdam(VAR input : BFILE;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size: LONGINT) : BOOLEAN;

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
        bss_size    : DWORD;
        hdr_adam    : ADAM_HEADER;
        s           : STRING;
BEGIN
        FillChar(i, SizeOf(BFile), #0);
        FillChar(hdr, SizeOf(BFile), #0);
        FillChar(code, SizeOf(BFile), #0);
        FillChar(data, SizeOf(BFile), #0);

        err := FALSE;

        code_segnum := 0;
        data_segnum := 1;
        bss_segnum := 2;

        Assign(o, outfname);
        ReWrite(o);
        err := err OR (NOT (IsOpen(input) AND IsOpen(o)));

        IF NOT err THEN BEGIN
                ReWriteTemp(hdr);
                ReWriteTemp(code);
                ReWriteTemp(data);
                ReWriteTemp(i);
        END;

        IF NOT err THEN err := err OR MergeCodeDataBss(input, i, FALSE);
        Seek(i, 0);
        err := err OR (NOT ReadRDF(i, hdr, code, data, code_segnum, data_segnum, bss_segnum));

        FilePosAlign(code, 2);
        FilePosAlign(data, 2);
        Seek(hdr, 0);
        err := err OR DisableRecs(hdr, RREC_SEGRELO);

        bss_size := 0;
        IF NOT err THEN BEGIN
                Seek(hdr, 0);
                WHILE RDF_LOOKUPREC(hdr, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
        END;

        Seek(hdr, 0);
        err := err OR (NOT FindEntryPoint(hdr, FileSize(hdr), entry_name, ip));

        Seek(hdr, 0);
        WHILE RDF_NLOOKUPREC(hdr, FileSize(hdr), RREC_RELOC, c) AND (NOT err) DO BEGIN
                GET_RELOC_REC(c, rec);
                self := (rec.seg AND $40) <> 0;
                dst_ofs := 0;                
                IF rec.rseg = code_segnum THEN
                        dst_ofs := 0
                ELSE IF rec.rseg = bss_segnum THEN
                        dst_ofs := FileSize(code)
                ELSE CONTINUE;
                IncMem(code, rec.width, rec.offset, dst_ofs);
        END;

        BlockWrite(o, DOS32_EXE_STUB, SizeOf(DOS32_EXE_STUB));

        FillChar(hdr_adam, SizeOf(ADAM_HEADER), #0);
        hdr_adam.sign := ADAM_MAGIC;
        hdr_adam.codeOfs := SizeOf(ADAM_HEADER);
        hdr_adam.codeSize := FileSize(code);
        hdr_adam.imgSize := hdr_adam.codeSize + bss_size + stack_size + 16;
        hdr_adam.eip := ip;
        hdr_adam.esp := hdr_adam.imgSize - 16;

        BlockWrite(o, hdr_adam, SizeOf(ADAM_HEADER));

        IF NOT err THEN BEGIN
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));
        END;
        Close(code);
        Close(data);
        Close(hdr);
        Close(i);
        Close(o);

        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(o);
        LinkAndGenAdam := err;
END;

END.
