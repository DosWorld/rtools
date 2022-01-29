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
UNIT rlocom;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt, rlo;

FUNCTION LinkAndGenCOM(VAR input : BFILE;
        code_ofs : DWORD;
        entry_name : RDFNAME;
        outfname : STRING;
        reserv_bss : BOOLEAN) : BOOLEAN;

IMPLEMENTATION

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

END.