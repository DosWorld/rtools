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
UNIT rlomz;

{$DEFINE DEBUG1}

INTERFACE

USES system2, rdffmt, rlo;

FUNCTION LinkAndGenMZS(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;

FUNCTION LinkAndGenMZL(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname   : STRING;
        stack_size : LONGINT) : BOOLEAN;

IMPLEMENTATION

USES exe;

FUNCTION LinkAndGenMZL(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname   : STRING;
        stack_size : LONGINT) : BOOLEAN;
VAR     err      : BOOLEAN;
        i, o     : BFIle;
        hdr      : MZ_HEADER;
        header_par : WORD;
        code     : BFile;
        stack_ss : WORD;
        r        : PRDFMETA;
        start    : PLINK_EXPORT;
        export   : PLINK_EXPORT;
        import   : PLINK_IMPORT;
        bss_size : DWORD;
        s        : STRING;
        rrec     : RRELOC_REC;
        mzr      : MZ_RELOC;
        fix      : WORD;
        p        : INTEGER;
        find     : BOOLEAN;
        selfr    : BOOLEAN;
BEGIN
        err := FALSE;
        Assign(o, outfname);
        ReWrite(o);
        err := NOT IsOpen(o);
        start := NIL;
        FillChar(hdr, SizeOf(MZ_HEADER), #0);
        BlockWrite(o, hdr, SizeOf(MZ_HEADER));

        ReWriteTemp(code);
        err := err OR (NOT IsOpen(code));
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Assign(i, r^.filename);
                Reset(i);

                err := NOT IsOpen(i) ;
                IF NOT err THEN BEGIN
                        Seek(i, r^.file_code);
                        r^.linker.hmz_code_seg := FilePos(code) SHR 4;
                        BlockCopy(i, code, r^.code_size);
                        FilePosAlign(code, $10);
        
                        Seek(i, r^.file_data);
                        r^.linker.hmz_data_seg := FilePos(code) SHR 4;
                        BlockCopy(i, code, r^.data_size);
                        FilePosAlign(code, $10);
        
                        Close(i);
                END;
                r := r^.next;
        END;
        IF NOT err THEN start := FindExportRdf(build_plan, entry_name);
        err := err OR (start = NIL);
        IF NOT err THEN BEGIN
                hdr.cs := start^.rdf^.linker.hmz_code_seg;
                hdr.ip := start^.rec.offset;
        END;

        { calculate bss seg's and SS }
        IF NOT err THEN hdr.ss := FileSize(code) SHR 4;
        hdr.min_ext_par := hdr.ss;
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                bss_size := 0;
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
                bss_size := AlignValue(bss_size, $10);
                r^.linker.hmz_bss_seg := hdr.ss;
                Inc(hdr.ss, bss_size SHR 4);
                r := r^.next;
        END;

        { resolve segrelo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_SEGRELO, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                                fix := r^.linker.hmz_code_seg;
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                fix := r^.linker.hmz_data_seg;
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                fix := r^.linker.hmz_bss_seg;
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import^.export^.rec.seg
                                        = import^.export^.rdf^.code_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_code_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.data_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_data_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.bss_segnum THEN
                                        fix := import^.export^.rdf^.linker.hmz_bss_seg;
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_code_seg SHL 4) + rrec.offset
                                        , fix);
                                mzr.seg := r^.linker.hmz_code_seg;
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , (r^.linker.hmz_data_seg SHL 4) + rrec.offset
                                        , fix);
                                mzr.seg := r^.linker.hmz_data_seg;
                        END;
                        mzr.ofs := rrec.offset;
                        BlockWrite(o, mzr, SizeOf(MZ_RELOC));
                        Inc(hdr.relocs_count);
                END;
                r := r^.next;
        END;

        { resolve relo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        selfr := (rrec.seg AND $40) <> 0;
                        fix := 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                Inc(fix, import^.export^.rec.offset);
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                IncMem(code, RWIDTH16
                                        , (r^.linker.hmz_code_seg SHL 4) + rrec.offset
                                        , fix);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                IncMem(code, RWIDTH16
                                        , (r^.linker.hmz_data_seg SHL 4) + rrec.offset
                                        , fix);
                        END;
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                FilePosAlign(o, $10);
                Seek(code, 0);
                hdr.sign := MZ_SIGN;
                hdr.header_par := FilePos(o) SHR 4;
                BlockCopy(code, o, FileSize(code));
                hdr.blk_count := (FileSize(code) SHR 9) + 1;
                hdr.lblk_size := (FileSize(code) AND $1FF);
                hdr.relocs_ofs := SizeOf(MZ_HEADER);
                hdr.min_ext_par :=
                        (hdr.ss - hdr.min_ext_par)
                        + (stack_size SHR 4) + 1;
                hdr.max_ext_par := hdr.min_ext_par;
                hdr.sp := stack_size;
                Seek(o, 0);
                BlockWrite(o, hdr, SizeOf(MZ_HEADER));
        END;
        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(code);
        Close(o);
        LinkAndGenMZL := err;
END;

FUNCTION LinkAndGenMZS(VAR build_plan : IMAGE_BUILD_PLAN;
        entry_name : RDFNAME;
        outfname : STRING;
        stack_size : LONGINT) : BOOLEAN;
VAR     err      : BOOLEAN;
        i, o     : BFIle;
        hdr      : MZ_HEADER;
        header_par : WORD;
        code     : BFile;
        data     : BFile;
        stack_ss : WORD;
        r        : PRDFMETA;
        start    : PLINK_EXPORT;
        export   : PLINK_EXPORT;
        import   : PLINK_IMPORT;
        bss_size : DWORD;
        s        : STRING;
        rrec     : RRELOC_REC;
        mzr      : MZ_RELOC;
        fix      : WORD;
        p        : INTEGER;
        find     : BOOLEAN;
        selfr    : BOOLEAN;
        smz_code_seg  : WORD;
        smz_data_seg  : WORD;
        smz_bss_seg   : WORD;
BEGIN
        err := FALSE;
        Assign(o, outfname);
        ReWrite(o);
        err := NOT IsOpen(o);
        start := NIL;
        FillChar(hdr, SizeOf(MZ_HEADER), #0);
        BlockWrite(o, hdr, SizeOf(MZ_HEADER));

        ReWriteTemp(code);
        ReWriteTemp(data);

        err := err OR (NOT (IsOpen(code) AND IsOpen(data)));
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Assign(i, r^.filename);
                Reset(i);

                err := NOT IsOpen(i) ;
                IF NOT err THEN BEGIN
                        Seek(i, r^.file_code);
                        r^.linker.smz_code_ofs := FilePos(code);
                        BlockCopy(i, code, r^.code_size);
                        FilePosAlign(code, 4);
        
                        Seek(i, r^.file_data);
                        r^.linker.smz_data_ofs := FilePos(data);
                        BlockCopy(i, data, r^.data_size);
                        FilePosAlign(data, 4);
        
                        Close(i);
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                FilePosAlign(code, $10);
                FilePosAlign(data, $10);
                smz_code_seg  := 0;
                smz_data_seg  := FileSize(code) SHR 4;
                smz_bss_seg   := smz_data_seg;
        END;
        IF NOT err THEN start := FindExportRdf(build_plan, entry_name);
        err := err OR (start = NIL);
        IF NOT err THEN BEGIN
                hdr.cs := smz_code_seg;
                hdr.ip := start^.rec.offset + start^.rdf^.linker.smz_code_ofs;
        END;

        { calculate bss seg's and SS }
        IF NOT err THEN hdr.ss := smz_bss_seg;
        bss_size := FileSize(data);
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                r^.linker.smz_bss_ofs := bss_size;
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_BSS, s) DO BEGIN
                        GET_BSS(s, bss_size);
                END;
                bss_size := AlignValue(bss_size, 2);
                r := r^.next;
        END;
        bss_size := AlignValue(bss_size, $10) - FileSize(data);
        hdr.ss := smz_bss_seg + (bss_size SHR 4);

        { resolve segrelo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_SEGRELO, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                Inc(rrec.offset, r^.linker.smz_code_ofs);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                Inc(rrec.offset, r^.linker.smz_data_ofs);
                        END;

                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                                fix := smz_code_seg;
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                fix := smz_data_seg;
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                fix := smz_bss_seg;
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import^.export^.rec.seg
                                        = import^.export^.rdf^.code_segnum THEN
                                        fix := smz_code_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.data_segnum THEN
                                        fix := smz_data_seg
                                ELSE IF import^.export^.rec.seg
                                        = import^.export^.rdf^.bss_segnum THEN
                                        fix := smz_bss_seg;
                        END;
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                SetMem(code, RWIDTH16
                                        , rrec.offset
                                        , fix);
                                mzr.seg := smz_code_seg;
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                SetMem(data, RWIDTH16
                                        , rrec.offset
                                        , fix);
                                mzr.seg := smz_data_seg;
                        END;
                        mzr.ofs := rrec.offset;
                        BlockWrite(o, mzr, SizeOf(MZ_RELOC));
                        Inc(hdr.relocs_count);
                END;
                r := r^.next;
        END;

        { resolve relo }
        r := build_plan.rdfs;
        WHILE (r <> NIL) AND (NOT err) DO BEGIN
                Seek(build_plan.hdr, r^.hdr_ofs);
                WHILE (NOT err) AND RDF_NLOOKUPREC(build_plan.hdr, r^.hdr_ofs + r^.hdr_size, RREC_RELOC, s) DO BEGIN
                        GET_RELOC_REC(s, rrec);
                        selfr := (rrec.seg AND $40) <> 0;
                        fix := 0;
                        rrec.seg := rrec.seg AND $3F;
                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                Inc(rrec.offset, r^.linker.smz_code_ofs);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                Inc(rrec.offset, r^.linker.smz_data_ofs);
                        END;
                        IF rrec.rseg = r^.code_segnum THEN BEGIN
                                IF NOT selfr THEN Inc(fix, r^.linker.smz_code_ofs);
                        END ELSE IF rrec.rseg = r^.data_segnum THEN BEGIN
                                IF NOT selfr THEN Inc(fix, r^.linker.smz_data_ofs);
                        END ELSE IF rrec.rseg = r^.bss_segnum THEN BEGIN
                                IF NOT selfr THEN Inc(fix, r^.linker.smz_bss_ofs);
                        END ELSE BEGIN
                                import := LookupImportByRSeg(r, rrec.rseg);
                                IF import^.export^.rec.seg = import^.export^.rdf^.code_segnum THEN BEGIN
                                        IF selfr THEN fix := -r^.linker.smz_code_ofs;
                                END ELSE IF import^.export^.rec.seg = import^.export^.rdf^.data_segnum THEN BEGIN
                                        IF selfr THEN fix := -r^.linker.smz_data_ofs;
                                END ELSE IF import^.export^.rec.seg = import^.export^.rdf^.bss_segnum THEN BEGIN
                                        IF selfr THEN fix := -r^.linker.smz_bss_ofs;
                                END;
                                Inc(fix, import^.export^.rec.offset);
                        END;

                        IF rrec.seg = r^.code_segnum THEN BEGIN
                                IncMem(code, rrec.width
                                        , rrec.offset
                                        , fix);
                        END ELSE IF rrec.seg = r^.data_segnum THEN BEGIN
                                IncMem(data, rrec.width
                                        , rrec.offset
                                        , fix);
                        END;
                END;
                r := r^.next;
        END;

        IF NOT err THEN BEGIN
                FilePosAlign(o, $10);
                hdr.sign := MZ_SIGN;
                hdr.header_par := FilePos(o) SHR 4;
                Seek(code, 0);
                BlockCopy(code, o, FileSize(code));
                Seek(data, 0);
                BlockCopy(data, o, FileSize(data));
                hdr.blk_count := ((FileSize(code) + FileSize(data)) SHR 9) + 1;
                hdr.lblk_size := ((FileSize(code) + FileSize(data)) AND $1FF);
                hdr.relocs_ofs := SizeOf(MZ_HEADER);
                hdr.min_ext_par :=
                        (hdr.ss - smz_bss_seg)
                        + (stack_size SHR 4) + 1;
                hdr.max_ext_par := hdr.min_ext_par;
                hdr.sp := stack_size;
                Seek(o, 0);
                BlockWrite(o, hdr, SizeOf(MZ_HEADER));
        END;
        IF err THEN SetDeleteOnClose(o, TRUE);
        Close(code);
        Close(data);
        Close(o);
        LinkAndGenMZS := err;
END;

END.
