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
USES utils;

CONST
RELOC_WIDTH = 2;

TYPE
IMAGE = RECORD
        i, o        : FILE;
        code        : PCHAR;
        data        : PCHAR;
        hdr         : PCHAR;
        code_size   : WORD;
        code_segnum : WORD;
        code_ofs    : WORD;
        data_size   : WORD;
        data_segnum : WORD;
        data_ofs    : WORD;
        bss_size    : DWORD;
        bss_segnum  : WORD;
        bss_ofs     : WORD;
        hdr_size    : WORD;
        ip          : WORD;
        err         : BOOLEAN;
        errMsg      : STRING;
        entry_name  : STRING;
        infname     : STRING;
        outfname    : STRING;
        header      : ARRAY[0..15] OF WORD;
        stack_size  : WORD;
        verbose     : BOOLEAN;
        com_file    : BOOLEAN;
        seg_align   : INTEGER;
END;

PROCEDURE mkerr(VAR img : IMAGE; str : STRING);
BEGIN
        IF img.err THEN EXIT;
        img.err := TRUE;
        img.errMsg := str;
END;

PROCEDURE Help;
BEGIN
        WriteLn('usage: REXE [/H] [/S nnnn] [/E name] [/T] [/V] file.rdf');
        WriteLn;
        WriteLn('/S nnnn - Set stack size (in bytes)');
        WriteLn('/E name - Set symbol name for entry point (default is "start")');
        WriteLn('/T      - Produce .COM file');
        WriteLn('/V      - Verbose output');
        WriteLn('/H      - Show this help');
        Halt(1);
END;

PROCEDURE read_headers(VAR img : IMAGE);
VAR     sign    : STRING[6];
        modsize : DWORD;
        hdrsize : DWORD;
BEGIN
        BlockRead(img.i, sign[1], 6);
        sign[0] := #6;
        IF sign <> 'RDOFF2' THEN BEGIN
                mkerr(img, 'Input file is not RDOFF2.');
                EXIT;
        END;
        modsize := read_dword(img.i);
        hdrsize := read_dword(img.i);
        IF hdrsize > 65000 THEN BEGIN
                mkerr(img, 'Too big headers.');
                EXIT;
        END;
        GetMem(img.hdr, hdrsize);
        IF img.hdr = NIL THEN BEGIN
                mkerr(img, 'No memory.');
                EXIT;
        END;
        BlockRead(img.i, img.hdr[0], hdrsize);
        img.hdr_size := hdrsize;
END;

PROCEDURE falign(VAR f : FILE; t : INTEGER);
VAR     pos : WORD;
        c   : ARRAY[0..511] OF CHAR;
BEGIN
        pos := FilePos(f) MOD t;
        FillChar(c, SizeOf(c), #0);
        IF pos <> 0 THEN BlockWrite(f, c[0], t - pos);
END;

FUNCTION var_align(w, toalign : WORD) : WORD;
BEGIN
        IF (w MOD toalign) <> 0 THEN
                w := ((w DIV toalign) + 1) * toalign;
        var_align := w;
END;

PROCEDURE read_segments(VAR img : IMAGE);
VAR     segtype : WORD;
        segnum  : WORD;
        reserv  : WORD;
        seglen  : DWORD;
BEGIN        
        WHILE NOT EOF(img.i) DO BEGIN
                segtype := read_word(img.i);
                segnum := read_word(img.i);
                reserv := read_word(img.i);
                seglen := read_dword(img.i);
                IF segtype = 0 THEN BREAK;
                IF seglen > 65535 THEN BEGIN
                        mkerr(img, 'Too big segment.');
                        EXIT;
                END;
                IF segtype = 1 THEN BEGIN
                        IF img.code <> NIL THEN BEGIN
                                mkerr(img, 'Multiple code-segment.');
                                EXIT;
                        END;
                        img.code_size := seglen;
                        WHILE (img.code_size AND img.seg_align) <> 0 DO Inc(img.code_size);
                        GetMem(img.code, img.code_size);
                        FillChar(img.code[0], img.code_size, #0);
                        BlockRead(img.i, img.code[0], seglen);
                        img.code_segnum := segnum;
                END ELSE IF segtype = 2 THEN BEGIN
                        IF img.data <> NIL THEN BEGIN
                                mkerr(img, 'Multiple data-segment.');
                                EXIT;
                        END;
                        img.data_size := seglen;
                        WHILE (img.data_size AND img.seg_align) <> 0 DO Inc(img.data_size);
                        GetMem(img.data, img.data_size);
                        FillChar(img.data[0], img.data_size, #0);
                        BlockRead(img.i, img.data[0], seglen);
                        img.data_segnum := segnum;
                END ELSE BEGIN
                        mkerr(img, 'Unknown type of segment.');
                        EXIT;
                END;
        END;
        img.bss_segnum := img.code_segnum;
        IF img.bss_segnum < img.data_segnum THEN img.bss_segnum := img.data_segnum;
        Inc(img.bss_segnum);
END;

PROCEDURE calc_entry(VAR img : IMAGE);
VAR     c, dst         : PCHAR;
        rlen, rtype    : INTEGER;
        reloc_size     : INTEGER;
BEGIN
        img.ip := $ffff;
        reloc_size := img.hdr_size;
        c := img.hdr;
        WHILE reloc_size <> 0 DO BEGIN
                rtype := ORD(c[0]);
                rlen := ORD(c[1]);
                Inc(c, 2);
                IF rtype = 3 THEN BEGIN
                        IF get_str(@c[6]) = img.entry_name THEN BEGIN
                                img.ip := img.code_ofs + get_dword(@c[2]);
                        END;
                END;
                Inc(c, rlen);
                Dec(reloc_size, rlen + 2);
        END;
        IF img.ip = $ffff THEN mkerr(img, 'Entry point not found.');
END;

PROCEDURE apply_relocs(VAR img : IMAGE);
VAR     exe_relo_seg   : WORD;
        exe_relo_ofs   : WORD;
        rdf_relo_seg   : BYTE;
        rdf_relo_ofs   : DWORD;
        rdf_relo_width : BYTE;
        rdf_relo_rseg  : WORD;
        c, dst         : PCHAR;
        rlen, rtype    : INTEGER;
        reloc_size     : INTEGER;
BEGIN
        reloc_size := img.hdr_size;
        c := img.hdr;
        WHILE reloc_size <> 0 DO BEGIN
                rtype := ORD(c[0]);
                rlen := ORD(c[1]);
                Inc(c, 2);
                CASE rtype OF
                1: BEGIN
                        rdf_relo_seg := ORD(c[0]);
                        rdf_relo_ofs :=  get_dword(c + 1);
                        rdf_relo_width := ORD(c[5]);
                        rdf_relo_rseg :=  get_word(c + 6);
                        
                        IF rdf_relo_seg = img.code_segnum THEN dst := img.code
                        ELSE IF rdf_relo_seg = img.data_segnum THEN dst := img.data
                        ELSE BEGIN
                            mkerr(img, 'Invalid relocation.');
                            EXIT;
                        END;
                        IF rdf_relo_width <> RELOC_WIDTH THEN BEGIN
                            mkerr(img, 'Invalid relocation bit-width.');
                            EXIT;
                        END;
                        IF rdf_relo_rseg = img.code_segnum THEN
                                set_word(@dst[rdf_relo_ofs],
                                        get_word(@dst[rdf_relo_ofs]) + img.code_ofs)
                        ELSE IF rdf_relo_rseg = img.data_segnum THEN
                                set_word(@dst[rdf_relo_ofs],
                                        get_word(@dst[rdf_relo_ofs]) + img.data_ofs)
                        ELSE IF rdf_relo_rseg = img.bss_segnum THEN
                                set_word(@dst[rdf_relo_ofs],
                                        get_word(@dst[rdf_relo_ofs]) + img.bss_ofs);
                END;
                2: BEGIN
                        mkerr(img, 'Not resolved import found.');
                        EXIT;
                   END;
                5:      Inc(img.bss_size, get_dword(c));
                6: BEGIN
                        IF img.com_file THEN BEGIN
                                mkerr(img, 'Got segment relocation when produce COM file.');
                                EXIT;
                        END;
                        rdf_relo_seg := ORD(c[0]);
                        rdf_relo_ofs :=  get_dword(c + 1);
                        rdf_relo_width := ORD(c[5]);
                        rdf_relo_rseg :=  get_word(c + 6);
                        IF NOT (rdf_relo_seg IN [img.code_segnum, img.data_segnum]) THEN BEGIN
                            mkerr(img, 'Invalid segment relocation.');
                            EXIT;
                        END;
                        IF rdf_relo_rseg = img.bss_segnum THEN BEGIN
                                rdf_relo_rseg := img.data_segnum;
                        END;
                        IF NOT (rdf_relo_rseg IN [img.code_segnum, img.data_segnum]) THEN BEGIN
                            mkerr(img, 'Invalid segment ref relocation.');
                            EXIT;
                        END;
                        IF rdf_relo_width <> RELOC_WIDTH THEN BEGIN
                            mkerr(img, 'Invalid relocation bit-width.');
                            EXIT;
                        END;
                        exe_relo_seg := 0;
                        IF rdf_relo_seg <> img.code_segnum THEN exe_relo_seg := img.code_size SHR 4;
                        exe_relo_ofs := rdf_relo_ofs;
                        IF rdf_relo_rseg = img.code_segnum THEN rdf_relo_rseg := 0
                        ELSE rdf_relo_rseg := img.code_size SHR 4;
                        IF rdf_relo_seg = 0 THEN BEGIN
                                set_word(@img.code[exe_relo_ofs], rdf_relo_rseg);
                        END ELSE BEGIN
                                set_word(@img.data[exe_relo_ofs], rdf_relo_rseg);
                        END;
                        write_word(img.o, exe_relo_ofs);
                        write_word(img.o, exe_relo_seg);
                        Inc(img.header[3]);
                END;
                END;
                Inc(c, rlen);
                Dec(reloc_size, rlen + 2);
        END;
END;

PROCEDURE convert(VAR img : IMAGE);
VAR     alloc_size : WORD;
        img_size   : DWORD;
        i          : INTEGER;
        jmp_instr  : ARRAY[0..3] OF BYTE;
        jmp_addr   : WORD;
BEGIN
        IF img.verbose THEN BEGIN
                WriteLn('Input file:  ', img.infname);
                WriteLn('Output file: ', img.outfname);
                WriteLn('Stack size:  ', img.stack_size);
                WriteLn('Entry name:  ', img.entry_name);
        END;

        read_headers(img);
        IF img.err THEN EXIT;
        read_segments(img);
        IF img.err THEN EXIT;
        IF img.code = NIL THEN BEGIN
                mkerr(img, 'No code segment.');
                EXIT;
        END;

        IF img.com_file THEN BEGIN
                img.data_ofs := img.code_ofs + img.code_size;
                img.bss_ofs := img.data_ofs + img.data_size;
        END ELSE BEGIN
                img.bss_ofs := img.data_ofs + img.data_size;
                FOR i := 0 TO 15 DO write_word(img.o, img.header[i]);
        END;
        calc_entry(img);
        IF img.err THEN EXIT;
        IF img.com_file AND (img.ip <> img.code_ofs) THEN BEGIN
                Inc(img.ip, SizeOf(jmp_instr));
                Inc(img.code_ofs, SizeOf(jmp_instr));
                Inc(img.data_ofs, SizeOf(jmp_instr));
                Inc(img.bss_ofs, SizeOf(jmp_instr));
                BlockWrite(img.o, jmp_instr, SizeOf(jmp_instr));
        END;
        apply_relocs(img);
        IF img.err THEN EXIT;

        IF NOT img.com_file THEN BEGIN
                falign(img.o, 16);
                img.header[4] := (FilePos(img.o) SHR 4);
        END;
        BlockWrite(img.o, img.code[0], img.code_size);
        IF img.data <> NIL THEN BEGIN
                BlockWrite(img.o, img.data[0], img.data_size);
        END;
        Seek(img.o, 0);
        IF img.com_file AND (img.ip <> img.code_ofs) THEN BEGIN
                jmp_addr := img.ip;
                jmp_addr := jmp_addr - $103;
                jmp_instr[0] := $e9;
                jmp_instr[1] := jmp_addr AND $FF;
                jmp_instr[2] := (jmp_addr SHR 8) AND $FF;
                jmp_instr[3] := $90;
                BlockWrite(img.o, jmp_instr, SizeOf(jmp_instr));
        END ELSE IF NOT img.com_file THEN BEGIN
                img_size := img.code_size + img.data_size;
                img.header[0] := $5a4d;
                img.header[1] := img_size AND $1ff;
                img.header[2] := img_size SHR 9;
                alloc_size := img.bss_size + img.stack_size;
                img.header[5] := alloc_size SHR 4;
                IF (alloc_size AND $0f) <> 0 THEN Inc(img.header[5]);
                img.header[6] := img.header[5];
                img.header[7] := img.code_size SHR 4;
                img.header[8] := img.data_size + img.bss_size + img.stack_size;
                img.header[10] := img.ip;
                img.header[12] := 32;
                FOR i := 0 TO 15 DO write_word(img.o, img.header[i]);
        END;
        IF img.verbose THEN BEGIN
                WriteLn('Code size:   ', img.code_size);
                WriteLn('Data size:   ', img.data_size);
                WriteLn('BSS size:    ', img.bss_size);
                WriteLn('Seg relocs:  ', img.header[3]);
        END;
END;

PROCEDURE parse_args(VAR img : IMAGE);
VAR     c       : CHAR;
        pc, pos : INTEGER;
        len, i  : INTEGER;
        str     : STRING;
BEGIN
        i := 1;
        pc := ParamCount;
        WHILE (i <= ParamCount) AND (NOT img.err) DO BEGIN
                str := ParamStr(i);
                c := str[1];
                IF (c IN ['-', '/']) AND (str[0] = #2) THEN BEGIN
                        c := upCase(str[2]);
                        Inc(i);
                        IF (c = 'S') AND (i <= pc) THEN BEGIN
                                img.stack_size := atoi(ParamStr(i), 1024 * 8);
                                Inc(i);
                        END ELSE IF c = 'T' THEN BEGIN
                                img.com_file := TRUE;
                        END ELSE IF c = 'V' THEN BEGIN
                                img.verbose := TRUE;
                        END ELSE IF c IN ['H', '?'] THEN Help
                        ELSE IF (c = 'E') AND (i <= pc) THEN BEGIN
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
                        img.outfname := str;
                        Inc(i);
                END;
        END;

        IF Length(img.infname) = 0 THEN mkerr(img, 'No input file.');
        IF Length(img.entry_name) = 0 THEN mkerr(img, 'No entry name.');
        IF (img.stack_size AND $0f) <> 0 THEN img.stack_size := (img.stack_size AND $FFF0) + $10;
        IF img.stack_size < 512 THEN mkerr(img, 'Too small stack.');
        IF Length(img.outfname) = 0 THEN mkerr(img, 'No output file.');

        IF img.err THEN EXIT;

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
        IF img.com_file THEN BEGIN
                img.outfname := img.outfname + 'COM';
                img.seg_align := 2;
                img.code_ofs := $100;
        END ELSE BEGIN
                img.outfname := img.outfname + 'EXE';
                img.seg_align := $0F;
        END;
END;

VAR     img : IMAGE;
        i   : INTEGER;

BEGIN
        FillChar(img, sizeof(IMAGE), #0);

        img.stack_size := 8 * 1024;
        img.entry_name := 'start';

        parse_args(img);

        IF img.err THEN BEGIN
                WriteLn(img.errMsg);
                WriteLn('  use /H for help');
                Halt(1);
        END;

        Assign(img.i, img.infname);
        {$I-}
        Reset(img.i, 1);
        i := IOResult;
        {$I+}
        IF i <> 0 THEN mkerr(img, 'Could not open input file')
        ELSE BEGIN
                Assign(img.o, img.outfname);
                {$I-}
                ReWrite(img.o, 1);
                i := IOResult;
                {$I+}
                IF i <> 0 THEN mkerr(img, 'Could not write output file')
                ELSE BEGIN
                        convert(img);
                        Close(img.o);
                END;
                Close(img.i);
        END;

        IF img.code <> NIL THEN FreeMem(img.code, img.code_size);
        IF img.data <> NIL THEN FreeMem(img.data, img.data_size); 
        IF img.hdr <> NIL THEN FreeMem(img.hdr, img.hdr_size);
        IF img.err THEN BEGIN
                WriteLn(img.errMsg);
                WriteLn('  use /H for help');
                { unlink(img.outfname); }
                Halt(1);
        END;
END.
