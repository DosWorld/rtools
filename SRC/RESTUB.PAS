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
USES system2, exe;

VAR     fin, fout, fstub : BFILE;
        in_size          : DWORD;
        stub_size        : DWORD;
        failed           : BOOLEAN;

PROCEDURE Fail(msg : STRING);
BEGIN
        System.Writeln(msg);
        failed := TRUE;
END;

FUNCTION AlignUp(v, a : DWORD) : DWORD;
BEGIN
        AlignUp := ((v + a - 1) DIV a) * a;
END;

PROCEDURE PadTo(VAR f : BFILE; size : DWORD);
BEGIN
        Seek(f, FileSize(f));
        WHILE FileSize(f) < size DO WriteByte(f, 0);
END;

FUNCTION MzSize(VAR f : BFILE) : DWORD;
VAR     last, pages : WORD;
BEGIN
        last := GetWord(f, 2);
        pages := GetWord(f, 4);
        IF last = 0 THEN MzSize := DWORD(pages) * 512
        ELSE MzSize := (DWORD(pages) - 1) * 512 + last;
END;

PROCEDURE WriteStub(newlf : DWORD; set_lfanew : BOOLEAN);
BEGIN
        Seek(fstub, 0);
        BlockCopy(fstub, fout, stub_size);
        IF set_lfanew THEN BEGIN
                PadTo(fout, newlf);
                SetDWord(fout, $3C, newlf);
        END;
END;

PROCEDURE CopyTail(from_ofs : DWORD);
BEGIN
        Seek(fin, from_ofs);
        Seek(fout, FileSize(fout));
        BlockCopy(fin, fout, in_size - from_ofs);
END;

PROCEDURE AddW(ofs : DWORD; delta : LONGINT);
VAR     v : LONGINT;
BEGIN
        v := GetWord(fout, ofs);
        IF v = 0 THEN EXIT;
        v := v + delta;
        IF (v < 1) OR (v > 65535) THEN BEGIN
                Fail('Offset does not fit into the file format after replacing the stub.');
                EXIT;
        END;
        SetWord(fout, ofs, v);
END;

PROCEDURE AddD(ofs : DWORD; delta : LONGINT);
VAR     v : LONGINT;
BEGIN
        v := GetDWord(fout, ofs);
        IF v = 0 THEN EXIT;
        SetDWord(fout, ofs, v + delta);
END;

PROCEDURE DoNE(lf : DWORD);
VAR     segshift, resshift : WORD;
        unit_, runit       : DWORD;
        d                  : LONGINT;
        newlf              : DWORD;
        nseg, i            : WORD;
        segtab, rt, rnt    : DWORD;
        p                  : DWORD;
        t, c, j            : WORD;
BEGIN
        segshift := GetWord(fin, lf + $32);
        IF segshift = 0 THEN segshift := 9;
        IF segshift > 15 THEN BEGIN
                Fail('Bad alignment shift in NE header.');
                EXIT;
        END;
        unit_ := DWORD(1) SHL segshift;
        rt := lf + GetWord(fin, lf + $24);
        rnt := lf + GetWord(fin, lf + $26);
        runit := 0;
        IF (GetWord(fin, lf + $34) > 0) AND (rnt > rt + 4) THEN BEGIN
                resshift := GetWord(fin, rt);
                IF resshift > 15 THEN BEGIN
                        Fail('Bad resource alignment shift in NE file.');
                        EXIT;
                END;
                runit := DWORD(1) SHL resshift;
                IF runit > unit_ THEN unit_ := runit;
        END;
        IF (lf AND 15) = 0 THEN newlf := AlignUp(stub_size, 16) ELSE newlf := stub_size;
        IF newlf >= lf THEN d := ((LONGINT(newlf) - LONGINT(lf) + LONGINT(unit_) - 1) DIV LONGINT(unit_)) * LONGINT(unit_)
        ELSE d := -(((LONGINT(lf) - LONGINT(newlf)) DIV LONGINT(unit_)) * LONGINT(unit_));
        newlf := lf + d;
        WriteStub(newlf, TRUE);
        CopyTail(lf);
        AddD(newlf + $2C, d);
        segtab := newlf + GetWord(fout, newlf + $22);
        nseg := GetWord(fout, newlf + $1C);
        FOR i := 0 TO nseg - 1 DO BEGIN
                IF failed THEN EXIT;
                AddW(segtab + (i * 8), d DIV LONGINT(DWORD(1) SHL segshift));
        END;
        IF runit > 0 THEN BEGIN
                rt := newlf + GetWord(fout, newlf + $24);
                p := rt + 2;
                WHILE (NOT failed) AND (p < rt + $FFFF) DO BEGIN
                        t := GetWord(fout, p);
                        IF t = 0 THEN BREAK;
                        c := GetWord(fout, p + 2);
                        Inc(p, 8);
                        FOR j := 1 TO c DO BEGIN
                                AddW(p, d DIV LONGINT(runit));
                                Inc(p, 12);
                        END;
                END;
        END;
END;

PROCEDURE DoLE(lf : DWORD; lx : BOOLEAN);
VAR     newlf : DWORD;
        d     : LONGINT;
BEGIN
        IF lx AND (GetDWord(fin, lf + $4C) <> 0) THEN BEGIN
                Fail('LX files with iterated pages are not supported.');
                EXIT;
        END;
        newlf := AlignUp(stub_size, 16);
        d := LONGINT(newlf) - LONGINT(lf);
        WriteStub(newlf, TRUE);
        CopyTail(lf);
        AddD(newlf + $80, d);
        AddD(newlf + $88, d);
        AddD(newlf + $98, d);
END;

FUNCTION PeChecksum(VAR f : BFILE; ckofs : DWORD) : DWORD;
VAR     sum, pos, size : DWORD;
        w              : WORD;
BEGIN
        sum := 0;
        size := FileSize(f);
        pos := 0;
        Seek(f, 0);
        WHILE pos + 1 < size DO BEGIN
                w := ReadWord(f);
                IF (pos <> ckofs) AND (pos <> ckofs + 2) THEN BEGIN
                        sum := sum + w;
                        IF sum > $FFFF THEN sum := (sum AND $FFFF) + (sum SHR 16);
                END;
                Inc(pos, 2);
        END;
        IF (size AND 1) <> 0 THEN BEGIN
                sum := sum + ReadByte(f);
                IF sum > $FFFF THEN sum := (sum AND $FFFF) + (sum SHR 16);
        END;
        sum := (sum AND $FFFF) + (sum SHR 16);
        PeChecksum := (sum AND $FFFF) + size;
END;

FUNCTION RvaToOfs(rva, newlf, nsec, optsz : DWORD) : DWORD;
VAR     i  : DWORD;
        p  : DWORD;
        va, vs, rs, pr : DWORD;
BEGIN
        RvaToOfs := 0;
        FOR i := 0 TO nsec - 1 DO BEGIN
                p := newlf + 24 + optsz + (i * 40);
                vs := GetDWord(fout, p + 8);
                va := GetDWord(fout, p + 12);
                rs := GetDWord(fout, p + 16);
                pr := GetDWord(fout, p + 20);
                IF rs > vs THEN vs := rs;
                IF (rva >= va) AND (rva < va + vs) THEN BEGIN
                        RvaToOfs := rva - va + pr;
                        EXIT;
                END;
        END;
END;

PROCEDURE DoPE(lf : DWORD);
VAR     magic, nsec, optsz : DWORD;
        oldsoh, newsoh, fa : DWORD;
        newlf, lenh        : DWORD;
        d, dlf             : LONGINT;
        i, dirs, p         : DWORD;
        cksum, dsz, dofs   : DWORD;
        k                  : DWORD;
BEGIN
        magic := GetWord(fin, lf + 24);
        optsz := GetWord(fin, lf + 20);
        nsec := GetWord(fin, lf + 6);
        IF (magic <> $10B) AND (magic <> $20B) THEN BEGIN
                Fail('Unknown PE optional header.');
                EXIT;
        END;
        fa := GetDWord(fin, lf + 24 + 36);
        oldsoh := GetDWord(fin, lf + 24 + 60);
        cksum := GetDWord(fin, lf + 24 + 64);
        IF (fa < $200) OR (fa > $10000) OR ((fa AND (fa - 1)) <> 0) THEN BEGIN
                Fail('Bad file alignment in PE header.');
                EXIT;
        END;
        IF (oldsoh < lf + 24 + optsz + (nsec * 40)) OR (oldsoh > in_size) THEN BEGIN
                Fail('Bad SizeOfHeaders in PE header.');
                EXIT;
        END;
        FOR i := 0 TO nsec - 1 DO BEGIN
                p := GetDWord(fin, lf + 24 + optsz + (i * 40) + 20);
                IF (p <> 0) AND (p < oldsoh) THEN BEGIN
                        Fail('A section starts inside the headers, cannot replace the stub.');
                        EXIT;
                END;
        END;
        newlf := AlignUp(stub_size, 8);
        lenh := oldsoh - lf;
        WHILE (lenh > (24 + optsz + (nsec * 40))) AND (GetByte(fin, lf + lenh - 1) = 0) DO Dec(lenh);
        newsoh := AlignUp(newlf + lenh, fa);
        d := LONGINT(newsoh) - LONGINT(oldsoh);
        dlf := LONGINT(newlf) - LONGINT(lf);
        WriteStub(newlf, TRUE);
        Seek(fin, lf);
        Seek(fout, FileSize(fout));
        BlockCopy(fin, fout, lenh);
        PadTo(fout, newsoh);
        CopyTail(oldsoh);
        SetDWord(fout, newlf + 24 + 60, newsoh);
        FOR i := 0 TO nsec - 1 DO BEGIN
                p := newlf + 24 + optsz + (i * 40);
                AddD(p + 20, d);
                AddD(p + 24, d);
                AddD(p + 28, d);
        END;
        AddD(newlf + 4 + 8, d);
        IF magic = $10B THEN dirs := newlf + 24 + 96 ELSE dirs := newlf + 24 + 112;
        AddD(dirs + (4 * 8), d);
        k := GetDWord(fout, dirs + (11 * 8));
        IF k <> 0 THEN SetDWord(fout, dirs + (11 * 8), LONGINT(k) + dlf);
        dofs := GetDWord(fout, dirs + (6 * 8));
        dsz := GetDWord(fout, dirs + (6 * 8) + 4);
        IF dofs <> 0 THEN BEGIN
                dofs := RvaToOfs(dofs, newlf, nsec, optsz);
                IF dofs <> 0 THEN FOR i := 0 TO (dsz DIV 28) - 1 DO BEGIN
                        p := dofs + (i * 28) + 24;
                        IF GetDWord(fout, p) >= oldsoh THEN AddD(p, d);
                END;
        END;
        IF cksum <> 0 THEN SetDWord(fout, newlf + 24 + 64, PeChecksum(fout, newlf + 24 + 64));
END;

PROCEDURE DoAdam;
BEGIN
        IF MzSize(fstub) <> stub_size THEN BEGIN
                Fail('The stub must be a DOS exe whose size is written in its header (ADAM).');
                EXIT;
        END;
        WriteStub(0, FALSE);
        CopyTail(MzSize(fin));
END;

VAR     lf     : DWORD;
        kind   : BYTE;
        sig    : WORD;
        sig2   : WORD;
BEGIN
        failed := FALSE;
        IF ParamCount <> 3 THEN BEGIN
                System.Writeln('RESTUB - replaces the DOS stub of NE, LE/LX, PE and ADAM files.');
                System.Writeln('usage: RESTUB input.exe output.exe stub.exe');
                Halt(1);
        END;
        IF ParamStr(1) = ParamStr(2) THEN BEGIN
                System.Writeln('Input and output files must be different.');
                Halt(1);
        END;
        Assign(fin, ParamStr(1));
        Reset(fin);
        IF NOT IsOpen(fin) THEN BEGIN
                System.Writeln('Could not open ', ParamStr(1), '.');
                Halt(1);
        END;
        Assign(fstub, ParamStr(3));
        Reset(fstub);
        IF NOT IsOpen(fstub) THEN BEGIN
                System.Writeln('Could not open ', ParamStr(3), '.');
                Halt(1);
        END;
        in_size := FileSize(fin);
        stub_size := FileSize(fstub);
        IF (in_size < $40) OR (GetWord(fin, 0) <> MZ_SIGN) THEN BEGIN
                System.Writeln(ParamStr(1), ' is not an MZ based file.');
                Halt(1);
        END;
        IF (stub_size < $40) OR (GetWord(fstub, 0) <> MZ_SIGN) THEN BEGIN
                System.Writeln(ParamStr(3), ' is not a DOS exe (stub).');
                Halt(1);
        END;
        kind := 0;
        lf := 0;
        IF GetWord(fin, $18) >= $40 THEN BEGIN
                lf := GetDWord(fin, $3C);
                IF (lf >= $40) AND (lf + 4 <= in_size) THEN BEGIN
                        sig := GetWord(fin, lf);
                        sig2 := GetWord(fin, lf + 2);
                        IF sig = NE_SIGN THEN kind := 1
                        ELSE IF sig = LE_MAGIC THEN kind := 2
                        ELSE IF sig = $584C THEN kind := 3
                        ELSE IF (sig = $4550) AND (sig2 = 0) THEN kind := 4;
                END;
        END;
        IF (kind = 0) AND (MzSize(fin) + 4 <= in_size) THEN BEGIN
                IF GetDWord(fin, MzSize(fin)) = $6D616441 THEN kind := 5;
        END;
        IF kind = 0 THEN BEGIN
                System.Writeln(ParamStr(1), ': not NE, LE, LX, PE or ADAM file.');
                Halt(1);
        END;
        Assign(fout, ParamStr(2));
        ReWrite(fout);
        IF NOT IsOpen(fout) THEN BEGIN
                System.Writeln('Could not create ', ParamStr(2), '.');
                Halt(1);
        END;
        CASE kind OF
        1: DoNE(lf);
        2: DoLE(lf, FALSE);
        3: DoLE(lf, TRUE);
        4: DoPE(lf);
        5: DoAdam;
        END;
        IF failed THEN SetDeleteOnClose(fout, TRUE);
        Close(fout);
        Close(fin);
        Close(fstub);
        IF failed THEN Halt(1);
END.
