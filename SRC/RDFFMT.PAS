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
{$I+,A+,R-,S-,O-,F-,D-,L-,Q-,F-,G-}
UNIT RdfFmt;

INTERFACE

USES System2;

CONST

RDFCS    = 1;
RDFDS    = 2;
RDFBS    = 3;

RREC_COMMENT   = #0;
RREC_RELOC     = #1;
RREC_IMPORT    = #2;
RREC_GLOBAL    = #3;
RREC_DLL       = #4;
RREC_BSS       = #5;
RREC_SEGRELO   = #6;
RREC_FARIMPORT = #7;
RREC_MODNAME   = #8;

RDOFF2_SIGN  : STRING[6] = 'RDOFF2';
RLIB_SIGN    : STRING[6] = 'RDLIB2';
RLIB_MODNAME : STRING[12] = '.sig'+#0;

RWIDTH8  = 1;
RWIDTH16 = 2;
RWIDTH32 = 4;
RWIDTH64 = 8;

TYPE
RDF_FILE_TYPE = (FILE_RDF,FILE_RDL,FILE_UNKNOWN);

DWORD = LONGINT;
RDFNAME = STRING[64];

PRNAME_REC = ^RNAME_REC;
RNAME_REC = RECORD
        name : STRING;
        next : POINTER;
END;

PRRELOC_REC = ^RRELOC_REC;
RRELOC_REC = RECORD
        seg    : BYTE;
        offset : DWORD;
        width  : BYTE;
        rseg   : WORD;
        next   : POINTER;
END;

PRIMP_REC = ^RIMP_REC;
RIMP_REC = RECORD
        flags : BYTE;
        seg   : WORD;
        name  : RDFNAME;
        next  : POINTER;
END;

PRFARIMP_REC = ^RFARIMP_REC;
RFARIMP_REC = RECORD
        flags : BYTE;
        seg   : WORD;
        next  : POINTER;
END;

PREXP_REC = ^REXP_REC;
REXP_REC = RECORD
        flags  : BYTE;
        seg    : BYTE;
        offset : DWORD;
        name   : RDFNAME;
        next   : POINTER;
END;

PRDF_SEG = ^RDF_SEG;
RDF_SEG = RECORD
        segnum      : WORD;
        segtype     : WORD;
        seglen      : DWORD;
        file_offset : DWORD;
        next        : POINTER;
END;

FUNCTION GET_FILE_TYPE(VAR f : BFILE) : RDF_FILE_TYPE;
PROCEDURE RDL_CREATE(VAR f : BFILE);
PROCEDURE RDL_APPEND_MODULE(VAR f : BFILE; VAR modname : STRING);
FUNCTION RDL_NEXT_MODULE(VAR f : BFILE; VAR modname : STRING) : BOOLEAN;

{ record iterators for reading }
FUNCTION RDF_LOOKUPREC(VAR f : BFILE; rt1 : CHAR; VAR rec : STRING) : BOOLEAN;
FUNCTION RDF_NLOOKUPREC(VAR f : BFILE; fposmax : DWORD; rt1 : CHAR; VAR rec : STRING) : BOOLEAN;
FUNCTION RDF_LOOKUPREC2(VAR f : BFILE; rt1, rt2 : CHAR; VAR rtype : CHAR; VAR rec : STRING) : BOOLEAN;
FUNCTION RDF_LOOKUPREC3(VAR f : BFILE; rt1, rt2, rt3 : CHAR; VAR rtype : CHAR; VAR rec : STRING) : BOOLEAN;
{ r/w records }
PROCEDURE RDF_READ_REC(VAR f : BFILE; VAR rtype : CHAR; VAR rec : STRING);
PROCEDURE RDF_WRITE_REC(VAR f : BFILE; rtype : CHAR; VAR rec : STRING);
{ string to record }
PROCEDURE GET_EXPORT_REC(VAR src : STRING; VAR dst : REXP_REC);
PROCEDURE GET_IMPORT_REC(VAR src : STRING; VAR dst : RIMP_REC);
PROCEDURE GET_RELOC_REC(VAR src : STRING; VAR dst : RRELOC_REC);
PROCEDURE GET_BSS(VAR src : STRING; VAR dst : DWORD);
PROCEDURE GET_NAME_REC(VAR src : STRING; VAR dst : RNAME_REC);
{ record to string }
PROCEDURE SET_EXPORT_REC(VAR src : REXP_REC; VAR dst : STRING);
PROCEDURE SET_IMPORT_REC(VAR src : RIMP_REC; VAR dst : STRING);
PROCEDURE SET_RELOC_REC(VAR src : RRELOC_REC; VAR dst : STRING);
PROCEDURE SET_BSS(src : DWORD; VAR dst : STRING);
PROCEDURE SET_NAME_REC(VAR src : RNAME_REC; VAR dst : STRING);
{ r/w segments }
FUNCTION READ_SEG_REC(VAR f : BFILE; VAR dst : RDF_SEG) : BOOLEAN;
PROCEDURE WRITE_SEG_REC(VAR f : BFILE; VAR dst : RDF_SEG);
PROCEDURE WRITE_SEG(VAR f : BFILE; segnum, segtype : WORD; seglen : DWORD);

PROCEDURE WRITE_RDF(VAR headers : BFILE; csegnum : WORD; VAR code : BFILE; dsegnum : WORD; VAR data : BFILE; VAR dst : BFILE);

IMPLEMENTATION

FUNCTION RDF_NLOOKUPREC(VAR f : BFILE; fposmax : DWORD; rt1 : CHAR; VAR rec : STRING) : BOOLEAN;
VAR     nrt : CHAR;
        r   : BOOLEAN;
BEGIN
        r := FALSE;
        IF (NOT EOF(f)) AND (FilePos(f) < fposmax) THEN BEGIN
                RDF_READ_REC(f, nrt, rec);
                r := rt1 = nrt;
                WHILE (NOT EOF(f)) AND (FilePos(f) < fposmax) AND (NOT r) DO BEGIN
                        RDF_READ_REC(f, nrt, rec);
                        r := rt1 = nrt;
                END;
        END;
        RDF_NLOOKUPREC := r;
END;

FUNCTION RDF_LOOKUPREC(VAR f : BFILE; rt1 : CHAR; VAR rec : STRING) : BOOLEAN;
BEGIN
        RDF_LOOKUPREC := RDF_NLOOKUPREC(f, FileSize(f), rt1, rec);
END;

FUNCTION RDF_LOOKUPREC2(VAR f : BFILE; rt1, rt2 : CHAR; VAR rtype : CHAR; VAR rec : STRING) : BOOLEAN;
VAR     nrt : CHAR;
        r   : BOOLEAN;
BEGIN
        r := FALSE;
        IF NOT EOF(f) THEN BEGIN
                RDF_READ_REC(f, nrt, rec);
                r := nrt IN [rt1, rt2];
                WHILE (NOT EOF(f)) AND (NOT r) DO BEGIN
                        RDF_READ_REC(f, nrt, rec);
                        r := nrt IN [rt1, rt2];
                END;
        END;
        rtype := nrt;
        RDF_LOOKUPREC2 := r;
END;

FUNCTION RDF_LOOKUPREC3(VAR f : BFILE; rt1, rt2, rt3 : CHAR; VAR rtype : CHAR; VAR rec : STRING) : BOOLEAN;
VAR     nrt : CHAR;
        r   : BOOLEAN;
BEGIN
        r := FALSE;
        IF NOT EOF(f) THEN BEGIN
                RDF_READ_REC(f, nrt, rec);
                r := nrt IN [rt1, rt2, rt3];
                WHILE (NOT EOF(f)) AND (NOT r) DO BEGIN
                        RDF_READ_REC(f, nrt, rec);
                        r := nrt IN [rt1, rt2, rt3];
                END;
        END;
        rtype := nrt;
        RDF_LOOKUPREC3 := r;
END;

PROCEDURE RDF_READ_REC(VAR f : BFILE; VAR rtype : CHAR; VAR rec : STRING);
BEGIN
        rtype := CHR(ReadByte(f));
        rec[0] := CHR(ReadByte(f));
        BlockRead(f, rec[1], ORD(rec[0]));
END;

PROCEDURE RDF_WRITE_REC(VAR f : BFILE; rtype : CHAR; VAR rec : STRING);
BEGIN
        WriteByte(f, ORD(rtype));
        WriteByte(f, ORD(rec[0]));
        Write(f, rec);
END;

FUNCTION get_word(VAR c : STRING; ofs : INTEGER) : WORD;
BEGIN
        get_word := ORD(c[ofs]) OR (ORD(c[ofs + 1]) SHL 8);
END;

FUNCTION get_dword(VAR c : STRING; ofs : INTEGER) : DWORD;
BEGIN
        get_dword := ORD(c[ofs]) OR (ORD(c[ofs + 1]) SHL 8) OR (ORD(c[ofs + 2]) SHL 16) OR (ORD(c[ofs + 3]) SHL 24);
END;

PROCEDURE set_word(VAR c : STRING; ofs : INTEGER; w : WORD);
BEGIN
        c[ofs] := CHR(w and $FF);
        c[ofs + 1] := CHR((w shr 8) and $FF);
END;

PROCEDURE set_dword(VAR c : STRING; ofs : INTEGER; w : DWORD);
BEGIN
        c[ofs] := CHR(w and $FF);
        c[ofs + 1] := CHR((w shr 8) and $FF);
        c[ofs + 2] := CHR((w shr 16) and $FF);
        c[ofs + 3] := CHR((w shr 24) and $FF);
END;

PROCEDURE GET_RELOC_REC(VAR src : STRING; VAR dst : RRELOC_REC);
BEGIN
        dst.next := NIL;
        dst.seg := ORD(src[1]);
        dst.offset :=  get_dword(src, 2);
        dst.width := ORD(src[6]);
        dst.rseg :=  get_word(src, 7);
END;

PROCEDURE SET_RELOC_REC(VAR src : RRELOC_REC; VAR dst : STRING);
BEGIN
        dst[0] := #8;
        dst[1] := CHR(src.seg);
        set_dword(dst, 2, src.offset);
        dst[6] := CHR(src.width);
        set_word(dst, 7, src.rseg);
END;

PROCEDURE GET_BSS(VAR src : STRING; VAR dst : DWORD);
BEGIN
        Inc(dst, get_dword(src, 1));
END;

PROCEDURE GET_EXPORT_REC(VAR src : STRING; VAR dst : REXP_REC);
VAR i : INTEGER;
BEGIN
        dst.next := NIL;
        dst.flags := ORD(src[1]);
        dst.seg := ORD(src[2]);
        dst.offset := get_dword(src, 3);
        i := 0;
        WHILE (i < SizeOf(RDFNAME)) AND (src[i + 7] <> #0) DO BEGIN
                Inc(i);
                dst.name[i] := src[i + 6];
        END;
        dst.name[0] := CHR(i);
END;

PROCEDURE GET_IMPORT_REC(VAR src : STRING; VAR dst : RIMP_REC);
VAR i : INTEGER;
BEGIN
        dst.next := NIL;
        dst.flags := ORD(src[1]);
        dst.seg := get_word(src, 2);
        i := 0;
        WHILE (i < SizeOf(RDFNAME)) AND (src[i + 4] <> #0) DO BEGIN
                Inc(i);
                dst.name[i] := src[i + 3];
        END;
        dst.name[0] := CHR(i);
END;

PROCEDURE SET_EXPORT_REC(VAR src : REXP_REC; VAR dst : STRING);
BEGIN
        dst[1] := CHR(src.flags);
        dst[2] := CHR(src.seg);
        set_dword(dst, 3, src.offset);
        dst[0] := #6;
        dst := dst + src.name + #0;
END;

PROCEDURE SET_IMPORT_REC(VAR src : RIMP_REC; VAR dst : STRING);
BEGIN
        dst[1] := CHR(src.flags);
        set_word(dst, 2, src.seg);
        dst[0] := #3;
        dst := dst + src.name + #0;
END;

PROCEDURE SET_BSS(src : DWORD; VAR dst : STRING);
BEGIN
        dst[0] := #4;
        set_dword(dst, 1, src);
END;

PROCEDURE GET_NAME_REC(VAR src : STRING; VAR dst : RNAME_REC);
VAR i, l : INTEGER;
BEGIN
        dst.name := src;
        l := Length(dst.name);
        i := 1;
        WHILE i <= l DO BEGIN
                IF dst.name[i] = #0 THEN BREAK;
                Inc(i);
        END;
        dst.name[0] := CHR(i - 1);
END;

PROCEDURE SET_NAME_REC(VAR src : RNAME_REC; VAR dst : STRING);
BEGIN
        dst := src.name + #0;
END;

PROCEDURE WRITE_SEG(VAR f : BFILE; segnum, segtype : WORD; seglen : DWORD);
BEGIN
        WriteWord(f, segtype);
        WriteWord(f, segnum);
        WriteWord(f, 0);
        WriteDWord(f, seglen);
END;

FUNCTION READ_SEG_REC(VAR f : BFILE; VAR dst : RDF_SEG) : BOOLEAN;
VAR     r : BOOLEAN;
BEGIN
        r := FALSE;
        IF NOT EOF(f) THEN BEGIN
                dst.segtype := ReadWord(f);
                dst.segnum := ReadWord(f);
                ReadWord(f);
                dst.seglen := ReadDWord(f);
                dst.file_offset := FilePos(f);
                r := dst.segtype <> 0;
        END;
        READ_SEG_REC := r;
END;

PROCEDURE WRITE_SEG_REC(VAR f : BFILE; VAR dst : RDF_SEG);
BEGIN
        WriteWord(f, dst.segtype);
        WriteWord(f, dst.segnum);
        WriteWord(f, 0);
        WriteDWord(f, dst.seglen);
END;

FUNCTION GET_FILE_TYPE(VAR f : BFILE) : RDF_FILE_TYPE;
VAR     r     : RDF_FILE_TYPE;
        sign1 : STRING[6];
BEGIN
        r := FILE_UNKNOWN;
        Seek(f, 0);
        BlockRead(f, sign1[1], 6);
        sign1[0] := #6;
        IF sign1 = RDOFF2_SIGN THEN BEGIN
                r := FILE_RDF;
        END ELSE IF sign1 = RLIB_SIGN THEN BEGIN
                Seek(f, 6);
                r := FILE_RDL;
        END;
        IF r IN [FILE_UNKNOWN,FILE_RDF] THEN Seek(f, 0);
        GET_FILE_TYPE := r;
END;

FUNCTION RDL_NEXT_MODULE(VAR f : BFILE; VAR modname : STRING) : BOOLEAN;
VAR     r : BOOLEAN;
        p : DWORD;
BEGIN
        r := FALSE;
        WHILE NOT EOF(f) DO BEGIN
                p := FilePos(f);
                BlockRead(f, modname[1], 255);
                modname[0] := #0;
                WHILE (modname[0] < #255) AND (modname[ORD(modname[0]) + 1] <> #0) DO Inc(modname[0]);
                Seek(f, p + ORD(modname[0]) + 1);
                IF modname[0] > #0 THEN
                        IF modname[1] <> '.' THEN BEGIN r := TRUE; BREAK; END;
                p := ReadDWord(f);
                Seek(f, FilePos(f) + p);
        END;
        RDL_NEXT_MODULE := r;
END;

PROCEDURE WRITE_RDF(VAR headers : BFILE; csegnum : WORD; VAR code : BFILE; dsegnum : WORD; VAR data : BFILE; VAR dst : BFILE);
VAR     p, p0 : DWORD;
BEGIN
        Seek(code, 0);
        Seek(data, 0);
        Seek(headers, 0);

        Write(dst, RDOFF2_SIGN);
        p := FilePos(dst);
        WriteDWord(dst, 0);

        IF IsOpen(headers) THEN BEGIN
                WriteDWord(dst, FileSize(headers));
                BlockCopy(headers, dst, FileSize(headers));
        END ELSE WriteDWord(dst, 0);

        IF IsOpen(code) THEN BEGIN
                WRITE_SEG(dst, csegnum, RDFCS, FileSize(code));
                BlockCopy(code, dst, FileSize(code));
        END;
        IF IsOpen(data) THEN BEGIN
                WRITE_SEG(dst, dsegnum, RDFDS, FileSize(data));
                BlockCopy(data, dst, FileSize(data));
        END;
        WRITE_SEG(dst, 0, 0, 0);

        p0 := FilePos(dst);
        Seek(dst, p);
        WriteDWord(dst, p0 - p - SizeOf(DWORD));

        Seek(dst, p0);
END;

PROCEDURE RDL_CREATE(VAR f : BFILE);
BEGIN
        IF IsOpen(f) THEN BEGIN
                Seek(f, 0);
                Write(f, RLIB_SIGN);
                Write(f, RLIB_MODNAME);
                WriteDWord(f, SizeOf(DWORD));
                WriteDWord(f, 0);
                Truncate(f);
        END;
END;

PROCEDURE RDL_APPEND_MODULE(VAR f : BFILE; VAR modname : STRING);
BEGIN
        IF IsOpen(f) THEN BEGIN
                Seek(f, FileSize(f));
                Write(f, modname + #0);
        END;
END;

END.