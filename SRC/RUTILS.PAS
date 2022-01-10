UNIT RUtils;

INTERFACE

USES System2;

TYPE
DWORD = LONGINT;

RRELOC_REC = RECORD
        seg    : BYTE;
        offset : DWORD;
        width  : BYTE;
        rseg   : WORD;
        next   : POINTER;
END;

RIMP_REC = RECORD
        flags : BYTE;
        seg   : WORD;
        name  : STRING[64];
        next  : POINTER;
END;

REXP_REC = RECORD
        flags  : BYTE;
        seg    : BYTE;
        offset : DWORD;
        name   : STRING[64];
        next   : POINTER;
END;

PROCEDURE RDF_READ_REC(VAR f : BFILE; VAR rtype : CHAR; VAR rec : STRING);
PROCEDURE RDF_WRITE_REC(VAR f : BFILE; rtype : CHAR; VAR rec : STRING);

PROCEDURE GET_EXPORT_REC(VAR src : STRING; VAR dst : REXP_REC; caseSens : BOOLEAN);

PROCEDURE GET_IMPORT_REC(VAR src : STRING; VAR dst : RIMP_REC; caseSens : BOOLEAN);

PROCEDURE GET_RELOC_REC(VAR src : STRING; VAR dst : RRELOC_REC);
PROCEDURE SET_RELOC_REC(VAR src : RRELOC_REC; VAR dst : STRING);

PROCEDURE GET_BSS(VAR src : STRING; VAR dst : DWORD);

IMPLEMENTATION

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

PROCEDURE GET_EXPORT_REC(VAR src : STRING; VAR dst : REXP_REC; caseSens : BOOLEAN);
VAR i : INTEGER;
BEGIN
        dst.next := NIL;
        dst.flags := ORD(src[1]);
        dst.seg := ORD(src[2]);
        dst.offset := get_word(src, 3);
        i := 0;
        WHILE (i < 64) AND (src[i + 7] <> #0) DO BEGIN
                Inc(i);
                dst.name[i] := src[i + 6];
                IF NOT caseSens THEN dst.name[i] := UPCASE(dst.name[i]);
        END;
        dst.name[0] := CHR(i);
END;

PROCEDURE GET_IMPORT_REC(VAR src : STRING; VAR dst : RIMP_REC;  caseSens : BOOLEAN);
VAR i : INTEGER;
BEGIN
        dst.next := NIL;
        dst.flags := ORD(src[1]);
        dst.seg := get_word(src, 2);
        i := 0;
        WHILE (i < 64) AND (src[i + 4] <> #0) DO BEGIN
                Inc(i);
                dst.name[i] := src[i + 3];
                IF NOT caseSens THEN dst.name[i] := UPCASE(dst.name[i]);
        END;
        dst.name[0] := CHR(i);
END;

END.