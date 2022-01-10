{ MIT License

Copyright (c) 2021 Viacheslav Komenda

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
UNIT utils;

INTERFACE

USES System2;

TYPE

PWORD  = ^WORD;
DWORD  = LONGINT;
PDWORD = ^DWORD;

FUNCTION atoi(s : STRING; default_val : INTEGER) : INTEGER;
FUNCTION itoa(w : LONGINT) : STRING;

PROCEDURE set_word(c : PCHAR; w : WORD);

FUNCTION get_word(c : PCHAR) : WORD;
FUNCTION get_dword(c : PCHAR) : DWORD;
FUNCTION get_str(c : PCHAR) : STRING;

FUNCTION strcmp(p1, p2 : PCHAR) : BOOLEAN;
FUNCTION strc2pas(p : PCHAR) : STRING;

PROCEDURE upstr(VAR s : STRING);

IMPLEMENTATION

FUNCTION itoa(w : LONGINT) : STRING;
VAR     s : STRING;
BEGIN
        str(w, s);
        itoa := s;
END;

FUNCTION atoi(s : STRING; default_val : INTEGER) : INTEGER;
VAR     res, err_pos : INTEGER;
BEGIN
        val(s, res, err_pos);
        IF err_pos <> 0 THEN res := default_val;
        atoi := res;
END;

FUNCTION get_word(c : PCHAR) : WORD;
BEGIN
        get_word := ORD(c[0]) OR (ORD(c[1]) SHL 8);
END;

FUNCTION get_dword(c : PCHAR) : DWORD;
BEGIN
        get_dword := ORD(c[0]) OR (ORD(c[1]) SHL 8) OR (ORD(c[2]) SHL 16) OR (ORD(c[3]) SHL 24);
END;

FUNCTION get_str(c : PCHAR) : STRING;
VAR     r : STRING;
BEGIN
        r := '';
        WHILE c[0] <> #0 DO BEGIN
                r := r + c[0];
                Inc(c);
        END;
        get_str := r;
END;

PROCEDURE set_word(c : PCHAR; w : WORD);
BEGIN
        c[0] := CHR(w and $FF);
        c[1] := CHR((w shr 8) and $FF);
END;

FUNCTION strcmp(p1, p2 : PCHAR) : BOOLEAN;
VAR     r : BOOLEAN;
BEGIN
        r := FALSE;
        WHILE p1[0] = p2[0] DO BEGIN
                IF p1[0] = #0 THEN BEGIN
                        r := TRUE;
                        BREAK;
                END;
                Inc(p1);
                Inc(p2);
        END;
        strcmp := r;
END;

FUNCTION strc2pas(p : PCHAR) : STRING;
VAR     r : STRING;
        i : INTEGER;
        c : CHAR;
BEGIN
        i := 0;
        WHILE i < 255 DO BEGIN
                c := p[0];
                IF c = #0 THEN BREAK;
                Inc(i);
                r[i] := c;
                Inc(p);
        END;
        r[0] := CHR(i);
        strc2pas := r;
END;

PROCEDURE upstr(VAR s : STRING);ASSEMBLER;
ASM
        push       ds
        push       es

        lds        si, s
        push       ds
        pop        es
        cld
        lodsb
        mov        cl, al
        or         cl, cl
        jz         @end
        mov        di, si
@cont:
        lodsb
        cmp        al, 'a'
        jl         @noconv
        cmp        al, 'z'
        jg         @noconv
        sub        al, $20
@noconv:
        stosb
        dec        cl
        jnz        @cont
@end:
        pop        es
        pop        ds
END;

END.
