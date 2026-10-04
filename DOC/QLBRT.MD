# QLB output of RLINK: what QuickBASIC 4.5 requires

This complements DOC\QLB.MD. Everything here was measured
against Microsoft QuickBASIC 4.50 (QB.EXE, 278804 bytes, see
TEST\QLB), not only read from the disassembly. The same
libraries also pass the tests with QuickBASIC 4.0 (QB.EXE,
230048 bytes). QBasic (QBASIC.EXE of MS-DOS 6.22) is a different
product, it has no /L option and does not load Quick Libraries.

See DOC\QLB-IMP.MD for what QuickBASIC provides to a library
(imports, names, thunks).

## File layout written by `rlink qlb`

```
MZ header + relocation table   header_par paragraphs (>= 40h)
+0                             2 bytes (zero)
+2                             code image: code segment of each
                               rdf, then the runtime, its hash
                               table and the name entries,
                               every segment paragraph aligned
data                           word 3360h, then the data tail
block                          QB header (CS:IP of the MZ header
                               points here)
```

Data tail (maps to offset 3360h of QB's data segment, the file
does not contain the bytes between, QB's own data is there):

```
+00h  b_ULVars (16 bytes): far pointers to the runtime
      dispatcher, stub, stub, word 0 at +0Ch, word 13h at
      +0Eh (QB checks both)
+10h  16 bytes scratch (BC_SAB)
...   data and bss of every rdf (bss is stored as zero
      bytes)
```

QB header block (offsets from the start of the block):

```
+00  EAh, far address of /entry, 02h, 6C75h, offset of CODE
     table, offset of DATA table
+0Ch 22 bytes: w0 = segment table offset, w1 = 0, w2 = code
     paragraphs, w3 = end of data (paragraphs), w4 = block
     size, w5 = w2, w6 = w7 = 0, w8 = w2, w9 = w10 = 0
     (w5..w7 and w8..w10 are the triples segment, size low,
     size high of the far data and the far BSS that the
     dispatcher of LINK libraries copies and clears; RLINK
     writes them empty)
CODE table     one entry {1, name, offset, segment} for every
               exported code symbol (none with /nonames), then
               word 0 (see below)
DATA table     b_ULVars (offset 3360h), the only entry (QB
               looks it up), then word 0
SEGMENT table  NULL, _DATA, BC_SAB, STACK, SYMBOL (flags 3);
               NULL has segment w2 (data base), _DATA and
               BC_SAB are in the data tail, STACK and SYMBOL
               are at w3 and last
name pool      NUL terminated names of the tables (b_ULVars
               and the segment names)
```

MZ header: e_ss = w3, e_sp = 0, minalloc = maxalloc = FFFFh,
size = header + w3*16 + block. The segment words of every table
entry, and the block words at +3, +14, +16, +18, +22, +28, have
MZ relocation entries (segment = w3, offset = offset in the
block). Values below w2 are relocated against the code image,
others against QB's data segment (minus w2).

QB checks while loading: the QB header (EAh, 6C75h, version byte
>= 2), the segment table (NULL has to be the data base, STACK
followed by SYMBOL and then the end of the table, BC_SAB must
exist), b_ULVars (word at +0Ch is 0, byte at +0Eh is 13h), and
the declared data size has to be bigger than QB's own data
(3380h is enough for QB 4.5).

## Names: CODE table, runtime hash table

QB does not resolve a CALL from the CODE table: it asks the
runtime of the library (selector 0Ah, see below) and calls the
address that comes back. Measured with QuickBASIC 4.50 and 4.0:
a library with an EMPTY CODE table (and without the b_ULSymSeg
entry in the DATA table), whose runtime keeps its own names and
hash table, loads and resolves CALL statements; making the
runtime's 0Ah answer fail makes QB 4.50 fail to resolve the
name. The CODE table is not needed by QB itself.

RLINK fills it, as Microsoft's LINK does: one entry for every
code symbol that the rdf files export, with the name in the
spelling of the source (QB upper-cases the names in memory).
Tools that read the table (Microsoft QLBDUMP) list the library.
Libraries with the table filled load and run in QuickBASIC 4.50
and 4.0 (tested with 3000 names, a symbol block of 45 KB).
`/nonames` leaves the table empty. If the table does not fit
into the 64 KB symbol block, RLINK leaves it empty and prints a
warning.

The runtime does not read the QB block (and not the variable of
QB at DS:00D3) when QB asks for a procedure: the names and the
hash table are kept in its own segment (see below).

### CDECL, case and the name string

What QB sends to the dispatcher (selector 0Ah), measured with a
logging runtime in QuickBASIC 4.50:

```
DECLARE SUB HELLO ()                 "HELLO"  DX = 0000h
DECLARE SUB HELLO CDECL ()           "HELLO"  DX = 0040h
DECLARE SUB HELLO CDECL ALIAS "x" () "x"      DX = 0000h
DECLARE SUB Hel.lo ()                "Hel.lo" DX = 0000h
```

The name is passed as written. `CDECL` only sets DX; the library
turns the flag into the underscore of the C symbol. Microsoft's
runtime does this (a library written by LINK /Q finds `_arbadd`
for `DECLARE FUNCTION arbadd CDECL`, and does not find it for a
plain `arbadd` or for `ALIAS "arbadd" CDECL`), and the runtime
of RLINK does the same: with DX not zero the hash starts after a
`_` and the compare skips the `_` of the stored name. The stored
names are upper case with their underscore (`_FOO`); the name of
the caller is folded to upper case, so the case of a declaration
does not matter (Microsoft's lookup ignores case as well: a
library with `_ArbAdd` binds `ARBADD CDECL` and `ALIAS
"_ARBADD"`).

CDECL routines are called with the C convention (measured):
arguments right to left, so the first argument is at `[bp+6]`;
by reference unless BYVAL is written; the routine ends with a
plain `retf` and the caller removes the arguments.

The name is a temporary string of QuickBASIC and the library has
to free it with the QuickBASIC service `B$STDALCTMP` (number 26,
BX = the descriptor, `call far [DS:00C2]` with DI = 26); the
runtime of RLINK does it before it returns, and skips the call
when the far pointer at DS:00C2 is 0:0 (a loader that is not
QuickBASIC may not provide it). Measured: the
services 26 and `B$STDALCALLTMP` (28) cure the hang, the
services 0, 2, 22, 24 (`B$STDALC`) and 40 do not. Microsoft's
GETPROC (listing: MSRT.LST of the QLB guides) copies the name
into a local string variable and frees that with `B$STDALC`. A
runtime that frees nothing leaks a string per lookup and
QuickBASIC hangs after about a dozen lookups (30 lookups of the
SUB `Say` of a program froze QB 4.50 and 4.0; with the string
freed 300 lookups are fine). QB looks up every SUB and FUNCTION
of the program, also those that the program defines itself; the
runtime answers 0:0.

## Imports

A module may `extern` the names of QuickBASIC: RLINK builds the
thunks and the data symbols itself. See DOC\QLB-IMP.MD section
9.

## Runtime (SRC\QBRT.ASM)

QB calls the library through b_ULVars[0] (far jump, CX =
selector, DS = QB data segment). Selectors 0 .. 6 have no
arguments (RETF), selectors 8 .. 10h have one word argument
(RETF 2). A wrong return hangs QuickBASIC.

```
00h Init  02h Term  04h DataRelease  06h AllocDataImage
08h CONERR  0Ch GetData  0Eh GetSeg
        -> forwarded to /entry
0Ah GETPROC     find a procedure by BASIC string descriptor,
                returns DX:AX (0 = not found)
10h GETCOMMON   returns AX = BX = DX = 0
```

Forwarding is a Pascal style far call of the entry-point
(`/entry`): the selector is pushed as a word parameter, the
procedure removes it (RETF 2), the selector is in CX too. A
procedure with nothing to do is just `retf 2`. The runtime keeps
its own copy of the selector and returns to QB with RETF or RETF
2.

Measured with a traced runtime (nasm -DTRACE): QB calls selector
0Ah once for each CALL (or SUB call) statement in the BASIC
source, before the program runs, not once for each execution of
the statement. A program with one CALL in a loop executed 5
times: 6 calls of the dispatcher (6, 10h, 0, 0Ah, 0, 2); five
CALL statements: 10 calls.

Procedures are found by hash code. RLINK generates the table and
appends it to the runtime (after its code, in the code segment
of the runtime): slots = power of two >= 2 * procedures (>= 4),
slot = {hash OR 8000h, offset of the name entry in the runtime
segment}, 0 = empty slot, open addressing with linear probing.
The name entries follow the slots: {offset, segment, upper-case
name, 0}; the segment word has an MZ relocation entry, the
loader turns it into the real segment. hash = h * 33 + c over
the upper-cased name, starting with h = 1505h (16 bit). The
runtime still compares the name, so a hash collision never
returns a wrong procedure. Exported are all symbols of the code
segments of the rdf files (the entry-point too). The runtime
asks for no memory of its own: htmask (+4) and the entry-point
far address (+0) are patched by the linker.
