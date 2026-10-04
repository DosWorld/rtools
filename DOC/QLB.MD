# The QuickBASIC QuickLibrary (`.QLB`) format

A reverse-engineering note on the container Microsoft QuickBASIC
(4.0 and 4.5) and BASIC PDS 7.1 (`QBX`) use for loadable user
libraries, on how such a library is loaded, and on how one is
built. (The `QBASIC.EXE` of MS-DOS does not load libraries: its
usage line has no `/L`, see section 15.)

Everything here was read off the shipped binaries and off
Microsoft's own dumper, which travels with QuickBASIC 4.5 as
`INC\EXAMPLES\QLBDUMP.BAS`. Where a measurement was possible it
was taken; where the file could not answer, the document says so
rather than guessing - and sec. 16, which loads a `.QLB` and
calls into it, is the part that was executed rather than read.

**Confidence is marked throughout**, because a
reverse-engineering document that does not say where its
certainty stops is worse than no document:

* *measured*
  - meaning: read out of the shipped files, reproducible with
    the reader in sec. 13
* *documented*
  - meaning: stated by Microsoft in a file that travels with the
    product
* *inferred*
  - meaning: follows from a measurement, but the step is mine
* **OPEN**
  - meaning: I could not settle it from the files; the evidence
    is given

Summary of what is known (details in the sections):

* QBasic does not load libraries; QuickBASIC 4.0, 4.5 and BASIC
  PDS 7.1 do (sections 1, 15).
* There are three tables: the segment table is the third
  (section 5).
* The 22 bytes after the QB header are explained (sections 4 and
  12). The data image is a continuation of QB's data segment
  (section 9.2); the two bytes at file `0x400` are a field, not
  filler (section 9.1).
* The magic is checked: the loader makes three header checks and
  then looks up five names (section 10).
* QB does not resolve a `CALL` from the name tables. It asks a
  dispatcher inside the library, which gives a library a
  start-up and shut-down interface (section 10.2).
* What a library takes from QB (its imports) is resolved at link
  time against `BQLB45.LIB` (section 10.3), and `LINK /Q` hides
  the names with prefix `B$`/`b$` (section 7).
* The byte-level spec (section 12) is what QuickBASIC accepts
  (libraries written by `RLINK`, see `TEST\QLB`); section 14
  lists what is still open.

More detail: `DOC\QLBRT.MD` (what `RLINK` writes),
`DOC\QLB-IMP.MD` (imports, names, thunks) and `MSRT.LST` of the
QLB guides (the runtime that `LINK /Q` embeds). Measured with
QuickBASIC 4.50 and 4.0.

---

## 1. What a `.QLB` is

A QuickLibrary is a **loadable library of compiled routines that
the QuickBASIC interpreter binds to at run time**. It is not a
program and it is not a DLL: it is an MZ image that QB loads
into its own address space, then resolves by *name* when a
program calls into it.

The user-visible purpose is the one the manual states: a `.QLB`
lets a QuickBASIC program call routines that were written and
compiled outside QuickBASIC - assembly language, or Microsoft C,
or `.OBJ` files - without producing an `.EXE`.

The library that ships this way in QuickBASIC 4.5 is `QB.QLB`,
which exposes six routines (`INTERRUPT`, `INTERRUPTX`,
`ABSOLUTE`, `INT86OLD`, `INT86XOLD`, `SetUEvent`) so that a
BASIC program can issue software interrupts and call absolute
addresses - which plain QuickBASIC cannot do.

The three QuickBASIC artifacts are easy to confuse, and
`PACKING.LST` describes each in one line (*documented*):

* `QB.LIB`
  - PACKING.LST says: "The stand-alone library containing
    support routines for DOS system calls"
  - what it is: an OMF library, linked into a `.EXE` with
    `BC.EXE`+`LINK.EXE`
* `QB.QLB`
  - PACKING.LST says: "The Quick library containing support
    routines for DOS system calls"
  - what it is: the same routines, in the loadable container
    described here
* `BQLB45.LIB`
  - PACKING.LST says: "The library of supporting routines that
    are used when creating Quick libraries"
  - what it is: the glue the QLB needs; linked into every QLB

So `QB.QLB` is `QB.LIB` **plus** `BQLB45.LIB`, run through `LINK
/Q` (sec. 11) - which the same file says in as many words,
describing one set of routines as available "in the QB.QLB Quick
library or in the QB.LIB stand-alone library".

---

## 2. The container

**Measured.** A `.QLB` is a perfectly ordinary DOS MZ executable
as far as the first 28 bytes go. `QB.QLB` (5822 bytes):

```
e_magic   = 4D5A  "MZ"
e_cblp    = 0465   e_cp = 0037   -> image = 18897 bytes
e_crlc    = 0143   (143 relocations)
e_cparhdr = 0040   -> header = 1024 bytes, image at 0x400
e_minalloc= FFFF   e_maxalloc = FFFF
e_ss      = 03DE   e_sp = 0000
e_ip      = 000D   e_cs = 00AC   -> entry at image 0x0ACD
e_lfarlc  = 001E   (relocation table at file 0x1E)
```

Two things about this header are worth stating plainly, because
both surprise:

**The file is shorter than the image it declares.** 5822 bytes
on disk against 18897 declared. The difference is BSS: the
library's data segment is mostly uninitialised, so the linker
needs no bytes for it. This is normal for an EXE too, but the
ratio here (a third) makes it obvious.

**`CS:IP` does not point at code.** It points at the
QuickLibrary's own header, which sits inside the image, after
the code and data. This is the single fact that makes a `.QLB` a
`.QLB`.

Two more fields to keep in mind, because sec. 9 comes back to
them: **`e_ss = 03DE`** is the same value 113 of the 143
relocation entries use as their frame, and **`e_minalloc =
e_maxalloc = FFFF`** is not what an ordinary EXE asks for - a
program that meant to run on its own would ask for zero extra
paragraphs and let the loader decide.

---

## 3. Finding the QB header

**Documented** by `QLBDUMP.BAS`, and **measured** to hold:

```
file offset of the QB header = (CParHdr + CS) * 16 + IP
QLBDUMP.BAS writes it as      (CParHdr + CS) * 16 + IP + 1
```

For `QB.QLB`: `(0x40 + 0xAC) * 16 + 0x0D` = **file offset
`0xECD`**, and the magic word is there. For the debug build
`DEBUG\D3\QB.QLB` it is `0x11CD`.

**The `+ 1` in `QLBDUMP.BAS` is not a displacement - it is the
0-based to 1-based conversion.** QuickBASIC's `GET #n, position,
var` and `SEEK` number bytes from 1, so the BASIC position of
file offset `0xECD` is `0xECE`. Read as a displacement the
sample looks like it lands one byte past the magic and would
print `Not a QB UserLibrary`; read as the conversion, it is
exactly right, which is one more independent confirmation of the
formula - this time from Microsoft's own code rather than from
the bytes.

In image-relative terms the header sits at `CS * 16 + IP` =
`0xACD` - but that number is relative to the base the MZ header
*declares* (`CParHdr * 16` = `0x400`), and the image really
begins at `0x402` (sec. 9.1), so the header's image offset is
`0xACB`. Nothing depends on the difference: the formula is a
file position, and both readings name the same byte.

---

## 4. The QB header

Twelve bytes. `QLBDUMP.BAS` declares all twelve (*documented*)
but gives the first six no meaning at all - it calls them
`QBHead AS STRING * 6`, "QB specific heading" - so the split
below is *documented* for the last six and *measured* for the
first six:

```
off  size  field     QB.QLB          what it is
---  ----  --------  --------------  ----------------------
 +0    5   entry     EA 10 00 7B 00  a far jump:
                                     EA <offset> <segment>
 +5    1   version    02             minimum version: QB
                                     refuses the library
                                     ("Invalid format") if
                                     below 2; QLBDUMP does
                                     not look at it
                                     (measured, LoadRtmInfo)
 +6    2   magic     75 6C (=6C75h)  "identifies file as a
                                     Quick library"
 +8    2   symStart  22 00 (=34)     offset from the QB
                                     header to the CODE
                                     symbol table
+10    2   datStart  D4 00 (=212)    offset from the QB
                                     header to the DATA
                                     symbol table
```

`QBHead` in `QLBDUMP.BAS` is declared `STRING * 6` and covers
`+0..+5`; the magic is the word at `+6`. Microsoft's comment on
the six bytes is only "QB specific heading", and `LINK /Q` fills
them with a far jump.

**The header is 34 bytes, not 12.** QB reads `0x22` bytes at
this position (section 10): the twelve above and eleven more
words. Written as they stand in the file (`w0`..`w10`):

```
+12 w0   offset, from the QB header, of the third table
         (the segment table, section 5)
+14 w1   0 in the file; relocated by the loader: the
         segment of the code image
+16 w2   size of the code image in paragraphs (in the
         file); relocated: QB's data segment
+18 w3   end of the data image in paragraphs, equal to
         e_ss (file); relocated: the segment where the
         data image ends, the base of the stack
+20 w4   size of the symbol block in bytes (the QB
         header, the tables and the names)
+22 w5   far data of the library, the segment (= w2 in
         the file; relocated: QB's data segment); read
         by the library's AllocDataImage and by its
         restore routine
+24 w6   low word and
+26 w7   high word of the size in bytes of the far data
         area (0 in all libraries)
+28 w8   far BSS of the library, the segment (= w2 in
         the file; relocated: QB's data segment); read
         by the library's Init routine, which clears
         the area
+30 w9   low word and
+32 w10  high word of the size in bytes of the far BSS
         area (0 in all libraries)
```

Words `w1`, `w2`, `w3`, `w5` and `w8` have entries in the
relocation table (the file value is a paragraph number that the
loader turns into a real segment, section 9.2); this is why the
file holds the sizes in the same words that hold the segments at
run time. `w0`, `w2`, `w3` and `w4` are used by QB's loader
(sections 9.2 and 10), `w1`, `w8`, `w9`, `w10` by the library
(`GETPROC` compares segments with `w1`, `AllocDataImage` and the
data restore use `w5`..`w7`, `Init` uses `w8`..`w10`: two
triples *segment, size low, size high*, section 10.2 and
`DOC\QLB-IMP.MD` section 8; measured, read from the code of the
dispatcher).

**Measured, and the neatest fact in the format: that jump lands
exactly on `_main`.** In `QB.QLB` the jump is `EA 10 00 7B 00` -
i.e. `jmp far 007B:0010` - and the symbol table's `_main` is
recorded at `007B:0010`. `__aulstart` is the same address. In
`DEBUG\D3\QB.QLB` the jump is `EA 10 00 95 00` and `_main` is at
`0095:0010`. So the entry stub is a jump to the C runtime
startup of the library: a `.QLB` is, at bottom, a small-model
Microsoft C program. *Inferred:* QB never executes this jump
(`_main` is `exit(1)`, and every library works); `RLINK` points
it at the entry-point routine of the library.

At `007B:0010` in `QB.QLB` sits `B8 01 4C CD 21 CB` - `mov
ax,4C01h / int 21h / retf`, the `exit(1)` thunk, at exactly the
address the symbol table records. The operand and the table
agree byte for byte, with no correction between them; they only
look two bytes apart if the entry jump is read against the base
the MZ header declares instead of the real one, which is sec.
9.1.

---

## 5. The symbol tables

Three tables of **8-byte entries**. The first two, described
here, are at `QHdrPos + symStart` (code) and `QHdrPos +
datStart` (data); the third, the segment table, is described at
the end of the section. Each is an array of entries terminated
by a zero `flags` word (*documented* for the layout, *measured*
for every field; the terminator is only that word, the next
table starts two bytes after the end of the previous one):

```
offset  size  field      what it is
------  ----  ---------  ----------------------------
  +0      2   flags      0001 = code   0002 = data
                         0005 = absolute
  +2      2   nameStart  offset FROM THE QB HEADER to
                         the symbol's name
  +4      2   offset     the symbol's offset within
                         its segment
  +6      2   segment    the symbol's segment
```

`QLBDUMP.BAS` declares this as `Flags`, `NameStart`, `other AS
STRING * 4` - it never looks at the last four bytes, but they
are the address: **`(offset, segment)`, in that order, the same
order the `EA` far jump uses.** Measured two ways:

* `_main` is recorded as `offset=0010 segment=007B`, and the far
  jump is `EA 10 00 7B 00` - byte for byte the same pair. (sec.
  4)
* `INT86OLD` is `0011:0004`, and image-relative that address
  lands on real code - see the table in sec. 9, which also shows
  how the segment half is used at call time (sec. 10.2) and why
  it cannot be flattened into an image offset.

`QB.QLB` has **22 code** and **68 data** entries;
`DEBUG\D3\QB.QLB` has 29 code and 69 data.

### The flags word

* `0001`
  - seen on: code symbols with a real segment (`007B`, `0095`,
    `0011`, `0023`)
  - reading: code
* `0002`
  - seen on: data symbols with a real segment (`00A6`, `00D6`)
  - reading: data
* `0005`
  - seen on: `FIARQQ`...`FJSRQQ`, `__acrtused`, `__fpmath`,
    `__fpsignal`, `__fptaskdata`, `__aDBdoswp` - **all with
    `segment = 0000`**
  - reading: absolute

The pattern that holds across both shipped files is *inferred*:
bit 0 marks code, bit 1 marks data, bit 2 marks an absolute
symbol. The three names in sec. 7 below, `ABSOLUTE` /
`INTERRUPT` / `INTERRUPTX`, are the exception that stops this
from being a rule - see sec. 9.

The `0005` group is worth naming, because it is not QuickBASIC
at all: `FIARQQ`, `FJARQQ`, `FICRQQ`, `FIDRQQ`, `FIERQQ`,
`FISRQQ`, `FIWRQQ`, `FJSRQQ` are the Microsoft C 5.x
**8087-emulator linkage symbols**, and `__acrtused` is the
classic MS C marker whose mere presence pulls in the C startup.

**For these, the `offset` field is not an offset - it is the
value**, and `segment = 0` is what says so. That is how
`__acrtused` reads as `9876h`, the value every MS C object
carries, and how `FJARQQ` / `FJSRQQ` / `FJCRQQ` read as `4000h`
/ `8000h` / `C000h`. Measured, all fourteen of them:

```
FISRQQ  0632   FIARQQ  FE32   __fptaskdata  0000
FJCRQQ  C000   FIWRQQ  A23D   FJARQQ        4000
__acrtused  9876   __fpmath  0000   FJSRQQ  8000
FICRQQ  0E32   FIERQQ  1632   __aDBdoswp  D6D6
FIDRQQ  5C32   __fpsignal  0000
```

### The third table: the segment table

The word `w0` of the 34-byte header (section 4) is the offset of
a third table, in the same entry format `{flags, nameOff,
offset, segment}`, that follows the DATA table and ends with a
zero word. It lists the segments of the library: the code
segments (`_TEXT`, `CODE`, `ABSOLUTE_TEXT`, `INTRPT_TEXT`,
`INT86OLD_TEXT` or the name of the segment of the user's
object), the segments of the data group (`FAR_DATA`, `FAR_BSS`,
`NULL`, `_DATA`, `CDATA`, `XIB`..`XCE`, `DBDATA`, `_BSS`,
`XOB`..`XOE`, `BC_SA`, `BC_SAB`), the near-heap markers
`NMALLOC` and `ENMALLOC` (the only entries with flags `4`, all
others have `3`) and, always last, `STACK` and `SYMBOL`. The
segment words are relocated like the segments of the other
tables.

QB's loader looks into it for exactly four names (section 10),
and a library is refused ("Invalid format") if these are missing
or in the wrong order: `NULL` has to be at QB's data segment
(its segment is the data base, `w2` in the file), the entry
after `NULL` has to lie high enough above it, `STACK` is
followed immediately by `SYMBOL`, and the table ends right after
`SYMBOL`; `BC_SAB` has to exist, its address is kept by QB.
Libraries with only the entries `NULL`, `_DATA`, `BC_SAB`,
`STACK` and `SYMBOL` are accepted by QB 4.0 and 4.5 (section
12).

---

## 6. The name pool

**Names do not live in the entries.** An entry carries only a
16-bit offset, and the name is a NUL-terminated string at
`QHdrPos + nameStart`. `QLBDUMP.BAS` reads it exactly that way
(`CurrentSym = QHdrPos + QlbSym.NameStart`, then `INPUT$(40)`).

**Measured.** In `QB.QLB` the first code symbol `_brkctl` has
`nameStart = 0x3F0`; `QHdrPos + 0x3F0` is file `0x12BD`, and the
bytes there are `_brkctl\0_execve\0` - the entries run in table
order and their names sit next to each other in the pool.

So the file's tail is:

```
[ code and initialised data ]  image 0x0000..
[ QB header ]                  0x0ACD
[ CODE table ]                 0x0AEF
[ DATA table ]                 0x0BA1
[ segment table ]              0x0DC3
[ name pool ]                  0x0EBD..
```

(positions counted from file offset `0x400`; the pool runs on to
the end of the file at `0x16BE`. The offset of the segment
table, section 5, is the word `w0` of the QB header, `0x2F6`
from the header in this file.)

with the pool running to the end of the file.

The pool is the text after the three tables, and QB's loader
walks over it and **upper-cases every name in memory** (`a`..`z`
only; the file keeps the case it was linked with). A name that
QB looks for is therefore compared in upper case: `B_ULVARS` for
`b_ULVars`.

---

## 7. What is exported - the API rule

**There are no ordinals.** The tables list the names and the
addresses of the symbols of the library, name to address. QB
does not resolve a `CALL` from the CODE table; it asks a routine
inside the library (selector `0Ah`, section 10.2), which may
keep the names anywhere. A library with an EMPTY CODE table
whose routine finds the names itself loads and works in
QuickBASIC 4.0 and 4.5. The tables are what Microsoft's tools
write and read, and what the rest of this section is about.

Microsoft's own dumper states the rule for telling the library's
API from its plumbing (*documented*, from `QLBDUMP.BAS`):

```basic
' Print only those names that do not begin with "__",
' "$", or "b$" as these names are usually considered
' reserved (the IF below is one line in QLBDUMP.BAS):
IF LEFT$(SName$, 2) <> "__" AND LEFT$(SName$, 1) <> "$"
   AND UCASE$(LEFT$(SName$, 2)) <> "B$" THEN
   PRINT #2, "  " + SName$
END IF
```

That filter is a heuristic and it leaks: it lets `_main`,
`_exit`, `_brkctl`, `_execve`, `_spawnve`, `_edata`, `_environ`,
`_errno` and the whole `F*QQ` set through, none of which is
QuickBASIC's API. The rule that actually identifies the API is
the one `QB.BI` states, by declaring it.

### The genuine API of `QB.QLB`

Six names (*measured*, and matching `QB.BI`):

| name | table | recorded address |
|---|---|---|
| `ABSOLUTE` | code | `0000:0000` (see sec. 9) |
| `INTERRUPT` | code | `0000:000C` (see sec. 9) |
| `INTERRUPTX` | code | `0000:0019` (see sec. 9) |
| `INT86OLD` | code | `0011:0004` |
| `INT86XOLD` | code | `0011:0011` |
| `SetUEvent` | code | `0023:0570` |

`QB.BI` (*documented*, it travels with QuickBASIC) declares five
of them and gives their signatures - `INTERRUPT(intnum, inreg AS
RegType, outreg AS RegType)`, `INTERRUPTX(intnum, inreg AS
RegTypeX, outreg AS RegTypeX)`, `ABSOLUTE(address)`, and the two
older array-based forms. `SetUEvent` is not in `QB.BI`.

The rest of `QB.QLB`'s non-reserved names are the C runtime and
the emulator linkage: `_main`, `_exit`, `_brkctl`, `_execve`,
`_spawnve`, `_end`, `_edata`, `_environ`, `_errno`, `b_errlin`,
`b_errmod`, `b_erradr`, `b_errnum`, `b_ULVars`, `b_ULSymSeg`,
`STKHQQ`, and the `F*QQ` set.

Two of those are not incidental - see sec. 10.

### The debug build exports more

`DEBUG\D3\QB.QLB` carries the QuickBASIC debugger's own library
on top of the same six: `DebOhex`, `DebAbort`, `DebHalt`,
`DebHaltID_STRINGS`, `DebOb`, `DebON`, `DebOszES` (all code,
segment `0023`) and `AssertSaveReg` (data). So a `.QLB` is a
general mechanism: the debugger is just another library loaded
the same way.

### Public and private names

Measured on the five `.QLB`/`.LIB` pairs that were available
(4.5, 4.5 debug, 4.0, PDS 7.1 and a library built from
`MYLIB.OBJ`), comparing the names in the tables with the public
symbols of the `.LIB` files (`QB.LIB` or `QBX.LIB`, and the
runtime library `BQLB45.LIB`, `BQLB40.LIB` or `QBXQLB.LIB`):

* Of the 90 names in `QB.QLB` (22 CODE and 68 DATA) only **5**
  come from `QB.LIB`: `ABSOLUTE`, `INT86OLD`, `INT86XOLD`,
  `INTERRUPT`, `INTERRUPTX`. 83 come from `BQLB45.LIB`, and 2
  (`_edata`, `_end`) are made by the linker. The runtime part is
  the same for every library: 8 modules of `BQLB45.LIB` that
  `LINK /Q` always includes, even for a library whose only
  routine is a `retf`.
* `LINK /Q` exports every public name of the modules it links
  **except names with the prefix `B$` or `b$`**: 96 public names
  of the included modules are left out for 4.5 (98 for the debug
  build, 82 for 4.0, 106 for PDS 7.1) and every one of them has
  that prefix; no exported name has it. They are the internal
  links of the library to the QB runtime (`B$ULInit`,
  `B$RUNERR`, `b$pULtoRTFar`, `b$errlin`, ...). The library also
  has twins with an underscore (`b_ULVars`, `b_errlin`) and
  those are exported.
* There is no flag for "private". `QLBDUMP.BAS` hides "__", "$"
  and "b$" by name (its own comment calls them reserved), and a
  BASIC identifier starts with a letter, so a name that starts
  with `_` or `$` cannot be called from BASIC anyway.

---

## 8. Worked example - the raw bytes of `QB.QLB`

```
file 0xECD   EA 10 00 7B 00 02 75 6C 22 00 D4 00
             QB header: entry, version, magic,
             symStart, datStart
file 0xEEF   01 00 F0 03 5E 00 7B 00   _brkctl
             CODE table, entry 1
file 0xEF7   01 00 F8 03 15 01 7B 00   _execve
...
file 0xF9F   00 00 ...       CODE terminator
file 0xFA1   05 00 ...       DATA table, FISRQQ
...
file 0x11C1  00 00 ...       DATA terminator
file 0x11C3  03 00 ...       segment table, ABSOLUTE_TEXT,
                             31 entries (section 5)
file 0x12BD  '_brkctl\0_execve\0...'   name pool
file 0x16BE  end of file
```

---

## 9. Address mapping - what is certain, and what is not

Code addresses turned out to be solid once one thing was right,
and that one thing was not what the header says: the image does
not begin where `CParHdr` puts it. Data addresses I could not
close. Both are set out precisely, so that nobody has to
rediscover either - and so that nobody trusts the data half
further than it goes.

**The header's own position is `CParHdr * 16 + CS * 16 + IP`**
and that formula is right: it lands on the magic, and the name
pool reached from there lands on the names. Two independent
confirmations, both in sec. 3 and sec. 6. It is a *file*
position, and reading it as the image base is what sec. 9.1
corrects.

**Certain: code symbols are image-relative, i.e. `image_offset =
segment * 16 + offset`, with no correction of any kind** - once
the image's real base is used, which is file `0x402` and *not*
the `CParHdr * 16` the MZ header declares (sec. 9.1 below is the
measurement). Measured on all 22 code entries of `QB.QLB`; these
are the seven that carry meaning, and for each the address
computed that way lands on a textbook routine:

* `ABSOLUTE`
  - recorded: `0000:0000`
  - -> image: `0x000`
  - the bytes there: `58 5A 5B 52 50 FF 36 C9 00 FF 37 CB`
  - read as: `pop ax / pop dx / pop bx / push dx / push ax /
    push [00C9] / push [bx] / retf`
* `INTERRUPT`
  - recorded: `0000:000C`
  - -> image: `0x00C`
  - the bytes there: `55 8B EC 83 C4 E2 C7 46 FA 08 00 EB 0B`
  - read as: `push bp / mov bp,sp / add sp,-30 / mov word
    [bp-6],8 / jmp +11`
* `INTERRUPTX`
  - recorded: `0000:0019`
  - -> image: `0x019`
  - the bytes there: `55 8B EC 83 C4 E2 C7 46 FA 0A 00 ...`
  - read as: the same prologue, with `0x0A`
* `INT86OLD`
  - recorded: `0011:0004`
  - -> image: `0x114`
  - the bytes there: `55 8B EC 83 C4 E0 C7 46 F8 08 00 ...`
  - read as: `push bp / mov bp,sp / add sp,-32 / mov word
    [bp-8],8`
* `INT86XOLD`
  - recorded: `0011:0011`
  - -> image: `0x121`
  - the bytes there: `55 8B EC 83 C4 E0 C7 46 F8 0A 00 ...`
  - read as: the same, with `0x0A`
* `SetUEvent`
  - recorded: `0023:0570`
  - -> image: `0x7A0`
  - the bytes there: `9A A8 01 23 00 CB`
  - read as: `call far 0023:01A8 / retf`
* `_main`
  - recorded: `007B:0010`
  - -> image: `0x7C0`
  - the bytes there: `B8 01 4C CD 21 CB`
  - read as: `mov ax,4C01h / int 21h / retf`

Read the bodies and they are exactly what the names promise:

* `ABSOLUTE` is a trampoline: it recovers the arguments, pushes
  the caller's address and far-returns to it.
  `ABSOLUTE(address)`.
* `INTERRUPT`, `INTERRUPTX`, `INT86OLD`, `INT86XOLD` are four C
  prologues, and the two pairs are byte-identical for their
  first nine bytes except for the size word each stores - 8
  words for the `INT86*` pair, 10 for the `INTERRUPT*` pair. The
  `jmp +11` at the end of the second prologue is what makes
  `INTERRUPTX` share the first one's body.
* `SetUEvent` is a two-instruction export thunk onto the real
  routine, which is the normal shape for a published entry
  point.
* `_main` is `exit(1)` - and the entry far jump of sec. 4 points
  straight at it.

Two footnotes for anyone disassembling this library:

* **A body is not always a prologue.** `__cexit`'s recorded
  address holds the single byte `CB` - a bare `retf`. That is
  not a misread; it is what a stub for a feature this
  configuration does not use looks like.
* **`__chkstk`, `__fptrap`, `__nullcheck`, `__fpreset` are not
  the routines MS C normally gives those names.** They are cells
  of a table of 4-byte entries, each `CD 3F` (`int 3Fh` -
  QuickBASIC's own far-pointer hook, which the interpreter
  traps) followed by a ModRM byte `2F`, `30`, `31`, `32`, `33`,
  `34`, `35`. The four names point at consecutive cells, so what
  follows each is an instruction the trap handler is meant to
  decode, not a compiled body. Do not read these against a stock
  Microsoft C runtime.

The pair of `push bp` prologues is worth reading with sec. 10.1
in hand: the routine's second half is reached by `push cs / push
00BE`, i.e. by an offset *inside its own segment*, which is why
the segment half of a symbol's address has to be honoured and
not merely turned into an image offset.

### 9.1 The image begins at file `0x402`, not at `CParHdr * 16`

The MZ header says `e_cparhdr = 0x40` (64 paragraphs, 1024
bytes), and the image begins two bytes later. **Every
address-bearing field in the file is measured from `0x402`**:
the symbol tables, the relocation table's entry addresses, the
far pointers stored in the code, and the immediates the code
pushes. Only the MZ header's own `cs:ip` agrees with `0x400`.

**The measurement** - the relocation table, on both shipped
`.QLB` files, read under both bases. A relocatable word must
hold a *segment* of the module (`0023`, `007B`, `03DE` ...).
Count how many entries point at a word that does:

```
                  entries whose target word is
                  a module segment
file          size   relocs   base 0x400   base 0x402
QB.QLB        5822     143    0 of 143     27 of 143
                      (20 x 0023, 7 x 007B)
DEBUG QB.QLB  6751     181    0 of 181     44 of 181
                      (the same two segments)
```

Under `0x400`, *not one* of the 324 entries across the two files
points at a segment value; under `0x402`, every entry that lands
inside the file does. (The ones that land nowhere - 116 of 143 -
are the DGROUP entries at segment `03DE`, which is past the end
of the file: the rest of the image is BSS, and `ss:sp` is in
there too.)

**The same thing seen three more ways**, all on `QB.QLB`:

* symbol `INT86OLD` = `0011:0004`
  - under `0x402`: image `0x114` = file `0x516` = `55 8B EC` -
    the prologue
* the entry far jump's operand `007B:0010`
  - under `0x402`: image `0x7C0` = `mov ax,4C01h / int 21h /
    retf`
* reloc entry `0023:006C`
  - under `0x402`: image `0x29C` - the *segment* half of the
    `jmp far 0023:0188` at image `0x299`

Under `0x400` each of the three is two bytes low, and the last
one lands on the far pointer's *offset* half - which is exactly
the failure mode sec. 10.1 reproduces with DOS's own overlay
load.

**The one field that disagrees.** `cs:ip` = `00AC:000D`, so
`(CParHdr + CS) * 16 + IP` = file `0xECD` - which is where the
QB header really is (that is the formula sec. 3 uses, and
`QLBDUMP.BAS` with it). It agrees with `0x400` because it is a
*file* offset, and the file is the same file; the two
conventions only diverge once something has to decide where the
module *starts* in memory. Nothing about the header's own
position is wrong.

**Why the file carries both conventions.** The two bytes at
`0x400` are `00 00`. They are not filler: `ULLoad` reads the
word at `e_cparhdr * 16` as the field `ULCodeSquishSize` (0 in
every library, section 9.2), and the code image follows it. So
the image starts at `e_cparhdr * 16 + 2` because something
precedes it, and nothing in the header counts it. The
operational rule is the same as before: **a `.QLB` loader seeks
to `0x402` and applies everything verbatim.** DOS's overlay call
cannot do that, it believes `e_cparhdr`, so it is not the way to
load a QuickLibrary, and section 10.1 has the dump.



**Measured, and consistent: the data segment `00A6` starts at
image `0xA60`**, where real initialised data sits - far pointers
into code segment `0023`, and the Microsoft C segment names
`XOB`, `XOE`, `XPB`, `XPE`, `XCB`, `XCE`, `XIB`, `XIE`,
`COMMON`.

### 9.2 Data image and symbol block

The contradiction came from a wrong model: that the declared
data image is a block of the file. It is not. The loader (read
in `dis/QLB-LOADER.md`, sections 6 to 8, and checked on the
libraries below) works with three regions of the declared image,
in paragraphs:

```
[0, w2)    the code image
           file: e_cparhdr*16 + 2 + paragraph*16 + offset
[w2, w3)   the data image
           declared size Z = (w3 - w2) * 16 bytes
[w3, ...)  the symbol block
           w4 bytes: the QB header, the three tables
           and the names
```

*The code image.* Its first two bytes are not code: the word at
`e_cparhdr * 16` is `ULCodeSquishSize` (`C`, 0 in every
library). This answers section 9.1: the image starts after it.

*The data image* is not loaded into a block of its own. QB makes
room at the end of **its own data segment** (it moves its
program image up by `Z` minus its own data end `b$pend`, and
refuses a library whose declared data is smaller: *Invalid
format*) and the library's data becomes the continuation of QB's
data. The data base `w2` *is* QB's data segment, and an offset
in the data image is an offset in that segment. The file holds
only two things of the data image: a word `D` at the data base
(file `(e_cparhdr + w2) * 16 + 2`) and, right after it, the
*tail* `T`, the initialised data. The tail goes to the **top**
of the declared range, at offset `X = Z - T`, and `D` is that
same offset (`D = X`). The bytes between offset 4 and `X` are
QB's own data: they are neither read from the file nor written,
and their number is the loader's `ULSquishSize`, `S = C + D -
4`. (*Inferred:* Microsoft's libraries have such a gap because
the C runtime of `BQLB45.LIB` puts its initialised data at the
top of its data group.)

*The symbol block* is read from the file position that its
declared position has, minus the gap: `e_cparhdr * 16 + w3 * 16
- S`. That is where the QB header is, and where `(e_cparhdr +
  e_cs) * 16 + e_ip` points. This answers the contradiction: the
  QB header and the tables are not inside the data image. They
  come after the tail in the file, and the two ranges only
  overlap because the gap is not in the file.

* QB 4.5 `QB.QLB`
  - `w2`: 00A6
  - `w3`: 03DE
  - `w4`: 07F1
  - `D = X`: 3317
  - tail `T`: 105
  - `Z`: 3380
  - `S`: 3313
  - symbol block in the file: 0ECD
* 4.5 `T0.QLB` (mylib)
  - `w2`: 0086
  - `w3`: 03BE
  - `w4`: 0787
  - `D = X`: 3317
  - tail `T`: 105
  - `Z`: 3380
  - `S`: 3313
  - symbol block in the file: 0CCD
* QB 4.0 `QB.QLB`
  - `w2`: 00A3
  - `w3`: 03D9
  - `w4`: 0647
  - `D = X`: 3317
  - tail `T`: 73
  - `Z`: 3360
  - `S`: 3313
  - symbol block in the file: 0E7D
* 4.5 debug `DEBUG-QB.QLB`
  - `w2`: 00D6
  - `w3`: 090E
  - `w4`: 0892
  - `D = X`: 8317
  - tail `T`: 105
  - `Z`: 8380
  - `S`: 8313
  - symbol block in the file: 11CD

In every row `e_cparhdr * 16 + w3 * 16 - S` is the file position
of the QB header, and the symbol block ends exactly at the end
of the file (QB header + `w4`).

*The relocations.* An entry is `(offset, segment)`; its location
is `segment * 16 + offset` in the declared image, so a segment
below `w2` is in the code image, from `w2` to below `w3` in the
data image, and `w3` is the symbol block itself. The loader adds
to the word at the location: a stored value **below `w2` is a
code paragraph and gets the segment of the code image; a value
from `w2` up is a data paragraph and gets QB's data segment
minus `w2`**. The 143 entries of `QB.QLB` are: 113 in the symbol
block (the segment word of every table entry and six words of
the header, section 4), 27 in the code image (segments `0023`
and `007B`) and 3 in the data tail (the far pointers of
`b_ULVars`, section 10.2). The entries of the segment `w3` patch
the symbol block; they are not far pointers in BSS.

*Where the data symbols are.* A data symbol below `X` (for
example `b_errlin` at `010C`) is a variable of QB.EXE itself at
its own offset in QB's data segment (section 10.3); a symbol at
`X` and above (for example `b_ULVars` at `3318`) is in the tail.

The model was checked by building libraries from it (section
12): QuickBASIC 4.0 and 4.5 load and run them.

`B$ULLoad` in `QB.EXE` was disassembled and read; the rule is
the plain MZ one:

```
address = (e_cparhdr + segment) * 16 + offset
```

with the segment taken **from the header block** rather than
assumed: `LoadRtmInfo` locates the QB header at `(e_cparhdr +
e_cs) * 16 + e_ip` and reads `0x22` bytes there, so DGROUP is
not segment `0000` and that is exactly why "segment 0" fitted
the code and contradicted the data. The whole loader - every
routine, every one of the 22 bytes, and what the eleven words of
that block actually hold - is `dis/QLB-LOADER.md`; the listings
are `dis/ULLOAD.ASM` and `dis/LOADRTM.ASM`.

### Settled: `segment = 0000` for three API names

The first three entries of sec. 7's table - `ABSOLUTE`,
`INTERRUPT`, `INTERRUPTX` at `0000:0000`, `0000:000C`,
`0000:0019` - look like the absolute `F*QQ` symbols, which also
carry `segment = 0`. They are not. **They are ordinary code
addresses into segment 0 of the image, which is the stub block
at image `0x000`**, and they obey the same rule as everything
else: image `0x000` is the `ABSOLUTE` trampoline, `0x00C` and
`0x019` are the two prologues.

They are byte-identical in both shipped `.QLB` files, which is
*expected* under that reading - LINK emits the same stub prefix
for both - and it is what misled my first pass into calling them
constants. The block is,

```
image 0x000  58 5A 5B 52 50 FF 36 C9 00 FF 37 CB
             ABSOLUTE, 12 bytes
image 0x00C  55 8B EC 83 C4 E2 C7 46 FA 08 00 EB 0B
             INTERRUPT, 13 bytes
image 0x019  55 8B EC 83 C4 E2 C7 46 FA 0A 00 ...
             INTERRUPTX
```

so `segment = 0` here means no more and no less than "the first
paragraph of the image", exactly as `007B` means image `0x7B0`.
The `jmp +11` at the end of `INTERRUPT`'s prologue lands on the
body `INTERRUPTX` shares; the same trick is in
`INT86OLD`/`INT86XOLD` at image `0x114`/`0x121`.

---

## 10. How a QuickLibrary is loaded

**Measured, from QuickBASIC's own symbol file** (`DEBUG\QB.SYM`,
the symbol table Microsoft shipped for `QB.EXE`). The QLB loader
is in there under names that give the mechanism away:

* `B$ULLoad`
  - reading: **U**ser **L**ibrary: load one
* `B$ULReload`, `B$ULInits`
  - reading: reload / initialise
* `B$ULSymSeg`, `B$ULSYMSEG`
  - reading: the segment the user library's symbols live in
* `QLBLIBNAME`, `QBLIBRESP`, `SZDOTQLB`, `SZDOTLIB`,
  `CHECKLIBNAME`
  - reading: the `"QB.QLB"` / `".QLB"` strings and the default
    names
* `BUFLIB`, `CB_BUFLIB`, `CB_BUFPATH`
  - reading: buffer and path for the library file

**"UL" is *User Library*** - the internal name for a `.QLB`.

### QB knows five names by heart

The neat part is on the other side, and it is measurable.
`QB.QLB` *exports* two data symbols to QB, **`b_ULVars` and
`b_ULSymSeg`** - and the string **`B_ULVARS`** (the exported
name, upper-cased) is a hard-coded literal inside every
interpreter, in its own name pool, with the length-and-offset
table entry that all its other internal names get (*measured*):

```
qbasic.exe        0x1B49
DISK2\QB.EXE      0x3BF6
DEBUG\D2\QB.EXE   0x6058
```

That is the hook, and it is not a guess: QB looks the name up in
the loaded library's DATA table, checks the structure it finds
there and keeps its address (section 10.2).

It is one of exactly **five** names QB looks for in a library.
The other four are in the segment table: `NULL`, `STACK`,
`SYMBOL` and `BC_SAB` (section 5). Searching `QB.EXE` 4.5
(release and debug), `QB.EXE` 4.0 and `QBX.EXE` 7.1 for all 146
distinct names in the tables of the five reference libraries
finds exactly these five as stand-alone strings. (The string
`NMALLOC` is also there, but it is a segment name in QB's own
debug symbols.) So QB takes nothing else from a library by name.

`QB.SYM` carries the whole QB-side machinery, and the names say
what it does (*measured*):

* `B$ULLoad`, `B$ULReloadl`, `B$ULInits`, `B$ULTerm`
  - what it says: load, reload, initialise, tear down
* `B$ULAllocDataImage`, `B$ULDataRelease`
  - what it says: QB's stubs for two routines *of the library*
    (selectors `06` and `04`, section 10.2)
* `b$ULDataLength`, `b$ULDataStart`
  - what it says: variables that QB sets when it loads the
    library (section 10.3)
* `B$ULSYMSEG`, `B$ULGetSeg`, `B_ULSYMSEG`
  - what it says: the segment the library's symbols ended up in
* `B$ULGetData`, `B$ULGetProc`, `B$ULGETCOMMON`, `B$ULGETPROC`,
  `B$ULtoRTFar`, `B$ULtoRTNear`
  - what it says: resolving a library name to a callable address
* `B_ULNAMELEN`, `b$ULNameLena`
  - what it says: the length of the literal name - i.e. the
    `B_ULVARS` pool entry above

`B$ULAllocDataImage` and its relatives are QB's end of the
dispatcher interface (section 10.2). The data image is not
allocated at an address chosen at load time: its address is the
offset `X` in QB's data segment that the library declares
(section 9.2).

### The header checks

`LoadRtmInfo` reads the 34 bytes of the header and makes three
checks, and all three are in the code of QuickBASIC 4.5 (release
and debug) and 4.0, as `cmp byte [..],0EAh / jne / cmp word
[..],6C75h / jne`, followed by the version test (the immediate
`75 6C` is at file offset `0x3FC6` in the release `QB.EXE` 4.5,
at `0x64A5` in the debug build and at `0x2E88` in 4.0):

1. the byte at `+0` is `EAh`,
2. the word at `+6` is `6C75h`,
3. the byte at `+5` is at least `2`.

A library that fails one of them is refused with *Invalid
format* (measured: libraries with the magic or the first bytes
broken are refused). The magic identifies the file to tools and
is checked by QB as well.

### The load sequence

From the loader (`dis/QLB-LOADER.md`, `dis/ULLOAD.ASM`) and from
libraries that QuickBASIC accepted or refused. Every refusal is
*Invalid format* unless another message is named.

1. `OpenRtmFile` opens the file; `LoadRtmInfo` reads the 28
   bytes of the MZ header, checks `MZ`, locates the QB header at
   `(e_cparhdr + e_cs) * 16 + e_ip` and reads its 34 bytes with
   the three checks of the previous section.
2. `ULLoad` reads the word `C` at `e_cparhdr * 16`
   (`ULCodeSquishSize`) and the word `D` at `(e_cparhdr + w2) *
   16 + 2`; the squish size is `S = C + D - 4`.
3. `LoadULData`: the declared data size `Z = (w3 - w2) * 16`
   must fit in QB's free memory (*Out of memory*) and must not
   be smaller than QB's own data end `b$pend` (measured:
   libraries with `Z` = `0400h` and `1000h` are refused, `3380h`
   is accepted). QB moves its program image up to make room, and
   `ReloadULData` reads the tail into the top of the range
   (section 9.2).
4. `LoadULSymbols` allocates `w4` bytes, reads the symbol block
   from file position `e_cparhdr * 16 + w3 * 16 - S`, walks the
   table at `w0` to its end and upper-cases the names behind it.
5. `LoadULCode` allocates `w2` paragraphs, zeroes the first `C`
   bytes and reads the code image from `e_cparhdr * 16 + 2`.
6. The relocation table is applied (section 9.2).
7. The file is closed, and `B$ULLoad` looks up the names it
   knows: `NULL`, `STACK`, `SYMBOL` and `BC_SAB` in the segment
   table (section 5) and `B_ULVARS` in the DATA table, where it
   checks the structure: the word at `+0Ch` is 0 and the byte at
   `+0Eh` is `13h` (section 10.2).
8. QB stores four words in its own data (section 10.3) and from
   then on calls the library through `b_ULVars` (section 10.2).

**Practical consequence for a reader of the format:** a `.QLB`
can be loaded from outside QB the way `qlbcall.asm` does
(section 16): seek to `0x402`, apply the relocations, use the
tables as a directory. That is the "load" half. Calling the
routines of a library from BASIC needs the other half, the
dispatcher of section 10.2.

### 10.1 DOS's overlay call is the wrong tool, measured

`INT 21h AH=4Bh AL=03h` is the service that is *supposed* to
load an overlay: the parameter block is four bytes, `{load
segment, relocation factor}`, no PSP is created, and each
relocation entry is applied as `word += load + factor`. It
cannot load a `.QLB`, and the reason is sec. 9.1: DOS takes
`e_cparhdr` at its word and puts file `0x400` at `loadseg:0`, so
the module sits two bytes low and **every entry of the
relocation table lands on the word before the one it names**.

`samples/qlbcall.asm` runs the experiment on identical file
bytes and prints the three words around a far pointer stored in
the code, `jmp far 0023:0188` at image `0x299` (its offset half
at `0x29A`, its segment half at `0x29C`, which is the address
the reloc table names):

```
                       the three words at the same
                       three file bytes
DOS, AH=4Bh AL=03h     EAEC  0C25  0023
                       <- 0x0188 + 0x0A9D, the load segment
DOS, factor 0          EAEC  0188  0023
                       (the control: nothing patched)
our own loader, 0x402  EAEC  0188  0AC0
                       <- 0x0023 + 0x0A9D
```

The middle line is the same bytes with the relocation switched
off, so the two DOS lines differ by exactly the load segment,
and it is the *offset* word that moved. A far pointer wants its
segment relocated and never its offset, so what DOS produced
there is a pointer into the same paragraph as before at a
nonsense offset. Ours differs from the control in the third
word, which is where the `0023` was.

The same run loads the library a second time by hand - seek to
`0x402`, read `CParHdr*16 + 2` bytes' worth of image, walk
`e_lfarlc`/`e_crlc` and add the load segment to each word the
table names - and finds that everything is then verbatim: the
prologue `55 8B EC` sits at image `0x114`, exactly the offset
the symbol table records for `INT86OLD`, with no correction
anywhere.

Two more differences worth knowing, both measured on the same
run:

* **The block has to be the *declared* image size.** `QB.QLB`'s
  MZ header declares 18897 bytes (`minalloc = maxalloc =
  0xFFFF`, and `e_cblp`/`e_cp` give the file part) while the
  file holds 4798 of them: the rest is BSS, and the library's
  own `ss:sp` (`0x3DE`) is inside it. Allocating the file's size
  and loading into that is what a `.QLB` reader must not do.
* **`ss:sp` and `minalloc` are not for the caller to honour.**
  The image is data in a block the caller owns; the library's
  stack pointer is its own business. DOS's overlay load ignores
  the block's memory anyway.

### 10.2 Calling into a loaded library

Measured by far-calling `INT86OLD` in the loaded `QB.QLB` and
printing what comes back (`samples/qlbcall.asm`, driven to run
`INT 21h, AH=02h, DL='Q'`):

**The segment half of an export's address is load-bearing.** The
obvious thing to do with a symbol recorded as `0011:0004` is to
turn it into the image offset `0x114` = `0x11 * 16 + 4` and call
it as `loadseg:0114`. That call *enters* the routine correctly
and then goes wrong inside it, because `INT86OLD` reaches its
own second half with

```
image 0x18A  0E        push cs
image 0x18B  B8 BE 00  mov ax,0x00BE
image 0x18E  50        push ax
```

and `0x00BE` is an offset *inside segment `0011`*, i.e. image
`0x1CE`. Entered with `CS = loadseg + 0`, that far return lands
on image `0xBE` - which is a real routine's real second half,
just the wrong one (`INTERRUPT`'s, whose capture stub sits at
the same offset in *its* segment). The failure is silent and
looks like a hang: the interrupt runs, prints its `Q`, and then
unwinds a frame that was never pushed. **Call an export as `CS =
loadseg + segment`, `IP = offset`.**

**The calling convention**, exactly as `QB.BI` declares it:

```
DECLARE SUB INT86OLD (intnum AS INTEGER,
                      inarray(1) AS INTEGER,
                      outarray(1) AS INTEGER)
```

* three near pointers in the *caller's* segment, pushed left to
  right, so at entry `[bp+6]` = `outarray`, `[bp+8]` =
  `inarray`, `[bp+0Ah]` = `intnum`;
* each array is a near pointer to a 4-byte **far** pointer to
  the data - the library's own dereference is image `0x22C`,
  `mov dx,[si+2] / mov ax,[si] / ret`;
* `intnum` is a near pointer to a word. A number above 255 (high
  byte non-zero) is rejected at image `0x217`: the routine
  writes `0xFFFF` through that pointer and returns without doing
  anything;
* the in-array is eight words - `ax, bx, cx, dx, bp, si, di,
  flags` (`RegType`) - and the out-array is the same eight for
  `INT86OLD`, ten for `INT86XOLD`, which adds `ds` and `es`
  (`RegTypeX`);
* the arguments are discarded by the routine's own `retf 6`, so
  a caller needs nothing after the call but a stack of its own
  to return on.

**What the in-array's `bp` field is:** the register value the
*simulated* code sees. It is not a frame, it needs no particular
value, and 0 will do.

**What happens to the stack:** nothing is switched and nothing
is saved. The routine takes a frame of its own (`push bp / mov
bp,sp / add sp,-20h`), assembles the `CD nn` instruction in the
twenty bytes below that frame, far-returns into it, and after
the interrupt a `retf 6` planted on the same stack returns to a
capture stub *inside the library*, which finds the routine's own
frame again through the BP it pushed before the interrupt. So
the interrupt executes on the caller's own stack, some 50 bytes
below the routine's frame - a red zone, and that is the caller's
only obligation: **the 56 bytes of stack the whole sequence
reaches below the call** must be free. The routine then unwinds
with `mov sp,bp / pop bp / retf 6`, which leaves `SS:SP` exactly
where it was.

**The one quirk in the results:** the out-array's `bp` word is
filled with the routine's frame address rather than with the
simulated BP - every other word is what the interrupt left,
including a `flags` word masked with `0x0FD5` before the `int`.
Measured: asked for `ax = 0200h, dx = 0051h, flags = 0202h` on
`INT 21h`, the array comes back `ax = 0251h` (AH consumed by the
DOS function), `dx = 0051h`, `flags = 0202h`.

**Initialisation, finalisation and the dispatcher.** `b_ULVars`,
found by name in the DATA table, is a 16-byte structure in the
data of the library: three far pointers (`+0`, `+4`, `+8`), the
word 0 at `+0Ch` and the word `13h` at `+0Eh`. QB keeps its
address in `b$pULVars` and **calls the library through the first
far pointer**: every `B$UL...` routine of QB (nine stubs at
`25D4:2B6B` in the debug build) loads a selector into `CX` and
jumps through it. In the libraries made by LINK the pointer is
`B$RTtoULFar` of `BQLB45.LIB` (`ultort.asm`), which dispatches
on `CX` through a table of near pointers.

* `00`
  - role: Init
  - routine in `BQLB45.LIB`: `B$ULInit` (`ulutil.asm` +013D)
* `02`
  - role: Term
  - routine in `BQLB45.LIB`: `B$ULTerm` (+0131)
* `04`
  - role: DataRelease
  - routine in `BQLB45.LIB`: `B$ULDataRelease` (+0313)
* `06`
  - role: AllocDataImage
  - routine in `BQLB45.LIB`: `B$ULAllocDataImage` (+02A5)
* `08`
  - role: CONERR
  - routine in `BQLB45.LIB`: `B$CONERR` (`erbcproc.asm` +0000)
* `0A`
  - role: GETPROC: find a procedure by name
  - routine in `BQLB45.LIB`: `B$ULGetProc` (+0059)
* `0C`
  - role: GetData
  - routine in `BQLB45.LIB`: `B$ULGetData` (+00CE)
* `0E`
  - role: GetSeg
  - routine in `BQLB45.LIB`: `B$ULGetSeg` (+00D1)
* `10`
  - role: GETCOMMON
  - routine in `BQLB45.LIB`: `B$ULGetCommon` (+0000)

(The table of the library, 9 near pointers at `cs:00EA` in
`T0.QLB`, holds these routines; the offsets differ from the
public offsets by the same `0220h` for all eight of
`ulutil.asm`.) Selectors from `08` up are called with **one word
of arguments and must end with `RETF 2`**; `00` to `06` end with
`RETF`. A routine that gets this wrong hangs QuickBASIC.

The order of the calls was measured with a logging dispatcher in
QuickBASIC 4.5 and 4.0: `06`, `10`, `00`, then **one `0A` for
every `CALL` or SUB-call statement in the BASIC source** (before
the program runs: a `CALL` in a loop executed five times causes
one `0A`, five `CALL` statements five), then `00` and, at the
end, `02`. `GETPROC` gets a near pointer to the BASIC string
descriptor `{length, pointer}` of the name, exactly as written
in the source (case kept, a dot kept, no prefix, no second try);
it returns the far address in `DX:AX`, `0:0` when the name is
unknown, and then QB stops with an error. After that QB calls
the routine directly, without the dispatcher. So a library does
have a start-up and a shut-down interface; the Microsoft runtime
clears its BSS and sets the pointers of its heap there, and a
library that needs nothing can answer with `retf`. QB's entry
far jump (`_main`) is never executed.

**Unloading:** DOS has no "unload overlay" service, because
`AL=03h` never had a counterpart - the load went into memory the
caller already owned. The caller releases it with `AH=49h`, and
since the image is pure data in that block there is nothing to
finalise first. What the caller *must* not do is free it while a
return address or a callback into it is still live; `SetUEvent`
and the `__chkstk`/`__fptrap` cells of sec. 9 exist precisely
because such callbacks are how a QuickLibrary is normally used.


### 10.3 Variables of QB and calls into QB (the imports)

More in `DOC\QLB-IMP.MD`. A `.QLB` has **no import records**.
What a library takes from QuickBASIC it takes by fixed addresses
and numbers, which `LINK /Q` fixes against the runtime library
`BQLB45.LIB`, the import library:

* **Variables of QB.** The DATA table entries with small offsets
  (below `0120h`) are variables of QB.EXE itself: all 46 of
  `DEBUG-QB.QLB` have exactly the address of the variable of the
  same name in the map of QB (`QB.MAP`, data segment `5517`).
  The code of a library addresses such a variable as its offset
  (a constant, `010Ch` for `b_errlin`) and the data base
  paragraph `w2` as segment, a relocated word. QB writes four
  words of this kind when it loads the library: `b$ULSymSeg`
  (`00D3`, the segment of the symbol block), `b$ULDataLength`
  (`00D5`), `b$ULDataStart` (`00D7`) and `b$pBC_SAB` (`00B8`,
  from the entry `BC_SAB`).
* **Procedures of QB.** QB keeps two far pointers in its data,
  `b$pULtoRTFar` (`DS:00BE`) and `b$pULtoRTNear` (`DS:00C2`), 4
  bytes each, filled by QB. For every routine of QB that it
  needs the library has a thunk in `ultort.asm` (`B$RUNERR`,
  `B$STDALC`, `B$ERR_OV`, ...; 38 of them in `BQLB45.LIB`) that
  puts a **number** in `DI` or `BX` and goes through the
  pointer. No name is passed. The numbers are the BASIC error
  codes for the `B$ERR_*` thunks, `0, 2 .. 42` for 22 services
  and `0, 4 .. 20` for six more (`B$ULReload`, `B$IStop`,
  `B$END`, `B$GetNmalloc`, `B$IEND`, `B$SetUEvent`).
* **Nothing else is imported.** A name that no module defines is
  an `L2029` link error, and LINK still writes the file, with
  `9A 00 00 00 00` (a call to `0000:0000`) and no relocation,
  and no entry in the tables.

---

### 10.4 How QB asks for a name: CDECL, ALIAS, dots

The name goes to selector `0Ah` as written in the source, and DX
tells how it was declared (logging dispatcher, QB 4.50):

```
DECLARE SUB HELLO ()                 "HELLO"  DX = 0000h
DECLARE SUB HELLO CDECL ()           "HELLO"  DX = 0040h
DECLARE SUB HELLO CDECL ALIAS "x" () "x"      DX = 0000h
DECLARE SUB Hel.lo ()                "Hel.lo" DX = 0000h
```

Microsoft's GETPROC (BQLB45.LIB), measured with libraries
written by LINK /Q:

1. DX not zero: the name becomes `_` + name, every dot becomes
   `_`. So `DECLARE FUNCTION foo CDECL` finds the C symbol
   `_foo` (`QB.QLB`: `main CDECL` finds `_main`); a plain `foo`
   does not find `_foo`, and `ALIAS "foo" CDECL` looks for
   `foo`.
2. The CODE table is searched, then the DATA table (an export
   placed in a far data segment, entry type 2, binds). The
   compare ignores case, the type word of the entry is not
   looked at (`FFFFh` binds), and the name stored in the library
   keeps the case of the object (`_ArbAdd` binds `ARBADD
   CDECL`).
3. A name that is renamed in the directory is not found.

A dispatcher that answers selector 0Ah by itself (with the far
address) binds; the directory is not needed then. The name is a
temporary string of QuickBASIC and the library has to free it
with the service B$STDALCTMP (number 26, BX = the descriptor;
B$STDALCALLTMP, 28, works too, the services 0, 2, 22, 24 and 40
do not); Microsoft's GETPROC copies the name into a local string
variable and frees that with B$STDALC (listing MSRT.LST in the
QLB guides). A dispatcher that frees nothing leaks one string
per lookup and QB hangs after about a dozen lookups (30 lookups
of one unknown name froze QB 4.50 and 4.0). QB looks up every
SUB and FUNCTION of the program, also the ones that the program
defines itself.

The routine of a CDECL declaration is called with the C
convention: arguments pushed right to left (the first argument
is at `[bp+6]` after `push bp / mov bp,sp`), by reference unless
`BYVAL` is written, the routine ends with `retf` and the caller
removes the arguments (measured). BASIC keywords (`EXIT`, `OFF`)
as the name of a routine or a parameter hang the editor.

## 11. How a QuickLibrary is generated

**Documented, and - unusually for this document - also
measurable, because `QB.EXE` builds the command itself.**
QuickBASIC's IDE can create a QuickLibrary from a menu, so the
pieces of the `LINK` command line are sitting in `QB.EXE` as
string fragments (*measured*, `DISK2\QB.EXE` at `0x426CC`):

```
.LIB\0 .QLB\0 BC \0 LIB \0 LINK \0 /AH\0 /MBF\0 /T\0
/QU \0 /NOE \0 /NOD:\0 /EX \0 +\0
,NUL,\0  BQLB45.LIB\0  BCOM45.LIB\0  BRUN45.LIB\0
@~QBLNK.TMP\0  @~QBLIB.TMP\0
```

Every field of the recipe below is in that list: `LINK`, the `+`
that joins libraries, **`,NUL,`** - the empty map-file field of
a LINK command line, which is the `,NUL,` in the form below -
the `/Q` family of switches, `BQLB45.LIB` as the companion
library, and `~QBLNK.TMP` / `~QBLIB.TMP` as the link response
file and the output the IDE then renames.

The recipe, **measured by running it**:

```
LINK /Q <yourlib>.LIB,<yourlib>.QLB,NUL,BQLB45.LIB;
```

`QB.QLB` is exactly this operation with `QB.LIB` in place of
`<yourlib>`:

```
LINK /Q QB.LIB,QB.QLB,NUL,BQLB45.LIB;
```

Run from a directory holding `LINK.EXE` (`DISK3\LINK.EXE`, 69133
bytes), `QB.LIB` and `BQLB45.LIB`, that command reproduces the
shipped library **byte for byte** - 5822 bytes, md5
`dd2bde6ded14f6b2b6f9c89087ce95a2`, the same bytes
`DISK3\QB.QLB` holds. The debug build reproduces the same way
with `DEBUG\D3\BQLB45.LIB` (26849 bytes) in the last field: 6751
bytes, md5 `3c535f3910481503cd2c913bfbd34e6a`, identical to
`DEBUG\D3\QB.QLB`. The linker is `Microsoft (R) Overlay Linker
Version 3.69`. The container is therefore not merely readable
but *deterministic*: two shipped files, two exact rebuilds, and
sec. 12's byte spec is what the rebuilder followed.

**Do not write `BQLB45.LIB` as an input** (measured). Writing
the input as `QB.LIB+BQLB45.LIB` links but does not finish:

```
BQLB45.LIB(..\crt\freect.asm) : error L2029 :
    '__asegds' : unresolved external
BQLB45.LIB(..\crt\freect.asm) : error L2029 :
    '__nmalloc' : unresolved external
```

and writes a 7539-byte `.QLB` holding 38 symbols instead of 31.
Naming `BQLB45.LIB` as an *input* drags its `freect` module into
the image; naming it only as the last field - where LINK reads
it purely to resolve the image's own references - pulls in only
the modules the image actually needs. `/NOE`, `/NOD:` and the
two together change nothing (all four write the same 7539-byte
file, md5 `57f27c90091392a259e66ae5bf5770d8`), and swapping the
two inputs' order gives a different 7539-byte file
(`8700b732dbb48842eb58ff1a635a26c7`). The correct form is the
one that reproduces the shipped bytes.

The fragment list above is what makes the command line
*documented* as well as measured: the `,NUL,` field, the `+`,
the `LINK` verb and the `BQLB45.LIB` operand are the strings
`QB.EXE` builds its own command from. The `+` is how the IDE
joins *a user's own* libraries; it is not the form that produced
the shipped `QB.QLB`.

The run is kept in the QBCALL store: `C:\dev\QBCALL\linkq\`
holds `LINK.EXE`, `QB.LIB`, `BQLB45.LIB`, `DBQLB45.LIB` (the
debug one), the batches that ran the seven link attempts and
their logs - including the wrong-recipe output, kept as the
counter-example.

The *inputs* are measurable as they stand - `QB.LIB` (2075
bytes, an OMF library holding `ABSOLUTE`, `INTERRUPT`,
`INTERRUPTX`, `INT86OLD`, `INT86XOLD`) and `BQLB45.LIB` (24789
bytes, holding `_main`, `SetUEvent` and the C runtime). Both are
OMF: they begin with the `F0` library signature and contain the
same names as ASCII, not MZ.

And the *outputs* agree, name by name - the split between the
two inputs is exactly the split the `.QLB` shows (*measured*):

* `QB.LIB` (2075 bytes)
  - what `QB.QLB` gets from it: the five API routines:
    `ABSOLUTE`, `INTERRUPT`, `INTERRUPTX`, `INT86OLD`,
    `INT86XOLD`
* `BQLB45.LIB` (24789 bytes)
  - what `QB.QLB` gets from it: everything else: `SetUEvent`,
    `_main`, and the C runtime - `_brkctl`, `_exit`, `__cexit`,
    `__chkstk`, `__BRUNERR`, `_environ`, `STKHQQ`, `b_ULVars`,
    `b_ULSymSeg` ...

Both are OMF libraries, not MZ images: each begins with the byte
`F0`, the OMF library signature. So `QB.QLB` is a straight
relink of two ordinary object libraries into the QuickLibrary
container - which is precisely what `LINK /Q` is for.

**What `LINK /Q` adds, hides and refuses** (measured, LINK
3.69). It always links the 8 modules of the runtime library that
make the same 83 names (section 7), even for a routine of one
byte. It exports every public name except the prefix `B$`/`b$`
(section 7). A module that refers to a name of the runtime
library (`B$RUNERR`, `b$errlin`) is resolved against it and
nothing is added to the tables (section 10.3). A name that
nobody defines gives `L2029 : unresolved external` and the
`.QLB` is written anyway. A `.LIB` made by `LIB.EXE` from the
same object gives a byte-identical `.QLB`. The Microsoft
Knowledge Base (articles Q27993, Q31156, Q35966) says that
`.QLB` files cannot be linked together or changed, only rebuilt
from the `.LIB` files, and names the runtime library by version:
`BQLB40.LIB` for 4.00, `BQLB41.LIB` for 4.00b, `BQLB45.LIB` for
4.50.

**A note on the distribution copies.** The CD-ROM tree (`COGS`)
holds the same file as `DISK3\QB.QL$` - 4567 bytes, no `MZ` at
the front but the signature `53 5A 20` = `"SZ "` (*measured*).
That is Microsoft's SETUP compression: in that tree the last
letter of every extension is replaced by `$` - `QB.EXE` ->
`QB.EX$`, `LINK.EXE` -> `LINK.EX$`, `BQLB45.LIB` ->
`BQLB45.LI$`, `QLBDUMP.BAS` -> `QLBDUMP.BA$` - and the file is
packed. `UNPACK.EXE` and `SETUP.EXE` sit on the same disks. So
`QB.QL$` is `QB.QLB` under compression; it is not a variant of
the format.

---

## 12. Emitting one yourself - the byte-level spec

What follows is what QuickBASIC 4.0 and 4.5 accept; a library
with only the header, two tables and the name pool is refused or
hangs QuickBASIC. It was measured with libraries written by
`RLINK` (`SRC\RLOQBE.PAS`, tests in `TEST\QLB`); sections 4, 5,
9.2 and 10 give the reasons. All values are little-endian. A
running implementation is `SRC\RLOQBE.PAS`, and the dispatcher
it embeds is `SRC\QBRT.ASM` (see also `DOC\QLBRT.MD`).

**Quantities.** `CODEPAR` is the size of the code image in
paragraphs (every code segment starts on a paragraph), `T` the
size of the data tail in bytes (a multiple of 16) and `X` the
offset in QB's data segment where the tail goes (a multiple of
16; `3360h` works in 4.0 and 4.5, LINK writes `3317h`). `Z = X +
T` is the declared data size; it must not be smaller than QB's
own data (`3380h` is accepted, `1000h` and `400h` were refused).
`w2 = CODEPAR` and `w3 = w2 + Z / 16`. `HDRPAR` is the size of
the MZ header in paragraphs: `40h` or more, the relocation table
at `1Eh` has to fit in it.

1. **File layout**

   ```
   MZ header + relocation table   HDRPAR * 16 bytes
   +0                   the word 0 (ULCodeSquishSize)
   +2                   code image, CODEPAR * 16 bytes
   data                 the word X, then the tail, T bytes
   block                QB header (34 bytes), the three
                        tables, the names
   ```

2. **MZ header.** The declared image size (`e_cblp`, `e_cp`) is
   `HDRPAR * 16 + w3 * 16 + w4` (more than the file holds).
   `e_crlc` is the number of relocations, `e_cparhdr = HDRPAR`,
   `e_minalloc = e_maxalloc = FFFFh`, `e_ss = w3`, `e_sp = 0`,
   `e_lfarlc = 1Eh`, and `(e_cparhdr + e_cs) * 16 + e_ip` is the
   file position of the QB header, `HDRPAR * 16 + 2 + CODEPAR *
   16 + 2 + T`.

3. **QB header.** `EAh`, a far address (not executed by QB),
   `02h`, `6C75h`, the offset of the CODE table (34) and of the
   DATA table, then the eleven words of section 4: `w0` = offset
   of the segment table, `w1 = 0`, `w2 = CODEPAR`, `w3`, `w4` =
   size of the block in bytes, `w5 = w2`, `w6 = w7 = 0`, `w8 =
   w2`, `w9 = w10 = 0`.

4. **Tables.** The CODE table may be empty (one zero word). The
   DATA table has one entry for `b_ULVars` `{2, name, X, w2}`
   and then a zero word. The segment table has `NULL {3, name,
   0, w2}`, `_DATA {3, name, 0, w2 + X/16}`, `BC_SAB {3, name,
   10h, w2 + X/16}`, `STACK {3, name, 0, w3}`, `SYMBOL {3, name,
   0, w3}` and a zero word. Then the names, NUL terminated, and
   a zero byte at the end. More entries are allowed; the order
   `NULL` ... `STACK`, `SYMBOL`, end, matters (section 5).

5. **`b_ULVars`** is the first 16 bytes of the tail (offset
   `X`): three far pointers (offset, segment paragraph of the
   code image) to the dispatcher and to two routines that only
   `retf`, the word 0 at `+0Ch` and the word `13h` at `+0Eh`.

6. **Relocations** (entries `(offset, segment)`): the segment
   word of every table entry (the location is `w3:` offset of
   the entry in the block `+ 6`), the words `+3` (the far jump)
   and `+14`, `+16`, `+18`, `+22`, `+28` (`w1`, `w2`, `w3`,
   `w5`, `w8`) of the QB header, the three segment words of
   `b_ULVars`, and every segment word in the code and the data
   (`mov ax,seg ...`, far calls, far pointers). Data paragraphs
   are `w2 + (X + offset in the tail) / 16`, code paragraphs are
   below `w2` (section 9.2).

7. **The dispatcher** (section 10.2) is code of the library:
   selector `0Ah` finds the routine for a name, `10h` may return
   zeros, and every other selector may only return (`retf` for
   `00` to `06`, `retf 2` for `08` to `10h`). `RLINK` makes the
   other selectors a Pascal style call of the entry-point (the
   selector is the word parameter and is in `CX` too) and keeps
   the names and a hash table after the dispatcher; the CODE
   table lists the exported names (see `DOC\QLBRT.MD`).

## 13. Reference reader

Self-contained Python 3; reads any `.QLB`. This is what produced
every measurement in this document. (It makes the three header
checks of QB, reads the 22-byte block and the segment table, and
sorts the relocations into those that patch the symbol block,
the code and the data. It reads QB 4.5, QB 4.0 and the libraries
written by `RLINK`.)

```python
import struct, sys

def read_qlb(path):
    d = open(path, 'rb').read()
    (magic, cblp, cp, crlc, cparhdr, minalloc, maxalloc,
     ss, sp, csum, ip, cs, lfarlc, ovno
     ) = struct.unpack_from('<14H', d, 0)
    if magic != 0x5A4D:
        raise ValueError('not an MZ image')

    # +2: see 9.1, the word at cparhdr*16 is ULCodeSquishSize
    image_base = cparhdr * 16 + 2
    # the QB header (34 bytes, see section 4)
    q = (cparhdr + cs) * 16 + ip

    stub = d[q:q + 5]
    entry = None
    if stub[0] == 0xEA:
        eoff, eseg = struct.unpack_from('<HH', stub, 1)
        entry = (eseg, eoff)

    version = d[q + 5]
    qmagic, symstart, datstart = struct.unpack_from(
        '<HHH', d, q + 6)
    if qmagic != 0x6C75 or stub[0] != 0xEA or version < 2:
        raise ValueError('not a QuickLibrary (the three '
                         'checks of QB: EAh, 6C75h, ver>=2)')
    words = struct.unpack_from('<11H', d, q + 12)
    w0, w1, w2, w3, w4 = words[:5]

    def table(start, limit=5000):
        out, p = [], q + start
        for _ in range(limit):
            flags, nameoff, off, seg = struct.unpack_from(
                '<HHHH', d, p)
            if flags == 0:
                break
            no = q + nameoff
            name = d[no:d.index(b'\0', no)].decode('latin-1')
            out.append((flags, seg, off, name))
            p += 8
        return out

    # DOS relocation table: (offset, segment), offset FIRST
    rel = [struct.unpack_from('<HH', d, lfarlc + 4 * i)
           for i in range(crlc)]
    # what they patch: the symbol block, the code, the data
    where = {'block': sum(1 for o, s in rel if s == w3),
             'code': sum(1 for o, s in rel if s < w2),
             'data': sum(1 for o, s in rel if w2 <= s < w3)}

    return dict(file=path, size=len(d), raw=d,
                image_size=(cp - 1) * 512 + cblp,
                image_base=image_base, qhdr=q, entry=entry,
                version=version, symstart=symstart,
                datstart=datstart, words=words,
                relocs=rel, reloc_where=where,
                code=table(symstart), data=table(datstart),
                segs=table(w0))

def body_offset(k, seg, off):
    # image_base + segment * 16 + offset (sections 9 and 9.1)
    return k['image_base'] + seg * 16 + off

if __name__ == '__main__':
    for path in sys.argv[1:]:
        k = read_qlb(path)
        w = k['words']
        rw = k['reloc_where']
        print('%s  %d bytes, declared image %d'
              % (k['file'], k['size'], k['image_size']))
        print('  QB header at file 0x%X, entry jump %04X:%04X,'
              ' version %d'
              % (k['qhdr'], k['entry'][0], k['entry'][1],
                 k['version']))
        print('  22-byte block: '
              + ' '.join('%04X' % x for x in w))
        print('    w0 segment table +%04X  w2 code paragraphs'
              ' %04X  w3 end of data %04X  w4 block size %04X'
              % (w[0], w[2], w[3], w[4]))
        print('  relocations: %d (patching the block %d,'
              ' code %d, data %d)'
              % (len(k['relocs']), rw['block'], rw['code'],
                 rw['data']))
        for label in ('code', 'data', 'segs'):
            print('  %s: %d entries'
                  % (label.upper(), len(k[label])))
            for flags, seg, off, name in k[label]:
                public = not (name.startswith('__')
                              or name.startswith('$')
                              or name[:2].upper() == 'B$')
                where = ''
                if label == 'code' and flags == 1:
                    b = body_offset(k, seg, off)
                    where = ('   body at file 0x%X: %s'
                             % (b, k['raw'][b:b + 8].hex(' ')))
                mark = ''
                if not (public or label == 'segs'):
                    mark = '   (reserved)'
                print('    %04X  %04X:%04X  %s%s%s'
                      % (flags, seg, off, name, mark, where))
```

The same thing in QuickBASIC, from Microsoft, is
`QB45\INC\EXAMPLES\QLBDUMP.BAS` - it is the primary source for
sec. 3, sec. 4, sec. 5 and sec. 7, and it is worth reading in
full.

---

## 14. Open questions

**Still open**

* **Non-zero `w6`/`w7` and `w9`/`w10`** (far data and far BSS
  areas of the library, section 4): the code that uses them was
  read, but every library examined has them 0, so the far-area
  paths were not run.
* **The third far pointer of `b_ULVars`** (`0025` in `T0.QLB`, a
  stack-check routine): its public name and who calls it. The
  first two are `B$RTtoULFar` and `B$RTtoULNear` by offset
  arithmetic (*inferred*).
* **How many procedure numbers QB implements** behind the
  gateway (section 10.3) beyond the 38 thunks of `BQLB45.LIB`,
  and the numbers of `BQLB40.LIB` and `QBXQLB.LIB` (compared by
  names only).
* **What the flag `4` of `NMALLOC` and `ENMALLOC` does:** no
  reader was found in the loader.
* **Whether other parts of QB read the tables** by other names
  (IDE, debugger). The loader and the dispatcher interface need
  only the five names, and `QB.EXE` has no other name as a
  string, but code could take a name from elsewhere.
* **QBasic.** The MS-DOS 6.22 `QBASIC.EXE` (194309 bytes) has no
  `/L`. The 254799-byte `qbasic.exe` of MS-DOS 5 in section 15
  has the same strings; whether it loads a library was not
  tested (the file was not available).

---

## 15. Where the samples live

All under `samples/QHelp/qb/` (read-only; nothing there was
modified). Two archives carry the same QuickBASIC 4.5 files -
`qb45.zip` lays them out under `QB45/`, and `QuickBASIC-4.5.zip`
under a `Microsoft QuickBASIC Compiler 4.5 (1988) (MSDN)/
DISK<n>/` tree. The paths below give the short form.

* `QB45/LIB/QB.QLB`
  - what: **5822 bytes - the working QuickLibrary; every
    measurement in sec. 2-sec. 9 is this file**
* `QB45/LIB/QB.LIB`
  - what: 2075 bytes - its OMF source library, the five API
    routines
* `QB45/LIB/BQLB45.LIB`
  - what: 24789 bytes - the QLB glue and the C runtime
* `QB45/INC/QB.BI`
  - what: the `DECLARE`s for the API (sec. 7)
* `QB45/INC/EXAMPLES/QLBDUMP.BAS`
  - what: Microsoft's own dumper - the primary source for sec.
    3, sec. 4, sec. 5, sec. 7
* `DEBUG/D3/QB.QLB`
  - what: 6751 bytes - the debug build, `SetUEvent`'s code
    segment plus the QBD library
* `DEBUG/QB.SYM`, `DEBUG/QB.MAP`
  - what: symbols for `QB.EXE` - the source for sec. 10's
    `B$UL*` names
* `DISK2/QB.EXE`
  - what: 278804 bytes - QuickBASIC itself; carries `B_ULVARS`,
    `LIB=QB.QLB`, the LINK-command fragments (sec. 11)
* `DISK3/LINK.EXE`
  - what: 69133 bytes - the linker with the `/Q` switch
* `DISK4/PACKING.LST`
  - what: the one-line description of each file, quoted in sec.
    1
* `COGS/DISK3/QB.QL$`
  - what: the same `.QLB`, SETUP-compressed;
    `COGS/DISK3/UNPACK.EXE` unpacks it
* `qbasic.zip` -> `qbasic.exe`
  - what: 254799 bytes - MS-DOS 5's `QBASIC.EXE`, unpacked, with
    the same QLB strings and the same `B_ULVARS`; **not tested**
    (not available)
* `F:\Compilers\QBASIC.ZIP` -> `QBASIC.EXE`
  - what: 194309 bytes, MS-DOS 6.22 QBasic 1.1, PKLITE-packed.
    Its usage line is `QBASIC [/B] [/EDITOR] [/G] [/H] [/MBF]
    [/NOHI] [[/RUN] file]`, **no `/L`**: QBasic does not load
    libraries (tested)
* `Microsoft QuickBASIC v4/`
  - what: QuickBASIC 4.0: `QB.EXE` 230048 bytes, `QB.LIB`,
    `QB.QLB` 5316 bytes, `BQLB40.LIB`; the same format and the
    same tests pass
* `PDSLITE/`
  - what: BASIC PDS 7.1 (`QBX.EXE`, `QBX.LIB`, `QBX.QLB`,
    `QBXQLB.LIB`): same names rules (sections 7 and 14)

---

## 16. The worked loader: `samples/qlbcall.asm`

One NASM source, `samples/qlbcall.asm`, built to
`samples/qlbcall.exe`, is the whole of sec. 10.1 and sec. 10.2
running. It is a DOS program (real mode; it makes no DPMI call)
and it demonstrates, in five steps, printing what it finds:

* 1
  - what: where the program was loaded (`CS`, `DS`, `PSP`) and
    `PSP:0002`, the first byte past its own block
* 2
  - what: `INT 21h AH=4Bh AL=00h`, load-and-execute: it runs
    itself again with the command tail `/x`, the child announces
    itself and exits with code 7, the parent reads the code back
    with `AH=4Dh` and prints it. Every register except `CS:IP`
    comes back destroyed, so the parent reloads `DS`/`ES` from a
    `CS`-relative saved word - that is worth seeing once
* 3
  - what: `INT 21h AH=4Bh AL=03h`, the overlay load - twice,
    once with a relocation factor of the load segment and once
    with 0, so the dump of the patched words shows exactly what
    DOS did (sec. 10.1)
* 4
  - what: the same library loaded by the program's own loader:
    seek to `0x402`, read the header, zero the block, read the
    image, apply the 143 entries verbatim - then far-call
    `INT86OLD` at `CS = block+0011`, `IP = 0004` with `INT
    21h/AH=02h/DL='Q'`, print the `Q`, and print the out-array
* 5
  - what: unloading with `AH=49h`, and the note that this is the
    whole of it

The measured output of step 4 in one place, because these are
the numbers the document quotes:

```
  the same three file bytes, at our image 0298:
      EAEC 0188 0AC0
  image 0114, where the symbol table says INT86OLD is:
      8B55 83EC E0C4
  calling INT86OLD at 0AAE:0004 with INT 21h/AH=02h/DL="Q" ...
Q
  out ax    = 0251  out bx    = 0000  out cx    = 0000
  out dx    = 0051  out flags = 0202
```

`0AAE` is the load segment `0A9D` plus `0x11` - the entry's own
segment half, and the reason sec. 10.2 exists: with `CS = 0A9D`
the same call prints its `Q` and then never comes back.

**How to build it**, under DOSBox-X (`C:\DOSBox-X`, `mount G` is
free; the batch must `cd` to its own directory and end in
`exit`):

```
NASM -s -f rdf QLBCALL.ASM
SET TMP=G:\TMP
SET TEMP=G:\TMP
RLINK mzs /o=QLBCALL.EXE QLBCALL.RDF
```

It must run from a directory that holds `QB.QLB`, because that
is the name it opens - the same name and the same directory
QuickBASIC uses.

Four toolchain traps, all met while building it:

* **`RLINK` needs `TMP` (or `TEMP`) set** or it fails with the
  misleading `Entry point start not found.` - it writes a
  temporary header, and with nowhere to put it, it reports the
  failure as a missing entry point. Without `TMP`/`TEMP` the
  temporary file goes to the current directory (full path from
  `GetDir` of `System2`); RLINK builds made with an older
  `System2` need `TMP` or `TEMP`.
* **`NASM 0.98` writes its diagnostics to stderr**, so a build
  driven through a redirected log shows a clean run unless `-s`
  is there to send them to stdout too.
* **`NASM 0.98` rejects `mov ds, es`** (`invalid combination of
  opcode and operands`); `push es / pop ds` is the spelling it
  takes.
* **It also refuses a doubled apostrophe inside a single-quoted
  string** - write `"Q"` inside a single-quoted `db` when a
  quote is wanted inside the string.

The MZS image the link produces is one flat span: the code at
`loadseg:0`, the data at `loadseg+0x4C0`, and the stack growing
down from `SS:0x2000` with `SS = loadseg+0x4C` - measured, `CS =
075D`, `DS = SS = 07A9`, and `07A9 - 075D` is exactly the `e_ss`
in the header. `minalloc = maxalloc = 513` paragraphs, so DOS
gives the program its image plus `0x2010` bytes and **nothing
more**: the memory above it stays free, which is why the
`AH=48h` of steps 3 and 4 works with no `AH=4Ah` resize first.
(A `.COM` file has no such header, owns everything DOS has, and
does need one - which is the whole reason this is an EXE.)

**The host side is two batch files, and no interpreter is
involved.** The whole set lives in `C:\dev\QBCALL\`, which is
the store for this work: `src\qlbcall.asm` and
`src\QLBDUMP.BAS`, `bin\qlbcall.exe`, `build\mkrun.cmd` and
`build\GO.BAT`, `lib\` with the libraries, `ref\` with
`QB.BI`/`QB.SYM`/`QB.MAP`, `tools\` with the analysers,
`docs\QLB.MD` (this document), `examples\` and `AI-MEM\`.
`run.cmd` at the root is a one-line forwarder to
`build\mkrun.cmd`.

* `mkrun.cmd` - copies `qlbcall.asm`, `QB.QLB` and `GO.BAT` into
  the mount (`C:\dos\e\QLBCALL`); deletes the stale
  `QLBCALL.RDF`, `QLBCALL.EXE` and `RUN.TXT`, so a failed build
  cannot masquerade as a good one; launches the emulator with
  `start "" /wait`; copies the built image into `..\bin\` and,
  if the repository is present, into `samples\`; and types
  `RUN.TXT`. It takes its source from **its own directory**,
  then `..\src\`, then `samples\qlbcall.asm`, so the folder can
  be moved or copied anywhere. Run it from anywhere.
* `GO.BAT` - the batch the *guest* runs, because NASM and RLINK
  are DOS programs: `cd \QLBCALL`, set `TMP`/`TEMP`, `NASM`,
  `RLINK`, `dir`, run the program, `exit`.

**`linkq\` is the other working area in the store, and it is
where sec. 11 was run.** It holds `LINK.EXE`, the two linkable
inputs `QB.LIB` and `BQLB45.LIB`, the debug `BQLB45.LIB` as
`DBQLB45.LIB`, the batches `GO.BAT`/`GO2.BAT`/`GO3.BAT` and
their logs `RUN.TXT`/`RUN2.TXT`/`RUN3.TXT`. The seven link
attempts are kept as written: `A.QLB`-`E.QLB` are the
wrong-recipe outputs (7539 bytes; `A`, `B`, `C` and `D` are the
same file, `E` differs only in input order) and `F.QLB` and
`DBG.QLB` are the two byte-exact rebuilds of `QB.QLB` and
`DEBUG-QB.QLB`. The batch mounts the folder itself - `MOUNT G
C:\dev\QBCALL\linkq`, then `G:` - which is why every name in it
is 8.3.

Both are CRLF. A second copy of the two harness batches, and of
`QB.QLB`, is in `C:\dev\dwak-scratch\qlbcall\`. `qbasic.hlp` and
the archives in `samples/QHelp/` are read-only throughout -
`QB.QLB` is extracted from `samples/QHelp/qb/qb45.zip` and never
modified.
