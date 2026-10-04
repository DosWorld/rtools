# QLB imports: what QuickBASIC provides to a Quick Library

Facts measured on QuickBASIC 4.50 (QB.EXE 278804 bytes, debug
build D2_QB.EXE for names), QuickBASIC 4.0 and PDS 7.1 (QBX),
with the Microsoft linker 3.69 (LINK /Q) and the libraries
QB.LIB, BQLB45.LIB, BQLB40.LIB, QBXQLB.LIB. Where something is
only inferred it says so. See also DOC\QLB.MD (format) and
DOC\QLBRT.MD (what RLINK writes).

## 1. Short version

* A QLB has NO import records. Its tables contain only
  definitions.
* Everything a library takes from QuickBASIC is resolved at LINK
  time, against BQLB45.LIB. BQLB45.LIB is the import library: it
  defines the B$... thunks (procedures of QB) and the addresses
  of QB's data variables.
* The import list is fixed: it is what BQLB45.LIB defines. A
  library cannot add imports.
* At run time QB provides only values in its own data segment:
  four words it writes at load, and two far pointers (the
  gateway) it keeps for calls from the library into QB.
* An unresolved name is a link error (L2029), and LINK /Q still
  writes a QLB (address 0:0).

## 2. What LINK /Q adds to every library (default imports)

A QLB built from a one-byte routine (PING.OBJ) has, besides
PING, exactly the same names as the QLB built from other
sources: 83 names from 8 modules of BQLB45.LIB, and all their
code (thunks):

* ulstart.asm
  - Names: 58
  - Role (from names and code): start-up, data variables
    mirroring the QB data segment, b_ULVars
* fixups.ASM
  - Names: 9
  - Role (from names and code): 8087 emulator linkage, absolute
    values FIARQQ .. FJSRQQ
* rtmint1.asm
  - Names: 7
  - Role (from names and code): runtime hooks: __chkstk,
    __fptrap, __fpreset, __cintDIV, __nullcheck, __amsg_exit,
    __FMSG_TEXT
* crt0stub.asm
  - Names: 4
  - Role (from names and code): _exit, __exit, __cexit,
    __acrtused
* execve.asm
  - Names: 2
  - Role (from names and code): _execve, _spawnve
* ultort.asm
  - Names: 1 (+ hidden)
  - Role (from names and code): "user library to runtime":
    thunks into QB, __BRUNERR
* ulutil.asm
  - Names: 1 (+ hidden)
  - Role (from names and code): dispatcher routines called by
    QB, SetUEvent
* brkctl.asm
  - Names: 1
  - Role (from names and code): _brkctl

The same set is present in QB.QLB (4.50: 5 names from QB.LIB, 83
from BQLB45.LIB, 2 from the linker: _edata and _end), in
QuickBASIC 4.0 and in PDS 7.1 (same counts of QB.LIB names,
other runtime sizes). The set does not depend on the user's
code. 16 thunks are in the image of a library that never
references them.

## 3. Public and private names

LINK /Q exports every public name of the linked modules EXCEPT
names with prefix B$ or b$. Measured: publics of the included
modules that are not in the tables: 96 (4.50), 98 (4.50 debug),
82 (4.0), 106 (PDS 7.1), 96 (mylib); in all cases 100% with the
prefix B$ or b$, and no exported name has that prefix. The
library also defines twins with underscore (b_ULVars,
b_ULSymSeg, b_errlin ...) which are exported. Microsoft's
QLBDUMP.BAS hides names starting with "__", "$" and "b$" as
"reserved", this is by name, there is no flag. Table flags seen:
1 code, 2 data, 5 absolute value (segment 0, the offset field is
a value), segment table 3 and 4 (NMALLOC, ENMALLOC). A BASIC
identifier starts with a letter, so names starting with _ or $
cannot be called from BASIC.

## 4. Variable imports (data of QB)

* The DATA table entries with small offsets are variables of
  QB.EXE itself: 46 of 46 names of DEBUG-QB.QLB below offset
  120h (STKHQQ, __anullsize, __abrkp, _errno, __osversion,
  b_errlin, b_errmod, b_erradr, b_errnum, b_ULSymSeg ...) have
  exactly the address of the variable of the same name in the
  data map of QB.EXE (QB.MAP, data segment 5517). The library is
  linked against the data layout of QB: ulstart.asm mirrors it.
* These addresses are fixed when LINK /Q runs. QB does not patch
  them by name: QB.EXE has only 5 name literals it looks up in a
  library (see 7), none of these.
* In the code of a library a reference to such a variable is:
  offset (2 bytes, constant, for example 010Ch for b_errlin) and
  segment = the data base paragraph (w2 of the QB block, same
  value as the segment-table entry NULL), stored as a relocated
  word; the loader turns it into the data segment of QB. Test:
  module with "mov ax,seg b$errlin / mov ax,[b$errlin]" gave
  "mov ax,0084" (w2 = 0084, MZ relocation entry present) and
  "mov ax,[010C]".
* What QB writes into its own data at load (B$ULLoad, 2-byte
  words):

* b$ULSymSeg (b_ULSymSeg)
  - Offset: 00D3
  - Content: segment of the loaded symbol block
* b$ULDataLength
  - Offset: 00D5
  - Content: length of the data image
* b$ULDataStart
  - Offset: 00D7
  - Content: start of the data image
* b$pBC_SAB
  - Offset: 00B8
  - Content: near pointer computed from the BC_SAB entry of the
    segment table

## 5. Procedure imports (procedures of QB): numbered gateway

* QB keeps two 4-byte far pointers in its data segment:
  b$pULtoRTFar at DS:00BE and b$pULtoRTNear at DS:00C2 (the
  library code uses "jmp far [00BE]" and "call far [00C2]").
  They are filled by QB itself.
* For every procedure of QB the library has a thunk in
  ultort.asm that puts a NUMBER into DI or BX and goes to the
  gateway. No name is passed. The thunks are the public names
  B$... (hidden, see 3).
* Because the pointer is a far pointer, offset and segment come
  from QB; the library needs only the number.

Thunks of BQLB45.LIB (4.50), numbers as found in the code:

* BASIC errors
  - Number: the error code (BFM 54, IFN 52, DV0 11, FC 5, RG 3,
    OM 7, AFE 73, OV 6; NOL and OSS use other forms) - inferred
    from names
  - Names: B$ERR_NOL B$ERR_BFM B$ERR_IFN B$ERR_DV0 B$ERR_FC
    B$ERR_RG B$ERR_OM B$ERR_AFE B$ERR_OV B$ERR_OSS
* 22 services
  - Number: 0,2,4 .. 42
  - Names: B$BREAK_CHK 0, B$FOUTBX 2, B$LHLOCFDB 4, B$RES_SETUP
    6, B$TYPUI 8, B$LHFDBLOC 10, B$$WCLF 12, B$$RCH 14, B$$TCR
    16, B$$WCH 18, B$STALCTMP 20, B$TTY_SOUT 22, B$STDALC 24,
    B$STDALCTMP 26, B$STDALCALLTMP 28, B$PUTNUM 30, __BRUNERR
    32, B$RUNERR 34, B$FHHighAlloc 36, B$FHHighDealloc 38,
    B$IFHAlloc 40, B$FHDealloc 42
* 6 entries
  - Number: 0,4,8,12,16,20 (4 bytes per entry, via the far
    pointer - inferred)
  - Names: B$ULReload, B$IStop, B$END, B$GetNmalloc, B$IEND,
    B$SetUEvent

Test: module with "call far B$RUNERR" gave "call far 0001:00C1"
with a relocated segment word, and the code at that address is
"push di / mov di,34 / jmp gateway": a thunk inside the library.

## 6. What the header and tables contain about imports: nothing

* CODE table: definitions inside the library. All 42 names of
  the reference libraries are public symbols of QB.LIB or
  BQLB45.LIB (the only exceptions are the linker symbols _edata
  and _end).
* DATA table: definitions; the low part describes data of QB.EXE
  (4).
* Segment table (flags 3, 4): segments of the library. A
  reference to an import adds NO entry to any table (a library
  with an imported procedure and variable has the tables of the
  exports only).
* Header word 1 of the 22-byte block is 0 in all libraries; the
  code that tests it in the debug QB is a debug assertion
  (DEBHALTID_STRINGS, "Assertion failed"), it is not an
  unresolved flag.
* Unresolved name: LINK 3.69 says "error L2029 : 'COOL' :
  unresolved external" and still writes the QLB; the call to
  COOL is "9A 00 00 00 00" (0000:0000), no relocation, nothing
  in the tables.
* A .LIB with the references (LIB.EXE, then LINK /Q
  IMP.LIB,IMP.QLB,NUL,BQLB45.LIB;) gives the same QLB, byte for
  byte, as the .OBJ.

## 7. How QuickBASIC uses names

QB.EXE (4.50, 4.50 debug, 4.0, PDS 7.1) has exactly five name
literals it looks up in a library: B_ULVARS (DATA table), NULL,
STACK, SYMBOL and BC_SAB (segment table); of 146 names of the
five reference QLBs nothing else exists as a literal (NMALLOC is
only a segment name in the debug symbols of QB). The loader
checks: the segment table (NULL has the data base, STACK
followed by SYMBOL and the end), BC_SAB, b_ULVars (word at +0Ch
is 0, byte at +0Eh is 13h).

A CALL in BASIC is resolved by the library, not from the CODE
table: QB jumps through b_ULVars[0] with CX = selector. A
library with an EMPTY CODE table, which finds the names itself,
loads and works in QB 4.0 and 4.50 (tested; RLINK fills the
table, see DOC\QLBRT.MD).

Dispatcher routines (library side, BQLB45.LIB), verified by the
same offset difference (0220h) for all eight entries of
ulutil.asm:

| Selector | Role | Public name | Module, offset |
|---|---|---|---|
| 00 | Init | B$ULInit | ulutil +013D |
| 02 | Term | B$ULTerm | ulutil +0131 |
| 04 | DataRelease | B$ULDataRelease | ulutil +0313 |
| 06 | AllocDataImage | B$ULAllocDataImage | ulutil +02A5 |
| 08 | CONERR | B$CONERR | erbcproc +0000 |
| 0A | GETPROC | B$ULGetProc | ulutil +0059 |
| 0C | GetData | B$ULGetData | ulutil +00CE |
| 0E | GetSeg | B$ULGetSeg | ulutil +00D1 |
| 10 | GETCOMMON | B$ULGetCommon | ulutil +0000 |

b_ULVars[0] (the entry of QB) is, by offset arithmetic,
B$RTtoULFar and b_ULVars[1] B$RTtoULNear (ultort.asm +2Fh and
+27h, 8 bytes apart like the pointers); the third pointer was
not identified.

Measured with a logging dispatcher (QB 4.50 and 4.0): selector
order 06, 10, 00, then one 0A for every CALL statement in the
source (not for every execution), 00, 02 at the end. The name
arrives as written in the source ("hello", "MY.PROC"), one
lookup, no variants (no "B$HELLO"). If the name is not found
(0:0 returned) QB stops (error box, no more calls). Selectors 08
and above have one word argument (GETPROC: near pointer to the
string descriptor {length, pointer}), the routine ends with RETF
2.

## 8. The dispatcher that LINK /Q builds: what it does

Disassembled from T0.QLB (4.50, built from MYLIB.OBJ with
BQLB45.LIB), data references named with the data map of QB
(QB.MAP). It is the code of two modules of BQLB45.LIB:
ultort.asm ("user library to runtime", base 00A6 in the code
segment of T0) and ulutil.asm (base 0220). In short: **it is the
glue between the life cycle of a BASIC program in QuickBASIC and
the Microsoft C runtime inside the library.** QB runs a program,
ends it, runs it again (RUN, CHAIN, END); the library is a C
program, so its initialisers, terminators, heap and static data
must be started, finished and reset at the same moments. It is
not a lookup helper (that is only three of its nine routines).

### 8.1 Entry and table

* `b_ULVars[0]` is `B$RTtoULFar` (ultort +002F): `add cx,00EAh /
  mov bx,cx / jmp near [cs:bx]`. The table at `cs:00EA` has nine
  near pointers (index = selector): 035D, 0351, 0533, 04C5,
  01B6, 0279, 02EE, 02F1, 0220.
* `b_ULVars[1]` is `B$RTtoULNear` (+0027): `add di,00E8h / call
  near [cs:di] / retf`, the same table for a call-and-return (QB
  did not use it in the traces).
* Selectors, names and entries (public name, module, offset,
  absolute offset in T0):

* 00
  - Role: Init
  - Public name: B$ULInit
  - Module +offset: ulutil +013D
  - T0: 035D
* 02
  - Role: Term
  - Public name: B$ULTerm
  - Module +offset: ulutil +0131
  - T0: 0351
* 04
  - Role: DataRelease
  - Public name: B$ULDataRelease
  - Module +offset: ulutil +0313
  - T0: 0533
* 06
  - Role: AllocDataImage
  - Public name: B$ULAllocDataImage
  - Module +offset: ulutil +02A5
  - T0: 04C5
* 08
  - Role: CONERR
  - Public name: B$CONERR
  - Module +offset: erbcproc +0000
  - T0: 01B6
* 0A
  - Role: GETPROC
  - Public name: B$ULGetProc
  - Module +offset: ulutil +0059
  - T0: 0279
* 0C
  - Role: GetData
  - Public name: B$ULGetData
  - Module +offset: ulutil +00CE
  - T0: 02EE
* 0E
  - Role: GetSeg
  - Public name: B$ULGetSeg
  - Module +offset: ulutil +00D1
  - T0: 02F1
* 10
  - Role: GETCOMMON
  - Public name: B$ULGetCommon
  - Module +offset: ulutil +0000
  - T0: 0220

* Selectors 08 and above take one word of arguments and end with
  `retf 2`; 00 to 06 end with `retf`.

### 8.2 Variables it uses (QB data segment, QB.MAP names)

* 00B4
  - Name: b$pend
  - Used for: end of the data of QB
* 00BA, 00BC, 000C, 005C
  - Name: b$nmalloc_start, b$nmalloc_end, __abrktb, __abrktbe
  - Used for: near heap of the library, table of DOS blocks of
    brk() (4 bytes per entry from 0010)
* 00D3
  - Name: b$ULSymSeg
  - Used for: segment of the symbol block (the tables)
* 00D5, 00D7
  - Name: b$ULDataLength, b$ULDataStart
  - Used for: length and start of the data image of the library
* 00D9, 00E1
  - Name: b$FHDULNearData, b$FHDULFarData
  - Used for: far-heap handles of the saved copies; the segment
    is in the word at +2 (00DB, 00E3)
* 00E9
  - Name: b$CtrlFlags
  - Used for: bit 1 = the library is initialised
* 0102, 0106, 010A, 010C, 010E
  - Name: b_erradr, b_errmod, b_errnum, b$errlin, b$inonerr
  - Used for: error state
* 3328, 333A, 3346
  - Name: in the data of the library
  - Used for: name tables (descriptors) of the terminator and
    initialiser groups; the descriptor "COMMON"

### 8.3 The routines

**AllocDataImage (06)** - saves the initial data. *Measured
(code read).*
```
if (b$ULDataLength == 0) return;
; far heap of QB, handle in b$FHDULNearData
blk = B$IFHAlloc(b$ULDataLength)
copy b$ULDataLength bytes from DS:b$ULDataStart to blk
; far data of the library, section 8.5
(sz_far = block words w7:w6, seg_far = w5)
; b$FHDULFarData
if (sz_far != 0) { blk2 = B$IFHAlloc(sz_far); copy sz_far bytes
    from seg_far:0 to blk2 }
```
It makes a pristine copy of the static data of the library. If
an allocation fails the first copy is freed again.

**DataRelease (04)** - frees both copies (`B$FHDealloc` on
b$FHDULNearData and on b$FHDULFarData).

**GETCOMMON (10)** - where is the COMMON area. *Measured.*
```
name = argument descriptor, or the built-in descriptor "COMMON"
    (DS:3346) if the argument is 0 or empty
e = lookup(segment table, name)                  ; section 8.4
if (not found) return BX = AX = DX = 0
; (segment - DS) * 16 + offset
BX = flat DS offset of e
; the size of the area
DX = offset of the next entry - BX
; an empty area
if (DX <= 0 or (BX == 336E and DX <= 6)) BX = DX = 0
return BX, DX                                    ; retf 2
```
QB asks for it while it loads the data image (`ReloadULData`,
the log shows `10` right after `06`), so that the COMMON area of
the library is treated separately.

**Init (00)** - (re)start the C runtime of the library.
*Measured, the table names are inferred.*
```
; a second start of a program: finish, restore the initial data
if (b$CtrlFlags & 2) { Term(); RestoreData(); }
; the BSS of the library (12 bytes in T0)
zero DS:_edata .. DS:_end
; the far BSS, section 8.5 (0 in T0)
zero (w10:w9) bytes at w8:0
near heap: the own area 336E..3374 if it is larger than 6 bytes,
    else a block that QB gives (B$GetNmalloc: size in AX,
           start in DX), and the own area again if QB gives none
b$nmalloc_start = __abrktb = start ; b$nmalloc_end = end
b$CtrlFlags |= 2
; the C initialisers (names XIB..XIE)
RunTable(descriptors at DS:333A)
```

**Term (02)** - end of a program run. *Measured, the table names
are inferred.*
```
; the terminators and onexit tables (XPB.., XCB.., XOB..)
RunTable(descriptors at DS:3328, 3 groups)
; free the brk() blocks
for each entry of __abrktb from 0010 to __abrktbe: INT 21h
    AH=49h on its segment
__abrktbe = 000C ; __aseglo = 0
```

**RunTable** (helper at 03F0): for each group the descriptors
name two markers (begin, end) of the segment table; it takes
their addresses (`GetSeg`) and calls the far pointers stored
between them, **from the last to the first**, skipping null
pointers. This is the Microsoft C convention of the tables `XI*`
(initialisers), `XP*` (pre-terminators), `XC*` (terminators) and
`XO*` (onexit), which are the segment names `XIB, XI, XIE, XPB,
...` in the segment table of every library (section 2 of
DOC\QLB.MD).

**RestoreData** (helper at 0457, in Init): puts the initial data
back. *Measured.* If there is no saved copy it calls
`B$ULReload` (QB reads the library again) and `AllocDataImage`.
Otherwise it asks GETCOMMON for the COMMON area and copies the
saved image back over DS:b$ULDataStart **except the COMMON
area** (before it and after it), and copies the saved far data
back with the long copy loop at 054E (segments of 64 KB). So a
`RUN` starts with the initial values of the static data of the
library, and the COMMON area survives (BASIC `COMMON`
semantics).

**GETPROC (0A), GetData (0C), GetSeg (0E)** - name lookup in the
CODE, DATA and segment table. One routine (`lookup` at 02F3)
does all three: the table is chosen by BL (08 CODE, 0A DATA, 0C
segment table: the offset of the table is read from the QB
header at that byte); `GetData` and `GetSeg` are `mov bl,0Ah` /
`mov bl,0Ch` and then the common code (the instruction `mov
bl,0Ch` is hidden inside `cmp ax,0CB3h` at 02F0).
```
lookup(table, name):
  ; upper case
  s = a temporary copy of the name, converted by QB (an INT 3Fh
      helper, section 8.4)
  for each entry of the table (until the zero word):
      if name == (NUL terminated name in the pool of the
          symbol block, compared with repe cmpsb)
          -> return the far address (entry offset, entry
          segment) in DX:AX and the pointer to the entry
          in CX
  free the temporary string (B$STDALCTMP); return 0:0 if nothing
      was found
GETPROC(name, flag in DX):
  if (flag != 0) name = "_" + name;  every '.' of it becomes '_'
  r = lookup(CODE, name)
  if (r not found) r = lookup(DATA, name)
  if (r.segment < w1)   return 0:0   ; below the code base
  free the temporary strings; retf 2
```
`w1` of the QB header is the segment of the code image after
relocation (section 4 of DOC\QLB.MD). The underscore for a
non-zero flag, the search in the DATA table, the case-blind
compare and that the type word of an entry is not read are
measured with libraries written by LINK /Q (DOC\QLB.MD 10.4).
The `name` descriptor that QB passes is a temporary string: a
library frees it with the service B$STDALCTMP (number 26).

**CONERR (08)** - the error hand-off. *Inferred from the code,
not run.* QB calls it with a pointer to an error record when a
run-time error is raised while code of the library is active. It
stores the module (`b_errmod = 2`, the library), the number and
the address from the record (`b_errnum`, `b_erradr`), computes
the line (a helper of ultort), and unless an error is being
handled already (`b$inonerr`) it looks for the handler of the
BASIC frame, rebuilds the stack pointer from the frame chain of
the library (so the frames of the library are dropped) and jumps
to the handler with its far address pushed. It is the way a
library routine written in C is left when the BASIC program has
an `ON ERROR`.

### 8.4 Two helpers the dispatcher borrows from QB

* **Numbered gateway** (section 5): `B$IFHAlloc` (ultort +00D2,
  number 40), `B$FHDealloc` (+00D9, 42), `B$STDALC` (+009E, 24),
  `B$STDALCTMP` (+00A4, 26), `B$GetNmalloc` and `B$ULReload`
  (the group with the far pointer).
* **INT 3Fh trap table.** The library has no string code of its
  own. Its `_TEXT` segment holds a table of 3-byte cells `CD 3F
  nn` (`int 3Fh` and an index byte: QB's far-pointer hook), and
  the code calls a cell as a far procedure (`call 5B:0261` and
  `5B:021F`, `5B:0222` in GETPROC): QB traps the interrupt and
  runs its own routine for the index. The lookup uses it to
  convert the name (case) before it compares. This is a second
  mechanism by which a library takes procedures from QB, besides
  the gateway.

### 8.5 The block words that the dispatcher reads

The 22 bytes of the QB header (section 4 of DOC\QLB.MD) are not
only read by the loader:

* w5, w6, w7 (+22, +24, +26)
  - Read by: AllocDataImage and RestoreData
  - Meaning: **far data of the library: segment, size low word,
    size high word.** The area is saved and restored with the
    data image. 0 in the libraries examined (no far data)
* w8, w9, w10 (+28, +30, +32)
  - Read by: Init
  - Meaning: **far BSS: segment, size low word, size high
    word.** The area is cleared at every start. 0 in the
    libraries examined
* w1
  - Read by: GETPROC
  - Meaning: segment of the code image (after relocation)

(Both areas are the C "far" segments `FAR_DATA` and `FAR_BSS` of
the segment table; the three words of each area are the triples
segment, size low, size high of the QB header.)

### 8.6 How it matches the measured call order

`06` (save the initial data) and `10` (where is COMMON) at load;
`00` Init (first start, nothing to restore); one `0A` for each
`CALL` statement of the source; a second `00` Init when the
program starts (this is the "already initialised" path: Term,
then RestoreData, then the initialisers again); `02` Term when
it ends. The logging runtime of section 7 saw exactly this order
in QB 4.50 and 4.0.

### 8.7 What the RLINK runtime does instead

`SRC\QBRT.ASM` answers `0A` itself (names and a hash table in
its own segment) and `10` with zeros (no COMMON area), and calls
the entry-point of the library for every other selector (Pascal
style, the selector as the parameter), so that a library can do
its own start-up and shut-down. A library written in assembly
has no C initialisers, no heap, no static data copy to restore
and no far areas, so nothing of this is needed; one that does
want a reset of its data at each `RUN` has to do it in its
entry-point (selector 00).

### 8.8 Confidence

* **Measured (code read and compared with the traces):** the
  entry and the table, all nine routines, the lookup, the use of
  `w1` and `w5`..`w10`, AllocDataImage, DataRelease, Init and
  Term flow, RestoreData, the helpers.
* **Inferred:** the names of the C tables behind RunTable (XI,
  XP, XC, XO groups), what the INT 3Fh cells compute, the exact
  behaviour of CONERR (not run), the near-heap choice in Init.
* **Not examined:** B$ULReload and B$GetNmalloc on the QB side,
  the routines `h0074` (the line number helper of CONERR),
  `h0025` (the third far pointer of `b_ULVars`).

## 9. Imports in RLINK

A module of a library may `extern` the names of QuickBASIC; for
`rlink qlb` they are resolved by RLINK itself, without
`BQLB45.LIB` and without a linker of Microsoft. RLINK looks at
the import records of all modules, and when a name of the table
below is used and no module exports it (a module that exports
the same name wins), it writes a small module (thunks and data
symbols), links it with the others, and nothing is added for a
library that does not use a name. Names are compared without
regard to case. A name that is neither exported nor in the table
stays an error (`Could not resolve name`).

* service
  - names: `B$BREAK_CHK` 0, `B$FOUTBX` 2, `B$LHLOCFDB` 4,
    `B$RES_SETUP` 6, `B$TYPUI` 8, `B$LHFDBLOC` 10, `B$$WCLF` 12,
    `B$$RCH` 14, `B$$TCR` 16, `B$$WCH` 18, `B$STALCTMP` 20,
    `B$TTY_SOUT` 22, `B$STDALC` 24, `B$STDALCTMP` 26,
    `B$STDALCALLTMP` 28, `B$PUTNUM` 30, `__BRUNERR` 32,
    `B$RUNERR` 34, `B$FHHighAlloc` 36, `B$FHHighDealloc` 38,
    `B$IFHAlloc` 40, `B$FHDealloc` 42
  - what RLINK does: far thunk: `push di / mov di,N / call far
    [00C2] / pop di / retf`
* service (far group)
  - names: `B$ULReload` 0, `B$IStop` 4, `B$END` 8,
    `B$GetNmalloc` 12, `B$IEND` 16, `B$SetUEvent` 20
  - what RLINK does: far thunk: `mov bx,N / jmp far [00BE]`
* error
  - names: `B$ERR_BFM` 54, `B$ERR_IFN` 52, `B$ERR_DV0` 11,
    `B$ERR_FC` 5, `B$ERR_RG` 3, `B$ERR_OM` 7, `B$ERR_AFE` 73,
    `B$ERR_OV` 6
  - what RLINK does: far thunk: `mov bx,code` and then as
    `B$RUNERR`
* variable
  - names: `b$pend` 00B4, `b$pBC_SAB` 00B8, `b$nmalloc_start`
    00BA, `b$nmalloc_end` 00BC, `b$pULtoRTFar` 00BE,
    `b$pULtoRTNear` 00C2, `b$ULSymSeg` and `b_ULSymSeg` 00D3,
    `b$ULDataLength` 00D5, `b$ULDataStart` 00D7, `b$CtrlFlags`
    00E9, `b_erradr` and `b$erradr` 0102, `b_errmod` and
    `b$errmod` 0106, `b_errnum` and `b$errnum` 010A, `b_errlin`
    and `b$errlin` 010C, `b$inonerr` 010E
  - what RLINK does: a data symbol at this offset of the QB data
    segment

The numbers and offsets are those of section 5 and 4 (QB 4.50).
Of these, `B$RUNERR`, the error thunks `B$ERR_FC` (ERR 5),
`B$ERR_OV` (6), `B$ERR_DV0` (11), `B$ERR_OM` (7) and the
variable `b_ULSymSeg` were executed (QuickBASIC 4.50; `B$RUNERR`
and `b_ULSymSeg` also in 4.0); the other services take their
arguments in registers whose meaning was not examined.
`B$ERR_NOL` and `B$ERR_OSS` use other forms in BQLB45.LIB and
are not provided.

Rules for the code of the module:

* The thunks need `DS` = the data segment of QuickBASIC, as the
  thunks of BQLB45.LIB do. A library routine has this value in
  `DS` when QB calls it; restore it before you call a service.
* A service is called with `call far`:

```
        extern  B$RUNERR
        mov     bx, 5
        call    far B$RUNERR
```

* A variable is addressed through the segment of its symbol,
  which RLINK sets to the QB data segment (a relocated word):

```
        extern  b_ULSymSeg
        push    ds
        mov     ax, seg b_ULSymSeg
        mov     ds, ax
        mov     ax, [b_ULSymSeg]
        pop     ds
```

Tested (TEST\QLB\IMPORT.ASM): `ON ERROR GOTO` sees `ERR = 5` and
`RESUME NEXT` continues after the `CALL`; `b_ULSymSeg` gives the
segment of the symbol block.

## 10. Not verified

* Whether any QB code outside the loader reads the CODE or DATA
  table by other names.
* How many procedure numbers QB itself implements beyond those
  of BQLB45.LIB.
* The meaning of the third pointer of b_ULVars (offset 0025 in
  T0) and of the flag 4 in the segment table.
* The run-time behaviour of CONERR (selector 08, read from the
  code only), the names of the C tables of Init and Term, and
  what the INT 3Fh cells compute (section 8).
* QuickBASIC 4.0 and PDS 7.1 numbers of thunks; QBasic
  (QBASIC.EXE) has no /L and does not load QLBs.

## 11. How it was measured

* LINK /Q 3.69 and LIB.EXE (from QBCALL), nasm -f obj for the
  test modules (PING, IMP, IMP2), DOSBox-X.
* Tables and relocations of QLBs read with a script from the MZ
  header and the QB header; public symbols of the libraries from
  the OMF records (PUBDEF); QB data map from QB.MAP of the debug
  QB.
* Name literals searched in QB.EXE, D2_QB.EXE, QB 4.0 QB.EXE,
  QBX.EXE.
* Logging dispatcher: SRC\QBRT.ASM based runtime with trace
  calls, test QLB HELLOLOG.QLB.
* Disassembly of the dispatcher (section 8): ndisasm of the code
  segments of T0.QLB, the offsets named with the public symbols
  of BQLB45.LIB (ulutil.asm, ultort.asm, erbcproc.asm) and the
  data map QB.MAP of the debug QB.
* Microsoft Knowledge Base (Q27993, Q35966, Q31156): QLB is made
  by LINK /Q from a .LIB with BQLBxx.LIB, .QLB files cannot be
  linked together; the format of the tables is not documented
  there.
