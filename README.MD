# RTools

This is MS-DOS tools for linking `RDF`/`RDL` files.
While playing with small compilers, I noticed one problem for all beginners.
It lacks runtime-libraries and linkers support.

I investigate the OBJ/OMF format and found it too complicated.
AOUTB has no segment memory support. COFF and ELF are also complex
and solve problems non-relevant to MS-DOS.

By chance, I meet the RDOFF2 format from NASM - a beautiful and simple
format for object modules.

This repository contains tools for working with RDOFF2 (and source code)
to help you build small compilers.

`RDF` - NASM builtin format `RDOFF2` for object files. Different version of
Nasm works different with this files. So, I strongly advise to use
`NASM version 0.98.39`. See DOC\RDOFF2.TXT and source code.

`RDL` - Again, NASM-format but for libraries.

* nasm - version `0.98.39`, just recompiled for MS-DOS (no DPMI) with RDF support
(by default - is disabled). No other changes.
* rdfdump - dump utility
* rlib - library manager (`rlib c|a|l|d|x`, see below)
* rlink - linker itself
* restub - replaces the DOS stub of an NE, LE, LX, PE or ADAM
  file (`restub input.exe output.exe stub.exe`), see below
* mkdef - makes a `.DEF` file from an NE or PE32 file (`mkdef
  [/o=FILE] [/imp] NAME.DLL`): exports and imports of the file,
  or with `/imp` the IMPORTS list for linking with that dll

# RLINK

RLINK can generate huge files. To speed up RLINK - point your TMP/TEMP directory to ramdrive.
So, don't be confused with dos 16-bit application - RLINK known how to handle more then 64kb and 640kb :).

## Supported output formats

* COM - simple MS-DOS .com file
* MZS - MS-DOS exe, small memory model. CS = code, one data
  segment for data and bss (the program must load DS itself).
  The stack is a separate segment: SS is the data segment plus
  the size of bss in paragraphs, so SS is not equal to DS, and
  SP is the stack size (`/s`). The stack segment starts inside
  the data segment, so a stack that grows to its full size can
  overlap data and bss; keep the stack small or use MZL.
* MZL - MS-DOS exe, large memory model (each rdf have own CS, DS and BSS segment)
* ADAM - DOS32 Extender.
* LX - OS/2 and DPMI exe file.
* PE - DOS PE32 file (`dospe`), the same writer as `winpe`:
  imports, exports and resources, see below.
* WINPE - Win32 PE32 file, exe or dll, with imports, exports
  and resources (`winpe`), see below.
* NE - 16-bit DPMI executable (`rlink ne`), see below.
* QLB - QuickBASIC Quick Library (`.QLB`), large memory model,
  see below.
* RDF - Linked rdf into one code-segment (like a .com, but with zero offset and name). Could be used as DLL.
If you load code segment at ????:0000 - you don't need process relocations. And, as bonus, you can use symbol table.

## Linking rules

* The rdf and rdl files are linked in the order of the
  command line. The modules are placed in the output in the
  reverse order of the command line (the first file is the
  last one in the image).
* Only the modules that can be reached from the entry-point
  (`/entry`, default `start`) are linked, so a module or a
  library member that nobody uses does not enlarge the file,
  and its unresolved imports are not an error. All modules are
  linked for a QLB, for a DLL (`winpe`, `dospe`, `ne` with
  `LIBRARY`) and for NE with exports.
* A whole `.RDL` library is read, but only the members that
  are used get into the output.
* If a symbol is defined by several modules, the module that
  is first on the command line wins (a warning is printed),
  so your own modules always win against a library.
* `RLIB` (environment variable) is the list of directories
  where the rdf and rdl files are searched; `@file` is a
  response file with a list of names.

## rlib

* `rlib c LIB.RDL` creates an empty library.
* `rlib a LIB.RDL FILE.RDF NAME` adds a module (the name is 1
  to 63 characters, must not start with a dot and must be new
  in the library; the file must be a complete rdf).
* `rlib l LIB.RDL` lists the modules.
* `rlib d LIB.RDL NAME` deletes a module.
* `rlib x LIB.RDL NAME FILE.RDF` extracts a module.

## Builtin stubs and extenders

The stub can be changed later with `restub` (see below).

* Simple stub (will write something like "This is dpmi exe!"). Can be used with HX-DOS Extender or with LX format
 (if you want bind other DOS-Extender).
* Loader DOS32 Extender (for ADAM)
* ZRDX DOS-Extender (for LX)
* Loader HX-DOS Extender (for PE).
* Loader HX-DOS Extender, 16-bit (for NE, DPMIST16.BIN: it starts
  DPMILD16.EXE).

If you need viewer for RDF, please visit to https://github.com/DosWorld/objview

"Make" utility available at https://github.com/DosWorld/smallmake

# restub

`restub input.exe output.exe stub.exe` writes a copy of
`input.exe` with another DOS stub. The input is an NE, LE, LX,
PE (PE32 and PE32+) or ADAM file, the stub is any DOS exe
(`stub.exe`, at least 64 bytes). The output file must not be the
input file. The tool moves the file as the format needs, so the
result is a correct file, and replacing the stub back gives the
original bytes.

* NE: the header is moved to the end of the new stub, the rest
  of the file is shifted by a multiple of the sector size (and
  of the resource alignment), and the segment sector numbers,
  the resource offsets and the nonresident names offset are
  corrected.
* LE and LX: the header follows the stub, the absolute offsets
  of the data pages, of the nonresident names and of the
  debug information are corrected (LX with iterated pages is
  refused).
* PE: the header follows the stub, `SizeOfHeaders` is
  recalculated, the file is shifted by a multiple of the file
  alignment, and the section, symbol table, debug and
  certificate offsets are corrected; the checksum is
  recalculated if the file had one.
* ADAM: the payload follows the stub, so the new stub must be
  a DOS exe whose size is written in its header (the DOS32
  loader finds the payload by that size).

The tool has no other options. TEST\RESTUB has the stubs of
RLINK as files (`S_*.STB`) and a check of all four formats.

# PE - dospe and winpe

The imports, exports, resources, DLLs and the definition
file of NE, winpe and dospe are described in DOC\DLL.MD.

`rlink winpe /o=NAME.EXE [/def=FILE] [/res=FILE.RES] A.RDF
B.RDF` links all rdf files into one PE32 file (small
model: one code, one data and one bss section) with `.idata`,
`.edata`, `.rsrc` and `.reloc` sections when they are needed.
`rlink dospe [/hx]` makes the same file for DOS: the sections
may be written and executed (DOS programs change their code),
and the stub is the simple one or, with `/hx`, the HX stub.
DOS PE programs can import functions from DLLs (the HX DOS
Extender loads them) and carry resources. `winpe` always
writes the standard Windows stub ("This program cannot be run
in DOS mode.") and the usual access rights of the sections
(`.text` is read and execute, `.data` and `.bss` read and
write). To run a `winpe` file under the HX DOS Extender call
`DPMILD32 NAME.EXE`. The definition
file is the same as for NE (see below): `NAME` or `LIBRARY`
(a DLL), `EXPORTS`, `IMPORTS`, `HEAPSIZE`, `STACKSIZE`;
`NAME x WINDOWAPI` selects the GUI subsystem (console is the
default). The other statements are accepted and ignored.

* Imports: `[internal=]module.entry` in the `IMPORTS` section,
  entry is a name or an ordinal; `.DLL` is added to the module
  name. `extern internal` in the rdf is a call (stdcall or
  any) to a generated `jmp [slot]` thunk; `__imp_internal` is
  the address of the import slot (`call [__imp_internal]`).
  Only imports that are used are written.
* Exports: `[entryname=]symbol [@ordinal] [NONAME]`; the symbol
  may be in the code or in the data section. Names are sorted
  in the export table as the loader needs it.
* DLL: `LIBRARY name`; the entry-point (`start`) is DllMain.
  All modules from the command line are linked into a DLL
  (not only the modules reachable from the entry-point).
  The base is 10000000h, the base relocation table is always
  written.
* Resources: `/res=FILE.RES` takes a 32-bit `.RES` file
  (type, name, language, memory flags are kept).
* TEST\WINPE (a console exe, a DLL, an exe that imports from
  that DLL by name and by ordinal, an exe with resources,
  tested with HX DPMILD32) and TEST\DOSPE4.
* Limits: 32-bit relocations in the code and data only, no
  forwarders, no bound imports, no delay load, no version info.

# NE - 16-bit DPMI executable

See also DOC\DLL.MD (DLLs, definition file, resources).

`rlink ne /o=NAME.EXE A.RDF B.RDF` links rdf files into a New
Executable (see DOC\NE.MD) with the HX-DOS Extender stub
(DPMIST16.BIN). It is a 16-bit protected mode program: run it
with `DPMILD16.EXE` and a DPMI host (HDPMI16) from HX-DOS
Extender on the PATH. Tested with HX DPMILD16 + HDPMI16, see
TEST\NE and TEST\NEDLL (CHECK.BAT builds the tests and
compares the result with the reference files with FC).

* Large memory model: each rdf gets its own code segment and its
  own data segment (an empty one is skipped). The bss of all
  rdf and the stack (`/s`, KB, default 8) are in one last data
  segment, which is DS and SS at start-up.
* The entry-point (`/entry`, default `start`) is CS:IP.
* Segment values (`seg label`, `dw label, seg label`) and
  offsets of other segments become NE relocations (BASE, OFFS,
  PTR); a far pointer is one PTR relocation.
* Only 16-bit relocations. A near (relative) reference to a
  symbol in another segment is an error, use far calls. The
  code and the data of one rdf are each limited to 64 KB.
* Imports from DLL: `extern MODULE_ORDINAL` (for example
  `extern KERNEL_91`) is an import of the module by ordinal;
  `KERNEL_INITTASK` is a name for KERNEL.91, which Borland
  Pascal programs call first. Any other symbol must be exported
  by one of the rdf.
* Definition file: `/def=FILE` (`;` starts a comment). Supported
  statements: `NAME [name] [WINDOWAPI|WINDOWCOMPAT|
  NOTWINDOWCOMPAT]`, `LIBRARY [name] [INITGLOBAL|INITINSTANCE]`,
  `DESCRIPTION 'text'`, `EXETYPE OS2|WINDOWS|DOS4|UNKNOWN
  [major.minor]`, `PROTMODE`, `REALMODE`, `HEAPSIZE n`,
  `STACKSIZE n`, `STUB 'file'` (own DOS stub instead of the
  builtin one), `CODE attrs`, `DATA [NONE|SINGLE|MULTIPLE]
  attrs` (attributes: PRELOAD LOADONCALL MOVEABLE FIXED
  DISCARDABLE NONDISCARDABLE SHARED NONSHARED PURE IMPURE
  EXECUTEONLY EXECUTEREAD READONLY READWRITE IOPL NOIOPL
  CONFORMING NONCONFORMING), `SEGMENTS` (`name [CLASS 'CODE'|
  'DATA'] attrs`, the name is the name of the rdf file without
  extension), `EXPORTS`, `IMPORTS`, `OLD` (ignored).
  Targets other than OS2 may be refused by the loader (HX
  DPMILD16 does not run EXETYPE WINDOWS).
* Exports: one line per export `[entryname=]symbol [@ordinal]
  [RESIDENTNAME] [NONAME] [NODATA] [parmwords]`. The symbol must
  be a global of a code segment. Names go to the nonresident
  names table (to the resident one with RESIDENTNAME), entries
  to the entry table (moveable entries, unused ordinals are
  skipped), NONAME needs an ordinal.
* Imports: `[internal=]module.entry`, entry is a name or an
  ordinal. `extern internal` in the rdf is resolved to that
  import (by name or by ordinal). Without IMPORTS the form
  `extern MODULE_ORDINAL` is used.
* DLL: `LIBRARY name` instead of `NAME` in the definition file
  makes a DLL (single shared data segment, no stack). The entry
  point (`start`) is the initialization routine: a far
  procedure that returns AX nonzero. An exe imports it by
  ordinal (`extern MYLIB_1`, the module name is the name of the
  `.DLL` file). See TEST\NEDLL.
* Resources: `/res=FILE.RES` adds the resources of a 16-bit
  `.RES` file (the output of a resource compiler). They are
  grouped by type, file offsets and sizes in the resource table
  are in 256-byte units. 32-bit `.RES` files are not supported.
  TEST\NE\R01.ASM builds a small `.RES` with NASM (`-f bin`).

# QLB - QuickBASIC Quick Library

`rlink qlb /o=NAME.QLB A.RDF B.RDF` links rdf files into a Quick
Library for QuickBASIC 4.5 (`QB /L NAME.QLB`). It was tested
with QuickBASIC 4.0 and 4.50 (`QB.EXE`); QBasic (`QBASIC.EXE`,
MS-DOS 5/6) is a different product and does not load Quick
Libraries (no `/L` option). The library is standalone: no
`BQLB45.LIB` or Microsoft linker is needed. See TEST\QLB for an
example, DOC\QLB.MD for the format description and DOC\QLBRT.MD
for what QuickBASIC requires.

* Every module from the command line is linked (not only modules
  reachable from the entry-point). Each rdf gets its own code,
  data and bss segment, as in MZL.
* All exported symbols from code segment go into the library,
  and BASIC finds them by name (`DECLARE SUB name ()` / `CALL
  name`), names are case-insensitive. Use A-Z, 0-9 and `_`.
* RLINK adds a small precompiled runtime (SRC\QBRT.ASM, source
  of the table in RLOQBE.PAS), which QuickBASIC calls through
  `b_ULVars`. Selector `0Ah` (find procedure) is solved by the
  runtime with a hash code table and the names, created by RLINK
  and kept after the runtime code, selector `10h` (find common)
  is handled by the runtime too. For all other selectors
  (start-up, shut-down, ...) the runtime calls the entry-point
  (`/entry`, default `start`), so the entry-point is the
  start-up/shut-down hook. It is a Pascal style far procedure:
  the selector is the word parameter on the stack, the procedure
  removes it (`retf 2`), the selector is also in CX. Without any
  work to do the entry-point is just `retf 2`.
* Names. The CODE table of the QB header lists every exported
  name in the spelling of the object (`/nonames` leaves it
  empty). The runtime of the library finds a routine like the
  runtime of Microsoft's libraries: QuickBASIC sends the name as
  written and, for a `CDECL` declaration, the flag `DX = 0040h`;
  the runtime then looks for `_` + name (`DECLARE FUNCTION foo
  CDECL` finds the symbol `_foo`). It also frees the temporary
  string that holds the name (service 26 of QuickBASIC),
  otherwise QuickBASIC hangs after a dozen lookups. See
  DOC\QLBRT.MD.
* Imports. A module may `extern` the names of QuickBASIC itself:
  services (`B$RUNERR`, `B$STDALC` ...) and variables
  (`b_errnum`, `b_ULSymSeg` ...). RLINK resolves them with
  thunks and offsets in the QB data segment, nothing else is
  needed. The list and the rules are in DOC\QLB-IMP.MD (section
  9), the test is TEST\QLB\IMPORT.ASM.
* Only 16-bit relocations. Library data is mapped into
  QuickBASIC data segment at offset 3360h, the library is built
  for the QuickBASIC 4.5 (QB.EXE) layout.
* TEST/QLB21: prototype that loads a QLB from a DOS program with
  INT 21h AH=4Bh AL=01h (see DOC/QLB21.MD).
* Size: every RDF is its own segment set, so the code, data and
  bss of one RDF are each limited to 64 KB; the library as a
  whole can be larger (up to about 1 MB). Tested: 80 KB library
  of two 40 KB modules in QuickBASIC 4.50.
# How to use

See MAKEFILE in TEST directory.

# Dependencies

Requires System2 library:

https://github.com/DosWorld/libsystem2

# Build

You need Turbo Pascal, System2 library and "make" in path.
Just type:

        cd src
        make

# License

NASM version 0.98.39 binaries distributed with own different license
and copyright-holders (see DOC\NASMLIC.TXT, GNU LGPL).

MIT License
