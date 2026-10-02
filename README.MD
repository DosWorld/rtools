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
* rlib - library manager
* rlink - linker itself

# RLINK

RLINK can generate huge files. To speed up RLINK - point your TMP/TEMP directory to ramdrive.
So, don't be confused with dos 16-bit application - RLINK known how to handle more then 64kb and 640kb :).

## Supported output formats

* COM - simple MS-DOS .com file
* MZS - MS-DOS exe, small memory model (CS = code, DS = data,bss,stack)
* MZL - MS-DOS exe, large memory model (each rdf have own CS, DS and BSS segment)
* ADAM - DOS32 Extender.
* LX - OS/2 and DPMI exe file.
* PE - DOS PE32 file (PE32 without imports).
* QLB - QuickBASIC Quick Library (`.QLB`), large memory model, see below.
* RDF - Linked rdf into one code-segment (like a .com, but with zero offset and name). Could be used as DLL.
If you load code segment at ????:0000 - you don't need process relocations. And, as bonus, you can use symbol table.

## Builtin stubs and extenders

* Simple stub (will write something like "This is dpmi exe!"). Can be used with HX-DOS Extender or with LX format
 (if you want bind other DOS-Extender).
* Loader DOS32 Extender (for ADAM)
* ZRDX DOS-Extender (for LX)
* Loader HX-DOS Extender (for PE).

If you need viewer for RDF, please visit to https://github.com/DosWorld/objview

"Make" utility available at https://github.com/DosWorld/smallmake

# QLB - QuickBASIC Quick Library

`rlink qlb /o=NAME.QLB A.RDF B.RDF` links rdf files into a Quick Library for QuickBASIC 4.5
(`QB /L NAME.QLB`). It was tested with QuickBASIC 4.0 and 4.50 (`QB.EXE`); QBasic (`QBASIC.EXE`, MS-DOS 5/6)
is a different product and does not load Quick Libraries (no `/L` option). The library is standalone: no `BQLB45.LIB` or Microsoft linker is needed.
See TEST\QLB for an example, DOC\QLB.MD for the format description and DOC\QLBRT.MD for what QuickBASIC requires.

* Every module from the command line is linked (not only modules reachable from the entry-point).
  Each rdf gets its own code, data and bss segment, as in MZL.
* All exported symbols from code segment go into the library, and BASIC finds them by name
  (`DECLARE SUB name ()` / `CALL name`), names are case-insensitive. Use A-Z, 0-9 and `_`.
* RLINK adds a small precompiled runtime (SRC\QBRT.ASM, source of the table in RLOQBE.PAS),
  which QuickBASIC calls through `b_ULVars`. Selector `0Ah` (find procedure) is solved by the runtime
  with a hash code table and the names, created by RLINK and kept after the runtime code (the CODE
  table of the QB header is empty), selector `10h` (find common) is handled by the runtime too. For all other selectors
  (start-up, shut-down, ...) the runtime calls the entry-point (`/entry`, default `start`), so the
  entry-point is the start-up/shut-down hook. It is a Pascal style far procedure: the selector is
  the word parameter on the stack, the procedure removes it (`retf 2`), the selector is also in CX.
  Without any work to do the entry-point is just `retf 2`.
* Only 16-bit relocations. Library data is mapped into QuickBASIC data segment at offset 3360h,
  the library is built for the QuickBASIC 4.5 (QB.EXE) layout.

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
