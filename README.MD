# RTools

This is MS-DOS tools for linking `RDF`/`RDL` files.
While playing with small compilers, I noticed one problem for all beginners.
It lacks runtime-libraries and linkers support.

I researched the OBJ/OMF format and found it too complicated.
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

rlink output formats:
* com - simple MS-DOS .com file
* mzs - MS-DOS exe, small memory model (CS = code, DS = data,bss,stack)
* mzl - MS-DOS exe, large memory model (each rdf have own CS, DS and BSS segment)
* adam - DOS32 Extender.
* dospe - PE32 with linked HX-DOS Extender loader (stub).
* rdf - Linked rdf into one segment (like a .com, but with zero offset and name). Could be used as DLL.

If you need viewer for RDF, please visit to https://github.com/DosWorld/objview

"Make" utility available at https://github.com/DosWorld/smallmake

# How to use

See MAKEFILE in TEST directory.

# Dependencies

Requires System2 library:

https://github.com/DosWorld/libsystem2

# Build

You need Turbo Pascal and "make" in path.
Just type:

        cd src
        make

# License

NASM version 0.98.39 binaries distributed with own different license
and copyright-holders (see DOC\NASMLIC.TXT, GNU LGPL).

MIT License