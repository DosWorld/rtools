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

# RLINK

RLINK support EMS/XMS memory or can work with temporary files.
So, don't be confused with dos 16-bit application - RLINK known how to handle more then 64kb and 640kb :).

## Supported output formats

* COM - simple MS-DOS .com file
* MZS - MS-DOS exe, small memory model (CS = code, DS = data,bss,stack)
* MZL - MS-DOS exe, large memory model (each rdf have own CS, DS and BSS segment)
* ADAM - DOS32 Extender.
* LX - OS/2 and DPMI exe file.
* PE - DOS PE32 file (PE32 without imports).
* RDF - Linked rdf into one code-segment (like a .com, but with zero offset and name). Could be used as DLL.
If you load code segment at ????:0000 - you don't need process relocations. And, as bonus, you can use symbol table.

## Buitin stubs and extenders

* Simple stub (will write something like "This is dpmi exe!"). Can be used with HX-DOS Extender or with LX format
 (if you want bind other DOS-Extender).
* Loader DOS32 Extender (for ADAM)
* ZRDX DOS-Extender (for LX)
* Loader HX-DOS Extender (for PE).

If you need viewer for RDF, please visit to https://github.com/DosWorld/objview

"Make" utility available at https://github.com/DosWorld/smallmake

## Memory usage

Memory using strategy could be setted with /emem=<v> parameter:

|---------|--------------------------------------------------------|
| /emem=0 | Use temporary files, 16k buffer in conventional memory |
| /emem=1 | Use temporary files, 16k buffer + cache in EMS/XMS     |
| /emem=2 | No temporary files, image will be build in EMS/XMS     |
|---------|--------------------------------------------------------|

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