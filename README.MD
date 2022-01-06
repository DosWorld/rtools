# RTools

This is MS-DOS tools for linking RDF/RDL files.
While playing with small compilers, I noticed one problem for all beginners.
It lacks runtime-libraries and linkers support.

I researched the OBJ / OMF format and found it too complicated.
AOUTB has no segment support. COFF and ELF are also complex and solve
problems not relevant to MS-DOS.

By chance I came across the RDOFF2 format from NASM - a
beautiful and simple format for object modules.

This repository contains tools for working with RDOFF2 (and source code)
to help you build small compilers.

RDF - NASM builtin format "RDOFF2" for object files. Different version of
Nasm works different with this files. So, I strongly advise to use
"NASM version 0.98.39".

RDL - Again, NASM format but for libraries.

* rdump - dump utility
* rlib - library manager
* rlink - link multiple RDF/RDL into single "fat RDF" (with resolved all dependencies).
* rexe - converter from "fat RDF" to MS-DOS .EXE (small memory model, CS=code, DS=SS=data+bss+stack)
or .COM (tiny memory model CS=DS=SS=code+data+bss+stack).
* nasm - version 0.98.39, just recompiled for MS-DOS (no DPMI) with RDF support (by default - is disabled).

I call "fat RDF" by analogy, as "fat JAR" from Java-world.

If you need viewer for RDF, please visit to https://github.com/DosWorld/objview

'Make' utility available at https://github.com/DosWorld/smallmake

# Build

You need Turbo Pascal and 'make' in path.
Just type:

        cd src
        make

# License

NASM version 0.98.39 binaries distributed with own license and copyright-holders (see DOC\NASMLIC.TXT, GNU LGPL).

MIT License

