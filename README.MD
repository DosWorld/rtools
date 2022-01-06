# RTools

This is MS-DOS tools for linking `RDF`/`RDL` files.
While playing with small compilers, I noticed one problem for all beginners.
It lacks runtime-libraries and linkers support.

I researched the `OBJ / OMF` format and found it too complicated.
`AOUTB` has no segment support. `COFF` and `ELF` are also complex and solve
problems not relevant to MS-DOS.

By chance I came across the `RDOFF2` format from NASM - a
beautiful and simple format for object modules.

This repository contains tools for working with `RDOFF2` (and source code)
to help you build small compilers.

`RDF` - NASM builtin format `RDOFF2` for object files. Different version of
Nasm works different with this files. So, I strongly advise to use
`NASM version 0.98.39`.

`RDL` - Again, NASM format but for libraries.

* `rdump` - dump utility
* `rlib` - library manager
* `rlink` - link multiple RDF/RDL into single `fat RDF` (with resolved
all dependencies). `rlink` is "optimized linker" - remove all unused
imports and link required symbols only. Also, segment of entry-point
symbol will be linked first (at segments begin).
* `rexe` - converter from `fat RDF` to MS-DOS `.EXE` (small memory model, CS=code,
DS=SS=data+bss+stack) or `.COM` (tiny memory model CS=DS=SS=code+data+bss+stack).
For `.COM` file, in case when entry point is not first byte - will be generated
code 0xE9, 0x??, 0x??, 0x90 for `jmp` to entry-point.
* `nasm` - version `0.98.39`, just recompiled for MS-DOS (no DPMI) with RDF support
(by default - is disabled). No other changes.

I call `fat RDF` similary as named `fat JAR` from Java-world. For example you
have `jar` with your web application (pages and classes), so `fat jar` will
contains your web application, database drivers classes and web-server (like
Tomcat) classes.

If you need viewer for RDF, please visit to https://github.com/DosWorld/objview

`Make` utility available at https://github.com/DosWorld/smallmake

# How to use

At first, you need a few assembler source.

`boot.asm`:

      bits 16
      global start
      section .text
      extern _main
      start:
          mov  ax, seg params
          mov  ds, ax
          mov  es, ax
          cld
          call _main
          mov  ah, 0x4c
          int  0x21
      section .data
      params:

and `code.asm`:
  
      bits 16
      global _main
      section .text
      _main:
             mov  dx, msg
             mov  ah, 9
             int  0x21
             ret
      section .data
      msg:   db  'Hello world$'

Now it is time to compile it:

      nasm -f rdf boot.asm -o boot.rdf
      nasm -f rdf code.asm -o code.rdf

Now, put `boot.rdf` into library `mylib.rdl`:

      rlib /c mylib.rdl
      rlib /a mylib.rdl boot.rdf boot

Link them to `out.rdf`:

      rlink code.rdf mylib.rdl -o out.rdf

and create executable: 

     rexe out.rdf

So, now, you have `out.exe` 

# Build

You need Turbo Pascal and `make` in path.
Just type:

        cd src
        make

# License

NASM version 0.98.39 binaries distributed with own different license
and copyright-holders (see DOC\NASMLIC.TXT, GNU LGPL).

MIT License

