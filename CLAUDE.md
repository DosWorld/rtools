# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

RTools: MS-DOS tools for linking NASM RDOFF2 object files (`.RDF`) and libraries (`.RDL`) — RLINK, RLIB, RDFDUMP, BIN2RDF. Tools in `SRC/` are Turbo Pascal; tests are NASM assembly; `EXAMPLES/RDFLOAD/` has RDF loader ports in Turbo Pascal (`TP/`) and C (`C/`).

## Build and test

- Build is DOS-only (run under DOSBox-X or similar, not natively on macOS): `cd SRC && make`. Needs `TPC`, the System2 library (https://github.com/DosWorld/libsystem2) and a DOS `make` (`BIN/MAKE.EXE`).
- `make install` overwrites the committed `BIN/*.EXE` binaries; `make clean` deletes `*.TPU`, `*.EXE`, `*.BAK`.
- C example: `wcl -ml main.c rdfload.c` (Open Watcom, 16-bit large model) plus `nasm -f rdf test.asm`. TP example: `tpc /m main.pas`.
- There is no automated test runner or CI. Each `TEST/<FMT>/` directory has a MAKEFILE that runs `nasm -f rdf` then `..\..\BIN\RLINK <fmt> /o=OUT T01.RDF T02.RDF`; run `make` there under DOS and run or inspect the output. These makefiles double as usage examples.

## Conventions and gotchas

- Use NASM 0.98.39 only (`BIN/NASM.EXE`); other NASM versions handle RDF differently.
- All files are ASCII with CRLF line endings — preserve CRLF when editing or creating files. Filenames are 8.3 uppercase.
- Pascal files: `{ MIT License ... }` header, then `{$I+,A+,R-,S-,O-,F-,D-,L-,Q-,F-,G-}`, then `UNIT X; INTERFACE; USES System2;`. Uppercase keywords.
- Makefiles in `SRC/` and `TEST/` use tabs; those in `EXAMPLES/` use spaces.
- RDF is little-endian; format spec is in `DOC/RDOFF2.TXT`.

## QLB output (rlink qlb, SRC/RLOQBE.PAS)

- Runtime bytes in RLOQBE.PAS (QB_RT) are the assembled SRC/QBRT.ASM (`nasm -f bin`); the offsets QB_RT_* must match the listing. The linker appends the hash table and the name entries after them (the CODE table of the QB block is empty); QbeRuntimeParas(n_code, names_size) must give the final size, QbeFinish checks it.
- Layout and QB loader facts are in DOC/QLB.MD; the QB loader checks are strict (segment table NULL/_DATA/BC_SAB/STACK/SYMBOL, b_ULVars 0x13 signature, relocated header words). Test with TEST/QLB and `QB.EXE /L HELLO.QLB /RUN HELLO.BAS`.
- Selectors >= 8 are called by QB with one argument: runtime must return with `retf 2`, otherwise QB hangs.
- `/entry` is called Pascal style (selector pushed as word parameter and in CX, procedure ends with `retf 2`).

