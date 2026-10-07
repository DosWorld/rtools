# RDF loaders

Small MS-DOS programs that load and run RDOFF2 (`.RDF`) files made by
NASM 0.98.39 and linked by [RLINK](../README.MD). The loaders are
written in NASM assembly, the sources have no EXE headers: they are
assembled to `.RDF` and linked to tiny EXE files by `rlink mzt`.

| File          | What it is                                              |
|---------------|---------------------------------------------------------|
| `RDFLDR.EXE`  | loader for 16-bit programs, real mode, 8086 only        |
| `RDFLD16.EXE` | loader for 16-bit programs, 16-bit DPMI host, 286 code  |
| `RDFLD32.EXE` | loader for 32-bit programs, 32-bit DPMI host            |
| `RDFEXEC.EXE` | resident program: runs RDF files through one of them   |

Every loader works in two ways:

* as a **stub**: append an RDF to the EXE and get a normal DOS program;
* as a **command**: `RDFLD16 prog.rdf [arguments]`.

## Contents

* [Quick start](#quick-start)
* [Entry point](#entry-point)
* [Modules and libraries](#modules-and-libraries)
* [DPMI host](#dpmi-host)
* [Long file names](#long-file-names)
* [Borland DPMI host](#borland-dpmi-host-rtm)
* [Limits](#limits)
* [RDFEXEC](#rdfexec)
* [Building](#building)
* [License](#license)

## Quick start

Append the linked RDF to a stub:

```
nasm -f rdf hello.asm -o hello.rdf
rlink rdf /o=prog.rdf hello.rdf
copy /b RDFLD32.EXE+PROG.RDF HELLO.EXE
```

`HELLO.EXE` is a normal DOS program: on start it opens itself, finds
the RDF after the end of the EXE image (the size comes from the MZ
header) and loads it. The command line of `HELLO.EXE` is left in the
PSP for the program.

If nothing is appended, the stub works as a loader:

```
RDFLD32 prog.rdf
```

## Entry point

The loader looks for the exported (`GLOBAL`) name `start` in all loaded
modules, the main one first. If there is no `start`, the program begins
at offset 0 of the code segment.

```
global start
start:
```

**32-bit** (`RDFLD32`): CS, DS, ES and SS have base 0 and limit 4 GB
(flat model). `EAX` = linear address of the code, `EBX` = linear address
of the PSP (command tail at +80h), `ESP` = top of a 64 KB stack,
`[ESP]` = return address: `RET` ends the program (exit code 0).

**16-bit** (`RDFLD16`): called with a far call, `RETF` ends the program
(exit code 0). CS = code, DS = SS = data (`SP` = FFF0h), ES = PSP
selector (command tail at `ES:80h`). Code and data are limited to 64 KB
each.

**Real mode** (`RDFLDR`): the same as 16-bit, but the segments are real
segments, `SEGRELO` adds the segment value. No DPMI host is needed, only
8086 instructions are used. Every module gets its own DOS memory blocks
(code, and data+bss); the main module has a 64 KB data segment,
DS = SS = data, `SP` = FFF0h, ES = PSP.

## Modules and libraries

A `library name` (DLL) record loads another RDF file from the directory
of the main file (`.RDF` is added if the name has no extension). That
file is a separate file, it is not embedded. `IMPORT` records are
resolved with the `GLOBAL` records of all loaded modules. Up to 16
modules.

`main.asm` (16-bit):

```
bits 16
library mylib
extern libmsg
extern libfn
segment .text
global start
start:
    mov ax, seg libmsg
    mov ds, ax
    mov dx, libmsg
    mov ah, 9
    int 21h
    call far libfn
    retf
```

`mylib.asm`:

```
bits 16
segment .text
global libfn
libfn:
    mov ah, 9
    mov dx, m2
    int 21h
    retf
segment .data
global libmsg
libmsg db "libmsg", 13, 10, "$"
m2 db "libfn", 13, 10, "$"
```

Build and run (`RDFLD16` or `RDFLDR`; `RDFLD32` is the same, with 32-bit
code and without `seg`):

```
nasm -f rdf main.asm -o main.rdf
nasm -f rdf mylib.asm -o mylib.rdf
copy /b RDFLD16.EXE+MAIN.RDF MAIN.EXE
MAIN
```

`library mylib` puts a DLL record into `MAIN.RDF`; the loader reads
`MYLIB.RDF` from the directory of `MAIN.EXE`. The name in `library` has
no path.

## DPMI host

Nothing is built in. `RDFLD16` and `RDFLD32` use a DPMI host that is
already running. Otherwise `HDPMI32.EXE` (`RDFLD32`) or `HDPMI16.EXE`
(`RDFLD16`) is searched in the directory of the EXE, then in `PATH`, and
started. The HX files are not distributed here. `RDFLDR` needs no host.

## Long file names

When DOS has the LFN API (Windows 9x, DOSBox-X with `lfn=true` and
`ver 7.x`) the loaders open files with `INT 21h AX=716Ch`, so long names
work for the RDF file, for the EXE with an appended RDF, and for
libraries:

```
RDFLD16 "My Long Program Name.rdf"
"Long Stub Program.exe"
```

A file name with spaces must be in double quotes on the command line.
Without the LFN API (plain DOS) the loaders use the usual open
(`AH=3Dh`), so only 8.3 names work. Paths up to 260 characters. If the
LFN open fails for any reason, the old open is tried once more.

## Borland DPMI host (RTM)

`RDFLD16` also runs under the DPMI server from Borland Pascal 7
(`RTM.EXE`, `DPMI16BI.OVL`, `RTMRES.EXE`). These files are not
distributed here. The loader does not start the server, preload it with
`RTMRES`, it starts a DOS shell:

```
set RTM=EXTMAX 8192
RTMRES
MAIN.EXE
exit
```

`RTMRES` can also start one command: `RTMRES COMMAND.COM /C T.BAT`.
Without a large enough `RTM=EXTMAX` the loader can report "not enough
memory" (each module needs a 64 KB data block). Tested this way with
`RDFLD16` (single module, and a module with a library) on an emulated
386. The Borland server did not start under an emulated 286 in DOSBox-X,
so `RDFLD16` was not run in protected mode on a 286. `RDFLD32` needs a
32-bit host (not RTM).

## Limits

* `SEGRELO` (record 6) works in the 16-bit loaders only. `FARIMPORT`
  (record 7) is not supported. The 32-bit loader reports "unsupported
  record".
* Relative references are allowed only inside one segment.
* Code and data+bss of a module must be below 64 KB (16-bit loaders).
* Up to 16 modules.

## RDFEXEC

```
RDFEXEC [-q] [-u] [loader.exe]
```

`RDFEXEC.EXE` is a TSR. It hooks `INT 21h` function 4B00h (EXEC).
When a program is started, the first 6 bytes of the file are checked:
if they are `RDOFF2`, the file is an RDF and it is started through
a loader as

```
loader.exe "file" tail
```

Any other file (EXE, COM, drivers, the DPMI host started by a loader) is
executed as usual. The extension is not checked, so the RDF may be named
`.EXE`, `.COM` or `.RDF`. The caller sees a normal EXEC: the exit code,
the registers and the carry flag are returned as for any other program.
Nested starts (an RDF program starts another RDF) work, 8 levels.

On install the environment block of RDFEXEC is released, only the code
and the buffers (about 2.3 KB) stay in memory.

```
RDFEXEC                  loader RDFLDR.EXE (real mode)
RDFEXEC RDFLD16.EXE      16-bit protected mode
RDFEXEC RDFLD32.EXE      32-bit protected mode
RDFEXEC C:\TOOLS\RDFLD32.EXE
```

A loader name without a path is looked up in the directory of
`RDFEXEC.EXE`. The path is converted to a full name at install time, so
it does not depend on the current directory. If the loader is not found,
nothing is installed.

| Option | Meaning                                                      |
|--------|--------------------------------------------------------------|
| `-q`   | do not print the message                                     |
| `-u`   | uninstall (only if no program hooked `INT 21h` after it)     |

Only one loader is active: an RDF file does not say whether it is a real
mode, 16-bit or 32-bit program, so the mode is chosen when RDFEXEC is
installed. To change it run `RDFEXEC -u` and install it again.

```
RDFEXEC RDFLD16.EXE
copy HELLO.RDF HELLO.EXE
HELLO arg1 arg2
```

The command interpreter runs only `.COM`, `.EXE` and `.BAT` files, so an
RDF with another extension (`HELLO.RDF`) cannot be typed at the prompt.
Programs that call EXEC themselves (make, shells, IDEs, batch tools) can
start it by the `.RDF` name. Without RDFEXEC, DOS would execute such a
file as a COM program, so install RDFEXEC before such calls.

Libraries (DLL records) are searched in the directory of the RDF file.
Long file names work (the name is passed in quotes). A command tail that
does not fit into the DOS limit of 126 characters together with the file
name is not handled: the file is executed as usual.

## Building

Needs NASM 0.98.39 (other versions write a different RDF) and RLINK
with the `mzt` format (`..\BIN`). `MAKE.BAT` does everything:

```
nasm -f rdf RDFLD32.ASM
rlink mzt /o=RDFLD32.EXE RDFLD32.RDF
nasm -f rdf RDFLD16.ASM
rlink mzt /o=RDFLD16.EXE RDFLD16.RDF
nasm -f rdf RDFLDR.ASM
rlink mzt /o=RDFLDR.EXE RDFLDR.RDF
nasm -f rdf RDFEXEC.ASM
rlink mzt /o=RDFEXEC.EXE RDFEXEC.RDF
```

The paths of the tools can be set with the `NASM` and `RLINK`
environment variables.

Sources: `RDFLD32.ASM`, `RDFLD16.ASM`, `RDFLDRM.INC` (the part shared by
the two DPMI loaders), `RDFLDR.ASM` (real mode), `RDFEXEC.ASM`.

## License

Copyright (c) 2026 Viacheslav Komenda

This is free and unencumbered software released into the public domain
([The Unlicense](https://unlicense.org/)). See the file `UNLICENSE`.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any means.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
