# DLL, imports, exports and resources

How to make NE and PE files with `rlink`, which use or
provide functions of DLLs and carry resources. The format of
the definition file (`.DEF`) is described in one place, in
section 3, and is used by `ne`, `winpe` and `dospe`.

## 1. Which command makes what

* `rlink ne`: NE exe or DLL, 16-bit, protected mode. Loader:
  HX DPMILD16.
* `rlink winpe`: PE32 exe or DLL for Win32. Loader: Windows or
  HX DPMILD32.
* `rlink dospe`: PE32 exe or DLL, DOS style. Loader: HX
  DPMILD32.

`dospe` writes a DOS PE program (INT 21h, DPMI) with the same
code as `winpe`: the file may import from DLLs, export and
carry resources.

Other formats (`le`, `adam`, `mzs`, `mzl`, `com`, `rdf`) have
no tables for DLLs.

Options of these commands:

* `/o=FILE` - output file (exe or dll, any name).
* `/def=FILE` - definition file (section 3).
* `/res=FILE.RES` - resources: a 16-bit `.RES` for `ne`, a
  32-bit `.RES` for `winpe` and `dospe`.
* `/entry=NAME` - entry-point symbol, default `start`.
* `/s=KB` - stack size, default 8 (a DLL has no stack).
* `/hx` - `dospe`: bind the HX DOS Extender stub (`winpe`
  always writes the standard Windows stub; run its files under
  HX with `DPMILD32 NAME.EXE`).

The entry-point symbol must exist (also for a DLL). All rdf
files of the command line are linked into a DLL (and into an
NE file with exports), for an exe only the modules reachable
from the entry-point.

## 2. Quick start

### 2.1 Win32 DLL and a program that uses it

`MYDLL.ASM` (`TEST\WINPE\T02.ASM`):

```nasm
bits 32
global start
global hello
global answer
extern GetStdHandle
extern WriteFile
section .text
start:                      ; DllMain, stdcall, 3 args
        mov     eax, 1
        ret     12
hello:
        push    -11
        call    GetStdHandle
        push    0
        push    written
        push    msglen
        push    msg
        push    eax
        call    WriteFile
        ret
answer:
        mov     eax, 42
        ret
section .data
msg:    db      'WinPE dll hello', 13, 10
msglen  equ     $ - msg
section .bss
written: resd   1
```

`MYDLL.DEF`:

```
LIBRARY MYDLL
EXPORTS
hello @1
answer @5
IMPORTS
KERNEL32.GetStdHandle
KERNEL32.WriteFile
```

```
nasm -f rdf mydll.asm
rlink winpe /def=mydll.def /o=MYDLL.DLL mydll.rdf
```

The program that calls it, `T03.DEF`:

```
NAME T03
IMPORTS
MYDLL.hello
MYDLL.answer
ansord=MYDLL.5
KERNEL32.ExitProcess
```

In the assembler the program only declares `extern hello`,
`extern answer`, `extern ansord`, `extern ExitProcess` and
uses `call hello`. `ansord` is the same function as `answer`,
imported by ordinal 5. Link it with
`rlink winpe /def=t03.def /o=T03.EXE t03.rdf`; `MYDLL.DLL`
must be in the current directory or on the PATH of the loader.

For a DOS PE program (INT 21h) use `dospe /hx` instead of
`winpe` (`TEST\DOSPE4`). The DLL itself is made with `winpe`.

### 2.2 NE DLL and a program that uses it

`T06.ASM` (`TEST\NEDLL`), 16-bit, the DLL:

```nasm
        bits 16
        cpu 8086
        global  start
        global  hello
        segment .text
start:                      ; init, far, AX nonzero = ok
        mov     ax, 1
        retf
hello:
        push    ds
        mov     ax, seg msg
        mov     ds, ax
        mov     dx, msg
        mov     ah, 9
        int     21h
        pop     ds
        retf
        segment .data
msg:    db      'NE dll hello', 13, 10, '$'
```

`T06.DEF`:

```
LIBRARY MYLIB
DESCRIPTION 'NE DLL test'
EXPORTS
hello @1
```

```
rlink ne /def=t06.def /o=MYLIB.DLL t06.rdf
```

The program (`T07.ASM`) calls the function with a far call.
The name `MYLIB_1` is: module `MYLIB`, ordinal 1.

```nasm
        extern  MYLIB_1
        ...
        call    far MYLIB_1
```

```
rlink ne /o=T07.EXE t07.rdf
```

The `.DEF` of the program (`T07.DEF`) declares the import:

```
IMPORTS
MYLIB_1=MYLIB.1
```

An import by name looks like this:

```
IMPORTS
myhello=MYLIB.hello
```

with `extern myhello` in the assembler (`TEST\NEDLL\T11`).

### 2.3 What the loader does

* NE: the module name of an import is the name of the `.DLL`
  file without extension, the loader looks for it in the
  directory of the program and on the PATH. The functions
  are far, so the call is `call far`. Segment values and far
  pointers are relocated by the loader.
* PE: the import table has the name of the DLL
  (`MODULE.DLL`). Every import has a slot in the data
  section, which the loader fills.

## 3. The definition file

A text file, one statement per line. `;` starts a comment.
Keywords and options are not case sensitive; names of
symbols are. One file may have all statements; a command
uses its own and accepts and ignores the others.

Statements (NE = used by `ne`, PE = used by `winpe` and
`dospe`):

* `NAME [name] [apptype]` - NE, PE.
* `LIBRARY [name] [INITGLOBAL|INITINSTANCE]` - NE, PE (a DLL).
* `DESCRIPTION 'text'` - NE.
* `EXETYPE OS2|WINDOWS|DOS4|UNKNOWN [x.y]` - NE.
* `PROTMODE`, `REALMODE` - NE.
* `HEAPSIZE n`, `STACKSIZE n` - NE, PE.
* `STUB 'file'` - NE.
* `CODE attrs`, `DATA [kind] attrs`, `SEGMENTS` - NE.
* `EXPORTS`, `IMPORTS` - NE, PE.
* `OLD 'file'` - accepted and ignored.

### 3.1 NAME and LIBRARY

`NAME T03 WINDOWAPI` makes a program, `LIBRARY MYDLL` makes a
DLL. The name is the module name (NE) or the name written in
the export table (PE, `MYDLL.DLL`); without it the name of
the output file is used. The application type is
`WINDOWAPI`, `WINDOWCOMPAT` or `NOTWINDOWCOMPAT`. In PE
`WINDOWAPI` is the GUI subsystem, all others and no type
give the console subsystem. In NE `LIBRARY ... INITGLOBAL`
sets the flag "global initialization".

A DLL (NE and PE) has no stack, `STACKSIZE` is ignored.

### 3.2 Exports

After `EXPORTS` every line is:

```
[entryname=]symbol [@ordinal] [RESIDENTNAME]
        [NONAME] [NODATA] [parmwords]
```

* `symbol` is a global symbol of an rdf file. In NE it must
  be in the code segment, in PE it may be in code or data.
  `entryname=symbol` exports it under another name.
* `@ordinal`, 1..2048. Without it a free number is used.
* `NONAME` exports by ordinal only, the ordinal is needed.
* NE: the name goes to the nonresident names table;
  `RESIDENTNAME` puts it into the resident one.
  `NODATA` clears the "single data" flag of the entry;
  `parmwords` (0..31) is the number of words of parameters.
* PE: `RESIDENTNAME`, `NODATA`, `PRIVATE`, `DATA`, `CONSTANT`
  and `parmwords` are accepted and ignored. The names in the
  export table are sorted as the loader requires. An export
  `name=module.function` (or `name=module.#ordinal`), whose
  right side contains a dot, is a forwarder: RLINK imports
  the function and exports a small `jmp [slot]` thunk under
  `name`. The thunk works with every loader; the real PE
  forwarder (a string in the export table) is not used,
  because the HX loader does not resolve it.
* At most 200 exports.

### 3.3 Imports

After `IMPORTS` every line is:

```
[internal=]module.entry
```

`entry` is the name of the function or its ordinal. The
module is the part before the last dot; a `.DLL` extension
of the module is accepted and ignored.
`internal` is the name that the rdf files use in `extern`;
without it `internal` is the name `entry` (for an ordinal
the internal name is required). At most 100 imports.

* PE: `extern internal` is resolved to a small thunk
  `jmp [slot]` made by RLINK, so `call internal` works.
  The slot itself is `__imp_internal`, which gives
  `call [__imp_internal]`. Only imports that are used by the
  code are written.
* NE: `extern internal` is a far pointer to the function.
  Every import must be declared in `IMPORTS` (for an import by
  ordinal write `MYLIB_1=MYLIB.1`); only `KERNEL_INITTASK`
  (`KERNEL.91`) is known without it. A symbol that is neither
  defined nor imported is an error. At most 16 modules.

### 3.4 Sizes

`HEAPSIZE n` and `STACKSIZE n` are in bytes. PE: heap and
stack reserve (the commit size is 4 KB). NE: the heap size
field of the header (the heap is added to the data segment);
`STACKSIZE` overrides `/s`.

### 3.5 Statements of NE only

* `DESCRIPTION 'text'` is the first name of the nonresident
  names table.
* `EXETYPE` is the target operating system and the version
  `major.minor`, for example `OS2 3.10`. The HX loader does
  not run `WINDOWS`.
* `PROTMODE` (default) and `REALMODE` set the protected mode
  flag.
* `STUB 'file.EXE'` is the DOS stub of the file, instead of
  the built-in HX stub.
* `CODE attrs` and `DATA [NONE|SINGLE|MULTIPLE] attrs` set
  the attributes of all code and data segments, `DATA`
  also the kind of the automatic data segment. The default
  for a program is `MULTIPLE`, for a DLL `SINGLE`.
* `SEGMENTS`, then lines `name [CLASS 'CODE'|'DATA'] attrs`;
  the name is the name of an rdf file without extension.
* Attributes: `PRELOAD LOADONCALL MOVEABLE FIXED DISCARDABLE
  NONDISCARDABLE SHARED NONSHARED PURE IMPURE EXECUTEONLY
  EXECUTEREAD READONLY READWRITE IOPL NOIOPL CONFORMING
  NONCONFORMING`.

A complete example is `TEST\NEDLL\T11.DEF`.

## 4. Resources

`/res=FILE.RES` adds the resources of a binary `.RES` file.

* NE needs the 16-bit format (a resource compiler of Windows
  3.x writes it). The resources are grouped by type, the
  file offsets and sizes in the table are in 256 byte units.
* PE needs the 32-bit format (the usual `.RES` of today).
  The type, name, language and the flags are kept.
* Up to 200 resources. The `.RES` file of the wrong kind is
  refused.

A small `.RES` can be written in NASM, see `TEST\NE\R01.ASM`
(16-bit) and `TEST\WINPE\R01.ASM` (32-bit); build it with
`nasm -f bin R01.ASM -o R01.RES`.

## 5. mkdef

`MKDEF [/o=FILE] [/imp] NAME.DLL` reads an NE or a PE32 or
PE32+ file
(exe or DLL) and writes a `.DEF` file for it. Without `/o`
it writes to the console.

NE: `LIBRARY` or `NAME`, `DESCRIPTION`, `EXETYPE`, `DATA`,
the sizes and the `EXPORTS` of the file (with ordinals,
`RESIDENTNAME`, `NONAME`, `NODATA` and parameter words).

PE: `LIBRARY` (a DLL) or `NAME` (`WINDOWAPI` for the GUI
subsystem), `HEAPSIZE` and `STACKSIZE` when they are not the
defaults of RLINK, the `EXPORTS` of the export table (the
module name is the name of the export table without the
extension; entries without a name become `ORDn @n NONAME`)
and the `IMPORTS` of the file (an import by ordinal gets the
internal name `MODULE_n`). A forwarder of the export table
is skipped with a message. With the file that `winpe` made
the `.DEF` link back to the same bytes (`TEST\WINPE`).

With `/imp` only an `IMPORTS` section is written: the exports
of the file as `module.entry` lines, for linking another
program with this DLL.

## 6. Limits

* NE: every rdf file is its own code and data segment
  (up to 64 KB each), bss and stack are one segment.
  Relative references between segments are refused (a near
  call to another module), use far calls.
* PE: one code, one data and one bss section for all files.
  Absolute relocations of 32 bit only.
* Not made: forwarders, delay load, bound imports, version
  resources (you can add them with `/res`), resources in NE
  of the 32-bit format, exports of NE other than code.
* The HX loaders (from their sources): `DPMILD32` applies
  only the `HIGHLOW` base relocations, does not resolve
  forwarders and refuses a GUI subsystem file unless it is
  told to allow it; `DPMILD16` refuses `EXETYPE WINDOWS` and
  needs a non-empty relocation block for a segment that is
  flagged as having relocations (RLINK writes the flag only
  then).
* The `MAKE` of the repository reads at most about 1.5 KB of
  a makefile, so the test directories are small.

## 7. Tests

* `TEST\NE` - NE programs, exports, resources.
* `TEST\NEDLL` - NE DLL, two DLLs, a `.DEF` with all
  statements, mkdef.
* `TEST\WINPE` - a console exe, a DLL, import by name and by
  ordinal, resources, mkdef of a PE DLL and back.
* The other directories of `TEST` check the other formats
  (COM, MZS, MZL, LE, ADAM, RDF, QLB) in the same way,
  `TEST\LINK` the linking rules and `rlib`.
* `TEST\DOSPE4` - a DOS PE program that imports from a DLL.

Every directory has a `MAKEFILE` and `CHECK.BAT`, which
builds the files and compares them with the `.REF` files
(`FC /B`). The programs were run with the HX DOS Extender
(`HDPMI16` or `HDPMI32` with `DPMILD16` or `DPMILD32`).
