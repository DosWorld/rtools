# QLB21 - loading a .QLB with INT 21h AH=4Bh AL=01h

Prototype: `TEST/QLB21/QLB21.ASM` (NASM + RLINK, `make` in that
directory). Usage: `QLB21 [library.qlb]` (default `QB.QLB` in
the current directory).

Background: `AH=4Bh AL=03h` (load overlay) cannot load a `.QLB`
(the image really starts at file offset 0402h, DOS believes
`e_cparhdr` and starts at 0400h, so every relocation lands on
the OFFSET half of a far pointer). This document tries the other
"load only" subfunction, `AL=01h` (load, create PSP, do not
execute).

All results below were measured under DOSBox-X (its own DOS
kernel) with `QB.QLB` from QuickBASIC 4.50 (5822 bytes), an
RLINK library (`HELLO.QLB`, 1669 bytes) and an 81 KB RLINK
library (two 40 KB modules). The prototype loads all three,
repairs the image, and compares it with a hand-loaded image: all
three are byte for byte equal. `INT86OLD` of `QB.QLB` is
far-called and prints `Q` (out-array `ax = 0251`, as in the hand
loader).

## 1. Can we use it to load a .QLB?

Yes, with two conditions and one repair.

1. Allocation words. A stock `.QLB` (LINK /Q) has `e_minalloc =
   e_maxalloc = FFFFh` (RLINK writes the same). `AL=01h` honours
   them, asks for 1 MB and fails with `AX = 0008` (insufficient
   memory). QuickBASIC does not read those two words (a QLB with
   `e_minalloc = 10h`, `e_maxalloc = 100h` loads and runs in
   QuickBASIC 4.50), so the prototype makes a copy of the file
   with both words set to 0010h and loads the copy (`QLB21.TMP`
   in the current directory, deleted right after the load). A
   library that already has sane values loads directly
   (`HELLOS.QLB` in the tests).
2. DOS applies the same wrong geometry as `AL=03h`: the image is
   two bytes low (file 0400h at load:0000) and each relocation
   entry patches the word before the one it names. DOS memory is
   ours, so it is repaired in place:
   - undo: for every relocation entry `(offset, segment)`
     subtract the load segment from the word at `(load +
     segment):offset` (what DOS patched);
   - shift: move `load:0002 ...` down to `load:0000 ...` (length
     = file size - 0402h, done in 32 KB chunks, so images over
     64 KB work);
   - redo: add the load segment to the same words (now they are
     the segment halves). The relocation table is read from the
     file header (the file is opened once for the header and its
     size). Entries are used as `segment:offset` relative to the
     load segment, never as a flat 16-bit sum (that breaks above
     64 KB: found with the 81 KB library).
3. The memory DOS allocates is the declared image (`e_cp`,
   `e_cblp`), so the BSS beyond the end of the file is already
   allocated.

## 2. Better than the QBCALL way (0402h, relocate, AH=49h)?

No. Measured differences:

* memory
  - hand loader (QLBCALL.ASM): one block, size chosen by the
    caller
  - AL=01h (QLB21.ASM): PSP + environment copy + image, size
    from the header
* stock QB.QLB
  - hand loader (QLBCALL.ASM): loads as is
  - AL=01h (QLB21.ASM): needs a patched temporary copy of the
    file
* relocation
  - hand loader (QLBCALL.ASM): one pass
  - AL=01h (QLB21.ASM): three passes (undo, shift, redo)
* file reads
  - hand loader (QLBCALL.ASM): header + image
  - AL=01h (QLB21.ASM): DOS reads the image, the program reads
    the header again
* unload
  - hand loader (QLBCALL.ASM): `AH=49h` on the block
  - AL=01h (QLB21.ASM): terminate the child process

What `AL=01h` buys: DOS finds the declared size and allocates
it, and unloading frees the environment and the child's handle
references with the memory. It costs more code and a temporary
file, so it is only worth it when the program already wants a
PSP.

## 3. How to use it, and how to get CS:IP

Parameter block for `AX = 4B01h`, `DS:DX` = ASCIZ file name,
`ES:BX` = block:

| offset | content |
|---|---|
| +00 | environment segment (0 = copy of the parent's) |
| +02 | far pointer to a command tail (`00 0D` is enough) |
| +06, +0A | far pointers to two FCBs (dummies) |
| +0E | returned `SP`, +10 returned `SS` |
| +12 | returned `IP`, +14 returned `CS` |

After the call every register except `CS:IP` is destroyed (save
`SS:SP` and reload `DS` and `ES` from `CS`-relative variables).
On success:

* the child's PSP is the current PSP (`AH=62h`); give the
  current PSP back to the parent with `AH=50h` if the program
  goes on using DOS services;
* the image segment is `child PSP + 10h` (call it `B`);
* `CS:IP` comes back already relocated by DOS, but in the
  two-bytes-low view. The `.QLB` header (far jump `EA`, version,
  magic `6C75`, table offsets) is at `B:(CS*16 + IP - 2)` after
  the repair above (`CS` counted from `B`). The prototype checks
  the magic there;
* exports are then read as in QLBCALL: CODE table of 8-byte
  entries `(flags, nameOff, off, seg)` at `header +
  word[header+8]`; a routine is called as `CS = B + seg`, `IP =
  off` (the segment half matters: routines reach their own
  second half with `push cs / push offset`). RLINK libraries
  have an empty CODE table (names live in the runtime hash
  table), so only the QB header is checked for them.

## 4. How to unload

There is no unload call, but the child was created by DOS, so it
is ended the way DOS ends a process:

1. `AH=50h`, `BX` = child PSP (make it current);
2. `AX = 4C00h`, `INT 21h`.

DOS frees the child's memory blocks (image and environment),
releases its handles and makes the parent current again. It then
RESUMES THE PARENT AT THE INSTRUCTION AFTER THE `INT 21h` THAT
DID THE `AL=01h` LOAD, a second time (the terminate address
stored in the child PSP). Everything but `CS:IP` is lost again,
so the prototype:

* saves `SS:SP` before the load and reloads it after the `INT
  21h` (the main code is flat, so the same `SP` is valid for
  both returns);
* keeps a flag (`unloading`) in the code segment, set just
  before step 1, and jumps to the clean-up code when the flag is
  set.

Measured: largest free block before the load `949A`, with the
library `8FCE`, after the unload `949A` again; the child exit
code read with `AH=4Dh` is 0. Freeing the blocks by hand with
`AH=49h` would leave the child's inherited handle references in
the system file table, so it is not used.

## 5. What was not checked

* Real MS-DOS. The error 8 for `FFFFh` is the documented
  behaviour; the "second return" is how debuggers use `AL=01h`;
  both are expected on real DOS but were run on DOSBox-X only.
* `QLB21.TMP` is written to the current directory, which must be
  writable.
* The prototype does not call routines of RLINK libraries (their
  dispatcher needs the QuickBASIC data segment layout).
