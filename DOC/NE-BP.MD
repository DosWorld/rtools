# NE (New Executable) / DPMI16 - reference format

## Part 1 - The Borland Pascal reference (empirical, byte-exact)

### 1.1 Overall file shape

```
+-------------------+  0x0000
|  MZ stub (real)   |   3646 bytes, byte-identical across all BPC /CP outputs
|                   |   (carries "16STUB" at 0x200 + real DOS stub code)
+-------------------+  0x0E3E  = e_lfanew (fixed)
|  NE header (64 B) |
+-------------------+  +0x40
|  segment table    |   segCount * 8 bytes
+-------------------+
|  resource table   |   present but empty: alignShift WORD + 0000 terminator
+-------------------+
|  resident names   |   module name (ord 0) + 00 terminator
+-------------------+
|  module ref table |   modRefCount * 2 bytes (each = offset into imp-names)
+-------------------+
|  imported names   |   00 <counted strings...>  (leading 00 = terminator@0)
+-------------------+
|  entry table      |   4 zero bytes (empty - see sec. 1.6)
+-------------------+
|  nonresident names|   "STEM.EXE" (ord 0) + 00 terminator  (at file offset)
+-------------------+  (padded to sector)
|  seg1 data+relocs |   each segment: raw bytes, then <count WORD><8*count>
|  seg2 data+relocs |
|  seg3 data        |   (DATA/DGROUP; no relocs here in these samples)
+-------------------+
```

`e_lfanew` is always **`0x0E3E`** in the BPC reference because its MZ stub is
a fixed 3646-byte blob. (Our own stub differs in size - see Part 2.)

