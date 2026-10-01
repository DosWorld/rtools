### New Executable (NE) File Format Specification

> **STRONG RULE: DOCS/NE.MD IS A READ-ONLY FILE.** This is an authoritative
> format specification. Do NOT edit, rewrite, or "align" it to any
> implementation or reference file. It is reference material only.

#### 1. Overview

The New Executable (NE) format is a segmented executable file format used by 16-bit Windows, OS/2 1.x, and other environments. An NE file is embedded within a standard DOS MZ executable. The MZ header's `e_lfanew` field (offset 3Ch) points to the start of the NE header. The MZ stub typically displays a message like "This program requires Microsoft Windows." when run under DOS.

#### 2. Identification

The NE header begins with the ASCII signature "NE" (4Eh 45h).

---

### 3. The NE Header

The main header follows the signature and describes the executable's structure, entry points, and memory requirements.

**Table 1: New Executable Header Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 2 | char[2] | **Signature**: "NE" (4Eh 45h) |
| 02 | 2 | BYTE[2] | **Linker Version**: Major version, then minor version. |
| 04 | 2 | WORD | **Entry Table Offset**: Offset from the start of this NE header to the entry table. |
| 06 | 2 | WORD | **Entry Table Length**: Total size of the entry table in bytes. |
| 08 | 4 | DWORD | **File Load CRC**: A 32-bit checksum of the file's load image. Often 0 (e.g., Borland's TPW). |
| 0C | 1 | BYTE | **Program Flags**: Bitfield describing the program's characteristics. (See Table 2) |
| 0D | 1 | BYTE | **Application Flags**: Bitfield describing the application type. (See Table 3) |
| 0E | 2 | WORD | **Auto Data Segment Index**: The segment table index (1-based) of the automatic data segment. This segment is the DGROUP used for local heaps and the stack. |
| 10 | 2 | WORD | **Initial Local Heap Size**: Size of the local heap in bytes, allocated above the stack in the automatic data segment. |
| 12 | 2 | WORD | **Initial Stack Size**: Size of the stack in bytes, allocated within the automatic data segment. If SS equals the auto data segment and SP is 0000h, the stack pointer is set to the top of the segment, just below the local heap. A value of 0000h here and for SP implies SS is not equal to DS. |
| 14 | 4 | DWORD | **Program Entry Point (CS:IP)**: The initial execution point. `CS` is a 1-based index into the segment table. `IP` is the offset within that segment. |
| 18 | 4 | DWORD | **Initial Stack Pointer (SS:SP)**: The initial stack. `SS` is a 1-based index into the segment table. |
| 1C | 2 | WORD | **Segment Count**: The total number of segments in the executable. |
| 1E | 2 | WORD | **Module Reference Count**: The number of entries in the Module Reference Table. |
| 20 | 2 | WORD | **Nonresident Names Table Length**: Size of the nonresident names table in bytes. |
| 22 | 2 | WORD | **Segment Table Offset**: Offset from the start of this NE header to the segment table. |
| 24 | 2 | WORD | **Resource Table Offset**: Offset from the start of this NE header to the resource table. |
| 26 | 2 | WORD | **Resident Names Table Offset**: Offset from the start of this NE header to the resident names table. |
| 28 | 2 | WORD | **Module Reference Table Offset**: Offset from the start of this NE header to the module reference table. |
| 2A | 2 | WORD | **Imported Names Table Offset**: Offset from the start of this NE header to the imported names table. This is an array of counted strings, terminated by a string of length 00h. |
| 2C | 4 | DWORD | **Nonresident Names Table Offset**: Offset from the start of the file (not the NE header) to the nonresident names table. |
| 30 | 2 | WORD | **Moveable Entry Point Count**: The number of moveable entry points listed in the entry table. |
| 32 | 2 | WORD | **File Alignment Size Shift Count**: The number of bits to shift to calculate the logical sector size. A value of 0 defaults to 9 (512-byte pages). The actual alignment is (1 << this value). |
| 34 | 2 | WORD | **Number of Resource Table Entries**: Count of resource types in the resource table. |
| 36 | 1 | BYTE | **Target Operating System**: Specifies the target OS.<br>`00h`: Unknown<br>`01h`: OS/2<br>`02h`: Windows<br>`03h`: European MS-DOS 4.x<br>`04h`: Windows 386<br>`05h`: BOSS (Borland Operating System Services)<br>`81h`: PharLap 286|DOS-Extender, OS/2<br>`82h`: PharLap 286|DOS-Extender, Windows |
| 37 | 1 | BYTE | **Other EXE Flags**: Additional flags. (See Table 4) |
| 38 | 2 | WORD | **Offset to Return Thunks** or **Start of Gangload Area**. |
| 3A | 2 | WORD | **Offset to Segment Reference Thunks** or **Length of Gangload Area**. |
| 3C | 2 | WORD | **Minimum Code Swap Area Size**: The minimum amount of memory in bytes reserved for swapping code segments. |
| 3E | 2 | BYTE[2] | **Expected Windows Version**: The minimum version of Windows required. Minor version first, then major version. |

---

### 4. Bitfield Definitions

**Table 2: Program Flags (Offset 0Ch)**

| Bit(s) | Description |
| :--- | :--- |
| 0-1 | **DGROUP Type**: How the automatic data group is managed.<br>00: None<br>01: Single shared<br>10: Multiple (unshared)<br>11: (null) |
| 2 | **Global Initialization**: If set, the program's initialization routine is called only once globally. |
| 3 | **Protected Mode Only**: The program requires protected mode and will not run in real mode. |
| 4 | **8086 Instructions**: The program contains 8086 instructions. |
| 5 | **80286 Instructions**: The program contains 80286 instructions. |
| 6 | **80386 Instructions**: The program contains 80386 instructions. |
| 7 | **80x87 Instructions**: The program contains floating-point instructions for an 80x87 coprocessor. |

**Table 3: Application Flags (Offset 0Dh)**

| Bit(s) | Description |
| :--- | :--- |
| 0-2 | **Application Type**:<br>`001`: Full-screen (not aware of Windows/P.M. API)<br>`010`: Compatible with Windows/P.M. API<br>`011`: Uses Windows/P.M. API |
| 3 | **Family Application (OS/2)**: The program is an OS/2 Family Application. |
| 5 | **Errors in Image**: If set, the executable image contains errors. 0 = valid executable. |
| 6 | **Non-conforming Program**: If set, a valid stack is not maintained by the program. |
| 7 | **DLL or Driver**: If set, this is a dynamic-link library or device driver rather than a standard application. If set, the SS:SP information in the main header is invalid. The CS:IP entry point instead points to a FAR initialization routine. This routine is called with `AX` = module handle and must return `AX` = nonzero on success or `AX` = 0000h on failure. |

**Table 4: Other EXE Flags (Offset 37h)**

| Bit(s) | Description |
| :--- | :--- |
| 0 | **Supports Long Filenames**: The application can handle long filenames. |
| 1 | **2.X Protected Mode**: The executable is compatible with 2.x protected mode. |
| 2 | **2.X Proportional Font**: The application can use proportional fonts in Windows 2.x. |
| 3 | **Gangload Area**: A valid gangload area is present. |

---

### 5. Segment Table

The segment table immediately follows the NE header. It consists of a sequence of segment table entries, each 8 bytes in length. The entries are 1-based indexed.

**Table 5: Segment Table Entry Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 2 | WORD | **File Offset**: The logical sector offset of the segment's data in the file. Multiply by the sector size (from the alignment shift count) to get the byte offset. |
| 02 | 2 | WORD | **Length of Image in File**: The size of the segment data in the file. A value of 0000h indicates the segment is 64K. |
| 04 | 2 | WORD | **Segment Attributes**: Bitfield describing the segment. (See Table 6) |
| 06 | 2 | WORD | **Minimum Allocation Size**: The minimum number of bytes to allocate for the segment in memory. A value of 0000h indicates 64K. |

**Table 6: Segment Attributes Bitfield**

| Bit(s) | Description |
| :--- | :--- |
| 0 | **Data Segment**: If set, this is a data segment. If clear, it is a code segment. |
| 2 | **Real Mode**: The segment can be accessed in real mode. |
| 3 | **Iterated**: The segment data is iterated. |
| 4 | **Moveable**: The segment can be moved in memory by the loader. |
| 5 | **Shareable**: The segment can be shared among multiple instances of the module. |
| 6 | **Preloaded**: The segment should be loaded immediately at module load time, rather than demand-loaded. |
| 7 | **Execute-only / Read-only**: If a code segment, it is execute-only. If a data segment, it is read-only. |
| 8 | **Has Relocations**: Relocation data directly follows the segment's raw data in the file. |
| 9 | **Debug Info Present**: Debug information is associated with this segment. |
| 10-11 | **80286 DPL Bits**: The Descriptor Privilege Level for the segment (used by OS/2). |
| 12 | **Discardable**: The segment can be discarded and reloaded from disk if its memory is needed. |
| 13-15 | **Discard Priority**: The priority level for discarding this segment (0 is highest, 7 is lowest). |

---

### 6. Entry Table

The entry table contains bundles of entry points. Each bundle defines entry points for a single segment.

**Table 7: Entry Table Bundle Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **Entry Count**: The number of entry points in this bundle. A value of 00h indicates the end of the entry table. |
| 01 | 1 | BYTE | **Segment Number**: The 1-based segment table index for all entries in this bundle. This field is ignored if the bundle is empty (Entry Count = 0). |
| 02 | var | RECORD[] | **Entry Records**: An array of entry point definitions, repeated `Entry Count` times. |

**Entry Record Layout (3 bytes per entry)**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **Flags**<br>Bit 0: **Exported**. If set, this entry point is exported.<br>Bit 1: **Single Data**. If set, the function uses a single, shared data segment. |
| 01 | 2 | WORD | **Offset**: The offset of the entry point within the specified segment. |

---

### 7. Module Reference Table

This table lists the external modules that the NE executable is dependent on. It is organized as a list of bundles.

**Table 8: Module Reference Table Bundle Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **Record Count**: The number of records in this bundle. A value of 00h marks the end of the table. |
| 01 | 1 | BYTE | **Segment Indicator**: Defines the target segment for the fixup.<br>`00h`: Unused entry.<br>`FFh`: Moveable segment. The record provides the segment number.<br>*Other*: A fixed segment number. |
| 02 | var | RECORD[] | **Module Records**: An array of record definitions, repeated `Record Count` times. |

**Module Record Layout (for Moveable Segment, Segment Indicator = FFh)**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **Flags**<br>Bit 0: **Exported**. The referenced entry is exported.<br>Bit 1: **Global Data**. The entry uses global (shared) data.<br>Bits 7-3: **Parameter Words**. Number of words for call parameters. |
| 01 | 2 | BYTE[2] | `INT 3Fh` instruction bytes (CDh 3Fh). |
| 03 | 1 | BYTE | **Segment Number**: The 1-based index into the segment table. |
| 04 | 2 | WORD | **Offset**: The offset of the referenced symbol. |

**Module Record Layout (for Fixed Segment, Segment Indicator ≠ 00h/FFh)**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **Flags**<br>Bit 0: **Exported**.<br>Bit 1: **Global Data**.<br>Bits 7-3: **Parameter Words**. |
| 01 | 2 | WORD | **Offset**: The offset of the referenced symbol. |

---

### 8. Names Tables

There are two names tables: resident and nonresident.

- **Resident Names Table**: Stored in the main header area, always loaded into memory. The first string is the module name.
- **Nonresident Names Table**: Stored at a location pointed to by the header and may be discarded to save memory. The first string is the module description.

**Table 9: Names Table Entry Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **String Length**: The length of the following string. A value of 00h marks the end of the table. |
| 01 | N | char[N] | **Name String**: An ASCII text string. The strings are case-sensitive, but if linked with `/IGNORECASE`, they are entirely uppercase. |
| N+1 | 2 | WORD | **Ordinal Number**: The 1-based index into the entry table that this name exports. |

---

### 9. Relocation Data

Relocation data is found directly after the raw data for a segment if bit 8 ("Has Relocations") is set in that segment's attributes. The data consists of a series of relocation items, each 8 bytes, preceded by a count.

**Table 10: Segment Relocation Data Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 2 | WORD | **Number of Relocation Items**: The count of relocation records that follow. |
| 02 | 8 * N | RECORD[] | **Relocation Items**: An array of 8-byte relocation records. |

**Relocation Item Record Layout (8 bytes each)**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 1 | BYTE | **Relocation Type**:<br>`00h`: LOBYTE<br>`02h`: BASE (16-bit segment)<br>`03h`: PTR (16:16 pointer, offset:segment)<br>`05h`: OFFS (16-bit offset)<br>`0Bh`: PTR48 (16:32 pointer)<br>`0Dh`: OFFS32 (32-bit offset) |
| 01 | 1 | BYTE | **Flags**<br>Bit 2: **Additive**. If set, the fixup value is added to the target instead of replacing it. |
| 02 | 2 | WORD | **Offset within Segment**: The offset within the current segment where the relocation is to be applied. |
| 04 | 2 | WORD | **Target Address Segment**: For `PTR` type relocations, the target segment index:<br>`00h`: Internal fixup to the segment's own base address.<br>`FFh`: External fixup. The offset field is an index into the Module Reference Table. <br>*Other*: Internal fixup to the specified 1-based segment index. |
| 06 | 2 | WORD | **Target Address Offset**: The offset of the target. For an external fixup (Segment = FFh), this is an index into the Imported Names Table. |

---

### 10. Resource Table

The resource table stores all application resources (icons, strings, menus, etc.). It is located at the offset specified in the NE header.

**Table 11: Resource Table Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 2 | WORD | **Alignment Shift Count**: The logical sector size for resource data, expressed as a power of 2. |
| 02 | var | RECORD[] | **Resource Type Records**: A sequence of records, one for each resource type. The list is terminated by a record with a Type ID of 0000h. |

**Resource Type Record Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 2 | WORD | **Type ID**:<br>`0000h`: End of resource records.<br>`>= 8000h`: An integer resource type.<br>*Other*: An offset from the start of the resource table to a type name string. |
| 02 | 2 | WORD | **Resource Count**: The number of resources for this type. |
| 04 | 4 | DWORD | **Reserved**: Set aside for runtime use. |
| 08 | var | RECORD[] | **Resource Entries**: An array of resource definitions, repeated `Resource Count` times. (See Table 12) |

**Table 12: Resource Entry Layout**

| Offset (hex) | Size (bytes) | Data Type | Description |
| :--- | :--- | :--- | :--- |
| 00 | 2 | WORD | **File Offset**: The offset of the resource data from the start of the file, in alignment units (shifted by the alignment shift count). |
| 02 | 2 | WORD | **Resource Length**: The size of the resource data in bytes. |
| 04 | 2 | WORD | **Flags**<br>Bit 4: **Moveable**<br>Bit 5: **Shareable**<br>Bit 6: **Preloaded** |
| 06 | 2 | WORD | **Resource ID**:<br>`>= 8000h`: An integer resource ID.<br>*Other*: An offset from the start of the resource table to a resource name string. |
| 08 | 4 | DWORD | **Reserved**: Set aside for runtime use. |

*Note: Resource type and name strings are stored immediately following the resource table. They are stored as counted strings (length-prefixed), not null-terminated, and a string of length 0 indicates the end of the table.*
