{ MIT License

Copyright (c) 2022 Viacheslav Komenda

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

https://github.com/DosWorld/rtools }
{$A+,I+,S-,R-,D-,L-,Q-,F-,G-}
UNIT Elf;

INTERFACE

TYPE DWORD   = LONGINT;

CONST
ET_NONE   = 0;
ET_REL    = 1;
ET_EXEC   = 2;
ET_DYN    = 3;
ET_CORE   = 4;
ET_LOPROC = $ff00;
ET_HIPROC = $ffff;

EM_386 = 3;
EV_CURRENT = 1;

EI_MAG0    = 0;
EI_MAG1    = 1;
EI_MAG2    = 2;
EI_MAG3    = 3;
EI_CLASS   = 4;
EI_DATA    = 5;
EI_VERSION = 6;

ELFMAG0 = $7f;
ELFMAG1 = ORD('E');
ELFMAG2 = ORD('L');
ELFMAG3 = ORD('F');

ELFCLASS32  = 1;
ELFDATA2LSB = $01020304;

TYPE
ELF_HEADER = RECORD
      e_ident     : ARRAY [0..15] OF BYTE;
      e_type      : WORD;
      e_machine   : WORD;
      e_version   : DWORD;
      e_entry     : DWORD;
      e_phoff     : DWORD;
      e_shoff     : DWORD;
      e_flags     : DWORD;
      e_ehsize    : WORD;
      e_phentsize : WORD;
      e_phnum     : WORD;
      e_shentsize : WORD;
      e_shnum     : WORD;
      e_shstrndx  : WORD;
END;

IMPLEMENTATION

END.