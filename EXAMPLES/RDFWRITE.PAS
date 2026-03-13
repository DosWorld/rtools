{  MIT License

Copyright (c) 2026 Viacheslav Komenda

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
SOFTWARE. }
{$A-,I-,S-,R-,D-,L-,Q-,F-,G-,O-,B-}
unit RDFWrite;

interface

const
WIDTH8 = 1;
WIDTH16 = 2;
WIDTH32 = 4;

SEGMENT_TYPE_CODE = 1;
SEGMENT_TYPE_DATA = 2;

type
  PRDFWriter = ^TRDFWriter;
  TRDFWriter = record
    f: file;
    headerPos: LongInt;
    nextImportID: Word;
    headerSize: LongInt;
  end;

function RDF_Create(var W: TRDFWriter; const FileName: string): Boolean;
procedure RDF_AddImport(var W: TRDFWriter; const Name: string; Flags: Byte;
                       var importID: Word);
procedure RDF_AddGlobal(var W: TRDFWriter; const Name: string;
                       Segment: Byte; Offset: LongInt; Flags: Byte);
procedure RDF_AddReloc(var W: TRDFWriter; patchSegment: Byte; offset: LongInt;
                      width: Byte; refSegment: Word; relative: Boolean);
procedure RDF_AddBSS(var W: TRDFWriter; amount: LongInt);
procedure RDF_AddSegReloc(var W: TRDFWriter; patchSegment: Byte; offset: LongInt;
                         width: Byte; refSegment: Word);
procedure RDF_AddSegment(var W: TRDFWriter; segType, segNumber: Word;
                        var data; dataSize: LongInt);
procedure RDF_Close(var W: TRDFWriter);

implementation

const
  RDF_SIGNATURE : array[1..6] of Char = 'RDOFF2';
  RDFREC_RELOC      = 1;
  RDFREC_IMPORT     = 2;
  RDFREC_GLOBAL     = 3;
  RDFREC_BSS        = 5;
  RDFREC_SEGRELOC   = 6;
  RDFREC_MODNAME    = 8;
  SEGMENT_TYPE_EOF  = 0;

procedure WriteString(var f: file; const s: string);
var     i: Integer;
        ch: Char;
begin
        for i := 1 to Length(s) do begin
                ch := s[i];
                BlockWrite(f, ch, 1);
        end;
        ch := #0;
        BlockWrite(f, ch, 1);
end;

function RDF_Create(var W: TRDFWriter; const FileName: string): Boolean;
var     zeros: array[1..8] of Byte;
        i : integer;
begin
        Assign(W.f, FileName);
        {$I-}
        Rewrite(W.f, 1);
        i := IOResult;
        {$I+}
        if i <> 0 then begin
                RDF_Create := False;
                Exit;
        end;
        BlockWrite(W.f, RDF_SIGNATURE, 6);
        FillChar(zeros, 8, 0);
        W.headerPos := FilePos(W.f);
        BlockWrite(W.f, zeros, 8);
        W.nextImportID := 3;
        W.headerSize := 0;
        RDF_Create := True;
end;

procedure RDF_AddImport(var W: TRDFWriter; const Name: string; Flags: Byte;
                       var importID: Word);
var     recType, recLen: Byte;
begin
        recType := RDFREC_IMPORT;
        recLen := 1 + 2 + Length(Name) + 1;
        BlockWrite(W.f, recType, 1);
        BlockWrite(W.f, recLen, 1);
        BlockWrite(W.f, Flags, 1);
        importID := W.nextImportID;
        Inc(W.nextImportID);
        BlockWrite(W.f, importID, 2);
        WriteString(W.f, Name);
        W.headerSize := W.headerSize + 2 + recLen;
end;

procedure RDF_AddGlobal(var W: TRDFWriter; const Name: string;
                       Segment: Byte; Offset: LongInt; Flags: Byte);
var     recType, recLen: Byte;
begin
        recType := RDFREC_GLOBAL;
        recLen := 1 + 1 + 4 + Length(Name) + 1;
        BlockWrite(W.f, recType, 1);
        BlockWrite(W.f, recLen, 1);
        BlockWrite(W.f, Flags, 1);
        BlockWrite(W.f, Segment, 1);
        BlockWrite(W.f, Offset, 4);
        WriteString(W.f, Name);
        W.headerSize := W.headerSize + 2 + recLen;
end;

procedure RDF_AddReloc(var W: TRDFWriter; patchSegment: Byte; offset: LongInt;
                      width: Byte; refSegment: Word; relative: Boolean);
var     recType, recLen: Byte;
        flags: Byte;
begin
        recType := RDFREC_RELOC;
        recLen := 1 + 4 + 1 + 2;
        flags := patchSegment and $3F;
        if relative then flags := flags or $40;
        BlockWrite(W.f, recType, 1);
        BlockWrite(W.f, recLen, 1);
        BlockWrite(W.f, flags, 1);
        BlockWrite(W.f, offset, 4);
        BlockWrite(W.f, width, 1);
        BlockWrite(W.f, refSegment, 2);
        W.headerSize := W.headerSize + 2 + recLen;
end;

procedure RDF_AddBSS(var W: TRDFWriter; amount: LongInt);
var     recType, recLen: Byte;
begin
        recType := RDFREC_BSS;
        recLen := 4;
        BlockWrite(W.f, recType, 1);
        BlockWrite(W.f, recLen, 1);
        BlockWrite(W.f, amount, 4);
        W.headerSize := W.headerSize + 2 + recLen;
end;

procedure RDF_AddSegReloc(var W: TRDFWriter; patchSegment: Byte; offset: LongInt;
                         width: Byte; refSegment: Word);
var     recType, recLen: Byte;
begin
        recType := RDFREC_SEGRELOC;
        recLen := 1 + 4 + 1 + 2;
        BlockWrite(W.f, recType, 1);
        BlockWrite(W.f, recLen, 1);
        BlockWrite(W.f, patchSegment, 1);
        BlockWrite(W.f, offset, 4);
        BlockWrite(W.f, width, 1);
        BlockWrite(W.f, refSegment, 2);
        W.headerSize := W.headerSize + 2 + recLen;
end;

procedure RDF_AddSegment(var W: TRDFWriter; segType, segNumber: Word;
                        var data; dataSize: LongInt);
var     reserved: Word;
begin
        reserved := 0;
        BlockWrite(W.f, segType, 2);
        BlockWrite(W.f, segNumber, 2);
        BlockWrite(W.f, reserved, 2);
        BlockWrite(W.f, dataSize, 4);
        if dataSize > 0 then BlockWrite(W.f, data, dataSize);
end;

procedure RDF_Close(var W: TRDFWriter);
var     totalSize, curPos: LongInt;
        eofType: Word;
begin
        eofType := SEGMENT_TYPE_EOF;
        BlockWrite(W.f, eofType, 2);
        BlockWrite(W.f, eofType, 2);
        BlockWrite(W.f, eofType, 2);
        eofType := 0;
        BlockWrite(W.f, eofType, 4);
        curPos := FilePos(W.f);
        totalSize := curPos;
        Seek(W.f, W.headerPos);
        BlockWrite(W.f, totalSize, 4);
        BlockWrite(W.f, W.headerSize, 4);
        Close(W.f);
end;

end.
