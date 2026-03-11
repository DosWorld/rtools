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
Unit RdfLoad;

Interface

Type 
PExportSym = ^TExportSym;
TExportSym = Record
        Name: String[32];
        Addr: Pointer;
        Next: PExportSym;
End;

PRDFModule = ^TRDFModule;
TRDFModule = Record
        CodeBase: Pointer;
        DataBase: Pointer;
        CodeSize: Word;
        DataSize: Word;
        DataRawSize: Word;
        Exports : PExportSym;
        Next    : PRDFModule;
End;

Function LoadLibrary(const FileName: String) : PRDFModule;
Function GetProcAddress(Module: PRDFModule; const Name: String): Pointer;
Procedure FreeLibrary(Module: PRDFModule);

Implementation

Const 
REC_RELOC    = 1;
REC_GLOBAL   = 3;
REC_BSS      = 5;
REC_SEGRELOC = 6;

Type
TRDFHeader = Record
        Sign: array[0..5] Of Char;
        ModSize: LongInt;
        HeadSize: LongInt;
End;

TSegHeader = Record
        SegType: Word;
        SegNum: Word;
        Reserved: Word;
        Length: LongInt;
End;

TRecHeader = Record
        RecType: Byte;
        RecLen: Byte;
End;

Function Align2(Size: Word): Word;
Begin
        If (Size And 1) <> 0 Then Inc(Size);
        Align2 := Size;
End;

Function ExtractString(Var Buf; Offset, MaxLen: Byte): String;
Var     B: array[0..255] Of Byte absolute Buf;
        S: String;
        I: Byte;
Begin
        S := '';
        I := 0;
        While (Offset + I < MaxLen) And (B[Offset + I] <> 0) Do Begin
                S := S + Chr(B[Offset + I]);
                Inc(I);
        End;
        ExtractString := S;
End;

Function GetBSSSize(Var F: File; StartPos, EndPos: LongInt): LongInt;
Var     H: TRecHeader;
        Buf: array[0..255] Of Byte;
        Total: LongInt;
        Val: LongInt;
Begin
        Total := 0;
        Seek(F, StartPos);
        While FilePos(F) < EndPos Do Begin
                BlockRead(F, H, SizeOf(H));
                If H.RecLen > 0 Then BlockRead(F, Buf, H.RecLen);
                If H.RecType = REC_BSS Then Begin
                        Move(Buf[0], Val, 4);
                        Total := Total + Val;
                End;
        End;
        GetBSSSize := Total;
End;

Procedure ScanSegments(Var F: File; StartPos: LongInt; Var CSize, DSize: LongInt);
Var     SH: TSegHeader;
Begin
        CSize := 0;
        DSize := 0;
        Seek(F, StartPos);
        Repeat
                BlockRead(F, SH, SizeOf(SH));
                If SH.SegType = 1 Then CSize := CSize + SH.Length
                Else If SH.SegType = 2 Then DSize := DSize + SH.Length;
                If SH.Length > 0 Then Seek(F, FilePos(F) + SH.Length);
        Until SH.SegType = 0;
End;

Procedure LoadSegmentData(Var F: File; StartPos: LongInt; Var Modul: TRDFModule);
Var     SH: TSegHeader;
Begin
        Seek(F, StartPos);
        Repeat
                BlockRead(F, SH, SizeOf(SH));
                If SH.Length > 0 Then Begin
                        If SH.SegType = 1 Then BlockRead(F, Modul.CodeBase^, Word(SH.Length))
                        Else If SH.SegType = 2 Then BlockRead(F, Modul.DataBase^, Word(SH.Length))
                        Else Seek(F, FilePos(F) + SH.Length);
                End;
        Until SH.SegType = 0;
End;

Procedure ApplyRecords(Var F: File; StartPos, EndPos: LongInt; Var Modul: TRDFModule);
Var     H: TRecHeader;
        Buf: array[0..255] Of Byte;
        BaseAddr, TargetPtr, PatchAddr: Pointer;
        RelFlags, RelWidth, GSegID: Byte;
        RelOffset, GOffset: LongInt;
        RelRSeg: Word;
        PatchVal: Word;
        NewSym: PExportSym;
Begin
  Seek(F, StartPos);
  While FilePos(F) < EndPos Do Begin
      BlockRead(F, H, SizeOf(H));
      If H.RecLen > 0 Then BlockRead(F, Buf, H.RecLen);
      Case H.RecType Of 
        REC_RELOC, REC_SEGRELOC:
                                 Begin
                                   RelFlags := Buf[0];
                                   Move(Buf[1], RelOffset, 4);
                                   RelWidth := Buf[5];
                                   Move(Buf[6], RelRSeg, 2);

                                   If (RelFlags And $0F) = 0 Then BaseAddr := Modul.CodeBase
                                   Else BaseAddr := Modul.DataBase;

                                   PatchAddr := Ptr(Seg(BaseAddr^), Ofs(BaseAddr^) + Word(RelOffset)
                                                );

                                   If RelRSeg = 0 Then TargetPtr := Modul.CodeBase
                                   Else If RelRSeg = 1 Then TargetPtr := Modul.DataBase
                                   Else If RelRSeg = 2 Then TargetPtr := Ptr(Seg(Modul.DataBase^),
                                                                         Ofs(Modul.DataBase^) +
                                                                         Modul.DataRawSize)
                                   Else TargetPtr := Modul.DataBase;

                                   If H.RecType = REC_RELOC Then
                                     Begin
                                       If RelWidth = 2 Then
                                         Begin
                                           PatchVal := Ofs(TargetPtr^);
                                           Inc(Word(PatchAddr^), PatchVal);
                                         End;
                                     End
                                   Else
                                     Begin
                                       If RelWidth = 2 Then
                                         Word(PatchAddr^) := Seg(TargetPtr^);
                                     End;
                                 End;

        REC_GLOBAL:
                    Begin
                      GSegID := Buf[1];
                      Move(Buf[2], GOffset, 4);

                      New(NewSym);
                      NewSym^.Name := ExtractString(Buf, 6, H.RecLen);
                      NewSym^.Next := Modul.Exports;
                      Modul.Exports := NewSym;

                      If GSegID = 0 Then
                        NewSym^.Addr := Ptr(Seg(Modul.CodeBase^), Ofs(Modul.CodeBase^) + Word(
                                        GOffset))
                      Else If GSegID = 2 Then
                             NewSym^.Addr := Ptr(Seg(Modul.DataBase^), Ofs(Modul.DataBase^) + Modul.
                                             DataRawSize + Word(GOffset))
                      Else
                        NewSym^.Addr := Ptr(Seg(Modul.DataBase^), Ofs(Modul.DataBase^) + Word(
                                        GOffset));
                    End;
      End;
    End;
End;

Function LoadLibrary(const FileName: String) : PRDFModule;
Var     F: File;
        Hdr: TRDFHeader;
        RecStart, SegStart: LongInt;
        RCSize, RDSize, RBSize: LongInt;
        i : integer;
        Module: PRDFModule;
Begin
        Module := Nil;
        LoadLibrary := Nil;
        Assign(F, FileName);
        Reset(F, 1); {$I-} i := IOResult; {$I+}
        If i <> 0 Then Exit;
        BlockRead(F, Hdr, SizeOf(Hdr));
        If Hdr.Sign <> 'RDOFF2' Then Begin
                Close(F);
                Exit;
        End;
        RecStart := FilePos(F);
        SegStart := RecStart + Hdr.HeadSize;
        RBSize := GetBSSSize(F, RecStart, SegStart);
        ScanSegments(F, SegStart, RCSize, RDSize);
        If (RCSize > 65520) Or ((RDSize + RBSize) > 65520) Then Begin
                Close(F);
                Exit;
        End;
        New(Module);
        FillChar(Module^, SizeOf(TRDFModule), 0);
        Module^.CodeSize := Align2(Word(RCSize));
        Module^.DataSize := Align2(Word(RDSize + RBSize));
        Module^.DataRawSize := Word(RDSize);

        If Module^.CodeSize > 0 Then GetMem(Module^.CodeBase, Module^.CodeSize);
        If Module^.DataSize > 0 Then Begin
                GetMem(Module^.DataBase, Module^.DataSize);
                FillChar(Module^.DataBase^, Module^.DataSize, 0);
        End;

        LoadSegmentData(F, SegStart, Module^);
        ApplyRecords(F, RecStart, SegStart, Module^);

        Close(F);
        LoadLibrary := Module;
End;

Function GetProcAddress(Module: PRDFModule; const Name: String): Pointer;
Var     Current: PExportSym;
Begin
        Current := Module^.Exports;
        While Current <> Nil Do Begin
                If Current^.Name = Name Then Begin
                        GetProcAddress := Current^.Addr;
                        Exit;
                End;
                Current := Current^.Next;
        End;
        GetProcAddress := Nil;
End;

Procedure FreeLibrary(Module: PRDFModule);
Var     Next: PExportSym;
Begin
        if Module = Nil then Exit;
        While Module^.Exports <> Nil Do Begin
                Next := Module^.Exports^.Next;
                Dispose(Module^.Exports);
                Module^.Exports := Next;
        End;
        If (Module^.CodeSize > 0) And (Module^.CodeBase <> Nil) Then
                FreeMem(Module^.CodeBase, Module^.CodeSize);
        If (Module^.DataSize > 0) And (Module^.DataBase <> Nil) Then
                FreeMem(Module^.DataBase, Module^.DataSize);
        Dispose(Module);
End;

End.
