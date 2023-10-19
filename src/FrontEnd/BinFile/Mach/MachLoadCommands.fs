(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

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
*)

module internal B2R2.FrontEnd.BinFile.Mach.LoadCommands

open System
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let parseSegCmd span (reader: IBinReader) baseAddr cls offset cmdType cmdSize =
  let span = (span: ByteSpan).Slice offset
  { Cmd = cmdType
    CmdSize = cmdSize
    SecOff = offset + if cls = WordSize.Bit64 then 72 else 56
    SegCmdName = readCString span 8
    VMAddr = readNative span reader cls 24 24 + baseAddr
    VMSize = readNative span reader cls 28 32
    FileOff = readNative span reader cls 32 40
    FileSize = readNative span reader cls 36 48
    MaxProt = reader.ReadInt32 (span, pickNum cls 40 56)
    InitProt = reader.ReadInt32 (span, pickNum cls 44 60)
    NumSecs = reader.ReadUInt32 (span, pickNum cls 48 64)
    SegFlag = reader.ReadUInt32 (span, pickNum cls 52 68) }

let parseSymCmd (span: ByteSpan) reader offset cmdType cmdSize =
  { Cmd = cmdType
    CmdSize = cmdSize
    SymOff = (reader: IBinReader).ReadInt32 (span, offset + 8)
    NumOfSym = reader.ReadUInt32 (span, offset + 12)
    StrOff = reader.ReadInt32 (span, offset + 16)
    StrSize = reader.ReadUInt32 (span, offset + 20) }

let parseDySymCmd (span: ByteSpan) reader offset cmdType cmdSize =
  { Cmd = cmdType
    CmdSize = cmdSize
    IdxLocalSym = (reader: IBinReader).ReadUInt32 (span, offset + 8)
    NumLocalSym = reader.ReadUInt32 (span, offset + 12)
    IdxExtSym = reader.ReadUInt32 (span, offset + 16)
    NumExtSym = reader.ReadUInt32 (span, offset + 20)
    IdxUndefSym = reader.ReadUInt32 (span, offset + 24)
    NumUndefSym = reader.ReadUInt32 (span, offset + 28)
    TOCOffset = reader.ReadUInt32 (span, offset + 32)
    NumTOCContents = reader.ReadUInt32 (span, offset + 36)
    ModTabOff = reader.ReadUInt32 (span, offset + 40)
    NumModTab = reader.ReadUInt32 (span, offset + 44)
    ExtRefSymOff = reader.ReadUInt32 (span, offset + 48)
    NumExtRefSym = reader.ReadUInt32 (span, offset + 52)
    IndirectSymOff = reader.ReadUInt32 (span, offset + 56)
    NumIndirectSym = reader.ReadUInt32 (span, offset + 60)
    ExtRelOff = reader.ReadUInt32 (span, offset + 64)
    NumExtRel = reader.ReadUInt32 (span, offset + 68)
    LocalRelOff = reader.ReadUInt32 (span, offset + 72)
    NumLocalRel = reader.ReadUInt32 (span, offset + 76) }

let parseMainCmd (span: ByteSpan) reader baseAddr offset cmdType cmdSize =
  { Cmd = cmdType
    CmdSize = cmdSize
    EntryOff = ((reader: IBinReader).ReadUInt64 (span, offset + 8)) + baseAddr
    StackSize = reader.ReadUInt64 (span, offset + 16) }

/// Read lc_str string.
let readLCStr (span: ByteSpan) reader (size: uint32) offset =
  let strOffset = (reader: IBinReader).ReadInt32 (span, offset + 8)
  let strLen = Convert.ToInt32 size - strOffset
  ByteArray.extractCStringFromSpan (span.Slice (offset + strOffset, strLen)) 0

let parseDyLibCmd span reader offset cmdType cmdSize =
  { Cmd = cmdType
    CmdSize = cmdSize
    DyLibName = readLCStr span reader cmdSize offset
    DyLibTimeStamp = reader.ReadUInt32 (span, offset + 12)
    DyLibCurVer = reader.ReadUInt32 (span, offset + 16)
    DyLibCmpVer = reader.ReadUInt32 (span, offset + 20) }

let parseDyLdInfo (span: ByteSpan) reader offset cmdType cmdSize =
  { Cmd = cmdType
    CmdSize = cmdSize
    RebaseOff = (reader: IBinReader).ReadInt32 (span, offset + 8)
    RebaseSize = reader.ReadUInt32 (span, offset + 12)
    BindOff = reader.ReadInt32 (span, offset + 16)
    BindSize = reader.ReadUInt32 (span, offset + 20)
    WeakBindOff = reader.ReadInt32 (span, offset + 24)
    WeakBindSize = reader.ReadUInt32 (span, offset + 28)
    LazyBindOff = reader.ReadInt32 (span, offset + 32)
    LazyBindSize = reader.ReadUInt32 (span, offset + 36)
    ExportOff = reader.ReadInt32 (span, offset + 40)
    ExportSize = reader.ReadUInt32 (span, offset + 44) }

let parseFuncStarts (span: ByteSpan) reader offset cmdType cmdSize =
  { Cmd = cmdType
    CmdSize = cmdSize
    DataOffset = (reader: IBinReader).ReadInt32 (span, offset + 8)
    DataSize = reader.ReadUInt32 (span, offset + 12) }

let parseCmd baddr (span: ByteSpan) (reader: IBinReader) cls offset =
  let cmdType =
    reader.ReadInt32 (span, offset) |> LanguagePrimitives.EnumOfValue
  let cmdSize = reader.ReadUInt32 (span, offset + 4)
  let command =
    match cmdType with
    | LoadCmdType.LCSegment
    | LoadCmdType.LCSegment64 ->
      Segment (parseSegCmd span reader baddr cls offset cmdType cmdSize)
    | LoadCmdType.LCSymTab ->
      SymTab (parseSymCmd span reader offset cmdType cmdSize)
    | LoadCmdType.LCDySymTab ->
      DySymTab (parseDySymCmd span reader offset cmdType cmdSize)
    | LoadCmdType.LCMain ->
      Main (parseMainCmd span reader baddr offset cmdType cmdSize)
    | LoadCmdType.LCLoadDyLib ->
      DyLib (parseDyLibCmd span reader offset cmdType cmdSize)
    | LoadCmdType.LCDyLDInfo
    | LoadCmdType.LCDyLDInfoOnly ->
      DyLdInfo (parseDyLdInfo span reader offset cmdType cmdSize)
    | LoadCmdType.LCFunStarts ->
      FuncStarts (parseFuncStarts span reader offset cmdType cmdSize)
    | _ -> Unhandled { Cmd = cmdType; CmdSize = cmdSize }
  struct (command, Convert.ToInt32 cmdSize)

let rec private cmdLoop baseAddr span reader machHdr cNum acc offset =
  if cNum = 0u then List.rev acc
  else
    let struct (cmd, cmdSize) =
      parseCmd baseAddr span reader machHdr.Class offset
    cmdLoop baseAddr span reader machHdr
            (cNum - 1u) (cmd :: acc) (offset + cmdSize)

let parse baseAddr span reader machHdr =
  let cmdOffset = if machHdr.Class = WordSize.Bit32 then 28 else 32
  cmdLoop baseAddr span reader machHdr machHdr.NumCmds [] cmdOffset
