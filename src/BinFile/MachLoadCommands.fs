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

module internal B2R2.BinFile.Mach.LoadCommands

open System
open B2R2
open B2R2.BinFile.FileHelper

let parseSegCmd (reader: BinReader) cls offset =
  { SecOff = offset + if cls = WordSize.Bit64 then 72 else 56
    SegCmdName = peekCStringOfSize reader (offset + 8) 16
    VMAddr = peekHeaderNative reader cls offset 24 24
    VMSize = peekHeaderNative reader cls offset 28 32
    FileOff = peekHeaderNative reader cls offset 32 40
    FileSize = peekHeaderNative reader cls offset 36 48
    MaxProt = peekHeaderI32 reader cls offset 40 56
    InitProt = peekHeaderI32 reader cls offset 44 60
    NumSecs = peekHeaderU32 reader cls offset 48 64
    SegFlag = peekHeaderU32 reader cls offset 52 68 }

let parseSymCmd (reader: BinReader) offset =
  { SymOff = offset + 8 |> reader.PeekInt32
    NumOfSym = offset + 12 |> reader.PeekUInt32
    StrOff = offset + 16 |> reader.PeekInt32
    StrSize = offset + 20 |> reader.PeekUInt32 }

let parseDySymCmd (reader: BinReader) offset =
  { IdxLocalSym = offset + 8 |> reader.PeekUInt32
    NumLocalSym = offset + 12 |> reader.PeekUInt32
    IdxExtSym = offset + 16 |> reader.PeekUInt32
    NumExtSym = offset + 20 |> reader.PeekUInt32
    IdxUndefSym = offset + 24 |> reader.PeekUInt32
    NumUndefSym = offset + 28 |> reader.PeekUInt32
    TOCOffset = offset + 32 |> reader.PeekUInt32
    NumTOCContents = offset + 36 |> reader.PeekUInt32
    ModTabOff = offset + 40 |> reader.PeekUInt32
    NumModTab = offset + 44 |> reader.PeekUInt32
    ExtRefSymOff = offset + 48 |> reader.PeekUInt32
    NumExtRefSym = offset + 52 |> reader.PeekUInt32
    IndirectSymOff = offset + 56 |> reader.PeekUInt32
    NumIndirectSym = offset + 60 |> reader.PeekUInt32
    ExtRelOff = offset + 64 |> reader.PeekUInt32
    NumExtRel = offset + 68 |> reader.PeekUInt32
    LocalRelOff = offset + 72 |> reader.PeekUInt32
    NumLocalRel = offset + 76 |> reader.PeekUInt32 }

let parseMainCmd (reader: BinReader) offset =
  { EntryOff = offset + 8 |> reader.PeekUInt64
    StackSize = offset + 16 |> reader.PeekUInt64 }

/// Read lc_str string.
let readLCStr (reader: BinReader) (size: uint32) offset =
  let strOffset = reader.PeekInt32 (offset + 8)
  let strLen = Convert.ToInt32 size - strOffset
  let bs = reader.PeekBytes (strLen, offset + strOffset)
  ByteArray.extractCString bs 0

let parseDyLibCmd (reader: BinReader) size offset =
  { DyLibName = readLCStr reader size offset
    DyLibTimeStamp = offset + 12 |> reader.PeekUInt32
    DyLibCurVer = offset + 16 |> reader.PeekUInt32
    DyLibCmpVer = offset + 20 |> reader.PeekUInt32 }

let parseDyLdInfo (reader: BinReader) offset =
  { RebaseOff = offset + 8 |> reader.PeekInt32
    RebaseSize = offset + 12 |> reader.PeekUInt32
    BindOff = offset + 16 |> reader.PeekInt32
    BindSize = offset + 20 |> reader.PeekUInt32
    WeakBindOff = offset + 24 |> reader.PeekInt32
    WeakBindSize = offset + 28 |> reader.PeekUInt32
    LazyBindOff = offset + 32 |> reader.PeekInt32
    LazyBindSize = offset + 36 |> reader.PeekUInt32
    ExportOff = offset + 40 |> reader.PeekInt32
    ExportSize = offset + 44 |> reader.PeekUInt32 }

let parseCmd (reader: BinReader) cls offset =
  let cmdType = reader.PeekInt32 offset |> LanguagePrimitives.EnumOfValue
  let cmdSize = reader.PeekUInt32 (offset + 4)
  let command =
    match cmdType with
    | LoadCmdType.LCSegment
    | LoadCmdType.LCSegment64 -> Segment (parseSegCmd reader cls offset)
    | LoadCmdType.LCSymTab -> SymTab (parseSymCmd reader offset)
    | LoadCmdType.LCDySymTab -> DySymTab (parseDySymCmd reader offset)
    | LoadCmdType.LCMain -> Main (parseMainCmd reader offset)
    | LoadCmdType.LCLoadDyLib -> DyLib (parseDyLibCmd reader cmdSize offset)
    | LoadCmdType.LCDyLDInfo
    | LoadCmdType.LCDyLDInfoOnly -> DyLdInfo (parseDyLdInfo reader offset)
    | _ -> Unhandled { Cmd = cmdType; CmdSize = cmdSize }
  struct (command, Convert.ToInt32 cmdSize)

let parse reader machHdr =
  let rec loop cNum acc offset =
    if cNum = 0u then List.rev acc
    else let struct (cmd, cmdSize) = parseCmd reader machHdr.Class offset
         loop (cNum - 1u) (cmd :: acc) (offset + cmdSize)
  let cmdOffset = if machHdr.Class = WordSize.Bit32 then 28 else 32
  cmdOffset |> loop machHdr.NumCmds []
