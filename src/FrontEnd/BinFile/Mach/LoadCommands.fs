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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

module internal LoadCommands =
  let parseSegCmd toolBox cmdOffset span =
    let reader = toolBox.Reader
    let cls = toolBox.Header.Class
    { SecOff = cmdOffset + selectByWordSize cls 56 72
      SegCmdName = readCString span 8
      VMAddr = readUIntByWordSize span reader cls 24 + toolBox.BaseAddress
      VMSize = readUIntByWordSizeAndOffset span reader cls 28 32
      FileOff = readUIntByWordSizeAndOffset span reader cls 32 40
      FileSize = readUIntByWordSizeAndOffset span reader cls 36 48
      MaxProt = reader.ReadInt32(span, selectByWordSize cls 40 56)
      InitProt = reader.ReadInt32(span, selectByWordSize cls 44 60)
      NumSecs = reader.ReadUInt32(span, selectByWordSize cls 48 64)
      SegFlag = reader.ReadUInt32(span, selectByWordSize cls 52 68) }

  let parseSymCmd toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { SymOff = reader.ReadInt32(span, 8)
      NumOfSym = reader.ReadUInt32(span, 12)
      StrOff = reader.ReadInt32(span, 16)
      StrSize = reader.ReadUInt32(span, 20) }

  let parseDySymCmd toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { IdxLocalSym = reader.ReadUInt32(span, 8)
      NumLocalSym = reader.ReadUInt32(span, 12)
      IdxExtSym = reader.ReadUInt32(span, 16)
      NumExtSym = reader.ReadUInt32(span, 20)
      IdxUndefSym = reader.ReadUInt32(span, 24)
      NumUndefSym = reader.ReadUInt32(span, 28)
      TOCOffset = reader.ReadUInt32(span, 32)
      NumTOCContents = reader.ReadUInt32(span, 36)
      ModTabOff = reader.ReadUInt32(span, 40)
      NumModTab = reader.ReadUInt32(span, 44)
      ExtRefSymOff = reader.ReadUInt32(span, 48)
      NumExtRefSym = reader.ReadUInt32(span, 52)
      IndirectSymOff = reader.ReadUInt32(span, 56)
      NumIndirectSym = reader.ReadUInt32(span, 60)
      ExtRelOff = reader.ReadUInt32(span, 64)
      NumExtRel = reader.ReadUInt32(span, 68)
      LocalRelOff = reader.ReadUInt32(span, 72)
      NumLocalRel = reader.ReadUInt32(span, 76) }

  let parseMainCmd toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { EntryOff = reader.ReadUInt64(span, 8) + toolBox.BaseAddress
      StackSize = reader.ReadUInt64(span, 16) }

  /// Read lc_str string.
  let readLCStr toolBox cmdSize (span: ByteSpan) =
    let strOffset = toolBox.Reader.ReadInt32(span, 8)
    let strLen = cmdSize - strOffset
    ByteArray.extractCStringFromSpan (span.Slice(strOffset, strLen)) 0

  let parseDyLibCmd toolBox cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { DyLibName = readLCStr toolBox cmdSize span
      DyLibTimeStamp = reader.ReadUInt32(span, 12)
      DyLibCurVer = reader.ReadUInt32(span, 16)
      DyLibCmpVer = reader.ReadUInt32(span, 20) }

  let parseDyLdInfo toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { RebaseOff = reader.ReadInt32(span, 8)
      RebaseSize = reader.ReadUInt32(span, 12)
      BindOff = reader.ReadInt32(span, 16)
      BindSize = reader.ReadUInt32(span, 20)
      WeakBindOff = reader.ReadInt32(span, 24)
      WeakBindSize = reader.ReadUInt32(span, 28)
      LazyBindOff = reader.ReadInt32(span, 32)
      LazyBindSize = reader.ReadUInt32(span, 36)
      ExportOff = reader.ReadInt32(span, 40)
      ExportSize = reader.ReadUInt32(span, 44) }

  let parseFuncStarts toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { DataOffset = reader.ReadInt32(span, 8)
      DataSize = reader.ReadUInt32(span, 12) }

  let parseCmd ({ Bytes = bytes; Reader = reader } as toolBox) offset =
    let cmdHdr = ReadOnlySpan(bytes, int offset, 8)
    let cmdType = reader.ReadInt32(cmdHdr, 0) |> LanguagePrimitives.EnumOfValue
    let cmdSize = reader.ReadInt32(cmdHdr, 4)
    let cmdOffset = int offset
    let span = ReadOnlySpan(bytes, int offset, cmdSize)
    let command =
      match cmdType with
      | CmdType.LC_SEGMENT
      | CmdType.LC_SEGMENT64 ->
        Segment(cmdType, uint32 cmdSize, parseSegCmd toolBox cmdOffset span)
      | CmdType.LC_SYMTAB ->
        SymTab(cmdType, uint32 cmdSize, parseSymCmd toolBox span)
      | CmdType.LC_DYSYMTAB ->
        DySymTab(cmdType, uint32 cmdSize, parseDySymCmd toolBox span)
      | CmdType.LC_MAIN ->
        Main(cmdType, uint32 cmdSize, parseMainCmd toolBox span)
      | CmdType.LC_LOAD_DYLIB ->
        DyLib(cmdType, uint32 cmdSize, parseDyLibCmd toolBox cmdSize span)
      | CmdType.LC_DYLD_INFO
      | CmdType.LC_DYLD_INFO_ONLY ->
        DyLdInfo(cmdType, uint32 cmdSize, parseDyLdInfo toolBox span)
      | CmdType.LC_FUNCTION_STARTS ->
        FuncStarts(cmdType, uint32 cmdSize, parseFuncStarts toolBox span)
      | _ ->
        Unhandled(cmdType, uint32 cmdSize)
    struct (command, uint64 cmdSize)

  let parse ({ Header = hdr } as toolBox) =
    let mutable cmdOffset = selectByWordSize hdr.Class 28UL 32UL
    let numCmds = Convert.ToInt32 hdr.NumCmds
    let cmds = Array.zeroCreate numCmds
    for i = 0 to numCmds - 1 do
      let struct (cmd, cmdSize) = parseCmd toolBox cmdOffset
      cmds[i] <- cmd
      cmdOffset <- cmdOffset + cmdSize
    cmds
