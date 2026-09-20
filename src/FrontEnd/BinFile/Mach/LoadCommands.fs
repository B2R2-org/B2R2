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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

module internal LoadCommands =
  let parseSegCmd toolBox cmdOffset span =
    let reader = toolBox.Reader
    let cls = toolBox.Header.Class
    { SecOff = cmdOffset + selectByWordSize cls 56 72
      SegCmdName = readCStringOfSize span 8 16
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

  /// Returns where the program counter sits within a thread state of the given
  /// flavor, in bytes, for the flavors that carry the general registers. The
  /// other flavors (floating point, debug, exception) name no entry point.
  let private pcOffsetOfFlavor cpuType flavor =
    match cpuType, flavor with
    | CPUType.I386, 1u -> Some 40 (* x86_THREAD_STATE32.eip *)
    | CPUType.X64, 4u -> Some 128 (* x86_THREAD_STATE64.rip *)
    | CPUType.ARM, 1u -> Some 60 (* ARM_THREAD_STATE.pc *)
    | CPUType.ARM64, 6u -> Some 256 (* ARM_THREAD_STATE64.pc *)
    | _ -> None

  /// Reads the initial program counter out of a thread state command, whose
  /// payload is a run of (flavor, count, state) triples that the count of each
  /// steps over. The count is in 32-bit words, as the kernel structures are.
  let rec private readThreadPC toolBox (span: ByteSpan) offset cmdSize =
    let reader = toolBox.Reader
    if offset + 8 > cmdSize then
      None
    else
      let flavor = reader.ReadUInt32(span, offset)
      let count = int (reader.ReadUInt32(span, offset + 4))
      let stateOff = offset + 8
      let next = stateOff + count * 4
      if count < 0 || next > cmdSize then
        None
      else
        match pcOffsetOfFlavor toolBox.Header.CPUType flavor with
        | Some pcOff when stateOff + pcOff < next ->
          let cls = toolBox.Header.Class
          Some(readUIntByWordSize span reader cls (stateOff + pcOff))
        | _ ->
          readThreadPC toolBox span next cmdSize

  let parseMainCmd toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { EntryOff = reader.ReadUInt64(span, 8)
      StackSize = reader.ReadUInt64(span, 16) }

  /// Read lc_str string.
  /// Reads the sixteen bytes that an LC_UUID command carries after its kind
  /// and its size. A command too short to hold them names nothing.
  let readUuid (span: ByteSpan) =
    if span.Length < 24 then [||] else span.Slice(8, 16).ToArray()

  /// Reads an lc_str, whose field at the given offset holds where the string
  /// starts within the command. A file is free to write an offset the command
  /// does not reach, which makes the command malformed rather than a slice to
  /// be attempted.
  let readLCStr toolBox cmdSize (span: ByteSpan) fieldOffset =
    let strOffset = toolBox.Reader.ReadInt32(span, fieldOffset)
    if strOffset < 0 || strOffset >= cmdSize then
      raise InvalidFileFormatException
    else
      let strLen = cmdSize - strOffset
      ByteArray.extractCStringFromSpan (span.Slice(strOffset, strLen)) 0

  let parseDyLibCmd toolBox cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { DyLibName = readLCStr toolBox cmdSize span 8
      DyLibTimeStamp = reader.ReadUInt32(span, 12)
      DyLibCurVer = reader.ReadUInt32(span, 16)
      DyLibCmpVer = reader.ReadUInt32(span, 20) }

  /// Reads the run of NUL-terminated strings that a linker option command
  /// holds, from the given offset onwards. A command whose last string is
  /// left unterminated names an option running past its own end, which makes
  /// the command malformed rather than a string to read to the end of it.
  let rec private readOptionStrings (span: ByteSpan) count offset acc =
    if count = 0 then
      List.rev acc |> List.toArray
    else
      let nul = span.Slice(offset).IndexOf 0uy
      if nul < 0 then
        raise InvalidFileFormatException
      else
        let str = ByteArray.extractCStringFromSpan span offset
        readOptionStrings span (count - 1) (offset + nul + 1) (str :: acc)

  /// Parses a linker option command, whose count is followed by that many
  /// strings from offset 12 on. Each of them takes a byte at the very least,
  /// so a count the command cannot hold is one to reject before reading.
  let parseLinkerOption toolBox cmdSize (span: ByteSpan) =
    let count = toolBox.Reader.ReadInt32(span, 8)
    if count < 0 || 12 + count > cmdSize then
      raise InvalidFileFormatException
    else
      readOptionStrings span count 12 []

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

  let parseChainedFixups toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { FixupsDataOffset = reader.ReadInt32(span, 8)
      FixupsDataSize = reader.ReadUInt32(span, 12) }

  let parseExportsTrie toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { TrieOffset = reader.ReadInt32(span, 8)
      TrieSize = reader.ReadUInt32(span, 12) }

  let parseDataInCode toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { TableOffset = reader.ReadInt32(span, 8)
      TableSize = reader.ReadUInt32(span, 12) }

  let parseFilesetEntry toolBox cmdSize (span: ByteSpan) =
    let reader = toolBox.Reader
    { EntryVMAddr = reader.ReadUInt64(span, 8) + toolBox.BaseAddress
      EntryFileOffset = reader.ReadUInt64(span, 16)
      EntryName = readLCStr toolBox cmdSize span 24 }

  let parseEncryptionInfo toolBox (span: ByteSpan) =
    let reader = toolBox.Reader
    { CryptOffset = reader.ReadInt32(span, 8)
      CryptSize = reader.ReadUInt32(span, 12)
      CryptId = reader.ReadUInt32(span, 16) }

  /// Checks that a command at the given offset both fits in the file and is
  /// long enough to hold what is being read out of it, so a truncated or
  /// corrupt table is reported as a bad file rather than as a span that could
  /// not be cut.
  let private checkCmdBounds (bytes: byte[]) offset size =
    if offset < 0 || size < 8 || offset + size > bytes.Length then
      raise InvalidFileFormatException
    else
      ()

  let parseCmd ({ Bytes = bytes; Reader = reader } as toolBox) offset =
    let cmdOffset = int offset
    checkCmdBounds bytes cmdOffset 8
    let cmdHdr = ReadOnlySpan(bytes, cmdOffset, 8)
    let cmdType = reader.ReadInt32(cmdHdr, 0) |> LanguagePrimitives.EnumOfValue
    let cmdSize = reader.ReadInt32(cmdHdr, 4)
    checkCmdBounds bytes cmdOffset cmdSize
    let span = ReadOnlySpan(bytes, cmdOffset, cmdSize)
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
      | CmdType.LC_THREAD
      | CmdType.LC_UNIXTHREAD ->
        let pc = readThreadPC toolBox span 8 cmdSize
        Thread(cmdType, uint32 cmdSize, pc)
      | CmdType.LC_LOAD_DYLIB
      | CmdType.LC_LOAD_WEAK_DYLIB
      | CmdType.LC_REEXPORT_DYLIB
      | CmdType.LC_LOAD_UPWARD_DYLIB
      | CmdType.LC_LAZY_LOAD_DYLIB ->
        DyLib(cmdType, uint32 cmdSize, parseDyLibCmd toolBox cmdSize span)
      | CmdType.LC_ID_DYLIB ->
        DyLibId(cmdType, uint32 cmdSize, parseDyLibCmd toolBox cmdSize span)
      | CmdType.LC_LINKER_OPTION ->
        let opts = parseLinkerOption toolBox cmdSize span
        LinkerOption(cmdType, uint32 cmdSize, opts)
      | CmdType.LC_LOAD_DYLINKER ->
        DyLinker(cmdType, uint32 cmdSize, readLCStr toolBox cmdSize span 8)
      | CmdType.LC_RPATH ->
        Rpath(cmdType, uint32 cmdSize, readLCStr toolBox cmdSize span 8)
      | CmdType.LC_UUID ->
        Uuid(cmdType, uint32 cmdSize, readUuid span)
      | CmdType.LC_DYLD_INFO
      | CmdType.LC_DYLD_INFO_ONLY ->
        DyLdInfo(cmdType, uint32 cmdSize, parseDyLdInfo toolBox span)
      | CmdType.LC_FUNCTION_STARTS ->
        FuncStarts(cmdType, uint32 cmdSize, parseFuncStarts toolBox span)
      | CmdType.LC_DYLD_CHAINED_FIXUPS ->
        ChainedFixups(cmdType, uint32 cmdSize, parseChainedFixups toolBox span)
      | CmdType.LC_DYLD_EXPORTS_TRIE ->
        ExportsTrie(cmdType, uint32 cmdSize, parseExportsTrie toolBox span)
      | CmdType.LC_DATA_IN_CODE ->
        DataInCode(cmdType, uint32 cmdSize, parseDataInCode toolBox span)
      | CmdType.LC_FILESET_ENTRY ->
        let entry = parseFilesetEntry toolBox cmdSize span
        FilesetEntry(cmdType, uint32 cmdSize, entry)
      | CmdType.LC_ENCRYPTION_INFO
      | CmdType.LC_ENCRYPTION_INFO_64 ->
        let info = parseEncryptionInfo toolBox span
        EncryptionInfo(cmdType, uint32 cmdSize, info)
      | _ ->
        Unhandled(cmdType, uint32 cmdSize)
    struct (command, uint64 cmdSize)

  /// Parses the load command table, which follows the header wherever that
  /// sits: at the start of the image for an ordinary file or a universal
  /// binary's slice, and deep inside the container for a fileset entry.
  let parse ({ Header = hdr } as toolBox) =
    let tableOffset = selectByWordSize hdr.Class 28UL 32UL
    let mutable cmdOffset = toolBox.HeaderOffset + tableOffset
    let numCmds = Convert.ToInt32 hdr.NumCmds
    let cmds = Array.zeroCreate numCmds
    for i = 0 to numCmds - 1 do
      let struct (cmd, cmdSize) = parseCmd toolBox cmdOffset
      cmds[i] <- cmd
      cmdOffset <- cmdOffset + cmdSize
    cmds
