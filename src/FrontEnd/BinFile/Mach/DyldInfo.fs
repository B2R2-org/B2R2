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

/// Represents an opcode in the LC_DYLD_INFO rebase opcode stream. The high
/// nibble selects the operation; the low nibble carries an immediate operand.
type internal RebaseOpcode =
  /// It's finished.
  | DONE = 0x00
  /// Set type to immediate (lower 4-bits). Used for ordinal numbers from
  /// 0-15.
  | SET_TYPE_IMM = 0x10
  /// Set segment's index to immediate (lower 4-bits) and segment's offset to
  /// following ULEB128 encoding.
  | SET_SEGMENT_AND_OFFSET_ULEB = 0x20
  /// Add segment's offset with the following ULEB128 encoding.
  | ADD_ADDR_ULEB = 0x30
  /// Add segment's offset with immediate scaling.
  | ADD_ADDR_IMM_SCALED = 0x40
  /// Rebase in the range of ``[segment's offset; segment's offset +
  /// immediate * sizeof(ptr)]``.
  | DO_REBASE_IMM_TIMES = 0x50
  /// Same as REBASE_OPCODE_DO_REBASE_IMM_TIMES but *immediate* is replaced
  /// with ULEB128 value.
  | DO_REBASE_ULEB_TIMES = 0x60
  /// Rebase and increment segment's offset with following ULEB128 encoding +
  /// pointer's size.
  | DO_REBASE_ADD_ADDR_ULEB = 0x70
  /// Rebase and skip several bytes.
  | DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

/// Represents an opcode in the LC_DYLD_INFO bind opcode stream. The same
/// encoding is shared by the regular, weak, and lazy bind streams. The high
/// nibble selects the operation; the low nibble carries an immediate operand.
type internal BindOpcode =
  /// It's finished.
  | DONE = 0x00
  /// Set the library ordinal to the immediate (lower 4-bits).
  | SET_DYLIB_ORDINAL_IMM = 0x10
  /// Set the library ordinal to the following ULEB128 encoding.
  | SET_DYLIB_ORDINAL_ULEB = 0x20
  /// Set a special (non-positive) library ordinal from the immediate.
  | SET_DYLIB_SPECIAL_IMM = 0x30
  /// Set the symbol name (trailing C-string) and bind flags (immediate).
  | SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
  /// Set the bind type to the immediate (lower 4-bits).
  | SET_TYPE_IMM = 0x50
  /// Set the addend to the following SLEB128 encoding.
  | SET_ADDEND_SLEB = 0x60
  /// Set segment's index to immediate (lower 4-bits) and segment's offset to
  /// following ULEB128 encoding.
  | SET_SEGMENT_AND_OFFSET_ULEB = 0x70
  /// Add segment's offset with the following ULEB128 encoding.
  | ADD_ADDR_ULEB = 0x80
  /// Bind at segment's offset and increment it by pointer's size.
  | DO_BIND = 0x90
  /// Bind and increment segment's offset with following ULEB128 encoding +
  /// pointer's size.
  | DO_BIND_ADD_ADDR_ULEB = 0xA0
  /// Bind and increment segment's offset with immediate scaling + pointer's
  /// size.
  | DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
  /// Bind several times, skipping several bytes between each.
  | DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

/// Parses the LC_DYLD_INFO rebase and bind opcode streams into fixups. The
/// regular, weak, and lazy bind streams all share the same opcode encoding, so
/// the same VM decodes them. The opcodes drive a tiny VM that walks (segment,
/// offset) cursors and emits a fixup at each DO_REBASE / DO_BIND. Pointer size
/// is assumed to be 8 bytes.
module internal DyldInfo =
  let [<Literal>] private PtrSize = 8

  let private chooser = function
    | DyLdInfo(_, _, c) -> Some c
    | _ -> None

  let inline private appendToList (lst: ResizeArray<_>) elm =
    lst.Add elm

  /// Decodes the rebase opcode stream, accumulating Rebase fixups. The target
  /// is the unslid pointer stored in place plus the image base.
  let private parseRebase toolBox (segCmds: _[]) off size acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let baseAddr = toolBox.BaseAddress
    let endOff = off + size
    let mutable cur = off
    let mutable segIdx = 0
    let mutable segOff = 0UL
    let emit count =
      for _ = 1 to count do
        let seg = segCmds[segIdx]
        let value = reader.ReadUInt64(bytes, int seg.FileOff + int segOff)
        { FixupAddr = seg.VMAddr + segOff
          FixupTarget = Rebase(baseAddr + value) }
        |> appendToList acc
        segOff <- segOff + uint64 PtrSize
    while cur < endOff do
      let opcode = int bytes[cur] &&& 0xF0
      let imm = int bytes[cur] &&& 0x0F
      cur <- cur + 1
      match enum<RebaseOpcode> opcode with
      | RebaseOpcode.SET_SEGMENT_AND_OFFSET_ULEB ->
        segIdx <- imm
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        segOff <- v
        cur <- cur + n
      | RebaseOpcode.ADD_ADDR_ULEB ->
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        segOff <- segOff + v
        cur <- cur + n
      | RebaseOpcode.ADD_ADDR_IMM_SCALED ->
        segOff <- segOff + uint64 (imm * PtrSize)
      | RebaseOpcode.DO_REBASE_IMM_TIMES -> emit imm
      | RebaseOpcode.DO_REBASE_ULEB_TIMES ->
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        cur <- cur + n
        emit (int v)
      | RebaseOpcode.DO_REBASE_ADD_ADDR_ULEB ->
        emit 1
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        segOff <- segOff + v
        cur <- cur + n
      | RebaseOpcode.DO_REBASE_ULEB_TIMES_SKIPPING_ULEB ->
        let count, n1 = reader.ReadUInt64LEB128(bytes, cur)
        cur <- cur + n1
        let skip, n2 = reader.ReadUInt64LEB128(bytes, cur)
        cur <- cur + n2
        for _ = 1 to int count do
          let seg = segCmds[segIdx]
          let value = reader.ReadUInt64(bytes, int seg.FileOff + int segOff)
          { FixupAddr = seg.VMAddr + segOff
            FixupTarget = Rebase(baseAddr + value) }
          |> appendToList acc
          segOff <- segOff + uint64 PtrSize + skip
      | _ -> () (* DONE, SET_TYPE_IMM, or unknown: no effect *)

  /// Decodes a bind opcode stream, accumulating Bind fixups. The bind type is
  /// consumed but not retained.
  let private parseBind toolBox (segCmds: _[]) dylibs off (size: uint32) acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let size = int size
    let endOff = off + size
    let mutable cur = off
    let mutable segIdx = 0
    let mutable segOff = 0UL
    let mutable name = ""
    let mutable addend = 0L
    let mutable libOrd = 0
    let emit () =
      let seg = segCmds[segIdx]
      { FixupAddr = seg.VMAddr + segOff
        FixupTarget = Bind(name, Fixup.resolveLibrary dylibs libOrd, addend) }
      |> appendToList acc
      segOff <- segOff + uint64 PtrSize
    while cur < endOff do
      let opcode = int bytes[cur] &&& 0xF0
      let imm = int bytes[cur] &&& 0x0F
      cur <- cur + 1
      match enum<BindOpcode> opcode with
      | BindOpcode.SET_DYLIB_ORDINAL_IMM -> libOrd <- imm
      | BindOpcode.SET_DYLIB_ORDINAL_ULEB ->
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        libOrd <- int v
        cur <- cur + n
      | BindOpcode.SET_DYLIB_SPECIAL_IMM ->
        libOrd <- if imm = 0 then 0 else imm - 16
      | BindOpcode.SET_SYMBOL_TRAILING_FLAGS_IMM ->
        let span = ReadOnlySpan(bytes, cur, endOff - cur)
        name <- ByteArray.extractCStringFromSpan span 0
        cur <- cur + name.Length + 1
      | BindOpcode.SET_ADDEND_SLEB ->
        let v, n = reader.ReadInt64LEB128(bytes, cur)
        addend <- v
        cur <- cur + n
      | BindOpcode.SET_SEGMENT_AND_OFFSET_ULEB ->
        segIdx <- imm
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        segOff <- v
        cur <- cur + n
      | BindOpcode.ADD_ADDR_ULEB ->
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        segOff <- segOff + v
        cur <- cur + n
      | BindOpcode.DO_BIND -> emit ()
      | BindOpcode.DO_BIND_ADD_ADDR_ULEB ->
        emit ()
        let v, n = reader.ReadUInt64LEB128(bytes, cur)
        segOff <- segOff + v
        cur <- cur + n
      | BindOpcode.DO_BIND_ADD_ADDR_IMM_SCALED ->
        emit ()
        segOff <- segOff + uint64 (imm * PtrSize)
      | BindOpcode.DO_BIND_ULEB_TIMES_SKIPPING_ULEB ->
        let count, n1 = reader.ReadUInt64LEB128(bytes, cur)
        cur <- cur + n1
        let skip, n2 = reader.ReadUInt64LEB128(bytes, cur)
        cur <- cur + n2
        for _ = 1 to int count do
          let seg = segCmds[segIdx]
          { FixupAddr = seg.VMAddr + segOff
            FixupTarget =
              Bind(name, Fixup.resolveLibrary dylibs libOrd, addend) }
          |> appendToList acc
          segOff <- segOff + uint64 PtrSize + skip
      | _ -> () (* DONE and IMM-only setters need no operand handling *)

  let parse toolBox cmds segCmds =
    match Array.tryPick chooser cmds with
    | None -> [||]
    | Some info ->
      let acc = ResizeArray()
      let dylibs = Fixup.dylibNames cmds
      parseRebase toolBox segCmds info.RebaseOff (int info.RebaseSize) acc
      parseBind toolBox segCmds dylibs info.BindOff info.BindSize acc
      parseBind toolBox segCmds dylibs info.WeakBindOff info.WeakBindSize acc
      parseBind toolBox segCmds dylibs info.LazyBindOff info.LazyBindSize acc
      acc.ToArray()
