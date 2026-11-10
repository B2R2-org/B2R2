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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// Represents jump table information.
type JmpTableInfo =
  { /// The address of the indirect branch instruction corresponding to the jump
    /// table.
    InsAddr: Addr
    /// The base address to be added to compute the final jump target.
    JumpBase: Addr
    /// The address of the jump table.
    TableAddress: Addr
    /// The size of each entry in the jump table (in bytes).
    EntrySize: int
    /// The number of bits by which the code shifts an entry to the left before
    /// adding it to the base, e.g., two for GCC on ARM, whose entries count
    /// instructions rather than bytes.
    EntryShift: int
    /// Indicates whether the load that reads an entry sign-extends it, rather
    /// than zero-extends it.
    IsSignedEntry: bool
    /// The number of entries in the jump table.
    mutable NumEntries: int
    /// Indirect branch instructions that share this table and should receive
    /// the same recovered outgoing edges as the original instruction.
    mutable WaitingInstructions: Addr list
    /// Indicates whether the jump table has only a single entry. We use this
    /// information when the jump table is accessed via a constant address
    /// without any index computation (e.g., jmp qword ptr [constant_address]).
    /// If so, we do not expand the entries during jump table analysis.
    IsSingleEntry: bool
    /// The number of entries, from the first, that the range check right before
    /// the indirect branch admits, or None if no such check bounds the table
    /// from its first entry.
    OwnRangeEntries: int option
    /// The number of entries, from the first, that a constant mask on the
    /// index lets it select, or None if no mask bounds the table within its
    /// section. Unlike a range check, a mask may let the index select more
    /// entries than the table has.
    MaskedEntries: int option
    /// Indicates whether the jump table is accessed via a function pointer
    /// table.
    mutable IsFunctionPointerTable: bool }

/// Provides functions to read the entries of a jump table.
[<RequireQualifiedAccess>]
module JmpTableInfo =
  /// Tells whether the given index lies past the entries that the range check
  /// of the given table admits, or that a mask on its index lets it select,
  /// when the code shifts its entries. Whatever a shifted entry holds sends the
  /// jump close by, so the bytes after such a table pass for more of its
  /// entries, and only the check or the mask keeps them out.
  let private isPastIndexBound jmptbl idx =
    let isPast = Option.exists (fun n -> idx >= n)
    jmptbl.EntryShift > 0
    && (isPast jmptbl.OwnRangeEntries || isPast jmptbl.MaskedEntries)

  /// Tells whether the entries of the given table are addresses of their own,
  /// as wide as a pointer, in an ELF binary, where a relocation of a slot says
  /// what the loader writes into it.
  let private isRelocatable (file: IBinFile) jmptbl =
    file.Format = FileFormat.ELFBinary
    && jmptbl.JumpBase = 0UL
    && jmptbl.EntrySize = WordSize.toByteWidth file.ISA.WordSize

  /// Tells whether the loader rebases the given binary as a whole, in which
  /// case every address that the binary holds has a relocation.
  let private isRebased (file: IBinFile) =
    file.IsBaseRelative && file.Kind <> BinFileKind.Object

  /// Reads the target of the entry at the given address, which the entry
  /// offsets from the base once extended and shifted as the code reading it
  /// does.
  let private tryReadEntry (hdl: BinHandle) jmptbl (addr: Addr) =
    let value =
      if jmptbl.IsSignedEntry then
        hdl.TryReadInt(addr, jmptbl.EntrySize) |> Result.map uint64
      else
        hdl.TryReadUInt(addr, jmptbl.EntrySize)
    match value with
    | Ok value -> Some(jmptbl.JumpBase + (value <<< jmptbl.EntryShift))
    | Error _ -> None

  /// Reads the target of the entry at the given index of the given table, or
  /// returns None if its slot holds no entry. An entry that is an address
  /// holds what the relocation of its slot writes, which the file may leave
  /// out, and in a binary that the loader rebases, a slot without one holds no
  /// address. A slot that lies past the bytes of the binary holds no entry
  /// either, nor does one of shifted entries past what the range check, or a
  /// mask on the index, admits.
  let tryReadTarget (hdl: BinHandle) jmptbl idx =
    let file = hdl.File
    let addr = jmptbl.TableAddress + uint64 (idx * jmptbl.EntrySize)
    if isPastIndexBound jmptbl idx then
      None
    elif isRelocatable file jmptbl then
      match BinFileOps.tryComputeRelocationValue file addr with
      | Ok target -> Some target
      | Error _ when isRebased file -> None
      | Error _ -> tryReadEntry hdl jmptbl addr
    else
      tryReadEntry hdl jmptbl addr
