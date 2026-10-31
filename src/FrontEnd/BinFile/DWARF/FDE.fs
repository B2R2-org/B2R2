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

namespace B2R2.FrontEnd.BinFile.DWARF

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// Represents the Frame Description Entry (FDE).
type internal FDE =
  { PCBegin: Addr
    PCEnd: Addr
    LSDAPointer: Addr option
    /// Unwinding entries of this FDE, lazily decoded from its call frame
    /// instructions, as function ranges and LSDA pointers alone do not need
    /// them.
    UnwindingInfo: Lazy<UnwindingEntry list>
    /// Tells whether this FDE starts in the middle of another function's
    /// frame, as a fragment that a compiler split off the function does,
    /// rather than at a function entry. Unlike the unwinding entries, this is
    /// known without decoding them.
    StartsMidFrame: bool }

/// Resolves the relocation addend to apply at the given (pc-relative-adjusted)
/// FDE begin address, if a relocation exists there. This is needed for
/// relocatable objects (e.g., ELF ET_REL); formats or files without such
/// relocations can supply a resolver that always returns None.
type internal RelocationResolver = Addr -> uint64 option

[<RequireQualifiedAccess>]
module internal FDE =
  /// Raised when CIE is not found by FDE
  exception CIENotFoundByFDEException

  let tryFindAugmentation cie format =
    cie.Augmentations |> List.tryFind (fun aug -> aug.Format = format)

  let parsePCInfo cls span reader sAddr resolveReloc venc aenc offset =
    let myAddr = sAddr + uint64 offset
    let struct (addr, offset) =
      ExceptionHeaderValue.read cls span reader venc offset
    let struct (range, offset) =
      ExceptionHeaderValue.read cls span reader venc offset
    let beginAddr = ExceptionHeader.adjustAddr aenc myAddr addr
    let endAddr = beginAddr + range
    match (resolveReloc: RelocationResolver) beginAddr with
    | Some addend ->
      let beginAddr = addr + addend
      struct (beginAddr, beginAddr + range, offset)
    | None ->
      struct (beginAddr, endAddr, offset)

  let parseLSDA cls span reader sAddr aug offset =
    let _, offset = FileHelper.readULEB128 span offset
    let myAddr = sAddr + uint64 offset
    let struct (addr, offset) =
      ExceptionHeaderValue.read cls span reader aug.ValueEncoding offset
    let app = aug.ApplicationEncoding
    Some(ExceptionHeader.adjustAddr app myAddr addr), offset

  /// Defers the interpretation of the given call frame instructions. An empty
  /// or all-zero instruction area unwinds to nothing, and such an FDE never
  /// forces the initial state of its CIE.
  let parseCallFrameInstrs cie isa regs instrs loc =
    lazy
      let span = (instrs: ReadOnlyMemory<byte>).Span
      if span.IndexOfAnyExcept(0uy) < 0 then
        []
      else
        let initial = cie.InitialUnwinding.Value
        let cf = cie.CodeAlignmentFactor
        let df = cie.DataAlignmentFactor
        let rr = cie.ReturnAddressRegister
        let ir = initial.CFARegister
        let r = initial.Rule
        let cfa = initial.CFA
        let info, _, _ =
          CIE.getUnwind [] cfa r [] r isa regs ir cf df rr span 0 loc
        info

  /// Tells whether the call frame instructions of an FDE restate the frame,
  /// i.e., define the CFA or save a register, before they first advance the
  /// location. A function entry inherits its frame from the CIE and restates
  /// nothing there, while a fragment that a compiler split off a function,
  /// such as a GCC cold part, starts in the middle of that function's frame
  /// and has to. Only the instructions before the first advance are read, and
  /// one that cannot be decoded ends the reading, as its operands cannot be
  /// skipped.
  let rec startsMidFrame (span: ByteSpan) =
    if span.IsEmpty then
      false
    else
      let op = span[0]
      let op = if op &&& 0xc0uy > 0uy then op &&& 0xc0uy else op
      match CFAInstruction.parse op with
      | CFAInstruction.DW_CFA_def_cfa
      | CFAInstruction.DW_CFA_def_cfa_sf
      | CFAInstruction.DW_CFA_def_cfa_register
      | CFAInstruction.DW_CFA_def_cfa_offset
      | CFAInstruction.DW_CFA_def_cfa_offset_sf
      | CFAInstruction.DW_CFA_def_cfa_expression
      | CFAInstruction.DW_CFA_offset
      | CFAInstruction.DW_CFA_offset_extended
      | CFAInstruction.DW_CFA_offset_extended_sf
      | CFAInstruction.DW_CFA_val_offset
      | CFAInstruction.DW_CFA_val_offset_sf
      | CFAInstruction.DW_CFA_register
      | CFAInstruction.DW_CFA_expression
      | CFAInstruction.DW_CFA_val_expression
      | CFAInstruction.DW_CFA_GNU_negative_offset_extended ->
        true
      | CFAInstruction.DW_CFA_nop
      | CFAInstruction.DW_CFA_restore
      | CFAInstruction.DW_CFA_remember_state
      | CFAInstruction.DW_CFA_restore_state ->
        startsMidFrame (span.Slice 1)
      (* Marking the return address undefined, as _start does, saves
         nothing. *)
      | CFAInstruction.DW_CFA_restore_extended
      | CFAInstruction.DW_CFA_undefined
      | CFAInstruction.DW_CFA_same_value
      | CFAInstruction.DW_CFA_GNU_args_size ->
        let _, cnt = LEB128.decodeUInt64 (span.Slice 1)
        startsMidFrame (span.Slice(1 + cnt))
      | CFAInstruction.DW_CFA_advance_loc
      | CFAInstruction.DW_CFA_advance_loc1
      | CFAInstruction.DW_CFA_advance_loc2
      | CFAInstruction.DW_CFA_advance_loc4
      | CFAInstruction.DW_CFA_set_loc ->
        false
      | _ ->
        false

  let parse cls isa regs mem reader sAddr offset nextOffset resolveReloc cie =
    match cie with
    | Some cie ->
      let span = (mem: ReadOnlyMemory<byte>).Span
      let venc, aenc =
        match tryFindAugmentation cie 'R' with
        | Some aug ->
          aug.ValueEncoding, aug.ApplicationEncoding
        | None ->
          let absptr = ExceptionHeaderValue.DW_EH_PE_absptr
          let omit = ExceptionHeaderApplication.DW_EH_PE_omit
          absptr, omit
      let struct (b, e, offset) =
        parsePCInfo cls span reader sAddr resolveReloc venc aenc offset
      let lsdaPointer, offset =
        match tryFindAugmentation cie 'L' with
        | Some aug -> parseLSDA cls span reader sAddr aug offset
        | None -> None, offset
      let instrs = mem.Slice(offset, nextOffset - offset)
      let info = parseCallFrameInstrs cie isa regs instrs b
      { PCBegin = b
        PCEnd = e
        LSDAPointer = lsdaPointer
        UnwindingInfo = info
        StartsMidFrame = startsMidFrame instrs.Span }
    | None ->
      raise CIENotFoundByFDEException
