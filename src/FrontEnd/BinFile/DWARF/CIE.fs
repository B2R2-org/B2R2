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
open System.Runtime.InteropServices
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents the unwinding state that a CIE establishes for its FDEs, i.e.,
/// the state obtained by running the CIE's initial call frame instructions.
type internal InitialUnwindingState =
  { /// Initial set of unwinding rules.
    Rule: UnwindingRule
    /// Initial CFA register.
    CFARegister: byte
    /// Initial Canonical Frame Address (CFA).
    CFA: CanonicalFrameAddress }

/// Represents the Common Information Entry (CIE).
and internal CIE =
  { /// Version assigned to the call frame information structure.
    Version: uint8
    /// This value is a NUL terminated string that identifies the augmentation
    /// to the CIE or to the FDEs associated with this CIE
    AugmentationString: string
    /// This value shall be multiplied by the delta argument of an adavance
    /// location instruction to obtain the new location value.
    CodeAlignmentFactor: uint64
    /// This value shall be multiplied by the register offset argument of an
    /// offset instruction to obtain the new offset value.
    DataAlignmentFactor: int64
    /// Register that holds the return address.
    ReturnAddressRegister: byte
    /// Initial set of unwinding actions (i.e., call frame instructions). This
    /// is lazily computed, as the initial instructions need not be interpreted
    /// unless an actual unwinding result is requested.
    InitialUnwinding: Lazy<InitialUnwindingState>
    /// Augmentation data.
    Augmentations: Augmentation list }

/// Represents the CIE augmetation data.
and internal Augmentation =
  { Format: char
    ValueEncoding: ExceptionHeaderValue
    ApplicationEncoding: ExceptionHeaderApplication
    /// Address that the 'P' augmentation encodes, i.e., the personality
    /// routine governing the frames of this CIE. An indirect encoding
    /// (DW_EH_PE_indirect) makes this the address of the slot that holds the
    /// routine's address, which is all the file statically records. None for
    /// every other augmentation format.
    PersonalityRoutine: Addr option }

[<RequireQualifiedAccess>]
module internal CIE =
  let parseReturnRegister (reader: IBinReader) (span: ByteSpan) version offset =
    if version = 1uy then
      span[offset], offset + 1
    else
      let r, cnt = reader.ReadUInt64LEB128(span, offset)
      byte r, offset + cnt

  (* DW_EH_PE_indirect (0x80) only says that the pointer is indirect; the value
     and application encodings live in the low seven bits. *)
  let private personalityEncoding b =
    if b = 0xFFuy then ExceptionHeader.parseEncoding b
    else ExceptionHeader.parseEncoding (b &&& 0x7Fuy)

  /// Parses the 'P' augmentation, whose encoding byte is followed by the
  /// pointer to the personality routine. augAddr is the address the
  /// augmentation data starts at, which a pc-relative pointer is relative to.
  let private parsePersonality reader cls augAddr (arr: byte[]) offset =
    let struct (v, app) = personalityEncoding arr[offset]
    if v = ExceptionHeaderValue.DW_EH_PE_omit then
      { Format = 'P'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutine = None }, offset + 1
    else
      let myAddr = augAddr + uint64 offset + 1UL
      let struct (addr, nextOffset) =
        ExceptionHeaderValue.read cls (ReadOnlySpan arr) reader v (offset + 1)
      let routine = ExceptionHeader.adjustAddr app myAddr addr
      { Format = 'P'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutine = Some routine }, nextOffset

  let obtainAugData reader cls augAddr (arr: byte[]) data offset = function
    | 'L' ->
      let struct (v, app) = ExceptionHeader.parseEncoding arr[offset]
      { Format = 'L'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutine = None } :: data, offset + 1
    | 'P' ->
      let aug, nextOffset = parsePersonality reader cls augAddr arr offset
      aug :: data, nextOffset
    | 'R' ->
      let struct (v, app) = ExceptionHeader.parseEncoding arr[offset]
      { Format = 'R'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutine = None } :: data, offset + 1
    | 'S' ->
      data, offset (* This is a signal frame. *)
    | _ ->
      Terminator.futureFeature ()

  let parseAugmentationData (reader: IBinReader) span offset sAddr cls augstr =
    if (augstr: string).StartsWith('z') then
      let len, cnt = reader.ReadUInt64LEB128(span = span, offset = offset)
      let offset = offset + cnt
      let span = span.Slice(offset, int len)
      let arr = span.ToArray()
      let augAddr = sAddr + uint64 offset
      augstr[1..]
      |> Seq.fold (fun (data, idx) ch ->
        obtainAugData reader cls augAddr arr data idx ch) ([], 0)
      |> fst
      |> List.rev, offset + int len
    else
      [], offset

  /// Returns the personality routine that the CIE's 'P' augmentation encodes,
  /// or None when the CIE carries no such augmentation.
  let personalityRoutine cie =
    cie.Augmentations |> List.tryPick (fun aug -> aug.PersonalityRoutine)

  let extractOldOffset = function
    | RegPlusOffset(_, o) -> o
    | UnknownCFA -> 0
    | e -> Terminator.impossible ()

  let restoreOne initialRule currentRule target =
    match Map.tryFind target initialRule with
    | Some oldVal -> Map.add target oldVal currentRule
    | None -> Map.remove target currentRule

  let getTarget isa returnAddressReg (reg: byte) =
    if returnAddressReg = reg then ReturnAddress
    else DWRegister.toRegID isa reg |> NormalReg

  let getOffset isa rr reg v = getTarget isa rr reg, Offset v

  let rec getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc =
    if i >= (span: ByteSpan).Length then
      { Location = loc
        CanonicalFrameAddress = cfa
        Rule = rule } :: acc |> List.rev, cfa, lr
    else
      let op = span[i]
      let oparg = span[i] &&& 0x3fuy
      let i = i + 1
      let op = if op &&& 0xc0uy > 0uy then op &&& 0xc0uy else op
      match CFAInstruction.parse op with
      | CFAInstruction.DW_CFA_def_cfa ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let offset, cnt = LEB128.decodeUInt64 (span.Slice i)
        let cfa = RegPlusOffset(DWRegister.toRegID isa reg, int offset)
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_sf ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.decodeSInt64 (span.Slice i)
        let offset = int (v * df)
        let cfa = RegPlusOffset(DWRegister.toRegID isa reg, offset)
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_offset ->
        let offset, cnt = LEB128.decodeUInt64 (span.Slice i)
        let cfa = RegPlusOffset(DWRegister.toRegID isa lr, int offset)
        getUnwind
          acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_offset_sf ->
        let offset, cnt = LEB128.decodeSInt64 (span.Slice i)
        let offset = int (offset * df)
        let cfa = RegPlusOffset(DWRegister.toRegID isa lr, offset)
        getUnwind
          acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_expression ->
        let v, cnt = LEB128.decodeUInt64 (span.Slice i)
        let i = i + cnt
        let nextIdx = int v + i
        let cfa = DWExpression.parse isa regs [] span i nextIdx |> Expression
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span nextIdx loc
      | CFAInstruction.DW_CFA_def_cfa_register ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let rid = DWRegister.toRegID isa reg
        let oldOffset = extractOldOffset cfa
        let cfa = RegPlusOffset(rid, oldOffset)
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_offset ->
        let v, cnt = LEB128.decodeUInt64 (span.Slice i)
        let offset = int64 v * df
        let target, action = getOffset isa rr oparg offset
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_offset_extended ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let offset, cnt = LEB128.decodeUInt64 (span.Slice i)
        let target, action = getOffset isa rr reg (int64 offset)
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_offset_extended_sf ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.decodeSInt64 (span.Slice i)
        let offset = v * df
        let target, action = getOffset isa rr reg offset
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_undefined ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let target = getTarget isa rr reg
        let rule = Map.remove target rule
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_register ->
        let reg1, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg1 = byte reg1
        let i = i + cnt
        let reg2, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg2 = byte reg2
        let target = getTarget isa rr reg1
        let action = Register(DWRegister.toRegID isa reg2)
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_same_value ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let target = getTarget isa rr reg
        let action = SameValue
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_expression ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.decodeUInt64 (span.Slice i)
        let i = i + cnt
        let nextIdx = int v + i
        let target = getTarget isa rr reg
        let action = DWExpression.parse isa regs [] span i nextIdx |> ActionExpr
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs reg cf df rr span nextIdx loc
      | CFAInstruction.DW_CFA_val_expression ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.decodeUInt64 (span.Slice i)
        let i = i + cnt
        let nextIdx = int v + i
        let target = getTarget isa rr reg
        let action =
          DWExpression.parse isa regs [] span i nextIdx |> ActionValExpr
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs reg cf df rr span nextIdx loc
      | CFAInstruction.DW_CFA_advance_loc ->
        let loc' = loc + uint64 oparg * cf
        let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
        let acc = ent :: acc
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc'
      | CFAInstruction.DW_CFA_advance_loc1 ->
        let loc' = loc + uint64 span[i]
        let i' = i + 1
        let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
        let acc = ent :: acc
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i' loc'
      | CFAInstruction.DW_CFA_advance_loc2 ->
        let loc' = loc + uint64 (MemoryMarshal.Read<int16>(span.Slice(i)))
        let i' = i + 2
        let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
        let acc = ent :: acc
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i' loc'
      | CFAInstruction.DW_CFA_advance_loc4 ->
        let loc' = loc + uint64 (MemoryMarshal.Read<int32>(span.Slice(i)))
        let i' = i + 4
        let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
        let acc = ent :: acc
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i' loc'
      | CFAInstruction.DW_CFA_remember_state ->
        let rst = (cfa, rule, lr) :: rst
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc
      | CFAInstruction.DW_CFA_restore ->
        let target = getTarget isa rr oparg
        let rule = restoreOne irule rule target
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc
      | CFAInstruction.DW_CFA_restore_extended ->
        let reg, cnt = LEB128.decodeUInt64 (span.Slice i)
        let target = getTarget isa rr (byte reg)
        let rule = restoreOne irule rule target
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_restore_state ->
        let cfa, rule, lr = List.head rst
        let rst = List.tail rst
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc
      | CFAInstruction.DW_CFA_GNU_args_size ->
        let _, cnt = LEB128.decodeUInt64 (span.Slice i)
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_nop ->
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc
      | op ->
        printfn "%A" op; Terminator.futureFeature ()

  let extractRule (unwindingInfo: UnwindingEntry list) =
    match unwindingInfo with
    | [ row ] -> row.Rule
    | _ -> Map.empty

  /// Returns the initial unwinding state of a CIE that has no initial call
  /// frame instructions, which leaves every rule and the CFA unknown.
  let emptyInitialUnwinding rr =
    lazy { Rule = Map.empty; CFARegister = rr; CFA = UnknownCFA }

  /// Defers the interpretation of the CIE's initial call frame instructions
  /// until an FDE of this CIE actually needs the resulting state.
  let private parseInitialState isa regs rr cf df mem offset nextOffset =
    let instrLen = nextOffset - offset
    if instrLen > 0 then
      let instrs = (mem: ReadOnlyMemory<byte>).Slice(offset, instrLen)
      lazy
        let span = instrs.Span
        let rule = Map.empty
        let info, cfa, reg =
          getUnwind [] UnknownCFA rule [] rule isa regs rr cf df rr span 0 0UL
        { Rule = extractRule info; CFARegister = reg; CFA = cfa }
    else
      emptyInitialUnwinding rr

  let parse reader mem cls isa regs sAddr offset nextOffset =
    let secChunk = (mem: ReadOnlyMemory<byte>).Span
    let version = secChunk[offset]
    let offset = offset + 1
    if version = 1uy || version = 3uy then
      let augstr = ByteArray.extractCStringFromSpan secChunk offset
      let addrSize = WordSize.toByteWidth cls
      let offset = offset + augstr.Length + 1
      let offset = if augstr.Contains "eh" then offset + addrSize else offset
      let cf, cnt = (reader: IBinReader).ReadUInt64LEB128(secChunk, offset)
      let offset = offset + cnt
      let df, cnt = reader.ReadInt64LEB128(secChunk, offset)
      let offset = offset + cnt
      let rr, offset = parseReturnRegister reader secChunk version offset
      let augs, offset =
        parseAugmentationData reader secChunk offset sAddr cls augstr
      let initial = parseInitialState isa regs rr cf df mem offset nextOffset
      { Version = version
        AugmentationString = augstr
        CodeAlignmentFactor = cf
        DataAlignmentFactor = df
        ReturnAddressRegister = byte rr
        InitialUnwinding = initial
        Augmentations = augs }
    else
      Terminator.futureFeature ()
