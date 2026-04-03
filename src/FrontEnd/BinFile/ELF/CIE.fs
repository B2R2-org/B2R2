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

namespace B2R2.FrontEnd.BinFile.ELF

open System.Runtime.InteropServices
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents the Common Information Entry (CIE).
type CIE =
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
    /// Initial set of unwinding actions (i.e., call frame instructions).
    InitialRule: UnwindingRule
    /// Initial CFA register.
    InitialCFARegister: byte
    /// Initial Canonical Frame Address (CFA).
    InitialCFA: CanonicalFrameAddress
    /// Augmentation data.
    Augmentations: Augmentation list }

/// Represents the CIE augmetation data.
and Augmentation =
  { Format: char
    ValueEncoding: ExceptionHeaderValue
    ApplicationEncoding: ExceptionHeaderApplication
    PersonalityRoutionPointer: byte[] }

[<RequireQualifiedAccess>]
module internal CIE =
  let parseReturnRegister toolBox (span: ByteSpan) version offset =
    if version = 1uy then span[offset], offset + 1
    else
      let r, cnt = toolBox.Reader.ReadUInt64LEB128(span, offset)
      byte r, offset + cnt

  let personalityRoutinePointerSize addrSize = function
    | 2uy -> 2
    | 3uy -> 4
    | 4uy -> 8
    | _ -> addrSize

  let obtainAugData addrSize (arr: byte[]) data offset = function
    | 'L' ->
      let struct (v, app) = ExceptionHeader.parseEncoding arr[offset]
      { Format = 'L'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutionPointer = [||] } :: data, offset + 1
    | 'P' ->
      let struct (v, app) = ExceptionHeader.parseEncoding arr[offset]
      let psz = arr[offset] &&& 7uy |> personalityRoutinePointerSize addrSize
      let prp = arr[offset + 1..offset + psz]
      { Format = 'P'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutionPointer = prp } :: data, offset + psz + 1
    | 'R' ->
      let struct (v, app) = ExceptionHeader.parseEncoding arr[offset]
      { Format = 'R'
        ValueEncoding = v
        ApplicationEncoding = app
        PersonalityRoutionPointer = [||] } :: data, offset + 1
    | 'S' -> data, offset (* This is a signal frame. *)
    | _ -> Terminator.futureFeature ()

  let parseAugmentationData toolBox (span: ByteSpan) offset addrSize augstr =
    if (augstr: string).StartsWith('z') then
      let len, cnt = toolBox.Reader.ReadUInt64LEB128(span, offset)
      let offset = offset + cnt
      let span = span.Slice(offset, int len)
      let arr = span.ToArray()
      augstr[1..]
      |> Seq.fold (fun (data, idx) ch ->
        obtainAugData addrSize arr data idx ch) ([], 0)
      |> fst
      |> List.rev, offset + int len
    else [], offset

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
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let offset, cnt = LEB128.DecodeUInt64(span.Slice i)
        let cfa = RegPlusOffset(DWRegister.toRegID isa reg, int offset)
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_sf ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.DecodeSInt64(span.Slice i)
        let offset = int (v * df)
        let cfa = RegPlusOffset(DWRegister.toRegID isa reg, offset)
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_offset ->
        let offset, cnt = LEB128.DecodeUInt64(span.Slice i)
        let cfa = RegPlusOffset(DWRegister.toRegID isa lr, int offset)
        getUnwind
          acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_offset_sf ->
        let offset, cnt = LEB128.DecodeSInt64(span.Slice i)
        let offset = int (offset * df)
        let cfa = RegPlusOffset(DWRegister.toRegID isa lr, offset)
        getUnwind
          acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_def_cfa_expression ->
        let v, cnt = LEB128.DecodeUInt64(span.Slice i)
        let i = i + cnt
        let nextIdx = int v + i
        let cfa = DWExpression.parse isa regs [] span i nextIdx |> Expression
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span nextIdx loc
      | CFAInstruction.DW_CFA_def_cfa_register ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let rid = DWRegister.toRegID isa reg
        let oldOffset = extractOldOffset cfa
        let cfa = RegPlusOffset(rid, oldOffset)
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_offset ->
        let v, cnt = LEB128.DecodeUInt64(span.Slice i)
        let offset = int64 v * df
        let target, action = getOffset isa rr oparg offset
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_offset_extended ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let offset, cnt = LEB128.DecodeUInt64(span.Slice i)
        let target, action = getOffset isa rr reg (int64 offset)
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_offset_extended_sf ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.DecodeSInt64(span.Slice i)
        let offset = v * df
        let target, action = getOffset isa rr reg offset
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_undefined ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let target = getTarget isa rr reg
        let rule = Map.remove target rule
        getUnwind
          acc cfa irule rst rule isa regs reg cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_register ->
        let reg1, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg1 = byte reg1
        let i = i + cnt
        let reg2, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg2 = byte reg2
        let target = getTarget isa rr reg1
        let action = Register(DWRegister.toRegID isa reg2)
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_same_value ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let target = getTarget isa rr reg
        let action = SameValue
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_expression ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.DecodeUInt64(span.Slice i)
        let i = i + cnt
        let nextIdx = int v + i
        let target = getTarget isa rr reg
        let action = DWExpression.parse isa regs [] span i nextIdx |> ActionExpr
        let rule = Map.add target action rule
        getUnwind acc cfa irule rst rule isa regs reg cf df rr span nextIdx loc
      | CFAInstruction.DW_CFA_val_expression ->
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let reg = byte reg
        let i = i + cnt
        let v, cnt = LEB128.DecodeUInt64(span.Slice i)
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
        let reg, cnt = LEB128.DecodeUInt64(span.Slice i)
        let target = getTarget isa rr (byte reg)
        let rule = restoreOne irule rule target
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_restore_state ->
        let cfa, rule, lr = List.head rst
        let rst = List.tail rst
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc
      | CFAInstruction.DW_CFA_GNU_args_size ->
        let _, cnt = LEB128.DecodeUInt64(span.Slice i)
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span (i + cnt) loc
      | CFAInstruction.DW_CFA_nop ->
        getUnwind acc cfa irule rst rule isa regs lr cf df rr span i loc
      | op -> printfn "%A" op; Terminator.futureFeature ()

  let extractRule unwindingInfo =
    match unwindingInfo with
    | [ row ] -> row.Rule
    | _ -> Map.empty

  let parse toolBox (secChunk: ByteSpan) cls isa regs offset nextOffset =
    let version = secChunk[offset]
    let offset = offset + 1
    if version = 1uy || version = 3uy then
      let augstr = ByteArray.extractCStringFromSpan secChunk offset
      let addrSize = WordSize.toByteWidth cls
      let offset = offset + augstr.Length + 1
      let offset = if augstr.Contains "eh" then offset + addrSize else offset
      let cf, cnt = toolBox.Reader.ReadUInt64LEB128(secChunk, offset)
      let offset = offset + cnt
      let df, cnt = toolBox.Reader.ReadInt64LEB128(secChunk, offset)
      let offset = offset + cnt
      let rr, offset = parseReturnRegister toolBox secChunk version offset
      let augs, offset =
        parseAugmentationData toolBox secChunk offset addrSize augstr
      let instrLen = nextOffset - offset
      if instrLen > 0 then
        let span = secChunk.Slice(offset, instrLen)
        let rule = Map.empty
        getUnwind [] UnknownCFA rule [] rule isa regs rr cf df rr span 0 0UL
      else [], UnknownCFA, rr
      |> fun (info, cfa, reg) ->
        { Version = version
          AugmentationString = augstr
          CodeAlignmentFactor = cf
          DataAlignmentFactor = df
          ReturnAddressRegister = byte rr
          InitialRule = extractRule info
          InitialCFARegister = reg
          InitialCFA = cfa
          Augmentations = augs }
    else
      Terminator.futureFeature ()
