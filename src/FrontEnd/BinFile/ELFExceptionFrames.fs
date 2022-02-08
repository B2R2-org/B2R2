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

[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.BinFile.ELF.ExceptionFrames

open System
open System.Runtime.InteropServices
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile.ELF.ExceptionHeaderEncoding

/// Raised when an unhandled eh_frame version is encountered.
exception UnhandledExceptionHandlingFrameVersion

/// Raised when an unhandled augment string is encountered.
exception UnhandledAugString

/// Raised when CIE is not found by FDE
exception CIENotFoundByFDE

/// Raised when invalid sequence of dwarf instructions encountered.
exception InvalidDWInstructionExpression

let [<Literal>] Ehframe = ".eh_frame"

let inline readInt (reader: BinReader) offset =
  reader.ReadInt32 offset

let inline readUInt64 (reader: BinReader) offset =
  reader.ReadUInt64 offset

let computeNextOffset len (reader: BinReader) offset =
  if len = -1 then
    let struct (len, offset) = readUInt64 reader offset
    int len + offset, offset
  else len + offset, offset

let parseReturnRegister (reader: BinReader) version offset =
  if version = 1uy then reader.PeekByte offset, offset + 1
  else
    let r, offset = parseULEB128 reader offset
    byte r, offset

let personalityRoutinePointerSize addrSize = function
  | 2uy -> 2
  | 3uy -> 4
  | 4uy -> 8
  | _ -> addrSize

let obtainAugData addrSize (arr: byte []) data offset = function
  | 'L' ->
    let struct (v, app) = parseEncoding arr[offset]
    { Format = 'L'
      ValueEncoding = v
      ApplicationEncoding = app
      PersonalityRoutionPointer = [||] } :: data, offset + 1
  | 'P' ->
    let struct (v, app) = parseEncoding arr[offset]
    let psz = arr[offset] &&& 7uy |> personalityRoutinePointerSize addrSize
    let prp = arr[ offset + 1 .. offset + psz ]
    { Format = 'P'
      ValueEncoding = v
      ApplicationEncoding = app
      PersonalityRoutionPointer = prp } :: data, offset + psz + 1
  | 'R' ->
    let struct (v, app) = parseEncoding arr[offset]
    { Format = 'R'
      ValueEncoding = v
      ApplicationEncoding = app
      PersonalityRoutionPointer = [||] } :: data, offset + 1
  | 'S' -> data, offset (* This is a signal frame. *)
  | _ -> raise UnhandledAugString

let parseAugmentationData (reader: BinReader) offset addrSize augstr =
  if (augstr: string).StartsWith ('z') then
    let len, offset = parseULEB128 reader offset
    let span = reader.PeekSpan (int len, offset)
    let arr = span.ToArray ()
    augstr[ 1.. ]
    |> Seq.fold (fun (data, idx) ch ->
      obtainAugData addrSize arr data idx ch) ([], 0)
    |> fst |> List.rev, offset + int len
  else [], offset

let num isa n =
  let rt = isa.WordSize |> WordSize.toRegType
  AST.num (BitVector.ofUInt64 n rt)

let regPlusNum isa regbay reg n =
  let regexp = DWRegister.toRegisterExpr isa regbay reg
  AST.binop BinOpType.ADD regexp (num isa n)

let parseOpBReg isa regbay exprs (span: ReadOnlySpan<byte>) idx reg =
  let offset, cnt = LEB128.DecodeUInt64 (span.Slice (idx))
  let exprs = regPlusNum isa regbay reg offset :: exprs
  struct (exprs, idx + cnt)

let pop exprs =
  match exprs with
  | fst :: rest -> struct (fst, rest)
  | _ -> Utils.impossible ()

let pop2 exprs =
  match exprs with
  | fst :: snd :: rest -> struct (fst, snd, rest)
  | _ -> Utils.impossible ()

let inline hasLessThanTwoOperands exprs =
  match exprs with
  | [ _ ] | [] -> true
  | _ -> false

let parseBinop op exprs =
  let struct (fst, snd, exprs) = pop2 exprs
  AST.binop op snd fst :: exprs

let parsePlusUconst isa exprs (span: ReadOnlySpan<byte>) idx =
  let n, cnt = LEB128.DecodeUInt64 (span.Slice (idx))
  let n = num isa n
  let struct (fst, exprs) = pop exprs
  let exprs = AST.binop BinOpType.ADD fst n :: exprs
  struct (exprs, idx + cnt)

let parseRel isa op exprs =
  let struct (fst, snd, exprs) = pop2 exprs
  let rt = isa.WordSize |> WordSize.toRegType
  AST.cast CastKind.ZeroExt rt (AST.relop op snd fst) :: exprs

let parseLoad isa exprs =
  let struct (addr, exprs) = pop exprs
  let rt = isa.WordSize |> WordSize.toRegType
  AST.loadLE rt addr :: exprs

let rec parseExprs isa regbay exprs (span: ReadOnlySpan<byte>) i maxIdx =
  if i >= maxIdx then
    match exprs with
    | [ exp ] -> exp
    | _ -> raise InvalidDWInstructionExpression
  else
    match span[i] |> DWOperation.parse with
    | DWOperation.DW_OP_breg0 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 0uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg1 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 1uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg2 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 2uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg3 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 3uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg4 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 4uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg5 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 5uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg6 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 6uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg7 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 7uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg8 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 8uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg9 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 9uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg10 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 10uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg11 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 11uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg12 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 12uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg13 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 13uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg14 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 14uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg15 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 15uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg16 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 16uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg17 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 17uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg18 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 18uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg19 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 19uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg20 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 20uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg21 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 21uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg22 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 22uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg23 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 23uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg24 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 24uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg25 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 25uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg26 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 26uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg27 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 27uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg28 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 28uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg29 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 29uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg30 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 30uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_breg31 ->
      let struct (exprs, i') = parseOpBReg isa regbay exprs span (i + 1) 31uy
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_const1u ->
      let exprs = num isa (uint64 span[i + 1]) :: exprs
      parseExprs isa regbay exprs span (i + 2) maxIdx
    | DWOperation.DW_OP_const1s ->
      let exprs = num isa (int64 span[i + 1] |> uint64) :: exprs
      parseExprs isa regbay exprs span (i + 2) maxIdx
    | DWOperation.DW_OP_const2u ->
      let c = MemoryMarshal.Read<uint16> (span.Slice (i + 1))
      let exprs = num isa (uint64 c) :: exprs
      parseExprs isa regbay exprs span (i + 3) maxIdx
    | DWOperation.DW_OP_const2s ->
      let c = MemoryMarshal.Read<int16> (span.Slice (i + 1))
      let exprs = num isa (int64 c |> uint64) :: exprs
      parseExprs isa regbay exprs span (i + 3) maxIdx
    | DWOperation.DW_OP_const4u ->
      let c = MemoryMarshal.Read<uint32> (span.Slice (i + 1))
      let exprs = num isa (uint64 c) :: exprs
      parseExprs isa regbay exprs span (i + 5) maxIdx
    | DWOperation.DW_OP_const4s ->
      let c = MemoryMarshal.Read<int32> (span.Slice (i + 1))
      let exprs = num isa (int64 c |> uint64) :: exprs
      parseExprs isa regbay exprs span (i + 5) maxIdx
    | DWOperation.DW_OP_lit0 ->
      let exprs = num isa 0UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit1 ->
      let exprs = num isa 1UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit2 ->
      let exprs = num isa 2UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit3 ->
      let exprs = num isa 3UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit4 ->
      let exprs = num isa 4UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit5 ->
      let exprs = num isa 5UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit6 ->
      let exprs = num isa 6UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit7 ->
      let exprs = num isa 7UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit8 ->
      let exprs = num isa 8UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit9 ->
      let exprs = num isa 9UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit10 ->
      let exprs = num isa 10UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit11 ->
      let exprs = num isa 11UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit12 ->
      let exprs = num isa 12UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit13 ->
      let exprs = num isa 13UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit14 ->
      let exprs = num isa 14UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit15 ->
      let exprs = num isa 15UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit16 ->
      let exprs = num isa 16UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit17 ->
      let exprs = num isa 17UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit18 ->
      let exprs = num isa 18UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit19 ->
      let exprs = num isa 19UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit20 ->
      let exprs = num isa 20UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit21 ->
      let exprs = num isa 21UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit22 ->
      let exprs = num isa 22UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit23 ->
      let exprs = num isa 23UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit24 ->
      let exprs = num isa 24UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit25 ->
      let exprs = num isa 25UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit26 ->
      let exprs = num isa 26UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit27 ->
      let exprs = num isa 27UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit28 ->
      let exprs = num isa 28UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit29 ->
      let exprs = num isa 29UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit30 ->
      let exprs = num isa 30UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit31 ->
      let exprs = num isa 31UL :: exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_and ->
      let exprs = parseBinop BinOpType.AND exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_or ->
      let exprs = parseBinop BinOpType.OR exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_xor ->
      let exprs = parseBinop BinOpType.XOR exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_div ->
      let exprs = parseBinop BinOpType.DIV exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_minus ->
      (* There is an exceptional case where ICC compbiler uses DW_OP_minus with
         a single opearnd. This is not the standard way. *)
      let exprs =
        if hasLessThanTwoOperands exprs then [ num isa 0UL ]
        else parseBinop BinOpType.SUB exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_plus ->
      let exprs = parseBinop BinOpType.ADD exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_plus_uconst ->
      let struct (exprs, i') = parsePlusUconst isa exprs span (i + 1)
      parseExprs isa regbay exprs span i' maxIdx
    | DWOperation.DW_OP_mul ->
      let exprs = parseBinop BinOpType.MUL exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_shl ->
      let exprs = parseBinop BinOpType.SHL exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_shr ->
      let exprs = parseBinop BinOpType.SHR exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_shra ->
      let exprs = parseBinop BinOpType.SAR exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_le ->
      let exprs = parseRel isa RelOpType.LE exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_ge ->
      let exprs = parseRel isa RelOpType.GE exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_eq ->
      let exprs = parseRel isa RelOpType.EQ exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lt ->
      let exprs = parseRel isa RelOpType.LT exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_gt ->
      let exprs = parseRel isa RelOpType.GT exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_ne ->
      let exprs = parseRel isa RelOpType.NEQ exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_deref ->
      let exprs = parseLoad isa exprs
      parseExprs isa regbay exprs span (i + 1) maxIdx
    | op -> printfn "TODO: %A" op; Utils.futureFeature ()

let extractOldOffset = function
  | RegPlusOffset (_, o) -> o
  | UnknownCFA -> 0
  | e -> Utils.impossible ()

let restoreOne initialRule currentRule target =
  match Map.tryFind target initialRule with
  | Some oldVal -> Map.add target oldVal currentRule
  | None -> Map.remove target currentRule

let rec getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i loc =
  if i >= (span: ReadOnlySpan<byte>).Length then
    { Location = loc
      CanonicalFrameAddress = cfa
      Rule = rule } :: acc |> List.rev, cfa, lr
  else
    let op = span[i]
    let oparg = span[i] &&& 0x3fuy
    let i = i + 1
    let op = if op &&& 0xc0uy > 0uy then op &&& 0xc0uy else op
    match DWCFAInstruction.parse op with
    | DWCFAInstruction.DW_CFA_def_cfa ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg = byte reg
      let i = i + cnt
      let offset, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let cfa = CanonicalFrameAddress.regPlusOffset isa rbay reg (int offset)
      getUnwind acc cfa irule rst rule isa rbay reg cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_def_cfa_offset ->
      let offset, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let cfa = CanonicalFrameAddress.regPlusOffset isa rbay lr (int offset)
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_def_cfa_offset_sf ->
      let offset, cnt = LEB128.DecodeSInt64 (span.Slice i)
      let offset = int (offset * df)
      let cfa = CanonicalFrameAddress.regPlusOffset isa rbay lr offset
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_def_cfa_expression ->
      let v, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let i = i + cnt
      let nextIdx = int v + i
      let cfa = parseExprs isa rbay [] span i nextIdx |> Expression
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span nextIdx loc
    | DWCFAInstruction.DW_CFA_def_cfa_register ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg = byte reg
      let rid = DWRegister.toRegID isa reg
      let oldOffset = extractOldOffset cfa
      let cfa = RegPlusOffset (rid, oldOffset)
      getUnwind acc cfa irule rst rule isa rbay reg cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_offset ->
      let v, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let offset = int64 v * df
      let target, action = Rule.offset isa rr oparg offset
      let rule = Map.add target action rule
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_offset_extended ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg = byte reg
      let i = i + cnt
      let offset, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let target, action = Rule.offset isa rr reg (int64 offset)
      let rule = Map.add target action rule
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_offset_extended_sf ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg = byte reg
      let i = i + cnt
      let v, cnt = LEB128.DecodeSInt64 (span.Slice i)
      let offset = v * df
      let target, action = Rule.offset isa rr reg offset
      let rule = Map.add target action rule
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_undefined ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg = byte reg
      let target = Rule.getTarget isa rr reg
      let rule = Map.remove target rule
      getUnwind acc cfa irule rst rule isa rbay reg cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_register ->
      let reg1, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg1 = byte reg1
      let i = i + cnt
      let reg2, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg2 = byte reg2
      let target = Rule.getTarget isa rr reg1
      let action = Register (DWRegister.toRegID isa reg2)
      let rule = Map.add target action rule
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_expression ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let reg = byte reg
      let i = i + cnt
      let v, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let i = i + cnt
      let nextIdx = int v + i
      let target = Rule.getTarget isa rr reg
      let action = parseExprs isa rbay [] span i nextIdx |> ActionExpr
      let rule = Map.add target action rule
      getUnwind acc cfa irule rst rule isa rbay reg cf df rr span nextIdx loc
    | DWCFAInstruction.DW_CFA_advance_loc ->
      let loc' = loc + uint64 oparg * cf
      let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
      let acc = ent :: acc
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i loc'
    | DWCFAInstruction.DW_CFA_advance_loc1 ->
      let loc' = loc + uint64 span[i]
      let i' = i + 1
      let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
      let acc = ent :: acc
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i' loc'
    | DWCFAInstruction.DW_CFA_advance_loc2 ->
      let loc' = loc + uint64 (MemoryMarshal.Read<int16> (span.Slice (i)))
      let i' = i + 2
      let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
      let acc = ent :: acc
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i' loc'
    | DWCFAInstruction.DW_CFA_advance_loc4 ->
      let loc' = loc + uint64 (MemoryMarshal.Read<int32> (span.Slice (i)))
      let i' = i + 4
      let ent = { Location = loc; CanonicalFrameAddress = cfa; Rule = rule }
      let acc = ent :: acc
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i' loc'
    | DWCFAInstruction.DW_CFA_remember_state ->
      let rst = (cfa, rule) :: rst
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i loc
    | DWCFAInstruction.DW_CFA_restore ->
      let target = Rule.getTarget isa rr oparg
      let rule = restoreOne irule rule target
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i loc
    | DWCFAInstruction.DW_CFA_restore_extended ->
      let reg, cnt = LEB128.DecodeUInt64 (span.Slice i)
      let target = Rule.getTarget isa rr (byte reg)
      let rule = restoreOne irule rule target
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_restore_state ->
      let cfa, rule = List.head rst
      let rst = List.tail rst
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i loc
    | DWCFAInstruction.DW_CFA_GNU_args_size ->
      let _, cnt = LEB128.DecodeUInt64 (span.Slice i)
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span (i + cnt) loc
    | DWCFAInstruction.DW_CFA_nop ->
      getUnwind acc cfa irule rst rule isa rbay lr cf df rr span i loc
    | op -> printfn "%A" op; Utils.futureFeature ()

let extractRule unwindingInfo =
  match unwindingInfo with
  | [ row ] -> row.Rule
  | _ -> Map.empty

let parseCIE cls isa rbay (reader: BinReader) offset nextOffset =
  let struct (version, offset) = reader.ReadByte offset
  if version = 1uy || version = 3uy then
    let span = reader.PeekSpan offset
    let augstr = ByteArray.extractCStringFromSpan span 0
    let addrSize = WordSize.toByteWidth cls
    let offset = offset + augstr.Length + 1
    let offset = if augstr.Contains "eh" then offset + addrSize else offset
    let cf, offset = parseULEB128 reader offset
    let df, offset = parseSLEB128 reader offset
    let rr, offset = parseReturnRegister reader version offset
    let augs, offset = parseAugmentationData reader offset addrSize augstr
    let instrLen = nextOffset - offset
    if instrLen > 0 then
      let span = reader.PeekSpan (instrLen, offset)
      let rule = Map.empty
      getUnwind [] UnknownCFA rule [] rule isa rbay rr cf df rr span 0 0UL
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
    raise UnhandledExceptionHandlingFrameVersion

let tryFindAugmentation cie format =
  cie.Augmentations |> List.tryFind (fun aug -> aug.Format = format)

let adjustAddr app myAddr addr =
  match app with
  | ExceptionHeaderApplication.DW_EH_PE_pcrel -> addr + myAddr
  | _ -> addr

let parsePCInfo cls reader sAddr venc aenc offset =
  let myAddr = sAddr + uint64 offset
  let struct (addr, offset) = computeValue cls reader venc offset
  let struct (range, offset) = computeValue cls reader venc offset
  let beginAddr = adjustAddr aenc myAddr addr
  let endAddr = beginAddr + range
  beginAddr, endAddr, offset

let parseLSDA cls reader sAddr aug offset =
  let _, offset = parseULEB128 reader offset
  let myAddr = sAddr + uint64 offset
  let struct (addr, offset) = computeValue cls reader aug.ValueEncoding offset
  Some (adjustAddr aug.ApplicationEncoding myAddr addr), offset

let parseCallFrameInstrs cie isa regbay reader offset nextOffset loc =
  let span = (reader: BinReader).PeekSpan (nextOffset - offset, offset)
  let insarr = span.ToArray ()
  if Array.forall (fun b -> b = 0uy) insarr then []
  else
    let cf = cie.CodeAlignmentFactor
    let df = cie.DataAlignmentFactor
    let rr = cie.ReturnAddressRegister
    let ir = cie.InitialCFARegister
    let r = cie.InitialRule
    let cfa = cie.InitialCFA
    let info, _, _ = getUnwind [] cfa r [] r isa regbay ir cf df rr span 0 loc
    info

let parseFDE cls isa regbay reader sAddr offset nextOffset cie =
  match cie with
  | Some cie ->
    let venc, aenc =
      match tryFindAugmentation cie 'R' with
      | Some aug -> aug.ValueEncoding, aug.ApplicationEncoding
      | None -> ExceptionHeaderValue.DW_EH_PE_absptr,
                ExceptionHeaderApplication.DW_EH_PE_absptr
    let b, e, offset =
      parsePCInfo cls reader sAddr venc aenc offset
    let lsdaPointer, offset =
      match tryFindAugmentation cie 'L' with
      | Some aug -> parseLSDA cls reader sAddr aug offset
      | None -> None, offset
    let info = parseCallFrameInstrs cie isa regbay reader offset nextOffset b
    { PCBegin = b
      PCEnd = e
      LSDAPointer = lsdaPointer
      UnwindingInfo = info }
  | None -> raise CIENotFoundByFDE

let accumulateCFIs cfis cie fdes =
  match cie with
  | Some cie ->
    { CIERecord = cie
      FDERecord = List.rev fdes |> List.toArray } :: cfis
  | None -> cfis

let rec parseCFI cls isa regbay reader sAddr cie cies fdes offset cfis =
  if offset >= ((reader: BinReader).Length ()) then accumulateCFIs cfis cie fdes
  else
    let originalOffset = offset
    let struct (len, offset) = readInt reader offset
    if len = 0 then accumulateCFIs cfis cie fdes
    else
      let nextOffset, offset = computeNextOffset len reader offset
      let mybase = offset
      let struct (id, offset) = readInt reader offset
      if id = 0 then
        let cfis = accumulateCFIs cfis cie fdes
        let cie = parseCIE cls isa regbay reader offset nextOffset
        let cies = Map.add originalOffset cie cies
        parseCFI cls isa regbay reader sAddr (Some cie) cies [] nextOffset cfis
      else
        let cieOffset = mybase - id (* id = a CIE pointer, when id <> 0 *)
        let fde =
          Map.tryFind cieOffset cies
          |> parseFDE cls isa regbay reader sAddr offset nextOffset
        let fdes = fde :: fdes
        parseCFI cls isa regbay reader sAddr cie cies fdes nextOffset cfis

let parse (reader: BinReader) cls (secs: SectionInfo) isa regbay =
  match Map.tryFind Ehframe secs.SecByName with
  | Some sec when Option.isSome regbay ->
    let size = Convert.ToInt32 sec.SecSize
    let offset = Convert.ToInt32 sec.SecOffset
    let reader = reader.SubReader offset size
    let regbay = Option.get regbay
    parseCFI cls isa regbay reader sec.SecAddr None Map.empty [] 0 []
    |> List.rev
  | _ -> []
