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
module internal B2R2.FrontEnd.BinFile.ELF.DWExpression

open System.Runtime.InteropServices
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter

/// Raised when invalid sequence of dwarf instructions encountered.
exception InvalidDWInstructionExpException

let num (isa: ISA) n =
  let rt = isa.WordSize |> WordSize.toRegType
  BitVector(u64 = n, bitLen = rt) |> AST.num

let regPlusNum isa registerFactory reg n =
  let regexp = DWRegister.toRegisterExpr isa registerFactory reg
  AST.binop BinOpType.ADD regexp (num isa n)

let parseOpBReg isa registerFactory exprs (span: ByteSpan) idx reg =
  let offset, cnt = LEB128.DecodeUInt64(span.Slice(idx))
  let exprs = regPlusNum isa registerFactory reg offset :: exprs
  struct (exprs, idx + cnt)

let pop exprs =
  match exprs with
  | fst :: rest -> struct (fst, rest)
  | _ -> Terminator.impossible ()

let pop2 exprs =
  match exprs with
  | fst :: snd :: rest -> struct (fst, snd, rest)
  | _ -> Terminator.impossible ()

let inline hasLessThanTwoOperands exprs =
  match exprs with
  | [ _ ] | [] -> true
  | _ -> false

let parseBinop op exprs =
  let struct (fst, snd, exprs) = pop2 exprs
  AST.binop op snd fst :: exprs

let parsePlusUconst isa exprs (span: ByteSpan) idx =
  let n, cnt = LEB128.DecodeUInt64(span.Slice(idx))
  let n = num isa n
  let struct (fst, exprs) = pop exprs
  let exprs = AST.binop BinOpType.ADD fst n :: exprs
  struct (exprs, idx + cnt)

let parseRel (isa: ISA) op exprs =
  let struct (fst, snd, exprs) = pop2 exprs
  let rt = isa.WordSize |> WordSize.toRegType
  AST.cast CastKind.ZeroExt rt (AST.relop op snd fst) :: exprs

let parseLoad (isa: ISA) exprs =
  let struct (addr, exprs) = pop exprs
  let rt = isa.WordSize |> WordSize.toRegType
  AST.loadLE rt addr :: exprs

let cfaRegister (regFactory: IRegisterFactory) = function
  | Some rid -> regFactory.GetRegVar(rid = rid)
  | None -> RegisterID.create 0 |> regFactory.GetRegVar

let rec parse isa regs exprs (span: ByteSpan) i maxIdx =
  if i >= maxIdx then
    match exprs with
    | [ exp ] -> exp
    | _ -> raise InvalidDWInstructionExpException
  else
    match span[i] |> DWOperation.parse with
    | DWOperation.DW_OP_breg0 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 0uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg1 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 1uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg2 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 2uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg3 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 3uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg4 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 4uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg5 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 5uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg6 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 6uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg7 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 7uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg8 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 8uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg9 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 9uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg10 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 10uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg11 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 11uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg12 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 12uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg13 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 13uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg14 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 14uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg15 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 15uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg16 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 16uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg17 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 17uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg18 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 18uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg19 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 19uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg20 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 20uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg21 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 21uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg22 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 22uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg23 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 23uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg24 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 24uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg25 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 25uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg26 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 26uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg27 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 27uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg28 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 28uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg29 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 29uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg30 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 30uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_breg31 ->
      let struct (exprs, i') = parseOpBReg isa regs exprs span (i + 1) 31uy
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_call_frame_cfa ->
      let sp = cfaRegister regs regs.StackPointer
      parse isa regs (sp :: exprs) span (i + 1) maxIdx
    | DWOperation.DW_OP_fbreg ->
      let offset, cnt = LEB128.DecodeUInt64(span.Slice(i + 1))
      let fp = cfaRegister regs regs.FramePointer
      let exp = AST.binop BinOpType.ADD fp (num isa offset)
      parse isa regs (exp :: exprs) span (i + 1 + cnt) maxIdx
    | DWOperation.DW_OP_const1u ->
      let exprs = num isa (uint64 span[i + 1]) :: exprs
      parse isa regs exprs span (i + 2) maxIdx
    | DWOperation.DW_OP_const1s ->
      let exprs = num isa (int64 span[i + 1] |> uint64) :: exprs
      parse isa regs exprs span (i + 2) maxIdx
    | DWOperation.DW_OP_const2u ->
      let c = MemoryMarshal.Read<uint16>(span.Slice(i + 1))
      let exprs = num isa (uint64 c) :: exprs
      parse isa regs exprs span (i + 3) maxIdx
    | DWOperation.DW_OP_const2s ->
      let c = MemoryMarshal.Read<int16>(span.Slice(i + 1))
      let exprs = num isa (int64 c |> uint64) :: exprs
      parse isa regs exprs span (i + 3) maxIdx
    | DWOperation.DW_OP_const4u ->
      let c = MemoryMarshal.Read<uint32>(span.Slice(i + 1))
      let exprs = num isa (uint64 c) :: exprs
      parse isa regs exprs span (i + 5) maxIdx
    | DWOperation.DW_OP_const4s ->
      let c = MemoryMarshal.Read<int32>(span.Slice(i + 1))
      let exprs = num isa (int64 c |> uint64) :: exprs
      parse isa regs exprs span (i + 5) maxIdx
    | DWOperation.DW_OP_lit0 ->
      let exprs = num isa 0UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit1 ->
      let exprs = num isa 1UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit2 ->
      let exprs = num isa 2UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit3 ->
      let exprs = num isa 3UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit4 ->
      let exprs = num isa 4UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit5 ->
      let exprs = num isa 5UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit6 ->
      let exprs = num isa 6UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit7 ->
      let exprs = num isa 7UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit8 ->
      let exprs = num isa 8UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit9 ->
      let exprs = num isa 9UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit10 ->
      let exprs = num isa 10UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit11 ->
      let exprs = num isa 11UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit12 ->
      let exprs = num isa 12UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit13 ->
      let exprs = num isa 13UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit14 ->
      let exprs = num isa 14UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit15 ->
      let exprs = num isa 15UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit16 ->
      let exprs = num isa 16UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit17 ->
      let exprs = num isa 17UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit18 ->
      let exprs = num isa 18UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit19 ->
      let exprs = num isa 19UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit20 ->
      let exprs = num isa 20UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit21 ->
      let exprs = num isa 21UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit22 ->
      let exprs = num isa 22UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit23 ->
      let exprs = num isa 23UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit24 ->
      let exprs = num isa 24UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit25 ->
      let exprs = num isa 25UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit26 ->
      let exprs = num isa 26UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit27 ->
      let exprs = num isa 27UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit28 ->
      let exprs = num isa 28UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit29 ->
      let exprs = num isa 29UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit30 ->
      let exprs = num isa 30UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lit31 ->
      let exprs = num isa 31UL :: exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_and ->
      let exprs = parseBinop BinOpType.AND exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_or ->
      let exprs = parseBinop BinOpType.OR exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_xor ->
      let exprs = parseBinop BinOpType.XOR exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_div ->
      let exprs = parseBinop BinOpType.DIV exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_minus ->
      (* There is an exceptional case where ICC compbiler uses DW_OP_minus
          with a single opearnd. This is not the standard way. *)
      let exprs =
        if hasLessThanTwoOperands exprs then [ num isa 0UL ]
        else parseBinop BinOpType.SUB exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_plus ->
      let exprs = parseBinop BinOpType.ADD exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_plus_uconst ->
      let struct (exprs, i') = parsePlusUconst isa exprs span (i + 1)
      parse isa regs exprs span i' maxIdx
    | DWOperation.DW_OP_mul ->
      let exprs = parseBinop BinOpType.MUL exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_shl ->
      let exprs = parseBinop BinOpType.SHL exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_shr ->
      let exprs = parseBinop BinOpType.SHR exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_shra ->
      let exprs = parseBinop BinOpType.SAR exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_le ->
      let exprs = parseRel isa RelOpType.LE exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_ge ->
      let exprs = parseRel isa RelOpType.GE exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_eq ->
      let exprs = parseRel isa RelOpType.EQ exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_lt ->
      let exprs = parseRel isa RelOpType.LT exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_gt ->
      let exprs = parseRel isa RelOpType.GT exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_ne ->
      let exprs = parseRel isa RelOpType.NEQ exprs
      parse isa regs exprs span (i + 1) maxIdx
    | DWOperation.DW_OP_deref ->
      let exprs = parseLoad isa exprs
      parse isa regs exprs span (i + 1) maxIdx
    | op -> printfn "TODO: %A" op; Terminator.futureFeature ()
