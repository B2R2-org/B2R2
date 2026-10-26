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

module internal B2R2.FrontEnd.PPC.PrefixedLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper
open B2R2.FrontEnd.PPC.VSXLifter

(*
  Lifts prefixed addresses and storage operations in the PPC front end.
*)
/// The prefixed effective address uses CIA for R=1, otherwise RA|0.
let private addressOf (ins: Instruction) (bld: ILowUIRBuilder) =
  match ins.Operands with
  | ThreeOperands(_, OprMem64(d, ra), OprImm relative) ->
    let baseValue =
      if relative = 1UL then numU64 ins.Address 64<rt>
      elif ra = Register.R0 then AST.num0 64<rt>
      else regVar bld ra
    baseValue .+ numI64 d 64<rt>
  | _ ->
    raise InvalidOperandException

let private targetOf (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(target, _, _) -> target
  | _ -> raise InvalidOperandException

/// PADDI adds the signed 34-bit immediate without changing XER or CR.
let addImmediate (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    match ins.Operands with
    | FourOperands(OprReg rt, OprReg ra, OprImm imm, OprImm relative) ->
      let baseValue =
        if relative = 1UL then numU64 ins.Address 64<rt>
        elif ra = Register.R0 then AST.num0 64<rt>
        else regVar bld ra
      regVar bld rt := baseValue .+ numU64 imm 64<rt>
    | _ ->
      raise InvalidOperandException
  }

/// The scalar integer loads extend their byte, halfword or word as defined.
let loadInteger ins (bld: ILowUIRBuilder) width signed =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let value = loadNative bld width ea
    let value = if signed then AST.sext 64<rt> value else AST.zext 64<rt> value
    transOpr bld (targetOf ins) := value
  }

let storeInteger ins (bld: ILowUIRBuilder) width =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    loadNative bld width ea := AST.xtlo width (transOpr bld (targetOf ins))
  }

let doubleOfSingle bld word = GeneralLifter.doubleOfSingle bld word

/// Floating-point singles widen exactly; NaN payloads retain their bits.
let loadFloat ins (bld: ILowUIRBuilder) single vector =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let target = targetOf ins
    let value =
      if single then doubleOfSingle bld (loadNative bld 32<rt> ea)
      else loadNative bld 64<rt> ea
    transOpr bld target := value
    if vector then
      let struct (_, low) = VSXLifter.vsrOf bld target
      low := AST.num0 64<rt>
    else
      ()
  }

let storeFloat ins (bld: ILowUIRBuilder) single =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let source = transOpr bld (targetOf ins)
    if single then
      loadNative bld 32<rt> ea := GeneralLifter.singleBits bld source
    else
      loadNative bld 64<rt> ea := source
  }

/// PLQ and PSTQ keep the even GPR at EA in either byte order.
let gprPair ins (bld: ILowUIRBuilder) load =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let reg =
      match targetOf ins with
      | OprReg reg -> reg
      | _ -> raise InvalidOperandException
    for i in 0 .. 1 do
      let variable = enum<Register> (int reg + i) |> regVar bld
      let memory = loadNative bld 64<rt> (ea .+ numI32 (8 * i) 64<rt>)
      if load then variable := memory else memory := variable
  }

/// A VSR or VSR pair is a 128- or 256-bit value in the guest's byte order.
let vector ins (bld: ILowUIRBuilder) load pair =
  lift bld ins {
    let ea = tmpVar bld 64<rt>
    ea := addressOf ins bld
    let target = targetOf ins
    for row in 0 .. (if pair then 1 else 0) do
      let operand =
        if row = 0 then
          target
        else
          match target with
          | OprReg reg -> OprReg(VSXLifter.secondOfPair reg)
          | _ -> raise InvalidOperandException
      let struct (h, l) = VSXLifter.vsrOf bld operand
      let little = bld.Endianness = Endian.Little
      let index = if pair && little then 1 - row else row
      let offset = index * 16
      let highOffset = offset + (if little then 8 else 0)
      let lowOffset = offset + (if little then 0 else 8)
      let high = loadNative bld 64<rt> (ea .+ numI32 highOffset 64<rt>)
      let low = loadNative bld 64<rt> (ea .+ numI32 lowOffset 64<rt>)
      if load then
        h := high
        l := low
      else
        high := h
        low := l
  }

(*
  Lifts the prefixed vector blend, evaluate, permute and splat forms.
*)
let private vectorReg bld operand =
  let struct (h, l) = VSXLifter.vsrOf bld operand
  AST.concat h l

/// Snapshot both halves before writing a destination that can alias a source.
let private write bld dst value =
  let result = tmpVar bld 128<rt>
  let struct (h, l) = VSXLifter.vsrOf bld dst
  append bld {
    result := value
    h := AST.xthi 64<rt> result
    l := AST.xtlo 64<rt> result
  }

let private element width index value =
  AST.extract value width (128 - int width * (index + 1))

let private arguments (ins: Instruction) =
  match ins.Operands with
  | FourOperands(t, a, b, c) -> t, a, b, c, 0UL
  | FiveOperands(t, a, b, c, OprImm imm) -> t, a, b, c, imm
  | _ -> raise InvalidOperandException

/// The sign of each control element selects the corresponding A or B element.
let blend ins bld width =
  lift bld ins {
    let t, a, b, c, _ = arguments ins
    let x, y, control = vectorReg bld a, vectorReg bld b, vectorReg bld c
    let values =
      Array.init (128 / int width) (fun i ->
        AST.ite (AST.xthi 1<rt> (element width i control))
          (element width i y)
          (element width i x))
    write bld t (Array.reduce AST.concat values)
  }

/// IMM bit 7-index is the truth-table result for the three source bits.
let evaluate ins bld =
  lift bld ins {
    let t, a, b, c, imm = arguments ins
    let x, y, z = vectorReg bld a, vectorReg bld b, vectorReg bld c
    let choose flag value = if flag then value else AST.not value
    let terms =
      Array.init 8 (fun i ->
        if imm &&& (1UL <<< (7 - i)) <> 0UL then
          choose (i &&& 4 <> 0) x
          .& choose (i &&& 2 <> 0) y
          .& choose (i &&& 1 <> 0) z
        else
          AST.num0 128<rt>)
    let result = Array.reduce (.|) terms
    write bld t result
  }

/// Each control byte names a byte in its selected 32-byte section.
let permute ins bld =
  lift bld ins {
    let t, a, b, c, section = arguments ins
    let x, y, control = vectorReg bld a, vectorReg bld b, vectorReg bld c
    let sources =
      Array.init 32 (fun i ->
        element 8<rt> (i % 16) (if i < 16 then x else y))
    let values =
      Array.init 16 (fun i ->
        let selector = element 8<rt> i control
        let index = selector .& numU32 31u 8<rt>
        let selected =
          Array.foldBack (fun k rest ->
            AST.ite (index == numI32 k 8<rt>) sources[k] rest)
            [| 0 .. 30 |] sources[31]
        AST.ite (AST.xthi 3<rt> selector == numU64 section 3<rt>)
          selected
          (AST.num0 8<rt>))
    write bld t (Array.reduce AST.concat values)
  }

/// The indexed form replaces one word in each doubleword, preserving the rest.
let splat (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | TwoOperands(dst, OprImm imm) ->
      let w = numU64 imm 32<rt>
      let pair =
        if ins.Opcode = Op.XXSPLTIDP then doubleOfSingle bld w
        else AST.concat w w
      write bld dst (AST.concat pair pair)
    | ThreeOperands(dst, OprImm index, OprImm imm) ->
      let old = vectorReg bld dst
      let w = numU64 imm 32<rt>
      let values =
        Array.init 4 (fun i ->
          if i % 2 = int index then w else element 32<rt> i old)
      write bld dst (Array.reduce AST.concat values)
    | _ ->
      raise InvalidOperandException
  }

(*
  Lifts the Matrix-Multiply Assist forms: the accumulator moves and the
  masked rank-k updates. Accumulator n is no state of its own:
  the manual has VSR 4n to 4n + 3 and ACC[n] hold the same data, so row i
  of the accumulator is VSR 4n + i, the moves between the two are no-ops,
  and an update writes those registers. A source never overlaps the
  accumulator it updates (the decoder refuses that form), so each row is
  written as soon as it is computed.
*)
/// The rows of the accumulator an operand names: the halves of VSR 4n to
/// 4n + 3.
let private rowsOf bld opr =
  match opr with
  | OprReg reg when reg >= Register.ACC0 && reg <= Register.ACC7 ->
    let n = int reg - int Register.ACC0
    Array.init 4 (fun i ->
      vsrOf bld (OprReg(getVsxRegister (uint32 (4 * n + i)))))
  | _ ->
    raise InvalidOperandException

/// Clears a row.
let private clearRow bld (struct (h: Expr, l: Expr)) =
  append bld {
    h := AST.num0 64<rt>
    l := AST.num0 64<rt>
  }

/// xxsetaccz: every row of the accumulator cleared.
let setAccumulatorZero ins bld =
  lift bld ins {
    rowsOf bld (getOneOpr ins) |> Array.iter (clearRow bld)
  }

/// The row, column and product masks are numbered most significant first.
let private fields (ins: Instruction) =
  match ins.Operands with
  | FiveOperands(t, a, b, OprImm x, OprImm y) -> t, a, b, x, y, 0xffUL
  | SixOperands(t, a, b, OprImm x, OprImm y, OprImm p) -> t, a, b, x, y, p
  | _ -> raise InvalidOperandException

/// Disabled products replace both factors with positive zero before arithmetic.
let private maskWord width mask value =
  let count = 32 / width
  let mutable keep = 0UL
  for i in 0 .. count - 1 do
    if mask &&& (1UL <<< (count - 1 - i)) <> 0UL then
      keep <- keep ||| (((1UL <<< width) - 1UL) <<< (32 - width * (i + 1)))
    else
      ()
  value .& numU64 keep 32<rt>

/// <summary>
/// A rank-k update over words: element j of row i computed by f from word i
/// of xA, word j of xB and the element itself, each row written through
/// temporaries once its four words are computed.
/// </summary>
let private updateWords (ins: Instruction) bld width f =
  let o1, o2, o3, xm, ym, pm = fields ins
  let struct (ah, al) = vsrOf bld o2
  let struct (bh, bl) = vsrOf bld o3
  let xs = VSXLifter.lanesOf 32<rt> ah al
  let ys = VSXLifter.lanesOf 32<rt> bh bl
  rowsOf bld o1
  |> Array.iteri (fun i (struct (h, l)) ->
    let accs = VSXLifter.lanesOf 32<rt> h l
    let results =
      Array.init 4 (fun j ->
        if xm &&& (8UL >>> i) <> 0UL && ym &&& (8UL >>> j) <> 0UL then
          f (maskWord width pm xs[i]) (maskWord width pm ys[j]) accs[j]
        else
          AST.num0 32<rt>)
    VSXLifter.writeLanes bld 32<rt> h l results)

/// A rank-k update over words, as one instruction.
let private wordUpdate ins bld width f =
  lift bld ins {
    updateWords ins bld width f
  }

/// <summary>
/// One element of a single- or double-precision update: the product (kind
/// 0) or the fused multiply-add of the four accumulating kinds -- 1 adds
/// the element, 2 subtracts it, 3 subtracts it and negates the rounded
/// result, 4 adds it and negates -- through the calls the other vector
/// multiply-adds make, NaNs in POWER's order.
/// </summary>
let private fusedElement bld lane kind x y acc =
  if kind = 0 then
    VSXLifter.arith AST.fmul lane [ x; y ]
  else
    let subtract = kind = 2 || kind = 3
    VSXLifter.mulAddLane bld lane false subtract (kind >= 3) x y acc

/// The register an operand names.
let private regOf = function
  | OprReg reg -> reg
  | _ -> raise InvalidOperandException

/// xvf32ger and its accumulating forms.
let singleUpdate ins bld kind =
  wordUpdate ins bld 32 (fusedElement bld VSXLifter.single kind)

/// <summary>
/// xvf64ger and its accumulating forms: the four doubles of the pair
/// starting at xA by the two of xB, each row of the accumulator two
/// doublewords.
/// </summary>
let doubleUpdate (ins: Instruction) bld kind =
  lift bld ins {
    let o1, o2, o3, xm, ym, _ = fields ins
    let struct (a0, a1) = vsrOf bld o2
    let struct (a2, a3) = vsrOf bld (OprReg(secondOfPair (regOf o2)))
    let struct (y0, y1) = vsrOf bld o3
    let xs = [| a0; a1; a2; a3 |]
    let f x y acc = fusedElement bld VSXLifter.double kind x y acc
    rowsOf bld o1
    |> Array.iteri (fun i (struct (h, l)) ->
      let element j y acc =
        if xm &&& (8UL >>> i) <> 0UL && ym &&& (2UL >>> j) <> 0UL then
          f xs[i] y acc
        else
          AST.num0 64<rt>
      let results = [| element 0 y0 h; element 1 y1 l |]
      VSXLifter.writeLanes bld 64<rt> h l results)
  }

/// A bfloat16 as the single it is, a NaN quieted.
let private widenBF16 (h: Expr) =
  let s = AST.zext 32<rt> h << numI32 16 32<rt>
  let lane = VSXLifter.single
  AST.ite (VSXLifter.isNaNOf lane s) (VSXLifter.quietOf lane s) s

/// Shares the staged NaN priorities of the unprefixed rank-2 updates.
let private settleDot = VSXLifter.settleDot

/// <summary>
/// xvf16ger2 and xvbf16ger2 and their accumulating forms: each element the
/// named call FGER2HALF or FGER2BF16 (lanes/X.md) of the two words and the
/// element, in the direction FPSCR[RN] names, its NaN settled here.
/// </summary>
let dotUpdate ins bld isBF16 kind =
  let name = if isBF16 then "FGER2BF16" else "FGER2HALF"
  let widen = if isBF16 then widenBF16 else VSXLifter.widenHalf VSXLifter.single
  let fpscr = regVar bld Register.FPSCR
  let mode = AST.zext 8<rt> (AST.extract fpscr 2<rt> 0)
  let element x y acc =
    let args = [ x; y; acc; numI32 kind 8<rt>; mode ]
    settleDot widen kind x y acc (AST.app name args 32<rt>)
  wordUpdate ins bld 16 element

/// The fields of a word, most significant first, each width bits wide.
let private fieldsOf (w: Expr) width =
  Array.init (32 / width) (fun k ->
    AST.extract w (width * 1<rt>) (32 - width * (k + 1)))

/// <summary>
/// The sum of the products of matching fields of two words, at a width:
/// xA's fields signed, xB's signed or not.
/// </summary>
let private dotOf rt width ySigned (x: Expr) (y: Expr) =
  let ext signed v = if signed then AST.sext rt v else AST.zext rt v
  Array.map2 (fun a b -> ext true a .* ext ySigned b)
    (fieldsOf x width) (fieldsOf y width)
  |> Array.reduce (.+)

/// xvi4ger8, xvi8ger4, xvi16ger2 and their "pp" forms: the sum of products,
/// plus the element where the form accumulates, modulo two to the 32.
let integerUpdate ins bld width ySigned accumulate =
  let element x y acc =
    let sum = dotOf 32<rt> width ySigned x y
    if accumulate then sum .+ acc else sum
  wordUpdate ins bld width element

/// The bounds of a signed word, at 64 bits.
let private wordMin = numI64 (-2147483648L) 64<rt>

let private wordMax = numI64 2147483647L 64<rt>

/// One saturated element: the sum (plus the element where the form
/// accumulates) clamped to a signed word, sat set where it was clamped.
let private saturated bld sat width ySigned accumulate x y acc =
  let sum = dotOf 64<rt> width ySigned x y
  let total = tmpVar bld 64<rt>
  let low = total ?< wordMin
  let high = total ?> wordMax
  append bld {
    total := if accumulate then sum .+ AST.sext 64<rt> acc else sum
    sat := sat .| low .| high
  }
  AST.xtlo 32<rt> (AST.ite low wordMin (AST.ite high wordMax total))

/// <summary>
/// xvi8ger4spp, xvi16ger2s and xvi16ger2spp: the sum of products, plus the
/// element where the form accumulates, saturated to a signed word; a
/// saturated element sets VSCR's sticky SAT bit.
/// </summary>
let saturatingUpdate ins bld width ySigned accumulate =
  lift bld ins {
    let sat = tmpVar bld 1<rt>
    let vscr = regVar bld Register.VSCR
    sat := AST.b0
    updateWords ins bld width (saturated bld sat width ySigned accumulate)
    vscr := vscr .| AST.zext 32<rt> sat
  }
