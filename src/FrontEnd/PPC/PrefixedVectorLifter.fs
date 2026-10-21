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

/// Lifts the prefixed vector blend, evaluate, permute and splat forms.
module internal B2R2.FrontEnd.PPC.PrefixedVectorLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils

let private vector bld operand =
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
    let x, y, control = vector bld a, vector bld b, vector bld c
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
    let x, y, z = vector bld a, vector bld b, vector bld c
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
    let x, y, control = vector bld a, vector bld b, vector bld c
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
        if ins.Opcode = Op.XXSPLTIDP then PrefixedLifter.doubleOfSingle bld w
        else AST.concat w w
      write bld dst (AST.concat pair pair)
    | ThreeOperands(dst, OprImm index, OprImm imm) ->
      let old = vector bld dst
      let w = numU64 imm 32<rt>
      let values =
        Array.init 4 (fun i ->
          if i % 2 = int index then w else element 32<rt> i old)
      write bld dst (Array.reduce AST.concat values)
    | _ ->
      raise InvalidOperandException
  }
