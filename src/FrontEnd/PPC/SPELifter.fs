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

/// <summary>
/// The Signal Processing Engine, whose instructions see a 64-bit general
/// register as two 32-bit elements, the high word and the low word. On a
/// 32-bit processor the low word is the register R0-R31 the other
/// instructions use and the high word is R0H-R31H, which only these
/// instructions reach; on a 64-bit one the register is the whole of it, high
/// word on top. A result is put together from its two words in temporaries
/// before it reaches the target, so a target that is also a source reads its
/// old value throughout.
/// </summary>
module internal B2R2.FrontEnd.PPC.SPELifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// The register that holds the high word of a general register on a 32-bit
/// processor.
let private highRegister (reg: Register): Register =
  LanguagePrimitives.EnumOfValue(int reg + int Register.R0H)

/// The high and the low word of a general register operand.
let wordsOf (bld: ILowUIRBuilder) opr =
  match opr with
  | OprReg reg when bld.RegType = 32<rt> ->
    struct (regVar bld (highRegister reg), regVar bld reg)
  | OprReg reg ->
    let whole = regVar bld reg
    struct (AST.xthi 32<rt> whole, AST.xtlo 32<rt> whole)
  | _ ->
    raise InvalidOperandException

/// Writes the high and the low word of a general register operand, both
/// computed before either is written.
let putWords (bld: ILowUIRBuilder) opr hi lo =
  let struct (th, tl) = tmpVars2 bld 32<rt>
  append bld {
    th := hi
    tl := lo
  }
  match opr with
  | OprReg reg when bld.RegType = 32<rt> ->
    append bld {
      regVar bld (highRegister reg) := th
      regVar bld reg := tl
    }
  | OprReg reg ->
    append bld { regVar bld reg := AST.concat th tl }
  | _ ->
    raise InvalidOperandException

/// An instruction that computes each word of RT from the matching words of
/// RA and RB.
let private vecBinary ins bld (compute: Expr -> Expr -> Expr) =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    putWords bld rt (compute ah bh) (compute al bl)
  }

let evand ins bld = vecBinary ins bld (.&)

let evandc ins bld = vecBinary ins bld (fun a b -> a .& AST.not b)

let eveqv ins bld = vecBinary ins bld (fun a b -> AST.not (a <+> b))

let evnand ins bld = vecBinary ins bld (fun a b -> AST.not (a .& b))

let evnor ins bld = vecBinary ins bld (fun a b -> AST.not (a .| b))

let evor ins bld = vecBinary ins bld (.|)

let evorc ins bld = vecBinary ins bld (fun a b -> a .| AST.not b)

let evxor ins bld = vecBinary ins bld (<+>)

let evaddw ins bld = vecBinary ins bld (.+)

/// evsubfw subtracts the elements of RA from those of RB.
let evsubfw ins bld = vecBinary ins bld (fun a b -> b .- a)

/// The immediate forms, which add or subtract the same five-bit number to
/// both words of RB.
let private vecImmediate ins bld rt rb (imm: Imm) compute =
  lift bld ins {
    let struct (bh, bl) = wordsOf bld rb
    let n = numU64 imm 32<rt>
    putWords bld rt (compute bh n) (compute bl n)
  }

/// evaddiw RT, RB, UI.
let evaddiw (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(rt, rb, OprImm ui) -> vecImmediate ins bld rt rb ui (.+)
  | _ -> raise InvalidOperandException

/// evsubifw RT, UI, RB.
let evsubifw (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(rt, OprImm ui, rb) -> vecImmediate ins bld rt rb ui (.-)
  | _ -> raise InvalidOperandException
