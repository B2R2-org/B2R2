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

/// An instruction that computes each word of RT from the matching word of RA.
let private vecUnary ins bld (compute: Expr -> Expr) =
  lift bld ins {
    let struct (rt, ra) = getTwoOprs ins
    let struct (ah, al) = wordsOf bld ra
    putWords bld rt (compute ah) (compute al)
  }

/// The 32-bit number a value of the instruction names, from its low bits.
let private word32 (imm: Imm) = numU32 (uint32 imm) 32<rt>

/// evabs, whose most negative word stays where it is: negating it gives it
/// back.
let evabs ins bld =
  let zero = AST.num0 32<rt>
  vecUnary ins bld (fun x -> AST.ite (x ?< zero) (zero .- x) x)

/// evneg.
let evneg ins bld = vecUnary ins bld (fun x -> AST.num0 32<rt> .- x)

/// evextsb and evextsh, which extend the sign of the low byte or the low
/// halfword of each word.
let evexts ins bld (size: RegType) =
  vecUnary ins bld (fun x -> AST.sext 32<rt> (AST.xtlo size x))

/// evrndw, which rounds each word to its top halfword and clears the rest.
let evrndw ins bld =
  vecUnary ins bld (fun x ->
    (x .+ numU32 0x8000u 32<rt>) .& numU32 0xffff0000u 32<rt>)

/// The number of leading zero bits of a word, by folding it down to a mask of
/// the bits at or below its highest set one and counting the ones in that.
let private leadingZeros (bld: ILowUIRBuilder) (word: Expr) =
  let x = tmpVar bld 32<rt>
  let n i = numI32 i 32<rt>
  let m1 = numU32 0x55555555u 32<rt>
  let m2 = numU32 0x33333333u 32<rt>
  let m3 = numU32 0x0f0f0f0fu 32<rt>
  append bld {
    x := word
    x := x .| (x >> n 1)
    x := x .| (x >> n 2)
    x := x .| (x >> n 4)
    x := x .| (x >> n 8)
    x := x .| (x >> n 16)
    x := x .- ((x >> n 1) .& m1)
    x := ((x >> n 2) .& m2) .+ (x .& m2)
    x := ((x >> n 4) .+ x) .& m3
    x := x .+ (x >> n 8)
    x := x .+ (x >> n 16)
  }
  n 32 .- (x .& n 63)

/// evcntlzw.
let evcntlzw ins bld = vecUnary ins bld (leadingZeros bld)

/// evcntlsw, which counts the leading bits equal to the sign: the leading
/// zeros of the word with its sign filled out and flipped away.
let evcntlsw ins bld =
  vecUnary ins bld (fun x -> leadingZeros bld (x <+> (x ?>> numI32 31 32<rt>)))

/// The bits of a word in the opposite order.
let private reverseBits (bld: ILowUIRBuilder) (word: Expr) =
  let x = tmpVar bld 32<rt>
  let swap shift (mask: uint32) =
    let m = numU32 mask 32<rt>
    let n = numI32 shift 32<rt>
    append bld { x := ((x >> n) .& m) .| ((x .& m) << n) }
  append bld { x := word }
  swap 1 0x55555555u
  swap 2 0x33333333u
  swap 4 0x0f0f0f0fu
  swap 8 0x00ff00ffu
  append bld { x := (x >> numI32 16 32<rt>) .| (x << numI32 16 32<rt>) }
  x

/// Writes the low word of a general register operand and leaves the high
/// word alone.
let private putLow (bld: ILowUIRBuilder) opr lo =
  let t = tmpVar bld 32<rt>
  append bld { t := lo }
  match opr with
  | OprReg reg when bld.RegType = 32<rt> ->
    append bld { regVar bld reg := t }
  | OprReg reg ->
    let whole = regVar bld reg
    append bld { whole := AST.concat (AST.xthi 32<rt> whole) t }
  | _ ->
    raise InvalidOperandException

/// brinc RT, RA, RB: the next index of a bit-reversed walk through a buffer,
/// RB masking the bits that count, the low sixteen of them on the e500 (the
/// manual leaves how many to the implementation). Only the low word of RT is
/// written.
let brinc ins bld =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (_, al) = wordsOf bld ra
    let struct (_, bl) = wordsOf bld rb
    let mask = numU32 0xffffu 32<rt>
    let m = tmpVar bld 32<rt>
    let a = tmpVar bld 32<rt>
    m := bl .& mask
    a := al .& mask
    let flipped = reverseBits bld (a .| AST.not m)
    let d = reverseBits bld (flipped .+ numI32 1 32<rt>)
    putLow bld rt ((al .& AST.not mask) .| (d .& m))
  }

/// A rotate or a shift of each word by the amount in the matching word of
/// RB, which counts bits 27:31 of it for the rotate and 26:31 for a shift.
let private vecShift ins bld (compute: Expr -> Expr -> Expr) (bits: int) =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    let mask = numI32 ((1 <<< bits) - 1) 32<rt>
    putWords bld rt (compute ah (bh .& mask)) (compute al (bl .& mask))
  }

/// ROTL of a word by an amount of at most 31.
let private rotateWord x n =
  (x << n) .| (x >> ((numI32 32 32<rt> .- n) .& numI32 31 32<rt>))

/// A shift of a word by a count of up to 63, which gives the fill value of
/// the shift -- zero, or for the arithmetic shift the sign -- from 32 up.
let private shiftWord (shift: Expr -> Expr -> Expr) (fill: Expr -> Expr) x n =
  AST.ite (n ?>= numI32 32 32<rt>) (fill x) (shift x n)

let private noFill (_: Expr) = AST.num0 32<rt>

let evrlw ins bld = vecShift ins bld rotateWord 5

let evslw ins bld = vecShift ins bld (shiftWord (<<) noFill) 6

let evsrwu ins bld = vecShift ins bld (shiftWord (>>) noFill) 6

let evsrws ins bld =
  let sign x = x ?>> numI32 31 32<rt>
  vecShift ins bld (shiftWord (?>>) sign) 6

/// The immediate forms, RT, RA, UI: the same count for both words.
let private vecShiftImmediate ins bld (compute: Expr -> Expr -> Expr) =
  lift bld ins {
    let struct (rt, ra, ui) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let n = word32 (getImmValue ui |> uint64)
    putWords bld rt (compute ah n) (compute al n)
  }

let evrlwi ins bld = vecShiftImmediate ins bld rotateWord

let evslwi ins bld = vecShiftImmediate ins bld (<<)

let evsrwiu ins bld = vecShiftImmediate ins bld (>>)

let evsrwis ins bld = vecShiftImmediate ins bld (?>>)

/// evsplati RT, SI: the sign-extended number in both words.
let evsplati ins bld =
  lift bld ins {
    let struct (rt, si) = getTwoOprs ins
    let n = word32 (getImmValue si |> uint64)
    putWords bld rt n n
  }

/// evsplatfi RT, SI: the number as the top five bits of both words.
let evsplatfi ins bld =
  lift bld ins {
    let struct (rt, si) = getTwoOprs ins
    let n = numU32 ((getImmValue si &&& 0x1fu) <<< 27) 32<rt>
    putWords bld rt n n
  }

/// The merges of the words of RA and RB: which word of each goes where.
let private vecMerge ins bld takeHighOfA takeHighOfB =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    putWords bld rt (if takeHighOfA then ah else al)
                    (if takeHighOfB then bh else bl)
  }

let evmergehi ins bld = vecMerge ins bld true true

let evmergelo ins bld = vecMerge ins bld false false

let evmergehilo ins bld = vecMerge ins bld true false

let evmergelohi ins bld = vecMerge ins bld false true

/// The compares, which write a CR field: whether the high words compare, then
/// whether the low words do, then either, then both.
let private vecCompare ins bld (relation: Expr -> Expr -> Expr) =
  lift bld ins {
    let struct (bf, ra, rb) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    let lt, gt, eq, so =
      match bf with
      | OprReg crf -> transCRxToExpr bld crf
      | _ -> raise InvalidOperandException
    let struct (ch, cl) = tmpVars2 bld 1<rt>
    ch := relation ah bh
    cl := relation al bl
    lt := ch
    gt := cl
    eq := ch .| cl
    so := ch .& cl
  }

let evcmpeq ins bld = vecCompare ins bld AST.eq

let evcmpgts ins bld = vecCompare ins bld AST.sgt

let evcmpgtu ins bld = vecCompare ins bld AST.gt

let evcmplts ins bld = vecCompare ins bld AST.slt

let evcmpltu ins bld = vecCompare ins bld AST.lt

/// evsel RT, RA, RB, BFA: each word of RT is that of RA where the matching
/// bit of CR field BFA (its first bit for the high word, its second for the
/// low one) is set, and that of RB where it is not.
let evsel ins bld =
  lift bld ins {
    let struct (rt, ra, rb, bfa) = getFourOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    let ch, cl, _, _ =
      match bfa with
      | OprReg crf -> transCRxToExpr bld crf
      | _ -> raise InvalidOperandException
    putWords bld rt (AST.ite ch ah bh) (AST.ite cl al bl)
  }
