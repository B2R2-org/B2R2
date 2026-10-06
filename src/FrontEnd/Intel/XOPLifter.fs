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

/// AMD's XOP instructions (AMD64 APM Vol. 4). The parser already puts their
/// operands in the order the operation reads them -- XOP.W only swaps which of
/// two sources ModRM names, never what they mean -- so these follow the
/// operand list as decoded. Every form writes a 128-bit or a 256-bit result
/// and clears the register above it, as a VEX encoding does.
module internal B2R2.FrontEnd.Intel.XOPLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils
open B2R2.FrontEnd.Intel.MMXLifter

/// The elements of an operand, sz bits each, low first.
let private elems ins bld oprSz sz opr =
  transOprToArr ins bld false sz (64<rt> / sz) oprSz opr

/// Writes the elements, low first, to the destination and clears everything
/// above them.
let private write ins bld oprSz sz dst result =
  assignPackedInstr ins bld false (64<rt> / sz) oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512

/// VPCMOV takes each bit from the first source where the selector's bit is
/// set, and from the second where it is clear.
let vpcmov (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2, sel) = getFourOprs ins
    let a = elems ins bld oprSz 64<rt> src1
    let b = elems ins bld oprSz 64<rt> src2
    let pick i s = (a[i] .& s) .| (b[i] .& AST.not s)
    let result = elems ins bld oprSz 64<rt> sel |> Array.mapi pick
    write ins bld oprSz 64<rt> dst result
  }

/// The test the low three bits of VPCOM's immediate name: the four orderings,
/// then equality and inequality, then false and true outright.
let private comTest isSigned pred (a: Expr) b =
  match pred &&& 7L with
  | 0L -> if isSigned then a ?< b else a .< b
  | 1L -> if isSigned then a ?<= b else a .<= b
  | 2L -> if isSigned then a ?> b else a .> b
  | 3L -> if isSigned then a ?>= b else a .>= b
  | 4L -> a == b
  | 5L -> a != b
  | 6L -> AST.b0
  | _ -> AST.b1

let private vpcom (ins: Instruction) bld sz isSigned =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let test = comTest isSigned (getImmValue imm)
    let mask a b = AST.ite (test a b) (getMask sz) (AST.num0 sz)
    let a = elems ins bld oprSz sz src1
    let result = Array.map2 mask a (elems ins bld oprSz sz src2)
    write ins bld oprSz sz dst result
  }

let vpcomb ins bld = vpcom ins bld 8<rt> true

let vpcomw ins bld = vpcom ins bld 16<rt> true

let vpcomd ins bld = vpcom ins bld 32<rt> true

let vpcomq ins bld = vpcom ins bld 64<rt> true

let vpcomub ins bld = vpcom ins bld 8<rt> false

let vpcomuw ins bld = vpcom ins bld 16<rt> false

let vpcomud ins bld = vpcom ins bld 32<rt> false

let vpcomuq ins bld = vpcom ins bld 64<rt> false

/// The horizontal adds widen as they add: each destination element is the sum
/// of the run of source elements it covers, each extended to the destination's
/// width first, so the sum neither wraps nor saturates.
let private vphadd (ins: Instruction) bld srcSz dstSz ext =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let s = elems ins bld oprSz srcSz src |> Array.map (ext dstSz)
    let run = dstSz / srcSz
    let sum i = Array.sub s (i * run) run |> Array.reduce (.+)
    write ins bld oprSz dstSz dst (Array.init (s.Length / run) sum)
  }

let vphaddbw ins bld = vphadd ins bld 8<rt> 16<rt> AST.sext

let vphaddbd ins bld = vphadd ins bld 8<rt> 32<rt> AST.sext

let vphaddbq ins bld = vphadd ins bld 8<rt> 64<rt> AST.sext

let vphaddwd ins bld = vphadd ins bld 16<rt> 32<rt> AST.sext

let vphaddwq ins bld = vphadd ins bld 16<rt> 64<rt> AST.sext

let vphadddq ins bld = vphadd ins bld 32<rt> 64<rt> AST.sext

let vphaddubw ins bld = vphadd ins bld 8<rt> 16<rt> AST.zext

let vphaddubd ins bld = vphadd ins bld 8<rt> 32<rt> AST.zext

let vphaddubq ins bld = vphadd ins bld 8<rt> 64<rt> AST.zext

let vphadduwd ins bld = vphadd ins bld 16<rt> 32<rt> AST.zext

let vphadduwq ins bld = vphadd ins bld 16<rt> 64<rt> AST.zext

let vphaddudq ins bld = vphadd ins bld 32<rt> 64<rt> AST.zext

/// The horizontal subtracts take the upper element of each pair from the lower
/// one, both sign-extended to twice their width.
let private vphsub (ins: Instruction) bld srcSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let dstSz = (srcSz: RegType) * 2
    let s = elems ins bld oprSz srcSz src |> Array.map (AST.sext dstSz)
    let diff i = s[2 * i] .- s[2 * i + 1]
    write ins bld oprSz dstSz dst (Array.init (s.Length / 2) diff)
  }

let vphsubbw ins bld = vphsub ins bld 8<rt>

let vphsubwd ins bld = vphsub ins bld 16<rt>

let vphsubdq ins bld = vphsub ins bld 32<rt>

/// A signed sum brought down to the accumulator's width, or to the nearer end
/// of its range where it does not fit there.
let private saturate bld wide accSz e =
  let t = tmpVar bld wide
  append bld {
    direct t := e
  }
  let lo = AST.xtlo accSz t
  let top = numI64 ((1L <<< (int accSz - 1)) - 1L) accSz
  let bound = AST.ite (AST.xthi 1<rt> t) (AST.not top) top
  AST.ite (AST.sext wide lo == t) lo bound

/// The multiply-accumulates: each destination element is the element of the
/// third source in its place plus the products of the elements of the first
/// two that picks names for it. The sum is formed at twice the accumulator's
/// width, which holds any of them exactly, then cut back to the accumulator
/// or saturated to it.
let private vpmacs (ins: Instruction) bld srcSz accSz picks isSat =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2, src3) = getFourOprs ins
    let wide = (accSz: RegType) * 2
    let a = elems ins bld oprSz srcSz src1 |> Array.map (AST.sext wide)
    let b = elems ins bld oprSz srcSz src2 |> Array.map (AST.sext wide)
    let c = elems ins bld oprSz accSz src3 |> Array.map (AST.sext wide)
    let product k = a[k] .* b[k]
    let sum i = picks i |> List.map product |> List.fold (.+) c[i]
    let narrow = if isSat then saturate bld wide accSz else AST.xtlo accSz
    let result = Array.init c.Length (fun i -> narrow (sum i))
    write ins bld oprSz accSz dst result
  }

let private same i = [ i ]

(* Of each pair of source elements the accumulator's element spans, the
   doubleword forms read the one their name says, and the word forms the high
   one: words 1, 3, 5 and 7, the "odd-numbered" ones of the manual. The
   manual's text and figure leave the count's origin open; GCC's definition
   of these instructions (xop_p<macs>wd in sse.md) and Bochs both settle it
   on the odd indexes counted from zero. *)
let private low i = [ 2 * i ]

let private high i = [ 2 * i + 1 ]

let private both i = [ 2 * i; 2 * i + 1 ]

let vpmacsww ins bld = vpmacs ins bld 16<rt> 16<rt> same false

let vpmacssww ins bld = vpmacs ins bld 16<rt> 16<rt> same true

let vpmacswd ins bld = vpmacs ins bld 16<rt> 32<rt> high false

let vpmacsswd ins bld = vpmacs ins bld 16<rt> 32<rt> high true

let vpmacsdd ins bld = vpmacs ins bld 32<rt> 32<rt> same false

let vpmacssdd ins bld = vpmacs ins bld 32<rt> 32<rt> same true

let vpmacsdql ins bld = vpmacs ins bld 32<rt> 64<rt> low false

let vpmacssdql ins bld = vpmacs ins bld 32<rt> 64<rt> low true

let vpmacsdqh ins bld = vpmacs ins bld 32<rt> 64<rt> high false

let vpmacssdqh ins bld = vpmacs ins bld 32<rt> 64<rt> high true

let vpmadcswd ins bld = vpmacs ins bld 16<rt> 32<rt> both false

let vpmadcsswd ins bld = vpmacs ins bld 16<rt> 32<rt> both true

/// The byte the low five bits of a VPPERM selector pick from the 32 the two
/// sources hold between them, the first source's sixteen coming first.
let private pickByte bld pool sel =
  let b = tmpVar bld 8<rt>
  let idx = AST.zext 256<rt> (sel .& numI32 0x1f 8<rt>)
  append bld {
    direct b := AST.xtlo 8<rt> (pool >> (idx << numI32 3 256<rt>))
  }
  b

/// The bits of a byte in the reverse order.
let private reverseBits b =
  Array.init 8 (fun i -> AST.extract b 1<rt> (7 - i)) |> AST.revConcat

/// One byte of VPPERM's result. Bits 7:5 of the selector say what becomes of
/// the byte it picks: kept, its bits reversed, its sign spread over it, or
/// zero -- and each of these inverted where bit 5 is set, which is an xor
/// with bit 5 spread across the byte.
let private permByte bld pool sel =
  let b = pickByte bld pool sel
  let bit n = AST.extract sel 1<rt> n
  let sign = b ?>> numI32 7 8<rt>
  let fill = AST.ite (bit 6) sign (AST.num0 8<rt>)
  let moved = AST.ite (bit 6) (reverseBits b) b
  AST.ite (bit 7) fill moved <+> AST.sext 8<rt> (bit 5)

let vpperm (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2, sel) = getFourOprs ins
    let a = elems ins bld oprSz 64<rt> src1
    let b = elems ins bld oprSz 64<rt> src2
    let pool = tmpVar bld 256<rt>
    direct pool := AST.revConcat (Array.append a b)
    let result = elems ins bld oprSz 8<rt> sel |> Array.map (permByte bld pool)
    write ins bld oprSz 8<rt> dst result
  }

(* The counts of the rotates and shifts are signed bytes: a positive count
   moves bits left and a negative one moves them right, by its magnitude
   modulo the element's width, as the manual has it for the forms it says
   anything about ("the count is modulo 64" for VPSHAQ, and so on). *)
/// A rotate by an immediate turns every element by the same count, which is
/// known while lifting. Turning right by a count is turning left by its
/// negation, both modulo the width.
let private rotateByImm (ins: Instruction) bld sz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src, imm) = getThreeOprs ins
    let mask = int64 (int sz) - 1L
    let left = numI64 (getImmValue imm &&& mask) sz
    let right = numI64 (-(getImmValue imm) &&& mask) sz
    let turn x = (x << left) .| (x >> right)
    write ins bld oprSz sz dst (elems ins bld oprSz sz src |> Array.map turn)
  }

/// The count an element of a count operand gives: the signed byte at its
/// bottom.
let private countByte sz (c: Expr) =
  if sz = 8<rt> then c else AST.xtlo 8<rt> c

/// The rotates and shifts whose count is an element of another operand, one
/// count for each element of the source.
let private byCounts (ins: Instruction) bld sz op =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src, cnt) = getThreeOprs ins
    let x = elems ins bld oprSz sz src
    let c = elems ins bld oprSz sz cnt |> Array.map (countByte sz)
    write ins bld oprSz sz dst (Array.map2 (op sz) x c)
  }

/// A count, taken modulo the element's width, as wide as the element.
let private amount sz c =
  let m = c .& numI32 (int sz - 1) 8<rt>
  if sz = 8<rt> then m else AST.zext sz m

/// The rotate by a count of its own, which like the one by an immediate needs
/// no test of the count's sign.
let private rotate sz x c =
  (x << amount sz c) .| (x >> amount sz (AST.neg c))

let private vprot (ins: Instruction) bld sz =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> rotateByImm ins bld sz
  | _ -> byCounts ins bld sz rotate

let vprotb ins bld = vprot ins bld 8<rt>

let vprotw ins bld = vprot ins bld 16<rt>

let vprotd ins bld = vprot ins bld 32<rt>

let vprotq ins bld = vprot ins bld 64<rt>

/// A shift by a count of its own, which goes left or right by the count's
/// sign; shr says what comes in from the left.
let private shiftBy shr sz x c =
  let right = shr x (amount sz (AST.neg c))
  AST.ite (AST.xthi 1<rt> c) right (x << amount sz c)

let vpshab ins bld = byCounts ins bld 8<rt> (shiftBy (?>>))

let vpshaw ins bld = byCounts ins bld 16<rt> (shiftBy (?>>))

let vpshad ins bld = byCounts ins bld 32<rt> (shiftBy (?>>))

let vpshaq ins bld = byCounts ins bld 64<rt> (shiftBy (?>>))

let vpshlb ins bld = byCounts ins bld 8<rt> (shiftBy (>>))

let vpshlw ins bld = byCounts ins bld 16<rt> (shiftBy (>>))

let vpshld ins bld = byCounts ins bld 32<rt> (shiftBy (>>))

let vpshlq ins bld = byCounts ins bld 64<rt> (shiftBy (>>))

/// The fraction of a floating-point value: what is left once its integer part,
/// truncated toward zero, is taken away. The difference is exact, and the
/// zero an integer leaves takes its sign from the subtraction, which is what
/// the manual's table of rounding directions describes.
let private fraction sz x =
  x |> AST.roundToIntegral RoundingMode.TowardZero sz |> AST.fsub x

let private vfrczp (ins: Instruction) bld sz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let result = elems ins bld oprSz sz src |> Array.map (fraction sz)
    write ins bld oprSz sz dst result
  }

let vfrczps ins bld = vfrczp ins bld 32<rt>

let vfrczpd ins bld = vfrczp ins bld 64<rt>

/// The scalar forms write the low element alone and clear the rest of the
/// register, the rest of its low 128 bits included.
let private vfrczs (ins: Instruction) bld sz =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let x = tmpVar bld sz
    direct x :=
      if sz = 32<rt> then transOpr32 ins bld false src
      else transOpr64 ins bld false src
    let r = fraction sz x
    direct dstA := if sz = 64<rt> then r else AST.zext 64<rt> r
    direct dstB := AST.num0 64<rt>
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

let vfrczss ins bld = vfrczs ins bld 32<rt>

let vfrczsd ins bld = vfrczs ins bld 64<rt>
