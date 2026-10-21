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

/// Integer-significand arithmetic for the embedded floating-point categories.
module internal B2R2.FrontEnd.PPC.SPEFloatArithmetic

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC.SPEFloatCommon

/// Addition aligns three extra bits and jams the smaller operand. A distant
/// subtrahend still borrows correctly and leaves a sticky remainder.
let private add bld f a b =
  let ea, eb = scale f a, scale f b
  let higher = ea ?>= eb
  let distance = AST.ite higher (ea .- eb) (eb .- ea)
  let ma, mb = mantissa f a << n128 3UL, mantissa f b << n128 3UL
  let large = AST.ite higher ma mb
  let small = jam bld (AST.ite higher mb ma) distance
  let sa, sb = sign f a, sign f b
  let same = sa == sb
  let bigger = large .>= small
  let absolute = AST.ite bigger (large .- small) (small .- large)
  let largeSign, smallSign = AST.ite higher sa sb, AST.ite higher sb sa
  { Mantissa = AST.ite same (large .+ small) absolute
    Scale = AST.ite higher ea eb .- n32 3
    Negative = AST.ite bigger largeSign smallSign }

let private multiply f a b =
  { Mantissa = mantissa f a .* mantissa f b
    Scale = scale f a .+ scale f b
    Negative = sign f a <+> sign f b }

/// The quotient keeps eleven extra bits even for a double. The remainder
/// is jammed into its last bit before normalization and rounding.
let private divide bld f a b =
  let numerator = mantissa f a << n128 64UL
  let divisor = mantissa f b
  let quotient = save bld (numerator ./ divisor)
  let remainder = AST.not (zero (numerator .% divisor))
  { Mantissa = quotient .| AST.zext 128<rt> remainder
    Scale = scale f a .- scale f b .- n32 64
    Negative = sign f a <+> sign f b }

let private sum bld f fscr subtract a b =
  let b = if subtract then b <+> withSign f AST.b1 (AST.num0 f.Size) else b
  let raw = add bld f a b
  let rounded = pack bld f fscr true raw
  let minusZero = (fscr .& n32 3) == n32 3
  let computed =
    { rounded with
        Value =
          AST.ite (zero raw.Mantissa) (signedZero f minusZero) rounded.Value }
  let sa, sb = sign f a, sign f b
  let zeroSign = AST.ite (sa == sb) sa minusZero
  let aSmall, bSmall = zero (exponent f a), zero (exponent f b)
  let ordinary =
    choose (normal f a .& normal f b) computed
      (exact (AST.ite
                (aSmall .& bSmall)
                (signedZero f zeroSign)
                (AST.ite aSmall b a)))
  let ordinary =
    { ordinary with Flags = ordinary.Flags
                            .| flag 11 (denormal f (magnitude f a)
                                        .| denormal f (magnitude f b)) }
  choose
    (special f a)
    (result (maxValue f sa) (n32 0x800))
    (choose (special f b) (result (maxValue f sb) (n32 0x800)) ordinary)

let private product bld f fscr a b =
  let negative = sign f a <+> sign f b
  let inputError = invalid f a .| invalid f b
  let small = zero (exponent f a) .| zero (exponent f b)
  let saturated = result (maxValue f negative) (n32 0x800)
  choose small (result (signedZero f negative) (flag 11 inputError))
    (choose
      (special f a .| special f b)
      saturated
      (pack bld f fscr true (multiply f a b)))

let private quotient bld f fscr a b =
  let negative = sign f a <+> sign f b
  let maximum = maxValue f negative
  let zeroResult = signedZero f negative
  let divideZero = normal f a .& isZero f b
  let byZero =
    result maximum (flag 10 divideZero .| flag 11 (AST.not divideZero))
  choose (special f b) (result zeroResult (n32 0x800))
    (choose (zero (exponent f b)) byZero
      (choose (special f a) (result maximum (n32 0x800))
        (choose (zero (exponent f a))
          (result zeroResult (flag 11 (denormal f (magnitude f a))))
          (pack bld f fscr true (divide bld f a b)))))

let compute bld f fscr operation a b =
  match operation with
  | "add" -> sum bld f fscr false a b
  | "sub" -> sum bld f fscr true a b
  | "mul" -> product bld f fscr a b
  | "div" -> quotient bld f fscr a b
  | _ -> raise InvalidOperandException
