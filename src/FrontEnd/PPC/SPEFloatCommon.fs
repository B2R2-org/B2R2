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

/// Shared representation and rounding for the embedded floating-point
/// categories of Power ISA 2.07B, Chapter 9 and Appendix D.
module internal B2R2.FrontEnd.PPC.SPEFloatCommon

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils

type Format =
  { Size: RegType
    Fraction: int
    Bias: int }

type Result =
  { Value: Expr
    Flags: Expr
    Touch: Expr }

let single = { Size = 32<rt>; Fraction = 23; Bias = 127 }

let double = { Size = 64<rt>; Fraction = 52; Bias = 1023 }

let n128 value = numU64 value 128<rt>

let n32 value = numI32 value 32<rt>

let bit value position = AST.extract value 1<rt> position

let zero value = value == AST.num0 (Expr.typeOf value)

let save bld value =
  let result = tmpVar bld (Expr.typeOf value)
  append bld { result := value }
  result

let sign _format value = AST.xthi 1<rt> value

let magnitude f value =
  value .& numU64 ((1UL <<< (int f.Size - 1)) - 1UL) f.Size

let exponent f value =
  let width = int f.Size - 1 - f.Fraction
  AST.zext 32<rt> (AST.extract value (RegType.fromBitWidth width) f.Fraction)

let denormal f value = zero (exponent f value) .& AST.not (zero value)

let special f value = exponent f value == n32 (2 * f.Bias + 1)

let isZero f value = zero (magnitude f value)

let normal f value =
  AST.not (zero (exponent f value)) .& AST.not (special f value)

let invalid f value = special f value .| denormal f (magnitude f value)

let withSign f negative value =
  value .| (AST.zext f.Size negative << numI32 (int f.Size - 1) f.Size)

let maxValue f negative =
  withSign f negative (numU64 ((1UL <<< (int f.Size - 1))
                              - (1UL <<< f.Fraction) - 1UL) f.Size)

let signedZero f negative = withSign f negative (AST.num0 f.Size)

let mantissa f value =
  let mask = numU64 ((1UL <<< f.Fraction) - 1UL) f.Size
  AST.zext 128<rt> (value .& mask) .| n128 (1UL <<< f.Fraction)

let scale f value = exponent f value .- n32 (f.Bias + f.Fraction)

let flag position condition = AST.zext 32<rt> condition << n32 position

let result value flags =
  { Value = value
    Flags = flags
    Touch = numU32 0x3f00u 32<rt> }

let exact value = result value (AST.num0 32<rt>)

let untouched value =
  { Value = value
    Flags = AST.num0 32<rt>
    Touch = AST.num0 32<rt> }

let choose condition yes no =
  { Value = AST.ite condition yes.Value no.Value
    Flags = AST.ite condition yes.Flags no.Flags
    Touch = AST.ite condition yes.Touch no.Touch }

/// A right shift and the guard and sticky bits below its truncated result.
/// Amounts past the width keep a sticky bit without an out-of-range shift.
let right bld value amount =
  let amount = save bld amount
  let shift = AST.zext 128<rt> amount
  let previous = AST.ite (amount ?> n32 0) (amount .- n32 1) (n32 0)
  let mask =
    AST.ite
      (previous .>= n32 128)
      (AST.not (n128 0UL))
      ((n128 1UL << AST.zext 128<rt> previous) .- n128 1UL)
  let truncated =
    AST.ite (amount .>= n32 128) (n128 0UL) (value >> shift)
  let guard =
    (amount ?> n32 0) .& (amount .<= n32 128)
    .& bit (value >> AST.zext 128<rt> previous) 0
  let sticky = AST.not (zero (value .& mask))
  struct (save bld truncated, save bld guard, save bld sticky)

/// Shift right with jamming, retaining every discarded bit in bit zero.
let jam bld value amount =
  let struct (truncated, guard, sticky) = right bld value amount
  truncated .| AST.zext 128<rt> (guard .| sticky)

/// The highest set bit, found in seven bounded binary steps.
let highest bld value =
  let remaining = save bld value
  let position = save bld (n32 0)
  for count in [ 64; 32; 16; 8; 4; 2; 1 ] do
    let shifted = remaining >> n128 (uint64 count)
    let present = AST.not (zero shifted)
    append bld {
      position := AST.ite present (position .+ n32 count) position
      remaining := AST.ite present shifted remaining
    }
  position

let nearest fscr = zero (fscr .& numU32 0x43u 32<rt>)

/// Round32 and Round64: infinity modes choose truncation, as permitted by
/// Appendix D. FINXE also requests truncation for the interrupt handler.
let rounded bld fscr truncated guard sticky =
  let increment = nearest fscr .& guard .& (sticky .| bit truncated 0)
  save bld (truncated .+ AST.zext 128<rt> increment)

type Exact =
  { Mantissa: Expr
    Scale: Expr
    Negative: Expr }

/// Pack an integer significand times a power of two. Only narrowing follows
/// Round32's edge saturation without setting overflow before rounding.
let pack bld f fscr strict (value: Exact) =
  let mant = save bld value.Mantissa
  let top = highest bld mant
  let unbiased = save bld (top .+ value.Scale)
  let shift = save bld (top .- n32 f.Fraction)
  let positive = AST.ite (shift ?> n32 0) shift (n32 0)
  let struct (right, guard, sticky) = right bld mant positive
  let truncated =
    AST.ite
      (shift ?>= n32 0)
      right
      (mant << AST.zext 128<rt> (n32 0 .- shift))
    |> save bld
  let rounded = rounded bld fscr truncated guard sticky
  let carry = bit rounded (f.Fraction + 1)
  let adjusted = AST.ite carry (rounded >> n128 1UL) rounded
  let newExponent = unbiased .+ n32 f.Bias .+ AST.zext 32<rt> carry
  let fractionMask = numU64 ((1UL <<< f.Fraction) - 1UL) f.Size
  let fraction = AST.xtlo f.Size adjusted .& fractionMask
  let encoding =
    (AST.zext f.Size newExponent << numI32 f.Fraction f.Size) .| fraction
    |> withSign f value.Negative
  let edge = truncated == n128 ((1UL <<< (f.Fraction + 1)) - 1UL)
  let overflow =
    (unbiased ?> n32 f.Bias)
    .| (if strict then
          (unbiased == n32 f.Bias) .& edge .& (guard .| sticky)
        else
          AST.b0)
  let underflow = unbiased ?< n32 (1 - f.Bias)
  let saturated = maxValue f value.Negative
  let finite = AST.ite (newExponent ?> n32 (2 * f.Bias)) saturated encoding
  let normalResult = result finite (flag 13 guard .| flag 12 sticky)
  let answer =
    choose overflow (result saturated (numU32 0x100u 32<rt>))
      (choose underflow
        (result (signedZero f value.Negative) (numU32 0x200u 32<rt>))
        normalResult)
  choose (zero mant) (exact (signedZero f value.Negative)) answer

/// The per-element status, sticky summaries and enabled data exceptions.
/// Every input is a snapshot, so aliases cannot observe a partial update.
let applyStatus bld fscr results =
  let mutable touched = AST.num0 32<rt>
  let mutable raised = AST.num0 32<rt>
  let mutable summary = AST.num0 32<rt>
  let mutable suppressed = AST.b0
  let mutable inexact = AST.b0
  for high, result in results do
    let offset = if high then n32 16 else n32 0
    let flags = save bld result.Flags
    touched <- touched .| (result.Touch << offset)
    raised <- raised .| (flags << offset)
    let statuses = [ 11, 20, 5; 10, 19, 4; 9, 18, 3; 8, 17, 2 ]
    for status, sticky, enable in statuses do
      summary <- summary .| flag sticky (bit flags status)
      suppressed <- suppressed .| (bit flags status .& bit fscr enable)
    inexact <- inexact .| bit flags 13 .| bit flags 12
               .| (bit flags 8 .& AST.not (bit fscr 2))
               .| (bit flags 9 .& AST.not (bit fscr 3))
  let suppressed = save bld suppressed
  append bld {
    regVar bld Register.SPEFSCR :=
      (fscr .& AST.not touched) .| raised .| summary
      .| flag 21 (inexact .& AST.not suppressed)
  }
  suppressed
