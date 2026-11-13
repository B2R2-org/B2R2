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

namespace B2R2.MiddleEnd.ConcEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type FloatingPointTests() =
  let check st expected expr =
    Assert.AreEqual<BitVector>(expected, Evaluator.evalExpr st expr)
    Assert.AreEqual(Ok(Def expected), SafeEvaluator.evalExpr st expr)

  let operand (st: ConcState) index value =
    st.SetTmp(index, value)
    AST.tmpvar value.Length index

  let fp value =
    BitVector(System.BitConverter.DoubleToUInt64Bits value, 64<rt>)

  let inMode mode expr = AST.roundCtrl (AST.roundingMode mode) expr

  [<TestMethod>]
  member _.``Floating inequality evaluates variables including NaNs``() =
    let st = ConcState()
    let x = operand st 0 (fp 0.0)
    let y = operand st 1 (fp -0.0)
    AST.relop RelOpType.FNEQ x y |> check st (BitVector.Zero 1<rt>)
    st.SetTmp(1, fp nan)
    AST.relop RelOpType.FNEQ x y |> check st (BitVector.One 1<rt>)

  [<TestMethod>]
  member _.``Nearest away rounds both signs at a midpoint``() =
    let st = ConcState()
    for input, output in [ 2.5, 3.0; -2.5, -3.0 ] do
      let x = operand st 0 (fp input)
      AST.roundToIntegral RoundingMode.ToNearestAway 64<rt> x
      |> check st (fp output)
      AST.floatToSInt RoundingMode.ToNearestAway 64<rt> x
      |> check st (BitVector(int64 output, 64<rt>))

  [<TestMethod>]
  member _.``Runtime modes cover a whole expression and nest lexically``() =
    let st = ConcState()
    let x = operand st 0 (fp 2.75)
    let mode = operand st 1 (BitVector(3UL, 8<rt>))
    let convert = AST.cast CastKind.FloatToSInt 64<rt> x
    AST.roundCtrl mode convert |> check st (BitVector(2UL, 64<rt>))
    AST.roundCtrl mode (AST.add convert (AST.num1 64<rt>))
    |> check st (BitVector(3UL, 64<rt>))
    let up = inMode RoundingMode.TowardPositive convert
    AST.roundCtrl mode (AST.add up convert)
    |> check st (BitVector(5UL, 64<rt>))
    convert |> check st (BitVector(3UL, 64<rt>))

  [<TestMethod>]
  member _.``Safe evaluation reports an undefined rounding mode``() =
    let st = ConcState()
    let mode = AST.tmpvar 8<rt> 0
    let body = AST.cast CastKind.FloatToSInt 64<rt> (AST.num (fp 2.75))
    let expr = AST.roundCtrl mode body
    match SafeEvaluator.evalExpr st expr with
    | Error _ -> ()
    | Ok v -> Assert.Fail $"Undefined mode evaluated to {v}."

  [<TestMethod>]
  member _.``Directed arithmetic rounds only once in the target format``() =
    let st = ConcState()
    let a = operand st 0 (BitVector(0x3f800000UL, 32<rt>))
    let b = operand st 1 (BitVector(0x33800000UL, 32<rt>))
    AST.fadd a b |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0x3f800001UL, 32<rt>))
    AST.fsub a b |> inMode RoundingMode.TowardNegative
    |> check st (BitVector(0x3f7fffffUL, 32<rt>))
    let a = operand st 0 (fp 1.0)
    let b = operand st 1 (fp (2.0 ** -53.0))
    AST.fadd a b |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0x3ff0000000000001UL, 64<rt>))
    let b = operand st 1 (fp 3.0)
    AST.fdiv a b |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0x3fd5555555555556UL, 64<rt>))
    let a = operand st 0 (fp 2.0)
    AST.unop UnOpType.FSQRT a |> inMode RoundingMode.TowardZero
    |> check st (BitVector(0x3ff6a09e667f3bccUL, 64<rt>))

  [<TestMethod>]
  member _.``Directed conversions respect the destination precision``() =
    let st = ConcState()
    let x = operand st 0 (BitVector(16777217UL, 64<rt>))
    AST.cast CastKind.UIntToFloat 32<rt> x
    |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0x4b800001UL, 32<rt>))
    let x = operand st 0 (fp (1.0 + 2.0 ** -24.0))
    AST.cast CastKind.FloatCast 32<rt> x
    |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0x3f800001UL, 32<rt>))

  [<TestMethod>]
  member _.``Extended rounding preserves integers beyond double precision``() =
    let st = ConcState()
    let bits = (bigint 0x4034 <<< 64) + (1I <<< 63) + (1I <<< 10)
    let value = BitVector(bits, 80<rt>)
    let x = operand st 0 value
    AST.cast CastKind.RoundToIntegral 80<rt> x |> check st value
    let large = BitVector((bigint 0x43ff <<< 64) + (1I <<< 63), 80<rt>)
    st.SetTmp(0, large)
    AST.cast CastKind.RoundToIntegral 80<rt> x |> check st large
    let exact = BitVector((1I <<< 53) + 1I, 64<rt>)
    let x = operand st 1 exact
    AST.cast CastKind.UIntToFloat 80<rt> x |> check st value

  [<TestMethod>]
  member _.``Directed arithmetic handles overflow and gradual underflow``() =
    let st = ConcState()
    let a = operand st 0 (BitVector(0x7f7fffffUL, 32<rt>))
    let b = operand st 1 (BitVector(0x40000000UL, 32<rt>))
    AST.fmul a b |> inMode RoundingMode.TowardZero
    |> check st (BitVector(0x7f7fffffUL, 32<rt>))
    AST.fmul a b |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0x7f800000UL, 32<rt>))
    st.SetTmp(0, BitVector(0xff7fffffUL, 32<rt>))
    AST.fmul a b |> inMode RoundingMode.TowardPositive
    |> check st (BitVector(0xff7fffffUL, 32<rt>))
    st.SetTmp(0, BitVector(1UL, 32<rt>))
    st.SetTmp(1, BitVector(0x3f000000UL, 32<rt>))
    AST.fmul a b |> check st (BitVector.Zero 32<rt>)
    AST.fmul a b |> inMode RoundingMode.ToNearestAway
    |> check st (BitVector.One 32<rt>)
    AST.fmul a b |> inMode RoundingMode.TowardPositive
    |> check st (BitVector.One 32<rt>)
    st.SetTmp(0, BitVector(0x80000001UL, 32<rt>))
    AST.fmul a b |> inMode RoundingMode.TowardNegative
    |> check st (BitVector(0x80000001UL, 32<rt>))

  [<TestMethod>]
  member _.``Extended fractional rounding and special values stay extended``() =
    let st = ConcState()
    let value = BitVector((bigint 0x3fff <<< 64) + (3I <<< 62), 80<rt>)
    let x = operand st 0 value
    let two = BitVector((bigint 0x4000 <<< 64) + (1I <<< 63), 80<rt>)
    AST.roundToIntegral RoundingMode.ToNearestEven 80<rt> x |> check st two
    let one = BitVector((bigint 0x3fff <<< 64) + (1I <<< 63), 80<rt>)
    AST.roundToIntegral RoundingMode.TowardZero 80<rt> x |> check st one
    for bits in [ 1I <<< 79; (bigint 0x7fff <<< 64) + (1I <<< 63) ] do
      let value = BitVector(bits, 80<rt>)
      st.SetTmp(0, value)
      AST.roundToIntegral RoundingMode.TowardZero 80<rt> x |> check st value

  [<TestMethod>]
  member _.``Exact cancellation follows the active zero sign rule``() =
    let st = ConcState()
    let a = operand st 0 (fp 1.0)
    let b = operand st 1 (fp -1.0)
    AST.fadd a b |> inMode RoundingMode.TowardNegative |> check st (fp -0.0)
    AST.fadd a b |> inMode RoundingMode.TowardPositive |> check st (fp 0.0)

  [<TestMethod>]
  member _.``Nearest arithmetic agrees with independent host operations``() =
    let st = ConcState()
    let rng = System.Random 42
    for _ in 1 .. 100 do
      let bytes = Array.zeroCreate<byte> 8
      rng.NextBytes bytes
      let av = System.BitConverter.ToDouble bytes
      rng.NextBytes bytes
      let bv = System.BitConverter.ToDouble bytes
      let a = operand st 0 (fp av)
      let b = operand st 1 (fp bv)
      for expr, value in
        [ AST.fadd a b, av + bv
          AST.fsub a b, av - bv
          AST.fmul a b, av * bv
          AST.fdiv a b, av / bv ] do
        if not (System.Double.IsNaN value) then check st (fp value) expr
        else ()
      if av >= 0.0 then
        AST.unop UnOpType.FSQRT a |> check st (fp (sqrt av))
      else
        ()

