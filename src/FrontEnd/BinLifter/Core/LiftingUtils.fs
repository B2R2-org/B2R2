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

module B2R2.FrontEnd.BinLifter.LiftingUtils

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter.LiftingOperators

let inline numU32 n t = BitVector.OfUInt32 n t |> AST.num

let inline numI32 n t = BitVector.OfInt32 n t |> AST.num

let inline numU64 n t = BitVector.OfUInt64 n t |> AST.num

let inline numI64 n t = BitVector.OfInt64 n t |> AST.num

let inline tmpVars2 ir t =
  struct (!+ir t, !+ir t)

let inline tmpVars3 ir t =
  struct (!+ir t, !+ir t, !+ir t)

let inline tmpVars4 ir t =
  struct (!+ir t, !+ir t, !+ir t, !+ir t)

module IEEE754Double =
  open B2R2.BinIR.LowUIR.AST.InfixOp

  let inline private hasFraction x =
    (x .& numU64 0xfffff_ffffffffUL 64<rt>) != AST.num0 64<rt>

  let isNaN x =
    let exponent = (x >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
    let e = numI32 0x7ff 64<rt>
    AST.xtlo 1<rt> ((exponent == e) .& hasFraction x)

  let isSNaN x =
    let nanChecker = isNaN x
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    nanChecker .& ((x .& signalBit) == AST.num0 64<rt>)

  let isQNaN x =
    let nanChecker = isNaN x
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    nanChecker .& ((x .& signalBit) != AST.num0 64<rt>)

  let isInfinity x =
    let exponent = (x >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
    let fraction = x .& numU64 0xfffff_ffffffffUL 64<rt>
    let e = numI32 0x7ff 64<rt>
    let zero = AST.num0 64<rt>
    AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))
