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
/// The vector facility's decimal integer instructions. A signed packed decimal
/// value is 31 four-bit digits, the most significant first, and a four-bit
/// sign code; it is read into the binary number it stands for, the arithmetic
/// is done in binary, and the answer is written back as digits. Every value
/// 31 digits hold is below 2^104, so a 128-bit number holds it with room for
/// a sum and a sign.
/// </summary>
module internal B2R2.FrontEnd.PPC.VectorDecimalLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements

/// Ten to a power, as a 128-bit number.
let private pow10 (n: int) = AST.num (BitVector(bigint.Pow(10I, n), 128<rt>))

/// The 31 digits of a packed decimal value, the most significant first.
let private digitsOf (q: Expr) =
  Array.init 31 (fun k -> AST.extract q 4<rt> (124 - 4 * k))

/// Whether a signed packed decimal value is a valid encoding: every digit at
/// most 9 and a sign code of 10 or more.
let private isValidSigned q =
  let digitsValid =
    digitsOf q
    |> Array.map (fun d -> d .<= numI32 9 4<rt>)
    |> Array.reduce (.&)
  digitsValid .& (AST.xtlo 4<rt> q .>= numI32 10 4<rt>)

/// The magnitude a packed decimal value's digits stand for.
let private magnitudeOf q =
  digitsOf q
  |> Array.mapi (fun k d -> AST.zext 128<rt> d .* pow10 (30 - k))
  |> Array.reduce (.+)

/// Whether a sign code says negative, which 0b1011 and 0b1101 do.
let private isMinus (q: Expr) =
  let sign = AST.xtlo 4<rt> q
  (sign == numI32 0xb 4<rt>) .| (sign == numI32 0xd 4<rt>)

/// The signed number a signed packed decimal value stands for.
let private signedValueOf q =
  let m = magnitudeOf q
  AST.ite (isMinus q) (AST.neg m) m

/// The low 31 decimal digits of a binary magnitude, packed, followed by a
/// sign code.
let private packedOf (m: Expr) sign =
  let digits =
    Array.init 31 (fun k ->
      AST.xtlo 4<rt> ((m ./ pow10 (30 - k)) .% numI32 10 128<rt>))
  concatElements (Array.append digits [| sign |])

/// The sign code of a result that is not negative: 0b1100, or 0b1111 where the
/// preferred-sign operand PS says so.
let private plusSign ps = numI32 (if ps then 0xf else 0xc) 4<rt>

/// Sets CR6 from a decimal result: less than, greater than and equal to zero
/// and the overflow bit, where both operands are valid; 0b0001 where either
/// is not.
let private setDecimalCR6 (bld: ILowUIRBuilder) valid (r: Expr) overflow =
  append bld {
    regVar bld Register.CR6_0 := valid .& (r ?< AST.num0 128<rt>)
    regVar bld Register.CR6_1 := valid .& (r ?> AST.num0 128<rt>)
    regVar bld Register.CR6_2 := valid .& (r == AST.num0 128<rt>)
    regVar bld Register.CR6_3 := AST.not valid .| overflow
  }

/// bcdadd./bcdsub.: the sum or the difference of two signed packed decimal
/// values, its low 31 digits written with a sign code saying negative (0b1101)
/// or not, and CR6 saying how it compares with zero and whether it overflowed
/// 31 digits. The ISA leaves the result undefined where an operand is not a
/// valid encoding; it is written as all ones there, as QEMU writes it.
let bcdAddSub ins bld subtract =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let ps = getImmValue o4 = 1u
    let struct (a, b) = tmpVars2 bld 128<rt>
    let struct (r, m) = tmpVars2 bld 128<rt>
    let valid = tmpVar bld 1<rt>
    a := quadOf bld o2
    b := quadOf bld o3
    valid := isValidSigned a .& isValidSigned b
    let combine = if subtract then (.-) else (.+)
    r := combine (signedValueOf a) (signedValueOf b)
    m := AST.ite (r ?< AST.num0 128<rt>) (AST.neg r) r
    let sign = AST.ite (r ?< AST.num0 128<rt>) (numI32 0xd 4<rt>) (plusSign ps)
    let ones = AST.not (AST.num0 128<rt>)
    putElements bld o1 [| AST.ite valid (packedOf m sign) ones |]
    setDecimalCR6 bld valid r (m .>= pow10 31)
  }
