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
/// The embedded floating-point categories of the Signal Processing Engine's
/// processors, which keep floating-point numbers in the general registers: a
/// single in a word (the scalar ones in the low word of the register, the
/// vector ones in both words) and a double in the whole register. They do not
/// follow IEEE 754 to the letter: an infinity, a NaN or a denormalized number
/// is not an operand but an input error, which has a default result of its
/// own, and a result that overflows or underflows is the largest number or a
/// zero, never an infinity or a denormalized number. SPEFSCR records what
/// each element found.
/// </summary>
module internal B2R2.FrontEnd.PPC.SPEFloatLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.SPELifter

/// The sign instructions on the words of the registers: the same operation on
/// the low word of the register (the scalar single, which leaves the rest of
/// RT as it is), on both words (the vector of two singles) or on the high word
/// of a double, which holds its sign.
let private signOnWords ins bld high low (op: Expr -> Expr) =
  lift bld ins {
    let struct (rt, ra) = getTwoOprs ins
    let struct (ah, al) = wordsOf bld ra
    if high then
      putWords bld rt (op ah) (if low then op al else al)
    else
      putLow bld rt (op al)
  }

let private clearSign (word: Expr) = word .& numU32 0x7fffffffu 32<rt>

let private setSign (word: Expr) = word .| numU32 0x80000000u 32<rt>

let private flipSign (word: Expr) = word <+> numU32 0x80000000u 32<rt>

let efsabs ins bld = signOnWords ins bld false true clearSign

let efsnabs ins bld = signOnWords ins bld false true setSign

let efsneg ins bld = signOnWords ins bld false true flipSign

let evfsabs ins bld = signOnWords ins bld true true clearSign

let evfsnabs ins bld = signOnWords ins bld true true setSign

let evfsneg ins bld = signOnWords ins bld true true flipSign

let efdabs ins bld = signOnWords ins bld true false clearSign

let efdnabs ins bld = signOnWords ins bld true false setSign

let efdneg ins bld = signOnWords ins bld true false flipSign

open B2R2.FrontEnd.PPC.SPEFloatCommon

/// The four one-bit registers of a condition field, in architectural order.
let private conditionBits bld operand =
  match operand with
  | OprReg reg -> transCRxToExpr bld reg
  | _ -> raise InvalidOperandException

let private views vector f a b =
  if vector then
    [ true, AST.xthi 32<rt> a, AST.xthi 32<rt> b
      false, AST.xtlo 32<rt> a, AST.xtlo 32<rt> b ]
  else
    [ false, AST.xtlo f.Size a, AST.xtlo f.Size b ]

/// Comparison uses sign-magnitude ordering even for NaNs and infinities;
/// both signed zeros have key zero. Tests never signal an input error.
let private compareKey f value =
  let absolute = magnitude f value
  AST.ite (sign f value) (AST.num0 f.Size .- absolute) absolute

let private compareValues f operation a b =
  let a, b = compareKey f a, compareKey f b
  match operation with
  | "eq" -> a == b
  | "gt" -> a ?> b
  | "lt" -> a ?< b
  | _ -> raise InvalidOperandException

let private compare ins bld vector f fscr (operation: string) =
  let struct (field, ra, rb) = getThreeOprs ins
  let whole opr =
    let struct (high, low) = wordsOf bld opr
    save bld (AST.concat high low)
  let a, b = whole ra, whole rb
  let values = views vector f a b
  let answers =
    values |> List.map (fun (_, a, b) ->
      save bld (compareValues f operation[3..] a b))
  let high, low =
    match answers with
    | [ high; low ] -> high, low
    | [ low ] -> AST.b0, low
    | _ -> raise InvalidOperandException
  let results =
    values |> List.map (fun (high, a, b) ->
      let flags = flag 11 (invalid f a .| invalid f b)
      let outcome =
        if operation.StartsWith "tst" then untouched AST.b0
        else result AST.b0 flags
      high, outcome)
  let suppressed = applyStatus bld fscr results
  let c0, c1, c2, c3 = conditionBits bld field
  let orBit, andBit =
    if vector then high .| low, high .& low else AST.b0, AST.b0
  append bld {
    c0 := AST.ite suppressed c0 high
    c1 := AST.ite suppressed c1 low
    c2 := AST.ite suppressed c2 orBit
    c3 := AST.ite suppressed c3 andBit
  }

/// Integer and fractional inputs use a 31-bit binary scale when signed and
/// a 32-bit binary scale when unsigned (Appendix D.6).
let private fromInteger bld f fscr (operation: string) value =
  let signed = operation[2] = 's'
  let fractional = operation.EndsWith "f"
  let size = if operation.EndsWith "id" then 64<rt> else 32<rt>
  let input = AST.xtlo size value
  let negative = if signed then AST.xthi 1<rt> input else AST.b0
  let absolute = AST.ite negative (AST.num0 size .- input) input
  let scale =
    if fractional then n32 (if signed then -31 else -32) else n32 0
  let exact =
    { Mantissa = AST.zext 128<rt> absolute
      Scale = scale
      Negative = negative }
  pack bld f fscr true exact

let private integerLimit size signed negative =
  if signed then
    let minimum = numU64 (1UL <<< (int size - 1)) size
    AST.ite negative minimum (minimum .- AST.num1 size)
  else
    AST.ite negative (AST.num0 size) (AST.not (AST.num0 size))

let private maximumIntegerExponent f size signed fractional input =
  let negative = sign f input
  let exp = exponent f input
  let precision = int size - 1
  let exactMinimum =
    (exp == n32 (f.Bias + precision))
    .& zero (input .& numU64 ((1UL <<< f.Fraction) - 1UL) f.Size)
    .& negative
  if fractional then
    n32 (f.Bias - 1)
  elif signed then
    AST.ite
      exactMinimum
      (n32 (f.Bias + precision))
      (n32 (f.Bias + precision - 1))
  else
    n32 (f.Bias + precision)

let private integerMagnitude bld f fscr (operation: string) input =
  let size = if operation.EndsWith "idz" then 64<rt> else 32<rt>
  let signed = operation[2] = 's'
  let fractional = operation.EndsWith "f"
  let exp = exponent f input
  let scale = if fractional then int size - (if signed then 1 else 0) else 0
  let amount = n32 (f.Bias + f.Fraction - scale) .- exp |> save bld
  let positive = AST.ite (amount ?> n32 0) amount (n32 0)
  let mant = mantissa f input
  let struct (shifted, guard, sticky) = right bld mant positive
  let truncated =
    AST.ite
      (amount ?>= n32 0)
      shifted
      (mant << AST.zext 128<rt> (n32 0 .- amount))
    |> save bld
  let rounded =
    if operation.EndsWith "z" then truncated
    else SPEFloatCommon.rounded bld fscr truncated guard sticky
  struct (rounded, guard, sticky)

/// Saturating conversion keeps guard and sticky before applying the selected
/// rounding mode. Overflow of this conversion signals FINV, as the results
/// tables and the definition of FINV specify, rather than FOVF.
let private toInteger bld f fscr (operation: string) input =
  let size = if operation.EndsWith "idz" then 64<rt> else 32<rt>
  let signed = operation[2] = 's'
  let fractional = operation.EndsWith "f"
  let negative = sign f input
  let exp = exponent f input
  let maximumExponent = maximumIntegerExponent f size signed fractional input
  let struct (rounded, guard, sticky) =
    integerMagnitude bld f fscr operation input
  let limit = integerLimit size signed negative
  let absoluteLimit =
    if signed then AST.ite negative limit (integerLimit size true AST.b0)
    else AST.not (AST.num0 size)
  let clamped =
    AST.ite
      (rounded .> AST.zext 128<rt> absoluteLimit)
      absoluteLimit
      (AST.xtlo size rounded)
  let converted =
    AST.ite
      (negative .& (if signed then AST.b1 else AST.b0))
      (AST.num0 size .- clamped)
      clamped
  let normal = result converted (flag 13 guard .| flag 12 sticky)
  let outOfRange =
    (exp .> maximumExponent)
    .| (if signed then AST.b0 else negative .& AST.not (isZero f input))
  let invalidValue =
    AST.ite (special f input
              .& AST.not (zero (input .& numU64
                ((1UL <<< f.Fraction) - 1UL) f.Size)))
      (AST.num0 size) limit
  choose (special f input) (result invalidValue (n32 0x800))
    (choose (denormal f (magnitude f input))
      (result (AST.num0 size) (n32 0x800))
      (choose
        (isZero f input)
        (untouched (AST.num0 size))
        (choose outOfRange (result limit (n32 0x800)) normal)))

let private resize bld fscr narrow input =
  let source, target = if narrow then double, single else single, double
  let input = AST.xtlo source.Size input
  let negative = sign source input
  let normal =
    if narrow then
      pack bld target fscr false
        { Mantissa = mantissa source input
          Scale = scale source input
          Negative = negative }
    else
      let exp = AST.zext 64<rt> (exponent source input .+ n32 896)
      let fraction = AST.zext 64<rt> (input .& numU32 0x7fffffu 32<rt>)
      untouched (withSign target negative
                   ((exp << numI32 52 64<rt>)
                    .| (fraction << numI32 29 64<rt>)))
  choose (isZero source input) (untouched (signedZero target negative))
    (choose (special source input)
      (result (maxValue target negative) (n32 0x800))
      (choose
        (denormal source (magnitude source input))
        (result (signedZero target negative) (n32 0x800))
        normal))

let private execute bld f fscr name operation a b =
  match name, (operation: string) with
  | "efscfd", _ ->
    resize bld fscr true b
  | "efdcfs", _ ->
    resize bld fscr false b
  | _, "add" | _, "sub" | _, "mul" | _, "div" ->
    SPEFloatArithmetic.compute bld f fscr operation a b
  | _, op when op.StartsWith "cf" ->
    fromInteger bld f fscr op b
  | _, op when op.StartsWith "ct" ->
    toInteger bld f fscr op b
  | _ ->
    raise InvalidOperandException

let private arithmetic ins bld vector f fscr name (operation: string) =
  let struct (target, ra, rb) =
    match (ins: Instruction).Operands with
    | ThreeOperands(rt, ra, rb) -> struct (rt, ra, rb)
    | TwoOperands(rt, rb) -> struct (rt, rb, rb)
    | _ -> raise InvalidOperandException
  let whole opr =
    let struct (high, low) = wordsOf bld opr
    save bld (AST.concat high low)
  let a, b = whole ra, whole rb
  let results =
    views vector f a b |> List.map (fun (high, a, b) ->
      let b = if name = "efscfd" then whole rb else b
      high, execute bld f fscr name operation a b)
  let suppressed = applyStatus bld fscr results
  let value =
    match results with
    | [ _, high; _, low ] -> AST.concat high.Value low.Value
    | [ _, result ] -> result.Value
    | _ -> raise InvalidOperandException
  if Expr.typeOf value = 64<rt> then
    let chosen = save bld (AST.ite suppressed (whole target) value)
    putWords bld target (AST.xthi 32<rt> chosen) (AST.xtlo 32<rt> chosen)
  else
    let struct (_, old) = wordsOf bld target
    putLow bld target (AST.ite suppressed old value)

/// The sign forms keep their original dispatch; every other embedded
/// floating-point mnemonic is described by its precision and operation.
let translate (ins: Instruction) bld =
  let name = ins.Opcode.ToString().ToLowerInvariant()
  let vector = name.StartsWith "evfs"
  let f = if name.StartsWith "efd" then double else single
  let start = if vector then 4 else 3
  let operation = name[start..]
  lift bld ins {
    let fscr = save bld (regVar bld Register.SPEFSCR)
    if operation.StartsWith "cmp" || operation.StartsWith "tst" then
      compare ins bld vector f fscr operation
    else
      arithmetic ins bld vector f fscr name operation
  }
