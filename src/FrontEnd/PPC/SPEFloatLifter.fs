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

module internal B2R2.FrontEnd.PPC.SPEFloatLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.SPELifter

(*
  Shared representation and rounding for the embedded floating-point
  categories of Power ISA 2.07B, Chapter 9 and Appendix D.
*)
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

(*
  Integer-significand arithmetic for the embedded floating-point categories.
*)
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

(*
  The embedded floating-point categories of the Signal Processing Engine's
  processors, which keep floating-point numbers in the general registers: a
  single in a word (the scalar ones in the low word of the register, the
  vector ones in both words) and a double in the whole register. They do not
  follow IEEE 754 to the letter: an infinity, a NaN or a denormalized number
  is not an operand but an input error, which has a default result of its
  own, and a result that overflows or underflows is the largest number or a
  zero, never an infinity or a denormalized number. SPEFSCR records what
  each element found.
*)
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
    else rounded bld fscr truncated guard sticky
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
    compute bld f fscr operation a b
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
