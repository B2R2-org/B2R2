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

/// The vector facility's integer arithmetic, lifted element by element.
module internal B2R2.FrontEnd.PPC.VectorIntegerLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements

/// What a pack does with an element too wide for the half-width one it
/// becomes: keep its low half, or clamp it to the range of a signed or an
/// unsigned element.
type PackKind =
  | Modulo
  | Saturate of signedResult: bool

/// The packs, which narrow the elements of vA followed by those of vB to half
/// their width. A saturating pack reads its sources as signed or unsigned and
/// clamps to the range of the result's kind, setting VSCR[SAT] where it had
/// to.
let vecPackElements ins bld esize signedSource kind =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let src = Array.append (elementsOf bld esize o2) (elementsOf bld esize o3)
    let half = regTypeOf (int esize / 2)
    let wide = regTypeOf (int esize * 2)
    match kind with
    | Modulo ->
      putElements bld o1 (Array.map (AST.xtlo half) src)
    | Saturate signedResult ->
      src
      |> Array.map (fun e ->
        saturate half signedResult (widen signedSource wide e))
      |> putSaturated bld o1
  }

/// The signedness a multiply-sum reads its three sources with.
type SumSigns =
  { A: bool
    B: bool
    C: bool }

/// Every source unsigned.
let unsignedSums = { A = false; B = false; C = false }

/// Every source signed.
let signedSums = { A = true; B = true; C = true }

/// vmsummbm's mix: signed bytes of vA times unsigned bytes of vB, added to a
/// signed word.
let mixedSums = { A = true; B = false; C = true }

/// The exact sums of a multiply-sum, at twice the width of its result
/// elements: for each element of vC, the products of the narrower elements of
/// vA and vB that lie within it, added to it.
let private multiplySums bld esize rsize signs (o2, o3, o4) =
  let a = elementsOf bld esize o2
  let b = elementsOf bld esize o3
  let c = elementsOf bld rsize o4
  let wide = regTypeOf (int rsize * 2)
  let per = int rsize / int esize
  Array.init c.Length (fun i ->
    Array.init per (fun j ->
      let k = i * per + j
      widen signs.A wide a[k] .* widen signs.B wide b[k])
    |> Array.fold (.+) (widen signs.C wide c[i]))

/// The multiply-sums and vmladduhm, each element of vD the low half of its
/// exact sum or that sum clamped to the element's range.
let vecMultiplySum ins bld esize rsize signs kind =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let sums = multiplySums bld esize rsize signs (o2, o3, o4)
    match kind with
    | Modulo ->
      putElements bld o1 (Array.map (AST.xtlo rsize) sums)
    | Saturate signedResult ->
      putSaturated bld o1 (Array.map (saturate rsize signedResult) sums)
  }

/// vmsumcud, the carry out of the 128 bits vmsumudm keeps: what its exact sum
/// holds above them.
let vmsumcud ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let sums = multiplySums bld 64<rt> 128<rt> unsignedSums (o2, o3, o4)
    putElements bld o1 (Array.map (AST.xthi 128<rt>) sums)
  }

/// vmhaddshs/vmhraddshs: each signed halfword product of vA and vB shifted
/// right fifteen bits -- after adding half of the bit shifted out first, for
/// the rounding form -- added to the matching halfword of vC and clamped to a
/// signed halfword.
let vecMultiplyHighAdd ins bld round =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let a = elementsOf bld 16<rt> o2
    let b = elementsOf bld 16<rt> o3
    let c = elementsOf bld 16<rt> o4
    let bias = numI32 (if round then 0x4000 else 0) 32<rt>
    Array.init 8 (fun i ->
      let product = AST.sext 32<rt> a[i] .* AST.sext 32<rt> b[i]
      ((product .+ bias) ?>> numI32 15 32<rt>) .+ AST.sext 32<rt> c[i]
      |> saturate 16<rt> true)
    |> putSaturated bld o1
  }

/// vpkpx, which packs each word of vA followed by vB, read as a pixel of four
/// bytes, into a halfword: the lowest bit of its first byte and the top five
/// bits of each of the other three.
let vpkpx ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let words =
      Array.append (elementsOf bld 32<rt> o2) (elementsOf bld 32<rt> o3)
    words
    |> Array.map (fun w ->
      concatElements
        [| AST.extract w 1<rt> 24
           AST.extract w 5<rt> 19
           AST.extract w 5<rt> 11
           AST.extract w 5<rt> 3 |])
    |> putElements bld o1
  }

/// vupkhpx/vupklpx, which unpack the high or the low four halfwords of vB,
/// each a pixel of a bit and three five-bit fields, into words: the bit
/// sign-extended to a byte, and each field zero-extended to one.
let vecUnpackPixel ins bld high =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let h = elementsOf bld 16<rt> o2
    let first = if high then 0 else 4
    Array.init 4 (fun i ->
      let p = h[first + i]
      concatElements
        [| AST.sext 8<rt> (AST.extract p 1<rt> 15)
           AST.zext 8<rt> (AST.extract p 5<rt> 10)
           AST.zext 8<rt> (AST.extract p 5<rt> 5)
           AST.zext 8<rt> (AST.extract p 5<rt> 0) |])
    |> putElements bld o1
  }

/// vmule*/vmulo*, which multiply the even (0, 2, ...) or the odd elements of
/// vA and vB into products twice as wide, which fill vD.
let vecMulEvenOdd ins bld esize signed even =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    let wide = regTypeOf (int esize * 2)
    let pick = if even then 0 else 1
    let product i =
      widen signed wide a[2 * i + pick] .* widen signed wide b[2 * i + pick]
    putElements bld o1 (Array.init (a.Length / 2) product)
  }

/// The operands of a quadword add: vD, vA and vB, whether or not a vC follows.
let private quadAddOperands (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) | FourOperands(o1, o2, o3, _) ->
    struct (o1, o2, o3)
  | _ ->
    raise InvalidOperandException

/// The carry into a quadword add: the lowest bit of vC for the extended forms,
/// the only ones with a vC, and otherwise 1 for a subtract and 0 for an add.
let private quadCarryIn bld (ins: Instruction) subtract =
  match ins.Operands with
  | FourOperands(_, _, _, o4) ->
    let struct (_, cl) = halvesOf bld o4
    AST.zext 128<rt> (AST.xtlo 1<rt> cl)
  | _ ->
    if subtract then AST.num1 128<rt> else AST.num0 128<rt>

/// The quadword adds and subtracts. A subtract adds the complement of vB and a
/// carry in of 1; the extended forms take their carry in from the lowest bit
/// of vC instead. The carry forms write the carry out of that sum -- out of
/// either of its two additions -- rather than the sum itself.
let vecQuadAdd ins bld subtract carryOut =
  lift bld ins {
    let struct (o1, o2, o3) = quadAddOperands ins
    let b = quadOf bld o3
    let struct (a, sum, total) = tmpVars3 bld 128<rt>
    a := quadOf bld o2
    sum := a .+ (if subtract then AST.not b else b)
    total := sum .+ quadCarryIn bld ins subtract
    if carryOut then
      putElements bld o1 [| AST.zext 128<rt> ((sum .< a) .| (total .< sum)) |]
    else
      putElements bld o1 [| total |]
  }

/// An element-wise "vD, vA, vB": each element of vD is f of the matching
/// elements of vA and vB.
let vecMap2 ins bld esize f =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    putElements bld o1 (Array.map2 f a b)
  }

/// The saturating adds and subtracts: the sum or the difference of each pair
/// of elements, computed exactly at twice the width and clamped to the
/// element's range, which sets VSCR[SAT] where it had to be.
let vecSaturating ins bld esize signed isAdd =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let wide = regTypeOf (int esize * 2)
    let f a b =
      let a = widen signed wide a
      let b = widen signed wide b
      saturate esize signed (if isAdd then a .+ b else a .- b)
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    putSaturated bld o1 (Array.map2 f a b)
  }

/// vaddcuw, the carry out of each unsigned word sum.
let vaddcuw ins bld =
  vecMap2 ins bld 32<rt> (fun a b -> AST.zext 32<rt> ((a .+ b) .< a))

/// vsubcuw, the carry out of each word of vA + ~vB + 1, which is set exactly
/// where vA is not below vB.
let vsubcuw ins bld =
  vecMap2 ins bld 32<rt> (fun a b -> AST.zext 32<rt> (a .>= b))

/// vavg*, the average of each pair of elements rounded up: (a + b + 1) / 2,
/// computed at twice the width so that the sum cannot overflow. The low bits of
/// the shifted sum are the same whether the shift brings in a sign or a zero.
let vecAverage ins bld esize signed =
  let wide = regTypeOf (int esize * 2)
  vecMap2 ins bld esize (fun a b ->
    let sum = widen signed wide a .+ widen signed wide b .+ AST.num1 wide
    AST.xtlo esize (sum >> AST.num1 wide))

/// vabsdu*, the absolute difference of each pair of unsigned elements.
let vecAbsoluteDifference ins bld esize =
  vecMap2 ins bld esize (fun a b -> AST.ite (a .> b) (a .- b) (b .- a))

/// The all-ones or all-zeros element a compare writes for one outcome.
let private maskOf esize cond =
  AST.ite cond (AST.not (AST.num0 esize)) (AST.num0 esize)

/// Sets CR6 from the outcomes of a recording compare, held in temporaries:
/// its first bit says every element compared true, its third that none did;
/// the other two are cleared.
let private setCR6 (bld: ILowUIRBuilder) (flags: Expr[]) =
  append bld {
    regVar bld Register.CR6_0 := Array.reduce (.&) flags
    regVar bld Register.CR6_1 := AST.b0
    regVar bld Register.CR6_2 := Array.reduce (.&) (Array.map AST.not flags)
    regVar bld Register.CR6_3 := AST.b0
  }

/// A vector compare that sets each element of vD to all ones where rel holds of
/// the matching elements of vA and vB and to all zeros where it does not; the
/// record form also reports in CR6. Each outcome is held before the target is
/// written, as the target may be a source.
let vecCompareElements ins bld esize rel record =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    let flags = Array.init a.Length (fun _ -> tmpVar bld 1<rt>)
    for i in 0 .. a.Length - 1 do flags[i] := rel a[i] b[i]
    putElements bld o1 (Array.map (maskOf esize) flags)
    if record then setCR6 bld flags else ()
  }

/// vcmpsq/vcmpuq, which compare two quadwords and set a CR field to less
/// than, greater than and equal, its fourth bit cleared.
let vecCompareQuadToCR ins bld signed =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let lt, gt, eq, so =
      match o1 with
      | OprReg reg -> transCRxToExpr bld reg
      | _ -> raise InvalidOperandException
    let struct (a, b) = tmpVars2 bld 128<rt>
    a := quadOf bld o2
    b := quadOf bld o3
    lt := if signed then a ?< b else a .< b
    gt := if signed then a ?> b else a .> b
    eq := a == b
    so := AST.b0
  }

/// Whether two elements differ or either of them is zero, which is what the
/// vcmpnez* compares test so that a string's end stops a search too.
let notEqualOrZero esize a b =
  let zero = AST.num0 esize
  (a != b) .| (a == zero) .| (b == zero)

/// vmulh*: the high half of each product of the elements of vA and vB, formed
/// exactly at twice their width.
let vecMulHigh ins bld esize signed =
  let wide = regTypeOf (int esize * 2)
  vecMap2 ins bld esize (fun a b ->
    AST.xthi esize (widen signed wide a .* widen signed wide b))

/// vmulld, the low doubleword of each product of the doublewords of vA and vB.
let vmulld ins bld = vecMap2 ins bld 64<rt> (.*)

/// maddhd/maddhdu/maddld rD, rA, rB, rC: the 128-bit product of rA and rB plus
/// rC, all read as signed or as unsigned numbers, and its high or its low
/// doubleword -- the low one being the same either way.
let multiplyAddDoubleword ins bld signed high =
  lift bld ins {
    let struct (rt, ra, rb, rc) = transFourOprs ins bld
    let sum =
      widen signed 128<rt> ra .* widen signed 128<rt> rb
      .+ widen signed 128<rt> rc
    rt := if high then AST.xthi 64<rt> sum else AST.xtlo 64<rt> sum
  }

/// What a vector divide writes: the quotient, the quotient of the dividend
/// shifted up by the element's width first, or the remainder.
type DivideKind =
  | Quotient
  | ExtendedQuotient
  | Remainder

/// The divides and the remainders, each element divided at twice its width
/// and the answer cut back to it. A zero divisor leaves the answer undefined,
/// as does a quotient that does not fit; the divide is made with a divisor of
/// one there so that it cannot fault, and the element is written as QEMU
/// writes it: the dividend's element for a quotient, zero for a remainder.
let vecDivide ins bld esize signed kind =
  let n = int esize
  let wide = regTypeOf (2 * n)
  vecMap2 ins bld esize (fun a b ->
    let dividend = widen signed wide a
    let dividend =
      if kind = ExtendedQuotient then dividend << numI32 n wide else dividend
    let divisor = widen signed wide b
    let zero = divisor == AST.num0 wide
    let safe = AST.ite zero (AST.num1 wide) divisor
    let answer =
      match kind, signed with
      | Remainder, true -> dividend ?% safe
      | Remainder, false -> dividend .% safe
      | _, true -> dividend ?/ safe
      | _, false -> dividend ./ safe
    let undefined = if kind = Remainder then AST.num0 esize else a
    AST.ite zero undefined (AST.xtlo esize answer))
