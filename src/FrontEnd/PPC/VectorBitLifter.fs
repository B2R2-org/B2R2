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

/// The vector facility's bit-level instructions: the counts, the parities,
/// the rotates and shifts, and the gathers and scatters of bits, lifted
/// element by element.
module internal B2R2.FrontEnd.PPC.VectorBitLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements
open B2R2.FrontEnd.PPC.VectorLifter
open B2R2.FrontEnd.PPC.VectorIntegerLifter

/// An element-wise "vD, vB": each element of vD is f of the matching element
/// of vB.
let vecMap1 ins bld esize f =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    putElements bld o1 (Array.map f (elementsOf bld esize o2))
  }

/// vctz*, the trailing zeros of each element: the set bits of the mask below
/// its lowest set bit, which is every bit for a zero element.
let vecCountTrailingZeros ins bld esize =
  vecMap1 ins bld esize (fun x ->
    popCountOf esize (AST.not x .& (x .- AST.num1 esize)))

/// vclzlsbb/vctzlsbb rD, vB: how many bytes of vB, from byte 0 or from byte
/// 15, have their lowest bit clear before the first that has it set.
let vecCountLsbZeroBytes ins (bld: ILowUIRBuilder) leading =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let rt = transOpr bld o1
    let bytes = elementsOf bld 8<rt> o2
    let order = if leading then bytes else Array.rev bytes
    let pick (i, b) acc =
      AST.ite (AST.xtlo 1<rt> b) (numI32 i bld.RegType) acc
    let none = numI32 16 bld.RegType
    rt := Array.foldBack pick (Array.indexed order) none
  }

/// vprtyb*, the parity of the lowest bits of the bytes of each element.
let vecParity ins bld esize =
  vecMap1 ins bld esize (fun x ->
    Array.init (int esize / 8) (fun j -> AST.extract x 1<rt> (8 * j))
    |> Array.reduce (<+>)
    |> AST.zext esize)

/// vextsb2w and the rest, which sign-extend the low byte, halfword, word or
/// doubleword of each element to the whole of it.
let vecSignExtend ins bld esize (from: RegType) =
  vecMap1 ins bld esize (fun x -> AST.sext esize (AST.xtlo from x))

/// The rotate left of an element by a run-time count. A zero count leaves the
/// element alone whichever way a shift by the whole width goes: the two halves
/// are then the element and either zero or the element again.
let private rotl esize (x: Expr) (n: Expr) =
  (x << n) .| (x >> (numI32 (int esize) esize .- n))

/// MASK(b, e) of an element: ones from bit b through bit e, counted from the
/// most significant end, wrapping round when b is past e.
let private maskFromTo esize b e =
  let ones = AST.not (AST.num0 esize)
  let fromB = ones >> b
  let toE = ones << (numI32 (int esize - 1) esize .- e)
  AST.ite (b .<= e) (fromB .& toE) (fromB .| toE)

/// The mask's first and last bits and the rotate count of a rotate-and-mask
/// element: three fields of the matching element of vB, eight bits apart and
/// as wide as a bit number of the element -- for the quadword, in vB's high
/// doubleword.
let private rotateFields esize (src: Expr) =
  let width = regTypeOf (System.Numerics.BitOperations.Log2(uint32 esize))
  let at = if int esize = 128 then 64 else 0
  let field pos = AST.zext esize (AST.extract src width (at + pos))
  struct (field 16, field 8, field 0)

/// vrlwnm/vrldnm/vrlqnm and vrlwmi/vrldmi/vrlqmi: each element of vA rotated
/// left by the count its element of vB gives, then kept under the mask that
/// element also gives -- ANDed with it, or inserted into vD through it.
let vecRotateMask ins bld esize insert =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    let t = elementsOf bld esize o1
    Array.init a.Length (fun i ->
      let struct (mb, me, n) = rotateFields esize b[i]
      let r = rotl esize a[i] n
      let m = maskFromTo esize mb me
      if insert then (r .& m) .| (t[i] .& AST.not m) else r .& m)
    |> putElements bld o1
  }

/// What a quadword shift does with the count in bits 57:63 of vB.
type QuadShift =
  | ShiftLeft
  | ShiftRight
  | ShiftRightAlgebraic
  | RotateLeft

/// vslq/vsrq/vsraq/vrlq: vA as one quadword, shifted or rotated by the count
/// in bits 57:63 of vB.
let vecShiftQuad ins bld kind =
  vecMap2 ins bld 128<rt> (fun a b ->
    let n = AST.zext 128<rt> (AST.extract b 7<rt> 64)
    match kind with
    | ShiftLeft -> a << n
    | ShiftRight -> a >> n
    | ShiftRightAlgebraic -> a ?>> n
    | RotateLeft -> rotl 128<rt> a n)

/// vslv/vsrv: each byte of vA shifted left or right by the low three bits of
/// the matching byte of vB, the bits shifted in coming from the next or the
/// previous byte of vA, and a zero byte beyond either end.
let vecShiftVariable ins bld left =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld 8<rt> o2
    let b = elementsOf bld 8<rt> o3
    let byteAt i = if i >= 0 && i < 16 then a[i] else AST.num0 8<rt>
    Array.init 16 (fun i ->
      let sh = AST.zext 16<rt> (AST.xtlo 3<rt> b[i])
      if left then AST.xthi 8<rt> (AST.concat a[i] (byteAt (i + 1)) << sh)
      else AST.xtlo 8<rt> (AST.concat (byteAt (i - 1)) a[i] >> sh))
    |> putElements bld o1
  }

/// vsldbi/vsrdbi: the 128 bits of vA || vB that start SH bits in from its left
/// end, or that end SH bits in from its right one.
let vecShiftDoubleBits ins bld left =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let sh = int (getImmValue o4)
    let both = AST.concat (quadOf bld o2) (quadOf bld o3)
    let pos = if left then 128 - sh else sh
    putElements bld o1 [| AST.extract both 128<rt> pos |]
  }

/// vgnb rD, vB, N: every Nth bit of vB from bit 0 on, concatenated from the
/// left of rD; the bits below them are cleared.
let vgnb ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rt = transOpr bld o1
    let n = int (getImmValue o3)
    let q = quadOf bld o2
    let picked = [| for i in 0 .. n .. 127 -> AST.extract q 1<rt> (127 - i) |]
    let value = AST.zext 64<rt> (concatElements picked)
    rt := value << numI32 (64 - picked.Length) 64<rt>
  }

/// vbpermd: for each doubleword, the bits of vA that the eight bytes of the
/// matching doubleword of vB index -- from the most significant end, an index
/// past 63 giving a zero -- in its low byte, the first index's bit the top
/// one; the rest of the doubleword is cleared.
let vbpermd ins bld =
  vecMap2 ins bld 64<rt> (fun a b ->
    Array.init 8 (fun j ->
      let index = AST.zext 64<rt> (AST.extract b 8<rt> (56 - 8 * j))
      let bit = AST.xtlo 1<rt> (a >> (numI32 63 64<rt> .- index))
      AST.ite (index .< numI32 64 64<rt>) bit AST.b0)
    |> concatElements
    |> AST.zext 64<rt>)

/// The bits of a that the set bits of m pick, packed into the low end of a
/// doubleword in their order: the parallel extract, one step per bit of m.
let private parallelExtract (bld: ILowUIRBuilder) (a: Expr) (m: Expr) =
  let struct (r, k) = tmpVars2 bld 64<rt>
  append bld {
    r := AST.num0 64<rt>
    k := AST.num0 64<rt>
    for j in 0 .. 63 do
      let pick = AST.extract m 1<rt> j
      r := r .| (AST.zext 64<rt> (pick .& AST.extract a 1<rt> j) << k)
      k := k .+ AST.zext 64<rt> pick
  }
  struct (r, k)

/// The low bits of a spread to the set bits of m in their order, the other
/// bits cleared: the parallel deposit.
let private parallelDeposit (bld: ILowUIRBuilder) (a: Expr) (m: Expr) =
  let struct (r, k) = tmpVars2 bld 64<rt>
  append bld {
    r := AST.num0 64<rt>
    k := AST.num0 64<rt>
    for j in 0 .. 63 do
      let pick = AST.extract m 1<rt> j
      let bit = AST.xtlo 1<rt> (a >> k)
      r := r .| (AST.zext 64<rt> (pick .& bit) << numI32 j 64<rt>)
      k := k .+ AST.zext 64<rt> pick
  }
  r

/// What vcfuged, vpdepd, vpextd, vclzdm and vctzdm compute of a doubleword of
/// vA under the mask in the matching doubleword of vB.
type MaskedBits =
  | Centrifuge
  | Deposit
  | Extract
  | LeadingZeros
  | TrailingZeros

/// One doubleword of a masked-bits instruction. A count under the mask is a
/// count of the extracted bits: the leading zeros of the field of as many bits
/// as the mask has set, or its trailing zeros, which are all of it where it
/// is zero.
let private maskedBits bld kind a m =
  match kind with
  | Deposit ->
    parallelDeposit bld a m
  | Extract ->
    let struct (r, _) = parallelExtract bld a m
    r
  | Centrifuge ->
    let struct (right, n) = parallelExtract bld a m
    let struct (left, _) = parallelExtract bld a (AST.not m)
    (left << n) .| right
  | LeadingZeros ->
    let struct (r, n) = parallelExtract bld a m
    countLeadingZerosOf 64<rt> r .- (numI32 64 64<rt> .- n)
  | TrailingZeros ->
    let struct (r, n) = parallelExtract bld a m
    let below = AST.not r .& (r .- AST.num1 64<rt>)
    AST.ite (r == AST.num0 64<rt>) n (popCountOf 64<rt> below)

/// vcfuged/vpdepd/vpextd/vclzdm/vctzdm vD, vA, vB, doubleword by doubleword.
let vecMaskedBits ins bld kind =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld 64<rt> o2
    let m = elementsOf bld 64<rt> o3
    let results = Array.init 2 (fun i -> maskedBits bld kind a[i] m[i])
    let held = Array.init 2 (fun _ -> tmpVar bld 64<rt>)
    for i in 0 .. 1 do held[i] := results[i]
    putElements bld o1 held
  }
