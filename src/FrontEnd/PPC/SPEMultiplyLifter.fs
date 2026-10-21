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
/// The multiplies and the accumulator forms of the Signal Processing Engine.
/// A multiply takes the halfwords or the words of its two sources, forms the
/// product as an integer or a fraction -- a fraction is the product shifted
/// left a bit, so that -1.0 times -1.0 is +1.0 once it has room -- and puts it
/// in RT, in the accumulator too where the mnemonic says so, or adds it to or
/// subtracts it from the accumulator first. A saturating form clamps what it
/// adds and reports it in SPEFSCR: OV and OVH say that the low or the high
/// element overflowed, SOV and SOVH keep it.
/// </summary>
module internal B2R2.FrontEnd.PPC.SPEMultiplyLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.SPELifter

/// Which halfword of a word a multiply takes.
type HalfSelect =
  | Even
  | Odd

/// How a source is read.
type Sign =
  | Signed
  | Unsigned

/// Whether a product is an integer or a fraction.
type Product =
  | Integer
  | Fractional

/// Whether what is added wraps or is clamped.
type Overflow =
  | Wrap
  | Clamp

/// What a multiply does with its product.
type Accumulate =
  /// Writes RT only.
  | Plain
  /// Writes RT and the accumulator.
  | ToAccumulator
  /// Adds each element to the matching word of the accumulator.
  | AddWords
  /// Subtracts each element from the matching word of the accumulator.
  | SubtractWords
  /// Adds the product to the whole accumulator.
  | AddWhole
  /// Subtracts the product from the whole accumulator.
  | SubtractWhole

/// The bit of SPEFSCR that holds the status named, counted from the least
/// significant bit of the 32 the register has.
let private sovhBit = 31

let private ovhBit = 30

let private sovBit = 15

let private ovBit = 14

let private num32 (v: uint32) = numU32 v 32<rt>

/// Sets SPEFSCR[OVH] and [OV] to what a word found, and ORs it into the
/// sticky SOVH and SOV; a form that reports one element leaves the other
/// alone by passing its current value.
let private setOverflow (bld: ILowUIRBuilder) (ovh: Expr) (ovl: Expr) =
  let fscr = regVar bld Register.SPEFSCR
  let bit n = AST.extract fscr 1<rt> n
  let struct (sovh, sov) = tmpVars2 bld 1<rt>
  append bld {
    sovh := bit sovhBit .| ovh
    sov := bit sovBit .| ovl
    bit ovhBit := ovh
    bit ovBit := ovl
    bit sovhBit := sovh
    bit sovBit := sov
  }

/// Writes the two words of RT, the accumulator where the instruction says so
/// and, where there are any, the overflow flags the words were computed with.
/// Everything is held in temporaries first, so that a source that is also RT,
/// or the accumulator that is read to compute a word, is read throughout.
let private commit (bld: ILowUIRBuilder) rt hi lo toAcc flags =
  let struct (th, tl) = tmpVars2 bld 32<rt>
  let struct (oh, ol) = tmpVars2 bld 1<rt>
  append bld {
    th := hi
    tl := lo
  }
  match flags with
  | Some(struct (h: Expr, l: Expr)) ->
    append bld {
      oh := h
      ol := l
    }
  | None ->
    ()
  putWords bld rt th tl
  if toAcc then
    append bld { regVar bld Register.ACC := AST.concat th tl }
  else
    ()
  match flags with
  | Some _ -> setOverflow bld oh ol
  | None -> ()

/// The product of two halfwords as a 32-bit value, and whether it is the one
/// product -1.0 times -1.0, which a saturating fractional multiply gives the
/// largest positive fraction instead.
let private halfProduct sign kind saturates (a: Expr) (b: Expr) =
  let widen (x: Expr) =
    match sign with
    | Signed -> AST.sext 32<rt> x
    | Unsigned -> AST.zext 32<rt> x
  let exact = widen a .* widen b
  let value =
    match kind with
    | Integer -> exact
    | Fractional -> exact << numI32 1 32<rt>
  if saturates then
    let minusOne = numU32 0x8000u 16<rt>
    let both = (a == minusOne) .& (b == minusOne)
    struct (AST.ite both (num32 0x7fffffffu) value, both)
  else
    struct (value, AST.b0)

/// One word of an accumulate that works on words: the accumulator word plus
/// or minus an element, wrapping or clamped to the range of the kind of
/// number, and whether it overflowed.
let private sumWord (bld: ILowUIRBuilder) sign saturation subtract acc prod =
  match saturation with
  | Wrap ->
    struct ((if subtract then acc .- prod else acc .+ prod), AST.b0)
  | Clamp ->
    let widen (x: Expr) =
      match sign with
      | Signed -> AST.sext 64<rt> x
      | Unsigned -> AST.zext 64<rt> x
    let t = tmpVar bld 64<rt>
    let a, p = widen acc, widen prod
    let sum = if subtract then a .- p else a .+ p
    append bld { t := sum }
    let bit n = AST.extract t 1<rt> n
    let low = AST.xtlo 32<rt> t
    match sign with
    | Signed ->
      let ov = bit 32 <+> bit 31
      let limit = AST.ite (bit 32) (num32 0x80000000u) (num32 0x7fffffffu)
      struct (AST.ite ov limit low, ov)
    | Unsigned ->
      let limit = if subtract then num32 0u else num32 0xffffffffu
      struct (AST.ite (bit 32) limit low, bit 32)

/// The halfword of a word a multiply takes.
let private halfOf half (word: Expr) =
  match half with
  | Even -> AST.xthi 16<rt> word
  | Odd -> AST.xtlo 16<rt> word

/// The accumulator's two words.
let private accumulatorWords (bld: ILowUIRBuilder) =
  let acc = regVar bld Register.ACC
  struct (AST.xthi 32<rt> acc, AST.xtlo 32<rt> acc)

/// Whether a form tests and reports the overflow of its words.
let private reports saturation = saturation = Clamp

/// How a pair of words, each an element of a multiply, is put to RT: the
/// product alone, or summed with the accumulator word.
let private finish bld sign saturation accumulate flagged element acc =
  let struct (value, special) = element
  match accumulate with
  | Plain | ToAccumulator ->
    struct (value, special)
  | _ ->
    let subtract = accumulate = SubtractWords
    let struct (sum, ov) = sumWord bld sign saturation subtract acc value
    struct (sum, if flagged then ov .| special else ov)

/// The multiplies of the halfwords of two words into words, with or without
/// the accumulator: evmhesmf, evmhossfaaw, evmheumianw and the rest.
let evmh ins bld half sign saturation kind accumulate =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    let struct (acch, accl) = accumulatorWords bld
    let saturates = reports saturation && kind = Fractional
    let element a b acc =
      let p = halfProduct sign kind saturates (halfOf half a) (halfOf half b)
      finish bld sign saturation accumulate (reports saturation) p acc
    let struct (hi, ovh) = element ah bh acch
    let struct (lo, ovl) = element al bl accl
    let flags = if reports saturation then Some(struct (ovh, ovl)) else None
    commit bld rt hi lo (accumulate <> Plain) flags
  }

/// The guarded multiplies of the low word's even or odd halfwords, whose
/// 64-bit product is added to or subtracted from the whole accumulator.
let evmhGuarded ins bld half sign kind accumulate =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (_, al) = wordsOf bld ra
    let struct (_, bl) = wordsOf bld rb
    let widen (x: Expr) =
      match sign with
      | Signed -> AST.sext 64<rt> x
      | Unsigned -> AST.zext 64<rt> x
    let exact = widen (halfOf half al) .* widen (halfOf half bl)
    let product =
      match kind with
      | Integer -> exact
      | Fractional -> exact << numI32 1 64<rt>
    let acc = regVar bld Register.ACC
    let subtract = accumulate = SubtractWhole
    let sum = if subtract then acc .- product else acc .+ product
    let result = tmpVar bld 64<rt>
    append bld { result := sum }
    commit bld rt (AST.xthi 32<rt> result) (AST.xtlo 32<rt> result) true None
  }

/// Which word of the 64-bit product of two words a multiply keeps.
type WordPart =
  | High
  | Low

/// The 64-bit product of two words.
let private wordProduct sign kind (a: Expr) (b: Expr) =
  let widen (x: Expr) =
    match sign with
    | Signed -> AST.sext 64<rt> x
    | Unsigned -> AST.zext 64<rt> x
  let exact = widen a .* widen b
  match kind with
  | Integer -> exact
  | Fractional -> exact << numI32 1 64<rt>

/// Whether both words are the most negative fraction, which a saturating
/// fractional multiply turns into the largest positive one.
let private bothMostNegative (a: Expr) (b: Expr) =
  let minusOne = num32 0x80000000u
  (a == minusOne) .& (b == minusOne)

/// The multiplies of each pair of words that keep the high or the low word of
/// the product: evmwhsmf, evmwhssfa, evmwlumiaaw, evmwlssianw and the rest.
let evmwPart ins bld part sign saturation kind accumulate =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (ah, al) = wordsOf bld ra
    let struct (bh, bl) = wordsOf bld rb
    let struct (acch, accl) = accumulatorWords bld
    let saturates = reports saturation && kind = Fractional
    let element a b acc =
      let p = wordProduct sign kind a b
      let value = if part = High then AST.xthi 32<rt> p else AST.xtlo 32<rt> p
      let special = bothMostNegative a b
      let shown = if saturates && part = High then special else AST.b0
      let chosen = AST.ite shown (num32 0x7fffffffu) value
      let flagged = reports saturation
      finish bld sign saturation accumulate flagged (struct (chosen, shown)) acc
    let struct (hi, ovh) = element ah bh acch
    let struct (lo, ovl) = element al bl accl
    let flags = if reports saturation then Some(struct (ovh, ovl)) else None
    commit bld rt hi lo (accumulate <> Plain) flags
  }

/// The multiplies of the low words, whose 64-bit product goes to RT whole,
/// into the accumulator too, or added to or subtracted from it: evmwsmi,
/// evmwumia, evmwsmfaa, evmwssfan and the rest.
let evmwWhole ins bld sign saturation kind accumulate =
  lift bld ins {
    let struct (rt, ra, rb) = getThreeOprs ins
    let struct (_, al) = wordsOf bld ra
    let struct (_, bl) = wordsOf bld rb
    let acc = regVar bld Register.ACC
    let saturates = reports saturation && kind = Fractional
    let special = bothMostNegative al bl
    let product = wordProduct sign kind al bl
    let most = numU64 0x7fffffffffffffffUL 64<rt>
    let p = tmpVar bld 64<rt>
    let mov = tmpVar bld 1<rt>
    append bld {
      p := if saturates then AST.ite special most product else product
      mov := if saturates then special else AST.b0
    }
    let sums = accumulate = AddWhole || accumulate = SubtractWhole
    let wide (x: Expr) = AST.sext 128<rt> x
    let t = tmpVar bld 128<rt>
    let ov = tmpVar bld 1<rt>
    let result = tmpVar bld 64<rt>
    let a, b = wide acc, wide p
    let total = if accumulate = SubtractWhole then a .- b else a .+ b
    let carried = AST.extract t 1<rt> 64 <+> AST.extract t 1<rt> 63
    append bld {
      t := total
      ov := if saturates && sums then carried else AST.b0
      result := if sums then AST.xtlo 64<rt> t else p
    }
    let hi = AST.xthi 32<rt> result
    let lo = AST.xtlo 32<rt> result
    let zero = AST.b0
    let flags = if saturates then Some(struct (zero, ov .| mov)) else None
    commit bld rt hi lo (accumulate <> Plain) flags
  }
