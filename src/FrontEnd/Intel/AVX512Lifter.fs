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

/// The AVX-512 instructions that no earlier extension has a form of: the ones
/// EVEX introduced rather than the ones it merely widened. What they share is
/// the decoration -- a write mask, an optional embedded broadcast, and a
/// vector length of 128, 256 or 512 bits chosen by the same encoding -- so the
/// builders at the top of this file carry it once and each instruction below
/// says only what one lane computes.
module internal B2R2.FrontEnd.Intel.AVX512Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils
open B2R2.FrontEnd.Intel.MMXLifter

/// A three-operand operation over packed lanes, written under the EVEX write
/// mask. An embedded broadcast needs nothing here: transOprToArr has already
/// given every lane of the source the one element the encoding named.
let private packedBinOp ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let s1 = transOprToArr ins bld false packSz packNum oprSz src1
    let s2 = transOprToArr ins bld false packSz packNum oprSz src2
    assignEVEXPacked ins bld packSz oprSz dst (Array.map2 opFn s1 s2)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// A two-operand operation over packed lanes, written under the write mask.
let private packedUnOp ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld false packSz packNum oprSz src
    assignEVEXPacked ins bld packSz oprSz dst (Array.map opFn s)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// A two-operand operation carrying an immediate every lane reads the same
/// way, written under the write mask.
let private packedImmOp ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src, imm) = getThreeOprs ins
    let s = transOprToArr ins bld false packSz packNum oprSz src
    let imm = getImmValue imm
    assignEVEXPacked ins bld packSz oprSz dst (Array.map (opFn imm) s)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

(* --- the bitwise logic, one width per mask granularity ------------------- *)
let vpandd ins bld = packedBinOp ins bld 32<rt> (.&)

let vpandq ins bld = packedBinOp ins bld 64<rt> (.&)

/// VPANDN complements the operand EVEX.vvvv names, which is the first source
/// written in Intel syntax rather than the one in the ModRM byte.
let private opAndn src1 src2 = AST.not src1 .& src2

let vpandnd ins bld = packedBinOp ins bld 32<rt> opAndn

let vpandnq ins bld = packedBinOp ins bld 64<rt> opAndn

let vpord ins bld = packedBinOp ins bld 32<rt> (.|)

let vporq ins bld = packedBinOp ins bld 64<rt> (.|)

let vpxorq ins bld = packedBinOp ins bld 64<rt> (<+>)

(* --- the arithmetic EVEX added at 64-bit granularity --------------------- *)
/// The absolute value of a signed lane, which for the most negative value is
/// itself: the result wraps rather than saturating.
let private opAbs src = AST.ite (AST.xthi 1<rt> src) (AST.neg src) src

let vpabsq ins bld = packedUnOp ins bld 64<rt> opAbs

let private opMaxs src1 src2 = AST.ite (src1 ?> src2) src1 src2

let private opMaxu src1 src2 = AST.ite (src1 .> src2) src1 src2

let private opMins src1 src2 = AST.ite (src1 ?< src2) src1 src2

let private opMinu src1 src2 = AST.ite (src1 .< src2) src1 src2

let vpmaxsq ins bld = packedBinOp ins bld 64<rt> opMaxs

let vpmaxuq ins bld = packedBinOp ins bld 64<rt> opMaxu

let vpminsq ins bld = packedBinOp ins bld 64<rt> opMins

let vpminuq ins bld = packedBinOp ins bld 64<rt> opMinu

/// VPMULLQ keeps the low 64 bits of the full 128-bit product, which is what a
/// 64-bit multiply in the IR already computes.
let vpmullq ins bld = packedBinOp ins bld 64<rt> (.*)

(* --- rotates and the variable shifts EVEX added --------------------------- *)
/// A count reduced to the lane's width, which every rotate in the set does
/// before it rotates: the low bits of the count are all that is read.
let private rotCount width cnt =
  cnt .& numI32 (RegType.toBitWidth width - 1) width

/// A rotate left. The complementary count is reduced the same way, so a count
/// of zero rotates by nothing rather than shifting the whole lane out.
let private opRotl width x cnt =
  let cnt = rotCount width cnt
  let w = numI32 (RegType.toBitWidth width) width
  (x << cnt) .| (x >> rotCount width (w .- cnt))

let private opRotr width x cnt =
  let cnt = rotCount width cnt
  let w = numI32 (RegType.toBitWidth width) width
  (x >> cnt) .| (x << rotCount width (w .- cnt))

let private rolImm width imm src = opRotl width src (numI64 imm width)

let private rorImm width imm src = opRotr width src (numI64 imm width)

let vprold ins bld = packedImmOp ins bld 32<rt> (rolImm 32<rt>)

let vprolq ins bld = packedImmOp ins bld 64<rt> (rolImm 64<rt>)

let vprord ins bld = packedImmOp ins bld 32<rt> (rorImm 32<rt>)

let vprorq ins bld = packedImmOp ins bld 64<rt> (rorImm 64<rt>)

let vprolvd ins bld = packedBinOp ins bld 32<rt> (opRotl 32<rt>)

let vprolvq ins bld = packedBinOp ins bld 64<rt> (opRotl 64<rt>)

let vprorvd ins bld = packedBinOp ins bld 32<rt> (opRotr 32<rt>)

let vprorvq ins bld = packedBinOp ins bld 64<rt> (opRotr 64<rt>)

/// A per-lane shift whose count comes from a lane of its own: a count that
/// reaches the lane's width shifts everything out, which the IR's own shift
/// does not promise, so the two cases are separated here.
let private opShiftVar width isArith x cnt =
  let w = numI32 (RegType.toBitWidth width) width
  let past =
    if isArith then
      AST.ite (AST.xthi 1<rt> x) (getMask width) (AST.num0 width)
    else
      AST.num0 width
  let shifted = if isArith then x ?>> cnt else x >> cnt
  AST.ite (cnt .< w) shifted past

let vpsravq ins bld = packedBinOp ins bld 64<rt> (opShiftVar 64<rt> true)

let vpsravw ins bld = packedBinOp ins bld 16<rt> (opShiftVar 16<rt> true)

let vpsrlvw ins bld = packedBinOp ins bld 16<rt> (opShiftVar 16<rt> false)

/// A left shift past the lane's width leaves nothing behind either.
let private opShiftLeftVar width x cnt =
  let w = numI32 (RegType.toBitWidth width) width
  AST.ite (cnt .< w) (x << cnt) (AST.num0 width)

let vpsllvw ins bld = packedBinOp ins bld 16<rt> (opShiftLeftVar 16<rt>)

/// VPSRAQ takes its count either from an immediate or from the low 64 bits of
/// an XMM operand, and a count of 64 or more fills every lane with its own
/// sign bit rather than shifting by a count the IR does not define.
let vpsraq (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 64<rt>
    let struct (dst, src1, src2) = getThreeOprs ins
    let s1 = transOprToArr ins bld false packSz 1 oprSz src1
    let cnt =
      match src2 with
      | OprImm _ ->
        numI64 (getImmValue src2) 64<rt>
      | _ ->
        let struct (_, lo) = transOpr128 ins bld false src2
        lo
    let t = tmpVar bld 64<rt>
    direct t := cnt
    let shift e = opShiftVar packSz true e t
    assignEVEXPacked ins bld packSz oprSz dst (Array.map shift s1)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

(* --- the per-bit counts -------------------------------------------------- *)
/// A two-operand operation whose lanes each need statements of their own --
/// a population count builds its result up in a temporary rather than in one
/// expression -- so the builder hands the lane function the IR builder too.
let private packedUnOpWith ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld false packSz packNum oprSz src
    let result = Array.map (opFn bld packSz) s
    assignEVEXPacked ins bld packSz oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let private opPopCount bld packSz src =
  buildPopCount bld packSz (tmpVar bld packSz) src

let vpopcntb ins bld = packedUnOpWith ins bld 8<rt> opPopCount

let vpopcntw ins bld = packedUnOpWith ins bld 16<rt> opPopCount

let vpopcntd ins bld = packedUnOpWith ins bld 32<rt> opPopCount

let vpopcntq ins bld = packedUnOpWith ins bld 64<rt> opPopCount

/// The leading zeros of a lane: smearing the highest set bit down through
/// every bit below it turns the count of leading zeros into the width less
/// the number of bits then set, and a lane of zeros smears to zero, which
/// gives the whole width.
let private opLzCount bld packSz src =
  let smeared = tmpVar bld packSz
  append bld {
    direct smeared := src
  }
  smearHighBit bld packSz smeared
  let ones = buildPopCount bld packSz (tmpVar bld packSz) smeared
  numI32 (RegType.toBitWidth packSz) packSz .- ones

let vplzcntd ins bld = packedUnOpWith ins bld 32<rt> opLzCount

let vplzcntq ins bld = packedUnOpWith ins bld 64<rt> opLzCount

/// VPCONFLICT reports, for each element, which of the elements before it hold
/// the same value: bit j of the result is set when element j equals element i,
/// for every j below i. The elements above i are never compared, so the first
/// element always comes back zero.
let private vpconflict (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld true packSz packNum oprSz src
    let bitAt i j =
      AST.ite (s[j] == s[i]) (numI32 (1 <<< j) packSz) (AST.num0 packSz)
    let lane i =
      if i = 0 then
        AST.num0 packSz
      else
        Array.init i (bitAt i) |> Array.reduce (.|)
    assignEVEXPacked ins bld packSz oprSz dst (Array.init s.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpconflictd ins bld = vpconflict ins bld 32<rt>

let vpconflictq ins bld = vpconflict ins bld 64<rt>

(* --- the immediate-programmed bitwise operation -------------------------- *)
/// One minterm of a three-input truth table: the three sources ANDed together,
/// each one complemented where the minterm's own bit is clear.
let private minterm a b c k =
  let pick bit e = if bit then e else AST.not e
  pick (k &&& 4 <> 0) a .& pick (k &&& 2 <> 0) b .& pick (k &&& 1 <> 0) c

/// VPTERNLOG computes any function of three bits at once: bit (a<<2)|(b<<1)|c
/// of the immediate is the result for that combination, so a lane is the OR of
/// the minterms the immediate selects. The destination is the first source.
let private vpternlog (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz dst
    let b = transOprToArr ins bld false packSz packNum oprSz src1
    let c = transOprToArr ins bld false packSz packNum oprSz src2
    let imm = getImmValue imm
    let selected = [| 0 .. 7 |] |> Array.filter (fun k -> imm >>> k &&& 1L = 1L)
    let lane i =
      if Array.isEmpty selected then
        AST.num0 packSz
      else
        selected |> Array.map (minterm a[i] b[i] c[i]) |> Array.reduce (.|)
    assignEVEXPacked ins bld packSz oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpternlogd ins bld = vpternlog ins bld 32<rt>

let vpternlogq ins bld = vpternlog ins bld 64<rt>

(* --- the funnel shifts --------------------------------------------------- *)
/// A funnel shift left: the pair of lanes is shifted left as one double-width
/// value and its top half kept. A count of zero is settled separately -- the
/// complementary shift would be by the whole width, which the IR's own shift
/// does not define.
let private opShld width hi lo cnt =
  let w = numI32 (RegType.toBitWidth width) width
  let cnt = rotCount width cnt
  let shifted = (hi << cnt) .| (lo >> (w .- cnt))
  AST.ite (cnt == AST.num0 width) hi shifted

/// A funnel shift right, keeping the bottom half of the pair.
let private opShrd width lo hi cnt =
  let w = numI32 (RegType.toBitWidth width) width
  let cnt = rotCount width cnt
  let shifted = (lo >> cnt) .| (hi << (w .- cnt))
  AST.ite (cnt == AST.num0 width) lo shifted

/// The immediate forms, which name both halves of the pair and leave the
/// destination write-only.
let private funnelImm ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    let cnt = numI64 (getImmValue imm) packSz
    let lane i = opFn packSz a[i] b[i] cnt
    assignEVEXPacked ins bld packSz oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The variable forms, where the destination is the half of the pair the
/// mnemonic's V does not name and the last source holds the count.
let private funnelVar ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz dst
    let b = transOprToArr ins bld false packSz packNum oprSz src1
    let c = transOprToArr ins bld false packSz packNum oprSz src2
    let lane i = opFn packSz a[i] b[i] c[i]
    assignEVEXPacked ins bld packSz oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpshldw ins bld = funnelImm ins bld 16<rt> opShld

let vpshldd ins bld = funnelImm ins bld 32<rt> opShld

let vpshldq ins bld = funnelImm ins bld 64<rt> opShld

let vpshrdw ins bld = funnelImm ins bld 16<rt> opShrd

let vpshrdd ins bld = funnelImm ins bld 32<rt> opShrd

let vpshrdq ins bld = funnelImm ins bld 64<rt> opShrd

let vpshldvw ins bld = funnelVar ins bld 16<rt> opShld

let vpshldvd ins bld = funnelVar ins bld 32<rt> opShld

let vpshldvq ins bld = funnelVar ins bld 64<rt> opShld

let vpshrdvw ins bld = funnelVar ins bld 16<rt> opShrd

let vpshrdvd ins bld = funnelVar ins bld 32<rt> opShrd

let vpshrdvq ins bld = funnelVar ins bld 64<rt> opShrd

(* --- the neural-network dot products ------------------------------------- *)
/// A source element widened to the accumulator's width, signed or not as the
/// mnemonic's own letters say.
let private widen isSigned e =
  if isSigned then AST.sext 64<rt> e else AST.zext 64<rt> e

/// A dot-product lane clamped back to 32 bits. The sum is built at 64 bits so
/// that the saturating forms can see the overflow the plain ones wrap through;
/// a form whose sources are both unsigned saturates against an unsigned range,
/// which is the only place the accumulator is read as unsigned.
let private clampDotProduct isSat isUnsigned total =
  if not isSat then
    AST.xtlo 32<rt> total
  elif isUnsigned then
    let hi = numU64 0xFFFFFFFFUL 64<rt>
    AST.ite (total .> hi) (numI64 -1L 32<rt>) (AST.xtlo 32<rt> total)
  else
    let hi = numI64 0x7FFFFFFFL 64<rt>
    let lo = numI64 -0x80000000L 64<rt>
    let wrapped = AST.xtlo 32<rt> total
    let low = AST.ite (total ?< lo) (numI32 0x80000000 32<rt>) wrapped
    AST.ite (total ?> hi) (numI64 0x7FFFFFFFL 32<rt>) low

/// The VNNI dot products: every 32-bit lane gains the sum of the products of
/// the byte or word pairs that lane covers, added to what the destination
/// already held.
let private dotProduct ins bld subSz signs isSat =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (isSigned1, isSigned2) = signs
    let struct (dst, src1, src2) = getThreeOprs ins
    let acc = transOprToArr ins bld true 32<rt> 2 oprSz dst
    let subNum = 64<rt> / subSz
    let a = transOprToArr ins bld false subSz subNum oprSz src1
    let b = transOprToArr ins bld false subSz subNum oprSz src2
    let per = 32 / RegType.toBitWidth subSz
    let term j = widen isSigned1 a[j] .* widen isSigned2 b[j]
    let isUnsigned = not isSigned1 && not isSigned2
    let lane i =
      let extAcc = widen (not isUnsigned) acc[i]
      Array.init per (fun k -> term (i * per + k))
      |> Array.fold (.+) extAcc
      |> clampDotProduct isSat isUnsigned
    assignEVEXPacked ins bld 32<rt> oprSz dst (Array.init acc.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let private sgnSS = struct (true, true)

let private sgnSU = struct (true, false)

let private sgnUS = struct (false, true)

let private sgnUU = struct (false, false)

let vpdpbusd ins bld = dotProduct ins bld 8<rt> sgnUS false

let vpdpbusds ins bld = dotProduct ins bld 8<rt> sgnUS true

let vpdpbssd ins bld = dotProduct ins bld 8<rt> sgnSS false

let vpdpbssds ins bld = dotProduct ins bld 8<rt> sgnSS true

let vpdpbsud ins bld = dotProduct ins bld 8<rt> sgnSU false

let vpdpbsuds ins bld = dotProduct ins bld 8<rt> sgnSU true

let vpdpbuud ins bld = dotProduct ins bld 8<rt> sgnUU false

let vpdpbuuds ins bld = dotProduct ins bld 8<rt> sgnUU true

let vpdpwssd ins bld = dotProduct ins bld 16<rt> sgnSS false

let vpdpwssds ins bld = dotProduct ins bld 16<rt> sgnSS true

let vpdpwsud ins bld = dotProduct ins bld 16<rt> sgnSU false

let vpdpwsuds ins bld = dotProduct ins bld 16<rt> sgnSU true

let vpdpwusd ins bld = dotProduct ins bld 16<rt> sgnUS false

let vpdpwusds ins bld = dotProduct ins bld 16<rt> sgnUS true

let vpdpwuud ins bld = dotProduct ins bld 16<rt> sgnUU false

let vpdpwuuds ins bld = dotProduct ins bld 16<rt> sgnUU true

/// VPMULTISHIFTQB fills each byte of the result with eight bits of the
/// quadword the second source names, starting at the bit the matching byte of
/// the first source selects and wrapping around the quadword's top.
let vpmultishiftqb (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let ctl = transOprToArr ins bld true 8<rt> 8 oprSz src1
    let data = transOprToArr ins bld true 64<rt> 1 oprSz src2
    let lane i =
      let pos = AST.zext 64<rt> (ctl[i] .& numI32 0x3F 8<rt>)
      AST.xtlo 8<rt> (opRotr 64<rt> data[i / 8] pos)
    assignEVEXPacked ins bld 8<rt> oprSz dst (Array.init ctl.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

(* --- the 52-bit multiply-accumulate -------------------------------------- *)
let private mask26 = numU64 0x3FFFFFFUL 64<rt>

let private mask52 = numU64 0xFFFFFFFFFFFFFUL 64<rt>

let private shift26 = numI32 26 64<rt>

let private shift52 = numI32 52 64<rt>

/// The 52-by-52-bit product IFMA is built on, as its low and high halves. The
/// full product is 104 bits wide, which no lane of the IR can hold, so it is
/// assembled from 26-bit pieces: every partial product then fits a 64-bit lane
/// and the two halves are recombined from those.
let private ifmaProduct bld a b =
  let struct (al, ah, bl, bh) = tmpVars4 bld 64<rt>
  let struct (mid, low) = tmpVars2 bld 64<rt>
  append bld {
    direct al := a .& mask26
    direct ah := (a .& mask52) >> shift26
    direct bl := b .& mask26
    direct bh := (b .& mask52) >> shift26
    direct mid := (ah .* bl) .+ (al .* bh)
    direct low := (al .* bl) .+ ((mid .& mask26) << shift26)
  }
  let hi = (ah .* bh) .+ (mid >> shift26) .+ (low >> shift52)
  struct (low .& mask52, hi)

/// VPMADD52 adds one half of the 104-bit product to the destination, which is
/// the accumulator as well as the destination.
let private vpmadd52 (ins: Instruction) bld isHigh =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packSz = 64<rt>
    let struct (dst, src1, src2) = getThreeOprs ins
    let acc = transOprToArr ins bld true packSz 1 oprSz dst
    let a = transOprToArr ins bld false packSz 1 oprSz src1
    let b = transOprToArr ins bld false packSz 1 oprSz src2
    let lane i =
      let struct (lo, hi) = ifmaProduct bld a[i] b[i]
      acc[i] .+ (if isHigh then hi else lo)
    assignEVEXPacked ins bld packSz oprSz dst (Array.init acc.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpmadd52luq ins bld = vpmadd52 ins bld false

let vpmadd52huq ins bld = vpmadd52 ins bld true

/// VDBPSADBW first rearranges the second source a doubleword at a time, the
/// same way in every 128-bit lane, and then takes eight sums of absolute
/// differences over four bytes each. The two windows move at different rates:
/// the window into the rearranged source advances by a byte for every result
/// word, and the quadruplet of the first source by four bytes for every two --
/// so the first two words share the first source's bytes 0 to 3, the next two
/// its bytes 4 to 7, and so on. The rearranged source skips a quadword between
/// the fourth word and the fifth, which the first source does not.
let vdbpsadbw (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true 8<rt> 8 oprSz src1
    let d = transOprToArr ins bld true 32<rt> 2 oprSz src2
    let imm = getImmValue imm |> int
    let sel = Array.init 4 (fun i -> imm >>> (i * 2) &&& 3)
    let shuffled lane b =
      AST.extract d[lane * 4 + sel[b / 4]] 8<rt> (b % 4 * 8)
    let diff lane bas off t =
      let x = AST.zext 16<rt> a[lane * 16 + bas + t]
      let y = AST.zext 16<rt> (shuffled lane (off + t))
      AST.ite (x .> y) (x .- y) (y .- x)
    let sad lane w =
      let bas = w / 2 * 4
      let off = if w < 4 then w else w + 4
      Array.init 4 (diff lane bas off) |> Array.reduce (.+)
    let lanes = RegType.toBitWidth oprSz / 128
    let result = Array.init (lanes * 8) (fun i -> sad (i / 8) (i % 8))
    assignEVEXPacked ins bld 16<rt> oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

(* --- the instructions that write a mask register -------------------------- *)
/// Writes one bit per element to a mask register, clearing every bit above the
/// elements the vector length covers -- a mask register is 64 bits wide
/// whatever produced its contents. The opmask the instruction itself carries
/// selects which elements are looked at: one it leaves out contributes a clear
/// bit rather than the element's own answer.
let private assignMask (ins: Instruction) bld dst bits =
  let bits =
    match opMaskVar bld ins with
    | ValueNone ->
      bits
    | ValueSome k ->
      Array.mapi (fun i b -> AST.extract k 1<rt> i .& b) bits
  let packed = AST.revConcat bits
  let value =
    if Array.length bits = 64 then packed else AST.zext 64<rt> packed
  append bld {
    direct (transOpr ins bld false dst) := value
  }

/// The comparison an immediate names. The eight predicates are the same for
/// both signednesses; only the ordering they are decided by differs.
let private cmpPred isSigned imm a b =
  match imm &&& 7L with
  | 0L -> a == b
  | 1L -> if isSigned then a ?< b else a .< b
  | 2L -> if isSigned then a ?<= b else a .<= b
  | 3L -> AST.b0
  | 4L -> a != b
  | 5L -> if isSigned then a ?>= b else a .>= b
  | 6L -> if isSigned then a ?> b else a .> b
  | _ -> AST.b1

let private vpcmpImm ins bld packSz isSigned =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    let imm = getImmValue imm
    assignMask ins bld dst (Array.map2 (cmpPred isSigned imm) a b)
  }

let vpcmpb ins bld = vpcmpImm ins bld 8<rt> true

let vpcmpw ins bld = vpcmpImm ins bld 16<rt> true

let vpcmpd ins bld = vpcmpImm ins bld 32<rt> true

let vpcmpq ins bld = vpcmpImm ins bld 64<rt> true

let vpcmpub ins bld = vpcmpImm ins bld 8<rt> false

let vpcmpuw ins bld = vpcmpImm ins bld 16<rt> false

let vpcmpud ins bld = vpcmpImm ins bld 32<rt> false

let vpcmpuq ins bld = vpcmpImm ins bld 64<rt> false

/// The fixed-predicate comparisons, whose EVEX forms write a mask register
/// where every earlier encoding writes a vector of all-ones and all-zeros
/// elements. Only the destination differs, so the earlier form is left to the
/// lifter that already has it.
let private vpcmpFixed ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    assignMask ins bld dst (Array.map2 opFn a b)
  }

let private evexOr fallback ins bld packSz opFn =
  if isEVEXEncoded ins then vpcmpFixed ins bld packSz opFn else fallback ins bld

let vpcmpeqb ins bld =
  evexOr AVXLifter.vpcmpeqb ins bld 8<rt> (==)

let vpcmpeqw ins bld =
  evexOr AVXLifter.vpcmpeqw ins bld 16<rt> (==)

let vpcmpeqd ins bld =
  evexOr AVXLifter.vpcmpeqd ins bld 32<rt> (==)

let vpcmpeqq ins bld =
  evexOr AVXLifter.vpcmpeqq ins bld 64<rt> (==)

let vpcmpgtb ins bld =
  evexOr AVXLifter.vpcmpgtb ins bld 8<rt> (?>)

let vpcmpgtw ins bld =
  evexOr AVXLifter.vpcmpgtw ins bld 16<rt> (?>)

let vpcmpgtd ins bld =
  evexOr AVXLifter.vpcmpgtd ins bld 32<rt> (?>)

let vpcmpgtq ins bld =
  evexOr AVXLifter.vpcmpgtq ins bld 64<rt> (?>)

/// VPTESTM reports the elements whose bitwise AND has any bit set, and
/// VPTESTNM the elements whose AND has none.
let private opTestm a b = (a .& b) != AST.num0 (Expr.typeOf a)

let private opTestnm a b = (a .& b) == AST.num0 (Expr.typeOf a)

let vptestmb ins bld = vpcmpFixed ins bld 8<rt> opTestm

let vptestmw ins bld = vpcmpFixed ins bld 16<rt> opTestm

let vptestmd ins bld = vpcmpFixed ins bld 32<rt> opTestm

let vptestmq ins bld = vpcmpFixed ins bld 64<rt> opTestm

let vptestnmb ins bld = vpcmpFixed ins bld 8<rt> opTestnm

let vptestnmw ins bld = vpcmpFixed ins bld 16<rt> opTestnm

let vptestnmd ins bld = vpcmpFixed ins bld 32<rt> opTestnm

let vptestnmq ins bld = vpcmpFixed ins bld 64<rt> opTestnm

/// The sign bit of every element, gathered into a mask register.
let private vpmov2m ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let src = transOprToArr ins bld false packSz packNum oprSz src
    assignMask ins bld dst (Array.map (AST.xthi 1<rt>) src)
  }

let vpmovb2m ins bld = vpmov2m ins bld 8<rt>

let vpmovw2m ins bld = vpmov2m ins bld 16<rt>

let vpmovd2m ins bld = vpmov2m ins bld 32<rt>

let vpmovq2m ins bld = vpmov2m ins bld 64<rt>

/// The other direction: every element becomes all ones where the mask has its
/// bit set, and all zeros where it does not.
let private vpmovm2 ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let k = transOpr ins bld false src
    let ones = getMask packSz
    let lane i =
      AST.ite (AST.extract k 1<rt> i) ones (AST.num0 packSz)
    let result = Array.init (oprSz / packSz) lane
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpmovm2b ins bld = vpmovm2 ins bld 8<rt>

let vpmovm2w ins bld = vpmovm2 ins bld 16<rt>

let vpmovm2d ins bld = vpmovm2 ins bld 32<rt>

let vpmovm2q ins bld = vpmovm2 ins bld 64<rt>

/// VPBROADCASTM copies the low bits of a mask register into every element,
/// zero-extended: the mask is read once and its width comes from the mnemonic
/// rather than from the element it fills.
let private vpbroadcastm ins bld packSz maskSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let k = transOpr ins bld false src
    let value = AST.zext packSz (AST.xtlo maskSz k)
    let result = Array.create (oprSz / packSz) value
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpbroadcastmb2q ins bld = vpbroadcastm ins bld 64<rt> 8<rt>

let vpbroadcastmw2d ins bld = vpbroadcastm ins bld 32<rt> 16<rt>

/// VPSHUFBITQMB reads one bit out of the quadword each byte of the result
/// belongs to, at the index that byte of the control names.
let vpshufbitqmb (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let data = transOprToArr ins bld true 64<rt> 1 oprSz src1
    let ctl = transOprToArr ins bld true 8<rt> 8 oprSz src2
    let bit i =
      let pos = AST.zext 64<rt> (ctl[i] .& numI32 0x3F 8<rt>)
      AST.xtlo 1<rt> (data[i / 8] >> pos)
    assignMask ins bld dst (Array.init ctl.Length bit)
  }

/// VP2INTERSECT writes a pair of mask registers: the first reports which
/// elements of one source appear anywhere in the other, the second the same
/// the other way round. The encoding names only the first of the pair, which
/// is why the second is the register after it.
let private vp2intersect (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz src1
    let b = transOprToArr ins bld true packSz packNum oprSz src2
    let anyEq (xs: Expr[]) x = xs |> Array.map ((==) x) |> Array.reduce (.|)
    let second =
      match dst with
      | OprReg r ->
        let next: Register = LanguagePrimitives.EnumOfValue(int r + 1)
        OprReg next
      | _ ->
        raise InvalidOperandException
    assignMask ins bld dst (Array.map (anyEq b) a)
    assignMask ins bld second (Array.map (anyEq a) b)
  }

let vp2intersectd ins bld = vp2intersect ins bld 32<rt>

let vp2intersectq ins bld = vp2intersect ins bld 64<rt>

/// The eight classes VFPCLASS can be asked about, each decided on the bit
/// pattern rather than on the value: a classification must answer for a NaN
/// rather than raise on one. MXCSR.DAZ is taken as clear, so a denormal counts
/// as a denormal and not as a zero.
let private fpClass width imm src =
  let fracSz =
    match width with
    | 64<rt> -> 52
    | 32<rt> -> 23
    | _ -> 10
  let expBits = RegType.toBitWidth width - fracSz - 1
  let expMask = numI64 ((1L <<< expBits) - 1L) width
  let fracMask = numI64 ((1L <<< fracSz) - 1L) width
  let zero = AST.num0 width
  let expo = (src >> numI32 fracSz width) .& expMask
  let allOnes = expo == expMask
  let allZeros = expo == zero
  let mantZero = (src .& fracMask) == zero
  let neg = AST.xthi 1<rt> src
  let quiet = AST.extract src 1<rt> (fracSz - 1)
  let isZero = allZeros .& mantZero
  let classes =
    [| allOnes .& AST.not mantZero .& quiet
       AST.not neg .& isZero
       neg .& isZero
       AST.not neg .& allOnes .& mantZero
       neg .& allOnes .& mantZero
       allZeros .& AST.not mantZero
       neg .& AST.not allOnes .& AST.not isZero
       allOnes .& AST.not mantZero .& AST.not quiet |]
  let selected = [| 0 .. 7 |] |> Array.filter (fun i -> imm >>> i &&& 1L = 1L)
  if Array.isEmpty selected then
    AST.b0
  else
    selected |> Array.map (fun i -> classes[i]) |> Array.reduce (.|)

let private vfpclassPacked ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src, imm) = getThreeOprs ins
    let s = transOprToArr ins bld false packSz packNum oprSz src
    let imm = getImmValue imm
    assignMask ins bld dst (Array.map (fpClass packSz imm) s)
  }

let vfpclasspd ins bld = vfpclassPacked ins bld 64<rt>

let vfpclassps ins bld = vfpclassPacked ins bld 32<rt>

/// The low element of a vector operand, or the whole of a memory one: a
/// scalar form reads exactly one element either way.
let private scalarSrc ins bld width src =
  match src with
  | OprMem _ ->
    transOpr ins bld false src
  | _ ->
    let struct (_, lo) = transOpr128 ins bld false src
    if width = 64<rt> then lo else AST.xtlo width lo

let private vfpclassScalar ins bld width =
  lift bld ins {
    let struct (dst, src, imm) = getThreeOprs ins
    let value = scalarSrc ins bld width src
    let imm = getImmValue imm
    assignMask ins bld dst [| fpClass width imm value |]
  }

let vfpclasssd ins bld = vfpclassScalar ins bld 64<rt>

let vfpclassss ins bld = vfpclassScalar ins bld 32<rt>

/// The floating-point compares write a mask register under EVEX, one bit per
/// lane, where every earlier encoding fills the lane itself with ones or with
/// zeros. The predicate the immediate names is the same either way.
let private vcmpToMask ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz src1
    let b = transOprToArr ins bld true packSz packNum oprSz src2
    let isDbl = packSz = 64<rt>
    let bit i =
      let c = tmpVar bld 1<rt>
      SSELifter.cmppCond bld ins imm isDbl c a[i] b[i]
      c
    assignMask ins bld dst (Array.init a.Length bit)
  }

let vcmppd ins bld =
  if isEVEXEncoded ins then
    vcmpToMask ins bld 64<rt>
  else
    SSELifter.cmppd ins bld

let vcmpps ins bld =
  if isEVEXEncoded ins then
    vcmpToMask ins bld 32<rt>
  else
    SSELifter.cmpps ins bld

let private vcmpScalarToMask ins bld width =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = scalarSrc ins bld width src1
    let b = scalarSrc ins bld width src2
    let c = tmpVar bld 1<rt>
    SSELifter.cmppCond bld ins imm (width = 64<rt>) c a b
    assignMask ins bld dst [| c |]
  }

let vcmpsd ins bld =
  if isEVEXEncoded ins then
    vcmpScalarToMask ins bld 64<rt>
  else
    SSELifter.cmpsd ins bld

let vcmpss ins bld =
  if isEVEXEncoded ins then
    vcmpScalarToMask ins bld 32<rt>
  else
    SSELifter.cmpss ins bld

(* --- moving data between lanes ------------------------------------------- *)
/// The vector length the encoding declares, which is not always the size of
/// the operation: an extracting instruction's destination is narrower than the
/// source it reads, and an inserting one's second source narrower than the
/// first.
let private vectorLength (ins: Instruction) =
  match ins.VEXInfo with
  | Some v -> v.VectorLength
  | None -> raise InvalidOperandException

/// VALIGN shifts the pair of sources right by whole elements, the second
/// source supplying the low end of the pair and the first its high end.
let private valign ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz src1
    let b = transOprToArr ins bld true packSz packNum oprSz src2
    let n = a.Length
    let shift = int (getImmValue imm) &&& (n - 1)
    let joined = Array.append b a
    assignEVEXPacked ins bld packSz oprSz dst (Array.sub joined shift n)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let valignd ins bld = valign ins bld 32<rt>

let valignq ins bld = valign ins bld 64<rt>

/// VBLENDM takes each element from the second source where the mask allows it
/// and from the first source where it does not -- which is the write mask's
/// own merge, except that what a masked-off element keeps comes from an
/// operand rather than from the destination.
let private blendm ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    let result =
      match opMaskVar bld ins with
      | ValueNone ->
        b
      | ValueSome k ->
        let kept i = if ins.IsZeroing then AST.num0 packSz else a[i]
        Array.mapi (fun i e -> AST.ite (AST.extract k 1<rt> i) e (kept i)) b
    assignPackedInstr ins bld false packNum oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vblendmpd ins bld = blendm ins bld 64<rt>

let vblendmps ins bld = blendm ins bld 32<rt>

let vpblendmb ins bld = blendm ins bld 8<rt>

let vpblendmw ins bld = blendm ins bld 16<rt>

let vpblendmd ins bld = blendm ins bld 32<rt>

let vpblendmq ins bld = blendm ins bld 64<rt>

/// VBROADCAST repeats a piece of its source -- a pair of elements, or a whole
/// 128- or 256-bit block -- through the destination. A register source is read
/// as a whole XMM even when only its low quadword is wanted, because a
/// register has no narrower reader.
let private vbroadcastx ins bld packSz srcSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let readSz = if srcSz = 64<rt> && not (isMemOpr src) then 128<rt> else srcSz
    let s = transOprToArr ins bld true packSz packNum readSz src
    let cnt = srcSz / packSz
    let result = Array.init (oprSz / packSz) (fun i -> s[i % cnt])
    assignEVEXPacked ins bld packSz oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vbroadcastf32x2 ins bld = vbroadcastx ins bld 32<rt> 64<rt>

let vbroadcasti32x2 ins bld = vbroadcastx ins bld 32<rt> 64<rt>

let vbroadcastf32x4 ins bld = vbroadcastx ins bld 32<rt> 128<rt>

let vbroadcasti32x4 ins bld = vbroadcastx ins bld 32<rt> 128<rt>

let vbroadcastf32x8 ins bld = vbroadcastx ins bld 32<rt> 256<rt>

let vbroadcasti32x8 ins bld = vbroadcastx ins bld 32<rt> 256<rt>

let vbroadcastf64x2 ins bld = vbroadcastx ins bld 64<rt> 128<rt>

let vbroadcasti64x2 ins bld = vbroadcastx ins bld 64<rt> 128<rt>

let vbroadcastf64x4 ins bld = vbroadcastx ins bld 64<rt> 256<rt>

let vbroadcasti64x4 ins bld = vbroadcastx ins bld 64<rt> 256<rt>

/// VEXTRACT keeps one 128- or 256-bit piece of its source, the immediate
/// choosing which. The destination is that piece's width, and the write mask
/// applies to the elements of the piece.
let private vextractx ins bld packSz =
  lift bld ins {
    let dstSz = getOperationSize ins
    let srcSz = vectorLength ins
    let packNum = 64<rt> / packSz
    let struct (dst, src, imm) = getThreeOprs ins
    let s = transOprToArr ins bld true packSz packNum srcSz src
    let n = dstSz / packSz
    let sel = int (getImmValue imm) % (srcSz / dstSz)
    assignEVEXPacked ins bld packSz dstSz dst (Array.sub s (sel * n) n)
    fillZeroFromVLToMaxVL bld dst dstSz 512
  }

let vextractf32x4 ins bld = vextractx ins bld 32<rt>

let vextracti32x4 ins bld = vextractx ins bld 32<rt>

let vextractf32x8 ins bld = vextractx ins bld 32<rt>

let vextracti32x8 ins bld = vextractx ins bld 32<rt>

let vextractf64x2 ins bld = vextractx ins bld 64<rt>

let vextracti64x2 ins bld = vextractx ins bld 64<rt>

let vextractf64x4 ins bld = vextractx ins bld 64<rt>

let vextracti64x4 ins bld = vextractx ins bld 64<rt>

/// VINSERT overwrites one 128- or 256-bit piece of its first source with the
/// second, the immediate choosing which piece, and leaves the rest standing.
let private vinsertx ins bld packSz partSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz src1
    let b = transOprToArr ins bld true packSz packNum partSz src2
    let n = b.Length
    let sel = int (getImmValue imm) % (oprSz / partSz)
    let lane i = if i / n = sel then b[i % n] else a[i]
    assignEVEXPacked ins bld packSz oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vinsertf32x4 ins bld = vinsertx ins bld 32<rt> 128<rt>

let vinserti32x4 ins bld = vinsertx ins bld 32<rt> 128<rt>

let vinsertf32x8 ins bld = vinsertx ins bld 32<rt> 256<rt>

let vinserti32x8 ins bld = vinsertx ins bld 32<rt> 256<rt>

let vinsertf64x2 ins bld = vinsertx ins bld 64<rt> 128<rt>

let vinserti64x2 ins bld = vinsertx ins bld 64<rt> 128<rt>

let vinsertf64x4 ins bld = vinsertx ins bld 64<rt> 256<rt>

let vinserti64x4 ins bld = vinsertx ins bld 64<rt> 256<rt>

/// VSHUF rearranges whole 128-bit lanes: the first half of the result is
/// picked out of the first source and the second half out of the second, each
/// lane by its own field of the immediate.
let private vshufx ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true packSz packNum oprSz src1
    let b = transOprToArr ins bld true packSz packNum oprSz src2
    let per = 128 / RegType.toBitWidth packSz
    let lanes = RegType.toBitWidth oprSz / 128
    let bits = if lanes = 4 then 2 else 1
    let imm = getImmValue imm |> int
    let lane i =
      let l = i / per
      let sel = imm >>> (l * bits) &&& ((1 <<< bits) - 1)
      let table = if l < lanes / 2 then a else b
      table[sel * per + i % per]
    assignEVEXPacked ins bld packSz oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vshuff32x4 ins bld = vshufx ins bld 32<rt>

let vshufi32x4 ins bld = vshufx ins bld 32<rt>

let vshuff64x2 ins bld = vshufx ins bld 64<rt>

let vshufi64x2 ins bld = vshufx ins bld 64<rt>

/// An element index widened to 64 bits and reduced to the table's size.
let private tableIdx packSz e n =
  let wide = if packSz = 64<rt> then e else AST.zext 64<rt> e
  wide .& numI32 (n - 1) 64<rt>

/// The element a variable index picks out of a table, found by selecting the
/// quadword that holds it and then shifting within that quadword. Comparing
/// the index against every element in turn would take as many comparisons as
/// the table has elements, which at a byte an element is thousands of them.
let private elemAt packSz (qwords: Expr[]) idx =
  let bits = RegType.toBitWidth packSz
  let per = 64 / bits
  let lg =
    match per with
    | 1 -> 0
    | 2 -> 1
    | 4 -> 2
    | _ -> 3
  let qsel = idx >> numI32 lg 64<rt>
  let mutable picked = qwords[qwords.Length - 1]
  for j in qwords.Length - 2 .. -1 .. 0 do
    picked <- AST.ite (qsel == numI32 j 64<rt>) qwords[j] picked
  let off = (idx .& numI32 (per - 1) 64<rt>) .* numI32 bits 64<rt>
  if bits = 64 then picked else AST.xtlo packSz (picked >> off)

/// VPERMB and VPERMW take every element of the result out of the second
/// source, at the index the matching element of the first source names.
let private vpermIdx ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let idx = transOprToArr ins bld true packSz packNum oprSz src1
    let table = transOprToArr ins bld true 64<rt> 1 oprSz src2
    let n = oprSz / packSz
    let lane i = elemAt packSz table (tableIdx packSz idx[i] n)
    assignEVEXPacked ins bld packSz oprSz dst (Array.init n lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vpermb ins bld = vpermIdx ins bld 8<rt>

let vpermw ins bld = vpermIdx ins bld 16<rt>

/// The two-table permutes, which differ only in where the indices come from
/// and which operand supplies the low half of the table.
let private vperm2 ins bld packSz idxOpr lowOpr highOpr =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let idx = transOprToArr ins bld true packSz packNum oprSz idxOpr
    let low = transOprToArr ins bld true 64<rt> 1 oprSz lowOpr
    let high = transOprToArr ins bld true 64<rt> 1 oprSz highOpr
    let table = Array.append low high
    let n = 2 * (oprSz / packSz)
    let lane i = elemAt packSz table (tableIdx packSz idx[i] n)
    let struct (dst, _, _) = getThreeOprs ins
    assignEVEXPacked ins bld packSz oprSz dst (Array.init idx.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// VPERMI2 reads its indices from the destination and its table from the two
/// sources, the first of them supplying the table's low half.
let private vpermi2 (ins: Instruction) bld packSz =
  let struct (dst, src1, src2) = getThreeOprs ins
  vperm2 ins bld packSz dst src1 src2

/// VPERMT2 reads its indices from the first source and its table from the
/// destination and the second source, the destination supplying the low half.
let private vpermt2 (ins: Instruction) bld packSz =
  let struct (dst, src1, src2) = getThreeOprs ins
  vperm2 ins bld packSz src1 dst src2

let vpermi2b ins bld = vpermi2 ins bld 8<rt>

let vpermi2w ins bld = vpermi2 ins bld 16<rt>

let vpermi2d ins bld = vpermi2 ins bld 32<rt>

let vpermi2q ins bld = vpermi2 ins bld 64<rt>

let vpermi2ps ins bld = vpermi2 ins bld 32<rt>

let vpermi2pd ins bld = vpermi2 ins bld 64<rt>

let vpermt2b ins bld = vpermt2 ins bld 8<rt>

let vpermt2w ins bld = vpermt2 ins bld 16<rt>

let vpermt2d ins bld = vpermt2 ins bld 32<rt>

let vpermt2q ins bld = vpermt2 ins bld 64<rt>

let vpermt2ps ins bld = vpermt2 ins bld 32<rt>

let vpermt2pd ins bld = vpermt2 ins bld 64<rt>

(* --- the down-converting moves ------------------------------------------- *)
/// A store narrower than a quadword, which no lane-splitting writer covers:
/// the destination is read back as one value, sliced for the merge, and
/// written as one value again.
let private assignPartTiny ins bld packSz dst result =
  let bits = RegType.toBitWidth packSz
  let whole = transOpr ins bld false dst
  let merged =
    match opMaskVar bld ins with
    | ValueNone ->
      result
    | ValueSome k ->
      let old i = AST.extract whole packSz (i * bits)
      Array.mapi (fun i e -> AST.ite (AST.extract k 1<rt> i) e (old i)) result
  append bld {
    direct (transOpr ins bld false dst) := AST.revConcat merged
  }

/// The bytes a masked store leaves alone. A store of a quadword or more goes
/// out a quadword at a time, as every other vector store does: the memory it
/// covers is wider than one value of the IR wherever the vector is.
let private assignPartMem ins bld packSz dst result =
  let bits = RegType.toBitWidth packSz
  let outBits = Array.length result * bits
  if outBits < 64 then
    assignPartTiny ins bld packSz dst result
  else
    let outSz: RegType = LanguagePrimitives.Int32WithMeasure outBits
    let packNum = 64<rt> / packSz
    let merged =
      match opMaskVar bld ins with
      | ValueNone ->
        result
      | ValueSome k ->
        let kept = transOprToArr ins bld false packSz packNum outSz dst
        let underMask i e = AST.ite (AST.extract k 1<rt> i) e kept[i]
        Array.mapi underMask result
    assignPackedInstr ins bld false packNum outSz dst merged

/// A register destination takes the result in its low bits and zeros above
/// them, which is what the architecture writes there in any case, so the
/// result is padded out to a whole XMM before it is written.
let private assignPartReg (ins: Instruction) bld packSz dst result =
  let bits = RegType.toBitWidth packSz
  let outBits = Array.length result * bits
  let padSz: RegType = LanguagePrimitives.Int32WithMeasure(max 128 outBits)
  let merged =
    match opMaskVar bld ins with
    | ValueNone ->
      result
    | ValueSome k ->
      let kept = transOprToArr ins bld false packSz (64<rt> / packSz) padSz dst
      let old i = if ins.IsZeroing then AST.num0 packSz else kept[i]
      Array.mapi (fun i e -> AST.ite (AST.extract k 1<rt> i) e (old i)) result
  let pad = (RegType.toBitWidth padSz - outBits) / bits
  let padded = Array.append merged (Array.create pad (AST.num0 packSz))
  assignPackedInstr ins bld false (64<rt> / packSz) padSz dst padded
  fillZeroFromVLToMaxVL bld dst padSz 512

/// Writes a result that need not fill the destination register: a
/// down-converting move, or a conversion whose lanes change width.
let private assignEVEXPart ins bld packSz dst result =
  if isMemOpr dst then
    assignPartMem ins bld packSz dst result
  else
    assignPartReg ins bld packSz dst result

/// A source element narrowed by truncation: the bits above the destination's
/// width are simply dropped.
let private narrowTrunc dstSz e = AST.xtlo dstSz e

/// Narrowed by signed saturation: a value outside the destination's signed
/// range becomes the nearest end of it.
let private narrowSat dstSz e =
  let width = Expr.typeOf e
  let bits = RegType.toBitWidth dstSz
  let hi = numI64 ((1L <<< (bits - 1)) - 1L) width
  let lo = numI64 (-(1L <<< (bits - 1))) width
  AST.xtlo dstSz (AST.ite (e ?< lo) lo (AST.ite (e ?> hi) hi e))

/// Narrowed by unsigned saturation, where the source is read as unsigned as
/// well: only the top of the destination's range can be exceeded.
let private narrowUsat dstSz e =
  let width = Expr.typeOf e
  let hi = numI64 ((1L <<< RegType.toBitWidth dstSz) - 1L) width
  AST.xtlo dstSz (AST.ite (e .> hi) hi e)

let private vpmovDown ins bld srcSz dstSz narrow =
  lift bld ins {
    let vl = vectorLength ins
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld true srcSz (64<rt> / srcSz) vl src
    assignEVEXPart ins bld dstSz dst (Array.map (narrow dstSz) s)
  }

let vpmovwb ins bld = vpmovDown ins bld 16<rt> 8<rt> narrowTrunc

let vpmovdb ins bld = vpmovDown ins bld 32<rt> 8<rt> narrowTrunc

let vpmovdw ins bld = vpmovDown ins bld 32<rt> 16<rt> narrowTrunc

let vpmovqb ins bld = vpmovDown ins bld 64<rt> 8<rt> narrowTrunc

let vpmovqw ins bld = vpmovDown ins bld 64<rt> 16<rt> narrowTrunc

let vpmovqd ins bld = vpmovDown ins bld 64<rt> 32<rt> narrowTrunc

let vpmovswb ins bld = vpmovDown ins bld 16<rt> 8<rt> narrowSat

let vpmovsdb ins bld = vpmovDown ins bld 32<rt> 8<rt> narrowSat

let vpmovsdw ins bld = vpmovDown ins bld 32<rt> 16<rt> narrowSat

let vpmovsqb ins bld = vpmovDown ins bld 64<rt> 8<rt> narrowSat

let vpmovsqw ins bld = vpmovDown ins bld 64<rt> 16<rt> narrowSat

let vpmovsqd ins bld = vpmovDown ins bld 64<rt> 32<rt> narrowSat

let vpmovuswb ins bld = vpmovDown ins bld 16<rt> 8<rt> narrowUsat

let vpmovusdb ins bld = vpmovDown ins bld 32<rt> 8<rt> narrowUsat

let vpmovusdw ins bld = vpmovDown ins bld 32<rt> 16<rt> narrowUsat

let vpmovusqb ins bld = vpmovDown ins bld 64<rt> 8<rt> narrowUsat

let vpmovusqw ins bld = vpmovDown ins bld 64<rt> 16<rt> narrowUsat

let vpmovusqd ins bld = vpmovDown ins bld 64<rt> 32<rt> narrowUsat

(* --- gather, scatter, and the moves that pack or unpack a vector ---------- *)
/// The opmask a gather or a scatter consumes, which it clears as it goes: a
/// program tells a run that finished from one that faulted part way through by
/// finding the mask empty afterwards.
let private gatherMask bld (ins: Instruction) =
  match opMaskVar bld ins with
  | ValueSome k -> k
  | ValueNone -> raise InvalidOperandException

/// The pieces a VSIB operand is built from: an address expression per index,
/// and how many indices the index vector holds. A gather or a scatter runs
/// over the shorter of that and its data vector, which the caller settles.
let private vsibParts ins (bld: ILowUIRBuilder) idxSz vsib =
  match vsib with
  | OprMem(baseReg, Some(idxReg, scale), disp, _) ->
    let addrSz = bld.RegType
    let struct (b, d) = AVXLifter.vsibBaseDisp bld addrSz baseReg disp
    let idxOpr = OprReg idxReg
    let idxWidth = AVXLifter.operandWidth bld idxOpr
    let idx = transOprToArr ins bld true idxSz (64<rt> / idxSz) idxWidth idxOpr
    let scaleNum = numI32 (int scale) addrSz
    let addrOf i = b .+ d .+ (AST.sext addrSz idx[i] .* scaleNum)
    struct (addrOf, RegType.toBitWidth idxWidth / RegType.toBitWidth idxSz)
  | _ ->
    raise InvalidOperandException

/// The EVEX gathers, which take their mask from an opmask register rather than
/// from a vector operand and so name one operand fewer than the VEX forms.
let private vgather (ins: Instruction) bld idxSz dataSz =
  lift bld ins {
    let struct (dst, vsib) = getTwoOprs ins
    let dstSz = getOperationSize ins
    let dataNum = 64<rt> / dataSz
    let k = gatherMask bld ins
    let struct (addrOf, idxCount) = vsibParts ins bld idxSz vsib
    let slots = transOprToArr ins bld false dataSz dataNum dstSz dst
    let count = min (dstSz / dataSz) idxCount
    let selects i = AST.extract k 1<rt> i
    AVXLifter.gatherElements bld dataSz bld.RegType count addrOf slots selects
    append bld {
      direct k := AST.num0 64<rt>
    }
    fillZeroFromVLToMaxVL bld dst dstSz 512
  }

let vgatherdpd ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 32<rt> 64<rt>
  else
    AVXLifter.vgatherdpd ins bld

let vgatherqpd ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 64<rt> 64<rt>
  else
    AVXLifter.vgatherqpd ins bld

let vgatherdps ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 32<rt> 32<rt>
  else
    AVXLifter.vgatherdps ins bld

let vgatherqps ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 64<rt> 32<rt>
  else
    AVXLifter.vgatherqps ins bld

let vpgatherdd ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 32<rt> 32<rt>
  else
    AVXLifter.vpgatherdd ins bld

let vpgatherdq ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 32<rt> 64<rt>
  else
    AVXLifter.vpgatherdq ins bld

let vpgatherqd ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 64<rt> 32<rt>
  else
    AVXLifter.vpgatherqd ins bld

let vpgatherqq ins bld =
  if isEVEXEncoded ins then
    vgather ins bld 64<rt> 64<rt>
  else
    AVXLifter.vpgatherqq ins bld

/// A scatter stores one element per index the mask selects, in order from the
/// lowest element up, so that two indices naming the same address leave the
/// higher element's value behind. Each store sits behind a branch: an element
/// the mask leaves out must not have its address formed at all.
let private vscatter (ins: Instruction) bld idxSz dataSz =
  lift bld ins {
    let struct (vsib, src) = getTwoOprs ins
    let srcSz = getOperationSize ins
    let k = gatherMask bld ins
    let struct (addrOf, idxCount) = vsibParts ins bld idxSz vsib
    let values = transOprToArr ins bld true dataSz (64<rt> / dataSz) srcSz src
    let count = min (srcSz / dataSz) idxCount
    for i in 0 .. count - 1 do
      let addr = tmpVar bld bld.RegType
      _if bld "Scattered" (AST.extract k 1<rt> i)
        (block {
          direct addr := addrOf i
          direct (AST.loadLE dataSz addr) := values[i] })
        (block { })
    append bld {
      direct k := AST.num0 64<rt>
    }
  }

let vscatterdpd ins bld = vscatter ins bld 32<rt> 64<rt>

let vscatterqpd ins bld = vscatter ins bld 64<rt> 64<rt>

let vscatterdps ins bld = vscatter ins bld 32<rt> 32<rt>

let vscatterqps ins bld = vscatter ins bld 64<rt> 32<rt>

let vpscatterdd ins bld = vscatter ins bld 32<rt> 32<rt>

let vpscatterdq ins bld = vscatter ins bld 32<rt> 64<rt>

let vpscatterqd ins bld = vscatter ins bld 64<rt> 32<rt>

let vpscatterqq ins bld = vscatter ins bld 64<rt> 64<rt>

/// The gather and scatter prefetch hints ask for a line to be brought into the
/// cache, which an emulator that has none has nothing to do about. They change
/// no register and no memory, so a hint is the whole of their architecture.
let vgatherpf ins bld = GeneralLifter.nop ins bld

/// The address a memory operand names, taken back out of the load the operand
/// translates to: an expanding load and a compressing store form their own
/// addresses, one element at a time, rather than touching the whole operand.
let private addressOf ins bld opr =
  match transOpr ins bld false opr with
  | Load(_, _, addr, _) -> addr
  | _ -> raise InvalidOperandException

/// VEXPAND spreads the source's elements over the destination's, one for each
/// element the mask selects and in order: the source is read from its low end
/// whatever the mask's pattern, so which element a slot takes depends on how
/// many slots before it were selected. A source in memory is read one element
/// at a time and only where the mask selects one, so no address past the last
/// element the instruction needs is ever formed.
let private vexpand (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src) = getTwoOprs ins
    let n = oprSz / packSz
    let idx = tmpVar bld 64<rt>
    direct idx := AST.num0 64<rt>
    let fetch =
      if isMemOpr src then
        let addr = addressOf ins bld src
        let addrSz = Expr.typeOf addr
        let bytes = numI32 (RegType.toByteWidth packSz) addrSz
        fun () -> AST.loadLE packSz (addr .+ (AST.xtlo addrSz idx .* bytes))
      else
        let table = transOprToArr ins bld true 64<rt> 1 oprSz src
        fun () -> elemAt packSz table idx
    let vals = Array.init n (fun _ -> tmpVar bld packSz)
    let old =
      if ins.IsZeroing then
        Array.create n (AST.num0 packSz)
      else
        transOprToArr ins bld false packSz packNum oprSz dst
    match opMaskVar bld ins with
    | ValueNone ->
      for i in 0 .. n - 1 do
        append bld {
          direct vals[i] := fetch ()
          direct idx := idx .+ AST.num1 64<rt>
        }
    | ValueSome k ->
      for i in 0 .. n - 1 do
        _if bld "Expanded" (AST.extract k 1<rt> i)
          (block {
            direct vals[i] := fetch ()
            direct idx := idx .+ AST.num1 64<rt> })
          (block {
            direct vals[i] := old[i] })
    assignPackedInstr ins bld false packNum oprSz dst vals
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vexpandpd ins bld = vexpand ins bld 64<rt>

let vexpandps ins bld = vexpand ins bld 32<rt>

let vpexpandb ins bld = vexpand ins bld 8<rt>

let vpexpandw ins bld = vexpand ins bld 16<rt>

let vpexpandd ins bld = vexpand ins bld 32<rt>

let vpexpandq ins bld = vexpand ins bld 64<rt>

/// VCOMPRESS with a destination in memory stores only the elements the mask
/// selected, each one where the count of the elements before it puts it, and
/// touches nothing past the last of them.
let private vcompressMem ins bld packSz oprSz dst src =
  let n = oprSz / packSz
  let values = transOprToArr ins bld true packSz (64<rt> / packSz) oprSz src
  let addr = addressOf ins bld dst
  let addrSz = Expr.typeOf addr
  let bytes = numI32 (RegType.toByteWidth packSz) addrSz
  let idx = tmpVar bld addrSz
  append bld {
    direct idx := AST.num0 addrSz
  }
  match opMaskVar bld ins with
  | ValueNone ->
    for i in 0 .. n - 1 do
      append bld {
        direct (AST.loadLE packSz (addr .+ (idx .* bytes))) := values[i]
        direct idx := idx .+ AST.num1 addrSz
      }
  | ValueSome k ->
    for i in 0 .. n - 1 do
      _if bld "Compressed" (AST.extract k 1<rt> i)
        (block {
          direct (AST.loadLE packSz (addr .+ (idx .* bytes))) := values[i]
          direct idx := idx .+ AST.num1 addrSz })
        (block { })

/// With a destination in a register the slot each element lands in is not
/// known until the instruction runs, so every slot is built from every element
/// instead: element j reaches slot i when the mask selects it and exactly i of
/// the elements before it were selected too.
let private vcompressReg (ins: Instruction) bld packSz oprSz dst src =
  let packNum = 64<rt> / packSz
  let n = oprSz / packSz
  let values = transOprToArr ins bld true packSz packNum oprSz src
  let result =
    match opMaskVar bld ins with
    | ValueNone ->
      values
    | ValueSome k ->
      let pfx = Array.init n (fun _ -> tmpVar bld 8<rt>)
      append bld {
        direct pfx[0] := AST.num0 8<rt>
      }
      for j in 1 .. n - 1 do
        let bit = AST.zext 8<rt> (AST.extract k 1<rt> (j - 1))
        append bld {
          direct pfx[j] := pfx[j - 1] .+ bit
        }
      let old =
        if ins.IsZeroing then
          Array.create n (AST.num0 packSz)
        else
          transOprToArr ins bld false packSz packNum oprSz dst
      let slot i =
        let mutable acc = old[i]
        for j in n - 1 .. -1 .. 0 do
          let sel = AST.extract k 1<rt> j .& (pfx[j] == numI32 i 8<rt>)
          acc <- AST.ite sel values[j] acc
        acc
      Array.init n slot
  assignPackedInstr ins bld false packNum oprSz dst result
  fillZeroFromVLToMaxVL bld dst oprSz 512

let private vcompress (ins: Instruction) bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    if isMemOpr dst then
      vcompressMem ins bld packSz oprSz dst src
    else
      vcompressReg ins bld packSz oprSz dst src
  }

let vcompresspd ins bld = vcompress ins bld 64<rt>

let vcompressps ins bld = vcompress ins bld 32<rt>

let vpcompressb ins bld = vcompress ins bld 8<rt>

let vpcompressw ins bld = vcompress ins bld 16<rt>

let vpcompressd ins bld = vcompress ins bld 32<rt>

let vpcompressq ins bld = vcompress ins bld 64<rt>

/// VMOVW moves sixteen bits between the low word of a vector register and a
/// general-purpose register or memory. A write to the vector register clears
/// everything above the word; a write to a general-purpose one is a 32-bit
/// write, zero-extended like every other.
let vmovw (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let isVec = function
      | OprReg r -> RegisterHelper.getKind r >= RegisterHelper.Kind.XMM
      | _ -> false
    if isVec dst then
      let word =
        if isMemOpr src then
          transOpr ins bld false src
        else
          AST.xtlo 16<rt> (transOpr ins bld false src)
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      direct dstA := AST.zext 64<rt> word
      direct dstB := AST.num0 64<rt>
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    else
      let struct (_, srcA) = transOpr128 ins bld false src
      let word = AST.xtlo 16<rt> srcA
      if isMemOpr dst then
        direct (transOpr ins bld false dst) := word
      else
        sized 32<rt> (transOpr ins bld false dst) := AST.zext 32<rt> word
  }

(* --- the conversions EVEX added ------------------------------------------ *)
/// The rounding a conversion uses. A register form with EVEX.b set names one
/// in L'L, which overrides MXCSR for that instruction alone; without it the
/// conversion rounds the way MXCSR says, which is taken to be to nearest --
/// the same assumption every other conversion in this front end makes.
let private fToIKind (ins: Instruction) isTrunc =
  match ins.VEXInfo with
  | Some { EVEXPrx = Some p } when p.RCDecor = StaticRounding && not isTrunc ->
    match p.RC with
    | RN -> CastKind.FtoIRound
    | RD -> CastKind.FtoIFloor
    | RU -> CastKind.FtoICeil
    | RZ -> CastKind.FtoITrunc
  | _ ->
    if isTrunc then CastKind.FtoITrunc else CastKind.FtoIRound

/// A float converted to a 32-bit unsigned integer. The IR has no unsigned form
/// of the cast, so the conversion is made at 64 bits and checked: a value the
/// destination cannot hold -- a NaN included, which casts to the most negative
/// integer -- becomes the all-ones the architecture writes for it.
let private toUnsigned32 kind e =
  let wide = AST.cast kind 64<rt> e
  let hi = numU64 0xFFFFFFFFUL 64<rt>
  let bad = (wide ?< AST.num0 64<rt>) .| (wide ?> hi)
  AST.ite bad (numI64 -1L 32<rt>) (AST.xtlo 32<rt> wide)

/// The bit pattern of two to the sixty-third, at the width of the float that
/// is being converted: the halfway point an unsigned conversion folds around.
let private twoTo63 width =
  if width = 64<rt> then numU64 0x43E0000000000000UL 64<rt>
  else numI32 0x5F000000 32<rt>

/// A float converted to a 64-bit unsigned integer, which the signed cast
/// cannot reach on its own: a value at or above two to the sixty-third has
/// that much taken off it first and put back afterwards.
let private toUnsigned64 kind width e =
  let half = twoTo63 width
  let big = AST.fge e half
  let converted = AST.cast kind 64<rt> (AST.ite big (AST.fsub e half) e)
  let folded = converted .+ numU64 0x8000000000000000UL 64<rt>
  let ok = AST.ite big folded converted
  AST.ite (converted ?< AST.num0 64<rt>) (numI64 -1L 64<rt>) ok

/// A conversion between lanes that may change width. The vector length is the
/// wider of the two sides, which is what settles how many elements there are;
/// the narrower side then fills only part of its register, and the rest of it
/// comes back zero.
let private cvtLanes ins bld srcSz dstSz conv =
  lift bld ins {
    let vl = RegType.toBitWidth (vectorLength ins)
    let wide = max (RegType.toBitWidth srcSz) (RegType.toBitWidth dstSz)
    let n = vl / wide
    let srcBits = RegType.fromBitWidth (n * RegType.toBitWidth srcSz)
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld true srcSz (64<rt> / srcSz) srcBits src
    assignEVEXPart ins bld dstSz dst (Array.map conv s)
  }

let private cvtToSigned ins bld srcSz dstSz isTrunc =
  cvtLanes ins bld srcSz dstSz (AST.cast (fToIKind ins isTrunc) dstSz)

let private cvtToUnsigned32 ins bld srcSz isTrunc =
  cvtLanes ins bld srcSz 32<rt> (toUnsigned32 (fToIKind ins isTrunc))

let private cvtToUnsigned64 ins bld srcSz isTrunc =
  cvtLanes ins bld srcSz 64<rt> (toUnsigned64 (fToIKind ins isTrunc) srcSz)

let vcvtpd2qq ins bld = cvtToSigned ins bld 64<rt> 64<rt> false

let vcvttpd2qq ins bld = cvtToSigned ins bld 64<rt> 64<rt> true

let vcvtps2qq ins bld = cvtToSigned ins bld 32<rt> 64<rt> false

let vcvttps2qq ins bld = cvtToSigned ins bld 32<rt> 64<rt> true

let vcvtpd2udq ins bld = cvtToUnsigned32 ins bld 64<rt> false

let vcvttpd2udq ins bld = cvtToUnsigned32 ins bld 64<rt> true

let vcvtps2udq ins bld = cvtToUnsigned32 ins bld 32<rt> false

let vcvttps2udq ins bld = cvtToUnsigned32 ins bld 32<rt> true

let vcvtpd2uqq ins bld = cvtToUnsigned64 ins bld 64<rt> false

let vcvttpd2uqq ins bld = cvtToUnsigned64 ins bld 64<rt> true

let vcvtps2uqq ins bld = cvtToUnsigned64 ins bld 32<rt> false

let vcvttps2uqq ins bld = cvtToUnsigned64 ins bld 32<rt> true

let private cvtFromInt ins bld srcSz dstSz isSigned =
  let kind = if isSigned then CastKind.SIntToFloat else CastKind.UIntToFloat
  cvtLanes ins bld srcSz dstSz (AST.cast kind dstSz)

let vcvtqq2pd ins bld = cvtFromInt ins bld 64<rt> 64<rt> true

let vcvtqq2ps ins bld = cvtFromInt ins bld 64<rt> 32<rt> true

let vcvtuqq2pd ins bld = cvtFromInt ins bld 64<rt> 64<rt> false

let vcvtuqq2ps ins bld = cvtFromInt ins bld 64<rt> 32<rt> false

let vcvtudq2pd ins bld = cvtFromInt ins bld 32<rt> 64<rt> false

let vcvtudq2ps ins bld = cvtFromInt ins bld 32<rt> 32<rt> false

/// VCVTUSI2SD and VCVTUSI2SS convert an unsigned general-purpose register or
/// memory operand into the low element of the destination; the rest of the low
/// 128 bits comes from the first source and everything above it is cleared.
let private cvtusi2 (ins: Instruction) bld width =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let value = transOpr ins bld false src2
    let converted = AST.cast CastKind.UIntToFloat width value
    let low =
      if width = 64<rt> then converted
      else AST.concat (AST.xthi 32<rt> src1A) converted
    direct dstA := low
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

let vcvtusi2sd ins bld = cvtusi2 ins bld 64<rt>

let vcvtusi2ss ins bld = cvtusi2 ins bld 32<rt>

/// VCVTSD2USI and friends convert the low element of a vector operand into an
/// unsigned general-purpose register, whose width the destination names.
let private cvt2usi (ins: Instruction) bld width isTrunc =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let value = scalarSrc ins bld width src
    let kind = fToIKind ins isTrunc
    let dstSz = AVXLifter.operandWidth bld dst
    let result =
      if dstSz = 64<rt> then toUnsigned64 kind width value
      else toUnsigned32 kind value
    sized dstSz (transOpr ins bld false dst) := result
  }

let vcvtsd2usi ins bld = cvt2usi ins bld 64<rt> false

let vcvttsd2usi ins bld = cvt2usi ins bld 64<rt> true

let vcvtss2usi ins bld = cvt2usi ins bld 32<rt> false

let vcvttss2usi ins bld = cvt2usi ins bld 32<rt> true

(* --- the floating-point instructions EVEX added --------------------------- *)
/// How wide a float's fraction field is at a given width.
let private fracBits width =
  match width with
  | 64<rt> -> 52
  | 32<rt> -> 23
  | _ -> 10

/// The exponent field with every bit set, which is what an infinity and a NaN
/// share.
let private expMaskOf width =
  match width with
  | 64<rt> -> 0x7FFL
  | 32<rt> -> 0xFFL
  | _ -> 0x1FL

/// What is added to a float's exponent to make its exponent field.
let private biasOf width =
  match width with
  | 64<rt> -> 1023
  | 32<rt> -> 127
  | _ -> 15

let private expField width src =
  (src >> numI32 (fracBits width) width) .& numI64 (expMaskOf width) width

let private fracField width src =
  src .& numI64 ((1L <<< fracBits width) - 1L) width

/// The sign bit alone, as a mask.
let private signBit width = numI64 (1L <<< (RegType.toBitWidth width - 1)) width

/// The quiet bit of a NaN's fraction, which turns a signalling NaN into the
/// quiet one an instruction is required to return in its place.
let private quietBit width = numI64 (1L <<< (fracBits width - 1)) width

let private posInf width =
  numI64 (expMaskOf width <<< fracBits width) width

let private negInf width = posInf width .| signBit width

/// The QNaN every instruction returns when it is asked for a value that does
/// not exist: the sign set, the exponent all ones, and only the quiet bit of
/// the fraction.
let private qnanIndefinite width = negInf width .| quietBit width

/// The bit pattern of a power of two, which is exact for every exponent a
/// scaling instruction can ask for.
let private powerOfTwo width n =
  numI64 (int64 (biasOf width + n) <<< fracBits width) width

/// VGETEXP returns the unbiased exponent of its source as a floating-point
/// value. For a denormal that is the exponent the value would have once
/// normalized, which the count of its leading zeros gives.
let private getExp bld width src =
  let bias = biasOf width
  let e = expField width src
  let frac = fracField width src
  let zero = AST.num0 width
  let isSpecial = e == numI64 (expMaskOf width) width
  let lz = opLzCount bld width frac
  let offset = RegType.toBitWidth width - bias - fracBits width
  let denormExp = numI32 offset width .- lz
  let value = AST.ite (e == zero) denormExp (e .- numI32 bias width)
  let special = AST.ite (frac == zero) (posInf width) (src .| quietBit width)
  let finite = AST.cast CastKind.SIntToFloat width value
  let zeroOrNot = AST.ite (frac == zero) (negInf width) finite
  AST.ite isSpecial special (AST.ite (e == zero) zeroOrNot finite)

/// Writes the low element of a scalar EVEX operation: the rest of the low 128
/// bits comes from the first source, everything above them is cleared, and the
/// one bit of the write mask decides whether the element is written at all.
let private assignScalar (ins: Instruction) bld width dst src1 value =
  let struct (dstB, dstA) = transOpr128 ins bld false dst
  let struct (src1B, src1A) = transOpr128 ins bld false src1
  let old = if width = 64<rt> then dstA else AST.xtlo width dstA
  let written =
    match opMaskVar bld ins with
    | ValueNone ->
      value
    | ValueSome k ->
      let kept = if ins.IsZeroing then AST.num0 width else old
      AST.ite (AST.xtlo 1<rt> k) value kept
  let low =
    if width = 64<rt> then
      written
    else
      let keep = RegType.fromBitWidth (64 - RegType.toBitWidth width)
      AST.concat (AST.extract src1A keep (RegType.toBitWidth width)) written
  append bld {
    direct dstA := low
    direct dstB := src1B
  }
  fillZeroFromVLToMaxVL bld dst 128<rt> 512

/// The three-operand scalar forms: the value is computed from the second
/// source, and the elements above it come from the first.
let private scalarUnOp ins bld width opFn =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let value = opFn bld width (scalarSrc ins bld width src2)
    assignScalar ins bld width dst src1 value
  }

/// The scalar forms that carry an immediate as well.
let private scalarImmOp ins bld width opFn =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let value = opFn bld width (getImmValue imm) (scalarSrc ins bld width src2)
    assignScalar ins bld width dst src1 value
  }

/// A packed two-operand form whose lanes carry an immediate and each need
/// statements of their own.
let private packedImmOpBld ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src, imm) = getThreeOprs ins
    let s = transOprToArr ins bld false packSz packNum oprSz src
    let imm = getImmValue imm
    let result = Array.map (opFn bld packSz imm) s
    assignEVEXPacked ins bld packSz oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vgetexppd ins bld = packedUnOpWith ins bld 64<rt> getExp

let vgetexpps ins bld = packedUnOpWith ins bld 32<rt> getExp

let vgetexpsd ins bld = scalarUnOp ins bld 64<rt> getExp

let vgetexpss ins bld = scalarUnOp ins bld 32<rt> getExp

/// VGETMANT normalizes the significand into the interval an immediate names
/// and settles its sign the same way. A denormal is normalized first, which
/// shifts its fraction up by one more than its leading zeros leave and moves
/// the exponent down by as much -- and since that shift and the exponent a
/// denormal really has differ by an even number, the parity the [1/2, 2)
/// interval turns on is the shift's own.
let private getMant bld width imm src =
  let fb = fracBits width
  let bias = biasOf width
  let e = expField width src
  let frac = fracField width src
  let zero = AST.num0 width
  let one = AST.num1 width
  let isSpecial = e == numI64 (expMaskOf width) width
  let isDenorm = (e == zero) .& (frac != zero)
  let lz = opLzCount bld width frac
  let shift = lz .- numI32 (RegType.toBitWidth width - fb - 1) width
  let mask = numI64 ((1L <<< fb) - 1L) width
  let normFrac = AST.ite isDenorm ((frac << shift) .& mask) frac
  let odd = AST.ite isDenorm shift (e .- numI32 bias width)
  let isOdd = AST.xtlo 1<rt> (odd .& one)
  let expLo = numI32 (bias - 1) width
  let expHi = numI32 bias width
  let chosen =
    match imm &&& 3L with
    | 0L -> expHi
    | 1L -> AST.ite isOdd expLo expHi
    | 2L -> expLo
    | _ -> AST.ite (AST.extract normFrac 1<rt> (fb - 1)) expLo expHi
  let sign = if imm &&& 4L <> 0L then zero else src .& signBit width
  let normal = sign .| (chosen << numI32 fb width) .| normFrac
  let plainOne = sign .| (expHi << numI32 fb width)
  (* A zero is answered before the immediate's rule about negative sources and
     an infinity after it, which is the one asymmetry here: a negative zero
     comes back as minus one where a negative infinity comes back as the
     indefinite. *)
  let isInf = isSpecial .& (frac == zero)
  let afterSign = AST.ite isInf plainOne normal
  let finite =
    if imm &&& 8L = 0L then
      afterSign
    else
      AST.ite (AST.xthi 1<rt> src) (qnanIndefinite width) afterSign
  let isZero = (e == zero) .& (frac == zero)
  let nan = src .| quietBit width
  AST.ite (isSpecial .& (frac != zero)) nan (AST.ite isZero plainOne finite)

let vgetmantpd ins bld = packedImmOpBld ins bld 64<rt> getMant

let vgetmantps ins bld = packedImmOpBld ins bld 32<rt> getMant

let vgetmantsd ins bld = scalarImmOp ins bld 64<rt> getMant

let vgetmantss ins bld = scalarImmOp ins bld 32<rt> getMant

/// The rounding an immediate names for VRNDSCALE and VREDUCE. Bit 2 asks for
/// MXCSR's instead, which is read as round-to-nearest here as everywhere.
let private rndKind imm =
  if imm &&& 4L <> 0L then
    CastKind.FtoFRound
  else
    match imm &&& 3L with
    | 0L -> CastKind.FtoFRound
    | 1L -> CastKind.FtoFFloor
    | 2L -> CastKind.FtoFCeil
    | _ -> CastKind.FtoFTrunc

/// Whether a float is a NaN, decided on its bit pattern.
let private isNaN width src =
  let allOnes = expField width src == numI64 (expMaskOf width) width
  allOnes .& (fracField width src != AST.num0 width)

/// VRNDSCALE rounds to a fixed number of fraction bits: the value is scaled up
/// by that many powers of two, rounded to an integer, and scaled back down. A
/// value already integral at that scale is returned as it stands, which is
/// also what keeps the scaling from overflowing on a large one.
let private rndScale _ width imm src =
  let m = int ((imm >>> 4) &&& 0xFL)
  let scaled = AST.fmul src (powerOfTwo width m)
  let rounded = AST.cast (rndKind imm) width scaled
  let back = AST.fmul rounded (powerOfTwo width (-m))
  let threshold = numI32 (biasOf width + fracBits width - m) width
  let big = expField width src .>= threshold
  AST.ite (isNaN width src) (src .| quietBit width) (AST.ite big src back)

let vrndscalepd ins bld = packedImmOpBld ins bld 64<rt> rndScale

let vrndscaleps ins bld = packedImmOpBld ins bld 32<rt> rndScale

let vrndscalesd ins bld = scalarImmOp ins bld 64<rt> rndScale

let vrndscaless ins bld = scalarImmOp ins bld 32<rt> rndScale

/// Evaluates one floating-point expression under a rounding direction the
/// instruction names rather than the one MXCSR holds. The IR has no per-
/// operation rounding, so the control register is set for the length of the
/// operation and put back; the value has to land in a temporary while it is
/// set, because an expression is not evaluated where it is built. The
/// immediate's two low bits are already MXCSR.RC's own encoding.
let private underRounding bld mode width value =
  let saved = tmpVar bld 32<rt>
  let result = tmpVar bld width
  let mxcsr = regVar bld R.MXCSR
  let rc = numI32 (mode <<< 13) 32<rt>
  append bld {
    direct saved := mxcsr
    direct mxcsr := (saved .& numI32 ~~~0x6000 32<rt>) .| rc
    direct result := value
    direct mxcsr := saved
  }
  result

/// VREDUCE keeps what VRNDSCALE rounded away: the part of the value below the
/// fraction bit the immediate names. The subtraction is where the rounding
/// direction the immediate names is felt -- a remainder just short of the
/// whole step is not representable, and rounds one way or the other, and a
/// remainder that cancels exactly comes back negative under round toward
/// negative infinity and positive under the rest -- so it is the one operation
/// here that cannot be left to MXCSR.
let private reduce bld width imm src =
  let rounded = rndScale bld width imm src
  let diff =
    if imm &&& 4L <> 0L then AST.fsub src rounded
    else underRounding bld (int (imm &&& 3L)) width (AST.fsub src rounded)
  let quiet = src .| quietBit width
  (* An infinity has nothing below any fraction bit, so what it leaves is a
     zero -- a positive one whichever way the infinity pointed, and not the
     indefinite that subtracting it from itself would give. *)
  let allOnes = expField width src == numI64 (expMaskOf width) width
  let isInf = allOnes .& (fracField width src == AST.num0 width)
  let onInf = AST.ite isInf (AST.num0 width) diff
  AST.ite (isNaN width src) quiet onInf

let vreducepd ins bld = packedImmOpBld ins bld 64<rt> reduce

let vreduceps ins bld = packedImmOpBld ins bld 32<rt> reduce

let vreducesd ins bld = scalarImmOp ins bld 64<rt> reduce

let vreducess ins bld = scalarImmOp ins bld 32<rt> reduce

/// Whether a float is a signalling NaN, which VRANGE answers for before it
/// looks at anything else.
let private isSignallingNaN width src =
  isNaN width src .& AST.not (AST.extract src 1<rt> (fracBits width - 1))

/// The source VRANGE picks before the sign control is applied. Two zeros are
/// settled before the comparison rather than by it: they compare equal
/// whatever their signs, so the comparison would hand back the wrong one, and
/// the manual gives the first source to a maximum and the second to a minimum.
/// A NaN in one source alone is passed over in favour of the other, and two
/// NaNs give the first, quieted.
let private rangePick width imm src1 src2 =
  let absMask = AST.not (signBit width)
  let onAbs = imm &&& 2L <> 0L
  let a = if onAbs then src1 .& absMask else src1
  let b = if onAbs then src2 .& absMask else src2
  (* A pair the comparison cannot separate -- two zeros, or two values of
     equal magnitude compared on their absolute values -- is settled by sign
     rather than by operand order: the minimum takes the negative one and the
     maximum the positive one, whichever way round the two were written. Two
     operands that tie and share a sign are the same value, so nothing is left
     to decide there. *)
  let lt = AST.flt a b
  let isMax = imm &&& 1L <> 0L
  let ordered = if isMax then AST.ite lt src2 src1 else AST.ite lt src1 src2
  let firstIsNeg = AST.xthi 1<rt> src1
  let negative = AST.ite firstIsNeg src1 src2
  let positive = AST.ite firstIsNeg src2 src1
  let onTie = if isMax then positive else negative
  let value = AST.ite (AST.feq a b) onTie ordered
  let nan1 = isNaN width src1
  let nan2 = isNaN width src2
  let ordered = AST.ite nan1 src2 (AST.ite nan2 src1 value)
  AST.ite (nan1 .& nan2) (src1 .| quietBit width) ordered

/// VRANGE picks one of its two sources by a comparison the immediate names --
/// the smaller, the larger, or either of those on absolute values -- and then
/// gives the answer the sign the immediate's other field asks for. A
/// signalling NaN in either source is returned quieted before any of that
/// happens, sign control included.
let private range _ width imm src1 src2 =
  let chosen = rangePick width imm src1 src2
  let absMask = AST.not (signBit width)
  let signed =
    match (imm >>> 2) &&& 3L with
    | 0L -> (src1 .& signBit width) .| (chosen .& absMask)
    | 1L -> chosen
    | 2L -> chosen .& absMask
    | _ -> chosen .| signBit width
  let onSecond =
    AST.ite (isSignallingNaN width src2) (src2 .| quietBit width) signed
  AST.ite (isSignallingNaN width src1) (src1 .| quietBit width) onSecond

/// The packed two-source forms that carry an immediate every lane reads the
/// same way, and whose lanes may need statements of their own.
let private packedBinImmOp ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    let imm = getImmValue imm
    let result = Array.map2 (opFn bld packSz imm) a b
    assignEVEXPacked ins bld packSz oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The scalar two-source forms with an immediate, whose upper elements come
/// from the first source as every scalar form's do.
let private scalarBinImmOp ins bld width opFn =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = scalarSrc ins bld width src1
    let b = scalarSrc ins bld width src2
    let value = opFn bld width (getImmValue imm) a b
    assignScalar ins bld width dst src1 value
  }

let vrangepd ins bld = packedBinImmOp ins bld 64<rt> range

let vrangeps ins bld = packedBinImmOp ins bld 32<rt> range

let vrangesd ins bld = scalarBinImmOp ins bld 64<rt> range

let vrangess ins bld = scalarBinImmOp ins bld 32<rt> range

/// The bit pattern of one, which the reciprocals divide and VFIXUPIMM tests
/// its source against.
let private oneOf width =
  numI64 (if width = 64<rt> then 0x3FF0000000000000L else 0x3F800000L) width

/// A packed two-source form whose lanes may need statements of their own.
let private packedBinOpBld ins bld packSz opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    let result = Array.map2 (opFn bld packSz) a b
    assignEVEXPacked ins bld packSz oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The scalar two-source forms, whose upper elements come from the first
/// source as every scalar form's do.
let private scalarBinOp ins bld width opFn =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = scalarSrc ins bld width src1
    let b = scalarSrc ins bld width src2
    assignScalar ins bld width dst src1 (opFn bld width a b)
  }

/// The exponent VSCALEF asks for, bounded to what the chunks below can apply.
/// A source past what an int64 can hold does not convert to a large integer
/// but to a wrapped one, which turns the overflow it asks for into an
/// underflow, so the bound is taken from the exponent field before the
/// conversion rather than from its result. The exponent named here is the
/// first one whose power of two already exceeds the bound, so everything the
/// conversion is still asked for fits.
let private scaleExp width limit src2 =
  let bigExp = if width = 64<rt> then 12 else 9
  let bigBiased = numI64 (int64 (biasOf width + bigExp)) width
  let huge = expField width src2 .>= bigBiased
  let floored = AST.cast CastKind.FtoFFloor width src2
  let raw = AST.cast CastKind.FtoITrunc 64<rt> floored
  let capped = AST.ite (raw ?> limit) limit raw
  let bounded = AST.ite (raw ?< AST.neg limit) (AST.neg limit) capped
  let saturated = AST.ite (AST.xthi 1<rt> src2) (AST.neg limit) limit
  AST.ite huge saturated bounded

/// VSCALEF multiplies its first source by two raised to the floor of the
/// second. The exponent is applied in chunks small enough for each power of
/// two to be a normal number, which is what lets an exponent past the format's
/// range still overflow or underflow the way one long multiplication would.
let private scaleByChunks bld width src1 src2 =
  let chunk = if width = 64<rt> then 1000 else 100
  let lo = numI64 (int64 -chunk) 64<rt>
  let hi = numI64 (int64 chunk) 64<rt>
  let struct (n, c1, c2) = tmpVars3 bld 64<rt>
  let clampTo v = AST.ite (v ?< lo) lo (AST.ite (v ?> hi) hi v)
  append bld {
    direct n := scaleExp width (numI64 (int64 chunk * 3L) 64<rt>) src2
    direct c1 := clampTo n
    direct c2 := clampTo (n .- c1)
  }
  let pow c =
    let cw = if width = 64<rt> then c else AST.xtlo width c
    (cw .+ numI32 (biasOf width) width) << numI32 (fracBits width) width
  let byPow acc c = AST.fmul acc (pow c)
  byPow (byPow (byPow src1 c1) c2) (n .- c1 .- c2)

/// The cases VSCALEF answers rather than scales. An infinity in the second
/// source against a zero or an opposing infinity in the first describes no
/// scaling at all, and each source's NaN propagates -- except that a quiet one
/// in the first source loses to an infinity in the second, which answers as
/// though the NaN were a positive number and so gives a positive infinity
/// against a positive exponent and a positive zero against a negative one.
/// The sign every other source keeps is not the NaN's, and a signalling NaN
/// is quieted and returned there as it is everywhere else.
let private scalef bld width src1 src2 =
  let scaled = scaleByChunks bld width src1 src2
  let sign2 = AST.xthi 1<rt> src2
  let allOnes2 = expField width src2 == numI64 (expMaskOf width) width
  let inf2 = allOnes2 .& (fracField width src2 == AST.num0 width)
  let isZero1 = (src1 .& AST.not (signBit width)) == AST.num0 width
  let allOnes1 = expField width src1 == numI64 (expMaskOf width) width
  let isInf1 = allOnes1 .& (fracField width src1 == AST.num0 width)
  let bad = (isZero1 .& inf2 .& AST.not sign2) .| (isInf1 .& inf2 .& sign2)
  let fixed1 = AST.ite bad (qnanIndefinite width) scaled
  let onNaN2 = AST.ite (isNaN width src2) (src2 .| quietBit width) fixed1
  let quieted1 = src1 .| quietBit width
  let onInf2 = AST.ite sign2 (AST.num0 width) (posInf width)
  let overridden = inf2 .& AST.not (isSignallingNaN width src1)
  AST.ite (isNaN width src1) (AST.ite overridden onInf2 quieted1) onNaN2

let vscalefpd ins bld = packedBinOpBld ins bld 64<rt> scalef

let vscalefps ins bld = packedBinOpBld ins bld 32<rt> scalef

let vscalefsd ins bld = scalarBinOp ins bld 64<rt> scalef

let vscalefss ins bld = scalarBinOp ins bld 32<rt> scalef

/// The reciprocal and reciprocal-square-root approximations. What the manual
/// promises is a bounded relative error and nothing more: the exact bits are
/// the implementation's to choose, and these compute the real quotient, which
/// is what the legacy approximations in this front end do too.
let private recip _ width src = AST.fdiv (oneOf width) src

let private rsqrt _ width src = AST.fdiv (oneOf width) (AST.fsqrt src)

let vrcp14pd ins bld = packedUnOpWith ins bld 64<rt> recip

let vrcp14ps ins bld = packedUnOpWith ins bld 32<rt> recip

let vrcp14sd ins bld = scalarUnOp ins bld 64<rt> recip

let vrcp14ss ins bld = scalarUnOp ins bld 32<rt> recip

let vrcp28pd ins bld = packedUnOpWith ins bld 64<rt> recip

let vrcp28ps ins bld = packedUnOpWith ins bld 32<rt> recip

let vrcp28sd ins bld = scalarUnOp ins bld 64<rt> recip

let vrcp28ss ins bld = scalarUnOp ins bld 32<rt> recip

let vrsqrt14pd ins bld = packedUnOpWith ins bld 64<rt> rsqrt

let vrsqrt14ps ins bld = packedUnOpWith ins bld 32<rt> rsqrt

let vrsqrt14sd ins bld = scalarUnOp ins bld 64<rt> rsqrt

let vrsqrt14ss ins bld = scalarUnOp ins bld 32<rt> rsqrt

let vrsqrt28pd ins bld = packedUnOpWith ins bld 64<rt> rsqrt

let vrsqrt28ps ins bld = packedUnOpWith ins bld 32<rt> rsqrt

let vrsqrt28sd ins bld = scalarUnOp ins bld 64<rt> rsqrt

let vrsqrt28ss ins bld = scalarUnOp ins bld 32<rt> rsqrt

/// The seven constants a fixup response can name, in the order the responses
/// nine to fifteen ask for them.
let private fixupConsts width =
  if width = 64<rt> then
    [| 0xBFF0000000000000L
       0x3FF0000000000000L
       0x3FE0000000000000L
       0x4056800000000000L
       0x3FF921FB54442D18L
       0x7FEFFFFFFFFFFFFFL
       0xFFEFFFFFFFFFFFFFL |]
  else
    [| 0xBF800000L
       0x3F800000L
       0x3F000000L
       0x42B40000L
       0x3FC90FDBL
       0x7F7FFFFFL
       0xFF7FFFFFL |]

/// The quiet NaN a fixup builds out of its source: the exponent forced to all
/// ones and the quiet bit set, with the sign and the fraction left as they
/// were. For a source that is already a NaN that quiets it and keeps its
/// payload; for anything else it keeps whatever the fraction held, which a
/// denormal shows and a zero does not.
let private asQuietNaN width tsrc =
  tsrc .| posInf width .| quietBit width

/// The value one of the sixteen fixup responses names. Only three of them
/// depend on anything: the two that pass the source through, and the one that
/// leaves the destination as it was.
let private fixupValue width old tsrc n =
  match n with
  | 0 -> old
  | 1 -> tsrc
  | 2 -> asQuietNaN width tsrc
  | 3 -> qnanIndefinite width
  | 4 -> negInf width
  | 5 -> posInf width
  | 6 -> AST.ite (AST.xthi 1<rt> tsrc) (negInf width) (posInf width)
  | 7 -> signBit width
  | 8 -> AST.num0 width
  | _ -> numI64 ((fixupConsts width)[n - 9]) width

/// Which of the eight classes a fixup's source falls into, as the index of the
/// response field that class reads.
let private fixupToken width tsrc =
  let e = expField width tsrc
  let frac = fracField width tsrc
  let zero = AST.num0 width
  let allOnes = e == numI64 (expMaskOf width) width
  let quiet = AST.extract tsrc 1<rt> (fracBits width - 1)
  let neg = AST.xthi 1<rt> tsrc
  let num n = numI32 n 8<rt>
  let signed = AST.ite neg (num 6) (num 7)
  let infinite = AST.ite neg (num 4) (num 5)
  let ordinary = AST.ite (tsrc == oneOf width) (num 3) signed
  let finite = AST.ite ((e == zero) .& (frac == zero)) (num 2) ordinary
  let special = AST.ite (frac == zero) infinite (AST.ite quiet (num 0) (num 1))
  AST.ite allOnes special finite

/// One lane of VFIXUPIMM: the second source names a class, the class picks a
/// four-bit field of the third operand, and that field names the value the
/// lane takes. The immediate settles only which exceptions are raised, which
/// leaves it with nothing to say about the value.
let private fixupLane width old tsrc ctl =
  let shift = AST.zext width (fixupToken width tsrc) .* numI32 4 width
  let resp = (ctl >> shift) .& numI32 0xF width
  let mutable acc = fixupValue width old tsrc 15
  for n in 14 .. -1 .. 0 do
    acc <- AST.ite (resp == numI32 n width) (fixupValue width old tsrc n) acc
  acc

let private vfixupimmPacked ins bld packSz =
  lift bld ins {
    let oprSz = getOperationSize ins
    let packNum = 64<rt> / packSz
    let struct (dst, src1, src2, _) = getFourOprs ins
    let old = transOprToArr ins bld true packSz packNum oprSz dst
    let a = transOprToArr ins bld false packSz packNum oprSz src1
    let b = transOprToArr ins bld false packSz packNum oprSz src2
    let lane i = fixupLane packSz old[i] a[i] b[i]
    assignEVEXPacked ins bld packSz oprSz dst (Array.init old.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let private vfixupimmScalar ins bld width =
  lift bld ins {
    let struct (dst, src1, src2, _) = getFourOprs ins
    let old = scalarSrc ins bld width dst
    let a = scalarSrc ins bld width src1
    let b = scalarSrc ins bld width src2
    assignScalar ins bld width dst src1 (fixupLane width old a b)
  }

let vfixupimmpd ins bld = vfixupimmPacked ins bld 64<rt>

let vfixupimmps ins bld = vfixupimmPacked ins bld 32<rt>

let vfixupimmsd ins bld = vfixupimmScalar ins bld 64<rt>

let vfixupimmss ins bld = vfixupimmScalar ins bld 32<rt>

(* --- the brain-float conversions ----------------------------------------- *)
/// A 32-bit float narrowed to a bfloat16, which is its top sixteen bits with
/// what lies below them rounded in: the tie goes to the even value, as it does
/// everywhere else, and a NaN keeps the top of its payload and is quieted.
let private toBf16 src =
  let sixteen = numI32 16 32<rt>
  let top = src >> sixteen
  let bias = numI32 0x7FFF 32<rt> .+ (top .& AST.num1 32<rt>)
  let rounded = (src .+ bias) >> sixteen
  let quiet = top .| numI32 0x40 32<rt>
  AST.xtlo 16<rt> (AST.ite (isNaN 32<rt> src) quiet rounded)

/// A bfloat16 widened to a 32-bit float, which is exact: the sixteen bits are
/// the top of the float and everything below them is zero.
let private fromBf16 e = AST.concat e (AST.num0 16<rt>)

/// VCVTNE2PS2BF16 narrows two whole vectors into one: the second source fills
/// the low half of the result and the first source the high half.
let vcvtne2ps2bf16 (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld true 32<rt> 2 oprSz src1
    let b = transOprToArr ins bld true 32<rt> 2 oprSz src2
    let n = a.Length
    let lane i = if i < n then toBf16 b[i] else toBf16 a[i - n]
    assignEVEXPacked ins bld 16<rt> oprSz dst (Array.init (n * 2) lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// VCVTNEPS2BF16 narrows one vector, so its destination is half as wide as its
/// source and the rest of the register it sits in comes back zero.
let vcvtneps2bf16 (ins: Instruction) bld =
  lift bld ins {
    let vl = vectorLength ins
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld true 32<rt> 2 vl src
    assignEVEXPart ins bld 16<rt> dst (Array.map toBf16 s)
  }

/// VDPBF16PS adds to each lane the two products of the bfloat16 pairs that
/// lane covers, the higher pair first. The sources are read a doubleword at a
/// time so that an embedded broadcast, which names a doubleword, still works.
let vdpbf16ps (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let acc = transOprToArr ins bld true 32<rt> 2 oprSz dst
    let a = transOprToArr ins bld true 32<rt> 2 oprSz src1
    let b = transOprToArr ins bld true 32<rt> 2 oprSz src2
    let low e = fromBf16 (AST.xtlo 16<rt> e)
    let high e = fromBf16 (AST.xthi 16<rt> e)
    let lane i =
      let hi = AST.fmul (high a[i]) (high b[i])
      let lo = AST.fmul (low a[i]) (low b[i])
      AST.fadd (AST.fadd acc[i] hi) lo
    assignEVEXPacked ins bld 32<rt> oprSz dst (Array.init acc.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// VBCSTNEBF162PS reads one bfloat16 from memory and fills every lane of the
/// destination with the float it widens to.
let vbcstnebf162ps (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let value = fromBf16 (transOpr ins bld false src)
    let result = Array.create (oprSz / 32<rt>) value
    assignPackedInstr ins bld false 2 oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// VCVTNEEBF162PS and VCVTNEOBF162PS widen every other bfloat16 of their
/// source, the even-numbered ones or the odd, into as many floats.
let private cvtneBf162ps (ins: Instruction) bld isOdd =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld true 32<rt> 2 oprSz src
    let pick e = if isOdd then AST.xthi 16<rt> e else AST.xtlo 16<rt> e
    let result = Array.map (fun e -> fromBf16 (pick e)) s
    assignPackedInstr ins bld false 2 oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vcvtneebf162ps ins bld = cvtneBf162ps ins bld false

let vcvtneobf162ps ins bld = cvtneBf162ps ins bld true

(* --- the half-precision instructions -------------------------------------- *)
/// A packed half-precision operation, carried out at single precision. Every
/// arithmetic instruction in the set works this way: a single has more than
/// twice a half's significand, so rounding the single-precision answer back to
/// a half gives what computing in half precision would have.
let private phBinOp ins bld opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSz src1
    let b = transOprToArr ins bld true 16<rt> 4 oprSz src2
    let lane i = singleToHalf (opFn (halfToSingle a[i]) (halfToSingle b[i]))
    assignEVEXPacked ins bld 16<rt> oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let private phUnOp ins bld opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSz src
    let lane i = singleToHalf (opFn (halfToSingle a[i]))
    assignEVEXPacked ins bld 16<rt> oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The scalar half-precision forms: the low element is computed and the rest
/// of the low 128 bits comes from the first source.
let private shBinOp ins bld opFn =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = halfToSingle (scalarSrc ins bld 16<rt> src1)
    let b = halfToSingle (scalarSrc ins bld 16<rt> src2)
    assignScalar ins bld 16<rt> dst src1 (singleToHalf (opFn a b))
  }

let private shUnOp ins bld opFn =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let value = opFn (halfToSingle (scalarSrc ins bld 16<rt> src2))
    assignScalar ins bld 16<rt> dst src1 (singleToHalf value)
  }

let vaddph ins bld = phBinOp ins bld AST.fadd

let vaddsh ins bld = shBinOp ins bld AST.fadd

let vsubph ins bld = phBinOp ins bld AST.fsub

let vsubsh ins bld = shBinOp ins bld AST.fsub

let vmulph ins bld = phBinOp ins bld AST.fmul

let vmulsh ins bld = shBinOp ins bld AST.fmul

let vdivph ins bld = phBinOp ins bld AST.fdiv

let vdivsh ins bld = shBinOp ins bld AST.fdiv

/// The minimum and maximum take the second source wherever the comparison is
/// false, which it is whenever either operand is a NaN.
let private opMinf a b = AST.ite (AST.flt a b) a b

let private opMaxf a b = AST.ite (AST.fgt a b) a b

let vminph ins bld = phBinOp ins bld opMinf

let vminsh ins bld = shBinOp ins bld opMinf

let vmaxph ins bld = phBinOp ins bld opMaxf

let vmaxsh ins bld = shBinOp ins bld opMaxf

let vsqrtph ins bld = phUnOp ins bld AST.fsqrt

let vsqrtsh ins bld = shUnOp ins bld AST.fsqrt

let private opRecipf x = AST.fdiv (oneOf 32<rt>) x

let private opRsqrtf x = AST.fdiv (oneOf 32<rt>) (AST.fsqrt x)

let vrcpph ins bld = phUnOp ins bld opRecipf

let vrcpsh ins bld = shUnOp ins bld opRecipf

let vrsqrtph ins bld = phUnOp ins bld opRsqrtf

let vrsqrtsh ins bld = shUnOp ins bld opRsqrtf

let vscalefph ins bld = phBinOp ins bld (scalef bld 32<rt>)

let vscalefsh ins bld = shBinOp ins bld (scalef bld 32<rt>)

/// The half-precision forms that carry an immediate, which every lane reads
/// the same way.
let private phImmOp ins bld opFn =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src, imm) = getThreeOprs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSz src
    let imm = getImmValue imm
    let lane i = singleToHalf (opFn imm (halfToSingle a[i]))
    assignEVEXPacked ins bld 16<rt> oprSz dst (Array.init a.Length lane)
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let private shImmOp ins bld opFn =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = halfToSingle (scalarSrc ins bld 16<rt> src2)
    let value = opFn (getImmValue imm) a
    assignScalar ins bld 16<rt> dst src1 (singleToHalf value)
  }

let vrndscaleph ins bld = phImmOp ins bld (rndScale bld 32<rt>)

let vrndscalesh ins bld = shImmOp ins bld (rndScale bld 32<rt>)

let vreduceph ins bld = phImmOp ins bld (reduce bld 32<rt>)

let vreducesh ins bld = shImmOp ins bld (reduce bld 32<rt>)

let vgetmantph ins bld = phImmOp ins bld (getMant bld 32<rt>)

let vgetmantsh ins bld = shImmOp ins bld (getMant bld 32<rt>)

let vgetexpph ins bld = phUnOp ins bld (getExp bld 32<rt>)

let vgetexpsh ins bld = shUnOp ins bld (getExp bld 32<rt>)

/// VCMPPH and VCMPSH write a mask, one bit per element, from the same
/// predicates the single- and double-precision compares take.
let vcmpph (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSz src1
    let b = transOprToArr ins bld true 16<rt> 4 oprSz src2
    let bit i =
      let c = tmpVar bld 1<rt>
      let x = halfToSingle a[i]
      let y = halfToSingle b[i]
      SSELifter.cmppCond bld ins imm false c x y
      c
    assignMask ins bld dst (Array.init a.Length bit)
  }

let vcmpsh (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let a = halfToSingle (scalarSrc ins bld 16<rt> src1)
    let b = halfToSingle (scalarSrc ins bld 16<rt> src2)
    let c = tmpVar bld 1<rt>
    SSELifter.cmppCond bld ins imm false c a b
    assignMask ins bld dst [| c |]
  }

let vfpclassph ins bld = vfpclassPacked ins bld 16<rt>

let vfpclasssh ins bld = vfpclassScalar ins bld 16<rt>

/// VCOMISH and VUCOMISH report on the low element in EFLAGS, exactly as the
/// single- and double-precision forms do: the two differ only in which NaN
/// raises, which changes no flag.
let private comish (ins: Instruction) bld =
  lift bld ins {
    let struct (opr1, opr2) = getTwoOprs ins
    let a = halfToSingle (scalarSrc ins bld 16<rt> opr1)
    let b = halfToSingle (scalarSrc ins bld 16<rt> opr2)
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    direct zf := AST.ite (AST.feq a b) AST.b1 AST.b0
    direct pf := AST.b0
    direct cf := AST.ite (AST.flt a b) AST.b1 AST.b0
    _when bld "IsNan" (isNaN 32<rt> a .| isNaN 32<rt> b)
      (block {
        direct zf := AST.b1
        direct pf := AST.b1
        direct cf := AST.b1 })
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let vcomish ins bld = comish ins bld

let vucomish ins bld = comish ins bld

/// VMOVSH moves one half between the low element of a vector register and
/// another such element or memory. The register-to-register form takes the
/// elements above the low one from its first source; a load clears them.
let vmovsh (ins: Instruction) bld =
  lift bld ins {
    match ins.Operands with
    | ThreeOperands(dst, src1, src2) ->
      assignScalar ins bld 16<rt> dst src1 (scalarSrc ins bld 16<rt> src2)
    | TwoOperands(dst, src) when isMemOpr dst ->
      let value = scalarSrc ins bld 16<rt> src
      let target = transOpr ins bld false dst
      let written =
        match opMaskVar bld ins with
        | ValueNone ->
          value
        | ValueSome k ->
          AST.ite (AST.xtlo 1<rt> k) value target
      direct (transOpr ins bld false dst) := written
    | TwoOperands(dst, src) ->
      let value = transOpr ins bld false src
      let struct (dstB, dstA) = transOpr128 ins bld false dst
      let written =
        match opMaskVar bld ins with
        | ValueNone ->
          value
        | ValueSome k ->
          let kept =
            if ins.IsZeroing then AST.num0 16<rt> else AST.xtlo 16<rt> dstA
          AST.ite (AST.xtlo 1<rt> k) value kept
      direct dstA := AST.zext 64<rt> written
      direct dstB := AST.num0 64<rt>
      fillZeroFromVLToMaxVL bld dst 128<rt> 512
    | _ ->
      raise InvalidOperandException
  }

/// A half converted to a 16-bit integer, which the cast cannot target
/// directly: it is made at 32 bits, which every half fits, and checked against
/// the destination's range -- a value outside it becomes the integer
/// indefinite the architecture writes there.
let private toSigned16 kind e =
  let wide = AST.cast kind 32<rt> e
  let bad = (wide ?< numI32 -32768 32<rt>) .| (wide ?> numI32 32767 32<rt>)
  AST.ite bad (numI32 0x8000 16<rt>) (AST.xtlo 16<rt> wide)

let private toUnsigned16 kind e =
  let wide = AST.cast kind 32<rt> e
  let bad = (wide ?< AST.num0 32<rt>) .| (wide ?> numI32 65535 32<rt>)
  AST.ite bad (numI64 0xFFFFL 16<rt>) (AST.xtlo 16<rt> wide)

let vcvtph2ps ins bld = cvtLanes ins bld 16<rt> 32<rt> halfToSingle

let vcvtph2psx ins bld = cvtLanes ins bld 16<rt> 32<rt> halfToSingle

let private half2Double h =
  AST.cast CastKind.FloatCast 64<rt> (halfToSingle h)

let vcvtph2pd ins bld = cvtLanes ins bld 16<rt> 64<rt> half2Double

let private double2Half d =
  singleToHalf (AST.cast CastKind.FloatCast 32<rt> d)

let vcvtpd2ph ins bld = cvtLanes ins bld 64<rt> 16<rt> double2Half

let vcvtps2phx ins bld = cvtLanes ins bld 32<rt> 16<rt> singleToHalf

/// VCVTPS2PH names its own rounding in the immediate, where every other
/// narrowing to a half rounds to nearest. Bit 2 asks for MXCSR's, which is
/// read as round-to-nearest here as everywhere.
let vcvtps2ph (ins: Instruction) bld =
  lift bld ins {
    let vl = vectorLength ins
    let struct (dst, src, imm) = getThreeOprs ins
    let s = transOprToArr ins bld true 32<rt> 2 vl src
    let imm = getImmValue imm
    let mode = if imm &&& 4L <> 0L then 0 else int (imm &&& 3L)
    assignEVEXPart ins bld 16<rt> dst (Array.map (singleToHalfWith mode) s)
  }

let private ph2int ins bld dstSz isTrunc =
  let kind = fToIKind ins isTrunc
  let conv h = AST.cast kind dstSz (halfToSingle h)
  cvtLanes ins bld 16<rt> dstSz conv

let vcvtph2dq ins bld = ph2int ins bld 32<rt> false

let vcvttph2dq ins bld = ph2int ins bld 32<rt> true

let vcvtph2qq ins bld = ph2int ins bld 64<rt> false

let vcvttph2qq ins bld = ph2int ins bld 64<rt> true

let private ph2uint32 ins bld isTrunc =
  let kind = fToIKind ins isTrunc
  cvtLanes ins bld 16<rt> 32<rt> (fun h -> toUnsigned32 kind (halfToSingle h))

let vcvtph2udq ins bld = ph2uint32 ins bld false

let vcvttph2udq ins bld = ph2uint32 ins bld true

let private ph2uint64 ins bld isTrunc =
  let kind = fToIKind ins isTrunc
  let conv h = toUnsigned64 kind 32<rt> (halfToSingle h)
  cvtLanes ins bld 16<rt> 64<rt> conv

let vcvtph2uqq ins bld = ph2uint64 ins bld false

let vcvttph2uqq ins bld = ph2uint64 ins bld true

let private ph2word ins bld isTrunc isSigned =
  let kind = fToIKind ins isTrunc
  let narrow = if isSigned then toSigned16 else toUnsigned16
  cvtLanes ins bld 16<rt> 16<rt> (fun h -> narrow kind (halfToSingle h))

let vcvtph2w ins bld = ph2word ins bld false true

let vcvttph2w ins bld = ph2word ins bld true true

let vcvtph2uw ins bld = ph2word ins bld false false

let vcvttph2uw ins bld = ph2word ins bld true false

let private int2ph ins bld srcSz isSigned =
  let kind = if isSigned then CastKind.SIntToFloat else CastKind.UIntToFloat
  let conv i = singleToHalf (AST.cast kind 32<rt> i)
  cvtLanes ins bld srcSz 16<rt> conv

let vcvtw2ph ins bld = int2ph ins bld 16<rt> true

let vcvtuw2ph ins bld = int2ph ins bld 16<rt> false

let vcvtdq2ph ins bld = int2ph ins bld 32<rt> true

let vcvtudq2ph ins bld = int2ph ins bld 32<rt> false

let vcvtqq2ph ins bld = int2ph ins bld 64<rt> true

let vcvtuqq2ph ins bld = int2ph ins bld 64<rt> false

/// The scalar conversions into a vector register's low element, whose upper
/// elements come from the first source as every scalar form's do.
let private cvtToScalar ins bld width srcWidth conv =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let value = conv (scalarSrc ins bld srcWidth src2)
    assignScalar ins bld width dst src1 value
  }

let vcvtsh2ss ins bld = cvtToScalar ins bld 32<rt> 16<rt> halfToSingle

let vcvtsh2sd ins bld = cvtToScalar ins bld 64<rt> 16<rt> half2Double

let vcvtss2sh ins bld = cvtToScalar ins bld 16<rt> 32<rt> singleToHalf

let vcvtsd2sh ins bld = cvtToScalar ins bld 16<rt> 64<rt> double2Half

/// VCVTSI2SH and VCVTUSI2SH read a general-purpose register or memory operand
/// rather than an element of a vector, so the source is taken whole.
let private cvtIntToSh (ins: Instruction) bld isSigned =
  lift bld ins {
    let kind = if isSigned then CastKind.SIntToFloat else CastKind.UIntToFloat
    let struct (dst, src1, src2) = getThreeOprs ins
    let value = transOpr ins bld false src2
    let half = singleToHalf (AST.cast kind 32<rt> value)
    assignScalar ins bld 16<rt> dst src1 half
  }

let vcvtsi2sh ins bld = cvtIntToSh ins bld true

let vcvtusi2sh ins bld = cvtIntToSh ins bld false

/// VCVTSH2SI and its relatives convert the low element into a general-purpose
/// register, whose width the destination names.
let private cvtShToInt (ins: Instruction) bld isTrunc isSigned =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let value = halfToSingle (scalarSrc ins bld 16<rt> src)
    let kind = fToIKind ins isTrunc
    let dstSz = AVXLifter.operandWidth bld dst
    let result =
      if isSigned then AST.cast kind dstSz value
      elif dstSz = 64<rt> then toUnsigned64 kind 32<rt> value
      else toUnsigned32 kind value
    sized dstSz (transOpr ins bld false dst) := result
  }

let vcvtsh2si ins bld = cvtShToInt ins bld false true

let vcvttsh2si ins bld = cvtShToInt ins bld true true

let vcvtsh2usi ins bld = cvtShToInt ins bld false false

let vcvttsh2usi ins bld = cvtShToInt ins bld true false

/// VBCSTNESH2PS reads one half from memory and fills every lane with the float
/// it widens to.
let vbcstnesh2ps (ins: Instruction) bld =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let value = halfToSingle (transOpr ins bld false src)
    let result = Array.create (oprSz / 32<rt>) value
    assignPackedInstr ins bld false 2 oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// VCVTNEEPH2PS and VCVTNEOPH2PS widen every other half of their source, the
/// even-numbered ones or the odd, into as many floats.
let private cvtnePh2ps (ins: Instruction) bld isOdd =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src) = getTwoOprs ins
    let s = transOprToArr ins bld true 32<rt> 2 oprSz src
    let pick e = if isOdd then AST.xthi 16<rt> e else AST.xtlo 16<rt> e
    let result = Array.map (fun e -> halfToSingle (pick e)) s
    assignPackedInstr ins bld false 2 oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vcvtneeph2ps ins bld = cvtnePh2ps ins bld false

let vcvtneoph2ps ins bld = cvtnePh2ps ins bld true

/// The complex forms read each pair of halves as one complex number: the real
/// part in the even element, the imaginary in the odd. Conjugating negates the
/// imaginary part of the first source, which turns two of the four signs
/// around. Every product is exact at single precision, so only the sums round
/// before the answer is narrowed back to a half.
let private complexPair conj ar ai br bi =
  let rr = AST.fmul ar br
  let ii = AST.fmul ai bi
  let ri = AST.fmul ar bi
  let ir = AST.fmul ai br
  if conj then
    struct (AST.fadd rr ii, AST.fsub ri ir)
  else
    struct (AST.fsub rr ii, AST.fadd ri ir)

let private complexPacked (ins: Instruction) bld conj accumulate =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let a = transOprToArr ins bld true 16<rt> 4 oprSz src1
    let b = transOprToArr ins bld true 16<rt> 4 oprSz src2
    let old = transOprToArr ins bld true 16<rt> 4 oprSz dst
    let accumulated i v =
      if accumulate then AST.fadd (halfToSingle old[i]) v else v
    let pairAt j =
      let ar = halfToSingle a[2 * j]
      let ai = halfToSingle a[2 * j + 1]
      let br = halfToSingle b[2 * j]
      let bi = halfToSingle b[2 * j + 1]
      let struct (re, im) = complexPair conj ar ai br bi
      [| singleToHalf (accumulated (2 * j) re)
         singleToHalf (accumulated (2 * j + 1) im) |]
    let result = Array.init (a.Length / 2) pairAt |> Array.concat
    assignEVEXPacked ins bld 16<rt> oprSz dst result
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

/// The low half of a doubleword and its high half, which is where a complex
/// pair's real and imaginary parts sit.
let private realOf e = AST.xtlo 16<rt> e

let private imagOf e = AST.extract e 16<rt> 16

/// The value one element of a scalar complex form writes, under its own bit of
/// the write mask: the pair takes two bits, one per half.
let private complexWritten (ins: Instruction) bld idx old value =
  match opMaskVar bld ins with
  | ValueNone ->
    value
  | ValueSome k ->
    let kept = if ins.IsZeroing then AST.num0 16<rt> else old
    AST.ite (AST.extract k 1<rt> idx) value kept

let private complexScalar (ins: Instruction) bld conj accumulate =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 ins bld false dst
    let struct (src1B, src1A) = transOpr128 ins bld false src1
    let a32 = AST.xtlo 32<rt> src1A
    let d32 = AST.xtlo 32<rt> dstA
    let b32 = scalarSrc ins bld 32<rt> src2
    let ar = halfToSingle (realOf a32)
    let ai = halfToSingle (imagOf a32)
    let br = halfToSingle (realOf b32)
    let bi = halfToSingle (imagOf b32)
    let struct (re, im) = complexPair conj ar ai br bi
    let accumulated old v =
      if accumulate then AST.fadd (halfToSingle old) v else v
    let low = realOf d32
    let high = imagOf d32
    let re = complexWritten ins bld 0 low (singleToHalf (accumulated low re))
    let im = complexWritten ins bld 1 high (singleToHalf (accumulated high im))
    direct dstA := AST.concat (AST.xthi 32<rt> src1A) (AST.concat im re)
    direct dstB := src1B
    fillZeroFromVLToMaxVL bld dst 128<rt> 512
  }

let vfmulcph ins bld = complexPacked ins bld false false

let vfcmulcph ins bld = complexPacked ins bld true false

let vfmaddcph ins bld = complexPacked ins bld false true

let vfcmaddcph ins bld = complexPacked ins bld true true

let vfmulcsh ins bld = complexScalar ins bld false false

let vfcmulcsh ins bld = complexScalar ins bld true false

let vfmaddcsh ins bld = complexScalar ins bld false true

let vfcmaddcsh ins bld = complexScalar ins bld true true

/// VP4DPWSSD runs four dot products over the same destination, one per
/// register of the block the first source names, each against one doubleword
/// of the 128-bit memory operand. The saturating form clamps after every
/// iteration rather than only at the end.
let private v4dpwssd (ins: Instruction) bld isSat =
  lift bld ins {
    let oprSz = getOperationSize ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let regs = AVXLifter.regQuadruple src1
    let words = transOprToArr ins bld true 16<rt> 4 128<rt> src2
    let d = transOprToArr ins bld true 32<rt> 2 oprSz dst
    let acc = Array.init d.Length (fun _ -> tmpVar bld 32<rt>)
    Array.iter2 (fun a e -> append bld { direct a := e }) acc d
    for j in 0 .. 3 do
      let a = transOprToArr ins bld true 16<rt> 4 oprSz regs[j]
      for i in 0 .. acc.Length - 1 do
        let lo = widen true a[2 * i] .* widen true words[2 * j]
        let hi = widen true a[2 * i + 1] .* widen true words[2 * j + 1]
        let total = widen true acc[i] .+ lo .+ hi
        append bld {
          direct acc[i] := clampDotProduct isSat false total
        }
    assignEVEXPacked ins bld 32<rt> oprSz dst acc
    fillZeroFromVLToMaxVL bld dst oprSz 512
  }

let vp4dpwssd ins bld = v4dpwssd ins bld false

let vp4dpwssds ins bld = v4dpwssd ins bld true

/// VEXP2 raises two to the power of each lane. What the manual promises is a
/// relative error under 2^-23 and nothing more, so the exact bits are the
/// implementation's to choose; this computes the real power, which is what
/// every other approximation in this front end does.
let private exp2Of _ width src =
  let bits = if width = 64<rt> then 0x4000000000000000L else 0x40000000L
  AST.fpow (numI64 bits width) src

let vexp2pd ins bld = packedUnOpWith ins bld 64<rt> exp2Of

let vexp2ps ins bld = packedUnOpWith ins bld 32<rt> exp2Of
