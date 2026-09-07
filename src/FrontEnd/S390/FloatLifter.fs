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

module internal B2R2.FrontEnd.S390.FloatLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390.LiftingUtils

/// The width of a long (double-precision) binary floating-point value.
let [<Literal>] LongFP = 64<rt>

/// The width of a short (single-precision) binary floating-point value.
let [<Literal>] ShortFP = 32<rt>

/// The part of a floating-point register a value of the given format occupies:
/// a long value fills the register, and a short one sits in its left half.
let private fpPart rt f = if rt = LongFP then f else AST.xthi rt f

/// The value a floating-point operand supplies in the given format, from a
/// register or from storage.
let private fpSrc bld rt o =
  match o with
  | OpReg r -> fpPart rt (reg bld r)
  | OpStore _ | OpStoreLen _ -> loadMem rt (transMem bld o)
  | _ -> raise InvalidOperandException

/// The condition code a floating-point comparison reports: the three a fixed
/// comparison gives, and a fourth for a pair no ordering relates -- which is
/// what a NaN operand leaves.
let private setCCFloat bld a b =
  append bld {
    let unordered = AST.ite (AST.fgt a b) (numCC 2) (numCC 3)
    let hi = AST.ite (AST.flt a b) (numCC 1) unordered
    ccVar bld := AST.ite (AST.feq a b) (numCC 0) hi
  }

/// A two-operand floating-point operation, whose result replaces the first
/// operand. Addition and subtraction go on to report how the result stands
/// against zero; multiplication and division leave the code alone.
let arith ins bld rt f setsCC =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := f (fpPart rt d) (fpSrc bld rt o2)
    if setsCC then setCCFloat bld t (AST.num0 rt) else ()
    fpPart rt d := t
  }

/// COMPARE, which reports how the operands stand and changes nothing else.
let compare ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let a = tmpVar bld rt
    let b = tmpVar bld rt
    a := fpPart rt (oprRegVar bld o1)
    b := fpSrc bld rt o2
    setCCFloat bld a b
  }

/// A load that reports how what it loaded stands against zero, which for a
/// NaN is the fourth code.
let loadTest ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := fpSrc bld rt o2
    setCCFloat bld t (AST.num0 rt)
    fpPart rt d := t
  }

/// The sign bit of a value of the given floating-point format.
let private signBit rt =
  if rt = LongFP then numI64 System.Int64.MinValue LongFP
  else numI64 (int64 System.Int32.MinValue) ShortFP

/// The sign-manipulating loads -- complement, positive, and negative -- each of
/// which works on the bits rather than the value, so a NaN keeps its payload.
let loadSign ins bld rt f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let t = tmpVar bld rt
    t := f (fpSrc bld rt o2) (signBit rt)
    setCCFloat bld t (AST.num0 rt)
    fpPart rt d := t
  }

/// A plain move of a floating-point value from one register to another, which
/// touches no condition code.
let move ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    fpPart rt d := fpSrc bld rt o2
  }

/// LOAD ZERO, which is how a register is cleared without touching storage.
let loadZero ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, _) = getTwoOprs ins
    let d = oprRegVar bld o1
    fpPart rt d := AST.num0 rt
  }

/// SQUARE ROOT.
let sqrt ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    fpPart rt d := AST.fsqrt (fpSrc bld rt o2)
  }

/// COPY SIGN: the first operand takes the third's sign and the second's
/// magnitude.
let copySign ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let sign = signBit LongFP
    d := (oprRegVar bld o3 .& sign)
         .| (oprRegVar bld o2 .& AST.not sign)
  }

/// TEST DATA CLASS: the second operand is not a value in storage but the
/// address the base, index, and displacement come to, whose low twelve bits
/// name a set of the twelve classes a floating-point value can fall in -- zero,
/// normal, subnormal, infinity, quiet and signalling NaN, each split by sign,
/// in that order from the left. The condition code says whether the first
/// operand's class is one of them, which is how a program asks "is this
/// finite?" without a comparison that a NaN would trap.
let testDataClass ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let width = RegType.toBitWidth rt
    let fracBits = if rt = LongFP then 52 else 23
    let expAll = (1L <<< (width - 1 - fracBits)) - 1L
    let v = tmpVar bld GRSize
    let cls = tmpVar bld GRSize
    v := zextTo GRSize (fpPart rt (oprRegVar bld o1))
    let sign = (v >> numG (int64 width - 1L)) .& AST.num1 GRSize
    let exponent = (v >> numG (int64 fracBits)) .& numG expAll
    let frac = v .& numG ((1L <<< fracBits) - 1L)
    let quiet = (v >> numG (int64 fracBits - 1L)) .& AST.num1 GRSize
    let nan = AST.ite (quiet == AST.num1 GRSize) (numG 4L) (numG 5L)
    let big = AST.ite (frac == AST.num0 GRSize) (numG 3L) nan
    let small = AST.ite (frac == AST.num0 GRSize) (numG 0L) (numG 2L)
    let high = AST.ite (exponent == numG expAll) big (numG 1L)
    cls := AST.ite (exponent == AST.num0 GRSize) small high
    let bit = numG 0x800L >> ((cls .+ cls) .+ sign)
    let selected = transMem bld o2 .& bit
    ccVar bld := AST.ite (selected == AST.num0 GRSize)
                         (numCC 0)
                         (numCC 1)
  }

/// The first two operands and the rounding mode of a conversion. The
/// architecture gives these in a two-operand form that rounds as the
/// floating-point control says, and in longer ones that name a mode.
let private convOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2, 0us)
  | ThreeOperands(o1, o2, m) -> struct (o1, o2, oprMask m)
  | FourOperands(o1, o2, m, _) -> struct (o1, o2, oprMask m)
  | _ -> raise InvalidOperandException

/// The rounding a conversion to an integer applies. A mode of zero defers to
/// the floating-point control, whose initial state -- and the only one a
/// program that never sets it has -- rounds to nearest.
let private intRounding (m: Mask) =
  match m &&& 0xfus with
  | 5us -> CastKind.FtoITrunc
  | 6us -> CastKind.FtoICeil
  | 7us -> CastKind.FtoIFloor
  | _ -> CastKind.FtoIRound

/// A conversion from a fixed-point value to a floating-point one.
let fromInt ins bld rt intW signed =
  lift bld (ins: Instruction) {
    let struct (o1, o2, _) = convOprs ins
    let d = oprRegVar bld o1
    let src = oprRegVar bld o2
    let v = if intW = GRSize then src else AST.xtlo intW src
    let kind = if signed then CastKind.SIntToFloat else CastKind.UIntToFloat
    fpPart rt d := AST.cast kind rt v
  }

/// A conversion from a floating-point value to a fixed-point one, which also
/// reports how the value stood against zero.
let toInt ins bld rt intW =
  lift bld (ins: Instruction) {
    let struct (o1, o2, m) = convOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld rt
    let t = tmpVar bld intW
    v := fpPart rt (oprRegVar bld o2)
    t := AST.cast (intRounding m) intW v
    setCCFloat bld v (AST.num0 rt)
    if intW = GRSize then append bld { d := t } else append bld { low d := t }
  }

/// The rounding a conversion to an integral floating-point value applies,
/// which follows the same mask as a conversion to a fixed-point one.
let private floatRounding (m: Mask) =
  match m &&& 0xfus with
  | 5us -> CastKind.FtoFTrunc
  | 6us -> CastKind.FtoFCeil
  | 7us -> CastKind.FtoFFloor
  | _ -> CastKind.FtoFRound

/// LOAD FP INTEGER: the value rounded to a whole number, still in floating
/// point, which is how a program floors or truncates without leaving the
/// format.
let roundToInt ins bld rt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, m) = convOprs ins
    let d = oprRegVar bld o1
    let v = AST.cast (floatRounding m) rt (fpPart rt (oprRegVar bld o2))
    fpPart rt d := v
  }

/// The sign-manipulating loads that leave the condition code alone, which is
/// what separates them from the ones named for the test they also perform.
let loadSignQuiet ins bld f =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    d := f (oprRegVar bld o2) (signBit LongFP)
  }

/// A conversion between the two floating-point formats.
let convertFormat ins bld fromRt toRt =
  lift bld (ins: Instruction) {
    let struct (o1, o2, _) = convOprs ins
    let d = oprRegVar bld o1
    let v = AST.cast CastKind.FloatCast toRt (fpPart fromRt (oprRegVar bld o2))
    fpPart toRt d := v
  }

/// MULTIPLY AND ADD, and MULTIPLY AND SUBTRACT, whose second and third
/// operands make the product: the add form adds the first operand to it and the
/// subtract form takes the first operand from it, which is the order a compiler
/// relies on when it turns a fused multiply-subtract into one instruction.
let mulAdd ins bld rt subtract =
  lift bld (ins: Instruction) {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let a = tmpVar bld rt
    let b = tmpVar bld rt
    a := fpSrc bld rt o2
    b := fpPart rt (oprRegVar bld o3)
    let prod = AST.fmul a b
    let r =
      if subtract then AST.fsub prod (fpPart rt d)
      else AST.fadd (fpPart rt d) prod
    fpPart rt d := r
  }

/// MULTIPLY, short to long: two short values make a long product, so nothing of
/// it is lost.
let mulWiden ins bld =
  lift bld (ins: Instruction) {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = tmpVar bld LongFP
    let b = tmpVar bld LongFP
    let widen e = AST.cast CastKind.FloatCast LongFP e
    a := widen (fpPart ShortFP d)
    b := widen (fpSrc bld ShortFP o2)
    d := AST.fmul a b
  }

/// DIVIDE TO INTEGER, which hands back both the whole part of the quotient and
/// the remainder -- what a language's floating-point modulus is built from.
let divideToInteger ins bld rt =
  lift bld (ins: Instruction) {
    let o = oprArray ins
    let d = oprRegVar bld o[0]
    let q = oprRegVar bld o[2]
    let a = tmpVar bld rt
    let b = tmpVar bld rt
    let whole = tmpVar bld rt
    a := fpPart rt d
    b := fpPart rt (oprRegVar bld o[1])
    whole := AST.cast CastKind.FtoFTrunc rt (AST.fdiv a b)
    fpPart rt d := AST.fsub a (AST.fmul whole b)
    fpPart rt q := whole
    setCC bld 0
  }

/// SET BFP ROUNDING MODE, which writes the mode the second operand's address
/// names into the floating-point control register's rightmost bits.
let setRoundingMode ins bld width =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    let fpc = reg bld Register.FPC
    let mask = numI32 ((1 <<< width) - 1) WSize
    fpc := (fpc .& AST.not mask)
           .| (narrowTo WSize (transMem bld o) .& mask)
  }

/// The extended binary format is 128 bits wide and lives in a pair of
/// floating-point registers: the even one carries the sign, the fifteen-bit
/// exponent, and the top of the fraction, and its partner the rest.
let private extPair bld r =
  struct (reg bld (r: Register), reg bld (RegisterHelper.getFPRpairReg r))

/// Whether a register begins one of the pairs an extended value may live in.
/// Only eight of the sixteen do; an encoding that names any other is a
/// specification exception on real hardware, so lifting it to the trap the
/// emulator rejects is the faithful answer -- and it keeps the lifter from
/// asking for a partner that does not exist.
let private startsPair (r: Register) =
  match int r - int Register.FPR0 with
  | 0 | 1 | 4 | 5 | 8 | 9 | 12 | 13 -> true
  | _ -> false

/// The trap an encoding that names no real pair raises.
let private specException ins bld =
  lift bld (ins: Instruction) {
    AST.sideEffect UndefinedInstruction
  }

/// Whether an extended value is a NaN, which is what makes a comparison
/// unordered: every exponent bit set and a fraction that is not zero.
let private extIsNaN hi lo =
  let expAll = numI64 0x7fff000000000000L 64<rt>
  let fracHi = hi .& numI64 0x0000ffffffffffffL 64<rt>
  ((hi .& expAll) == expAll)
  .& ((fracHi != AST.num0 64<rt>) .| (lo != AST.num0 64<rt>))

/// Whether an extended value is a zero of either sign.
let private extIsZero hi lo =
  ((hi .& numI64 0x7fffffffffffffffL 64<rt>) == AST.num0 64<rt>)
  .& (lo == AST.num0 64<rt>)

/// The condition code an extended value's standing against zero gives.
let private setCCExt bld hi lo =
  append bld {
    let neg =
      AST.ite ((hi >> numI64 63L 64<rt>) == AST.num1 64<rt>) (numCC 1) (numCC 2)
    let ordered = AST.ite (extIsZero hi lo) (numCC 0) neg
    ccVar bld := AST.ite (extIsNaN hi lo) (numCC 3) ordered
  }

/// LOAD, LOAD ZERO, and the sign-manipulating loads of the extended format,
/// which work on the bits and so are exact whatever the fraction holds.
let extLoadSign ins bld f setsCC =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1) && startsPair (oprReg o2)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let struct (shi, slo) = extPair bld (oprReg o2)
    let hi = tmpVar bld 64<rt>
    let lo = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      hi := f shi (numI64 System.Int64.MinValue 64<rt>)
      lo := slo
      if setsCC then setCCExt bld hi lo else ()
      dhi := hi
      dlo := lo
    }

let extLoadZero ins bld =
  let struct (o1, _) = getTwoOprs ins
  if not (startsPair (oprReg o1)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    lift bld (ins: Instruction) {
      dhi := AST.num0 64<rt>
      dlo := AST.num0 64<rt>
    }

/// COMPARE of two extended values, done on the bit patterns: for anything but
/// a NaN, the format orders sign and magnitude the way the integers do, so no
/// 128-bit arithmetic is needed to get the answer exactly right.
let extCompare ins bld =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1) && startsPair (oprReg o2)) then
    specException ins bld
  else
    let struct (ahi0, alo0) = extPair bld (oprReg o1)
    let struct (bhi0, blo0) = extPair bld (oprReg o2)
    let ahi = tmpVar bld 64<rt>
    let alo = tmpVar bld 64<rt>
    let bhi = tmpVar bld 64<rt>
    let blo = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      ahi := ahi0
      alo := alo0
      bhi := bhi0
      blo := blo0
      let asign = (ahi >> numI64 63L 64<rt>) == AST.num1 64<rt>
      let bsign = (bhi >> numI64 63L 64<rt>) == AST.num1 64<rt>
      let amag = ahi .& numI64 0x7fffffffffffffffL 64<rt>
      let bmag = bhi .& numI64 0x7fffffffffffffffL 64<rt>
      (* Magnitudes compare as the pair of unsigned words they are. *)
      let magGreater = (amag .> bmag) .| ((amag == bmag) .& (alo .> blo))
      let magEqual = (amag == bmag) .& (alo == blo)
      let bothZero = extIsZero ahi alo .& extIsZero bhi blo
      let sameSign =
        AST.ite magEqual
                (numCC 0)
                (AST.ite (magGreater != asign) (numCC 2) (numCC 1))
      let diffSign = AST.ite asign (numCC 1) (numCC 2)
      let ordered =
        AST.ite bothZero (numCC 0) (AST.ite (asign == bsign) sameSign diffSign)
      let unordered = extIsNaN ahi alo .| extIsNaN bhi blo
      ccVar bld := AST.ite unordered (numCC 3) ordered
    }

/// TEST DATA CLASS for the extended format, which asks the same twelve-way
/// question the narrower ones do.
let extTestDataClass ins bld =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1)) then
    specException ins bld
  else
    let struct (hi0, lo0) = extPair bld (oprReg o1)
    let hi = tmpVar bld 64<rt>
    let lo = tmpVar bld 64<rt>
    let cls = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      hi := hi0
      lo := lo0
      let sign = (hi >> numI64 63L 64<rt>) .& AST.num1 64<rt>
      let expo = (hi >> numI64 48L 64<rt>) .& numI64 0x7fffL 64<rt>
      let fracZero =
        ((hi .& numI64 0x0000ffffffffffffL 64<rt>) == AST.num0 64<rt>)
        .& (lo == AST.num0 64<rt>)
      let quiet = (hi >> numI64 47L 64<rt>) .& AST.num1 64<rt>
      let nan =
        AST.ite (quiet == AST.num1 64<rt>) (numI64 4L 64<rt>) (numI64 5L 64<rt>)
      let big = AST.ite fracZero (numI64 3L 64<rt>) nan
      let small = AST.ite fracZero (AST.num0 64<rt>) (numI64 2L 64<rt>)
      let high = AST.ite (expo == numI64 0x7fffL 64<rt>) big (AST.num1 64<rt>)
      cls := AST.ite (expo == AST.num0 64<rt>) small high
      let bit = numI64 0x800L 64<rt> >> ((cls .+ cls) .+ sign)
      let selected = transMem bld o2 .& bit
      ccVar bld := AST.ite (selected == AST.num0 64<rt>)
                           (numCC 0)
                           (numCC 1)
    }

/// Where a fraction of the given width sits in an extended value's two words:
/// forty-eight of its bits fit in the even register and the rest spill into
/// its partner, left-aligned there.
let private extSplitFrac frac fbits =
  if fbits <= 48 then
    struct (frac << numI64 (48L - int64 fbits) 64<rt>, AST.num0 64<rt>)
  else
    let rshf = frac >> numI64 (int64 fbits - 48L) 64<rt>
    let lshf = frac << numI64 (112L - int64 fbits) 64<rt>
    struct (rshf, lshf)

/// The reverse: the fraction of the given width the two words hold, cut rather
/// than rounded when the width asked for is the narrower.
let private extJoinFrac hi lo fbits =
  let top = hi .& numI64 0x0000ffffffffffffL 64<rt>
  if fbits <= 48 then
    top >> numI64 (48L - int64 fbits) 64<rt>
  else
    (top << numI64 (int64 fbits - 48L) 64<rt>)
    .| (lo >> numI64 (112L - int64 fbits) 64<rt>)

/// A widening to the extended format, which loses nothing: a longer fraction
/// holds a shorter one exactly, so this is a matter of moving the fields.
let extFromNarrow ins bld fromRt =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let src = tmpVar bld 64<rt>
    let expo = tmpVar bld 64<rt>
    let frac = tmpVar bld 64<rt>
    let bias = if fromRt = LongFP then 1023L else 127L
    let fbits = if fromRt = LongFP then 52 else 23
    lift bld (ins: Instruction) {
      let raw =
        match o2 with
        | OpReg r -> zextTo 64<rt> (fpPart fromRt (reg bld r))
        | _ -> zextTo 64<rt> (loadMem fromRt (transMem bld o2))
      src := raw
      let width = RegType.toBitWidth fromRt
      let sign = (src >> numI64 (int64 width - 1L) 64<rt>) .& AST.num1 64<rt>
      expo := (src >> numI64 (int64 fbits) 64<rt>)
              .& numI64 ((1L <<< (width - 1 - fbits)) - 1L) 64<rt>
      frac := src .& numI64 ((1L <<< fbits) - 1L) 64<rt>
      let newExp = expo .- numI64 bias 64<rt> .+ numI64 16383L 64<rt>
      let struct (hiFrac, loFrac) = extSplitFrac frac fbits
      let hi =
        (sign << numI64 63L 64<rt>)
        .| ((newExp .& numI64 0x7fffL 64<rt>) << numI64 48L 64<rt>)
        .| hiFrac
      let zero = expo == AST.num0 64<rt>
      dhi := AST.ite zero (sign << numI64 63L 64<rt>) hi
      dlo := AST.ite zero (AST.num0 64<rt>) loFrac
    }

/// A narrowing from the extended format, which cannot keep every bit: the
/// fraction is cut rather than rounded, so a result can differ from the
/// hardware's in its last place.
let extToNarrow ins bld toRt =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o2)) then
    specException ins bld
  else
    let d = oprRegVar bld o1
    let struct (shi, slo) = extPair bld (oprReg o2)
    let hi = tmpVar bld 64<rt>
    let expo = tmpVar bld 64<rt>
    let bias = if toRt = LongFP then 1023L else 127L
    let fbits = if toRt = LongFP then 52 else 23
    let width = RegType.toBitWidth toRt
    lift bld (ins: Instruction) {
      hi := shi
      expo := (hi >> numI64 48L 64<rt>) .& numI64 0x7fffL 64<rt>
      let sign = (hi >> numI64 63L 64<rt>) .& AST.num1 64<rt>
      let frac = extJoinFrac hi slo fbits
      let newExp = expo .- numI64 16383L 64<rt> .+ numI64 bias 64<rt>
      let value =
        (sign << numI64 (int64 width - 1L) 64<rt>)
        .| (newExp << numI64 (int64 fbits) 64<rt>)
        .| frac
      let zero = extIsZero hi slo
      let out = AST.ite zero (sign << numI64 (int64 width - 1L) 64<rt>) value
      fpPart toRt d := narrowTo toRt out
    }

/// Splits a widened integer into a sign bit and a magnitude. An unsigned value
/// is its own magnitude and carries no sign.
let private splitSignAndMagnitude bld signed raw parts =
  append bld {
    let sign, mag = parts
    if signed then
      sign := AST.ite (raw ?< AST.num0 64<rt>)
                      (AST.num1 64<rt>)
                      (AST.num0 64<rt>)
      mag := AST.ite (raw ?< AST.num0 64<rt>) (AST.neg raw) raw
    else
      sign := AST.num0 64<rt>
      mag := raw
  }

/// Where the leftmost one bit stands. Every bit above the first is tried, and
/// the highest one that is set is the answer; a magnitude of zero has none and
/// the answer stays at zero.
let private highestSetBit mag =
  let mutable pos = AST.num0 64<rt>
  for i in 1 .. 63 do
    let isOne =
      ((mag >> numI64 (int64 i) 64<rt>) .& AST.num1 64<rt>) == AST.num1 64<rt>
    pos <- AST.ite isOne (numI64 (int64 i) 64<rt>) pos
  pos

/// A conversion from a fixed-point value to the extended format, which is exact
/// -- a 112-bit fraction holds any integer a register can.
let extFromInt ins bld intW signed =
  let struct (o1, o2, _) = convOprs ins
  if not (startsPair (oprReg o1)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let src = oprRegVar bld o2
    let raw = tmpVar bld 64<rt>
    let mag = tmpVar bld 64<rt>
    let sign = tmpVar bld 64<rt>
    let shift = tmpVar bld 64<rt>
    let hi = tmpVar bld 64<rt>
    let lo = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      let widened =
        if intW = GRSize then src
        elif signed then AST.sext 64<rt> (AST.xtlo intW src)
        else AST.zext 64<rt> (AST.xtlo intW src)
      raw := widened
      splitSignAndMagnitude bld signed raw (sign, mag)
      (* the leftmost one bit fixes the exponent, and the bits below it become
         the fraction, left-aligned in the field *)
      shift := highestSetBit mag
      let expo = numI64 16383L 64<rt> .+ shift
      let frac = mag .& ((AST.num1 64<rt> << shift) .- AST.num1 64<rt>)
      (* Forty-eight of the fraction's bits live in the even register and the
         rest in its partner, so a shift of the whole becomes the two it is made
         of. *)
      let wide = shift .> numI64 48L 64<rt>
      let hiFrac =
        AST.ite wide (frac >> (shift .- numI64 48L 64<rt>))
                     (frac << (numI64 48L 64<rt> .- shift))
      let loFrac =
        AST.ite wide (frac << (numI64 112L 64<rt> .- shift)) (AST.num0 64<rt>)
      hi := (sign << numI64 63L 64<rt>)
            .| (expo << numI64 48L 64<rt>)
            .| (hiFrac .& numI64 0x0000ffffffffffffL 64<rt>)
      lo := loFrac
      let isZero = mag == AST.num0 64<rt>
      dhi := AST.ite isZero (sign << numI64 63L 64<rt>) hi
      dlo := AST.ite isZero (AST.num0 64<rt>) lo
    }

/// A conversion from the extended format to a fixed-point value, truncating
/// toward zero, which is exact for anything the integer can hold.
let extToInt ins bld intW =
  let struct (o1, o2, _) = convOprs ins
  if not (startsPair (oprReg o2)) then
    specException ins bld
  else
    let d = oprRegVar bld o1
    let struct (shi, slo) = extPair bld (oprReg o2)
    let hi = tmpVar bld 64<rt>
    let expo = tmpVar bld 64<rt>
    let mant = tmpVar bld 64<rt>
    let out = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      hi := shi
      expo := ((hi >> numI64 48L 64<rt>) .& numI64 0x7fffL 64<rt>)
              .- numI64 16383L 64<rt>
      (* The fraction with its implicit one restored, left-aligned so that one
         shift right by the exponent's distance from it yields the integer. *)
      mant := (AST.num1 64<rt> << numI64 48L 64<rt>)
              .| (hi .& numI64 0x0000ffffffffffffL 64<rt>)
      let big = expo ?>= numI64 48L 64<rt>
      let value =
        AST.ite big (mant << (expo .- numI64 48L 64<rt>))
                    (mant >> (numI64 48L 64<rt> .- expo))
      let negative = (hi >> numI64 63L 64<rt>) == AST.num1 64<rt>
      out := AST.ite (expo ?< AST.num0 64<rt>) (AST.num0 64<rt>) value
      out := AST.ite negative (AST.neg out) out
      setCCExt bld hi slo
      if intW = GRSize then append bld { d := out }
      else append bld { low d := AST.xtlo intW out }
    }

/// The double an extended value comes nearest to, as the bits of one. Fifty-two
/// of the 112 fraction bits survive -- the even register's forty-eight and four
/// more from its partner -- and the rest are cut away.
let private extAsDouble hi lo =
  let sign = (hi >> numI64 63L 64<rt>) .& AST.num1 64<rt>
  let expo = (hi >> numI64 48L 64<rt>) .& numI64 0x7fffL 64<rt>
  let frac = extJoinFrac hi lo 52
  let value =
    (sign << numI64 63L 64<rt>)
    .| (((expo .- numI64 16383L 64<rt> .+ numI64 1023L 64<rt>)
         .& numI64 0x7ffL 64<rt>) << numI64 52L 64<rt>)
    .| frac
  AST.ite (extIsZero hi lo) (sign << numI64 63L 64<rt>) value

/// The extended value a double widens to, which loses nothing: the wider
/// fraction holds the narrower one exactly.
let private extOfDouble src =
  let sign = (src >> numI64 63L 64<rt>) .& AST.num1 64<rt>
  let expo = (src >> numI64 52L 64<rt>) .& numI64 0x7ffL 64<rt>
  let frac = src .& numI64 0xfffffffffffffL 64<rt>
  let struct (hiFrac, loFrac) = extSplitFrac frac 52
  let hi =
    (sign << numI64 63L 64<rt>)
    .| (((expo .- numI64 1023L 64<rt> .+ numI64 16383L 64<rt>)
         .& numI64 0x7fffL 64<rt>) << numI64 48L 64<rt>)
    .| hiFrac
  let zero1 = AST.ite (expo == AST.num0 64<rt>) (sign << numI64 63L 64<rt>) hi
  let zero2 = AST.ite (expo == AST.num0 64<rt>) (AST.num0 64<rt>) loFrac
  struct (zero1, zero2)

/// Writes a double back to an extended register pair, which is where every
/// operation below lands.
let private extPutDouble bld dhi dlo src =
  append bld {
    let struct (hi, lo) = extOfDouble src
    dhi := hi
    dlo := lo
  }

/// The arithmetic of the extended format, carried out in double precision. No
/// type the IR has holds a 112-bit fraction, so each operand is rounded to the
/// nearest double, the operation is done there, and the result is widened
/// back: a program that asked for the extra precision gets an answer good to
/// 53 bits rather than 113. Addition and subtraction report how the result
/// stands against zero, as their narrower kin do.
let extArith ins bld f setsCC =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1) && startsPair (oprReg o2)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let struct (shi, slo) = extPair bld (oprReg o2)
    let r = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      r := f (extAsDouble dhi dlo) (extAsDouble shi slo)
      if setsCC then setCCFloat bld r (AST.num0 64<rt>) else ()
      extPutDouble bld dhi dlo r
    }

/// SQUARE ROOT of an extended value, in the same double precision.
let extSqrt ins bld =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1) && startsPair (oprReg o2)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let struct (shi, slo) = extPair bld (oprReg o2)
    let r = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      r := AST.unop UnOpType.FSQRT (extAsDouble shi slo)
      extPutDouble bld dhi dlo r
    }

/// MULTIPLY (long to extended), whose operands are two long values and whose
/// product fills a register pair. The first of them is the long value in the
/// pair's even register.
let extMulLong ins bld =
  let struct (o1, o2) = getTwoOprs ins
  if not (startsPair (oprReg o1)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let r = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      r := AST.fmul dhi (fpSrc bld LongFP o2)
      extPutDouble bld dhi dlo r
    }

/// LOAD FP INTEGER of an extended value, rounded in double precision.
let extRoundToInt ins bld =
  let struct (o1, o2, m) = convOprs ins
  if not (startsPair (oprReg o1) && startsPair (oprReg o2)) then
    specException ins bld
  else
    let struct (dhi, dlo) = extPair bld (oprReg o1)
    let struct (shi, slo) = extPair bld (oprReg o2)
    let r = tmpVar bld 64<rt>
    lift bld (ins: Instruction) {
      r := AST.cast (floatRounding m) 64<rt> (extAsDouble shi slo)
      extPutDouble bld dhi dlo r
    }

/// SET and EXTRACT of the floating-point control register, which a program
/// reads and writes to choose a rounding mode and to see which exceptions it
/// has raised.
let setFpc ins bld =
  lift bld (ins: Instruction) {
    let d = oprRegVar bld (getOneOpr ins)
    reg bld Register.FPC := low d
  }

let extractFpc ins bld =
  lift bld (ins: Instruction) {
    let d = oprRegVar bld (getOneOpr ins)
    low d := reg bld Register.FPC
  }

let loadFpc ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    reg bld Register.FPC := loadMem WSize (transMem bld o)
  }

let storeFpc ins bld =
  lift bld (ins: Instruction) {
    let o = getOneOpr ins
    storeMem (transMem bld o) (reg bld Register.FPC)
  }
