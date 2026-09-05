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

/// Hexadecimal floating point, the format System/360 began with and
/// z/Architecture still carries: a sign, a seven-bit characteristic biased by
/// 64, and a fraction read as a hexadecimal rather than a binary one, so the
/// value is the fraction times sixteen to the characteristic's power.
///
/// Each operation is carried out by turning its operands into the binary format
/// the evaluator can compute in, working there, and turning the result back.
/// For the short format that is exact -- a 24-bit fraction fits a double's 53
/// bits with room to spare. For the long format, whose fraction is 56 bits, the
/// three lowest bits of a result can differ from what the hardware would give.
/// Nothing a Linux compiler emits uses these instructions, so the alternative
/// would be to refuse them outright; a result correct to a double's precision
/// is the more useful answer, and this is where to look when it is not enough.
module internal B2R2.FrontEnd.S390.HexFloatLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390.LiftingUtils

/// The width of a short hexadecimal value.
let [<Literal>] ShortHFP = 32<rt>

/// The width of a long one.
let [<Literal>] LongHFP = 64<rt>

/// How many bits of fraction a format carries.
let private fracBits (w: RegType) = if w = ShortHFP then 24 else 56

/// The part of a floating-point register a value of the given width occupies:
/// a long one fills it, and a short one sits in its left half.
let private part (w: RegType) f = if w = LongHFP then f else AST.xthi w f

/// The double whose value a hexadecimal one has: the fraction read as an
/// integer, scaled by two to the power the characteristic names. The scale is
/// built as a double's bit pattern directly, since the exponent is data and so
/// cannot be a literal.
let private toDouble bld w e =
  let bits = fracBits w
  let frac = tmpVar bld 64<rt>
  let ch = tmpVar bld 64<rt>
  let mag = tmpVar bld 64<rt>
  let scale = tmpVar bld 64<rt>
  let out = tmpVar bld 64<rt>
  append bld {
    frac := zextTo 64<rt> e .& numG ((1L <<< bits) - 1L)
    ch := (zextTo 64<rt> e >> numG (int64 bits)) .& numG 0x7fL
    mag := AST.cast CastKind.SIntToFloat 64<rt> frac
  }
  (* Two to the power four times the unbiased characteristic, less the bits the
     fraction was read as an integer over. *)
  let k = (ch .- numG 64L) .* numG 4L .- numG (int64 bits)
  append bld {
    scale := (k .+ numG 1023L) << numG 52L
    out := AST.fmul mag scale
  }
  (* A zero fraction is a true zero whatever the characteristic says, and the
     sign travels as the bit it is. *)
  let signed = out .| (zextTo 64<rt> e .& numG 0x8000000000000000L
                       >> numG (63L - int64 (RegType.toBitWidth w - 1))
                       << numG 63L)
  AST.ite (frac == AST.num0 64<rt>) (AST.num0 64<rt>) signed

/// The hexadecimal value of a double, which is the harder direction: the
/// characteristic has to be chosen so that the fraction lands in the range a
/// hexadecimal one occupies, and the fraction shifted to suit it.
let private ofDouble bld w d =
  let bits = fracBits w
  let e = tmpVar bld 64<rt>
  let m = tmpVar bld 64<rt>
  let ch = tmpVar bld 64<rt>
  let frac = tmpVar bld 64<rt>
  let out = tmpVar bld 64<rt>
  append bld {
    e := (d >> numG 52L) .& numG 0x7ffL
    m := d .& numG 0xfffffffffffffL
  }
  (* The binary exponent runs from the bias; a hexadecimal characteristic must
     leave the fraction between a sixteenth and one, which pins it to the
     quotient below, and the remainder is how far the fraction shifts. *)
  let n = e .- numG 1023L
  append bld {
    ch := (n .+ numG 260L) ?>> numG 2L
  }
  let t = n .+ numG 260L .- (ch .* numG 4L)
  append bld {
    frac := (m .| numG 0x10000000000000L) << t
  }
  let frac56 = if bits = 56 then frac else frac >> numG 32L
  let body =
    (ch .& numG 0x7fL) << numG (int64 bits) .| (frac56 .& numG
                                                 ((1L <<< bits) - 1L))
  let sign = (d >> numG 63L) << numG (int64 bits + 7L)
  append bld {
    out := body .| sign
  }
  (* A zero, a denormal, or a characteristic outside the seven bits it has all
     come out as a true zero, which is what the architecture's underflow leaves
     when the exception is masked off. *)
  let bad = (e == AST.num0 64<rt>) .| (ch ?< AST.num0 64<rt>)
            .| (ch ?> numG 127L)
  narrowTo w (AST.ite bad (AST.num0 64<rt>) out)

/// A two-operand arithmetic instruction: the first operand supplies one input
/// and receives the result.
let arith ins insLen bld w f =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    a := toDouble bld w (part w d)
    let src =
      match o2 with
      | OpReg r2 -> part w (reg bld r2)
      | _ -> loadMem w (transMem bld o2)
    b := toDouble bld w src
    r := f a b
    part w d := ofDouble bld w r
  }

/// The same, but with a result twice as wide as the operands, which is what the
/// short-to-long multiplies produce.
let arithWiden ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    a := toDouble bld ShortHFP (part ShortHFP d)
    let src =
      match o2 with
      | OpReg r2 -> part ShortHFP (reg bld r2)
      | _ -> loadMem ShortHFP (transMem bld o2)
    b := toDouble bld ShortHFP src
    r := f a b
    d := ofDouble bld LongHFP r
  }

/// The condition code a comparison reports, which for these formats never has
/// an unordered case to report -- a hexadecimal value cannot be a NaN.
let compare ins insLen bld w =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    a := toDouble bld w (part w (oprRegVar bld o1))
    let src =
      match o2 with
      | OpReg r2 -> part w (reg bld r2)
      | _ -> loadMem w (transMem bld o2)
    b := toDouble bld w src
    let hi = AST.ite (AST.flt a b) (numCC 1) (numCC 2)
    ccVar bld := AST.ite (AST.feq a b) (numCC 0) hi
  }

/// The sign-manipulating loads, which work on the bits rather than the value.
let loadSign ins insLen bld w f setsCC =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let sign = numI64 (1L <<< (RegType.toBitWidth w - 1)) w
    let t = tmpVar bld w
    t := f (part w (oprRegVar bld o2)) sign
    if setsCC then
      let v = tmpVar bld 64<rt>
      v := toDouble bld w t
      let hi = AST.ite (AST.flt v (AST.num0 64<rt>)) (numCC 1) (numCC 2)
      ccVar bld := AST.ite (AST.feq v (AST.num0 64<rt>)) (numCC 0) hi
    else
      ()
    part w d := t
  }

/// HALVE, which is a multiply by a half and so needs no rounding decision.
let halve ins insLen bld w =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    v := toDouble bld w (part w (oprRegVar bld o2))
    part w d := ofDouble bld w (AST.fmul v (numG 0x3fe0000000000000L))
  }

/// A move between the two hexadecimal formats.
let convertFormat ins insLen bld fromW toW =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    v := toDouble bld fromW (part fromW (oprRegVar bld o2))
    part toW d := ofDouble bld toW v
  }

/// LOAD FP INTEGER, which rounds to a whole number without leaving the format.
let roundToInt ins insLen bld w =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    v := toDouble bld w (part w (oprRegVar bld o2))
    let r = AST.cast CastKind.FtoFTrunc 64<rt> v
    part w d := ofDouble bld w r
  }

/// SQUARE ROOT.
let squareRoot ins insLen bld w =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    let src =
      match o2 with
      | OpReg r2 -> part w (reg bld r2)
      | _ -> loadMem w (transMem bld o2)
    v := toDouble bld w src
    part w d := ofDouble bld w (AST.fsqrt v)
  }

/// A conversion from a fixed-point value to a hexadecimal one.
let fromInt ins insLen bld w intW =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    let src = oprRegVar bld o2
    let n = if intW = GRSize then src else AST.xtlo intW src
    v := AST.cast CastKind.SIntToFloat 64<rt> n
    part w d := ofDouble bld w v
  }

/// A conversion from a hexadecimal value to a fixed-point one, which also
/// reports how the value stood against zero.
let toInt ins insLen bld w intW =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    let t = tmpVar bld intW
    v := toDouble bld w (part w (oprRegVar bld o2))
    t := AST.cast CastKind.FtoITrunc intW v
    let hi = AST.ite (AST.flt v (AST.num0 64<rt>)) (numCC 1) (numCC 2)
    ccVar bld := AST.ite (AST.feq v (AST.num0 64<rt>)) (numCC 0) hi
    if intW = GRSize then append bld { d := t } else append bld { low d := t }
  }

/// The conversions between the hexadecimal and the binary formats, which are
/// just the two conversions this module is built on, back to back.
let toBinary ins insLen bld fromW toW =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    v := toDouble bld fromW (part fromW (oprRegVar bld o2))
    if toW = ShortHFP then
      AST.xthi 32<rt> d := AST.cast CastKind.FloatCast 32<rt> v
    else
      d := v
  }

let fromBinary ins insLen bld fromW toW =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2) = getTwoOprs ins
    let d = oprRegVar bld o1
    let v = tmpVar bld 64<rt>
    let src = oprRegVar bld o2
    if fromW = ShortHFP then
      v := AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> src)
    else
      v := src
    part toW d := ofDouble bld toW v
  }

/// The multiply-and-add and multiply-and-subtract instructions, whose third
/// operand is the one added to or taken from the product.
let mulAdd ins insLen bld w subtract =
  lift bld (ins: Instruction) insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let d = oprRegVar bld o1
    let a = tmpVar bld 64<rt>
    let b = tmpVar bld 64<rt>
    let c = tmpVar bld 64<rt>
    let second =
      match o2 with
      | OpReg r2 -> part w (reg bld r2)
      | _ -> loadMem w (transMem bld o2)
    a := toDouble bld w second
    b := toDouble bld w (part w (oprRegVar bld o3))
    c := toDouble bld w (part w d)
    let prod = AST.fmul a b
    let r = if subtract then AST.fsub c prod else AST.fadd c prod
    part w d := ofDouble bld w r
  }

/// An instruction of the format this module does not model: the extended one,
/// whose 128 bits carry a 112-bit fraction that no type the IR has can hold.
let unsupported ins insLen bld =
  lift bld (ins: Instruction) insLen {
    AST.sideEffect UnsupportedInstruction
  }

/// Translates one hexadecimal floating-point instruction.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Opcode.AD | Opcode.ADR | Opcode.AW | Opcode.AWR ->
    arith ins insLen bld LongHFP AST.fadd
  | Opcode.AE | Opcode.AER | Opcode.AU | Opcode.AUR ->
    arith ins insLen bld ShortHFP AST.fadd
  | Opcode.SD | Opcode.SDR | Opcode.SW | Opcode.SWR ->
    arith ins insLen bld LongHFP AST.fsub
  | Opcode.SE | Opcode.SER | Opcode.SU | Opcode.SUR ->
    arith ins insLen bld ShortHFP AST.fsub
  | Opcode.MD | Opcode.MDR ->
    arith ins insLen bld LongHFP AST.fmul
  | Opcode.MEE | Opcode.MEER ->
    arith ins insLen bld ShortHFP AST.fmul
  | Opcode.MDE | Opcode.MDER ->
    arithWiden ins insLen bld AST.fmul
  | Opcode.DD | Opcode.DDR ->
    arith ins insLen bld LongHFP AST.fdiv
  | Opcode.DE | Opcode.DER ->
    arith ins insLen bld ShortHFP AST.fdiv
  | Opcode.CD | Opcode.CDR ->
    compare ins insLen bld LongHFP
  | Opcode.CE | Opcode.CER ->
    compare ins insLen bld ShortHFP
  | Opcode.LTDR ->
    loadSign ins insLen bld LongHFP (fun v _ -> v) true
  | Opcode.LTER ->
    loadSign ins insLen bld ShortHFP (fun v _ -> v) true
  | Opcode.LCDR ->
    loadSign ins insLen bld LongHFP (<+>) true
  | Opcode.LCER ->
    loadSign ins insLen bld ShortHFP (<+>) true
  | Opcode.LNDR ->
    loadSign ins insLen bld LongHFP (fun v s -> v .| s) true
  | Opcode.LNER ->
    loadSign ins insLen bld ShortHFP (fun v s -> v .| s) true
  | Opcode.LPER ->
    loadSign ins insLen bld ShortHFP (fun v s -> v .& AST.not s) true
  | Opcode.HDR ->
    halve ins insLen bld LongHFP
  | Opcode.HER ->
    halve ins insLen bld ShortHFP
  | Opcode.LDE | Opcode.LDER ->
    convertFormat ins insLen bld ShortHFP LongHFP
  | Opcode.LEDR ->
    convertFormat ins insLen bld LongHFP ShortHFP
  | Opcode.FIDR ->
    roundToInt ins insLen bld LongHFP
  | Opcode.FIER ->
    roundToInt ins insLen bld ShortHFP
  | Opcode.SQD | Opcode.SQDR ->
    squareRoot ins insLen bld LongHFP
  | Opcode.SQE | Opcode.SQER ->
    squareRoot ins insLen bld ShortHFP
  | Opcode.CEFR ->
    fromInt ins insLen bld ShortHFP WSize
  | Opcode.CDFR ->
    fromInt ins insLen bld LongHFP WSize
  | Opcode.CEGR ->
    fromInt ins insLen bld ShortHFP GRSize
  | Opcode.CDGR ->
    fromInt ins insLen bld LongHFP GRSize
  | Opcode.CFER ->
    toInt ins insLen bld ShortHFP WSize
  | Opcode.CFDR ->
    toInt ins insLen bld LongHFP WSize
  | Opcode.CGER ->
    toInt ins insLen bld ShortHFP GRSize
  | Opcode.CGDR ->
    toInt ins insLen bld LongHFP GRSize
  | Opcode.THDER ->
    toBinary ins insLen bld ShortHFP LongHFP
  | Opcode.THDR ->
    toBinary ins insLen bld LongHFP LongHFP
  | Opcode.TBEDR ->
    fromBinary ins insLen bld LongHFP ShortHFP
  | Opcode.TBDR ->
    fromBinary ins insLen bld LongHFP LongHFP
  | Opcode.MAD | Opcode.MADR ->
    mulAdd ins insLen bld LongHFP false
  | Opcode.MAE | Opcode.MAER ->
    mulAdd ins insLen bld ShortHFP false
  | Opcode.MSD | Opcode.MSDR ->
    mulAdd ins insLen bld LongHFP true
  | Opcode.MSE | Opcode.MSER ->
    mulAdd ins insLen bld ShortHFP true
  | _ ->
    unsupported ins insLen bld
