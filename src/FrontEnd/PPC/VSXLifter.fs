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
/// Lifts the VSX loads and stores ISA 3.0 and 3.1 added, and the moves beside
/// them. A vector-scalar register is kept as two 64-bit halves: doubleword 0,
/// the high one, in the register an operand names (an FPR for VSR0-31, a
/// vector register's high half for VSR32-63), and doubleword 1 in the next.
/// Byte element 0 of a vector-scalar register is the most significant byte of
/// doubleword 0, whatever the byte order of the guest.
/// </summary>
module internal B2R2.FrontEnd.PPC.VSXLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper
open B2R2.FrontEnd.PPC.LiftingUtils

/// The register holding doubleword 1 of the vector-scalar register whose
/// doubleword 0 the given register holds.
let private lowHalfOf (reg: Register) =
  if reg >= Register.V0A then getLowHalf reg else getVsxLowHalf reg

/// The two halves of the vector-scalar register an operand names, doubleword
/// 0 first.
let vsrOf bld opr =
  match opr with
  | OprReg reg -> struct (regVar bld reg, regVar bld (lowHalfOf reg))
  | _ -> raise InvalidOperandException

/// The register operand an access moves to or from, which comes first.
let private targetOf (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o, _) | ThreeOperands(o, _, _) -> o
  | _ -> raise InvalidOperandException

/// The address an access reaches, from "D(rA)" or from "rA, rB", rA being
/// zero where it names r0.
let private addressOf (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(_, mem) -> transEAWithOffset mem bld
  | ThreeOperands(_, ra, rb) -> transEAWithIndexReg ra rb bld
  | _ -> raise InvalidOperandException

/// lxsibzx, lxsihzx, lxsiwzx and lxsiwax: an integer of the given size from
/// memory, extended into doubleword 0; doubleword 1 is cleared.
let loadScalarInt ins (bld: ILowUIRBuilder) size ext =
  lift bld ins {
    let struct (dh, dl) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    dh := ext 64<rt> (loadNative bld size ea)
    dl := AST.num0 64<rt>
  }

/// stxsibx, stxsihx and stxsiwx: the low end of doubleword 0 -- byte element
/// 7, halfword element 3 or word element 1 -- stored.
let storeScalarInt ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (sh, _) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    loadNative bld size ea := AST.xtlo size sh
  }

/// lxvrbx, lxvrhx, lxvrwx and lxvrdx: an integer of the given size from
/// memory, zero-extended into the whole register, so it lands in the
/// rightmost element.
let loadRightmost ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (dh, dl) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    dh := AST.num0 64<rt>
    dl := AST.zext 64<rt> (loadNative bld size ea)
  }

/// stxvrbx, stxvrhx, stxvrwx and stxvrdx: the rightmost element of the given
/// size stored.
let storeRightmost ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (_, sl) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    loadNative bld size ea := AST.xtlo size sl
  }

/// The double a single-precision value stands for. Every single but a NaN
/// converts exactly by the host's cast; a NaN keeps its payload and its
/// signalling bit, which a cast would quiet, by splicing the fields as the
/// architecture's conversion of a loaded single does.
let private doubleOfSingle bld word =
  let w = tmpVar bld 32<rt>
  let res = tmpVar bld 64<rt>
  append bld {
    w := word
    let isNaN =
      (w .& numU32 0x7f800000u 32<rt> == numU32 0x7f800000u 32<rt>)
      .& (w .& numU32 0x007fffffu 32<rt> != AST.num0 32<rt>)
    let w64 = AST.zext 64<rt> w
    let nan =
      ((w64 .& numU64 0x80000000UL 64<rt>) << numI32 32 64<rt>)
      .| numU64 0x7ff0000000000000UL 64<rt>
      .| ((w64 .& numU64 0x007fffffUL 64<rt>) << numI32 29 64<rt>)
    res := AST.ite isNaN nan (AST.cast CastKind.FloatCast 64<rt> w)
  }
  res

/// lxssp and lxsspx: a single from memory, in double format in doubleword 0;
/// doubleword 1 is cleared.
let loadScalarSingle ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dh, dl) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    dh := doubleOfSingle bld (loadNative bld 32<rt> ea)
    dl := AST.num0 64<rt>
  }

/// stxssp and stxsspx: the double in doubleword 0 stored as a single by the
/// same splice stfs makes, which does not round.
let storeScalarSingle ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (sh, _) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    loadNative bld 32<rt> ea := GeneralLifter.singleBits bld sh
  }

/// The addresses of a quadword's two halves, doubleword 0 first. A big-endian
/// guest keeps the most significant half at the lower address; on a
/// little-endian one the whole quadword's byte order reverses, which puts it
/// at the higher one.
let private quadHalves (bld: ILowUIRBuilder) ea =
  let next = ea .+ numI32 8 bld.RegType
  if bld.Endianness = Endian.Big then struct (ea, next) else struct (next, ea)

/// One quadword moved between memory and a register's two halves.
let private quadAccess bld isLoad addr (h: Expr) (l: Expr) =
  let struct (hiAddr, loAddr) = quadHalves bld addr
  if isLoad then
    append bld {
      h := loadNative bld 64<rt> hiAddr
      l := loadNative bld 64<rt> loAddr
    }
  else
    append bld {
      loadNative bld 64<rt> hiAddr := h
      loadNative bld 64<rt> loAddr := l
    }

/// lxv, lxvx, stxv and stxvx: a whole quadword in the guest's byte order.
let quadword ins (bld: ILowUIRBuilder) isLoad =
  lift bld ins {
    let struct (h, l) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    quadAccess bld isLoad ea h l
  }

/// The register holding doubleword 0 of the second register of a pair, whose
/// first is the given (even) one.
let private secondOfPair (reg: Register) =
  let step = if reg >= Register.V0A then 2 else 1
  int reg + step |> LanguagePrimitives.EnumOfValue

/// lxvp, lxvpx, stxvp and stxvpx: two quadwords between memory and a pair of
/// registers. The 32 bytes are one octword, so on a little-endian guest its
/// byte order reverses as a whole, and the first register of the pair takes
/// the quadword at the higher address.
let pair ins (bld: ILowUIRBuilder) isLoad =
  lift bld ins {
    let first =
      match targetOf ins with
      | OprReg reg -> reg
      | _ -> raise InvalidOperandException
    let struct (h0, l0) = vsrOf bld (OprReg first)
    let struct (h1, l1) = vsrOf bld (OprReg(secondOfPair first))
    let ea = tmpVar bld bld.RegType
    ea := addressOf ins bld
    let upper = ea .+ numI32 16 bld.RegType
    let struct (a0, a1) =
      if bld.Endianness = Endian.Big then struct (ea, upper)
      else struct (upper, ea)
    quadAccess bld isLoad a0 h0 l0
    quadAccess bld isLoad a1 h1 l1
  }

/// lxvwsx: a word from memory in all four word elements.
let lxvwsx ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dh, dl) = vsrOf bld (targetOf ins)
    let ea = tmpVar bld bld.RegType
    let word = tmpVar bld 32<rt>
    ea := addressOf ins bld
    word := loadNative bld 32<rt> ea
    dh := AST.concat word word
    dl := AST.concat word word
  }

/// mtvsrws: the low word of a general register in all four word elements.
let mtvsrws ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let word = tmpVar bld 32<rt>
    word := AST.xtlo 32<rt> (transOpr bld o2)
    dh := AST.concat word word
    dl := AST.concat word word
  }

/// The high doubleword of the quad-precision constant an lxvkq UIM names: 1.0
/// to 7.0, +Inf and the default quiet NaN, and the same negated from 16 on
/// (the NaN excepted, whose place is -0.0). The low doubleword is zero.
let private quadConstant uim =
  let magnitude =
    match uim &&& 0xfUL with
    | 0UL -> 0x0000000000000000UL
    | 1UL -> 0x3fff000000000000UL
    | 2UL -> 0x4000000000000000UL
    | 3UL -> 0x4000800000000000UL
    | 4UL -> 0x4001000000000000UL
    | 5UL -> 0x4001400000000000UL
    | 6UL -> 0x4001800000000000UL
    | 7UL -> 0x4001c00000000000UL
    | 8UL -> 0x7fff000000000000UL
    | 9UL -> 0x7fff800000000000UL
    | _ -> raise InvalidOperandException
  if uim &&& 0x10UL = 0UL then magnitude
  else magnitude ||| 0x8000000000000000UL

/// lxvkq: a quad-precision constant from the table UIM indexes.
let lxvkq ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let uim =
      match o2 with
      | OprImm n -> n
      | _ -> raise InvalidOperandException
    dh := numU64 (quadConstant uim) 64<rt>
    dl := AST.num0 64<rt>
  }

/// The byte element at index b of a register held as two halves, as a place
/// to read or write.
let private byteAt (h: Expr) (l: Expr) b =
  if b < 8 then AST.extract h 8<rt> ((7 - b) * 8)
  else AST.extract l 8<rt> ((15 - b) * 8)

/// How many bytes a with-length access moves: the top byte of rB, at most 16.
let private lengthOf bld (rb: Expr) =
  let nb = tmpVar bld 8<rt>
  let sixteen = numI32 16 8<rt>
  append bld {
    nb := AST.xthi 8<rt> rb
    nb := AST.ite (nb .> sixteen) sixteen nb
  }
  nb

/// The base address of a with-length access, which adds nothing to rA.
let private baseOf (bld: ILowUIRBuilder) opr =
  match opr with
  | OprReg Register.R0 -> AST.num0 bld.RegType
  | _ -> transOpr bld opr

/// <summary>
/// lxvl and lxvll: the first nb bytes at rA, nb being the top byte of rB
/// (at most 16), the rest of the register cleared. lxvll and a big-endian
/// lxvl fill byte elements 0 to nb-1 from rA upwards; a little-endian lxvl
/// fills the rightmost nb in reverse, byte element 15 from rA. A byte past nb
/// is never read, so each read stands under its own condition.
/// </summary>
let loadWithLength ins (bld: ILowUIRBuilder) leftJustified =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let ea = tmpVar bld bld.RegType
    let struct (th, tl) = tmpVars2 bld 64<rt>
    ea := baseOf bld o2
    let nb = lengthOf bld (transOpr bld o3)
    th := AST.num0 64<rt>
    tl := AST.num0 64<rt>
    let reversed = not leftJustified && bld.Endianness = Endian.Little
    for k in 0 .. 15 do
      let dst = byteAt th tl (if reversed then 15 - k else k)
      let src = loadNative bld 8<rt> (ea .+ numI32 k bld.RegType)
      _when bld "Length" (numI32 k 8<rt> .< nb) (block { dst := src })
    dh := th
    dl := tl
  }

/// stxvl and stxvll, the stores counterpart: nb bytes from the byte elements
/// the matching load fills, and nothing past them.
let storeWithLength ins (bld: ILowUIRBuilder) leftJustified =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (sh, sl) = vsrOf bld o1
    let ea = tmpVar bld bld.RegType
    ea := baseOf bld o2
    let nb = lengthOf bld (transOpr bld o3)
    let reversed = not leftJustified && bld.Endianness = Endian.Little
    for k in 0 .. 15 do
      let src = byteAt sh sl (if reversed then 15 - k else k)
      let dst = loadNative bld 8<rt> (ea .+ numI32 k bld.RegType)
      _when bld "Length" (numI32 k 8<rt> .< nb) (block { dst := src })
  }
