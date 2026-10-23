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

(*
  Lifts the VSX loads and stores ISA 3.0 and 3.1 added, and the moves beside
  them. A vector-scalar register is kept as two 64-bit halves: doubleword 0,
  the high one, in the register an operand names (an FPR for VSR0-31, a
  vector register's high half for VSR32-63), and doubleword 1 in the next.
  Byte element 0 of a vector-scalar register is the most significant byte of
  doubleword 0, whatever the byte order of the guest.
*)
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
let secondOfPair (reg: Register) =
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

/// <summary>
/// xsresp and xsrsqrtesp: a single-precision estimate of the reciprocal (of
/// the square root) of the double in doubleword 0 of xB, in double format in
/// doubleword 0 of xT, doubleword 1 cleared and FPRF set. The architecture
/// lets an estimate stray from the exact answer by a part in 16384, which no
/// analysis can usefully model, so the exact answer rounded to single stands
/// in, as it does for fres. An answer that became a NaN with no NaN operand
/// -- the square root of a negative number -- is the default quiet NaN, which
/// is positive. A NaN result is made from the NaN operand's own bits --
/// quieted, keeping the sign, the exponent and the leading 23 fraction bits --
/// since the cast and the arithmetic of a NaN are left to the host.
/// </summary>
let reciprocalEstimateSingle ins bld isSqrt =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, _) = vsrOf bld o2
    let one = numU64 0x3ff0000000000000UL 64<rt>
    let quiet = numU64 0x0008000000000000UL 64<rt>
    let singleNaN = numU64 0xffffffffe0000000UL 64<rt>
    let res = tmpVar bld 64<rt>
    res := AST.fdiv one (if isSqrt then AST.fsqrt bh else bh)
    let single = AST.cast CastKind.FloatCast 32<rt> res
    let widened = AST.cast CastKind.FloatCast 64<rt> single
    let operand = AST.ite (IEEE754Double.isNaN bh) bh GeneralLifter.defaultQNaN
    let nan = (operand .| quiet) .& singleNaN
    dh := AST.ite (IEEE754Double.isNaN res) nan widened
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

/// The bytes of a register held as two halves, byte element 0 first.
let private bytesOf (h: Expr) (l: Expr) = Array.init 16 (byteAt h l)

/// Writes sixteen bytes, byte element 0 first, into a register's two halves
/// through temporaries, so a source that is also the target is read whole
/// before it is written.
let private writeBytes bld (dh: Expr) (dl: Expr) (bytes: Expr[]) =
  let struct (th, tl) = tmpVars2 bld 64<rt>
  append bld {
    th := AST.revConcat (Array.rev bytes[0..7])
    tl := AST.revConcat (Array.rev bytes[8..15])
    dh := th
    dl := tl
  }

/// xxbrh, xxbrw, xxbrd and xxbrq: the bytes of each element of the given
/// size reversed, the elements themselves left where they are.
let byteReverse ins bld size =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, bl) = vsrOf bld o2
    let src = bytesOf bh bl
    let reversed =
      Array.init 16 (fun i -> src[(i / size) * size + size - 1 - i % size])
    writeBytes bld dh dl reversed
  }

/// The immediate operand at the end of an instruction.
let private immOf = function
  | OprImm n -> int n
  | _ -> raise InvalidOperandException

/// xxextractuw: the four bytes from byte element UIM of xB, zero-extended
/// into doubleword 0 (word element 1); the rest of xT is cleared. A UIM past
/// 12 is undefined and reads the bytes it reaches, wrapping round.
let xxextractuw ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, bl) = vsrOf bld o2
    let src = bytesOf bh bl
    let uim = immOf o3
    let word = Array.init 4 (fun k -> src[(uim + k) % 16])
    let value = tmpVar bld 32<rt>
    value := AST.revConcat (Array.rev word)
    dh := AST.zext 64<rt> value
    dl := AST.num0 64<rt>
  }

/// xxinsertw: word element 1 of xB into byte elements UIM to UIM+3 of xT,
/// the other bytes of xT kept. A UIM past 12 is undefined and writes the
/// bytes it reaches, wrapping round.
let xxinsertw ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, _) = vsrOf bld o2
    let dst = bytesOf dh dl
    let uim = immOf o3
    let word = Array.init 4 (fun k -> AST.extract bh 8<rt> ((3 - k) * 8))
    let bytes =
      Array.init 16 (fun i ->
        let k = (i - uim + 16) % 16
        if k < 4 then word[k] else dst[i])
    writeBytes bld dh dl bytes
  }

/// xxperm and xxpermr: each byte of xT from the 32-byte pair xA || xT, at the
/// index the low five bits of the matching byte of xB give -- counted from
/// the left by xxperm and from the right by xxpermr.
let permute ins bld fromRight =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (ah, al) = vsrOf bld o2
    let struct (bh, bl) = vsrOf bld o3
    let src = Array.append (bytesOf ah al) (bytesOf dh dl)
    let pcv = bytesOf bh bl
    let picked =
      Array.init 16 (fun i ->
        let index = tmpVar bld 8<rt>
        let raw = pcv[i] .& numI32 31 8<rt>
        append bld {
          index := if fromRight then numI32 31 8<rt> .- raw else raw
        }
        Array.fold (fun acc k ->
          AST.ite (index == numI32 k 8<rt>) src[k] acc) src[0] [| 1 .. 31 |])
    writeBytes bld dh dl picked
  }

/// xvtlsbb: whether the least significant bit of every byte of xB is set
/// (CR field bit 0) or every one is clear (bit 2); bits 1 and 3 are zero.
let xvtlsbb ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (bh, bl) = vsrOf bld o2
    let lsbs = numU64 0x0101010101010101UL 64<rt>
    let lt, gt, eq, so =
      match o1 with
      | OprReg reg -> transCRxToExpr bld reg
      | _ -> raise InvalidOperandException
    lt := ((bh .& lsbs) == lsbs) .& ((bl .& lsbs) == lsbs)
    gt := AST.b0
    eq := ((bh .& lsbs) == AST.num0 64<rt>) .& ((bl .& lsbs) == AST.num0 64<rt>)
    so := AST.b0
  }

/// The bits the xxgenpcv forms read: the most significant bit of each
/// element of the given size, element 0 first.
let private maskBits (h: Expr) (l: Expr) size =
  Array.init (16 / size) (fun i ->
    let b = i * size
    if b < 8 then AST.extract h 1<rt> (63 - b * 8)
    else AST.extract l 1<rt> (63 - (b - 8) * 8))

/// How many of the mask bits before each element are set: entry i counts
/// elements 0 to i-1, so the last entry counts them all.
let private prefixCounts bld (masks: Expr[]) =
  let counts = Array.init (masks.Length + 1) (fun _ -> tmpVar bld 8<rt>)
  append bld {
    counts[0] := AST.num0 8<rt>
    for i in 0 .. masks.Length - 1 do
      counts[i + 1] := counts[i] .+ AST.zext 8<rt> masks[i]
  }
  counts

/// IMM 0: element i of the expansion takes the next unused leading element
/// of the source where its mask bit is set, and its own index into the
/// second source where it is clear.
let private expandLeft (masks: Expr[]) (counts: Expr[]) size =
  Array.init 16 (fun b ->
    let i, k = b / size, b % size
    let used = (counts[i] .* numI32 size 8<rt>) .+ numI32 k 8<rt>
    AST.ite masks[i] used (numI32 (size * i + 16 + k) 8<rt>))

/// IMM 2: the same counted from the right, for a right-indexed permute: the
/// i-th element from the right and its bytes from the right.
let private expandRight (masks: Expr[]) (counts: Expr[]) size =
  let n = masks.Length
  Array.init 16 (fun b ->
    let p, k = b / size, size - 1 - b % size
    let after = counts[n] .- counts[p + 1]
    let used = (after .* numI32 size 8<rt>) .+ numI32 k 8<rt>
    AST.ite masks[p] used (numI32 (size * (n - 1 - p) + 16 + k) 8<rt>))

/// IMM 1: output element q takes the index of the q-th selected element;
/// the elements past the selected ones are undefined and are cleared.
let private compressLeft (masks: Expr[]) (counts: Expr[]) size =
  Array.init 16 (fun b ->
    let q, k = b / size, b % size
    [| 0 .. masks.Length - 1 |]
    |> Array.fold (fun acc i ->
      let hit = masks[i] .& (counts[i] == numI32 q 8<rt>)
      AST.ite hit (numI32 (size * i + k) 8<rt>) acc) (AST.num0 8<rt>))

/// IMM 3: the same counted from the right.
let private compressRight (masks: Expr[]) (counts: Expr[]) size =
  let n = masks.Length
  Array.init 16 (fun b ->
    let q, k = b / size, size - 1 - b % size
    [| 0 .. n - 1 |]
    |> Array.fold (fun acc i ->
      let p = n - 1 - i
      let after = counts[n] .- counts[p + 1]
      let hit = masks[p] .& (after == numI32 (n - 1 - q) 8<rt>)
      AST.ite hit (numI32 (size * i + k) 8<rt>) acc) (AST.num0 8<rt>))

/// xxgenpcvbm, xxgenpcvhm, xxgenpcvwm and xxgenpcvdm: the permute control
/// vector that expands or compresses the elements of the given size vRB's
/// mask selects, for a permute indexed from the left (IMM 0 and 1) or from
/// the right (IMM 2 and 3).
let genPCV ins bld size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, bl) = vsrOf bld o2
    let masks = maskBits bh bl size
    let counts = prefixCounts bld masks
    let build =
      match immOf o3 with
      | 0 -> expandLeft
      | 1 -> compressLeft
      | 2 -> expandRight
      | _ -> compressRight
    writeBytes bld dh dl (build masks counts size)
  }

(*
  Lifts the VSX floating-point arithmetic ISA 2.07 to 3.1 added beyond what
  VectorLifter does: the vector single-precision forms and the double ones
  that were missing, the multiply-adds, the estimates, the roundings to an
  integral value, maximum and minimum, and the sign operations.

  The arithmetic follows the host-op pattern the PPC lifter uses: the
  operation is the IR's own floating-point operation at the lane's width,
  which the evaluator rounds once in the direction FPSCR[RN] names, and what
  the host makes of a NaN is settled afterwards. FPSCR's exception bits are
  not written, as they are not by the rest of the PPC lifter; FPRF is, by
  the scalar forms that set it.
*)
/// The fields of a binary floating-point lane: its width, and how many bits
/// its exponent and its fraction take.
type Lane =
  { Width: RegType
    ExpBits: int
    FracBits: int }

/// A single-precision lane.
let single = { Width = 32<rt>; ExpBits = 8; FracBits = 23 }

/// A double-precision lane.
let double = { Width = 64<rt>; ExpBits = 11; FracBits = 52 }

/// A constant of a lane's width.
let private bits lane (v: uint64) = numU64 v lane.Width

/// The sign bit of a lane.
let signOf lane = bits lane (1UL <<< (int lane.Width - 1))

/// The exponent field of a lane, in place.
let private expMask lane =
  bits lane (((1UL <<< lane.ExpBits) - 1UL) <<< lane.FracBits)

/// The fraction field of a lane, in place.
let private fracMask lane = bits lane ((1UL <<< lane.FracBits) - 1UL)

/// The bit that tells a quiet NaN from a signalling one.
let private quietBit lane = bits lane (1UL <<< (lane.FracBits - 1))

/// Whether a lane holds a NaN.
let isNaNOf lane x =
  ((x .& expMask lane) == expMask lane)
  .& ((x .& fracMask lane) != AST.num0 lane.Width)

/// Whether a lane holds a signalling NaN.
let isSNaNOf lane x =
  isNaNOf lane x .& ((x .& quietBit lane) == AST.num0 lane.Width)

/// Whether a lane holds a quiet NaN.
let isQNaNOf lane x =
  isNaNOf lane x .& ((x .& quietBit lane) != AST.num0 lane.Width)

/// Whether a lane holds a zero of either sign.
let isZeroOf lane x =
  (x .& AST.not (signOf lane)) == AST.num0 lane.Width

/// A NaN made quiet, its payload kept.
let quietOf lane x = x .| quietBit lane

/// The positive default quiet NaN of a lane.
let defaultNaNOf lane = expMask lane .| quietBit lane

/// The lane format of an element size.
let laneOf (esize: RegType) = if esize = 32<rt> then single else double

/// The lanes of a register held as two halves, element 0 first: two
/// doublewords or four words.
let lanesOf (esize: RegType) (h: Expr) (l: Expr) =
  if esize = 64<rt> then
    [| h; l |]
  else
    [| AST.xthi 32<rt> h
       AST.xtlo 32<rt> h
       AST.xthi 32<rt> l
       AST.xtlo 32<rt> l |]

/// Writes lanes, element 0 first, into a register's halves through
/// temporaries, so a source that is also the target is read whole first.
let writeLanes bld (esize: RegType) (dh: Expr) (dl: Expr) (r: Expr[]) =
  let struct (th, tl) = tmpVars2 bld 64<rt>
  if esize = 64<rt> then
    append bld {
      th := r[0]
      tl := r[1]
    }
  else
    append bld {
      th := AST.concat r[0] r[1]
      tl := AST.concat r[2] r[3]
    }
  append bld {
    dh := th
    dl := tl
  }

/// The registers an operation reads, after the one it writes.
let private sourcesOf (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> o1, [ o2; o3 ]
  | TwoOperands(o1, o2) -> o1, [ o2 ]
  | _ -> raise InvalidOperandException

/// An element-wise vector operation, "xT, xA, xB" or "xT, xB": each lane of
/// xT computed by f from the matching lanes of the sources, in order.
let vectorMap ins bld esize f =
  lift bld ins {
    let dst, srcs = sourcesOf ins
    let struct (dh, dl) = vsrOf bld dst
    let lanes =
      srcs
      |> List.map (fun o ->
        let struct (h, l) = vsrOf bld o
        lanesOf esize h l)
    let n = if esize = 64<rt> then 2 else 4
    let lane = laneOf esize
    let results =
      Array.init n (fun i -> f lane (lanes |> List.map (fun ls -> ls[i])))
    writeLanes bld esize dh dl results
  }

/// A scalar double operation, "xT, xA, xB" or "xT, xB": doubleword 0 of xT
/// from doubleword 0 of the sources, doubleword 1 cleared, and FPRF set
/// where the instruction sets it.
let scalarMap ins bld setsFPRF f =
  lift bld ins {
    let dst, srcs = sourcesOf ins
    let struct (dh, dl) = vsrOf bld dst
    let xs =
      srcs
      |> List.map (fun o ->
        let struct (h, _) = vsrOf bld o
        h)
    let res = tmpVar bld 64<rt>
    res := f double xs
    dh := res
    dl := AST.num0 64<rt>
    if setsFPRF then setFPRF bld dh else ()
  }

/// An answer settled by the architecture's NaN rules, not by what the host
/// makes of a NaN: the first operand that is a NaN, quieted, or else -- an
/// invalid operation -- the positive default quiet NaN.
let private settleNaN lane (operands: Expr list) res =
  let made = AST.ite (isNaNOf lane res) (defaultNaNOf lane) res
  List.foldBack (fun x acc ->
    AST.ite (isNaNOf lane x) (quietOf lane x) acc) operands made

/// The operand list of a binary operation.
let two = function
  | [ a; b ] -> struct (a, b)
  | _ -> raise InvalidOperandException

/// The operand of a unary operation.
let one = function
  | [ b ] -> b
  | _ -> raise InvalidOperandException

/// A binary arithmetic lane: the host operation, the NaN settled after.
/// The first NaN operand comes back quieted, as POWER does.
let arith op lane xs =
  let struct (a, b) = two xs
  settleNaN lane xs (op a b)

/// The square root of a lane.
let squareRoot lane xs = settleNaN lane xs (AST.fsqrt (one xs))

/// The value 1.0 in a lane.
let private oneOf lane =
  if lane.Width = 32<rt> then bits lane 0x3f800000UL
  else bits lane 0x3ff0000000000000UL

/// The reciprocal (isSqrt: of the square root) estimate of a lane. The
/// architecture lets an estimate stray by a part in 16384, which no analysis
/// can usefully model, so the exact answer stands in, as it does for fres.
let estimate isSqrt lane xs =
  let b = one xs
  settleNaN lane xs (AST.fdiv (oneOf lane) (if isSqrt then AST.fsqrt b else b))

/// A NaN quieted, and anything else rounded by the given rounding: a host's
/// rounding to an integral value need not quiet a signalling NaN, which the
/// architecture does.
let private unlessNaN lane round xs =
  let b = one xs
  AST.ite (isNaNOf lane b) (quietOf lane b) (round b)

/// A lane rounded to an integral value in a direction.
let private roundIn mode lane xs =
  unlessNaN lane (AST.roundToIntegral mode lane.Width) xs

/// Rounded to the nearest integral value, ties away from zero.
let awayFromZero lane xs = roundIn RoundingMode.ToNearestAway lane xs

/// Rounded toward -Inf.
let downward lane xs = roundIn RoundingMode.TowardNegative lane xs

/// Rounded toward +Inf.
let upward lane xs = roundIn RoundingMode.TowardPositive lane xs

/// Rounded toward zero.
let towardZero lane xs = roundIn RoundingMode.TowardZero lane xs

/// Rounded in the direction FPSCR[RN] names, which a rounding no RoundCtrl
/// encloses takes.
let byFPSCR lane xs =
  unlessNaN lane (AST.cast CastKind.RoundToIntegral lane.Width) xs

/// The sign operations, which touch only the sign bit, so a NaN is no
/// exception and nothing is raised: 0 clears it, 1 sets it, 2 flips it.
let signOp kind lane xs =
  let b = one xs
  match kind with
  | 0 -> b .& AST.not (signOf lane)
  | 1 -> b .| signOf lane
  | _ -> b <+> signOf lane

/// xvcpsgndp and xvcpsgnsp: the sign of xA on the magnitude of xB.
let copySignOf lane xs =
  let struct (a, b) = two xs
  (a .& signOf lane) .| (b .& AST.not (signOf lane))

/// <summary>
/// bfp_MAXIMUM and bfp_MINIMUM (Book I 7.3.2): a quiet NaN loses to a
/// number, a signalling one wins and comes back quiet, x being preferred
/// where both are NaNs; otherwise the greater (or lesser), +0 counting as
/// greater than -0, which for two zeroes is the bitwise and (or or) of them.
/// </summary>
let maxMin isMax lane xs =
  let struct (x, y) = two xs
  let ordered = if isMax then AST.fgt x y else AST.flt x y
  let zeroes = isZeroOf lane x .& isZeroOf lane y
  let both = if isMax then x .& y else x .| y
  let pick = AST.ite zeroes both (AST.ite ordered x y)
  let fromSNaNY = AST.ite (isSNaNOf lane y) (quietOf lane y) pick
  let fromY = AST.ite (isQNaNOf lane y) x fromSNaNY
  let fromX = AST.ite (isSNaNOf lane x) (quietOf lane x) fromY
  let afterQuietX = AST.ite (isNaNOf lane y) x y
  AST.ite (isQNaNOf lane x) afterQuietX fromX

/// bfp_MAXIMUM_TYPE_C and bfp_MINIMUM_TYPE_C: y whenever either operand is
/// a NaN, or on a tie; otherwise the greater (or lesser). An ordered
/// comparison with a NaN is false, which is what picks y then.
let maxMinC isMax (_: Lane) xs =
  let struct (x, y) = two xs
  AST.ite (if isMax then AST.fgt x y else AST.flt x y) x y

/// bfp_MAXIMUM_TYPE_J and bfp_MINIMUM_TYPE_J: a NaN in x, then one in y,
/// passes as it is; two zeroes give +0 (or -0) if either is; otherwise the
/// greater (or lesser), y on a tie.
let maxMinJ isMax lane xs =
  let struct (x, y) = two xs
  let ordered = if isMax then AST.fgt x y else AST.flt x y
  let zeroes = isZeroOf lane x .& isZeroOf lane y
  let both = if isMax then x .& y else x .| y
  let pick = AST.ite zeroes both (AST.ite ordered x y)
  AST.ite (isNaNOf lane x) x (AST.ite (isNaNOf lane y) y pick)

/// The fused multiply-add of one lane, through the call the scalar forms
/// make: bit 1 of the flags negates the addend.
let private fused lane x y z subtract =
  let f = numU64 (if subtract then 2UL else 0UL) 8<rt>
  let name = if lane.Width = 32<rt> then "FMA32" else "FMA64"
  AST.app name [ x; y; z; f ] lane.Width

/// <summary>
/// One lane of a vector multiply-add. The "a" forms multiply xA by xB and
/// add xT; the "m" forms multiply xA by xT and add xB. Which NaN comes back
/// follows POWER's order -- xA, then the addend, then the other factor --
/// quieted; an invalid operation answers with the default quiet NaN; the
/// negating forms flip the sign of the rounded result, a NaN excepted.
/// </summary>
let mulAddLane bld lane targetIsFactor subtract negate a b t =
  let res = tmpVar bld lane.Width
  let x, y, z = if targetIsFactor then a, t, b else a, b, t
  let addend, other = if targetIsFactor then b, t else t, b
  let quietIfNaN v orElse = AST.ite (isNaNOf lane v) (quietOf lane v) orElse
  let chosen = quietIfNaN a (quietIfNaN addend (quietOf lane other))
  let noNaN = AST.not (isNaNOf lane a .| isNaNOf lane b .| isNaNOf lane t)
  append bld {
    res := fused lane x y z subtract
    res := AST.ite (isNaNOf lane res) (defaultNaNOf lane) res
    res := AST.ite noNaN res chosen
  }
  if negate then AST.ite (isNaNOf lane res) res (res <+> signOf lane)
  else res

/// The vector multiply-adds, over lanes of the given size.
let vectorMulAdd ins bld esize targetIsFactor subtract negate =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (th, tl) = vsrOf bld o1
    let struct (ah, al) = vsrOf bld o2
    let struct (bh, bl) = vsrOf bld o3
    let lane = laneOf esize
    let ts = lanesOf esize th tl
    let xs = lanesOf esize ah al
    let ys = lanesOf esize bh bl
    let results =
      Array.init ts.Length (fun i ->
        mulAddLane bld lane targetIsFactor subtract negate xs[i] ys[i] ts[i])
    writeLanes bld esize th tl results
  }

/// The all-ones or all-zeroes a compare writes into a lane.
let private maskOf lane cond =
  AST.ite cond (AST.not (AST.num0 lane.Width)) (AST.num0 lane.Width)

/// <summary>
/// The vector compares, "xT, xA, xB": each lane all ones where the matching
/// lanes compare true and all zeroes where not, a NaN comparing false. The
/// record forms also say in CR6 whether every lane compared true (bit 0) or
/// none did (bit 2).
/// </summary>
let vectorCompare ins bld esize rel record =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (ah, al) = vsrOf bld o2
    let struct (bh, bl) = vsrOf bld o3
    let lane = laneOf esize
    let xs = lanesOf esize ah al
    let ys = lanesOf esize bh bl
    let conds = Array.init xs.Length (fun i -> tmpVar bld 1<rt>)
    for i in 0 .. xs.Length - 1 do
      conds[i] := rel xs[i] ys[i]
    writeLanes bld esize dh dl (Array.map (maskOf lane) conds)
    if record then
      let all = Array.reduce (.&) conds
      let none = Array.reduce (.&) (Array.map AST.not conds)
      regVar bld Register.CR6_0 := all
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 := none
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }

/// xscmpeqdp, xscmpgtdp and xscmpgedp: doubleword 0 of xT all ones where the
/// doubles in doubleword 0 of xA and xB compare true, doubleword 1 cleared.
let scalarCompare ins bld rel =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (ah, _) = vsrOf bld o2
    let struct (bh, _) = vsrOf bld o3
    dh := maskOf double (rel ah bh)
    dl := AST.num0 64<rt>
  }

/// The four bits of the CR field an operand names, and FPSCR's FPCC.
let private crAndFPCC bld opr =
  let lt, gt, eq, un =
    match opr with
    | OprReg reg -> transCRxToExpr bld reg
    | _ -> raise InvalidOperandException
  let fpscr = regVar bld Register.FPSCR
  let fpcc = [| for pos in [ 15; 14; 13; 12 ] -> AST.extract fpscr 1<rt> pos |]
  struct ([| lt; gt; eq; un |], fpcc)

/// Writes four bits to a CR field and, where asked, to FPCC.
let writeField bld opr withFPCC (bits: Expr[]) =
  let struct (cr, fpcc) = crAndFPCC bld opr
  let vals = Array.init 4 (fun _ -> tmpVar bld 1<rt>)
  append bld {
    for i in 0 .. 3 do
      vals[i] := bits[i]
    for i in 0 .. 3 do
      cr[i] := vals[i]
  }
  if withFPCC then
    append bld {
      for i in 0 .. 3 do
        fpcc[i] := vals[i]
    }
  else
    ()

/// <summary>
/// xscmpodp: the ordered compare of the doubles in doubleword 0 of xA and
/// xB into a CR field and FPCC, as xscmpudp does. A signalling NaN sets
/// VXSNAN, and VXVC with it unless VE is set; a quiet one sets VXVC.
/// </summary>
let xscmpodp ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (a, _) = vsrOf bld o2
    let struct (b, _) = vsrOf bld o3
    let un = isNaNOf double a .| isNaNOf double b
    let snan = isSNaNOf double a .| isSNaNOf double b
    let fpscr = regVar bld Register.FPSCR
    let ve = AST.extract fpscr 1<rt> 7
    let vxsnan = AST.extract fpscr 1<rt> 24
    let vxvc = AST.extract fpscr 1<rt> 19
    let lt = AST.not un .& AST.flt a b
    let gt = AST.not un .& AST.fgt a b
    let eq = AST.not un .& AST.not (AST.flt a b) .& AST.not (AST.fgt a b)
    writeField bld o1 true [| lt; gt; eq; un |]
    vxsnan := vxsnan .| snan
    vxvc := vxvc .| AST.ite snan (AST.not ve) un
  }

/// xscmpexpdp: the exponent fields of the doubles in doubleword 0 of xA and
/// xB compared as unsigned numbers into a CR field and FPCC, unordered where
/// either is a NaN.
let xscmpexpdp ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (a, _) = vsrOf bld o2
    let struct (b, _) = vsrOf bld o3
    let ea = AST.extract a 11<rt> 52
    let eb = AST.extract b 11<rt> 52
    let un = isNaNOf double a .| isNaNOf double b
    let lt = AST.not un .& (ea .< eb)
    let gt = AST.not un .& (ea .> eb)
    let eq = AST.not un .& (ea == eb)
    writeField bld o1 true [| lt; gt; eq; un |]
  }

/// The exponent fields of a lane's format: how wide, and the bias.
let private expWidth lane = regTypeOf lane.ExpBits

let private bias lane = (1 <<< (lane.ExpBits - 1)) - 1

/// The unbiased exponent of a lane, as a signed 16-bit number: the biased
/// field less the bias, so a zero or a denormal reads as -bias.
let private unbiased lane x =
  let e = AST.extract x (expWidth lane) lane.FracBits
  AST.zext 16<rt> e .- numI32 (bias lane) 16<rt>

/// Whether a lane holds an infinity.
let private isInfOf lane x =
  AST.extract x (expWidth lane) lane.FracBits
  == AST.not (AST.num0 (expWidth lane))
  .& (AST.extract x (regTypeOf lane.FracBits) 0
      == AST.num0 (regTypeOf lane.FracBits))

/// Whether a lane holds a denormal.
let private isDenOf lane x =
  (AST.extract x (expWidth lane) lane.FracBits == AST.num0 (expWidth lane))
  .& AST.not (isZeroOf lane x)

/// A signed 16-bit constant.
let private s16 v = numI32 v 16<rt>

/// <summary>
/// The software-divide test of one pair of lanes (xstdivdp, xvtdivdp,
/// xvtdivsp): fe where the quotient needs a software fix-up -- an operand
/// that is a NaN or an infinity, a zero divisor, exponents so far apart or
/// so extreme that the estimate-and-refine sequence would over- or
/// underflow -- and fg where an operand is an infinity or the divisor a
/// zero or a denormal. The thresholds are the format's.
/// </summary>
let private divideTest lane a b =
  let ea = unbiased lane a
  let eb = unbiased lane b
  let isDouble = lane.Width = 64<rt>
  let lo, hi = if isDouble then -1022, 1021 else -126, 125
  let far, near, tiny = if isDouble then 1023, -1021, -970 else 127, -125, -103
  let live = AST.not (isZeroOf lane a)
  let fe =
    isNaNOf lane a .| isInfOf lane a .| isNaNOf lane b .| isInfOf lane b
    .| isZeroOf lane b .| (eb ?<= s16 lo) .| (eb ?>= s16 hi)
    .| (live .& ((ea .- eb) ?>= s16 far))
    .| (live .& ((ea .- eb) ?<= s16 near))
    .| (live .& (ea ?<= s16 tiny))
  let fg =
    isInfOf lane a .| isInfOf lane b .| isZeroOf lane b .| isDenOf lane b
  struct (fe, fg)

/// The software-square-root test of one lane (xstsqrtdp, xvtsqrtdp,
/// xvtsqrtsp): fe for a zero, a NaN, an infinity, a negative number or an
/// exponent too small, fg for a zero, an infinity or a denormal.
let private sqrtTest lane b =
  let eb = unbiased lane b
  let tiny = if lane.Width = 64<rt> then -970 else -103
  let negative = AST.extract b 1<rt> (int lane.Width - 1)
  let fe =
    isNaNOf lane b .| isInfOf lane b .| isZeroOf lane b .| negative
    .| (eb ?<= s16 tiny)
  let fg = isInfOf lane b .| isZeroOf lane b .| isDenOf lane b
  struct (fe, fg)

/// The lanes a test reads: element 0 alone for the scalar forms.
let private testLanes esize scalar (h: Expr) l =
  if scalar then [| h |] else lanesOf esize h l

/// <summary>
/// The software divide and square-root tests, "BF, xA, xB" and "BF, xB":
/// CR field BF set to 0b1 || fg || fe || 0b0, fe and fg gathered over every
/// lane tested.
/// </summary>
let softwareTest (ins: Instruction) bld esize scalar isDivide =
  lift bld ins {
    let lane = laneOf esize
    let field, flags =
      match ins.Operands with
      | ThreeOperands(f, o2, o3) when isDivide ->
        let struct (ah, al) = vsrOf bld o2
        let struct (bh, bl) = vsrOf bld o3
        let xs = testLanes esize scalar ah al
        let ys = testLanes esize scalar bh bl
        f, Array.map2 (divideTest lane) xs ys
      | TwoOperands(f, o2) ->
        let struct (bh, bl) = vsrOf bld o2
        f, Array.map (sqrtTest lane) (testLanes esize scalar bh bl)
      | _ ->
        raise InvalidOperandException
    let fe = flags |> Array.map (fun struct (e, _) -> e) |> Array.reduce (.|)
    let fg = flags |> Array.map (fun struct (_, g) -> g) |> Array.reduce (.|)
    writeField bld field false [| AST.b1; fg; fe; AST.b0 |]
  }

/// The classes a data-class mask names, bit 0 (the mask's highest) first:
/// NaN, +Inf, -Inf, +0, -0, +denormal, -denormal; given the class tests of
/// a value, whether it is in any class the mask selects.
let private classMatch dcmx sign nan inf zero den =
  let positive = AST.not sign
  [| nan
     inf .& positive
     inf .& sign
     zero .& positive
     zero .& sign
     den .& positive
     den .& sign |]
  |> Array.indexed
  |> Array.filter (fun (k, _) -> (dcmx >>> (6 - k)) &&& 1 = 1)
  |> Array.map snd
  |> Array.fold (.|) AST.b0

/// Whether a lane is in a class the mask selects.
let private laneMatch lane dcmx x =
  let sign = AST.extract x 1<rt> (int lane.Width - 1)
  let nan, inf = isNaNOf lane x, isInfOf lane x
  let zero, den = isZeroOf lane x, isDenOf lane x
  classMatch dcmx sign nan inf zero den

/// The immediate operand at the end of an instruction, as an int.
let private floatImmOf = function
  | OprImm n -> int n
  | _ -> raise InvalidOperandException

/// <summary>
/// xvtstdcdp and xvtstdcsp, "xT, xB, DCMX": each lane of xT all ones where
/// the matching lane of xB is in a class DCMX selects, all zeroes where not.
/// </summary>
let vectorTestClass ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, bl) = vsrOf bld o2
    let lane = laneOf esize
    let dcmx = floatImmOf o3
    let results =
      lanesOf esize bh bl
      |> Array.map (fun x -> maskOf lane (laneMatch lane dcmx x))
    writeLanes bld esize dh dl results
  }

/// <summary>
/// xststdcdp and xststdcsp, "BF, xB, DCMX": the sign of the double in
/// doubleword 0 of xB, whether it is in a class DCMX selects, and -- for
/// xststdcsp -- whether no single represents it, into a CR field and FPCC.
/// xststdcsp reads the classes as the value would be in single precision:
/// an exponent below the single range is a denormal there.
/// </summary>
let scalarTestClass ins bld isSingle =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (b, _) = vsrOf bld o2
    let dcmx = floatImmOf o3
    let sign = AST.extract b 1<rt> 63
    let exp = AST.extract b 11<rt> 52
    let tinyForSingle =
      (exp != AST.num0 11<rt>) .& (exp .< numI32 0x381 11<rt>)
    let den =
      if isSingle then isDenOf double b .| tinyForSingle else isDenOf double b
    let nan, inf, zero = isNaNOf double b, isInfOf double b, isZeroOf double b
    let matched = classMatch dcmx sign nan inf zero den
    let narrowed = AST.cast CastKind.FloatCast 32<rt> b
    let back = AST.cast CastKind.FloatCast 64<rt> narrowed
    let payloadLost =
      AST.extract b 29<rt> 0 != AST.num0 29<rt>
    let notSingle =
      if isSingle then AST.ite (isNaNOf double b) payloadLost (back != b)
      else AST.b0
    writeField bld o1 true [| sign; AST.b0; matched; notSingle |]
  }

/// xsiexpdp, "xT, rA, rB": the sign and fraction of rA with the low eleven
/// bits of rB as the exponent, in doubleword 0; doubleword 1 cleared.
let xsiexpdp ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let ra = AST.zext 64<rt> (transOpr bld o2)
    let rb = AST.zext 64<rt> (transOpr bld o3)
    let keep = numU64 0x800fffffffffffffUL 64<rt>
    let exp = (rb .& numU64 0x7ffUL 64<rt>) << numI32 52 64<rt>
    dh := (ra .& keep) .| exp
    dl := AST.num0 64<rt>
  }

/// xsxexpdp and xsxsigdp, "rT, xB": the exponent field, or the significand
/// with its implicit bit where the value is normal, of the double in
/// doubleword 0 of xB, into a general register.
let scalarExtract ins (bld: ILowUIRBuilder) significand =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let rt = transOpr bld o1
    let struct (b, _) = vsrOf bld o2
    let exp = AST.extract b 11<rt> 52
    let normal = (exp != AST.num0 11<rt>) .& (exp != numI32 0x7ff 11<rt>)
    let fraction = b .& numU64 0xfffffffffffffUL 64<rt>
    let implicit = numU64 (1UL <<< 52) 64<rt>
    let withImplicit = AST.ite normal (fraction .| implicit) fraction
    let value = if significand then withImplicit else AST.zext 64<rt> exp
    rt := AST.xtlo bld.RegType value
  }

/// <summary>
/// xviexpdp and xviexpsp, "xT, xA, xB": each lane the sign and fraction of
/// xA's with the low exponent-width bits of xB's as the exponent.
/// </summary>
let insertExponent lane xs =
  let struct (a, b) = two xs
  let field = (AST.num1 lane.Width << numI32 lane.ExpBits lane.Width)
              .- AST.num1 lane.Width
  let exp = (b .& field) << numI32 lane.FracBits lane.Width
  (a .& AST.not (field << numI32 lane.FracBits lane.Width)) .| exp

/// xvxexpdp and xvxexpsp: each lane's exponent field, zero-extended.
let extractExponent lane xs =
  let b = one xs
  AST.zext lane.Width (AST.extract b (expWidth lane) lane.FracBits)

/// xvxsigdp and xvxsigsp: each lane's fraction with the implicit bit where
/// the value is normal.
let extractSignificand lane xs =
  let b = one xs
  let exp = AST.extract b (expWidth lane) lane.FracBits
  let normal =
    (exp != AST.num0 (expWidth lane))
    .& (exp != AST.not (AST.num0 (expWidth lane)))
  let fraction = AST.zext lane.Width (AST.extract b (regTypeOf lane.FracBits) 0)
  let implicit = AST.num1 lane.Width << numI32 lane.FracBits lane.Width
  AST.ite normal (fraction .| implicit) fraction

(*
  Lifts the VSX conversions ISA 2.07 to 3.1 added: between the vector
  single and double formats, from either to the integers and back, and to
  and from half precision and bfloat16.

  A conversion that can round is the IR's own cast, which the evaluator
  rounds in the direction FPSCR[RN] names, except where the target is half
  precision or bfloat16, which the IR has no type for: those go out as the
  named calls FCVTHALF and FCVTBF16 (specified in lanes/X.md), the
  direction passed with them. A conversion that cannot round -- from half
  precision or bfloat16, which every wider format holds exactly -- is spelt
  out in the IR.
*)
/// The rounding direction FPSCR[RN] names, as the eight-bit argument the
/// named conversions take: 0 to nearest, 1 toward zero, 2 toward +Inf, 3
/// toward -Inf.
let private roundingArg bld =
  AST.zext 8<rt> (AST.extract (regVar bld Register.FPSCR) 2<rt> 0)

/// Two to the -24, the weight of a half-precision denormal's last bit, in
/// a lane.
let private halfUlp lane =
  if lane.Width = 32<rt> then numU64 0x33800000UL lane.Width
  else numU64 0x3e70000000000000UL lane.Width

/// <summary>
/// A half-precision value widened exactly into a lane. A normal value, an
/// infinity and a NaN move their fields, a signalling NaN coming back quiet;
/// a denormal one is its fraction times two to the -24, which the IR's own
/// conversion and multiply compute exactly, and so is a zero.
/// </summary>
let widenHalf lane (h: Expr) =
  let rt = lane.Width
  let exp = AST.extract h 5<rt> 10
  let frac = AST.zext rt (AST.extract h 10<rt> 0)
  let sign = AST.zext rt (AST.extract h 1<rt> 15) << numI32 (int rt - 1) rt
  let moved = frac << numI32 (lane.FracBits - 10) rt
  let ones = (AST.num1 rt << numI32 lane.ExpBits rt) .- AST.num1 rt
  let top = ones << numI32 lane.FracBits rt
  let quiet = AST.num1 rt << numI32 (lane.FracBits - 1) rt
  let rebias = numI32 ((1 <<< (lane.ExpBits - 1)) - 16) rt
  let normal = ((AST.zext rt exp .+ rebias) << numI32 lane.FracBits rt) .| moved
  let isInf = frac == AST.num0 rt
  let special = AST.ite isInf (top .| moved) (top .| moved .| quiet)
  let small = AST.fmul (AST.cast CastKind.UIntToFloat rt frac) (halfUlp lane)
  let finite = AST.ite (exp == AST.num0 5<rt>) small normal
  sign .| AST.ite (exp == numI32 31 5<rt>) special finite

/// A double of the same class as a half, for FPRF: its exact widening, but
/// for a half denormal, which widens to a normal double, a double denormal
/// of its sign.
let private classOfHalf (h: Expr) =
  let tiny =
    (AST.extract h 5<rt> 10 == AST.num0 5<rt>)
    .& (AST.extract h 10<rt> 0 != AST.num0 10<rt>)
  let sign = AST.zext 64<rt> (AST.extract h 1<rt> 15) << numI32 63 64<rt>
  AST.ite tiny (sign .| AST.num1 64<rt>) (widenHalf double h)

/// A float narrowed to half precision in the direction FPSCR[RN] names.
let private toHalf bld (x: Expr) =
  AST.app "FCVTHALF" [ x; roundingArg bld ] 16<rt>

/// <summary>
/// xscvhpdp and xscvdphp: the half in halfword 3 of xB widened to a double
/// in doubleword 0 of xT, or the double in doubleword 0 narrowed to a half
/// there, zero-extended; doubleword 1 is cleared and FPRF set to the
/// result's class as represented in its own format.
/// </summary>
let scalarHalf ins (bld: ILowUIRBuilder) toDouble =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, _) = vsrOf bld o2
    let half = tmpVar bld 16<rt>
    if toDouble then
      dh := widenHalf double (AST.xtlo 16<rt> bh)
      dl := AST.num0 64<rt>
      setFPRF bld dh
    else
      half := toHalf bld bh
      dh := AST.zext 64<rt> half
      dl := AST.num0 64<rt>
      setFPRF bld (classOfHalf half)
  }

/// xvcvhpsp: the half in the low halfword of each word, widened.
let halfToSingle (_: Lane) xs = widenHalf single (AST.xtlo 16<rt> (one xs))

/// xvcvsphp: each single narrowed to a half in its word's low halfword.
let singleToHalf bld (_: Lane) xs = AST.zext 32<rt> (toHalf bld (one xs))

/// xvcvbf16spn: the bfloat16 in the low halfword of each word moved to the
/// high one, which is the single it stands for, NaNs and all.
let bfloat16ToSingle (_: Lane) xs =
  AST.concat (AST.xtlo 16<rt> (one xs)) (AST.num0 16<rt>)

/// xvcvspbf16: each single narrowed to bfloat16 in the direction FPSCR[RN]
/// names, into its word's low halfword.
let singleToBfloat16 bld (_: Lane) xs =
  let bf = AST.app "FCVTBF16" [ one xs; roundingArg bld ] 16<rt>
  AST.zext 32<rt> bf

/// A double rounded to a single, a NaN by its own bits -- quieted, keeping
/// its sign and the leading 22 bits of its payload -- as the cast of a NaN is
/// left to the host.
let private narrowDouble (x: Expr) =
  let sign = AST.extract x 1<rt> 63
  let payload = AST.extract x 22<rt> 29
  let top = AST.concat sign (numU32 0xffu 8<rt>)
  let nan = AST.concat top (AST.concat (AST.num1 1<rt>) payload)
  AST.ite (isNaNOf double x) nan (AST.cast CastKind.FloatCast 32<rt> x)

/// xvcvdpsp: each double rounded to a single, in both words of its
/// doubleword.
let doubleToSingle (_: Lane) xs =
  let s = narrowDouble (one xs)
  AST.concat s s

/// xvcvspdp: the single in the high word of each doubleword, widened.
let singleToDouble (_: Lane) xs =
  AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> (one xs))

/// <summary>
/// Where a conversion to an integer saturates: the doubles beyond which it
/// does and the integers it answers there, one row of the ISA's tables. A
/// NaN answers with the low end, the smallest signed value or zero.
/// </summary>
let private limits isWord isSigned =
  match isWord, isSigned with
  | true, true ->
    let lo, hi = 0xc1e0000000000000UL, 0x41dfffffffc00000UL
    struct (lo, hi, 0xffffffff80000000UL, 0x000000007fffffffUL)
  | true, false ->
    struct (0UL, 0x41efffffffe00000UL, 0UL, 0x00000000ffffffffUL)
  | false, true ->
    let lo, hi = 0xc3e0000000000000UL, 0x43e0000000000000UL
    struct (lo, hi, 0x8000000000000000UL, 0x7fffffffffffffffUL)
  | false, false ->
    struct (0UL, 0x43f0000000000000UL, 0UL, 0xffffffffffffffffUL)

/// The conversion itself, before the limits: truncation toward zero, an
/// unsigned value at or above 2^63 folded down and biased back.
let private truncated isSigned src =
  let toInt e = AST.floatToSInt RoundingMode.TowardZero 64<rt> e
  let twoPow63 = numU64 0x43e0000000000000UL 64<rt>
  let bias = numU64 0x8000000000000000UL 64<rt>
  let folded = toInt (AST.fsub src twoPow63) .+ bias
  if isSigned then toInt src
  else AST.ite (AST.fge src twoPow63) folded (toInt src)

/// <summary>
/// A double converted to a 64-bit or a 32-bit integer (the word in the low
/// half), truncated toward zero and saturated at the ends of the range, a
/// NaN answering with the low end, as the ISA's convert-to-integer tables
/// say.
/// </summary>
let toInteger isWord isSigned src =
  let struct (lo, hi, loValue, hiValue) = limits isWord isSigned
  let n v = numU64 v 64<rt>
  let cut = truncated isSigned src
  let inRange = AST.ite (AST.fle src (n lo)) (n loValue) cut
  let ranged = AST.ite (AST.fge src (n hi)) (n hiValue) inRange
  AST.ite (isNaNOf double src) (n loValue) ranged

/// xvcvdp[su]xds: each double to a doubleword integer.
let doubleToLong isSigned (_: Lane) xs = toInteger false isSigned (one xs)

/// xvcvdp[su]xws: each double to a word integer, in both words of its
/// doubleword.
let doubleToInt isSigned (_: Lane) xs =
  let w = AST.xtlo 32<rt> (toInteger true isSigned (one xs))
  AST.concat w w

/// xvcvsp[su]xds: the single in the high word of each doubleword to a
/// doubleword integer, through its exact double.
let singleToLong isSigned (_: Lane) xs =
  toInteger false isSigned (singleToDouble single xs)

/// xvcvsp[su]xws: each single to a word integer.
let singleToInt isSigned (_: Lane) xs =
  let d = AST.cast CastKind.FloatCast 64<rt> (one xs)
  AST.xtlo 32<rt> (toInteger true isSigned d)

/// The cast from an integer, signed or unsigned.
let private fromInt isSigned rt x =
  let kind = if isSigned then CastKind.SIntToFloat else CastKind.UIntToFloat
  AST.cast kind rt x

/// xvcv[su]xddp and xvcv[su]xwsp: each element converted to the float of its
/// own width, rounded in the direction FPSCR[RN] names.
let intToFloat isSigned (lane: Lane) xs = fromInt isSigned lane.Width (one xs)

/// xvcv[su]xdsp: each doubleword integer rounded to a single, in both words.
let longToSingle isSigned (_: Lane) xs =
  let s = fromInt isSigned 32<rt> (one xs)
  AST.concat s s

/// xvcvuxwdp: the unsigned word in the high half of each doubleword,
/// converted exactly to a double.
let uintToDouble (_: Lane) xs =
  fromInt false 64<rt> (AST.zext 64<rt> (AST.xthi 32<rt> (one xs)))

(*
  Lifts the quad-precision forms of primary opcode 60's neighbour 63: the
  arithmetic, the compares, the conversions and the operations on a quad's
  fields. A quad is the whole of a vector register, VSR 32 to 63, read
  here as one 128-bit value whose high half is doubleword 0.

  LowUIR has no 128-bit floating-point type, so every operation that
  rounds a quad goes out as a named call -- FADD128, FSUB128, FMUL128,
  FDIV128, FSQRT128, FMA128, FRINT128, FRND80, FCVT128TO64 and FCVTINT128,
  specified in lanes/X.md -- with the rounding direction passed in. What
  does not round is spelt out in the IR: the signs, the fields, the
  compares, the conversions to an integer, and the exact conversions from
  a double and from a doubleword. Which NaN an operation answers with is
  settled in the IR too, in POWER's order, so a named call's own NaN
  does not matter.
*)
/// A 128-bit constant from its two halves.
let private q128 (hi: uint64) (lo: uint64) =
  let v = (bigint hi <<< 64) ||| bigint lo
  AST.num (BitVector(v, 128<rt>))

/// The sign bit of a quad.
let private signBit = q128 0x8000000000000000UL 0UL

/// The exponent field of a quad, in place.
let private quadExpMask = q128 0x7fff000000000000UL 0UL

/// The fraction field of a quad, in place.
let private quadFracMask = q128 0x0000ffffffffffffUL 0xffffffffffffffffUL

/// The bit that makes a NaN quiet.
let private quadQuietBit = q128 0x0000800000000000UL 0UL

/// The positive default quiet NaN.
let private defaultNaN = q128 0x7fff800000000000UL 0UL

let private zero128 = AST.num0 128<rt>

let isNaN q =
  ((q .& quadExpMask) == quadExpMask) .& ((q .& quadFracMask) != zero128)

let isSNaN q = isNaN q .& ((q .& quadQuietBit) == zero128)

let isQNaN q = isNaN q .& ((q .& quadQuietBit) != zero128)

let isInf q =
  ((q .& quadExpMask) == quadExpMask) .& ((q .& quadFracMask) == zero128)

let isZero q = (q .& AST.not signBit) == zero128

let isDenormal q = ((q .& quadExpMask) == zero128) .& AST.not (isZero q)

let private quieted q = q .| quadQuietBit

let private negative q = AST.xthi 1<rt> q

/// The quad in the vector register an operand names.
let quadOf bld opr =
  let struct (h, l) = vsrOf bld opr
  AST.concat h l

/// Writes a quad into the vector register an operand names, through a
/// temporary so a source that is also the target is read first.
let private writeQuad bld opr (q: Expr) =
  let struct (h, l) = vsrOf bld opr
  let t = tmpVar bld 128<rt>
  append bld {
    t := q
    h := AST.xthi 64<rt> t
    l := AST.xtlo 64<rt> t
  }
  t

/// FPRF set to the class and sign of a quad.
let private setFPRF128 bld q =
  let fpscr = regVar bld Register.FPSCR
  let nan = isNaN q
  let zero = isZero q
  let sign = negative q
  let finiteOrInf = AST.not nan .& AST.not zero
  append bld {
    AST.extract fpscr 1<rt> 16 := nan .| isDenormal q .| (zero .& sign)
    AST.extract fpscr 1<rt> 15 := finiteOrInf .& sign
    AST.extract fpscr 1<rt> 14 := finiteOrInf .& AST.not sign
    AST.extract fpscr 1<rt> 13 := zero
    AST.extract fpscr 1<rt> 12 := nan .| isInf q
  }

/// The rounding direction FPSCR[RN] names, as the named calls take it.
let private quadByFPSCR bld =
  AST.zext 8<rt> (AST.extract (regVar bld Register.FPSCR) 2<rt> 0)

/// The direction an "o" form or a plain one rounds in: to odd (4), or the
/// one FPSCR[RN] names.
let private directionOf bld toOdd =
  if toOdd then numI32 4 8<rt> else quadByFPSCR bld

/// The first NaN of the operands in the order given, quieted, or the
/// default NaN where none is a NaN but the answer is.
let private quadSettleNaN operands (res: Expr) =
  let rec firstNaN = function
    | [] -> AST.ite (isNaN res) defaultNaN res
    | x :: rest -> AST.ite (isNaN x) (quieted x) (firstNaN rest)
  firstNaN operands

/// The operands of a "vRT, vRA, vRB".
let private three (ins: Instruction) bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  struct (o1, quadOf bld o2, quadOf bld o3)

/// <summary>
/// xsaddqp, xssubqp, xsmulqp and xsdivqp (and their round-to-odd "o"
/// forms): the named call, its NaN settled in POWER's order (vRA, then
/// vRB), the result in vRT and its class in FPRF.
/// </summary>
let quadArith ins bld name toOdd =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let mode = directionOf bld toOdd
    let res = AST.app name [ a; b; mode ] 128<rt>
    let t = writeQuad bld dst (quadSettleNaN [ a; b ] res)
    setFPRF128 bld t
  }

/// xssqrtqp[o]: the square root of vRB, a negative operand being invalid.
let quadSquareRoot ins bld toOdd =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let mode = directionOf bld toOdd
    let res = AST.app "FSQRT128" [ b; mode ] 128<rt>
    let t = writeQuad bld o1 (quadSettleNaN [ b ] res)
    setFPRF128 bld t
  }

/// <summary>
/// The quad multiply-adds: vRA times vRB plus (or minus) vRT, fused, the
/// negating forms flipping the rounded result's sign, a NaN excepted. A NaN
/// comes back in POWER's order: vRA, then the addend vRT, then vRB.
/// </summary>
let mulAdd ins bld subtract negate toOdd =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let t = quadOf bld dst
    let old = tmpVar bld 128<rt>
    let res = tmpVar bld 128<rt>
    let flags = numI32 (if subtract then 2 else 0) 8<rt>
    let mode = directionOf bld toOdd
    old := t
    res := AST.app "FMA128" [ a; b; old; flags; mode ] 128<rt>
    res := quadSettleNaN [ a; old; b ] res
    let flipped = AST.ite (isNaN res) res (res <+> signBit)
    let written = writeQuad bld dst (if negate then flipped else res)
    setFPRF128 bld written
  }

/// xsabsqp, xsnabsqp and xsnegqp: the sign bit cleared (0), set (1) or
/// flipped (2), nothing else touched, NaNs included.
let quadSignOp ins bld kind =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let res =
      match kind with
      | 0 -> b .& AST.not signBit
      | 1 -> b .| signBit
      | _ -> b <+> signBit
    writeQuad bld o1 res |> ignore
  }

/// xscpsgnqp: the sign of vRA on the rest of vRB.
let copySign ins bld =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let res = (a .& signBit) .| (b .& AST.not signBit)
    writeQuad bld dst res |> ignore
  }

/// Whether a is less than b, neither a NaN: two zeroes are equal whatever
/// their signs; otherwise a sign-magnitude comparison.
let private lessThan a b =
  let ma = a .& AST.not signBit
  let mb = b .& AST.not signBit
  let sa = negative a
  let sb = negative b
  let bothZero = (ma == zero128) .& (mb == zero128)
  let bySign = AST.ite (sa != sb) sa (AST.ite sa (ma .> mb) (ma .< mb))
  AST.not bothZero .& bySign

/// Whether a equals b, neither a NaN.
let private equalTo a b = (a == b) .| (isZero a .& isZero b)

/// The all-ones or all-zeroes of a 128-bit mask.
let private quadMaskOf cond = AST.ite cond (AST.not zero128) zero128

/// xscmpeqqp, xscmpgtqp and xscmpgeqp: vRT all ones where the compare is
/// true, a NaN comparing false.
let compareMask ins bld kind =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let ordered = AST.not (isNaN a .| isNaN b)
    let cond =
      match kind with
      | 0 -> equalTo a b
      | 1 -> lessThan b a
      | _ -> lessThan b a .| equalTo a b
    writeQuad bld dst (quadMaskOf (ordered .& cond)) |> ignore
  }

/// <summary>
/// The invalid-operation bits a quad compare into a CR field sets: VXSNAN
/// for a signalling NaN; for the ordered compare also VXVC for any NaN,
/// except a signalling one when VE is set.
/// </summary>
let private compareFlags bld ordered a b =
  let fpscr = regVar bld Register.FPSCR
  let vxsnan = AST.extract fpscr 1<rt> 24
  let snan = isSNaN a .| isSNaN b
  append bld { vxsnan := vxsnan .| snan }
  if ordered then
    let vxvc = AST.extract fpscr 1<rt> 19
    let ve = AST.extract fpscr 1<rt> 7
    let un = isNaN a .| isNaN b
    append bld { vxvc := vxvc .| AST.ite snan (AST.not ve) un }
  else
    ()

/// xscmpuqp and xscmpoqp: less-than, greater-than, equal or unordered into a
/// CR field and FPCC.
let compareField ins bld ordered =
  lift bld ins {
    let struct (f, a, b) = three ins bld
    let un = isNaN a .| isNaN b
    let lt = AST.not un .& lessThan a b
    let gt = AST.not un .& lessThan b a
    let eq = AST.not un .& equalTo a b
    writeField bld f true [| lt; gt; eq; un |]
    compareFlags bld ordered a b
  }

/// xscmpexpqp: the exponent fields compared as unsigned numbers, unordered
/// where either quad is a NaN.
let compareExponents ins bld =
  lift bld ins {
    let struct (f, a, b) = three ins bld
    let ea = AST.extract a 15<rt> 112
    let eb = AST.extract b 15<rt> 112
    let un = isNaN a .| isNaN b
    let lt = AST.not un .& (ea .< eb)
    let gt = AST.not un .& (ea .> eb)
    let eq = AST.not un .& (ea == eb)
    writeField bld f true [| lt; gt; eq; un |]
  }

/// xsmaxcqp and xsmincqp: vRB where either is a NaN or on a tie, otherwise
/// the greater (or lesser).
let quadMaxMinC ins bld isMax =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let picked = if isMax then lessThan b a else lessThan a b
    let ordered = AST.not (isNaN a .| isNaN b)
    writeQuad bld dst (AST.ite (ordered .& picked) a b) |> ignore
  }

/// The immediate operand an instruction carries, as an int.
let private quadImmOf = function
  | OprImm n -> int n
  | _ -> raise InvalidOperandException

/// <summary>
/// xststdcqp, "BF, vRB, DCMX": the sign of the quad in vRB, 0, whether it
/// is in a class DCMX selects (bit 0 the highest: NaN, +Inf, -Inf, +0, -0,
/// +denormal, -denormal), and 0, into a CR field and FPCC.
/// </summary>
let testClass ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = quadOf bld o2
    let dcmx = quadImmOf o3
    let sign = negative b
    let positive = AST.not sign
    let classes =
      [| isNaN b
         isInf b .& positive
         isInf b .& sign
         isZero b .& positive
         isZero b .& sign
         isDenormal b .& positive
         isDenormal b .& sign |]
    let matched =
      classes
      |> Array.indexed
      |> Array.filter (fun (k, _) -> (dcmx >>> (6 - k)) &&& 1 = 1)
      |> Array.map snd
      |> Array.fold (.|) AST.b0
    writeField bld o1 true [| sign; AST.b0; matched; AST.b0 |]
  }

/// A doubleword moved into a quad's doubleword 0, doubleword 1 cleared.
let private inDoubleword0 (d: Expr) = AST.zext 128<rt> d << numI32 64 128<rt>

/// xsxexpqp: the exponent field of vRB, zero-extended into doubleword 0.
let quadExtractExponent ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let exp = AST.zext 64<rt> (AST.extract b 15<rt> 112)
    writeQuad bld o1 (inDoubleword0 exp) |> ignore
  }

/// The implicit bit of a quad's significand.
let private implicitBit = q128 0x0001000000000000UL 0UL

/// Whether a quad is normal: its exponent field neither zero nor all ones.
let private isNormal q =
  ((q .& quadExpMask) != zero128) .& ((q .& quadExpMask) != quadExpMask)

/// xsxsigqp: the fraction of vRB with the implicit bit where it is normal.
let quadExtractSignificand ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let frac = b .& quadFracMask
    let res = AST.ite (isNormal b) (frac .| implicitBit) frac
    writeQuad bld o1 res |> ignore
  }

/// xsiexpqp: the sign and fraction of vRA with the low 15 bits of vRB's
/// doubleword 0 as the exponent field.
let quadInsertExponent ins bld =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let exp = AST.zext 128<rt> (AST.extract b 15<rt> 64)
    let res = (a .& AST.not quadExpMask) .| (exp << numI32 112 128<rt>)
    writeQuad bld dst res |> ignore
  }

/// <summary>
/// A 64-bit magnitude, nonzero, as a quad's exponent field and fraction: it
/// is normalized by its leading zeroes, the leading one becoming the
/// implicit bit (shifted to bit 112 and masked off), so the conversion is
/// exact. top is the exponent the magnitude's bit 63 stands for.
/// </summary>
let private normalized (mag: Expr) top =
  let lz = VectorLifter.countLeadingZerosOf 64<rt> mag
  let shift = AST.zext 128<rt> lz .+ numI32 49 128<rt>
  let frac = (AST.zext 128<rt> mag << shift) .& quadFracMask
  let biased = numI32 (16383 + top) 64<rt> .- lz
  (AST.zext 128<rt> biased << numI32 112 128<rt>) .| frac

/// <summary>
/// xscvdpqp: the double in doubleword 0 of vRB, exactly as a quad: a normal
/// one by its fields, a denormal one normalized, a signalling NaN quieted.
/// FPRF is set.
/// </summary>
let fromDouble ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let d = AST.xthi 64<rt> (quadOf bld o2)
    let sign = AST.zext 128<rt> (AST.xthi 1<rt> d) << numI32 127 128<rt>
    let exp = AST.extract d 11<rt> 52
    let frac = d .& numU64 0xfffffffffffffUL 64<rt>
    let moved = AST.zext 128<rt> frac << numI32 60 128<rt>
    let rebiased = AST.zext 128<rt> exp .+ numI32 (16383 - 1023) 128<rt>
    let normal = (rebiased << numI32 112 128<rt>) .| moved
    let inf = quadExpMask .| moved
    let noFraction = frac == AST.num0 64<rt>
    let special = AST.ite noFraction inf (inf .| quadQuietBit)
    let tiny = AST.ite noFraction zero128 (normalized frac (-1011))
    let byExp = AST.ite (exp == AST.num0 11<rt>) tiny normal
    let res = sign .| AST.ite (exp == numI32 0x7ff 11<rt>) special byExp
    let t = writeQuad bld o1 res
    setFPRF128 bld t
  }

/// xscvsdqp and xscvudqp: the doubleword integer in doubleword 0 of vRB,
/// exactly as a quad. FPRF is set.
let fromLong ins bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let x = AST.xthi 64<rt> (quadOf bld o2)
    let neg = if isSigned then AST.xthi 1<rt> x else AST.b0
    let mag = AST.ite neg (AST.neg x) x
    let sign = AST.zext 128<rt> neg << numI32 127 128<rt>
    let value = sign .| normalized mag 63
    let res = AST.ite (mag == AST.num0 64<rt>) zero128 value
    let t = writeQuad bld o1 res
    setFPRF128 bld t
  }

/// xscvsqqp and xscvuqqp: the quadword integer in vRB rounded to a quad in
/// the direction FPSCR[RN] names, through the named call. FPRF is set.
let fromQuadword ins bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let x = quadOf bld o2
    let signed = numI32 (if isSigned then 1 else 0) 8<rt>
    let args = [ x; signed; quadByFPSCR bld ]
    let t = writeQuad bld o1 (AST.app "FCVTINT128" args 128<rt>)
    setFPRF128 bld t
  }

/// <summary>
/// xscvqpdp and xscvqpdpo: vRB rounded to a double in doubleword 0, in the
/// direction FPSCR[RN] names or to odd, through the named call; a NaN keeps
/// the top of its fraction and comes back quiet. Doubleword 1 is cleared
/// and FPRF set.
/// </summary>
let toDouble ins bld toOdd =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let struct (dh, dl) = vsrOf bld o1
    let sign = AST.xthi 64<rt> b .& numU64 0x8000000000000000UL 64<rt>
    let top = AST.xtlo 64<rt> ((b .& quadFracMask) >> numI32 60 128<rt>)
    let nan = sign .| numU64 0x7ff8000000000000UL 64<rt> .| top
    let rounded = AST.app "FCVT128TO64" [ b; directionOf bld toOdd ] 64<rt>
    dh := AST.ite (isNaN b) nan rounded
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

/// 2 to the n as a 128-bit integer.
let private pow2 n = AST.num1 128<rt> << numI32 n 128<rt>

/// <summary>
/// A quad truncated toward zero to an integer of the given width, as a
/// 128-bit magnitude: the significand shifted by the unbiased exponent. A
/// magnitude too big for the width is caught by the caller; anything below
/// one is zero.
/// </summary>
let private truncatedMagnitude q =
  let biased = AST.zext 16<rt> (AST.extract q 15<rt> 112)
  let unbiased = biased .- numI32 16383 16<rt>
  let mant = (q .& quadFracMask) .| implicitBit
  let right = AST.zext 128<rt> (numI32 112 16<rt> .- unbiased)
  let left = AST.zext 128<rt> (unbiased .- numI32 112 16<rt>)
  let shifted =
    AST.ite (unbiased ?<= numI32 112 16<rt>) (mant >> right) (mant << left)
  struct (unbiased, AST.ite (unbiased ?< AST.num0 16<rt>) zero128 shifted)

/// <summary>
/// A quad converted to a signed or unsigned integer of a width (32, 64 or
/// 128), truncated toward zero and saturated, as the ISA's convert tables
/// say: a NaN gives the smallest signed value or zero; a value past either
/// end gives that end; a negative value gives zero to an unsigned one. The
/// result is the width's bits, at 128.
/// </summary>
let private toIntegerOf width isSigned q =
  let struct (unbiased, t) = truncatedMagnitude q
  let huge = unbiased ?>= numI32 width 16<rt>
  let neg = negative q
  let mask =
    if width = 128 then AST.not zero128 else pow2 width .- AST.num1 128<rt>
  if isSigned then
    let half = pow2 (width - 1)
    let maxValue = half .- AST.num1 128<rt>
    let minValue = half
    let posOver = huge .| (t .> maxValue)
    let negOver = huge .| (t .> half)
    let positive = AST.ite posOver maxValue t
    let negated = AST.ite negOver minValue (AST.neg t .& mask)
    AST.ite (isNaN q) minValue (AST.ite neg negated positive)
  else
    let over = huge .| (t .> mask)
    let positive = AST.ite over mask t
    AST.ite (isNaN q .| neg) zero128 positive

/// <summary>
/// xscvqp[su][dwq]z: vRB converted to an integer of the given width,
/// truncated and saturated. A word is extended to a doubleword as its
/// signedness says; a word or a doubleword goes in doubleword 0 with
/// doubleword 1 cleared. FPRF is left alone (the ISA leaves it undefined).
/// </summary>
let quadToInteger ins bld width isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let bits = toIntegerOf width isSigned b
    let res =
      match width with
      | 128 ->
        bits
      | 64 ->
        inDoubleword0 (AST.xtlo 64<rt> bits)
      | _ ->
        let w = AST.xtlo 32<rt> bits
        let ext = if isSigned then AST.sext 64<rt> w else AST.zext 64<rt> w
        inDoubleword0 ext
    writeQuad bld o1 res |> ignore
  }

/// <summary>
/// The rounding direction a Z23-form's R and RMC name, as the named calls
/// take it: R = 0 with RMC = 0 rounds to nearest with ties away from zero
/// (5), R = 0 with RMC = 3 in the direction FPSCR[RN] names, and R = 1 in
/// the direction RMC names (0 to nearest, 1 toward zero, 2 toward +Inf, 3
/// toward -Inf).
/// </summary>
let private directionOfRMC bld r rmc =
  match r, rmc with
  | 0, 0 -> numI32 5 8<rt>
  | 0, _ -> quadByFPSCR bld
  | _ -> numI32 rmc 8<rt>

/// The operands of a Z23-form: "R, vRT, vRB, RMC".
let private z23 (ins: Instruction) =
  match ins.Operands with
  | FourOperands(OprImm r, t, b, OprImm rmc) -> struct (int r, t, b, int rmc)
  | _ -> raise InvalidOperandException

/// <summary>
/// xsrqpi and xsrqpix: vRB rounded to an integral value in the direction R
/// and RMC name, through the named call; a NaN comes back quiet, an
/// infinity or a zero as it is. FPRF is set.
/// </summary>
let roundToIntegral ins bld =
  lift bld ins {
    let struct (r, o1, o2, rmc) = z23 ins
    let b = quadOf bld o2
    let mode = directionOfRMC bld r rmc
    let rounded = AST.app "FRINT128" [ b; mode ] 128<rt>
    let t = writeQuad bld o1 (AST.ite (isNaN b) (quieted b) rounded)
    setFPRF128 bld t
  }

/// The low 49 bits of a quad's fraction, which double-extended precision's
/// 64-bit significand does not hold.
let private beyondX80 = q128 0UL 0x0001ffffffffffffUL

/// <summary>
/// xsrqpxp: vRB rounded to double-extended precision -- the quad's exponent
/// range, a 64-bit significand -- in the direction R and RMC name, through
/// the named call; a NaN comes back quiet with its fraction cut to that
/// precision. FPRF is set.
/// </summary>
let roundToX80 ins bld =
  lift bld ins {
    let struct (r, o1, o2, rmc) = z23 ins
    let b = quadOf bld o2
    let mode = directionOfRMC bld r rmc
    let rounded = AST.app "FRND80" [ b; mode ] 128<rt>
    let nan = quieted b .& AST.not beyondX80
    let t = writeQuad bld o1 (AST.ite (isNaN b) nan rounded)
    setFPRF128 bld t
  }

(*
  Lifts the Matrix-Multiply Assist forms: the accumulator moves and the
  rank-k updates (the "ger" forms). Accumulator n is no state of its own:
  the manual has VSR 4n to 4n + 3 and ACC[n] hold the same data, so row i
  of the accumulator is VSR 4n + i, the moves between the two are no-ops,
  and an update writes those registers. A source never overlaps the
  accumulator it updates (the decoder refuses that form), so each row is
  written as soon as it is computed.
*)
/// The rows of the accumulator an operand names: the halves of VSR 4n to
/// 4n + 3.
let private rowsOf bld opr =
  match opr with
  | OprReg reg when reg >= Register.ACC0 && reg <= Register.ACC7 ->
    let n = int reg - int Register.ACC0
    Array.init 4 (fun i ->
      vsrOf bld (OprReg(getVsxRegister (uint32 (4 * n + i)))))
  | _ ->
    raise InvalidOperandException

/// Clears a row.
let private clearRow bld (struct (h: Expr, l: Expr)) =
  append bld {
    h := AST.num0 64<rt>
    l := AST.num0 64<rt>
  }

/// xxsetaccz: every row of the accumulator cleared.
let setAccumulatorZero ins bld =
  lift bld ins {
    rowsOf bld (getOneOpr ins) |> Array.iter (clearRow bld)
  }

/// <summary>
/// A rank-k update over words: element j of row i computed by f from word i
/// of xA, word j of xB and the element itself, each row written through
/// temporaries once its four words are computed.
/// </summary>
let private updateWords (ins: Instruction) bld f =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (ah, al) = vsrOf bld o2
  let struct (bh, bl) = vsrOf bld o3
  let xs = lanesOf 32<rt> ah al
  let ys = lanesOf 32<rt> bh bl
  rowsOf bld o1
  |> Array.iteri (fun i (struct (h, l)) ->
    let accs = lanesOf 32<rt> h l
    let results = Array.init 4 (fun j -> f xs[i] ys[j] accs[j])
    writeLanes bld 32<rt> h l results)

/// A rank-k update over words, as one instruction.
let private wordUpdate ins bld f =
  lift bld ins {
    updateWords ins bld f
  }

/// <summary>
/// One element of a single- or double-precision update: the product (kind
/// 0) or the fused multiply-add of the four accumulating kinds -- 1 adds
/// the element, 2 subtracts it, 3 subtracts it and negates the rounded
/// result, 4 adds it and negates -- through the calls the other vector
/// multiply-adds make, NaNs in POWER's order.
/// </summary>
let private fusedElement bld lane kind x y acc =
  if kind = 0 then
    arith AST.fmul lane [ x; y ]
  else
    let subtract = kind = 2 || kind = 3
    mulAddLane bld lane false subtract (kind >= 3) x y acc

/// The register an operand names.
let private regOf = function
  | OprReg reg -> reg
  | _ -> raise InvalidOperandException

/// xvf32ger and its accumulating forms.
let singleUpdate ins bld kind =
  wordUpdate ins bld (fusedElement bld single kind)

/// <summary>
/// xvf64ger and its accumulating forms: the four doubles of the pair
/// starting at xA by the two of xB, each row of the accumulator two
/// doublewords.
/// </summary>
let doubleUpdate (ins: Instruction) bld kind =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (a0, a1) = vsrOf bld o2
    let struct (a2, a3) = vsrOf bld (OprReg(secondOfPair (regOf o2)))
    let struct (y0, y1) = vsrOf bld o3
    let xs = [| a0; a1; a2; a3 |]
    let f x y acc = fusedElement bld double kind x y acc
    rowsOf bld o1
    |> Array.iteri (fun i (struct (h, l)) ->
      writeLanes bld 64<rt> h l [| f xs[i] y0 h; f xs[i] y1 l |])
  }

/// The 16-bit value in halfword k (0 the high one) of a word.
let private halfword (w: Expr) k =
  if k = 0 then AST.xthi 16<rt> w else AST.xtlo 16<rt> w

/// A bfloat16 as the single it is, a NaN quieted.
let private widenBF16 (h: Expr) =
  let s = AST.zext 32<rt> h << numI32 16 32<rt>
  let lane = single
  AST.ite (isNaNOf lane s) (quietOf lane s) s

/// The first NaN of a stage, quieted, or the stage's computed fallback.
let private nanChoice candidates fallback =
  let lane = single
  List.foldBack (fun c rest ->
    AST.ite (isNaNOf lane c) (quietOf lane c) rest)
    candidates fallback

/// A single-precision infinity, with either sign.
let private isInfinity value =
  (value .& numU32 0x7fffffffu 32<rt>) == numU32 0x7f800000u 32<rt>

/// Infinity times zero creates a default NaN before later NaNs are selected.
let private invalidProduct x y =
  let lane = single
  (isInfinity x .& isZeroOf lane y)
  .| (isZeroOf lane x .& isInfinity y)

/// A NaN generated by a stage, or a non-NaN placeholder for a regular result.
let private generatedNaN invalid =
  AST.ite invalid (defaultNaNOf single) (AST.num0 32<rt>)

/// Preserve the staged multiply, fused sum and accumulator NaN priorities.
let settleDot widen kind x y acc res =
  let lane = single
  let x0, x1 = widen (halfword x 0), widen (halfword x 1)
  let y0, y1 = widen (halfword y 0), widen (halfword y 1)
  let product =
    nanChoice [ x0; y0 ] (generatedNaN (invalidProduct x0 y0))
  let inf0 = isInfinity x0 .| isInfinity y0
  let inf1 = isInfinity x1 .| isInfinity y1
  let sign0 = AST.xthi 1<rt> (x0 <+> y0)
  let sign1 = AST.xthi 1<rt> (x1 <+> y1)
  let invalidSum = invalidProduct x1 y1 .| (inf0 .& inf1 .& (sign0 != sign1))
  let sum = nanChoice [ x1; product; y1 ] (generatedNaN invalidSum)
  let candidates = if kind = 0 then [ sum ] else [ sum; acc ]
  let fallback =
    AST.ite (isNaNOf lane res) (defaultNaNOf lane) res
  nanChoice candidates fallback

/// <summary>
/// xvf16ger2 and xvbf16ger2 and their accumulating forms: each element the
/// named call FGER2HALF or FGER2BF16 (lanes/X.md) of the two words and the
/// element, in the direction FPSCR[RN] names, its NaN settled here.
/// </summary>
let dotUpdate ins bld isBF16 kind =
  let name = if isBF16 then "FGER2BF16" else "FGER2HALF"
  let widen = if isBF16 then widenBF16 else widenHalf single
  let fpscr = regVar bld Register.FPSCR
  let mode = AST.zext 8<rt> (AST.extract fpscr 2<rt> 0)
  let element x y acc =
    let args = [ x; y; acc; numI32 kind 8<rt>; mode ]
    settleDot widen kind x y acc (AST.app name args 32<rt>)
  wordUpdate ins bld element

/// The fields of a word, most significant first, each width bits wide.
let private fieldsOf (w: Expr) width =
  Array.init (32 / width) (fun k ->
    AST.extract w (width * 1<rt>) (32 - width * (k + 1)))

/// <summary>
/// The sum of the products of matching fields of two words, at a width:
/// xA's fields signed, xB's signed or not.
/// </summary>
let private dotOf rt width ySigned (x: Expr) (y: Expr) =
  let ext signed v = if signed then AST.sext rt v else AST.zext rt v
  Array.map2 (fun a b -> ext true a .* ext ySigned b)
    (fieldsOf x width) (fieldsOf y width)
  |> Array.reduce (.+)

/// xvi4ger8, xvi8ger4, xvi16ger2 and their "pp" forms: the sum of products,
/// plus the element where the form accumulates, modulo two to the 32.
let integerUpdate ins bld width ySigned accumulate =
  let element x y acc =
    let sum = dotOf 32<rt> width ySigned x y
    if accumulate then sum .+ acc else sum
  wordUpdate ins bld element

/// The bounds of a signed word, at 64 bits.
let private wordMin = numI64 (-2147483648L) 64<rt>

let private wordMax = numI64 2147483647L 64<rt>

/// One saturated element: the sum (plus the element where the form
/// accumulates) clamped to a signed word, sat set where it was clamped.
let private saturated bld sat width ySigned accumulate x y acc =
  let sum = dotOf 64<rt> width ySigned x y
  let total = tmpVar bld 64<rt>
  let low = total ?< wordMin
  let high = total ?> wordMax
  append bld {
    total := if accumulate then sum .+ AST.sext 64<rt> acc else sum
    sat := sat .| low .| high
  }
  AST.xtlo 32<rt> (AST.ite low wordMin (AST.ite high wordMax total))

/// <summary>
/// xvi8ger4spp, xvi16ger2s and xvi16ger2spp: the sum of products, plus the
/// element where the form accumulates, saturated to a signed word; a
/// saturated element sets VSCR's sticky SAT bit.
/// </summary>
let saturatingUpdate ins bld width ySigned accumulate =
  lift bld ins {
    let sat = tmpVar bld 1<rt>
    let vscr = regVar bld Register.VSCR
    sat := AST.b0
    updateWords ins bld (saturated bld sat width ySigned accumulate)
    vscr := vscr .| AST.zext 32<rt> sat
  }
