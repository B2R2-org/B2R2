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
