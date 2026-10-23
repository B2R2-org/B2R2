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

module internal B2R2.FrontEnd.PPC.VectorLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper
open B2R2.BinIR
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.GeneralLifter

(*
  The vector facility's registers seen as rows of elements. A vector register
  is kept as two 64-bit halves; the instructions name its elements from the
  most significant end, element 0 sitting at the top of the high half, so an
  element is read out of whichever half holds it and a result is put back
  together from its elements in that same order. A result is assembled in
  temporaries before it reaches the target, so a target that is also a source
  reads its old value throughout.
*)
/// The two halves of a vector register operand, the high one first.
let halvesOf bld opr =
  match opr with
  | OprReg reg -> struct (regVar bld reg, regVar bld (getLowHalf reg))
  | _ -> raise InvalidOperandException

/// The elements of a 128-bit value given as its two halves, element 0 first.
let elementsOfHalves (esize: RegType) hi lo =
  let n = int esize
  if n = 128 then
    [| AST.concat hi lo |]
  else
    let perHalf = 64 / n
    Array.init (128 / n) (fun i ->
      let half = if i < perHalf then hi else lo
      AST.extract half esize ((perHalf - 1 - i % perHalf) * n))

/// The esize-bit elements of a vector register operand, element 0 first.
let elementsOf bld esize opr =
  let struct (hi, lo) = halvesOf bld opr
  elementsOfHalves esize hi lo

/// The 128-bit value a vector register holds.
let quadOf bld opr = (elementsOf bld 128<rt> opr)[0]

/// The value whose elements, element 0 first, are the given ones.
let concatElements (elements: Expr[]) = Array.reduce AST.concat elements

/// Writes a 128-bit value, given as its elements with element 0 first, to a
/// vector register through temporaries. A single quadword element is held
/// whole first, so that its two halves are taken from one computation.
let putElements (bld: ILowUIRBuilder) opr (elements: Expr[]) =
  let struct (dh, dl) = halvesOf bld opr
  if elements.Length = 1 then
    let q = tmpVar bld 128<rt>
    append bld {
      q := elements[0]
      dh := AST.xthi 64<rt> q
      dl := AST.xtlo 64<rt> q
    }
  else
    let half = elements.Length / 2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    append bld {
      th := concatElements elements[..half - 1]
      tl := concatElements elements[half..]
      dh := th
      dl := tl
    }

/// A number of a given width, from a signed 64-bit value.
let numOf (rt: RegType) (v: int64) = numI64 v rt

/// The smallest and the largest value an esize-bit element holds, signed or
/// unsigned, as numbers of the given wider type. No instruction saturates to
/// a doubleword, so an element is narrower than 64 bits.
let private elementRange esize signed (wide: RegType) =
  let n = int esize
  if signed then
    struct (numOf wide (-(1L <<< (n - 1))), numOf wide ((1L <<< (n - 1)) - 1L))
  else
    struct (AST.num0 wide, numOf wide ((1L <<< n) - 1L))

/// A value computed exactly at a wider type, clamped to the range of an
/// esize-bit element -- signed or unsigned -- and narrowed to it, with whether
/// it had to be clamped. The wider type leaves room for a sign, so the clamp
/// compares as signed whichever kind of element it is.
let saturate esize signed (wide: Expr) =
  let rt = Expr.typeOf wide
  let struct (lo, hi) = elementRange esize signed rt
  let above = wide ?> hi
  let below = wide ?< lo
  let inRange = AST.ite below (AST.xtlo esize lo) (AST.xtlo esize wide)
  let value = AST.ite above (AST.xtlo esize hi) inRange
  struct (value, above .| below)

/// Widens an element, sign- or zero-extending it.
let widen signed (rt: RegType) e =
  if signed then AST.sext rt e else AST.zext rt e

/// Writes the elements of a saturating instruction and sets VSCR[SAT], which
/// is sticky, where any element had to be clamped. Whether one did is settled
/// before the target is written, as the target may be a source.
let putSaturated (bld: ILowUIRBuilder) opr (results: struct (Expr * Expr)[]) =
  let sat = tmpVar bld 1<rt>
  let vscr = regVar bld Register.VSCR
  let clamped = results |> Array.map (fun struct (_, s) -> s)
  append bld { sat := Array.reduce (.|) clamped }
  putElements bld opr (results |> Array.map (fun struct (v, _) -> v))
  append bld { vscr := vscr .| AST.zext 32<rt> sat }

let private vecHalves bld opr =
  match opr with
  | OprReg reg ->
    let lo = if reg >= Register.V0A then getLowHalf reg else getVsxLowHalf reg
    struct (regVar bld reg, regVar bld lo)
  | _ ->
    raise InvalidOperandException

/// The byte of a vector at PowerPC byte index b, where 0 is the most
/// significant byte -- which lives at the top of the high half.
let private vecByte hi lo b =
  if b < 8 then AST.extract hi 8<rt> ((7 - b) * 8)
  else AST.extract lo 8<rt> ((15 - b) * 8)

/// Writes every `esize`-wide element of one 64-bit half from f applied to the
/// matching elements of a and b.
let private applyElements (bld: ILowUIRBuilder) esize dst a b f =
  append bld {
    for i in 0 .. (64 / int esize) - 1 do
      let pos = i * int esize
      AST.extract dst esize pos :=
        f (AST.extract a esize pos) (AST.extract b esize pos)
  }

/// An element-wise "vD, vA, vB" over both halves. The result goes through
/// temporaries first, so a destination that is also a source reads its old
/// value throughout.
let vecBinary ins bld esize f =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    applyElements bld esize th ah bh f
    applyElements bld esize tl al bl f
    dh := th
    dl := tl
  }

/// An element-wise "vD, vB" over both halves.
let vecUnary ins bld esize f =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (64 / int esize) - 1 do
      let pos = i * int esize
      AST.extract th esize pos := f (AST.extract bh esize pos)
      AST.extract tl esize pos := f (AST.extract bl esize pos)
    dh := th
    dl := tl
  }

/// vmulesw/vmulosw, which multiply the signed words at even (0 and 2) or odd
/// (1 and 3) positions of the two sources into doubleword products. An even
/// word is the high one of its doubleword.
let vecMulWord ins bld even =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let pos = if even then 32 else 0
    let word x = AST.sext 64<rt> (AST.extract x 32<rt> pos)
    th := word ah .* word bh
    tl := word al .* word bl
    dh := th
    dl := tl
  }

/// One unsigned byte added or subtracted with saturation: the answer clamped
/// to 0..255 rather than wrapped, and whether it had to be.
let private saturatedByte isAdd a b =
  if isAdd then
    let sum = AST.zext 16<rt> a .+ AST.zext 16<rt> b
    let over = sum .> numI32 255 16<rt>
    struct (AST.ite over (numI32 255 8<rt>) (AST.xtlo 8<rt> sum), over)
  else
    let over = a .< b
    struct (AST.ite over (AST.num0 8<rt>) (a .- b), over)

/// vaddubs/vsububs, the unsigned byte add and subtract that saturate. A byte
/// that had to be clamped sets VSCR's sticky SAT bit, the register's lowest.
let vecSaturateByte ins bld isAdd =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let sat = tmpVar bld 1<rt>
    sat := AST.b0
    for (t, a, b) in [ th, ah, bh; tl, al, bl ] do
      for i in 0 .. 7 do
        let pos = i * 8
        let x = AST.extract a 8<rt> pos
        let y = AST.extract b 8<rt> pos
        let struct (r, over) = saturatedByte isAdd x y
        AST.extract t 8<rt> pos := r
        sat := sat .| over
    dh := th
    dl := tl
    let vscr = regVar bld Register.VSCR
    vscr := vscr .| AST.zext 32<rt> sat
  }

/// The all-ones or all-zeroes an element-wise compare writes per element.
let private compareMask esize cond =
  AST.ite cond (AST.not (AST.num0 esize)) (AST.num0 esize)

/// A vector compare. The record form also reports in CR6 whether every element
/// compared true (bit 0) or none did (bit 2).
let vecCompare ins bld esize rel record =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let f x y = compareMask esize (rel x y)
    applyElements bld esize th ah bh f
    applyElements bld esize tl al bl f
    dh := th
    dl := tl
    if record then
      let ones = AST.not (AST.num0 64<rt>)
      let zero = AST.num0 64<rt>
      regVar bld Register.CR6_0 := (th == ones) .& (tl == ones)
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 := (th == zero) .& (tl == zero)
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }

/// The two addresses a 16-byte vector access uses for the vector's high and low
/// halves. A big-endian guest keeps the most significant half at the lower
/// address; on a little-endian one the whole quadword's byte order reverses,
/// which puts the most significant half at the higher address.
let private quadwordHalves (bld: ILowUIRBuilder) ea =
  let next = ea .+ numI32 8 bld.RegType
  if bld.Endianness = Endian.Big then struct (ea, next) else struct (next, ea)

/// lvx/lvxl, which load the aligned quadword the address falls in.
let lvx ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 15 bld.RegType)
    let struct (hiAddr, loAddr) = quadwordHalves bld tmpEA
    dh := loadNative bld 64<rt> hiAddr
    dl := loadNative bld 64<rt> loAddr
  }

/// stvx/stvxl, which store to the aligned quadword the address falls in.
let stvx ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (sh, sl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 15 bld.RegType)
    let struct (hiAddr, loAddr) = quadwordHalves bld tmpEA
    loadNative bld 64<rt> hiAddr := sh
    loadNative bld 64<rt> loAddr := sl
  }

/// lvsl/lvsr, which build the permute control vector that vperm needs to
/// realign data straddling two quadwords: lvsl counts up from the address's
/// offset within its quadword, lvsr counts down to it.
let lvsx ins (bld: ILowUIRBuilder) isLeft =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let sh = tmpVar bld 8<rt>
    let struct (th, tl) = tmpVars2 bld 64<rt>
    sh := AST.xtlo 8<rt> ea .& numI32 15 8<rt>
    for b in 0 .. 15 do
      let value =
        if isLeft then sh .+ numI32 b 8<rt> else numI32 (16 + b) 8<rt> .- sh
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (7 - b) * 8 else (15 - b) * 8
      AST.extract dst 8<rt> pos := value .& numI32 31 8<rt>
    dh := th
    dl := tl
  }

/// The byte offset within a quadword at which an element access of the given
/// width reaches vector byte b: b itself on a big-endian guest, and on a
/// little-endian one the mirror image, as the register's bytes are numbered
/// from the other end (the ISA's "15 - eb").
let private elementOffset (bld: ILowUIRBuilder) bytes b =
  if bld.Endianness = Endian.Big then b else 16 - bytes - b

/// lvebx/lvehx/lvewx, which load one element into the vector slot the address
/// selects and leave the rest of the register undefined -- modeled here as
/// leaving it unchanged, which is what a real part does in practice.
let lvex ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let bytes = int size / 8
    let tmpEA = tmpVar bld bld.RegType
    let value = tmpVar bld size
    let index = tmpVar bld 8<rt>
    tmpEA := ea .& AST.not (numI32 (bytes - 1) bld.RegType)
    value := loadNative bld size tmpEA
    index := AST.xtlo 8<rt> tmpEA .& numI32 15 8<rt>
    (* The element's slot is fixed at run time, so every slot is written under
       the guard that the address selects it. *)
    for slot in 0 .. (16 / bytes) - 1 do
      let b = slot * bytes
      let dst = if b < 8 then dh else dl
      let pos = if b < 8 then (8 - bytes - b % 8) * 8 else (16 - bytes - b) * 8
      let picked = index == numI32 (elementOffset bld bytes b) 8<rt>
      AST.extract dst size pos :=
        AST.ite picked value (AST.extract dst size pos)
  }

/// stvebx/stvehx/stvewx, the store counterparts of lvebx and friends.
let stvex ins (bld: ILowUIRBuilder) size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (sh, sl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let bytes = int size / 8
    let tmpEA = tmpVar bld bld.RegType
    let index = tmpVar bld 8<rt>
    let value = tmpVar bld size
    tmpEA := ea .& AST.not (numI32 (bytes - 1) bld.RegType)
    index := AST.xtlo 8<rt> tmpEA .& numI32 15 8<rt>
    value := AST.num0 size
    for slot in 0 .. (16 / bytes) - 1 do
      let b = slot * bytes
      let src = if b < 8 then sh else sl
      let pos = if b < 8 then (8 - bytes - b % 8) * 8 else (16 - bytes - b) * 8
      let picked = index == numI32 (elementOffset bld bytes b) 8<rt>
      value := AST.ite picked (AST.extract src size pos) value
    loadNative bld size tmpEA := value
  }

/// lxvd2x/stxvd2x and lxvw4x/stxvw4x, which access a quadword element by
/// element: each element keeps the guest's byte order but the elements
/// themselves are not reordered, unlike lvx.
let lxvx ins (bld: ILowUIRBuilder) esize isLoad =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let bytes = int esize / 8
    let perHalf = 8 / bytes
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    for i in 0 .. (16 / bytes) - 1 do
      let addr = tmpEA .+ numI32 (i * bytes) bld.RegType
      let reg = if i < perHalf then dh else dl
      let pos = (perHalf - 1 - i % perHalf) * int esize
      if isLoad then
        AST.extract reg esize pos := loadNative bld esize addr
      else
        loadNative bld esize addr := AST.extract reg esize pos
  }

/// lxsdx/stxsdx, which move one doubleword to or from a VSX register's high
/// half, and lxvdsx, which splats one into both halves.
let lxsdx ins (bld: ILowUIRBuilder) splat isLoad =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    if isLoad then
      dh := loadNative bld 64<rt> tmpEA
      if splat then
        append bld { dl := dh }
      else
        append bld { dl := AST.num0 64<rt> }
    else
      loadNative bld 64<rt> tmpEA := dh
  }

/// lxsd/stxsd, the ISA 3.0 DS-form moves of one doubleword between memory and
/// the high half of a vector register (VSR32-63). The load clears the low half,
/// as the indexed lxsdx does.
let lxsd ins (bld: ILowUIRBuilder) isLoad =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := transEAWithOffset o2 bld
    if isLoad then
      dh := loadNative bld 64<rt> tmpEA
      dl := AST.num0 64<rt>
    else
      loadNative bld 64<rt> tmpEA := dh
  }

/// A whole-register logical "xT, xA, xB", which the xxl family and the vector
/// logical ops share.
let vecLogical ins bld f = vecBinary ins bld 64<rt> f

/// vsel/xxsel, a bitwise select: a set bit of vC takes vB, a clear one vA.
let vecSelect ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (ch, cl) = vecHalves bld o4
    let struct (th, tl) = tmpVars2 bld 64<rt>
    th := (bh .& ch) .| (ah .& AST.not ch)
    tl := (bl .& cl) .| (al .& AST.not cl)
    dh := th
    dl := tl
  }

/// xxpermdi, which builds a vector from one doubleword of each source: DM's
/// high bit picks which doubleword of xA lands in the result's high half, its
/// low bit which of xB lands in the low half.
let vecPermuteDouble ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let dm =
      match o4 with
      | OprImm n -> int n
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    th := if dm &&& 2 = 0 then ah else al
    tl := if dm &&& 1 = 0 then bh else bl
    dh := th
    dl := tl
  }

/// vperm, which fills each byte of vD from the byte of the 32-byte pair
/// vA || vB that the matching byte of vC indexes.
let vecPermute ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (ch, cl) = vecHalves bld o4
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for b in 0 .. 15 do
      let index = tmpVar bld 8<rt>
      index := vecByte ch cl b .& numI32 31 8<rt>
      let mutable picked = AST.num0 8<rt>
      for src in 0 .. 31 do
        let byteOf =
          if src < 16 then vecByte ah al src else vecByte bh bl (src - 16)
        picked <- AST.ite (index == numI32 src 8<rt>) byteOf picked
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (7 - b) * 8 else (15 - b) * 8
      AST.extract dst 8<rt> pos := picked
    dh := th
    dl := tl
  }

/// vsldoi and xxsldwi, which take the 16 bytes starting a given distance into
/// the 32-byte pair vA || vB -- counted in bytes by vsldoi and in words by
/// xxsldwi.
let vecShiftDouble ins bld scale =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let shift =
      match o4 with
      | OprImm n -> int n * scale
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for b in 0 .. 15 do
      let src = b + shift
      let byteOf =
        if src < 16 then vecByte ah al src else vecByte bh bl (src - 16)
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (7 - b) * 8 else (15 - b) * 8
      AST.extract dst 8<rt> pos := byteOf
    dh := th
    dl := tl
  }

/// vspltb/vsplth/vspltw, which copy one element of vB into every element of vD.
let vecSplat ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let index =
      match o3 with
      | OprImm n -> int n % (128 / int esize)
      | _ -> raise InvalidOperandException
    let perHalf = 64 / int esize
    let element = tmpVar bld esize
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let src = if index < perHalf then bh else bl
    let pos = (perHalf - 1 - index % perHalf) * int esize
    element := AST.extract src esize pos
    for i in 0 .. perHalf - 1 do
      AST.extract th esize (i * int esize) := element
      AST.extract tl esize (i * int esize) := element
    dh := th
    dl := tl
  }

/// vspltisb/vspltish/vspltisw, which fill every element with a signed
/// immediate.
let vecSplatImm ins bld esize =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let value =
      match o2 with
      | OprImm n -> numU64 n esize
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (64 / int esize) - 1 do
      AST.extract th esize (i * int esize) := value
      AST.extract tl esize (i * int esize) := value
    dh := th
    dl := tl
  }

/// vmrgh*/vmrgl*, which interleave the elements of one half of vA with those of
/// the matching half of vB.
let vecMerge ins bld esize high =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (8 / bytes) - 1 do
      let src = if high then i * bytes else 8 + i * bytes
      for (half, srcH, srcL) in [ 0, ah, al; 1, bh, bl ] do
        let b = (2 * i + half) * bytes
        let dst = if b < 8 then th else tl
        let pos = if b < 8 then (8 - bytes - b) * 8 else (16 - bytes - b) * 8
        let value =
          Array.init bytes (fun k -> vecByte srcH srcL (src + k))
          |> Array.rev
          |> AST.revConcat
        AST.extract dst esize pos := value
    dh := th
    dl := tl
  }

/// vmrgew/vmrgow, which take the even (or the odd) words of vA and vB in turn:
/// words 0 and 2 of each for the even form, words 1 and 3 for the odd.
let vecMergeWord ins bld even =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let pick = if even then AST.xthi 32<rt> else AST.xtlo 32<rt>
    let struct (th, tl) = tmpVars2 bld 64<rt>
    th := AST.concat (pick ah) (pick bh)
    tl := AST.concat (pick al) (pick bl)
    dh := th
    dl := tl
  }

/// vpkuhum/vpkuwum, which pack the low half of each element of vA || vB into
/// the elements of vD.
let vecPack ins bld (esize: RegType) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (32 / bytes) - 1 do
      let src = i * bytes + bytes / 2 (* the element's low half *)
      let value =
        Array.init (bytes / 2) (fun k ->
          if src + k < 16 then vecByte ah al (src + k)
          else vecByte bh bl (src + k - 16))
        |> Array.rev
        |> AST.revConcat
      let b = i * (bytes / 2)
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (8 - bytes / 2 - b) * 8
                else (16 - bytes / 2 - b) * 8
      AST.extract dst (regTypeOf (int esize / 2)) pos := value
    dh := th
    dl := tl
  }

/// vupkhs*/vupkls*, which sign-extend the elements of one half of vB into the
/// wider elements of vD.
let vecUnpack ins bld (esize: RegType) high =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (8 / bytes) - 1 do
      let src = (if high then 0 else 8) + i * bytes
      let value =
        Array.init bytes (fun k -> vecByte bh bl (src + k))
        |> Array.rev
        |> AST.revConcat
      let b = i * bytes * 2
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (8 - bytes * 2 - b) * 8
                else (16 - bytes * 2 - b) * 8
      AST.extract dst (regTypeOf (int esize * 2)) pos :=
        AST.sext (regTypeOf (int esize * 2)) value
    dh := th
    dl := tl
  }

/// vsl/vsr, which shift the whole 128-bit vector by the count the low three
/// bits of vB's last byte give, and vslo/vsro, which shift it by whole octets.
let vecShiftWhole ins (bld: ILowUIRBuilder) left byOctet =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (_, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let n = tmpVar bld 64<rt>
    if byOctet then
      n := AST.zext 64<rt> (AST.xtlo 8<rt> bl .& numI32 0x78 8<rt>)
    else
      n := AST.zext 64<rt> (AST.xtlo 8<rt> bl .& numI32 7 8<rt>)
    (* A 128-bit shift over two halves: each half keeps what stays in it and
       takes what the other half shifts across. A count of zero would shift a
       whole half's width, which is undefined, so that case is selected out; a
       count of 64 or more (vslo/vsro by eight octets or more) moves the other
       half over entirely. *)
    let zero = n == AST.num0 64<rt>
    let wide = n .>= numI32 64 64<rt>
    let across = numI32 64 64<rt> .- n
    let beyond = n .- numI32 64 64<rt>
    if left then
      th := AST.ite wide
                    (al << beyond)
                    (AST.ite zero ah ((ah << n) .| (al >> across)))
      tl := AST.ite wide (AST.num0 64<rt>) (al << n)
    else
      th := AST.ite wide (AST.num0 64<rt>) (ah >> n)
      tl := AST.ite wide
                    (ah >> beyond)
                    (AST.ite zero al ((al >> n) .| (ah << across)))
    dh := th
    dl := tl
  }

/// vgbbd, which transposes the bits of each doubleword's eight bytes: bit j of
/// byte i moves to bit i of byte j.
let vecGatherBits ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for (dst, src) in [ th, bh; tl, bl ] do
      for i in 0 .. 7 do
        for j in 0 .. 7 do
          AST.extract dst 1<rt> (j * 8 + i) :=
            AST.extract src 1<rt> (i * 8 + j)
    dh := th
    dl := tl
  }

/// vbpermq, which gathers the sixteen bits of vA that vB's byte indices name
/// into the low halfword of vD; an index past 127 contributes a zero.
let vecBitPermute ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let res = tmpVar bld 64<rt>
    res := AST.num0 64<rt>
    for i in 0 .. 15 do
      let index = tmpVar bld 8<rt>
      index := vecByte bh bl i
      let mutable bit = AST.num0 64<rt>
      for k in 0 .. 127 do
        let src = if k < 64 then ah else al
        let pos = if k < 64 then 63 - k else 127 - k
        let one = AST.zext 64<rt> (AST.extract src 1<rt> pos)
        bit <- AST.ite (index == numI32 k 8<rt>) one bit
      res := res .| (bit << numI32 (15 - i) 64<rt>)
    dh := res
    dl := AST.num0 64<rt>
  }

/// mfvscr/mtvscr, which move the vector status register to or from the low
/// word of a vector register.
let vscrMove ins bld toVector =
  lift bld ins {
    let struct (dh, dl) = vecHalves bld (getOneOpr ins)
    let vscr = regVar bld Register.VSCR
    if toVector then
      dh := AST.num0 64<rt>
      dl := AST.zext 64<rt> vscr
    else
      vscr := AST.xtlo 32<rt> dl
  }

/// Counts the leading zeroes of one element, folding the value down to a mask
/// of the bits at or below its highest set one and counting the ones in it.
let countLeadingZerosOf (esize: RegType) e =
  let n i = numI32 i esize
  let mutable x = e
  let mutable s = 1
  while s < int esize do
    x <- x .| (x >> n s)
    s <- s * 2
  let mask1 = numU64 0x5555555555555555UL esize
  let mask2 = numU64 0x3333333333333333UL esize
  let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL esize
  let mutable p = x .- ((x >> n 1) .& mask1)
  p <- ((p >> n 2) .& mask2) .+ (p .& mask2)
  p <- ((p >> n 4) .+ p) .& mask3
  let mutable s = 8
  while s < int esize do
    p <- p .+ (p >> n s)
    s <- s * 2
  n (int esize) .- (p .& n 127)

/// Counts the set bits of one element by the same halving fold.
let popCountOf (esize: RegType) e =
  let n i = numI32 i esize
  let mask1 = numU64 0x5555555555555555UL esize
  let mask2 = numU64 0x3333333333333333UL esize
  let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL esize
  let mutable p = (e .& mask1) .+ ((e >> n 1) .& mask1)
  p <- (p .& mask2) .+ ((p >> n 2) .& mask2)
  p <- (p .& mask3) .+ ((p >> n 4) .& mask3)
  let mutable s = 8
  while s < int esize do
    p <- p .+ (p >> n s)
    s <- s * 2
  p .& n 127

/// The element-wise shift a vs*b/vs*h/vs*w/vs*d takes: the count comes from the
/// low bits of the matching element of vB.
let elementShift (esize: RegType) kind a b =
  let n = b .& numI32 (int esize - 1) esize
  match kind with
  | 0 ->
    a << n
  | 1 ->
    a >> n
  | 2 ->
    a ?>> n
  | _ ->
    let width = numI32 (int esize) esize
    (a << n) .| (a >> (width .- n)) (* a rotate, whose zero count is a no-op *)
(* The VSX scalar forms work on a double in a vector-scalar register's high
   doubleword, which is the same storage the floating-point forms use for
   VSR0-31; the low doubleword of the target is set to zero, as ISA 3.0
   specifies. *)

/// An "xT, xA, xB" whose operands are the doubles in the sources' high halves.
/// The arithmetic forms set FPRF; the sign-copying one does not.
let vsxScalarBinary ins bld fnOp setsFPRF =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    dh := fnOp ah bh
    dl := AST.num0 64<rt>
    if setsFPRF then setFPRF bld dh else ()
  }

/// The single-precision scalar forms, which compute the same operation and
/// round the answer to single precision, leaving it in the double format a
/// vector-scalar register holds.
let vsxScalarBinarySingle ins bld fnOp =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    let single = AST.cast CastKind.FloatCast 32<rt> (fnOp ah bh)
    dh := AST.cast CastKind.FloatCast 64<rt> single
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

/// A result that became a NaN on its own -- neither operand was one -- is an
/// invalid operation, which on POWER answers with the positive default quiet
/// NaN. The host arithmetic hands back a negative one, so it is rewritten, as
/// the multiply-adds do; a NaN that came in through an operand propagates.
let private withDefaultNaN a b res =
  AST.ite (noNaNOperand a b b .& IEEE754Double.isNaN res) defaultQNaN res

/// The vector double-precision forms of an "xT, xA, xB": the same operation on
/// each doubleword, a double in both. Unlike the scalar forms they leave FPRF
/// alone.
let vsxVectorBinary ins bld fnOp =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    th := withDefaultNaN ah bh (fnOp ah bh)
    tl := withDefaultNaN al bl (fnOp al bl)
    dh := th
    dl := tl
  }

/// xvnegdp, which flips the sign of both doubles. It is a bit operation, so a
/// NaN flips too and nothing is raised.
let xvnegdp ins bld =
  vecUnary ins bld 64<rt> (fun a -> a <+> numU64 0x8000000000000000UL 64<rt>)

/// An "xT, xB" over the double in the source's high half.
let vsxScalarUnary ins bld fnOp setsFPRF =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    dh := fnOp bh
    dl := AST.num0 64<rt>
    if setsFPRF then setFPRF bld dh else ()
  }

/// The VSX scalar multiply-adds, which are fused: the product is formed
/// exactly and only the sum is rounded, so they go out as the FMA call rather
/// than as a multiply inside an add.
///
/// The two shapes differ in which register the addend comes from. The "a"
/// forms multiply xA by xB and add xT; the "m" forms multiply xA by xT and add
/// xB. Either way the target is read before it is written, which is why the
/// old value is taken into a temporary first.
///
/// Bit 1 of the FMA flag negates the addend, which is the subtracting forms;
/// the negating forms flip the sign of the rounded result, a NaN excepted, as
/// the floating-point-register forms in GeneralLifter do.
let private vsxScalarMulAdd ins bld isDouble targetIsFactor subtract negate =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    let old = tmpVar bld 64<rt>
    let res = tmpVar bld 64<rt>
    let f = numU64 (if subtract then 2UL else 0UL) 8<rt>
    old := dh
    let x, y, z = if targetIsFactor then ah, old, bh else ah, bh, old
    if isDouble then
      res := AST.app "FMA64" [ x; y; z; f ] 64<rt>
    else
      let xS = AST.cast CastKind.FloatCast 32<rt> x
      let yS = AST.cast CastKind.FloatCast 32<rt> y
      let zS = AST.cast CastKind.FloatCast 32<rt> z
      let resS = AST.app "FMA32" [ xS; yS; zS; f ] 32<rt>
      res := AST.cast CastKind.FloatCast 64<rt> resS
    (* Which NaN comes back follows a order of its own -- xA first, then
       whichever register the addend came from, then the remaining
       multiplicand -- so the choice is made here rather than left to the
       primitive, which would take them in the order the product is written
       in. A signalling one is quieted on the way out; where no operand was a
       NaN and the answer still is, the operation was invalid and answers with
       the default quiet NaN, which is positive. *)
    let quieted v = v .| numU64 0x0008000000000000UL 64<rt>
    let addend, other = if targetIsFactor then bh, old else old, bh
    let fromAddend =
      AST.ite (IEEE754Double.isNaN addend) (quieted addend) (quieted other)
    let chosen = AST.ite (IEEE754Double.isNaN ah) (quieted ah) fromAddend
    res :=
      AST.ite (noNaNOperand ah bh old)
        (AST.ite (IEEE754Double.isNaN res) defaultQNaN res)
        chosen
    if negate then
      let signBit = numU64 0x8000000000000000UL 64<rt>
      dh := AST.ite (IEEE754Double.isNaN res) res (res <+> signBit)
    else
      dh := res
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

let xsmaddadp ins bld = vsxScalarMulAdd ins bld true false false false

let xsmaddmdp ins bld = vsxScalarMulAdd ins bld true true false false

let xsmsubadp ins bld = vsxScalarMulAdd ins bld true false true false

let xsmsubmdp ins bld = vsxScalarMulAdd ins bld true true true false

let xsnmaddadp ins bld = vsxScalarMulAdd ins bld true false false true

let xsnmaddmdp ins bld = vsxScalarMulAdd ins bld true true false true

let xsnmsubadp ins bld = vsxScalarMulAdd ins bld true false true true

let xsnmsubmdp ins bld = vsxScalarMulAdd ins bld true true true true

let xsmaddasp ins bld = vsxScalarMulAdd ins bld false false false false

let xsmaddmsp ins bld = vsxScalarMulAdd ins bld false true false false

let xsmsubasp ins bld = vsxScalarMulAdd ins bld false false true false

let xsmsubmsp ins bld = vsxScalarMulAdd ins bld false true true false

let xsnmaddasp ins bld = vsxScalarMulAdd ins bld false false false true

let xsnmaddmsp ins bld = vsxScalarMulAdd ins bld false true false true

let xsnmsubasp ins bld = vsxScalarMulAdd ins bld false false true true

let xsnmsubmsp ins bld = vsxScalarMulAdd ins bld false true true true

/// Where a conversion stops at each end and what it answers there: one row of
/// the ISA's convert-to-integer table, as the doubles the comparisons need and
/// the integers they select. A NaN answers with the low end of the range,
/// which is the smallest signed value or zero, so it needs no row of its own.
let private conversionLimits isWord isSigned =
  match isWord, isSigned with
  | true, true ->
    let lo = numU64 0xc1e0000000000000UL 64<rt>
    let hi = numU64 0x41dfffffffc00000UL 64<rt>
    let loValue = numU64 0xffffffff80000000UL 64<rt>
    let hiValue = numU64 0x000000007fffffffUL 64<rt>
    struct (lo, hi, loValue, hiValue)
  | true, false ->
    let hi = numU64 0x41efffffffe00000UL 64<rt>
    let hiValue = numU64 0x00000000ffffffffUL 64<rt>
    struct (AST.num0 64<rt>, hi, AST.num0 64<rt>, hiValue)
  | false, true ->
    let lo = numU64 0xc3e0000000000000UL 64<rt>
    let hi = numU64 0x43e0000000000000UL 64<rt>
    let loValue = numU64 0x8000000000000000UL 64<rt>
    let hiValue = numU64 0x7fffffffffffffffUL 64<rt>
    struct (lo, hi, loValue, hiValue)
  | false, false ->
    let hi = numU64 0x43f0000000000000UL 64<rt>
    let hiValue = numU64 0xffffffffffffffffUL 64<rt>
    struct (AST.num0 64<rt>, hi, AST.num0 64<rt>, hiValue)

/// The conversion itself, before the limits are applied: truncation toward
/// zero whatever the rounding mode says, which is why it names its direction.
/// An unsigned target above 2^63 is folded down and biased back, a signed
/// conversion being all the IR has to reach for.
let private vsxTruncate isSigned src =
  let toInt e = AST.floatToSInt RoundingMode.TowardZero 64<rt> e
  let twoPow63 = numU64 0x43e0000000000000UL 64<rt>
  let bias = numU64 0x8000000000000000UL 64<rt>
  let folded = toInt (AST.fsub src twoPow63) .+ bias
  if isSigned then toInt src
  else AST.ite (AST.fge src twoPow63) folded (toInt src)

/// A double converted to an integer, saturating at the ends of the target's
/// range, a NaN going to the smallest signed value or to zero as the ISA's
/// convert-to-integer tables say.
let private vsxToInt ins bld isWord isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    let struct (src, res) = tmpVars2 bld 64<rt>
    let struct (loLimit, hiLimit, loValue, hiValue) =
      conversionLimits isWord isSigned
    src := bh
    res := vsxTruncate isSigned src
    res := AST.ite (AST.fle src loLimit) loValue res
    res := AST.ite (AST.fge src hiLimit) hiValue res
    res := AST.ite (IEEE754Double.isNaN src) loValue res
    (* ISA 3.1 requires a word result in both words of doubleword zero. *)
    let word = AST.xtlo 32<rt> res
    dh := if isWord then AST.concat word word else res
    dl := AST.num0 64<rt>
  }

let xscvdpsxws ins bld = vsxToInt ins bld true true

let xscvdpuxws ins bld = vsxToInt ins bld true false

let xscvdpsxds ins bld = vsxToInt ins bld false true

let xscvdpuxds ins bld = vsxToInt ins bld false false

/// An integer in doubleword element 0 converted to a floating-point value,
/// rounded to double or -- for the "sp" forms -- to single and left in the
/// double format a scalar register holds.
let private vsxFromInt ins bld isSigned toSingle =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    let kind = if isSigned then CastKind.SIntToFloat else CastKind.UIntToFloat
    let value = AST.cast kind 64<rt> bh
    let narrowed = AST.cast CastKind.FloatCast 32<rt> value
    if toSingle then dh := AST.cast CastKind.FloatCast 64<rt> narrowed
    else dh := value
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

let xscvsxddp ins bld = vsxFromInt ins bld true false

let xscvuxddp ins bld = vsxFromInt ins bld false false

let xscvsxdsp ins bld = vsxFromInt ins bld true true

let xscvuxdsp ins bld = vsxFromInt ins bld false true

/// xvcvsxwdp, which converts the signed word at the top of each doubleword of
/// xB to a double -- exactly, as a double holds every 32-bit integer.
let xvcvsxwdp ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let toDouble x =
      AST.sext 64<rt> (AST.extract x 32<rt> 32)
      |> AST.cast CastKind.SIntToFloat 64<rt>
    th := toDouble bh
    tl := toDouble bl
    dh := th
    dl := tl
  }

/// xscvdpsp, the double-to-single conversion that rounds: the result is a
/// single in word element 0, which is the high half of the target's first
/// doubleword.
let xscvdpsp ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    let single = AST.cast CastKind.FloatCast 32<rt> bh
    dh := AST.concat single single
    dl := AST.num0 64<rt>
    setFPRF bld (AST.cast CastKind.FloatCast 64<rt> single)
  }

/// xscvspdp, the other way: the single in word element 0 widened into the
/// double the register holds.
let xscvspdp ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    dh := AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> bh)
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

/// xscvdpspn, the non-signalling double-to-single conversion: the same bit
/// splice stfs performs, placed in words 0 and 1 of the target.
let xscvdpspn ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    let word = singleBits bld bh
    dh := AST.concat word word
    dl := AST.num0 64<rt>
  }

/// xscvspdpn, the non-signalling single-to-double conversion of word 0: every
/// finite single converts exactly, and an infinity too, so the floating-point
/// cast serves; a NaN keeps its payload and its signalling bit by splicing.
let xscvspdpn ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    let word = tmpVar bld 32<rt>
    word := AST.xthi 32<rt> bh
    let isNaN = (word .& numU32 0x7f800000u 32<rt> == numU32 0x7f800000u 32<rt>)
                .& (word .& numU32 0x007fffffu 32<rt> != AST.num0 32<rt>)
    let w64 = AST.zext 64<rt> word
    let nan = ((w64 .& numU64 0x80000000UL 64<rt>) << numI32 32 64<rt>)
              .| numU64 0x7ff0000000000000UL 64<rt>
              .| ((w64 .& numU64 0x007fffffUL 64<rt>) << numI32 29 64<rt>)
    dh := AST.ite isNaN nan (AST.cast CastKind.FloatCast 64<rt> word)
    dl := AST.num0 64<rt>
  }

/// xscmpudp, which compares two doubles and reports less-than, greater-than,
/// equal and unordered in a condition-register field, as fcmpu does.
let xscmpudp ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let crf0, crf1, crf2, crf3 =
      match o1 with
      | OprReg reg -> transCRxToExpr bld reg
      | _ -> raise InvalidOperandException
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    let fpscr = regVar bld Register.FPSCR
    let unordered = tmpVar bld 1<rt>
    unordered := IEEE754Double.isNaN ah .| IEEE754Double.isNaN bh
    crf0 := AST.ite unordered AST.b0 (AST.flt ah bh)
    crf1 := AST.ite unordered AST.b0 (AST.fgt ah bh)
    crf2 := AST.ite unordered AST.b0 (AST.eq ah bh)
    crf3 := unordered
    AST.extract fpscr 1<rt> 15 := crf0
    AST.extract fpscr 1<rt> 14 := crf1
    AST.extract fpscr 1<rt> 13 := crf2
    AST.extract fpscr 1<rt> 12 := crf3
    AST.extract fpscr 1<rt> 24 :=
      AST.extract fpscr 1<rt> 24
      .| IEEE754Double.isSNaN ah .| IEEE754Double.isSNaN bh
  }

/// xxspltw, which copies one word of xB into all four words of xT.
let xxspltw ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let index =
      match o3 with
      | OprImm n -> int n % 4
      | _ -> raise InvalidOperandException
    let word = tmpVar bld 32<rt>
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let src = if index < 2 then bh else bl
    word := AST.extract src 32<rt> ((1 - index % 2) * 32)
    for half in [ th; tl ] do
      AST.extract half 32<rt> 0 := word
      AST.extract half 32<rt> 32 := word
    dh := th
    dl := tl
  }

/// xxspltib, which fills every byte of xT with an immediate.
let xxspltib ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let value =
      match o2 with
      | OprImm n -> numU64 n 8<rt>
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. 7 do
      AST.extract th 8<rt> (i * 8) := value
      AST.extract tl 8<rt> (i * 8) := value
    dh := th
    dl := tl
  }

/// mtvsrdd, which fills both halves of xT from two general registers; an rA
/// of 0 stands for the value zero, as in an address.
let mtvsrdd ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let rb = transOpr bld o3
    match o2 with
    | OprReg Register.R0 -> dh := AST.num0 64<rt>
    | _ -> dh := AST.zext 64<rt> (transOpr bld o2)
    dl := AST.zext 64<rt> rb
  }

/// mfvsrld, which reads xS's low half into a general register.
let mfvsrld ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (_, sl) = vecHalves bld o1
    let ra = transOpr bld o2
    ra := AST.zext bld.RegType sl
  }

/// The double whose sign comes from one operand and magnitude from the other,
/// which is what fcpsgn and xscpsgndp both compute.
let copySign signSrc magnitude =
  let signBit = numU64 0x8000000000000000UL 64<rt>
  (signSrc .& signBit) .| (magnitude .& AST.not signBit)

/// fcpsgn frD, frA, frB.
let fcpsgn ins bld =
  lift bld ins {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    frd := copySign fra frb
  }

(*
  The vector facility's integer arithmetic, lifted element by element.
*)
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
    let overflow =
      if signed && kind = ExtendedQuotient then
        let min = AST.num1 wide << numI32 (2 * n - 1) wide
        (dividend == min) .& (divisor == AST.not (AST.num0 wide))
      else
        AST.b0
    let invalid = zero .| overflow
    let safe = AST.ite invalid (AST.num1 wide) divisor
    let answer =
      match kind, signed with
      | Remainder, true -> dividend ?% safe
      | Remainder, false -> dividend .% safe
      | _, true -> dividend ?/ safe
      | _, false -> dividend ./ safe
    let undefined = if kind = Remainder then AST.num0 esize else a
    AST.ite invalid undefined (AST.xtlo esize answer))

/// vsum4ubs/vsum4sbs/vsum4shs: each word of vD the sum of the elements of vA
/// that lie within it plus the matching word of vB, computed exactly and
/// clamped to a word, which sets VSCR[SAT] where it has to.
let vecSumWithin ins bld esize signed =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld 32<rt> o3
    let per = 32 / int esize
    Array.init 4 (fun i ->
      Array.init per (fun j -> widen signed 64<rt> a[i * per + j])
      |> Array.fold (.+) (widen signed 64<rt> b[i])
      |> saturate 32<rt> signed)
    |> putSaturated bld o1
  }

/// vsum2sws/vsumsws: the signed words of vA summed in groups -- two of two
/// words, or one of four -- each sum added to the last word of its group in
/// vB, clamped and written there; the other words of vD are cleared.
let vecSumAcross ins bld groups =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld 32<rt> o2
    let b = elementsOf bld 32<rt> o3
    let size = 4 / groups
    let sumOf i =
      Array.init size (fun j -> AST.sext 64<rt> a[i - size + 1 + j])
      |> Array.fold (.+) (AST.sext 64<rt> b[i])
      |> saturate 32<rt> true
    Array.init 4 (fun i ->
      if i % size = size - 1 then sumOf i
      else struct (AST.num0 32<rt>, AST.b0))
    |> putSaturated bld o1
  }

(*
  The vector facility's cryptography support: the AES rounds, the SHA-2
  sigma functions, the carry-less multiply-sums and the permute-and-XOR.
  An AES round goes out as the named call the other front ends use for it,
  a round being one operation no shorter spelling makes clearer. Those calls
  number the state's bytes from the least significant end, where the vector
  facility numbers them from the most significant one, so the state and the
  round key are laid out the other way round on the way in and the answer's
  bytes are read back from that end.
*)
/// A vector register's value laid out the way the named AES calls take a
/// state: its byte k at bits 8k, counted from the least significant end.
let private aesState bld opr =
  elementsOf bld 8<rt> opr |> Array.rev |> concatElements

/// The two operands of an AES round, held in that layout.
let private aesOperands bld o2 o3 =
  let struct (state, key) = tmpVars2 bld 128<rt>
  append bld {
    state := aesState bld o2
    key := aesState bld o3
  }
  struct (state, key)

/// The answer of a named AES call, held, as the bytes the vector facility
/// numbers 0 to 15.
let private aesCall bld name args =
  let t = tmpVar bld 128<rt>
  append bld { t := AST.app name args 128<rt> }
  Array.init 16 (fun k -> AST.extract t 8<rt> (8 * k))

/// vcipher/vcipherlast/vncipherlast: one AES round over vA as the state and vB
/// as the round key, the named call doing exactly what the instruction does.
let aesRound ins bld name =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (state, key) = aesOperands bld o2 o3
    putElements bld o1 (aesCall bld name [ state; key ])
  }

/// vncipher, whose round adds the key before InvMixColumns rather than after
/// it: the last-round call (InvShiftRows, InvSubBytes, AddRoundKey) followed
/// by InvMixColumns on its own.
let vncipher ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (state, key) = aesOperands bld o2 o3
    let round = tmpVar bld 128<rt>
    round := AST.app "AESDECLAST" [ state; key ] 128<rt>
    putElements bld o1 (aesCall bld "AESIMC" [ round ])
  }

/// vsbox, SubBytes alone. The last-round call applies ShiftRows as well,
/// which moves bytes without changing them, so its answer is put back in
/// place: byte r + 4c of the state comes from byte r + 4((c - r) mod 4) of
/// the call's.
let vsbox ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let state = tmpVar bld 128<rt>
    state := aesState bld o2
    let bytes = aesCall bld "AESENCLAST" [ state; AST.num0 128<rt> ]
    Array.init 16 (fun k -> bytes[k % 4 + 4 * ((k / 4 - k % 4 + 4) % 4)])
    |> putElements bld o1
  }

/// The rotate-right of an element by a fixed count.
let private rotr esize (x: Expr) n =
  (x >> numI32 n esize) .| (x << numI32 (int esize - n) esize)

/// The SHA-2 sigma functions of one element, as rotate and shift counts: the
/// lower-case sigma (ST = 0) ends in a shift, the upper-case one (ST = 1) in a
/// third rotate.
let private sigma esize st six (x: Expr) =
  let n i = numI32 i esize
  let a, b, c =
    match int esize, st, six with
    | 32, false, false -> 7, 18, 3
    | 32, false, true -> 17, 19, 10
    | 32, true, false -> 2, 13, 22
    | 32, true, true -> 6, 11, 25
    | _, false, false -> 1, 8, 7
    | _, false, true -> 19, 61, 6
    | _, true, false -> 28, 34, 39
    | _, true, true -> 14, 18, 41
  let last = if st then rotr esize x c else x >> n c
  rotr esize x a <+> rotr esize x b <+> last

/// vshasigmaw/vshasigmad: a SHA-256 or SHA-512 sigma function of each element
/// of vA, ST picking the upper- or lower-case one and a bit of SIX for each
/// element which of its two: bit i for word i, and bit 2i for doubleword i.
let vshasigma ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let st = getImmValue o3 = 1u
    let six = getImmValue o4
    let a = elementsOf bld esize o2
    let step = if int esize = 32 then 1 else 2
    a
    |> Array.mapi (fun i x ->
      sigma esize st ((six >>> (3 - step * i)) &&& 1u = 1u) x)
    |> putElements bld o1
  }

/// The carry-less product of two elements, twice their width: the XOR of a
/// copy of a shifted to each bit of b that is set.
let private carrylessProduct (esize: RegType) a b =
  let wide = regTypeOf (int esize * 2)
  let aw = AST.zext wide a
  Array.init (int esize) (fun j ->
    AST.ite (AST.extract b 1<rt> j) (aw << numI32 j wide) (AST.num0 wide))
  |> Array.reduce (<+>)

/// vpmsum*: the carry-less products of each pair of elements of vA and vB,
/// XORed in twos into elements twice as wide.
let vpmsum ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = elementsOf bld esize o2
    let b = elementsOf bld esize o3
    Array.init (a.Length / 2) (fun i ->
      carrylessProduct esize a[2 * i] b[2 * i]
      <+> carrylessProduct esize a[2 * i + 1] b[2 * i + 1])
    |> putElements bld o1
  }

/// The byte of a 16-byte vector a run-time index names, by a chain of selects.
let byteAt (bytes: Expr[]) index =
  let rt = Expr.typeOf index
  bytes
  |> Array.mapi (fun k b -> k, b)
  |> Array.fold (fun acc (k, b) ->
    AST.ite (index == numI32 k rt) b acc) (AST.num0 8<rt>)

/// vpermxor, which XORs the byte of vA the high nibble of each byte of vC
/// names with the byte of vB its low nibble names.
let vpermxor ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let a = elementsOf bld 8<rt> o2
    let b = elementsOf bld 8<rt> o3
    let c = elementsOf bld 8<rt> o4
    c
    |> Array.map (fun sel ->
      byteAt a (sel >> numI32 4 8<rt>) <+> byteAt b (sel .& numI32 15 8<rt>))
    |> putElements bld o1
  }

(*
  The vector facility's decimal integer instructions. A signed packed decimal
  value is 31 four-bit digits, the most significant first, and a four-bit
  sign code; it is read into the binary number it stands for, the arithmetic
  is done in binary, and the answer is written back as digits. Every value
  31 digits hold is below 2^104, so a 128-bit number holds it with room for
  a sum and a sign.
*)
/// Ten to a power, as a 128-bit number.
let private pow10 (n: int) = AST.num (BitVector(bigint.Pow(10I, n), 128<rt>))

/// The 31 digits of a packed decimal value, the most significant first.
let private digitsOf (q: Expr) =
  Array.init 31 (fun k -> AST.extract q 4<rt> (124 - 4 * k))

/// Whether a signed packed decimal value is a valid encoding: every digit at
/// most 9 and a sign code of 10 or more.
let private isValidSigned q =
  let digitsValid =
    digitsOf q
    |> Array.map (fun d -> d .<= numI32 9 4<rt>)
    |> Array.reduce (.&)
  digitsValid .& (AST.xtlo 4<rt> q .>= numI32 10 4<rt>)

/// The magnitude a packed decimal value's digits stand for.
let private magnitudeOf q =
  digitsOf q
  |> Array.mapi (fun k d -> AST.zext 128<rt> d .* pow10 (30 - k))
  |> Array.reduce (.+)

/// Whether a sign code says negative, which 0b1011 and 0b1101 do.
let private isMinus (q: Expr) =
  let sign = AST.xtlo 4<rt> q
  (sign == numI32 0xb 4<rt>) .| (sign == numI32 0xd 4<rt>)

/// The signed number a signed packed decimal value stands for.
let private signedValueOf q =
  let m = magnitudeOf q
  AST.ite (isMinus q) (AST.neg m) m

/// The low 31 decimal digits of a binary magnitude, packed, followed by a
/// sign code.
let private packedOf (m: Expr) sign =
  let digits =
    Array.init 31 (fun k ->
      AST.xtlo 4<rt> ((m ./ pow10 (30 - k)) .% numI32 10 128<rt>))
  concatElements (Array.append digits [| sign |])

/// The sign code of a result that is not negative: 0b1100, or 0b1111 where the
/// preferred-sign operand PS says so.
let private plusSign ps = numI32 (if ps then 0xf else 0xc) 4<rt>

/// Sets CR6 from a decimal result: less than, greater than and equal to zero
/// and the overflow bit, where both operands are valid; 0b0001 where either
/// is not.
let private setDecimalCR6 (bld: ILowUIRBuilder) valid (r: Expr) overflow =
  append bld {
    regVar bld Register.CR6_0 := valid .& (r ?< AST.num0 128<rt>)
    regVar bld Register.CR6_1 := valid .& (r ?> AST.num0 128<rt>)
    regVar bld Register.CR6_2 := valid .& (r == AST.num0 128<rt>)
    regVar bld Register.CR6_3 := AST.not valid .| overflow
  }

/// bcdadd./bcdsub.: the sum or the difference of two signed packed decimal
/// values, its low 31 digits written with a sign code saying negative (0b1101)
/// or not, and CR6 saying how it compares with zero and whether it overflowed
/// 31 digits. The ISA leaves the result undefined where an operand is not a
/// valid encoding; it is written as all ones there, as QEMU writes it.
let bcdAddSub ins bld subtract =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let ps = getImmValue o4 = 1u
    let struct (a, b) = tmpVars2 bld 128<rt>
    let struct (r, m) = tmpVars2 bld 128<rt>
    let valid = tmpVar bld 1<rt>
    a := quadOf bld o2
    b := quadOf bld o3
    valid := isValidSigned a .& isValidSigned b
    let combine = if subtract then (.-) else (.+)
    r := combine (signedValueOf a) (signedValueOf b)
    m := AST.ite (r ?< AST.num0 128<rt>) (AST.neg r) r
    let sign = AST.ite (r ?< AST.num0 128<rt>) (numI32 0xd 4<rt>) (plusSign ps)
    let ones = AST.not (AST.num0 128<rt>)
    putElements bld o1 [| AST.ite valid (packedOf m sign) ones |]
    setDecimalCR6 bld valid r (m .>= pow10 31)
  }

/// Sets CR6 from a decimal instruction's flags: less than, greater than and
/// equal to zero where the operands are valid, and the last bit where either
/// one is invalid or the result overflowed.
let private setDecimalFlags (bld: ILowUIRBuilder) invalid lt gt eq overflow =
  let valid = AST.not invalid
  append bld {
    regVar bld Register.CR6_0 := valid .& lt
    regVar bld Register.CR6_1 := valid .& gt
    regVar bld Register.CR6_2 := valid .& eq
    regVar bld Register.CR6_3 := invalid .| overflow
  }

/// The 31 digits of a signed packed decimal value as one 124-bit field, kept
/// in the low bits of a 128-bit number.
let private digitField (q: Expr) = q >> numI32 4 128<rt>

/// What a decimal instruction writes where an operand is invalid, which the
/// ISA leaves undefined: the target as it was, or the result computed as if
/// the operand were valid -- the choice QEMU makes for each.
type private OnInvalid =
  | KeepTarget
  | WriteResult

/// Writes a decimal result and sets CR6 from whether the value reported on is
/// negative or zero.
let private finishDecimal bld opr onInvalid invalid minus zero overflow result =
  let nonzero = AST.not zero
  let lt = nonzero .& minus
  let gt = nonzero .& AST.not minus
  let written =
    match onInvalid with
    | KeepTarget -> AST.ite invalid (quadOf bld opr) result
    | WriteResult -> result
  putElements bld opr [| written |]
  setDecimalFlags bld invalid lt gt zero overflow

/// Whether a signed packed decimal operand is invalid, negative, and zero.
let private signedFlags q =
  let zero = digitField q == AST.num0 128<rt>
  struct (AST.not (isValidSigned q), isMinus q, zero)

/// The sign code a result takes: 0b1101 when negative, else 0b1100, or
/// 0b1111 where PS is 1.
let private signCode minus ps = AST.ite minus (numI32 0xd 4<rt>) (plusSign ps)

/// A 128-bit value with its sign code replaced.
let private withSign (q: Expr) sign =
  (q .& AST.not (numI32 0xf 128<rt>)) .| AST.zext 128<rt> sign

/// The PS operand of a decimal instruction.
let private psOf opr = getImmValue opr = 1u

/// A vector operand held in a temporary.
let private heldQuad bld opr =
  let q = tmpVar bld 128<rt>
  append bld { q := quadOf bld opr }
  q

/// bcdcpsgn. vD, vA, vB: vA's digits with vB's sign code.
let bcdcpsgn ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = heldQuad bld o2
    let b = heldQuad bld o3
    let struct (badA, _, zero) = signedFlags a
    let struct (badB, minus, _) = signedFlags b
    let result = withSign a (AST.xtlo 4<rt> b)
    finishDecimal bld o1 KeepTarget (badA .| badB) minus zero AST.b0 result
  }

/// bcdsetsgn. vD, vB, PS: vB with the preferred sign code for its sign.
let bcdsetsgn ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    let result = withSign b (signCode minus (psOf o3))
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 result
  }

/// bcdcfsq. vD, vB, PS: the signed quadword vB as a signed packed decimal;
/// one past 31 digits overflows and leaves vD undefined, kept as it was.
let bcdcfsq ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let v = heldQuad bld o2
    let minus = v ?< AST.num0 128<rt>
    let m = AST.ite minus (AST.neg v) v
    let overflow = tmpVar bld 1<rt>
    overflow := m .>= pow10 31
    let zero = v == AST.num0 128<rt>
    let result = packedOf m (signCode minus (psOf o3))
    putElements bld o1 [| AST.ite overflow (quadOf bld o1) result |]
    let positive = AST.not minus .& AST.not zero
    setDecimalFlags bld AST.b0 minus positive zero overflow
  }

/// bcdctsq. vD, vB: the signed packed decimal vB as a signed quadword.
let bcdctsq ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 (signedValueOf b)
  }

/// The digit shift count of bcds., bcdus. and bcdsr.: the signed byte 7 of
/// vA, positive for a left shift, clamped to the number of digits.
let private shiftCount bld opr digits =
  let struct (ah, _) = halvesOf bld opr
  let n = tmpVar bld 8<rt>
  let limit = numI32 digits 8<rt>
  append bld { n := AST.xtlo 8<rt> ah }
  let left = n ?> AST.num0 8<rt>
  let back = AST.neg n
  let count = AST.ite left n back
  let clamped = AST.ite (count .> limit) limit count
  struct (left, AST.zext 128<rt> clamped .* numI32 4 128<rt>)

/// A digit field of `digits` digits shifted left or right by `bits` (four per
/// digit), and whether a nonzero digit went out on the left.
let private shiftDigits (field: Expr) digits left (bits: Expr) =
  let width = numI32 (4 * digits) 128<rt>
  let mask = AST.not (AST.not (AST.num0 128<rt>) << width)
  let shifted = AST.ite left ((field << bits) .& mask) (field >> bits)
  let out = field >> (width .- bits)
  let lost = bits != AST.num0 128<rt> .& (out != AST.num0 128<rt>)
  struct (shifted, left .& lost)

/// bcds. vD, vA, vB, PS: the digits of vB shifted left or right by byte 7 of
/// vA, a nonzero digit shifted out on the left overflowing.
let bcds ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let b = heldQuad bld o3
    let struct (bad, minus, zero) = signedFlags b
    let struct (left, bits) = shiftCount bld o2 31
    let struct (shifted, overflow) = shiftDigits (digitField b) 31 left bits
    let sign = AST.zext 128<rt> (signCode minus (psOf o4))
    let result = (shifted << numI32 4 128<rt>) .| sign
    finishDecimal bld o1 KeepTarget bad minus zero overflow result
  }

/// Whether an unsigned packed decimal value is valid: every nibble a digit.
let private isValidUnsigned (q: Expr) =
  Array.init 32 (fun k -> AST.extract q 4<rt> (4 * k) .<= numI32 9 4<rt>)
  |> Array.reduce (.&)

/// bcdus. vD, vA, vB: the 32 unsigned digits of vB shifted as bcds. shifts.
let bcdus ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o3
    let bad = AST.not (isValidUnsigned b)
    let zero = b == AST.num0 128<rt>
    let struct (left, bits) = shiftCount bld o2 32
    let struct (shifted, overflow) = shiftDigits b 32 left bits
    finishDecimal bld o1 KeepTarget bad AST.b0 zero overflow shifted
  }

/// bcdsr. vD, vA, vB, PS: bcds. that rounds a right shift, the magnitude
/// incremented where the last digit shifted out is 5 or more.
let bcdsr ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let b = heldQuad bld o3
    let struct (bad, minus, zero) = signedFlags b
    let struct (left, bits) = shiftCount bld o2 31
    let field = digitField b
    let struct (shifted, overflow) = shiftDigits field 31 left bits
    let four = numI32 4 128<rt>
    let last = AST.xtlo 4<rt> (field >> (bits .- four))
    let up = AST.not left .& (bits != AST.num0 128<rt>)
    let round = up .& (last .>= numI32 5 4<rt>)
    let shiftedQ = tmpVar bld 128<rt>
    shiftedQ := (shifted << four) .| numI32 0xc 128<rt>
    let rounded = magnitudeOf shiftedQ .+ AST.zext 128<rt> round
    let result = packedOf rounded (signCode minus (psOf o4))
    finishDecimal bld o1 KeepTarget bad minus zero overflow result
  }

/// The digits of a field kept to its rightmost `length` ones, where `length`
/// is below the number it has, and whether a nonzero digit was cut off.
let private truncateDigits (field: Expr) digits (length: Expr) =
  let bits = AST.zext 128<rt> length .* numI32 4 128<rt>
  let short = length .< numI32 digits 16<rt>
  let kept = field .& AST.not (AST.not (AST.num0 128<rt>) << bits)
  let lost = short .& ((field >> bits) != AST.num0 128<rt>)
  struct (AST.ite short kept field, lost)

/// The digit count of bcdtrunc. and bcdutrunc.: bits 48:63 of vA.
let private truncateLength bld opr =
  let struct (ah, _) = halvesOf bld opr
  let length = tmpVar bld 16<rt>
  append bld { length := AST.xtlo 16<rt> ah }
  length

/// bcdtrunc. vD, vA, vB, PS: vB kept to its rightmost N digits, N being bits
/// 48:63 of vA, a nonzero digit cut off overflowing.
let bcdtrunc ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let b = heldQuad bld o3
    let struct (bad, minus, zero) = signedFlags b
    let length = truncateLength bld o2
    let struct (kept, overflow) = truncateDigits (digitField b) 31 length
    let sign = AST.zext 128<rt> (signCode minus (psOf o4))
    let result = (kept << numI32 4 128<rt>) .| sign
    finishDecimal bld o1 KeepTarget bad minus zero overflow result
  }

/// bcdutrunc. vD, vA, vB: the 32 unsigned digits of vB kept as bcdtrunc.
/// keeps them.
let bcdutrunc ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o3
    let bad = AST.not (isValidUnsigned b)
    let zero = b == AST.num0 128<rt>
    let length = truncateLength bld o2
    let struct (kept, overflow) = truncateDigits b 32 length
    finishDecimal bld o1 KeepTarget bad AST.b0 zero overflow kept
  }

/// bcdcfn. vD, vB, PS: the national decimal vB -- seven halfwords 0x0030 to
/// 0x0039 and a sign halfword 0x002B or 0x002D -- as a signed packed decimal.
let bcdcfn ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o2
    let h = elementsOfHalves 16<rt> (AST.xthi 64<rt> b) (AST.xtlo 64<rt> b)
    let digit x = (x .>= numI32 0x30 16<rt>) .& (x .<= numI32 0x39 16<rt>)
    let plus = h[7] == numI32 0x2b 16<rt>
    let minus = AST.not plus
    let signOk = plus .| (h[7] == numI32 0x2d 16<rt>)
    let digitsOk = h[..6] |> Array.map digit |> Array.reduce (.&)
    let isZero x = x == numI32 0x30 16<rt>
    let zero = h[..6] |> Array.map isZero |> Array.reduce (.&)
    let digits = h[..6] |> Array.map (AST.xtlo 4<rt>)
    let result =
      Array.append digits [| signCode minus (psOf o3) |]
      |> concatElements
      |> AST.zext 128<rt>
    let bad = AST.not (signOk .& digitsOk)
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 result
  }

/// bcdctn. vD, vB: the low seven digits of the signed packed decimal vB as a
/// national decimal, more digits than that overflowing.
let bcdctn ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    let overflow = (b >> numI32 32 128<rt>) != AST.num0 128<rt>
    let digits =
      Array.init 7 (fun i ->
        AST.zext 16<rt> (AST.extract b 4<rt> (28 - 4 * i))
        .| numI32 0x30 16<rt>)
    let sign = AST.ite minus (numI32 0x2d 16<rt>) (numI32 0x2b 16<rt>)
    let result = concatElements (Array.append digits [| sign |])
    finishDecimal bld o1 WriteResult bad minus zero overflow result
  }

/// bcdcfz. vD, vB, PS: the zoned decimal vB -- a digit in the low nibble of
/// each byte, a zone of 0x3 (PS 0) or 0xF (PS 1) above the first fifteen and
/// the sign above the last -- as a signed packed decimal.
let bcdcfz ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ps = psOf o3
    let b = heldQuad bld o2
    let bytes = elementsOfHalves 8<rt> (AST.xthi 64<rt> b) (AST.xtlo 64<rt> b)
    let zone = numI32 (if ps then 0xf else 0x3) 4<rt>
    let zonedOk x =
      (AST.xthi 4<rt> x == zone) .& (AST.xtlo 4<rt> x .<= numI32 9 4<rt>)
    let signZone = AST.xthi 4<rt> bytes[15]
    let lastOk = AST.xtlo 4<rt> bytes[15] .<= numI32 9 4<rt>
    let signOk = if ps then signZone .>= numI32 0xa 4<rt> else AST.b1
    let digitsOk = bytes[..14] |> Array.map zonedOk |> Array.reduce (.&)
    let minusSign =
      (signZone == numI32 0xb 4<rt>) .| (signZone == numI32 0xd 4<rt>)
    let minus = if ps then minusSign else AST.extract signZone 1<rt> 2
    let digits = bytes |> Array.map (AST.xtlo 4<rt>)
    let zero =
      digits |> Array.map (fun d -> d == AST.num0 4<rt>) |> Array.reduce (.&)
    let result =
      Array.append digits [| signCode minus false |]
      |> concatElements
      |> AST.zext 128<rt>
    let bad = AST.not (signOk .& lastOk .& digitsOk)
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 result
  }

/// bcdctz. vD, vB, PS: the low sixteen digits of the signed packed decimal vB
/// as a zoned decimal, more digits than that overflowing. The pseudocode
/// tests nibbles 0 to 15 for the overflow, one more than the sixteen digits
/// leave out and than its own text says; the text is followed, as QEMU does.
let bcdctz ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ps = psOf o3
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    let overflow = (b >> numI32 68 128<rt>) != AST.num0 128<rt>
    let zone = numI32 (if ps then 0xf else 0x3) 4<rt>
    let digit i = AST.extract b 4<rt> (64 - 4 * i)
    let sign =
      if ps then AST.ite minus (numI32 0xd 4<rt>) (numI32 0xc 4<rt>)
      else AST.ite minus (numI32 0x7 4<rt>) (numI32 0x3 4<rt>)
    let bytes =
      Array.init 16 (fun i ->
        AST.concat (if i = 15 then sign else zone) (digit i))
    let result = concatElements bytes
    finishDecimal bld o1 WriteResult bad minus zero overflow result
  }

/// vmul10uq/vmul10cuq/vmul10euq/vmul10ecuq: vA times ten, plus the digit in
/// the low nibble of vB for the extended forms, as a 128-bit number -- or the
/// part of it above 128 bits, for the carry forms.
let vecMultiplyByTen (ins: Instruction) bld extended carry =
  lift bld ins {
    let o1, o2 =
      match ins.Operands with
      | TwoOperands(o1, o2) | ThreeOperands(o1, o2, _) -> o1, o2
      | _ -> raise InvalidOperandException
    let cin =
      match ins.Operands with
      | ThreeOperands(_, _, o3) when extended ->
        let struct (_, bl) = halvesOf bld o3
        AST.zext 256<rt> (AST.xtlo 4<rt> bl)
      | _ ->
        AST.num0 256<rt>
    let ten = numI32 10 256<rt>
    let product = (AST.zext 256<rt> (quadOf bld o2) .* ten) .+ cin
    let pick = if carry then AST.xthi 128<rt> else AST.xtlo 128<rt>
    putElements bld o1 [| pick product |]
  }

(*
  The vector facility's bit-level instructions: the counts, the parities,
  the rotates and shifts, and the gathers and scatters of bits, lifted
  element by element.
*)
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

(*
  The vector facility's instructions that move bytes about rather than
  compute with them: the extracts and inserts, the masks, the string
  isolates and the permutes. Where an instruction names a byte at run time,
  the register is read as one 128-bit number and shifted so that the byte
  lands where a fixed extract or insert reaches it.
*)
/// vexpand*m: each element of vD all ones where the top bit of the matching
/// element of vB is set and all zeros where it is clear.
let vecExpandMask ins bld esize =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    elementsOf bld esize o2
    |> Array.map (fun e -> AST.sext esize (AST.xthi 1<rt> e))
    |> putElements bld o1
  }

/// vextract*m rD, vB: the top bits of the elements of vB, element 0's the most
/// significant, in the low bits of rD, the rest of it cleared.
let vecExtractMask ins (bld: ILowUIRBuilder) esize =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let rt = transOpr bld o1
    let bits =
      elementsOf bld esize o2 |> Array.map (AST.xthi 1<rt>) |> concatElements
    rt := AST.zext bld.RegType bits
  }

/// Each element of vD all ones or all zeros as the matching bit of `bits` is
/// set or clear: one bit per element, element 0's the most significant of the
/// low ones.
let private maskFromBits bld opr esize (bits: Expr) =
  let n = 128 / int esize
  Array.init n (fun i -> AST.sext esize (AST.extract bits 1<rt> (n - 1 - i)))
  |> putElements bld opr

/// mtvsr*m vD, rB: vD built from the low bits of rB, one bit per element.
let vecMoveToMask ins bld esize =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    maskFromBits bld o1 esize (transOpr bld o2)
  }

/// mtvsrbmi vD, bm: vD's bytes built from the sixteen bits of bm.
let mtvsrbmi ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    maskFromBits bld o1 8<rt> (numU32 (getImmValue o2) 16<rt>)
  }

/// vcntmb* rD, vB, MP: how many elements of vB have their top bit equal to MP,
/// placed at the top of rD -- in the eight bits a byte count takes, and one
/// fewer for each doubling of the element.
let vecCountMaskBits ins (bld: ILowUIRBuilder) esize =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rt = transOpr bld o1
    let mp = getImmValue o3 = 1u
    let count =
      elementsOf bld esize o2
      |> Array.map (fun e ->
        let top = AST.xthi 1<rt> e
        AST.zext 64<rt> (if mp then top else AST.not top))
      |> Array.reduce (.+)
    let shift = 56 + System.Numerics.BitOperations.Log2(uint32 esize / 8u)
    rt := count << numI32 shift 64<rt>
  }

/// vstri*: the elements of vB from the left (or the right) up to and including
/// the first zero one, the rest of vD cleared. The record form sets CR6 to
/// 0b0010 where a zero element was found and to zero where none was.
let vecStringIsolate ins bld esize left record =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let e = elementsOf bld esize o2
    let zero = AST.num0 esize
    let step (kept, found) x =
      AST.ite found zero x :: kept, found .| (x == zero)
    let kept, found =
      Array.fold step ([], AST.b0) (if left then e else Array.rev e)
    let kept = List.toArray kept
    let flag = tmpVar bld 1<rt>
    flag := found
    putElements bld o1 (if left then Array.rev kept else kept)
    if record then
      regVar bld Register.CR6_0 := AST.b0
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 := flag
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }

/// vpermr, vperm with the 32 bytes of vA || vB counted from the right: each
/// byte of vD is byte 31 - i of the pair, i being the low five bits of the
/// matching byte of vC.
let vpermr ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let pair =
      Array.append (elementsOf bld 8<rt> o2) (elementsOf bld 8<rt> o3)
    let picks = elementsOf bld 8<rt> o4
    picks
    |> Array.map (fun c ->
      byteAt pair (numI32 31 8<rt> .- (c .& numI32 31 8<rt>)))
    |> putElements bld o1
  }

/// The `size` bytes of a value from byte `index` on, bytes counted from its
/// most significant end; the index is a run-time value of any width.
let private bytesAt (q: Expr) (index: Expr) size =
  let w = Expr.typeOf q
  let shift = AST.zext w index .* numI32 8 w
  AST.xthi (regTypeOf (8 * size)) (q << shift)

/// A 128-bit value with `value` written over its bytes from `index` on, the
/// other bytes kept.
let private withBytesAt (q: Expr) (index: Expr) (value: Expr) =
  let size = int (Expr.typeOf value) / 8
  let top = numI32 (128 - 8 * size) 128<rt>
  let shift = top .- (AST.zext 128<rt> index .* numI32 8 128<rt>)
  let mask = AST.zext 128<rt> (AST.not (AST.num0 (Expr.typeOf value))) << shift
  (q .& AST.not mask) .| (AST.zext 128<rt> value << shift)

/// The low bits of a general register that pick a byte: four of them for a
/// sixteen-byte register, five for the 32 bytes of a register pair.
let private indexOf (r: Expr) bits = AST.xtlo 8<rt> r .& numI32 (bits - 1) 8<rt>

/// Where a run-time byte index starts an element counted from the left or,
/// for the "r" forms, mirrored from the right of a `total`-byte source.
let private startOf index size total left =
  if left then index else numI32 (total - size) 8<rt> .- index

/// The immediate of an operand.
let private uimOf opr = numI32 (int (getImmValue opr)) 8<rt>

/// vextractub/uh/uw/d vD, vB, UIM: the element of `size` bytes at byte UIM of
/// vB, zero-extended into doubleword 0 of vD; doubleword 1 is cleared.
let vecExtractImm ins bld size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let e = bytesAt (quadOf bld o2) (uimOf o3) size
    putElements bld o1 [| AST.zext 64<rt> e; AST.num0 64<rt> |]
  }

/// vinsertb/h/w/d vD, vB, UIM: the low `size` bytes of doubleword 0 of vB
/// written over the bytes of vD from UIM on, the rest of vD kept.
let vecInsertImm ins bld size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (bh, _) = halvesOf bld o2
    let value = AST.xtlo (regTypeOf (8 * size)) bh
    putElements bld o1 [| withBytesAt (quadOf bld o1) (uimOf o3) value |]
  }

/// vextu*lx/vextu*rx rD, rA, vB: the element of `size` bytes of vB at the
/// byte the low four bits of rA name, counted from the left or, for the "r"
/// forms, from the right, zero-extended into rD.
let vecExtractToGpr ins (bld: ILowUIRBuilder) size left =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rt = transOpr bld o1
    let start = startOf (indexOf (transOpr bld o2) 16) size 16 left
    rt := AST.zext bld.RegType (bytesAt (quadOf bld o3) start size)
  }

/// vext*v*x vD, vA, vB, rC: the element of `size` bytes of the 32-byte pair vA
/// || vB at the byte the low five bits of rC name, from the left or the right,
/// zero-extended into doubleword 0 of vD; doubleword 1 is cleared.
let vecExtractPair ins bld size left =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let pair = AST.concat (quadOf bld o2) (quadOf bld o3)
    let start = startOf (indexOf (transOpr bld o4) 32) size 32 left
    let e = bytesAt pair start size
    putElements bld o1 [| AST.zext 64<rt> e; AST.num0 64<rt> |]
  }

/// vins*lx/vins*rx vD, rA, rB and vins*vlx/vins*vrx vD, rA, vB: the low `size`
/// bytes of rB -- or of doubleword 0 of vB -- written over vD at the byte the
/// low four bits of rA name, from the left or the right, the rest kept.
let vecInsertAt ins bld size left fromVector =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rt = regTypeOf (8 * size)
    let value =
      if fromVector then
        let struct (bh, _) = halvesOf bld o3
        AST.xtlo rt bh
      else
        AST.xtlo rt (transOpr bld o3)
    let start = startOf (indexOf (transOpr bld o2) 16) size 16 left
    putElements bld o1 [| withBytesAt (quadOf bld o1) start value |]
  }

/// vinsw/vinsd vD, rB, UIM: the low word, or the whole, of rB written over vD
/// from byte UIM on, the rest kept.
let vecInsertGprImm ins bld size =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let value = AST.xtlo (regTypeOf (8 * size)) (transOpr bld o2)
    putElements bld o1 [| withBytesAt (quadOf bld o1) (uimOf o3) value |]
  }

/// vclrlb/vclrrb vD, vA, rB: vA with all but its rightmost (or leftmost) N
/// bytes cleared, N being rB, or 16 where rB is above 15.
let vecClearBytes ins (bld: ILowUIRBuilder) left =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rb = transOpr bld o3
    let n = tmpVar bld 128<rt>
    let big = rb .> numI32 15 bld.RegType
    n := AST.ite big (numI32 16 128<rt>) (AST.zext 128<rt> rb)
    let ones = AST.not (AST.num0 128<rt>)
    let bits = n .* numI32 8 128<rt>
    let cleared = if left then ones << bits else ones >> bits
    let keep = AST.ite (n == numI32 16 128<rt>) ones (AST.not cleared)
    putElements bld o1 [| quadOf bld o2 .& keep |]
  }

(*
  The vector facility's floating-point instructions, on four singles at a
  time. They round to nearest whatever FPSCR[RN] holds, so each rounding
  operation is enclosed in a RoundCtrl naming that direction; they set no
  FPSCR bit at all. A NaN answer follows the ISA's order -- the first NaN
  operand, quieted, or else the standard QNaN 0x7FC00000 for an invalid
  operation -- rather than whatever the host's arithmetic hands back. With
  VSCR[NJ] set, a denormal operand is read as a zero of its sign and a
  denormal result written as one.
*)
/// VSCR[NJ], the non-Java mode bit, bit 16 of VSCR as it is kept here.
let private nonJava bld = AST.extract (regVar bld Register.VSCR) 1<rt> 16

/// Whether a single is a denormal: its exponent zero and its fraction not.
let private isDenormal x =
  let exponent = x .& numU32 0x7f800000u 32<rt>
  let fraction = x .& numU32 0x007fffffu 32<rt>
  (exponent == AST.num0 32<rt>) .& (fraction != AST.num0 32<rt>)

/// A single with a denormal replaced by a zero of its sign where NJ is set.
let private flush nj x =
  AST.ite (nj .& isDenormal x) (x .& numU32 0x80000000u 32<rt>) x

/// The standard QNaN of the vector facility.
let private standardQNaN = numU32 0x7fc00000u 32<rt>

/// An answer settled by the ISA's NaN rules: the first operand that is a
/// NaN, in the order given, quieted; else a NaN the operation itself made is
/// the standard QNaN.
let private settleNaN operands r =
  let quiet x = x .| numU32 0x00400000u 32<rt>
  let made = AST.ite (IEEE754Single.isNaN r) standardQNaN r
  List.foldBack (fun x acc ->
    AST.ite (IEEE754Single.isNaN x) (quiet x) acc) operands made

/// An expression rounded to nearest, ties to even, whatever FPSCR[RN] says.
let private nearest e =
  AST.roundCtrl (AST.roundingMode RoundingMode.ToNearestEven) e

/// The singles of a vector register, flushed as NJ says.
let private singlesOf bld nj opr =
  elementsOf bld 32<rt> opr |> Array.map (flush nj)

/// The NJ bit, held for an instruction that reads it more than once.
let private heldNonJava bld =
  let nj = tmpVar bld 1<rt>
  append bld { nj := nonJava bld }
  nj

/// vaddfp/vsubfp: the sum or difference of each pair of singles.
let vecFloatBinary ins bld op =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let b = singlesOf bld nj o3
    Array.map2 (fun x y -> flush nj (settleNaN [ x; y ] (nearest (op x y)))) a b
    |> putElements bld o1
  }

/// vmaddfp/vnmsubfp vD, vA, vC, vB: vA times vC plus vB -- or the negation of
/// vA times vC minus vB -- as one fused operation rounded once; the NaN taken
/// is vA's, then vB's, then vC's. The negation of a NaN is left alone.
let vecFloatMultiplyAdd ins bld negate =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let c = singlesOf bld nj o3
    let b = singlesOf bld nj o4
    let flags = numI32 (if negate then 2 else 0) 8<rt>
    let signBit = numU32 0x80000000u 32<rt>
    Array.init 4 (fun i ->
      let fused = nearest (AST.app "FMA32" [ a[i]; c[i]; b[i]; flags ] 32<rt>)
      let r = settleNaN [ a[i]; b[i]; c[i] ] fused
      let negated = AST.ite (IEEE754Single.isNaN r) r (r <+> signBit)
      flush nj (if negate then negated else r))
    |> putElements bld o1
  }

/// vmaxfp/vminfp: the larger (or smaller) of each pair of singles, +0 being
/// the larger of the two zeros, a NaN operand giving a QNaN.
let vecFloatMaxMin ins bld isMax =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let b = singlesOf bld nj o3
    Array.map2 (fun x y ->
      let pick, tie = if isMax then AST.fgt x y, x .& y else AST.flt x y, x .| y
      let r = AST.ite pick x (AST.ite (AST.feq x y) tie y)
      flush nj (settleNaN [ x; y ] r)) a b
    |> putElements bld o1
  }

/// vrefp/vrsqrtefp: the reciprocal, or the reciprocal square root, of each
/// single, computed exactly and rounded once for each operation it takes.
let vecFloatReciprocal ins bld root =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let nj = heldNonJava bld
    let one = numU32 0x3f800000u 32<rt>
    singlesOf bld nj o2
    |> Array.map (fun x ->
      let d = if root then nearest (AST.fsqrt x) else x
      flush nj (settleNaN [ x ] (nearest (AST.fdiv one d))))
    |> putElements bld o1
  }

/// vexptefp/vlogefp: 2 raised to each single, or the base-2 logarithm of it.
let vecFloatExpLog ins bld isExp =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let nj = heldNonJava bld
    let two = numU32 0x40000000u 32<rt>
    singlesOf bld nj o2
    |> Array.map (fun x ->
      let r = if isExp then AST.fpow two x else AST.flog two x
      flush nj (settleNaN [ x ] (nearest r)))
    |> putElements bld o1
  }

/// vrfin/vrfiz/vrfip/vrfim: each single rounded to an integral value in the
/// direction the instruction names.
let vecFloatRound ins bld mode =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let nj = heldNonJava bld
    singlesOf bld nj o2
    |> Array.map (fun x ->
      settleNaN [ x ] (AST.roundToIntegral mode 32<rt> x))
    |> putElements bld o1
  }

/// vcfsx/vcfux vD, vB, UIM: each signed or unsigned word converted to the
/// nearest single and divided by 2^UIM, which a nonzero result takes exactly
/// as a smaller exponent.
let vecFloatFromInt ins bld signed =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let scale = numU32 (getImmValue o3 <<< 23) 32<rt>
    let kind = if signed then CastKind.SIntToFloat else CastKind.UIntToFloat
    elementsOf bld 32<rt> o2
    |> Array.map (fun w ->
      let r = nearest (AST.cast kind 32<rt> w)
      AST.ite (w == AST.num0 32<rt>) (AST.num0 32<rt>) (r .- scale))
    |> putElements bld o1
  }

/// The word a single converts to under VSCR's saturating rules, the
/// conversion made exactly on the single's bits: UIM added to its exponent,
/// the fraction shifted into place and truncated toward zero. A NaN gives 0;
/// a value past the word's range, an infinity included, gives the nearer end
/// and saturates; a negative value an unsigned word cannot hold gives 0 and
/// saturates, unless it lies between -1 and 0 and so truncates to 0 anyway.
let private floatToWord signed uim (x: Expr) =
  let exponent = AST.zext 32<rt> (AST.extract x 8<rt> 23)
  let e = exponent .+ numI32 (int uim - 127) 32<rt>
  let negative = AST.xthi 1<rt> x
  let nan = IEEE754Single.isNaN x
  let significand = (x .& numU32 0x007fffffu 32<rt>) .| numU32 0x800000u 32<rt>
  let wide = AST.zext 64<rt> significand << numI32 32 64<rt>
  let magnitude =
    AST.xtlo 32<rt> (wide >> AST.zext 64<rt> (numI32 55 32<rt> .- e))
  let limit = if signed then 30 else 31
  let large = (e ?> numI32 limit 32<rt>) .| IEEE754Single.isInfinity x
  let small = e ?< AST.num0 32<rt>
  let zero = AST.num0 32<rt>
  if signed then
    let minWord = numU32 0x80000000u 32<rt>
    let top = AST.ite negative minWord (numU32 0x7fffffffu 32<rt>)
    let value = AST.ite negative (AST.neg magnitude) magnitude
    let inRange = AST.ite small zero value
    let r = AST.ite nan zero (AST.ite large top inRange)
    struct (r, AST.not nan .& large)
  else
    let top = AST.ite negative zero (numU32 0xffffffffu 32<rt>)
    let negativeSat = AST.not small .& negative
    let inRange = AST.ite (small .| negative) zero magnitude
    let r = AST.ite nan zero (AST.ite large top inRange)
    struct (r, AST.not nan .& (large .| negativeSat))

/// vctsxs/vctuxs vD, vB, UIM: each single times 2^UIM converted to a signed
/// or unsigned word toward zero, saturating and setting VSCR[SAT] where it
/// does.
let vecFloatToInt ins bld signed =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let uim = getImmValue o3
    elementsOf bld 32<rt> o2
    |> Array.map (floatToWord signed uim)
    |> putSaturated bld o1
  }

/// vcmpeqfp/vcmpgefp/vcmpgtfp: each pair of singles compared, a NaN making
/// the compare false.
let vecFloatCompare ins bld rel record =
  let nj = nonJava bld
  let flushed a b = rel (flush nj a) (flush nj b)
  vecCompareElements ins bld 32<rt> flushed record

/// vcmpbfp[.]: whether each single of vA lies within the bounds -vB .. vB,
/// as two bits at the top of its word: the first set where it is not at most
/// vB, the second where it is not at least -vB, both where either is a NaN.
/// The record form sets CR6 to 0b0010 where every single is within bounds.
let vcmpbfp ins bld record =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let b = singlesOf bld nj o3
    let signBit = numU32 0x80000000u 32<rt>
    let words =
      Array.map2 (fun x y ->
        let above = AST.not (AST.fle x y)
        let below = AST.not (AST.fge x (y <+> signBit))
        AST.concat (AST.concat above below) (AST.num0 30<rt>)) a b
    let held = Array.init 4 (fun _ -> tmpVar bld 32<rt>)
    for i in 0 .. 3 do held[i] := words[i]
    putElements bld o1 held
    if record then
      let zero = AST.num0 32<rt>
      regVar bld Register.CR6_0 := AST.b0
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 :=
        Array.map (fun w -> w == zero) held |> Array.reduce (.&)
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }
