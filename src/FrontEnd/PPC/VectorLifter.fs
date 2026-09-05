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
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.GeneralLifter

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
let vecBinary ins insLen bld esize f =
  lift bld ins insLen {
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
let vecUnary ins insLen bld esize f =
  lift bld ins insLen {
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

/// The all-ones or all-zeroes an element-wise compare writes per element.
let private compareMask esize cond =
  AST.ite cond (AST.not (AST.num0 esize)) (AST.num0 esize)

/// A vector compare. The record form also reports in CR6 whether every element
/// compared true (bit 0) or none did (bit 2).
let vecCompare ins insLen bld esize rel record =
  lift bld ins insLen {
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
let lvx ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
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
let stvx ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
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
let lvsx ins insLen (bld: ILowUIRBuilder) isLeft =
  lift bld ins insLen {
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

/// lvebx/lvehx/lvewx, which load one element into the vector slot the address
/// selects and leave the rest of the register undefined -- modeled here as
/// leaving it unchanged, which is what a real part does in practice.
let lvex ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
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
      let picked = index == numI32 b 8<rt>
      AST.extract dst size pos :=
        AST.ite picked value (AST.extract dst size pos)
  }

/// stvebx/stvehx/stvewx, the store counterparts of lvebx and friends.
let stvex ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
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
      let picked = index == numI32 b 8<rt>
      value := AST.ite picked (AST.extract src size pos) value
    loadNative bld size tmpEA := value
  }

/// lxvd2x/stxvd2x and lxvw4x/stxvw4x, which access a quadword element by
/// element: each element keeps the guest's byte order but the elements
/// themselves are not reordered, unlike lvx.
let lxvx ins insLen (bld: ILowUIRBuilder) esize isLoad =
  lift bld ins insLen {
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
let lxsdx ins insLen (bld: ILowUIRBuilder) splat isLoad =
  lift bld ins insLen {
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

/// A whole-register logical "xT, xA, xB", which the xxl family and the vector
/// logical ops share.
let vecLogical ins insLen bld f = vecBinary ins insLen bld 64<rt> f

/// vsel/xxsel, a bitwise select: a set bit of vC takes vB, a clear one vA.
let vecSelect ins insLen bld =
  lift bld ins insLen {
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
let vecPermuteDouble ins insLen bld =
  lift bld ins insLen {
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
let vecPermute ins insLen bld =
  lift bld ins insLen {
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
let vecShiftDouble ins insLen bld scale =
  lift bld ins insLen {
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
let vecSplat ins insLen bld esize =
  lift bld ins insLen {
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
let vecSplatImm ins insLen bld esize =
  lift bld ins insLen {
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
let vecMerge ins insLen bld esize high =
  lift bld ins insLen {
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
          |> AST.revConcat
        AST.extract dst esize pos := value
    dh := th
    dl := tl
  }

/// vpkuhum/vpkuwum, which pack the low half of each element of vA || vB into
/// the elements of vD.
let vecPack ins insLen bld (esize: RegType) =
  lift bld ins insLen {
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
let vecUnpack ins insLen bld (esize: RegType) high =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (8 / bytes) - 1 do
      let src = (if high then 0 else 8) + i * bytes
      let value =
        Array.init bytes (fun k -> vecByte bh bl (src + k)) |> AST.revConcat
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
let vecShiftWhole ins insLen (bld: ILowUIRBuilder) left byOctet =
  lift bld ins insLen {
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
       whole half's width, which is undefined, so that case is selected out. *)
    let zero = n == AST.num0 64<rt>
    let across = numI32 64 64<rt> .- n
    if left then
      th := AST.ite zero ah ((ah << n) .| (al >> across))
      tl := al << n
    else
      th := ah >> n
      tl := AST.ite zero al ((al >> n) .| (ah << across))
    dh := th
    dl := tl
  }

/// vgbbd, which transposes the bits of each doubleword's eight bytes: bit j of
/// byte i moves to bit i of byte j.
let vecGatherBits ins insLen bld =
  lift bld ins insLen {
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
let vecBitPermute ins insLen bld =
  lift bld ins insLen {
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
    dh := AST.num0 64<rt>
    dl := res
  }

/// mfvscr/mtvscr, which move the vector status register to or from the low
/// word of a vector register.
let vscrMove ins insLen bld toVector =
  lift bld ins insLen {
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
   VSR0-31; the low doubleword the architecture leaves undefined stays put. *)

/// An "xT, xA, xB" whose operands are the doubles in the sources' high halves.
let vsxScalarBinary ins insLen bld fnOp =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, _) = vecHalves bld o1
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    dh := fnOp ah bh
    setFPRF bld dh
  }

/// An "xT, xB" over the double in the source's high half.
let vsxScalarUnary ins insLen bld fnOp =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, _) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    dh := fnOp bh
  }

/// xscmpudp, which compares two doubles and reports less-than, greater-than,
/// equal and unordered in a condition-register field, as fcmpu does.
let xscmpudp ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let crf0, crf1, crf2, crf3 =
      match o1 with
      | OprReg reg -> transCRxToExpr bld reg
      | _ -> raise InvalidOperandException
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    let unordered = tmpVar bld 1<rt>
    unordered := IEEE754Double.isNaN ah .| IEEE754Double.isNaN bh
    crf0 := AST.ite unordered AST.b0 (AST.flt ah bh)
    crf1 := AST.ite unordered AST.b0 (AST.fgt ah bh)
    crf2 := AST.ite unordered AST.b0 (AST.eq ah bh)
    crf3 := unordered
  }

/// xxspltw, which copies one word of xB into all four words of xT.
let xxspltw ins insLen bld =
  lift bld ins insLen {
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
let xxspltib ins insLen bld =
  lift bld ins insLen {
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

/// mtvsrdd, which fills both halves of xT from two general registers.
let mtvsrdd ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ra = transOpr bld o2
    let rb = transOpr bld o3
    dh := AST.zext 64<rt> ra
    dl := AST.zext 64<rt> rb
  }

/// mfvsrld, which reads xS's low half into a general register.
let mfvsrld ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
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
let fcpsgn ins insLen bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    frd := copySign fra frb
  }
