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
/// The vector facility's instructions that move bytes about rather than
/// compute with them: the extracts and inserts, the masks, the string
/// isolates and the permutes. Where an instruction names a byte at run time,
/// the register is read as one 128-bit number and shifted so that the byte
/// lands where a fixed extract or insert reaches it.
/// </summary>
module internal B2R2.FrontEnd.PPC.VectorPermuteLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements
open B2R2.FrontEnd.PPC.VectorCryptoLifter

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
