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

/// The runtime the generated legacy-map parser (DLegacy) is written against:
/// the per-instruction state as one struct passed by reference, and the
/// operand readers that take it. Nothing here reads a table.
module internal B2R2.FrontEnd.Intel.DOps

open System.Buffers.Binary
open B2R2
open B2R2.FrontEnd.BinLifter

/// The state of one instruction being parsed. Lives on the caller's stack and
/// is passed by reference, so that the reads and writes of the widths, the
/// position and the prefixes stay in registers rather than round-tripping
/// through a heap object.
[<Struct>]
type DState =
  { /// The position of the next byte to read, from the instruction start.
    mutable Pos: int
    mutable Pref: Prefix
    mutable REX: REXPrefix
    /// The REX and mandatory-prefix state, 0 to 23, plus 24 in 64-bit mode.
    mutable Ctx: int
    /// The effective address size.
    mutable AddrSz: RegType
    mutable Is64: bool
    /// No LOCK prefix is present.
    mutable NoLock: bool
    mutable Addr: Addr
    mutable Lifter: ILiftable
    /// The VEX or EVEX prefix, or None for a legacy instruction.
    mutable Vex: VEXInfo option
    /// The vector length the prefix encodes; 0<rt> without one.
    mutable VL: RegType
    mutable VVVV: int
    mutable IsEVEX: bool
    /// EVEX.b, EVEX.aaa and EVEX.z; zero and false without an EVEX prefix.
    mutable EvexB: bool
    mutable AAA: int
    mutable Zeroing: bool }

let inline isReg (m: byte) = m &&& 0b11000000uy = 0b11000000uy

let inline isMem (m: byte) = m &&& 0b11000000uy <> 0b11000000uy

let inline reg (m: byte) = (int m >>> 3) &&& 0b111

let inline rm (m: byte) = int m &&& 0b111

let inline regv (v: int): Register = LanguagePrimitives.EnumOfValue v

/// The byte at the current position, or 0 where the bytes end: a row that
/// needs it then fails to read it where it is consumed.
let inline peek (span: ByteSpan) (st: byref<DState>) =
  if st.Pos < span.Length then span[st.Pos] else 0uy

let inline readByte (span: ByteSpan) (st: byref<DState>) =
  let v = span[st.Pos]
  st.Pos <- st.Pos + 1
  v

let inline private oprSize (size: RegType) (szCond: SzCond) =
  if szCond = SzCond.F64 || (size = 32<rt> && szCond = SzCond.D64) then 64<rt>
  else size

/// The effective operand size under the given size condition.
let inline effOprSz (st: byref<DState>) (szCond: SzCond) =
  if not st.Is64 then
    if Prefix.hasOprSz st.Pref then 16<rt> else 32<rt>
  elif REXPrefix.hasW st.REX then
    64<rt>
  elif Prefix.hasOprSz st.Pref then
    oprSize 16<rt> szCond
  else
    oprSize 32<rt> szCond

let inline wordSize (st: byref<DState>) =
  if st.Is64 then WordSize.Bit64 else WordSize.Bit32

/// The width of a fixed register whose width depends on the mode.
let inline regTypeOf (st: byref<DState>) (r: Register) =
  RegisterHelper.toRegType (wordSize &st) r

let inline readSigned (span: ByteSpan) (st: byref<DState>) (bytes: int) =
  let p = st.Pos
  st.Pos <- p + bytes
  match bytes with
  | 1 -> int64 (int8 span[p])
  | 2 -> int64 (BinaryPrimitives.ReadInt16LittleEndian(span.Slice p))
  | 4 -> int64 (BinaryPrimitives.ReadInt32LittleEndian(span.Slice p))
  | 8 -> BinaryPrimitives.ReadInt64LittleEndian(span.Slice p)
  | _ -> raise ParsingFailureException

let inline readUnsigned (span: ByteSpan) (st: byref<DState>) (bytes: int) =
  let p = st.Pos
  st.Pos <- p + bytes
  match bytes with
  | 1 -> uint64 span[p]
  | 2 -> uint64 (BinaryPrimitives.ReadUInt16LittleEndian(span.Slice p))
  | 4 -> uint64 (BinaryPrimitives.ReadUInt32LittleEndian(span.Slice p))
  | 8 -> BinaryPrimitives.ReadUInt64LittleEndian(span.Slice p)
  | _ -> raise ParsingFailureException

/// An unsigned immediate of the given width.
let inline uimm (span: ByteSpan) (st: byref<DState>) (sz: RegType) =
  let v = readUnsigned span &st (int sz >>> 3)
  Operands.oprImm (int64 v) sz

/// A sign-extended immediate of the given width.
let inline simm (span: ByteSpan) (st: byref<DState>) (sz: RegType) =
  let v = readSigned span &st (int sz >>> 3)
  Operands.oprImm v sz

/// A relative branch target of the given offset width.
let inline rel (span: ByteSpan) (st: byref<DState>) (sz: RegType) =
  let offset = readSigned span &st (int sz >>> 3)
  Operands.relTarget (offset + int64 st.Pos)

/// A far pointer spelled out in the instruction: ptr16:16 or ptr16:32.
let inline farPtr (span: ByteSpan) (st: byref<DState>) (sz: RegType) =
  let addrValue = readUnsigned span &st (int sz >>> 3)
  let selector = int16 (readSigned span &st 2)
  OprDirAddr(Absolute(selector, addrValue, sz))

let inline private oprMem span (st: byref<DState>) b s dispSz memSz =
  if dispSz = 0 then
    OprMem(b, s, None, memSz)
  else
    let disp = readSigned span &st dispSz
    OprMem(b, s, OperandParsers.someDisp disp, memSz)

/// A memory operand named by a displacement alone (moffs).
let inline moffs (span: ByteSpan) (st: byref<DState>) (memSz: RegType) =
  oprMem span &st None None (int st.AddrSz >>> 3) memSz

let private mem16 span (st: byref<DState>) (m: byte) memSz =
  let bx, bp = OperandParsers.someReg R.BX, OperandParsers.someReg R.BP
  let si, di = OperandParsers.someReg R.SI, OperandParsers.someReg R.DI
  let si1 = OperandParsers.someScaledIndex R.SI 0
  let di1 = OperandParsers.someScaledIndex R.DI 0
  match int (m >>> 3) &&& 0b11000 ||| rm m with
  | 0 -> oprMem span &st bx si1 0 memSz
  | 1 -> oprMem span &st bx di1 0 memSz
  | 2 -> oprMem span &st bp si1 0 memSz
  | 3 -> oprMem span &st bp di1 0 memSz
  | 4 -> oprMem span &st si None 0 memSz
  | 5 -> oprMem span &st di None 0 memSz
  | 6 -> oprMem span &st None None 2 memSz
  | 7 -> oprMem span &st bx None 0 memSz
  | 8 -> oprMem span &st bx si1 1 memSz
  | 9 -> oprMem span &st bx di1 1 memSz
  | 10 -> oprMem span &st bp si1 1 memSz
  | 11 -> oprMem span &st bp di1 1 memSz
  | 12 -> oprMem span &st si None 1 memSz
  | 13 -> oprMem span &st di None 1 memSz
  | 14 -> oprMem span &st bp None 1 memSz
  | 15 -> oprMem span &st bx None 1 memSz
  | 16 -> oprMem span &st bx si1 2 memSz
  | 17 -> oprMem span &st bx di1 2 memSz
  | 18 -> oprMem span &st bp si1 2 memSz
  | 19 -> oprMem span &st bp di1 2 memSz
  | 20 -> oprMem span &st si None 2 memSz
  | 21 -> oprMem span &st di None 2 memSz
  | 22 -> oprMem span &st bp None 2 memSz
  | 23 -> oprMem span &st bx None 2 memSz
  | _ -> raise ParsingFailureException

let private memSIB span (st: byref<DState>) (m: byte) dispSz memSz =
  let sib = int (readByte span &st)
  let s = (sib >>> 6) &&& 0b11
  let i = (sib >>> 3) &&& 0b111
  let b = sib &&& 0b111
  let rex = st.REX
  let idxReg = OperandParsers.findRegSIBIdx st.AddrSz rex i
  let index =
    if i = 0b100 && not (REXPrefix.hasX rex) then None
    else OperandParsers.someScaledIndex idxReg s
  let modVal = m &&& 0b11000000uy
  let bReg = OperandParsers.findRegRmAndSIBBase st.AddrSz rex b
  let baseReg =
    if b = 0b101 && modVal = 0uy then None
    else OperandParsers.someReg bReg
  let dispSz =
    if dispSz > 0 then dispSz
    elif (modVal = 0uy || modVal = 0b10000000uy) && b = 0b101 then 4
    elif modVal = 0b01000000uy && b = 0b101 then 1
    else 0
  oprMem span &st baseReg index dispSz memSz

let private mem32 span (st: byref<DState>) (m: byte) memSz =
  let md = int m >>> 6
  let r = rm m
  let dispSz = if md = 0 then 0 elif md = 1 then 1 else 4
  if r = 0b100 then
    memSIB span &st m dispSz memSz
  elif md = 0 && r = 0b101 then
    if st.Is64 then
      let b = if Prefix.hasAddrSz st.Pref then R.EIP else R.RIP
      oprMem span &st (OperandParsers.someReg b) None 4 memSz
    else
      oprMem span &st None None 4 memSz
  else
    let b =
      OperandParsers.findRegRmAndSIBBase st.AddrSz st.REX r
      |> OperandParsers.someReg
    oprMem span &st b None dispSz memSz

/// The memory operand ModRM names, of the given width.
let mem (span: ByteSpan) (st: byref<DState>) (m: byte) (memSz: RegType) =
  if st.AddrSz = 16<rt> then mem16 span &st m memSz
  else mem32 span &st m memSz

/// The register ModRM.rm names, at the given width.
let inline rmReg (st: byref<DState>) (m: byte) (sz: RegType) =
  OperandParsers.findRegRmAndSIBBase sz st.REX (rm m)

/// The register ModRM.reg names, at the given width.
let inline regReg (st: byref<DState>) (m: byte) (sz: RegType) =
  OperandParsers.findRegRBits sz st.REX (reg m)

/// The register the low three bits of the opcode byte name.
let inline opReg (st: byref<DState>) (rd: int) (sz: RegType) =
  OperandParsers.findRegRmAndSIBBase sz st.REX rd

/// Register or memory, of one width.
let inline rmOpr (span: ByteSpan) (st: byref<DState>) (m: byte) (sz: RegType) =
  if isReg m then Operands.oprReg (rmReg &st m sz) else mem span &st m sz

/// The instruction, once every operand has been read.
let inline finish (st: byref<DState>) opcode oprs opsz isFar (sel: Prefix) =
  let pref = st.Pref &&& ~~~sel
  let len = uint32 st.Pos
  let wsz = wordSize &st
  let packed =
    Instruction.Pack(len, wsz, pref, st.REX, opcode, opsz, st.AddrSz, isFar)
  Instruction(st.Addr, packed, None, oprs, st.Lifter)

let inline private hi16 (b: bool) = if b then 16 else 0

/// The register ModRM.reg names, widened by EVEX.R' where the prefix carries
/// one.
let inline regRegV (st: byref<DState>) (m: byte) (sz: RegType) =
  let rex = st.REX
  OperandParsers.findRegRBits sz rex (reg m + hi16 (REXPrefix.hasEVEXR rex))

/// The register ModRM.rm names. In a register form EVEX spends X on the fifth
/// bit of rm.
let inline rmRegV (st: byref<DState>) (m: byte) (sz: RegType) =
  let rex = st.REX
  let hi = hi16 (st.IsEVEX && REXPrefix.hasX rex)
  OperandParsers.findRegRmAndSIBBase sz rex (rm m + hi)

/// The register (E)VEX.vvvv names: a general-purpose register at a GPR width
/// (BMI, CMPccXADD), a vector register otherwise, widened by EVEX.V'.
let vvvvReg (st: byref<DState>) (sz: RegType) =
  if sz <= 64<rt> then
    int (RegGroup.grpEAX sz) + (st.VVVV &&& 0b1111)
    |> LanguagePrimitives.EnumOfValue<int, Register>
  else
    let n = st.VVVV + hi16 (REXPrefix.hasEVEXV st.REX)
    match sz with
    | 512<rt> -> RegisterHelper.zmm n
    | 256<rt> -> RegisterHelper.ymm n
    | _ -> RegisterHelper.xmm n

/// The register imm8[7:4] names.
let inline is4Reg (span: ByteSpan) (st: byref<DState>) (sz: RegType) =
  let n = int (readByte span &st >>> 4 &&& 0b1111uy)
  OperandParsers.findRegIS4 (wordSize &st) sz n

/// An opmask register named by a field of the encoding. In 64-bit mode a
/// prefix bit that would carry ModRM.reg past the eight registers is #UD;
/// outside it the bits are ignored.
let opmaskReg (st: byref<DState>) (idx: int) (isRegField: bool) =
  let rex = st.REX
  if not st.Is64 then
    OperandParsers.parseOpMaskReg (idx &&& 0b111)
  elif isRegField && (REXPrefix.hasR rex || REXPrefix.hasEVEXR rex) then
    raise ParsingFailureException
  else
    OperandParsers.parseOpMaskReg idx

/// The vector-length constraint of a row in a slot that offers a rounding
/// decoration: EVEX.b on a register form spends L'L on the rounding mode, so
/// only a row offering one (rc) answers there; otherwise the length has to
/// be the row's, or the row constrains none (vl = 0).
let inline vlOk (st: byref<DState>) (m: byte) (rc: bool) (vl: RegType) =
  if st.EvexB && isReg m then rc
  else vl = 0<rt> || st.VL = vl

/// The width of one element an embedded broadcast reads: the operand's, or
/// REX.W's word where the operand declared none.
let inline private bcstElemSz (st: byref<DState>) (bcst: RegType) =
  if bcst <> 0<rt> then bcst
  elif REXPrefix.hasW st.REX then 64<rt>
  else 32<rt>

/// EVEX compressed displacement (disp8*N) and the width it settles. See the
/// manual Chap. 15 of Vol. 1 and OperandParsers.uncompressedDisp.
let private uncompressed (st: byref<DState>) (tt: TupleType) bcst memSz disp =
  let b = st.EvexB
  let w = REXPrefix.hasW st.REX
  let inputSz = bcstElemSz &st bcst
  let vl = st.VL
  match tt, b, inputSz, w with
  | TupleType.Full, false, _, _ ->
    struct (disp * (int64 vl / 8L), memSz)
  | TupleType.Full, true, _, _ ->
    struct (disp * (int64 inputSz / 8L), inputSz)
  | TupleType.Half, false, _, _ ->
    struct (disp * (int64 vl / 16L), memSz)
  | TupleType.Half, true, _, _ ->
    struct (disp * (int64 inputSz / 8L), inputSz)
  | TupleType.FullMem, false, _, _ ->
    struct (disp * (int64 vl / 8L), memSz)
  | TupleType.Tuple1Scalar, false, _, _ when memSz <= 16<rt> ->
    struct (disp * (int64 memSz / 8L), memSz)
  | TupleType.Tuple1Scalar, false, 32<rt>, false ->
    struct (disp * 4L, memSz)
  | TupleType.Tuple1Scalar, false, 64<rt>, true ->
    struct (disp * 8L, memSz)
  | TupleType.Tuple1Fixed, false, _, _ ->
    struct (disp * (int64 memSz / 8L), memSz)
  | TupleType.Tuple2, false, 32<rt>, false ->
    struct (disp * 8L, memSz)
  | TupleType.Tuple2, false, 64<rt>, true when vl <> 128<rt> ->
    struct (disp * 16L, memSz)
  | TupleType.Tuple4, false, 32<rt>, false when vl <> 128<rt> ->
    struct (disp * 16L, memSz)
  | TupleType.Tuple4, false, 64<rt>, true when vl = 512<rt> ->
    struct (disp * 32L, memSz)
  | TupleType.Tuple8, false, 32<rt>, false when vl = 512<rt> ->
    struct (disp * 32L, memSz)
  | TupleType.HalfMem, false, _, _ ->
    struct (disp * (int64 vl / 16L), memSz)
  | TupleType.QuarterMem, false, _, _ ->
    struct (disp * (int64 vl / 32L), memSz)
  | TupleType.EighthMem, false, _, _ ->
    struct (disp * (int64 vl / 64L), memSz)
  | TupleType.Mem128, false, _, _ ->
    struct (disp * 16L, memSz)
  | TupleType.MOVDDUP, false, _, _ when vl = 128<rt> ->
    struct (disp * 8L, memSz)
  | TupleType.MOVDDUP, false, _, _ ->
    struct (disp * (int64 vl / 8L), memSz)
  | TupleType.Tuple1_4X, false, _, _ ->
    struct (disp * 16L, memSz)
  | TupleType.Scalar, _, _, _ ->
    struct (disp * (int64 memSz / 8L), memSz)
  | TupleType.Quarter, false, _, _ ->
    struct (disp * (int64 vl / 32L), memSz)
  | TupleType.Quarter, true, _, _ ->
    struct (disp * (int64 inputSz / 8L), inputSz)
  | _ ->
    struct (disp, memSz)

/// A memory operand under an EVEX prefix: the displacement is compressed and
/// a broadcast narrows the width to one element.
let private oprMemE span (st: byref<DState>) b s dispSz memSz tt bcst =
  if dispSz = 0 then
    if st.EvexB then OprMem(b, s, None, bcstElemSz &st bcst)
    else OprMem(b, s, None, memSz)
  elif dispSz = 1 then
    let disp = readSigned span &st 1
    let struct (disp, memSz) = uncompressed &st tt bcst memSz disp
    OprMem(b, s, OperandParsers.someDisp disp, memSz)
  elif dispSz = 4 && st.EvexB then
    let disp = readSigned span &st 4
    OprMem(b, s, OperandParsers.someDisp disp, bcstElemSz &st bcst)
  else
    let disp = readSigned span &st dispSz
    OprMem(b, s, OperandParsers.someDisp disp, memSz)

let private mem16E span (st: byref<DState>) (m: byte) memSz tt bcst =
  let bx, bp = OperandParsers.someReg R.BX, OperandParsers.someReg R.BP
  let si, di = OperandParsers.someReg R.SI, OperandParsers.someReg R.DI
  let si1 = OperandParsers.someScaledIndex R.SI 0
  let di1 = OperandParsers.someScaledIndex R.DI 0
  match int (m >>> 3) &&& 0b11000 ||| rm m with
  | 0 -> oprMemE span &st bx si1 0 memSz tt bcst
  | 1 -> oprMemE span &st bx di1 0 memSz tt bcst
  | 2 -> oprMemE span &st bp si1 0 memSz tt bcst
  | 3 -> oprMemE span &st bp di1 0 memSz tt bcst
  | 4 -> oprMemE span &st si None 0 memSz tt bcst
  | 5 -> oprMemE span &st di None 0 memSz tt bcst
  | 6 -> oprMemE span &st None None 2 memSz tt bcst
  | 7 -> oprMemE span &st bx None 0 memSz tt bcst
  | 8 -> oprMemE span &st bx si1 1 memSz tt bcst
  | 9 -> oprMemE span &st bx di1 1 memSz tt bcst
  | 10 -> oprMemE span &st bp si1 1 memSz tt bcst
  | 11 -> oprMemE span &st bp di1 1 memSz tt bcst
  | 12 -> oprMemE span &st si None 1 memSz tt bcst
  | 13 -> oprMemE span &st di None 1 memSz tt bcst
  | 14 -> oprMemE span &st bp None 1 memSz tt bcst
  | 15 -> oprMemE span &st bx None 1 memSz tt bcst
  | 16 -> oprMemE span &st bx si1 2 memSz tt bcst
  | 17 -> oprMemE span &st bx di1 2 memSz tt bcst
  | 18 -> oprMemE span &st bp si1 2 memSz tt bcst
  | 19 -> oprMemE span &st bp di1 2 memSz tt bcst
  | 20 -> oprMemE span &st si None 2 memSz tt bcst
  | 21 -> oprMemE span &st di None 2 memSz tt bcst
  | 22 -> oprMemE span &st bp None 2 memSz tt bcst
  | 23 -> oprMemE span &st bx None 2 memSz tt bcst
  | _ -> raise ParsingFailureException

let private memSIBE span (st: byref<DState>) (m: byte) dispSz memSz tt bcst =
  let sib = int (readByte span &st)
  let s = (sib >>> 6) &&& 0b11
  let i = (sib >>> 3) &&& 0b111
  let b = sib &&& 0b111
  let rex = st.REX
  let idxReg = OperandParsers.findRegSIBIdx st.AddrSz rex i
  let index =
    if i = 0b100 && not (REXPrefix.hasX rex) then None
    else OperandParsers.someScaledIndex idxReg s
  let modVal = m &&& 0b11000000uy
  let bReg = OperandParsers.findRegRmAndSIBBase st.AddrSz rex b
  let baseReg =
    if b = 0b101 && modVal = 0uy then None
    else OperandParsers.someReg bReg
  let dispSz =
    if dispSz > 0 then dispSz
    elif (modVal = 0uy || modVal = 0b10000000uy) && b = 0b101 then 4
    elif modVal = 0b01000000uy && b = 0b101 then 1
    else 0
  oprMemE span &st baseReg index dispSz memSz tt bcst

let private mem32E span (st: byref<DState>) (m: byte) memSz tt bcst =
  let md = int m >>> 6
  let r = rm m
  let dispSz = if md = 0 then 0 elif md = 1 then 1 else 4
  if r = 0b100 then
    memSIBE span &st m dispSz memSz tt bcst
  elif md = 0 && r = 0b101 then
    if st.Is64 then
      let b = if Prefix.hasAddrSz st.Pref then R.EIP else R.RIP
      oprMemE span &st (OperandParsers.someReg b) None 4 memSz tt bcst
    else
      oprMemE span &st None None 4 memSz tt bcst
  else
    let b =
      OperandParsers.findRegRmAndSIBBase st.AddrSz st.REX r
      |> OperandParsers.someReg
    oprMemE span &st b None dispSz memSz tt bcst

/// The memory operand ModRM names under a VEX or EVEX prefix. tt is the
/// row's tuple type and bcst the element width the operand broadcasts, or
/// 0<rt>; both matter only under EVEX.
let memV (span: ByteSpan) (st: byref<DState>) (m: byte) memSz tt bcst =
  if not st.IsEVEX then mem span &st m memSz
  elif st.AddrSz = 16<rt> then mem16E span &st m memSz tt bcst
  else mem32E span &st m memSz tt bcst

/// Register or memory under a VEX or EVEX prefix.
let inline rmOprV span (st: byref<DState>) (m: byte) rsz msz tt bcst =
  if isReg m then Operands.oprReg (rmRegV &st m rsz)
  else memV span &st m msz tt bcst

/// A VSIB memory operand of the given index element width. See
/// Parser.parseVSIBOperand: the vector length says how many elements there
/// are, the index register holds that many indices and the access covers
/// that many data elements.
let memVSIB (span: ByteSpan) (st: byref<DState>) (m: byte) elemSz tt =
  let vl = st.VL
  let dataSz = if REXPrefix.hasW st.REX then 64<rt> else 32<rt>
  let count = vl / max elemSz dataSz
  let idxVl = max 128<rt> (count * elemSz)
  let memSz = count * dataSz
  if rm m <> 0b100 then raise ParsingFailureException else ()
  let sib = int (readByte span &st)
  let s = (sib >>> 6) &&& 0b11
  let i = ((sib >>> 3) &&& 0b111) + hi16 (REXPrefix.hasEVEXV st.REX)
  let b = sib &&& 0b111
  let rex = st.REX
  let idxReg = OperandParsers.findRegSIBIdx idxVl rex i
  let index = OperandParsers.someScaledIndex idxReg s
  let modVal = m &&& 0b11000000uy
  let bReg = OperandParsers.findRegRmAndSIBBase st.AddrSz rex b
  let baseReg =
    if b = 0b101 && modVal = 0uy then None
    else OperandParsers.someReg bReg
  let dispSz =
    match modVal with
    | 0uy -> if b = 0b101 then 4 else 0
    | 0b01000000uy -> 1
    | 0b10000000uy -> 4
    | _ -> raise ParsingFailureException
  if st.IsEVEX then oprMemE span &st baseReg index dispSz memSz tt 0<rt>
  else oprMem span &st baseReg index dispSz memSz

/// The instruction under a VEX or EVEX prefix. A broadcast width the memory
/// form declared, or the reading EVEX.b took on a register form, is carried
/// into the EVEX prefix the instruction keeps, as the table parser does.
let finishV (st: byref<DState>) opcode oprs opsz (bcst: RegType) rc isRegForm =
  let pref = st.Pref &&& ~~~(Prefix.OPSIZE ||| Prefix.REPZ ||| Prefix.REPNZ)
  let len = uint32 st.Pos
  let wsz = wordSize &st
  let packed =
    Instruction.Pack(len, wsz, pref, st.REX, opcode, opsz, st.AddrSz, false)
  let vex =
    match st.Vex with
    | Some({ EVEXPrx = Some e } as v) when bcst <> 0<rt> ->
      Some { v with EVEXPrx = Some { e with BcstElemSize = bcst } }
    | Some({ EVEXPrx = Some e } as v) when e.B = 1uy && isRegForm ->
      Some { v with EVEXPrx = Some { e with RCDecor = rc } }
    | v ->
      v
  Instruction(st.Addr, packed, vex, oprs, st.Lifter)
