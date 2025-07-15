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

[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.Intel.OperandParsers

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel.RegGroup

/// Represents an operand descriptor that defines the shape of operands within
/// an instruction.
type OprDesc =
  | RmGpr = 0
  | RmSeg = 1
  | GprCtrl = 2
  | GprDbg = 3
  | RMMmx = 4
  | MmMmx = 5
  | BmBnd = 6
  | RmBnd = 7
  | GprRm = 8
  | GprM = 9
  | MGpr = 10
  | SegRm = 11
  | BndBm = 12
  | BndRm = 13
  | CtrlGpr = 14
  | DbgGpr = 15
  | MmxRm = 16
  | MmxMm = 17
  | MxMx = 18
  | GprRMm = 19
  | RegImm8 = 20
  | Imm8Reg = 21
  | Imm8 = 22
  | Imm16 = 23
  | RegImm = 24
  | SImm8 = 25
  | Imm = 26
  | Es = 27
  | Cs = 28
  | Ss = 29
  | Ds = 30
  | Fs = 31
  | Gs = 32
  | ALDx = 33
  | EaxDx = 34
  | DxEax = 35
  | DxAL = 36
  | No = 37
  | Eax = 38
  | Ecx = 39
  | Edx = 40
  | Ebx = 41
  | Esp = 42
  | Ebp = 43
  | Esi = 44
  | Edi = 45
  | Rax = 46
  | Rcx = 47
  | Rdx = 48
  | Rbx = 49
  | Rsp = 50
  | Rbp = 51
  | Rsi = 52
  | Rdi = 53
  | RaxRax = 54
  | RaxRcx = 55
  | RaxRdx = 56
  | RaxRbx = 57
  | RaxRsp = 58
  | RaxRbp = 59
  | RaxRsi = 60
  | RaxRdi = 61
  | GprRmImm8 = 62
  | GprRmImm = 63
  | Rel8 = 64
  | Rel = 65
  | Dir = 66
  | RaxFar = 67
  | FarRax = 68
  | ALImm8 = 69
  | CLImm8 = 70
  | DLImm8 = 71
  | BLImm8 = 72
  | AhImm8 = 73
  | ChImm8 = 74
  | DhImm8 = 75
  | BhImm8 = 76
  | RaxImm = 77
  | RcxImm = 78
  | RdxImm = 79
  | RbxImm = 80
  | RspImm = 81
  | RbpImm = 82
  | RsiImm = 83
  | RdiImm = 84
  | ImmImm = 85
  | RmImm = 86
  | RmImm8 = 87
  | RmSImm8 = 88
  | MmxImm8 = 89
  | Mem = 90
  | M1 = 91
  | RmCL = 92
  | XmmVvXm = 93
  | GprVvRm = 94
  | XmVvXmm = 95
  | Gpr = 96
  | RmXmmImm8 = 97
  | XmmRmImm8 = 98
  | MmxMmImm8 = 99
  | MmxRmImm8 = 100
  | GprMmxImm8 = 101
  | XmmVvXmImm8 = 102
  | XmmVvXmXmm = 103
  | XmRegImm8 = 104
  | GprRmVv = 105
  | VvRmImm8 = 106
  | RmGprCL = 107
  | XmmXmXmm0 = 108
  | XmmXmVv = 109
  | VvRm = 110
  | GprRmImm8Imm8 = 111
  | RmImm8Imm8 = 112
  | KnVvXm = 113
  | GprKn = 114
  | KnVvXmImm8 = 115
  | KnGpr = 116
  | XmmVvXmmXm = 117
  | KnKm = 118
  | MKn = 119
  | KKn = 120
  | KnKmImm8 = 121
  | XmmVsXm = 122
  | XmVsXmm = 123

/// We define 8 different RegGrp types. Intel instructions use an integer
/// value such as a REG field of a ModR/M value.
type RegGrp =
  /// AL/AX/EAX/...
  | RG0 = 0
  /// CL/CX/ECX/...
  | RG1 = 1
  /// DL/DX/EDX/...
  | RG2 = 2
  /// BL/BX/EBX/...
  | RG3 = 3
  /// AH/SP/ESP/...
  | RG4 = 4
  /// CH/BP/EBP/...
  | RG5 = 5
  /// DH/SI/ESI/...
  | RG6 = 6
  /// BH/DI/EDI/...
  | RG7 = 7

open type RegGrp

/// Find a specific reg. The bitmask will be used to extract a specific REX
/// bit (R/X/B).
let inline private findReg sz rex bitmask (n: int) =
  let r = int (grpEAX sz) + n
  let r =
    if rex = REXPrefix.NOREX then r
    else
      if (int rex &&& bitmask) > 0 then r + 8
      elif sz > 8<rt> || ((n &&& 4) = 0) then r
      else r + 12
  LanguagePrimitives.EnumOfValue<int, Register> r

/// Registers defined by the SIB index field.
let findRegSIBIdx sz rex (n: int) = findReg sz rex 2 n

/// Registers defined by the SIB base field, or base registers defined by the
/// RM field (first three rows of Table 2-2), or registers defined by REG bit
/// of the opcode, which can change the symbol by REX bits.
let findRegRmAndSIBBase sz rex (n: int) = findReg sz rex 1 n

/// Registers defined by REG field of the ModR/M byte.
let findRegRBits sz rex (n: int): Register = findReg sz rex 4 n

/// Registers defined by REG bit of the opcode: some instructions such as PUSH
/// make use of its opcode to represent the REG bit. REX bits *cannot* change
/// the symbol.
let findRegNoREX sz rex (n: int): Register =
  let r = int (grpEAX sz) + n
  let r =
    if rex = REXPrefix.NOREX then r
    else
      if sz > 8<rt> || ((n &&& 4) = 0) then r
      else r + 12
  LanguagePrimitives.EnumOfValue<int, Register> r

let inline getOprFromRegGrpNoREX rgrp (phlp: ParsingHelper) =
  findRegNoREX phlp.RegSize phlp.REXPrefix rgrp |> OprReg

let inline getOprFromRegGrpREX rgrp (phlp: ParsingHelper) =
  findRegRmAndSIBBase phlp.RegSize phlp.REXPrefix rgrp |> OprReg

let parseSignedImm span (phlp: ParsingHelper) = function
  | 1 -> phlp.ReadInt8 span |> int64
  | 2 -> phlp.ReadInt16 span |> int64
  | 4 -> phlp.ReadInt32 span |> int64
  | 8 -> phlp.ReadInt64 span
  | _ -> raise ParsingFailureException

let parseUnsignedImm span (phlp: ParsingHelper) = function
  | 1 -> phlp.ReadUInt8 span |> uint64
  | 2 -> phlp.ReadUInt16 span |> uint64
  | 4 -> phlp.ReadUInt32 span |> uint64
  | 8 -> phlp.ReadUInt64 span
  | _ -> raise ParsingFailureException

/// EVEX uses compressed displacement. See the manual Chap. 15 of Vol. 1.
let uncompressedDisp (phlp: ParsingHelper) disp =
  let vInfo = phlp.VEXInfo.Value
  let evex = vInfo.EVEXPrx.Value
  let tt = phlp.TupleType
  let b = evex.B = 1uy
  let w = phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW
  let inputSz = if w then 64<rt> else 32<rt>
  let memSz = phlp.MemEffOprSize
  let vl = vInfo.VectorLength
  match tt, b, inputSz, w with
  (* Table 2-34. Compressed Displacement (DISP8*N) Affected by Embedded
     Broadcast. *)
  | TupleType.Full, false, 32<rt>, false ->
    disp * (int64 vl / 8L), memSz
  | TupleType.Full, true, 32<rt>, false -> disp * 4L, inputSz
  | TupleType.Full, false, 64<rt>, true -> disp * (int64 vl / 8L), memSz
  | TupleType.Full, true, 64<rt>, true -> disp * 8L, inputSz
  | TupleType.Half, false, 32<rt>, false ->
    disp * (int64 vl / 16L), memSz
  | TupleType.Half, true, 32<rt>, false -> disp * 4L, inputSz
  (* Table 2-35. EVEX DISP8*N for Instructions Not Affected by Embedded
     Broadcast. *)
  | TupleType.FullMem, false, _, _ -> disp * (int64 vl / 8L), memSz
  | TupleType.Tuple1Scalar, false, 8<rt>, _ -> disp, memSz
  | TupleType.Tuple1Scalar, false, 16<rt>, _ -> disp * 2L, memSz
  | TupleType.Tuple1Scalar, false, 32<rt>, false -> disp * 4L, memSz
  | TupleType.Tuple1Scalar, false, 64<rt>, true -> disp * 8L, memSz
  | TupleType.Tuple1Fixed, false, 32<rt>, _ -> disp * 4L, memSz
  | TupleType.Tuple1Fixed, false, 64<rt>, _ -> disp * 8L, memSz
  | TupleType.Tuple2, false, 32<rt>, false -> disp * 8L, memSz
  | TupleType.Tuple2, false, 64<rt>, true when vl <> 128<rt> ->
    disp * 16L, memSz
  | TupleType.Tuple4, false, 32<rt>, true when vl <> 128<rt> ->
    disp * 16L, memSz
  | TupleType.Tuple4, false, 64<rt>, true when vl = 512<rt> ->
    disp * 32L, memSz
  | TupleType.Tuple8, false, 32<rt>, false when vl = 512<rt> ->
    disp * 32L, memSz
  | TupleType.HalfMem, false, _, _ -> disp * (int64 vl / 16L), memSz
  | TupleType.QuarterMem, false, _, _ -> disp * (int64 vl / 32L), memSz
  | TupleType.EighthMem, false, _, _ -> disp * (int64 vl / 64L), memSz
  | TupleType.Mem128, false, _, _ -> disp * 16L, memSz
  | TupleType.MOVDDUP, false, _, _ -> disp * (int64 vl / 16L), memSz
  | _ (* TupleType.NA *) -> disp, memSz

let inline private isEVEX (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | Some vInfo -> vInfo.VEXType &&& VEXType.EVEX = VEXType.EVEX
  | _ -> false

let parseOprMem span (phlp: ParsingHelper) b s dispSz =
  let memSz = phlp.MemEffOprSize
#if LCACHE
    phlp.MarkHashEnd ()
#endif
  if isEVEX phlp then
    let isBcst = phlp.VEXInfo.Value.EVEXPrx.Value.B = 1uy
    match dispSz, isBcst with
    | 0, false -> OprMem (b, s, None, memSz)
    | 0, true ->
      let w = phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW
      let memSz = if w then 64<rt> else 32<rt>
      OprMem (b, s, None, memSz)
    | 1, _ ->
      let disp = parseSignedImm span phlp dispSz
      let disp, memSz = uncompressedDisp phlp disp
      OprMem (b, s, Some disp, memSz)
    | 4, true ->
      let disp = parseSignedImm span phlp dispSz
      let w = phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW
      let memSz = if w then 64<rt> else 32<rt>
      OprMem (b, s, Some disp, memSz)
    | _, _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem (b, s, Some disp, memSz)
  else
    match dispSz with
    | 0 -> OprMem (b, s, None, memSz)
    | _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem (b, s, Some disp, memSz)

let parseOprImm span (phlp: ParsingHelper) immSize =
#if LCACHE
  phlp.MarkHashEnd ()
#endif
  let imm = parseUnsignedImm span phlp (RegType.toByteWidth immSize)
  OprImm (int64 imm, immSize)

let parseOprSImm span (phlp: ParsingHelper) immSize =
#if LCACHE
  phlp.MarkHashEnd ()
#endif
  let imm = parseSignedImm span phlp (RegType.toByteWidth immSize)
  OprImm (imm, immSize)

/// The first 24 rows of Table 2-1. of the manual Vol. 2A.
/// The index of this tbl is a number that is a concatenation of (mod) and
/// (r/m) field of the ModR/M byte. Each element is a tuple of base register,
/// scaled index register, and the size of the displacement.
/// Table for scales (of SIB). This tbl is indexbed by the scale value of SIB.
let parseMEM16 span phlp modRM =
  let m = Operands.getMod modRM
  let rm =Operands.getRM modRM
  match (m <<< 3) ||| rm with (* Concatenation of mod and rm bit *)
  | 0 -> parseOprMem span phlp (Some R.BX) (Some (R.SI, Scale.X1)) 0
  | 1 -> parseOprMem span phlp (Some R.BX) (Some (R.DI, Scale.X1)) 0
  | 2 -> parseOprMem span phlp (Some R.BP) (Some (R.SI, Scale.X1)) 0
  | 3 -> parseOprMem span phlp (Some R.BP) (Some (R.DI, Scale.X1)) 0
  | 4 -> parseOprMem span phlp (Some R.SI) None 0
  | 5 -> parseOprMem span phlp (Some R.DI) None 0
  | 6 -> parseOprMem span phlp None None 2
  | 7 -> parseOprMem span phlp (Some R.BX) None 0
  (* Mod 01b *)
  | 8 -> parseOprMem span phlp (Some R.BX) (Some (R.SI, Scale.X1)) 1
  | 9 -> parseOprMem span phlp (Some R.BX) (Some (R.DI, Scale.X1)) 1
  | 10 -> parseOprMem span phlp (Some R.BP) (Some (R.SI, Scale.X1)) 1
  | 11 -> parseOprMem span phlp (Some R.BP) (Some (R.DI, Scale.X1)) 1
  | 12 -> parseOprMem span phlp (Some R.SI) None 1
  | 13 -> parseOprMem span phlp (Some R.DI) None 1
  | 14 -> parseOprMem span phlp (Some R.BP) None 1
  | 15 -> parseOprMem span phlp (Some R.BX) None 1
  (* Mod 10b *)
  | 16 -> parseOprMem span phlp (Some R.BX) (Some (R.SI, Scale.X1)) 2
  | 17 -> parseOprMem span phlp (Some R.BX) (Some (R.DI, Scale.X1)) 2
  | 18 -> parseOprMem span phlp (Some R.BP) (Some (R.SI, Scale.X1)) 2
  | 19 -> parseOprMem span phlp (Some R.BP) (Some (R.DI, Scale.X1)) 2
  | 20 -> parseOprMem span phlp (Some R.SI) None 2
  | 21 -> parseOprMem span phlp (Some R.DI) None 2
  | 22 -> parseOprMem span phlp (Some R.BP) None 2
  | 23 -> parseOprMem span phlp (Some R.BX) None 2
  | _ -> raise ParsingFailureException

let inline hasREXX rexPref = rexPref &&& REXPrefix.REXX = REXPrefix.REXX

let getScaledIndex s i (phlp: ParsingHelper) =
  let rexPref = phlp.REXPrefix
  (* Handling a special case with REXX and SIB index = 0b100 (ESP) *)
  if i = 0b100 && (not <| hasREXX rexPref) then None
  else
    let r = findRegSIBIdx phlp.MemEffAddrSize rexPref i
    Some (r, LanguagePrimitives.EnumOfValue<int, Scale> (1 <<< s))

/// See Notes 1 of Table 2-3 of the manual Vol. 2A
let getSIBBaseReg b (phlp: ParsingHelper) modVal =
  let rexPref = phlp.REXPrefix
  if b = int RegGrp.RG5 && modVal = 0b00uy then None
  else Some (findRegRmAndSIBBase phlp.MemEffAddrSize rexPref b)

let inline private getSIB b =
  struct ((b >>> 6) &&& 0b11, (b >>> 3) &&& 0b111, b &&& 0b111)

let parseSIB span (phlp: ParsingHelper) modVal =
  let struct (s, i, b) = phlp.ReadByte span |> int |> getSIB
  let si = getScaledIndex s i phlp
  let baseReg = getSIBBaseReg b phlp modVal
  struct (si, baseReg, b)

let baseRMReg (phlp: ParsingHelper) regGrp =
  findRegRmAndSIBBase phlp.MemEffAddrSize phlp.REXPrefix (int regGrp) |> Some

let sibWithDisp span (phlp: ParsingHelper) b s dispSz memSz =
#if LCACHE
  phlp.MarkHashEnd ()
#endif
  if isEVEX phlp then
    let isBcst = phlp.VEXInfo.Value.EVEXPrx.Value.B = 1uy
    match dispSz, isBcst with
    | 0, false -> OprMem (b, s, None, memSz)
    | 0, true ->
      let w = phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW
      let memSz = if w then 64<rt> else 32<rt>
      OprMem (b, s, None, memSz)
    | 1, _ ->
      let disp = parseSignedImm span phlp dispSz
      let disp, memSz = uncompressedDisp phlp disp
      OprMem (b, s, Some disp, memSz)
    | 4, true ->
      let disp = parseSignedImm span phlp dispSz
      let w = phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW
      let memSz = if w then 64<rt> else 32<rt>
      OprMem (b, s, Some disp, memSz)
    | _, _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem (b, s, Some disp, memSz)
  else
    match dispSz with
    | 0 -> OprMem (b, s, None, memSz)
    | _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem (b, s, Some disp, memSz)

let parseOprMemWithSIB span phlp modVal dispSz =
  let struct (si, b, bgrp) = parseSIB span phlp modVal
  let oprSize = phlp.MemEffOprSize
  if dispSz > 0 then sibWithDisp span phlp b si dispSz oprSize
  else
    if (modVal = 0b00000000uy || modVal = 0b10000000uy)
      && bgrp = int RegGrp.RG5 then
      sibWithDisp span phlp b si 4 oprSize
    elif modVal = 0b01000000uy && bgrp = int RegGrp.RG5 then
      sibWithDisp span phlp b si 1 oprSize
    else OprMem (b, si, None, oprSize)

/// RIP-relative addressing (see Section 2.2.1.6. of Vol. 2A).
let parseOprRIPRelativeMem span (phlp: ParsingHelper) disp =
  if phlp.WordSize = WordSize.Bit64 then
    if Prefix.hasAddrSz phlp.Prefixes then
      parseOprMem span phlp (Some R.EIP) None disp
    else parseOprMem span phlp (Some R.RIP) None disp
  else parseOprMem span phlp None None disp

/// The first 24 rows of Table 2-2. of the manual Vol. 2A. The index of this
/// tbl is a number that is a concatenation of (mod) and (r/m) field of the
/// ModR/M byte. Each element is a tuple of (MemLookupType, and the size of
/// the displacement). If the first value of the tuple (register group) is
/// None, it means we need to look up the SIB tbl (Table 2-3). If not, then it
/// represents the reg group of the base reigster.
let parseMEM32 span phlp modRM =
  let modVal = modRM &&& 0b11000000uy
  match modVal >>> 3 ||| (modRM &&& 0b00000111uy) with
  (* Mod 00b *)
  | 0uy -> parseOprMem span phlp (baseRMReg phlp RG0) None 0
  | 1uy -> parseOprMem span phlp (baseRMReg phlp RG1) None 0
  | 2uy -> parseOprMem span phlp (baseRMReg phlp RG2) None 0
  | 3uy -> parseOprMem span phlp (baseRMReg phlp RG3) None 0
  | 4uy -> parseOprMemWithSIB span phlp modVal 0
  | 5uy -> parseOprRIPRelativeMem span phlp 4
  | 6uy -> parseOprMem span phlp (baseRMReg phlp RG6) None 0
  | 7uy -> parseOprMem span phlp (baseRMReg phlp RG7) None 0
  (* Mod 01b *)
  | 8uy -> parseOprMem span phlp (baseRMReg phlp RG0) None 1
  | 9uy -> parseOprMem span phlp (baseRMReg phlp RG1) None 1
  | 10uy -> parseOprMem span phlp (baseRMReg phlp RG2) None 1
  | 11uy -> parseOprMem span phlp (baseRMReg phlp RG3) None 1
  | 12uy -> parseOprMemWithSIB span phlp modVal 1
  | 13uy -> parseOprMem span phlp (baseRMReg phlp RG5) None 1
  | 14uy -> parseOprMem span phlp (baseRMReg phlp RG6) None 1
  | 15uy -> parseOprMem span phlp (baseRMReg phlp RG7) None 1
  (* Mod 10b *)
  | 16uy -> parseOprMem span phlp (baseRMReg phlp RG0) None 4
  | 17uy -> parseOprMem span phlp (baseRMReg phlp RG1) None 4
  | 18uy -> parseOprMem span phlp (baseRMReg phlp RG2) None 4
  | 19uy -> parseOprMem span phlp (baseRMReg phlp RG3) None 4
  | 20uy -> parseOprMemWithSIB span phlp modVal 4
  | 21uy -> parseOprMem span phlp (baseRMReg phlp RG5) None 4
  | 22uy -> parseOprMem span phlp (baseRMReg phlp RG6) None 4
  | 23uy -> parseOprMem span phlp (baseRMReg phlp RG7) None 4
  | _ -> raise ParsingFailureException

let parseMemory modRM span (phlp: ParsingHelper) =
  if phlp.MemEffAddrSize = 16<rt> then parseMEM16 span phlp modRM
  else parseMEM32 span phlp modRM

let parseMemOrReg modRM span (phlp: ParsingHelper) =
  if modRM &&& 0b11000000uy = 0b11000000uy then
    findRegRmAndSIBBase phlp.MemEffRegSize phlp.REXPrefix
      (Operands.getRM modRM) |> OprReg
  else parseMemory modRM span phlp

let parseVVVVReg (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | None -> raise ParsingFailureException
  | Some vInfo when vInfo.VectorLength = 512<rt> ->
    Register.zmm (int vInfo.VVVV) |> OprReg
  | Some vInfo when vInfo.VectorLength = 256<rt> ->
    Register.ymm (int vInfo.VVVV) |> OprReg
  | Some vInfo ->
    Register.xmm (int vInfo.VVVV) |> OprReg

/// FIXME
let parseVVVVRegRC isReg (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | None -> raise ParsingFailureException
  | Some vInfo ->
    match vInfo.EVEXPrx with
    | Some evex when evex.B = 1uy && isReg ->
      Register.zmm (int vInfo.VVVV) |> OprReg
    | _ ->
      match vInfo.VectorLength with
      | 512<rt> -> Register.zmm (int vInfo.VVVV) |> OprReg
      | 256<rt> -> Register.ymm (int vInfo.VVVV) |> OprReg
      | 128<rt> -> Register.xmm (int vInfo.VVVV) |> OprReg
      | _ -> raise ParsingFailureException

let parseVEXtoGPR (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | None -> raise ParsingFailureException
  | Some vInfo ->
    let grp = (int vInfo.VVVV) &&& 0b1111
    int (grpEAX phlp.RegSize) + grp
    |> LanguagePrimitives.EnumOfValue<int, Register>
    |> OprReg

let parseMMXReg n =
  Register.mm n |> OprReg

let parseSegReg n =
  if n < 6 then Register.seg n |> OprReg
  else raise ParsingFailureException

let parseBoundRegister n =
  if n < 4 then Register.bound n |> OprReg
  else raise ParsingFailureException

let parseControlReg n =
  Register.control n |> OprReg

let parseDebugReg n =
  Register.debug n |> OprReg

let parseOpMaskReg n =
  Register.opmask n |> OprReg

let parseOprOnlyDisp span (phlp: ParsingHelper) =
  let dispSz = RegType.toByteWidth phlp.MemEffAddrSize
  parseOprMem span phlp None None dispSz

let getImmZ (phlp: ParsingHelper) =
  if phlp.MemEffOprSize = 64<rt> || phlp.MemEffOprSize = 32<rt> then 32<rt>
  else phlp.MemEffOprSize

let opGprImm span phlp regGrp =
  let o1 = getOprFromRegGrpREX (int regGrp) phlp
  let o2 = parseOprSImm span phlp phlp.MemEffOprSize
  TwoOperands (o1, o2)

let parseOprForRelJmp span (phlp: ParsingHelper) immSz =
#if LCACHE
  phlp.MarkHashEnd ()
#endif
  let immSz = RegType.toByteWidth immSz
  let offset = parseSignedImm span phlp immSz
  let relOffset = offset + int64 (phlp.ParsedLen ())
  OprDirAddr (Relative (relOffset))

type OpRmGpr () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    TwoOperands (opr1, opr2)

type OpRmSeg () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 = parseSegReg (Operands.getReg modRM)
    TwoOperands (opr1, opr2)

type OpGprCtrl () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    if Operands.modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseMemOrReg modRM span phlp
      let opr2 = parseControlReg (Operands.getReg modRM)
      TwoOperands (opr1, opr2)

type OpGprDbg () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    if Operands.modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseMemOrReg modRM span phlp
      let opr2 = parseDebugReg (Operands.getReg modRM)
      TwoOperands (opr1, opr2)

type OpRMMmx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 = parseMMXReg (Operands.getReg modRM)
    TwoOperands (opr1, opr2)

type OpMmMmx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      if Operands.modIsReg modRM then parseMMXReg (Operands.getRM modRM)
      else parseMemory modRM span phlp
    let opr2 = parseMMXReg (Operands.getReg modRM)
    TwoOperands (opr1, opr2)

type OpBmBnd () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      if Operands.modIsReg modRM then parseBoundRegister (Operands.getRM modRM)
      else parseMemory modRM span phlp
    let opr2 = parseBoundRegister (Operands.getReg modRM)
    TwoOperands (opr1, opr2)

type OpRmBnd () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 = parseBoundRegister (Operands.getReg modRM)
    TwoOperands (opr1, opr2)

type OpGprRm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span phlp
    TwoOperands (opr1, opr2)

type OpGprM () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    if Operands.modIsMemory modRM then
      let opr1 =
        findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM)
        |> OprReg
      let opr2 = parseMemory modRM span phlp
      TwoOperands (opr1, opr2)
    else raise ParsingFailureException

type OpMGpr () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    if Operands.modIsMemory modRM then
      let opr1 = parseMemory modRM span phlp
      let opr2 =
        findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM)
        |> OprReg
      TwoOperands (opr1, opr2)
    else raise ParsingFailureException

type OpSegRm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseSegReg (Operands.getReg modRM)
    let opr2 = parseMemOrReg modRM span phlp
    TwoOperands (opr1, opr2)

type OpBndBm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseBoundRegister (Operands.getReg modRM)
    let opr2 =
      if Operands.modIsReg modRM then parseBoundRegister (Operands.getRM modRM)
      else parseMemory modRM span phlp
    TwoOperands (opr1, opr2)

type OpBndRm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseBoundRegister (Operands.getReg modRM)
    let opr2 = parseMemOrReg modRM span phlp
    TwoOperands (opr1, opr2)

type OpCtrlGpr () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    if Operands.modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseControlReg (Operands.getReg modRM)
      let opr2 = parseMemOrReg modRM span phlp
      TwoOperands (opr1, opr2)

type OpDbgGpr () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    if Operands.modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseDebugReg (Operands.getReg modRM)
      let opr2 = parseMemOrReg modRM span phlp
      TwoOperands (opr1, opr2)

type OpMmxRm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMMXReg (Operands.getReg modRM)
    let opr2 =
      if Operands.modIsReg modRM then parseMMXReg (Operands.getRM modRM)
      else parseMemory modRM span phlp
    TwoOperands (opr1, opr2)

type OpMmxMm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMMXReg (Operands.getReg modRM)
    let opr2 = parseMemOrReg modRM span phlp
    TwoOperands (opr1, opr2)

type OpMxMx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMMXReg (Operands.getReg modRM)
    let opr2 =
      if Operands.modIsMemory modRM then raise ParsingFailureException
      else parseMMXReg (Operands.getRM modRM)
    TwoOperands (opr1, opr2)

type OpGprRMm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 =
      if Operands.modIsReg modRM then parseMMXReg (Operands.getRM modRM)
      else parseMemOrReg modRM span phlp
    TwoOperands (opr1, opr2)

type OpRegImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpNoREX (int RegGrp.RG0) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpImm8Reg () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = parseOprImm span phlp 8<rt>
    let o2 = getOprFromRegGrpNoREX (int RegGrp.RG0) phlp
    TwoOperands (o1, o2)

type OpImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr = parseOprImm span phlp 8<rt>
    OneOperand opr

type OpImm16 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr = parseOprImm span phlp 16<rt>
    OneOperand opr

type OpRegImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpNoREX (int RegGrp.RG0) phlp
    let o2 = parseOprSImm span phlp (getImmZ phlp)
    TwoOperands (o1, o2)

type OpSImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr = parseOprSImm span phlp 8<rt>
    OneOperand opr

type OpImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr = parseOprSImm span phlp (getImmZ phlp)
    OneOperand opr

type OpEs () =
  inherit OperandParser ()
  override _.Render (_, _) =
    OneOperand (OprReg R.ES)

type OpCs () =
  inherit OperandParser ()
  override _.Render (_, _) =
    OneOperand (OprReg R.CS)

type OpSs () =
  inherit OperandParser ()
  override _.Render (_, _) =
    OneOperand (OprReg R.SS)

type OpDs () =
  inherit OperandParser ()
  override _.Render (_, _) =
    OneOperand (OprReg R.DS)

type OpFs () =
  inherit OperandParser ()
  override _.Render (_, _) =
    OneOperand (OprReg R.FS)

type OpGs () =
  inherit OperandParser ()
  override _.Render (_, _) =
    OneOperand (OprReg R.GS)

type OpALDx () =
  inherit OperandParser ()
  override _.Render (_, _) =
    TwoOperands (OprReg R.AL, OprReg R.DX)

type OpEaxDx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let reg = if Prefix.hasOprSz phlp.Prefixes then R.AX else R.EAX
    TwoOperands (OprReg reg, OprReg R.DX)

type OpDxEax () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let reg = if Prefix.hasOprSz phlp.Prefixes then R.AX else R.EAX
    TwoOperands (OprReg R.DX, OprReg reg)

type OpDxAL () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    TwoOperands (OprReg R.DX, OprReg R.AL)

type OpNo () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    NoOperand

type OpEax () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    OneOperand o

type OpEcx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG1)  phlp
    OneOperand o

type OpEdx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG2)  phlp
    OneOperand o

type OpEbx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG3)  phlp
    OneOperand o

type OpEsp () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG4)  phlp
    OneOperand o

type OpEbp () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG5)  phlp
    OneOperand o

type OpEsi () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG6)  phlp
    OneOperand o

type OpEdi () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG7)  phlp
    OneOperand o

type OpRax () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG0) phlp
    OneOperand o

type OpRcx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG1) phlp
    OneOperand o

type OpRdx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG2) phlp
    OneOperand o

type OpRbx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG3) phlp
    OneOperand o

type OpRsp () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG4) phlp
    OneOperand o

type OpRbp () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG5) phlp
    OneOperand o

type OpRsi () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG6) phlp
    OneOperand o

type OpRdi () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG7) phlp
    OneOperand o

type OpRaxRax () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 =
      getOprFromRegGrpREX (int RegGrp.RG0) phlp
    TwoOperands (o1, o2)

type OpRaxRcx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG1) phlp
    TwoOperands (o1, o2)

type OpRaxRdx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 =
      getOprFromRegGrpREX (int RegGrp.RG2) phlp
    TwoOperands (o1, o2)

type OpRaxRbx () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG3) phlp
    TwoOperands (o1, o2)

type OpRaxRsp () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG4) phlp
    TwoOperands (o1, o2)

type OpRaxRbp () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG5) phlp
    TwoOperands (o1, o2)

type OpRaxRsi () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG6) phlp
    TwoOperands (o1, o2)

type OpRaxRdi () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG7) phlp
    TwoOperands (o1, o2)

type OpGprRmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let o1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let o2 = parseMemOrReg modRM span phlp
    let opr3 = parseOprSImm span phlp 8<rt>
    ThreeOperands (o1, o2, opr3)

type OpGprRmImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let o1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let o2 = parseMemOrReg modRM span phlp
    let opr3 = parseOprSImm span phlp (getImmZ phlp)
    ThreeOperands (o1, o2, opr3)

type OpRel8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr = parseOprForRelJmp span phlp 8<rt>
    OneOperand opr

type OpRel () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr = parseOprForRelJmp span phlp (getImmZ phlp)
    OneOperand opr

type OpDir () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let addrSz = RegType.toByteWidth phlp.MemEffAddrSize
    let addrValue = parseUnsignedImm span phlp addrSz
    let selector = phlp.ReadInt16 span
    let absAddr = Absolute (selector, addrValue, RegType.fromByteWidth addrSz)
    let opr = OprDirAddr absAddr
    OneOperand opr

type OpRaxFar () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    let o2 = parseOprOnlyDisp span phlp
    TwoOperands (o1, o2)

type OpFarRax () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = parseOprOnlyDisp span phlp
    let o2 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  phlp
    TwoOperands (o1, o2)

type OpALImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG0) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpCLImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG1) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpDLImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG2) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpBLImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG3) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpAhImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG4) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpChImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG5) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpDhImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG6) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpBhImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG7) phlp
    let o2 = parseOprImm span phlp 8<rt>
    TwoOperands (o1, o2)

type OpRaxImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG0

type OpRcxImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG1

type OpRdxImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG2

type OpRbxImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG3

type OpRspImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG4

type OpRbpImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG5

type OpRsiImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG6

type OpRdiImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    opGprImm span phlp RegGrp.RG7

type OpImmImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let opr1 = parseOprImm span phlp 16<rt>
    let opr2 = parseOprImm span phlp 8<rt>
    TwoOperands (opr1, opr2)

type OpRmImm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 = parseOprSImm span phlp (getImmZ phlp)
    TwoOperands (opr1, opr2)

type OpRmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 = parseOprImm span phlp 8<rt>
    TwoOperands (opr1, opr2)

type OpRmSImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 = parseOprSImm span phlp 8<rt>
    TwoOperands (opr1, opr2)

type OpMmxImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      if Operands.modIsReg modRM then parseMMXReg (Operands.getRM modRM)
      else parseMemory modRM span phlp
    let opr2 = parseOprSImm span phlp 8<rt>
    TwoOperands (opr1, opr2)

type OpMem () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr = parseMemOrReg modRM span phlp
    OneOperand opr

type OpM1 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr = parseMemOrReg modRM span phlp
    TwoOperands (opr, OprImm (1L, phlp.OperationSize))

type OpRmCL () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr = parseMemOrReg modRM span phlp
    TwoOperands (opr, OprReg R.CL)

type OpXmmVvXm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr3 = parseMemOrReg modRM span phlp
    ThreeOperands (opr1, parseVVVVRegRC (Operands.modIsReg modRM) phlp, opr3)

type OpGprVvRm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseVEXtoGPR phlp
    let opr3 = parseMemOrReg modRM span phlp
    ThreeOperands (opr1, opr2, opr3)

type OpXmVvXmm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr3 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    ThreeOperands (opr1, parseVVVVReg phlp, opr3)

type OpGpr () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr =
      findRegRmAndSIBBase phlp.RegSize phlp.REXPrefix (Operands.getRM modRM)
      |> OprReg
    OneOperand opr

type OpRmXmmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpXmmRmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span phlp
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpMmxMmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMMXReg (Operands.getReg modRM)
    let opr2 =
      if Operands.modIsReg modRM then parseMMXReg (Operands.getRM modRM)
      else parseMemory modRM span phlp
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpMmxRmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMMXReg (Operands.getReg modRM)
    let opr2 = parseMemOrReg modRM span phlp
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpGprMmxImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 =
      if Operands.modIsReg modRM then parseMMXReg (Operands.getRM modRM)
      else parseMemory modRM span phlp
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpXmmVvXmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseVVVVReg phlp
    let opr3 = parseMemOrReg modRM span phlp
    let opr4 = parseOprImm span phlp 8<rt>
    FourOperands (opr1, opr2, opr3, opr4)

type OpXmmVvXmXmm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseVVVVReg phlp
    let opr3 = parseMemOrReg modRM span phlp
    let mask = if phlp.WordSize = WordSize.Bit32 then 0b0111uy else 0b1111uy
    let imm8 = (phlp.ReadUInt8 (span) >>> 4) &&& mask |> int (* imm8[7:4] *)
    let opr4 = findRegNoREX phlp.RegSize phlp.REXPrefix imm8 |> OprReg
    FourOperands (opr1, opr2, opr3, opr4)

type OpXmRegImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpGprRmVv () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span phlp
    let opr3 = parseVEXtoGPR phlp
    ThreeOperands (opr1, opr2, opr3)

type OpVvRmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr2 = parseMemOrReg modRM span phlp
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (parseVVVVReg phlp, opr2, opr3)

type OpRmGprCL () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr3 = Register.CL |> OprReg
    ThreeOperands (opr1, opr2, opr3)

type OpXmmXmXmm0 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span phlp
    ThreeOperands (opr1, opr2, OprReg R.XMM0)

type OpXmmXmVv () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span phlp
    ThreeOperands (opr1, opr2, parseVVVVReg phlp)

type OpVvRm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseVEXtoGPR phlp
    let opr2 = parseMemOrReg modRM span phlp
    TwoOperands (opr1, opr2)

type OpGprRmImm8Imm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 =
      if Operands.modIsMemory modRM then raise ParsingFailureException
      else parseMemOrReg modRM span phlp
    let opr3 = parseOprImm span phlp 8<rt>
    let opr4 = parseOprImm span phlp 8<rt>
    FourOperands (opr1, opr2, opr3, opr4)

type OpRmImm8Imm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      if Operands.modIsMemory modRM then raise ParsingFailureException
      else parseMemOrReg modRM span phlp
    let opr2 = parseOprImm span phlp 8<rt>
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpKnVvXm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseOpMaskReg (Operands.getReg modRM)
    let opr3 = parseMemOrReg modRM span phlp
    ThreeOperands (opr1, parseVVVVReg phlp, opr3)

type OpGprKn () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseOpMaskReg (Operands.getRM modRM)
    TwoOperands (opr1, opr2)

type OpKnVvXmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseOpMaskReg (Operands.getReg modRM)
    let opr2 = parseVVVVReg phlp
    let opr3 = parseMemOrReg modRM span phlp
    let opr4 = parseOprImm span phlp 8<rt>
    FourOperands (opr1, opr2, opr3, opr4)

type OpKnGpr () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseOpMaskReg (Operands.getReg modRM)
    let opr2 =
      findRegRmAndSIBBase phlp.RegSize phlp.REXPrefix (Operands.getRM modRM)
      |> OprReg
    TwoOperands (opr1, opr2)

type OpXmmVvXmmXm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 = parseVVVVReg phlp
    let mask = if phlp.WordSize = WordSize.Bit32 then 0b0111uy else 0b1111uy
    let opr4 = parseMemOrReg modRM span phlp
    let imm8 = (phlp.ReadUInt8 (span) >>> 4) &&& mask |> int (* imm8[7:4] *)
    let opr3 = findRegNoREX phlp.RegSize phlp.REXPrefix imm8 |> OprReg
    FourOperands (opr1, opr2, opr3, opr4)

type OpKnKm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseOpMaskReg (Operands.getReg modRM)
    let opr2 = if Operands.modIsMemory modRM then parseMemory modRM span phlp
               else parseOpMaskReg (Operands.getRM modRM)
    TwoOperands (opr1, opr2)

type OpMKn () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = if Operands.modIsMemory modRM then parseMemory modRM span phlp
               else raise ParsingFailureException
    let opr2 = parseOpMaskReg (Operands.getReg modRM)
    TwoOperands (opr1, opr2)

type OpKKn () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseOpMaskReg (Operands.getReg modRM)
    let opr2 = if Operands.modIsMemory modRM then raise ParsingFailureException
               else parseOpMaskReg (Operands.getRM modRM)
    TwoOperands (opr1, opr2)

type OpKnKmImm8 () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseOpMaskReg (Operands.getReg modRM)
    let opr2 = if Operands.modIsMemory modRM then raise ParsingFailureException
               else parseOpMaskReg (Operands.getRM modRM)
    let opr3 = parseOprImm span phlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type OpXmmVsXm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    let opr2 =
      match phlp.VEXInfo with
      | Some vInfo -> Register.xmm (int vInfo.VVVV) |> OprReg
      | None -> raise ParsingFailureException
    let opr3 = parseMemOrReg modRM span phlp
    ThreeOperands (opr1, opr2, opr3)

type OpXmVsXmm () =
  inherit OperandParser ()
  override _.Render (span, phlp) =
    let modRM = phlp.ReadByte span
    let opr1 = parseMemOrReg modRM span phlp
    let opr2 =
      match phlp.VEXInfo with
      | Some vInfo -> Register.xmm (int vInfo.VVVV) |> OprReg
      | None -> raise ParsingFailureException
    let opr3 =
      findRegRBits phlp.RegSize phlp.REXPrefix (Operands.getReg modRM) |> OprReg
    ThreeOperands (opr1, opr2, opr3)
