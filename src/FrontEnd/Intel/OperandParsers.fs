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

open System
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

/// The register of the given width at the given index. The general-purpose
/// widths come first, being asked for most; the vector registers go through
/// the helpers because 16 to 31 sit outside the 0 to 15 run.
let inline private regOfIndex sz (n: int) =
  match sz with
  | 32<rt> -> int R.EAX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 64<rt> -> int R.RAX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 8<rt> -> int R.AL + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 16<rt> -> int R.AX + n |> LanguagePrimitives.EnumOfValue<int, Register>
  | 128<rt> -> RegisterHelper.xmm n
  | 256<rt> -> RegisterHelper.ymm n
  | 512<rt> -> RegisterHelper.zmm n
  | _ -> raise ParsingFailureException

/// Find a specific reg. The bitmask will be used to extract a specific REX
/// bit (R/X/B). The index is settled first and mapped to a register once:
/// mapping it on every branch had the compiler split the match into
/// continuation methods, and a call for every register read.
let inline private findReg sz rex bitmask (n: int) =
  let n =
    if rex = REXPrefix.NOREX then n
    elif (int rex &&& bitmask) > 0 then n + 8
    elif sz > 8<rt> || ((n &&& 4) = 0) then n
    (* SPL/BPL/SIL/DIL displace AH/CH/DH/BH once a REX byte is present. *)
    else n + 12
  regOfIndex sz n

/// Registers defined by the SIB index field.
let findRegSIBIdx sz rex (n: int) = findReg sz rex 2 n

/// Registers defined by the SIB base field, or base registers defined by the
/// RM field (first three rows of Table 2-2), or registers defined by REG bit
/// of the opcode, which can change the symbol by REX bits.
let findRegRmAndSIBBase sz rex (n: int) = findReg sz rex 1 n

/// Registers defined by REG field of the ModR/M byte.
let findRegRBits sz rex (n: int): Register = findReg sz rex 4 n

/// The register an /is4 operand names. Its four bits of imm8 already reach
/// every register the mode has, so nothing in the REX or VEX prefix extends
/// them; a 32-bit mode ignores the top one instead of adding to it.
let findRegIS4 wordSize sz (n: int) =
  if wordSize = WordSize.Bit32 then regOfIndex sz (n &&& 0b0111)
  else regOfIndex sz n

/// Registers defined by REG bit of the opcode: some instructions such as PUSH
/// make use of its opcode to represent the REG bit. REX bits *cannot* change
/// the symbol.
let findRegNoREX sz rex (n: int): Register =
  let n =
    if rex = REXPrefix.NOREX then n
    elif sz > 8<rt> || ((n &&& 4) = 0) then n
    else n + 12
  regOfIndex sz n

let inline getOprFromRegGrpNoREX rgrp (phlp: ParsingHelper) =
  findRegNoREX phlp.RegSize phlp.REXPrefix rgrp |> Operands.oprReg

let inline getOprFromRegGrpREX rgrp (phlp: ParsingHelper) =
  findRegRmAndSIBBase phlp.RegSize phlp.REXPrefix rgrp |> Operands.oprReg

/// Some r for every register, made once. A memory operand names its base
/// register through an option, and a fresh one for every operand was a heap
/// allocation for a value that never changes.
let private someRegs =
  let regs = Enum.GetValues typeof<Register> :?> Register[]
  Array.init ((regs |> Array.map int |> Array.max) + 1) (fun i ->
    Some(LanguagePrimitives.EnumOfValue<int, Register> i))

let inline private someReg (r: Register) = someRegs[int r]

/// Some (r, scale) for every register and scale, made once for the same
/// reason. Indexed by the two-bit SIB.scale field, then by the register.
let private someScaledIndexes =
  Array.init 4 (fun s ->
    someRegs
    |> Array.mapi (fun i _ ->
      let r: Register = LanguagePrimitives.EnumOfValue i
      Some(r, LanguagePrimitives.EnumOfValue<int, Scale>(1 <<< s))))

let inline private someScaledIndex (r: Register) s = someScaledIndexes[s][int r]

/// Some d for every displacement a byte can hold, made once. Most memory
/// operands carry one, and a fresh option per operand was an allocation for
/// one of 256 values.
let private someDisp8 = Array.init 256 (fun i -> Some(int64 (i - 128)))

let inline private someDisp (d: int64) =
  if d >= -128L && d <= 127L then someDisp8[int d + 128] else Some d

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

/// The width of one element an embedded broadcast reads. The operand knows it
/// (an FP16 element is 16 bits either way), and REX.W is only the fallback for
/// operands that did not declare one.
let broadcastElemSize (phlp: ParsingHelper) =
  if phlp.BroadcastSize <> 0<rt> then phlp.BroadcastSize
  elif phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW then 64<rt>
  else 32<rt>

/// EVEX uses compressed displacement. See the manual Chap. 15 of Vol. 1.
let uncompressedDisp (phlp: ParsingHelper) disp =
  let vInfo = phlp.VEXInfo.Value
  let evex = vInfo.EVEXPrx.Value
  let tt = phlp.TupleType
  let b = evex.B = 1uy
  let w = phlp.REXPrefix &&& REXPrefix.REXW = REXPrefix.REXW
  let inputSz = broadcastElemSize phlp
  let memSz = phlp.MemEffOprSize
  let vl = vInfo.VectorLength
  match tt, b, inputSz, w with
  (* Table 2-34. Compressed Displacement (DISP8*N) Affected by Embedded
     Broadcast. *)
  (* Without broadcast N follows the vector length, with it N is one element
     wide, so neither case needs to consult REX.W. *)
  | TupleType.Full, false, _, _ ->
    disp * (int64 vl / 8L), memSz
  | TupleType.Full, true, _, _ ->
    disp * (int64 inputSz / 8L), inputSz
  | TupleType.Half, false, _, _ ->
    disp * (int64 vl / 16L), memSz
  | TupleType.Half, true, _, _ ->
    disp * (int64 inputSz / 8L), inputSz
  (* Table 2-35. EVEX DISP8*N for Instructions Not Affected by Embedded
     Broadcast. *)
  | TupleType.FullMem, false, _, _ ->
    disp * (int64 vl / 8L), memSz
  (* N is the width of the scalar element. A byte or word one says so in memSz
     and cannot be read off REX.W, which those forms leave ignored; the wider
     two have to come from REX.W instead, because a VSIB operand reports the
     whole vector in memSz rather than its element. *)
  | TupleType.Tuple1Scalar, false, _, _ when memSz <= 16<rt> ->
    disp * (int64 memSz / 8L), memSz
  | TupleType.Tuple1Scalar, false, 32<rt>, false ->
    disp * 4L, memSz
  | TupleType.Tuple1Scalar, false, 64<rt>, true ->
    disp * 8L, memSz
  | TupleType.Tuple1Fixed, false, _, _ ->
    disp * (int64 memSz / 8L), memSz
  | TupleType.Tuple2, false, 32<rt>, false ->
    disp * 8L, memSz
  | TupleType.Tuple2, false, 64<rt>, true when vl <> 128<rt> ->
    disp * 16L, memSz
  | TupleType.Tuple4, false, 32<rt>, false when vl <> 128<rt> ->
    disp * 16L, memSz
  | TupleType.Tuple4, false, 64<rt>, true when vl = 512<rt> ->
    disp * 32L, memSz
  | TupleType.Tuple8, false, 32<rt>, false when vl = 512<rt> ->
    disp * 32L, memSz
  | TupleType.HalfMem, false, _, _ ->
    disp * (int64 vl / 16L), memSz
  | TupleType.QuarterMem, false, _, _ ->
    disp * (int64 vl / 32L), memSz
  | TupleType.EighthMem, false, _, _ ->
    disp * (int64 vl / 64L), memSz
  | TupleType.Mem128, false, _, _ ->
    disp * 16L, memSz
  | TupleType.MOVDDUP, false, _, _ when vl = 128<rt> ->
    disp * 8L, memSz
  | TupleType.MOVDDUP, false, _, _ ->
    disp * (int64 vl / 8L), memSz
  | TupleType.Tuple1_4X, false, _, _ ->
    disp * 16L, memSz
  (* AVX512-FP16 tuple types, whose element is 2 bytes wide. *)
  | TupleType.Scalar, _, _, _ ->
    disp * (int64 memSz / 8L), memSz
  | TupleType.Quarter, false, _, _ ->
    disp * (int64 vl / 32L), memSz
  | TupleType.Quarter, true, _, _ ->
    disp * (int64 inputSz / 8L), inputSz
  | _ (* TupleType.NA *) ->
    disp, memSz

let inline private isEVEX (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | Some vInfo -> vInfo.VEXType &&& VEXType.EVEX = VEXType.EVEX
  | _ -> false

let parseOprMem span (phlp: ParsingHelper) b s dispSz =
  let memSz = phlp.MemEffOprSize
#if LCACHE
    phlp.MarkHashEnd()
#endif
  if isEVEX phlp then
    let isBcst = phlp.VEXInfo.Value.EVEXPrx.Value.B = 1uy
    match dispSz, isBcst with
    | 0, false ->
      OprMem(b, s, None, memSz)
    | 0, true ->
      let memSz = broadcastElemSize phlp
      OprMem(b, s, None, memSz)
    | 1, _ ->
      let disp = parseSignedImm span phlp dispSz
      let disp, memSz = uncompressedDisp phlp disp
      OprMem(b, s, someDisp disp, memSz)
    | 4, true ->
      let disp = parseSignedImm span phlp dispSz
      let memSz = broadcastElemSize phlp
      OprMem(b, s, someDisp disp, memSz)
    | _, _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem(b, s, someDisp disp, memSz)
  else
    match dispSz with
    | 0 ->
      OprMem(b, s, None, memSz)
    | _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem(b, s, someDisp disp, memSz)

let parseOprImm span (phlp: ParsingHelper) immSize =
#if LCACHE
  phlp.MarkHashEnd()
#endif
  let imm = parseUnsignedImm span phlp (RegType.toByteWidth immSize)
  OprImm(int64 imm, immSize)

let parseOprSImm span (phlp: ParsingHelper) immSize =
#if LCACHE
  phlp.MarkHashEnd()
#endif
  let imm = parseSignedImm span phlp (RegType.toByteWidth immSize)
  OprImm(imm, immSize)

/// The first 24 rows of Table 2-1. of the manual Vol. 2A.
/// The index of this tbl is a number that is a concatenation of (mod) and
/// (r/m) field of the ModR/M byte. Each element is a tuple of base register,
/// scaled index register, and the size of the displacement.
/// Table for scales (of SIB). This tbl is indexbed by the scale value of SIB.
let parseMEM16 span phlp modRM =
  let m = Operands.getMod modRM
  let rm = Operands.getRM modRM
  let bx, bp, si, di = someReg R.BX, someReg R.BP, someReg R.SI, someReg R.DI
  let si1, di1 = someScaledIndex R.SI 0, someScaledIndex R.DI 0
  match (m <<< 3) ||| rm with (* Concatenation of mod and rm bit *)
  | 0 -> parseOprMem span phlp bx si1 0
  | 1 -> parseOprMem span phlp bx di1 0
  | 2 -> parseOprMem span phlp bp si1 0
  | 3 -> parseOprMem span phlp bp di1 0
  | 4 -> parseOprMem span phlp si None 0
  | 5 -> parseOprMem span phlp di None 0
  | 6 -> parseOprMem span phlp None None 2
  | 7 -> parseOprMem span phlp bx None 0
  (* Mod 01b *)
  | 8 -> parseOprMem span phlp bx si1 1
  | 9 -> parseOprMem span phlp bx di1 1
  | 10 -> parseOprMem span phlp bp si1 1
  | 11 -> parseOprMem span phlp bp di1 1
  | 12 -> parseOprMem span phlp si None 1
  | 13 -> parseOprMem span phlp di None 1
  | 14 -> parseOprMem span phlp bp None 1
  | 15 -> parseOprMem span phlp bx None 1
  (* Mod 10b *)
  | 16 -> parseOprMem span phlp bx si1 2
  | 17 -> parseOprMem span phlp bx di1 2
  | 18 -> parseOprMem span phlp bp si1 2
  | 19 -> parseOprMem span phlp bp di1 2
  | 20 -> parseOprMem span phlp si None 2
  | 21 -> parseOprMem span phlp di None 2
  | 22 -> parseOprMem span phlp bp None 2
  | 23 -> parseOprMem span phlp bx None 2
  | _ -> raise ParsingFailureException

let inline hasREXX rexPref = rexPref &&& REXPrefix.REXX = REXPrefix.REXX

let getScaledIndex s i (phlp: ParsingHelper) =
  let rexPref = phlp.REXPrefix
  (* Handling a special case with REXX and SIB index = 0b100 (ESP) *)
  if i = 0b100 && (not <| hasREXX rexPref) then
    None
  else
    someScaledIndex (findRegSIBIdx phlp.MemEffAddrSize rexPref i) s

/// See Notes 1 of Table 2-3 of the manual Vol. 2A
let getSIBBaseReg b (phlp: ParsingHelper) modVal =
  let rexPref = phlp.REXPrefix
  if b = int RegGrp.RG5 && modVal = 0b00uy then None
  else someReg (findRegRmAndSIBBase phlp.MemEffAddrSize rexPref b)

let inline private getSIB b =
  struct ((b >>> 6) &&& 0b11, (b >>> 3) &&& 0b111, b &&& 0b111)

let parseSIB span (phlp: ParsingHelper) modVal =
  let struct (s, i, b) = phlp.ReadByte span |> int |> getSIB
  let si = getScaledIndex s i phlp
  let baseReg = getSIBBaseReg b phlp modVal
  struct (si, baseReg, b)

let baseRMReg (phlp: ParsingHelper) regGrp =
  findRegRmAndSIBBase phlp.MemEffAddrSize phlp.REXPrefix (int regGrp)
  |> someReg

let sibWithDisp span (phlp: ParsingHelper) b s dispSz memSz =
#if LCACHE
  phlp.MarkHashEnd()
#endif
  if isEVEX phlp then
    let isBcst = phlp.VEXInfo.Value.EVEXPrx.Value.B = 1uy
    match dispSz, isBcst with
    | 0, false ->
      OprMem(b, s, None, memSz)
    | 0, true ->
      let memSz = broadcastElemSize phlp
      OprMem(b, s, None, memSz)
    | 1, _ ->
      let disp = parseSignedImm span phlp dispSz
      let disp, memSz = uncompressedDisp phlp disp
      OprMem(b, s, someDisp disp, memSz)
    | 4, true ->
      let disp = parseSignedImm span phlp dispSz
      let memSz = broadcastElemSize phlp
      OprMem(b, s, someDisp disp, memSz)
    | _, _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem(b, s, someDisp disp, memSz)
  else
    match dispSz with
    | 0 ->
      OprMem(b, s, None, memSz)
    | _ ->
      let disp = parseSignedImm span phlp dispSz
      OprMem(b, s, someDisp disp, memSz)

let parseOprMemWithSIB span phlp modVal dispSz =
  let struct (si, b, bgrp) = parseSIB span phlp modVal
  let oprSize = phlp.MemEffOprSize
  if dispSz > 0 then
    sibWithDisp span phlp b si dispSz oprSize
  else
    let dispSz =
      if (modVal = 0b00000000uy || modVal = 0b10000000uy)
        && bgrp = int RegGrp.RG5 then 4
      elif modVal = 0b01000000uy && bgrp = int RegGrp.RG5 then 1
      else 0
    sibWithDisp span phlp b si dispSz oprSize

/// Unlike a GPR SIB index, every SIB.index value denotes a real vector
/// register in VSIB addressing (there is no "index=100 means no index"
/// exception for ESP), so the index operand is always present.
let getScaledIndexVSIB s i vl (phlp: ParsingHelper) =
  let i = i + REXPrefix.highBit (REXPrefix.hasEVEXV phlp.REXPrefix)
  someScaledIndex (findRegSIBIdx vl phlp.REXPrefix i) s

let parseSIBForVSIB span (phlp: ParsingHelper) modVal vl =
  let struct (s, i, b) = phlp.ReadByte span |> int |> getSIB
  let si = getScaledIndexVSIB s i vl phlp
  let baseReg = getSIBBaseReg b phlp modVal
  struct (si, baseReg, b)

/// VSIB addressing always requires a SIB byte (ModRM.rm = 100b) with no
/// non-SIB memory form, so this does not need the mod/rm dispatch table
/// that parseMEM32 uses for general memory operands.
let parseOprMemVSIB span (phlp: ParsingHelper) modVal vl =
  let struct (si, b, bgrp) = parseSIBForVSIB span phlp modVal vl
  let oprSize = phlp.MemEffOprSize
  let dispSz =
    match modVal with
    | 0b00000000uy -> if bgrp = int RegGrp.RG5 then 4 else 0
    | 0b01000000uy -> 1
    | 0b10000000uy -> 4
    | _ -> raise ParsingFailureException
  sibWithDisp span phlp b si dispSz oprSize

/// RIP-relative addressing (see Section 2.2.1.6. of Vol. 2A).
let parseOprRIPRelativeMem span (phlp: ParsingHelper) disp =
  if phlp.WordSize = WordSize.Bit64 then
    if Prefix.hasAddrSz phlp.Prefixes then
      parseOprMem span phlp (someReg R.EIP) None disp
    else
      parseOprMem span phlp (someReg R.RIP) None disp
  else
    parseOprMem span phlp None None disp

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

/// The ModRM.reg register, widened by EVEX.R' where the prefix carries one.
let findRegReg sz modRM (phlp: ParsingHelper) =
  let hi = REXPrefix.highBit (REXPrefix.hasEVEXR phlp.REXPrefix)
  findRegRBits sz phlp.REXPrefix (Operands.getReg modRM + hi)

/// The ModRM.rm register. In a register form EVEX spends X on the fifth bit
/// of rm; in a memory form the same bit extends the SIB index instead.
let findRegRM modRM (phlp: ParsingHelper) =
  let hi =
    REXPrefix.highBit (isEVEX phlp && REXPrefix.hasX phlp.REXPrefix)
  findRegRmAndSIBBase
    phlp.MemEffRegSize
    phlp.REXPrefix
    (Operands.getRM modRM + hi)

let parseMemOrReg modRM span (phlp: ParsingHelper) =
  if modRM &&& 0b11000000uy = 0b11000000uy then
    findRegRM modRM phlp |> Operands.oprReg
  else
    parseMemory modRM span phlp

/// Sized by phlp.RegSize (set by the caller from the operand's declared
/// size) rather than the instruction's nominal VectorLength: they differ
/// for the VSIB gather/scatter forms whose mask register is narrower than
/// VectorLength (e.g. VGATHERQPS/VPGATHERQD, Q-index + 32-bit data).
let parseVVVVReg (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | None ->
    raise ParsingFailureException
  | Some vInfo ->
    let n =
      int vInfo.VVVV
      + REXPrefix.highBit (REXPrefix.hasEVEXV phlp.REXPrefix)
    match phlp.RegSize with
    | 512<rt> -> RegisterHelper.zmm n |> Operands.oprReg
    | 256<rt> -> RegisterHelper.ymm n |> Operands.oprReg
    | _ -> RegisterHelper.xmm n |> Operands.oprReg

/// FIXME
let parseVVVVRegRC isReg (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | None ->
    raise ParsingFailureException
  | Some vInfo ->
    match vInfo.EVEXPrx with
    | Some evex when evex.B = 1uy && isReg ->
      RegisterHelper.zmm (int vInfo.VVVV) |> Operands.oprReg
    | _ ->
      match vInfo.VectorLength with
      | 512<rt> -> RegisterHelper.zmm (int vInfo.VVVV) |> Operands.oprReg
      | 256<rt> -> RegisterHelper.ymm (int vInfo.VVVV) |> Operands.oprReg
      | 128<rt> -> RegisterHelper.xmm (int vInfo.VVVV) |> Operands.oprReg
      | _ -> raise ParsingFailureException

let parseVEXtoGPR (phlp: ParsingHelper) =
  match phlp.VEXInfo with
  | None ->
    raise ParsingFailureException
  | Some vInfo ->
    let grp = (int vInfo.VVVV) &&& 0b1111
    int (grpEAX phlp.RegSize) + grp
    |> LanguagePrimitives.EnumOfValue<int, Register>
    |> Operands.oprReg

let parseMMXReg n = RegisterHelper.mm n |> Operands.oprReg

let parseSegReg n =
  if n < 6 then RegisterHelper.seg n |> Operands.oprReg
  else raise ParsingFailureException

let parseBoundRegister n =
  if n < 4 then RegisterHelper.bound n |> Operands.oprReg
  else raise ParsingFailureException

/// The index a control or debug register move selects its register with: the
/// ModRM.reg field, which REX.R extends so that CR8 becomes reachable.
let sysRegIndex modRM (rex: REXPrefix) =
  let n = Operands.getReg modRM
  if (int rex &&& 0b100) > 0 then n + 8 else n

/// The control register of the given index. Every index left out here is one
/// the manual reserves - CR1, CR5 to CR7, and CR9 upwards - and a processor
/// raises #UD rather than selecting a register for it.
let parseControlReg n =
  match n with
  | 0 -> Operands.oprReg R.CR0
  | 2 -> Operands.oprReg R.CR2
  | 3 -> Operands.oprReg R.CR3
  | 4 -> Operands.oprReg R.CR4
  | 8 -> Operands.oprReg R.CR8
  | _ -> raise ParsingFailureException

/// The debug register of the given index. Indices 4 and 5 name DR4 and DR5,
/// which the processor aliases to DR6 and DR7 while CR4.DE is clear, so they
/// select the register those accesses land on rather than failing. Index 8
/// upwards, which only REX.R reaches, names nothing: a processor raises #UD.
let parseDebugReg n =
  match n with
  | 0 -> Operands.oprReg R.DR0
  | 1 -> Operands.oprReg R.DR1
  | 2 -> Operands.oprReg R.DR2
  | 3 -> Operands.oprReg R.DR3
  | 4 | 6 -> Operands.oprReg R.DR6
  | 5 | 7 -> Operands.oprReg R.DR7
  | _ -> raise ParsingFailureException

let parseOpMaskReg n = RegisterHelper.opmask n |> Operands.oprReg

let parseOprOnlyDisp span (phlp: ParsingHelper) =
  let dispSz = RegType.toByteWidth phlp.MemEffAddrSize
  parseOprMem span phlp None None dispSz

let getImmZ (phlp: ParsingHelper) =
  if phlp.MemEffOprSize = 64<rt> || phlp.MemEffOprSize = 32<rt> then 32<rt>
  else phlp.MemEffOprSize

let opGprImm span phlp regGrp =
  let o1 = getOprFromRegGrpREX (int regGrp) phlp
  let o2 = parseOprSImm span phlp phlp.MemEffOprSize
  TwoOperands(o1, o2)

let parseOprForRelJmp span (phlp: ParsingHelper) immSz =
#if LCACHE
  phlp.MarkHashEnd()
#endif
  let immSz = RegType.toByteWidth immSz
  let offset = parseSignedImm span phlp immSz
  let relOffset = offset + int64 (phlp.ParsedLen())
  OprDirAddr(Relative(relOffset))

