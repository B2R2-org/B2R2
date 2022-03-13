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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel.RegGroup
open B2R2.FrontEnd.BinLifter.Intel.Helper

/// Operand descriptor, which describes the shape of operands in an instruction.
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
  | GprRMm = 18
  | RegImm8 = 19
  | Imm8Reg = 20
  | Imm8 = 21
  | Imm16 = 22
  | RegImm = 23
  | SImm8 = 24
  | Imm = 25
  | Es = 26
  | Cs = 27
  | Ss = 28
  | Ds = 29
  | Fs = 30
  | Gs = 31
  | ALDx = 32
  | EaxDx = 33
  | DxEax = 34
  | DxAL = 35
  | No = 36
  | Eax = 37
  | Ecx = 38
  | Edx = 39
  | Ebx = 40
  | Esp = 41
  | Ebp = 42
  | Esi = 43
  | Edi = 44
  | Rax = 45
  | Rcx = 46
  | Rdx = 47
  | Rbx = 48
  | Rsp = 49
  | Rbp = 50
  | Rsi = 51
  | Rdi = 52
  | RaxRax = 53
  | RaxRcx = 54
  | RaxRdx = 55
  | RaxRbx = 56
  | RaxRsp = 57
  | RaxRbp = 58
  | RaxRsi = 59
  | RaxRdi = 60
  | GprRmImm8 = 61
  | GprRmImm = 62
  | Rel8 = 63
  | Rel = 64
  | Dir = 65
  | RaxFar = 66
  | FarRax = 67
  | ALImm8 = 68
  | CLImm8 = 69
  | DLImm8 = 70
  | BLImm8 = 71
  | AhImm8 = 72
  | ChImm8 = 73
  | DhImm8 = 74
  | BhImm8 = 75
  | RaxImm = 76
  | RcxImm = 77
  | RdxImm = 78
  | RbxImm = 79
  | RspImm = 80
  | RbpImm = 81
  | RsiImm = 82
  | RdiImm = 83
  | ImmImm = 84
  | RmImm = 85
  | RmImm8 = 86
  | MmxImm8 = 87
  | Mem = 88
  | M1 = 89
  | RmCL = 90
  | XmmVvXm = 91
  | GprVvRm = 92
  | XmVvXmm = 93
  | Gpr = 94
  | RmXmmImm8 = 95
  | XmmRmImm8 = 96
  | MmxMmImm8 = 97
  | MmxRmImm8 = 98
  | GprMmxImm8 = 99
  | XmmVvXmImm8 = 100
  | XmmVvXmXmm = 101
  | XmRegImm8 = 102
  | GprRmVv = 103
  | VvRmImm8 = 104
  | RmGprCL = 105
  | XmmXmXmm0 = 106
  | XmmXmVv = 107
  | VvRm = 108
  | GprRmImm8Imm8 = 109
  | RmImm8Imm8 = 110

module internal OperandParsingHelper =
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

  let inline getOprFromRegGrpNoREX rgrp (rhlp: ReadHelper) =
    findRegNoREX rhlp.RegSize rhlp.REXPrefix rgrp |> OprReg

  let inline getOprFromRegGrpREX rgrp (rhlp: ReadHelper) =
    findRegRmAndSIBBase rhlp.RegSize rhlp.REXPrefix rgrp |> OprReg

  let parseSignedImm span (rhlp: ReadHelper) = function
    | 1 -> rhlp.ReadInt8 span |> int64
    | 2 -> rhlp.ReadInt16 span |> int64
    | 4 -> rhlp.ReadInt32 span |> int64
    | 8 -> rhlp.ReadInt64 span
    | _ -> raise ParsingFailureException

  let parseUnsignedImm span (rhlp: ReadHelper) = function
    | 1 -> rhlp.ReadUInt8 span |> uint64
    | 2 -> rhlp.ReadUInt16 span |> uint64
    | 4 -> rhlp.ReadUInt32 span |> uint64
    | 8 -> rhlp.ReadUInt64 span
    | _ -> raise ParsingFailureException

  /// EVEX uses compressed displacement. See the manual Chap. 15 of Vol. 1.
  let compressDisp vInfo disp =
    match vInfo with
    | None -> disp
    | Some { VectorLength = 128<rt>; VEXType = t }
      when t &&& VEXType.EVEX = VEXType.EVEX -> disp * 16L
    | Some { VectorLength = 256<rt>; VEXType = t }
        when t &&& VEXType.EVEX = VEXType.EVEX -> disp * 32L
    | Some { VectorLength = 512<rt>; VEXType = t }
        when t &&& VEXType.EVEX = VEXType.EVEX -> disp * 64L
    | _ -> disp

  let parseOprMem span (rhlp: ReadHelper) b s dispSz =
    let memSz = rhlp.MemEffOprSize
    if dispSz = 0 then OprMem (b, s, None, memSz)
    else
#if LCACHE
      rhlp.MarkHashEnd ()
#endif
      let disp = parseSignedImm span rhlp dispSz
      let disp = compressDisp rhlp.VEXInfo disp
      OprMem (b, s, Some disp, memSz)

  let parseOprImm span (rhlp: ReadHelper) immSize =
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let imm = parseUnsignedImm span rhlp (RegType.toByteWidth immSize)
    OprImm (int64 imm, immSize)

  let parseOprSImm span (rhlp: ReadHelper) immSize =
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let imm = parseSignedImm span rhlp (RegType.toByteWidth immSize)
    OprImm (imm, immSize)

  /// The first 24 rows of Table 2-1. of the manual Vol. 2A.
  /// The index of this tbl is a number that is a concatenation of (mod) and
  /// (r/m) field of the ModR/M byte. Each element is a tuple of base register,
  /// scaled index register, and the size of the displacement.
  /// Table for scales (of SIB). This tbl is indexbed by the scale value of SIB.
  let parseMEM16 span rhlp modRM =
    let m = getMod modRM
    let rm = getRM modRM
    match (m <<< 3) ||| rm with (* Concatenation of mod and rm bit *)
    | 0 -> parseOprMem span rhlp (Some R.BX) (Some (R.SI, Scale.X1)) 0
    | 1 -> parseOprMem span rhlp (Some R.BX) (Some (R.DI, Scale.X1)) 0
    | 2 -> parseOprMem span rhlp (Some R.BP) (Some (R.SI, Scale.X1)) 0
    | 3 -> parseOprMem span rhlp (Some R.BP) (Some (R.DI, Scale.X1)) 0
    | 4 -> parseOprMem span rhlp (Some R.SI) None 0
    | 5 -> parseOprMem span rhlp (Some R.DI) None 0
    | 6 -> parseOprMem span rhlp None None 2
    | 7 -> parseOprMem span rhlp (Some R.BX) None 0
    (* Mod 01b *)
    | 8 -> parseOprMem span rhlp (Some R.BX) (Some (R.SI, Scale.X1)) 1
    | 9 -> parseOprMem span rhlp (Some R.BX) (Some (R.DI, Scale.X1)) 1
    | 10 -> parseOprMem span rhlp (Some R.BP) (Some (R.SI, Scale.X1)) 1
    | 11 -> parseOprMem span rhlp (Some R.BP) (Some (R.DI, Scale.X1)) 1
    | 12 -> parseOprMem span rhlp (Some R.SI) None 1
    | 13 -> parseOprMem span rhlp (Some R.DI) None 1
    | 14 -> parseOprMem span rhlp (Some R.BP) None 1
    | 15 -> parseOprMem span rhlp (Some R.BX) None 1
    (* Mod 10b *)
    | 16 -> parseOprMem span rhlp (Some R.BX) (Some (R.SI, Scale.X1)) 2
    | 17 -> parseOprMem span rhlp (Some R.BX) (Some (R.DI, Scale.X1)) 2
    | 18 -> parseOprMem span rhlp (Some R.BP) (Some (R.SI, Scale.X1)) 2
    | 19 -> parseOprMem span rhlp (Some R.BP) (Some (R.DI, Scale.X1)) 2
    | 20 -> parseOprMem span rhlp (Some R.SI) None 2
    | 21 -> parseOprMem span rhlp (Some R.DI) None 2
    | 22 -> parseOprMem span rhlp (Some R.BP) None 2
    | 23 -> parseOprMem span rhlp (Some R.BX) None 2
    | _ -> raise ParsingFailureException

  let inline hasREXX rexPref = rexPref &&& REXPrefix.REXX = REXPrefix.REXX

  let getScaledIndex s i (rhlp: ReadHelper) =
    let rexPref = rhlp.REXPrefix
    (* Handling a special case with REXX and SIB index = 0b100 (ESP) *)
    if i = 0b100 && (not <| hasREXX rexPref) then None
    else
      let r = findRegSIBIdx rhlp.MemEffAddrSize rexPref i
      Some (r, LanguagePrimitives.EnumOfValue<int, Scale> (1 <<< s))

  /// See Notes 1 of Table 2-3 of the manual Vol. 2A
  let getSIBBaseReg b (rhlp: ReadHelper) modVal =
    let rexPref = rhlp.REXPrefix
    if b = int RegGrp.RG5 && modVal = 0b00uy then None
    else Some (findRegRmAndSIBBase rhlp.MemEffAddrSize rexPref b)

  let inline private getSIB b =
    struct ((b >>> 6) &&& 0b11, (b >>> 3) &&& 0b111, b &&& 0b111)

  let parseSIB span (rhlp: ReadHelper) modVal =
    let struct (s, i, b) = rhlp.ReadByte span |> int |> getSIB
    let si = getScaledIndex s i rhlp
    let baseReg = getSIBBaseReg b rhlp modVal
    struct (si, baseReg, b)

  let baseRMReg (rhlp: ReadHelper) regGrp =
    findRegRmAndSIBBase rhlp.MemEffAddrSize rhlp.REXPrefix (int regGrp) |> Some

  let sibWithDisp span (rhlp: ReadHelper) b si dispSz oprSz =
    let vInfo = rhlp.VEXInfo
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let disp = parseSignedImm span rhlp dispSz
    let disp = compressDisp vInfo disp
    OprMem (b, si, Some disp, oprSz)

  let parseOprMemWithSIB span rhlp modVal dispSz =
    let struct (si, b, bgrp) = parseSIB span rhlp modVal
    let oprSize = rhlp.MemEffOprSize
    if dispSz > 0 then sibWithDisp span rhlp b si dispSz oprSize
    else
      if (modVal = 0b00000000uy || modVal = 0b10000000uy)
        && bgrp = int RegGrp.RG5 then
        sibWithDisp span rhlp b si 4 oprSize
      elif modVal = 0b01000000uy && bgrp = int RegGrp.RG5 then
        sibWithDisp span rhlp b si 1 oprSize
      else OprMem (b, si, None, oprSize)

  /// RIP-relative addressing (see Section 2.2.1.6. of Vol. 2A).
  let parseOprRIPRelativeMem span (rhlp: ReadHelper) disp =
    if rhlp.WordSize = WordSize.Bit64 then
      if hasAddrSz rhlp.Prefixes then
        parseOprMem span rhlp (Some R.EIP) None disp
      else parseOprMem span rhlp (Some R.RIP) None disp
    else parseOprMem span rhlp None None disp

  open type RegGrp

  /// The first 24 rows of Table 2-2. of the manual Vol. 2A.
  /// The index of this tbl is a number that is a concatenation of (mod) and
  /// (r/m) field of the ModR/M byte. Each element is a tuple of (MemLookupType,
  /// and the size of the displacement). If the first value of the tuple (register
  /// group) is None, it means we need to look up the SIB tbl (Table 2-3). If
  /// not, then it represents the reg group of the base reigster.
  let parseMEM32 span rhlp modRM =
    let modVal = modRM &&& 0b11000000uy
    match modVal >>> 3 ||| (modRM &&& 0b00000111uy) with
    (* Mod 00b *)
    | 0uy -> parseOprMem span rhlp (baseRMReg rhlp RG0) None 0
    | 1uy -> parseOprMem span rhlp (baseRMReg rhlp RG1) None 0
    | 2uy -> parseOprMem span rhlp (baseRMReg rhlp RG2) None 0
    | 3uy -> parseOprMem span rhlp (baseRMReg rhlp RG3) None 0
    | 4uy -> parseOprMemWithSIB span rhlp modVal 0
    | 5uy -> parseOprRIPRelativeMem span rhlp 4
    | 6uy -> parseOprMem span rhlp (baseRMReg rhlp RG6) None 0
    | 7uy -> parseOprMem span rhlp (baseRMReg rhlp RG7) None 0
    (* Mod 01b *)
    | 8uy -> parseOprMem span rhlp (baseRMReg rhlp RG0) None 1
    | 9uy -> parseOprMem span rhlp (baseRMReg rhlp RG1) None 1
    | 10uy -> parseOprMem span rhlp (baseRMReg rhlp RG2) None 1
    | 11uy -> parseOprMem span rhlp (baseRMReg rhlp RG3) None 1
    | 12uy -> parseOprMemWithSIB span rhlp modVal 1
    | 13uy -> parseOprMem span rhlp (baseRMReg rhlp RG5) None 1
    | 14uy -> parseOprMem span rhlp (baseRMReg rhlp RG6) None 1
    | 15uy -> parseOprMem span rhlp (baseRMReg rhlp RG7) None 1
    (* Mod 10b *)
    | 16uy -> parseOprMem span rhlp (baseRMReg rhlp RG0) None 4
    | 17uy -> parseOprMem span rhlp (baseRMReg rhlp RG1) None 4
    | 18uy -> parseOprMem span rhlp (baseRMReg rhlp RG2) None 4
    | 19uy -> parseOprMem span rhlp (baseRMReg rhlp RG3) None 4
    | 20uy -> parseOprMemWithSIB span rhlp modVal 4
    | 21uy -> parseOprMem span rhlp (baseRMReg rhlp RG5) None 4
    | 22uy -> parseOprMem span rhlp (baseRMReg rhlp RG6) None 4
    | 23uy -> parseOprMem span rhlp (baseRMReg rhlp RG7) None 4
    | _ -> raise ParsingFailureException

  let parseMemory modRM span (rhlp: ReadHelper) =
    if rhlp.MemEffAddrSize = 16<rt> then parseMEM16 span rhlp modRM
    else parseMEM32 span rhlp modRM

  let parseMemOrReg modRM span (rhlp: ReadHelper) =
    if modRM &&& 0b11000000uy = 0b11000000uy then
      findRegRmAndSIBBase rhlp.MemEffRegSize rhlp.REXPrefix (getRM modRM)
      |> OprReg
    else parseMemory modRM span rhlp

  let parseVVVVReg (rhlp: ReadHelper) =
    match rhlp.VEXInfo with
    | None -> raise ParsingFailureException
    | Some vInfo when vInfo.VectorLength = 512<rt> ->
      Register.zmm (int vInfo.VVVV) |> OprReg
    | Some vInfo when vInfo.VectorLength = 256<rt> ->
      Register.ymm (int vInfo.VVVV) |> OprReg
    | Some vInfo ->
      Register.xmm (int vInfo.VVVV) |> OprReg

  let parseVEXtoGPR (rhlp: ReadHelper) =
    match rhlp.VEXInfo with
    | None -> raise ParsingFailureException
    | Some vInfo ->
      let grp = (int vInfo.VVVV) &&& 0b111
      int (grpEAX rhlp.RegSize) + grp
      |> LanguagePrimitives.EnumOfValue<int, Register>
      |> OprReg

  let parseMMXReg n =
    Register.mm n |> OprReg

  let parseSegReg n =
    if n < 6 then Register.seg n |> OprReg
    else raise ParsingFailureException

  let parseBoundRegister n =
    Register.bound n |> OprReg

  let parseControlReg n =
    Register.control n |> OprReg

  let parseDebugReg n =
    Register.debug n |> OprReg

  let parseOprOnlyDisp span (rhlp: ReadHelper) =
    let dispSz = RegType.toByteWidth rhlp.MemEffAddrSize
    parseOprMem span rhlp None None dispSz

  let getImmZ (rhlp: ReadHelper) =
    if rhlp.MemEffOprSize = 64<rt> || rhlp.MemEffOprSize = 32<rt> then 32<rt>
    else rhlp.MemEffOprSize

  let opGprImm span rhlp regGrp =
    let o1 = getOprFromRegGrpREX (int regGrp) rhlp
    let o2 = parseOprSImm span rhlp rhlp.MemEffOprSize
    TwoOperands (o1, o2)

  let parseOprForRelJmp span (rhlp: ReadHelper) immSz =
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let immSz = RegType.toByteWidth immSz
    let offset = parseSignedImm span rhlp immSz
    let relOffset = offset + int64 (rhlp.ParsedLen ())
    OprDirAddr (Relative (relOffset))

open OperandParsingHelper

type internal OpRmGpr () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    TwoOperands (opr1, opr2)

type internal OpRmSeg () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = parseSegReg (getReg modRM)
    TwoOperands (opr1, opr2)

type internal OpGprCtrl () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    if modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseMemOrReg modRM span rhlp
      let opr2 = parseControlReg (getReg modRM)
      TwoOperands (opr1, opr2)

type internal OpGprDbg () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    if modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseMemOrReg modRM span rhlp
      let opr2 = parseDebugReg (getReg modRM)
      TwoOperands (opr1, opr2)

type internal OpRMMmx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = parseMMXReg (getReg modRM)
    TwoOperands (opr1, opr2)

type internal OpMmMmx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM span rhlp
    let opr2 = parseMMXReg (getReg modRM)
    TwoOperands (opr1, opr2)

type internal OpBmBnd () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      if modIsReg modRM then parseBoundRegister (getRM modRM)
      else parseMemory modRM span rhlp
    let opr2 = parseBoundRegister (getReg modRM)
    TwoOperands (opr1, opr2)

type internal OpRmBnd () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = parseBoundRegister (getReg modRM)
    TwoOperands (opr1, opr2)

type internal OpGprRm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpGprM () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    if modIsMemory modRM then
      let opr1 =
        findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
      let opr2 = parseMemory modRM span rhlp
      TwoOperands (opr1, opr2)
    else raise ParsingFailureException

type internal OpMGpr () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    if modIsMemory modRM then
      let opr1 = parseMemory modRM span rhlp
      let opr2 =
        findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
      TwoOperands (opr1, opr2)
    else raise ParsingFailureException

type internal OpSegRm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseSegReg (getReg modRM)
    let opr2 = parseMemOrReg modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpBndBm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseBoundRegister (getReg modRM)
    let opr2 =
      if modIsReg modRM then parseBoundRegister (getRM modRM)
      else parseMemory modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpBndRm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseBoundRegister (getReg modRM)
    let opr2 = parseMemOrReg modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpCtrlGpr () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    if modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseControlReg (getReg modRM)
      let opr2 = parseMemOrReg modRM span rhlp
      TwoOperands (opr1, opr2)

type internal OpDbgGpr () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    if modIsMemory modRM then raise ParsingFailureException
    else
      let opr1 = parseDebugReg (getReg modRM)
      let opr2 = parseMemOrReg modRM span rhlp
      TwoOperands (opr1, opr2)

type internal OpMmxRm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpMmxMm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 = parseMemOrReg modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpGprRMm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemOrReg modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpRegImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpNoREX (int RegGrp.RG0) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpImm8Reg () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = parseOprImm span rhlp 8<rt>
    let o2 = getOprFromRegGrpNoREX (int RegGrp.RG0) rhlp
    TwoOperands (o1, o2)

type internal OpImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr = parseOprImm span rhlp 8<rt>
    OneOperand opr

type internal OpImm16 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr = parseOprImm span rhlp 16<rt>
    OneOperand opr

type internal OpRegImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpNoREX (int RegGrp.RG0) rhlp
    let o2 = parseOprSImm span rhlp (getImmZ rhlp)
    TwoOperands (o1, o2)

type internal OpSImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr = parseOprSImm span rhlp 8<rt>
    OneOperand opr

type internal OpImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr = parseOprSImm span rhlp (getImmZ rhlp)
    OneOperand opr

type internal OpEs () =
  inherit OperandParser ()
  override __.Render (_, _) =
    OneOperand (OprReg R.ES)

type internal OpCs () =
  inherit OperandParser ()
  override __.Render (_, _) =
    OneOperand (OprReg R.CS)

type internal OpSs () =
  inherit OperandParser ()
  override __.Render (_, _) =
    OneOperand (OprReg R.SS)

type internal OpDs () =
  inherit OperandParser ()
  override __.Render (_, _) =
    OneOperand (OprReg R.DS)

type internal OpFs () =
  inherit OperandParser ()
  override __.Render (_, _) =
    OneOperand (OprReg R.FS)

type internal OpGs () =
  inherit OperandParser ()
  override __.Render (_, _) =
    OneOperand (OprReg R.GS)

type internal OpALDx () =
  inherit OperandParser ()
  override __.Render (_, _) =
    TwoOperands (OprReg R.AL, OprReg R.DX)

type internal OpEaxDx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let reg = if hasOprSz rhlp.Prefixes then R.AX else R.EAX
    TwoOperands (OprReg reg, OprReg R.DX)

type internal OpDxEax () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let reg = if hasOprSz rhlp.Prefixes then R.AX else R.EAX
    TwoOperands (OprReg R.DX, OprReg reg)

type internal OpDxAL () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    TwoOperands (OprReg R.DX, OprReg R.AL)

type internal OpNo () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    NoOperand

type internal OpEax () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    OneOperand o

type internal OpEcx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG1)  rhlp
    OneOperand o

type internal OpEdx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG2)  rhlp
    OneOperand o

type internal OpEbx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG3)  rhlp
    OneOperand o

type internal OpEsp () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG4)  rhlp
    OneOperand o

type internal OpEbp () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG5)  rhlp
    OneOperand o

type internal OpEsi () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG6)  rhlp
    OneOperand o

type internal OpEdi () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpNoREX (int RegGrp.RG7)  rhlp
    OneOperand o

type internal OpRax () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG0) rhlp
    OneOperand o

type internal OpRcx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG1) rhlp
    OneOperand o

type internal OpRdx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG2) rhlp
    OneOperand o

type internal OpRbx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG3) rhlp
    OneOperand o

type internal OpRsp () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG4) rhlp
    OneOperand o

type internal OpRbp () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG5) rhlp
    OneOperand o

type internal OpRsi () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG6) rhlp
    OneOperand o

type internal OpRdi () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o = getOprFromRegGrpREX (int RegGrp.RG7) rhlp
    OneOperand o

type internal OpRaxRax () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 =
      getOprFromRegGrpREX (int RegGrp.RG0) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRcx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG1) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRdx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 =
      getOprFromRegGrpREX (int RegGrp.RG2) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRbx () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG3) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRsp () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG4) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRbp () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG5) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRsi () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG6) rhlp
    TwoOperands (o1, o2)

type internal OpRaxRdi () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = getOprFromRegGrpREX (int RegGrp.RG7) rhlp
    TwoOperands (o1, o2)

type internal OpGprRmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let o1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let o2 = parseMemOrReg modRM span rhlp
    let opr3 = parseOprSImm span rhlp 8<rt>
    ThreeOperands (o1, o2, opr3)

type internal OpGprRmImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let o1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let o2 = parseMemOrReg modRM span rhlp
    let opr3 = parseOprSImm span rhlp (getImmZ rhlp)
    ThreeOperands (o1, o2, opr3)

type internal OpRel8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr = parseOprForRelJmp span rhlp 8<rt>
    OneOperand opr

type internal OpRel () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr = parseOprForRelJmp span rhlp (getImmZ rhlp)
    OneOperand opr

type internal OpDir () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let addrSz = RegType.toByteWidth rhlp.MemEffAddrSize
    let addrValue = parseUnsignedImm span rhlp addrSz
    let selector = rhlp.ReadInt16 span
    let absAddr = Absolute (selector, addrValue, RegType.fromByteWidth addrSz)
    let opr = OprDirAddr absAddr
    OneOperand opr

type internal OpRaxFar () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    let o2 = parseOprOnlyDisp span rhlp
    TwoOperands (o1, o2)

type internal OpFarRax () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = parseOprOnlyDisp span rhlp
    let o2 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp
    TwoOperands (o1, o2)

type internal OpALImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG0) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpCLImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG1) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpDLImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG2) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpBLImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG3) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpAhImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG4) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpChImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG5) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpDhImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG6) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpBhImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG7) rhlp
    let o2 = parseOprImm span rhlp 8<rt>
    TwoOperands (o1, o2)

type internal OpRaxImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG0

type internal OpRcxImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG1

type internal OpRdxImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG2

type internal OpRbxImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG3

type internal OpRspImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG4

type internal OpRbpImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG5

type internal OpRsiImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG6

type internal OpRdiImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    opGprImm span rhlp RegGrp.RG7

type internal OpImmImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let opr1 = parseOprImm span rhlp 16<rt>
    let opr2 = parseOprImm span rhlp 8<rt>
    TwoOperands (opr1, opr2)

type internal OpRmImm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = parseOprSImm span rhlp (getImmZ rhlp)
    TwoOperands (opr1, opr2)

type internal OpRmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = parseOprSImm span rhlp 8<rt>
    TwoOperands (opr1, opr2)

type internal OpMmxImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM span rhlp
    let opr2 = parseOprSImm span rhlp 8<rt>
    TwoOperands (opr1, opr2)

type internal OpMem () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr = parseMemOrReg modRM span rhlp
    OneOperand opr

type internal OpM1 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr = parseMemOrReg modRM span rhlp
    TwoOperands (opr, OprImm (1L, 0<rt>))

type internal OpRmCL () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr = parseMemOrReg modRM span rhlp
    TwoOperands (opr, OprReg R.CL)

type internal OpXmmVvXm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = parseMemOrReg modRM span rhlp
    let oprs = ThreeOperands (opr1, parseVVVVReg rhlp, opr3)
    oprs

type internal OpGprVvRm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseVEXtoGPR rhlp
    let opr3 = parseMemOrReg modRM span rhlp
    ThreeOperands (opr1, opr2, opr3)

type internal OpXmVvXmm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr3 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    ThreeOperands (opr1, parseVVVVReg rhlp, opr3)

type internal OpGpr () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr =
      findRegRmAndSIBBase rhlp.RegSize rhlp.REXPrefix (getRM modRM) |> OprReg
    OneOperand opr

type internal OpRmXmmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type internal OpXmmRmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span rhlp
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type internal OpMmxMmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM span rhlp
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type internal OpMmxRmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 = parseMemOrReg modRM span rhlp
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type internal OpGprMmxImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM span rhlp
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type internal OpXmmVvXmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseVVVVReg rhlp
    let opr3 = parseMemOrReg modRM span rhlp
    let opr4 = parseOprImm span rhlp 8<rt>
    FourOperands (opr1, opr2, opr3, opr4)

type internal OpXmmVvXmXmm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseVVVVReg rhlp
    let opr3 = parseMemOrReg modRM span rhlp
    let mask = if rhlp.WordSize = WordSize.Bit32 then 0b0111uy else 0b1111uy
    let imm8 = (rhlp.ReadUInt8 (span) >>> 4) &&& mask |> int (* imm8[7:4] *)
    let opr4 = findRegNoREX rhlp.RegSize rhlp.REXPrefix imm8 |> OprReg
    FourOperands (opr1, opr2, opr3, opr4)

type internal OpXmRegImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)

type internal OpGprRmVv () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span rhlp
    let opr3 = parseVEXtoGPR rhlp
    ThreeOperands (opr1, opr2, opr3)

type internal OpVvRmImm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr2 = parseMemOrReg modRM span rhlp
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (parseVVVVReg rhlp, opr2, opr3)

type internal OpRmGprCL () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseMemOrReg modRM span rhlp
    let opr2 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = Register.CL |> OprReg
    ThreeOperands (opr1, opr2, opr3)

type internal OpXmmXmXmm0 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span rhlp
    ThreeOperands (opr1, opr2, OprReg R.XMM0)

type internal OpXmmXmVv () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM span rhlp
    ThreeOperands (opr1, opr2, parseVVVVReg rhlp)

type internal OpVvRm () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 = parseVEXtoGPR rhlp
    let opr2 = parseMemOrReg modRM span rhlp
    TwoOperands (opr1, opr2)

type internal OpGprRmImm8Imm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      findRegRBits rhlp.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 =
      if modIsMemory modRM then raise ParsingFailureException
      else parseMemOrReg modRM span rhlp
    let opr3 = parseOprImm span rhlp 8<rt>
    let opr4 = parseOprImm span rhlp 8<rt>
    FourOperands (opr1, opr2, opr3, opr4)

type internal OpRmImm8Imm8 () =
  inherit OperandParser ()
  override __.Render (span, rhlp) =
    let modRM = rhlp.ReadByte span
    let opr1 =
      if modIsMemory modRM then raise ParsingFailureException
      else parseMemOrReg modRM span rhlp
    let opr2 = parseOprImm span rhlp 8<rt>
    let opr3 = parseOprImm span rhlp 8<rt>
    ThreeOperands (opr1, opr2, opr3)
