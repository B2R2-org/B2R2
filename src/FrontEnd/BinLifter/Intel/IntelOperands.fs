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
  | RmCtrl = 2
  | RmDbg = 3
  | RMMmx = 4
  | MmMmx = 5
  | BmBnd = 6
  | RmBnd = 7
  | GprRm = 8
  | GprM = 9
  | SegRm = 10
  | BndBm = 11
  | BndRm = 12
  | CtrlRm = 13
  | DbgRm = 14
  | MmxRm = 15
  | MmxMm = 16
  | GprRMm = 17
  | RegImm8 = 18
  | Imm8Reg = 19
  | Imm8 = 20
  | Imm16 = 21
  | RegImm = 22
  | SImm8 = 23
  | Imm = 24
  | Es = 25
  | Cs = 26
  | Ss = 27
  | Ds = 28
  | Fs = 29
  | Gs = 30
  | ALDx = 31
  | EaxDx = 32
  | DxEax = 33
  | DxAL = 34
  | No = 35
  | Eax = 36
  | Ecx = 37
  | Edx = 38
  | Ebx = 39
  | Esp = 40
  | Ebp = 41
  | Esi = 42
  | Edi = 43
  | Rax = 44
  | Rcx = 45
  | Rdx = 46
  | Rbx = 47
  | Rsp = 48
  | Rbp = 49
  | Rsi = 50
  | Rdi = 51
  | RaxRax = 52
  | RaxRcx = 53
  | RaxRdx = 54
  | RaxRbx = 55
  | RaxRsp = 56
  | RaxRbp = 57
  | RaxRsi = 58
  | RaxRdi = 59
  | GprRmImm8 = 60
  | GprRmImm = 61
  | Rel8 = 62
  | Rel = 63
  | Dir = 64
  | RaxFar = 65
  | FarRax = 66
  | ALImm8 = 67
  | CLImm8 = 68
  | DLImm8 = 69
  | BLImm8 = 70
  | AhImm8 = 71
  | ChImm8 = 72
  | DhImm8 = 73
  | BhImm8 = 74
  | RaxImm = 75
  | RcxImm = 76
  | RdxImm = 77
  | RbxImm = 78
  | RspImm = 79
  | RbpImm = 80
  | RsiImm = 81
  | RdiImm = 82
  | ImmImm = 83
  | RmImm = 84
  | RmImm8 = 85
  | MmxImm8 = 86
  | Mem = 87
  | M1 = 88
  | RmCL = 89
  | XmmVvXm = 90
  | GprVvRm = 91
  | XmVvXmm = 92
  | Gpr = 93
  | XmmRmImm8 = 94
  | MmxMmImm8 = 95
  | MmxRmImm8 = 96
  | GprMmxImm8 = 97
  | XmmVvXmImm8 = 98
  | XmRegImm8 = 99
  | GprRmVv = 100
  | VvRmImm8 = 101
  | RmGprCL = 102

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

  let inline getOprFromRegGrpNoREX rgrp (rhlp: ReadHelper) insSize =
    findRegNoREX insSize.RegSize rhlp.REXPrefix rgrp |> OprReg

  let inline getOprFromRegGrpREX rgrp (rhlp: ReadHelper) insSize =
    findRegRmAndSIBBase insSize.RegSize rhlp.REXPrefix rgrp |> OprReg

  let parseSignedImm (rhlp: ReadHelper) = function
    | 1 -> rhlp.ReadInt8 () |> int64
    | 2 -> rhlp.ReadInt16 () |> int64
    | 4 -> rhlp.ReadInt32 () |> int64
    | 8 -> rhlp.ReadInt64 ()
    | _ -> raise ParsingFailureException

  let parseUnsignedImm (rhlp: ReadHelper) = function
    | 1 -> rhlp.ReadUInt8 () |> uint64
    | 2 -> rhlp.ReadUInt16 () |> uint64
    | 4 -> rhlp.ReadUInt32 () |> uint64
    | 8 -> rhlp.ReadUInt64 ()
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

  let parseOprMem insSize (rhlp: ReadHelper) b s dispSz =
    let memSz = insSize.MemEffOprSize
    if dispSz = 0 then OprMem (b, s, None, memSz)
    else
#if LCACHE
      rhlp.MarkHashEnd ()
#endif
      let disp = parseSignedImm rhlp dispSz
      let disp = compressDisp rhlp.VEXInfo disp
      OprMem (b, s, Some disp, memSz)

  let parseOprImm (rhlp: ReadHelper) immSize =
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let imm = parseUnsignedImm rhlp (RegType.toByteWidth immSize)
    OprImm (int64 imm, immSize)

  let parseOprSImm (rhlp: ReadHelper) immSize =
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let imm = parseSignedImm rhlp (RegType.toByteWidth immSize)
    OprImm (imm, immSize)

  /// The first 24 rows of Table 2-1. of the manual Vol. 2A.
  /// The index of this tbl is a number that is a concatenation of (mod) and
  /// (r/m) field of the ModR/M byte. Each element is a tuple of base register,
  /// scaled index register, and the size of the displacement.
  /// Table for scales (of SIB). This tbl is indexbed by the scale value of SIB.
  let parseMEM16 insSize rhlp modRM =
    let m = getMod modRM
    let rm = getRM modRM
    match (m <<< 3) ||| rm with (* Concatenation of mod and rm bit *)
    | 0 -> parseOprMem insSize rhlp (Some R.BX) (Some (R.SI, Scale.X1)) 0
    | 1 -> parseOprMem insSize rhlp (Some R.BX) (Some (R.DI, Scale.X1)) 0
    | 2 -> parseOprMem insSize rhlp (Some R.BP) (Some (R.SI, Scale.X1)) 0
    | 3 -> parseOprMem insSize rhlp (Some R.BP) (Some (R.DI, Scale.X1)) 0
    | 4 -> parseOprMem insSize rhlp (Some R.SI) None 0
    | 5 -> parseOprMem insSize rhlp (Some R.DI) None 0
    | 6 -> parseOprMem insSize rhlp None None 2
    | 7 -> parseOprMem insSize rhlp (Some R.BX) None 0
    (* Mod 01b *)
    | 8 -> parseOprMem insSize rhlp (Some R.BX) (Some (R.SI, Scale.X1)) 1
    | 9 -> parseOprMem insSize rhlp (Some R.BX) (Some (R.DI, Scale.X1)) 1
    | 10 -> parseOprMem insSize rhlp (Some R.BP) (Some (R.SI, Scale.X1)) 1
    | 11 -> parseOprMem insSize rhlp (Some R.BP) (Some (R.DI, Scale.X1)) 1
    | 12 -> parseOprMem insSize rhlp (Some R.SI) None 1
    | 13 -> parseOprMem insSize rhlp (Some R.DI) None 1
    | 14 -> parseOprMem insSize rhlp (Some R.BP) None 1
    | 15 -> parseOprMem insSize rhlp (Some R.BX) None 1
    (* Mod 10b *)
    | 16 -> parseOprMem insSize rhlp (Some R.BX) (Some (R.SI, Scale.X1)) 2
    | 17 -> parseOprMem insSize rhlp (Some R.BX) (Some (R.DI, Scale.X1)) 2
    | 18 -> parseOprMem insSize rhlp (Some R.BP) (Some (R.SI, Scale.X1)) 2
    | 19 -> parseOprMem insSize rhlp (Some R.BP) (Some (R.DI, Scale.X1)) 2
    | 20 -> parseOprMem insSize rhlp (Some R.SI) None 2
    | 21 -> parseOprMem insSize rhlp (Some R.DI) None 2
    | 22 -> parseOprMem insSize rhlp (Some R.BP) None 2
    | 23 -> parseOprMem insSize rhlp (Some R.BX) None 2
    | _ -> raise ParsingFailureException

  let inline hasREXX rexPref = rexPref &&& REXPrefix.REXX = REXPrefix.REXX

  let getScaledIndex s i insSize (rexPref: REXPrefix) =
    (* Handling a special case with REXX and SIB index = 0b100 (ESP) *)
    if i = 0b100 && (not <| hasREXX rexPref) then None
    else
      let r = findRegSIBIdx insSize.MemEffAddrSize rexPref i
      Some (r, LanguagePrimitives.EnumOfValue<int, Scale> (1 <<< s))

  /// See Notes 1 of Table 2-3 of the manual Vol. 2A
  let getSIBBaseReg b insSize modVal rexPref =
    if b = int RegGrp.RG5 && modVal = 0b00uy then None
    else Some (findRegRmAndSIBBase insSize.MemEffAddrSize rexPref b)

  let inline private getSIB b =
    struct ((b >>> 6) &&& 0b11, (b >>> 3) &&& 0b111, b &&& 0b111)

  let parseSIB insSize (rhlp: ReadHelper) modVal =
    let struct (s, i, b) = rhlp.ReadByte () |> int |> getSIB
    let rexPref = rhlp.REXPrefix
    let si = getScaledIndex s i insSize rexPref
    let baseReg = getSIBBaseReg b insSize modVal rexPref
    struct (si, baseReg, b)

  let baseRMReg insSize (rhlp: ReadHelper) regGrp =
    let rexPref = rhlp.REXPrefix
    let regSz = insSize.MemEffAddrSize
    findRegRmAndSIBBase regSz rexPref (int regGrp) |> Some

  let sibWithDisp (rhlp: ReadHelper) b si dispSz oprSz =
    let vInfo = rhlp.VEXInfo
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let disp = parseSignedImm rhlp dispSz
    let disp = compressDisp vInfo disp
    OprMem (b, si, Some disp, oprSz)

  let parseOprMemWithSIB insSize rhlp oprSz modVal dispSz =
    let struct (si, b, bgrp) = parseSIB insSize rhlp modVal
    if dispSz > 0 then sibWithDisp rhlp b si dispSz oprSz
    else
      if (modVal = 0b00000000uy || modVal = 0b10000000uy)
        && bgrp = int RegGrp.RG5 then
        sibWithDisp rhlp b si 4 oprSz
      elif modVal = 0b01000000uy && bgrp = int RegGrp.RG5 then
        sibWithDisp rhlp b si 1 oprSz
      else OprMem (b, si, None, oprSz)

  /// RIP-relative addressing (see Section 2.2.1.6. of Vol. 2A).
  let parseOprRIPRelativeMem insSize (rhlp: ReadHelper) disp =
    if rhlp.WordSize = WordSize.Bit64 then
      if hasAddrSz rhlp.Prefixes then
        parseOprMem insSize rhlp (Some R.EIP) None disp
      else parseOprMem insSize rhlp (Some R.RIP) None disp
    else parseOprMem insSize rhlp None None disp

  open type RegGrp

  /// The first 24 rows of Table 2-2. of the manual Vol. 2A.
  /// The index of this tbl is a number that is a concatenation of (mod) and
  /// (r/m) field of the ModR/M byte. Each element is a tuple of (MemLookupType,
  /// and the size of the displacement). If the first value of the tuple (register
  /// group) is None, it means we need to look up the SIB tbl (Table 2-3). If
  /// not, then it represents the reg group of the base reigster.
  let parseMEM32 insSize rhlp osz modRM =
    let modVal = modRM &&& 0b11000000uy
    match modVal >>> 3 ||| (modRM &&& 0b00000111uy) with
    (* Mod 00b *)
    | 0uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG0) None 0
    | 1uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG1) None 0
    | 2uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG2) None 0
    | 3uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG3) None 0
    | 4uy -> parseOprMemWithSIB insSize rhlp osz modVal 0
    | 5uy -> parseOprRIPRelativeMem insSize rhlp 4
    | 6uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG6) None 0
    | 7uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG7) None 0
    (* Mod 01b *)
    | 8uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG0) None 1
    | 9uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG1) None 1
    | 10uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG2) None 1
    | 11uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG3) None 1
    | 12uy -> parseOprMemWithSIB insSize rhlp osz modVal 1
    | 13uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG5) None 1
    | 14uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG6) None 1
    | 15uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG7) None 1
    (* Mod 10b *)
    | 16uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG0) None 4
    | 17uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG1) None 4
    | 18uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG2) None 4
    | 19uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG3) None 4
    | 20uy -> parseOprMemWithSIB insSize rhlp osz modVal 4
    | 21uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG5) None 4
    | 22uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG6) None 4
    | 23uy -> parseOprMem insSize rhlp (baseRMReg insSize rhlp RG7) None 4
    | _ -> raise ParsingFailureException

  let parseMemory modRM insSize rhlp =
    if insSize.MemEffAddrSize = 16<rt> then parseMEM16 insSize rhlp modRM
    else parseMEM32 insSize rhlp insSize.MemEffOprSize modRM

  let parseMemOrReg modRM insSize (rhlp: ReadHelper) =
    if modRM &&& 0b11000000uy = 0b11000000uy then
      findRegRmAndSIBBase insSize.MemEffRegSize rhlp.REXPrefix (getRM modRM)
      |> OprReg
    else parseMemory modRM insSize rhlp

  let parseVVVVReg (rhlp: ReadHelper) =
    match rhlp.VEXInfo with
    | None -> raise ParsingFailureException
    | Some vInfo when vInfo.VectorLength = 512<rt> ->
      Register.make (int vInfo.VVVV) Register.Kind.ZMM 512 |> OprReg
    | Some vInfo when vInfo.VectorLength = 256<rt> ->
      Register.make (int vInfo.VVVV) Register.Kind.YMM 256 |> OprReg
    | Some vInfo ->
      Register.make (int vInfo.VVVV) Register.Kind.XMM 128 |> OprReg

  let parseVEXtoGPR (rhlp: ReadHelper) insSize =
    match rhlp.VEXInfo with
    | None -> raise ParsingFailureException
    | Some vInfo ->
      let grp = ~~~(int vInfo.VVVV) &&& 0b111
      int (grpEAX insSize.RegSize) + grp
      |> LanguagePrimitives.EnumOfValue<int, Register>
      |> OprReg

  let parseMMXReg n = Register.make n Register.Kind.MMX 64 |> OprReg

  let parseSegReg n = Register.make n Register.Kind.Segment 16 |> OprReg

  let parseBoundRegister n = Register.make n Register.Kind.Bound 128 |> OprReg

  let parseControlReg n = Register.make n Register.Kind.Control 32 |> OprReg

  let parseDebugReg n = Register.make n Register.Kind.Debug 0 |> OprReg

  let parseOprOnlyDisp rhlp insSize =
    RegType.toByteWidth insSize.MemEffAddrSize
    |> parseOprMem insSize rhlp None None

  let getImmZ insSize =
    if insSize.MemEffOprSize = 64<rt>
      || insSize.MemEffOprSize = 32<rt> then 32<rt>
    else insSize.MemEffOprSize

  let opGprImm rhlp insSize regGrp =
    let o1 = getOprFromRegGrpREX (int regGrp) rhlp insSize
    let o2 = parseOprSImm rhlp insSize.MemEffOprSize
    struct (TwoOperands (o1, o2), insSize)

  let parseOprForRelJmp (rhlp: ReadHelper) immSz =
#if LCACHE
    rhlp.MarkHashEnd ()
#endif
    let immSz = RegType.toByteWidth immSz
    let offset = parseSignedImm rhlp immSz
    let relOffset = offset + int64 (rhlp.ParsedLen ())
    OprDirAddr (Relative (relOffset))

open OperandParsingHelper

type internal OpRmGpr () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRmSeg () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseSegReg (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRmCtrl () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseControlReg (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRmDbg () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseDebugReg (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRMMmx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseMMXReg (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpMmMmx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM insSize rhlp
    let opr2 = parseMMXReg (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpBmBnd () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      if modIsReg modRM then parseBoundRegister (getRM modRM)
      else parseMemory modRM insSize rhlp
    let opr2 = parseBoundRegister (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRmBnd () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseBoundRegister (getReg modRM)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpGprRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpGprM () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    if modIsMemory modRM then
      let opr1 =
        findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
      let opr2 = parseMemory modRM insSize rhlp
      struct (TwoOperands (opr1, opr2), insSize)
    else raise ParsingFailureException

type internal OpSegRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseSegReg (getReg modRM)
    let opr2 = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpBndBm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseBoundRegister (getReg modRM)
    let opr2 =
      if modIsReg modRM then parseBoundRegister (getRM modRM)
      else parseMemory modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpBndRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseBoundRegister (getReg modRM)
    let opr2 = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpCtrlRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseControlReg (getReg modRM)
    let opr2 = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpDbgRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseDebugReg (getReg modRM)
    let opr2 = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpMmxRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpMmxMm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpGprRMm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRegImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpNoREX (int RegGrp.RG0) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpImm8Reg () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = parseOprImm rhlp 8<rt>
    let o2 = getOprFromRegGrpNoREX (int RegGrp.RG0) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr = parseOprImm rhlp 8<rt>
    struct (OneOperand opr, insSize)

type internal OpImm16 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr = parseOprImm rhlp 16<rt>
    struct (OneOperand opr, insSize)

type internal OpRegImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpNoREX (int RegGrp.RG0) rhlp insSize
    let o2 = parseOprSImm rhlp (getImmZ insSize)
    struct (TwoOperands (o1, o2), insSize)

type internal OpSImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr = parseOprSImm rhlp 8<rt>
    struct (OneOperand opr, insSize)

type internal OpImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr = parseOprSImm rhlp (getImmZ insSize)
    struct (OneOperand opr, insSize)

type internal OpEs () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (OneOperand (OprReg R.ES), insSize)

type internal OpCs () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (OneOperand (OprReg R.CS), insSize)

type internal OpSs () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (OneOperand (OprReg R.SS), insSize)

type internal OpDs () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (OneOperand (OprReg R.DS), insSize)

type internal OpFs () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (OneOperand (OprReg R.FS), insSize)

type internal OpGs () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (OneOperand (OprReg R.GS), insSize)

type internal OpALDx () =
  inherit OperandParser ()
  override __.Render _rhlp insSize =
    struct (TwoOperands (OprReg R.AL, OprReg R.DX), insSize)

type internal OpEaxDx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let reg = if hasOprSz rhlp.Prefixes then R.AX else R.EAX
    struct (TwoOperands (OprReg reg, OprReg R.DX), insSize)

type internal OpDxEax () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let reg = if hasOprSz rhlp.Prefixes then R.AX else R.EAX
    struct (TwoOperands (OprReg R.DX, OprReg reg), insSize)

type internal OpDxAL () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    struct (TwoOperands (OprReg R.DX, OprReg R.AL), insSize)

type internal OpNo () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    struct (NoOperand, insSize)

type internal OpEax () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEcx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG1)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEdx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG2)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEbx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG3)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEsp () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG4)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEbp () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG5)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEsi () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG6)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpEdi () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o =
      getOprFromRegGrpNoREX (int RegGrp.RG7)  rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRax () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG0) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRcx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG1) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRdx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG2) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRbx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG3) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRsp () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG4) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRbp () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG5) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRsi () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG6) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRdi () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o = getOprFromRegGrpREX (int RegGrp.RG7) rhlp insSize
    struct (OneOperand o, insSize)

type internal OpRaxRax () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 =
      getOprFromRegGrpREX (int RegGrp.RG0) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRcx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = getOprFromRegGrpREX (int RegGrp.RG1) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRdx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 =
      getOprFromRegGrpREX (int RegGrp.RG2) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRbx () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = getOprFromRegGrpREX (int RegGrp.RG3) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRsp () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = getOprFromRegGrpREX (int RegGrp.RG4) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRbp () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = getOprFromRegGrpREX (int RegGrp.RG5) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRsi () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = getOprFromRegGrpREX (int RegGrp.RG6) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxRdi () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = getOprFromRegGrpREX (int RegGrp.RG7) rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpGprRmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let o1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let o2 = parseMemOrReg modRM insSize rhlp
    let opr3 = parseOprSImm rhlp 8<rt>
    struct (ThreeOperands (o1, o2, opr3), insSize)

type internal OpGprRmImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let o1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let o2 = parseMemOrReg modRM insSize rhlp
    let opr3 = parseOprSImm rhlp (getImmZ insSize)
    struct (ThreeOperands (o1, o2, opr3), insSize)

type internal OpRel8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr = parseOprForRelJmp rhlp 8<rt>
    struct (OneOperand opr, insSize)

type internal OpRel () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr = parseOprForRelJmp rhlp (getImmZ insSize)
    struct (OneOperand opr, insSize)

type internal OpDir () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let addrSz = RegType.toByteWidth insSize.MemEffAddrSize
    let addrValue = parseUnsignedImm rhlp addrSz
    let selector = rhlp.ReadInt16 ()
    let absAddr = Absolute (selector, addrValue, RegType.fromByteWidth addrSz)
    let opr = OprDirAddr absAddr
    struct (OneOperand opr, insSize)

type internal OpRaxFar () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    let o2 = parseOprOnlyDisp rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpFarRax () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = parseOprOnlyDisp rhlp insSize
    let o2 =
      getOprFromRegGrpNoREX (int RegGrp.RG0)  rhlp insSize
    struct (TwoOperands (o1, o2), insSize)

type internal OpALImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG0) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpCLImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG1) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpDLImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG2) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpBLImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG3) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpAhImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG4) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpChImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG5) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpDhImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG6) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpBhImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let o1 = getOprFromRegGrpREX (int RegGrp.RG7) rhlp insSize
    let o2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (o1, o2), insSize)

type internal OpRaxImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG0

type internal OpRcxImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG1

type internal OpRdxImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG2

type internal OpRbxImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG3

type internal OpRspImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG4

type internal OpRbpImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG5

type internal OpRsiImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG6

type internal OpRdiImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    opGprImm rhlp insSize RegGrp.RG7

type internal OpImmImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let opr1 = parseOprImm rhlp 16<rt>
    let opr2 = parseOprImm rhlp 8<rt>
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRmImm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseOprSImm rhlp (getImmZ insSize)
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpRmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 = parseOprSImm rhlp 8<rt>
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpMmxImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM insSize rhlp
    let opr2 = parseOprSImm rhlp 8<rt>
    struct (TwoOperands (opr1, opr2), insSize)

type internal OpMem () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr = parseMemOrReg modRM insSize rhlp
    struct (OneOperand opr, insSize)

type internal OpM1 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr, OprImm (1L, 0<rt>)), insSize)

type internal OpRmCL () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr = parseMemOrReg modRM insSize rhlp
    struct (TwoOperands (opr, OprReg R.CL), insSize)

type internal OpXmmVvXm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = parseMemOrReg modRM insSize rhlp
    let oprs = ThreeOperands (opr1, parseVVVVReg rhlp, opr3)
    struct (oprs, insSize)

type internal OpGprVvRm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseVEXtoGPR rhlp insSize
    let opr3 = parseMemOrReg modRM insSize rhlp
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpXmVvXmm () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr3 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let oprs = ThreeOperands (opr1, parseVVVVReg rhlp, opr3)
    struct (oprs, insSize)

type internal OpGpr () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr =
      findRegRmAndSIBBase insSize.RegSize rhlp.REXPrefix (getRM modRM)
      |> OprReg
    struct (OneOperand opr, insSize)

type internal OpXmmRmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM insSize rhlp
    let opr3 = parseOprImm rhlp 8<rt>
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpMmxMmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM insSize rhlp
    let opr3 = parseOprImm rhlp 8<rt>
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpMmxRmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMMXReg (getReg modRM)
    let opr2 = parseMemOrReg modRM insSize rhlp
    let opr3 = parseOprImm rhlp 8<rt>
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpGprMmxImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 =
      if modIsReg modRM then parseMMXReg (getRM modRM)
      else parseMemory modRM insSize rhlp
    let opr3 = parseOprImm rhlp 8<rt>
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpXmmVvXmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseVVVVReg rhlp
    let opr3 = parseMemOrReg modRM insSize rhlp
    let opr4 = parseOprImm rhlp 8<rt>
    struct (FourOperands (opr1, opr2, opr3, opr4), insSize)

type internal OpXmRegImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = parseOprImm rhlp 8<rt>
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpGprRmVv () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr2 = parseMemOrReg modRM insSize rhlp
    let opr3 = parseVEXtoGPR rhlp insSize
    struct (ThreeOperands (opr1, opr2, opr3), insSize)

type internal OpVvRmImm8 () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr2 = parseMemOrReg modRM insSize rhlp
    let opr3 = parseOprImm rhlp 8<rt>
    let oprs = ThreeOperands (parseVVVVReg rhlp, opr2, opr3)
    struct (oprs, insSize)

type internal OpRmGprCL () =
  inherit OperandParser ()
  override __.Render rhlp insSize =
    let modRM = rhlp.ReadByte ()
    let opr1 = parseMemOrReg modRM insSize rhlp
    let opr2 =
      findRegRBits insSize.RegSize rhlp.REXPrefix (getReg modRM) |> OprReg
    let opr3 = Register.CL |> OprReg
    struct (ThreeOperands (opr1, opr2, opr3), insSize)
