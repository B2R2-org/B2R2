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

module internal B2R2.FrontEnd.ARM32.NEONLifter

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.IRHelper
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.GeneralLifter

let checkSingleReg = function
  | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
  | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17 | R.S18
  | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25 | R.S26 | R.S27
  | R.S28 | R.S29 | R.S30 | R.S31 -> true
  | _ -> false

let parseOprOfVLDR (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector d)),
                OprMemory(OffsetMode(ImmOffset(rn, s, imm)))) ->
    let pc = regVar bld rn |> convertPCOpr ins bld
    let baseAddr = align pc (numI32 4 32<rt>)
    regVar bld d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ ->
    raise InvalidOperandException

let vldr ins bld =
  lift bld ins {
    let rd, addr, isSReg = parseOprOfVLDR ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSReg then
      let data = tmpVar bld 32<rt>
      data := AST.loadLE 32<rt> addr
      rd := data
    else
      let struct (d1, d2) = tmpVars2 bld 32<rt>
      d1 := AST.loadLE 32<rt> addr
      d2 := AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      rd := if bld.Endianness = Endian.Big then AST.concat d1 d2
            else AST.concat d2 d1
    putEndLabel bld lblIgnore
  }

let parseOprOfVSTR (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector d)),
                OprMemory(OffsetMode(ImmOffset(rn, s, imm)))) ->
    let baseAddr = regVar bld rn
    regVar bld d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ ->
    raise InvalidOperandException

let vstr (ins: Instruction) bld =
  lift bld ins {
    let rd, addr, isSReg = parseOprOfVSTR ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSReg then
      AST.loadLE 32<rt> addr := rd
    else
      let mem1 = AST.loadLE 32<rt> addr
      let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let isbig = bld.Endianness = Endian.Big
      mem1 := if isbig then AST.xthi 32<rt> rd else AST.xtlo 32<rt> rd
      mem2 := if isbig then AST.xtlo 32<rt> rd else AST.xthi 32<rt> rd
    putEndLabel bld lblIgnore
  }

let parseOprOfVPUSHVPOP (ins: Instruction) =
  match ins.Operands with
  | OneOperand(OprRegList r) -> r
  | _ -> raise InvalidOperandException

let getVFPSRegisterToInt = function
  | R.S0 -> 0x00
  | R.S1 -> 0x01
  | R.S2 -> 0x02
  | R.S3 -> 0x03
  | R.S4 -> 0x04
  | R.S5 -> 0x05
  | R.S6 -> 0x06
  | R.S7 -> 0x07
  | R.S8 -> 0x08
  | R.S9 -> 0x09
  | R.S10 -> 0x0A
  | R.S11 -> 0x0B
  | R.S12 -> 0x0C
  | R.S13 -> 0x0D
  | R.S14 -> 0x0E
  | R.S15 -> 0x0F
  | R.S16 -> 0x10
  | R.S17 -> 0x11
  | R.S18 -> 0x12
  | R.S19 -> 0x13
  | R.S20 -> 0x14
  | R.S21 -> 0x15
  | R.S22 -> 0x16
  | R.S23 -> 0x17
  | R.S24 -> 0x18
  | R.S25 -> 0x19
  | R.S26 -> 0x1A
  | R.S27 -> 0x1B
  | R.S28 -> 0x1C
  | R.S29 -> 0x1D
  | R.S30 -> 0x1E
  | R.S31 -> 0x1F
  | _ -> raise InvalidRegisterException

let getVFPDRegisterToInt = function
  | R.D0 -> 0x00
  | R.D1 -> 0x01
  | R.D2 -> 0x02
  | R.D3 -> 0x03
  | R.D4 -> 0x04
  | R.D5 -> 0x05
  | R.D6 -> 0x06
  | R.D7 -> 0x07
  | R.D8 -> 0x08
  | R.D9 -> 0x09
  | R.D10 -> 0x0A
  | R.D11 -> 0x0B
  | R.D12 -> 0x0C
  | R.D13 -> 0x0D
  | R.D14 -> 0x0E
  | R.D15 -> 0x0F
  | R.D16 -> 0x10
  | R.D17 -> 0x11
  | R.D18 -> 0x12
  | R.D19 -> 0x13
  | R.D20 -> 0x14
  | R.D21 -> 0x15
  | R.D22 -> 0x16
  | R.D23 -> 0x17
  | R.D24 -> 0x18
  | R.D25 -> 0x19
  | R.D26 -> 0x1A
  | R.D27 -> 0x1B
  | R.D28 -> 0x1C
  | R.D29 -> 0x1D
  | R.D30 -> 0x1E
  | R.D31 -> 0x1F
  | R.FPINST2 -> 0x20
  | R.MVFR0 -> 0x21
  | R.MVFR1 -> 0x22
  | _ -> raise InvalidRegisterException

let parsePUSHPOPsubValue ins =
  let regs = parseOprOfVPUSHVPOP ins
  let isSReg = checkSingleReg regs.Head
  let imm = if isSReg then regs.Length else regs.Length * 2
  let d = if isSReg then getVFPSRegisterToInt regs.Head
          else getVFPDRegisterToInt regs.Head
  d, imm, isSReg

let vpopLoop bld d imm isSReg addr =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      append bld {
        regVar bld reg := AST.loadLE 32<rt> addr
      }
      singleRegLoop (r + 1) nextAddr
    else
      ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let word1 = AST.loadLE 32<rt> addr
      let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = bld.Endianness = Endian.Big
      append bld {
        regVar bld reg := if isbig then AST.concat word1 word2
                             else AST.concat word2 word1
      }
      nonSingleRegLoop (r + 1) nextAddr
    else
      ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpop ins bld =
  lift bld ins {
    let t0 = tmpVar bld 32<rt>
    let sp = regVar bld R.SP
    let d, imm, isSReg = parsePUSHPOPsubValue ins
    let addr = sp
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t0 := addr
    sp := addr .+ (numI32 (imm <<< 2) 32<rt>)
    vpopLoop bld d imm isSReg t0
    putEndLabel bld lblIgnore
  }

let vpushLoop bld d imm isSReg addr =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      append bld {
        AST.loadLE 32<rt> addr := regVar bld reg
      }
      singleRegLoop (r + 1) nextAddr
    else
      ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let mem1 = AST.loadLE 32<rt> addr
      let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = bld.Endianness = Endian.Big
      let data1 = AST.xthi 32<rt> (regVar bld reg)
      let data2 = AST.xtlo 32<rt> (regVar bld reg)
      append bld {
        mem1 := if isbig then data1 else data2
        mem2 := if isbig then data2 else data1
      }
      nonSingleRegLoop (r + 1) nextAddr
    else
      ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpush ins bld =
  lift bld ins {
    let t0 = tmpVar bld 32<rt>
    let sp = regVar bld R.SP
    let d, imm, isSReg = parsePUSHPOPsubValue ins
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t0 := sp .- (numI32 (imm <<< 2) 32<rt>)
    sp := t0
    vpushLoop bld d imm isSReg t0
    putEndLabel bld lblIgnore
  }

let parseOprOfVAND (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector r1)),
                  OprSIMD(SFReg(Vector r2)),
                  OprSIMD(SFReg(Vector r3))) ->
    regVar bld r1, regVar bld r2, regVar bld r3
  | _ ->
    raise InvalidOperandException

let vand (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      dstA := src1A .& src2A
      dstB := src1B .& src2B
    | _ ->
      let dst, src1, src2 = parseOprOfVAND ins bld
      dst := src1 .& src2
    putEndLabel bld lblIgnore
  }

let vmrs ins bld =
  lift bld ins {
    let struct (rt, fpscr) = transTwoOprs ins bld
    let cpsr = regVar bld R.CPSR
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.Operands with
    | TwoOperands(OprReg R.APSR, _) | TwoOperands(OprReg R.CPSR, _) ->
      cpsr := disablePSRBits bld R.CPSR PSR.Cond .|
                  getPSR bld R.FPSCR PSR.Cond
    | _ ->
      rt := fpscr
    putEndLabel bld lblIgnore
  }

let vmsr ins bld =
  lift bld ins {
    let struct (fpscr, rt) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    fpscr := rt
    putEndLabel bld lblIgnore
  }

let vcmp ins bld =
  lift bld ins {
    let struct (op1, op2) = transTwoOprs ins bld
    let fpscr = regVar bld R.FPSCR
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let unordered = AST.not (AST.feq op1 op1) .| AST.not (AST.feq op2 op2)
    let lt = AST.flt op1 op2
    fpscr := lt |> setPSR bld R.FPSCR PSR.N
    fpscr := AST.feq op1 op2 |> setPSR bld R.FPSCR PSR.Z
    fpscr := AST.not lt |> setPSR bld R.FPSCR PSR.C
    fpscr := unordered |> setPSR bld R.FPSCR PSR.V
    putEndLabel bld lblIgnore
  }

let mrc (ins: Instruction) bld =
  match ins.Operands with
  (* MRC p15, #0, <Rt>, c13, c0, #3 reads TPIDRURO, the PL0 read-only
     software thread ID register -- the body of Linux's __kuser_get_tls.
     Rt = PC is UNPREDICTABLE for this encoding, so it is excluded. Every
     other system-register access stays unsupported. *)
  | SixOperands(OprReg R.P15,
                OprImm 0L,
                OprReg rt,
                OprReg R.C13,
                OprReg R.C0,
                OprImm 3L) when rt <> R.PC ->
    let rt = regVar bld rt
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    lift bld ins {
      let lblIgnore = checkCondition ins bld isUnconditional
      rt := regVar bld R.TPIDRURO
      putEndLabel bld lblIgnore
    }
  | _ ->
    sideEffects ins bld UnsupportedInstruction

type ParsingInfo =
  { EBytes: int
    ESize: int
    RtESize: int<rt>
    Elements: int
    RegIndex: bool option }

let getRegs = function
  | TwoOperands(OprSIMD(OneReg _), _) -> 1
  | TwoOperands(OprSIMD(TwoRegs _), _) -> 2
  | TwoOperands(OprSIMD(ThreeRegs _), _) -> 3
  | TwoOperands(OprSIMD(FourRegs _), _) -> 4
  | _ -> raise InvalidOperandException

let getEBytes = function
  | Some(OneDT SIMDTyp8) | Some(OneDT SIMDTypS8) | Some(OneDT SIMDTypI8)
  | Some(OneDT SIMDTypU8) | Some(OneDT SIMDTypP8) -> 1
  | Some(OneDT SIMDTyp16) | Some(OneDT SIMDTypS16) | Some(OneDT SIMDTypI16)
  | Some(OneDT SIMDTypU16) | Some(OneDT SIMDTypF16)
  | Some(TwoDT(SIMDTypF32, SIMDTypF16))
  | Some(TwoDT(SIMDTypF16, SIMDTypF32)) -> 2
  | Some(OneDT SIMDTyp32) | Some(OneDT SIMDTypS32) | Some(OneDT SIMDTypI32)
  | Some(OneDT SIMDTypU32) | Some(OneDT SIMDTypF32) -> 4
  | Some(OneDT SIMDTyp64) | Some(OneDT SIMDTypS64) | Some(OneDT SIMDTypI64)
  | Some(OneDT SIMDTypU64) | Some(OneDT SIMDTypP64)
  | Some(OneDT SIMDTypF64) -> 8
  | _ -> raise InvalidOperandException

let registerIndex = function
  | TwoOperands(_, OprMemory(OffsetMode(AlignOffset _)))
  | TwoOperands(_, OprMemory(PreIdxMode(AlignOffset _))) -> Some false
  | TwoOperands(_, OprMemory(PostIdxMode(AlignOffset _))) -> Some true
  | _ -> None

/// Parsing information for SIMD instructions
let getParsingInfo (ins: Instruction) =
  let ebytes = getEBytes ins.SIMDTyp
  let esize = ebytes * 8
  let elements = 8 / ebytes
  let regIndex = registerIndex ins.Operands
  { EBytes = ebytes
    ESize = esize
    RtESize = RegType.fromBitWidth esize
    Elements = elements
    RegIndex = regIndex }

let private elem vector e size =
  AST.extract vector (RegType.fromBitWidth size) (e * size)

let elemForIR vector vSize index size =
  let index = AST.zext vSize index
  let mask = AST.num <| BitVector(BigInteger.makeMask size, vSize)
  let eSize = numI32 size vSize
  (vector >> (index .* eSize)) .& mask |> AST.xtlo (RegType.fromBitWidth size)

let isUnsigned = function
  | Some(OneDT SIMDTypU8) | Some(OneDT SIMDTypU16)
  | Some(OneDT SIMDTypU32) | Some(OneDT SIMDTypU64) -> true
  | Some(OneDT SIMDTypS8) | Some(OneDT SIMDTypS16)
  | Some(OneDT SIMDTypS32) | Some(OneDT SIMDTypS64) | Some(OneDT SIMDTypP8)
  | Some(OneDT SIMDTypP64) | Some(OneDT SIMDTyp8) | Some(OneDT SIMDTyp16)
  | Some(OneDT SIMDTyp32) | Some(OneDT SIMDTyp64) -> false
  | _ -> raise InvalidOperandException

let parseOprOfVMOV (ins: Instruction) bld =
  match ins.Operands with
  (* VMOV (immediate) *)
  | TwoOperands(OprSIMD _, OprImm _) ->
    let struct (dst, imm) = getTwoOprs ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 bld dst
      let imm = transOpr ins bld imm
      append bld {
        dstB := imm
        dstA := imm
      }
    | _ ->
      let dst = transOpr ins bld dst
      let imm = transOpr ins bld imm
      append bld {
        dst := imm
      }
  (* VMOV (general-purpose register to scalar) *)
  | TwoOperands(OprSIMD(SFReg(Scalar(_, Some element))), OprReg _) ->
    let struct (dst, src) = transTwoOprs ins bld
    let p = getParsingInfo ins
    let index = int element
    append bld {
      elem dst index p.ESize := AST.xtlo p.RtESize src
    }
  (* VMOV (scalar to general-purpose register) *)
  | TwoOperands(OprReg _, OprSIMD(SFReg(Scalar(_, Some element)))) ->
    let struct (dst, src) = transTwoOprs ins bld
    let p = getParsingInfo ins
    let index = int element
    let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    append bld {
      dst := extend 32<rt> (elem src index p.ESize)
    }
  (* VMOV (between general-purpose register and single-precision) *)
  | TwoOperands _ ->
    let struct (dst, src) = transTwoOprs ins bld
    append bld {
      dst := src
    }
  (* VMOV (between two general-purpose registers and a doubleword
    floating-point register) *)
  | ThreeOperands(OprSIMD _, OprReg _, OprReg _) ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    append bld {
      AST.xtlo 32<rt> dst := src1
      AST.xthi 32<rt> dst := src2
    }
  | ThreeOperands(OprReg _, OprReg _, OprSIMD _) ->
    let struct (dst1, dst2, src) = transThreeOprs ins bld
    append bld {
      dst1 := AST.xtlo 32<rt> src
      dst2 := AST.xthi 32<rt> src
    }
  (* VMOV (between two general-purpose registers and two single-precision
    registers) *)
  | FourOperands _ ->
    let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
    append bld {
      dst1 := src1
      dst2 := src2
    }
  | _ ->
    raise InvalidOperandException

let parseOprOfVMOVFP (ins: Instruction) bld =
  append bld {
    match ins.Operands with
    (* VMOV (between general-purpose register and half-precision) *)
    | TwoOperands(OprSIMD _, OprReg _) | TwoOperands(OprReg _, OprSIMD _) ->
      let struct (dst, src) = transTwoOprs ins bld
      dst := AST.zext 32<rt> (AST.xtlo 16<rt> src)
    (* VMOV (register) *)
    | TwoOperands(OprSIMD _, OprSIMD _) ->
      let struct (dst, src) = transTwoOprs ins bld
      dst := src
    (* VMOV (immediate) *)
    | TwoOperands(OprSIMD _, OprImm _) ->
      let struct (dst, imm) = transTwoOprs ins bld
      dst := AST.zext ins.OprSize imm
    | _ ->
      AST.sideEffect UnsupportedInstruction
  }

let vmov (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    parseOprOfVMOV ins bld
    putEndLabel bld lblIgnore
  }

let vmovfp (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    parseOprOfVMOVFP ins bld
    putEndLabel bld lblIgnore
  }

(* VMOV(immediate)/VMOV(register) *)
let isF32orF64 = function
  | Some(OneDT SIMDTypF32) | Some(OneDT SIMDTypF64) -> true
  | _ -> false

(* VABS(immediate)/VABS(register) *)
let isF16orF32orF64 = function
  | Some(OneDT SIMDTypF16) | Some(OneDT SIMDTypF32) | Some(OneDT SIMDTypF64)
    -> true
  | _ -> false

let private absExpr expr size =
  AST.ite (AST.slt expr (AST.num0 size)) (AST.neg expr) (expr)

let vabs (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := absExpr (elem srcB e p.ESize) p.RtESize
        elem dstA e p.ESize := absExpr (elem srcA e p.ESize) p.RtESize
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      for e in 0 .. p.Elements - 1 do
        elem dst e p.ESize := absExpr (elem src e p.ESize) p.RtESize
    putEndLabel bld lblIgnore
  }

let vabsf (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match (getParsingInfo ins).ESize with
    | 16 ->
      dst :=
        AST.zext 32<rt> (AST.xtlo 16<rt> src .& numU32 0x7fffu 16<rt>)
    | 32 ->
      dst := src .& numU32 0x7fffffffu 32<rt>
    | _ ->
      dst := src .& numU64 0x7fffffffffffffffUL 64<rt>
    putEndLabel bld lblIgnore
  }

let vnegf (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match (getParsingInfo ins).ESize with
    | 16 ->
      dst :=
        AST.zext 32<rt> (AST.xtlo 16<rt> src <+> numU32 0x8000u 16<rt>)
    | 32 ->
      dst := src <+> numU32 0x80000000u 32<rt>
    | _ ->
      dst := src <+> numU64 0x8000000000000000UL 64<rt>
    putEndLabel bld lblIgnore
  }

let vsqrtf (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match (getParsingInfo ins).ESize with
    | 16 ->
      append bld { dst := AST.zext 32<rt> (AST.fsqrt (AST.xtlo 16<rt> src)) }
    | _ ->
      append bld { dst := AST.fsqrt src }
    putEndLabel bld lblIgnore
  }

/// Flips the sign bit of a floating-point value of the given element size, the
/// bitwise form of FPNeg used by the VFP negated multiply family.
let fpNegBits esize e =
  match esize with
  | 16 -> e <+> numU32 0x8000u 16<rt>
  | 32 -> e <+> numU32 0x80000000u 32<rt>
  | _ -> e <+> numU64 0x8000000000000000UL 64<rt>

/// VFP scalar multiply-accumulate family (VMLA/VMLS/VNMUL/VNMLA/VNMLS). combine
/// receives the element size, the accumulator (dst) and the product of the two
/// source operands, and yields the result written back to dst.
let vfpMulAcc (ins: Instruction) bld combine =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match (getParsingInfo ins).ESize with
    | 16 ->
      let d = AST.xtlo 16<rt> dst
      let p = AST.fmul (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)
      dst := AST.zext 32<rt> (combine 16 d p)
    | 32 ->
      dst := combine 32 dst (AST.fmul src1 src2)
    | _ ->
      dst := combine 64 dst (AST.fmul src1 src2)
    putEndLabel bld lblIgnore
  }

let vaddsub (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    (* FP, p.ESize 16 *)
    | 32<rt> when p.ESize = 16 ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst :=
        AST.zext 32<rt> (opFn (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2))
    (* FP, p.ESize 32 *)
    | 32<rt> ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := opFn src1 src2
    (* FP, p.ESize 64 *)
    | 64<rt> when p.ESize = 64 ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := opFn src1 src2
    (* SIMD *)
    | 64<rt> ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let elem value = elem value e p.ESize
        elem dst := (opFn (elem src1) (elem src2))
    (* SIMD *)
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let elem expr = elem expr e p.ESize
        elem dstB := (opFn (elem src1B) (elem src2B))
        elem dstA := (opFn (elem src1A) (elem src2A))
    | _ ->
      raise InvalidOperandException
    putEndLabel bld lblIgnore
  }

let vaddl (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let src1 = transOpr ins bld src1
    let src2 = transOpr ins bld src2
    for e in 0 .. (p.Elements - 1) / 2 do
      elem dstA e (2 * p.ESize) :=
        AST.zext (p.RtESize * 2) (elem src1 e p.ESize) .+
        AST.zext (p.RtESize * 2) (elem src2 e p.ESize)
      elem dstB e (2 * p.ESize) :=
        AST.zext (p.RtESize * 2) (elem src1 (e + p.Elements / 2) p.ESize) .+
        AST.zext (p.RtESize * 2) (elem src2 (e + p.Elements / 2) p.ESize)
    putEndLabel bld lblIgnore
  }

let vcvtCastKind = function
  (* float <-> float *)
  | Some(TwoDT(SIMDTypF32, SIMDTypF64)) -> struct (CastKind.FloatCast, 32<rt>)
  | Some(TwoDT(SIMDTypF64, SIMDTypF32)) -> struct (CastKind.FloatCast, 64<rt>)
  (* int -> float *)
  | Some(TwoDT(SIMDTypF32, SIMDTypS32)) -> struct (CastKind.SIntToFloat, 32<rt>)
  | Some(TwoDT(SIMDTypF64, SIMDTypS32)) -> struct (CastKind.SIntToFloat, 64<rt>)
  | Some(TwoDT(SIMDTypF32, SIMDTypU32)) -> struct (CastKind.UIntToFloat, 32<rt>)
  | Some(TwoDT(SIMDTypF64, SIMDTypU32)) -> struct (CastKind.UIntToFloat, 64<rt>)
  (* float -> int (round toward zero) *)
  | Some(TwoDT(SIMDTypS32, SIMDTypF32))
  | Some(TwoDT(SIMDTypU32, SIMDTypF32)) -> struct (CastKind.FtoITrunc, 32<rt>)
  | Some(TwoDT(SIMDTypS32, SIMDTypF64))
  | Some(TwoDT(SIMDTypU32, SIMDTypF64)) -> struct (CastKind.FtoITrunc, 32<rt>)
  | _ -> raise InvalidOperandException

let parseOprOfVCVT (ins: Instruction) bld =
  (* FIXME *)
  match ins.Operands with
  | TwoOperands(OprSIMD _, OprSIMD _) ->
    match ins.OprSize with
    (* FIXME *)
    (* VCVT (between half-precision and single-precision, Advanced SIMD) *)
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let src = transOpr ins bld src
      let p = getParsingInfo ins
      let struct (tdstB, tdstA) = tmpVars2 bld 64<rt>
      append bld {
        tdstA := (dstB << numI32 63 64<rt>) .| (dstA >> AST.num1 64<rt>)
        tdstB := dstB >> AST.num1 64<rt>
      }
      for e in 0 .. (p.Elements - 1) / 2 do
        append bld {
          elem tdstB e 32 :=
            AST.cast CastKind.FloatCast 32<rt> (elem src (e + 2) 16)
          elem tdstA e 32 :=
            AST.cast CastKind.FloatCast 32<rt> (elem src e 16)
        }
      append bld {
        dstB := tdstB
        dstA := tdstA
      }
    | 64<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let dst = transOpr ins bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let p = getParsingInfo ins
      let struct (tsrcB, tsrcA) = tmpVars2 bld 64<rt>
      append bld {
        tsrcA := (srcB << numI32 63 64<rt>) .| (srcA >> AST.num1 64<rt>)
        tsrcB := srcB >> AST.num1 64<rt>
      }
      for e in 0 .. (p.Elements - 1) / 2 do
        append bld {
          elem dst (e + 2) 16 :=
            AST.cast CastKind.FloatCast 16<rt> (elem tsrcB e 32)
          elem dst e 16 :=
            AST.cast CastKind.FloatCast 16<rt> (elem tsrcA e 32)
        }
    (* VCVT (between double-precision and single-precision) *)
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      match ins.SIMDTyp with
      | Some(TwoDT(SIMDTypU32, SIMDTypF32))
      | Some(TwoDT(SIMDTypU32, SIMDTypF64)) ->
        (* LowUIR has no unsigned float-to-int cast; widen to a signed 64-bit
           integer (values in [0, 2^32) are exact) and keep the low 32 bits. *)
        append bld {
          dst := AST.xtlo 32<rt> (AST.cast CastKind.FtoITrunc 64<rt> src)
        }
      | _ ->
        let struct (kind, size) = vcvtCastKind ins.SIMDTyp
        append bld {
          dst := AST.cast kind size src
        }
  | _ ->
    raise InvalidOperandException

let vcvt (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    parseOprOfVCVT ins bld
    putEndLabel bld lblIgnore
  }

let parseOprOfVDUP (ins: Instruction) bld esize =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dst)),
                OprSIMD(SFReg(Scalar(src, Some idx)))) ->
    regVar bld dst, elem (regVar bld src) (int32 idx) esize
  | TwoOperands(OprSIMD(SFReg(Vector dst)), OprReg src) ->
    regVar bld dst, AST.xtlo (RegType.fromBitWidth esize) (regVar bld src)
  | _ ->
    raise InvalidOperandException

let parseOprOfVDUP128 (ins: Instruction) bld esize =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dst)),
                OprSIMD(SFReg(Scalar(src, Some idx)))) ->
    let struct (rb, ra) = pseudoRegVar128 bld dst
    struct (rb, ra, elem (regVar bld src) (int32 idx) esize)
  | TwoOperands(OprSIMD(SFReg(Vector dst)), OprReg src) ->
    let struct (rb, ra) = pseudoRegVar128 bld dst
    struct (rb, ra, AST.xtlo (RegType.fromBitWidth esize) (regVar bld src))
  | _ ->
    raise InvalidOperandException

let vdiv (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match p.ESize with
    | 16 ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst :=
        AST.zext 32<rt> (AST.fdiv (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2))
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := AST.fdiv src1 src2
    putEndLabel bld lblIgnore
  }

let vdup (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA, scalar) = parseOprOfVDUP128 ins bld p.ESize
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := scalar
        elem dstA e p.ESize := scalar
    | _ ->
      let dst, scalar = parseOprOfVDUP ins bld p.ESize
      for e in 0 .. p.Elements - 1 do
        append bld { elem dst e p.ESize := scalar }
    putEndLabel bld lblIgnore
  }

let highestSetBitForIR dst src width oprSz bld =
  append bld {
    let lblLoop = label bld "Loop"
    let lblLoopCont = label bld "LoopContinue"
    let lblUpdateTmp = label bld "UpdateTmp"
    let lblEnd = label bld "End"
    let t = tmpVar bld oprSz
    let width = (numI32 (width - 1) oprSz)
    t := width
    AST.lmark lblLoop
    AST.cjmp (src >> t == AST.num1 oprSz)
             (AST.jmpDest lblEnd)
             (AST.jmpDest lblLoopCont)
    AST.lmark lblLoopCont
    AST.cjmp (t == AST.num0 oprSz)
             (AST.jmpDest lblEnd)
             (AST.jmpDest lblUpdateTmp)
    AST.lmark lblUpdateTmp
    t := t .- AST.num1 oprSz
    AST.jmp (AST.jmpDest lblLoop)
    AST.lmark lblEnd
    dst := width .- t
  }

let countLeadingZeroBitsForIR dst src oprSize bld =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize bld

let vclz (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. p.Elements - 1 do
        countLeadingZeroBitsForIR (elem dstB e p.ESize)
                                  (elem srcB e p.ESize)
                                  p.RtESize
                                  bld
        countLeadingZeroBitsForIR (elem dstA e p.ESize)
                                  (elem srcA e p.ESize)
                                  p.RtESize
                                  bld
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      for e in 0 .. p.Elements - 1 do
        countLeadingZeroBitsForIR (elem dst e p.ESize)
                                  (elem src e p.ESize)
                                  p.RtESize
                                  bld
    putEndLabel bld lblIgnore
  }

let maxExpr isUnsigned expr1 expr2 =
  let op = if isUnsigned then AST.gt else AST.sgt
  AST.ite (op expr1 expr2) expr1 expr2

let minExpr isUnsigned expr1 expr2 =
  let op = if isUnsigned then AST.lt else AST.slt
  AST.ite (op expr1 expr2) expr1 expr2

let private mulZExtend p size expr1 expr2 amtOp =
  amtOp (AST.zext (p.RtESize * size) expr1) (AST.zext (p.RtESize * size) expr2)

let private mulSExtend p size expr1 expr2 amtOp =
  amtOp (AST.sext (p.RtESize * size) expr1) (AST.sext (p.RtESize * size) expr2)

let private unsignExtend (ins: Instruction) p size expr1 expr2 amtOp =
  if isUnsigned ins.SIMDTyp then mulZExtend p size expr1 expr2 amtOp
  else mulSExtend p size expr1 expr2 amtOp

let vmaxmin (ins: Instruction) bld maximum =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let unsigned = isUnsigned ins.SIMDTyp
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let op1B, op2B = elem src1B e p.ESize, elem src2B e p.ESize
        let op1A, op2A = elem src1A e p.ESize, elem src2A e p.ESize
        let result1 =
          if maximum then maxExpr unsigned op1B op2B
          else minExpr unsigned op1B op2B
        let result2 =
          if maximum then maxExpr unsigned op1A op2A
          else minExpr unsigned op1A op2A
        elem dstB e p.ESize := AST.xtlo p.RtESize result1
        elem dstA e p.ESize := AST.xtlo p.RtESize result2
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let op1 = elem src1 e p.ESize
        let op2 = elem src2 e p.ESize
        let result =
          if maximum then maxExpr unsigned op1 op2 else minExpr unsigned op1 op2
        elem dst e p.ESize := AST.xtlo p.RtESize result
    putEndLabel bld lblIgnore
  }

let parseOprOfVSTLDM (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprRegList regs) ->
    regVar bld reg, List.map (regVar bld) regs
  | _ ->
    raise InvalidOperandException

let vstm (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rn, regList = parseOprOfVSTLDM ins bld
    let add =
      match ins.Opcode with
      | Op.VSTMIA -> true
      | Op.VSTMDB -> false
      | _ -> raise InvalidOpcodeException
    let regs = List.length regList
    let imm32 = numI32 ((regs * 2) <<< 2) 32<rt>
    let addr = tmpVar bld 32<rt>
    let updateRn rn =
      if ins.WriteBack then
        if add then rn .+ imm32 else rn .- imm32
      else
        rn
    addr := if add then rn else rn .- imm32
    rn := updateRn rn
    for r in 0 .. (regs - 1) do
      let mem1 = AST.loadLE 32<rt> addr
      let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let data1 = AST.xtlo 32<rt> regList[r]
      let data2 = AST.xthi 32<rt> regList[r]
      let isbig = bld.Endianness = Endian.Big
      mem1 := if isbig then data2 else data1
      mem2 := if isbig then data1 else data2
      addr := addr .+ (numI32 8 32<rt>)
    putEndLabel bld lblIgnore
  }

let vldm (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rn, regList = parseOprOfVSTLDM ins bld
    let add =
      match ins.Opcode with
      | Op.VLDMIA -> true
      | Op.VLDMDB -> false
      | _ -> raise InvalidOpcodeException
    let regs = List.length regList
    let imm32 = numI32 ((regs * 2) <<< 2) 32<rt>
    let addr = tmpVar bld 32<rt>
    let updateRn rn =
      if ins.WriteBack then
        if add then rn .+ imm32 else rn .- imm32
      else
        rn
    addr := if add then rn else rn .- imm32
    rn := updateRn rn
    for r in 0 .. (regs - 1) do
      let word1 = AST.loadLE 32<rt> addr
      let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let isbig = bld.Endianness = Endian.Big
      regList[r] :=
             if isbig then AST.concat word1 word2 else AST.concat word2 word1
      addr := addr .+ (numI32 8 32<rt>)
    putEndLabel bld lblIgnore
  }

let vecMulAccOrSub (ins: Instruction) bld add =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let sext1A = AST.sext p.RtESize (elem src1A e p.ESize)
        let sext1B = AST.sext p.RtESize (elem src1B e p.ESize)
        let sext2A = AST.sext p.RtESize (elem src2A e p.ESize)
        let sext2B = AST.sext p.RtESize (elem src2B e p.ESize)
        let productA = sext1A .* sext2A
        let productB = sext1B .* sext2B
        let addendA, addendB =
          if add then productA, productB else AST.not productA, AST.not productB
        elem dstB e p.ESize := elem dstB e p.ESize .+ addendB
        elem dstA e p.ESize := elem dstA e p.ESize .+ addendA
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let sext1 = AST.sext p.RtESize (elem src1 e p.ESize)
        let sext2 = AST.sext p.RtESize (elem src2 e p.ESize)
        let product = sext1 .* sext2
        let addend = if add then product else AST.not product
        elem dst e p.ESize := elem dst e p.ESize .+ addend
    putEndLabel bld lblIgnore
  }

let vecMulAccOrSubLong (ins: Instruction) bld add =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let unsigned = isUnsigned ins.SIMDTyp
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let src1 = transOpr ins bld src1
    let src2 = transOpr ins bld src2
    for e in 0 .. (p.Elements - 1) / 2 do
      let extend expr =
        if unsigned then AST.zext (p.RtESize * 2) expr
        else AST.sext (p.RtESize * 2) expr
      let productA =
        extend (elem src1 e p.ESize) .* extend (elem src2 e p.ESize)
      let productB = extend (elem src1 (e + p.Elements / 2) p.ESize) .*
                     extend (elem src2 (e + p.Elements / 2) p.ESize)
      let addendA, addendB =
        if add then productA, productB else AST.not productA, AST.not productB
      elem dstB e (p.ESize * 2) := elem dstB e (p.ESize * 2) .+ addendB
      elem dstA e (p.ESize * 2) := elem dstA e (p.ESize * 2) .+ addendA
    putEndLabel bld lblIgnore
  }

let vecMulAccOrSubByScalar (ins: Instruction) bld add =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let src2, index = transOprToScalar bld src2
    let op2Val = AST.sext p.RtESize (elem src2 index p.ESize)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      for e in 0 .. p.Elements - 1 do
        let op1valA = AST.sext p.RtESize (elem src1A e p.ESize)
        let op1valB = AST.sext p.RtESize (elem src1B e p.ESize)
        let addendA, addendB =
          if add then op1valA .* op2Val, op1valB .* op2Val
          else AST.not (op1valA .* op2Val), AST.not (op1valB .* op2Val)
        elem dstB e p.ESize := elem dstB e p.ESize .+ addendB
        elem dstA e p.ESize := elem dstA e p.ESize .+ addendA
    | _ ->
      let dst = transOpr ins bld dst
      let src1 = transOpr ins bld src1
      for e in 0 .. p.Elements - 1 do
        let op1val = AST.sext p.RtESize (elem src1 e p.ESize)
        let addend =
          if add then op1val .* op2Val else AST.not (op1val .* op2Val)
        elem dst e p.ESize := elem dst e p.ESize .+ addend
    putEndLabel bld lblIgnore
  }

let vecMulAccOrSubLongByScalar (ins: Instruction) bld add =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let src1 = transOpr ins bld src1
    let src2, index = transOprToScalar bld src2
    let p = getParsingInfo ins
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let op2val = ext (p.RtESize * 2) (elem src2 index p.ESize)
    for e in 0 .. (p.Elements - 1) / 2 do
      let op1valA = ext (p.RtESize * 2) (elem src1 e p.ESize)
      let op1valB = ext (p.RtESize * 2) (elem src1 (e + p.Elements / 2) p.ESize)
      let addendA, addendB =
        if add then op1valA .* op2val, op1valB .* op2val
        else AST.not (op1valA .* op2val), AST.not (op1valB .* op2val)
      elem dstB e (p.ESize * 2) := elem dstB e (p.ESize * 2) .+ addendB
      elem dstA e (p.ESize * 2) := elem dstA e (p.ESize * 2) .+ addendA
    putEndLabel bld lblIgnore
  }

let vmla (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Vector _))) ->
    vecMulAccOrSub ins bld true
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    vecMulAccOrSubByScalar ins bld true
  | _ ->
    raise InvalidOperandException

let vmlal (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Vector _))) ->
    vecMulAccOrSubLong ins bld true
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    vecMulAccOrSubLongByScalar ins bld true
  | _ ->
    raise InvalidOperandException

let vmls (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Vector _))) ->
    vecMulAccOrSub ins bld false
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    vecMulAccOrSubByScalar ins bld false
  | _ ->
    raise InvalidOperandException

let vmlsl (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Vector _))) ->
    vecMulAccOrSubLong ins bld false
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    vecMulAccOrSubLongByScalar ins bld false
  | _ ->
    raise InvalidOperandException

let isPolynomial = function
  | Some(OneDT SIMDTypP8) | Some(OneDT SIMDTypP64) -> true
  | _ -> false

/// shared/functions/vector/PolynomialMult, in page Armv8 Pseudocode-7927
let polynomialMult op1 op2 size rtsize res bld =
  append bld {
    let extendedOP2 = AST.zext rtsize op2
    for i = 0 to size - 1 do
      let cond = AST.extract op1 1<rt> i
      res := AST.ite cond (res <+> (extendedOP2 << numI32 i rtsize)) res
  }

let polynomialMultP64 op1 op2 size rtsize resA resB bld =
  append bld {
    for i = 0 to size - 1 do
      let cond = AST.extract op1 1<rt> i
      resA := AST.ite cond (resA <+> (op2 << numI32 i rtsize)) resA
      resB := AST.ite cond
                      (resB <+> (op2 >> numI32 (64 - i) rtsize))
                      resB
  }

/// Multiplies the lanes of two doubleword operands, one lane at a time.
let private vecMulD ins bld p opFn polynomial resultA =
  append bld {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let struct (op1, op2) = elem src1 e p.ESize, elem src2 e p.ESize
      if polynomial then
        polynomialMult op1 op2 p.ESize (p.RtESize * 2) resultA bld
      else
        resultA := mulSExtend p 2 op1 op2 opFn
      elem dst e p.ESize := AST.xtlo p.RtESize resultA
  }

/// Multiplies the lanes of two quadword operands, one lane of each half at a
/// time.
let private vecMulQ ins bld p opFn polynomial (resultA, resultB) =
  append bld {
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let struct (src1B, src1A) = transOpr128 bld src1
    let struct (src2B, src2A) = transOpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let struct (op1A, op2A, op1B, op2B) =
        let src1A = elem src1A e p.ESize
        let src2A = elem src2A e p.ESize
        let src1B = elem src1B e p.ESize
        let src2B = elem src2B e p.ESize
        src1A, src2A, src1B, src2B
      if polynomial then
        polynomialMult op1A op2A p.ESize (p.RtESize * 2) resultA bld
        polynomialMult op1B op2B p.ESize (p.RtESize * 2) resultB bld
      else
        resultA := mulSExtend p 2 op1A op2A opFn
        resultB := mulSExtend p 2 op1B op2B opFn
      elem dstA e p.ESize := AST.xtlo p.RtESize resultA
      elem dstB e p.ESize := AST.xtlo p.RtESize resultB
  }

let vecMul (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let polynomial = isPolynomial ins.SIMDTyp
    let struct (resultA, resultB) = tmpVars2 bld (p.RtESize * 2)
    match ins.OprSize with
    (* FP, p.ESize 16 *)
    | 32<rt> when p.ESize = 16 ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst :=
        AST.zext 32<rt> (opFn (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2))
    (* FP, p.ESize 32 *)
    | 32<rt> ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := opFn src1 src2
    (* FP, p.ESize 64 *)
    | 64<rt> when p.ESize = 64 ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := opFn src1 src2
    (* SIMD *)
    | 64<rt> ->
      vecMulD ins bld p opFn polynomial resultA
    (* SIMD *)
    | 128<rt> ->
      vecMulQ ins bld p opFn polynomial (resultA, resultB)
    | _ ->
      raise InvalidOperandException
    putEndLabel bld lblIgnore
  }

let vecMulLong (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let polynomial = isPolynomial ins.SIMDTyp
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let src1 = transOpr ins bld src1
    let src2 = transOpr ins bld src2
    let isPolyAndE64 = polynomial && p.ESize = 64
    let struct (regSize, eSize) =
      if isPolyAndE64 then p.RtESize, p.ESize else p.RtESize * 2, p.ESize * 2
    let struct (resA, resB) = tmpVars2 bld regSize
    for e in 0 .. (p.Elements - 1) / 2 do
      let struct (op1A, op2A, op1B, op2B) =
        let src1A = elem src1 e p.ESize
        let src2A = elem src2 e p.ESize
        let src1B = elem src1 (e + p.Elements / 2) p.ESize
        let src2B = elem src2 (e + p.Elements / 2) p.ESize
        src1A, src2A, src1B, src2B
      if isPolyAndE64 then
        polynomialMultP64 op1A op2A p.ESize p.RtESize resA resB bld
      elif polynomial then
        polynomialMult op1A op2A p.ESize (p.RtESize * 2) resA bld
        polynomialMult op1A op2A p.ESize (p.RtESize * 2) resB bld
      else
        resA := unsignExtend ins p 2 op1A op2A (.*)
        resB := unsignExtend ins p 2 op1B op2B (.*)
      elem dstB e eSize := AST.xtlo regSize resB
      elem dstA e eSize := AST.xtlo regSize resA
    putEndLabel bld lblIgnore
  }

let vecMulByScalar (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let src2, index = transOprToScalar bld src2
    let op2val = elem src2 index p.ESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      for e in 0 .. p.Elements - 1 do
        let resA = mulSExtend p 1 (elem src1A e p.ESize) op2val opFn
        let resB = mulSExtend p 1 (elem src1B e p.ESize) op2val opFn
        elem dstB e p.ESize := AST.xtlo p.RtESize resB
        elem dstA e p.ESize := AST.xtlo p.RtESize resA
    | _ ->
      let dst = transOpr ins bld dst
      let src1 = transOpr ins bld src1
      for e in 0 .. p.Elements - 1 do
        let res = mulSExtend p 1 (elem src1 e p.ESize) op2val opFn
        elem dst e p.ESize := AST.xtlo p.RtESize res
    putEndLabel bld lblIgnore
  }

let vecMulLongByScalar (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let src1 = transOpr ins bld src1
    let src2, index = transOprToScalar bld src2
    let p = getParsingInfo ins
    let op2val = elem src2 index p.ESize
    let pele2 = p.Elements / 2
    for e in 0 .. (p.Elements - 1) / 2 do
      let resA = unsignExtend ins p 2 (elem src1 e p.ESize) op2val (.*)
      let resB =
        unsignExtend ins p 2 (elem src1 (e + pele2) p.ESize) op2val (.*)
      elem dstB e (p.ESize * 2) := AST.xtlo (p.RtESize * 2) resB
      elem dstA e (p.ESize * 2) := AST.xtlo (p.RtESize * 2) resA
    putEndLabel bld lblIgnore
  }

let vmul (ins: Instruction) bld opFn =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Vector _))) ->
    vecMul ins bld opFn
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    vecMulByScalar ins bld opFn
  | _ ->
    raise InvalidOperandException

let vmull (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Vector _))) ->
    vecMulLong ins bld
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    vecMulLongByScalar ins bld
  | _ ->
    raise InvalidOperandException

let getSizeStartFromI16 = function
  | Some(OneDT SIMDTypI16) -> 0b00
  | Some(OneDT SIMDTypI32) -> 0b01
  | Some(OneDT SIMDTypI64) -> 0b10
  | _ -> raise InvalidOperandException

let getSizeStartFrom16 = function
  | Some(OneDT SIMDTyp16) -> 0b00
  | Some(OneDT SIMDTyp32) -> 0b01
  | Some(OneDT SIMDTyp64) -> 0b10
  | _ -> raise InvalidOperandException

let vmovn (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    let esize = 8 <<< getSizeStartFrom16 ins.SIMDTyp
    let rtEsz = RegType.fromBitWidth esize
    let elements = 64 / esize
    for e in 0 .. (elements - 1) / 2 do
      elem dst e esize := AST.xtlo rtEsz (elem srcB e esize)
      elem dst (e + elements / 2) esize :=
           AST.xtlo rtEsz (elem srcA e esize)
    putEndLabel bld lblIgnore
  }

let vneg (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. p.Elements - 1 do
        let result1 = AST.neg <| AST.sext p.RtESize (elem srcB e p.ESize)
        let result2 = AST.neg <| AST.sext p.RtESize (elem srcA e p.ESize)
        elem dstB e p.ESize := AST.xtlo p.RtESize result1
        elem dstA e p.ESize := AST.xtlo p.RtESize result2
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let result = AST.neg <| AST.sext p.RtESize (elem src e p.ESize)
        elem dst e p.ESize := AST.xtlo p.RtESize result
    putEndLabel bld lblIgnore
  }

let vpadd (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let p = getParsingInfo ins
    let h = p.Elements / 2
    let dest = tmpVar bld 64<rt>
    for e in 0 .. h - 1 do
      let addPair expr =
        elem expr (2 * e) p.ESize .+ elem expr (2 * e + 1) p.ESize
      elem dest e p.ESize := addPair rn
      elem dest (e + h) p.ESize := addPair rm
    rd := dest
    putEndLabel bld lblIgnore
  }

let vrshr (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, imm) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let imm = AST.zext 64<rt> (transOpr ins bld imm)
      let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
      for e in 0 .. p.Elements - 1 do
        let result1 = (extend 64<rt> (elem srcB e p.ESize) .+ roundConst) >> imm
        let result2 = (extend 64<rt> (elem srcA e p.ESize) .+ roundConst) >> imm
        elem dstB e p.ESize := AST.xtlo p.RtESize result1
        elem dstA e p.ESize := AST.xtlo p.RtESize result2
    | _ ->
      let struct (dst, src, imm) = transThreeOprs ins bld
      let imm = AST.zext 64<rt> imm
      let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
      for e in 0 .. p.Elements - 1 do
        let result = (extend 64<rt> (elem src e p.ESize) .+ roundConst) >> imm
        elem dst e p.ESize := AST.xtlo p.RtESize result
    putEndLabel bld lblIgnore
  }

let vshlImm (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, imm) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let imm = AST.zext p.RtESize (transOpr ins bld imm)
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := elem srcB e p.ESize << imm
        elem dstA e p.ESize := elem srcA e p.ESize << imm
    | _ ->
      let struct (dst, src, imm) = transThreeOprs ins bld
      let imm = AST.zext p.RtESize imm
      for e in 0 .. p.Elements - 1 do
        elem dst e p.ESize := elem src e p.ESize << imm
    putEndLabel bld lblIgnore
  }

let vshlReg (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let shift1 = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2B e p.ESize))
        let shift2 = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2A e p.ESize))
        let result1 = extend 64<rt> (elem src1B e p.ESize) << shift1
        let result2 = extend 64<rt> (elem src1A e p.ESize) << shift2
        elem dstB e p.ESize := AST.xtlo p.RtESize result1
        elem dstA e p.ESize := AST.xtlo p.RtESize result2
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let shift = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2 e p.ESize))
        let result = extend 64<rt> (elem src1 e p.ESize) << shift
        elem dst e p.ESize := AST.xtlo p.RtESize result
    putEndLabel bld lblIgnore
  }

let vshl (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> vshlImm ins bld
  | ThreeOperands(_, _, OprSIMD _) -> vshlReg ins bld
  | _ -> raise InvalidOperandException

let vshr (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, imm) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld dst
      let imm = AST.zext 64<rt> (transOpr ins bld imm)
      for e in 0 .. p.Elements - 1 do
        let result1 = extend 64<rt> (elem srcB e p.ESize) >> imm
        let result2 = extend 64<rt> (elem srcA e p.ESize) >> imm
        elem dstB e p.ESize := AST.xtlo p.RtESize result1
        elem dstA e p.ESize := AST.xtlo p.RtESize result2
    | _ ->
      let struct (dst, src, imm) = transThreeOprs ins bld
      let imm = AST.zext 64<rt> imm
      for e in 0 .. p.Elements - 1 do
        let result = extend 64<rt> (elem src e p.ESize) >> imm
        elem dst e p.ESize := AST.xtlo p.RtESize result
    putEndLabel bld lblIgnore
  }

let parseVectors = function
  | OneReg(Vector d) -> [ d ]
  | TwoRegs(Vector d1, Vector d2) -> [ d1; d2 ]
  | ThreeRegs(Vector d1, Vector d2, Vector d3) -> [ d1; d2; d3 ]
  | FourRegs(Vector d1, Vector d2, Vector d3, Vector d4) -> [ d1; d2; d3; d4 ]
  | _ -> raise InvalidOperandException

let parseOprOfVecTbl (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector rd)),
                  OprSIMD regs,
                  OprSIMD(SFReg(Vector rm))) ->
    regVar bld rd, parseVectors regs, regVar bld rm
  | _ ->
    raise InvalidOperandException

let vecTbl (ins: Instruction) bld isVtbl =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rd, list, rm = parseOprOfVecTbl ins bld
    let vectors = list |> List.map (regVar bld)
    let length = List.length list
    let table = AST.revConcat (List.toArray vectors) |> AST.zext 256<rt>
    for i in 0 .. 7 do
      let index = elem rm i 8
      let cond = AST.lt index (numI32 (8 * length) 8<rt>)
      let e = if isVtbl then AST.num0 8<rt> else elem rd i 8
      elem rd i 8 := AST.ite cond (elemForIR table 256<rt> index 8) e
    putEndLabel bld lblIgnore
  }

let isImm = function
  | Num _ -> true
  | _ -> false

let vectorCompareImm (ins: Instruction) bld cmp =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let num0 = AST.num0 p.RtESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      for e in 0 .. p.Elements - 1 do
        let t1 = cmp (elem src1B e p.ESize) num0
        let t2 = cmp (elem src1A e p.ESize) num0
        elem dstB e p.ESize := AST.ite t1 (ones p.RtESize) num0
        elem dstA e p.ESize := AST.ite t2 (ones p.RtESize) num0
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let t = cmp (elem src1 e p.ESize) num0
        elem dst e p.ESize := AST.ite t (ones p.RtESize) num0
    putEndLabel bld lblIgnore
  }

let vectorCompareReg (ins: Instruction) bld cmp =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let num0 = AST.num0 p.RtESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let t1 = cmp (elem src1B e p.ESize) (elem src2B e p.ESize)
        let t2 = cmp (elem src1A e p.ESize) (elem src2A e p.ESize)
        elem dstB e p.ESize := AST.ite t1 (ones p.RtESize) num0
        elem dstA e p.ESize := AST.ite t2 (ones p.RtESize) num0
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let t = cmp (elem src1 e p.ESize) (elem src2 e p.ESize)
        elem dst e p.ESize := AST.ite t (ones p.RtESize) num0
    putEndLabel bld lblIgnore
  }

let getCmp (ins: Instruction) unsigned signed =
  if isUnsigned ins.SIMDTyp then unsigned else signed

let vceq (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> vectorCompareImm ins bld (==)
  | ThreeOperands(_, _, OprSIMD _) -> vectorCompareReg ins bld (==)
  | _ -> raise InvalidOperandException

let vcge (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    vectorCompareImm ins bld (getCmp ins AST.ge AST.sge)
  | ThreeOperands(_, _, OprSIMD _) ->
    vectorCompareReg ins bld (getCmp ins AST.ge AST.sge)
  | _ ->
    raise InvalidOperandException

let vcgt (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    vectorCompareImm ins bld (getCmp ins AST.gt AST.sgt)
  | ThreeOperands(_, _, OprSIMD _) ->
    vectorCompareReg ins bld (getCmp ins AST.gt AST.sgt)
  | _ ->
    raise InvalidOperandException

let vcle (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    vectorCompareImm ins bld (getCmp ins AST.le AST.sle)
  | ThreeOperands(_, _, OprSIMD _) ->
    vectorCompareReg ins bld (getCmp ins AST.le AST.sle)
  | _ ->
    raise InvalidOperandException

let vclt (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    vectorCompareImm ins bld (getCmp ins AST.lt AST.slt)
  | ThreeOperands(_, _, OprSIMD _) ->
    vectorCompareReg ins bld (getCmp ins AST.lt AST.slt)
  | _ ->
    raise InvalidOperandException

let vtst (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let n0 = AST.num0 p.RtESize
    let n1 = AST.num1 p.RtESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let c = (elem src1B e p.ESize .& elem src2B e p.ESize) != n0
        let c2 = (elem src1A e p.ESize .& elem src2A e p.ESize) != n0
        elem dstB e p.ESize := AST.ite c n1 n0
        elem dstA e p.ESize := AST.ite c2 n1 n0
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let c = (elem src1 e p.ESize .& elem src2 e p.ESize) != n0
        elem dst e p.ESize := AST.ite c n1 n0
    putEndLabel bld lblIgnore
  }

let vrshrn (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
    let rtEsz = RegType.fromBitWidth esize
    let elements = 64 / esize
    let struct (dst, src, imm) = getThreeOprs ins
    let dst = transOpr ins bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    let imm = AST.zext (rtEsz * 2) (transOpr ins bld imm)
    let roundConst = AST.num1 (rtEsz * 2) << (imm .- AST.num1 (rtEsz * 2))
    for e in 0 .. (elements / 2) - 1 do
      let result1 = (elem srcB e (esize * 2) .+ roundConst) >> imm
      let result2 = (elem srcA e (esize * 2) .+ roundConst) >> imm
      elem dst e esize := AST.xtlo rtEsz result1
      elem dst e esize := AST.xtlo rtEsz result2
    putEndLabel bld lblIgnore
  }

let vorrReg (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      dstB := src1B .| src2B
      dstA := src1A .| src2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := src1 .| src2
    putEndLabel bld lblIgnore
  }

let vorrImm (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, imm) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let imm =
        AST.concat (transOpr ins bld imm) (transOpr ins bld imm)
      dstB := dstB .| imm
      dstA := dstA .| imm
    | _ ->
      let struct (dst, imm) = transTwoOprs ins bld
      let imm = AST.concat imm imm // FIXME: A8-975
      dst := dst .| imm
    putEndLabel bld lblIgnore
  }

let vorr (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ -> vorrReg ins bld
  | TwoOperands _ -> vorrImm ins bld
  | _ -> raise InvalidOperandException

let vornReg (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      dstB := src1B .| (AST.not <| src2B)
      dstA := src1A .| (AST.not <| src2A)
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := src1 .| (AST.not <| src2)
    putEndLabel bld lblIgnore
  }

let vornImm (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, imm) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let imm =
        AST.concat (transOpr ins bld imm) (transOpr ins bld imm)
      dstB := dstB .| AST.not imm
      dstA := dstA .| AST.not imm
    | _ ->
      let struct (dst, imm) = transTwoOprs ins bld
      let imm = AST.concat imm imm // FIXME: A8-975
      dst := dst .| AST.not imm
    putEndLabel bld lblIgnore
  }

let vorn (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ -> vornReg ins bld
  | TwoOperands _ -> vornImm ins bld
  | _ -> raise InvalidOperandException

let parseDstList = function
  | TwoOperands(OprSIMD(OneReg(Vector d)), _) ->
    [ d ]
  | TwoOperands(OprSIMD(TwoRegs(Vector d1, Vector d2)), _) ->
    [ d1; d2 ]
  | TwoOperands(OprSIMD(ThreeRegs(Vector d1, Vector d2, Vector d3)), _) ->
    [ d1; d2; d3 ]
  | TwoOperands(OprSIMD(FourRegs(Vector d1,
                                 Vector d2,
                                 Vector d3,
                                 Vector d4)), _) ->
    [ d1; d2; d3; d4 ]
  | TwoOperands(OprSIMD(OneReg(Scalar(d, None))), _) ->
    [ d ]
  | TwoOperands(OprSIMD(TwoRegs(Scalar(d1, _), Scalar(d2, _))), _) ->
    [ d1; d2 ]
  | TwoOperands(OprSIMD(ThreeRegs(Scalar(d1, _),
                                  Scalar(d2, _),
                                  Scalar(d3, _))), _) ->
    [ d1; d2; d3 ]
  | TwoOperands(OprSIMD(FourRegs(Scalar(d1, _),
                                 Scalar(d2, _),
                                 Scalar(d3, _),
                                 Scalar(d4, _))), _) ->
    [ d1; d2; d3; d4 ]
  | _ ->
    raise InvalidOperandException

let getRnAndRm bld = function
  | TwoOperands(_, OprMemory(OffsetMode(AlignOffset(rn, _, _))))
  | TwoOperands(_, OprMemory(PreIdxMode(AlignOffset(rn, _, _)))) ->
    regVar bld rn, None
  | TwoOperands(_, OprMemory(PostIdxMode(AlignOffset(rn, _, Some rm)))) ->
    regVar bld rn, regVar bld rm |> Some
  | _ ->
    raise InvalidOperandException

let assignByEndian (bld: ILowUIRBuilder) dst src =
  append bld {
    let isbig = bld.Endianness = Endian.Big
    dst := if isbig then AST.xthi 32<rt> src else AST.xtlo 32<rt> src
  }

let parseOprOfVecStAndLd bld (ins: Instruction) =
  let rdList = parseDstList ins.Operands |> List.map (regVar bld)
  let rn, rm = getRnAndRm bld ins.Operands
  rdList, rn, rm

let updateRn (ins: Instruction) rn (rm: Expr option) n (regIdx: bool option) =
  let rmOrTransSz = if regIdx.Value then rm.Value else numI32 n 32<rt>
  if ins.WriteBack then rn .+ rmOrTransSz else rn

let incAddr addr n = addr .+ (numI32 n 32<rt>)

let vst1Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let regs = getRegs ins.Operands
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (8 * regs) p.RegIndex
    for r in 0 .. (regs - 1) do
      for e in 0 .. (p.Elements - 1) do
        if p.EBytes <> 8 then
          let mem = AST.loadLE p.RtESize addr
          mem := elem rdList[r] e p.ESize
        else
          let mem1 = AST.loadLE 32<rt> addr
          let mem2 = AST.loadLE 32<rt> (incAddr addr 4)
          let reg = elem rdList[r] e p.ESize
          assignByEndian bld mem1 reg
          assignByEndian bld mem2 reg
        addr := addr .+ (numI32 p.EBytes 32<rt>)
    putEndLabel bld lblIgnore
  }

let vst1Single (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rd, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm p.EBytes p.RegIndex
    let mem = AST.loadLE p.RtESize addr
    mem := elem rd[0] (int32 index) p.ESize
    putEndLabel bld lblIgnore
  }

let vst1 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(OneReg(Scalar(_, Some index))), _) ->
    vst1Single ins bld index
  | TwoOperands(OprSIMD(OneReg _), _)
  | TwoOperands(OprSIMD(TwoRegs _), _)
  | TwoOperands(OprSIMD(ThreeRegs _), _)
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vst1Multi ins bld
  | _ ->
    raise InvalidOperandException

let vld1SingleOne (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rd, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm p.EBytes p.RegIndex
    let mem = AST.loadLE p.RtESize addr
    elem rd[0] (int32 index) p.ESize := mem
    putEndLabel bld lblIgnore
  }

let vld1SingleAll (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm p.EBytes p.RegIndex
    let mem = AST.loadLE p.RtESize addr
    let repElem = Array.replicate p.Elements mem |> AST.revConcat
    for r in 0 .. (List.length rdList - 1) do
      append bld { rdList[r] := repElem } done
    putEndLabel bld lblIgnore
  }

let vld1Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let regs = getRegs ins.Operands
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (8 * regs) p.RegIndex
    for r in 0 .. (regs - 1) do
      for e in 0 .. (p.Elements - 1) do
        if p.EBytes <> 8 then
          let data = tmpVar bld p.RtESize
          data := AST.loadLE p.RtESize addr
          elem rdList[r] e p.ESize := data
        else
          let struct (data1, data2) = tmpVars2 bld 32<rt>
          let mem1 = AST.loadLE 32<rt> addr
          let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
          let isbig = bld.Endianness = Endian.Big
          data1 := if isbig then mem2 else mem1
          data2 := if isbig then mem1 else mem1
          elem rdList[r] e p.ESize := AST.concat data2 data1
        addr := incAddr addr p.EBytes
    putEndLabel bld lblIgnore
  }

let vld1 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(OneReg(Scalar(_, Some index))), _) ->
    vld1SingleOne ins bld index
  | TwoOperands(OprSIMD(OneReg(Scalar _)), _)
  | TwoOperands(OprSIMD(TwoRegs(Scalar _, Scalar _)), _) ->
    vld1SingleAll ins bld
  | TwoOperands(OprSIMD(OneReg _), _)
  | TwoOperands(OprSIMD(TwoRegs _), _)
  | TwoOperands(OprSIMD(ThreeRegs _), _)
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vld1Multi ins bld
  | _ ->
    raise InvalidOperandException

let vst2Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let regs = getRegs ins.Operands / 2
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (16 * regs) p.RegIndex
    for r in 0 .. (regs - 1) do
      let rd1 = rdList[r * 2]
      let rd2 = rdList[r * 2 + 1]
      for e in 0 .. (p.Elements - 1) do
        let mem1 = AST.loadLE p.RtESize addr
        let mem2 = AST.loadLE p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
        mem1 := elem rd1 e p.ESize
        mem2 := elem rd2 e p.ESize
        addr := addr .+ (numI32 (2 * p.EBytes) 32<rt>)
    putEndLabel bld lblIgnore
  }

let vst2Single (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (16 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
    mem1 := elem rdList[0] index p.ESize
    mem2 := elem rdList[1] index p.ESize
    putEndLabel bld lblIgnore
  }

let vst2 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(TwoRegs(Scalar(_, Some index), _)), _) ->
    vst2Single ins bld (int32 index)
  | TwoOperands(OprSIMD(OneReg _), _)
  | TwoOperands(OprSIMD(TwoRegs _), _)
  | TwoOperands(OprSIMD(ThreeRegs _), _)
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vst2Multi ins bld
  | _ ->
    raise InvalidOperandException

let vst3Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm 24 p.RegIndex
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
      let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
      mem1 := elem rdList[0] e p.ESize
      mem2 := elem rdList[1] e p.ESize
      mem3 := elem rdList[2] e p.ESize
      addr := incAddr addr (3 * p.EBytes)
    putEndLabel bld lblIgnore
  }

let vst3Single (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    mem1 := elem rdList[0] index p.ESize
    mem2 := elem rdList[1] index p.ESize
    mem3 := elem rdList[2] index p.ESize
    putEndLabel bld lblIgnore
  }

let vst3 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(ThreeRegs(Scalar(_, Some index), _, _)), _) ->
    vst3Single ins bld (int32 index)
  | TwoOperands(OprSIMD(OneReg _), _)
  | TwoOperands(OprSIMD(TwoRegs _), _)
  | TwoOperands(OprSIMD(ThreeRegs _), _)
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vst3Multi ins bld
  | _ ->
    raise InvalidOperandException

let vst4Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm 32 p.RegIndex
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
      let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
      let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
      mem1 := elem rdList[0] e p.ESize
      mem2 := elem rdList[1] e p.ESize
      mem3 := elem rdList[2] e p.ESize
      mem4 := elem rdList[3] e p.ESize
      addr := incAddr addr (4 * p.EBytes)
    putEndLabel bld lblIgnore
  }

let vst4Single (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    mem1 := elem rdList[0] index p.ESize
    mem2 := elem rdList[1] index p.ESize
    mem3 := elem rdList[2] index p.ESize
    mem4 := elem rdList[3] index p.ESize
    putEndLabel bld lblIgnore
  }

let vst4 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(FourRegs(Scalar(_, Some index), _, _, _)), _) ->
    vst4Single ins bld (int32 index)
  | TwoOperands(OprSIMD(OneReg _), _)
  | TwoOperands(OprSIMD(TwoRegs _), _)
  | TwoOperands(OprSIMD(ThreeRegs _), _)
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vst4Multi ins bld
  | _ ->
    raise InvalidOperandException

let vld2SingleOne (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    elem rdList[0] (int32 index) p.ESize := mem1
    elem rdList[1] (int32 index) p.ESize := mem2
    putEndLabel bld lblIgnore
  }

let vld2SingleAll (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let repElem1 = Array.replicate p.Elements mem1 |> AST.revConcat
    let repElem2 = Array.replicate p.Elements mem2 |> AST.revConcat
    rdList[0] := repElem1
    rdList[1] := repElem2
    putEndLabel bld lblIgnore
  }

let vld2Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let regs = getRegs ins.Operands / 2
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (16 * regs) p.RegIndex
    for r in 0 .. (regs - 1) do
      let rd1 = rdList[r * 2]
      let rd2 = rdList[r * 2 + 1]
      for e in 0 .. (p.Elements - 1) do
        let mem1 = AST.loadLE p.RtESize addr
        let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
        elem rd1 e p.ESize := mem1
        elem rd2 e p.ESize := mem2
        addr := incAddr addr (2 * p.EBytes)
    putEndLabel bld lblIgnore
  }

let vld2 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(TwoRegs(Scalar(_, Some index), _)), _) ->
    vld2SingleOne ins bld index
  | TwoOperands(OprSIMD(TwoRegs(Scalar _, Scalar _)), _) ->
    vld2SingleAll ins bld
  | TwoOperands(OprSIMD(TwoRegs _), _)
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vld2Multi ins bld
  | _ ->
    raise InvalidOperandException

let vld3SingleOne (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    elem rdList[0] (int32 index) p.ESize := mem1
    elem rdList[1] (int32 index) p.ESize := mem2
    elem rdList[2] (int32 index) p.ESize := mem3
    putEndLabel bld lblIgnore
  }

let vld3SingleAll (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let repElem1 = Array.replicate p.Elements mem1 |> AST.revConcat
    let repElem2 = Array.replicate p.Elements mem2 |> AST.revConcat
    let repElem3 = Array.replicate p.Elements mem3 |> AST.revConcat
    rdList[0] := repElem1
    rdList[1] := repElem2
    rdList[2] := repElem3
    putEndLabel bld lblIgnore
  }

let vld3Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm 24 p.RegIndex
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
      let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
      elem rdList[0] e p.ESize := mem1
      elem rdList[1] e p.ESize := mem2
      elem rdList[2] e p.ESize := mem3
      addr := addr .+ (numI32 (3 * p.EBytes) 32<rt>)
    putEndLabel bld lblIgnore
  }

let vld3 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(ThreeRegs(Scalar(_, Some index), _, _)), _) ->
    vld3SingleOne ins bld index
  | TwoOperands(OprSIMD(ThreeRegs(Scalar(_, None), _, _)), _) ->
    vld3SingleAll ins bld
  | TwoOperands(OprSIMD(ThreeRegs _), _) ->
    vld3Multi ins bld
  | _ ->
    raise InvalidOperandException

let vld4SingleOne (ins: Instruction) bld index =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    elem rdList[0] (int32 index) p.ESize := mem1
    elem rdList[1] (int32 index) p.ESize := mem2
    elem rdList[2] (int32 index) p.ESize := mem3
    elem rdList[3] (int32 index) p.ESize := mem4
    putEndLabel bld lblIgnore
  }

let vld4SingleAll (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    let repElem1 = Array.replicate p.Elements mem1 |> AST.revConcat
    let repElem2 = Array.replicate p.Elements mem2 |> AST.revConcat
    let repElem3 = Array.replicate p.Elements mem3 |> AST.revConcat
    let repElem4 = Array.replicate p.Elements mem4 |> AST.revConcat
    rdList[0] := repElem1
    rdList[1] := repElem2
    rdList[2] := repElem3
    rdList[3] := repElem4
    putEndLabel bld lblIgnore
  }

let vld4Multi (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rdList, rn, rm = parseOprOfVecStAndLd bld ins
    let p = getParsingInfo ins
    let addr = tmpVar bld 32<rt>
    addr := rn
    rn := updateRn ins rn rm 24 p.RegIndex
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
      let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
      let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
      elem rdList[0] e p.ESize := mem1
      elem rdList[1] e p.ESize := mem2
      elem rdList[2] e p.ESize := mem3
      elem rdList[3] e p.ESize := mem4
      addr := addr .+ (numI32 (4 * p.EBytes) 32<rt>)
    putEndLabel bld lblIgnore
  }

let vld4 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSIMD(FourRegs(Scalar(_, Some index), _, _, _)), _) ->
    vld4SingleOne ins bld index
  | TwoOperands(OprSIMD(FourRegs(Scalar(_, None), _, _, _)), _) ->
    vld4SingleAll ins bld
  | TwoOperands(OprSIMD(FourRegs _), _) ->
    vld4Multi ins bld
  | _ ->
    raise InvalidOperandException

let udf (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand(OprImm n) -> sideEffects ins bld (Interrupt(int n))
  | _ -> raise InvalidOperandException

let uasx (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let cpsr = regVar bld R.CPSR
    let struct (diff, sum) = tmpVars2 bld 32<rt>
    let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
    let struct (ge10, ge32) = tmpVars2 bld 32<rt>
    let numI32 n = numI32 n 32<rt>
    diff := xtlo src1 .- xthi src2
    sum := xthi src1 .+ xtlo src2
    dst := AST.concat (AST.xtlo 16<rt> sum) (AST.xtlo 16<rt> diff)
    ge10 := AST.ite (diff .>= numI32 0) (numI32 0xC0000) (numI32 0)
    ge32 := AST.ite (sum .>= numI32 0x10000) (numI32 0x30000) (numI32 0)
    cpsr := (cpsr .& (numI32 0xFFF0FFFF)) .| (ge32 .| ge10)
    putEndLabel bld lblIgnore
  }

let uhsub16 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (diff1, diff2) = tmpVars2 bld 32<rt>
    let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
    let n1 = AST.num1 32<rt>
    diff1 := xtlo src1 .- xtlo src2
    diff2 := xthi src1 .- xthi src2
    dst :=
      AST.concat (AST.xtlo 16<rt> (diff2 >> n1)) (AST.xtlo 16<rt> (diff1 >> n1))
    putEndLabel bld lblIgnore
  }

let uqsax (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (sum, diff) = tmpVars2 bld 32<rt>
    let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
    sum := xtlo src1 .+ xthi src2
    diff := xthi src1 .- xtlo src2
    dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum)
    putEndLabel bld lblIgnore
  }

let usax (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let cpsr = regVar bld R.CPSR
    let struct (sum, diff) = tmpVars2 bld 32<rt>
    let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
    let struct (ge10, ge32) = tmpVars2 bld 32<rt>
    let numI32 n = numI32 n 32<rt>
    sum := xtlo src1 .+ xthi src2
    diff := xthi src1 .- xtlo src2
    dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum)
    ge10 := AST.ite (sum .>= numI32 0x10000) (numI32 0x30000) (numI32 0)
    ge32 := AST.ite (diff .>= numI32 0) (numI32 0xC0000) (numI32 0)
    cpsr := (cpsr .& (numI32 0xFFF0FFFF)) .| (ge10 .| ge32)
    putEndLabel bld lblIgnore
  }

let vext (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2, imm) = getFourOprs ins
    let imm = getImmValue imm
    let rightAmt = numI64 ((8L * imm) % 64L) 64<rt>
    let leftAmt = numI64 (64L - ((8L * imm) % 64L)) 64<rt>
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      let struct (tSrc1B, tSrc1A, tSrc2B, tSrc2A) = tmpVars4 bld 64<rt>
      tSrc1A := src1A
      tSrc1B := src1B
      tSrc2A := src2A
      tSrc2B := src2B
      if 8L * imm < 64L then
        dstA := (tSrc1B << leftAmt) .| (tSrc1A >> rightAmt)
        dstB := (tSrc2A << leftAmt) .| (tSrc1B >> rightAmt)
      else
        dstA := (tSrc2A << leftAmt) .| (tSrc1B >> rightAmt)
        dstB := (tSrc2B << leftAmt) .| (tSrc2A >> rightAmt)
    | _ ->
      let struct (dst, src1, src2, _imm) = transFourOprs ins bld
      let struct (tSrc2, tSrc1) = tmpVars2 bld 64<rt>
      tSrc1 := src1
      tSrc2 := src2
      dst := (tSrc2 << leftAmt) .| (tSrc1 >> rightAmt)
    putEndLabel bld lblIgnore
  }

let vhaddsub (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      let struct (op1B, op2B, op1A, op2A) = tmpVars4 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1B := elem src1B e p.ESize
        op2B := elem src2B e p.ESize
        op1A := elem src1A e p.ESize
        op2A := elem src2A e p.ESize
        elem dstB e p.ESize := (opFn op1B op2B) >> (AST.num1 p.RtESize)
        elem dstA e p.ESize := (opFn op1A op2A) >> (AST.num1 p.RtESize)
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := (opFn op1 op2) >> (AST.num1 p.RtESize)
    putEndLabel bld lblIgnore
  }

let vrhadd (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (op1, op2) = tmpVars2 bld p.RtESize
    let n1 = AST.num1 p.RtESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. (64 / p.ESize) - 1 do
        op1 := elem src1B e p.ESize .+ elem src2B e p.ESize .+ n1
        op2 := elem src1A e p.ESize .+ elem src2A e p.ESize .+ n1
        elem dstB e p.ESize := AST.xtlo p.RtESize (op1 >> n1)
        elem dstA e p.ESize := AST.xtlo p.RtESize (op2 >> n1)
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. (64 / p.ESize) - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        let result = op1 .+ op2 .+ n1
        elem dst e p.ESize := AST.xtlo p.RtESize (result >> n1)
    putEndLabel bld lblIgnore
  }

let vsra (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (result1, result2, shfAmt) = tmpVars3 bld p.RtESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, imm) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let imm = transOpr ins bld imm
      shfAmt := if p.RtESize = 64<rt> then AST.zext p.RtESize imm
              else AST.xtlo p.RtESize imm
      for e in 0 .. p.Elements - 1 do
        result1 := srcB >> shfAmt
        result2 := srcA >> shfAmt
        dstB := dstB .+ result1
        dstA := dstA .+ result2
    | _ ->
      let struct (dst, src, imm) = transThreeOprs ins bld
      shfAmt := if p.RtESize = 64<rt> then AST.zext p.RtESize imm
              else AST.xtlo p.RtESize imm
      for e in 0 .. p.Elements - 1 do
        result1 := src >> shfAmt
        dst := dst .+ result1
    putEndLabel bld lblIgnore
  }

/// Deinterleaves the lanes of a pair of quadword operands, which is what VUZP
/// does to the wider form.
let private vuzpQ ins bld p elements (zip1B, zip1A, zip2B, zip2A) =
  append bld {
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    if dstB = srcB && dstA = srcA then
      dstB := AST.undef 64<rt> "UNKNOWN"
      dstA := AST.undef 64<rt> "UNKNOWN"
      srcB := AST.undef 64<rt> "UNKNOWN"
      srcA := AST.undef 64<rt> "UNKNOWN"
    else
      zip1B := srcB
      zip1A := srcA
      zip2B := dstB
      zip2A := dstA
      for e in 0 .. elements do
        let pos = e + p.Elements / 2
        elem dstB pos p.ESize := elem zip1B (e * 2) p.ESize
        elem srcB pos p.ESize := elem zip1B (e * 2 + 1) p.ESize
        elem dstB e p.ESize := elem zip1A (e * 2) p.ESize
        elem srcB e p.ESize := elem zip1A (e * 2 + 1) p.ESize
        elem dstA pos p.ESize := elem zip2B (e * 2) p.ESize
        elem srcA pos p.ESize := elem zip2B (e * 2 + 1) p.ESize
        elem dstA e p.ESize := elem zip2A (e * 2) p.ESize
        elem srcA e p.ESize := elem zip2A (e * 2 + 1) p.ESize
  }

let vuzp (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (zip1B, zip1A, zip2B, zip2A) = tmpVars4 bld 64<rt>
    let elements = (p.Elements - 1) / 2
    match ins.OprSize with
    | 128<rt> ->
      vuzpQ ins bld p elements (zip1B, zip1A, zip2B, zip2A)
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      if dst = src then
        dst := AST.undef ins.OprSize "UNKNOWN"
        src := AST.undef ins.OprSize "UNKNOWN"
      else
        zip1B := src
        zip1A := dst
        for e in 0 .. elements do
          let pos = e + p.Elements / 2
          elem dst e p.ESize := elem zip1B (e * 2) p.ESize
          elem src e p.ESize := elem zip1B (e * 2 + 1) p.ESize
          elem dst pos p.ESize := elem zip1A (e * 2) p.ESize
          elem src pos p.ESize := elem zip1A (e * 2 + 1) p.ESize
    putEndLabel bld lblIgnore
  }
