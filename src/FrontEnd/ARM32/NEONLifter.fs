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
      data := loadNative bld 32<rt> addr
      rd := data
    else
      let struct (d1, d2) = tmpVars2 bld 32<rt>
      d1 := loadNative bld 32<rt> addr
      d2 := loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
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
      loadNative bld 32<rt> addr := rd
    else
      let mem1 = loadNative bld 32<rt> addr
      let mem2 = loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
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
        regVar bld reg := loadNative bld 32<rt> addr
      }
      singleRegLoop (r + 1) nextAddr
    else
      ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let word1 = loadNative bld 32<rt> addr
      let word2 = loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
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
        loadNative bld 32<rt> addr := regVar bld reg
      }
      singleRegLoop (r + 1) nextAddr
    else
      ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let mem1 = loadNative bld 32<rt> addr
      let mem2 = loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
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

/// <summary>
/// VMSR, which does not keep every bit it is handed.
///
/// FPSCR has two bits that are RES0, 6 and 5, and a row of trap enables --
/// IDE at 15 and IXE through IOE at 12:8 -- that an implementation without
/// trapped floating-point exceptions leaves read-as-zero, write-ignored.
/// There is no FP trapping anywhere in this front end, so storing those bits
/// would let a program read back a mode nothing here can enter; the reference
/// answers 0xffff009f to all ones written and read straight back, and the
/// bits that vanish are exactly these.
///
/// Length and stride, 21:20 and 18:16, are NOT among them: short vectors are
/// part of VFPv4 and the field is writable there.
///
/// The mask is FPSCR's alone, so a VMSR naming another system register --
/// FPEXC is the one an implementation may allow -- stores what it was given.
/// </summary>
let vmsr ins bld =
  lift bld ins {
    let struct (dst, rt) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.Operands with
    | TwoOperands(OprReg R.FPSCR, _) ->
      dst := rt .& numU32 0xffff009fu 32<rt>
    | _ ->
      dst := rt
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
    unsupported ins bld

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

/// Whether a structure access steps its base by a register rather than by
/// its own size, from either of the shapes its memory operand is decoded in
/// -- see <see cref="getRnAndRm"/>.
let registerIndex = function
  | TwoOperands(_, OprMemory(OffsetMode(AlignOffset _)))
  | TwoOperands(_, OprMemory(PreIdxMode(AlignOffset _)))
  | TwoOperands(_, OprMemory(OffsetMode(ImmOffset _)))
  | TwoOperands(_, OprMemory(PreIdxMode(ImmOffset _))) -> Some false
  | TwoOperands(_, OprMemory(PostIdxMode(AlignOffset _)))
  | TwoOperands(_, OprMemory(PostIdxMode(RegOffset _))) -> Some true
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

/// <summary>
/// A shift or fraction immediate at the width the arithmetic wants it.
///
/// The operand arrives at the width of the instruction's REGISTERS, which for
/// a quadword form is sixty-four bits, and it feeds arithmetic done at the
/// width of an ELEMENT. A zero-extension cannot narrow, so asking for one
/// raises instead of truncating -- which is what VSHL and VRSHRN did, at lift
/// time, for every quadword form they have.
/// </summary>
let private immAt width e =
  let sz = Expr.typeOf e
  if sz = width then e
  elif sz > width then AST.xtlo width e
  else AST.zext width e

/// <summary>
/// The immediate of a SIMD move, filled out to the width of the register it
/// is written into.
///
/// The operand carries the immediate the DISASSEMBLY names: VMOV.I8 is
/// written with eight bits and printed with eight, and AdvSIMDExpandImm's
/// answer is masked back down to them on the way out of the parser. What the
/// instruction writes is a copy of it in every element, so assigning it as it
/// stands leaves the first element set and the rest zero -- VMOV.I8 Dd, #255
/// filled a register with 0xff rather than with eight of them, and the guests
/// that build an all-ones vector that way came out wrong from there on.
/// </summary>
let private replicatedImm (p: ParsingInfo) imm =
  let rec fill acc shift =
    if shift >= 64 then acc
    else fill (acc .| (imm << numI32 shift 64<rt>)) (shift + p.ESize)
  fill imm p.ESize

let parseOprOfVMOV (ins: Instruction) bld =
  match ins.Operands with
  (* VMOV (immediate) *)
  | TwoOperands(OprSIMD _, OprImm _) ->
    let struct (dst, imm) = getTwoOprs ins
    let imm = transOpr ins bld imm |> replicatedImm (getParsingInfo ins)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 bld dst
      append bld {
        dstB := imm
        dstA := imm
      }
    | _ ->
      let dst = transOpr ins bld dst
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

/// Whether a VMOV is the Advanced SIMD one that copies a single-precision
/// constant into every lane of a doubleword or quadword, rather than the
/// floating-point one that writes a single register.
let isSIMDF32Imm (ins: Instruction) =
  match ins.SIMDTyp, ins.Operands with
  | Some(OneDT SIMDTypF32), TwoOperands(_, OprImm _) -> ins.OprSize > 32<rt>
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

/// <summary>
/// The NaN a VFP operation answers with where it had no operand to propagate.
///
/// FPDefaultNaN is a fixed constant and, on ARM as on AArch64, a POSITIVE
/// one. IEEE 754 does not say which NaN an invalid operation produces, so an
/// evaluator answers with its host's, and the one x86 makes has its sign bit
/// set. Nothing but the front end knows which of the two the architecture
/// means.
/// </summary>
let private fpDefaultNan esize =
  match esize with
  | 16 -> numU32 0x7e00u 16<rt>
  | 32 -> numU32 0x7fc00000u 32<rt>
  | _ -> numU64 0x7ff8000000000000UL 64<rt>

/// Whether the value has every exponent bit set and a mantissa that is not
/// zero, which is what makes it a NaN.
let private isNaNOf esize e =
  match esize with
  | 16 ->
    ((e .& numU32 0x7c00u 16<rt>) == numU32 0x7c00u 16<rt>)
    .& ((e .& numU32 0x3ffu 16<rt>) != AST.num0 16<rt>)
  | 32 ->
    ((e .& numU32 0x7f800000u 32<rt>) == numU32 0x7f800000u 32<rt>)
    .& ((e .& numU32 0x7fffffu 32<rt>) != AST.num0 32<rt>)
  | _ ->
    ((e .& numU64 0x7ff0000000000000UL 64<rt>)
     == numU64 0x7ff0000000000000UL 64<rt>)
    .& ((e .& numU64 0xfffffffffffffUL 64<rt>) != AST.num0 64<rt>)

/// A NaN made quiet, which is the top mantissa bit set. The manual's
/// FPProcessNaN does this to a signalling NaN and leaves a quiet one alone,
/// and setting a bit that is already set is the same thing -- so one
/// expression serves both and no test is needed to tell them apart.
let private quietNaNOf esize e =
  match esize with
  | 16 -> e .| numU32 0x200u 16<rt>
  | 32 -> e .| numU32 0x400000u 32<rt>
  | _ -> e .| numU64 0x8000000000000UL 64<rt>

/// The zero test that goes with it: the sign bit ignored, everything else
/// clear. The square root of minus zero is minus zero and not an invalid
/// operation, so it has to be told apart from a negative.
let private isZeroOf esize e =
  match esize with
  | 16 -> (e .& numU32 0x7fffu 16<rt>) == AST.num0 16<rt>
  | 32 -> (e .& numU32 0x7fffffffu 32<rt>) == AST.num0 32<rt>
  | _ -> (e .& numU64 0x7fffffffffffffffUL 64<rt>) == AST.num0 64<rt>

/// <summary>
/// VSQRT.
///
/// A NaN operand comes back QUIET -- a signalling one has its top mantissa
/// bit set, which is what the reference does and what returning the operand
/// unchanged got wrong; a negative operand that is not a zero
/// is an invalid operation and answers the default NaN; everything else,
/// minus zero and positive infinity included, is what the arithmetic gives.
/// The negative arm is why this is written out rather than left to a bare
/// square root, which answers with whatever NaN the host makes.
/// </summary>
let private sqrtOf bld esize e =
  let rt = RegType.fromBitWidth esize
  let res = tmpVar bld rt
  let struct (nan, zero, sign) = tmpVars3 bld 1<rt>
  append bld {
    nan := isNaNOf esize e
    zero := isZeroOf esize e
    sign := AST.xthi 1<rt> e
    let negative = sign .& AST.not zero
    let ofNumber = AST.ite negative (fpDefaultNan esize) (AST.fsqrt e)
    res := AST.ite nan (quietNaNOf esize e) ofNumber
  }
  res

let vsqrtf (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match (getParsingInfo ins).ESize with
    | 16 ->
      append bld {
        dst := AST.zext 32<rt> (sqrtOf bld 16 (AST.xtlo 16<rt> src))
      }
    | esize ->
      append bld { dst := sqrtOf bld esize src }
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

/// <summary>
/// The VFP scalar FUSED multiply-accumulate family: VFMA, VFMS, VFNMA and
/// VFNMS.
///
/// These sit beside VMLA and VMLS, which are the unfused pair and keep the
/// function above. The ARM manual gives this four as FPMulAdd, one operation
/// that rounds once, and gives VMLA and VMLS as a multiply and an add that
/// round twice. An instruction set that carries both is telling them apart,
/// so writing this four the way that four are written lifts the wrong
/// instruction.
///
/// negN and negD say which operands the manual passes through FPNeg: Sn for
/// VFMS and VFNMA, Sd for VFNMA and VFNMS. FPNeg flips the sign bit of
/// whatever it is given, a NaN included, so the flip is made on the operand
/// before the multiply-add. Asking the multiply-add to negate its product or
/// its addend gives the same answer on every number and hands a NaN back with
/// the sign it went in with.
/// </summary>
let vfpFusedMulAcc (ins: Instruction) bld negN negD =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let neg esize flag e = if flag then fpNegBits esize e else e
    let fused sz x y z =
      let esize = RegType.toBitWidth sz
      fma sz false false (neg esize negN x) y (neg esize negD z)
    match (getParsingInfo ins).ESize with
    | 16 ->
      let half e = AST.xtlo 16<rt> e
      dst := AST.zext 32<rt> (fused 16<rt> (half src1) (half src2) (half dst))
    | 32 ->
      dst := fused 32<rt> src1 src2 dst
    | _ ->
      dst := fused 64<rt> src1 src2 dst
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
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let struct (op1, op2) = tmpVars2 bld 64<rt>
    (* The sources are read as they were before the first result lane is
       written, because the destination can be one of them. *)
    op1 := transOpr ins bld src1
    op2 := transOpr ins bld src2
    let sum e =
      ext (p.RtESize * 2) (elem op1 e p.ESize)
      .+ ext (p.RtESize * 2) (elem op2 e p.ESize)
    for e in 0 .. (p.Elements - 1) / 2 do
      elem dstA e (2 * p.ESize) := sum e
      elem dstB e (2 * p.ESize) := sum (e + p.Elements / 2)
    putEndLabel bld lblIgnore
  }

/// The conversion VCVT names, as the function that performs it and the width
/// it leaves its result in.
let vcvtCastKind =
  let fext = AST.cast CastKind.FloatCast
  let ofSInt = AST.cast CastKind.SIntToFloat
  let ofUInt = AST.cast CastKind.UIntToFloat
  let toInt = AST.floatToSInt RoundingMode.TowardZero
  function
  (* float <-> float *)
  | Some(TwoDT(SIMDTypF32, SIMDTypF64)) -> struct (fext, 32<rt>)
  | Some(TwoDT(SIMDTypF64, SIMDTypF32)) -> struct (fext, 64<rt>)
  (* int -> float *)
  | Some(TwoDT(SIMDTypF32, SIMDTypS32)) -> struct (ofSInt, 32<rt>)
  | Some(TwoDT(SIMDTypF64, SIMDTypS32)) -> struct (ofSInt, 64<rt>)
  | Some(TwoDT(SIMDTypF32, SIMDTypU32)) -> struct (ofUInt, 32<rt>)
  | Some(TwoDT(SIMDTypF64, SIMDTypU32)) -> struct (ofUInt, 64<rt>)
  (* float -> int (round toward zero) *)
  | Some(TwoDT(SIMDTypS32, SIMDTypF32))
  | Some(TwoDT(SIMDTypU32, SIMDTypF32)) -> struct (toInt, 32<rt>)
  | Some(TwoDT(SIMDTypS32, SIMDTypF64))
  | Some(TwoDT(SIMDTypU32, SIMDTypF64)) -> struct (toInt, 32<rt>)
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
          dst :=
            AST.xtlo 32<rt>
              (AST.floatToSInt RoundingMode.TowardZero 64<rt> src)
        }
      | _ ->
        let struct (conv, size) = vcvtCastKind ins.SIMDTyp
        append bld {
          dst := conv size src
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
    (* HighestSetBit of zero is -1, which makes the count for a zero lane the
       whole width; the loop above stops at bit 0 and would answer one less. *)
    dst :=
      AST.ite (src == AST.num0 oprSz) (width .+ AST.num1 oprSz) (width .- t)
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
      let mem1 = loadNative bld 32<rt> addr
      let mem2 = loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
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
      let word1 = loadNative bld 32<rt> addr
      let word2 = loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
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
    (* Subtracting the product, which adding its NOT is one short of. *)
    let acc = if add then (.+) else (.-)
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
        elem dstB e p.ESize := acc (elem dstB e p.ESize) productB
        elem dstA e p.ESize := acc (elem dstA e p.ESize) productA
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let sext1 = AST.sext p.RtESize (elem src1 e p.ESize)
        let sext2 = AST.sext p.RtESize (elem src2 e p.ESize)
        elem dst e p.ESize := acc (elem dst e p.ESize) (sext1 .* sext2)
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
    let struct (op1, op2) = tmpVars2 bld 64<rt>
    (* Din: the destination can be one of the sources. *)
    op1 := transOpr ins bld src1
    op2 := transOpr ins bld src2
    let acc = if add then (.+) else (.-)
    for e in 0 .. (p.Elements - 1) / 2 do
      let extend expr =
        if unsigned then AST.zext (p.RtESize * 2) expr
        else AST.sext (p.RtESize * 2) expr
      let productA =
        extend (elem op1 e p.ESize) .* extend (elem op2 e p.ESize)
      let productB = extend (elem op1 (e + p.Elements / 2) p.ESize) .*
                     extend (elem op2 (e + p.Elements / 2) p.ESize)
      elem dstB e (p.ESize * 2) := acc (elem dstB e (p.ESize * 2)) productB
      elem dstA e (p.ESize * 2) := acc (elem dstA e (p.ESize * 2)) productA
    putEndLabel bld lblIgnore
  }

let vecMulAccOrSubByScalar (ins: Instruction) bld add =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let src2, index = transOprToScalar bld src2
    let op2Val = tmpVar bld p.RtESize
    (* The scalar is read once, before any lane is written: it can be a lane
       of the destination itself. *)
    op2Val := elem src2 index p.ESize
    let acc = if add then (.+) else (.-)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      for e in 0 .. p.Elements - 1 do
        let op1valA = AST.sext p.RtESize (elem src1A e p.ESize)
        let op1valB = AST.sext p.RtESize (elem src1B e p.ESize)
        elem dstB e p.ESize := acc (elem dstB e p.ESize) (op1valB .* op2Val)
        elem dstA e p.ESize := acc (elem dstA e p.ESize) (op1valA .* op2Val)
    | _ ->
      let dst = transOpr ins bld dst
      let src1 = transOpr ins bld src1
      for e in 0 .. p.Elements - 1 do
        let op1val = AST.sext p.RtESize (elem src1 e p.ESize)
        elem dst e p.ESize := acc (elem dst e p.ESize) (op1val .* op2Val)
    putEndLabel bld lblIgnore
  }

let vecMulAccOrSubLongByScalar (ins: Instruction) bld add =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let src2, index = transOprToScalar bld src2
    let p = getParsingInfo ins
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let op1 = tmpVar bld 64<rt>
    let scalar = tmpVar bld p.RtESize
    (* Din: the destination can hold the vector operand and the scalar. *)
    op1 := transOpr ins bld src1
    scalar := elem src2 index p.ESize
    let op2val = ext (p.RtESize * 2) scalar
    let acc = if add then (.+) else (.-)
    for e in 0 .. (p.Elements - 1) / 2 do
      let op1valA = ext (p.RtESize * 2) (elem op1 e p.ESize)
      let op1valB = ext (p.RtESize * 2) (elem op1 (e + p.Elements / 2) p.ESize)
      elem dstB e (p.ESize * 2) :=
        acc (elem dstB e (p.ESize * 2)) (op1valB .* op2val)
      elem dstA e (p.ESize * 2) :=
        acc (elem dstA e (p.ESize * 2)) (op1valA .* op2val)
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
    (* The product is built up from nothing; res is a scratch variable that
       still holds whatever the previous lane left in it. *)
    res := AST.num0 rtsize
    for i = 0 to size - 1 do
      let cond = AST.extract op1 1<rt> i
      res := AST.ite cond (res <+> (extendedOP2 << numI32 i rtsize)) res
  }

let polynomialMultP64 op1 op2 size rtsize resA resB bld =
  append bld {
    resA := AST.num0 rtsize
    resB := AST.num0 rtsize
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
    let struct (op1, op2) = tmpVars2 bld 64<rt>
    (* Din: the destination can be one of the sources. *)
    op1 := transOpr ins bld src1
    op2 := transOpr ins bld src2
    let isPolyAndE64 = polynomial && p.ESize = 64
    let struct (regSize, eSize) =
      if isPolyAndE64 then p.RtESize, p.ESize else p.RtESize * 2, p.ESize * 2
    let struct (resA, resB) = tmpVars2 bld regSize
    for e in 0 .. (p.Elements - 1) / 2 do
      let struct (op1A, op2A, op1B, op2B) =
        let src1A = elem op1 e p.ESize
        let src2A = elem op2 e p.ESize
        let src1B = elem op1 (e + p.Elements / 2) p.ESize
        let src2B = elem op2 (e + p.Elements / 2) p.ESize
        src1A, src2A, src1B, src2B
      if isPolyAndE64 then
        polynomialMultP64 op1A op2A p.ESize p.RtESize resA resB bld
      elif polynomial then
        polynomialMult op1A op2A p.ESize (p.RtESize * 2) resA bld
        polynomialMult op1B op2B p.ESize (p.RtESize * 2) resB bld
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
    let src2, index = transOprToScalar bld src2
    let p = getParsingInfo ins
    let op1 = tmpVar bld 64<rt>
    let op2val = tmpVar bld p.RtESize
    (* Din: the destination can hold the vector operand and the scalar. *)
    op1 := transOpr ins bld src1
    op2val := elem src2 index p.ESize
    let pele2 = p.Elements / 2
    for e in 0 .. (p.Elements - 1) / 2 do
      let resA = unsignExtend ins p 2 (elem op1 e p.ESize) op2val (.*)
      let resB =
        unsignExtend ins p 2 (elem op1 (e + pele2) p.ESize) op2val (.*)
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

/// <summary>
/// The same, for a narrowing whose data type carries a SIGNEDNESS.
///
/// VMOVN's type is an integer one and says nothing about sign, because a
/// truncation does not care. A saturating narrowing does -- what it clamps to
/// depends on it -- so its type is signed or unsigned and the plain reader
/// above rejects it.
/// </summary>
let getNarrowSizeStart = function
  | Some(OneDT SIMDTypI16)
  | Some(OneDT SIMDTypS16)
  | Some(OneDT SIMDTypU16) -> 0b00
  | Some(OneDT SIMDTypI32)
  | Some(OneDT SIMDTypS32)
  | Some(OneDT SIMDTypU32) -> 0b01
  | Some(OneDT SIMDTypI64)
  | Some(OneDT SIMDTypS64)
  | Some(OneDT SIMDTypU64) -> 0b10
  | _ -> raise InvalidOperandException

/// VMOVN: the low half of every lane of a quadword, as a doubleword of lanes
/// half as wide. esize below is the NARROW size, and each source lane is twice
/// that; lane 0 of the lower source register becomes lane 0 of the result.
let vmovn (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
    let rtEsz = RegType.fromBitWidth esize
    let perReg = 32 / esize
    let struct (lo, hi) = tmpVars2 bld 64<rt>
    (* Qin: the destination can be one half of the source. *)
    lo := srcA
    hi := srcB
    for e in 0 .. perReg - 1 do
      elem dst e esize := AST.xtlo rtEsz (elem lo e (2 * esize))
      elem dst (e + perReg) esize := AST.xtlo rtEsz (elem hi e (2 * esize))
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

/// The immediate of a shift, as the number of bits it shifts by.
let private shiftAmountOf (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm imm) -> int imm
  | _ -> raise InvalidOperandException

/// One lane shifted right by an immediate between 1 and the lane's width,
/// arithmetically for a signed type. The shift is made at 64 bits, where a
/// narrower lane's shift by its whole width still fits. A 64-bit lane shifted
/// by 64 keeps nothing but its sign, which is what a shift by 63 gives too,
/// or nothing at all when it is unsigned.
let private shiftRightLane p signed shift e =
  if signed then
    AST.xtlo p.RtESize (AST.sext 64<rt> e ?>> numI32 (min shift 63) 64<rt>)
  elif shift >= 64 then
    AST.num0 p.RtESize
  else
    AST.xtlo p.RtESize (AST.zext 64<rt> e >> numI32 shift 64<rt>)

/// The same shift, rounded: the last bit shifted out is added back. That is
/// (x + 2^(shift-1)) >> shift without forming the sum, which has no room in a
/// 64-bit lane.
let private roundingShiftRightLane p signed shift e =
  let last = AST.zext 64<rt> e >> numI32 (shift - 1) 64<rt>
  let round = AST.xtlo p.RtESize (last .& AST.num1 64<rt>)
  shiftRightLane p signed shift e .+ round

let vrshr (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let signed = not (isUnsigned ins.SIMDTyp)
    let shift = shiftAmountOf ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, _) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize :=
          roundingShiftRightLane p signed shift (elem srcB e p.ESize)
        elem dstA e p.ESize :=
          roundingShiftRightLane p signed shift (elem srcA e p.ESize)
    | _ ->
      let struct (dst, src, _) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        elem dst e p.ESize :=
          roundingShiftRightLane p signed shift (elem src e p.ESize)
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
      let imm = immAt p.RtESize (transOpr ins bld imm)
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := elem srcB e p.ESize << imm
        elem dstA e p.ESize := elem srcA e p.ESize << imm
    | _ ->
      let struct (dst, src, imm) = transThreeOprs ins bld
      let imm = immAt p.RtESize imm
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
    let signed = not (isUnsigned ins.SIMDTyp)
    let shift = shiftAmountOf ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, _) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let shifted v e = shiftRightLane p signed shift (elem v e p.ESize)
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := shifted srcB e
        elem dstA e p.ESize := shifted srcA e
    | _ ->
      let struct (dst, src, _) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        elem dst e p.ESize := shiftRightLane p signed shift (elem src e p.ESize)
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
    (* The table is as wide as the list is long, and no wider. It used to be
       widened to 256 bits whatever the list held, so a one-register VTBL --
       the common form -- asked an evaluator for a 256-bit shift to read a
       64-bit table, and got nothing back. *)
    let tableSz = RegType.fromBitWidth (64 * length)
    let table = AST.revConcat (List.toArray vectors)
    for i in 0 .. 7 do
      let index = elem rm i 8
      let cond = AST.lt index (numI32 (8 * length) 8<rt>)
      let e = if isVtbl then AST.num0 8<rt> else elem rd i 8
      elem rd i 8 := AST.ite cond (elemForIR table tableSz index 8) e
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

/// <summary>
/// VACGE, VACGT, VACLE and VACLT: the floating-point compares taken on the
/// MAGNITUDES.
///
/// An absolute value is the sign bit cleared and nothing else, so it needs no
/// arithmetic -- and doing it that way leaves a NaN a NaN, which the compare
/// then answers false about, as the manual requires. The LE and LT forms are
/// the GE and GT ones with the operands the other way round.
/// </summary>
let private vabscmp (ins: Instruction) bld cmp =
  let bare e = e .& numU32 0x7fffffffu 32<rt>
  vectorCompareReg ins bld (fun a b -> cmp (bare a) (bare b))

let vacge ins bld = vabscmp ins bld AST.fge

let vacgt ins bld = vabscmp ins bld AST.fgt

let vacle ins bld = vabscmp ins bld (fun a b -> AST.fge b a)

let vaclt ins bld = vabscmp ins bld (fun a b -> AST.fgt b a)

/// Whether a single-precision value is an infinity: every exponent bit set
/// and a mantissa of zero, the sign ignored.
let private isInf32 e =
  (e .& numU32 0x7fffffffu 32<rt>) == numU32 0x7f800000u 32<rt>

/// Advanced SIMD reads a denormal as a zero of the same sign: flush-to-zero
/// is fixed on for it, whatever FPSCR says. An operand therefore has to be
/// flushed before anything is computed with it -- a product of two ordinary
/// numbers can be a denormal that the host keeps and the reference does not,
/// and the difference then shows up in the step that follows.
let private flushDenormal32 e =
  let isDenorm =
    ((e .& numU32 0x7f800000u 32<rt>) == AST.num0 32<rt>)
    .& ((e .& numU32 0x007fffffu 32<rt>) != AST.num0 32<rt>)
  AST.ite isDenorm (e .& numU32 0x80000000u 32<rt>) e

let private recipStepLane isSqrt x y =
  let a = flushDenormal32 x
  let b = flushDenormal32 y
  let two = numU32 0x40000000u 32<rt>
  let three = numU32 0x40400000u 32<rt>
  let onePointFive = numU32 0x3fc00000u 32<rt>
  let half = numU32 0x3f000000u 32<rt>
  let degenerate =
    (isInf32 a .& isZeroOf 32 b) .| (isZeroOf 32 a .& isInf32 b)
  let ordinary =
    if isSqrt then AST.fmul (AST.fsub three (AST.fmul a b)) half
    else AST.fsub two (AST.fmul a b)
  let stepped =
    AST.ite degenerate (if isSqrt then onePointFive else two) ordinary
  (* Advanced SIMD runs in default-NaN mode always, so a NaN operand answers
     with the default NaN rather than with itself quieted. The host's
     subtraction propagates the operand instead, which is what showed up as
     seven lanes out of three thousand. *)
  let answer = AST.ite (isNaNOf 32 a .| isNaNOf 32 b) (fpDefaultNan 32) stepped
  flushDenormal32 answer

/// <summary>
/// VRECPS and VRSQRTS, the steps of the Newton-Raphson iterations whose
/// estimates VRECPE and VRSQRTE start.
///
/// Each is one expression -- two minus the product, or three minus it
/// halved -- except where one operand is an infinity and the other a zero.
/// The product is a NaN there, but the manual answers with the step's
/// CONSTANT instead, so that an estimate of zero for an infinite input
/// converges rather than poisoning the iteration.
/// </summary>
let private vrecpstep (ins: Instruction) bld isSqrt =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let lane = recipStepLane isSqrt
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
        elem dstB e p.ESize := lane op1B op2B
        elem dstA e p.ESize := lane op1A op2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := lane op1 op2
    putEndLabel bld lblIgnore
  }

let vrecps ins bld = vrecpstep ins bld false

let vrsqrts ins bld = vrecpstep ins bld true

/// <summary>
/// The manual's RecipEstimate: the reciprocal of a nine-bit fixed-point
/// number in [0.5, 1), to nine bits.
///
/// It is stated as a division and needs no table: the input is rounded to
/// the middle of its interval by doubling and adding one, the reciprocal is
/// taken at nineteen bits, and the answer is rounded back to nine.
/// </summary>
let private recipEstimate9 a =
  let rounded = (a .* numI32 2 64<rt>) .+ AST.num1 64<rt>
  let b = numI32 0x80000 64<rt> ./ rounded
  (b .+ AST.num1 64<rt>) ./ numI32 2 64<rt>

/// <summary>
/// The manual's RecipSqrtEstimate, which it states as a SEARCH: the largest
/// b whose square, times the input, stays under two to the twenty-eighth.
///
/// A loop that counts b up from 512 is not something the IR can say, but the
/// condition is monotone in b, so the same answer comes out of building b
/// one bit at a time from the top. Nine steps rather than up to five hundred,
/// and no table.
/// </summary>
let private recipSqrtEstimate9 bld a =
  let limit = numI32 0x10000000 64<rt>
  let struct (rounded, b) = tmpVars2 bld 64<rt>
  let low = (a .* numI32 2 64<rt>) .+ AST.num1 64<rt>
  let high = ((a >> AST.num1 64<rt>) << AST.num1 64<rt>) .+ AST.num1 64<rt>
  append bld {
    rounded := AST.ite (a .< numI32 256 64<rt>) low (high .* numI32 2 64<rt>)
    b := numI32 512 64<rt>
  }
  (* One temporary per step, because each step names the running value twice
     -- once in the candidate and once as what to keep -- and an expression
     that does that nine times over is five hundred times the size. *)
  for bit in [ 256; 128; 64; 32; 16; 8; 4; 2; 1 ] do
    let cand = b .+ numI32 bit 64<rt>
    append bld { b := AST.ite ((rounded .* cand .* cand) .< limit) cand b }
  (b .+ AST.num1 64<rt>) ./ numI32 2 64<rt>

/// <summary>
/// VRECPE and VRSQRTE in their unsigned forms: a nine-bit estimate of the
/// reciprocal, or of the reciprocal square root, of the top of the element.
///
/// An element too small to estimate answers all ones, which is the largest
/// the format holds: below a half for the reciprocal and below a quarter for
/// the reciprocal square root. Everything else is read as a fixed-point
/// number from its top nine bits and the estimate written back to the same
/// place.
/// </summary>
let private vestimate (ins: Instruction) bld isSqrt =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let ones32 = numU32 0xffffffffu 32<rt>
    let tooSmall e =
      if isSqrt then e .< numU32 0x40000000u 32<rt>
      else e .< numU32 0x80000000u 32<rt>
    let lane e =
      let top = AST.zext 64<rt> (e >> numI32 23 32<rt>)
      let est =
        if isSqrt then recipSqrtEstimate9 bld top else recipEstimate9 top
      let scaled = AST.xtlo 32<rt> est << numI32 23 32<rt>
      AST.ite (tooSmall e) ones32 scaled
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let struct (opB, opA) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        opB := elem srcB e p.ESize
        opA := elem srcA e p.ESize
        elem dstB e p.ESize := lane opB
        elem dstA e p.ESize := lane opA
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      let op = tmpVar bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op := elem src e p.ESize
        elem dst e p.ESize := lane op
    putEndLabel bld lblIgnore
  }

let vrecpe ins bld = vestimate ins bld false

let vrsqrte ins bld = vestimate ins bld true

/// <summary>
/// One half-precision value widened to single or double, written out of its
/// bits rather than cast -- the IR has no half-precision type to cast from.
///
/// Three cases, and the middle one is the only one with work in it. A zero
/// exponent with a zero significand is a signed zero. A zero exponent with
/// anything else is a DENORMAL, and the wider format has room to write it as
/// an ordinary number -- so the leading one has to be found and the exponent
/// derived from where it was. Every exponent bit set is an infinity or a NaN
/// and carries across as one. Everything else is the exponent rebiased and
/// the significand moved up.
/// </summary>
let private halfToWide bld (rt: int<rt>) h =
  let mantBits = if rt = 32<rt> then 23 else 52
  let bias = if rt = 32<rt> then 112 else 1008
  let expMax = if rt = 32<rt> then 0xff else 0x7ff
  let sign = AST.zext rt (h >> numI32 15 16<rt>) << numI32 (int rt - 1) rt
  let e = AST.zext rt ((h >> numI32 10 16<rt>) .& numU32 0x1fu 16<rt>)
  let m = AST.zext rt (h .& numU32 0x3ffu 16<rt>)
  let up = m << numI32 (mantBits - 10) rt
  let normal = ((e .+ numI32 bias rt) << numI32 mantBits rt) .| up
  (* an infinity carries across as it is, but a NaN comes out QUIET: the
     manual's FPProcessNaN sets the top significand bit, and VFP is not in
     default-NaN mode, so the payload is kept rather than replaced *)
  let quiet = AST.num1 rt << numI32 (mantBits - 1) rt
  let infOrNaN = (numI32 expMax rt << numI32 mantBits rt) .| up
  let special =
    AST.ite (m == AST.num0 rt) infOrNaN (infOrNaN .| quiet)
  let lz = tmpVar bld rt
  countLeadingZeroBitsForIR lz m rt bld
  (* the leading one sits where the count says it does, and the exponent is
     that position less the twenty-four the format's smallest step is *)
  let k = numI32 (int rt - 1) rt .- lz
  let denExp = (k .+ numI32 (bias - 9) rt) << numI32 mantBits rt
  let mantMask = (AST.num1 rt << numI32 mantBits rt) .- AST.num1 rt
  let denMant = (m << (numI32 mantBits rt .- k)) .& mantMask
  let subnormal =
    AST.ite (m == AST.num0 rt) (AST.num0 rt) (denExp .| denMant)
  (* thirty-one, not the target's own maximum: the exponent being tested is
     the HALF's, and five bits is all it has *)
  let ordinary = AST.ite (e == AST.num0 rt) subnormal normal
  let body = AST.ite (e == numI32 31 rt) special ordinary
  sign .| body

/// <summary>
/// VCVTB and VCVTT: a half-precision value taken from the bottom or the top
/// half of the source and widened.
///
/// The destination's width is what the first of the two data types names,
/// and the source is a word either way -- which is why the half is picked
/// out of it rather than read as a register of its own.
/// </summary>
let private vcvtHalfWiden (ins: Instruction) bld isTop =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = transTwoOprs ins bld
    let rt =
      match ins.SIMDTyp with
      | Some(TwoDT(SIMDTypF64, SIMDTypF16)) -> 64<rt>
      | _ -> 32<rt>
    let h = if isTop then AST.xthi 16<rt> src else AST.xtlo 16<rt> src
    dst := halfToWide bld rt h
    putEndLabel bld lblIgnore
  }

let vcvtb ins bld = vcvtHalfWiden ins bld false

let vcvtt ins bld = vcvtHalfWiden ins bld true

let vtst (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let n0 = AST.num0 p.RtESize
    (* A lane that tests true is set to ones, not to one: every comparison in
       this part of the instruction set answers with a mask, which is what
       vectorCompareReg beside this does. *)
    let mask = ones p.RtESize
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      for e in 0 .. p.Elements - 1 do
        let c = (elem src1B e p.ESize .& elem src2B e p.ESize) != n0
        let c2 = (elem src1A e p.ESize .& elem src2A e p.ESize) != n0
        elem dstB e p.ESize := AST.ite c mask n0
        elem dstA e p.ESize := AST.ite c2 mask n0
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let c = (elem src1 e p.ESize .& elem src2 e p.ESize) != n0
        elem dst e p.ESize := AST.ite c mask n0
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
    let imm = immAt (rtEsz * 2) (transOpr ins bld imm)
    let roundConst = AST.num1 (rtEsz * 2) << (imm .- AST.num1 (rtEsz * 2))
    (* The source's two halves land in the destination's two halves. Both
       results were written to the same element index, so every low element
       was overwritten by the high one and the top half of the answer never
       reached the register. *)
    let half = elements / 2
    for e in 0 .. half - 1 do
      let result1 = (elem srcB e (esize * 2) .+ roundConst) >> imm
      let result2 = (elem srcA e (esize * 2) .+ roundConst) >> imm
      elem dst (e + half) esize := AST.xtlo rtEsz result1
      elem dst e esize := AST.xtlo rtEsz result2
    putEndLabel bld lblIgnore
  }

/// The shape every bitwise operation on two vector registers has: a pair of
/// halves where the operands are quadwords, and one register where they are
/// doublewords.
let private vbitwise (ins: Instruction) bld op =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      dstB := op src1B src2B
      dstA := op src1A src2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      dst := op src1 src2
    putEndLabel bld lblIgnore
  }

let veor ins bld = vbitwise ins bld (<+>)

/// <summary>
/// VBIC, which clears the bits its second operand names.
///
/// The immediate form reads the destination as well as writing it, because
/// what it clears is named by the immediate and everything else is kept.
/// </summary>
let vbic (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ ->
    vbitwise ins bld (fun a b -> a .& AST.not b)
  | _ ->
    lift bld ins {
      let isUnconditional = ParseUtils.isUnconditional ins.Condition
      let lblIgnore = checkCondition ins bld isUnconditional
      let struct (dst, imm) = getTwoOprs ins
      let p = getParsingInfo ins
      let mask = transOpr ins bld imm |> replicatedImm p |> AST.not
      match ins.OprSize with
      | 128<rt> ->
        let struct (dstB, dstA) = transOpr128 bld dst
        dstB := dstB .& mask
        dstA := dstA .& mask
      | _ ->
        let dst = transOpr ins bld dst
        dst := dst .& mask
      putEndLabel bld lblIgnore
    }

/// <summary>
/// VMVN, the bitwise complement.
///
/// The immediate form does not read the destination at all: it writes the
/// complement of the immediate, which is why it is a move and not an
/// operation on what was there.
/// </summary>
let vmvn (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.Operands with
    | TwoOperands(_, OprImm _) ->
      let struct (dst, imm) = getTwoOprs ins
      let p = getParsingInfo ins
      let value = transOpr ins bld imm |> replicatedImm p |> AST.not
      match ins.OprSize with
      | 128<rt> ->
        let struct (dstB, dstA) = transOpr128 bld dst
        dstB := value
        dstA := value
      | _ ->
        let dst = transOpr ins bld dst
        dst := value
    | _ ->
      match ins.OprSize with
      | 128<rt> ->
        let struct (dst, src) = getTwoOprs ins
        let struct (dstB, dstA) = transOpr128 bld dst
        let struct (srcB, srcA) = transOpr128 bld src
        dstB := AST.not srcB
        dstA := AST.not srcA
      | _ ->
        let struct (dst, src) = transTwoOprs ins bld
        dst := AST.not src
    putEndLabel bld lblIgnore
  }

/// VSWP, which exchanges two whole registers. Both are latched first, because
/// the second write would otherwise read back what the first one put there.
let vswp (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let struct (tB, tA) = tmpVars2 bld 64<rt>
      tB := dstB
      tA := dstA
      dstB := srcB
      dstA := srcA
      srcB := tB
      srcA := tA
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      let t = tmpVar bld 64<rt>
      t := dst
      dst := src
      src := t
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
      let imm = transOpr ins bld imm |> replicatedImm (getParsingInfo ins)
      dstB := dstB .| imm
      dstA := dstA .| imm
    | _ ->
      let struct (dst, imm) = transTwoOprs ins bld
      let imm = replicatedImm (getParsingInfo ins) imm
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
  | TwoOperands(OprSIMD(OneReg(Scalar(d, _))), _) ->
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

/// The base register of a structure access and the register that steps it,
/// if any. The accesses that take no alignment -- VLD3 and VST3 of one lane
/// and VLD3 to all lanes -- are decoded with a plain offset in place of an
/// aligned one, and read the same.
let getRnAndRm bld = function
  | TwoOperands(_, OprMemory(OffsetMode(AlignOffset(rn, _, _))))
  | TwoOperands(_, OprMemory(PreIdxMode(AlignOffset(rn, _, _))))
  | TwoOperands(_, OprMemory(OffsetMode(ImmOffset(rn, _, _))))
  | TwoOperands(_, OprMemory(PreIdxMode(ImmOffset(rn, _, _)))) ->
    regVar bld rn, None
  | TwoOperands(_, OprMemory(PostIdxMode(AlignOffset(rn, _, Some rm))))
  | TwoOperands(_, OprMemory(PostIdxMode(RegOffset(rn, _, rm, _)))) ->
    regVar bld rn, regVar bld rm |> Some
  | _ ->
    raise InvalidOperandException

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
          let mem = loadNative bld p.RtESize addr
          mem := elem rdList[r] e p.ESize
        else
          (* a doubleword is two words, the one at the lower address its
             low half on a little-endian access and its high half on a
             big-endian one *)
          let mem1 = loadNative bld 32<rt> addr
          let mem2 = loadNative bld 32<rt> (incAddr addr 4)
          let reg = elem rdList[r] e p.ESize
          let isbig = bld.Endianness = Endian.Big
          mem1 := if isbig then AST.xthi 32<rt> reg else AST.xtlo 32<rt> reg
          mem2 := if isbig then AST.xtlo 32<rt> reg else AST.xthi 32<rt> reg
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
    let mem = loadNative bld p.RtESize addr
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
    let mem = loadNative bld p.RtESize addr
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
    let mem = loadNative bld p.RtESize addr
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
          data := loadNative bld p.RtESize addr
          elem rdList[r] e p.ESize := data
        else
          let struct (data1, data2) = tmpVars2 bld 32<rt>
          let mem1 = loadNative bld 32<rt> addr
          let mem2 = loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>))
          let isbig = bld.Endianness = Endian.Big
          data1 := if isbig then mem2 else mem1
          data2 := if isbig then mem1 else mem2
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
    (* the second register of a pair is regs further on: two pairs are
       D[d] with D[d+2] and D[d+1] with D[d+3] *)
    for r in 0 .. (regs - 1) do
      let rd1 = rdList[r]
      let rd2 = rdList[r + regs]
      for e in 0 .. (p.Elements - 1) do
        let mem1 = loadNative bld p.RtESize addr
        let mem2 = loadNative bld p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
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
    rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
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
      let mem1 = loadNative bld p.RtESize addr
      let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
      let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
    let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
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
      let mem1 = loadNative bld p.RtESize addr
      let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
      let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
      let mem4 = loadNative bld p.RtESize (incAddr addr (3 * p.EBytes))
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
    let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = loadNative bld p.RtESize (incAddr addr (3 * p.EBytes))
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
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
    (* the second register of a pair is regs further on: two pairs are
       D[d] with D[d+2] and D[d+1] with D[d+3] *)
    for r in 0 .. (regs - 1) do
      let rd1 = rdList[r]
      let rd2 = rdList[r + regs]
      for e in 0 .. (p.Elements - 1) do
        let mem1 = loadNative bld p.RtESize addr
        let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
    let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
    let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
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
      let mem1 = loadNative bld p.RtESize addr
      let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
      let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
    let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = loadNative bld p.RtESize (incAddr addr (3 * p.EBytes))
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
    let mem1 = loadNative bld p.RtESize addr
    let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
    let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = loadNative bld p.RtESize (incAddr addr (3 * p.EBytes))
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
    rn := updateRn ins rn rm 32 p.RegIndex
    for e in 0 .. (p.Elements - 1) do
      let mem1 = loadNative bld p.RtESize addr
      let mem2 = loadNative bld p.RtESize (incAddr addr p.EBytes)
      let mem3 = loadNative bld p.RtESize (incAddr addr (2 * p.EBytes))
      let mem4 = loadNative bld p.RtESize (incAddr addr (3 * p.EBytes))
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

/// <summary>
/// The halved sum or difference one element of VHADD, VHSUB or VRHADD
/// answers with.
///
/// The arithmetic is done at twice the element's width, because what the
/// pseudocode takes is bits esize:1 of a value that has esize+1 of them:
/// VHADD.U8 of 0xff and 0xff is 0xff, and an eight-bit add loses the carry
/// the answer is built out of. The widening is the one the data type names,
/// so that a signed halving brings the sign down into the element rather than
/// a zero.
///
/// VRHADD rounds where the other two truncate, which is the one added before
/// the shift.
/// </summary>
let private halvedElem p unsigned opFn round e1 e2 =
  let wide = RegType.fromBitWidth (p.ESize * 2)
  let ext = if unsigned then AST.zext wide else AST.sext wide
  let sum = opFn (ext e1) (ext e2)
  let sum = if round then sum .+ AST.num1 wide else sum
  AST.xtlo p.RtESize (sum >> AST.num1 wide)

let private vhaddsubrnd (ins: Instruction) bld opFn round =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let half = halvedElem p (isUnsigned ins.SIMDTyp) opFn round
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
        elem dstB e p.ESize := half op1B op2B
        elem dstA e p.ESize := half op1A op2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := half op1 op2
    putEndLabel bld lblIgnore
  }

let vhaddsub ins bld opFn = vhaddsubrnd ins bld opFn false

let vrhadd ins bld = vhaddsubrnd ins bld (.+) true

/// <summary>
/// One lane of a saturating operation, clamped to what the destination
/// element holds.
///
/// The value arrives at a width it cannot have been lost at -- one bit more
/// than the element for a sum, twice as many for a narrowing -- because an
/// element that has already wrapped no longer carries what the saturation
/// exists to catch.
///
/// The source's signedness and the destination's are separate, and not only
/// for tidiness: VQMOVUN reads a signed element and writes an unsigned one,
/// so the comparison has to be signed while the limits are not. An unsigned
/// comparison against a signed value reads every negative as larger than the
/// positive limit and clamps it to the top instead of the bottom.
///
/// FPSCR's QC bit records that some lane was clamped. It is sticky by
/// design -- a program reads it after a whole block of vector arithmetic to
/// ask whether ANY of it saturated -- so it is set here and never cleared.
/// </summary>
let private satLane bld srcUnsigned dstUnsigned wide (eSize: int<rt>) value =
  let qc = AST.extract (regVar bld R.FPSCR) 1<rt> 27
  let width = RegType.toBitWidth eSize
  let allOnes =
    if width >= 64 then 0xffffffffffffffffUL else (1UL <<< width) - 1UL
  let maxV =
    if dstUnsigned then
      numU64 allOnes wide
    else
      numI64 ((1L <<< (width - 1)) - 1L) wide
  let minV =
    if dstUnsigned then AST.num0 wide else numI64 (-(1L <<< (width - 1))) wide
  let t = tmpVar bld wide
  append bld { t := value }
  let tooHigh = if srcUnsigned then t .> maxV else t ?> maxV
  let tooLow = if srcUnsigned then t .< minV else t ?< minV
  append bld { qc := qc .| tooHigh .| tooLow }
  AST.xtlo eSize (AST.ite tooHigh maxV (AST.ite tooLow minV t))

/// <summary>
/// VQADD and VQSUB: the element-wise sum or difference, clamped.
///
/// One bit wider than the element is enough for either, and the extension is
/// the one the data type names so that an unsigned difference borrows into a
/// bit that is there to be borrowed from rather than wrapping. The comparison
/// that follows is signed either way: a zero-extended operand is never
/// negative at the wider width, so the two agree there.
/// </summary>
let private vqaddsub (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let unsigned = isUnsigned ins.SIMDTyp
    let wide = RegType.fromBitWidth (p.ESize * 2)
    let ext = if unsigned then AST.zext wide else AST.sext wide
    let sat e1 e2 =
      satLane bld false unsigned wide p.RtESize (opFn (ext e1) (ext e2))
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
        elem dstB e p.ESize := sat op1B op2B
        elem dstA e p.ESize := sat op1A op2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := sat op1 op2
    putEndLabel bld lblIgnore
  }

let vqadd ins bld = vqaddsub ins bld (.+)

let vqsub ins bld = vqaddsub ins bld (.-)

/// <summary>
/// VQABS and VQNEG, which saturate for one input each.
///
/// The element at the bottom of the signed range has no positive counterpart
/// -- neither negating nor taking the absolute value of -128 can answer 128
/// in eight bits -- so both clamp it to the top of the range and raise QC.
/// Every other input passes through.
/// </summary>
let private vqabsneg (ins: Instruction) bld isNeg =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let wide = RegType.fromBitWidth (p.ESize * 2)
    let sat e =
      let v = AST.sext wide e
      let v =
        if isNeg then AST.neg v
        else AST.ite (v ?< AST.num0 wide) (AST.neg v) v
      satLane bld false false wide p.RtESize v
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let struct (opB, opA) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        opB := elem srcB e p.ESize
        opA := elem srcA e p.ESize
        elem dstB e p.ESize := sat opB
        elem dstA e p.ESize := sat opA
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      let op = tmpVar bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op := elem src e p.ESize
        elem dst e p.ESize := sat op
    putEndLabel bld lblIgnore
  }

let vqabs ins bld = vqabsneg ins bld false

let vqneg ins bld = vqabsneg ins bld true

/// <summary>
/// VQMOVN and VQMOVUN: each element halved in width and clamped to what the
/// narrower one holds.
///
/// Three signednesses, not two: VQMOVN reads and writes the same one, and
/// VQMOVUN reads a signed element and writes an unsigned one. The source is
/// snapshotted first because the destination can be one half of it.
/// </summary>
let private vqmovnarrow (ins: Instruction) bld srcUnsigned dstUnsigned =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src) = getTwoOprs ins
    let dst = transOpr ins bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    let esize = 8 <<< getNarrowSizeStart ins.SIMDTyp
    let wide = RegType.fromBitWidth (2 * esize)
    let narrow = RegType.fromBitWidth esize
    let perReg = 32 / esize
    let struct (lo, hi) = tmpVars2 bld 64<rt>
    lo := srcA
    hi := srcB
    let sat v = satLane bld srcUnsigned dstUnsigned wide narrow v
    for e in 0 .. perReg - 1 do
      elem dst e esize := sat (elem lo e (2 * esize))
      elem dst (e + perReg) esize := sat (elem hi e (2 * esize))
    putEndLabel bld lblIgnore
  }

let vqmovn (ins: Instruction) bld =
  let unsigned = isUnsigned ins.SIMDTyp
  vqmovnarrow ins bld unsigned unsigned

let vqmovun ins bld = vqmovnarrow ins bld false true

/// <summary>
/// One lane of a shift by a REGISTER amount: left when the amount is
/// positive and right when it is negative, clamped for the saturating forms.
///
/// The amount is split into a left half and a right half so that neither
/// computation is ever run at the other's distance, and both are done at
/// twice the element's width, where a left shift of a whole element still
/// has somewhere to go.
///
/// A rounding right shift adds half of what it is about to discard. At or
/// beyond the element's width that constant is larger than the whole
/// element, so every value rounds to zero -- which is why the amount is not
/// simply clamped there: a clamped amount would add the constant for a
/// shorter shift than the one being taken.
/// </summary>
let private shiftByRegLane bld p unsigned isRound saturate e amt =
  let rt = p.RtESize
  let wide = RegType.fromBitWidth (p.ESize * 2)
  let n0 = AST.num0 rt
  let widest = numI32 p.ESize rt
  let deepest = numI32 (p.ESize - 1) rt
  let struct (isNeg, left, right) = tmpVars3 bld rt
  let struct (over, capped) = tmpVars2 bld rt
  append bld {
    isNeg := AST.ite (amt ?< n0) (AST.num1 rt) n0
    left := AST.ite (amt ?< n0) n0 (AST.ite (amt ?> widest) widest amt)
    right := AST.ite (amt ?< n0) (AST.neg amt) n0
    over := AST.ite (right .>= widest) (AST.num1 rt) n0
    capped := AST.ite (right .>= widest) deepest right
  }
  let ext = if unsigned then AST.zext wide else AST.sext wide
  let wideE = ext e
  let down v = if unsigned then v >> AST.zext wide capped
               else v ?>> AST.zext wide capped
  let rounded =
    let half = AST.num1 wide << (AST.zext wide capped .- AST.num1 wide)
    wideE .+ AST.ite (capped == n0) (AST.num0 wide) half
  let rightRes =
    if isRound then
      AST.ite (over == AST.num1 rt) (AST.num0 wide) (down rounded)
    else
      down wideE
  let leftRes = wideE << AST.zext wide left
  let answer = AST.ite (isNeg == AST.num1 rt) rightRes leftRes
  if saturate then satLane bld unsigned unsigned wide rt answer
  else AST.xtlo rt answer

/// VQSHL, VQRSHL and VRSHL in their register forms: the amount is the low
/// byte of each element of the second source, read as signed so that a
/// negative one shifts the other way.
let private vshiftByReg (ins: Instruction) bld isRound saturate =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let unsigned = isUnsigned ins.SIMDTyp
    let amountOf e = AST.sext p.RtESize (AST.xtlo 8<rt> e)
    let lane v a =
      shiftByRegLane bld p unsigned isRound saturate v (amountOf a)
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
        elem dstB e p.ESize := lane op1B op2B
        elem dstA e p.ESize := lane op1A op2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := lane op1 op2
    putEndLabel bld lblIgnore
  }

let vqshlReg ins bld = vshiftByReg ins bld false true

let vqrshl ins bld = vshiftByReg ins bld true true

let vrshl ins bld = vshiftByReg ins bld true false

/// <summary>
/// VQSHL and VQSHLU in their IMMEDIATE forms, which only ever shift left.
///
/// VQSHLU is the odd one: it reads a SIGNED element and saturates to the
/// UNSIGNED range, so a negative input clamps to zero rather than to the
/// bottom of a signed range. That is the one place the source's signedness
/// and the destination's differ here.
/// </summary>
let private vqshlImm (ins: Instruction) bld dstUnsigned =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let srcUnsigned = isUnsigned ins.SIMDTyp
    let wide = RegType.fromBitWidth (p.ESize * 2)
    let ext = if srcUnsigned then AST.zext wide else AST.sext wide
    let shift = numI32 (shiftAmountOf ins) wide
    let lane v =
      satLane bld srcUnsigned dstUnsigned wide p.RtESize (ext v << shift)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, _) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let struct (opB, opA) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        opB := elem srcB e p.ESize
        opA := elem srcA e p.ESize
        elem dstB e p.ESize := lane opB
        elem dstA e p.ESize := lane opA
    | _ ->
      let struct (dst, src, _) = getThreeOprs ins
      let dst = transOpr ins bld dst
      let src = transOpr ins bld src
      let op = tmpVar bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op := elem src e p.ESize
        elem dst e p.ESize := lane op
    putEndLabel bld lblIgnore
  }

let vqshlu ins bld = vqshlImm ins bld true

let vqshl (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> vqshlImm ins bld (isUnsigned ins.SIMDTyp)
  | _ -> vqshlReg ins bld

/// <summary>
/// VQSHRN, VQSHRUN and their rounding pair: each element shifted right by an
/// immediate, narrowed to half its width and clamped to what that holds.
///
/// The shift is of the WIDE element and happens before the narrowing. The
/// UN forms read a signed element and write an unsigned one, so the source's
/// signedness and the destination's are given separately.
/// </summary>
let private vqshrnarrow (ins: Instruction) bld isRound dstUnsigned =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src, _) = getThreeOprs ins
    let dst = transOpr ins bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    let srcUnsigned = isUnsigned ins.SIMDTyp
    let esize = 8 <<< getNarrowSizeStart ins.SIMDTyp
    let wide = RegType.fromBitWidth (2 * esize)
    let narrow = RegType.fromBitWidth esize
    let perReg = 32 / esize
    let amount = shiftAmountOf ins
    let shift = numI32 amount wide
    let struct (lo, hi) = tmpVars2 bld 64<rt>
    lo := srcA
    hi := srcB
    let lane v e =
      let x = elem v e (2 * esize)
      let x =
        if isRound then x .+ (AST.num1 wide << numI32 (amount - 1) wide)
        else x
      let x = if srcUnsigned then x >> shift else x ?>> shift
      satLane bld srcUnsigned dstUnsigned wide narrow x
    for e in 0 .. perReg - 1 do
      elem dst e esize := lane lo e
      elem dst (e + perReg) esize := lane hi e
    putEndLabel bld lblIgnore
  }

let vqshrn ins bld = vqshrnarrow ins bld false (isUnsigned ins.SIMDTyp)

let vqrshrn ins bld = vqshrnarrow ins bld true (isUnsigned ins.SIMDTyp)

let vqshrun ins bld = vqshrnarrow ins bld false true

let vqrshrun ins bld = vqshrnarrow ins bld true true

/// <summary>
/// The doubled product of two signed elements, saturated to twice their
/// width.
///
/// The doubling is the one place a product of two elements no longer fits in
/// two elements' worth of bits: both operands at the signed minimum give
/// exactly the bit above the top, which is the only input that saturates
/// here. The product is therefore formed at FOUR times the element's width,
/// where it cannot be lost before the clamp is asked about it.
/// </summary>
let private doubledProduct bld p e1 e2 =
  let room = RegType.fromBitWidth (p.ESize * 4)
  let wide = RegType.fromBitWidth (p.ESize * 2)
  let prod = AST.sext room e1 .* AST.sext room e2
  satLane bld false false room wide (prod << AST.num1 room)

/// <summary>
/// VQDMULH and VQRDMULH: the doubled product with only its TOP half kept,
/// saturated, and for the rounding form with half of the discarded part
/// added before it is discarded.
/// </summary>
let private vqdmulhigh (ins: Instruction) bld isRound =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let room = RegType.fromBitWidth (p.ESize * 4)
    let lane e1 e2 =
      let prod = (AST.sext room e1 .* AST.sext room e2) << AST.num1 room
      let prod =
        if isRound then
          prod .+ (AST.num1 room << numI32 (p.ESize - 1) room)
        else
          prod
      satLane bld false false room p.RtESize (prod ?>> numI32 p.ESize room)
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
        elem dstB e p.ESize := lane op1B op2B
        elem dstA e p.ESize := lane op1A op2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := lane op1 op2
    putEndLabel bld lblIgnore
  }

let vqdmulh ins bld = vqdmulhigh ins bld false

let vqrdmulh ins bld = vqdmulhigh ins bld true

/// <summary>
/// VQDMULL, VQDMLAL and VQDMLSL: the doubled product written long, on its
/// own or added to or subtracted from what the destination holds.
///
/// The manual saturates TWICE for the accumulating pair -- once on the
/// doubled product and once on the accumulation -- and both are kept here,
/// because a product that clamped and an accumulation that clamped are
/// different events and either can raise QC on its own.
/// </summary>
let private vqdmullong (ins: Instruction) bld combine =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let struct (op1, op2) = tmpVars2 bld 64<rt>
    op1 := transOpr ins bld src1
    op2 := transOpr ins bld src2
    let room = RegType.fromBitWidth (p.ESize * 4)
    let wide = p.RtESize * 2
    let half = p.Elements / 2
    let answer old e =
      let prod = doubledProduct bld p (elem op1 e p.ESize) (elem op2 e p.ESize)
      match combine with
      | Some opFn ->
        let sum = opFn (AST.sext room old) (AST.sext room prod)
        satLane bld false false room wide sum
      | None ->
        prod
    for e in 0 .. half - 1 do
      elem dstA e (2 * p.ESize) := answer (elem dstA e (2 * p.ESize)) e
      elem dstB e (2 * p.ESize) :=
        answer (elem dstB e (2 * p.ESize)) (e + half)
    putEndLabel bld lblIgnore
  }

let vqdmull ins bld = vqdmullong ins bld None

let vqdmlal ins bld = vqdmullong ins bld (Some(.+))

let vqdmlsl ins bld = vqdmullong ins bld (Some(.-))

/// <summary>
/// VCLS: the number of bits below the top one that match it, which is the
/// leading-zero count of the value with its sign folded away, less one.
///
/// Folding is the complement for a negative and the value itself for a
/// positive: either way the top bit becomes zero and the run of bits that
/// matched the sign becomes a run of zeros. The count of those is one more
/// than the answer, because the sign bit itself is not one of them.
/// </summary>
let private vclsElem dst src rt bld =
  let folded = tmpVar bld rt
  let zeros = tmpVar bld rt
  append bld { folded := AST.ite (AST.xthi 1<rt> src) (AST.not src) src }
  countLeadingZeroBitsForIR zeros folded rt bld
  append bld { dst := zeros .- AST.num1 rt }

let vcls (ins: Instruction) bld =
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
        vclsElem (elem dstB e p.ESize) (elem srcB e p.ESize) p.RtESize bld
        vclsElem (elem dstA e p.ESize) (elem srcA e p.ESize) p.RtESize bld
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      for e in 0 .. p.Elements - 1 do
        vclsElem (elem dst e p.ESize) (elem src e p.ESize) p.RtESize bld
    putEndLabel bld lblIgnore
  }

/// <summary>
/// VCNT: how many bits of each BYTE are set. The element size is always
/// eight, whatever the data type says.
///
/// Eight additions of one masked bit each, which is what the IR can say
/// without a population count of its own. A byte is short enough that the
/// halving trick a wider word would want is not worth the obscurity.
/// </summary>
let private vcntElem dst src bld =
  let acc = tmpVar bld 8<rt>
  append bld { acc := src .& AST.num1 8<rt> }
  for b in 1 .. 7 do
    append bld {
      acc := acc .+ ((src >> numI32 b 8<rt>) .& AST.num1 8<rt>)
    }
  append bld { dst := acc }

let vcnt (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let elems = int ins.OprSize / 8 / (if ins.OprSize = 128<rt> then 2 else 1)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. elems - 1 do
        vcntElem (elem dstB e 8) (elem srcB e 8) bld
        vcntElem (elem dstA e 8) (elem srcA e 8) bld
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      for e in 0 .. elems - 1 do
        vcntElem (elem dst e 8) (elem src e 8) bld
    putEndLabel bld lblIgnore
  }

/// <summary>
/// VBSL, VBIT and VBIF: one bit of the answer taken from one source or the
/// other, chosen by a bit of the third.
///
/// The three differ only in which register holds the selector and which way
/// round it reads, so one body serves all of them: `pick` is handed the
/// destination's old value and the two sources and says what the selection
/// is. Every register is read into a temporary first, because the
/// destination is one of the sources in all three.
/// </summary>
let private vbitselect (ins: Instruction) bld pick =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src1, src2) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (src1B, src1A) = transOpr128 bld src1
      let struct (src2B, src2A) = transOpr128 bld src2
      let struct (dB, nB, mB) = tmpVars3 bld 64<rt>
      let struct (dA, nA, mA) = tmpVars3 bld 64<rt>
      dB := dstB
      nB := src1B
      mB := src2B
      dA := dstA
      nA := src1A
      mA := src2A
      dstB := pick dB nB mB
      dstA := pick dA nA mA
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (d, n, m) = tmpVars3 bld 64<rt>
      d := dst
      n := src1
      m := src2
      dst := pick d n m
    putEndLabel bld lblIgnore
  }

let vbsl ins bld =
  vbitselect ins bld (fun d n m -> (d .& n) .| (AST.not d .& m))

let vbit ins bld =
  vbitselect ins bld (fun d n m -> (n .& m) .| (d .& AST.not m))

let vbif ins bld =
  vbitselect ins bld (fun d n m -> (d .& m) .| (n .& AST.not m))

/// <summary>
/// VREV16, VREV32 and VREV64: the elements within each container reversed.
///
/// The container is what the mnemonic names and the element what the data
/// type does, so VREV64.8 reverses eight bytes within each doubleword and
/// VREV32.16 two halfwords within each word. The reversal is a renaming of
/// the element indices, so it is done by index arithmetic and not by any
/// operation on the values.
/// </summary>
let private vrevContainer (ins: Instruction) bld containerBits =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let perContainer = containerBits / p.ESize
    let swap e = (e / perContainer) * perContainer
                 + (perContainer - 1 - e % perContainer)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let tB = Array.init p.Elements (fun _ -> tmpVar bld p.RtESize)
      let tA = Array.init p.Elements (fun _ -> tmpVar bld p.RtESize)
      for e in 0 .. p.Elements - 1 do
        tB[e] := elem srcB e p.ESize
        tA[e] := elem srcA e p.ESize
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := tB[swap e]
        elem dstA e p.ESize := tA[swap e]
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      let t = Array.init p.Elements (fun _ -> tmpVar bld p.RtESize)
      for e in 0 .. p.Elements - 1 do
        t[e] := elem src e p.ESize
      for e in 0 .. p.Elements - 1 do
        elem dst e p.ESize := t[swap e]
    putEndLabel bld lblIgnore
  }

let vrev16 ins bld = vrevContainer ins bld 16

let vrev32 ins bld = vrevContainer ins bld 32

let vrev64 ins bld = vrevContainer ins bld 64

/// <summary>
/// VSUBL and VSUBW, and VADDW beside them: the long and wide forms of the
/// element-wise sum and difference.
///
/// A LONG form widens both sources; a WIDE form widens only the second,
/// because the first is already a quadword. Both write a quadword, and both
/// read every source before writing a lane of it -- the destination can be
/// the first source of a wide form.
/// </summary>
let private vsublong (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let struct (op1, op2) = tmpVars2 bld 64<rt>
    op1 := transOpr ins bld src1
    op2 := transOpr ins bld src2
    let wide = p.RtESize * 2
    let half = p.Elements / 2
    let answer e =
      opFn (ext wide (elem op1 e p.ESize)) (ext wide (elem op2 e p.ESize))
    for e in 0 .. half - 1 do
      elem dstA e (2 * p.ESize) := answer e
      elem dstB e (2 * p.ESize) := answer (e + half)
    putEndLabel bld lblIgnore
  }

let vsubl ins bld = vsublong ins bld (.-)

/// The WIDE forms, whose first source is already a quadword and so is not
/// widened. Everything else about them is the long form above.
let private vaddsubWide (ins: Instruction) bld opFn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let struct (s1B, s1A) = transOpr128 bld src1
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let struct (w1B, w1A, op2) = tmpVars3 bld 64<rt>
    w1B := s1B
    w1A := s1A
    op2 := transOpr ins bld src2
    let wide = p.RtESize * 2
    let half = p.Elements / 2
    let answer reg e off =
      opFn (elem reg e (2 * p.ESize)) (ext wide (elem op2 (e + off) p.ESize))
    for e in 0 .. half - 1 do
      elem dstA e (2 * p.ESize) := answer w1A e 0
      elem dstB e (2 * p.ESize) := answer w1B e half
    putEndLabel bld lblIgnore
  }

let vaddw ins bld = vaddsubWide ins bld (.+)

let vsubw ins bld = vaddsubWide ins bld (.-)

/// The destination and the one source of a two-operand form, or of a
/// three-operand one whose third is an immediate the caller reads itself.
let private dstSrcOf (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(d, s) -> d, s
  | ThreeOperands(d, s, _) -> d, s
  | _ -> raise InvalidOperandException

/// <summary>
/// VMOVL and VSHLL: every element widened, and for VSHLL shifted left as
/// well.
///
/// The shift is done AFTER the widening, so a bit shifted past the source's
/// width is kept rather than lost -- which is the whole of what VSHLL is
/// for, and why its widest shift is the element's own width.
/// </summary>
let private vwidenShift (ins: Instruction) bld amount =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let dst, src = dstSrcOf ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let wide = p.RtESize * 2
    let op = tmpVar bld 64<rt>
    op := transOpr ins bld src
    let half = p.Elements / 2
    let shifted e =
      let v = ext wide (elem op e p.ESize)
      if amount = 0 then v else v << numI32 amount wide
    for e in 0 .. half - 1 do
      elem dstA e (2 * p.ESize) := shifted e
      elem dstB e (2 * p.ESize) := shifted (e + half)
    putEndLabel bld lblIgnore
  }

let vmovl ins bld = vwidenShift ins bld 0

let vshll (ins: Instruction) bld = vwidenShift ins bld (shiftAmountOf ins)

/// <summary>
/// VADDHN, VSUBHN and their rounding pair: a sum or difference of quadword
/// elements, with only the TOP half of each kept.
///
/// The rounding forms add half of what is about to be discarded before
/// discarding it, which is the bit below the half being kept. The data type
/// names the WIDE element, so the narrow one is half of it.
/// </summary>
let private vaddsubHN (ins: Instruction) bld opFn round =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = getThreeOprs ins
    let dst = transOpr ins bld dst
    let struct (s1B, s1A) = transOpr128 bld src1
    let struct (s2B, s2A) = transOpr128 bld src2
    let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
    let wide = RegType.fromBitWidth (2 * esize)
    let narrow = RegType.fromBitWidth esize
    let perReg = 32 / esize
    let struct (n1B, n1A, n2B) = tmpVars3 bld 64<rt>
    let n2A = tmpVar bld 64<rt>
    n1B := s1B
    n1A := s1A
    n2B := s2B
    n2A := s2A
    let answer a b e =
      let v = opFn (elem a e (2 * esize)) (elem b e (2 * esize))
      let v =
        if round then v .+ (AST.num1 wide << numI32 (esize - 1) wide) else v
      AST.xtlo narrow (v >> numI32 esize wide)
    for e in 0 .. perReg - 1 do
      elem dst e esize := answer n1A n2A e
      elem dst (e + perReg) esize := answer n1B n2B e
    putEndLabel bld lblIgnore
  }

let vaddhn ins bld = vaddsubHN ins bld (.+) false

let vsubhn ins bld = vaddsubHN ins bld (.-) false

let vraddhn ins bld = vaddsubHN ins bld (.+) true

let vrsubhn ins bld = vaddsubHN ins bld (.-) true

/// <summary>
/// The absolute difference of one lane, computed one bit wider than the
/// element.
///
/// Wider because the difference of two UNSIGNED elements can need the extra
/// bit -- 0 minus 255 is -255, which eight bits cannot hold even before the
/// sign is taken off it. The subtraction is therefore done at the wider
/// width with the operands extended the way the data type says, and the
/// absolute value taken there.
/// </summary>
let private absDiffLane (wide: int<rt>) ext e1 e2 =
  let d = ext wide e1 .- ext wide e2
  AST.ite (d ?< AST.num0 wide) (AST.neg d) d

/// <summary>
/// VABD and VABA: the absolute difference of each pair of elements, kept at
/// the element's own width, and for VABA added to what the destination
/// already holds.
/// </summary>
let private vabsdiff (ins: Instruction) bld accumulate =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let wide = RegType.fromBitWidth (p.ESize * 2)
    let answer old e1 e2 =
      let d = AST.xtlo p.RtESize (absDiffLane wide ext e1 e2)
      if accumulate then old .+ d else d
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
        elem dstB e p.ESize := answer (elem dstB e p.ESize) op1B op2B
        elem dstA e p.ESize := answer (elem dstA e p.ESize) op1A op2A
    | _ ->
      let struct (dst, src1, src2) = transThreeOprs ins bld
      let struct (op1, op2) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op1 := elem src1 e p.ESize
        op2 := elem src2 e p.ESize
        elem dst e p.ESize := answer (elem dst e p.ESize) op1 op2
    putEndLabel bld lblIgnore
  }

let vabd ins bld = vabsdiff ins bld false

let vaba ins bld = vabsdiff ins bld true

/// <summary>
/// VABDL and VABAL, the long forms: the same difference written into an
/// element twice as wide, and for VABAL added to what is there.
///
/// The sources are read into temporaries before the first lane is written,
/// because the quadword destination overlaps the doubleword sources.
/// </summary>
let private vabsdiffLong (ins: Instruction) bld accumulate =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOpr128 bld dst
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let struct (op1, op2) = tmpVars2 bld 64<rt>
    op1 := transOpr ins bld src1
    op2 := transOpr ins bld src2
    let wide = p.RtESize * 2
    let half = p.Elements / 2
    let answer old e =
      let d = absDiffLane wide ext (elem op1 e p.ESize) (elem op2 e p.ESize)
      if accumulate then old .+ d else d
    for e in 0 .. half - 1 do
      elem dstA e (2 * p.ESize) := answer (elem dstA e (2 * p.ESize)) e
      elem dstB e (2 * p.ESize) :=
        answer (elem dstB e (2 * p.ESize)) (e + half)
    putEndLabel bld lblIgnore
  }

let vabdl ins bld = vabsdiffLong ins bld false

let vabal ins bld = vabsdiffLong ins bld true

/// <summary>
/// VSHRN: each element shifted right by an immediate and narrowed to half
/// its width, keeping what is left rather than saturating.
///
/// The shift is of the WIDE element and happens before the narrowing, which
/// is what makes the instruction different from a narrow followed by a
/// shift. The data type names the wide element, so the narrow one is half.
/// </summary>
let vshrn (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src, _) = getThreeOprs ins
    let dst = transOpr ins bld dst
    let struct (srcB, srcA) = transOpr128 bld src
    let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
    let wide = RegType.fromBitWidth (2 * esize)
    let narrow = RegType.fromBitWidth esize
    let perReg = 32 / esize
    let shift = numI32 (shiftAmountOf ins) wide
    let struct (lo, hi) = tmpVars2 bld 64<rt>
    lo := srcA
    hi := srcB
    let answer v e = AST.xtlo narrow (elem v e (2 * esize) >> shift)
    for e in 0 .. perReg - 1 do
      elem dst e esize := answer lo e
      elem dst (e + perReg) esize := answer hi e
    putEndLabel bld lblIgnore
  }

/// <summary>
/// VPMAX and VPMIN: the larger or smaller of each ADJACENT PAIR, the first
/// source's pairs filling the bottom half of the answer and the second
/// source's the top.
///
/// Only the doubleword form exists, so there is no quadword arm. The answer
/// is built in a temporary because a source can be the destination and the
/// second half of it is read after the first half has been written.
/// </summary>
let private vpmaxmin (ins: Instruction) bld isMax =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let p = getParsingInfo ins
    let unsigned = isUnsigned ins.SIMDTyp
    let better a b =
      let cmp = if unsigned then (if isMax then (.>) else (.<))
                else (if isMax then (?>) else (?<))
      AST.ite (cmp a b) a b
    let h = p.Elements / 2
    let dest = tmpVar bld 64<rt>
    for e in 0 .. h - 1 do
      let pair expr =
        better (elem expr (2 * e) p.ESize) (elem expr (2 * e + 1) p.ESize)
      elem dest e p.ESize := pair rn
      elem dest (e + h) p.ESize := pair rm
    rd := dest
    putEndLabel bld lblIgnore
  }

let vpmax ins bld = vpmaxmin ins bld true

let vpmin ins bld = vpmaxmin ins bld false

/// <summary>
/// VPADDL and VPADAL: each ADJACENT PAIR summed into an element twice as
/// wide, and for VPADAL added to what the destination already holds.
///
/// The widening is what tells these from VPADD: the sum of two elements
/// cannot overflow when it is written at twice their width, so nothing is
/// lost and no signedness question arises after the extension.
/// </summary>
let private vpaddlong (ins: Instruction) bld accumulate =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    let wide = p.RtESize * 2
    let h = p.Elements / 2
    let sum src e =
      ext wide (elem src (2 * e) p.ESize)
      .+ ext wide (elem src (2 * e + 1) p.ESize)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let struct (tB, tA) = tmpVars2 bld 64<rt>
      tB := srcB
      tA := srcA
      let answer d src e =
        let s = sum src e
        if accumulate then elem d e (2 * p.ESize) .+ s else s
      for e in 0 .. h - 1 do
        elem dstA e (2 * p.ESize) := answer dstA tA e
        elem dstB e (2 * p.ESize) := answer dstB tB e
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      let t = tmpVar bld 64<rt>
      t := src
      let answer e =
        let s = sum t e
        if accumulate then elem dst e (2 * p.ESize) .+ s else s
      for e in 0 .. h - 1 do
        elem dst e (2 * p.ESize) := answer e
    putEndLabel bld lblIgnore
  }

let vpaddl ins bld = vpaddlong ins bld false

let vpadal ins bld = vpaddlong ins bld true

/// <summary>
/// VRSRA: VSRA with the rounding shift rather than the truncating one.
///
/// The rounding is of the SHIFT and not of the accumulation, so the constant
/// goes in before the shift and the sum that follows is ordinary.
/// </summary>
let vrsra (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let signed = not (isUnsigned ins.SIMDTyp)
    let shift = shiftAmountOf ins
    let lane v e = roundingShiftRightLane p signed shift (elem v e p.ESize)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, _) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. p.Elements - 1 do
        elem dstB e p.ESize := elem dstB e p.ESize .+ lane srcB e
        elem dstA e p.ESize := elem dstA e p.ESize .+ lane srcA e
    | _ ->
      let struct (dst, src, _) = getThreeOprs ins
      let dst = transOpr ins bld dst
      let src = transOpr ins bld src
      for e in 0 .. p.Elements - 1 do
        elem dst e p.ESize := elem dst e p.ESize .+ lane src e
    putEndLabel bld lblIgnore
  }

/// <summary>
/// VSLI and VSRI: the source shifted into the destination, with the bits the
/// shift vacated left as they were rather than zeroed.
///
/// That is the whole of what makes them different from VSHL and VSHR, and it
/// is done with a mask: the bits the shift can reach come from the shifted
/// source and the rest from the destination. A shift by the element's whole
/// width leaves the destination alone, which the mask says without a special
/// case.
/// </summary>
let private vshiftInsert (ins: Instruction) bld isLeft =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let shift = shiftAmountOf ins
    let rt = p.RtESize
    let keep =
      (* the bits the shift cannot reach, which the destination keeps *)
      if shift >= p.ESize then System.UInt64.MaxValue
      elif isLeft then (1UL <<< shift) - 1UL
      else ~~~((1UL <<< (p.ESize - shift)) - 1UL)
    let mask = numU64 keep rt
    let moved e =
      if shift >= p.ESize then AST.num0 rt
      elif isLeft then e << numI32 shift rt
      else e >> numI32 shift rt
    let answer old src = (old .& mask) .| (moved src .& AST.not mask)
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, _) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      let struct (opB, opA) = tmpVars2 bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        opB := elem srcB e p.ESize
        opA := elem srcA e p.ESize
        elem dstB e p.ESize := answer (elem dstB e p.ESize) opB
        elem dstA e p.ESize := answer (elem dstA e p.ESize) opA
    | _ ->
      let struct (dst, src, _) = getThreeOprs ins
      let dst = transOpr ins bld dst
      let src = transOpr ins bld src
      let op = tmpVar bld p.RtESize
      for e in 0 .. p.Elements - 1 do
        op := elem src e p.ESize
        elem dst e p.ESize := answer (elem dst e p.ESize) op
    putEndLabel bld lblIgnore
  }

let vsli ins bld = vshiftInsert ins bld true

let vsri ins bld = vshiftInsert ins bld false

/// <summary>
/// VTRN and VZIP: the elements of two registers rearranged between them.
///
/// VZIP interleaves the pair whole -- the first register takes the bottom
/// half of the interleaving and the second the top. VTRN swaps the odd
/// elements of the first with the even elements of the second, which
/// transposes two-by-two blocks.
///
/// Both write BOTH registers, and each register is a source and a
/// destination at once, so every element is read into a temporary before any
/// of them is written. The quadword form is the same permutation over twice
/// as many elements, not the doubleword one done twice.
/// </summary>
let private vpermute (ins: Instruction) bld isZip =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let struct (dst, src) = getTwoOprs ins
    let wide = ins.OprSize = 128<rt>
    let n = if wide then p.Elements * 2 else p.Elements
    let struct (dB, dA) =
      if wide then transOpr128 bld dst
      else struct (transOpr ins bld dst, transOpr ins bld dst)
    let struct (sB, sA) =
      if wide then transOpr128 bld src
      else struct (transOpr ins bld src, transOpr ins bld src)
    let half = p.Elements
    let at reg1 reg2 i =
      elem (if i < half then reg1 else reg2) (i % half) p.ESize
    let a = Array.init n (fun _ -> tmpVar bld p.RtESize)
    let b = Array.init n (fun _ -> tmpVar bld p.RtESize)
    for i in 0 .. n - 1 do
      a[i] := at dA dB i
      b[i] := at sA sB i
    let zipped which i =
      let j = if which then i else i + n
      if j % 2 = 0 then a[j / 2] else b[j / 2]
    let transposed which i =
      if i % 2 = 0 then
        if which then a[i] else a[i + 1]
      else
        if which then b[i - 1] else b[i]
    let pick which i =
      if isZip then zipped which i else transposed which i
    for i in 0 .. n - 1 do
      at dA dB i := pick true i
      at sA sB i := pick false i
    putEndLabel bld lblIgnore
  }

let vtrn ins bld = vpermute ins bld false

let vzip ins bld = vpermute ins bld true

/// VSRA: each lane of the destination gains its own lane of the source,
/// shifted right as VSHR shifts it.
let vsra (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let p = getParsingInfo ins
    let signed = not (isUnsigned ins.SIMDTyp)
    let shift = shiftAmountOf ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dst, src, _) = getThreeOprs ins
      let struct (dstB, dstA) = transOpr128 bld dst
      let struct (srcB, srcA) = transOpr128 bld src
      for e in 0 .. p.Elements - 1 do
        let laneB = shiftRightLane p signed shift (elem srcB e p.ESize)
        let laneA = shiftRightLane p signed shift (elem srcA e p.ESize)
        elem dstB e p.ESize := elem dstB e p.ESize .+ laneB
        elem dstA e p.ESize := elem dstA e p.ESize .+ laneA
    | _ ->
      let struct (dst, src, _) = transThreeOprs ins bld
      for e in 0 .. p.Elements - 1 do
        let lane = shiftRightLane p signed shift (elem src e p.ESize)
        elem dst e p.ESize := elem dst e p.ESize .+ lane
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
