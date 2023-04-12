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

module internal B2R2.FrontEnd.BinLifter.ARM32.Lifter

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.ARM32
open B2R2.FrontEnd.BinLifter.ARM32.IRHelper

let getPC ctxt = getRegVar ctxt R.PC

let getRegNum = function
  | R.R0 -> 1u
  | R.R1 -> 2u
  | R.R2 -> 4u
  | R.R3 -> 8u
  | R.R4 -> 16u
  | R.R5 -> 32u
  | R.R6 -> 64u
  | R.R7 -> 128u
  | R.R8 -> 256u
  | R.SB -> 512u
  | R.SL -> 1024u
  | R.FP -> 2048u
  | R.IP -> 4096u
  | R.SP -> 8192u
  | R.LR -> 16384u
  | R.PC -> 32768u
  | _ -> raise InvalidRegisterException

let regsToUInt32 regs = List.fold (fun acc reg -> acc + getRegNum reg) 0u regs

let regsToExpr regs = numU32 (regsToUInt32 regs) 16<rt>

let sfRegToExpr ctxt = function
  | Vector reg -> getRegVar ctxt reg
  | Scalar (reg, _) -> getRegVar ctxt reg

let simdToExpr ctxt = function
  | SFReg s -> sfRegToExpr ctxt s
(*
  | OneReg s -> sfRegToExpr ctxt s
  | TwoRegs (s1, s2) -> [ sfRegToExpr ctxt s1; sfRegToExpr ctxt s2 ]
  | ThreeRegs (s1, s2, s3) ->
    [ sfRegToExpr ctxt s1; sfRegToExpr ctxt s2; sfRegToExpr ctxt s3 ]
  | FourRegs (s1, s2, s3, s4) -> [ sfRegToExpr ctxt s1; sfRegToExpr ctxt s2;
                                   sfRegToExpr ctxt s3; sfRegToExpr ctxt s4 ]
*)
  | _ -> raise InvalidOperandException

let inline getPseudoRegVar (ctxt: TranslationContext) name pos =
  ctxt.GetPseudoRegVar (Register.toRegID name) pos

let getTwoOprs (ins: InsInfo) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: InsInfo) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: InsInfo) =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

let getImmValue imm =
  match imm with
  | OprImm imm -> imm
  | _ -> raise InvalidOperandException

let getPseudoRegVar128 ctxt r =
  getPseudoRegVar ctxt r 2, getPseudoRegVar ctxt r 1

let transOprToExpr128 ctxt = function
  | OprSIMD (SFReg (Vector reg)) -> getPseudoRegVar128 ctxt reg
  | _ -> raise InvalidOperandException

let transOprToSclar ctxt = function
  | OprSIMD (SFReg (Scalar (reg, Some idx))) -> getRegVar ctxt reg, int32 idx
  | _ -> raise InvalidOperandException

let transOprToExpr (ins: InsInfo) ctxt = function
  | OprSpecReg (reg, _)
  | OprReg reg -> getRegVar ctxt reg
  | OprRegList regs -> regsToExpr regs
  | OprSIMD simd -> simdToExpr ctxt simd
  | OprImm imm ->
    let oprSize = if ins.OprSize = 128<rt> then 64<rt> else ins.OprSize
    numI64 imm oprSize
  | _ -> raise InvalidOperandException

let transOneOpr (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr ins ctxt opr
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (opr1, opr2) ->
    struct (transOprToExpr ins ctxt opr1, transOprToExpr ins ctxt opr2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, opr3) ->
    struct (transOprToExpr ins ctxt opr1,
            transOprToExpr ins ctxt opr2,
            transOprToExpr ins ctxt opr3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins ctxt o1,
            transOprToExpr ins ctxt o2,
            transOprToExpr ins ctxt o3,
            transOprToExpr ins ctxt o4)
  | _ -> raise InvalidOperandException

let bvOfBaseAddr addr = numU64 addr 32<rt>

/// Gets the mask bits for fetching the RFR bit from the NSACR.
/// NSACR bit[19]
let maskNSACRForRFRbit = numI32 524288 32<rt>

let getNSACR ctxt nsacrType =
  let nsacr = getRegVar ctxt R.NSACR
  match nsacrType with
  | NSACR_RFR -> nsacr .& maskNSACRForRFRbit

let isSetNSACRForRFR ctxt = getNSACR ctxt NSACR_RFR == maskNSACRForRFRbit

/// Gets the mask bits for fetching the AW bit from the SCR.
/// SCR bit[5]
let maskSCRForAWbit = numI32 32 32<rt>

/// Gets the mask bits for fetching the FW bit from the SCR.
/// SCR bit[4]
let maskSCRForFWbit = numI32 16 32<rt>

/// Gets the mask bits for fetching the NS bit from the SCR.
/// SCR bit[0]
let maskSCRForNSbit = AST.num1 32<rt>

let getSCR ctxt scrType =
  let scr = getRegVar ctxt R.SCR
  match scrType with
  | SCR_AW -> scr .& maskSCRForAWbit
  | SCR_FW -> scr .& maskSCRForFWbit
  | SCR_NS -> scr .& maskSCRForNSbit

let isSetSCRForAW ctxt = getSCR ctxt SCR_AW == maskSCRForAWbit
let isSetSCRForFW ctxt = getSCR ctxt SCR_FW == maskSCRForFWbit
let isSetSCRForNS ctxt = getSCR ctxt SCR_NS == maskSCRForNSbit

/// Gets the mask bits for fetching the NMFI bit from the SCTLR.
/// SCTLR bit[27]
let maskSCTLRForNMFIbit = AST.num <| BitVector.OfBInt 134217728I 32<rt>

let getSCTLR ctxt sctlrType =
  let sctlr = getRegVar ctxt R.SCTLR
  match sctlrType with
  | SCTLR_NMFI -> sctlr .& maskSCTLRForNMFIbit

let isSetSCTLRForNMFI ctxt = getSCTLR ctxt SCTLR_NMFI == maskSCTLRForNMFIbit

let enablePSRBits ctxt reg psrType =
  let psr = getRegVar ctxt reg
  match psrType with
  | PSR.Cond -> psr .| maskPSRForCondbits
  | PSR.N -> psr .| maskPSRForNbit
  | PSR.Z -> psr .| maskPSRForZbit
  | PSR.C -> psr .| maskPSRForCbit
  | PSR.V -> psr .| maskPSRForVbit
  | PSR.Q -> psr .| maskPSRForQbit
  | PSR.IT10 -> psr .| maskPSRForIT10bits
  | PSR.J -> psr .| maskPSRForJbit
  | PSR.GE -> psr .| maskPSRForGEbits
  | PSR.IT72 -> psr .| maskPSRForIT72bits
  | PSR.E -> psr .| maskPSRForEbit
  | PSR.A -> psr .| maskPSRForAbit
  | PSR.I -> psr .| maskPSRForIbit
  | PSR.F -> psr .| maskPSRForFbit
  | PSR.T -> psr .| maskPSRForTbit
  | PSR.M -> psr .| maskPSRForMbits
  | _ -> Utils.impossible ()

let disablePSRBits ctxt reg psrType =
  let psr = getRegVar ctxt reg
  match psrType with
  | PSR.Cond -> psr .& AST.not maskPSRForCondbits
  | PSR.N -> psr .& AST.not maskPSRForNbit
  | PSR.Z -> psr .& AST.not maskPSRForZbit
  | PSR.C -> psr .& AST.not maskPSRForCbit
  | PSR.V -> psr .& AST.not maskPSRForVbit
  | PSR.Q -> psr .& AST.not maskPSRForQbit
  | PSR.IT10 -> psr .& AST.not maskPSRForIT10bits
  | PSR.J -> psr .& AST.not maskPSRForJbit
  | PSR.GE -> psr .& AST.not maskPSRForGEbits
  | PSR.IT72 -> psr .& AST.not maskPSRForIT72bits
  | PSR.E -> psr .& AST.not maskPSRForEbit
  | PSR.A -> psr .& AST.not maskPSRForAbit
  | PSR.I -> psr .& AST.not maskPSRForIbit
  | PSR.F -> psr .& AST.not maskPSRForFbit
  | PSR.T -> psr .& AST.not maskPSRForTbit
  | PSR.M -> psr .& AST.not maskPSRForMbits
  | _ -> Utils.impossible ()

let psrShift psrType expr =
  match psrType with
  | PSR.Cond -> expr << (numI32 28 32<rt>)
  | PSR.N -> expr << (numI32 31 32<rt>)
  | PSR.Z -> expr << (numI32 30 32<rt>)
  | PSR.C -> expr << (numI32 29 32<rt>)
  | PSR.V -> expr << (numI32 28 32<rt>)
  | PSR.Q -> expr << (numI32 27 32<rt>)
  | PSR.IT10 -> expr << (numI32 25 32<rt>)
  | PSR.J -> expr << (numI32 24 32<rt>)
  | PSR.GE -> expr << (numI32 16 32<rt>)
  | PSR.IT72 -> expr << (numI32 10 32<rt>)
  | PSR.E -> expr << (numI32 9 32<rt>)
  | PSR.A -> expr << (numI32 8 32<rt>)
  | PSR.I -> expr << (numI32 7 32<rt>)
  | PSR.F -> expr << (numI32 6 32<rt>)
  | PSR.T -> expr << (numI32 5 32<rt>)
  | PSR.M -> expr
  | _ -> Utils.impossible ()

let setPSR ctxt reg psrType expr =
  disablePSRBits ctxt reg psrType
  .| (AST.zext 32<rt> expr |> psrShift psrType)

let getCarryFlag ctxt =
  getPSR ctxt R.CPSR PSR.C >> (numI32 29 32<rt>)

let getZeroMask maskSize regType =
  BitVector.OfBInt (BigInteger.getMask maskSize) regType
  |> BitVector.BNot |> AST.num

let zMaskAnd e regType maskSize =
  e .& (getZeroMask maskSize regType)

let maskAndOR e1 e2 regType maskSize =
  let mask = getZeroMask maskSize regType
  let expr = e1 .& mask
  expr .| e2

let getOverflowFlagOnAdd e1 e2 r (ir: IRBuilder) =
  let struct (e1High, rHigh) = tmpVars2 ir 1<rt>
  !!ir (e1High := AST.xthi 1<rt> e1)
  let e2High = AST.xthi 1<rt> e2
  !!ir (rHigh := AST.xthi 1<rt> r)
  struct ((e1High == e2High) .& (e1High <+> rHigh), rHigh)

let parseCond = function
  | Condition.EQ -> struct (0b000, 0)
  | Condition.NE -> struct (0b000, 1)
  | Condition.CS -> struct (0b001, 0)
  | Condition.CC -> struct (0b001, 1)
  | Condition.MI -> struct (0b010, 0)
  | Condition.PL -> struct (0b010, 1)
  | Condition.VS -> struct (0b011, 0)
  | Condition.VC -> struct (0b011, 1)
  | Condition.HI -> struct (0b100, 0)
  | Condition.LS -> struct (0b100, 1)
  | Condition.GE -> struct (0b101, 0)
  | Condition.LT -> struct (0b101, 1)
  | Condition.GT -> struct (0b110, 0)
  | Condition.LE -> struct (0b110, 1)
  | Condition.AL -> struct (0b111, 0)
  | Condition.UN -> struct (0b111, 1)
  | _ -> raise InvalidOperandException

/// Returns TRUE if the current instruction needs to be executed. See page
/// A8-289. function : ConditionPassed()
let conditionPassed ctxt cond =
  let struct (cond1, cond2) = parseCond cond
  let result =
    match cond1 with
    | 0b000 -> isSetCPSRz ctxt
    | 0b001 -> isSetCPSRc ctxt
    | 0b010 -> isSetCPSRn ctxt
    | 0b011 -> isSetCPSRv ctxt
    | 0b100 -> isSetCPSRc ctxt .& AST.not (isSetCPSRz ctxt)
    | 0b101 -> isSetCPSRn ctxt == isSetCPSRv ctxt
    | 0b110 ->
      isSetCPSRn ctxt == isSetCPSRv ctxt .& AST.not (isSetCPSRz ctxt)
    | 0b111 -> AST.b1
    | _ -> raise InvalidOperandException
  if cond1 <> 0b111 && cond2 = 1 then AST.not result else result

/// Logical shift left of a bitstring, with carry output, on page A2-41.
/// for Register amount. function : LSL_C()
let shiftLSLCForRegAmount value regType amount carryIn =
  let chkZero = AST.relop RelOpType.EQ amount (numU32 0u regType)
  let result = value << amount
  let carryOut = value << (amount .- AST.num1 regType) |> AST.xthi 1<rt>
  AST.ite chkZero value result, AST.ite chkZero carryIn carryOut

/// Logical shift left of a bitstring, on page A2-41. for Register amount.
/// function : LSL()
let shiftLSLForRegAmount value regType amount carryIn =
  shiftLSLCForRegAmount value regType amount carryIn |> fst

/// Logical shift right of a bitstring, with carry output, on page A2-41.
/// for Register amount. function : LSR_C()
let shiftLSRCForRegAmount value regType amount carryIn =
  let chkZero = AST.relop RelOpType.EQ amount (numU32 0u regType)
  let result = value >> amount
  let carryOut = value >> (amount .- AST.num1 regType ) |> AST.xtlo 1<rt>
  AST.ite chkZero value result, AST.ite chkZero carryIn carryOut

/// Logical shift right of a bitstring, on page A2-41. for Register amount.
/// function : LSR()
let shiftLSRForRegAmount value regType amount carryIn =
  shiftLSRCForRegAmount value regType amount carryIn |> fst

/// Arithmetic shift right of a bitstring, with carry output, on page A2-41.
/// for Register amount. function : ASR_C()
let shiftASRCForRegAmount value regType amount carryIn =
  let chkZero = AST.relop RelOpType.EQ amount (numU32 0u regType)
  let result = value ?>> amount
  let carryOut = value ?>> (amount .- AST.num1 regType ) |> AST.xtlo 1<rt>
  AST.ite chkZero value result, AST.ite chkZero carryIn carryOut

/// Logical shift right of a bitstring, on page A2-41. for Register amount.
/// function : ASR()
let shiftASRForRegAmount value regType amount carryIn =
  shiftASRCForRegAmount value regType amount carryIn|> fst

/// Rotate right of a bitstring, with carry output, on page A2-41.
/// for Register amount. function : ROR_C()
let shiftRORCForRegAmount value regType amount carryIn =
  let chkZero = AST.relop RelOpType.EQ amount (numU32 0u regType)
  let m = amount .% (numI32 (RegType.toBitWidth regType) regType)
  let nm = (numI32 32 32<rt>) .- m
  let result = shiftLSRForRegAmount value regType m carryIn .|
               shiftLSLForRegAmount value regType nm carryIn
  let carryOut = AST.xthi 1<rt> result
  AST.ite chkZero value result, AST.ite chkZero carryIn carryOut

/// Rotate right of a bitstring, on page A2-41. for Register amount.
/// function : ROR()
let shiftRORForRegAmount value regType amount carryIn =
  shiftRORCForRegAmount value regType amount carryIn |> fst

/// Rotate right with extend of a bitstring, with carry output, on page A2-41.
/// for Register amount. function : RRX_C()
let shiftRRXCForRegAmount value regType amount carryIn =
  let chkZero = AST.relop RelOpType.EQ amount (numU32 0u regType)
  let amount1 = numI32 (RegType.toBitWidth regType) regType
  let e1 = shiftLSLForRegAmount (AST.zext 32<rt> carryIn) regType
            (amount1 .- AST.num1 regType) carryIn
  let e2 = shiftLSRForRegAmount value regType (AST.num1 regType) carryIn
  AST.ite chkZero value (e1 .| e2),
  AST.ite chkZero carryIn (AST.xtlo 1<rt> value)

/// Rotate right with extend of a bitstring, on page A2-41. for Register amount.
/// function : RRX()
let shiftRRXForRegAmount value regType amount carryIn =
  shiftRRXCForRegAmount value regType amount carryIn |> fst

/// Perform a specified shift by a specified amount on a bitstring,
/// with carry output, on page A8-292.
let shiftCForRegAmount value regType shiftType amount carryIn =
  let carryIn = AST.xtlo 1<rt> carryIn
  match shiftType with
  | SRTypeLSL -> shiftLSLCForRegAmount value regType amount carryIn
  | SRTypeLSR -> shiftLSRCForRegAmount value regType amount carryIn
  | SRTypeASR -> shiftASRCForRegAmount value regType amount carryIn
  | SRTypeROR -> shiftRORCForRegAmount value regType amount carryIn
  | SRTypeRRX -> shiftRRXCForRegAmount value regType amount carryIn

/// Logical shift left of a bitstring, with carry output, on page A2-41.
/// function : LSL_C()
let shiftLSLC value regType amount =
  Utils.assertByCond (amount > 0u) InvalidShiftAmountException
  let amount = numU32 amount regType
  value << amount, value << (amount .- AST.num1 regType ) |> AST.xthi 1<rt>

/// Logical shift left of a bitstring, on page A2-41. function : LSL()
let shiftLSL value regType amount =
  Utils.assertByCond (amount >= 0u) InvalidShiftAmountException
  if amount = 0u then value else shiftLSLC value regType amount |> fst

/// Logical shift right of a bitstring, with carry output, on page A2-41.
/// function : LSR_C()
let shiftLSRC value regType amount =
  Utils.assertByCond (amount > 0u) InvalidShiftAmountException
  let amount' = numU32 amount regType
  value >> amount', AST.extract value 1<rt> (amount - 1u |> Convert.ToInt32)

/// Logical shift right of a bitstring, on page A2-41. function : LSR()
let shiftLSR value regType amount =
  Utils.assertByCond (amount >= 0u) InvalidShiftAmountException
  if amount = 0u then value else shiftLSRC value regType amount |> fst

/// Arithmetic shift right of a bitstring, with carry output, on page A2-41.
/// function : ASR_C()
let shiftASRC value regType amount =
  Utils.assertByCond (amount > 0u) InvalidShiftAmountException
  let amount = numU32 amount regType
  value ?>> amount, value ?>> (amount .- AST.num1 regType ) |> AST.xtlo 1<rt>

/// Logical shift right of a bitstring, on page A2-41. function : ASR()
let shiftASR value regType amount =
  Utils.assertByCond (amount >= 0u) InvalidShiftAmountException
  if amount = 0u then value else shiftASRC value regType amount |> fst

/// Rotate right of a bitstring, with carry output, on page A2-41.
/// function : ROR_C()
let shiftRORC value regType amount =
  Utils.assertByCond (amount <> 0u) InvalidShiftAmountException
  let m = amount % uint32 (RegType.toBitWidth regType)
  let result = shiftLSR value regType m .| shiftLSL value regType (32u - m)
  result, AST.xthi 1<rt> result

/// Rotate right of a bitstring, on page A2-41. function : ROR()
let shiftROR value regType amount =
  if amount = 0u then value else shiftRORC value regType amount |> fst

/// Rotate right with extend of a bitstring, with carry output, on page A2-41.
/// function : RRX_C()
let shiftRRXC value regType amount =
  let e1 = uint32 (RegType.toBitWidth regType) - 1u |> shiftLSL amount regType
  let e2 = shiftLSR value regType 1u
  e1 .| e2, AST.xtlo 1<rt> value

/// Rotate right with extend of a bitstring, on page A2-41.
/// function : RRX()
let shiftRRX value regType amount = shiftRRXC value regType amount |> fst

/// Perform a specified shift by a specified amount on a bitstring,
/// with carry output, on page A8-292. function : Shift_C()
let shiftC value regType shiftType amount carryIn =
  if amount = 0u then value, carryIn
  else
    match shiftType with
    | SRTypeLSL -> shiftLSLC value regType amount
    | SRTypeLSR -> shiftLSRC value regType amount
    | SRTypeASR -> shiftASRC value regType amount
    | SRTypeROR -> shiftRORC value regType amount
    | SRTypeRRX -> shiftRRXC value regType carryIn

/// Perform a specified shift by a specified amount on a bitstring,
/// on page A8-292.
let shiftForRegAmount value regType shiftType amount carryIn =
  shiftCForRegAmount value regType shiftType amount carryIn |> fst

/// Perform a specified shift by a specified amount on a bitstring,
/// on page A8-292. function : OprShift()
let shift value regType shiftType amount carryIn =
  shiftC value regType shiftType amount carryIn |> fst

/// Addition of bitstrings, with carry input and carry/overflow outputs,
/// on page A2-43. function : AddWithCarry()
let addWithCarry src1 src2 carryIn (ir: IRBuilder) =
  let result = !+ir 32<rt>
  !!ir (result := src1 .+ src2 .+ carryIn)
  let carryOut =
    AST.ite (carryIn == (numU32 1u 32<rt>))
      (AST.ge src1 (AST.not src2)) (AST.gt src1 (AST.not src2))
  let struct (overflow, rHigh) = getOverflowFlagOnAdd src1 src2 result ir
  struct (result, carryOut, overflow, rHigh)

let addWithCarryOnlyResult src1 src2 carryIn = src1 .+ src2 .+ carryIn

/// Sets the ARM instruction set, on page A2-51.
let selectARMInstrSet ctxt (ir: IRBuilder) =
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.J)
  !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.T)

/// Sets the ARM instruction set, on page A2-51.
let selectThumbInstrSet ctxt (ir: IRBuilder) =
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.J)
  !!ir (cpsr := enablePSRBits ctxt R.CPSR PSR.T)

/// Sets the instruction set currently in use, on page A2-51.
/// SelectInstrSet()
let selectInstrSet ctxt ir = function
  | ArchOperationMode.ARMMode -> selectARMInstrSet ctxt ir
  | _ -> selectThumbInstrSet ctxt ir

/// Write value to R.PC, without interworking, on page A2-47.
/// function : BranchWritePC()
let branchWritePC ctxt (ins: InsInfo) addr jmpInfo =
  let addr = zMaskAnd addr 32<rt> 1
  match ins.Mode with
  | ArchOperationMode.ARMMode -> AST.interjmp addr jmpInfo
  | _ -> AST.interjmp addr jmpInfo

let disableITStateForCondBranches ctxt isUnconditional (ir: IRBuilder) =
  if isUnconditional then ()
  else
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.IT10)
    !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.IT72)

/// Write value to R.PC, with interworking, on page A2-47.
/// function : BXWritePC()
let bxWritePC ctxt isUnconditional addr (ir: IRBuilder) =
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let cond1 = AST.xtlo 1<rt> addr == AST.b1
  disableITStateForCondBranches ctxt isUnconditional ir
  !!ir (AST.cjmp cond1 (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  selectThumbInstrSet ctxt ir
  !!ir (AST.interjmp (zMaskAnd addr 32<rt> 1) InterJmpKind.SwitchToThumb)
  !!ir (AST.lmark lblL1)
  selectARMInstrSet ctxt ir
  !!ir (AST.interjmp addr InterJmpKind.SwitchToARM)

/// Write value to R.PC, with interworking for ARM only from ARMv7 on page
/// A2-47. function : ALUWritePC()
let aluWritePC ctxt (ins: InsInfo) isUnconditional addr ir =
  match ins.Mode with
  | ArchOperationMode.ARMMode -> bxWritePC ctxt isUnconditional addr ir
  | _ -> !!ir (branchWritePC ctxt ins addr InterJmpKind.Base)

/// Write value to R.PC, with interworking (without it before ARMv5T),
/// on page A2-47. function : LoadWritePC()
let loadWritePC ctxt isUnconditional ir result =
  bxWritePC ctxt isUnconditional result ir

/// Position of rightmost 1 in a bitstring, on page AppxP-2653.
/// function : LowestSetBit()
let lowestSetBit b size =
  let rec loop = function
    | n when n = size -> n
    | n when (b >>> n) &&& 1u = 1u -> n
    | n -> loop (n + 1)
  loop 0

/// Position of leftmost 1 in a bitstring, on page AppxP-2653.
/// function : HighestSetBit()
let highestSetBit b size =
  let rec loop = function
    | n when n < 0 -> -1
    | n when b &&& (1u <<< n) <> 0u -> n
    | n -> loop (n - 1)
  loop (size - 1)

/// Count number of ones in a bitstring, on page AppxP-2653.
/// function : BitCount()
let bitCountFor16Bits expr =
  let n0 = AST.num0 16<rt>
  let n1 = AST.num1 16<rt>
  let res0 = AST.ite (expr .& n1 == n1) n1 n0
  let res1 = AST.ite ((expr >> n1) .& n1 == n1) n1 n0
  let res2 = AST.ite ((expr >> (numI32 2 16<rt>)) .& n1 == n1) n1 n0
  let res3 = AST.ite ((expr >> (numI32 3 16<rt>)) .& n1 == n1) n1 n0
  let res4 = AST.ite ((expr >> (numI32 4 16<rt>)) .& n1 == n1) n1 n0
  let res5 = AST.ite ((expr >> (numI32 5 16<rt>)) .& n1 == n1) n1 n0
  let res6 = AST.ite ((expr >> (numI32 6 16<rt>)) .& n1 == n1) n1 n0
  let res7 = AST.ite ((expr >> (numI32 7 16<rt>)) .& n1 == n1) n1 n0
  let res8 = AST.ite ((expr >> (numI32 8 16<rt>)) .& n1 == n1) n1 n0
  let res9 = AST.ite ((expr >> (numI32 9 16<rt>)) .& n1 == n1) n1 n0
  let res10 = AST.ite ((expr >> (numI32 10 16<rt>)) .& n1 == n1) n1 n0
  let res11 = AST.ite ((expr >> (numI32 11 16<rt>)) .& n1 == n1) n1 n0
  let res12 = AST.ite ((expr >> (numI32 12 16<rt>)) .& n1 == n1) n1 n0
  let res13 = AST.ite ((expr >> (numI32 13 16<rt>)) .& n1 == n1) n1 n0
  let res14 = AST.ite ((expr >> (numI32 14 16<rt>)) .& n1 == n1) n1 n0
  let res15 = AST.ite ((expr >> (numI32 15 16<rt>)) .& n1 == n1) n1 n0
  res0 .+ res1 .+ res2 .+ res3 .+ res4 .+ res5 .+ res6 .+ res7 .+ res8 .+
  res9 .+ res10 .+ res11 .+ res12 .+ res13 .+ res14 .+ res15

/// Count number of ones in a bitstring, on page AppxP-2653.
/// function : BitCount() (for uint32)
let bitCount num size =
  let rec loop cnt res =
    if cnt = size then res
    elif (num >>> cnt) &&& 1u = 1u then loop (cnt + 1) (res + 1)
    else loop (cnt + 1) res
  loop 0 0

/// Number of zeros at left end of bitstring, on page AppxP-2653.
/// function : CountLeadingZeroBits()
let countLeadingZeroBits b size = size - 1 - highestSetBit b size

/// OprMemory access that must be aligned, at specified privilege level,
/// on page B2-1294. function : MemA[]
let memAWithPriv addr size value = AST.b0 // FIXME

/// OprMemory access that must be aligned, at current privilege level,
/// on page B2-1294. function : MemA_with_priv[]
let memA addr size value = memAWithPriv addr size value

/// OprMemory access that must be aligned, at specified privilege level,
/// on page B2-1294. function : MemU_with_priv[]
let memUWithPriv addr size value = AST.b0 // FIXME

/// OprMemory access without alignment requirement, at current privilege level,
/// on page B2-1295. function : MemU[]
let memU addr size value = memUWithPriv addr size value

/// Value stored when an ARM instruction stores the R.PC, on page A2-47.
/// function : PCStoreValue()
let pcStoreValue ctxt = getPC ctxt

/// Returns TRUE in Secure state or if no Security Extensions, on page B1-1157.
/// function : IsSecure()
let isSecure ctxt =
  AST.not (haveSecurityExt ()) .| AST.not (isSetSCRForNS ctxt) .|
  (getPSR ctxt R.CPSR PSR.M == (numI32 0b10110 32<rt>))

/// Return TRUE if current mode is executes at PL1 or higher, on page B1-1142.
/// function : CurrentModeIsNotUser()
let currentModeIsNotUser ctxt =
  let modeM = getPSR ctxt R.CPSR PSR.M
  let modeCond = isBadMode modeM
  let ite1 =
    AST.ite (modeM == (numI32 0b10000 32<rt>)) AST.b0 AST.b1
  AST.ite modeCond (AST.undef 1<rt> "UNPREDICTABLE") ite1

/// Bitstring replication, on page AppxP-2652.
/// function : Replicate()
let replicate expr regType lsb width value =
  let v = BitVector.OfBInt (BigInteger.getMask width <<< lsb) regType
  if value = 0 then expr .& (v |> BitVector.BNot |> AST.num)
  else expr .| (v |> AST.num)

/// All-ones bitstring, on page AppxP-2652.
let ones rt = BitVector.OfBInt (RegType.getMask rt) rt |> AST.num

let writeModeBits ctxt value isExcptReturn (ir: IRBuilder) =
  let lblL8 = !%ir "L8"
  let lblL9 = !%ir "L9"
  let lblL10 = !%ir "L10"
  let lblL11 = !%ir "L11"
  let lblL12 = !%ir "L12"
  let lblL13 = !%ir "L13"
  let lblL14 = !%ir "L14"
  let lblL15 = !%ir "L15"
  let lblL16 = !%ir "L16"
  let lblL17 = !%ir "L17"
  let valueM = value .& maskPSRForMbits
  let cpsrM = getPSR ctxt R.CPSR PSR.M
  let num11010 = numI32 0b11010 32<rt>
  let chkSecure = AST.not (isSecure ctxt)
  let cond1 = chkSecure .& (valueM == (numI32 0b10110 32<rt>))
  let cond2 = chkSecure .& isSetNSACRForRFR ctxt .&
              (valueM == (numI32 0b10001 32<rt>))
  let cond3 = chkSecure .& (valueM == num11010)
  let cond4 = chkSecure .& (cpsrM != num11010) .& (valueM == num11010)
  let cond5 = (cpsrM == num11010) .& (valueM != num11010)
  !!ir (AST.cjmp cond1 (AST.name lblL8) (AST.name lblL9))
  !!ir (AST.lmark lblL8)
  !!ir (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  !!ir (AST.lmark lblL9)
  !!ir (AST.cjmp cond2 (AST.name lblL10) (AST.name lblL11))
  !!ir (AST.lmark lblL10)
  !!ir (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  !!ir (AST.lmark lblL11)
  !!ir (AST.cjmp cond3 (AST.name lblL12) (AST.name lblL13))
  !!ir (AST.lmark lblL12)
  !!ir (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  !!ir (AST.lmark lblL13)
  !!ir (AST.cjmp cond4 (AST.name lblL14) (AST.name lblL15))
  !!ir (AST.lmark lblL14)
  !!ir (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  !!ir (AST.lmark lblL15)
  !!ir (AST.cjmp cond5 (AST.name lblL16) (AST.name lblL17))
  !!ir (AST.lmark lblL16)
  if Operators.not isExcptReturn then
    !!ir (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  else ()
  !!ir (AST.lmark lblL17)
  let mValue = value .& maskPSRForMbits
  !!ir
    (getRegVar ctxt R.CPSR := disablePSRBits ctxt R.CPSR PSR.M .| mValue)

let transShiftOprs ins ctxt opr1 opr2 =
  match opr1, opr2 with
  | OprReg _, OprShift (typ, Imm imm) ->
    let e = transOprToExpr ins ctxt opr1
    shift e 32<rt> typ imm (getCarryFlag ctxt)
  | OprReg _, OprRegShift (typ, reg) ->
    let e = transOprToExpr ins ctxt opr1
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    shiftForRegAmount e 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfMVNS (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins ctxt
  | ThreeOperands (opr1, opr2, opr3) ->
    struct (transOprToExpr ins ctxt opr1, transShiftOprs ins ctxt opr2 opr3)
  | _ -> raise InvalidOperandException

let transTwoOprsOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    struct (e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let transThreeOprsOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> transThreeOprs ins ctxt
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let struct (e1, e2, e3) = transThreeOprs ins ctxt
    e1, e2, shift e3 32<rt> SRTypeLSL 0u carryIn
  | _ -> raise InvalidOperandException

let transFourOprsOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1, e2 = transOprToExpr ins ctxt opr1, transOprToExpr ins ctxt opr2
    struct (e1, e2, transShiftOprs ins ctxt opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    let e3 = transOprToExpr ins ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let parseOprOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADC ins ctxt
  | ThreeOperands _ -> transThreeOprsOfADC ins ctxt
  | FourOperands _ -> transFourOprsOfADC ins ctxt
  | _ -> raise InvalidOperandException

let checkCondition (ins: InsInfo) ctxt isUnconditional (ir: IRBuilder) =
  if isUnconditional then None
  else
    let lblIgnore = !%ir "IgnoreExec"
    let lblPass = !%ir "NeedToExec"
    let cond = conditionPassed ctxt ins.Condition
    !!ir (AST.cjmp cond (AST.name lblPass) (AST.name lblIgnore))
    !!ir (AST.lmark lblPass)
    Some lblIgnore

/// Update ITState after normal execution of an IT-block instruction. See A2-52
/// function: ITAdvance().
let itAdvance ctxt (ir: IRBuilder) =
  let cond = !+ir 1<rt>
  let struct (itstate, nextstate) = tmpVars2 ir 32<rt>
  let lblThen = !%ir "LThen"
  let lblElse = !%ir "LElse"
  let lblEnd = !%ir "LEnd"
  let cpsr = getRegVar ctxt R.CPSR
  let cpsrIT10 =
    getPSR ctxt R.CPSR PSR.IT10 >> (numI32 25 32<rt>)
  let cpsrIT72 =
    getPSR ctxt R.CPSR PSR.IT72 >> (numI32 8 32<rt>)
  let mask10 = numI32 0x3 32<rt> (* For ITSTATE[1:0] *)
  let mask20 = numI32 0x7 32<rt> (* For ITSTATE[2:0] *)
  let mask40 = numI32 0x1f 32<rt> (* For ITSTATE[4:0] *)
  let mask42 = numI32 0x1c 32<rt> (* For ITSTATE[4:2] *)
  let cpsrIT42 = cpsr .& (numI32 0xffffe3ff 32<rt>)
  let num8 = numI32 8 32<rt>
  !!ir (itstate := cpsrIT72 .| cpsrIT10)
  !!ir (cond := ((itstate .& mask20) == AST.num0 32<rt>))
  !!ir (AST.cjmp cond (AST.name lblThen) (AST.name lblElse))
  !!ir (AST.lmark lblThen)
  !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.IT10)
  !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.IT72)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblElse)
  !!ir (nextstate := (itstate .& mask40 << AST.num1 32<rt>))
  !!ir (cpsr := nextstate .& mask10 |> setPSR ctxt R.CPSR PSR.IT10)
  !!ir (cpsr := cpsrIT42 .| ((nextstate .& mask42) << num8))
  !!ir (AST.lmark lblEnd)

let putEndLabel ctxt lblIgnore ir =
  match lblIgnore with
  | Some lblIgnore ->
    !!ir (AST.lmark lblIgnore)
    itAdvance ctxt ir
  | None -> ()

let putEndLabelForBranch ctxt lblIgnore (brIns: InsInfo) ir =
  match lblIgnore with
  | Some lblIgnore ->
    !!ir (AST.lmark lblIgnore)
    itAdvance ctxt ir
    let target = numU64 (brIns.Address + uint64 brIns.Length) 32<rt>
    !!ir (AST.interjmp target InterJmpKind.Base)
  | None -> ()

let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let convertPCOpr (ins: InsInfo) insLen ctxt opr =
  if opr = getPC ctxt then
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
    opr .+ (numI32 rel 32<rt>)
  else opr

let adc isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = parseOprOfADC ins ctxt
  let src1 = convertPCOpr ins insLen ctxt src1
  let src2 = convertPCOpr ins insLen ctxt src2
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSetFlags then
    let struct (t1, t2) = tmpVars2 ir 32<rt>
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 t2 (getCarryFlag ctxt) ir
    !!ir (dst := result)
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  else
    let result = !+ir 32<rt>
    !!ir (result := addWithCarryOnlyResult src1 src2 (getCarryFlag ctxt))
    if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
    else !!ir (dst := result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transTwoOprsOfADD (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    struct (e1, e1, e2)
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    struct (e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let transThreeOprsOfADD (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> transThreeOprs ins ctxt
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let struct (e1, e2, e3) = transThreeOprs ins ctxt
    struct (e1, e2, shift e3 32<rt> SRTypeLSL 0u carryIn)
  | _ -> raise InvalidOperandException

let transFourOprsOfADD (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    struct (e1, e2, transShiftOprs ins ctxt opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    let e3 = transOprToExpr ins ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let parseOprOfADD (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADD ins insLen ctxt
  | ThreeOperands _ -> transThreeOprsOfADD ins insLen ctxt
  | FourOperands _ -> transFourOprsOfADD ins insLen ctxt
  | _ -> raise InvalidOperandException

let add isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = parseOprOfADD ins insLen ctxt
  let src1 = convertPCOpr ins insLen ctxt src1
  let src2 = convertPCOpr ins insLen ctxt src2
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSetFlags then
    let struct (t1, t2) = tmpVars2 ir 32<rt>
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 t2 (AST.num0 32<rt>) ir
    !!ir (dst := result)
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  else
    let result = !+ir 32<rt>
    !!ir (result := addWithCarryOnlyResult src1 src2 (AST.num0 32<rt>))
    if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
    else !!ir (dst := result)
    putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// Align integer or bitstring to multiple of an integer, on page AppxP-2655
/// function : Align()
let align e1 e2 = e2 .* (e1 ./ e2)

let pcOffset (ins: InsInfo) =
  if ins.Mode = ArchOperationMode.ARMMode then 8UL else 4UL

let transLableOprsOfBL ins targetMode imm =
  let offset = pcOffset ins
  let pc =
    match targetMode with
    | ArchOperationMode.ARMMode ->
      let addr = bvOfBaseAddr (ins.Address + offset)
      align addr (numI32 4 32<rt>)
    | ArchOperationMode.ThumbMode -> bvOfBaseAddr (ins.Address + offset)
    | _ -> raise InvalidTargetArchModeException
  pc .+ (numI64 imm 32<rt>)

let targetModeOfBL (ins: InsInfo) =
  match ins.Opcode, ins.Mode with
  | Op.BL, mode -> struct (mode, InterJmpKind.IsCall)
  | Op.BLX, ArchOperationMode.ARMMode ->
    struct (ArchOperationMode.ThumbMode, InterJmpKind.SwitchToThumb)
  | Op.BLX, ArchOperationMode.ThumbMode ->
    struct (ArchOperationMode.ARMMode, InterJmpKind.SwitchToARM)
  | _ -> raise InvalidTargetArchModeException

let parseOprOfBL ins =
  let struct (targetMode, callKind) = targetModeOfBL ins
  match ins.Operands with
  | OneOperand (OprMemory (LiteralMode imm)) ->
    struct (transLableOprsOfBL ins targetMode imm, targetMode, callKind)
  | _ -> raise InvalidOperandException

let bl ins insLen ctxt =
  let ir = !*ctxt
  let struct (alignedAddr, targetMode, callKind) = parseOprOfBL ins
  let lr = getRegVar ctxt R.LR
  let retAddr = bvOfBaseAddr ins.Address .+ (numI32 4 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if ins.Mode = ArchOperationMode.ARMMode then !!ir (lr := retAddr)
  else !!ir (lr := maskAndOR retAddr (AST.num1 32<rt>) 32<rt> 1)
  selectInstrSet ctxt ir targetMode
  !!ir (branchWritePC ctxt ins alignedAddr callKind)
  putEndLabelForBranch ctxt lblIgnore ins ir
  !>ir insLen

let blxWithReg (ins: InsInfo) insLen reg ctxt =
  let ir = !*ctxt
  let lr = getRegVar ctxt R.LR
  let addr = bvOfBaseAddr ins.Address
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if ins.Mode = ArchOperationMode.ARMMode then
    !!ir (lr := addr .+ (numI32 4 32<rt>))
  else
    let addr = addr .+ (numI32 2 32<rt>)
    !!ir (lr := maskAndOR addr (AST.num1 32<rt>) 32<rt> 1)
  bxWritePC ctxt isUnconditional (getRegVar ctxt reg) ir
  putEndLabelForBranch ctxt lblIgnore ins ir
  !>ir insLen

let branchWithLink (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand (OprReg reg) -> blxWithReg ins insLen reg ctxt
  | _ -> bl ins insLen ctxt

let parseOprOfPUSHPOP (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprReg r) -> regsToUInt32 [ r ]
  | OneOperand (OprRegList regs) -> regsToUInt32 regs
  | _ -> raise InvalidOperandException

let pushLoop ctxt numOfReg addr (ir: IRBuilder) =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let t = !+ir 32<rt>
      !!ir (t := addr)
      if count = 13 && count <> lowestSetBit numOfReg 32 then
        !!ir (AST.loadLE 32<rt> t := (AST.undef 32<rt> "UNKNOWN"))
      else
        let reg = count |> uint32 |> OperandHelper.getRegister
        !!ir (AST.loadLE 32<rt> t := getRegVar ctxt reg)
      t .+ (numI32 4 32<rt>)
    else addr
  List.fold loop addr [ 0 .. 14 ]

let push ins insLen ctxt =
  let ir = !*ctxt
  let t0 = !+ir 32<rt>
  let sp = getRegVar ctxt R.SP
  let numOfReg = parseOprOfPUSHPOP ins
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = sp .- (numI32 stackWidth 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t0 := addr)
  let addr = pushLoop ctxt numOfReg t0 ir
  if (numOfReg >>> 15 &&& 1u) = 1u then
    !!ir (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  else ()
  !!ir (sp := t0)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// shared/functions/vector/SignedSatQ, on page Armv8 Pseudocode-7927
let sSatQ ir i n =
  let n1 = AST.num1 n
  let cond = n1 << (numI32 (RegType.toBitWidth n) n .- n1)
  let struct (t1, t2) = tmpVars2 ir n
  !!ir (t1 := i)
  !!ir (t2 := cond)
  let cond1 = t1 .> (t2 .- n1)
  let cond2 = t1 .< AST.not t2
  let r = (AST.ite cond1 (t2 .- n1) (AST.ite cond2 (AST.not t2) t1))
  let r = AST.xtlo n r
  let sat = AST.ite cond1 AST.b1 (AST.ite cond2 AST.b1 (AST.num0 1<rt>))
  struct (r, sat)

let sSat ir i n =
  let struct (r, _) = sSatQ ir i n
  r

let qdadd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let struct (sat1,sat2) = tmpVars2 ir 1<rt>
  let struct (dou, sat) =
    sSatQ ir (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
  !!ir (sat1 := sat)
  let struct (r, sat) =
    sSatQ ir (src1 .+ dou) (RegType.fromBitWidth 32)
  !!ir (dst := r)
  !!ir (sat2 := sat)
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := AST.ite (sat1 .| sat2) (enablePSRBits ctxt R.CPSR PSR.Q) cpsr)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let qdsub (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let struct (sat1,sat2) = tmpVars2 ir 1<rt>
  let struct (dou, sat) =
    sSatQ ir (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
  !!ir (sat1 := sat)
  let struct (r, sat) = sSatQ ir (src1 .- dou) (RegType.fromBitWidth 32)
  !!ir (dst := r)
  !!ir (sat2 := sat)
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := AST.ite (sat1 .| sat2) (enablePSRBits ctxt R.CPSR PSR.Q) cpsr)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let qsax (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let struct (sum, diff) = tmpVars2 ir 16<rt>
  let xtlo src = AST.xtlo 16<rt> src
  let xthi src = AST.xthi 16<rt> src
  !!ir (sum := xtlo src1 .+ xthi src2)
  !!ir (diff := xthi src1 .- xtlo src2)
  !!ir (sum := sSat ir sum (RegType.fromBitWidth 16))
  !!ir (diff := sSat ir diff (RegType.fromBitWidth 16))
  !!ir (dst := AST.concat diff sum)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let qsub16 (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let struct (diff1, diff2) = tmpVars2 ir 16<rt>
  let xtlo src = AST.xtlo 16<rt> src
  let xthi src = AST.xthi 16<rt> src
  !!ir (diff1 := xtlo src1 .- xtlo src2)
  !!ir (diff2 := xthi src1 .- xthi src2)
  !!ir (diff1 := sSat ir diff1 (RegType.fromBitWidth 16))
  !!ir (diff2 := sSat ir diff2 (RegType.fromBitWidth 16))
  !!ir (dst := AST.concat diff2 diff1)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let sub isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = parseOprOfADD ins insLen ctxt
  let src1 = convertPCOpr ins insLen ctxt src1
  let src2 = convertPCOpr ins insLen ctxt src2
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSetFlags then
    let struct (t1, t2) = tmpVars2 ir 32<rt>
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 (AST.not t2) (AST.num1 32<rt>) ir
    !!ir (dst := result)
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  else
    let result = !+ir 32<rt>
    !!ir (result :=
      addWithCarryOnlyResult src1 (AST.not src2) (AST.num1 32<rt>))
    if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
    else !!ir (dst := result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// B9.3.19 SUBS R.PC, R.LR (Thumb), on page B9-2008
let subsPCLRThumb ins insLen ctxt =
  let ir = !*ctxt
  let struct (_, _, src2) = parseOprOfADD ins insLen ctxt
  let pc = getPC ctxt
  let struct (result, _, _, _) =
    addWithCarry pc (AST.not src2) (AST.num1 32<rt>) ir
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (branchWritePC ctxt ins result InterJmpKind.IsRet)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseResultOfSUBAndRela (ins: InsInfo) ctxt =
  match ins.Opcode with
  | Op.ANDS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    src1.& src2
  | Op.EORS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    src1 <+> src2
  | Op.SUBS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    addWithCarryOnlyResult src1 (AST.not src2) (AST.num1 32<rt>)
  | Op.RSBS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    addWithCarryOnlyResult (AST.not src1) src2 (AST.num1 32<rt>)
  | Op.ADDS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    addWithCarryOnlyResult src1 src2 (AST.num0 32<rt>)
  | Op.ADCS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    addWithCarryOnlyResult src1 src2 (getCarryFlag ctxt)
  | Op.SBCS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    addWithCarryOnlyResult src1 (AST.not src2) (getCarryFlag ctxt)
  | Op.RSCS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    addWithCarryOnlyResult (AST.not src1) src2 (getCarryFlag ctxt)
  | Op.ORRS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    src1 .| src2
  | Op.MOVS ->
    let struct (_, src) = transTwoOprs ins ctxt
    src
  | Op.ASRS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeASR src2 (getCarryFlag ctxt)
  | Op.LSLS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeLSL src2 (getCarryFlag ctxt)
  | Op.LSRS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeLSR src2 (getCarryFlag ctxt)
  | Op.RORS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeROR src2 (getCarryFlag ctxt)
  | Op.RRXS ->
    let struct (_, src) = transTwoOprs ins ctxt
    shiftForRegAmount src 32<rt> SRTypeRRX (AST.num1 32<rt>) (getCarryFlag ctxt)
  | Op.BICS ->
    let struct (_, src1, src2) = parseOprOfADC ins ctxt
    src1 .& (AST.not src2)
  | Op.MVNS ->
    let struct (_, src) = parseOprOfMVNS ins ctxt
    AST.not src
  | _ -> raise InvalidOperandException

/// B9.3.20 SUBS R.PC, R.LR and related instruction (ARM), on page B9-2010
let subsAndRelatedInstr (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let result = !+ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (result := parseResultOfSUBAndRela ins ctxt)
  !!ir (branchWritePC ctxt ins result InterJmpKind.IsRet)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let computeCarryOutFromImmCflag (ins: InsInfo) insLen ctxt =
  match ins.Cflag with
  | Some v ->
    if v then BitVector.One 1<rt> |> AST.num
    else BitVector.Zero 1<rt> |> AST.num
  | None -> getCarryFlag ctxt

let translateLogicOp (ins: InsInfo) insLen ctxt (ir: IRBuilder) =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let t = !+ir 32<rt>
    let struct (e1, e2) = transTwoOprs ins ctxt
    !!ir (t := e2)
    let shifted, carryOut = shiftC t 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    e1, e1, shifted, carryOut
  | ThreeOperands (_, _, OprImm _) ->
    let struct (e1, e2, e3) = transThreeOprs ins ctxt
    let carryOut = computeCarryOutFromImmCflag ins insLen ctxt
    e1, e2, e3, carryOut
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let t = !+ir 32<rt>
    let struct (e1, e2, e3) = transThreeOprs ins ctxt
    !!ir (t := e3)
    let shifted, carryOut = shiftC t 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    e1, e2, shifted, carryOut
  | FourOperands (opr1, opr2, opr3, OprShift (typ, Imm imm)) ->
    let t = !+ir 32<rt>
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src1 = transOprToExpr ins ctxt opr2
    let rm = transOprToExpr ins ctxt opr3
    !!ir (t := rm)
    let shifted, carryOut = shiftC t 32<rt> typ imm carryIn
    dst, src1, shifted, carryOut
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let t = !+ir 32<rt>
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src1 = transOprToExpr ins ctxt opr2
    let rm = transOprToExpr ins ctxt opr3
    !!ir (t := rm)
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount t 32<rt> typ amount carryIn
    dst, src1, shifted, carryOut
  | _ -> raise InvalidOperandException

let logicalAnd isSetFlags (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2, carryOut = translateLogicOp ins insLen ctxt ir
  let result = !+ir 32<rt>
  !!ir (result := src1 .& src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprsOfMOV (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprs ins ctxt
  | ThreeOperands (opr1, opr2, opr3) ->
    struct (transOprToExpr ins ctxt opr1, transShiftOprs ins ctxt opr2 opr3)
  | _ -> raise InvalidOperandException

let mov isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = parseOprsOfMOV ins ctxt
  let result = !+ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  let pc = getPC ctxt
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if src = pc then !!ir (result := src .+ (numU64 (pcOffset ins) 32<rt>))
  else !!ir (result := src)
  if dst = pc then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let eor isSetFlags (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2, carryOut = translateLogicOp ins insLen ctxt ir
  let result = !+ir 32<rt>
  !!ir (result := src1 <+> src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transFourOprsOfRSB (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    struct (e1, e2, transShiftOprs ins ctxt opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    let e3 = transOprToExpr ins ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let parseOprOfRSB (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt
  | FourOperands _ -> transFourOprsOfRSB ins insLen ctxt
  | _ -> raise InvalidOperandException

let rsb isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = parseOprOfRSB ins insLen ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSetFlags then
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry (AST.not t1) t2 (AST.num1 32<rt>) ir
    !!ir (dst := result)
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  else
    let result = !+ir 32<rt>
    !!ir (result :=
      addWithCarryOnlyResult (AST.not src1) src2 (AST.num1 32<rt>))
    if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
    else !!ir (dst := result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transTwoOprsOfSBC (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    struct (e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let transFourOprsOfSBC (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    struct (e1, e2, transShiftOprs ins ctxt opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    let e3 = transOprToExpr ins ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let parseOprOfSBC (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfSBC ins insLen ctxt
  | ThreeOperands _ -> transThreeOprs ins ctxt
  | FourOperands _ -> transFourOprsOfSBC ins insLen ctxt
  | _ -> raise InvalidOperandException

let sbc isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = parseOprOfSBC ins insLen ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSetFlags then
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 (AST.not t2) (getCarryFlag ctxt) ir
    !!ir (dst := result)
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  else
    let result = !+ir 32<rt>
    !!ir (result :=
      addWithCarryOnlyResult src1 (AST.not src2) (getCarryFlag ctxt))
    if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
    else !!ir (dst := result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transFourOprsOfRSC (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    e1, e2, transShiftOprs ins ctxt opr3 opr4
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    let e3 = transOprToExpr ins ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfRSC (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt
  | FourOperands _ -> transFourOprsOfRSB ins insLen ctxt
  | _ -> raise InvalidOperandException

let rsc isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src1, src2) = parseOprOfRSC ins insLen ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSetFlags then
    !!ir (t1 := src1)
    !!ir (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry (AST.not t1) t2 (getCarryFlag ctxt) ir
    !!ir (dst := result)
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
    !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  else
    let result = !+ir 32<rt>
    !!ir (result :=
      addWithCarryOnlyResult (AST.not src1) src2 (getCarryFlag ctxt))
    if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
    else !!ir (dst := result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let orr isSetFlags (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2, carryOut = translateLogicOp ins insLen ctxt ir
  let result = !+ir 32<rt>
  !!ir (result := src1 .| src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let orn isSetFlags (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2, carryOut = translateLogicOp ins insLen ctxt ir
  let result = !+ir 32<rt>
  !!ir (result := src1 .| AST.not src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let bic isSetFlags (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2, carryOut = translateLogicOp ins insLen ctxt ir
  let result = !+ir 32<rt>
  !!ir (result := src1 .& (AST.not src2))
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transTwoOprsOfMVN (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    struct (e1, e2, getCarryFlag ctxt)
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    let shifted, carryOut = shiftC e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    struct (e1, shifted, carryOut)
  | _ -> raise InvalidOperandException

let transThreeOprsOfMVN (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src = transOprToExpr ins ctxt opr2
    let shifted, carryOut = shiftC src 32<rt> typ imm carryIn
    struct (dst, shifted, carryOut)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src = transOprToExpr ins ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount src 32<rt> typ amount carryIn
    struct (dst, shifted, carryOut)
  | _ -> raise InvalidOperandException

let parseOprOfMVN (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfMVN ins insLen ctxt
  | ThreeOperands _ -> transThreeOprsOfMVN ins insLen ctxt
  | _ -> raise InvalidOperandException

let mvn isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src, carryOut) = parseOprOfMVN ins insLen ctxt
  let result = !+ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (result := AST.not src)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let svc (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand (OprImm n) -> sideEffects insLen ctxt (Interrupt (int n))
  | _ -> raise InvalidOperandException

let getImmShiftFromShiftType imm = function
  | SRTypeLSL | SRTypeROR -> imm
  | SRTypeLSR -> if imm = 0ul then 32ul else imm
  | SRTypeASR -> if imm = 0ul then 32ul else imm
  | SRTypeRRX -> 1ul

let transTwoOprsOfShiftInstr (ins: InsInfo) shiftTyp ctxt tmp =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) when shiftTyp = SRTypeRRX ->
    let carryIn = getCarryFlag ctxt
    let struct (e1, e2) = transTwoOprs ins ctxt
    let result, carryOut = shiftC tmp 32<rt> shiftTyp 1ul carryIn
    e1, e2, result, carryOut
  | TwoOperands (OprReg _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let struct (e1, e2) = transTwoOprs ins ctxt
    let shiftN = AST.xtlo 8<rt> e2 |> AST.zext 32<rt>
    let result, carryOut = shiftCForRegAmount tmp 32<rt> shiftTyp shiftN carryIn
    e1, e1, result, carryOut
  | _ -> raise InvalidOperandException

let transThreeOprsOfShiftInstr (ins: InsInfo) shiftTyp ctxt tmp =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprImm imm) ->
    let e1 = transOprToExpr ins ctxt opr1
    let e2 = transOprToExpr ins ctxt opr2
    let shiftN = getImmShiftFromShiftType (uint32 imm) shiftTyp
    let shifted, carryOut =
      shiftC tmp 32<rt> shiftTyp shiftN (getCarryFlag ctxt)
    e1, e2, shifted, carryOut
  | ThreeOperands (_, _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let struct (e1, e2, e3) = transThreeOprs ins ctxt
    let amount = AST.xtlo 8<rt> e3 |> AST.zext 32<rt>
    let shifted, carryOut =
      shiftCForRegAmount tmp 32<rt> shiftTyp amount carryIn
    e1, e2, shifted, carryOut
  | _ -> raise InvalidOperandException

let parseOprOfShiftInstr (ins: InsInfo) shiftTyp ctxt tmp =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfShiftInstr ins shiftTyp ctxt tmp
  | ThreeOperands _ -> transThreeOprsOfShiftInstr ins shiftTyp ctxt tmp
  | _ -> raise InvalidOperandException

let shiftInstr isSetFlags ins insLen typ ctxt =
  let ir = !*ctxt
  let struct (srcTmp, result) = tmpVars2 ir 32<rt>
  let dst, src, res, carryOut = parseOprOfShiftInstr ins typ ctxt srcTmp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (srcTmp := src)
  !!ir (result := res)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else
    !!ir (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
      !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
      !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
    else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let subs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
    when ins.Mode = ArchOperationMode.ThumbMode ->
    subsPCLRThumb ins insLen ctxt
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> sub isSetFlags ins insLen ctxt

let adds isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> add isSetFlags ins insLen ctxt

let adcs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> adc isSetFlags ins insLen ctxt

let ands isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> logicalAnd isSetFlags ins insLen ctxt

let movs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> mov isSetFlags ins insLen ctxt

let eors isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> eor isSetFlags ins insLen ctxt

let rsbs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> rsb isSetFlags ins insLen ctxt

let sbcs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> sbc isSetFlags ins insLen ctxt

let rscs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> rsc isSetFlags ins insLen ctxt

let orrs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> orr isSetFlags ins insLen ctxt

let orns isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> orn isSetFlags ins insLen ctxt

let bics isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> bic isSetFlags ins insLen ctxt

let mvns isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _)
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> mvn isSetFlags ins insLen ctxt

let asrs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> shiftInstr isSetFlags ins insLen SRTypeASR ctxt

let lsls isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> shiftInstr isSetFlags ins insLen SRTypeLSL ctxt

let lsrs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> shiftInstr isSetFlags ins insLen SRTypeLSR ctxt

let rors isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> shiftInstr isSetFlags ins insLen SRTypeROR ctxt

let rrxs isSetFlags (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _) -> subsAndRelatedInstr ins insLen ctxt
  | _ -> shiftInstr isSetFlags ins insLen SRTypeRRX ctxt

let clz ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = transTwoOprs ins ctxt
  let lblBoundCheck = !%ir "LBoundCheck"
  let lblZeroCheck = !%ir "LZeroCheck"
  let lblCount = !%ir "LCount"
  let lblEnd = !%ir "LEnd"
  let numSize = (numI32 32 32<rt>)
  let t1 = !+ir 32<rt>
  let cond1 = t1 == (AST.num0 32<rt>)
  let cond2 =
    src .& ((AST.num1 32<rt>) << (t1 .- AST.num1 32<rt>)) != (AST.num0 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t1 := numSize)
  !!ir (AST.lmark lblBoundCheck)
  !!ir (AST.cjmp cond1 (AST.name lblEnd) (AST.name lblZeroCheck))
  !!ir (AST.lmark lblZeroCheck)
  !!ir (AST.cjmp cond2 (AST.name lblEnd) (AST.name lblCount))
  !!ir (AST.lmark lblCount)
  !!ir (t1 := t1 .- (AST.num1 32<rt>))
  !!ir (AST.jmp (AST.name lblBoundCheck))
  !!ir (AST.lmark lblEnd)
  !!ir (dst := numSize .- t1)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transTwoOprsOfCMN (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins ctxt
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    let shifted = shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    struct (e1, shifted)
  | _ -> raise InvalidOperandException

let transThreeOprsOfCMN (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src = transOprToExpr ins ctxt opr2
    let shifted = shift src 32<rt> typ imm carryIn
    struct (dst, shifted)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src = transOprToExpr ins ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted = shiftForRegAmount src 32<rt> typ amount carryIn
    struct (dst, shifted)
  | _ -> raise InvalidOperandException

let parseOprOfCMN (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMN ins insLen ctxt
  | ThreeOperands _ -> transThreeOprsOfCMN ins insLen ctxt
  | _ -> raise InvalidOperandException

let cmn ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, src) = parseOprOfCMN ins insLen ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t1 := dst)
  !!ir (t2 := src)
  let struct (result, carryOut, overflow, rHigh) =
    addWithCarry t1 t2 (AST.num0 32<rt>) ir
  !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
  !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
  !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
  !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let mla isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (rd, rn, rm, ra) = transFourOprs ins ctxt
  let r = !+ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (r := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+
                                     AST.zext 64<rt> ra))
  !!ir (rd := r)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := AST.xthi 1<rt> r |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := r == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transTwoOprsOfCMP (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins ctxt
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    struct (e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt))
  | _ -> raise InvalidOperandException

let transThreeOprsOfCMP (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src = transOprToExpr ins ctxt opr2
    struct (dst, shift src 32<rt> typ imm carryIn)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ins ctxt opr1
    let src = transOprToExpr ins ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    struct (dst, shiftForRegAmount src 32<rt> typ amount carryIn)
  | _ -> raise InvalidOperandException

let parseOprOfCMP (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMP ins insLen ctxt
  | ThreeOperands _ -> transThreeOprsOfCMP ins insLen ctxt
  | _ -> raise InvalidOperandException

let cmp ins insLen ctxt =
  let ir = !*ctxt
  let struct (rn, rm) = parseOprOfCMP ins insLen ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t1 := rn)
  !!ir (t2 := rm)
  let struct (result, carryOut, overflow, rHigh) =
    addWithCarry t1 (AST.not t2) (AST.num1 32<rt>) ir
  !!ir (cpsr := rHigh |> setPSR ctxt R.CPSR PSR.N)
  !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
  !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
  !!ir (cpsr := overflow |> setPSR ctxt R.CPSR PSR.V)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let umlal isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins ctxt
  let result = !+ir 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir
    (result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+ AST.concat rdHi rdLo)
  !!ir (rdHi := AST.xthi 32<rt> result)
  !!ir (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 64<rt> |> setPSR ctxt R.CPSR PSR.Z)
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let umull isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins ctxt
  let result = !+ir 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm)
  !!ir (rdHi := AST.xthi 32<rt> result)
  !!ir (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 64<rt> |> setPSR ctxt R.CPSR PSR.Z)
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transOprsOfTEQ (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (rn, imm) = transTwoOprs ins ctxt
    rn, imm, getCarryFlag ctxt
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ins ctxt opr1
    let rm = transOprToExpr ins ctxt opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    rn, shifted, carryOut
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ins ctxt opr1
    let rm = transOprToExpr ins ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    rn, shifted, carryOut
  | _ -> raise InvalidOperandException

let teq ins insLen ctxt =
  let ir = !*ctxt
  let src1, src2, carryOut = transOprsOfTEQ ins insLen ctxt
  let result = !+ir 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (result := src1 <+> src2)
  !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
  !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
  !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let mul isSetFlags ins insLen ctxt =
  let ir = !*ctxt
  let struct (rd, rn, rm) = transThreeOprs ins ctxt
  let result = !+ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir
    (result := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm))
  !!ir (rd := result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let transOprsOfTST (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (rn, imm) = transTwoOprs ins ctxt
    let carryOut = computeCarryOutFromImmCflag ins insLen ctxt
    struct (rn, imm, carryOut)
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins ctxt
    let shifted, carryOut = shiftC e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    struct (e1, shifted, carryOut)
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ins ctxt opr1
    let rm = transOprToExpr ins ctxt opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    struct (rn, shifted, carryOut)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ins ctxt opr1
    let rm = transOprToExpr ins ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    struct (rn, shifted, carryOut)
  | _ -> raise InvalidOperandException

let tst ins insLen ctxt =
  let ir = !*ctxt
  let struct (src1, src2, carryOut) = transOprsOfTST ins insLen ctxt
  let result = !+ir 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (result := src1 .& src2)
  !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
  !!ir (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR.Z)
  !!ir (cpsr := carryOut |> setPSR ctxt R.CPSR PSR.C)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let smulhalf ins insLen ctxt s1top s2top =
  let ir = !*ctxt
  let struct (rd, rn, rm) = transThreeOprs ins ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if s1top then !!ir (t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt>)
  else !!ir (t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt>)
  if s2top then !!ir (t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt>)
  else !!ir (t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt>)
  !!ir (rd := t1 .* t2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// SMULL, SMLAL, etc.
let smulandacc isSetFlags doAcc ins insLen ctxt =
  let ir = !*ctxt
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins ctxt
  let struct (tmpresult, result) = tmpVars2 ir 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (tmpresult := AST.sext 64<rt> rn .* AST.sext 64<rt> rm)
  if doAcc then !!ir (result := tmpresult .+ AST.concat rdHi rdLo)
  else !!ir (result := tmpresult)
  !!ir (rdHi := AST.xthi 32<rt> result)
  !!ir (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    !!ir (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR.N)
    !!ir (cpsr := result == AST.num0 64<rt> |> setPSR ctxt R.CPSR PSR.Z)
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let smulacclongdual (ins: InsInfo) insLen ctxt sign =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst1, dst2, src1, src2) = transFourOprs ins ctxt
  let o = !+ir 32<rt>
  let struct (p1, p2, result) = tmpVars3 ir 64<rt>
  let rotated = shiftROR src2 32<rt> 16u
  let xtlo src = AST.xtlo 16<rt> src |> AST.sext 64<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.sext 64<rt>
  if sign then !!ir (o := rotated)
  else !!ir (o := src2)
  !!ir (p1 := xtlo src1 .* xtlo o)
  !!ir (p2 := xthi src1 .* xthi o)
  !!ir (result := p1 .+ p2 .+ AST.concat dst2 dst1)
  !!ir (dst2 := AST.xthi 32<rt> result)
  !!ir (dst1 := AST.xtlo 32<rt> result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let smulaccwordbyhalf (ins: InsInfo) insLen ctxt sign =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2, src3) = transFourOprs ins ctxt
  let o = !+ir 32<rt>
  let result = !+ir 64<rt>
  let sext src = AST.sext 64<rt> src
  if sign then !!ir (o := AST.xthi 16<rt> src2 |> AST.sext 32<rt>)
  else !!ir (o := AST.xtlo 16<rt> src2 |> AST.sext 32<rt>)
  !!ir (result := sext src1 .* sext o .+ sext (src3 << numI32 16 32<rt>))
  !!ir (dst := AST.extract result 32<rt> 16)
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := AST.ite ((result >> numI32 16 64<rt>) != sext dst)
                           (enablePSRBits ctxt R.CPSR PSR.Q) cpsr)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let smulacchalf ins insLen ctxt s1top s2top =
  let ir = !*ctxt
  let struct (rd, rn, rm, ra) = transFourOprs ins ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if s1top then !!ir (t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt>)
  else !!ir (t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt>)
  if s2top then !!ir (t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt>)
  else !!ir (t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt>)
  !!ir (rd := (t1 .* t2) .+ AST.sext 32<rt> ra)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let smulacclonghalf (ins: InsInfo) insLen ctxt s1top s2top =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst1, dst2, src1, src2) = transFourOprs ins ctxt
  let struct (o1, o2, result) = tmpVars3 ir 64<rt>
  if s1top then !!ir (o1 := AST.xthi 16<rt> src1 |> AST.sext 64<rt>)
  else !!ir (o1 := AST.xtlo 16<rt> src1 |> AST.sext 64<rt>)
  if s2top then !!ir (o2 := AST.xthi 16<rt> src2 |> AST.sext 64<rt>)
  else !!ir (o2 := AST.xtlo 16<rt> src2 |> AST.sext 64<rt>)
  !!ir (result := o1 .* o2 .+ AST.concat dst2 dst1)
  !!ir (dst2 := AST.xthi 32<rt> result)
  !!ir (dst1 := AST.xtlo 32<rt> result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfB (ins: InsInfo) =
  let addr = bvOfBaseAddr (ins.Address + pcOffset ins)
  match ins.Operands with
  | OneOperand (OprMemory (LiteralMode imm)) ->
    addr .+ (numI64 imm 32<rt>)
  | _ -> raise InvalidOperandException

let b ins insLen ctxt =
  let ir = !*ctxt
  let e = parseOprOfB ins
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (branchWritePC ctxt ins e InterJmpKind.Base)
  putEndLabelForBranch ctxt lblIgnore ins ir
  !>ir insLen

let bx ins insLen ctxt =
  let ir = !*ctxt
  let rm = transOneOpr ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rm = convertPCOpr ins insLen ctxt rm
  bxWritePC ctxt isUnconditional rm ir
  putEndLabelForBranch ctxt lblIgnore ins ir
  !>ir insLen

let movtAssign dst src =
  let maskHigh16In32 = AST.num <| BitVector.OfBInt 4294901760I 32<rt>
  let clearHigh16In32 expr = expr .& AST.not maskHigh16In32
  dst := clearHigh16In32 dst .|
         (src << (numI32 16 32<rt>))

let movt ins insLen ctxt =
  let ir = !*ctxt
  let struct (dst, res) = transTwoOprs ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (movtAssign dst res)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let popLoop ctxt numOfReg addr (ir: IRBuilder) =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let reg = count |> uint32 |> OperandHelper.getRegister
      !!ir (getRegVar ctxt reg := AST.loadLE 32<rt> addr)
      (addr .+ (numI32 4 32<rt>))
    else addr
  List.fold loop addr [ 0 .. 14 ]

let pop ins insLen ctxt =
  let ir = !*ctxt
  let t0 = !+ir 32<rt>
  let sp = getRegVar ctxt R.SP
  let numOfReg = parseOprOfPUSHPOP ins
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = sp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t0 := addr)
  let addr = popLoop ctxt numOfReg t0 ir
  if (numOfReg >>> 13 &&& 1u) = 0u then
    !!ir (sp := sp .+ (numI32 stackWidth 32<rt>))
  else !!ir (sp := (AST.undef 32<rt> "UNKNOWN"))
  if (numOfReg >>> 15 &&& 1u) = 1u then
    AST.loadLE 32<rt> addr |> loadWritePC ctxt isUnconditional ir
  else ()
  putEndLabelForBranch ctxt lblIgnore ins ir
  !>ir insLen

let parseOprOfLDM (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    struct (getRegVar ctxt reg, getRegNum reg, regsToUInt32 regs)
  | _ -> raise InvalidOperandException

let getLDMStartAddr rn stackWidth = function
  | Op.LDM | Op.LDMIA -> rn
  | Op.LDMDA -> rn .- (numI32 stackWidth 32<rt>) .+ (numI32 4 32<rt>)
  | Op.LDMDB -> rn .- (numI32 stackWidth 32<rt>)
  | Op.LDMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let ldm opcode ins insLen ctxt wbackop =
  let ir = !*ctxt
  let struct (t0, t1) = tmpVars2 ir 32<rt>
  let struct (rn, numOfRn, numOfReg) = parseOprOfLDM ins ctxt
  let wback = ins.WriteBack
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = getLDMStartAddr t0 stackWidth opcode
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t0 := rn)
  !!ir (t1 := addr)
  let addr = popLoop ctxt numOfReg t1 ir
  if (numOfReg >>> 15 &&& 1u) = 1u then
    AST.loadLE 32<rt> addr |> loadWritePC ctxt isUnconditional ir
  else ()
  if wback && (numOfReg &&& numOfRn) = 0u then
    !!ir (rn := wbackop t0 (numI32 stackWidth 32<rt>))
  else ()
  if wback && (numOfReg &&& numOfRn) = numOfRn then
    !!ir (rn := (AST.undef 32<rt> "UNKNOWN"))
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let getOffAddrWithExpr s r e = if s = Some Plus then r .+ e else r .- e

let getOffAddrWithImm s r imm =
  match s, imm with
  | Some Plus, Some i -> r .+ (numI64 i 32<rt>)
  | Some Minus, Some i -> r .- (numI64 i 32<rt>)
  | _, _ -> r

let parseMemOfLDR ins insLen ctxt = function
  | OprMemory (OffsetMode (ImmOffset (rn, s, imm))) ->
    let rn = getRegVar ctxt rn |> convertPCOpr ins insLen ctxt
    struct (getOffAddrWithImm s rn imm, None)
  | OprMemory (PreIdxMode (ImmOffset (rn, s, imm))) ->
    let rn = getRegVar ctxt rn
    struct (getOffAddrWithImm s rn imm, Some (rn, None))
  | OprMemory (PostIdxMode (ImmOffset (rn, s, imm))) ->
    let rn = getRegVar ctxt rn
    struct (rn, Some (rn, Some (getOffAddrWithImm s rn imm)))
  | OprMemory (LiteralMode imm) ->
    let addr = bvOfBaseAddr ins.Address
    let pc = align addr (numI32 4 32<rt>)
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8u else 4u
    struct (pc .+ (numU32 rel 32<rt>) .+ (numI64 imm 32<rt>), None)
  | OprMemory (OffsetMode (RegOffset (n, _, m, None))) ->
    let m = getRegVar ctxt m |> convertPCOpr ins insLen ctxt
    let n = getRegVar ctxt n |> convertPCOpr ins insLen ctxt
    struct (n .+ shift m 32<rt> SRTypeLSL 0u (getCarryFlag ctxt), None)
  | OprMemory (PreIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    let offset =
      shift (getRegVar ctxt m) 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    struct (getOffAddrWithExpr s rn offset, Some (rn, None))
  | OprMemory (PostIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    let offset =
      shift (getRegVar ctxt m) 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    struct (rn, Some (rn, Some (getOffAddrWithExpr s rn offset)))
  | OprMemory (OffsetMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = getRegVar ctxt n |> convertPCOpr ins insLen ctxt
    let rm = getRegVar ctxt m |> convertPCOpr ins insLen ctxt
    let offset = shift rm 32<rt> t i (getCarryFlag ctxt)
    struct (getOffAddrWithExpr s rn offset, None)
  | OprMemory (PreIdxMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = getRegVar ctxt n
    let offset = shift (getRegVar ctxt m) 32<rt> t i (getCarryFlag ctxt)
    struct (getOffAddrWithExpr s rn offset, Some (rn, None))
  | OprMemory (PostIdxMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = getRegVar ctxt n
    let offset = shift (getRegVar ctxt m) 32<rt> t i (getCarryFlag ctxt)
    struct (rn, Some (rn, Some (getOffAddrWithExpr s rn offset)))
  | _ -> raise InvalidOperandException

let parseOprOfLDR (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg rt, (OprMemory _ as mem)) ->
    let struct (addr, writeback) = parseMemOfLDR ins insLen ctxt mem
    struct (getRegVar ctxt rt, addr, writeback)
  | _ -> raise InvalidOperandException

/// Load register
let ldr ins insLen ctxt size ext =
  let ir = !*ctxt
  let data = !+ir 32<rt>
  let struct (rt, addr, writeback) = parseOprOfLDR ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  match writeback with
  | Some (basereg, Some newoffset) ->
    let struct (taddr, twriteback) = tmpVars2 ir 32<rt>
    !!ir (taddr := addr)
    !!ir (twriteback := newoffset)
    !!ir (data := AST.loadLE size taddr |> ext 32<rt>)
    !!ir (basereg := twriteback)
  | Some (basereg, None) ->
    let taddr = !+ir 32<rt>
    !!ir (taddr := addr)
    !!ir (data := AST.loadLE size taddr |> ext 32<rt>)
    !!ir (basereg := taddr)
  | None ->
    !!ir (data := AST.loadLE size addr |> ext 32<rt>)
  if rt = getPC ctxt then loadWritePC ctxt isUnconditional ir data
  else !!ir (rt := data)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseMemOfLDRD ins insLen ctxt = function
  | OprMemory (OffsetMode (RegOffset (n, s, m, None))) ->
    struct (getOffAddrWithExpr s (getRegVar ctxt n) (getRegVar ctxt m), None)
  | OprMemory (PreIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    struct (getOffAddrWithExpr s rn (getRegVar ctxt m), Some (rn, None))
  | OprMemory (PostIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    struct (rn, Some (rn, Some (getOffAddrWithExpr s rn (getRegVar ctxt m))))
  | mem -> parseMemOfLDR ins insLen ctxt mem

let parseOprOfLDRD (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg t, OprReg t2, (OprMemory _ as mem)) ->
    let struct (addr, stmt) = parseMemOfLDRD ins insLen ctxt mem
    struct (getRegVar ctxt t, getRegVar ctxt t2, addr, stmt)
  | _ -> raise InvalidOperandException

let ldrd ins insLen ctxt =
  let ir = !*ctxt
  let taddr = !+ir 32<rt>
  let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let n4 = numI32 4 32<rt>
  match writeback with
  | Some (basereg, Some newoffset) ->
    let twriteback = !+ir 32<rt>
    !!ir (taddr := addr)
    !!ir (twriteback := newoffset)
    !!ir (rt := AST.loadLE 32<rt> taddr)
    !!ir (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
    !!ir (basereg := twriteback)
  | Some (basereg, None) ->
    !!ir (taddr := addr)
    !!ir (rt := AST.loadLE 32<rt> taddr)
    !!ir (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
    !!ir (basereg := taddr)
  | None ->
    !!ir (taddr := addr)
    !!ir (rt := AST.loadLE 32<rt> taddr)
    !!ir (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let sel8Bits r offset =
  AST.extract r 8<rt> offset |> AST.zext 32<rt>

let combine8bitResults t1 t2 t3 t4 =
  let mask = numI32 0xff 32<rt>
  let n8 = numI32 8 32<rt>
  let n16 = numI32 16 32<rt>
  let n24 = numI32 24 32<rt>
  ((t4 .& mask) << n24)
  .| ((t3 .& mask) << n16)
  .| ((t2 .& mask) << n8)
  .| (t1 .& mask)

let combineGEs ge0 ge1 ge2 ge3 =
  let n1 = AST.num1 32<rt>
  let n2 = numI32 2 32<rt>
  let n3 = numI32 3 32<rt>
  ge0 .| (ge1 << n1) .| (ge2 << n2) .| (ge3 << n3)

let uadd8 ins insLen ctxt =
  let ir = !*ctxt
  let struct (rd, rn, rm) = transThreeOprs ins ctxt
  let struct (sum1, sum2, sum3, sum4) = tmpVars4 ir 32<rt>
  let struct (ge0, ge1, ge2, ge3) = tmpVars4 ir 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let n100 = numI32 0x100 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (sum1 := sel8Bits rn 0 .+ sel8Bits rm 0)
  !!ir (sum2 := sel8Bits rn 8 .+ sel8Bits rm 8)
  !!ir (sum3 := sel8Bits rn 16 .+ sel8Bits rm 16)
  !!ir (sum4 := sel8Bits rn 24 .+ sel8Bits rm 24)
  !!ir (rd := combine8bitResults sum1 sum2 sum3 sum4)
  !!ir (ge0 := AST.zext 32<rt> (AST.ge sum1 n100))
  !!ir (ge1 := AST.zext 32<rt> (AST.ge sum2 n100))
  !!ir (ge2 := AST.zext 32<rt> (AST.ge sum3 n100))
  !!ir (ge3 := AST.zext 32<rt> (AST.ge sum4 n100))
  !!ir (cpsr := combineGEs ge0 ge1 ge2 ge3 |> setPSR ctxt R.CPSR PSR.GE)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let sel ins insLen ctxt =
  let ir = !*ctxt
  let struct (t1, t2, t3, t4) = tmpVars4 ir 32<rt>
  let struct (rd, rn, rm) = transThreeOprs ins ctxt
  let n1 = AST.num1 32<rt>
  let n2 = numI32 2 32<rt>
  let n4 = numI32 4 32<rt>
  let n8 = numI32 8 32<rt>
  let ge = getPSR ctxt R.CPSR PSR.GE >> (numI32 16 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t1 := AST.ite ((ge .& n1) == n1) (sel8Bits rn 0) (sel8Bits rm 0))
  !!ir (t2 := AST.ite ((ge .& n2) == n2) (sel8Bits rn 8) (sel8Bits rm 8))
  !!ir (t3 := AST.ite ((ge .& n4) == n4) (sel8Bits rn 16) (sel8Bits rm 16))
  !!ir (t4 := AST.ite ((ge .& n8) == n8) (sel8Bits rn 24) (sel8Bits rm 24))
  !!ir (rd := combine8bitResults t1 t2 t3 t4)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let rbit ins insLen ctxt =
  let ir = !*ctxt
  let struct (t1, t2) = tmpVars2 ir 32<rt>
  let struct (rd, rm) = transTwoOprs ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t1 := rm)
  !!ir (rd := rd <+> rd)
  for i = 0 to 31 do
    !!ir (t2 := (AST.extract t1 1<rt> i) |> AST.zext 32<rt>)
    !!ir (rd := rd .| (t2 << (numI32 (31 - i) 32<rt>)))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let rev ins insLen ctxt =
  let ir = !*ctxt
  let struct (t1, t2, t3, t4) = tmpVars4 ir 32<rt>
  let struct (rd, rm) = transTwoOprs ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t1 := sel8Bits rm 0)
  !!ir (t2 := sel8Bits rm 8)
  !!ir (t3 := sel8Bits rm 16)
  !!ir (t4 := sel8Bits rm 24)
  !!ir (rd := combine8bitResults t4 t3 t2 t1)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let rfedb (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst = transOneOpr ins ctxt
  let wback = ins.WriteBack
  let struct (addr, newPcValue, spsr) = tmpVars3 ir 32<rt>
  !!ir (addr := dst .- numI32 8 32<rt>)
  !!ir (newPcValue := AST.loadLE 32<rt> addr)
  !!ir (spsr := AST.loadLE 32<rt> (addr .+ numI32 4 32<rt>))
  match wback with
  | true -> !!ir (dst := dst .- numI32 8 32<rt>)
  | _ -> !!ir (dst := dst)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// Store register.
let str ins insLen ctxt size =
  let ir = !*ctxt
  let struct (rt, addr, writeback) = parseOprOfLDR ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if rt = getPC ctxt then !!ir (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  elif size = 32<rt> then !!ir (AST.loadLE 32<rt> addr := rt)
  else !!ir (AST.loadLE size addr := AST.xtlo size rt)
  match writeback with
  | Some (basereg, Some newoffset) -> !!ir (basereg := newoffset)
  | Some (basereg, None) -> !!ir (basereg := addr)
  | None -> ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let strex ins insLen ctxt =
  let ir = !*ctxt
  let struct (rd, rt, addr, writeback) = parseOprOfLDRD ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if rt = getPC ctxt then !!ir (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  else !!ir (AST.loadLE 32<rt> addr := rt)
  match writeback with
  | Some (basereg, Some newoffset) -> !!ir (basereg := newoffset)
  | Some (basereg, None) -> !!ir (basereg := addr)
  | None -> ()
  !!ir (rd := AST.num0 32<rt>) (* XXX: always succeeds for now *)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let strd ins insLen ctxt =
  let ir = !*ctxt
  let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (AST.loadLE 32<rt> addr := rt)
  !!ir (AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>)) := rt2)
  match writeback with
  | Some (basereg, Some newoffset) -> !!ir (basereg := newoffset)
  | Some (basereg, None) -> !!ir (basereg := addr)
  | None -> ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfSTM (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    getRegVar ctxt reg, regsToUInt32 regs
  | _ -> raise InvalidOperandException

let getSTMStartAddr rn msize = function
  | Op.STM | Op.STMIA | Op.STMEA -> rn
  | Op.STMDA -> rn .- msize .+ (numI32 4 32<rt>)
  | Op.STMDB -> rn .- msize
  | Op.STMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let stmLoop ctxt regs wback rn addr (ir: IRBuilder) =
  let loop addr count =
    if (regs >>> count) &&& 1u = 1u then
      let ri = count |> uint32 |> OperandHelper.getRegister |> getRegVar ctxt
      if ri = rn && wback && count <> lowestSetBit regs 32 then
        !!ir (AST.loadLE 32<rt> addr := (AST.undef 32<rt> "UNKNOWN"))
      else
        !!ir (AST.loadLE 32<rt> addr := ri)
      addr .+ (numI32 4 32<rt>)
    else addr
  List.fold loop addr [ 0 .. 14 ]

let stm opcode ins insLen ctxt wbop =
  let ir = !*ctxt
  let taddr = !+ir 32<rt>
  let rn, regs = parseOprOfSTM ins insLen ctxt
  let wback = ins.WriteBack
  let msize = numI32 (4 * bitCount regs 16) 32<rt>
  let addr = getSTMStartAddr rn msize opcode
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (taddr := addr)
  let addr = stmLoop ctxt regs wback rn taddr ir
  if (regs >>> 15 &&& 1u) = 1u then
    !!ir (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  else ()
  if wback then !!ir (rn := wbop rn msize) else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfCBZ (ins: InsInfo) insLen ctxt =
  let pc = bvOfBaseAddr ins.Address
  let offset = pcOffset ins |> int64
  match ins.Operands with
  | TwoOperands (OprReg rn, (OprMemory (LiteralMode imm))) ->
    getRegVar ctxt rn, pc .+ (numI64 (imm + offset) 32<rt>)
  | _ -> raise InvalidOperandException

let cbz nonZero ins insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let n = if nonZero then AST.num1 1<rt> else AST.num0 1<rt>
  let rn, pc = parseOprOfCBZ ins insLen ctxt
  let cond = n <+> (rn == AST.num0 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (branchWritePC ctxt ins pc InterJmpKind.Base)
  !!ir (AST.lmark lblL1)
  let fallAddr = ins.Address + uint64 ins.Length
  let fallAddrExp = numU64 fallAddr 32<rt>
  !!ir (AST.interjmp fallAddrExp InterJmpKind.Base)
  putEndLabelForBranch ctxt lblIgnore ins ir
  !>ir insLen

let parseOprOfTableBranch (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand (OprMemory (OffsetMode (RegOffset (rn, None, rm, None)))) ->
    let rn = getRegVar ctxt rn |> convertPCOpr ins insLen ctxt
    let rm = getRegVar ctxt rm |> convertPCOpr ins insLen ctxt
    let addr = rn .+ rm
    AST.loadLE 8<rt> addr |> AST.zext 32<rt>
  | OneOperand (OprMemory (OffsetMode (RegOffset (rn,
                                                  None,
                                                  rm, Some (_, Imm i))))) ->
    let rn = getRegVar ctxt rn |> convertPCOpr ins insLen ctxt
    let rm = getRegVar ctxt rm |> convertPCOpr ins insLen ctxt
    let addr = rn .+ (shiftLSL rm 32<rt> i)
    AST.loadLE 16<rt> addr |> AST.zext 32<rt>
  | _ -> raise InvalidOperandException

let tableBranch (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let offset = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
  let pc = bvOfBaseAddr ins.Address .+ (numI32 offset 32<rt>)
  let halfwords = parseOprOfTableBranch ins insLen ctxt
  let numTwo = numI32 2 32<rt>
  let result = pc .+ (numTwo .* halfwords)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (branchWritePC ctxt ins result InterJmpKind.Base)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfBFC (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg rd, OprImm lsb, OprImm width) ->
    getRegVar ctxt rd, Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ -> raise InvalidOperandException

let bfc (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let rd, lsb, width = parseOprOfBFC ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (rd := replicate rd 32<rt> lsb width 0)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfRdRnLsbWidth (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    getRegVar ctxt rd, getRegVar ctxt rn,
    Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ -> raise InvalidOperandException

let bfi ins insLen ctxt =
  let ir = !*ctxt
  let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins insLen ctxt
  let struct (t0, t1) = tmpVars2 ir 32<rt>
  let n = rn .& (BitVector.OfBInt (BigInteger.getMask width) 32<rt> |> AST.num)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t0 := n << (numI32 lsb 32<rt>))
  !!ir (t1 := replicate rd 32<rt> lsb width 0)
  !!ir (rd := t0 .| t1)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let bfx ins insLen ctxt signExtend =
  let ir = !*ctxt
  let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if lsb + width - 1 > 31 || width < 0 then raise InvalidOperandException
  else ()
  let v = BitVector.OfBInt (BigInteger.getMask width) 32<rt> |> AST.num
  !!ir (rd := (rn >> (numI32 lsb 32<rt>)) .& v)
  if signExtend && width > 1 then
    let struct (msb, mask) = tmpVars2 ir 32<rt>
    let msboffset = numI32 (lsb + width - 1) 32<rt>
    let shift = numI32 width 32<rt>
    !!ir (msb := (rn >> msboffset) .& AST.num1 32<rt>)
    !!ir (mask := (AST.not (msb .- AST.num1 32<rt>)) << shift)
    !!ir (rd := rd .| mask)
  else ()
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfUqOpr ctxt = function
  | ThreeOperands (OprReg rd, OprReg rn, OprReg rm) ->
    getRegVar ctxt rd, getRegVar ctxt rn, getRegVar ctxt rm
  | _ -> raise InvalidOperandException

let createTemporaries (ir: IRBuilder) cnt regtype =
  Array.init cnt (fun _ -> !+ir regtype)

let extractUQOps r width =
  let typ = RegType.fromBitWidth width
  [| for w in 0 .. width .. 31 do
       yield AST.extract r typ w |> AST.zext 32<rt>
     done |]

let saturate e width =
  let max32 = numI32 (pown 2 width - 1) 32<rt>
  let zero = AST.num0 32<rt>
  let resultType = RegType.fromBitWidth width
  AST.ite (AST.sgt e max32) (AST.xtlo resultType max32)
    (AST.ite (AST.slt e zero) (AST.num0 resultType) (AST.xtlo resultType e))

let getUQAssignment tmps width =
  tmps
  |> Array.mapi (fun idx t ->
       (AST.zext 32<rt> t) << (numI32 (idx * width) 32<rt>))
  |> Array.reduce (.|)

let uqopr (ins: InsInfo) insLen ctxt width opr =
  let ir = !*ctxt
  let rd, rn, rm = parseOprOfUqOpr ctxt ins.Operands
  let tmps = createTemporaries ir (32 / width) 32<rt>
  let sats = createTemporaries ir (32 / width) (RegType.fromBitWidth width)
  let rns = extractUQOps rn width
  let rms = extractUQOps rm width
  let diffs = Array.map2 opr rns rms
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  Array.iter2 (fun tmp diff -> !!ir (tmp := diff)) tmps diffs
  Array.iter2 (fun s t -> !!ir (s := saturate t width)) sats tmps
  !!ir (rd := getUQAssignment sats width)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// ADR For ThumbMode (T1 case)
let parseOprOfADR (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg rd, OprMemory (LiteralMode imm)) ->
    let addr = bvOfBaseAddr ins.Address
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
    let addr = addr .+ (numI32 rel 32<rt>)
    let pc = align addr (numI32 4 32<rt>)
    let imm = numI64 imm 32<rt>
    let pc = if ins.IsAdd then pc .+ imm else pc .- imm
    getRegVar ctxt rd, pc
  | _ -> raise InvalidOperandException

let it (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let cpsr = getRegVar ctxt R.CPSR
  let itState = numI32 (int ins.ITState) 32<rt>
  let mask10 = numI32 0b11 32<rt>
  let mask72 = (numI32 0b11111100 32<rt>)
  let itState10 = itState .& mask10
  let itState72 = (itState .& mask72) >> (numI32 2 32<rt>)
  !<ir insLen
  !!ir (cpsr := itState10 |> setPSR ctxt R.CPSR PSR.IT10)
  !!ir (cpsr := itState72 |> setPSR ctxt R.CPSR PSR.IT72)
  !>ir insLen

let adr ins insLen ctxt =
  let ir = !*ctxt
  let rd, result = parseOprOfADR ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if rd = getPC ctxt then aluWritePC ctxt ins isUnconditional result ir
  else !!ir (rd := result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let mls ins insLen ctxt =
  let ir = !*ctxt
  let struct (rd, rn, rm, ra) = transFourOprs ins ctxt
  let r = !+ir 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (r := AST.xtlo 32<rt> (AST.zext 64<rt> ra .- AST.zext 64<rt> rn .*
                                     AST.zext 64<rt> rm))
  !!ir (rd := r)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfExtend (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg rd, OprReg rm) ->
    getRegVar ctxt rd, getRegVar ctxt rm, 0u
  | ThreeOperands (OprReg rd, OprReg rm, OprShift (_, Imm i)) ->
    getRegVar ctxt rd, getRegVar ctxt rm, i
  | _ -> raise InvalidOperandException

let extend (ins: InsInfo) insLen ctxt extractfn amount =
  let ir = !*ctxt
  let rd, rm, rotation = parseOprOfExtend ins insLen ctxt
  let rotated = shiftROR rm 32<rt> rotation
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (rd := extractfn 32<rt> (AST.xtlo amount rotated))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfXTA (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (OprReg rd, OprReg rn, OprReg rm, OprShift (_, Imm i)) ->
    getRegVar ctxt rd, getRegVar ctxt rn, getRegVar ctxt rm, i
  | _ -> raise InvalidOperandException

let extendAndAdd (ins: InsInfo) insLen ctxt amount =
  let ir = !*ctxt
  let rd, rn, rm, rotation = parseOprOfXTA ins insLen ctxt
  let rotated = shiftROR rm 32<rt> rotation
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (rd := rn .+ AST.zext 32<rt> (AST.xtlo amount rotated))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let checkSingleReg = function
  | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
  | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17 | R.S18
  | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25 | R.S26 | R.S27
  | R.S28 | R.S29 | R.S30 | R.S31 -> true
  | _ -> false

let parseOprOfVLDR (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector d)),
                 OprMemory (OffsetMode (ImmOffset (rn, s, imm)))) ->
    let pc = getRegVar ctxt rn |> convertPCOpr ins insLen ctxt
    let baseAddr = align pc (numI32 4 32<rt>)
    getRegVar ctxt d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ -> raise InvalidOperandException

let vldr ins insLen ctxt =
  let ir = !*ctxt
  let rd, addr, isSReg = parseOprOfVLDR ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSReg then
    let data = !+ir 32<rt>
    !!ir (data := AST.loadLE 32<rt> addr)
    !!ir (rd := data)
  else
    let struct (d1, d2) = tmpVars2 ir 32<rt>
    !!ir (d1 := AST.loadLE 32<rt> addr)
    !!ir (d2 := AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>)))
    !!ir (rd := if ctxt.Endianness = Endian.Big then AST.concat d1 d2
                else AST.concat d2 d1)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfVSTR (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector d)),
                 OprMemory (OffsetMode (ImmOffset (rn, s, imm)))) ->
    let baseAddr = getRegVar ctxt rn
    getRegVar ctxt d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ -> raise InvalidOperandException

let vstr (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let rd, addr, isSReg = parseOprOfVSTR ins insLen ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if isSReg then !!ir (AST.loadLE 32<rt> addr := rd)
  else
    let mem1 = AST.loadLE 32<rt> addr
    let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let isbig = ctxt.Endianness = Endian.Big
    !!ir (mem1 := if isbig then AST.xthi 32<rt> rd else AST.xtlo 32<rt> rd)
    !!ir (mem2 := if isbig then AST.xtlo 32<rt> rd else AST.xthi 32<rt> rd)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfVPUSHVPOP (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprRegList r) -> r
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

let vpopLoop ctxt d imm isSReg addr (ir: IRBuilder) =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      !!ir (getRegVar ctxt reg := AST.loadLE 32<rt> addr)
      singleRegLoop (r + 1) nextAddr
    else ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let word1 = AST.loadLE 32<rt> addr
      let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = ctxt.Endianness = Endian.Big
      !!ir (getRegVar ctxt reg := if isbig then AST.concat word1 word2
                                  else AST.concat word2 word1)
      nonSingleRegLoop (r + 1) nextAddr
    else ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpop ins insLen ctxt =
  let ir = !*ctxt // FIXME
  let t0 = !+ir 32<rt>
  let sp = getRegVar ctxt R.SP
  let d, imm, isSReg = parsePUSHPOPsubValue ins
  let addr = sp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t0 := addr)
  !!ir (sp := addr .+ (numI32 (imm <<< 2) 32<rt>))
  vpopLoop ctxt d imm isSReg t0 ir
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vpushLoop ctxt d imm isSReg addr (ir: IRBuilder) =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      !!ir (AST.loadLE 32<rt> addr := getRegVar ctxt reg)
      singleRegLoop (r + 1) nextAddr
    else ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let mem1 = AST.loadLE 32<rt> addr
      let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = ctxt.Endianness = Endian.Big
      let data1 = AST.xthi 32<rt> (getRegVar ctxt reg)
      let data2 = AST.xtlo 32<rt> (getRegVar ctxt reg)
      !!ir (mem1 := if isbig then data1 else data2)
      !!ir (mem2 := if isbig then data2 else data1)
      nonSingleRegLoop (r + 1) nextAddr
    else ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpush ins insLen ctxt =
  let ir = !*ctxt // FIXME
  let t0 = !+ir 32<rt>
  let sp = getRegVar ctxt R.SP
  let d, imm, isSReg = parsePUSHPOPsubValue ins
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  !!ir (t0 := sp .- (numI32 (imm <<< 2) 32<rt>))
  !!ir (sp := t0)
  vpushLoop ctxt d imm isSReg t0 ir
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfVAND (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands
      (OprSIMD (SFReg (Vector r1)), OprSIMD (SFReg (Vector r2)),
        OprSIMD (SFReg (Vector r3))) ->
            getRegVar ctxt r1, getRegVar ctxt r2, getRegVar ctxt r3
  | _ -> raise InvalidOperandException

let vand (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    !!ir (dstA := src1A .& src2A)
    !!ir (dstB := src1B .& src2B)
  | _ ->
    let dst, src1, src2 = parseOprOfVAND ins insLen ctxt
    !!ir (dst := src1 .& src2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vmrs ins insLen ctxt =
  let ir = !*ctxt
  let struct (rt, fpscr) = transTwoOprs ins ctxt
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  if rt <> cpsr then !!ir (rt := fpscr)
  else !!ir (cpsr := disablePSRBits ctxt R.CPSR PSR.Cond .|
                           getPSR ctxt R.FPSCR PSR.Cond)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

type ParsingInfo = {
  EBytes: int
  ESize: int
  RtESize: int<rt>
  Elements: int
  RegIndex: bool option
}

let getRegs = function
  | TwoOperands (OprSIMD (OneReg _), _) -> 1
  | TwoOperands (OprSIMD (TwoRegs _), _) -> 2
  | TwoOperands (OprSIMD (ThreeRegs _), _) -> 3
  | TwoOperands (OprSIMD (FourRegs _), _) -> 4
  | _ -> raise InvalidOperandException

let getEBytes = function
  | Some (OneDT SIMDTyp8) | Some (OneDT SIMDTypS8) | Some (OneDT SIMDTypI8)
  | Some (OneDT SIMDTypU8) | Some (OneDT SIMDTypP8) -> 1
  | Some (OneDT SIMDTyp16) | Some (OneDT SIMDTypS16) | Some (OneDT SIMDTypI16)
  | Some (OneDT SIMDTypU16) | Some (OneDT SIMDTypF16)
  | Some (TwoDT (SIMDTypF32, SIMDTypF16))
  | Some (TwoDT (SIMDTypF16, SIMDTypF32)) -> 2
  | Some (OneDT SIMDTyp32) | Some (OneDT SIMDTypS32) | Some (OneDT SIMDTypI32)
  | Some (OneDT SIMDTypU32) | Some (OneDT SIMDTypF32) -> 4
  | Some (OneDT SIMDTyp64) | Some (OneDT SIMDTypS64) | Some (OneDT SIMDTypI64)
  | Some (OneDT SIMDTypU64) | Some (OneDT SIMDTypP64)
  | Some (OneDT SIMDTypF64) -> 8
  | _ -> raise InvalidOperandException

let registerIndex = function
  | TwoOperands (_, OprMemory (OffsetMode (AlignOffset _)))
  | TwoOperands (_, OprMemory (PreIdxMode (AlignOffset _))) -> Some false
  | TwoOperands (_, OprMemory (PostIdxMode (AlignOffset _))) -> Some true
  | _ -> None

/// Parsing information for SIMD instructions
let getParsingInfo (ins: InsInfo) =
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
  let mask = AST.num <| BitVector.OfBInt (BigInteger.getMask size) vSize
  let eSize = numI32 size vSize
  (vector >> (index .* eSize)) .& mask |> AST.xtlo (RegType.fromBitWidth size)

let isUnsigned = function
  | Some (OneDT SIMDTypU8) | Some (OneDT SIMDTypU16)
  | Some (OneDT SIMDTypU32) | Some (OneDT SIMDTypU64) -> true
  | Some (OneDT SIMDTypS8) | Some (OneDT SIMDTypS16)
  | Some (OneDT SIMDTypS32) | Some (OneDT SIMDTypS64) | Some (OneDT SIMDTypP8)
  | Some (OneDT SIMDTypP64) | Some (OneDT SIMDTyp8) | Some (OneDT SIMDTyp16)
  | Some (OneDT SIMDTyp32) | Some (OneDT SIMDTyp64) -> false
  | _ -> raise InvalidOperandException

let parseOprOfVMOV (ins: InsInfo) ctxt ir =
  match ins.Operands with
  (* VMOV (immediate) *)
  | TwoOperands (OprSIMD _, OprImm _) ->
    let struct (dst, imm) = getTwoOprs ins
    match ins.OprSize with
    | 128<rt> ->
      let dstB, dstA = transOprToExpr128 ctxt dst
      let imm = transOprToExpr ins ctxt imm
      !!ir (dstB := imm)
      !!ir (dstA := imm)
    | _ ->
      let dst = transOprToExpr ins ctxt dst
      let imm = transOprToExpr ins ctxt imm
      !!ir (dst := imm)
  (* VMOV (general-purpose register to scalar) *)
  | TwoOperands (OprSIMD (SFReg (Scalar (_, Some element))), OprReg _) ->
    let struct (dst, src) = transTwoOprs ins ctxt
    let p = getParsingInfo ins
    let index = int element
    !!ir (elem dst index p.ESize := AST.xtlo p.RtESize src)
  (* VMOV (scalar to general-purpose register) *)
  | TwoOperands (OprReg _, OprSIMD (SFReg (Scalar (_, Some element)))) ->
    let struct (dst, src) = transTwoOprs ins ctxt
    let p = getParsingInfo ins
    let index = int element
    let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    !!ir (dst := extend 32<rt> (elem src index p.ESize))
  (* VMOV (between general-purpose register and single-precision) *)
  | TwoOperands _ ->
    let struct (dst, src) = transTwoOprs ins ctxt
    !!ir (dst := src)
  (* VMOV (between two general-purpose registers and a doubleword
    floating-point register) *)
  | ThreeOperands (OprSIMD _, OprReg _, OprReg _) ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (AST.xtlo 32<rt> dst := src1)
    !!ir (AST.xthi 32<rt> dst := src2)
  | ThreeOperands (OprReg _, OprReg _, OprSIMD _) ->
    let struct (dst1, dst2, src) = transThreeOprs ins ctxt
    !!ir (dst1 := AST.xtlo 32<rt> src)
    !!ir (dst2 := AST.xthi 32<rt> src)
  (* VMOV (between two general-purpose registers and two single-precision
    registers) *)
  | FourOperands _ ->
    let struct (dst1, dst2, src1, src2) = transFourOprs ins ctxt
    !!ir (dst1 := src1)
    !!ir (dst2 := src2)
  | _ -> raise InvalidOperandException

let parseOprOfVMOVFP (ins: InsInfo) ctxt ir =
  match ins.Operands with
  (* VMOV (between general-purpose register and half-precision) *)
  | TwoOperands (OprSIMD _, OprReg _) | TwoOperands (OprReg _, OprSIMD _) ->
    let struct (dst, src) = transTwoOprs ins ctxt
    !!ir (dst := AST.zext 32<rt> (AST.xtlo 16<rt> src))
  (* VMOV (register) *)
  | TwoOperands (OprSIMD _, OprSIMD _) ->
    let struct (dst, src) = transTwoOprs ins ctxt
    !!ir (dst := src)
  (* VMOV (immediate) *)
  | TwoOperands (OprSIMD _, OprImm _) ->
    let struct (dst, imm) = transTwoOprs ins ctxt
    !!ir (dst := AST.zext ins.OprSize imm)
  | _ -> !!ir (AST.sideEffect UnsupportedFP)

let vmov (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  parseOprOfVMOV ins ctxt ir
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vmovfp (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  parseOprOfVMOVFP ins ctxt ir
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

(* VMOV(immediate)/VMOV(register) *)
let isF32orF64 = function
  | Some (OneDT SIMDTypF32) | Some (OneDT SIMDTypF64) -> true
  | _ -> false

(* VABS(immediate)/VABS(register) *)
let isF16orF32orF64 = function
  | Some (OneDT SIMDTypF16) | Some (OneDT SIMDTypF32) | Some (OneDT SIMDTypF64)
    -> true
  | _ -> false

let private absExpr expr size =
  AST.ite (AST.slt expr (AST.num0 size)) (AST.neg expr) (expr)

let vabs (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    for e in 0 .. p.Elements - 1 do
      !!ir (elem dstB e p.ESize := absExpr (elem srcB e p.ESize) p.RtESize)
      !!ir (elem dstA e p.ESize := absExpr (elem srcA e p.ESize) p.RtESize)
  | _ ->
    let struct (dst, src) = transTwoOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      !!ir (elem dst e p.ESize := absExpr (elem src e p.ESize) p.RtESize)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vaddsub (ins: InsInfo) insLen ctxt opFn =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  (* FP, p.ESize 16 *)
  | 32<rt> when p.ESize = 16 ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst :=
      AST.zext 32<rt> (opFn (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)))
  (* FP, p.ESize 32 *)
  | 32<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := opFn src1 src2)
  (* FP, p.ESize 64 *)
  | 64<rt> when p.ESize = 64 ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := opFn src1 src2)
  (* SIMD *)
  | 64<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let elem value = elem value e p.ESize
      !!ir (elem dst := (opFn (elem src1) (elem src2)))
  (* SIMD *)
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let elem expr = elem expr e p.ESize
      !!ir (elem dstB := (opFn (elem src1B) (elem src2B)))
      !!ir (elem dstA := (opFn (elem src1A) (elem src2A)))
  | _ -> raise InvalidOperandException
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vaddl (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ctxt dst
  let src1 = transOprToExpr ins ctxt src1
  let src2 = transOprToExpr ins ctxt src2
  for e in 0 .. (p.Elements - 1) / 2 do
    !!ir (elem dstA e (2 * p.ESize) :=
      AST.zext (p.RtESize * 2) (elem src1 e p.ESize) .+
      AST.zext (p.RtESize * 2) (elem src2 e p.ESize))
    !!ir (elem dstB e (2 * p.ESize) :=
      AST.zext (p.RtESize * 2) (elem src1 (e + p.Elements / 2) p.ESize) .+
      AST.zext (p.RtESize * 2) (elem src2 (e + p.Elements / 2) p.ESize))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let isDoubleToSingle = function
  | Some (TwoDT (SIMDTypF32, SIMDTypF64)) -> true
  | Some (TwoDT (SIMDTypF64, SIMDTypF32)) -> false
  | _ -> raise InvalidOperandException

let parseOprOfVCVT (ins: InsInfo) ctxt ir =
  (* FIXME *)
  match ins.Operands with
  | TwoOperands(OprSIMD _, OprSIMD _) ->
    match ins.OprSize with
    (* FIXME *)
    (* VCVT (between half-precision and single-precision, Advanced SIMD) *)
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let dstB, dstA = transOprToExpr128 ctxt dst
      let src = transOprToExpr ins ctxt src
      let p = getParsingInfo ins
      let struct (tdstB, tdstA) = tmpVars2 ir 64<rt>
      !!ir (tdstA := (dstB << numI32 63 64<rt>) .| (dstA >> AST.num1 64<rt>))
      !!ir (tdstB := dstB >> AST.num1 64<rt>)
      for e in 0 .. (p.Elements - 1) / 2 do
        !!ir (elem tdstB e 32 :=
          AST.cast CastKind.FloatCast 32<rt> (elem src (e + 2) 16))
        !!ir (elem tdstA e 32 :=
          AST.cast CastKind.FloatCast 32<rt> (elem src e 16))
      !!ir (dstB := tdstB)
      !!ir (dstA := tdstA)
    | 64<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let dst = transOprToExpr ins ctxt dst
      let srcB, srcA = transOprToExpr128 ctxt src
      let p = getParsingInfo ins
      let struct (tsrcB, tsrcA) = tmpVars2 ir 64<rt>
      !!ir (tsrcA := (srcB << numI32 63 64<rt>) .| (srcA >> AST.num1 64<rt>))
      !!ir (tsrcB := srcB >> AST.num1 64<rt>)
      for e in 0 .. (p.Elements - 1) / 2 do
        !!ir (elem dst (e + 2) 16 :=
          AST.cast CastKind.FloatCast 16<rt> (elem tsrcB e 32))
        !!ir (elem dst e 16 :=
          AST.cast CastKind.FloatCast 16<rt> (elem tsrcA e 32))
    (* VCVT (between double-precision and single-precision) *)
    | _ ->
      let struct (dst, src) = transTwoOprs ins ctxt
      let cast =
        if isDoubleToSingle ins.SIMDTyp then AST.cast CastKind.FloatCast 32<rt>
        else AST.cast CastKind.FloatCast 64<rt>
      !!ir (dst := cast src)
  | _ -> raise InvalidOperandException

let vcvt (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  parseOprOfVCVT ins ctxt ir
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfVDUP (ins: InsInfo) insLen ctxt esize =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector dst)),
                 OprSIMD (SFReg (Scalar (src, Some idx)))) ->
    getRegVar ctxt dst, elem (getRegVar ctxt src) (int32 idx) esize
  | TwoOperands (OprSIMD (SFReg (Vector dst)), OprReg src) ->
    getRegVar ctxt dst,
    AST.xtlo (RegType.fromBitWidth esize) (getRegVar ctxt src)
  | _ -> raise InvalidOperandException

let parseOprOfVDUP128 (ins: InsInfo) insLen ctxt esize =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector dst)),
                 OprSIMD (SFReg (Scalar (src, Some idx)))) ->
    getPseudoRegVar128 ctxt dst, elem (getRegVar ctxt src) (int32 idx) esize
  | TwoOperands (OprSIMD (SFReg (Vector dst)), OprReg src) ->
    getPseudoRegVar128 ctxt dst,
    AST.xtlo (RegType.fromBitWidth esize) (getRegVar ctxt src)
  | _ -> raise InvalidOperandException

let vdiv (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match p.ESize with
  | 16 ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst :=
      AST.zext 32<rt> (AST.fdiv (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := AST.fdiv src1 src2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vdup (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let (dstB, dstA), scalar = parseOprOfVDUP128 ins insLen ctxt p.ESize
    for e in 0 .. p.Elements - 1 do
      !!ir (elem dstB e p.ESize := scalar)
      !!ir (elem dstA e p.ESize := scalar)
  | _ ->
    let dst, scalar = parseOprOfVDUP ins insLen ctxt p.ESize
    for e in 0 .. p.Elements - 1 do !!ir (elem dst e p.ESize := scalar) done
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let highestSetBitForIR dst src width oprSz (ir: IRBuilder) =
  let lblLoop = !%ir "Loop"
  let lblLoopCont = !%ir "LoopContinue"
  let lblUpdateTmp = !%ir "UpdateTmp"
  let lblEnd = !%ir "End"
  let t = !+ir oprSz
  let width = (numI32 (width - 1) oprSz)
  !!ir (t := width)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (src >> t == AST.num1 oprSz)
                       (AST.name lblEnd) (AST.name lblLoopCont))
  !!ir (AST.lmark lblLoopCont)
  !!ir (AST.cjmp (t == AST.num0 oprSz)
                       (AST.name lblEnd) (AST.name lblUpdateTmp))
  !!ir (AST.lmark lblUpdateTmp)
  !!ir (t := t .- AST.num1 oprSz)
  !!ir (AST.jmp (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (dst := width .- t)

let countLeadingZeroBitsForIR dst src oprSize ir =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize ir

let vclz (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    for e in 0 .. p.Elements - 1 do
      countLeadingZeroBitsForIR (elem dstB e p.ESize)
                                (elem srcB e p.ESize) p.RtESize ir
      countLeadingZeroBitsForIR (elem dstA e p.ESize)
                                (elem srcA e p.ESize) p.RtESize ir
  | _ ->
    let struct (dst, src) = transTwoOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      countLeadingZeroBitsForIR (elem dst e p.ESize)
                                (elem src e p.ESize) p.RtESize ir
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

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

let private unsignExtend (ins: InsInfo) p size expr1 expr2 amtOp =
  if isUnsigned ins.SIMDTyp then mulZExtend p size expr1 expr2 amtOp
  else mulSExtend p size expr1 expr2 amtOp

let vmaxmin (ins: InsInfo) insLen ctxt maximum =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let unsigned = isUnsigned ins.SIMDTyp
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let op1B, op2B = elem src1B e p.ESize, elem src2B e p.ESize
      let op1A, op2A = elem src1A e p.ESize, elem src2A e p.ESize
      let result1 =
        if maximum then maxExpr unsigned op1B op2B
        else minExpr unsigned op1B op2B
      let result2 =
        if maximum then maxExpr unsigned op1A op2A
        else minExpr unsigned op1A op2A
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let op1 = elem src1 e p.ESize
      let op2 = elem src2 e p.ESize
      let result =
        if maximum then maxExpr unsigned op1 op2 else minExpr unsigned op1 op2
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseOprOfVSTLDM (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    getRegVar ctxt reg, List.map (getRegVar ctxt) regs
  | _ -> raise InvalidOperandException

let vstm (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rn, regList = parseOprOfVSTLDM ins insLen ctxt
  let add =
    match ins.Opcode with
    | Op.VSTMIA -> true
    | Op.VSTMDB -> false
    | _ -> raise InvalidOpcodeException
  let regs = List.length regList
  let imm32 = numI32 ((regs * 2) <<< 2) 32<rt>
  let addr = !+ir 32<rt>
  let updateRn rn =
    if ins.WriteBack then
      if add then rn .+ imm32 else rn .- imm32
    else rn
  !!ir (addr := if add then rn else rn .- imm32)
  !!ir (rn := updateRn rn)
  for r in 0 .. (regs - 1) do
    let mem1 = AST.loadLE 32<rt> addr
    let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let data1 = AST.xtlo 32<rt> regList[r]
    let data2 = AST.xthi 32<rt> regList[r]
    let isbig = ctxt.Endianness = Endian.Big
    !!ir (mem1 := if isbig then data2 else data1)
    !!ir (mem2 := if isbig then data1 else data2)
    !!ir (addr := addr .+ (numI32 8 32<rt>))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vldm (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rn, regList = parseOprOfVSTLDM ins insLen ctxt
  let add =
    match ins.Opcode with
    | Op.VLDMIA -> true
    | Op.VLDMDB -> false
    | _ -> raise InvalidOpcodeException
  let regs = List.length regList
  let imm32 = numI32 ((regs * 2) <<< 2) 32<rt>
  let addr = !+ir 32<rt>
  let updateRn rn =
    if ins.WriteBack then
      if add then rn .+ imm32 else rn .- imm32
    else rn
  !!ir (addr := if add then rn else rn .- imm32)
  !!ir (rn := updateRn rn)
  for r in 0 .. (regs - 1) do
    let word1 = AST.loadLE 32<rt> addr
    let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let isbig = ctxt.Endianness = Endian.Big
    !!ir (regList[r] :=
           if isbig then AST.concat word1 word2 else AST.concat word2 word1)
    !!ir (addr := addr .+ (numI32 8 32<rt>))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulAccOrSub (ins: InsInfo) insLen ctxt add =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let sext1A = AST.sext p.RtESize (elem src1A e p.ESize)
      let sext1B = AST.sext p.RtESize (elem src1B e p.ESize)
      let sext2A = AST.sext p.RtESize (elem src2A e p.ESize)
      let sext2B = AST.sext p.RtESize (elem src2B e p.ESize)
      let productA = sext1A .* sext2A
      let productB = sext1B .* sext2B
      let addendA, addendB =
        if add then productA, productB else AST.not productA, AST.not productB
      !!ir (elem dstB e p.ESize := elem dstB e p.ESize .+ addendB)
      !!ir (elem dstA e p.ESize := elem dstA e p.ESize .+ addendA)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let sext1 = AST.sext p.RtESize (elem src1 e p.ESize)
      let sext2 = AST.sext p.RtESize (elem src2 e p.ESize)
      let product = sext1 .* sext2
      let addend = if add then product else AST.not product
      !!ir (elem dst e p.ESize := elem dst e p.ESize .+ addend)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulAccOrSubLong (ins: InsInfo) insLen ctxt add =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let unsigned = isUnsigned ins.SIMDTyp
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ctxt dst
  let src1 = transOprToExpr ins ctxt src1
  let src2 = transOprToExpr ins ctxt src2
  for e in 0 .. (p.Elements - 1) / 2 do
    let extend expr =
      if unsigned then AST.zext (p.RtESize * 2) expr
      else AST.sext (p.RtESize * 2) expr
    let productA = extend (elem src1 e p.ESize) .* extend (elem src2 e p.ESize)
    let productB = extend (elem src1 (e + p.Elements / 2) p.ESize) .*
                   extend (elem src2 (e + p.Elements / 2) p.ESize)
    let addendA, addendB =
      if add then productA, productB else AST.not productA, AST.not productB
    !!ir (elem dstB e (p.ESize * 2) := elem dstB e (p.ESize * 2) .+ addendB)
    !!ir (elem dstA e (p.ESize * 2) := elem dstA e (p.ESize * 2) .+ addendA)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulAccOrSubByScalar (ins: InsInfo) insLen ctxt add =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let struct (dst, src1, src2) = getThreeOprs ins
  let src2, index = transOprToSclar ctxt src2
  let op2Val = AST.sext p.RtESize (elem src2 index p.ESize)
  match ins.OprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    for e in 0 .. p.Elements - 1 do
      let op1valA = AST.sext p.RtESize (elem src1A e p.ESize)
      let op1valB = AST.sext p.RtESize (elem src1B e p.ESize)
      let addendA, addendB =
        if add then op1valA .* op2Val, op1valB .* op2Val
        else AST.not (op1valA .* op2Val), AST.not (op1valB .* op2Val)
      !!ir (elem dstB e p.ESize := elem dstB e p.ESize .+ addendB)
      !!ir (elem dstA e p.ESize := elem dstA e p.ESize .+ addendA)
  | _ ->
    let dst = transOprToExpr ins ctxt dst
    let src1 = transOprToExpr ins ctxt src1
    for e in 0 .. p.Elements - 1 do
      let op1val = AST.sext p.RtESize (elem src1 e p.ESize)
      let addend =
        if add then op1val .* op2Val else AST.not (op1val .* op2Val)
      !!ir (elem dst e p.ESize := elem dst e p.ESize .+ addend)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulAccOrSubLongByScalar (ins: InsInfo) insLen ctxt add =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ctxt dst
  let src1 = transOprToExpr ins ctxt src1
  let src2, index = transOprToSclar ctxt src2
  let p = getParsingInfo ins
  let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  let op2val = ext (p.RtESize * 2) (elem src2 index p.ESize)
  for e in 0 .. (p.Elements - 1) / 2 do
    let op1valA = ext (p.RtESize * 2) (elem src1 e p.ESize)
    let op1valB = ext (p.RtESize * 2) (elem src1 (e + p.Elements / 2) p.ESize)
    let addendA, addendB =
      if add then op1valA .* op2val, op1valB .* op2val
      else AST.not (op1valA .* op2val), AST.not (op1valB .* op2val)
    !!ir (elem dstB e (p.ESize * 2) := elem dstB e (p.ESize * 2) .+ addendB)
    !!ir (elem dstA e (p.ESize * 2) := elem dstA e (p.ESize * 2) .+ addendA)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vmla (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSub ins insLen ctxt true
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubByScalar ins insLen ctxt true
  | _ -> raise InvalidOperandException

let vmlal (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSubLong ins insLen ctxt true
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubLongByScalar ins insLen ctxt true
  | _ -> raise InvalidOperandException

let vmls (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSub ins insLen ctxt false
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubByScalar ins insLen ctxt false
  | _ -> raise InvalidOperandException

let vmlsl (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSubLong ins insLen ctxt false
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubLongByScalar ins insLen ctxt false
  | _ -> raise InvalidOperandException

let isPolynomial = function
  | Some (OneDT SIMDTypP8) | Some (OneDT SIMDTypP64) -> true
  | _ -> false

/// shared/functions/vector/PolynomialMult, in page Armv8 Pseudocode-7927
let polynomialMult op1 op2 size rtsize res (ir: IRBuilder) =
  let extendedOP2 = AST.zext rtsize op2
  for i = 0 to size - 1 do
    let cond = AST.extract op1 1<rt> i
    !!ir (res := AST.ite cond (res <+> (extendedOP2 << numI32 i rtsize)) res)

let polynomialMultP64 op1 op2 size rtsize resA resB (ir: IRBuilder) =
  for i = 0 to size - 1 do
    let cond = AST.extract op1 1<rt> i
    !!ir (resA := AST.ite cond (resA <+> (op2 << numI32 i rtsize)) resA)
    !!ir (resB := AST.ite cond (resB <+> (op2 >> numI32 (64 - i) rtsize)) resB)

let vecMul (ins: InsInfo) insLen ctxt opFn =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let polynomial = isPolynomial ins.SIMDTyp
  let struct (resultA, resultB) = tmpVars2 ir (p.RtESize * 2)
  match ins.OprSize with
  (* FP, p.ESize 16 *)
  | 32<rt> when p.ESize = 16 ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst :=
      AST.zext 32<rt> (opFn (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)))
  (* FP, p.ESize 32 *)
  | 32<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := opFn src1 src2)
  (* FP, p.ESize 64 *)
  | 64<rt> when p.ESize = 64 ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := opFn src1 src2)
  (* SIMD *)
  | 64<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let struct (op1, op2) = elem src1 e p.ESize, elem src2 e p.ESize
      if polynomial then
        polynomialMult op1 op2 p.ESize (p.RtESize * 2) resultA ir
      else !!ir (resultA := mulSExtend p 2 op1 op2 opFn)
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize resultA)
  (* SIMD *)
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let struct (op1A, op2A, op1B, op2B) =
        elem src1A e p.ESize, elem src2A e p.ESize,
        elem src1B e p.ESize, elem src2B e p.ESize
      if polynomial then
        polynomialMult op1A op2A p.ESize (p.RtESize * 2) resultA ir
        polynomialMult op1B op2B p.ESize (p.RtESize * 2) resultB ir
      else
        !!ir (resultA := mulSExtend p 2 op1A op2A opFn)
        !!ir (resultB := mulSExtend p 2 op1B op2B opFn)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize resultA)
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize resultB)
  | _ -> raise InvalidOperandException
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulLong (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let polynomial = isPolynomial ins.SIMDTyp
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ctxt dst
  let src1 = transOprToExpr ins ctxt src1
  let src2 = transOprToExpr ins ctxt src2
  let isPolyAndE64 = polynomial && p.ESize = 64
  let struct (regSize, eSize) =
    if isPolyAndE64 then p.RtESize, p.ESize
    else p.RtESize * 2, p.ESize * 2
  let struct (resA, resB) = tmpVars2 ir regSize
  for e in 0 .. (p.Elements - 1) / 2 do
    let struct (op1A, op2A, op1B, op2B) =
      elem src1 e p.ESize, elem src2 e p.ESize,
      elem src1 (e + p.Elements / 2) p.ESize,
      elem src2 (e + p.Elements / 2) p.ESize
    if isPolyAndE64 then
      polynomialMultP64 op1A op2A p.ESize p.RtESize resA resB ir
    elif polynomial then
      polynomialMult op1A op2A p.ESize (p.RtESize * 2) resA ir
      polynomialMult op1A op2A p.ESize (p.RtESize * 2) resB ir
    else
      !!ir (resA := unsignExtend ins p 2 op1A op2A (.*))
      !!ir (resB := unsignExtend ins p 2 op1B op2B (.*))
    !!ir (elem dstB e eSize := AST.xtlo regSize resB)
    !!ir (elem dstA e eSize := AST.xtlo regSize resA)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulByScalar (ins: InsInfo) insLen ctxt opFn =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let struct (dst, src1, src2) = getThreeOprs ins
  let src2, index = transOprToSclar ctxt src2
  let op2val = elem src2 index p.ESize
  match ins.OprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    for e in 0 .. p.Elements - 1 do
      let resA = mulSExtend p 1 (elem src1A e p.ESize) op2val opFn
      let resB = mulSExtend p 1 (elem src1B e p.ESize) op2val opFn
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize resB)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize resA)
  | _ ->
    let dst = transOprToExpr ins ctxt dst
    let src1 = transOprToExpr ins ctxt src1
    for e in 0 .. p.Elements - 1 do
      let res = mulSExtend p 1 (elem src1 e p.ESize) op2val opFn
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize res)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vecMulLongByScalar (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = getThreeOprs ins
  let dstB, dstA = transOprToExpr128 ctxt dst
  let src1 = transOprToExpr ins ctxt src1
  let src2, index = transOprToSclar ctxt src2
  let p = getParsingInfo ins
  let op2val = elem src2 index p.ESize
  let pele2 = p.Elements / 2
  for e in 0 .. (p.Elements - 1) / 2 do
    let resA = unsignExtend ins p 2 (elem src1 e p.ESize) op2val (.*)
    let resB = unsignExtend ins p 2 (elem src1 (e + pele2) p.ESize) op2val (.*)
    !!ir (elem dstB e (p.ESize * 2) := AST.xtlo (p.RtESize * 2) resB)
    !!ir (elem dstA e (p.ESize * 2) := AST.xtlo (p.RtESize * 2) resA)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vmul (ins: InsInfo) insLen ctxt opFn =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMul ins insLen ctxt opFn
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulByScalar ins insLen ctxt opFn
  | _ -> raise InvalidOperandException

let vmull (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulLong ins insLen ctxt
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulLongByScalar ins insLen ctxt
  | _ -> raise InvalidOperandException

let getSizeStartFromI16 = function
  | Some (OneDT SIMDTypI16) -> 0b00
  | Some (OneDT SIMDTypI32) -> 0b01
  | Some (OneDT SIMDTypI64) -> 0b10
  | _ -> raise InvalidOperandException

let getSizeStartFrom16 = function
  | Some (OneDT SIMDTyp16) -> 0b00
  | Some (OneDT SIMDTyp32) -> 0b01
  | Some (OneDT SIMDTyp64) -> 0b10
  | _ -> raise InvalidOperandException

let vmovn (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins ctxt dst
  let srcB, srcA = transOprToExpr128 ctxt src
  let esize = 8 <<< getSizeStartFrom16 ins.SIMDTyp
  let rtEsz = RegType.fromBitWidth esize
  let elements = 64 / esize
  for e in 0 .. (elements - 1) / 2 do
    !!ir (elem dst e esize := AST.xtlo rtEsz (elem srcB e esize))
    !!ir (elem dst (e + elements / 2) esize :=
         AST.xtlo rtEsz (elem srcA e esize))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vneg (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    for e in 0 .. p.Elements - 1 do
      let result1 = AST.neg <| AST.sext p.RtESize (elem srcB e p.ESize)
      let result2 = AST.neg <| AST.sext p.RtESize (elem srcA e p.ESize)
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src) = transTwoOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let result = AST.neg <| AST.sext p.RtESize (elem src e p.ESize)
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vpadd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (rd, rn, rm) = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let h = p.Elements / 2
  let dest = !+ir 64<rt>
  for e in 0 .. h - 1 do
    let addPair expr =
      elem expr (2 * e) p.ESize .+ elem expr (2 * e + 1) p.ESize
    !!ir (elem dest e p.ESize := addPair rn)
    !!ir (elem dest (e + h) p.ESize := addPair rm)
  !!ir (rd := dest)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vrshr (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    let imm = AST.zext 64<rt> (transOprToExpr ins ctxt imm)
    let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
    for e in 0 .. p.Elements - 1 do
      let result1 = (extend 64<rt> (elem srcB e p.ESize) .+ roundConst) >> imm
      let result2 = (extend 64<rt> (elem srcA e p.ESize) .+ roundConst) >> imm
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins ctxt
    let imm = AST.zext 64<rt> imm
    let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
    for e in 0 .. p.Elements - 1 do
      let result = (extend 64<rt> (elem src e p.ESize) .+ roundConst) >> imm
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vshlImm (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    let imm = AST.zext p.RtESize (transOprToExpr ins ctxt imm)
    for e in 0 .. p.Elements - 1 do
      !!ir (elem dstB e p.ESize := elem srcB e p.ESize << imm)
      !!ir (elem dstA e p.ESize := elem srcA e p.ESize << imm)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins ctxt
    let imm = AST.zext p.RtESize imm
    for e in 0 .. p.Elements - 1 do
      !!ir (elem dst e p.ESize := elem src e p.ESize << imm)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vshlReg (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let shift1 = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2B e p.ESize))
      let shift2 = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2A e p.ESize))
      let result1 = extend 64<rt> (elem src1B e p.ESize) << shift1
      let result2 = extend 64<rt> (elem src1A e p.ESize) << shift2
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let shift = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2 e p.ESize))
      let result = extend 64<rt> (elem src1 e p.ESize) << shift
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vshl (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vshlImm ins insLen ctxt
  | ThreeOperands (_, _, OprSIMD _) -> vshlReg ins insLen ctxt
  | _ -> raise InvalidOperandException

let vshr (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt dst
    let imm = AST.zext 64<rt> (transOprToExpr ins ctxt imm)
    for e in 0 .. p.Elements - 1 do
      let result1 = extend 64<rt> (elem srcB e p.ESize) >> imm
      let result2 = extend 64<rt> (elem srcA e p.ESize) >> imm
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins ctxt
    let imm = AST.zext 64<rt> imm
    for e in 0 .. p.Elements - 1 do
      let result = extend 64<rt> (elem src e p.ESize) >> imm
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let parseVectors = function
  | OneReg (Vector d) -> [ d ]
  | TwoRegs (Vector d1, Vector d2) -> [ d1; d2 ]
  | ThreeRegs (Vector d1, Vector d2, Vector d3) -> [ d1; d2; d3 ]
  | FourRegs (Vector d1, Vector d2, Vector d3, Vector d4) -> [ d1; d2; d3; d4 ]
  | _ -> raise InvalidOperandException

let parseOprOfVecTbl (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (OprSIMD (SFReg (Vector rd)), OprSIMD regs,
                   OprSIMD (SFReg (Vector rm))) ->
    getRegVar ctxt rd, parseVectors regs, getRegVar ctxt rm
  | _ -> raise InvalidOperandException

let vecTbl (ins: InsInfo) insLen ctxt isVtbl =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rd, list, rm = parseOprOfVecTbl ins insLen ctxt
  let vectors = list |> List.map (getRegVar ctxt)
  let length = List.length list
  let table = AST.concatArr (List.toArray vectors) |> AST.zext 256<rt>
  for i in 0 .. 7 do
    let index = elem rm i 8
    let cond = AST.lt index (numI32 (8 * length) 8<rt>)
    let e = if isVtbl then AST.num0 8<rt> else elem rd i 8
    !!ir (elem rd i 8 := AST.ite cond (elemForIR table 256<rt> index 8) e)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let isImm = function
  | Num _ -> true
  | _ -> false

let vectorCompareImm (ins: InsInfo) insLen ctxt cmp =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let num0 = AST.num0 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    for e in 0 .. p.Elements - 1 do
      let t1 = cmp (elem src1B e p.ESize) num0
      let t2 = cmp (elem src1A e p.ESize) num0
      !!ir (elem dstB e p.ESize := AST.ite t1 (ones p.RtESize) num0)
      !!ir (elem dstA e p.ESize := AST.ite t2 (ones p.RtESize) num0)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let t = cmp (elem src1 e p.ESize) num0
      !!ir (elem dst e p.ESize := AST.ite t (ones p.RtESize) num0)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vectorCompareReg (ins: InsInfo) insLen ctxt cmp =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let num0 = AST.num0 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let t1 = cmp (elem src1B e p.ESize) (elem src2B e p.ESize)
      let t2 = cmp (elem src1A e p.ESize) (elem src2A e p.ESize)
      !!ir (elem dstB e p.ESize := AST.ite t1 (ones p.RtESize) num0)
      !!ir (elem dstA e p.ESize := AST.ite t2 (ones p.RtESize) num0)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let t = cmp (elem src1 e p.ESize) (elem src2 e p.ESize)
      !!ir (elem dst e p.ESize := AST.ite t (ones p.RtESize) num0)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let getCmp (ins: InsInfo) unsigned signed =
  if isUnsigned ins.SIMDTyp then unsigned else signed

let vceq (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen ctxt (==)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen ctxt (==)
  | _ -> raise InvalidOperandException

let vcge (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen ctxt
                                        (getCmp ins AST.ge AST.sge)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen ctxt
                                         (getCmp ins AST.ge AST.sge)
  | _ -> raise InvalidOperandException

let vcgt (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen ctxt
                                        (getCmp ins AST.gt AST.sgt)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen ctxt
                                         (getCmp ins AST.gt AST.sgt)
  | _ -> raise InvalidOperandException

let vcle (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen ctxt
                                        (getCmp ins AST.le AST.sle)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen ctxt
                                         (getCmp ins AST.le AST.sle)
  | _ -> raise InvalidOperandException

let vclt (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen ctxt
                                        (getCmp ins AST.lt AST.slt)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen ctxt
                                         (getCmp ins AST.lt AST.slt)
  | _ -> raise InvalidOperandException

let vtst (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let n0 = AST.num0 p.RtESize
  let n1 = AST.num1 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. p.Elements - 1 do
      let c = (elem src1B e p.ESize .& elem src2B e p.ESize) != n0
      let c2 = (elem src1A e p.ESize .& elem src2A e p.ESize) != n0
      !!ir (elem dstB e p.ESize := AST.ite c n1 n0)
      !!ir (elem dstA e p.ESize := AST.ite c2 n1 n0)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. p.Elements - 1 do
      let c = (elem src1 e p.ESize .& elem src2 e p.ESize) != n0
      !!ir (elem dst e p.ESize := AST.ite c n1 n0)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vrshrn (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
  let rtEsz = RegType.fromBitWidth esize
  let elements = 64 / esize
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr ins ctxt dst
  let srcB, srcA = transOprToExpr128 ctxt src
  let imm = AST.zext (rtEsz * 2) (transOprToExpr ins ctxt imm)
  let roundConst = AST.num1 (rtEsz * 2) << (imm .- AST.num1 (rtEsz * 2))
  for e in 0 .. (elements / 2) - 1 do
    let result1 = (elem srcB e (esize * 2) .+ roundConst) >> imm
    let result2 = (elem srcA e (esize * 2) .+ roundConst) >> imm
    !!ir (elem dst e esize := AST.xtlo rtEsz result1)
    !!ir (elem dst e esize := AST.xtlo rtEsz result2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vorrReg (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    !!ir (dstB := src1B .| src2B)
    !!ir (dstA := src1A .| src2A)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := src1 .| src2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vorrImm (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, imm) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let imm =
      AST.concat (transOprToExpr ins ctxt imm) (transOprToExpr ins ctxt imm)
    !!ir (dstB := dstB .| imm)
    !!ir (dstA := dstA .| imm)
  | _ ->
    let struct (dst, imm) = transTwoOprs ins ctxt
    let imm = AST.concat imm imm // FIXME: A8-975
    !!ir (dst := dst .| imm)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vorr (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands _ -> vorrReg ins insLen ctxt
  | TwoOperands _ -> vorrImm ins insLen ctxt
  | _ -> raise InvalidOperandException

let vornReg (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    !!ir (dstB := src1B .| (AST.not <| src2B))
    !!ir (dstA := src1A .| (AST.not <| src2A))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    !!ir (dst := src1 .| (AST.not <| src2))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vornImm (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, imm) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let imm =
      AST.concat (transOprToExpr ins ctxt imm) (transOprToExpr ins ctxt imm)
    !!ir (dstB := dstB .| AST.not imm)
    !!ir (dstA := dstA .| AST.not imm)
  | _ ->
    let struct (dst, imm) = transTwoOprs ins ctxt
    let imm = AST.concat imm imm // FIXME: A8-975
    !!ir (dst := dst .| AST.not imm)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vorn (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands _ -> vornReg ins insLen ctxt
  | TwoOperands _ -> vornImm ins insLen ctxt
  | _ -> raise InvalidOperandException

let parseDstList = function
  | TwoOperands (OprSIMD (OneReg (Vector d)), _) -> [ d ]
  | TwoOperands (OprSIMD (TwoRegs (Vector d1, Vector d2)), _) -> [ d1; d2 ]
  | TwoOperands (OprSIMD (ThreeRegs (Vector d1, Vector d2, Vector d3)), _) ->
    [ d1; d2; d3 ]
  | TwoOperands (OprSIMD (FourRegs (Vector d1, Vector d2,
                                    Vector d3, Vector d4)), _) ->
    [ d1; d2; d3; d4 ]
  | TwoOperands (OprSIMD (OneReg (Scalar (d, None))), _) -> [ d ]
  | TwoOperands (OprSIMD (TwoRegs (Scalar (d1, _), Scalar (d2, _))), _) ->
    [ d1; d2 ]
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (d1, _), Scalar (d2, _),
                                     Scalar (d3, _))), _) -> [ d1; d2; d3 ]
  | TwoOperands (OprSIMD (FourRegs (Scalar (d1, _), Scalar (d2, _),
                                    Scalar (d3, _), Scalar (d4, _))), _) ->
    [ d1; d2; d3; d4 ]
  | _ -> raise InvalidOperandException

let getRnAndRm ctxt = function
  | TwoOperands (_, OprMemory (OffsetMode (AlignOffset (rn, _, _))))
  | TwoOperands (_, OprMemory (PreIdxMode (AlignOffset (rn, _, _)))) ->
    getRegVar ctxt rn, None
  | TwoOperands (_, OprMemory (PostIdxMode (AlignOffset (rn, _, Some rm)))) ->
    getRegVar ctxt rn, getRegVar ctxt rm |> Some
  | _ -> raise InvalidOperandException

let assignByEndian (ctxt: TranslationContext) dst src ir =
  let isbig = ctxt.Endianness = Endian.Big
  !!ir (dst := if isbig then AST.xthi 32<rt> src else AST.xtlo 32<rt> src)

let parseOprOfVecStAndLd ctxt (ins: InsInfo) =
  let rdList = parseDstList ins.Operands |> List.map (getRegVar ctxt)
  let rn, rm = getRnAndRm ctxt ins.Operands
  rdList, rn, rm

let updateRn (ins: InsInfo) rn (rm: Expr option) n (regIdx: bool option) =
  let rmOrTransSz = if regIdx.Value then rm.Value else numI32 n 32<rt>
  if ins.WriteBack then rn .+ rmOrTransSz else rn

let incAddr addr n = addr .+ (numI32 n 32<rt>)

let vst1Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let regs = getRegs ins.Operands
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (8 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    for e in 0 .. (p.Elements - 1) do
      if p.EBytes <> 8 then
        let mem = AST.loadLE p.RtESize addr
        !!ir (mem := elem rdList[r] e p.ESize)
      else
        let mem1 = AST.loadLE 32<rt> addr
        let mem2 = AST.loadLE 32<rt> (incAddr addr 4)
        let reg = elem rdList[r] e p.ESize
        assignByEndian ctxt mem1 reg ir
        assignByEndian ctxt mem2 reg ir
      !!ir (addr := addr .+ (numI32 p.EBytes 32<rt>))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst1Single (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rd, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm p.EBytes p.RegIndex)
  let mem = AST.loadLE p.RtESize addr
  !!ir (mem := elem rd[0] (int32 index) p.ESize)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst1 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (OneReg (Scalar (_, Some index))), _) ->
    vst1Single ins insLen ctxt index
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst1Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vld1SingleOne (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rd, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm p.EBytes p.RegIndex)
  let mem = AST.loadLE p.RtESize addr
  !!ir (elem rd[0] (int32 index) p.ESize := mem)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld1SingleAll (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm p.EBytes p.RegIndex)
  let mem = AST.loadLE p.RtESize addr
  let repElem = Array.replicate p.Elements mem |> AST.concatArr
  for r in 0 .. (List.length rdList - 1) do
    !!ir (rdList[r] := repElem) done
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld1Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let regs = getRegs ins.Operands
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (8 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    for e in 0 .. (p.Elements - 1) do
      if p.EBytes <> 8 then
        let data = !+ir p.RtESize
        !!ir (data := AST.loadLE p.RtESize addr)
        !!ir (elem rdList[r] e p.ESize := data)
      else
        let struct (data1, data2) = tmpVars2 ir 32<rt>
        let mem1 = AST.loadLE 32<rt> addr
        let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
        let isbig = ctxt.Endianness = Endian.Big
        !!ir (data1 := if isbig then mem2 else mem1)
        !!ir (data2 := if isbig then mem1 else mem1)
        !!ir (elem rdList[r] e p.ESize := AST.concat data2 data1)
      !!ir (addr := incAddr addr p.EBytes)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld1 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (OneReg (Scalar (_, Some index))), _) ->
    vld1SingleOne ins insLen ctxt index
  | TwoOperands (OprSIMD (OneReg (Scalar _)), _)
  | TwoOperands (OprSIMD (TwoRegs (Scalar _, Scalar _)), _) ->
    vld1SingleAll ins insLen ctxt
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld1Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vst2Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let regs = getRegs ins.Operands / 2
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (16 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    let rd1 = rdList[r * 2]
    let rd2 = rdList[r * 2 + 1]
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
      !!ir (mem1 := elem rd1 e p.ESize)
      !!ir (mem2 := elem rd2 e p.ESize)
      !!ir (addr := addr .+ (numI32 (2 * p.EBytes) 32<rt>))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst2Single (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (16 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
  !!ir (mem1 := elem rdList[0] index p.ESize)
  !!ir (mem2 := elem rdList[1] index p.ESize)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst2 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (TwoRegs (Scalar (_, Some index), _)), _) ->
    vst2Single ins insLen ctxt (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst2Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vst3Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm 24 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    !!ir (mem1 := elem rdList[0] e p.ESize)
    !!ir (mem2 := elem rdList[1] e p.ESize)
    !!ir (mem3 := elem rdList[2] e p.ESize)
    !!ir (addr := incAddr addr (3 * p.EBytes))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst3Single (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  !!ir (mem1 := elem rdList[0] index p.ESize)
  !!ir (mem2 := elem rdList[1] index p.ESize)
  !!ir (mem3 := elem rdList[2] index p.ESize)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst3 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, Some index), _, _)), _) ->
    vst3Single ins insLen ctxt (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst3Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vst4Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm 32 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    !!ir (mem1 := elem rdList[0] e p.ESize)
    !!ir (mem2 := elem rdList[1] e p.ESize)
    !!ir (mem3 := elem rdList[2] e p.ESize)
    !!ir (mem4 := elem rdList[3] e p.ESize)
    !!ir (addr := incAddr addr (4 * p.EBytes))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst4Single (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
  !!ir (mem1 := elem rdList[0] index p.ESize)
  !!ir (mem2 := elem rdList[1] index p.ESize)
  !!ir (mem3 := elem rdList[2] index p.ESize)
  !!ir (mem4 := elem rdList[3] index p.ESize)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vst4 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, Some index), _, _, _)), _) ->
    vst4Single ins insLen ctxt (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst4Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vld2SingleOne (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  !!ir (elem rdList[0] (int32 index) p.ESize := mem1)
  !!ir (elem rdList[1] (int32 index) p.ESize := mem2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld2SingleAll (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let repElem1 = Array.replicate p.Elements mem1 |> AST.concatArr
  let repElem2 = Array.replicate p.Elements mem2 |> AST.concatArr
  !!ir (rdList[0] := repElem1)
  !!ir (rdList[1] := repElem2)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld2Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let regs = getRegs ins.Operands / 2
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (16 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    let rd1 = rdList[r * 2]
    let rd2 = rdList[r * 2 + 1]
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
      !!ir (elem rd1 e p.ESize := mem1)
      !!ir (elem rd2 e p.ESize := mem2)
      !!ir (addr := incAddr addr (2 * p.EBytes))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld2 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (TwoRegs (Scalar (_, Some index), _)), _) ->
    vld2SingleOne ins insLen ctxt index
  | TwoOperands (OprSIMD (TwoRegs (Scalar _, Scalar _)), _) ->
    vld2SingleAll ins insLen ctxt
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld2Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vld3SingleOne (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  !!ir (elem rdList[0] (int32 index) p.ESize := mem1)
  !!ir (elem rdList[1] (int32 index) p.ESize := mem2)
  !!ir (elem rdList[2] (int32 index) p.ESize := mem3)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld3SingleAll (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let repElem1 = Array.replicate p.Elements mem1 |> AST.concatArr
  let repElem2 = Array.replicate p.Elements mem2 |> AST.concatArr
  let repElem3 = Array.replicate p.Elements mem3 |> AST.concatArr
  !!ir (rdList[0] := repElem1)
  !!ir (rdList[1] := repElem2)
  !!ir (rdList[2] := repElem3)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld3Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm 24 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    !!ir (elem rdList[0] e p.ESize := mem1)
    !!ir (elem rdList[1] e p.ESize := mem2)
    !!ir (elem rdList[2] e p.ESize := mem3)
    !!ir (addr := addr .+ (numI32 (3 * p.EBytes) 32<rt>))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld3 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, Some index), _, _)), _) ->
    vld3SingleOne ins insLen ctxt index
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, None), _, _)), _) ->
    vld3SingleAll ins insLen ctxt
  | TwoOperands (OprSIMD (ThreeRegs _), _) -> vld3Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let vld4SingleOne (ins: InsInfo) insLen ctxt index =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
  !!ir (elem rdList[0] (int32 index) p.ESize := mem1)
  !!ir (elem rdList[1] (int32 index) p.ESize := mem2)
  !!ir (elem rdList[2] (int32 index) p.ESize := mem3)
  !!ir (elem rdList[3] (int32 index) p.ESize := mem4)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld4SingleAll (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
  let repElem1 = Array.replicate p.Elements mem1 |> AST.concatArr
  let repElem2 = Array.replicate p.Elements mem2 |> AST.concatArr
  let repElem3 = Array.replicate p.Elements mem3 |> AST.concatArr
  let repElem4 = Array.replicate p.Elements mem4 |> AST.concatArr
  !!ir (rdList[0] := repElem1)
  !!ir (rdList[1] := repElem2)
  !!ir (rdList[2] := repElem3)
  !!ir (rdList[3] := repElem4)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld4Multi (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let p = getParsingInfo ins
  let addr = !+ir 32<rt>
  !!ir (addr := rn)
  !!ir (rn := updateRn ins rn rm 24 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    !!ir (elem rdList[0] e p.ESize := mem1)
    !!ir (elem rdList[1] e p.ESize := mem2)
    !!ir (elem rdList[2] e p.ESize := mem3)
    !!ir (elem rdList[3] e p.ESize := mem4)
    !!ir (addr := addr .+ (numI32 (4 * p.EBytes) 32<rt>))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vld4 (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, Some index), _, _, _)), _) ->
    vld4SingleOne ins insLen ctxt index
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, None), _, _, _)), _) ->
    vld4SingleAll ins insLen ctxt
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld4Multi ins insLen ctxt
  | _ -> raise InvalidOperandException

let udf (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand (OprImm n) -> sideEffects insLen ctxt (Interrupt (int n))
  | _ -> raise InvalidOperandException

let uasx (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let cpsr = getRegVar ctxt R.CPSR
  let struct (diff, sum) = tmpVars2 ir 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let struct (ge10, ge32) = tmpVars2 ir 32<rt>
  let numI32 n = numI32 n 32<rt>
  !!ir (diff := xtlo src1 .- xthi src2)
  !!ir (sum := xthi src1 .+ xtlo src2)
  !!ir (dst := AST.concat (AST.xtlo 16<rt> sum) (AST.xtlo 16<rt> diff))
  !!ir (ge10 := AST.ite (diff .>= numI32 0) (numI32 0xC0000) (numI32 0))
  !!ir (ge32 := AST.ite (sum .>= numI32 0x10000) (numI32 0x30000) (numI32 0))
  !!ir (cpsr := (cpsr .& (numI32 0xFFF0FFFF)) .| (ge32 .| ge10))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let uhsub16 (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let struct (diff1, diff2) = tmpVars2 ir 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let n1 = AST.num1 32<rt>
  !!ir (diff1 := xtlo src1 .- xtlo src2)
  !!ir (diff2 := xthi src1 .- xthi src2)
  !!ir (dst :=
    AST.concat (AST.xtlo 16<rt> (diff2 >> n1)) (AST.xtlo 16<rt> (diff1 >> n1)))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let uqsax (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let struct (sum, diff) = tmpVars2 ir 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  !!ir (sum := xtlo src1 .+ xthi src2)
  !!ir (diff := xthi src1 .- xtlo src2)
  !!ir (dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let usax (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let cpsr = getRegVar ctxt R.CPSR
  let struct (sum, diff) = tmpVars2 ir 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let struct (ge10, ge32) = tmpVars2 ir 32<rt>
  let numI32 n = numI32 n 32<rt>
  !!ir (sum := xtlo src1 .+ xthi src2)
  !!ir (diff := xthi src1 .- xtlo src2)
  !!ir (dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum))
  !!ir (ge10 := AST.ite (sum .>= numI32 0x10000) (numI32 0x30000) (numI32 0))
  !!ir (ge32 := AST.ite (diff .>= numI32 0) (numI32 0xC0000) (numI32 0))
  !!ir (cpsr := (cpsr .& (numI32 0xFFF0FFFF)) .| (ge10 .| ge32))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vext (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = getImmValue imm
  let rightAmt = numI64 ((8L * imm) % 64L) 64<rt>
  let leftAmt = numI64 (64L - ((8L * imm) % 64L)) 64<rt>
  match ins.OprSize with
  | 128<rt> ->
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    let struct (tSrc1B, tSrc1A, tSrc2B, tSrc2A) = tmpVars4 ir 64<rt>
    !!ir (tSrc1A := src1A)
    !!ir (tSrc1B := src1B)
    !!ir (tSrc2A := src2A)
    !!ir (tSrc2B := src2B)
    if 8L * imm < 64 then
      !!ir (dstA := (tSrc1B << leftAmt) .| (tSrc1A >> rightAmt))
      !!ir (dstB := (tSrc2A << leftAmt) .| (tSrc1B >> rightAmt))
    else
      !!ir (dstA := (tSrc2A << leftAmt) .| (tSrc1B >> rightAmt))
      !!ir (dstB := (tSrc2B << leftAmt) .| (tSrc2A >> rightAmt))
  | _ ->
    let struct (dst, src1, src2, _imm) = transFourOprs ins ctxt
    let struct (tSrc2, tSrc1) = tmpVars2 ir 64<rt>
    !!ir (tSrc1 := src1)
    !!ir (tSrc2 := src2)
    !!ir (dst := (tSrc2 << leftAmt) .| (tSrc1 >> rightAmt))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vhaddsub (ins: InsInfo) insLen ctxt opFn =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    let struct (op1B, op2B, op1A, op2A) = tmpVars4 ir p.RtESize
    for e in 0 .. p.Elements - 1 do
      !!ir (op1B := elem src1B e p.ESize)
      !!ir (op2B := elem src2B e p.ESize)
      !!ir (op1A := elem src1A e p.ESize)
      !!ir (op2A := elem src2A e p.ESize)
      !!ir (elem dstB e p.ESize := (opFn op1B op2B) >> (AST.num1 p.RtESize))
      !!ir (elem dstA e p.ESize := (opFn op1A op2A) >> (AST.num1 p.RtESize))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    let struct (op1, op2) = tmpVars2 ir p.RtESize
    for e in 0 .. p.Elements - 1 do
      !!ir (op1 := elem src1 e p.ESize)
      !!ir (op2 := elem src2 e p.ESize)
      !!ir (elem dst e p.ESize := (opFn op1 op2) >> (AST.num1 p.RtESize))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vrhadd (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let struct (op1, op2) = tmpVars2 ir p.RtESize
  let n1 = AST.num1 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let src1B, src1A = transOprToExpr128 ctxt src1
    let src2B, src2A = transOprToExpr128 ctxt src2
    for e in 0 .. (64 / p.ESize) - 1 do
      !!ir (op1 := elem src1B e p.ESize .+ elem src2B e p.ESize .+ n1)
      !!ir (op2 := elem src1A e p.ESize .+ elem src2A e p.ESize .+ n1)
      !!ir (elem dstB e p.ESize := AST.xtlo p.RtESize (op1 >> n1))
      !!ir (elem dstA e p.ESize := AST.xtlo p.RtESize (op2 >> n1))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins ctxt
    for e in 0 .. (64 / p.ESize) - 1 do
      !!ir (op1 := elem src1 e p.ESize)
      !!ir (op2 := elem src2 e p.ESize)
      let result = op1 .+ op2 .+ n1
      !!ir (elem dst e p.ESize := AST.xtlo p.RtESize (result >> n1))
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vsra (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let struct (result1, result2, shfAmt) = tmpVars3 ir p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    let imm = transOprToExpr ins ctxt imm
    !!ir (shfAmt := if p.RtESize = 64<rt> then AST.zext p.RtESize imm
                    else AST.xtlo p.RtESize imm)
    for e in 0 .. p.Elements - 1 do
      !!ir (result1 := srcB >> shfAmt)
      !!ir (result2 := srcA >> shfAmt)
      !!ir (dstB := dstB .+ result1)
      !!ir (dstA := dstA .+ result2)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins ctxt
    !!ir (shfAmt := if p.RtESize = 64<rt> then AST.zext p.RtESize imm
                    else AST.xtlo p.RtESize imm)
    for e in 0 .. p.Elements - 1 do
      !!ir (result1 := src >> shfAmt)
      !!ir (dst := dst .+ result1)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

let vuzp (ins: InsInfo) insLen ctxt =
  let ir = !*ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let p = getParsingInfo ins
  let struct (zip1B, zip1A, zip2B, zip2A) = tmpVars4 ir 64<rt>
  let elements = (p.Elements - 1) / 2
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let dstB, dstA = transOprToExpr128 ctxt dst
    let srcB, srcA = transOprToExpr128 ctxt src
    if dstB = srcB && dstA = srcA then
      !!ir (dstB := AST.undef 64<rt> "UNKNOWN")
      !!ir (dstA := AST.undef 64<rt> "UNKNOWN")
      !!ir (srcB := AST.undef 64<rt> "UNKNOWN")
      !!ir (srcA := AST.undef 64<rt> "UNKNOWN")
    else
      !!ir (zip1B := srcB)
      !!ir (zip1A := srcA)
      !!ir (zip2B := dstB)
      !!ir (zip2A := dstA)
      for e in 0 .. elements do
        let pos = e + p.Elements / 2
        !!ir (elem dstB pos p.ESize := elem zip1B (e * 2) p.ESize)
        !!ir (elem srcB pos p.ESize := elem zip1B (e * 2 + 1) p.ESize)
        !!ir (elem dstB e p.ESize := elem zip1A (e * 2) p.ESize)
        !!ir (elem srcB e p.ESize := elem zip1A (e * 2 + 1) p.ESize)
        !!ir (elem dstA pos p.ESize := elem zip2B (e * 2) p.ESize)
        !!ir (elem srcA pos p.ESize := elem zip2B (e * 2 + 1) p.ESize)
        !!ir (elem dstA e p.ESize := elem zip2A (e * 2) p.ESize)
        !!ir (elem srcA e p.ESize := elem zip2A (e * 2 + 1) p.ESize)
  | _ ->
    let struct (dst, src) = transTwoOprs ins ctxt
    if dst = src then
      !!ir (dst := AST.undef ins.OprSize "UNKNOWN")
      !!ir (src := AST.undef ins.OprSize "UNKNOWN")
    else
      !!ir (zip1B := src)
      !!ir (zip1A := dst)
      for e in 0 .. elements do
        let pos = e + p.Elements / 2
        !!ir (elem dst e p.ESize := elem zip1B (e * 2) p.ESize)
        !!ir (elem src e p.ESize := elem zip1B (e * 2 + 1) p.ESize)
        !!ir (elem dst pos p.ESize := elem zip1A (e * 2) p.ESize)
        !!ir (elem src pos p.ESize := elem zip1A (e * 2 + 1) p.ESize)
  putEndLabel ctxt lblIgnore ir
  !>ir insLen

/// Translate IR.
let translate (ins: ARM32InternalInstruction) insLen ctxt =
  match ins.Opcode with
  | Op.ADC -> adc false ins insLen ctxt
  | Op.ADCS -> adcs true ins insLen ctxt
  | Op.ADD | Op.ADDW -> add false ins insLen ctxt
  | Op.ADDS -> adds true ins insLen ctxt
  | Op.ADR -> adr ins insLen ctxt // for Thumb mode
  | Op.AND -> logicalAnd false ins insLen ctxt
  | Op.ANDS -> ands true ins insLen ctxt
  | Op.ASR -> shiftInstr false ins insLen SRTypeASR ctxt
  | Op.ASRS -> asrs true ins insLen ctxt
  | Op.B -> b ins insLen ctxt
  | Op.BFC -> bfc ins insLen ctxt
  | Op.BFI -> bfi ins insLen ctxt
  | Op.BIC -> bic false ins insLen ctxt
  | Op.BICS -> bics true ins insLen ctxt
  | Op.BKPT -> sideEffects insLen ctxt Breakpoint
  | Op.BL -> bl ins insLen ctxt
  | Op.BLX -> branchWithLink ins insLen ctxt
  | Op.BX -> bx ins insLen ctxt
  | Op.BXJ -> bx ins insLen ctxt
  | Op.CBNZ -> cbz true ins insLen ctxt
  | Op.CBZ -> cbz false ins insLen ctxt
  | Op.CDP | Op.CDP2 | Op.LDC | Op.LDC2 | Op.LDC2L | Op.LDCL | Op.MCR | Op.MCR2
  | Op.MCRR | Op.MCRR2 | Op.MRC | Op.MRC2 | Op.MRRC | Op.MRRC2 | Op.STC
  | Op.STC2 | Op.STC2L | Op.STCL ->
    sideEffects insLen ctxt UnsupportedExtension (* coprocessor instructions *)
  | Op.CLZ -> clz ins insLen ctxt
  | Op.CMN -> cmn ins insLen ctxt
  | Op.CMP -> cmp ins insLen ctxt
  | Op.DMB | Op.DSB | Op.ISB | Op.PLD -> nop insLen ctxt
  | Op.EOR -> eor false ins insLen ctxt
  | Op.EORS -> eors true ins insLen ctxt
  | Op.ERET -> sideEffects insLen ctxt UnsupportedExtension
  | Op.IT | Op.ITT | Op.ITE | Op.ITTT | Op.ITET | Op.ITTE | Op.ITEE | Op.ITTTT
  | Op.ITETT | Op.ITTET | Op.ITEET | Op.ITTTE | Op.ITETE | Op.ITTEE
  | Op.ITEEE -> it ins insLen ctxt
  | Op.LDM -> ldm Op.LDM ins insLen ctxt (.+)
  | Op.LDMDA -> ldm Op.LDMDA ins insLen ctxt (.-)
  | Op.LDMDB -> ldm Op.LDMDB ins insLen ctxt (.-)
  | Op.LDMIA -> ldm Op.LDMIA ins insLen ctxt (.+)
  | Op.LDMIB -> ldm Op.LDMIB ins insLen ctxt (.+)
  | Op.LDR -> ldr ins insLen ctxt 32<rt> AST.zext
  | Op.LDRB -> ldr ins insLen ctxt 8<rt> AST.zext
  | Op.LDRBT -> ldr ins insLen ctxt 8<rt> AST.zext
  | Op.LDRD -> ldrd ins insLen ctxt
  | Op.LDREX -> ldr ins insLen ctxt 32<rt> AST.zext
  | Op.LDRH -> ldr ins insLen ctxt 16<rt> AST.zext
  | Op.LDRHT -> ldr ins insLen ctxt 16<rt> AST.zext
  | Op.LDRSB -> ldr ins insLen ctxt 8<rt> AST.sext
  | Op.LDRSBT -> ldr ins insLen ctxt 8<rt> AST.sext
  | Op.LDRSH -> ldr ins insLen ctxt 16<rt> AST.sext
  | Op.LDRSHT -> ldr ins insLen ctxt 16<rt> AST.sext
  | Op.LDRT -> ldr ins insLen ctxt 32<rt> AST.zext
  | Op.LSL -> shiftInstr false ins insLen SRTypeLSL ctxt
  | Op.LSLS -> lsls true ins insLen ctxt
  | Op.LSR -> shiftInstr false ins insLen SRTypeLSR ctxt
  | Op.LSRS -> lsrs true ins insLen ctxt
  | Op.MLA -> mla false ins insLen ctxt
  | Op.MLAS -> mla true ins insLen ctxt
  | Op.MLS -> mls ins insLen ctxt
  | Op.MOV | Op.MOVW -> mov false ins insLen ctxt
  | Op.MOVS -> movs true ins insLen ctxt
  | Op.MOVT -> movt ins insLen ctxt
  | Op.MUL -> mul false ins insLen ctxt
  | Op.MULS -> mul true ins insLen ctxt
  | Op.MVN -> mvn false ins insLen ctxt
  | Op.MVNS -> mvns true ins insLen ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.ORN -> orn false ins insLen ctxt
  | Op.ORNS -> orns true ins insLen ctxt
  | Op.ORR -> orr false ins insLen ctxt
  | Op.ORRS -> orrs true ins insLen ctxt
  | Op.POP -> pop ins insLen ctxt
  | Op.PUSH -> push ins insLen ctxt
  | Op.QDADD -> qdadd ins insLen ctxt
  | Op.QDSUB -> qdsub ins insLen ctxt
  | Op.QSAX -> qsax ins insLen ctxt
  | Op.QSUB16 -> qsub16 ins insLen ctxt
  | Op.RBIT -> rbit ins insLen ctxt
  | Op.REV -> rev ins insLen ctxt
  | Op.RFEDB -> rfedb ins insLen ctxt
  | Op.ROR -> shiftInstr false ins insLen SRTypeROR ctxt
  | Op.RORS -> rors true ins insLen ctxt
  | Op.RRX -> shiftInstr false ins insLen SRTypeRRX ctxt
  | Op.RRXS -> rrxs true ins insLen ctxt
  | Op.RSB -> rsb false ins insLen ctxt
  | Op.RSBS -> rsbs true ins insLen ctxt
  | Op.RSC -> rsc false ins insLen ctxt
  | Op.RSCS -> rscs true ins insLen ctxt
  | Op.SBC -> sbc false ins insLen ctxt
  | Op.SBCS -> sbcs true ins insLen ctxt
  | Op.SBFX -> bfx ins insLen ctxt true
  | Op.SEL -> sel ins insLen ctxt
  | Op.SMLABB -> smulacchalf ins insLen ctxt false false
  | Op.SMLABT -> smulacchalf ins insLen ctxt false true
  | Op.SMLAL -> smulandacc false true ins insLen ctxt
  | Op.SMLALS -> smulandacc true true ins insLen ctxt
  | Op.SMLATB -> smulacchalf ins insLen ctxt true false
  | Op.SMLATT -> smulacchalf ins insLen ctxt true true
  | Op.SMLALBT -> smulacclonghalf ins insLen ctxt false true
  | Op.SMLALTT -> smulacclonghalf ins insLen ctxt true true
  | Op.SMLALD -> smulacclongdual ins insLen ctxt false
  | Op.SMLALDX -> smulacclongdual ins insLen ctxt true
  | Op.SMLAWB -> smulaccwordbyhalf ins insLen ctxt false
  | Op.SMLAWT -> smulaccwordbyhalf ins insLen ctxt true
  | Op.SMULBB -> smulhalf ins insLen ctxt false false
  | Op.SMULBT -> smulhalf ins insLen ctxt false true
  | Op.SMULL -> smulandacc false false ins insLen ctxt
  | Op.SMULLS -> smulandacc true false ins insLen ctxt
  | Op.SMULTB -> smulhalf ins insLen ctxt true false
  | Op.SMULTT -> smulhalf ins insLen ctxt true true
  | Op.STM -> stm Op.STM ins insLen ctxt (.+)
  | Op.STMDA -> stm Op.STMDA ins insLen ctxt (.-)
  | Op.STMDB -> stm Op.STMDB ins insLen ctxt (.-)
  | Op.STMEA -> stm Op.STMIA ins insLen ctxt (.+)
  | Op.STMIA -> stm Op.STMIA ins insLen ctxt (.+)
  | Op.STMIB -> stm Op.STMIB ins insLen ctxt (.+)
  | Op.STR -> str ins insLen ctxt 32<rt>
  | Op.STRB -> str ins insLen ctxt 8<rt>
  | Op.STRBT -> str ins insLen ctxt 8<rt>
  | Op.STRD -> strd ins insLen ctxt
  | Op.STREX -> strex ins insLen ctxt
  | Op.STRH -> str ins insLen ctxt 16<rt>
  | Op.STRHT -> str ins insLen ctxt 16<rt>
  | Op.STRT -> str ins insLen ctxt 32<rt>
  | Op.SUB | Op.SUBW -> sub false ins insLen ctxt
  | Op.SUBS -> subs true ins insLen ctxt
  | Op.SVC -> svc ins insLen ctxt
  | Op.SXTB -> extend ins insLen ctxt AST.sext 8<rt>
  | Op.SXTH -> extend ins insLen ctxt AST.sext 16<rt>
  | Op.TBH | Op.TBB -> tableBranch ins insLen ctxt
  | Op.TEQ -> teq ins insLen ctxt
  | Op.TST -> tst ins insLen ctxt
  | Op.UADD8 -> uadd8 ins insLen ctxt
  | Op.UASX -> uasx ins insLen ctxt
  | Op.UBFX -> bfx ins insLen ctxt false
  | Op.UDF -> udf ins insLen ctxt
  | Op.UHSUB16 -> uhsub16 ins insLen ctxt
  | Op.UMLAL -> umlal false ins insLen ctxt
  | Op.UMLALS -> umlal true ins insLen ctxt
  | Op.UMULL -> umull false ins insLen ctxt
  | Op.UMULLS -> umull true ins insLen ctxt
  | Op.UQADD16 -> uqopr ins insLen ctxt 16 (.+)
  | Op.UQADD8 -> uqopr ins insLen ctxt 8 (.+)
  | Op.UQSAX -> uqsax ins insLen ctxt
  | Op.UQSUB16 -> uqopr ins insLen ctxt 16 (.-)
  | Op.UQSUB8 -> uqopr ins insLen ctxt 8 (.-)
  | Op.USAX -> usax ins insLen ctxt
  | Op.UXTAB -> extendAndAdd ins insLen ctxt 8<rt>
  | Op.UXTAH -> extendAndAdd ins insLen ctxt 16<rt>
  | Op.UXTB -> extend ins insLen ctxt AST.zext 8<rt>
  | Op.UXTH -> extend ins insLen ctxt AST.zext 16<rt>
  | Op.VABS when isF16orF32orF64 ins.SIMDTyp ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.VABS -> vabs ins insLen ctxt
  | Op.VADD when isF16orF32orF64 ins.SIMDTyp -> vaddsub ins insLen ctxt AST.fadd
  | Op.VADD -> vaddsub ins insLen ctxt (.+)
  | Op.VADDL -> vaddl ins insLen ctxt
  | Op.VAND -> vand ins insLen ctxt
  | Op.VCEQ | Op.VCGE | Op.VCGT | Op.VCLE | Op.VCLT
    when isF32orF64 ins.SIMDTyp -> sideEffects insLen ctxt UnsupportedFP
  | Op.VCEQ -> vceq ins insLen ctxt
  | Op.VCGE -> vcge ins insLen ctxt
  | Op.VCGT -> vcgt ins insLen ctxt
  | Op.VCLE -> vcle ins insLen ctxt
  | Op.VCLT -> vclt ins insLen ctxt
  | Op.VCLZ -> vclz ins insLen ctxt
  | Op.VCMLA -> sideEffects insLen ctxt UnsupportedFP
  | Op.VCMP | Op.VCMPE | Op.VACGE | Op.VACGT | Op.VACLE | Op.VACLT | Op.VCVTR
  | Op.VFMA | Op.VFMS | Op.VFNMA | Op.VFNMS | Op.VMSR | Op.VNMLA | Op.VNMLS
  | Op.VNMUL | Op.VSQRT -> sideEffects insLen ctxt UnsupportedFP
  | Op.VCVT -> vcvt ins insLen ctxt
  | Op.VDIV -> vdiv ins insLen ctxt
  | Op.VDUP -> vdup ins insLen ctxt
  | Op.VEXT -> vext ins insLen ctxt
  | Op.VHADD -> vhaddsub ins insLen ctxt (.+)
  | Op.VHSUB -> vhaddsub ins insLen ctxt (.-)
  | Op.VLD1 -> vld1 ins insLen ctxt
  | Op.VLD2 -> vld2 ins insLen ctxt
  | Op.VLD3 -> vld3 ins insLen ctxt
  | Op.VLD4 -> vld4 ins insLen ctxt
  | Op.VLDM | Op.VLDMIA | Op.VLDMDB -> vldm ins insLen ctxt
  | Op.VLDR -> vldr ins insLen ctxt
  | Op.VMAX | Op.VMIN when isF32orF64 ins.SIMDTyp ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.VMAX -> vmaxmin ins insLen ctxt true
  | Op.VMIN -> vmaxmin ins insLen ctxt false
  | Op.VMLA | Op.VMLS when isF16orF32orF64 ins.SIMDTyp ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.VMLA -> vmla ins insLen ctxt
  | Op.VMLAL -> vmlal ins insLen ctxt
  | Op.VMLS -> vmls ins insLen ctxt
  | Op.VMLSL -> vmlsl ins insLen ctxt
  | Op.VMOV when isF16orF32orF64 ins.SIMDTyp -> vmovfp ins insLen ctxt
  | Op.VMOV -> vmov ins insLen ctxt
  | Op.VMOVN -> vmovn ins insLen ctxt
  | Op.VMRS -> vmrs ins insLen ctxt
  | Op.VMUL when isF16orF32orF64 ins.SIMDTyp -> vmul ins insLen ctxt AST.fmul
  | Op.VMUL -> vmul ins insLen ctxt (.*)
  | Op.VMULL -> vmull ins insLen ctxt
  | Op.VNEG when isF32orF64 ins.SIMDTyp ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.VNEG -> vneg ins insLen ctxt
  | Op.VORN -> vorn ins insLen ctxt
  | Op.VORR -> vorr ins insLen ctxt
  | Op.VPADD when isF32orF64 ins.SIMDTyp ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.VPADD -> vpadd ins insLen ctxt
  | Op.VPOP -> vpop ins insLen ctxt
  | Op.VPUSH -> vpush ins insLen ctxt
  | Op.VRHADD -> vrhadd ins insLen ctxt
  | Op.VRINTP -> sideEffects insLen ctxt UnsupportedFP
  | Op.VRSHR -> vrshr ins insLen ctxt
  | Op.VRSHRN -> vrshrn ins insLen ctxt
  | Op.VSHL -> vshl ins insLen ctxt
  | Op.VSHR -> vshr ins insLen ctxt
  | Op.VSRA -> vsra ins insLen ctxt
  | Op.VST1 -> vst1 ins insLen ctxt
  | Op.VST2 -> vst2 ins insLen ctxt
  | Op.VST3 -> vst3 ins insLen ctxt
  | Op.VST4 -> vst4 ins insLen ctxt
  | Op.VSTM | Op.VSTMIA | Op.VSTMDB -> vstm ins insLen ctxt
  | Op.VSTR -> vstr ins insLen ctxt
  | Op.VSUB when isF16orF32orF64 ins.SIMDTyp -> vaddsub ins insLen ctxt AST.fsub
  | Op.VSUB -> vaddsub ins insLen ctxt (.-)
  | Op.VTBL -> vecTbl ins insLen ctxt true
  | Op.VTBX -> vecTbl ins insLen ctxt false
  | Op.VTST -> vtst ins insLen ctxt
  | Op.VUZP -> vuzp ins insLen ctxt
  | Op.InvalidOP -> raise InvalidOpcodeException
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
