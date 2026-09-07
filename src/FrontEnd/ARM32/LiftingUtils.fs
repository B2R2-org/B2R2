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

module internal B2R2.FrontEnd.ARM32.LiftingUtils

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.IRHelper

type internal SCTLR =
  | SCTLR_NMFI

type internal SCR =
  | SCR_AW
  | SCR_FW
  | SCR_NS

type internal NSACR =
  | NSACR_RFR

let getPC bld = regVar bld R.PC

/// Assert check condition. If not, raise an exception (exn).
let assertByCond condition exn = if condition then () else raise exn

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

let sfRegToExpr bld = function
  | Vector reg -> regVar bld reg
  | Scalar(reg, _) -> regVar bld reg

let simdToExpr bld = function
  | SFReg s -> sfRegToExpr bld s
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

let getImmValue imm =
  match imm with
  | OprImm imm -> imm
  | _ -> raise InvalidOperandException

let transOpr128 bld = function
  | OprSIMD(SFReg(Vector reg)) -> pseudoRegVar128 bld reg
  | _ -> raise InvalidOperandException

let transOprToScalar bld = function
  | OprSIMD(SFReg(Scalar(reg, Some idx))) -> regVar bld reg, int32 idx
  | _ -> raise InvalidOperandException

let transOpr (ins: Instruction) bld = function
  | OprSpecReg(reg, _)
  | OprReg reg ->
    regVar bld reg
  | OprRegList regs ->
    regsToExpr regs
  | OprSIMD simd ->
    simdToExpr bld simd
  | OprImm imm ->
    let oprSize = if ins.OprSize = 128<rt> then 64<rt> else ins.OprSize
    numI64 imm oprSize
  | _ ->
    raise InvalidOperandException

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand opr -> transOpr ins bld opr
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(opr1, opr2) ->
    struct (transOpr ins bld opr1, transOpr ins bld opr2)
  | _ ->
    raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(opr1, opr2, opr3) ->
    let opr1 = transOpr ins bld opr1
    let opr2 = transOpr ins bld opr2
    let opr3 = transOpr ins bld opr3
    struct (opr1, opr2, opr3)
  | _ ->
    raise InvalidOperandException

let transFourOprs (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    let o4 = transOpr ins bld o4
    struct (o1, o2, o3, o4)
  | _ ->
    raise InvalidOperandException

let bvOfBaseAddr addr = numU64 addr 32<rt>

/// Gets the mask bits for fetching the RFR bit from the NSACR.
/// NSACR bit[19]
let maskNSACRForRFRbit = numI32 524288 32<rt>

let getNSACR bld nsacrType =
  let nsacr = regVar bld R.NSACR
  match nsacrType with
  | NSACR_RFR -> nsacr .& maskNSACRForRFRbit

let isSetNSACRForRFR bld = getNSACR bld NSACR_RFR == maskNSACRForRFRbit

/// Gets the mask bits for fetching the AW bit from the SCR.
/// SCR bit[5]
let maskSCRForAWbit = numI32 32 32<rt>

/// Gets the mask bits for fetching the FW bit from the SCR.
/// SCR bit[4]
let maskSCRForFWbit = numI32 16 32<rt>

/// Gets the mask bits for fetching the NS bit from the SCR.
/// SCR bit[0]
let maskSCRForNSbit = AST.num1 32<rt>

let getSCR bld scrType =
  let scr = regVar bld R.SCR
  match scrType with
  | SCR_AW -> scr .& maskSCRForAWbit
  | SCR_FW -> scr .& maskSCRForFWbit
  | SCR_NS -> scr .& maskSCRForNSbit

let isSetSCRForAW bld = getSCR bld SCR_AW == maskSCRForAWbit

let isSetSCRForFW bld = getSCR bld SCR_FW == maskSCRForFWbit

let isSetSCRForNS bld = getSCR bld SCR_NS == maskSCRForNSbit

/// Gets the mask bits for fetching the NMFI bit from the SCTLR.
/// SCTLR bit[27]
let maskSCTLRForNMFIbit = AST.num <| BitVector(134217728I, 32<rt>)

let getSCTLR bld sctlrType =
  let sctlr = regVar bld R.SCTLR
  match sctlrType with
  | SCTLR_NMFI -> sctlr .& maskSCTLRForNMFIbit

let isSetSCTLRForNMFI bld = getSCTLR bld SCTLR_NMFI == maskSCTLRForNMFIbit

let enablePSRBits bld reg psrType =
  let psr = regVar bld reg
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
  | _ -> Terminator.impossible ()

let disablePSRBits bld reg psrType =
  let psr = regVar bld reg
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
  | _ -> Terminator.impossible ()

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
  | _ -> Terminator.impossible ()

let setPSR bld reg psrType expr =
  disablePSRBits bld reg psrType
  .| (AST.zext 32<rt> expr |> psrShift psrType)

let getCarryFlag bld = getPSR bld R.CPSR PSR.C >> (numI32 29 32<rt>)

let getZeroMask maskSize regType =
  BitVector(BigInteger.makeMask maskSize, regType)
  |> BitVector.Not
  |> AST.num

let zMaskAnd e regType maskSize = e .& (getZeroMask maskSize regType)

let maskAndOR e1 e2 regType maskSize =
  let mask = getZeroMask maskSize regType
  let expr = e1 .& mask
  expr .| e2

let getOverflowFlagOnAdd e1 e2 r bld =
  let struct (e1High, rHigh) = tmpVars2 bld 1<rt>
  append bld {
    e1High := AST.xthi 1<rt> e1
  }
  let e2High = AST.xthi 1<rt> e2
  append bld {
    rHigh := AST.xthi 1<rt> r
  }
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
let conditionPassed bld cond =
  let struct (cond1, cond2) = parseCond cond
  let result =
    match cond1 with
    | 0b000 -> isSetCPSRz bld
    | 0b001 -> isSetCPSRc bld
    | 0b010 -> isSetCPSRn bld
    | 0b011 -> isSetCPSRv bld
    | 0b100 -> isSetCPSRc bld .& AST.not (isSetCPSRz bld)
    | 0b101 -> isSetCPSRn bld == isSetCPSRv bld
    | 0b110 -> isSetCPSRn bld == isSetCPSRv bld .& AST.not (isSetCPSRz bld)
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
  let carryOut = value >> (amount .- AST.num1 regType) |> AST.xtlo 1<rt>
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
  let carryOut = value ?>> (amount .- AST.num1 regType) |> AST.xtlo 1<rt>
  AST.ite chkZero value result, AST.ite chkZero carryIn carryOut

/// Logical shift right of a bitstring, on page A2-41. for Register amount.
/// function : ASR()
let shiftASRForRegAmount value regType amount carryIn =
  shiftASRCForRegAmount value regType amount carryIn |> fst

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
  let e1 =
    shiftLSLForRegAmount (AST.zext 32<rt> carryIn)
                         regType
                         (amount1 .- AST.num1 regType)
                         carryIn
  let e2 = shiftLSRForRegAmount value regType (AST.num1 regType) carryIn
  let value = AST.ite chkZero value (e1 .| e2)
  let carryIn = AST.ite chkZero carryIn (AST.xtlo 1<rt> value)
  value, carryIn

/// Rotate right with extend of a bitstring, on page A2-41. for Register amount.
/// function : RRX()
let shiftRRXForRegAmount value regType amount carryIn =
  shiftRRXCForRegAmount value regType amount carryIn |> fst

/// Perform a specified shift by a specified amount on a bitstring,
/// with carry output, on page A8-292.
let shiftCForRegAmount value regType shiftType amount carryIn =
  let carryIn = AST.xtlo 1<rt> carryIn
  match shiftType with
  | ShiftOp.LSL -> shiftLSLCForRegAmount value regType amount carryIn
  | ShiftOp.LSR -> shiftLSRCForRegAmount value regType amount carryIn
  | ShiftOp.ASR -> shiftASRCForRegAmount value regType amount carryIn
  | ShiftOp.ROR -> shiftRORCForRegAmount value regType amount carryIn
  | ShiftOp.RRX -> shiftRRXCForRegAmount value regType amount carryIn

/// Logical shift left of a bitstring, with carry output, on page A2-41.
/// function : LSL_C()
let shiftLSLC value regType amount =
  assertByCond (amount > 0u) InvalidOperandException
  let amount = numU32 amount regType
  value << amount, value << (amount .- AST.num1 regType) |> AST.xthi 1<rt>

/// Logical shift left of a bitstring, on page A2-41. function : LSL()
let shiftLSL value regType amount =
  assertByCond (amount >= 0u) InvalidOperandException
  if amount = 0u then value else shiftLSLC value regType amount |> fst

/// Logical shift right of a bitstring, with carry output, on page A2-41.
/// function : LSR_C()
let shiftLSRC value regType amount =
  assertByCond (amount > 0u) InvalidOperandException
  let amount' = numU32 amount regType
  value >> amount', AST.extract value 1<rt> (amount - 1u |> Convert.ToInt32)

/// Logical shift right of a bitstring, on page A2-41. function : LSR()
let shiftLSR value regType amount =
  assertByCond (amount >= 0u) InvalidOperandException
  if amount = 0u then value else shiftLSRC value regType amount |> fst

/// Arithmetic shift right of a bitstring, with carry output, on page A2-41.
/// function : ASR_C()
let shiftASRC value regType amount =
  assertByCond (amount > 0u) InvalidOperandException
  let amount = numU32 amount regType
  value ?>> amount, value ?>> (amount .- AST.num1 regType) |> AST.xtlo 1<rt>

/// Logical shift right of a bitstring, on page A2-41. function : ASR()
let shiftASR value regType amount =
  assertByCond (amount >= 0u) InvalidOperandException
  if amount = 0u then value else shiftASRC value regType amount |> fst

/// Rotate right of a bitstring, with carry output, on page A2-41.
/// function : ROR_C()
let shiftRORC value regType amount =
  assertByCond (amount <> 0u) InvalidOperandException
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
  if amount = 0u then
    value, carryIn
  else
    match shiftType with
    | ShiftOp.LSL -> shiftLSLC value regType amount
    | ShiftOp.LSR -> shiftLSRC value regType amount
    | ShiftOp.ASR -> shiftASRC value regType amount
    | ShiftOp.ROR -> shiftRORC value regType amount
    | ShiftOp.RRX -> shiftRRXC value regType carryIn

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
let addWithCarry src1 src2 carryIn bld =
  let result = tmpVar bld 32<rt>
  append bld {
    result := src1 .+ src2 .+ carryIn
  }
  let carryOut =
    AST.ite (carryIn == (numU32 1u 32<rt>))
      (AST.ge src1 (AST.not src2))
      (AST.gt src1 (AST.not src2))
  let struct (overflow, rHigh) = getOverflowFlagOnAdd src1 src2 result bld
  struct (result, carryOut, overflow, rHigh)

let addWithCarryOnlyResult src1 src2 carryIn = src1 .+ src2 .+ carryIn

/// Sets the ARM instruction set, on page A2-51.
let selectARMInstrSet bld =
  append bld {
    let cpsr = regVar bld R.CPSR
    cpsr := disablePSRBits bld R.CPSR PSR.J
    cpsr := disablePSRBits bld R.CPSR PSR.T
  }

/// Sets the ARM instruction set, on page A2-51.
let selectThumbInstrSet bld =
  append bld {
    let cpsr = regVar bld R.CPSR
    cpsr := disablePSRBits bld R.CPSR PSR.J
    cpsr := enablePSRBits bld R.CPSR PSR.T
  }

/// Sets the instruction set currently in use, on page A2-51.
/// SelectInstrSet()
let selectInstrSet bld isThumb =
  if isThumb then selectThumbInstrSet bld else selectARMInstrSet bld

/// Write value to R.PC, without interworking, on page A2-47.
/// function : BranchWritePC()
let branchWritePC addr jmpInfo =
  let addr = zMaskAnd addr 32<rt> 1
  AST.interjmp addr jmpInfo

let disableITStateForCondBranches bld isUnconditional =
  append bld {
    if isUnconditional then
      ()
    else
      let cpsr = regVar bld R.CPSR
      cpsr := disablePSRBits bld R.CPSR PSR.IT10
      cpsr := disablePSRBits bld R.CPSR PSR.IT72
  }

/// Write value to R.PC, with interworking, on page A2-47.
/// function : BXWritePC()
let bxWritePC bld isUnconditional addr =
  append bld {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let cond1 = AST.xtlo 1<rt> addr == AST.b1
    disableITStateForCondBranches bld isUnconditional
    AST.cjmp cond1 (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    selectThumbInstrSet bld
    AST.interjmp (zMaskAnd addr 32<rt> 1) InterJmpKind.SwitchToThumb
    AST.lmark lblL1
    selectARMInstrSet bld
    AST.interjmp addr InterJmpKind.SwitchToARM
  }

/// Write value to R.PC, with interworking for ARM only from ARMv7 on page
/// A2-47. function : ALUWritePC()
let aluWritePC bld (ins: Instruction) isUnconditional addr =
  if ins.IsThumb then append bld { branchWritePC addr InterJmpKind.Base }
  else bxWritePC bld isUnconditional addr

/// Write value to R.PC, with interworking (without it before ARMv5T),
/// on page A2-47. function : LoadWritePC()
let loadWritePC bld isUnconditional result =
  bxWritePC bld isUnconditional result

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
let pcStoreValue bld = getPC bld

/// Returns TRUE in Secure state or if no Security Extensions, on page B1-1157.
/// function : IsSecure()
let isSecure bld =
  AST.not (haveSecurityExt ()) .| AST.not (isSetSCRForNS bld) .|
  (getPSR bld R.CPSR PSR.M == (numI32 0b10110 32<rt>))

/// Return TRUE if current mode is executes at PL1 or higher, on page B1-1142.
/// function : CurrentModeIsNotUser()
let currentModeIsNotUser bld =
  let modeM = getPSR bld R.CPSR PSR.M
  let modeCond = isBadMode modeM
  let ite1 = AST.ite (modeM == (numI32 0b10000 32<rt>)) AST.b0 AST.b1
  AST.ite modeCond (AST.undef 1<rt> "UNPREDICTABLE") ite1

/// Bitstring replication, on page AppxP-2652.
/// function : Replicate()
let replicate expr regType lsb width value =
  let v = BitVector(BigInteger.makeMask width <<< lsb, regType)
  if value = 0 then expr .& (v |> BitVector.Not |> AST.num)
  else expr .| (v |> AST.num)

/// All-ones bitstring, on page AppxP-2652.
let ones rt = BitVector(RegType.makeMask rt, rt) |> AST.num

/// A mode the write is not allowed to name. Where the condition holds the
/// architecture calls the instruction unpredictable, which is reported as
/// undefined for now; where it does not, the write carries on. The two labels
/// are passed in because the IR names them, and every guard needs its own.
let private unpredictableWhen bld cond lblHolds lblCarriesOn =
  append bld {
    AST.cjmp cond (AST.jmpDest lblHolds) (AST.jmpDest lblCarriesOn)
    AST.lmark lblHolds
    append bld { AST.sideEffect UndefinedInstruction } // FIXME: UNPREDICTABLE
    AST.lmark lblCarriesOn
  }

let writeModeBits bld value isExcptReturn =
  let lblL8 = label bld "L8"
  let lblL9 = label bld "L9"
  let lblL10 = label bld "L10"
  let lblL11 = label bld "L11"
  let lblL12 = label bld "L12"
  let lblL13 = label bld "L13"
  let lblL14 = label bld "L14"
  let lblL15 = label bld "L15"
  let lblL16 = label bld "L16"
  let lblL17 = label bld "L17"
  let valueM = value .& maskPSRForMbits
  let cpsrM = getPSR bld R.CPSR PSR.M
  let num11010 = numI32 0b11010 32<rt>
  let chkSecure = AST.not (isSecure bld)
  let cond1 = chkSecure .& (valueM == (numI32 0b10110 32<rt>))
  let cond2 = chkSecure .& isSetNSACRForRFR bld .&
              (valueM == (numI32 0b10001 32<rt>))
  let cond3 = chkSecure .& (valueM == num11010)
  let cond4 = chkSecure .& (cpsrM != num11010) .& (valueM == num11010)
  let cond5 = (cpsrM == num11010) .& (valueM != num11010)
  unpredictableWhen bld cond1 lblL8 lblL9
  unpredictableWhen bld cond2 lblL10 lblL11
  unpredictableWhen bld cond3 lblL12 lblL13
  unpredictableWhen bld cond4 lblL14 lblL15
  append bld {
    AST.cjmp cond5 (AST.jmpDest lblL16) (AST.jmpDest lblL17)
    AST.lmark lblL16
  }
  if Operators.not isExcptReturn then
    append bld { AST.sideEffect UndefinedInstruction } // FIXME: UNPREDICTABLE
  else
    ()
  append bld {
    AST.lmark lblL17
  }
  let mValue = value .& maskPSRForMbits
  append bld {
    regVar bld R.CPSR := disablePSRBits bld R.CPSR PSR.M .| mValue
  }
