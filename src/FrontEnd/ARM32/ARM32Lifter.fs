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

module internal B2R2.FrontEnd.ARM32.Lifter

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32.IRHelper

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
  | Scalar (reg, _) -> regVar bld reg

let simdToExpr bld = function
  | SFReg s -> sfRegToExpr bld s
  | _ -> raise InvalidOperandException

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

let transOprToExpr128 bld = function
  | OprSIMD (SFReg (Vector reg)) -> pseudoRegVar128 bld reg
  | _ -> raise InvalidOperandException

let transOprToSclar bld = function
  | OprSIMD (SFReg (Scalar (reg, Some idx))) -> regVar bld reg, int32 idx
  | _ -> raise InvalidOperandException

let transOprToExpr (ins: InsInfo) bld = function
  | OprSpecReg (reg, _)
  | OprReg reg -> regVar bld reg
  | OprRegList regs -> regsToExpr regs
  | OprSIMD simd -> simdToExpr bld simd
  | OprImm imm ->
    let oprSize = if ins.OprSize = 128<rt> then 64<rt> else ins.OprSize
    numI64 imm oprSize
  | _ -> raise InvalidOperandException

let transOneOpr (ins: InsInfo) bld =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr ins bld opr
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands (opr1, opr2) ->
    struct (transOprToExpr ins bld opr1, transOprToExpr ins bld opr2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) bld =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, opr3) ->
    struct (transOprToExpr ins bld opr1,
            transOprToExpr ins bld opr2,
            transOprToExpr ins bld opr3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: InsInfo) bld =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins bld o1,
            transOprToExpr ins bld o2,
            transOprToExpr ins bld o3,
            transOprToExpr ins bld o4)
  | _ -> raise InvalidOperandException

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
let maskSCTLRForNMFIbit = AST.num <| BitVector.OfBInt 134217728I 32<rt>

let getSCTLR bld sctlrType =
  let sctlr = regVar bld R.SCTLR
  match sctlrType with
  | SCTLR_NMFI -> sctlr .& maskSCTLRForNMFIbit

let isSetSCTLRForNMFI bld =
  getSCTLR bld SCTLR_NMFI == maskSCTLRForNMFIbit

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

let getCarryFlag bld =
  getPSR bld R.CPSR PSR.C >> (numI32 29 32<rt>)

let getZeroMask maskSize regType =
  BitVector.OfBInt (BigInteger.getMask maskSize) regType
  |> BitVector.BNot |> AST.num

let zMaskAnd e regType maskSize =
  e .& (getZeroMask maskSize regType)

let maskAndOR e1 e2 regType maskSize =
  let mask = getZeroMask maskSize regType
  let expr = e1 .& mask
  expr .| e2

let getOverflowFlagOnAdd e1 e2 r bld =
  let struct (e1High, rHigh) = tmpVars2 bld 1<rt>
  bld <+ (e1High := AST.xthi 1<rt> e1)
  let e2High = AST.xthi 1<rt> e2
  bld <+ (rHigh := AST.xthi 1<rt> r)
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
    | 0b110 ->
      isSetCPSRn bld == isSetCPSRv bld .& AST.not (isSetCPSRz bld)
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
  assertByCond (amount > 0u) InvalidShiftAmountException
  let amount = numU32 amount regType
  value << amount, value << (amount .- AST.num1 regType ) |> AST.xthi 1<rt>

/// Logical shift left of a bitstring, on page A2-41. function : LSL()
let shiftLSL value regType amount =
  assertByCond (amount >= 0u) InvalidShiftAmountException
  if amount = 0u then value else shiftLSLC value regType amount |> fst

/// Logical shift right of a bitstring, with carry output, on page A2-41.
/// function : LSR_C()
let shiftLSRC value regType amount =
  assertByCond (amount > 0u) InvalidShiftAmountException
  let amount' = numU32 amount regType
  value >> amount', AST.extract value 1<rt> (amount - 1u |> Convert.ToInt32)

/// Logical shift right of a bitstring, on page A2-41. function : LSR()
let shiftLSR value regType amount =
  assertByCond (amount >= 0u) InvalidShiftAmountException
  if amount = 0u then value else shiftLSRC value regType amount |> fst

/// Arithmetic shift right of a bitstring, with carry output, on page A2-41.
/// function : ASR_C()
let shiftASRC value regType amount =
  assertByCond (amount > 0u) InvalidShiftAmountException
  let amount = numU32 amount regType
  value ?>> amount, value ?>> (amount .- AST.num1 regType ) |> AST.xtlo 1<rt>

/// Logical shift right of a bitstring, on page A2-41. function : ASR()
let shiftASR value regType amount =
  assertByCond (amount >= 0u) InvalidShiftAmountException
  if amount = 0u then value else shiftASRC value regType amount |> fst

/// Rotate right of a bitstring, with carry output, on page A2-41.
/// function : ROR_C()
let shiftRORC value regType amount =
  assertByCond (amount <> 0u) InvalidShiftAmountException
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
let addWithCarry src1 src2 carryIn bld =
  let result = tmpVar bld 32<rt>
  bld <+ (result := src1 .+ src2 .+ carryIn)
  let carryOut =
    AST.ite (carryIn == (numU32 1u 32<rt>))
      (AST.ge src1 (AST.not src2)) (AST.gt src1 (AST.not src2))
  let struct (overflow, rHigh) = getOverflowFlagOnAdd src1 src2 result bld
  struct (result, carryOut, overflow, rHigh)

let addWithCarryOnlyResult src1 src2 carryIn = src1 .+ src2 .+ carryIn

/// Sets the ARM instruction set, on page A2-51.
let selectARMInstrSet bld =
  let cpsr = regVar bld R.CPSR
  bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.J)
  bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.T)

/// Sets the ARM instruction set, on page A2-51.
let selectThumbInstrSet bld =
  let cpsr = regVar bld R.CPSR
  bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.J)
  bld <+ (cpsr := enablePSRBits bld R.CPSR PSR.T)

/// Sets the instruction set currently in use, on page A2-51.
/// SelectInstrSet()
let selectInstrSet bld = function
  | ArchOperationMode.ARMMode -> selectARMInstrSet bld
  | _ -> selectThumbInstrSet bld

/// Write value to R.PC, without interworking, on page A2-47.
/// function : BranchWritePC()
let branchWritePC bld (ins: InsInfo) addr jmpInfo =
  let addr = zMaskAnd addr 32<rt> 1
  match ins.Mode with
  | ArchOperationMode.ARMMode -> AST.interjmp addr jmpInfo
  | _ -> AST.interjmp addr jmpInfo

let disableITStateForCondBranches bld isUnconditional =
  if isUnconditional then ()
  else
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.IT10)
    bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.IT72)

/// Write value to R.PC, with interworking, on page A2-47.
/// function : BXWritePC()
let bxWritePC bld isUnconditional addr =
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let cond1 = AST.xtlo 1<rt> addr == AST.b1
  disableITStateForCondBranches bld isUnconditional
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  selectThumbInstrSet bld
  bld <+ (AST.interjmp (zMaskAnd addr 32<rt> 1) InterJmpKind.SwitchToThumb)
  bld <+ (AST.lmark lblL1)
  selectARMInstrSet bld
  bld <+ (AST.interjmp addr InterJmpKind.SwitchToARM)

/// Write value to R.PC, with interworking for ARM only from ARMv7 on page
/// A2-47. function : ALUWritePC()
let aluWritePC bld (ins: InsInfo) isUnconditional addr =
  match ins.Mode with
  | ArchOperationMode.ARMMode -> bxWritePC bld isUnconditional addr
  | _ -> bld <+ (branchWritePC bld ins addr InterJmpKind.Base)

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
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL8) (AST.jmpDest lblL9))
  bld <+ (AST.lmark lblL8)
  bld <+ (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  bld <+ (AST.lmark lblL9)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL10) (AST.jmpDest lblL11))
  bld <+ (AST.lmark lblL10)
  bld <+ (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  bld <+ (AST.lmark lblL11)
  bld <+ (AST.cjmp cond3 (AST.jmpDest lblL12) (AST.jmpDest lblL13))
  bld <+ (AST.lmark lblL12)
  bld <+ (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  bld <+ (AST.lmark lblL13)
  bld <+ (AST.cjmp cond4 (AST.jmpDest lblL14) (AST.jmpDest lblL15))
  bld <+ (AST.lmark lblL14)
  bld <+ (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  bld <+ (AST.lmark lblL15)
  bld <+ (AST.cjmp cond5 (AST.jmpDest lblL16) (AST.jmpDest lblL17))
  bld <+ (AST.lmark lblL16)
  if Operators.not isExcptReturn then
    bld <+ (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
  else ()
  bld <+ (AST.lmark lblL17)
  let mValue = value .& maskPSRForMbits
  bld <+
    (regVar bld R.CPSR := disablePSRBits bld R.CPSR PSR.M .| mValue)

let transShiftOprs ins bld opr1 opr2 =
  match opr1, opr2 with
  | OprReg _, OprShift (typ, Imm imm) ->
    let e = transOprToExpr ins bld opr1
    shift e 32<rt> typ imm (getCarryFlag bld)
  | OprReg _, OprRegShift (typ, reg) ->
    let e = transOprToExpr ins bld opr1
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    shiftForRegAmount e 32<rt> typ amount (getCarryFlag bld)
  | _ -> raise InvalidOperandException

let parseOprOfMVNS (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins bld
  | ThreeOperands (opr1, opr2, opr3) ->
    struct (transOprToExpr ins bld opr1, transShiftOprs ins bld opr2 opr3)
  | _ -> raise InvalidOperandException

let transTwoOprsOfADC (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let transThreeOprsOfADC (ins: InsInfo) bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> transThreeOprs ins bld
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2, e3) = transThreeOprs ins bld
    e1, e2, shift e3 32<rt> SRTypeLSL 0u carryIn
  | _ -> raise InvalidOperandException

let transFourOprsOfADC (ins: InsInfo) bld =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1, e2 = transOprToExpr ins bld opr1, transOprToExpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    let e3 = transOprToExpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2,
            shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let parseOprOfADC (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADC ins bld
  | ThreeOperands _ -> transThreeOprsOfADC ins bld
  | FourOperands _ -> transFourOprsOfADC ins bld
  | _ -> raise InvalidOperandException

let checkCondition (ins: InsInfo) bld isUnconditional =
  if isUnconditional then None
  else
    let lblIgnore = label bld "IgnoreExec"
    let lblPass = label bld "NeedToExec"
    let cond = conditionPassed bld ins.Condition
    bld <+ (AST.cjmp cond (AST.jmpDest lblPass) (AST.jmpDest lblIgnore))
    bld <+ (AST.lmark lblPass)
    Some lblIgnore

/// Update ITState after normal execution of an IT-block instruction. See A2-52
/// function: ITAdvance().
let itAdvance bld =
  let cond = tmpVar bld 1<rt>
  let struct (itstate, nextstate) = tmpVars2 bld 32<rt>
  let lblThen = label bld "LThen"
  let lblElse = label bld "LElse"
  let lblEnd = label bld "LEnd"
  let cpsr = regVar bld R.CPSR
  let cpsrIT10 =
    getPSR bld R.CPSR PSR.IT10 >> (numI32 25 32<rt>)
  let cpsrIT72 =
    getPSR bld R.CPSR PSR.IT72 >> (numI32 8 32<rt>)
  let mask10 = numI32 0x3 32<rt> (* For ITSTATE[1:0] *)
  let mask20 = numI32 0x7 32<rt> (* For ITSTATE[2:0] *)
  let mask40 = numI32 0x1f 32<rt> (* For ITSTATE[4:0] *)
  let mask42 = numI32 0x1c 32<rt> (* For ITSTATE[4:2] *)
  let cpsrIT42 = cpsr .& (numI32 0xffffe3ff 32<rt>)
  let num8 = numI32 8 32<rt>
  bld <+ (itstate := cpsrIT72 .| cpsrIT10)
  bld <+ (cond := ((itstate .& mask20) == AST.num0 32<rt>))
  bld <+ (AST.cjmp cond (AST.jmpDest lblThen) (AST.jmpDest lblElse))
  bld <+ (AST.lmark lblThen)
  bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.IT10)
  bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.IT72)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblElse)
  bld <+ (nextstate := (itstate .& mask40 << AST.num1 32<rt>))
  bld <+ (cpsr := nextstate .& mask10 |> setPSR bld R.CPSR PSR.IT10)
  bld <+ (cpsr := cpsrIT42 .| ((nextstate .& mask42) << num8))
  bld <+ (AST.lmark lblEnd)

let putEndLabel bld lblIgnore =
  match lblIgnore with
  | Some lblIgnore ->
    bld <+ (AST.lmark lblIgnore)
    itAdvance bld
  | None -> ()

let putEndLabelForBranch bld lblIgnore (brIns: InsInfo) =
  match lblIgnore with
  | Some lblIgnore ->
    bld <+ (AST.lmark lblIgnore)
    itAdvance bld
    let target = numU64 (brIns.Address + uint64 brIns.Length) 32<rt>
    bld <+ (AST.interjmp target InterJmpKind.Base)
  | None -> ()

let sideEffects (ins: InsInfo) insLen bld name =
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect name)
  bld --!> insLen

let nop (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let convertPCOpr (ins: InsInfo) bld opr =
  if opr = getPC bld then
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
    opr .+ (numI32 rel 32<rt>)
  else opr

let adc isSetFlags ins insLen bld =
  let struct (dst, src1, src2) = parseOprOfADC ins bld
  let src1 = convertPCOpr ins bld src1
  let src2 = convertPCOpr ins bld src2
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSetFlags then
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 t2 (getCarryFlag bld) bld
    bld <+ (dst := result)
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  else
    let result = tmpVar bld 32<rt>
    bld <+ (result := addWithCarryOnlyResult src1 src2 (getCarryFlag bld))
    if dst = getPC bld then aluWritePC bld ins isUnconditional result
    else bld <+ (dst := result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let transTwoOprsOfADD (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, e2)
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let transThreeOprsOfADD (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> transThreeOprs ins bld
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2, e3) = transThreeOprs ins bld
    struct (e1, e2, shift e3 32<rt> SRTypeLSL 0u carryIn)
  | _ -> raise InvalidOperandException

let transFourOprsOfADD (ins: InsInfo) insLen bld =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    let e3 = transOprToExpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let parseOprOfADD (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADD ins insLen bld
  | ThreeOperands _ -> transThreeOprsOfADD ins insLen bld
  | FourOperands _ -> transFourOprsOfADD ins insLen bld
  | _ -> raise InvalidOperandException

let add isSetFlags ins insLen bld =
  let struct (dst, src1, src2) = parseOprOfADD ins insLen bld
  let src1 = convertPCOpr ins bld src1
  let src2 = convertPCOpr ins bld src2
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSetFlags then
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 t2 (AST.num0 32<rt>) bld
    bld <+ (dst := result)
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  else
    let result = tmpVar bld 32<rt>
    bld <+ (result := addWithCarryOnlyResult src1 src2 (AST.num0 32<rt>))
    if dst = getPC bld then aluWritePC bld ins isUnconditional result
    else bld <+ (dst := result)
    putEndLabel bld lblIgnore
  bld --!> insLen

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

let bl ins insLen bld =
  let struct (alignedAddr, targetMode, callKind) = parseOprOfBL ins
  let lr = regVar bld R.LR
  let retAddr = bvOfBaseAddr ins.Address .+ (numI32 4 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if ins.Mode = ArchOperationMode.ARMMode then bld <+ (lr := retAddr)
  else bld <+ (lr := maskAndOR retAddr (AST.num1 32<rt>) 32<rt> 1)
  selectInstrSet bld targetMode
  bld <+ (branchWritePC bld ins alignedAddr callKind)
  putEndLabelForBranch bld lblIgnore ins
  bld --!> insLen

let blxWithReg (ins: InsInfo) insLen reg bld =
  let lr = regVar bld R.LR
  let addr = bvOfBaseAddr ins.Address
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if ins.Mode = ArchOperationMode.ARMMode then
    bld <+ (lr := addr .+ (numI32 4 32<rt>))
  else
    let addr = addr .+ (numI32 2 32<rt>)
    bld <+ (lr := maskAndOR addr (AST.num1 32<rt>) 32<rt> 1)
  bxWritePC bld isUnconditional (regVar bld reg)
  putEndLabelForBranch bld lblIgnore ins
  bld --!> insLen

let branchWithLink (ins: InsInfo) insLen bld =
  match ins.Operands with
  | OneOperand (OprReg reg) -> blxWithReg ins insLen reg bld
  | _ -> bl ins insLen bld

let parseOprOfPUSHPOP (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprReg r) -> regsToUInt32 [ r ]
  | OneOperand (OprRegList regs) -> regsToUInt32 regs
  | _ -> raise InvalidOperandException

let pushLoop bld numOfReg addr =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let t = tmpVar bld 32<rt>
      bld <+ (t := addr)
      if count = 13 && count <> lowestSetBit numOfReg 32 then
        bld <+ (AST.loadLE 32<rt> t := (AST.undef 32<rt> "UNKNOWN"))
      else
        let reg = count |> uint32 |> OperandHelper.getRegister
        bld <+ (AST.loadLE 32<rt> t := regVar bld reg)
      t .+ (numI32 4 32<rt>)
    else addr
  List.fold loop addr [ 0 .. 14 ]

let push ins insLen bld =
  let t0 = tmpVar bld 32<rt>
  let sp = regVar bld R.SP
  let numOfReg = parseOprOfPUSHPOP ins
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = sp .- (numI32 stackWidth 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t0 := addr)
  let addr = pushLoop bld numOfReg t0
  if (numOfReg >>> 15 &&& 1u) = 1u then
    bld <+ (AST.loadLE 32<rt> addr := pcStoreValue bld)
  else ()
  bld <+ (sp := t0)
  putEndLabel bld lblIgnore
  bld --!> insLen

/// shared/functions/vector/SignedSatQ, on page Armv8 Pseudocode-7927
let sSatQ bld i n =
  let n1 = AST.num1 n
  let cond = n1 << (numI32 (RegType.toBitWidth n) n .- n1)
  let struct (t1, t2) = tmpVars2 bld n
  bld <+ (t1 := i)
  bld <+ (t2 := cond)
  let cond1 = t1 .> (t2 .- n1)
  let cond2 = t1 .< AST.not t2
  let r = (AST.ite cond1 (t2 .- n1) (AST.ite cond2 (AST.not t2) t1))
  let r = AST.xtlo n r
  let sat = AST.ite cond1 AST.b1 (AST.ite cond2 AST.b1 (AST.num0 1<rt>))
  struct (r, sat)

let sSat bld i n =
  let struct (r, _) = sSatQ bld i n
  r

let qdadd (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (sat1,sat2) = tmpVars2 bld 1<rt>
  let struct (dou, sat) =
    sSatQ bld (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
  bld <+ (sat1 := sat)
  let struct (r, sat) =
    sSatQ bld (src1 .+ dou) (RegType.fromBitWidth 32)
  bld <+ (dst := r)
  bld <+ (sat2 := sat)
  let cpsr = regVar bld R.CPSR
  bld <+ (cpsr := AST.ite (sat1 .| sat2) (enablePSRBits bld R.CPSR PSR.Q) cpsr)
  putEndLabel bld lblIgnore
  bld --!> insLen

let qdsub (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (sat1,sat2) = tmpVars2 bld 1<rt>
  let struct (dou, sat) =
    sSatQ bld (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
  bld <+ (sat1 := sat)
  let struct (r, sat) = sSatQ bld (src1 .- dou) (RegType.fromBitWidth 32)
  bld <+ (dst := r)
  bld <+ (sat2 := sat)
  let cpsr = regVar bld R.CPSR
  bld <+ (cpsr := AST.ite (sat1 .| sat2) (enablePSRBits bld R.CPSR PSR.Q) cpsr)
  putEndLabel bld lblIgnore
  bld --!> insLen

let qsax (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (sum, diff) = tmpVars2 bld 16<rt>
  let xtlo src = AST.xtlo 16<rt> src
  let xthi src = AST.xthi 16<rt> src
  bld <+ (sum := xtlo src1 .+ xthi src2)
  bld <+ (diff := xthi src1 .- xtlo src2)
  bld <+ (sum := sSat bld sum (RegType.fromBitWidth 16))
  bld <+ (diff := sSat bld diff (RegType.fromBitWidth 16))
  bld <+ (dst := AST.concat diff sum)
  putEndLabel bld lblIgnore
  bld --!> insLen

let qsub16 (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (diff1, diff2) = tmpVars2 bld 16<rt>
  let xtlo src = AST.xtlo 16<rt> src
  let xthi src = AST.xthi 16<rt> src
  bld <+ (diff1 := xtlo src1 .- xtlo src2)
  bld <+ (diff2 := xthi src1 .- xthi src2)
  bld <+ (diff1 := sSat bld diff1 (RegType.fromBitWidth 16))
  bld <+ (diff2 := sSat bld diff2 (RegType.fromBitWidth 16))
  bld <+ (dst := AST.concat diff2 diff1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let sub isSetFlags ins insLen bld =
  let struct (dst, src1, src2) = parseOprOfADD ins insLen bld
  let src1 = convertPCOpr ins bld src1
  let src2 = convertPCOpr ins bld src2
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSetFlags then
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 (AST.not t2) (AST.num1 32<rt>) bld
    bld <+ (dst := result)
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  else
    let result = tmpVar bld 32<rt>
    bld <+ (result :=
      addWithCarryOnlyResult src1 (AST.not src2) (AST.num1 32<rt>))
    if dst = getPC bld then aluWritePC bld ins isUnconditional result
    else bld <+ (dst := result)
  putEndLabel bld lblIgnore
  bld --!> insLen

/// B9.3.19 SUBS R.PC, R.LR (Thumb), on page B9-2008
let subsPCLRThumb ins insLen bld =
  let struct (_, _, src2) = parseOprOfADD ins insLen bld
  let pc = getPC bld
  let struct (result, _, _, _) =
    addWithCarry pc (AST.not src2) (AST.num1 32<rt>) bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (branchWritePC bld ins result InterJmpKind.IsRet)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseResultOfSUBAndRela (ins: InsInfo) bld =
  match ins.Opcode with
  | Op.ANDS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    src1.& src2
  | Op.EORS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    src1 <+> src2
  | Op.SUBS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    addWithCarryOnlyResult src1 (AST.not src2) (AST.num1 32<rt>)
  | Op.RSBS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    addWithCarryOnlyResult (AST.not src1) src2 (AST.num1 32<rt>)
  | Op.ADDS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    addWithCarryOnlyResult src1 src2 (AST.num0 32<rt>)
  | Op.ADCS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    addWithCarryOnlyResult src1 src2 (getCarryFlag bld)
  | Op.SBCS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    addWithCarryOnlyResult src1 (AST.not src2) (getCarryFlag bld)
  | Op.RSCS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    addWithCarryOnlyResult (AST.not src1) src2 (getCarryFlag bld)
  | Op.ORRS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    src1 .| src2
  | Op.MOVS ->
    let struct (_, src) = transTwoOprs ins bld
    src
  | Op.ASRS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> SRTypeASR src2 (getCarryFlag bld)
  | Op.LSLS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> SRTypeLSL src2 (getCarryFlag bld)
  | Op.LSRS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> SRTypeLSR src2 (getCarryFlag bld)
  | Op.RORS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> SRTypeROR src2 (getCarryFlag bld)
  | Op.RRXS ->
    let struct (_, src) = transTwoOprs ins bld
    shiftForRegAmount src 32<rt> SRTypeRRX (AST.num1 32<rt>) (getCarryFlag bld)
  | Op.BICS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    src1 .& (AST.not src2)
  | Op.MVNS ->
    let struct (_, src) = parseOprOfMVNS ins bld
    AST.not src
  | _ -> raise InvalidOperandException

/// B9.3.20 SUBS R.PC, R.LR and related instruction (ARM), on page B9-2010
let subsAndRelatedInstr (ins: InsInfo) insLen bld =
  let result = tmpVar bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (result := parseResultOfSUBAndRela ins bld)
  bld <+ (branchWritePC bld ins result InterJmpKind.IsRet)
  putEndLabel bld lblIgnore
  bld --!> insLen

let computeCarryOutFromImmCflag (ins: InsInfo) insLen bld =
  match ins.Cflag with
  | Some v ->
    if v then BitVector.One 1<rt> |> AST.num
    else BitVector.Zero 1<rt> |> AST.num
  | None -> getCarryFlag bld

let translateLogicOp (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let t = tmpVar bld 32<rt>
    let struct (e1, e2) = transTwoOprs ins bld
    bld <+ (t := e2)
    let shifted, carryOut = shiftC t 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    e1, e1, shifted, carryOut
  | ThreeOperands (_, _, OprImm _) ->
    let struct (e1, e2, e3) = transThreeOprs ins bld
    let carryOut = computeCarryOutFromImmCflag ins insLen bld
    e1, e2, e3, carryOut
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let t = tmpVar bld 32<rt>
    let struct (e1, e2, e3) = transThreeOprs ins bld
    bld <+ (t := e3)
    let shifted, carryOut = shiftC t 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    e1, e2, shifted, carryOut
  | FourOperands (opr1, opr2, opr3, OprShift (typ, Imm imm)) ->
    let t = tmpVar bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src1 = transOprToExpr ins bld opr2
    let rm = transOprToExpr ins bld opr3
    bld <+ (t := rm)
    let shifted, carryOut = shiftC t 32<rt> typ imm carryIn
    dst, src1, shifted, carryOut
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let t = tmpVar bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src1 = transOprToExpr ins bld opr2
    let rm = transOprToExpr ins bld opr3
    bld <+ (t := rm)
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount t 32<rt> typ amount carryIn
    dst, src1, shifted, carryOut
  | _ -> raise InvalidOperandException

let logicalAnd isSetFlags (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let dst, src1, src2, carryOut = translateLogicOp ins insLen bld
  let result = tmpVar bld 32<rt>
  bld <+ (result := src1 .& src2)
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprsOfMOV (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprs ins bld
  | ThreeOperands (opr1, opr2, opr3) ->
    struct (transOprToExpr ins bld opr1, transShiftOprs ins bld opr2 opr3)
  | _ -> raise InvalidOperandException

let mov isSetFlags ins insLen bld =
  let struct (dst, src) = parseOprsOfMOV ins bld
  let result = tmpVar bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  let pc = getPC bld
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if src = pc then bld <+ (result := src .+ (numU64 (pcOffset ins) 32<rt>))
  else bld <+ (result := src)
  if dst = pc then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let eor isSetFlags (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let dst, src1, src2, carryOut = translateLogicOp ins insLen bld
  let result = tmpVar bld 32<rt>
  bld <+ (result := src1 <+> src2)
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let transFourOprsOfRSB (ins: InsInfo) insLen bld =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    let e3 = transOprToExpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let parseOprOfRSB (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsOfRSB ins insLen bld
  | _ -> raise InvalidOperandException

let rsb isSetFlags ins insLen bld =
  let struct (dst, src1, src2) = parseOprOfRSB ins insLen bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSetFlags then
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry (AST.not t1) t2 (AST.num1 32<rt>) bld
    bld <+ (dst := result)
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  else
    let result = tmpVar bld 32<rt>
    bld <+ (result :=
      addWithCarryOnlyResult (AST.not src1) src2 (AST.num1 32<rt>))
    if dst = getPC bld then aluWritePC bld ins isUnconditional result
    else bld <+ (dst := result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let transTwoOprsOfSBC (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let transFourOprsOfSBC (ins: InsInfo) insLen bld =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    let e3 = transOprToExpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let parseOprOfSBC (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfSBC ins insLen bld
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsOfSBC ins insLen bld
  | _ -> raise InvalidOperandException

let sbc isSetFlags ins insLen bld =
  let struct (dst, src1, src2) = parseOprOfSBC ins insLen bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSetFlags then
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 (AST.not t2) (getCarryFlag bld) bld
    bld <+ (dst := result)
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  else
    let result = tmpVar bld 32<rt>
    bld <+ (result :=
      addWithCarryOnlyResult src1 (AST.not src2) (getCarryFlag bld))
    if dst = getPC bld then aluWritePC bld ins isUnconditional result
    else bld <+ (dst := result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let transFourOprsOfRSC (ins: InsInfo) insLen bld =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    e1, e2, transShiftOprs ins bld opr3 opr4
  | FourOperands (opr1, opr2, opr3, OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    let e3 = transOprToExpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld)
  | _ -> raise InvalidOperandException

let parseOprOfRSC (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsOfRSB ins insLen bld
  | _ -> raise InvalidOperandException

let rsc isSetFlags ins insLen bld =
  let struct (dst, src1, src2) = parseOprOfRSC ins insLen bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSetFlags then
    bld <+ (t1 := src1)
    bld <+ (t2 := src2)
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry (AST.not t1) t2 (getCarryFlag bld) bld
    bld <+ (dst := result)
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
    bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  else
    let result = tmpVar bld 32<rt>
    bld <+ (result :=
      addWithCarryOnlyResult (AST.not src1) src2 (getCarryFlag bld))
    if dst = getPC bld then aluWritePC bld ins isUnconditional result
    else bld <+ (dst := result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let orr isSetFlags (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let dst, src1, src2, carryOut = translateLogicOp ins insLen bld
  let result = tmpVar bld 32<rt>
  bld <+ (result := src1 .| src2)
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let orn isSetFlags (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let dst, src1, src2, carryOut = translateLogicOp ins insLen bld
  let result = tmpVar bld 32<rt>
  bld <+ (result := src1 .| AST.not src2)
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let bic isSetFlags (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let dst, src1, src2, carryOut = translateLogicOp ins insLen bld
  let result = tmpVar bld 32<rt>
  bld <+ (result := src1 .& (AST.not src2))
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let transTwoOprsOfMVN (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e2, getCarryFlag bld)
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted, carryOut = shiftC e2 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    struct (e1, shifted, carryOut)
  | _ -> raise InvalidOperandException

let transThreeOprsOfMVN (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src = transOprToExpr ins bld opr2
    let shifted, carryOut = shiftC src 32<rt> typ imm carryIn
    struct (dst, shifted, carryOut)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src = transOprToExpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount src 32<rt> typ amount carryIn
    struct (dst, shifted, carryOut)
  | _ -> raise InvalidOperandException

let parseOprOfMVN (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfMVN ins insLen bld
  | ThreeOperands _ -> transThreeOprsOfMVN ins insLen bld
  | _ -> raise InvalidOperandException

let mvn isSetFlags ins insLen bld =
  let struct (dst, src, carryOut) = parseOprOfMVN ins insLen bld
  let result = tmpVar bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (result := AST.not src)
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let svc (ins: InsInfo) insLen bld =
  match ins.Operands with
  | OneOperand (OprImm n) -> sideEffects ins insLen bld (Interrupt (int n))
  | _ -> raise InvalidOperandException

let getImmShiftFromShiftType imm = function
  | SRTypeLSL | SRTypeROR -> imm
  | SRTypeLSR -> if imm = 0ul then 32ul else imm
  | SRTypeASR -> if imm = 0ul then 32ul else imm
  | SRTypeRRX -> 1ul

let transTwoOprsOfShiftInstr (ins: InsInfo) shiftTyp bld tmp =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) when shiftTyp = SRTypeRRX ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2) = transTwoOprs ins bld
    let result, carryOut = shiftC tmp 32<rt> shiftTyp 1ul carryIn
    e1, e2, result, carryOut
  | TwoOperands (OprReg _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2) = transTwoOprs ins bld
    let shiftN = AST.xtlo 8<rt> e2 |> AST.zext 32<rt>
    let result, carryOut = shiftCForRegAmount tmp 32<rt> shiftTyp shiftN carryIn
    e1, e1, result, carryOut
  | _ -> raise InvalidOperandException

let transThreeOprsOfShiftInstr (ins: InsInfo) shiftTyp bld tmp =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprImm imm) ->
    let e1 = transOprToExpr ins bld opr1
    let e2 = transOprToExpr ins bld opr2
    let shiftN = getImmShiftFromShiftType (uint32 imm) shiftTyp
    let shifted, carryOut =
      shiftC tmp 32<rt> shiftTyp shiftN (getCarryFlag bld)
    e1, e2, shifted, carryOut
  | ThreeOperands (_, _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2, e3) = transThreeOprs ins bld
    let amount = AST.xtlo 8<rt> e3 |> AST.zext 32<rt>
    let shifted, carryOut =
      shiftCForRegAmount tmp 32<rt> shiftTyp amount carryIn
    e1, e2, shifted, carryOut
  | _ -> raise InvalidOperandException

let parseOprOfShiftInstr (ins: InsInfo) shiftTyp bld tmp =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfShiftInstr ins shiftTyp bld tmp
  | ThreeOperands _ -> transThreeOprsOfShiftInstr ins shiftTyp bld tmp
  | _ -> raise InvalidOperandException

let shiftInstr isSetFlags ins insLen typ bld =
  let struct (srcTmp, result) = tmpVars2 bld 32<rt>
  let dst, src, res, carryOut = parseOprOfShiftInstr ins typ bld srcTmp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (srcTmp := src)
  bld <+ (result := res)
  if dst = getPC bld then aluWritePC bld ins isUnconditional result
  else
    bld <+ (dst := result)
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
      bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
      bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
    else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let subs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
    when ins.Mode = ArchOperationMode.ThumbMode ->
    subsPCLRThumb ins insLen bld
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> sub isSetFlags ins insLen bld

let adds isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> add isSetFlags ins insLen bld

let adcs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> adc isSetFlags ins insLen bld

let ands isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> logicalAnd isSetFlags ins insLen bld

let movs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> mov isSetFlags ins insLen bld

let eors isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> eor isSetFlags ins insLen bld

let rsbs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> rsb isSetFlags ins insLen bld

let sbcs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> sbc isSetFlags ins insLen bld

let rscs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> rsc isSetFlags ins insLen bld

let orrs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> orr isSetFlags ins insLen bld

let orns isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> orn isSetFlags ins insLen bld

let bics isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> bic isSetFlags ins insLen bld

let mvns isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _)
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> mvn isSetFlags ins insLen bld

let asrs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> shiftInstr isSetFlags ins insLen SRTypeASR bld

let lsls isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> shiftInstr isSetFlags ins insLen SRTypeLSL bld

let lsrs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> shiftInstr isSetFlags ins insLen SRTypeLSR bld

let rors isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> shiftInstr isSetFlags ins insLen SRTypeROR bld

let rrxs isSetFlags (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _) -> subsAndRelatedInstr ins insLen bld
  | _ -> shiftInstr isSetFlags ins insLen SRTypeRRX bld

let clz ins insLen bld =
  let struct (dst, src) = transTwoOprs ins bld
  let lblBoundCheck = label bld "LBoundCheck"
  let lblZeroCheck = label bld "LZeroCheck"
  let lblCount = label bld "LCount"
  let lblEnd = label bld "LEnd"
  let numSize = (numI32 32 32<rt>)
  let t1 = tmpVar bld 32<rt>
  let cond1 = t1 == (AST.num0 32<rt>)
  let cond2 =
    src .& ((AST.num1 32<rt>) << (t1 .- AST.num1 32<rt>)) != (AST.num0 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t1 := numSize)
  bld <+ (AST.lmark lblBoundCheck)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblEnd) (AST.jmpDest lblZeroCheck))
  bld <+ (AST.lmark lblZeroCheck)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblEnd) (AST.jmpDest lblCount))
  bld <+ (AST.lmark lblCount)
  bld <+ (t1 := t1 .- (AST.num1 32<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblBoundCheck))
  bld <+ (AST.lmark lblEnd)
  bld <+ (dst := numSize .- t1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let transTwoOprsOfCMN (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins bld
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted = shift e2 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    struct (e1, shifted)
  | _ -> raise InvalidOperandException

let transThreeOprsOfCMN (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src = transOprToExpr ins bld opr2
    let shifted = shift src 32<rt> typ imm carryIn
    struct (dst, shifted)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src = transOprToExpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted = shiftForRegAmount src 32<rt> typ amount carryIn
    struct (dst, shifted)
  | _ -> raise InvalidOperandException

let parseOprOfCMN (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMN ins insLen bld
  | ThreeOperands _ -> transThreeOprsOfCMN ins insLen bld
  | _ -> raise InvalidOperandException

let cmn ins insLen bld =
  let struct (dst, src) = parseOprOfCMN ins insLen bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let cpsr = regVar bld R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  let struct (result, carryOut, overflow, rHigh) =
    addWithCarry t1 t2 (AST.num0 32<rt>) bld
  bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
  bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
  bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
  bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  putEndLabel bld lblIgnore
  bld --!> insLen

let mla isSetFlags ins insLen bld =
  let struct (rd, rn, rm, ra) = transFourOprs ins bld
  let r = tmpVar bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (r := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+
                                     AST.zext 64<rt> ra))
  bld <+ (rd := r)
  if isSetFlags then
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := AST.xthi 1<rt> r |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := r == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let transTwoOprsOfCMP (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins bld
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag bld))
  | _ -> raise InvalidOperandException

let transThreeOprsOfCMP (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src = transOprToExpr ins bld opr2
    struct (dst, shift src 32<rt> typ imm carryIn)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src = transOprToExpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    struct (dst, shiftForRegAmount src 32<rt> typ amount carryIn)
  | _ -> raise InvalidOperandException

let parseOprOfCMP (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMP ins insLen bld
  | ThreeOperands _ -> transThreeOprsOfCMP ins insLen bld
  | _ -> raise InvalidOperandException

let cmp ins insLen bld =
  let struct (rn, rm) = parseOprOfCMP ins insLen bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let cpsr = regVar bld R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t1 := rn)
  bld <+ (t2 := rm)
  let struct (result, carryOut, overflow, rHigh) =
    addWithCarry t1 (AST.not t2) (AST.num1 32<rt>) bld
  bld <+ (cpsr := rHigh |> setPSR bld R.CPSR PSR.N)
  bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
  bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
  bld <+ (cpsr := overflow |> setPSR bld R.CPSR PSR.V)
  putEndLabel bld lblIgnore
  bld --!> insLen

let umaal (ins: InsInfo) insLen bld =
  bld <!-- (ins.Address, insLen)
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  let lblIgnore = checkCondition ins bld isUnconditional
  let res = tmpVar bld 64<rt>
  let mul = AST.zext 64<rt> rn .* AST.zext 64<rt> rm
  bld <+ (res := mul .+ AST.zext 64<rt> rdHi .+ AST.zext 64<rt> rdLo)
  bld <+ (rdHi := AST.xthi 32<rt> res)
  bld <+ (rdLo := AST.xtlo 32<rt> res)
  putEndLabel bld lblIgnore
  bld --!> insLen

let umlal isSetFlags ins insLen bld =
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
  let result = tmpVar bld 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+
    (result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+ AST.concat rdHi rdLo)
  bld <+ (rdHi := AST.xthi 32<rt> result)
  bld <+ (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 64<rt> |> setPSR bld R.CPSR PSR.Z)
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let umull isSetFlags ins insLen bld =
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
  let result = tmpVar bld 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm)
  bld <+ (rdHi := AST.xthi 32<rt> result)
  bld <+ (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 64<rt> |> setPSR bld R.CPSR PSR.Z)
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let transOprsOfTEQ (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (rn, imm) = transTwoOprs ins bld
    rn, imm, getCarryFlag bld
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let rn = transOprToExpr ins bld opr1
    let rm = transOprToExpr ins bld opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    rn, shifted, carryOut
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag bld
    let rn = transOprToExpr ins bld opr1
    let rm = transOprToExpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    rn, shifted, carryOut
  | _ -> raise InvalidOperandException

let teq ins insLen bld =
  let src1, src2, carryOut = transOprsOfTEQ ins insLen bld
  let result = tmpVar bld 32<rt>
  let cpsr = regVar bld R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (result := src1 <+> src2)
  bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
  bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
  bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
  putEndLabel bld lblIgnore
  bld --!> insLen

let mul isSetFlags ins insLen bld =
  let struct (rd, rn, rm) = transThreeOprs ins bld
  let result = tmpVar bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+
    (result := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm))
  bld <+ (rd := result)
  if isSetFlags then
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let transOprsOfTST (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let struct (rn, imm) = transTwoOprs ins bld
    let carryOut = computeCarryOutFromImmCflag ins insLen bld
    struct (rn, imm, carryOut)
  | TwoOperands (OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted, carryOut = shiftC e2 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    struct (e1, shifted, carryOut)
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let rn = transOprToExpr ins bld opr1
    let rm = transOprToExpr ins bld opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    struct (rn, shifted, carryOut)
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag bld
    let rn = transOprToExpr ins bld opr1
    let rm = transOprToExpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    struct (rn, shifted, carryOut)
  | _ -> raise InvalidOperandException

let tst ins insLen bld =
  let struct (src1, src2, carryOut) = transOprsOfTST ins insLen bld
  let result = tmpVar bld 32<rt>
  let cpsr = regVar bld R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (result := src1 .& src2)
  bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
  bld <+ (cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z)
  bld <+ (cpsr := carryOut |> setPSR bld R.CPSR PSR.C)
  putEndLabel bld lblIgnore
  bld --!> insLen

let smulhalf ins insLen bld s1top s2top =
  let struct (rd, rn, rm) = transThreeOprs ins bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if s1top then bld <+ (t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt>)
  else bld <+ (t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt>)
  if s2top then bld <+ (t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt>)
  else bld <+ (t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt>)
  bld <+ (rd := t1 .* t2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let smmla (ins: InsInfo) insLen bld isRound =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2, src3) = transFourOprs ins bld
  let result = tmpVar bld 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  let lblIgnore = checkCondition ins bld isUnconditional
  let ra = (AST.sext 64<rt> src3) << numI32 32 64<rt>
  bld <+ (result := ra .+ AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  if isRound then bld <+ (result := result .+ numU32 0x80000000u 64<rt>)
  bld <+ (dst := AST.xthi 32<rt> result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let smmul (ins: InsInfo) insLen bld isRound =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let result = tmpVar bld 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (result := AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  if isRound then bld <+ (result := result .+ numU32 0x80000000u 64<rt>)
  bld <+ (dst := AST.xthi 32<rt> result)
  putEndLabel bld lblIgnore
  bld --!> insLen

/// SMULL, SMLAL, etc.
let smulandacc isSetFlags doAcc ins insLen bld =
  let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
  let struct (tmpresult, result) = tmpVars2 bld 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (tmpresult := AST.sext 64<rt> rn .* AST.sext 64<rt> rm)
  if doAcc then bld <+ (result := tmpresult .+ AST.concat rdHi rdLo)
  else bld <+ (result := tmpresult)
  bld <+ (rdHi := AST.xthi 32<rt> result)
  bld <+ (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = regVar bld R.CPSR
    bld <+ (cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N)
    bld <+ (cpsr := result == AST.num0 64<rt> |> setPSR bld R.CPSR PSR.Z)
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let smulacclongdual (ins: InsInfo) insLen bld sign =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
  let o = tmpVar bld 32<rt>
  let struct (p1, p2, result) = tmpVars3 bld 64<rt>
  let rotated = shiftROR src2 32<rt> 16u
  let xtlo src = AST.xtlo 16<rt> src |> AST.sext 64<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.sext 64<rt>
  if sign then bld <+ (o := rotated)
  else bld <+ (o := src2)
  bld <+ (p1 := xtlo src1 .* xtlo o)
  bld <+ (p2 := xthi src1 .* xthi o)
  bld <+ (result := p1 .+ p2 .+ AST.concat dst2 dst1)
  bld <+ (dst2 := AST.xthi 32<rt> result)
  bld <+ (dst1 := AST.xtlo 32<rt> result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let smulaccwordbyhalf (ins: InsInfo) insLen bld sign =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2, src3) = transFourOprs ins bld
  let o = tmpVar bld 32<rt>
  let result = tmpVar bld 64<rt>
  let sext src = AST.sext 64<rt> src
  if sign then bld <+ (o := AST.xthi 16<rt> src2 |> AST.sext 32<rt>)
  else bld <+ (o := AST.xtlo 16<rt> src2 |> AST.sext 32<rt>)
  bld <+ (result := sext src1 .* sext o .+ sext (src3 << numI32 16 32<rt>))
  bld <+ (dst := AST.extract result 32<rt> 16)
  let cpsr = regVar bld R.CPSR
  bld <+ (cpsr := AST.ite ((result >> numI32 16 64<rt>) != sext dst)
                           (enablePSRBits bld R.CPSR PSR.Q) cpsr)
  putEndLabel bld lblIgnore
  bld --!> insLen

let smulacchalf ins insLen bld s1top s2top =
  let struct (rd, rn, rm, ra) = transFourOprs ins bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if s1top then bld <+ (t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt>)
  else bld <+ (t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt>)
  if s2top then bld <+ (t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt>)
  else bld <+ (t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt>)
  bld <+ (rd := (t1 .* t2) .+ AST.sext 32<rt> ra)
  putEndLabel bld lblIgnore
  bld --!> insLen

let smulacclonghalf (ins: InsInfo) insLen bld s1top s2top =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
  let struct (o1, o2, result) = tmpVars3 bld 64<rt>
  if s1top then bld <+ (o1 := AST.xthi 16<rt> src1 |> AST.sext 64<rt>)
  else bld <+ (o1 := AST.xtlo 16<rt> src1 |> AST.sext 64<rt>)
  if s2top then bld <+ (o2 := AST.xthi 16<rt> src2 |> AST.sext 64<rt>)
  else bld <+ (o2 := AST.xtlo 16<rt> src2 |> AST.sext 64<rt>)
  bld <+ (result := o1 .* o2 .+ AST.concat dst2 dst1)
  bld <+ (dst2 := AST.xthi 32<rt> result)
  bld <+ (dst1 := AST.xtlo 32<rt> result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfB (ins: InsInfo) =
  let addr = bvOfBaseAddr (ins.Address + pcOffset ins)
  match ins.Operands with
  | OneOperand (OprMemory (LiteralMode imm)) ->
    addr .+ (numI64 imm 32<rt>)
  | _ -> raise InvalidOperandException

let b ins insLen bld =
  let e = parseOprOfB ins
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (branchWritePC bld ins e InterJmpKind.Base)
  putEndLabelForBranch bld lblIgnore ins
  bld --!> insLen

let bx ins insLen bld =
  let rm = transOneOpr ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rm = convertPCOpr ins bld rm
  bxWritePC bld isUnconditional rm
  putEndLabelForBranch bld lblIgnore ins
  bld --!> insLen

let movtAssign dst src =
  let maskHigh16In32 = AST.num <| BitVector.OfBInt 4294901760I 32<rt>
  let clearHigh16In32 expr = expr .& AST.not maskHigh16In32
  dst := clearHigh16In32 dst .|
         (src << (numI32 16 32<rt>))

let movt ins insLen bld =
  let struct (dst, res) = transTwoOprs ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (movtAssign dst res)
  putEndLabel bld lblIgnore
  bld --!> insLen

let transFourOprsWithBarrelShift (ins: InsInfo) bld =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOprToExpr ins bld opr1
    let src1 = transOprToExpr ins bld opr2
    let src2 = transOprToExpr ins bld opr3
    let shifted = shift src2 32<rt> typ imm carryIn
    struct (dst, src1, shifted)
  | _ -> raise InvalidOperandException

let pkh (ins: InsInfo) insLen bld isTbform =
  bld <!-- (ins.Address, insLen)
  let struct (dst, src1, src2) = transFourOprsWithBarrelShift ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  let lblIgnore = checkCondition ins bld isUnconditional
  let src1H, src1L = AST.xthi 16<rt> src1, AST.xtlo 16<rt> src1
  let src2H, src2L = AST.xthi 16<rt> src2, AST.xtlo 16<rt> src2
  let res = if isTbform then AST.concat src1H src2L else AST.concat src2H src1L
  bld <+ (dst := res)
  putEndLabel bld lblIgnore
  bld --!> insLen

let popLoop bld numOfReg addr =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let reg = count |> uint32 |> OperandHelper.getRegister
      bld <+ (regVar bld reg := AST.loadLE 32<rt> addr)
      (addr .+ (numI32 4 32<rt>))
    else addr
  List.fold loop addr [ 0 .. 14 ]

let pop ins insLen bld =
  let t0 = tmpVar bld 32<rt>
  let sp = regVar bld R.SP
  let numOfReg = parseOprOfPUSHPOP ins
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = sp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t0 := addr)
  let addr = popLoop bld numOfReg t0
  if (numOfReg >>> 13 &&& 1u) = 0u then
    bld <+ (sp := sp .+ (numI32 stackWidth 32<rt>))
  else bld <+ (sp := (AST.undef 32<rt> "UNKNOWN"))
  if (numOfReg >>> 15 &&& 1u) = 1u then
    AST.loadLE 32<rt> addr |> loadWritePC bld isUnconditional
  else ()
  putEndLabelForBranch bld lblIgnore ins
  bld --!> insLen

let parseOprOfLDM (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    struct (regVar bld reg, getRegNum reg, regsToUInt32 regs)
  | _ -> raise InvalidOperandException

let getLDMStartAddr rn stackWidth = function
  | Op.LDM | Op.LDMIA -> rn
  | Op.LDMDA -> rn .- (numI32 stackWidth 32<rt>) .+ (numI32 4 32<rt>)
  | Op.LDMDB -> rn .- (numI32 stackWidth 32<rt>)
  | Op.LDMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let ldm opcode ins insLen bld wbackop =
  let struct (t0, t1) = tmpVars2 bld 32<rt>
  let struct (rn, numOfRn, numOfReg) = parseOprOfLDM ins bld
  let wback = ins.WriteBack
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = getLDMStartAddr t0 stackWidth opcode
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t0 := rn)
  bld <+ (t1 := addr)
  let addr = popLoop bld numOfReg t1
  if (numOfReg >>> 15 &&& 1u) = 1u then
    AST.loadLE 32<rt> addr |> loadWritePC bld isUnconditional
  else ()
  if wback && (numOfReg &&& numOfRn) = 0u then
    bld <+ (rn := wbackop t0 (numI32 stackWidth 32<rt>))
  else ()
  if wback && (numOfReg &&& numOfRn) = numOfRn then
    bld <+ (rn := (AST.undef 32<rt> "UNKNOWN"))
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let getOffAddrWithExpr s r e = if s = Some Plus then r .+ e else r .- e

let getOffAddrWithImm s r imm =
  match s, imm with
  | Some Plus, Some i -> r .+ (numI64 i 32<rt>)
  | Some Minus, Some i -> r .- (numI64 i 32<rt>)
  | _, _ -> r

let parseMemOfLDR ins insLen bld = function
  | OprMemory (OffsetMode (ImmOffset (rn, s, imm))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    struct (getOffAddrWithImm s rn imm, None)
  | OprMemory (PreIdxMode (ImmOffset (rn, s, imm))) ->
    let rn = regVar bld rn
    struct (getOffAddrWithImm s rn imm, Some (rn, None))
  | OprMemory (PostIdxMode (ImmOffset (rn, s, imm))) ->
    let rn = regVar bld rn
    struct (rn, Some (rn, Some (getOffAddrWithImm s rn imm)))
  | OprMemory (LiteralMode imm) ->
    let addr = bvOfBaseAddr ins.Address
    let pc = align addr (numI32 4 32<rt>)
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8u else 4u
    struct (pc .+ (numU32 rel 32<rt>) .+ (numI64 imm 32<rt>), None)
  | OprMemory (OffsetMode (RegOffset (n, _, m, None))) ->
    let m = regVar bld m |> convertPCOpr ins bld
    let n = regVar bld n |> convertPCOpr ins bld
    struct (n .+ shift m 32<rt> SRTypeLSL 0u (getCarryFlag bld), None)
  | OprMemory (PreIdxMode (RegOffset (n, s, m, None))) ->
    let rn = regVar bld n
    let offset =
      shift (regVar bld m) 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    struct (getOffAddrWithExpr s rn offset, Some (rn, None))
  | OprMemory (PostIdxMode (RegOffset (n, s, m, None))) ->
    let rn = regVar bld n
    let offset =
      shift (regVar bld m) 32<rt> SRTypeLSL 0u (getCarryFlag bld)
    struct (rn, Some (rn, Some (getOffAddrWithExpr s rn offset)))
  | OprMemory (OffsetMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = regVar bld n |> convertPCOpr ins bld
    let rm = regVar bld m |> convertPCOpr ins bld
    let offset = shift rm 32<rt> t i (getCarryFlag bld)
    struct (getOffAddrWithExpr s rn offset, None)
  | OprMemory (PreIdxMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = regVar bld n
    let offset = shift (regVar bld m) 32<rt> t i (getCarryFlag bld)
    struct (getOffAddrWithExpr s rn offset, Some (rn, None))
  | OprMemory (PostIdxMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = regVar bld n
    let offset = shift (regVar bld m) 32<rt> t i (getCarryFlag bld)
    struct (rn, Some (rn, Some (getOffAddrWithExpr s rn offset)))
  | _ -> raise InvalidOperandException

let parseOprOfLDR (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg rt, (OprMemory _ as mem)) ->
    let struct (addr, writeback) = parseMemOfLDR ins insLen bld mem
    struct (regVar bld rt, addr, writeback)
  | _ -> raise InvalidOperandException

/// Load register
let ldr ins insLen bld size ext =
  let data = tmpVar bld 32<rt>
  let struct (rt, addr, writeback) = parseOprOfLDR ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  match writeback with
  | Some (basereg, Some newoffset) ->
    let struct (taddr, twriteback) = tmpVars2 bld 32<rt>
    bld <+ (taddr := addr)
    bld <+ (twriteback := newoffset)
    bld <+ (data := AST.loadLE size taddr |> ext 32<rt>)
    bld <+ (basereg := twriteback)
  | Some (basereg, None) ->
    let taddr = tmpVar bld 32<rt>
    bld <+ (taddr := addr)
    bld <+ (data := AST.loadLE size taddr |> ext 32<rt>)
    bld <+ (basereg := taddr)
  | None ->
    bld <+ (data := AST.loadLE size addr |> ext 32<rt>)
  if rt = getPC bld then loadWritePC bld isUnconditional data
  else bld <+ (rt := data)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseMemOfLDRD ins insLen bld = function
  | OprMemory (OffsetMode (RegOffset (n, s, m, None))) ->
    struct (getOffAddrWithExpr s (regVar bld n) (regVar bld m), None)
  | OprMemory (PreIdxMode (RegOffset (n, s, m, None))) ->
    let rn = regVar bld n
    struct (getOffAddrWithExpr s rn (regVar bld m), Some (rn, None))
  | OprMemory (PostIdxMode (RegOffset (n, s, m, None))) ->
    let rn = regVar bld n
    struct (rn, Some (rn, Some (getOffAddrWithExpr s rn (regVar bld m))))
  | mem -> parseMemOfLDR ins insLen bld mem

let parseOprOfLDRD (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg t, OprReg t2, (OprMemory _ as mem)) ->
    let struct (addr, stmt) = parseMemOfLDRD ins insLen bld mem
    struct (regVar bld t, regVar bld t2, addr, stmt)
  | _ -> raise InvalidOperandException

let ldrd ins insLen bld =
  let taddr = tmpVar bld 32<rt>
  let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let n4 = numI32 4 32<rt>
  match writeback with
  | Some (basereg, Some newoffset) ->
    let twriteback = tmpVar bld 32<rt>
    bld <+ (taddr := addr)
    bld <+ (twriteback := newoffset)
    bld <+ (rt := AST.loadLE 32<rt> taddr)
    bld <+ (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
    bld <+ (basereg := twriteback)
  | Some (basereg, None) ->
    bld <+ (taddr := addr)
    bld <+ (rt := AST.loadLE 32<rt> taddr)
    bld <+ (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
    bld <+ (basereg := taddr)
  | None ->
    bld <+ (taddr := addr)
    bld <+ (rt := AST.loadLE 32<rt> taddr)
    bld <+ (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
  putEndLabel bld lblIgnore
  bld --!> insLen

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

let uadd8 ins insLen bld =
  let struct (rd, rn, rm) = transThreeOprs ins bld
  let struct (sum1, sum2, sum3, sum4) = tmpVars4 bld 32<rt>
  let struct (ge0, ge1, ge2, ge3) = tmpVars4 bld 32<rt>
  let cpsr = regVar bld R.CPSR
  let n100 = numI32 0x100 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (sum1 := sel8Bits rn 0 .+ sel8Bits rm 0)
  bld <+ (sum2 := sel8Bits rn 8 .+ sel8Bits rm 8)
  bld <+ (sum3 := sel8Bits rn 16 .+ sel8Bits rm 16)
  bld <+ (sum4 := sel8Bits rn 24 .+ sel8Bits rm 24)
  bld <+ (rd := combine8bitResults sum1 sum2 sum3 sum4)
  bld <+ (ge0 := AST.zext 32<rt> (AST.ge sum1 n100))
  bld <+ (ge1 := AST.zext 32<rt> (AST.ge sum2 n100))
  bld <+ (ge2 := AST.zext 32<rt> (AST.ge sum3 n100))
  bld <+ (ge3 := AST.zext 32<rt> (AST.ge sum4 n100))
  bld <+ (cpsr := combineGEs ge0 ge1 ge2 ge3 |> setPSR bld R.CPSR PSR.GE)
  putEndLabel bld lblIgnore
  bld --!> insLen

let sel ins insLen bld =
  let struct (t1, t2, t3, t4) = tmpVars4 bld 32<rt>
  let struct (rd, rn, rm) = transThreeOprs ins bld
  let n1 = AST.num1 32<rt>
  let n2 = numI32 2 32<rt>
  let n4 = numI32 4 32<rt>
  let n8 = numI32 8 32<rt>
  let ge = getPSR bld R.CPSR PSR.GE >> (numI32 16 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t1 := AST.ite ((ge .& n1) == n1) (sel8Bits rn 0) (sel8Bits rm 0))
  bld <+ (t2 := AST.ite ((ge .& n2) == n2) (sel8Bits rn 8) (sel8Bits rm 8))
  bld <+ (t3 := AST.ite ((ge .& n4) == n4) (sel8Bits rn 16) (sel8Bits rm 16))
  bld <+ (t4 := AST.ite ((ge .& n8) == n8) (sel8Bits rn 24) (sel8Bits rm 24))
  bld <+ (rd := combine8bitResults t1 t2 t3 t4)
  putEndLabel bld lblIgnore
  bld --!> insLen

let rbit ins insLen bld =
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  let struct (rd, rm) = transTwoOprs ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t1 := rm)
  bld <+ (rd := rd <+> rd)
  for i = 0 to 31 do
    bld <+ (t2 := (AST.extract t1 1<rt> i) |> AST.zext 32<rt>)
    bld <+ (rd := rd .| (t2 << (numI32 (31 - i) 32<rt>)))
  putEndLabel bld lblIgnore
  bld --!> insLen

let rev ins insLen bld =
  let struct (t1, t2, t3, t4) = tmpVars4 bld 32<rt>
  let struct (rd, rm) = transTwoOprs ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t1 := sel8Bits rm 0)
  bld <+ (t2 := sel8Bits rm 8)
  bld <+ (t3 := sel8Bits rm 16)
  bld <+ (t4 := sel8Bits rm 24)
  bld <+ (rd := combine8bitResults t4 t3 t2 t1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let rev16 ins insLen bld =
  let struct (rd, rm) = transTwoOprs ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let r1 = AST.extract rm 8<rt> 16
  let r2 = AST.extract rm 8<rt> 24
  let r3 = AST.extract rm 8<rt> 0
  let r4 = AST.extract rm 8<rt> 8
  bld <+ (rd := AST.revConcat [| r4; r3; r2; r1 |])
  putEndLabel bld lblIgnore
  bld --!> insLen

let revsh ins insLen bld =
  let struct (rd, rm) = transTwoOprs ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let r1 = (AST.xtlo 8<rt> rm |> AST.sext 32<rt>) << numI32 8 32<rt>
  let r2 = AST.extract rm 8<rt> 8 |> AST.zext 32<rt>
  bld <+ (rd := r1 .| r2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let rfedb (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let dst = transOneOpr ins bld
  let wback = ins.WriteBack
  let struct (addr, newPcValue, spsr) = tmpVars3 bld 32<rt>
  bld <+ (addr := dst .- numI32 8 32<rt>)
  bld <+ (newPcValue := AST.loadLE 32<rt> addr)
  bld <+ (spsr := AST.loadLE 32<rt> (addr .+ numI32 4 32<rt>))
  match wback with
  | true -> bld <+ (dst := dst .- numI32 8 32<rt>)
  | _ -> bld <+ (dst := dst)
  putEndLabel bld lblIgnore
  bld --!> insLen

/// Store register.
let str ins insLen bld size =
  let struct (rt, addr, writeback) = parseOprOfLDR ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if rt = getPC bld then bld <+ (AST.loadLE 32<rt> addr := pcStoreValue bld)
  elif size = 32<rt> then bld <+ (AST.loadLE 32<rt> addr := rt)
  else bld <+ (AST.loadLE size addr := AST.xtlo size rt)
  match writeback with
  | Some (basereg, Some newoffset) -> bld <+ (basereg := newoffset)
  | Some (basereg, None) -> bld <+ (basereg := addr)
  | None -> ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let strex ins insLen bld =
  let struct (rd, rt, addr, writeback) = parseOprOfLDRD ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if rt = getPC bld then bld <+ (AST.loadLE 32<rt> addr := pcStoreValue bld)
  else bld <+ (AST.loadLE 32<rt> addr := rt)
  match writeback with
  | Some (basereg, Some newoffset) -> bld <+ (basereg := newoffset)
  | Some (basereg, None) -> bld <+ (basereg := addr)
  | None -> ()
  bld <+ (rd := AST.num0 32<rt>) (* XXX: always succeeds for now *)
  putEndLabel bld lblIgnore
  bld --!> insLen

let strd ins insLen bld =
  let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (AST.loadLE 32<rt> addr := rt)
  bld <+ (AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>)) := rt2)
  match writeback with
  | Some (basereg, Some newoffset) -> bld <+ (basereg := newoffset)
  | Some (basereg, None) -> bld <+ (basereg := addr)
  | None -> ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfSTM (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    regVar bld reg, regsToUInt32 regs
  | _ -> raise InvalidOperandException

let getSTMStartAddr rn msize = function
  | Op.STM | Op.STMIA | Op.STMEA -> rn
  | Op.STMDA -> rn .- msize .+ (numI32 4 32<rt>)
  | Op.STMDB -> rn .- msize
  | Op.STMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let stmLoop bld regs wback rn addr =
  let loop addr count =
    if (regs >>> count) &&& 1u = 1u then
      let ri = count |> uint32 |> OperandHelper.getRegister |> regVar bld
      if ri = rn && wback && count <> lowestSetBit regs 32 then
        bld <+ (AST.loadLE 32<rt> addr := (AST.undef 32<rt> "UNKNOWN"))
      else
        bld <+ (AST.loadLE 32<rt> addr := ri)
      addr .+ (numI32 4 32<rt>)
    else addr
  List.fold loop addr [ 0 .. 14 ]

let stm opcode ins insLen bld wbop =
  let taddr = tmpVar bld 32<rt>
  let rn, regs = parseOprOfSTM ins insLen bld
  let wback = ins.WriteBack
  let msize = numI32 (4 * bitCount regs 16) 32<rt>
  let addr = getSTMStartAddr rn msize opcode
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (taddr := addr)
  let addr = stmLoop bld regs wback rn taddr
  if (regs >>> 15 &&& 1u) = 1u then
    bld <+ (AST.loadLE 32<rt> addr := pcStoreValue bld)
  else ()
  if wback then bld <+ (rn := wbop rn msize) else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfCBZ (ins: InsInfo) bld =
  let pc = bvOfBaseAddr ins.Address
  let offset = pcOffset ins |> int64
  match ins.Operands with
  | TwoOperands (OprReg rn, (OprMemory (LiteralMode imm))) ->
    regVar bld rn, pc .+ (numI64 (imm + offset) 32<rt>)
  | _ -> raise InvalidOperandException

let cbz nonZero ins insLen bld =
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let n = if nonZero then AST.num1 1<rt> else AST.num0 1<rt>
  let rn, pc = parseOprOfCBZ ins bld
  let cond = n <+> (rn == AST.num0 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (branchWritePC bld ins pc InterJmpKind.Base)
  bld <+ (AST.lmark lblL1)
  let fallAddr = ins.Address + uint64 ins.Length
  let fallAddrExp = numU64 fallAddr 32<rt>
  bld <+ (AST.interjmp fallAddrExp InterJmpKind.Base)
  putEndLabelForBranch bld lblIgnore ins
  bld --!> insLen

let parseOprOfTableBranch (ins: InsInfo) insLen bld =
  match ins.Operands with
  | OneOperand (OprMemory (OffsetMode (RegOffset (rn, None, rm, None)))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    let rm = regVar bld rm |> convertPCOpr ins bld
    let addr = rn .+ rm
    AST.loadLE 8<rt> addr |> AST.zext 32<rt>
  | OneOperand (OprMemory (OffsetMode (RegOffset (rn,
                                                  None,
                                                  rm, Some (_, Imm i))))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    let rm = regVar bld rm |> convertPCOpr ins bld
    let addr = rn .+ (shiftLSL rm 32<rt> i)
    AST.loadLE 16<rt> addr |> AST.zext 32<rt>
  | _ -> raise InvalidOperandException

let tableBranch (ins: InsInfo) insLen bld =
  let offset = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
  let pc = bvOfBaseAddr ins.Address .+ (numI32 offset 32<rt>)
  let halfwords = parseOprOfTableBranch ins insLen bld
  let numTwo = numI32 2 32<rt>
  let result = pc .+ (numTwo .* halfwords)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (branchWritePC bld ins result InterJmpKind.Base)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfBFC (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprReg rd, OprImm lsb, OprImm width) ->
    regVar bld rd, Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ -> raise InvalidOperandException

let bfc (ins: InsInfo) insLen bld =
  let rd, lsb, width = parseOprOfBFC ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (rd := replicate rd 32<rt> lsb width 0)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfRdRnLsbWidth (ins: InsInfo) insLen bld =
  match ins.Operands with
  | FourOperands (OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    regVar bld rd, regVar bld rn,
    Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ -> raise InvalidOperandException

let bfi ins insLen bld =
  let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins insLen bld
  let struct (t0, t1) = tmpVars2 bld 32<rt>
  let n = rn .& (BitVector.OfBInt (BigInteger.getMask width) 32<rt> |> AST.num)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t0 := n << (numI32 lsb 32<rt>))
  bld <+ (t1 := replicate rd 32<rt> lsb width 0)
  bld <+ (rd := t0 .| t1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let bfx ins insLen bld signExtend =
  let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if lsb + width - 1 > 31 || width < 0 then raise InvalidOperandException
  else ()
  let v = BitVector.OfBInt (BigInteger.getMask width) 32<rt> |> AST.num
  bld <+ (rd := (rn >> (numI32 lsb 32<rt>)) .& v)
  if signExtend && width > 1 then
    let struct (msb, mask) = tmpVars2 bld 32<rt>
    let msboffset = numI32 (lsb + width - 1) 32<rt>
    let shift = numI32 width 32<rt>
    bld <+ (msb := (rn >> msboffset) .& AST.num1 32<rt>)
    bld <+ (mask := (AST.not (msb .- AST.num1 32<rt>)) << shift)
    bld <+ (rd := rd .| mask)
  else ()
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfUqOpr bld = function
  | ThreeOperands (OprReg rd, OprReg rn, OprReg rm) ->
    regVar bld rd, regVar bld rn, regVar bld rm
  | _ -> raise InvalidOperandException

let createTemporaries bld cnt regtype =
  Array.init cnt (fun _ -> tmpVar bld regtype)

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

let uqopr (ins: InsInfo) insLen bld width opr =
  let rd, rn, rm = parseOprOfUqOpr bld ins.Operands
  let tmps = createTemporaries bld (32 / width) 32<rt>
  let sats = createTemporaries bld (32 / width) (RegType.fromBitWidth width)
  let rns = extractUQOps rn width
  let rms = extractUQOps rm width
  let diffs = Array.map2 opr rns rms
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  Array.iter2 (fun tmp diff -> bld <+ (tmp := diff)) tmps diffs
  Array.iter2 (fun s t -> bld <+ (s := saturate t width)) sats tmps
  bld <+ (rd := getUQAssignment sats width)
  putEndLabel bld lblIgnore
  bld --!> insLen

/// ADR For ThumbMode (T1 case)
let parseOprOfADR (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg rd, OprMemory (LiteralMode imm)) ->
    let addr = bvOfBaseAddr ins.Address
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
    let addr = addr .+ (numI32 rel 32<rt>)
    let pc = align addr (numI32 4 32<rt>)
    let imm = numI64 imm 32<rt>
    let pc = if ins.IsAdd then pc .+ imm else pc .- imm
    regVar bld rd, pc
  | _ -> raise InvalidOperandException

let it (ins: InsInfo) insLen bld =
  let cpsr = regVar bld R.CPSR
  let itState = numI32 (int ins.ITState) 32<rt>
  let mask10 = numI32 0b11 32<rt>
  let mask72 = (numI32 0b11111100 32<rt>)
  let itState10 = itState .& mask10
  let itState72 = (itState .& mask72) >> (numI32 2 32<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (cpsr := itState10 |> setPSR bld R.CPSR PSR.IT10)
  bld <+ (cpsr := itState72 |> setPSR bld R.CPSR PSR.IT72)
  bld --!> insLen

let adr ins insLen bld =
  let rd, result = parseOprOfADR ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if rd = getPC bld then aluWritePC bld ins isUnconditional result
  else bld <+ (rd := result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let mls ins insLen bld =
  let struct (rd, rn, rm, ra) = transFourOprs ins bld
  let r = tmpVar bld 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (r := AST.xtlo 32<rt> (AST.zext 64<rt> ra .- AST.zext 64<rt> rn .*
                                     AST.zext 64<rt> rm))
  bld <+ (rd := r)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfExtend (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg rd, OprReg rm) ->
    regVar bld rd, regVar bld rm, 0u
  | ThreeOperands (OprReg rd, OprReg rm, OprShift (_, Imm i)) ->
    regVar bld rd, regVar bld rm, i
  | _ -> raise InvalidOperandException

let extend (ins: InsInfo) insLen bld extractfn amount =
  let rd, rm, rotation = parseOprOfExtend ins insLen bld
  let rotated = shiftROR rm 32<rt> rotation
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (rd := extractfn 32<rt> (AST.xtlo amount rotated))
  putEndLabel bld lblIgnore
  bld --!> insLen

let uxtb16 ins insLen bld =
  let rd, rm, rotation = parseOprOfExtend ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rotated = shiftROR rm 32<rt> rotation
  let r1 = AST.xtlo 8<rt> rotated |> AST.zext 32<rt>
  let r2 = (AST.extract rotated 8<rt> 16 |> AST.zext 32<rt>) << numI32 16 32<rt>
  bld <+ (rd := r2 .| r1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfXTA (ins: InsInfo) insLen bld =
  match ins.Operands with
  | FourOperands (OprReg rd, OprReg rn, OprReg rm, OprShift (_, Imm i)) ->
    regVar bld rd, regVar bld rn, regVar bld rm, i
  | _ -> raise InvalidOperandException

let extendAndAdd (ins: InsInfo) insLen bld amount =
  let rd, rn, rm, rotation = parseOprOfXTA ins insLen bld
  let rotated = shiftROR rm 32<rt> rotation
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (rd := rn .+ AST.zext 32<rt> (AST.xtlo amount rotated))
  putEndLabel bld lblIgnore
  bld --!> insLen

let checkSingleReg = function
  | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
  | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17 | R.S18
  | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25 | R.S26 | R.S27
  | R.S28 | R.S29 | R.S30 | R.S31 -> true
  | _ -> false

let parseOprOfVLDR (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector d)),
                 OprMemory (OffsetMode (ImmOffset (rn, s, imm)))) ->
    let pc = regVar bld rn |> convertPCOpr ins bld
    let baseAddr = align pc (numI32 4 32<rt>)
    regVar bld d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ -> raise InvalidOperandException

let vldr ins insLen bld =
  let rd, addr, isSReg = parseOprOfVLDR ins insLen bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSReg then
    let data = tmpVar bld 32<rt>
    bld <+ (data := AST.loadLE 32<rt> addr)
    bld <+ (rd := data)
  else
    let struct (d1, d2) = tmpVars2 bld 32<rt>
    bld <+ (d1 := AST.loadLE 32<rt> addr)
    bld <+ (d2 := AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>)))
    bld <+ (rd := if bld.Endianness = Endian.Big then AST.concat d1 d2
                  else AST.concat d2 d1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfVSTR (ins: InsInfo) bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector d)),
                 OprMemory (OffsetMode (ImmOffset (rn, s, imm)))) ->
    let baseAddr = regVar bld rn
    regVar bld d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ -> raise InvalidOperandException

let vstr (ins: InsInfo) insLen bld =
  let rd, addr, isSReg = parseOprOfVSTR ins bld
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if isSReg then bld <+ (AST.loadLE 32<rt> addr := rd)
  else
    let mem1 = AST.loadLE 32<rt> addr
    let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let isbig = bld.Endianness = Endian.Big
    bld <+ (mem1 := if isbig then AST.xthi 32<rt> rd else AST.xtlo 32<rt> rd)
    bld <+ (mem2 := if isbig then AST.xtlo 32<rt> rd else AST.xthi 32<rt> rd)
  putEndLabel bld lblIgnore
  bld --!> insLen

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

let vpopLoop bld d imm isSReg addr =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      bld <+ (regVar bld reg := AST.loadLE 32<rt> addr)
      singleRegLoop (r + 1) nextAddr
    else ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let word1 = AST.loadLE 32<rt> addr
      let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = bld.Endianness = Endian.Big
      bld <+ (regVar bld reg := if isbig then AST.concat word1 word2
                                   else AST.concat word2 word1)
      nonSingleRegLoop (r + 1) nextAddr
    else ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpop ins insLen bld =
  let t0 = tmpVar bld 32<rt>
  let sp = regVar bld R.SP
  let d, imm, isSReg = parsePUSHPOPsubValue ins
  let addr = sp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t0 := addr)
  bld <+ (sp := addr .+ (numI32 (imm <<< 2) 32<rt>))
  vpopLoop bld d imm isSReg t0
  putEndLabel bld lblIgnore
  bld --!> insLen

let vpushLoop bld d imm isSReg addr =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      bld <+ (AST.loadLE 32<rt> addr := regVar bld reg)
      singleRegLoop (r + 1) nextAddr
    else ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let mem1 = AST.loadLE 32<rt> addr
      let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = bld.Endianness = Endian.Big
      let data1 = AST.xthi 32<rt> (regVar bld reg)
      let data2 = AST.xtlo 32<rt> (regVar bld reg)
      bld <+ (mem1 := if isbig then data1 else data2)
      bld <+ (mem2 := if isbig then data2 else data1)
      nonSingleRegLoop (r + 1) nextAddr
    else ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpush ins insLen bld =
  let t0 = tmpVar bld 32<rt>
  let sp = regVar bld R.SP
  let d, imm, isSReg = parsePUSHPOPsubValue ins
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  bld <+ (t0 := sp .- (numI32 (imm <<< 2) 32<rt>))
  bld <+ (sp := t0)
  vpushLoop bld d imm isSReg t0
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfVAND (ins: InsInfo) bld =
  match ins.Operands with
  | ThreeOperands
      (OprSIMD (SFReg (Vector r1)), OprSIMD (SFReg (Vector r2)),
        OprSIMD (SFReg (Vector r3))) ->
            regVar bld r1, regVar bld r2, regVar bld r3
  | _ -> raise InvalidOperandException

let vand (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    bld <+ (dstA := src1A .& src2A)
    bld <+ (dstB := src1B .& src2B)
  | _ ->
    let dst, src1, src2 = parseOprOfVAND ins bld
    bld <+ (dst := src1 .& src2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vmrs ins insLen bld =
  let struct (rt, fpscr) = transTwoOprs ins bld
  let cpsr = regVar bld R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  if rt <> cpsr then bld <+ (rt := fpscr)
  else bld <+ (cpsr := disablePSRBits bld R.CPSR PSR.Cond .|
                           getPSR bld R.FPSCR PSR.Cond)
  putEndLabel bld lblIgnore
  bld --!> insLen

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

let parseOprOfVMOV (ins: InsInfo) bld =
  match ins.Operands with
  (* VMOV (immediate) *)
  | TwoOperands (OprSIMD _, OprImm _) ->
    let struct (dst, imm) = getTwoOprs ins
    match ins.OprSize with
    | 128<rt> ->
      let struct (dstB, dstA) = transOprToExpr128 bld dst
      let imm = transOprToExpr ins bld imm
      bld <+ (dstB := imm)
      bld <+ (dstA := imm)
    | _ ->
      let dst = transOprToExpr ins bld dst
      let imm = transOprToExpr ins bld imm
      bld <+ (dst := imm)
  (* VMOV (general-purpose register to scalar) *)
  | TwoOperands (OprSIMD (SFReg (Scalar (_, Some element))), OprReg _) ->
    let struct (dst, src) = transTwoOprs ins bld
    let p = getParsingInfo ins
    let index = int element
    bld <+ (elem dst index p.ESize := AST.xtlo p.RtESize src)
  (* VMOV (scalar to general-purpose register) *)
  | TwoOperands (OprReg _, OprSIMD (SFReg (Scalar (_, Some element)))) ->
    let struct (dst, src) = transTwoOprs ins bld
    let p = getParsingInfo ins
    let index = int element
    let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
    bld <+ (dst := extend 32<rt> (elem src index p.ESize))
  (* VMOV (between general-purpose register and single-precision) *)
  | TwoOperands _ ->
    let struct (dst, src) = transTwoOprs ins bld
    bld <+ (dst := src)
  (* VMOV (between two general-purpose registers and a doubleword
    floating-point register) *)
  | ThreeOperands (OprSIMD _, OprReg _, OprReg _) ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (AST.xtlo 32<rt> dst := src1)
    bld <+ (AST.xthi 32<rt> dst := src2)
  | ThreeOperands (OprReg _, OprReg _, OprSIMD _) ->
    let struct (dst1, dst2, src) = transThreeOprs ins bld
    bld <+ (dst1 := AST.xtlo 32<rt> src)
    bld <+ (dst2 := AST.xthi 32<rt> src)
  (* VMOV (between two general-purpose registers and two single-precision
    registers) *)
  | FourOperands _ ->
    let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
    bld <+ (dst1 := src1)
    bld <+ (dst2 := src2)
  | _ -> raise InvalidOperandException

let parseOprOfVMOVFP (ins: InsInfo) bld =
  match ins.Operands with
  (* VMOV (between general-purpose register and half-precision) *)
  | TwoOperands (OprSIMD _, OprReg _) | TwoOperands (OprReg _, OprSIMD _) ->
    let struct (dst, src) = transTwoOprs ins bld
    bld <+ (dst := AST.zext 32<rt> (AST.xtlo 16<rt> src))
  (* VMOV (register) *)
  | TwoOperands (OprSIMD _, OprSIMD _) ->
    let struct (dst, src) = transTwoOprs ins bld
    bld <+ (dst := src)
  (* VMOV (immediate) *)
  | TwoOperands (OprSIMD _, OprImm _) ->
    let struct (dst, imm) = transTwoOprs ins bld
    bld <+ (dst := AST.zext ins.OprSize imm)
  | _ -> bld <+ (AST.sideEffect UnsupportedFP)

let vmov (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  parseOprOfVMOV ins bld
  putEndLabel bld lblIgnore
  bld --!> insLen

let vmovfp (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  parseOprOfVMOVFP ins bld
  putEndLabel bld lblIgnore
  bld --!> insLen

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

let vabs (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    for e in 0 .. p.Elements - 1 do
      bld <+ (elem dstB e p.ESize := absExpr (elem srcB e p.ESize) p.RtESize)
      bld <+ (elem dstA e p.ESize := absExpr (elem srcA e p.ESize) p.RtESize)
  | _ ->
    let struct (dst, src) = transTwoOprs ins bld
    for e in 0 .. p.Elements - 1 do
      bld <+ (elem dst e p.ESize := absExpr (elem src e p.ESize) p.RtESize)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vaddsub (ins: InsInfo) insLen bld opFn =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  (* FP, p.ESize 16 *)
  | 32<rt> when p.ESize = 16 ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst :=
      AST.zext 32<rt> (opFn (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)))
  (* FP, p.ESize 32 *)
  | 32<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := opFn src1 src2)
  (* FP, p.ESize 64 *)
  | 64<rt> when p.ESize = 64 ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := opFn src1 src2)
  (* SIMD *)
  | 64<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let elem value = elem value e p.ESize
      bld <+ (elem dst := (opFn (elem src1) (elem src2)))
  (* SIMD *)
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let elem expr = elem expr e p.ESize
      bld <+ (elem dstB := (opFn (elem src1B) (elem src2B)))
      bld <+ (elem dstA := (opFn (elem src1A) (elem src2A)))
  | _ -> raise InvalidOperandException
  putEndLabel bld lblIgnore
  bld --!> insLen

let vaddl (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld dst
  let src1 = transOprToExpr ins bld src1
  let src2 = transOprToExpr ins bld src2
  for e in 0 .. (p.Elements - 1) / 2 do
    bld <+ (elem dstA e (2 * p.ESize) :=
      AST.zext (p.RtESize * 2) (elem src1 e p.ESize) .+
      AST.zext (p.RtESize * 2) (elem src2 e p.ESize))
    bld <+ (elem dstB e (2 * p.ESize) :=
      AST.zext (p.RtESize * 2) (elem src1 (e + p.Elements / 2) p.ESize) .+
      AST.zext (p.RtESize * 2) (elem src2 (e + p.Elements / 2) p.ESize))
  putEndLabel bld lblIgnore
  bld --!> insLen

let isDoubleToSingle = function
  | Some (TwoDT (SIMDTypF32, SIMDTypF64)) -> true
  | Some (TwoDT (SIMDTypF64, SIMDTypF32)) -> false
  | _ -> raise InvalidOperandException

let parseOprOfVCVT (ins: InsInfo) bld =
  (* FIXME *)
  match ins.Operands with
  | TwoOperands(OprSIMD _, OprSIMD _) ->
    match ins.OprSize with
    (* FIXME *)
    (* VCVT (between half-precision and single-precision, Advanced SIMD) *)
    | 128<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let struct (dstB, dstA) = transOprToExpr128 bld dst
      let src = transOprToExpr ins bld src
      let p = getParsingInfo ins
      let struct (tdstB, tdstA) = tmpVars2 bld 64<rt>
      bld <+ (tdstA := (dstB << numI32 63 64<rt>) .| (dstA >> AST.num1 64<rt>))
      bld <+ (tdstB := dstB >> AST.num1 64<rt>)
      for e in 0 .. (p.Elements - 1) / 2 do
        bld <+ (elem tdstB e 32 :=
          AST.cast CastKind.FloatCast 32<rt> (elem src (e + 2) 16))
        bld <+ (elem tdstA e 32 :=
          AST.cast CastKind.FloatCast 32<rt> (elem src e 16))
      bld <+ (dstB := tdstB)
      bld <+ (dstA := tdstA)
    | 64<rt> ->
      let struct (dst, src) = getTwoOprs ins
      let dst = transOprToExpr ins bld dst
      let struct (srcB, srcA) = transOprToExpr128 bld src
      let p = getParsingInfo ins
      let struct (tsrcB, tsrcA) = tmpVars2 bld 64<rt>
      bld <+ (tsrcA := (srcB << numI32 63 64<rt>) .| (srcA >> AST.num1 64<rt>))
      bld <+ (tsrcB := srcB >> AST.num1 64<rt>)
      for e in 0 .. (p.Elements - 1) / 2 do
        bld <+ (elem dst (e + 2) 16 :=
          AST.cast CastKind.FloatCast 16<rt> (elem tsrcB e 32))
        bld <+ (elem dst e 16 :=
          AST.cast CastKind.FloatCast 16<rt> (elem tsrcA e 32))
    (* VCVT (between double-precision and single-precision) *)
    | _ ->
      let struct (dst, src) = transTwoOprs ins bld
      let cast =
        if isDoubleToSingle ins.SIMDTyp then AST.cast CastKind.FloatCast 32<rt>
        else AST.cast CastKind.FloatCast 64<rt>
      bld <+ (dst := cast src)
  | _ -> raise InvalidOperandException

let vcvt (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  parseOprOfVCVT ins bld
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfVDUP (ins: InsInfo) insLen bld esize =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector dst)),
                 OprSIMD (SFReg (Scalar (src, Some idx)))) ->
    regVar bld dst, elem (regVar bld src) (int32 idx) esize
  | TwoOperands (OprSIMD (SFReg (Vector dst)), OprReg src) ->
    regVar bld dst,
    AST.xtlo (RegType.fromBitWidth esize) (regVar bld src)
  | _ -> raise InvalidOperandException

let parseOprOfVDUP128 (ins: InsInfo) bld esize =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector dst)),
                 OprSIMD (SFReg (Scalar (src, Some idx)))) ->
    let struct (rb, ra) = pseudoRegVar128 bld dst
    struct (rb, ra, elem (regVar bld src) (int32 idx) esize)
  | TwoOperands (OprSIMD (SFReg (Vector dst)), OprReg src) ->
    let struct (rb, ra) = pseudoRegVar128 bld dst
    struct (rb, ra, AST.xtlo (RegType.fromBitWidth esize) (regVar bld src))
  | _ -> raise InvalidOperandException

let vdiv (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match p.ESize with
  | 16 ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst :=
      AST.zext 32<rt> (AST.fdiv (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := AST.fdiv src1 src2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vdup (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dstB, dstA, scalar) = parseOprOfVDUP128 ins bld p.ESize
    for e in 0 .. p.Elements - 1 do
      bld <+ (elem dstB e p.ESize := scalar)
      bld <+ (elem dstA e p.ESize := scalar)
  | _ ->
    let dst, scalar = parseOprOfVDUP ins insLen bld p.ESize
    for e in 0 .. p.Elements - 1 do bld <+ (elem dst e p.ESize := scalar) done
  putEndLabel bld lblIgnore
  bld --!> insLen

let highestSetBitForIR dst src width oprSz bld =
  let lblLoop = label bld "Loop"
  let lblLoopCont = label bld "LoopContinue"
  let lblUpdateTmp = label bld "UpdateTmp"
  let lblEnd = label bld "End"
  let t = tmpVar bld oprSz
  let width = (numI32 (width - 1) oprSz)
  bld <+ (t := width)
  bld <+ (AST.lmark lblLoop)
  bld <+ (AST.cjmp (src >> t == AST.num1 oprSz)
                       (AST.jmpDest lblEnd) (AST.jmpDest lblLoopCont))
  bld <+ (AST.lmark lblLoopCont)
  bld <+ (AST.cjmp (t == AST.num0 oprSz)
                       (AST.jmpDest lblEnd) (AST.jmpDest lblUpdateTmp))
  bld <+ (AST.lmark lblUpdateTmp)
  bld <+ (t := t .- AST.num1 oprSz)
  bld <+ (AST.jmp (AST.jmpDest lblLoop))
  bld <+ (AST.lmark lblEnd)
  bld <+ (dst := width .- t)

let countLeadingZeroBitsForIR dst src oprSize bld =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize bld

let vclz (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    for e in 0 .. p.Elements - 1 do
      countLeadingZeroBitsForIR (elem dstB e p.ESize)
                                (elem srcB e p.ESize) p.RtESize bld
      countLeadingZeroBitsForIR (elem dstA e p.ESize)
                                (elem srcA e p.ESize) p.RtESize bld
  | _ ->
    let struct (dst, src) = transTwoOprs ins bld
    for e in 0 .. p.Elements - 1 do
      countLeadingZeroBitsForIR (elem dst e p.ESize)
                                (elem src e p.ESize) p.RtESize bld
  putEndLabel bld lblIgnore
  bld --!> insLen

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

let vmaxmin (ins: InsInfo) insLen bld maximum =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let unsigned = isUnsigned ins.SIMDTyp
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let op1B, op2B = elem src1B e p.ESize, elem src2B e p.ESize
      let op1A, op2A = elem src1A e p.ESize, elem src2A e p.ESize
      let result1 =
        if maximum then maxExpr unsigned op1B op2B
        else minExpr unsigned op1B op2B
      let result2 =
        if maximum then maxExpr unsigned op1A op2A
        else minExpr unsigned op1A op2A
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let op1 = elem src1 e p.ESize
      let op2 = elem src2 e p.ESize
      let result =
        if maximum then maxExpr unsigned op1 op2 else minExpr unsigned op1 op2
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseOprOfVSTLDM (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    regVar bld reg, List.map (regVar bld) regs
  | _ -> raise InvalidOperandException

let vstm (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rn, regList = parseOprOfVSTLDM ins insLen bld
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
    else rn
  bld <+ (addr := if add then rn else rn .- imm32)
  bld <+ (rn := updateRn rn)
  for r in 0 .. (regs - 1) do
    let mem1 = AST.loadLE 32<rt> addr
    let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let data1 = AST.xtlo 32<rt> regList[r]
    let data2 = AST.xthi 32<rt> regList[r]
    let isbig = bld.Endianness = Endian.Big
    bld <+ (mem1 := if isbig then data2 else data1)
    bld <+ (mem2 := if isbig then data1 else data2)
    bld <+ (addr := addr .+ (numI32 8 32<rt>))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vldm (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rn, regList = parseOprOfVSTLDM ins insLen bld
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
    else rn
  bld <+ (addr := if add then rn else rn .- imm32)
  bld <+ (rn := updateRn rn)
  for r in 0 .. (regs - 1) do
    let word1 = AST.loadLE 32<rt> addr
    let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let isbig = bld.Endianness = Endian.Big
    bld <+ (regList[r] :=
           if isbig then AST.concat word1 word2 else AST.concat word2 word1)
    bld <+ (addr := addr .+ (numI32 8 32<rt>))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulAccOrSub (ins: InsInfo) insLen bld add =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let sext1A = AST.sext p.RtESize (elem src1A e p.ESize)
      let sext1B = AST.sext p.RtESize (elem src1B e p.ESize)
      let sext2A = AST.sext p.RtESize (elem src2A e p.ESize)
      let sext2B = AST.sext p.RtESize (elem src2B e p.ESize)
      let productA = sext1A .* sext2A
      let productB = sext1B .* sext2B
      let addendA, addendB =
        if add then productA, productB else AST.not productA, AST.not productB
      bld <+ (elem dstB e p.ESize := elem dstB e p.ESize .+ addendB)
      bld <+ (elem dstA e p.ESize := elem dstA e p.ESize .+ addendA)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let sext1 = AST.sext p.RtESize (elem src1 e p.ESize)
      let sext2 = AST.sext p.RtESize (elem src2 e p.ESize)
      let product = sext1 .* sext2
      let addend = if add then product else AST.not product
      bld <+ (elem dst e p.ESize := elem dst e p.ESize .+ addend)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulAccOrSubLong (ins: InsInfo) insLen bld add =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let unsigned = isUnsigned ins.SIMDTyp
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld dst
  let src1 = transOprToExpr ins bld src1
  let src2 = transOprToExpr ins bld src2
  for e in 0 .. (p.Elements - 1) / 2 do
    let extend expr =
      if unsigned then AST.zext (p.RtESize * 2) expr
      else AST.sext (p.RtESize * 2) expr
    let productA = extend (elem src1 e p.ESize) .* extend (elem src2 e p.ESize)
    let productB = extend (elem src1 (e + p.Elements / 2) p.ESize) .*
                   extend (elem src2 (e + p.Elements / 2) p.ESize)
    let addendA, addendB =
      if add then productA, productB else AST.not productA, AST.not productB
    bld <+ (elem dstB e (p.ESize * 2) := elem dstB e (p.ESize * 2) .+ addendB)
    bld <+ (elem dstA e (p.ESize * 2) := elem dstA e (p.ESize * 2) .+ addendA)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulAccOrSubByScalar (ins: InsInfo) insLen bld add =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let struct (dst, src1, src2) = getThreeOprs ins
  let src2, index = transOprToSclar bld src2
  let op2Val = AST.sext p.RtESize (elem src2 index p.ESize)
  match ins.OprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    for e in 0 .. p.Elements - 1 do
      let op1valA = AST.sext p.RtESize (elem src1A e p.ESize)
      let op1valB = AST.sext p.RtESize (elem src1B e p.ESize)
      let addendA, addendB =
        if add then op1valA .* op2Val, op1valB .* op2Val
        else AST.not (op1valA .* op2Val), AST.not (op1valB .* op2Val)
      bld <+ (elem dstB e p.ESize := elem dstB e p.ESize .+ addendB)
      bld <+ (elem dstA e p.ESize := elem dstA e p.ESize .+ addendA)
  | _ ->
    let dst = transOprToExpr ins bld dst
    let src1 = transOprToExpr ins bld src1
    for e in 0 .. p.Elements - 1 do
      let op1val = AST.sext p.RtESize (elem src1 e p.ESize)
      let addend =
        if add then op1val .* op2Val else AST.not (op1val .* op2Val)
      bld <+ (elem dst e p.ESize := elem dst e p.ESize .+ addend)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulAccOrSubLongByScalar (ins: InsInfo) insLen bld add =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld dst
  let src1 = transOprToExpr ins bld src1
  let src2, index = transOprToSclar bld src2
  let p = getParsingInfo ins
  let ext = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  let op2val = ext (p.RtESize * 2) (elem src2 index p.ESize)
  for e in 0 .. (p.Elements - 1) / 2 do
    let op1valA = ext (p.RtESize * 2) (elem src1 e p.ESize)
    let op1valB = ext (p.RtESize * 2) (elem src1 (e + p.Elements / 2) p.ESize)
    let addendA, addendB =
      if add then op1valA .* op2val, op1valB .* op2val
      else AST.not (op1valA .* op2val), AST.not (op1valB .* op2val)
    bld <+ (elem dstB e (p.ESize * 2) := elem dstB e (p.ESize * 2) .+ addendB)
    bld <+ (elem dstA e (p.ESize * 2) := elem dstA e (p.ESize * 2) .+ addendA)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vmla (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSub ins insLen bld true
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubByScalar ins insLen bld true
  | _ -> raise InvalidOperandException

let vmlal (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSubLong ins insLen bld true
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubLongByScalar ins insLen bld true
  | _ -> raise InvalidOperandException

let vmls (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSub ins insLen bld false
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubByScalar ins insLen bld false
  | _ -> raise InvalidOperandException

let vmlsl (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSubLong ins insLen bld false
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubLongByScalar ins insLen bld false
  | _ -> raise InvalidOperandException

let isPolynomial = function
  | Some (OneDT SIMDTypP8) | Some (OneDT SIMDTypP64) -> true
  | _ -> false

/// shared/functions/vector/PolynomialMult, in page Armv8 Pseudocode-7927
let polynomialMult op1 op2 size rtsize res bld =
  let extendedOP2 = AST.zext rtsize op2
  for i = 0 to size - 1 do
    let cond = AST.extract op1 1<rt> i
    bld <+ (res := AST.ite cond (res <+> (extendedOP2 << numI32 i rtsize)) res)

let polynomialMultP64 op1 op2 size rtsize resA resB bld =
  for i = 0 to size - 1 do
    let cond = AST.extract op1 1<rt> i
    bld <+ (resA := AST.ite cond (resA <+> (op2 << numI32 i rtsize)) resA)
    bld <+ (resB := AST.ite cond
                            (resB <+> (op2 >> numI32 (64 - i) rtsize)) resB)

let vecMul (ins: InsInfo) insLen bld opFn =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let polynomial = isPolynomial ins.SIMDTyp
  let struct (resultA, resultB) = tmpVars2 bld (p.RtESize * 2)
  match ins.OprSize with
  (* FP, p.ESize 16 *)
  | 32<rt> when p.ESize = 16 ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst :=
      AST.zext 32<rt> (opFn (AST.xtlo 16<rt> src1) (AST.xtlo 16<rt> src2)))
  (* FP, p.ESize 32 *)
  | 32<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := opFn src1 src2)
  (* FP, p.ESize 64 *)
  | 64<rt> when p.ESize = 64 ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := opFn src1 src2)
  (* SIMD *)
  | 64<rt> ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let struct (op1, op2) = elem src1 e p.ESize, elem src2 e p.ESize
      if polynomial then
        polynomialMult op1 op2 p.ESize (p.RtESize * 2) resultA bld
      else bld <+ (resultA := mulSExtend p 2 op1 op2 opFn)
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize resultA)
  (* SIMD *)
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let struct (op1A, op2A, op1B, op2B) =
        elem src1A e p.ESize, elem src2A e p.ESize,
        elem src1B e p.ESize, elem src2B e p.ESize
      if polynomial then
        polynomialMult op1A op2A p.ESize (p.RtESize * 2) resultA bld
        polynomialMult op1B op2B p.ESize (p.RtESize * 2) resultB bld
      else
        bld <+ (resultA := mulSExtend p 2 op1A op2A opFn)
        bld <+ (resultB := mulSExtend p 2 op1B op2B opFn)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize resultA)
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize resultB)
  | _ -> raise InvalidOperandException
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulLong (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let polynomial = isPolynomial ins.SIMDTyp
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld dst
  let src1 = transOprToExpr ins bld src1
  let src2 = transOprToExpr ins bld src2
  let isPolyAndE64 = polynomial && p.ESize = 64
  let struct (regSize, eSize) =
    if isPolyAndE64 then p.RtESize, p.ESize
    else p.RtESize * 2, p.ESize * 2
  let struct (resA, resB) = tmpVars2 bld regSize
  for e in 0 .. (p.Elements - 1) / 2 do
    let struct (op1A, op2A, op1B, op2B) =
      elem src1 e p.ESize, elem src2 e p.ESize,
      elem src1 (e + p.Elements / 2) p.ESize,
      elem src2 (e + p.Elements / 2) p.ESize
    if isPolyAndE64 then
      polynomialMultP64 op1A op2A p.ESize p.RtESize resA resB bld
    elif polynomial then
      polynomialMult op1A op2A p.ESize (p.RtESize * 2) resA bld
      polynomialMult op1A op2A p.ESize (p.RtESize * 2) resB bld
    else
      bld <+ (resA := unsignExtend ins p 2 op1A op2A (.*))
      bld <+ (resB := unsignExtend ins p 2 op1B op2B (.*))
    bld <+ (elem dstB e eSize := AST.xtlo regSize resB)
    bld <+ (elem dstA e eSize := AST.xtlo regSize resA)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulByScalar (ins: InsInfo) insLen bld opFn =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let struct (dst, src1, src2) = getThreeOprs ins
  let src2, index = transOprToSclar bld src2
  let op2val = elem src2 index p.ESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    for e in 0 .. p.Elements - 1 do
      let resA = mulSExtend p 1 (elem src1A e p.ESize) op2val opFn
      let resB = mulSExtend p 1 (elem src1B e p.ESize) op2val opFn
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize resB)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize resA)
  | _ ->
    let dst = transOprToExpr ins bld dst
    let src1 = transOprToExpr ins bld src1
    for e in 0 .. p.Elements - 1 do
      let res = mulSExtend p 1 (elem src1 e p.ESize) op2val opFn
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize res)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vecMulLongByScalar (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = getThreeOprs ins
  let struct (dstB, dstA) = transOprToExpr128 bld dst
  let src1 = transOprToExpr ins bld src1
  let src2, index = transOprToSclar bld src2
  let p = getParsingInfo ins
  let op2val = elem src2 index p.ESize
  let pele2 = p.Elements / 2
  for e in 0 .. (p.Elements - 1) / 2 do
    let resA = unsignExtend ins p 2 (elem src1 e p.ESize) op2val (.*)
    let resB = unsignExtend ins p 2 (elem src1 (e + pele2) p.ESize) op2val (.*)
    bld <+ (elem dstB e (p.ESize * 2) := AST.xtlo (p.RtESize * 2) resB)
    bld <+ (elem dstA e (p.ESize * 2) := AST.xtlo (p.RtESize * 2) resA)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vmul (ins: InsInfo) insLen bld opFn =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMul ins insLen bld opFn
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulByScalar ins insLen bld opFn
  | _ -> raise InvalidOperandException

let vmull (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulLong ins insLen bld
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulLongByScalar ins insLen bld
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

let vmovn (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src) = getTwoOprs ins
  let dst = transOprToExpr ins bld dst
  let struct (srcB, srcA) = transOprToExpr128 bld src
  let esize = 8 <<< getSizeStartFrom16 ins.SIMDTyp
  let rtEsz = RegType.fromBitWidth esize
  let elements = 64 / esize
  for e in 0 .. (elements - 1) / 2 do
    bld <+ (elem dst e esize := AST.xtlo rtEsz (elem srcB e esize))
    bld <+ (elem dst (e + elements / 2) esize :=
         AST.xtlo rtEsz (elem srcA e esize))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vneg (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    for e in 0 .. p.Elements - 1 do
      let result1 = AST.neg <| AST.sext p.RtESize (elem srcB e p.ESize)
      let result2 = AST.neg <| AST.sext p.RtESize (elem srcA e p.ESize)
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src) = transTwoOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let result = AST.neg <| AST.sext p.RtESize (elem src e p.ESize)
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vpadd (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (rd, rn, rm) = transThreeOprs ins bld
  let p = getParsingInfo ins
  let h = p.Elements / 2
  let dest = tmpVar bld 64<rt>
  for e in 0 .. h - 1 do
    let addPair expr =
      elem expr (2 * e) p.ESize .+ elem expr (2 * e + 1) p.ESize
    bld <+ (elem dest e p.ESize := addPair rn)
    bld <+ (elem dest (e + h) p.ESize := addPair rm)
  bld <+ (rd := dest)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vrshr (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    let imm = AST.zext 64<rt> (transOprToExpr ins bld imm)
    let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
    for e in 0 .. p.Elements - 1 do
      let result1 = (extend 64<rt> (elem srcB e p.ESize) .+ roundConst) >> imm
      let result2 = (extend 64<rt> (elem srcA e p.ESize) .+ roundConst) >> imm
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins bld
    let imm = AST.zext 64<rt> imm
    let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
    for e in 0 .. p.Elements - 1 do
      let result = (extend 64<rt> (elem src e p.ESize) .+ roundConst) >> imm
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vshlImm (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    let imm = AST.zext p.RtESize (transOprToExpr ins bld imm)
    for e in 0 .. p.Elements - 1 do
      bld <+ (elem dstB e p.ESize := elem srcB e p.ESize << imm)
      bld <+ (elem dstA e p.ESize := elem srcA e p.ESize << imm)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins bld
    let imm = AST.zext p.RtESize imm
    for e in 0 .. p.Elements - 1 do
      bld <+ (elem dst e p.ESize := elem src e p.ESize << imm)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vshlReg (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let shift1 = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2B e p.ESize))
      let shift2 = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2A e p.ESize))
      let result1 = extend 64<rt> (elem src1B e p.ESize) << shift1
      let result2 = extend 64<rt> (elem src1A e p.ESize) << shift2
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let shift = AST.sext 64<rt> (AST.xtlo 8<rt> (elem src2 e p.ESize))
      let result = extend 64<rt> (elem src1 e p.ESize) << shift
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vshl (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vshlImm ins insLen bld
  | ThreeOperands (_, _, OprSIMD _) -> vshlReg ins insLen bld
  | _ -> raise InvalidOperandException

let vshr (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld dst
    let imm = AST.zext 64<rt> (transOprToExpr ins bld imm)
    for e in 0 .. p.Elements - 1 do
      let result1 = extend 64<rt> (elem srcB e p.ESize) >> imm
      let result2 = extend 64<rt> (elem srcA e p.ESize) >> imm
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize result1)
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize result2)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins bld
    let imm = AST.zext 64<rt> imm
    for e in 0 .. p.Elements - 1 do
      let result = extend 64<rt> (elem src e p.ESize) >> imm
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel bld lblIgnore
  bld --!> insLen

let parseVectors = function
  | OneReg (Vector d) -> [ d ]
  | TwoRegs (Vector d1, Vector d2) -> [ d1; d2 ]
  | ThreeRegs (Vector d1, Vector d2, Vector d3) -> [ d1; d2; d3 ]
  | FourRegs (Vector d1, Vector d2, Vector d3, Vector d4) -> [ d1; d2; d3; d4 ]
  | _ -> raise InvalidOperandException

let parseOprOfVecTbl (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (OprSIMD (SFReg (Vector rd)), OprSIMD regs,
                   OprSIMD (SFReg (Vector rm))) ->
    regVar bld rd, parseVectors regs, regVar bld rm
  | _ -> raise InvalidOperandException

let vecTbl (ins: InsInfo) insLen bld isVtbl =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rd, list, rm = parseOprOfVecTbl ins insLen bld
  let vectors = list |> List.map (regVar bld)
  let length = List.length list
  let table = AST.revConcat (List.toArray vectors) |> AST.zext 256<rt>
  for i in 0 .. 7 do
    let index = elem rm i 8
    let cond = AST.lt index (numI32 (8 * length) 8<rt>)
    let e = if isVtbl then AST.num0 8<rt> else elem rd i 8
    bld <+ (elem rd i 8 := AST.ite cond (elemForIR table 256<rt> index 8) e)
  putEndLabel bld lblIgnore
  bld --!> insLen

let isImm = function
  | Num _ -> true
  | _ -> false

let vectorCompareImm (ins: InsInfo) insLen bld cmp =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let num0 = AST.num0 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    for e in 0 .. p.Elements - 1 do
      let t1 = cmp (elem src1B e p.ESize) num0
      let t2 = cmp (elem src1A e p.ESize) num0
      bld <+ (elem dstB e p.ESize := AST.ite t1 (ones p.RtESize) num0)
      bld <+ (elem dstA e p.ESize := AST.ite t2 (ones p.RtESize) num0)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let t = cmp (elem src1 e p.ESize) num0
      bld <+ (elem dst e p.ESize := AST.ite t (ones p.RtESize) num0)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vectorCompareReg (ins: InsInfo) insLen bld cmp =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let num0 = AST.num0 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let t1 = cmp (elem src1B e p.ESize) (elem src2B e p.ESize)
      let t2 = cmp (elem src1A e p.ESize) (elem src2A e p.ESize)
      bld <+ (elem dstB e p.ESize := AST.ite t1 (ones p.RtESize) num0)
      bld <+ (elem dstA e p.ESize := AST.ite t2 (ones p.RtESize) num0)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let t = cmp (elem src1 e p.ESize) (elem src2 e p.ESize)
      bld <+ (elem dst e p.ESize := AST.ite t (ones p.RtESize) num0)
  putEndLabel bld lblIgnore
  bld --!> insLen

let getCmp (ins: InsInfo) unsigned signed =
  if isUnsigned ins.SIMDTyp then unsigned else signed

let vceq (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen bld (==)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen bld (==)
  | _ -> raise InvalidOperandException

let vcge (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen bld
                                        (getCmp ins AST.ge AST.sge)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen bld
                                         (getCmp ins AST.ge AST.sge)
  | _ -> raise InvalidOperandException

let vcgt (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen bld
                                        (getCmp ins AST.gt AST.sgt)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen bld
                                         (getCmp ins AST.gt AST.sgt)
  | _ -> raise InvalidOperandException

let vcle (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen bld
                                        (getCmp ins AST.le AST.sle)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen bld
                                         (getCmp ins AST.le AST.sle)
  | _ -> raise InvalidOperandException

let vclt (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vectorCompareImm ins insLen bld
                                        (getCmp ins AST.lt AST.slt)
  | ThreeOperands (_, _, OprSIMD _) -> vectorCompareReg ins insLen bld
                                         (getCmp ins AST.lt AST.slt)
  | _ -> raise InvalidOperandException

let vtst (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let n0 = AST.num0 p.RtESize
  let n1 = AST.num1 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. p.Elements - 1 do
      let c = (elem src1B e p.ESize .& elem src2B e p.ESize) != n0
      let c2 = (elem src1A e p.ESize .& elem src2A e p.ESize) != n0
      bld <+ (elem dstB e p.ESize := AST.ite c n1 n0)
      bld <+ (elem dstA e p.ESize := AST.ite c2 n1 n0)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. p.Elements - 1 do
      let c = (elem src1 e p.ESize .& elem src2 e p.ESize) != n0
      bld <+ (elem dst e p.ESize := AST.ite c n1 n0)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vrshrn (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
  let rtEsz = RegType.fromBitWidth esize
  let elements = 64 / esize
  let struct (dst, src, imm) = getThreeOprs ins
  let dst = transOprToExpr ins bld dst
  let struct (srcB, srcA) = transOprToExpr128 bld src
  let imm = AST.zext (rtEsz * 2) (transOprToExpr ins bld imm)
  let roundConst = AST.num1 (rtEsz * 2) << (imm .- AST.num1 (rtEsz * 2))
  for e in 0 .. (elements / 2) - 1 do
    let result1 = (elem srcB e (esize * 2) .+ roundConst) >> imm
    let result2 = (elem srcA e (esize * 2) .+ roundConst) >> imm
    bld <+ (elem dst e esize := AST.xtlo rtEsz result1)
    bld <+ (elem dst e esize := AST.xtlo rtEsz result2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vorrReg (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    bld <+ (dstB := src1B .| src2B)
    bld <+ (dstA := src1A .| src2A)
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := src1 .| src2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vorrImm (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, imm) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let imm =
      AST.concat (transOprToExpr ins bld imm) (transOprToExpr ins bld imm)
    bld <+ (dstB := dstB .| imm)
    bld <+ (dstA := dstA .| imm)
  | _ ->
    let struct (dst, imm) = transTwoOprs ins bld
    let imm = AST.concat imm imm // FIXME: A8-975
    bld <+ (dst := dst .| imm)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vorr (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands _ -> vorrReg ins insLen bld
  | TwoOperands _ -> vorrImm ins insLen bld
  | _ -> raise InvalidOperandException

let vornReg (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    bld <+ (dstB := src1B .| (AST.not <| src2B))
    bld <+ (dstA := src1A .| (AST.not <| src2A))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    bld <+ (dst := src1 .| (AST.not <| src2))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vornImm (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, imm) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let imm =
      AST.concat (transOprToExpr ins bld imm) (transOprToExpr ins bld imm)
    bld <+ (dstB := dstB .| AST.not imm)
    bld <+ (dstA := dstA .| AST.not imm)
  | _ ->
    let struct (dst, imm) = transTwoOprs ins bld
    let imm = AST.concat imm imm // FIXME: A8-975
    bld <+ (dst := dst .| AST.not imm)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vorn (ins: InsInfo) insLen bld =
  match ins.Operands with
  | ThreeOperands _ -> vornReg ins insLen bld
  | TwoOperands _ -> vornImm ins insLen bld
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

let getRnAndRm bld = function
  | TwoOperands (_, OprMemory (OffsetMode (AlignOffset (rn, _, _))))
  | TwoOperands (_, OprMemory (PreIdxMode (AlignOffset (rn, _, _)))) ->
    regVar bld rn, None
  | TwoOperands (_, OprMemory (PostIdxMode (AlignOffset (rn, _, Some rm)))) ->
    regVar bld rn, regVar bld rm |> Some
  | _ -> raise InvalidOperandException

let assignByEndian (bld: ILowUIRBuilder) dst src =
  let isbig = bld.Endianness = Endian.Big
  bld <+ (dst := if isbig then AST.xthi 32<rt> src else AST.xtlo 32<rt> src)

let parseOprOfVecStAndLd bld (ins: InsInfo) =
  let rdList = parseDstList ins.Operands |> List.map (regVar bld)
  let rn, rm = getRnAndRm bld ins.Operands
  rdList, rn, rm

let updateRn (ins: InsInfo) rn (rm: Expr option) n (regIdx: bool option) =
  let rmOrTransSz = if regIdx.Value then rm.Value else numI32 n 32<rt>
  if ins.WriteBack then rn .+ rmOrTransSz else rn

let incAddr addr n = addr .+ (numI32 n 32<rt>)

let vst1Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let regs = getRegs ins.Operands
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (8 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    for e in 0 .. (p.Elements - 1) do
      if p.EBytes <> 8 then
        let mem = AST.loadLE p.RtESize addr
        bld <+ (mem := elem rdList[r] e p.ESize)
      else
        let mem1 = AST.loadLE 32<rt> addr
        let mem2 = AST.loadLE 32<rt> (incAddr addr 4)
        let reg = elem rdList[r] e p.ESize
        assignByEndian bld mem1 reg
        assignByEndian bld mem2 reg
      bld <+ (addr := addr .+ (numI32 p.EBytes 32<rt>))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst1Single (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rd, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm p.EBytes p.RegIndex)
  let mem = AST.loadLE p.RtESize addr
  bld <+ (mem := elem rd[0] (int32 index) p.ESize)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst1 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (OneReg (Scalar (_, Some index))), _) ->
    vst1Single ins insLen bld index
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst1Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vld1SingleOne (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rd, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm p.EBytes p.RegIndex)
  let mem = AST.loadLE p.RtESize addr
  bld <+ (elem rd[0] (int32 index) p.ESize := mem)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld1SingleAll (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm p.EBytes p.RegIndex)
  let mem = AST.loadLE p.RtESize addr
  let repElem = Array.replicate p.Elements mem |> AST.revConcat
  for r in 0 .. (List.length rdList - 1) do
    bld <+ (rdList[r] := repElem) done
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld1Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let regs = getRegs ins.Operands
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (8 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    for e in 0 .. (p.Elements - 1) do
      if p.EBytes <> 8 then
        let data = tmpVar bld p.RtESize
        bld <+ (data := AST.loadLE p.RtESize addr)
        bld <+ (elem rdList[r] e p.ESize := data)
      else
        let struct (data1, data2) = tmpVars2 bld 32<rt>
        let mem1 = AST.loadLE 32<rt> addr
        let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
        let isbig = bld.Endianness = Endian.Big
        bld <+ (data1 := if isbig then mem2 else mem1)
        bld <+ (data2 := if isbig then mem1 else mem1)
        bld <+ (elem rdList[r] e p.ESize := AST.concat data2 data1)
      bld <+ (addr := incAddr addr p.EBytes)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld1 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (OneReg (Scalar (_, Some index))), _) ->
    vld1SingleOne ins insLen bld index
  | TwoOperands (OprSIMD (OneReg (Scalar _)), _)
  | TwoOperands (OprSIMD (TwoRegs (Scalar _, Scalar _)), _) ->
    vld1SingleAll ins insLen bld
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld1Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vst2Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let regs = getRegs ins.Operands / 2
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (16 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    let rd1 = rdList[r * 2]
    let rd2 = rdList[r * 2 + 1]
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
      bld <+ (mem1 := elem rd1 e p.ESize)
      bld <+ (mem2 := elem rd2 e p.ESize)
      bld <+ (addr := addr .+ (numI32 (2 * p.EBytes) 32<rt>))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst2Single (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (16 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (addr .+ (numI32 p.EBytes 32<rt>))
  bld <+ (mem1 := elem rdList[0] index p.ESize)
  bld <+ (mem2 := elem rdList[1] index p.ESize)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst2 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (TwoRegs (Scalar (_, Some index), _)), _) ->
    vst2Single ins insLen bld (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst2Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vst3Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm 24 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    bld <+ (mem1 := elem rdList[0] e p.ESize)
    bld <+ (mem2 := elem rdList[1] e p.ESize)
    bld <+ (mem3 := elem rdList[2] e p.ESize)
    bld <+ (addr := incAddr addr (3 * p.EBytes))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst3Single (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  bld <+ (mem1 := elem rdList[0] index p.ESize)
  bld <+ (mem2 := elem rdList[1] index p.ESize)
  bld <+ (mem3 := elem rdList[2] index p.ESize)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst3 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, Some index), _, _)), _) ->
    vst3Single ins insLen bld (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst3Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vst4Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm 32 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    bld <+ (mem1 := elem rdList[0] e p.ESize)
    bld <+ (mem2 := elem rdList[1] e p.ESize)
    bld <+ (mem3 := elem rdList[2] e p.ESize)
    bld <+ (mem4 := elem rdList[3] e p.ESize)
    bld <+ (addr := incAddr addr (4 * p.EBytes))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst4Single (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
  bld <+ (mem1 := elem rdList[0] index p.ESize)
  bld <+ (mem2 := elem rdList[1] index p.ESize)
  bld <+ (mem3 := elem rdList[2] index p.ESize)
  bld <+ (mem4 := elem rdList[3] index p.ESize)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vst4 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, Some index), _, _, _)), _) ->
    vst4Single ins insLen bld (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst4Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vld2SingleOne (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  bld <+ (elem rdList[0] (int32 index) p.ESize := mem1)
  bld <+ (elem rdList[1] (int32 index) p.ESize := mem2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld2SingleAll (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (2 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let repElem1 = Array.replicate p.Elements mem1 |> AST.revConcat
  let repElem2 = Array.replicate p.Elements mem2 |> AST.revConcat
  bld <+ (rdList[0] := repElem1)
  bld <+ (rdList[1] := repElem2)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld2Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let regs = getRegs ins.Operands / 2
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (16 * regs) p.RegIndex)
  for r in 0 .. (regs - 1) do
    let rd1 = rdList[r * 2]
    let rd2 = rdList[r * 2 + 1]
    for e in 0 .. (p.Elements - 1) do
      let mem1 = AST.loadLE p.RtESize addr
      let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
      bld <+ (elem rd1 e p.ESize := mem1)
      bld <+ (elem rd2 e p.ESize := mem2)
      bld <+ (addr := incAddr addr (2 * p.EBytes))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld2 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (TwoRegs (Scalar (_, Some index), _)), _) ->
    vld2SingleOne ins insLen bld index
  | TwoOperands (OprSIMD (TwoRegs (Scalar _, Scalar _)), _) ->
    vld2SingleAll ins insLen bld
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld2Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vld3SingleOne (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  bld <+ (elem rdList[0] (int32 index) p.ESize := mem1)
  bld <+ (elem rdList[1] (int32 index) p.ESize := mem2)
  bld <+ (elem rdList[2] (int32 index) p.ESize := mem3)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld3SingleAll (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (3 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let repElem1 = Array.replicate p.Elements mem1 |> AST.revConcat
  let repElem2 = Array.replicate p.Elements mem2 |> AST.revConcat
  let repElem3 = Array.replicate p.Elements mem3 |> AST.revConcat
  bld <+ (rdList[0] := repElem1)
  bld <+ (rdList[1] := repElem2)
  bld <+ (rdList[2] := repElem3)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld3Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm 24 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    bld <+ (elem rdList[0] e p.ESize := mem1)
    bld <+ (elem rdList[1] e p.ESize := mem2)
    bld <+ (elem rdList[2] e p.ESize := mem3)
    bld <+ (addr := addr .+ (numI32 (3 * p.EBytes) 32<rt>))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld3 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, Some index), _, _)), _) ->
    vld3SingleOne ins insLen bld index
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, None), _, _)), _) ->
    vld3SingleAll ins insLen bld
  | TwoOperands (OprSIMD (ThreeRegs _), _) -> vld3Multi ins insLen bld
  | _ -> raise InvalidOperandException

let vld4SingleOne (ins: InsInfo) insLen bld index =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
  bld <+ (elem rdList[0] (int32 index) p.ESize := mem1)
  bld <+ (elem rdList[1] (int32 index) p.ESize := mem2)
  bld <+ (elem rdList[2] (int32 index) p.ESize := mem3)
  bld <+ (elem rdList[3] (int32 index) p.ESize := mem4)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld4SingleAll (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm (4 * p.EBytes) p.RegIndex)
  let mem1 = AST.loadLE p.RtESize addr
  let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
  let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
  let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
  let repElem1 = Array.replicate p.Elements mem1 |> AST.revConcat
  let repElem2 = Array.replicate p.Elements mem2 |> AST.revConcat
  let repElem3 = Array.replicate p.Elements mem3 |> AST.revConcat
  let repElem4 = Array.replicate p.Elements mem4 |> AST.revConcat
  bld <+ (rdList[0] := repElem1)
  bld <+ (rdList[1] := repElem2)
  bld <+ (rdList[2] := repElem3)
  bld <+ (rdList[3] := repElem4)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld4Multi (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let rdList, rn, rm = parseOprOfVecStAndLd bld ins
  let p = getParsingInfo ins
  let addr = tmpVar bld 32<rt>
  bld <+ (addr := rn)
  bld <+ (rn := updateRn ins rn rm 24 p.RegIndex)
  for e in 0 .. (p.Elements - 1) do
    let mem1 = AST.loadLE p.RtESize addr
    let mem2 = AST.loadLE p.RtESize (incAddr addr p.EBytes)
    let mem3 = AST.loadLE p.RtESize (incAddr addr (2 * p.EBytes))
    let mem4 = AST.loadLE p.RtESize (incAddr addr (3 * p.EBytes))
    bld <+ (elem rdList[0] e p.ESize := mem1)
    bld <+ (elem rdList[1] e p.ESize := mem2)
    bld <+ (elem rdList[2] e p.ESize := mem3)
    bld <+ (elem rdList[3] e p.ESize := mem4)
    bld <+ (addr := addr .+ (numI32 (4 * p.EBytes) 32<rt>))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vld4 (ins: InsInfo) insLen bld =
  match ins.Operands with
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, Some index), _, _, _)), _) ->
    vld4SingleOne ins insLen bld index
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, None), _, _, _)), _) ->
    vld4SingleAll ins insLen bld
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld4Multi ins insLen bld
  | _ -> raise InvalidOperandException

let udf (ins: InsInfo) insLen bld =
  match ins.Operands with
  | OneOperand (OprImm n) -> sideEffects ins insLen bld (Interrupt (int n))
  | _ -> raise InvalidOperandException

let uasx (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let cpsr = regVar bld R.CPSR
  let struct (diff, sum) = tmpVars2 bld 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let struct (ge10, ge32) = tmpVars2 bld 32<rt>
  let numI32 n = numI32 n 32<rt>
  bld <+ (diff := xtlo src1 .- xthi src2)
  bld <+ (sum := xthi src1 .+ xtlo src2)
  bld <+ (dst := AST.concat (AST.xtlo 16<rt> sum) (AST.xtlo 16<rt> diff))
  bld <+ (ge10 := AST.ite (diff .>= numI32 0) (numI32 0xC0000) (numI32 0))
  bld <+ (ge32 := AST.ite (sum .>= numI32 0x10000) (numI32 0x30000) (numI32 0))
  bld <+ (cpsr := (cpsr .& (numI32 0xFFF0FFFF)) .| (ge32 .| ge10))
  putEndLabel bld lblIgnore
  bld --!> insLen

let uhsub16 (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (diff1, diff2) = tmpVars2 bld 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let n1 = AST.num1 32<rt>
  bld <+ (diff1 := xtlo src1 .- xtlo src2)
  bld <+ (diff2 := xthi src1 .- xthi src2)
  bld <+ (dst :=
    AST.concat (AST.xtlo 16<rt> (diff2 >> n1)) (AST.xtlo 16<rt> (diff1 >> n1)))
  putEndLabel bld lblIgnore
  bld --!> insLen

let uqsax (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (sum, diff) = tmpVars2 bld 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  bld <+ (sum := xtlo src1 .+ xthi src2)
  bld <+ (diff := xthi src1 .- xtlo src2)
  bld <+ (dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum))
  putEndLabel bld lblIgnore
  bld --!> insLen

let usax (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let cpsr = regVar bld R.CPSR
  let struct (sum, diff) = tmpVars2 bld 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let struct (ge10, ge32) = tmpVars2 bld 32<rt>
  let numI32 n = numI32 n 32<rt>
  bld <+ (sum := xtlo src1 .+ xthi src2)
  bld <+ (diff := xthi src1 .- xtlo src2)
  bld <+ (dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum))
  bld <+ (ge10 := AST.ite (sum .>= numI32 0x10000) (numI32 0x30000) (numI32 0))
  bld <+ (ge32 := AST.ite (diff .>= numI32 0) (numI32 0xC0000) (numI32 0))
  bld <+ (cpsr := (cpsr .& (numI32 0xFFF0FFFF)) .| (ge10 .| ge32))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vext (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let struct (dst, src1, src2, imm) = getFourOprs ins
  let imm = getImmValue imm
  let rightAmt = numI64 ((8L * imm) % 64L) 64<rt>
  let leftAmt = numI64 (64L - ((8L * imm) % 64L)) 64<rt>
  match ins.OprSize with
  | 128<rt> ->
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    let struct (tSrc1B, tSrc1A, tSrc2B, tSrc2A) = tmpVars4 bld 64<rt>
    bld <+ (tSrc1A := src1A)
    bld <+ (tSrc1B := src1B)
    bld <+ (tSrc2A := src2A)
    bld <+ (tSrc2B := src2B)
    if 8L * imm < 64 then
      bld <+ (dstA := (tSrc1B << leftAmt) .| (tSrc1A >> rightAmt))
      bld <+ (dstB := (tSrc2A << leftAmt) .| (tSrc1B >> rightAmt))
    else
      bld <+ (dstA := (tSrc2A << leftAmt) .| (tSrc1B >> rightAmt))
      bld <+ (dstB := (tSrc2B << leftAmt) .| (tSrc2A >> rightAmt))
  | _ ->
    let struct (dst, src1, src2, _imm) = transFourOprs ins bld
    let struct (tSrc2, tSrc1) = tmpVars2 bld 64<rt>
    bld <+ (tSrc1 := src1)
    bld <+ (tSrc2 := src2)
    bld <+ (dst := (tSrc2 << leftAmt) .| (tSrc1 >> rightAmt))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vhaddsub (ins: InsInfo) insLen bld opFn =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    let struct (op1B, op2B, op1A, op2A) = tmpVars4 bld p.RtESize
    for e in 0 .. p.Elements - 1 do
      bld <+ (op1B := elem src1B e p.ESize)
      bld <+ (op2B := elem src2B e p.ESize)
      bld <+ (op1A := elem src1A e p.ESize)
      bld <+ (op2A := elem src2A e p.ESize)
      bld <+ (elem dstB e p.ESize := (opFn op1B op2B) >> (AST.num1 p.RtESize))
      bld <+ (elem dstA e p.ESize := (opFn op1A op2A) >> (AST.num1 p.RtESize))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (op1, op2) = tmpVars2 bld p.RtESize
    for e in 0 .. p.Elements - 1 do
      bld <+ (op1 := elem src1 e p.ESize)
      bld <+ (op2 := elem src2 e p.ESize)
      bld <+ (elem dst e p.ESize := (opFn op1 op2) >> (AST.num1 p.RtESize))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vrhadd (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let struct (op1, op2) = tmpVars2 bld p.RtESize
  let n1 = AST.num1 p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (src1B, src1A) = transOprToExpr128 bld src1
    let struct (src2B, src2A) = transOprToExpr128 bld src2
    for e in 0 .. (64 / p.ESize) - 1 do
      bld <+ (op1 := elem src1B e p.ESize .+ elem src2B e p.ESize .+ n1)
      bld <+ (op2 := elem src1A e p.ESize .+ elem src2A e p.ESize .+ n1)
      bld <+ (elem dstB e p.ESize := AST.xtlo p.RtESize (op1 >> n1))
      bld <+ (elem dstA e p.ESize := AST.xtlo p.RtESize (op2 >> n1))
  | _ ->
    let struct (dst, src1, src2) = transThreeOprs ins bld
    for e in 0 .. (64 / p.ESize) - 1 do
      bld <+ (op1 := elem src1 e p.ESize)
      bld <+ (op2 := elem src2 e p.ESize)
      let result = op1 .+ op2 .+ n1
      bld <+ (elem dst e p.ESize := AST.xtlo p.RtESize (result >> n1))
  putEndLabel bld lblIgnore
  bld --!> insLen

let vsra (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let struct (result1, result2, shfAmt) = tmpVars3 bld p.RtESize
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src, imm) = getThreeOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    let imm = transOprToExpr ins bld imm
    bld <+ (shfAmt := if p.RtESize = 64<rt> then AST.zext p.RtESize imm
                    else AST.xtlo p.RtESize imm)
    for e in 0 .. p.Elements - 1 do
      bld <+ (result1 := srcB >> shfAmt)
      bld <+ (result2 := srcA >> shfAmt)
      bld <+ (dstB := dstB .+ result1)
      bld <+ (dstA := dstA .+ result2)
  | _ ->
    let struct (dst, src, imm) = transThreeOprs ins bld
    bld <+ (shfAmt := if p.RtESize = 64<rt> then AST.zext p.RtESize imm
                    else AST.xtlo p.RtESize imm)
    for e in 0 .. p.Elements - 1 do
      bld <+ (result1 := src >> shfAmt)
      bld <+ (dst := dst .+ result1)
  putEndLabel bld lblIgnore
  bld --!> insLen

let vuzp (ins: InsInfo) insLen bld =
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  bld <!-- (ins.Address, insLen)
  let lblIgnore = checkCondition ins bld isUnconditional
  let p = getParsingInfo ins
  let struct (zip1B, zip1A, zip2B, zip2A) = tmpVars4 bld 64<rt>
  let elements = (p.Elements - 1) / 2
  match ins.OprSize with
  | 128<rt> ->
    let struct (dst, src) = getTwoOprs ins
    let struct (dstB, dstA) = transOprToExpr128 bld dst
    let struct (srcB, srcA) = transOprToExpr128 bld src
    if dstB = srcB && dstA = srcA then
      bld <+ (dstB := AST.undef 64<rt> "UNKNOWN")
      bld <+ (dstA := AST.undef 64<rt> "UNKNOWN")
      bld <+ (srcB := AST.undef 64<rt> "UNKNOWN")
      bld <+ (srcA := AST.undef 64<rt> "UNKNOWN")
    else
      bld <+ (zip1B := srcB)
      bld <+ (zip1A := srcA)
      bld <+ (zip2B := dstB)
      bld <+ (zip2A := dstA)
      for e in 0 .. elements do
        let pos = e + p.Elements / 2
        bld <+ (elem dstB pos p.ESize := elem zip1B (e * 2) p.ESize)
        bld <+ (elem srcB pos p.ESize := elem zip1B (e * 2 + 1) p.ESize)
        bld <+ (elem dstB e p.ESize := elem zip1A (e * 2) p.ESize)
        bld <+ (elem srcB e p.ESize := elem zip1A (e * 2 + 1) p.ESize)
        bld <+ (elem dstA pos p.ESize := elem zip2B (e * 2) p.ESize)
        bld <+ (elem srcA pos p.ESize := elem zip2B (e * 2 + 1) p.ESize)
        bld <+ (elem dstA e p.ESize := elem zip2A (e * 2) p.ESize)
        bld <+ (elem srcA e p.ESize := elem zip2A (e * 2 + 1) p.ESize)
  | _ ->
    let struct (dst, src) = transTwoOprs ins bld
    if dst = src then
      bld <+ (dst := AST.undef ins.OprSize "UNKNOWN")
      bld <+ (src := AST.undef ins.OprSize "UNKNOWN")
    else
      bld <+ (zip1B := src)
      bld <+ (zip1A := dst)
      for e in 0 .. elements do
        let pos = e + p.Elements / 2
        bld <+ (elem dst e p.ESize := elem zip1B (e * 2) p.ESize)
        bld <+ (elem src e p.ESize := elem zip1B (e * 2 + 1) p.ESize)
        bld <+ (elem dst pos p.ESize := elem zip1A (e * 2) p.ESize)
        bld <+ (elem src pos p.ESize := elem zip1A (e * 2 + 1) p.ESize)
  putEndLabel bld lblIgnore
  bld --!> insLen

/// Translate IR.
let translate (ins: ARM32InternalInstruction) insLen bld =
  match ins.Opcode with
  | Op.ADC -> adc false ins insLen bld
  | Op.ADCS -> adcs true ins insLen bld
  | Op.ADD | Op.ADDW -> add false ins insLen bld
  | Op.ADDS -> adds true ins insLen bld
  | Op.ADR -> adr ins insLen bld // for Thumb mode
  | Op.AND -> logicalAnd false ins insLen bld
  | Op.ANDS -> ands true ins insLen bld
  | Op.ASR -> shiftInstr false ins insLen SRTypeASR bld
  | Op.ASRS -> asrs true ins insLen bld
  | Op.B -> b ins insLen bld
  | Op.BFC -> bfc ins insLen bld
  | Op.BFI -> bfi ins insLen bld
  | Op.BIC -> bic false ins insLen bld
  | Op.BICS -> bics true ins insLen bld
  | Op.BKPT -> sideEffects ins insLen bld Breakpoint
  | Op.BL -> bl ins insLen bld
  | Op.BLX -> branchWithLink ins insLen bld
  | Op.BX -> bx ins insLen bld
  | Op.BXJ -> bx ins insLen bld
  | Op.CBNZ -> cbz true ins insLen bld
  | Op.CBZ -> cbz false ins insLen bld
  | Op.CDP | Op.CDP2 | Op.LDC | Op.LDC2 | Op.LDC2L | Op.LDCL | Op.MCR | Op.MCR2
  | Op.MCRR | Op.MCRR2 | Op.MRC | Op.MRC2 | Op.MRRC | Op.MRRC2 | Op.STC
  | Op.STC2 | Op.STC2L | Op.STCL ->
    (* coprocessor instructions *)
    sideEffects ins insLen bld UnsupportedExtension
  | Op.CLZ -> clz ins insLen bld
  | Op.CMN -> cmn ins insLen bld
  | Op.CMP -> cmp ins insLen bld
  | Op.DMB | Op.DSB | Op.ISB | Op.PLD -> nop ins insLen bld
  | Op.EOR -> eor false ins insLen bld
  | Op.EORS -> eors true ins insLen bld
  | Op.ERET -> sideEffects ins insLen bld UnsupportedExtension
  | Op.IT | Op.ITT | Op.ITE | Op.ITTT | Op.ITET | Op.ITTE | Op.ITEE | Op.ITTTT
  | Op.ITETT | Op.ITTET | Op.ITEET | Op.ITTTE | Op.ITETE | Op.ITTEE
  | Op.ITEEE -> it ins insLen bld
  | Op.LDM -> ldm Op.LDM ins insLen bld (.+)
  | Op.LDMDA -> ldm Op.LDMDA ins insLen bld (.-)
  | Op.LDMDB -> ldm Op.LDMDB ins insLen bld (.-)
  | Op.LDMIA -> ldm Op.LDMIA ins insLen bld (.+)
  | Op.LDMIB -> ldm Op.LDMIB ins insLen bld (.+)
  | Op.LDR -> ldr ins insLen bld 32<rt> AST.zext
  | Op.LDRB -> ldr ins insLen bld 8<rt> AST.zext
  | Op.LDRBT -> ldr ins insLen bld 8<rt> AST.zext
  | Op.LDRD -> ldrd ins insLen bld
  | Op.LDREX -> ldr ins insLen bld 32<rt> AST.zext
  | Op.LDRH -> ldr ins insLen bld 16<rt> AST.zext
  | Op.LDRHT -> ldr ins insLen bld 16<rt> AST.zext
  | Op.LDRSB -> ldr ins insLen bld 8<rt> AST.sext
  | Op.LDRSBT -> ldr ins insLen bld 8<rt> AST.sext
  | Op.LDRSH -> ldr ins insLen bld 16<rt> AST.sext
  | Op.LDRSHT -> ldr ins insLen bld 16<rt> AST.sext
  | Op.LDRT -> ldr ins insLen bld 32<rt> AST.zext
  | Op.LSL -> shiftInstr false ins insLen SRTypeLSL bld
  | Op.LSLS -> lsls true ins insLen bld
  | Op.LSR -> shiftInstr false ins insLen SRTypeLSR bld
  | Op.LSRS -> lsrs true ins insLen bld
  | Op.MLA -> mla false ins insLen bld
  | Op.MLAS -> mla true ins insLen bld
  | Op.MLS -> mls ins insLen bld
  | Op.MOV | Op.MOVW -> mov false ins insLen bld
  | Op.MOVS -> movs true ins insLen bld
  | Op.MOVT -> movt ins insLen bld
  | Op.MSR | Op.MRS -> sideEffects ins insLen bld UndefinedInstr
  | Op.MUL -> mul false ins insLen bld
  | Op.MULS -> mul true ins insLen bld
  | Op.MVN -> mvn false ins insLen bld
  | Op.MVNS -> mvns true ins insLen bld
  | Op.NOP -> nop ins insLen bld
  | Op.ORN -> orn false ins insLen bld
  | Op.ORNS -> orns true ins insLen bld
  | Op.ORR -> orr false ins insLen bld
  | Op.ORRS -> orrs true ins insLen bld
  | Op.PKHBT -> pkh ins insLen bld false
  | Op.PKHTB -> pkh ins insLen bld true
  | Op.POP -> pop ins insLen bld
  | Op.PUSH -> push ins insLen bld
  | Op.QDADD -> qdadd ins insLen bld
  | Op.QDSUB -> qdsub ins insLen bld
  | Op.QSAX -> qsax ins insLen bld
  | Op.QSUB16 -> qsub16 ins insLen bld
  | Op.RBIT -> rbit ins insLen bld
  | Op.REV -> rev ins insLen bld
  | Op.REV16 -> rev16 ins insLen bld
  | Op.REVSH -> revsh ins insLen bld
  | Op.RFEDB -> rfedb ins insLen bld
  | Op.ROR -> shiftInstr false ins insLen SRTypeROR bld
  | Op.RORS -> rors true ins insLen bld
  | Op.RRX -> shiftInstr false ins insLen SRTypeRRX bld
  | Op.RRXS -> rrxs true ins insLen bld
  | Op.RSB -> rsb false ins insLen bld
  | Op.RSBS -> rsbs true ins insLen bld
  | Op.RSC -> rsc false ins insLen bld
  | Op.RSCS -> rscs true ins insLen bld
  | Op.SBC -> sbc false ins insLen bld
  | Op.SBCS -> sbcs true ins insLen bld
  | Op.SBFX -> bfx ins insLen bld true
  | Op.SEL -> sel ins insLen bld
  | Op.SMLABB -> smulacchalf ins insLen bld false false
  | Op.SMLABT -> smulacchalf ins insLen bld false true
  | Op.SMLAL -> smulandacc false true ins insLen bld
  | Op.SMLALS -> smulandacc true true ins insLen bld
  | Op.SMLATB -> smulacchalf ins insLen bld true false
  | Op.SMLATT -> smulacchalf ins insLen bld true true
  | Op.SMLALBT -> smulacclonghalf ins insLen bld false true
  | Op.SMLALTT -> smulacclonghalf ins insLen bld true true
  | Op.SMLALD -> smulacclongdual ins insLen bld false
  | Op.SMLALDX -> smulacclongdual ins insLen bld true
  | Op.SMLAWB -> smulaccwordbyhalf ins insLen bld false
  | Op.SMLAWT -> smulaccwordbyhalf ins insLen bld true
  | Op.SMMLA -> smmla ins insLen bld false
  | Op.SMMLAR -> smmla ins insLen bld true
  | Op.SMMUL -> smmul ins insLen bld false
  | Op.SMMULR -> smmul ins insLen bld true
  | Op.SMULBB -> smulhalf ins insLen bld false false
  | Op.SMULBT -> smulhalf ins insLen bld false true
  | Op.SMULL -> smulandacc false false ins insLen bld
  | Op.SMULLS -> smulandacc true false ins insLen bld
  | Op.SMULTB -> smulhalf ins insLen bld true false
  | Op.SMULTT -> smulhalf ins insLen bld true true
  | Op.STM -> stm Op.STM ins insLen bld (.+)
  | Op.STMDA -> stm Op.STMDA ins insLen bld (.-)
  | Op.STMDB -> stm Op.STMDB ins insLen bld (.-)
  | Op.STMEA -> stm Op.STMIA ins insLen bld (.+)
  | Op.STMIA -> stm Op.STMIA ins insLen bld (.+)
  | Op.STMIB -> stm Op.STMIB ins insLen bld (.+)
  | Op.STR -> str ins insLen bld 32<rt>
  | Op.STRB -> str ins insLen bld 8<rt>
  | Op.STRBT -> str ins insLen bld 8<rt>
  | Op.STRD -> strd ins insLen bld
  | Op.STREX -> strex ins insLen bld
  | Op.STRH -> str ins insLen bld 16<rt>
  | Op.STRHT -> str ins insLen bld 16<rt>
  | Op.STRT -> str ins insLen bld 32<rt>
  | Op.SUB | Op.SUBW -> sub false ins insLen bld
  | Op.SUBS -> subs true ins insLen bld
  | Op.SVC -> svc ins insLen bld
  | Op.SXTB -> extend ins insLen bld AST.sext 8<rt>
  | Op.SXTH -> extend ins insLen bld AST.sext 16<rt>
  | Op.TBH | Op.TBB -> tableBranch ins insLen bld
  | Op.TEQ -> teq ins insLen bld
  | Op.TST -> tst ins insLen bld
  | Op.UADD8 -> uadd8 ins insLen bld
  | Op.UASX -> uasx ins insLen bld
  | Op.UBFX -> bfx ins insLen bld false
  | Op.UDF -> udf ins insLen bld
  | Op.UHSUB16 -> uhsub16 ins insLen bld
  | Op.UMAAL -> umaal ins insLen bld
  | Op.UMLAL -> umlal false ins insLen bld
  | Op.UMLALS -> umlal true ins insLen bld
  | Op.UMULL -> umull false ins insLen bld
  | Op.UMULLS -> umull true ins insLen bld
  | Op.UQADD16 -> uqopr ins insLen bld 16 (.+)
  | Op.UQADD8 -> uqopr ins insLen bld 8 (.+)
  | Op.UQSAX -> uqsax ins insLen bld
  | Op.UQSUB16 -> uqopr ins insLen bld 16 (.-)
  | Op.UQSUB8 -> uqopr ins insLen bld 8 (.-)
  | Op.USAX -> usax ins insLen bld
  | Op.UXTAB -> extendAndAdd ins insLen bld 8<rt>
  | Op.UXTAH -> extendAndAdd ins insLen bld 16<rt>
  | Op.UXTB -> extend ins insLen bld AST.zext 8<rt>
  | Op.UXTB16 -> uxtb16 ins insLen bld
  | Op.UXTH -> extend ins insLen bld AST.zext 16<rt>
  | Op.VABS when isF16orF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedFP
  | Op.VABS -> vabs ins insLen bld
  | Op.VADD when isF16orF32orF64 ins.SIMDTyp -> vaddsub ins insLen bld AST.fadd
  | Op.VADD -> vaddsub ins insLen bld (.+)
  | Op.VADDL -> vaddl ins insLen bld
  | Op.VAND -> vand ins insLen bld
  | Op.VCEQ | Op.VCGE | Op.VCGT | Op.VCLE | Op.VCLT
    when isF32orF64 ins.SIMDTyp -> sideEffects ins insLen bld UnsupportedFP
  | Op.VCEQ -> vceq ins insLen bld
  | Op.VCGE -> vcge ins insLen bld
  | Op.VCGT -> vcgt ins insLen bld
  | Op.VCLE -> vcle ins insLen bld
  | Op.VCLT -> vclt ins insLen bld
  | Op.VCLZ -> vclz ins insLen bld
  | Op.VCMLA -> sideEffects ins insLen bld UnsupportedFP
  | Op.VCMP | Op.VCMPE | Op.VACGE | Op.VACGT | Op.VACLE | Op.VACLT | Op.VCVTR
  | Op.VFMA | Op.VFMS | Op.VFNMA | Op.VFNMS | Op.VMSR | Op.VNMLA | Op.VNMLS
  | Op.VNMUL | Op.VSQRT -> sideEffects ins insLen bld UnsupportedFP
  | Op.VCVT -> vcvt ins insLen bld
  | Op.VDIV -> vdiv ins insLen bld
  | Op.VDUP -> vdup ins insLen bld
  | Op.VEXT -> vext ins insLen bld
  | Op.VHADD -> vhaddsub ins insLen bld (.+)
  | Op.VHSUB -> vhaddsub ins insLen bld (.-)
  | Op.VLD1 -> vld1 ins insLen bld
  | Op.VLD2 -> vld2 ins insLen bld
  | Op.VLD3 -> vld3 ins insLen bld
  | Op.VLD4 -> vld4 ins insLen bld
  | Op.VLDM | Op.VLDMIA | Op.VLDMDB -> vldm ins insLen bld
  | Op.VLDR -> vldr ins insLen bld
  | Op.VMAX | Op.VMIN when isF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedFP
  | Op.VMAX -> vmaxmin ins insLen bld true
  | Op.VMIN -> vmaxmin ins insLen bld false
  | Op.VMLA | Op.VMLS when isF16orF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedFP
  | Op.VMLA -> vmla ins insLen bld
  | Op.VMLAL -> vmlal ins insLen bld
  | Op.VMLS -> vmls ins insLen bld
  | Op.VMLSL -> vmlsl ins insLen bld
  | Op.VMOV when isF16orF32orF64 ins.SIMDTyp -> vmovfp ins insLen bld
  | Op.VMOV -> vmov ins insLen bld
  | Op.VMOVN -> vmovn ins insLen bld
  | Op.VMRS -> vmrs ins insLen bld
  | Op.VMUL when isF16orF32orF64 ins.SIMDTyp -> vmul ins insLen bld AST.fmul
  | Op.VMUL -> vmul ins insLen bld (.*)
  | Op.VMULL -> vmull ins insLen bld
  | Op.VNEG when isF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedFP
  | Op.VNEG -> vneg ins insLen bld
  | Op.VORN -> vorn ins insLen bld
  | Op.VORR -> vorr ins insLen bld
  | Op.VPADD when isF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedFP
  | Op.VPADD -> vpadd ins insLen bld
  | Op.VPOP -> vpop ins insLen bld
  | Op.VPUSH -> vpush ins insLen bld
  | Op.VRHADD -> vrhadd ins insLen bld
  | Op.VRINTP -> sideEffects ins insLen bld UnsupportedFP
  | Op.VRSHR -> vrshr ins insLen bld
  | Op.VRSHRN -> vrshrn ins insLen bld
  | Op.VSHL -> vshl ins insLen bld
  | Op.VSHR -> vshr ins insLen bld
  | Op.VSRA -> vsra ins insLen bld
  | Op.VST1 -> vst1 ins insLen bld
  | Op.VST2 -> vst2 ins insLen bld
  | Op.VST3 -> vst3 ins insLen bld
  | Op.VST4 -> vst4 ins insLen bld
  | Op.VSTM | Op.VSTMIA | Op.VSTMDB -> vstm ins insLen bld
  | Op.VSTR -> vstr ins insLen bld
  | Op.VSUB when isF16orF32orF64 ins.SIMDTyp ->
    vaddsub ins insLen bld AST.fsub
  | Op.VSUB -> vaddsub ins insLen bld (.-)
  | Op.VTBL -> vecTbl ins insLen bld true
  | Op.VTBX -> vecTbl ins insLen bld false
  | Op.VTST -> vtst ins insLen bld
  | Op.VUZP -> vuzp ins insLen bld
  | Op.InvalidOP -> raise InvalidOpcodeException
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
