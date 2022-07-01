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

let inline private (<!) (builder: IRBuilder) (s) = builder.Append (s)

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

let transOprToExpr ctxt = function
  | OprSpecReg (reg, _)
  | OprReg reg -> getRegVar ctxt reg
  | OprRegList regs -> regsToExpr regs
  | OprSIMD simd -> simdToExpr ctxt simd
  | OprImm imm -> numI64 imm 32<rt> // FIXME
  | _ -> raise InvalidOperandException

let transOneOpr (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand opr -> transOprToExpr ctxt opr
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (opr1, opr2) -> transOprToExpr ctxt opr1,
                                transOprToExpr ctxt opr2
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, opr3) -> transOprToExpr ctxt opr1,
                                        transOprToExpr ctxt opr2,
                                        transOprToExpr ctxt opr3
  | _ -> raise InvalidOperandException

let transFourOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> transOprToExpr ctxt o1,
                                     transOprToExpr ctxt o2,
                                     transOprToExpr ctxt o3,
                                     transOprToExpr ctxt o4
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
  | PSR_Cond -> psr .| maskPSRForCondbits
  | PSR_N -> psr .| maskPSRForNbit
  | PSR_Z -> psr .| maskPSRForZbit
  | PSR_C -> psr .| maskPSRForCbit
  | PSR_V -> psr .| maskPSRForVbit
  | PSR_Q -> psr .| maskPSRForQbit
  | PSR_IT10 -> psr .| maskPSRForIT10bits
  | PSR_J -> psr .| maskPSRForJbit
  | PSR_GE -> psr .| maskPSRForGEbits
  | PSR_IT72 -> psr .| maskPSRForIT72bits
  | PSR_E -> psr .| maskPSRForEbit
  | PSR_A -> psr .| maskPSRForAbit
  | PSR_I -> psr .| maskPSRForIbit
  | PSR_F -> psr .| maskPSRForFbit
  | PSR_T -> psr .| maskPSRForTbit
  | PSR_M -> psr .| maskPSRForMbits

let disablePSRBits ctxt reg psrType =
  let psr = getRegVar ctxt reg
  match psrType with
  | PSR_Cond -> psr .& AST.not maskPSRForCondbits
  | PSR_N -> psr .& AST.not maskPSRForNbit
  | PSR_Z -> psr .& AST.not maskPSRForZbit
  | PSR_C -> psr .& AST.not maskPSRForCbit
  | PSR_V -> psr .& AST.not maskPSRForVbit
  | PSR_Q -> psr .& AST.not maskPSRForQbit
  | PSR_IT10 -> psr .& AST.not maskPSRForIT10bits
  | PSR_J -> psr .& AST.not maskPSRForJbit
  | PSR_GE -> psr .& AST.not maskPSRForGEbits
  | PSR_IT72 -> psr .& AST.not maskPSRForIT72bits
  | PSR_E -> psr .& AST.not maskPSRForEbit
  | PSR_A -> psr .& AST.not maskPSRForAbit
  | PSR_I -> psr .& AST.not maskPSRForIbit
  | PSR_F -> psr .& AST.not maskPSRForFbit
  | PSR_T -> psr .& AST.not maskPSRForTbit
  | PSR_M -> psr .& AST.not maskPSRForMbits

let setPSR ctxt reg psrType expr =
  let shift expr =
    match psrType with
    | PSR_Cond -> expr << (numI32 28 32<rt>)
    | PSR_N -> expr << (numI32 31 32<rt>)
    | PSR_Z -> expr << (numI32 30 32<rt>)
    | PSR_C -> expr << (numI32 29 32<rt>)
    | PSR_V -> expr << (numI32 28 32<rt>)
    | PSR_Q -> expr << (numI32 27 32<rt>)
    | PSR_IT10 -> expr << (numI32 25 32<rt>)
    | PSR_J -> expr << (numI32 24 32<rt>)
    | PSR_GE -> expr << (numI32 16 32<rt>)
    | PSR_IT72 -> expr << (numI32 10 32<rt>)
    | PSR_E -> expr << (numI32 9 32<rt>)
    | PSR_A -> expr << (numI32 8 32<rt>)
    | PSR_I -> expr << (numI32 7 32<rt>)
    | PSR_F -> expr << (numI32 6 32<rt>)
    | PSR_T -> expr << (numI32 5 32<rt>)
    | PSR_M -> expr
  disablePSRBits ctxt reg psrType .| (AST.zext 32<rt> expr |> shift)

let getCarryFlag ctxt =
  getPSR ctxt R.CPSR PSR_C >> (numI32 29 32<rt>)

let getZeroMask maskSize regType =
  BitVector.OfBInt (BigInteger.getMask maskSize) regType
  |> BitVector.BNot |> AST.num

let zMaskAnd e regType maskSize =
  e .& (getZeroMask maskSize regType)

let maskAndOR e1 e2 regType maskSize =
  let mask = getZeroMask maskSize regType
  let expr = e1 .& mask
  expr .| e2

let getOverflowFlagOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  (e1High == e2High) .& (e1High <+> rHigh)

let parseCond = function
  | Condition.EQ -> 0b000, 0
  | Condition.NE -> 0b000, 1
  | Condition.CS -> 0b001, 0
  | Condition.CC -> 0b001, 1
  | Condition.MI -> 0b010, 0
  | Condition.PL -> 0b010, 1
  | Condition.VS -> 0b011, 0
  | Condition.VC -> 0b011, 1
  | Condition.HI -> 0b100, 0
  | Condition.LS -> 0b100, 1
  | Condition.GE -> 0b101, 0
  | Condition.LT -> 0b101, 1
  | Condition.GT -> 0b110, 0
  | Condition.LE -> 0b110, 1
  | Condition.AL -> 0b111, 0
  | Condition.UN -> 0b111, 1
  | _ -> raise InvalidOperandException

/// Returns TRUE if the current instruction needs to be executed. See page
/// A8-289. function : ConditionPassed()
let conditionPassed ctxt cond =
  let cond1, cond2 = parseCond cond
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
let addWithCarry src1 src2 carryIn =
  let result = src1 .+ src2 .+ carryIn
  let carryOut =
    AST.ite (carryIn == (numU32 1u 32<rt>))
      (AST.ge src1 (AST.not src2)) (AST.gt src1 (AST.not src2))
  let overflow = getOverflowFlagOnAdd src1 src2 result
  result, carryOut, overflow

/// Sets the ARM instruction set, on page A2-51.
let selectARMInstrSet ctxt (builder: IRBuilder) =
  let cpsr = getRegVar ctxt R.CPSR
  builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_J)
  builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_T)

/// Sets the ARM instruction set, on page A2-51.
let selectThumbInstrSet ctxt (builder: IRBuilder) =
  let cpsr = getRegVar ctxt R.CPSR
  builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_J)
  builder <! (cpsr := enablePSRBits ctxt R.CPSR PSR_T)

/// Sets the instruction set currently in use, on page A2-51.
/// SelectInstrSet()
let selectInstrSet ctxt builder = function
  | ArchOperationMode.ARMMode -> selectARMInstrSet ctxt builder
  | _ -> selectThumbInstrSet ctxt builder

/// Write value to R.PC, without interworking, on page A2-47.
/// function : BranchWritePC()
let branchWritePC ctxt (ins: InsInfo) addr jmpInfo =
  let addr = zMaskAnd addr 32<rt> 1
  match ins.Mode with
  | ArchOperationMode.ARMMode -> AST.interjmp addr jmpInfo
  | _ -> AST.interjmp addr jmpInfo

let disableITStateForCondBranches ctxt isUnconditional (builder: IRBuilder) =
  if isUnconditional then ()
  else
    let cpsr = getRegVar ctxt R.CPSR
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_IT10)
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_IT72)

/// Write value to R.PC, with interworking, on page A2-47.
/// function : BXWritePC()
let bxWritePC ctxt isUnconditional addr (builder: IRBuilder) =
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let cond1 = AST.xtlo 1<rt> addr == AST.b1
  disableITStateForCondBranches ctxt isUnconditional builder
  builder <! (AST.cjmp cond1 (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  selectThumbInstrSet ctxt builder
  builder <! (AST.interjmp (zMaskAnd addr 32<rt> 1) InterJmpKind.SwitchToThumb)
  builder <! (AST.lmark lblL1)
  selectARMInstrSet ctxt builder
  builder <! (AST.interjmp addr InterJmpKind.SwitchToARM)

/// Write value to R.PC, with interworking for ARM only from ARMv7 on page
/// A2-47. function : ALUWritePC()
let aluWritePC ctxt (ins: InsInfo) isUnconditional addr builder =
  match ins.Mode with
  | ArchOperationMode.ARMMode -> bxWritePC ctxt isUnconditional addr builder
  | _ -> builder <! branchWritePC ctxt ins addr InterJmpKind.Base

/// Write value to R.PC, with interworking (without it before ARMv5T),
/// on page A2-47. function : LoadWritePC()
let loadWritePC ctxt isUnconditional builder result =
  bxWritePC ctxt isUnconditional result builder

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
let memAWithPriv addr size value = AST.b0  // FIXME

/// OprMemory access that must be aligned, at current privilege level,
/// on page B2-1294. function : MemA_with_priv[]
let memA addr size value = memAWithPriv addr size value

/// OprMemory access that must be aligned, at specified privilege level,
/// on page B2-1294. function : MemU_with_priv[]
let memUWithPriv addr size value = AST.b0  // FIXME

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
  (getPSR ctxt R.CPSR PSR_M == (numI32 0b10110 32<rt>))

/// Return TRUE if current mode is executes at PL1 or higher, on page B1-1142.
/// function : CurrentModeIsNotUser()
let currentModeIsNotUser ctxt =
  let modeM = getPSR ctxt R.CPSR PSR_M
  let modeCond = isBadMode modeM
  let ite1 =
    AST.ite (modeM == (numI32 0b10000 32<rt>))
            AST.b0 AST.b1
  AST.ite modeCond (AST.undef 1<rt> "UNPREDICTABLE") ite1

/// Bitstring replication, on page AppxP-2652.
/// function : Replicate()
let replicate expr regType lsb width value =
  let v = BitVector.OfBInt (BigInteger.getMask width <<< lsb) regType
  if value = 0 then expr .& (v |> BitVector.BNot |> AST.num)
  else expr .| (v |> AST.num)

/// All-ones bitstring, on page AppxP-2652.
let ones rt = BitVector.OfBInt (RegType.getMask rt) rt |> AST.num

let writeModeBits ctxt value isExcptReturn (builder: IRBuilder) =
  let lblL8 = builder.NewSymbol "L8"
  let lblL9 = builder.NewSymbol "L9"
  let lblL10 = builder.NewSymbol "L10"
  let lblL11 = builder.NewSymbol "L11"
  let lblL12 = builder.NewSymbol "L12"
  let lblL13 = builder.NewSymbol "L13"
  let lblL14 = builder.NewSymbol "L14"
  let lblL15 = builder.NewSymbol "L15"
  let lblL16 = builder.NewSymbol "L16"
  let lblL17 = builder.NewSymbol "L17"
  let valueM = value .& maskPSRForMbits
  let cpsrM = getPSR ctxt R.CPSR PSR_M
  let num11010 = numI32 0b11010 32<rt>
  let chkSecure = AST.not (isSecure ctxt)
  let cond1 = chkSecure .& (valueM == (numI32 0b10110 32<rt>))
  let cond2 = chkSecure .& isSetNSACRForRFR ctxt .&
              (valueM == (numI32 0b10001 32<rt>))
  let cond3 = chkSecure .& (valueM == num11010)
  let cond4 = chkSecure .& (cpsrM != num11010) .& (valueM == num11010)
  let cond5 = (cpsrM == num11010) .& (valueM != num11010)
  builder <! (AST.cjmp cond1 (AST.name lblL8) (AST.name lblL9))
  builder <! (AST.lmark lblL8)
  builder <! (AST.sideEffect UndefinedInstr)  // FIXME: (use UNPREDICTABLE)
  builder <! (AST.lmark lblL9)
  builder <! (AST.cjmp cond2 (AST.name lblL10) (AST.name lblL11))
  builder <! (AST.lmark lblL10)
  builder <! (AST.sideEffect UndefinedInstr)  // FIXME: (use UNPREDICTABLE)
  builder <! (AST.lmark lblL11)
  builder <! (AST.cjmp cond3 (AST.name lblL12) (AST.name lblL13))
  builder <! (AST.lmark lblL12)
  builder <! (AST.sideEffect UndefinedInstr)  // FIXME: (use UNPREDICTABLE)
  builder <! (AST.lmark lblL13)
  builder <! (AST.cjmp cond4 (AST.name lblL14) (AST.name lblL15))
  builder <! (AST.lmark lblL14)
  builder <! (AST.sideEffect UndefinedInstr)  // FIXME: (use UNPREDICTABLE)
  builder <! (AST.lmark lblL15)
  builder <! (AST.cjmp cond5 (AST.name lblL16) (AST.name lblL17))
  builder <! (AST.lmark lblL16)
  if Operators.not isExcptReturn then
    builder <! (AST.sideEffect UndefinedInstr)  // FIXME: (use UNPREDICTABLE)
  else ()
  builder <! (AST.lmark lblL17)
  let mValue = value .& maskPSRForMbits
  builder <!
    (getRegVar ctxt R.CPSR := disablePSRBits ctxt R.CPSR PSR_M .| mValue)

/// R.CPSR write by an instruction, on page B1-1152.
/// function : CPSRWriteByInstr()
let cpsrWriteByInstr ctxt value bytemask isExcptReturn (builder: IRBuilder) =
  let cpsr = getRegVar ctxt R.CPSR
  let privileged = currentModeIsNotUser ctxt
  if bytemask &&& 0b1000 = 0b1000 then
    let nzcvValue = value .& maskPSRForCondbits
    let qValue = value .& maskPSRForQbit
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_Cond .| nzcvValue)
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_Q .| qValue)
    if isExcptReturn then
      let itValue = value .& maskPSRForIT10bits
      let jValue = value .& maskPSRForJbit
      builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_IT10 .| itValue)
      builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_J .| jValue)
    else ()
  else ()

  if bytemask &&& 0b0100 = 0b0100 then
    let geValue = value .& maskPSRForGEbits
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_GE .| geValue)
  else ()

  if bytemask &&& 0b0010 = 0b0010 then
    let lblL0 = builder.NewSymbol "cpsrWriteByInstrL0"
    let lblL1 = builder.NewSymbol "cpsrWriteByInstrL1"
    if isExcptReturn then
      let itValue = value .& maskPSRForIT72bits
      builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_IT72 .| itValue)
    else ()
    let eValue = value .& maskPSRForEbit
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_E .| eValue)
    let cond =
      privileged .& (isSecure ctxt .| isSetSCRForAW ctxt .| haveVirtExt ())
    builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    builder <! (AST.lmark lblL0)
    let aValue = value .& maskPSRForAbit
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_A .| aValue)
    builder <! (AST.lmark lblL1)
  else ()

  if bytemask &&& 0b0001 = 0b0001 then
    let lblL2 = builder.NewSymbol "cpsrWriteByInstrL2"
    let lblL3 = builder.NewSymbol "cpsrWriteByInstrL3"
    let lblL4 = builder.NewSymbol "cpsrWriteByInstrL4"
    let lblL5 = builder.NewSymbol "cpsrWriteByInstrL5"
    let lblL6 = builder.NewSymbol "cpsrWriteByInstrL6"
    let lblL7 = builder.NewSymbol "cpsrWriteByInstrL7"
    let lblEnd = builder.NewSymbol "cpsrWriteByInstrEnd"
    let nmfi = isSetSCTLRForNMFI ctxt
    builder <! (AST.cjmp privileged (AST.name lblL2) (AST.name lblL3))
    builder <! (AST.lmark lblL2)
    let iValue = value .& maskPSRForIbit
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_I .| iValue)
    builder <! (AST.lmark lblL3)

    let chkValueF = (value .& maskPSRForFbit) == AST.num0 32<rt>
    let cond = privileged .& (AST.not nmfi .| chkValueF) .&
               (isSecure ctxt .| isSetSCRForFW ctxt .| haveVirtExt ())
    builder <! (AST.cjmp cond (AST.name lblL4) (AST.name lblL5))
    builder <! (AST.lmark lblL4)
    let fValue = value .& maskPSRForFbit
    builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_F .| fValue)
    builder <! (AST.lmark lblL5)

    if isExcptReturn then
      let tValue = value .& maskPSRForTbit
      builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_T .| tValue)
    else ()

    builder <! (AST.cjmp privileged (AST.name lblL6) (AST.name lblL7))
    builder <! (AST.lmark lblL6)
    builder <! (AST.sideEffect UndefinedInstr) // FIXME: (use UNPREDICTABLE)
    builder <! (AST.jmp (AST.name lblEnd))
    builder <! (AST.lmark lblL7)
    writeModeBits ctxt value isExcptReturn builder
    builder <! (AST.lmark lblEnd)
  else ()

let transShiftOprs ctxt opr1 opr2 =
  match opr1, opr2 with
  | OprReg _, OprShift (typ, Imm imm) ->
    let e = transOprToExpr ctxt opr1
    let carryIn = getCarryFlag ctxt
    shift e 32<rt> typ imm carryIn
  | _ -> raise InvalidOperandException

let parseOprOfMVNS (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins ctxt
  | ThreeOperands (opr1, opr2, opr3) ->
    transOprToExpr ctxt opr1, transShiftOprs ctxt opr2 opr3
  | _ -> raise InvalidOperandException

let transTwoOprsOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let transThreeOprsOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> transThreeOprs ins ctxt
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let e1, e2, e3 = transThreeOprs ins ctxt
    e1, e2, shift e3 32<rt> SRTypeLSL 0u carryIn
  | _ -> raise InvalidOperandException

let transFourOprsOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3 , (OprShift (_, Imm _) as opr4)) ->
    let e1, e2 =
      transOprToExpr ctxt opr1, transOprToExpr ctxt opr2
    e1, e2, transShiftOprs ctxt opr3 opr4
  | FourOperands (opr1, opr2, opr3 , OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    let e3 = transOprToExpr ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfADC (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADC ins ctxt
  | ThreeOperands _ -> transThreeOprsOfADC ins ctxt
  | FourOperands _ -> transFourOprsOfADC ins ctxt
  | _ -> raise InvalidOperandException

let startMark (ins: InsInfo) builder =
  builder <! (AST.ismark (ins.Length))

let checkCondition (ins: InsInfo) ctxt isUnconditional (builder: IRBuilder) =
  let lblPass = builder.NewSymbol "NeedToExec"
  let lblIgnore = builder.NewSymbol "IgnoreExec"
  if isUnconditional then lblIgnore
  else
    let cond = conditionPassed ctxt ins.Condition
    builder <! (AST.cjmp cond (AST.name lblPass) (AST.name lblIgnore))
    builder <! (AST.lmark lblPass)
    lblIgnore

/// Update ITState after normal execution of an IT-block instruction. See A2-52
/// function: ITAdvance().
let itAdvance ctxt (builder: IRBuilder) =
  let itstate = builder.NewTempVar 32<rt>
  let cond = builder.NewTempVar 1<rt>
  let nextstate = builder.NewTempVar 32<rt>
  let lblThen = builder.NewSymbol "LThen"
  let lblElse = builder.NewSymbol "LElse"
  let lblEnd = builder.NewSymbol "LEnd"
  let cpsr = getRegVar ctxt R.CPSR
  let cpsrIT10 =
    getPSR ctxt R.CPSR PSR_IT10 >> (numI32 25 32<rt>)
  let cpsrIT72 =
    getPSR ctxt R.CPSR PSR_IT72 >> (numI32 8 32<rt>)
  let mask10 = numI32 0x3 32<rt> (* For ITSTATE[1:0] *)
  let mask20 = numI32 0x7 32<rt> (* For ITSTATE[2:0] *)
  let mask40 = numI32 0x1f 32<rt> (* For ITSTATE[4:0] *)
  let mask42 = numI32 0x1c 32<rt> (* For ITSTATE[4:2] *)
  let cpsrIT42 = cpsr .& (numI32 0xffffe3ff 32<rt>)
  let num8 = numI32 8 32<rt>
  builder <! (itstate := cpsrIT72 .| cpsrIT10)
  builder <! (cond := ((itstate .& mask20) == AST.num0 32<rt>))
  builder <! AST.cjmp cond (AST.name lblThen) (AST.name lblElse)
  builder <! AST.lmark lblThen
  builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_IT10)
  builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_IT72)
  builder <! AST.jmp (AST.name lblEnd)
  builder <! AST.lmark lblElse
  builder <! (nextstate := (itstate .& mask40 << AST.num1 32<rt>))
  builder <! (cpsr := nextstate .& mask10 |> setPSR ctxt R.CPSR PSR_IT10)
  builder <! (cpsr := cpsrIT42 .| ((nextstate .& mask42) << num8))
  builder <! AST.lmark lblEnd

let putEndLabel ctxt lblIgnore isUnconditional isBranch builder =
  if isUnconditional then ()
  else
    builder <! (AST.lmark lblIgnore)
    itAdvance ctxt builder
    match isBranch with
    | None -> ()
    | Some (i: InsInfo) ->
      let target = numU64 (i.Address + uint64 i.Length) 32<rt>
      builder <! (AST.interjmp target InterJmpKind.Base)

let endMark (ins: InsInfo) builder =
  builder <! (AST.iemark ins.Length)
  builder

let sideEffects ins name =
  let builder = IRBuilder (4)
  startMark ins builder
  builder <! (AST.sideEffect name)
  endMark ins builder

let nop ins =
  let builder = IRBuilder (4)
  startMark ins builder
  endMark ins builder

let convertPCOpr (ins: InsInfo) ctxt opr =
  if opr = getPC ctxt then
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8 else 4
    opr .+ (numI32 rel 32<rt>)
  else opr

let adc isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src1, src2 = parseOprOfADC ins ctxt
  let src1 = convertPCOpr ins ctxt src1
  let src2 = convertPCOpr ins ctxt src2
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  let res, carryOut, overflow = addWithCarry t1 t2 (getCarryFlag ctxt)
  builder <! (result := res)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
      builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transTwoOprsOfADD (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let e1, e2 = transTwoOprs ins ctxt in e1, e1, e2
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let transThreeOprsOfADD (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> transThreeOprs ins ctxt
  | ThreeOperands (OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let e1, e2, e3 = transThreeOprs ins ctxt
    e1, e2, shift e3 32<rt> SRTypeLSL 0u carryIn
  | _ -> raise InvalidOperandException

let transFourOprsOfADD (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3 , (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    e1, e2, transShiftOprs ctxt opr3 opr4
  | FourOperands (opr1, opr2, opr3 , OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    let e3 = transOprToExpr ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfADD (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADD ins ctxt
  | ThreeOperands _ -> transThreeOprsOfADD ins ctxt
  | FourOperands _ -> transFourOprsOfADD ins ctxt
  | _ -> raise InvalidOperandException

let add isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src1, src2 = parseOprOfADD ins ctxt
  let src1 = convertPCOpr ins ctxt src1
  let src2 = convertPCOpr ins ctxt src2
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  let result, carryOut, overflow = addWithCarry t1 t2 (AST.num0 32<rt>)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
      builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

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
  | Op.BL, mode -> mode
  | Op.BLX, ArchOperationMode.ARMMode -> ArchOperationMode.ThumbMode
  | Op.BLX, ArchOperationMode.ThumbMode -> ArchOperationMode.ARMMode
  | _ -> raise InvalidTargetArchModeException

let parseOprOfBL ins =
  let targetMode = targetModeOfBL ins
  match ins.Operands with
  | OneOperand (OprMemory (LiteralMode imm)) ->
    transLableOprsOfBL ins targetMode imm, targetMode
  | _ -> raise InvalidOperandException

let bl ins ctxt =
  let builder = IRBuilder (16)
  let alignedAddr, targetMode = parseOprOfBL ins
  let lr = getRegVar ctxt R.LR
  let retAddr = bvOfBaseAddr ins.Address .+ (numI32 4 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if ins.Mode = ArchOperationMode.ARMMode then builder <! (lr := retAddr)
  else builder <! (lr := maskAndOR retAddr (AST.num1 32<rt>) 32<rt> 1)
  selectInstrSet ctxt builder targetMode
  builder <! (branchWritePC ctxt ins alignedAddr InterJmpKind.IsCall)
  putEndLabel ctxt lblIgnore isUnconditional (Some ins) builder
  endMark ins builder

let blxWithReg (ins: InsInfo) reg ctxt =
  let builder = IRBuilder (32)
  let lr = getRegVar ctxt R.LR
  let addr = bvOfBaseAddr ins.Address
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if ins.Mode = ArchOperationMode.ARMMode then
    builder <! (lr := addr .+ (numI32 4 32<rt>))
  else
    let addr = addr .+ (numI32 2 32<rt>)
    builder <! (lr := maskAndOR addr (AST.num1 32<rt>) 32<rt> 1)
  bxWritePC ctxt isUnconditional (getRegVar ctxt reg) builder
  putEndLabel ctxt lblIgnore isUnconditional (Some ins) builder
  endMark ins builder

let branchWithLink (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand (OprReg reg) -> blxWithReg ins reg ctxt
  | _ -> bl ins ctxt

let parseOprOfPUSHPOP (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprReg r) -> regsToUInt32 [ r ]
  | OneOperand (OprRegList regs) -> regsToUInt32 regs
  | _ -> raise InvalidOperandException

let pushLoop ctxt numOfReg addr (builder: IRBuilder) =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      if count = 13 && count <> lowestSetBit numOfReg 32 then
        builder <! (AST.loadLE 32<rt> addr := (AST.undef 32<rt> "UNKNOWN"))
      else
        let reg = count |> uint32 |> OperandHelper.getRegister
        builder <! (AST.loadLE 32<rt> addr := getRegVar ctxt reg)
      addr .+ (numI32 4 32<rt>)
    else addr
  List.fold loop addr [ 0 .. 14 ]

let push ins ctxt =
  let builder = IRBuilder (32)
  let t0 = builder.NewTempVar 32<rt>
  let sp = getRegVar ctxt R.SP
  let numOfReg = parseOprOfPUSHPOP ins
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = sp .- (numI32 stackWidth 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t0 := addr)
  let addr = pushLoop ctxt numOfReg t0 builder
  if (numOfReg >>> 15 &&& 1u) = 1u then
    builder <! (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  else ()
  builder <! (sp := t0)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

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
  (r, sat)

let sSat ir i n =
  let (r, _) = sSatQ ir i n
  r

let qdadd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let struct (sat1,sat2) = tmpVars2 ir 1<rt>
  let (dou, sat) = sSatQ ir (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
  !!ir (sat1 := sat)
  let (r, sat) = sSatQ ir (src1 .+ dou) (RegType.fromBitWidth 32)
  !!ir (dst := r)
  !!ir (sat2 := sat)
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := AST.ite (sat1 .| sat2) (enablePSRBits ctxt R.CPSR PSR_Q) cpsr)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let qdsub (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let struct (sat1,sat2) = tmpVars2 ir 1<rt>
  let (dou, sat) = sSatQ ir (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
  !!ir (sat1 := sat)
  let (r, sat) = sSatQ ir (src1 .- dou) (RegType.fromBitWidth 32)
  !!ir (dst := r)
  !!ir (sat2 := sat)
  let cpsr = getRegVar ctxt R.CPSR
  !!ir (cpsr := AST.ite (sat1 .| sat2) (enablePSRBits ctxt R.CPSR PSR_Q) cpsr)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let qsax (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let struct (sum, diff) = tmpVars2 ir 16<rt>
  let xtlo src = AST.xtlo 16<rt> src
  let xthi src = AST.xthi 16<rt> src
  !!ir (sum := xtlo src1 .+ xthi src2)
  !!ir (diff := xthi src1 .- xtlo src2)
  !!ir (sum := sSat ir sum (RegType.fromBitWidth 16))
  !!ir (diff := sSat ir diff (RegType.fromBitWidth 16))
  !!ir (dst := AST.concat diff sum)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let qsub16 (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let struct (diff1, diff2) = tmpVars2 ir 16<rt>
  let xtlo src = AST.xtlo 16<rt> src
  let xthi src = AST.xthi 16<rt> src
  !!ir (diff1 := xtlo src1 .- xtlo src2)
  !!ir (diff2 := xthi src1 .- xthi src2)
  !!ir (diff1 := sSat ir diff1 (RegType.fromBitWidth 16))
  !!ir (diff2 := sSat ir diff2 (RegType.fromBitWidth 16))
  !!ir (dst := AST.concat diff2 diff1)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let sub isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src1, src2 = parseOprOfADD ins ctxt
  let src1 = convertPCOpr ins ctxt src1
  let src2 = convertPCOpr ins ctxt src2
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  let res, carryOut, overflow = addWithCarry t1 (AST.not t2) (AST.num1 32<rt>)
  builder <! (result := res)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
      builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

/// B9.3.19 SUBS R.PC, R.LR (Thumb), on page B9-2008
let subsPCLRThumb ins ctxt =
  let builder = IRBuilder (64)
  let _, _, src2 = parseOprOfADD ins ctxt
  let pc = getPC ctxt
  let result, _, _ = addWithCarry pc (AST.not src2) (AST.num1 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  cpsrWriteByInstr ctxt (getRegVar ctxt R.SPSR) 0b1111 true builder
  builder <! (branchWritePC ctxt ins result InterJmpKind.IsRet)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseResultOfSUBAndRela (ins: InsInfo) ctxt =
  match ins.Opcode with
  | Op.ANDS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    src1.& src2
  | Op.EORS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    src1 <+> src2
  | Op.SUBS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    let r, _, _ = addWithCarry src1 (AST.not src2) (AST.num1 32<rt>)
    r
  | Op.RSBS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    let r, _, _ = addWithCarry (AST.not src1) src2 (AST.num1 32<rt>)
    r
  | Op.ADDS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    let r, _, _ = addWithCarry src1 src2 (AST.num0 32<rt>)
    r
  | Op.ADCS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    let r, _, _ = addWithCarry src1 src2 (getCarryFlag ctxt)
    r
  | Op.SBCS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    let r, _, _ = addWithCarry src1 (AST.not src2) (getCarryFlag ctxt)
    r
  | Op.RSCS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    let r, _, _ = addWithCarry (AST.not src1) src2 (getCarryFlag ctxt)
    r
  | Op.ORRS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    src1 .| src2
  | Op.MOVS ->
    let _, src = transTwoOprs ins ctxt
    src
  | Op.ASRS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeASR src2 (getCarryFlag ctxt)
  | Op.LSLS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeLSL src2 (getCarryFlag ctxt)
  | Op.LSRS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeLSR src2 (getCarryFlag ctxt)
  | Op.RORS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    shiftForRegAmount src1 32<rt> SRTypeROR src2 (getCarryFlag ctxt)
  | Op.RRXS ->
    let _, src = transTwoOprs ins ctxt
    shiftForRegAmount src 32<rt> SRTypeRRX (AST.num1 32<rt>) (getCarryFlag ctxt)
  | Op.BICS ->
    let _, src1, src2 = parseOprOfADC ins ctxt
    src1 .& (AST.not src2)
  | Op.MVNS ->
    let _, src = parseOprOfMVNS ins ctxt
    AST.not src
  | _ -> raise InvalidOperandException

/// B9.3.20 SUBS R.PC, R.LR and related instruction (ARM), on page B9-2010
let subsAndRelatedInstr (ins: InsInfo) ctxt =
  let builder = IRBuilder (64)
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  cpsrWriteByInstr ctxt (getRegVar ctxt R.SPSR) 0b1111 true builder
  builder <! (result := parseResultOfSUBAndRela ins ctxt)
  builder <! (branchWritePC ctxt ins result InterJmpKind.IsRet)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let computeCarryOutFromImmCflag (ins: InsInfo) ctxt =
  match ins.Cflag with
  | Some v ->
    if v then BitVector.One 1<rt> |> AST.num
    else BitVector.Zero 1<rt> |> AST.num
  | None -> getCarryFlag ctxt

let translateLogicOp (ins: InsInfo) ctxt (builder: IRBuilder) =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let t = builder.NewTempVar 32<rt>
    let e1, e2 = transTwoOprs ins ctxt
    builder <! (t := e2)
    let shifted, carryOut = shiftC t 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    e1, e1, shifted, carryOut
  | ThreeOperands (_, _, OprImm _) ->
    let e1, e2, e3 = transThreeOprs ins ctxt
    let carryOut = computeCarryOutFromImmCflag ins ctxt
    e1, e2, e3, carryOut
  | FourOperands (opr1, opr2, opr3 , OprShift (typ, Imm imm)) ->
    let t = builder.NewTempVar 32<rt>
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src1 = transOprToExpr ctxt opr2
    let rm = transOprToExpr ctxt opr3
    builder <! (t := rm)
    let shifted, carryOut = shiftC t 32<rt> typ imm carryIn
    dst, src1, shifted, carryOut
  | FourOperands (opr1, opr2, opr3 , OprRegShift (typ, reg)) ->
    let t = builder.NewTempVar 32<rt>
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src1 = transOprToExpr ctxt opr2
    let rm = transOprToExpr ctxt opr3
    builder <! (t := rm)
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount t 32<rt> typ amount carryIn
    dst, src1, shifted, carryOut
  | _ -> raise InvalidOperandException

let logicalAnd isSetFlags (ins: InsInfo) ctxt =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let dst, src1, src2, carryOut = translateLogicOp ins ctxt builder
  let result = builder.NewTempVar 32<rt>
  builder <! (result := src1 .& src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let mov isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, res = transTwoOprs ins ctxt
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := res)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let eor isSetFlags (ins: InsInfo) ctxt =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let dst, src1, src2, carryOut = translateLogicOp ins ctxt builder
  let result = builder.NewTempVar 32<rt>
  builder <! (result := src1 <+> src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transFourOprsOfRSB (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3 , (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    e1, e2, transShiftOprs ctxt opr3 opr4
  | FourOperands (opr1, opr2, opr3 , OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    let e3 = transOprToExpr ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfRSB (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt
  | FourOperands _ -> transFourOprsOfRSB ins ctxt
  | _ -> raise InvalidOperandException

let rsb isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src1, src2 = parseOprOfRSB ins ctxt
  let result = builder.NewTempVar 32<rt>
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  let res, carryOut, overflow = addWithCarry (AST.not t1) t2 (AST.num1 32<rt>)
  builder <! (result := res)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
      builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transTwoOprsOfSBC (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    e1, e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let transFourOprsOfSBC (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3 , (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    e1, e2, transShiftOprs ctxt opr3 opr4
  | FourOperands (opr1, opr2, opr3 , OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    let e3 = transOprToExpr ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfSBC (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfSBC ins ctxt
  | ThreeOperands _ -> transThreeOprs ins ctxt
  | FourOperands _ -> transFourOprsOfSBC ins ctxt
  | _ -> raise InvalidOperandException

let sbc isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src1, src2 = parseOprOfSBC ins ctxt
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  let r, carryOut, overflow = addWithCarry t1 (AST.not t2) (getCarryFlag ctxt)
  builder <! (result := r)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
      builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transFourOprsOfRSC (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (opr1, opr2, opr3 , (OprShift (_, Imm _) as opr4)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    e1, e2, transShiftOprs ctxt opr3 opr4
  | FourOperands (opr1, opr2, opr3 , OprRegShift (typ, reg)) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    let e3 = transOprToExpr ctxt opr3
    let amount = AST.xtlo 8<rt> (getRegVar ctxt reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let parseOprOfRSC (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins ctxt
  | FourOperands _ -> transFourOprsOfRSB ins ctxt
  | _ -> raise InvalidOperandException

let rsc isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src1, src2 = parseOprOfRSC ins ctxt
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := src1)
  builder <! (t2 := src2)
  let r, carryOut, overflow = addWithCarry (AST.not t1) t2 (getCarryFlag ctxt)
  builder <! (result := r)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
      builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let orr isSetFlags (ins: InsInfo) ctxt =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let dst, src1, src2, carryOut = translateLogicOp ins ctxt builder
  let result = builder.NewTempVar 32<rt>
  builder <! (result := src1 .| src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let orn isSetFlags (ins: InsInfo) ctxt =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let dst, src1, src2, carryOut = translateLogicOp ins ctxt builder
  let result = builder.NewTempVar 32<rt>
  builder <! (result := src1 .| AST.not src2)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let bic isSetFlags (ins: InsInfo) ctxt =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let dst, src1, src2, carryOut = translateLogicOp ins ctxt builder
  let result = builder.NewTempVar 32<rt>
  builder <! (result := src1 .& (AST.not src2))
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transTwoOprsOfMVN (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let e1, e2 = transTwoOprs ins ctxt
    e1, e2, getCarryFlag ctxt
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    let shifted, carryOut = shiftC e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    e1, shifted, carryOut
  | _ -> raise InvalidOperandException

let transThreeOprsOfMVN (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src = transOprToExpr ctxt opr2
    let shifted, carryOut = shiftC src 32<rt> typ imm carryIn
    dst, shifted, carryOut
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src = transOprToExpr ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount src 32<rt> typ amount carryIn
    dst, shifted, carryOut
  | _ -> raise InvalidOperandException

let parseOprOfMVN (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfMVN ins ctxt
  | ThreeOperands _ -> transThreeOprsOfMVN ins ctxt
  | _ -> raise InvalidOperandException

let mvn isSetFlags ins ctxt =
  let builder = IRBuilder (32)
  let dst, src, carryOut = parseOprOfMVN ins ctxt
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := AST.not src)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let svc (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand (OprImm n) -> sideEffects ins (Interrupt (int n))
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
    let e1, e2 = transTwoOprs ins ctxt
    let result, carryOut = shiftC tmp 32<rt> shiftTyp 1ul carryIn
    e1, e2, result, carryOut
  | TwoOperands (OprReg _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let e1, e2 = transTwoOprs ins ctxt
    let shiftN = AST.xtlo 8<rt> e2 |> AST.zext 32<rt>
    let result, carryOut = shiftCForRegAmount tmp 32<rt> shiftTyp shiftN carryIn
    e1, e1, result, carryOut
  | _ -> raise InvalidOperandException

let transThreeOprsOfShiftInstr (ins: InsInfo) shiftTyp ctxt tmp =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprImm imm) ->
    let e1 = transOprToExpr ctxt opr1
    let e2 = transOprToExpr ctxt opr2
    let shiftN = getImmShiftFromShiftType (uint32 imm) shiftTyp
    let shifted, carryOut =
      shiftC tmp 32<rt> shiftTyp shiftN (getCarryFlag ctxt)
    e1, e2, shifted, carryOut
  | ThreeOperands (_, _, OprReg _) ->
    let carryIn = getCarryFlag ctxt
    let e1, e2, e3 = transThreeOprs ins ctxt
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

let shiftInstr isSetFlags ins typ ctxt =
  let builder = IRBuilder (32)
  let srcTmp = builder.NewTempVar 32<rt>
  let result = builder.NewTempVar 32<rt>
  let dst, src, res, carryOut = parseOprOfShiftInstr ins typ ctxt srcTmp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (srcTmp := src)
  builder <! (result := res)
  if dst = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else
    builder <! (dst := result)
    if isSetFlags then
      let cpsr = getRegVar ctxt R.CPSR
      builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
      builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
      builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
    else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let subs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
    when ins.Mode = ArchOperationMode.ThumbMode ->
    subsPCLRThumb ins ctxt
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> sub isSetFlags ins ctxt

let adds isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> add isSetFlags ins ctxt

let adcs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> adc isSetFlags ins ctxt

let ands isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> logicalAnd isSetFlags ins ctxt

let movs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _) -> subsAndRelatedInstr ins ctxt
  | _ -> mov isSetFlags ins ctxt

  (*
let mrs (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let rd, sreg = transTwoOprs ins ctxt
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen
  *)

let eors isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> eor isSetFlags ins ctxt

let rsbs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> rsb isSetFlags ins ctxt

let sbcs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> sbc isSetFlags ins ctxt

let rscs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> rsc isSetFlags ins ctxt

let orrs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> orr isSetFlags ins ctxt

let orns isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> orn isSetFlags ins ctxt

let bics isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _)
  | FourOperands (OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> bic isSetFlags ins ctxt

let mvns isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _)
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> mvn isSetFlags ins ctxt

let asrs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> shiftInstr isSetFlags ins SRTypeASR ctxt

let lsls isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> shiftInstr isSetFlags ins SRTypeLSL ctxt

let lsrs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> shiftInstr isSetFlags ins SRTypeLSR ctxt

let rors isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg R.PC, _, _) -> subsAndRelatedInstr ins ctxt
  | _ -> shiftInstr isSetFlags ins SRTypeROR ctxt

let rrxs isSetFlags (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg R.PC, _) -> subsAndRelatedInstr ins ctxt
  | _ -> shiftInstr isSetFlags ins SRTypeRRX ctxt

let clz ins ctxt =
  let builder = IRBuilder (32)
  let dst, src = transTwoOprs ins ctxt
  let lblBoundCheck = builder.NewSymbol "LBoundCheck"
  let lblZeroCheck = builder.NewSymbol "LZeroCheck"
  let lblCount = builder.NewSymbol "LCount"
  let lblEnd = builder.NewSymbol "LEnd"
  let numSize = (numI32 32 32<rt>)
  let t1 = builder.NewTempVar 32<rt>
  let cond1 = t1 == (AST.num0 32<rt>)
  let cond2 =
    src .& ((AST.num1 32<rt>) << (t1 .- AST.num1 32<rt>)) != (AST.num0 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := numSize)
  builder <! (AST.lmark lblBoundCheck)
  builder <! (AST.cjmp cond1 (AST.name lblEnd) (AST.name lblZeroCheck))
  builder <! (AST.lmark lblZeroCheck)
  builder <! (AST.cjmp cond2 (AST.name lblEnd) (AST.name lblCount))
  builder <! (AST.lmark lblCount)
  builder <! (t1 := t1 .- (AST.num1 32<rt>))
  builder <! (AST.jmp (AST.name lblBoundCheck))
  builder <! (AST.lmark lblEnd)
  builder <! (dst := numSize .- t1)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transTwoOprsOfCMN (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins ctxt
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    let shifted = shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    e1, shifted
  | _ -> raise InvalidOperandException

let transThreeOprsOfCMN (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src = transOprToExpr ctxt opr2
    let shifted = shift src 32<rt> typ imm carryIn
    dst, shifted
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src = transOprToExpr ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted = shiftForRegAmount src 32<rt> typ amount carryIn
    dst, shifted
  | _ -> raise InvalidOperandException

let parseOprOfCMN (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMN ins ctxt
  | ThreeOperands _ -> transThreeOprsOfCMN ins ctxt
  | _ -> raise InvalidOperandException

let cmn ins ctxt =
  let builder = IRBuilder (16)
  let dst, src = parseOprOfCMN ins ctxt
  let result = builder.NewTempVar 32<rt>
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := dst)
  builder <! (t2 := src)
  let res, carryOut, overflow = addWithCarry t1 t2 (AST.num0 32<rt>)
  builder <! (result := res)
  builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
  builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
  builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
  builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let mla isSetFlags ins ctxt =
  let builder = IRBuilder (16)
  let rd, rn, rm, ra = transFourOprs ins ctxt
  let r = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (r := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+
                                     AST.zext 64<rt> ra))
  builder <! (rd := r)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    builder <! (cpsr := AST.xthi 1<rt> r |> setPSR ctxt R.CPSR PSR_N)
    builder <! (cpsr := r == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transTwoOprsOfCMP (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) -> transTwoOprs ins ctxt
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    e1, shift e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
  | _ -> raise InvalidOperandException

let transThreeOprsOfCMP (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src = transOprToExpr ctxt opr2
    dst, shift src 32<rt> typ imm carryIn
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let dst = transOprToExpr ctxt opr1
    let src = transOprToExpr ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    dst, shiftForRegAmount src 32<rt> typ amount carryIn
  | _ -> raise InvalidOperandException

let parseOprOfCMP (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMP ins ctxt
  | ThreeOperands _ -> transThreeOprsOfCMP ins ctxt
  | _ -> raise InvalidOperandException

let cmp ins ctxt =
  let builder = IRBuilder (16)
  let rn, rm = parseOprOfCMP ins ctxt
  let result = builder.NewTempVar 32<rt>
  let t1, t2 = builder.NewTempVar 32<rt>, builder.NewTempVar 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := rn)
  builder <! (t2 := rm)
  let res, carryOut, overflow = addWithCarry t1 (AST.not t2) (AST.num1 32<rt>)
  builder <! (result := res)
  builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
  builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
  builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
  builder <! (cpsr := overflow |> setPSR ctxt R.CPSR PSR_V)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let umlal isSetFlags ins ctxt =
  let builder = IRBuilder (16)
  let rdLo, rdHi, rn, rm = transFourOprs ins ctxt
  let result = builder.NewTempVar 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm
                     .+ AST.concat rdLo rdHi)
  builder <! (rdHi := AST.xthi 32<rt> result)
  builder <! (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
    builder <! (cpsr := result == AST.num0 64<rt> |> setPSR ctxt R.CPSR PSR_Z)
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let umull isSetFlags ins ctxt =
  let builder = IRBuilder (16)
  let rdLo, rdHi, rn, rm = transFourOprs ins ctxt
  let result = builder.NewTempVar 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm)
  builder <! (rdHi := AST.xthi 32<rt> result)
  builder <! (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
    builder <! (cpsr := result == AST.num0 64<rt> |> setPSR ctxt R.CPSR PSR_Z)
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transOprsOfTEQ (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let rn, imm = transTwoOprs ins ctxt
    rn, imm, getCarryFlag ctxt
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ctxt opr1
    let rm = transOprToExpr ctxt opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    rn, shifted, carryOut
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ctxt opr1
    let rm = transOprToExpr ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    rn, shifted, carryOut
  | _ -> raise InvalidOperandException

let teq ins ctxt =
  let builder = IRBuilder (16)
  let src1, src2, carryOut = transOprsOfTEQ ins ctxt
  let result = builder.NewTempVar 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := src1 <+> src2)
  builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
  builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
  builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let mul isSetFlags ins ctxt =
  let builder = IRBuilder (16)
  let rd, rn, rm = transThreeOprs ins ctxt
  let result = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := AST.xtlo 32<rt>
                        (AST.zext 64<rt> rn .* AST.zext 64<rt> rm))
  builder <! (rd := result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
    builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let transOprsOfTST (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg _, OprImm _) ->
    let rn, imm = transTwoOprs ins ctxt
    let carryOut = computeCarryOutFromImmCflag ins ctxt
    rn, imm, carryOut
  | TwoOperands (OprReg _, OprReg _) ->
    let e1, e2 = transTwoOprs ins ctxt
    let shifted, carryOut = shiftC e2 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    e1, shifted, carryOut
  | ThreeOperands (opr1, opr2, OprShift (typ, Imm imm)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ctxt opr1
    let rm = transOprToExpr ctxt opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    rn, shifted, carryOut
  | ThreeOperands (opr1, opr2, OprRegShift (typ, rs)) ->
    let carryIn = getCarryFlag ctxt
    let rn = transOprToExpr ctxt opr1
    let rm = transOprToExpr ctxt opr2
    let amount = AST.xtlo 8<rt> (getRegVar ctxt rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    rn, shifted, carryOut
  | _ -> raise InvalidOperandException

let tst ins ctxt =
  let builder = IRBuilder (16)
  let src1, src2, carryOut = transOprsOfTST ins ctxt
  let result = builder.NewTempVar 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (result := src1 .& src2)
  builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
  builder <! (cpsr := result == AST.num0 32<rt> |> setPSR ctxt R.CPSR PSR_Z)
  builder <! (cpsr := carryOut |> setPSR ctxt R.CPSR PSR_C)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let smulhalf ins ctxt s1top s2top =
  let builder = IRBuilder (8)
  let rd, rn, rm = transThreeOprs ins ctxt
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if s1top then builder <! (t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt>)
  else builder <! (t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt>)
  if s2top then builder <! (t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt>)
  else builder <! (t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt>)
  builder <! (rd := t1 .* t2)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

/// SMULL, SMLAL, etc.
let smulandacc isSetFlags doAcc ins ctxt =
  let builder = IRBuilder (16)
  let rdLo, rdHi, rn, rm = transFourOprs ins ctxt
  let tmpresult = builder.NewTempVar 64<rt>
  let result = builder.NewTempVar 64<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (tmpresult := AST.sext 64<rt> rn .* AST.sext 64<rt> rm)
  if doAcc then builder <! (result := tmpresult .+ AST.concat rdHi rdLo)
  else builder <! (result := tmpresult)
  builder <! (rdHi := AST.xthi 32<rt> result)
  builder <! (rdLo := AST.xtlo 32<rt> result)
  if isSetFlags then
    let cpsr = getRegVar ctxt R.CPSR
    builder <! (cpsr := AST.xthi 1<rt> result |> setPSR ctxt R.CPSR PSR_N)
    builder <! (cpsr := result == AST.num0 64<rt> |> setPSR ctxt R.CPSR PSR_Z)
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let smulacchalf ins ctxt s1top s2top =
  let builder = IRBuilder (8)
  let rd, rn, rm, ra = transFourOprs ins ctxt
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if s1top then builder <! (t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt>)
  else builder <! (t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt>)
  if s2top then builder <! (t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt>)
  else builder <! (t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt>)
  builder <! (rd := (t1 .* t2) .+ AST.sext 32<rt> ra)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfB (ins: InsInfo) =
  let addr = bvOfBaseAddr (ins.Address + pcOffset ins)
  match ins.Operands with
  | OneOperand (OprMemory (LiteralMode imm)) ->
    addr .+ (numI64 imm 32<rt>)
  | _ -> raise InvalidOperandException

let b ins ctxt =
  let builder = IRBuilder (8)
  let e = parseOprOfB ins
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (branchWritePC ctxt ins e InterJmpKind.Base)
  putEndLabel ctxt lblIgnore isUnconditional (Some ins) builder
  endMark ins builder

let bx ins ctxt =
  let builder = IRBuilder (32)
  let rm = transOneOpr ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  bxWritePC ctxt isUnconditional rm builder
  putEndLabel ctxt lblIgnore isUnconditional (Some ins) builder
  endMark ins builder

let movtAssign dst src =
  let maskHigh16In32 = AST.num <| BitVector.OfBInt 4294901760I 32<rt>
  let clearHigh16In32 expr = expr .& AST.not maskHigh16In32
  dst := clearHigh16In32 dst .|
         (src << (numI32 16 32<rt>))

let movt ins ctxt =
  let builder = IRBuilder (8)
  let dst, res = transTwoOprs ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (movtAssign dst res)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let popLoop ctxt numOfReg addr (builder: IRBuilder) =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let reg = count |> uint32 |> OperandHelper.getRegister
      builder <! (getRegVar ctxt reg := AST.loadLE 32<rt> addr)
      (addr .+ (numI32 4 32<rt>))
    else addr
  List.fold loop addr [ 0 .. 14 ]

let pop ins ctxt =
  let builder = IRBuilder (32)
  let t0 = builder.NewTempVar 32<rt>
  let sp = getRegVar ctxt R.SP
  let numOfReg = parseOprOfPUSHPOP ins
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = sp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t0 := addr)
  let addr = popLoop ctxt numOfReg t0 builder
  if (numOfReg >>> 13 &&& 1u) = 0u then
    builder <! (sp := sp .+ (numI32 stackWidth 32<rt>))
  else builder <! (sp := (AST.undef 32<rt> "UNKNOWN"))
  if (numOfReg >>> 15 &&& 1u) = 1u then
    AST.loadLE 32<rt> addr |> loadWritePC ctxt isUnconditional builder
  else ()
  putEndLabel ctxt lblIgnore isUnconditional (Some ins) builder
  endMark ins builder

let parseOprOfLDM (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    getRegVar ctxt reg, getRegNum reg, regsToUInt32 regs
  | _ -> raise InvalidOperandException

let getLDMStartAddr rn stackWidth = function
  | Op.LDM | Op.LDMIA -> rn
  | Op.LDMDA -> rn .- (numI32 (stackWidth + 4) 32<rt>)
  | Op.LDMDB -> rn .- (numI32 stackWidth 32<rt>)
  | Op.LDMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let ldm opcode ins ctxt wbackop =
  let builder = IRBuilder (32)
  let t0 = builder.NewTempVar 32<rt>
  let t1 = builder.NewTempVar 32<rt>
  let rn, numOfRn, numOfReg = parseOprOfLDM ins ctxt
  let wback = ins.WriteBack
  let stackWidth = 4 * bitCount numOfReg 16
  let addr = getLDMStartAddr t0 stackWidth opcode
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t0 := rn)
  builder <! (t1 := addr)
  let addr = popLoop ctxt numOfReg t1 builder
  if (numOfReg >>> 15 &&& 1u) = 1u then
    AST.loadLE 32<rt> addr |> loadWritePC ctxt isUnconditional builder
  else ()
  if wback && (numOfReg &&& numOfRn) = 0u then
    builder <! (rn := wbackop t0 (numI32 stackWidth 32<rt>))
  else ()
  if wback && (numOfReg &&& numOfRn) = numOfRn then
    builder <! (rn := (AST.undef 32<rt> "UNKNOWN"))
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let getOffAddrWithExpr s r e = if s = Some Plus then r .+ e else r .- e

let getOffAddrWithImm s r imm =
  match s, imm with
  | Some Plus, Some i -> r .+ (numI64 i 32<rt>)
  | Some Minus, Some i -> r .- (numI64 i 32<rt>)
  | _, _ -> r

let parseMemOfLDR ins ctxt = function
  | OprMemory (OffsetMode (ImmOffset (rn , s, imm))) ->
    let rn = getRegVar ctxt rn |> convertPCOpr ins ctxt
    getOffAddrWithImm s rn imm, None
  | OprMemory (PreIdxMode (ImmOffset (rn , s, imm))) ->
    let rn = getRegVar ctxt rn
    let offsetAddr = getOffAddrWithImm s rn imm
    offsetAddr, Some (rn, offsetAddr)
  | OprMemory (PostIdxMode (ImmOffset (rn , s, imm))) ->
    let rn = getRegVar ctxt rn
    rn, Some (rn, getOffAddrWithImm s rn imm)
  | OprMemory (LiteralMode imm) ->
    let addr = bvOfBaseAddr ins.Address
    let pc = align addr (numI32 4 32<rt>)
    let rel = if ins.Mode = ArchOperationMode.ARMMode then 8u else 4u
    pc .+ (numU32 rel 32<rt>)
       .+ (numI64 imm 32<rt>), None
  | OprMemory (OffsetMode (RegOffset (n, _, m, None))) ->
    let m = getRegVar ctxt m |> convertPCOpr ins ctxt
    let n = getRegVar ctxt n |> convertPCOpr ins ctxt
    let offset = shift m 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    n .+ offset, None
  | OprMemory (PreIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    let offset =
      shift (getRegVar ctxt m) 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    let offsetAddr = getOffAddrWithExpr s rn offset
    offsetAddr, Some (rn, offsetAddr)
  | OprMemory (PostIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    let offset =
      shift (getRegVar ctxt m) 32<rt> SRTypeLSL 0u (getCarryFlag ctxt)
    rn, Some (rn, getOffAddrWithExpr s rn offset)
  | OprMemory (OffsetMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = getRegVar ctxt n |> convertPCOpr ins ctxt
    let rm = getRegVar ctxt m |> convertPCOpr ins ctxt
    let offset = shift rm 32<rt> t i (getCarryFlag ctxt)
    getOffAddrWithExpr s rn offset, None
  | OprMemory (PreIdxMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = getRegVar ctxt n
    let offset = shift (getRegVar ctxt m) 32<rt> t i (getCarryFlag ctxt)
    let offsetAddr = getOffAddrWithExpr s rn offset
    offsetAddr, Some (rn, offsetAddr)
  | OprMemory (PostIdxMode (RegOffset (n, s, m, Some (t, Imm i)))) ->
    let rn = getRegVar ctxt n
    let offset = shift (getRegVar ctxt m) 32<rt> t i (getCarryFlag ctxt)
    rn, Some (rn, getOffAddrWithExpr s rn offset)
  | _ -> raise InvalidOperandException

let parseOprOfLDR (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg rt, (OprMemory _ as mem)) ->
    let addr, writeback = parseMemOfLDR ins ctxt mem
    getRegVar ctxt rt, addr, writeback
  | _ -> raise InvalidOperandException

/// Load register
let ldr ins ctxt size ext =
  let builder = IRBuilder (16)
  let data = builder.NewTempVar 32<rt>
  let rt, addr, writeback = parseOprOfLDR ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  match writeback with
  | Some (basereg, newoffset) ->
    let taddr = builder.NewTempVar 32<rt>
    let twriteback = builder.NewTempVar 32<rt>
    builder <! (taddr := addr)
    builder <! (twriteback := newoffset)
    builder <! (data := AST.loadLE size taddr |> ext 32<rt>)
    builder <! (basereg := twriteback)
  | None ->
    builder <! (data := AST.loadLE size addr |> ext 32<rt>)
  if rt = getPC ctxt then loadWritePC ctxt isUnconditional builder data
  else builder <! (rt := data)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseMemOfLDRD ins ctxt = function
  | OprMemory (OffsetMode (RegOffset (n, s, m, None))) ->
    getOffAddrWithExpr s (getRegVar ctxt n) (getRegVar ctxt m), None
  | OprMemory (PreIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    let offsetAddr = getOffAddrWithExpr s rn (getRegVar ctxt m)
    offsetAddr, Some (rn, offsetAddr)
  | OprMemory (PostIdxMode (RegOffset (n, s, m, None))) ->
    let rn = getRegVar ctxt n
    rn, Some (rn, getOffAddrWithExpr s rn (getRegVar ctxt m))
  | mem -> parseMemOfLDR ins ctxt mem

let parseOprOfLDRD (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg t, OprReg t2, (OprMemory _ as mem)) ->
    let addr, stmt = parseMemOfLDRD ins ctxt mem
    getRegVar ctxt t, getRegVar ctxt t2, addr, stmt
  | _ -> raise InvalidOperandException

let ldrd ins ctxt =
  let builder = IRBuilder (8)
  let taddr = builder.NewTempVar 32<rt>
  let rt, rt2, addr, writeback = parseOprOfLDRD ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let n4 = numI32 4 32<rt>
  match writeback with
  | Some (basereg, newoffset) ->
    let twriteback = builder.NewTempVar 32<rt>
    builder <! (taddr := addr)
    builder <! (twriteback := newoffset)
    builder <! (rt := AST.loadLE 32<rt> taddr)
    builder <! (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
    builder <! (basereg := twriteback)
  | None ->
    builder <! (taddr := addr)
    builder <! (rt := AST.loadLE 32<rt> taddr)
    builder <! (rt2 := AST.loadLE 32<rt> (taddr .+ n4))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

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

let uadd8 ins ctxt =
  let builder = IRBuilder (32)
  let rd, rn, rm = transThreeOprs ins ctxt
  let sum1 = builder.NewTempVar 32<rt>
  let sum2 = builder.NewTempVar 32<rt>
  let sum3 = builder.NewTempVar 32<rt>
  let sum4 = builder.NewTempVar 32<rt>
  let ge0 = builder.NewTempVar 32<rt>
  let ge1 = builder.NewTempVar 32<rt>
  let ge2 = builder.NewTempVar 32<rt>
  let ge3 = builder.NewTempVar 32<rt>
  let cpsr = getRegVar ctxt R.CPSR
  let n100 = numI32 0x100 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let n0 = AST.num1 32<rt>
  let n1 = AST.num1 32<rt>
  builder <! (sum1 := sel8Bits rn 0 .+ sel8Bits rm 0)
  builder <! (sum2 := sel8Bits rn 8 .+ sel8Bits rm 8)
  builder <! (sum3 := sel8Bits rn 16 .+ sel8Bits rm 16)
  builder <! (sum4 := sel8Bits rn 24 .+ sel8Bits rm 24)
  builder <! (rd := combine8bitResults sum1 sum2 sum3 sum4)
  builder <!
    (ge0 := AST.ite (AST.ge sum1 n100) (AST.num1 32<rt>) (AST.num0 32<rt>))
  builder <!
    (ge1 := AST.ite (AST.ge sum2 n100) (AST.num1 32<rt>) (AST.num0 32<rt>))
  builder <!
    (ge2 := AST.ite (AST.ge sum3 n100) (AST.num1 32<rt>) (AST.num0 32<rt>))
  builder <!
    (ge3 := AST.ite (AST.ge sum4 n100) (AST.num1 32<rt>) (AST.num0 32<rt>))
  builder <! (cpsr := combineGEs ge0 ge1 ge2 ge3 |> setPSR ctxt R.CPSR PSR_GE)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let sel ins ctxt =
  let builder = IRBuilder (16)
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let t3 = builder.NewTempVar 32<rt>
  let t4 = builder.NewTempVar 32<rt>
  let rd, rn, rm = transThreeOprs ins ctxt
  let n1 = AST.num1 32<rt>
  let n2 = numI32 2 32<rt>
  let n4 = numI32 4 32<rt>
  let n8 = numI32 8 32<rt>
  let ge = getPSR ctxt R.CPSR PSR_GE >> (numI32 16 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := AST.ite ((ge .& n1) == n1) (sel8Bits rn 0) (sel8Bits rm 0))
  builder <! (t2 := AST.ite ((ge .& n2) == n2) (sel8Bits rn 8) (sel8Bits rm 8))
  builder <!
    (t3 := AST.ite ((ge .& n4) == n4) (sel8Bits rn 16) (sel8Bits rm 16))
  builder <!
    (t4 := AST.ite ((ge .& n8) == n8) (sel8Bits rn 24) (sel8Bits rm 24))
  builder <! (rd := combine8bitResults t1 t2 t3 t4)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let rbit ins ctxt =
  let builder = IRBuilder (16)
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let rd, rm = transTwoOprs ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 := rm)
  builder <! (rd := rd <+> rd)
  for i = 0 to 31 do
    builder <! (t2 := (AST.extract t1 1<rt> i) |> AST.zext 32<rt>)
    builder <! (rd := rd .| (t2 << (numI32 (31 - i) 32<rt>)))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let rev ins ctxt =
  let builder = IRBuilder (16)
  let t1 = builder.NewTempVar 32<rt>
  let t2 = builder.NewTempVar 32<rt>
  let t3 = builder.NewTempVar 32<rt>
  let t4 = builder.NewTempVar 32<rt>
  let rd, rm = transTwoOprs ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t1 :=  sel8Bits rm 0)
  builder <! (t2 :=  sel8Bits rm 8)
  builder <! (t3 :=  sel8Bits rm 16)
  builder <! (t4 :=  sel8Bits rm 24)
  builder <! (rd := combine8bitResults t4 t3 t2 t1)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

/// Store register.
let str ins ctxt size =
  let builder = IRBuilder (16)
  let rt, addr, writeback = parseOprOfLDR ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if rt = getPC ctxt then
    builder <! (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  elif size = 32<rt> then builder <! (AST.loadLE 32<rt> addr := rt)
  else builder <! (AST.loadLE size addr := AST.xtlo size rt)
  match writeback with
  | Some (basereg, newoffset) -> builder <! (basereg := newoffset)
  | None -> ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let strex ins ctxt =
  let builder = IRBuilder (16)
  let rd, rt, addr, writeback = parseOprOfLDRD ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if rt = getPC ctxt then
    builder <! (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  else builder <! (AST.loadLE 32<rt> addr := rt)
  match writeback with
  | Some (basereg, newoffset) -> builder <! (basereg := newoffset)
  | None -> ()
  builder <! (rd := AST.num0 32<rt>) (* XXX: always succeeds for now *)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let strd ins ctxt =
  let builder = IRBuilder (8)
  let rt, rt2, addr, writeback = parseOprOfLDRD ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (AST.loadLE 32<rt> addr := rt)
  builder <! (AST.loadLE 32<rt>
               (addr .+ (numI32 4 32<rt>)) := rt2)
  match writeback with
  | Some (basereg, newoffset) -> builder <! (basereg := newoffset)
  | None -> ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfSTM (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    getRegVar ctxt reg, regsToUInt32 regs
  | _ -> raise InvalidOperandException

let getSTMStartAddr rn msize = function
  | Op.STM | Op.STMIA | Op.STMEA -> rn
  | Op.STMDA -> rn .- msize .+  (numI32 4 32<rt>)
  | Op.STMDB -> rn .- msize
  | Op.STMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let stmLoop ctxt regs wback rn addr (builder: IRBuilder) =
  let loop addr count =
    if (regs >>> count) &&& 1u = 1u then
      let ri = count |> uint32 |> OperandHelper.getRegister |> getRegVar ctxt
      if ri = rn && wback && count <> lowestSetBit regs 32 then
        builder <! (AST.loadLE 32<rt> addr := (AST.undef 32<rt> "UNKNOWN"))
      else
        builder <! (AST.loadLE 32<rt> addr := ri)
      addr .+ (numI32 4 32<rt>)
    else addr
  List.fold loop addr [ 0 .. 14 ]

let stm opcode ins ctxt wbop =
  let builder = IRBuilder (32)
  let taddr = builder.NewTempVar 32<rt>
  let rn, regs = parseOprOfSTM ins ctxt
  let wback = ins.WriteBack
  let msize = numI32 (4 * bitCount regs 16) 32<rt>
  let addr = getSTMStartAddr rn msize opcode
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (taddr := addr)
  let addr = stmLoop ctxt regs wback rn taddr builder
  if (regs >>> 15 &&& 1u) = 1u then
    builder <! (AST.loadLE 32<rt> addr := pcStoreValue ctxt)
  else ()
  if wback then builder <! (rn := wbop rn msize) else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfCBZ (ins: InsInfo) ctxt =
  let pc = bvOfBaseAddr ins.Address
  let offset = pcOffset ins |> int64
  match ins.Operands with
  | TwoOperands (OprReg rn, (OprMemory (LiteralMode imm))) ->
    getRegVar ctxt rn, pc .+ (numI64 (imm + offset) 32<rt>)
  | _ -> raise InvalidOperandException

let cbz nonZero ins ctxt =
  let builder = IRBuilder (16)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let n = if nonZero then AST.num1 1<rt> else AST.num0 1<rt>
  let rn, pc = parseOprOfCBZ ins ctxt
  let cond = n <+> (rn == AST.num0 32<rt>)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (branchWritePC ctxt ins pc InterJmpKind.Base)
  builder <! (AST.lmark lblL1)
  let fallAddr = ins.Address + uint64 ins.Length
  let fallAddrExp = numU64 fallAddr 32<rt>
  builder <! (AST.interjmp fallAddrExp InterJmpKind.Base)
  putEndLabel ctxt lblIgnore isUnconditional (Some ins) builder
  endMark ins builder

let parseOprOfTableBranch (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand (OprMemory (OffsetMode (RegOffset (rn, None, rm, None)))) ->
    let rn = getRegVar ctxt rn |> convertPCOpr ins ctxt
    let rm = getRegVar ctxt rm |> convertPCOpr ins ctxt
    let addr = rn .+ rm
    AST.loadLE 8<rt> addr |> AST.zext 32<rt>
  | OneOperand (OprMemory (OffsetMode (RegOffset (rn,
                                                  None,
                                                  rm, Some (_, Imm i))))) ->
    let rn = getRegVar ctxt rn |> convertPCOpr ins ctxt
    let rm = getRegVar ctxt rm |> convertPCOpr ins ctxt
    let addr = rn .+ (shiftLSL rm 32<rt> i)
    AST.loadLE 16<rt> addr |> AST.zext 32<rt>
  | _ -> raise InvalidOperandException

let tableBranch (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let pc = bvOfBaseAddr ins.Address
  let halfwords = parseOprOfTableBranch ins ctxt
  let numTwo = numI32 2 32<rt>
  let result = pc .+ (numTwo .* halfwords)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (branchWritePC ctxt ins result InterJmpKind.Base)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfBFC (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg rd, OprImm lsb, OprImm width) ->
    getRegVar ctxt rd, Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ -> raise InvalidOperandException

let bfc (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let rd, lsb, width = parseOprOfBFC ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (rd := replicate rd 32<rt> lsb width 0)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfRdRnLsbWidth (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    getRegVar ctxt rd, getRegVar ctxt rn,
    Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ -> raise InvalidOperandException

let bfi ins ctxt =
  let builder = IRBuilder (8)
  let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins ctxt
  let t0 = builder.NewTempVar 32<rt>
  let t1 = builder.NewTempVar 32<rt>
  let n = rn .&
          (BitVector.OfBInt (BigInteger.getMask width) 32<rt> |> AST.num)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t0 := n << (numI32 lsb 32<rt>))
  builder <! (t1 := replicate rd 32<rt> lsb width 0)
  builder <! (rd := t0 .| t1)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let bfx ins ctxt signExtend =
  let builder = IRBuilder (8)
  let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if lsb + width - 1 > 31 || width < 0 then raise InvalidOperandException
  else ()
  let v = BitVector.OfBInt (BigInteger.getMask width) 32<rt> |> AST.num
  builder <! (rd := (rn >> (numI32 lsb 32<rt>)) .& v)
  if signExtend && width > 1 then
    let msb = builder.NewTempVar 32<rt>
    let mask = builder.NewTempVar 32<rt>
    let msboffset = numI32 (lsb + width - 1) 32<rt>
    let shift = numI32 width 32<rt>
    builder <! (msb := (rn >> msboffset) .& AST.num1 32<rt>)
    builder <! (mask := (AST.not (msb .- AST.num1 32<rt>)) << shift)
    builder <! (rd := rd .| mask)
  else ()
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfUqOpr ctxt = function
  | ThreeOperands (OprReg rd, OprReg rn, OprReg rm) ->
    getRegVar ctxt rd, getRegVar ctxt rn, getRegVar ctxt rm
  | _ -> raise InvalidOperandException

let createTemporaries (builder: IRBuilder) cnt regtype =
  Array.init cnt (fun _ -> builder.NewTempVar regtype)

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

let uqopr (ins: InsInfo) ctxt width opr =
  let builder = IRBuilder (16)
  let rd, rn, rm = parseOprOfUqOpr ctxt ins.Operands
  let tmps = createTemporaries builder (32 / width) 32<rt>
  let sats = createTemporaries builder (32 / width) (RegType.fromBitWidth width)
  let rns = extractUQOps rn width
  let rms = extractUQOps rm width
  let diffs = Array.map2 opr rns rms
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  Array.iter2 (fun tmp diff -> builder <! (tmp := diff)) tmps diffs
  Array.iter2 (fun s t -> builder <! (s := saturate t width)) sats tmps
  builder <! (rd := getUQAssignment sats width)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

/// ADR For ThumbMode (T1 case)
let parseOprOfADR (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg rd, OprMemory (LiteralMode imm)) ->
    let addr = bvOfBaseAddr ins.Address
    let addr = addr .+ (numI32 4 32<rt>)
    let pc = align addr (numI32 4 32<rt>)
    getRegVar ctxt rd, pc .+ (numI64 imm 32<rt>)
  | _ -> raise InvalidOperandException

let it (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let cpsr = getRegVar ctxt R.CPSR
  let itState = numI32 (int ins.ITState) 32<rt>
  let mask10 = numI32 0b11 32<rt>
  let mask72 = (numI32 0b11111100 32<rt>)
  let itState10 = itState .& mask10
  let itState72 = (itState .& mask72) >> (numI32 2 32<rt>)
  startMark ins builder
  builder <! (cpsr := itState10 |> setPSR ctxt R.CPSR PSR_IT10)
  builder <! (cpsr := itState72 |> setPSR ctxt R.CPSR PSR_IT72)
  endMark ins builder

let adr ins ctxt =
  let builder = IRBuilder (32)
  let rd, result = parseOprOfADR ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if rd = getPC ctxt then aluWritePC ctxt ins isUnconditional result builder
  else builder <! (rd := result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let mls ins ctxt =
  let builder = IRBuilder (8)
  let rd, rn, rm, ra = transFourOprs ins ctxt
  let r = builder.NewTempVar 32<rt>
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (r := AST.xtlo 32<rt> (AST.zext 64<rt> ra .- AST.zext 64<rt> rn .*
                                     AST.zext 64<rt> rm))
  builder <! (rd := r)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfExtend (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg rd, OprReg rm) ->
    getRegVar ctxt rd, getRegVar ctxt rm, 0u
  | ThreeOperands (OprReg rd, OprReg rm, OprShift (_, Imm i)) ->
    getRegVar ctxt rd, getRegVar ctxt rm, i
  | _ -> raise InvalidOperandException

let extend (ins: InsInfo) ctxt extractfn amount =
  let builder = IRBuilder (8)
  let rd, rm, rotation = parseOprOfExtend ins ctxt
  let rotated = shiftROR rm 32<rt> rotation
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (rd := extractfn 32<rt> (AST.xtlo amount rotated))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfXTA (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (OprReg rd, OprReg rn, OprReg rm, OprShift (_, Imm i)) ->
    getRegVar ctxt rd, getRegVar ctxt rn, getRegVar ctxt rm, i
  | _ -> raise InvalidOperandException

let extendAndAdd (ins: InsInfo) ctxt amount =
  let builder = IRBuilder (8)
  let rd, rn, rm, rotation = parseOprOfXTA ins ctxt
  let rotated = shiftROR rm 32<rt> rotation
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (rd := rn .+ AST.zext 32<rt> (AST.xtlo amount rotated))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let checkSingleReg = function
  | R.S0 | R.S1 | R.S2 | R.S3 | R.S4 | R.S5 | R.S6 | R.S7 | R.S8 | R.S9
  | R.S10 | R.S11 | R.S12 | R.S13 | R.S14 | R.S15 | R.S16 | R.S17 | R.S18
  | R.S19 | R.S20 | R.S21 | R.S22 | R.S23 | R.S24 | R.S25 | R.S26 | R.S27
  | R.S28 | R.S29 | R.S30 | R.S31 -> true
  | _ -> false

let parseOprOfVLDR (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector d)),
                 OprMemory (OffsetMode (ImmOffset (rn , s, imm)))) ->
    let pc = getRegVar ctxt rn |> convertPCOpr ins ctxt
    let baseAddr = align pc (numI32 4 32<rt>)
    getRegVar ctxt d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ -> raise InvalidOperandException

let vldr ins ctxt =
  let builder = IRBuilder (8)
  let rd, addr, isSReg = parseOprOfVLDR ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if isSReg then
    let data = builder.NewTempVar 32<rt>
    builder <! (data := AST.loadLE 32<rt> addr)
    builder <! (rd := data)
  else
    let d1 = builder.NewTempVar 32<rt>
    let d2 = builder.NewTempVar 32<rt>
    builder <! (d1 := AST.loadLE 32<rt> addr)
    builder <! (d2 := AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>)))
    builder <! (rd := if ctxt.Endianness = Endian.Big then AST.concat d1 d2
                      else AST.concat d2 d1)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfVSTR (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector d)),
                 OprMemory (OffsetMode (ImmOffset (rn , s, imm)))) ->
    let baseAddr = getRegVar ctxt rn
    getRegVar ctxt d, getOffAddrWithImm s baseAddr imm, checkSingleReg d
  | _ -> raise InvalidOperandException

let vstr (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let rd, addr, isSReg = parseOprOfVSTR ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if isSReg then builder <! (AST.loadLE 32<rt> addr := rd)
  else
    let mem1 = AST.loadLE 32<rt> addr
    let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let isbig = ctxt.Endianness = Endian.Big
    builder <!
      (mem1 := if isbig then AST.xthi 32<rt> rd else AST.xtlo 32<rt> rd)
    builder <!
      (mem2 := if isbig then AST.xtlo 32<rt> rd else AST.xthi 32<rt> rd)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

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

let vpopLoop ctxt d imm isSReg addr (builder: IRBuilder) =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      builder <! (getRegVar ctxt reg := AST.loadLE 32<rt> addr)
      singleRegLoop (r + 1) nextAddr
    else ()
  let rec nonSingleRegLoop r addr =
    if r < imm / 2 then
      let reg = d + r |> byte |> OperandHelper.getVFPDRegister
      let word1 = AST.loadLE 32<rt> addr
      let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
      let nextAddr = addr .+ (numI32 8 32<rt>)
      let isbig = ctxt.Endianness = Endian.Big
      builder <! (getRegVar ctxt reg := if isbig then AST.concat word1 word2
                                        else AST.concat word2 word1)
      nonSingleRegLoop (r + 1) nextAddr
    else ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpop ins ctxt =
  let builder = IRBuilder (64) // FIXME
  let t0 = builder.NewTempVar 32<rt>
  let sp = getRegVar ctxt R.SP
  let d, imm, isSReg = parsePUSHPOPsubValue ins
  let addr = sp
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t0 := addr)
  builder <! (sp := addr .+ (numI32 (imm <<< 2) 32<rt>))
  vpopLoop ctxt d imm isSReg t0 builder
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vpushLoop ctxt d imm isSReg addr (builder: IRBuilder) =
  let rec singleRegLoop r addr =
    if r < imm then
      let reg = d + r |> byte |> OperandHelper.getVFPSRegister
      let nextAddr = (addr .+ (numI32 4 32<rt>))
      builder <! (AST.loadLE 32<rt> addr := getRegVar ctxt reg)
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
      builder <! (mem1 := if isbig then data1 else data2)
      builder <! (mem2 := if isbig then data2 else data1)
      nonSingleRegLoop (r + 1) nextAddr
    else ()
  let loopFn = if isSReg then singleRegLoop else nonSingleRegLoop
  loopFn 0 addr

let vpush ins ctxt =
  let builder = IRBuilder (64) // FIXME
  let t0 = builder.NewTempVar 32<rt>
  let sp = getRegVar ctxt R.SP
  let d, imm, isSReg = parsePUSHPOPsubValue ins
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (t0 := sp .- (numI32 (imm <<< 2) 32<rt>))
  builder <! (sp := t0)
  vpushLoop ctxt d imm isSReg t0 builder
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfVAND (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands
      (OprSIMD (SFReg (Vector r1)), OprSIMD (SFReg (Vector r2)),
        OprSIMD (SFReg (Vector r3))) ->
            getRegVar ctxt r1, getRegVar ctxt r2, getRegVar ctxt r3
  | _ -> raise InvalidOperandException

let vand (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let dst, src1, src2 = parseOprOfVAND ins ctxt
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  builder <! (dst := src1 .& src2)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vmrs ins ctxt =
  let builder = IRBuilder (8)
  let rt, fpscr = transTwoOprs ins ctxt
  let cpsr = getRegVar ctxt R.CPSR
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  if rt <> cpsr then builder <! (rt := fpscr)
  else builder <! (cpsr := disablePSRBits ctxt R.CPSR PSR_Cond .|
                           getPSR ctxt R.FPSCR PSR_Cond)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

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
  | Some (OneDT SIMDTypU16) -> 2
  | Some (OneDT SIMDTyp32) | Some (OneDT SIMDTypS32) | Some (OneDT SIMDTypI32)
  | Some (OneDT SIMDTypU32) -> 4
  | Some (OneDT SIMDTyp64) | Some (OneDT SIMDTypS64) | Some (OneDT SIMDTypI64)
  | Some (OneDT SIMDTypU64) -> 8
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
  {
    EBytes = ebytes
    ESize = esize
    RtESize = RegType.fromBitWidth esize
    Elements = elements
    RegIndex = regIndex
  }

let elem vector e size =
  AST.extract vector (RegType.fromBitWidth size) (e * size)

let elemForIR vector vSize index size =
  let index = AST.zext vSize index
  let mask = AST.num <| BitVector.OfBInt (BigInteger.getMask size) vSize
  let eSize = numI32 size vSize
  (vector >> (index .* eSize)) .& mask |> AST.xtlo (RegType.fromBitWidth size)

let getESzieOfVMOV = function
  | Some (OneDT SIMDTyp8) -> 8
  | Some (OneDT SIMDTyp16) -> 16
  | Some (OneDT SIMDTyp32) -> 32
  | _ -> raise InvalidOperandException

let getIndexOfVMOV = function
  | TwoOperands (OprSIMD (SFReg (Scalar (_, Some element))), _) -> int element
  | _ -> raise InvalidOperandException

let isQwordReg = function
  | R.Q0 | R.Q1 | R.Q2 | R.Q3 | R.Q4 | R.Q5 | R.Q6 | R.Q7 | R.Q8 | R.Q9 | R.Q10
  | R.Q11 | R.Q12 | R.Q13 | R.Q14 | R.Q15 -> true
  | _ -> false

let parseOprOfVMOV (ins: InsInfo) ctxt builder =
  match ins.Operands with
  | TwoOperands (OprSIMD _, OprSIMD _) ->
    let dst, src = transTwoOprs ins ctxt
    builder <! (dst := src)
  | TwoOperands (OprSIMD (SFReg (Vector reg)), OprImm _) ->
    if isQwordReg reg then
      let dst, imm = transTwoOprs ins ctxt
      let imm64 = AST.concat imm imm // FIXME
      builder <! (AST.xtlo 64<rt> dst := imm64)
      builder <! (AST.xthi 64<rt> dst := imm64)
    else
      let dst, imm = transTwoOprs ins ctxt
      let imm64 = AST.concat imm imm // FIXME
      builder <! (dst := imm64)
  | TwoOperands (OprSIMD _, OprReg _) ->
    let dst, src = transTwoOprs ins ctxt
    let index = getIndexOfVMOV ins.Operands
    let esize = getESzieOfVMOV ins.SIMDTyp
    builder <! (elem dst index esize := src)
  | _ -> raise InvalidOperandException

let vmov (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  parseOprOfVMOV ins ctxt builder
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

(* VMOV(immediate)/VMOV(register) *)
let isF32orF64 = function
  | Some (OneDT SIMDTypF32) | Some (OneDT SIMDTypF64) -> true
  | _ -> false

let isAdvSIMDByDT = function
  (* VMOV (ARM core register to scalar/scalar to ARM core register) *)
  | Some (OneDT SIMDTyp8) | Some (OneDT SIMDTyp16) -> true
  | Some (OneDT SIMDTyp32) -> false
  (* VMOV (between ARM core register and single-precision register) *)
  (* VMOV (between two ARM core registers and two single-precision registers) *)
  | None -> false
  | _ -> raise UndefinedException

let isAdvancedSIMD (ins: InsInfo) =
  match ins.Operands with
  | TwoOperands (OprSIMD _, OprImm _) | TwoOperands (OprSIMD _, OprSIMD _) ->
    isF32orF64 ins.SIMDTyp |> not
  | TwoOperands (OprSIMD _, OprReg _) | TwoOperands (OprReg _, OprSIMD _)
  | FourOperands (OprSIMD _, OprSIMD _, OprReg _, OprReg _)
  | FourOperands (OprReg _, OprReg _, OprSIMD _, OprSIMD _) ->
    isAdvSIMDByDT ins.SIMDTyp
  (* VMOV (between two ARM core registers and a dword extension register) *)
  | ThreeOperands (OprSIMD _, OprReg _, OprReg _)
  | ThreeOperands (OprReg _, OprReg _, OprSIMD _) -> false
  | _ -> false

let absExpr expr size =
  AST.ite (AST.slt expr (AST.num0 size)) (AST.neg expr) (expr)

let vabs (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm = transTwoOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      builder <! (elem rd e p.ESize := absExpr (elem rm e p.ESize) p.RtESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vadd (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      builder <! (elem rd e p.ESize := elem rn e p.ESize .+ elem rm e p.ESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vaddl (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let esize = 8 * (getEBytes ins.SIMDTyp)
  let rtEsize = RegType.fromBitWidth esize
  let eSzDbl = rtEsize * 2
  let elements = 64 / esize
  let op1 = !*ir rtEsize
  let result = !*ir eSzDbl
  for e in 0 .. elements - 1 do
    !!ir (op1 := elem src1 e esize)
    !!ir (result := AST.zext eSzDbl op1 .+ AST.zext eSzDbl (elem src2 e esize))
    !!ir (elem dst e (2 * esize) := result)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let parseOprOfVDUP (ins: InsInfo) ctxt esize =
  match ins.Operands with
  | TwoOperands (OprSIMD (SFReg (Vector rd)),
                 OprSIMD (SFReg (Scalar (rm, Some idx)))) ->
    getRegVar ctxt rd, elem (getRegVar ctxt rm) (int32 idx) esize
  | TwoOperands (OprSIMD (SFReg (Vector rd)), OprReg rm) ->
    getRegVar ctxt rd,
    AST.xtlo (RegType.fromBitWidth esize) (getRegVar ctxt rm)
  | _ -> raise InvalidOperandException

let vdup (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let esize = 8 * getEBytes ins.SIMDTyp
  let rd, scalar = parseOprOfVDUP ins ctxt esize
  let elements = 64 / esize
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    for e in 0 .. elements - 1 do builder <! (elem rd e esize := scalar) done
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let highestSetBitForIR dst src width oprSz (builder: IRBuilder) =
  let lblLoop = builder.NewSymbol "Loop"
  let lblLoopCont = builder.NewSymbol "LoopContinue"
  let lblUpdateTmp = builder.NewSymbol "UpdateTmp"
  let lblEnd = builder.NewSymbol "End"
  let t = builder.NewTempVar oprSz
  let width = (numI32 (width - 1) oprSz)
  builder <! (t := width)
  builder <! (AST.lmark lblLoop)
  builder <! (AST.cjmp (src >> t == AST.num1 oprSz)
                       (AST.name lblEnd) (AST.name lblLoopCont))
  builder <! (AST.lmark lblLoopCont)
  builder <! (AST.cjmp (t == AST.num0 oprSz)
                       (AST.name lblEnd) (AST.name lblUpdateTmp))
  builder <! (AST.lmark lblUpdateTmp)
  builder <! (t := t .- AST.num1 oprSz)
  builder <! (AST.jmp (AST.name lblLoop))
  builder <! (AST.lmark lblEnd)
  builder <! (dst := width .- t)

let countLeadingZeroBitsForIR dst src oprSize builder =
  highestSetBitForIR dst src (RegType.toBitWidth oprSize) oprSize builder

let vclz (ins: InsInfo) ctxt =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm = transTwoOprs ins ctxt
  let pInfo = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. pInfo.Elements - 1 do
      countLeadingZeroBitsForIR (elem rd e pInfo.ESize) (elem rm e pInfo.ESize)
                                pInfo.RtESize builder
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let maxExpr isUnsigned expr1 expr2 =
  let op = if isUnsigned then AST.gt else AST.sgt
  AST.ite (op expr1 expr2) expr1 expr2

let minExpr isUnsigned expr1 expr2 =
  let op = if isUnsigned then AST.lt else AST.slt
  AST.ite (op expr1 expr2) expr1 expr2

let isUnsigned = function
  | Some (OneDT SIMDTypU8) | Some (OneDT SIMDTypU16)
  | Some (OneDT SIMDTypU32) | Some (OneDT SIMDTypU64) -> true
  | Some (OneDT SIMDTypS8) | Some (OneDT SIMDTypS16)
  | Some (OneDT SIMDTypS32) | Some (OneDT SIMDTypS64) | Some (OneDT SIMDTypP8)
    -> false
  | _ -> raise InvalidOperandException

let vmaxmin (ins: InsInfo) ctxt maximum =
  let builder = IRBuilder (32)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let pInfo = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let unsigned = isUnsigned ins.SIMDTyp
  for r in 0 .. regs - 1 do
    let rn = AST.extract rn 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    let rd = AST.extract rd 64<rt> (r * 64)
    for e in 0 .. pInfo.Elements - 1 do
      let op1 = elem rn e pInfo.ESize
      let op2 = elem rm e pInfo.ESize
      let result =
        if maximum then maxExpr unsigned op1 op2 else minExpr unsigned op1 op2
      builder <! (elem rd e pInfo.ESize := AST.xtlo pInfo.RtESize result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vsub (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      builder <! (elem rd e p.ESize := elem rn e p.ESize .- elem rm e p.ESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfVSTLDM (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg reg, OprRegList regs) ->
    getRegVar ctxt reg, List.map (getRegVar ctxt) regs
  | _ -> raise InvalidOperandException

let vstm (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rn, regList = parseOprOfVSTLDM ins ctxt
  let add =
    match ins.Opcode with
    | Op.VSTMIA -> true
    | Op.VSTMDB -> false
    | _ -> raise InvalidOpcodeException
  let regs = List.length regList
  let imm32 = numI32 ((regs * 2) <<< 2) 32<rt>
  let addr = builder.NewTempVar 32<rt>
  let updateRn rn =
    if ins.WriteBack then
      if add then rn .+ imm32 else rn .- imm32
    else rn
  builder <! (addr := if add then rn else rn .- imm32)
  builder <! (rn := updateRn rn)
  for r in 0 .. (regs - 1) do
    let mem1 = AST.loadLE 32<rt> addr
    let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let data1 = AST.xtlo 32<rt> regList[r]
    let data2 = AST.xthi 32<rt> regList[r]
    let isbig = ctxt.Endianness = Endian.Big
    builder <! (mem1 := if isbig then data2 else data1)
    builder <! (mem2 := if isbig then data1 else data2)
    builder <! (addr := addr .+ (numI32 8 32<rt>))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vldm (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rn, regList = parseOprOfVSTLDM ins ctxt
  let add =
    match ins.Opcode with
    | Op.VLDMIA -> true
    | Op.VLDMDB -> false
    | _ -> raise InvalidOpcodeException
  let regs = List.length regList
  let imm32 = numI32 ((regs * 2) <<< 2) 32<rt>
  let addr = builder.NewTempVar 32<rt>
  let updateRn rn =
    if ins.WriteBack then
      if add then rn .+ imm32 else rn .- imm32
    else rn
  builder <! (addr := if add then rn else rn .- imm32)
  builder <! (rn := updateRn rn)
  for r in 0 .. (regs - 1) do
    let word1 = AST.loadLE 32<rt> addr
    let word2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
    let isbig = ctxt.Endianness = Endian.Big
    builder <!
      (regList[r] := if isbig then AST.concat word1 word2
                     else AST.concat word2 word1)
    builder <! (addr := addr .+ (numI32 8 32<rt>))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vecMulAccOrSub (ins: InsInfo) ctxt add =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let pInfo = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. pInfo.Elements - 1 do
      let sext reg = AST.sext pInfo.RtESize (elem reg e pInfo.ESize)
      let product = sext rn .* sext rm
      let addend = if add then product else AST.not product
      builder <! (elem rd e pInfo.ESize := elem rd e pInfo.ESize .+ addend)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vecMulAccOrSubLong (ins: InsInfo) ctxt add =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let unsigned = isUnsigned ins.SIMDTyp
  for e in 0 .. p.Elements - 1 do
    let extend expr =
      if unsigned then AST.zext (p.RtESize * 2) expr
      else AST.sext (p.RtESize * 2) expr
    let product = extend (elem rn e p.ESize) .* extend (elem rm e p.ESize)
    let addend = if add then product else AST.not product
    builder <! (elem rd e (p.ESize * 2) := elem rd e (p.ESize * 2) .+ addend)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseOprOfVMulByScalar (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprSIMD (SFReg (Vector rd)),
                   OprSIMD (SFReg (Vector rn)),
                   OprSIMD (SFReg (Scalar (rm, Some index)))) ->
    getRegVar ctxt rd, getRegVar ctxt rn, (getRegVar ctxt rm, int32 index)
  | _ -> raise InvalidOperandException

let vecMulAccOrSubByScalar (ins: InsInfo) ctxt add =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, (rm, index) = parseOprOfVMulByScalar ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let op2val = AST.sext p.RtESize (elem rm index p.ESize)
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let op1val = AST.sext p.RtESize (elem rn e p.ESize)
      let addend = if add then op1val .* op2val else AST.not (op1val .* op2val)
      builder <! (elem rd e p.ESize := elem rd e p.ESize .+ addend)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vecMulAccOrSubLongByScalar (ins: InsInfo) ctxt add =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, (rm, index) = parseOprOfVMulByScalar ins ctxt
  let p = getParsingInfo ins
  let ext = if isUnsigned ins.SIMDTyp then AST.sext else AST.zext
  let op2val = ext (p.RtESize * 2) (elem rm index p.ESize)
  for e in 0 .. p.Elements - 1 do
    let op1val = ext (p.RtESize * 2) (elem rn e p.ESize)
    let addend = if add then op1val .* op2val else AST.not (op1val .* op2val)
    builder <! (elem rd e (p.ESize * 2) := elem rd e (p.ESize * 2) .+ addend)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vmla (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSub ins ctxt true
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubByScalar ins ctxt true
  | _ -> raise InvalidOperandException

let vmlal (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSubLong ins ctxt true
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubLongByScalar ins ctxt true
  | _ -> raise InvalidOperandException

let vmls (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSub ins ctxt false
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubByScalar ins ctxt false
  | _ -> raise InvalidOperandException

let vmlsl (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulAccOrSubLong ins ctxt false
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulAccOrSubLongByScalar ins ctxt false
  | _ -> raise InvalidOperandException

let isPolynomial = function
  | Some (OneDT SIMDTypP8) -> true
  | _ -> false

// PolynomialMult()
// A2.8.1 Pseudocode details of polynomial multiplication
let polynomialMult op1 op2 size = AST.concat op1 op2 // FIXME
(* A2.8.1 Pseudocode details of polynomial multiplication
bits(M+N) PolynomialMult(bits(M) op1, bits(N) op2)
  result = Zeros(M+N);
  extended_op2 = Zeros(M) : op2;
  for i=0 to M-1
    if op1<i> == '1' then
      result = result EOR LSL(extended_op2, i);
  return result;
*)

let vecMul (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let polynomial = isPolynomial ins.SIMDTyp
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let sext reg = AST.sext (p.RtESize * 2) (elem reg e p.ESize)
      let product =
        if polynomial then polynomialMult rn rm p.ESize else sext rn .* sext rm
      builder <! (elem rd e p.ESize := AST.xtlo p.RtESize product)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vecMulLong (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let unsigned = isUnsigned ins.SIMDTyp
  for e in 0 .. p.Elements - 1 do
    let extend reg =
      if unsigned then AST.zext (p.RtESize * 2) (elem reg e p.ESize)
      else AST.sext (p.RtESize * 2) (elem reg e p.ESize)
    let product = AST.xtlo (p.RtESize * 2) (extend rn .* extend rm)
    builder <! (elem rd e (p.ESize * 2) := product)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vecMulByScalar (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, (rm, index) = parseOprOfVMulByScalar ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let op2val = AST.sext (RegType.fromBitWidth p.ESize) (elem rm index p.ESize)
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let op1val = AST.sext p.RtESize (elem rn e p.ESize)
      builder <! (elem rd e p.ESize := AST.xtlo p.RtESize (op1val .* op2val))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vecMulLongByScalar (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, (rm, index) = parseOprOfVMulByScalar ins ctxt
  let p = getParsingInfo ins
  let rtESz = p.RtESize * 2
  let ext = if isUnsigned ins.SIMDTyp then AST.sext else AST.zext
  let op2val = ext rtESz (elem rm index p.ESize)
  for e in 0 .. p.Elements - 1 do
    let op1val = ext rtESz (elem rn e p.ESize)
    builder <! (elem rd e (p.ESize * 2) := AST.xtlo rtESz (op1val .* op2val))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vmul (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMul ins ctxt
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulByScalar ins ctxt
  | _ -> raise InvalidOperandException

let vmull (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprSIMD (SFReg (Vector _))) ->
    vecMulLong ins ctxt
  | ThreeOperands (_, _, OprSIMD (SFReg (Scalar _))) ->
    vecMulLongByScalar ins ctxt
  | _ -> raise InvalidOperandException

let getSizeStartFromI16 = function
  | Some (OneDT SIMDTypI16) -> 0b00
  | Some (OneDT SIMDTypI32) -> 0b01
  | Some (OneDT SIMDTypI64) -> 0b10
  | _ -> raise InvalidOperandException

let vmovn (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm = transTwoOprs ins ctxt
  let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
  let rtEsz = RegType.fromBitWidth esize
  let elements = 64 / esize
  for e in 0 .. elements - 1 do
    builder <! (elem rd e esize := AST.xtlo rtEsz (elem rm e (esize * 2)))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vneg (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm = transTwoOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let result = AST.neg <| AST.sext p.RtESize (elem rm e p.ESize)
      builder <! (elem rd e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vpadd (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let h = p.Elements / 2
  let dest = builder.NewTempVar 64<rt>
  builder <! (dest := AST.num0 64<rt>)
  for e in 0 .. h - 1 do
    let addPair expr =
      elem expr (2 * e) p.ESize .+ elem expr (2 * e + 1) p.ESize
    builder <! (elem dest e p.ESize := addPair rn)
    builder <! (elem dest (e + h) p.ESize := addPair rm)
  builder <! (rd := dest)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vrshr (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm, imm = transThreeOprs ins ctxt
  let imm = AST.zext 64<rt> imm
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  let roundConst = AST.num1 64<rt> << (imm .- AST.num1 64<rt>)
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let result = (extend 64<rt> (elem rm e p.ESize) .+ roundConst) >> imm
      builder <! (elem rd e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vshlImm (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm, imm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let imm = AST.zext p.RtESize imm
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      builder <! (elem rd e p.ESize := elem rm e p.ESize << imm)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vshlReg (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm, rn = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let shift = AST.sext 64<rt> (AST.xtlo 8<rt> (elem rn e p.ESize))
      let result = extend 64<rt> (elem rm e p.ESize) << shift
      builder <! (elem rd e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vshl (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (_, _, OprImm _) -> vshlImm ins ctxt
  | ThreeOperands (_, _, OprSIMD _) -> vshlReg ins ctxt
  | _ -> raise InvalidOperandException

let vshr (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm, imm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let imm = AST.zext 64<rt> imm
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let extend = if isUnsigned ins.SIMDTyp then AST.zext else AST.sext
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let result = extend 64<rt> (elem rm e p.ESize) >> imm
      builder <! (elem rd e p.ESize := AST.xtlo p.RtESize result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let parseVectors = function
  | OneReg (Vector d) -> [ d ]
  | TwoRegs (Vector d1, Vector d2) -> [ d1; d2 ]
  | ThreeRegs (Vector d1, Vector d2, Vector d3) -> [ d1; d2; d3 ]
  | FourRegs (Vector d1, Vector d2, Vector d3, Vector d4) -> [ d1; d2; d3; d4 ]
  | _ -> raise InvalidOperandException

let parseOprOfVecTbl (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprSIMD (SFReg (Vector rd)), OprSIMD regs,
                   OprSIMD (SFReg (Vector rm))) ->
    getRegVar ctxt rd, parseVectors regs, getRegVar ctxt rm
  | _ -> raise InvalidOperandException

let vecTbl (ins: InsInfo) ctxt isVtbl =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, list, rm = parseOprOfVecTbl ins ctxt
  let vectors = list |> List.map (getRegVar ctxt)
  let length = List.length list
  let table = AST.concatArr (List.toArray vectors) |> AST.zext 256<rt>
  for i in 0 .. 7 do
    let index = elem rm i 8
    let cond = AST.lt index (numI32 (8 * length) 8<rt>)
    let e = if isVtbl then AST.num0 8<rt> else elem rd i 8
    builder <! (elem rd i 8 := AST.ite cond (elemForIR table 256<rt> index 8) e)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let isImm = function
  | Num _ -> true
  | _ -> false

let vectorCompare (ins: InsInfo) ctxt cmp =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, src1, src2 = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let src1 = AST.extract src1 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let src2 = if isImm src2.E then AST.num0 p.RtESize
                 else elem (AST.extract src2 64<rt> (r * 64)) e p.ESize
      let t = cmp (elem src1 e p.ESize) src2
      builder <!
        (elem rd e p.ESize := AST.ite t (ones p.RtESize) (AST.num0 p.RtESize))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let getCmp (ins: InsInfo) unsigned signed =
  if isUnsigned ins.SIMDTyp then unsigned else signed

let vceq ins ctxt = vectorCompare ins ctxt (==)
let vcge ins ctxt = vectorCompare ins ctxt (getCmp ins AST.ge AST.sge)
let vcgt ins ctxt = vectorCompare ins ctxt (getCmp ins AST.gt AST.sgt)
let vcle ins ctxt = vectorCompare ins ctxt (getCmp ins AST.le AST.sle)
let vclt ins ctxt = vectorCompare ins ctxt (getCmp ins AST.lt AST.slt)

let vtst (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let p = getParsingInfo ins
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  let n0 = AST.num0 p.RtESize
  let n1 = AST.num1 p.RtESize
  for r in 0 .. regs - 1 do
    let rd = AST.extract rd 64<rt> (r * 64)
    let rn = AST.extract rn 64<rt> (r * 64)
    let rm = AST.extract rm 64<rt> (r * 64)
    for e in 0 .. p.Elements - 1 do
      let c = (elem rn e p.ESize .& elem rm e p.ESize) != AST.num0 p.RtESize
      builder <!
        (elem rd e p.ESize :=
          AST.ite c (AST.num1 p.RtESize) (AST.num0 p.RtESize))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vrshrn (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rm, imm = transThreeOprs ins ctxt
  let esize = 8 <<< getSizeStartFromI16 ins.SIMDTyp
  let rtEsz = RegType.fromBitWidth esize
  let imm = AST.zext (rtEsz * 2) imm
  let elements = 64 / esize
  let roundConst = AST.num1 (rtEsz * 2) << (imm .- AST.num1 (rtEsz * 2))
  for e in 0 .. elements - 1 do
    let result = (elem rm e (2 * esize) .+ roundConst) >> imm
    builder <! (elem rd e esize := AST.xtlo rtEsz result)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vorrReg (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let reg expr = AST.extract expr 64<rt> (r * 64)
    builder <! (reg rd := reg rn .| reg rm)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vorrImm (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, imm = transTwoOprs ins ctxt
  let imm = AST.concat imm imm // FIXME: A8-975
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    builder <!
      (AST.extract rd 64<rt> (r * 64) := AST.extract rd 64<rt> (r * 64) .| imm)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vorr (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands _ -> vorrReg ins ctxt
  | TwoOperands _ -> vorrImm ins ctxt
  | _ -> raise InvalidOperandException

let vornReg (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = transThreeOprs ins ctxt
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    let reg expr = AST.extract expr 64<rt> (r * 64)
    builder <! (reg rd := reg rn .| (AST.not <| reg rm))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vornImm (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, imm = transTwoOprs ins ctxt
  let imm = AST.concat imm imm // FIXME: A8-975
  let regs = if TypeCheck.typeOf rd = 64<rt> then 1 else 2
  for r in 0 .. regs - 1 do
    builder <!
      (AST.extract rd 64<rt> (r * 64) :=
        AST.extract rd 64<rt> (r * 64) .| AST.not imm)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vorn (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands _ -> vornReg ins ctxt
  | TwoOperands _ -> vornImm ins ctxt
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

let assignByEndian (ctxt: TranslationContext) dst src builder =
  let isbig = ctxt.Endianness = Endian.Big
  builder <!
    (dst := if isbig then AST.xthi 32<rt> src else AST.xtlo 32<rt> src)

let parseOprOfVecStAndLd ctxt (ins: InsInfo) =
  let rdList = parseDstList ins.Operands |> List.map (getRegVar ctxt)
  let rn, rm = getRnAndRm ctxt ins.Operands
  rdList, rn, rm

let updateRn (ins: InsInfo) rn (rm: Expr option) n (regIdx: bool option) =
  let rmOrTransSz = if regIdx.Value then rm.Value else numI32 n 32<rt>
  if ins.WriteBack then rn .+ rmOrTransSz else rn

let incAddr addr n = addr .+ (numI32 n 32<rt>)

let vst1Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let regs = getRegs ins.Operands
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (8 * regs) pInfo.RegIndex)
  for r in 0 .. (regs - 1) do
    for e in 0 .. (pInfo.Elements - 1) do
      if pInfo.EBytes <> 8 then
        let mem = AST.loadLE pInfo.RtESize addr
        builder <! (mem := elem rdList[r] e pInfo.ESize)
      else
        let mem1 = AST.loadLE 32<rt> addr
        let mem2 = AST.loadLE 32<rt> (incAddr addr 4)
        let reg = elem rdList[r] e pInfo.ESize
        assignByEndian ctxt mem1 reg builder
        assignByEndian ctxt mem2 reg builder
      builder <! (addr := addr .+ (numI32 pInfo.EBytes 32<rt>))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst1Single (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm pInfo.EBytes pInfo.RegIndex)
  let mem = AST.loadLE pInfo.RtESize addr
  builder <! (mem := elem rd[0] (int32 index) pInfo.ESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst1 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (OneReg (Scalar (_, Some index))), _) ->
    vst1Single ins ctxt index
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst1Multi ins ctxt
  | _ -> raise InvalidOperandException

let vld1SingleOne (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rd, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm pInfo.EBytes pInfo.RegIndex)
  let mem = AST.loadLE pInfo.RtESize addr
  builder <! (elem rd[0] (int32 index) pInfo.ESize := mem)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld1SingleAll (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm pInfo.EBytes pInfo.RegIndex)
  let mem = AST.loadLE pInfo.RtESize addr
  let repElem = Array.replicate pInfo.Elements mem |> AST.concatArr
  for r in 0 .. (List.length rdList - 1) do
    builder <! (rdList[r] := repElem) done
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld1Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let regs = getRegs ins.Operands
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (8 * regs) pInfo.RegIndex)
  for r in 0 .. (regs - 1) do
    for e in 0 .. (pInfo.Elements - 1) do
      if pInfo.EBytes <> 8 then
        let data = builder.NewTempVar pInfo.RtESize
        builder <! (data := AST.loadLE pInfo.RtESize addr)
        builder <! (elem rdList[r] e pInfo.ESize := data)
      else
        let data1 = builder.NewTempVar 32<rt>
        let data2 = builder.NewTempVar 32<rt>
        let mem1 = AST.loadLE 32<rt> addr
        let mem2 = AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>))
        let isbig = ctxt.Endianness = Endian.Big
        builder <! (data1 := if isbig then mem2 else mem1)
        builder <! (data2 := if isbig then mem1 else mem1)
        builder <! (elem rdList[r] e pInfo.ESize := AST.concat data2 data1)
      builder <! (addr := incAddr addr pInfo.EBytes)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld1 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (OneReg (Scalar (_, Some index))), _) ->
    vld1SingleOne ins ctxt index
  | TwoOperands (OprSIMD (OneReg (Scalar _)), _)
  | TwoOperands (OprSIMD (TwoRegs (Scalar _, Scalar _)), _) ->
    vld1SingleAll ins ctxt
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld1Multi ins ctxt
  | _ -> raise InvalidOperandException

let vst2Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let regs = getRegs ins.Operands / 2
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (16 * regs) pInfo.RegIndex)
  for r in 0 .. (regs - 1) do
    let rd1 = rdList[r * 2]
    let rd2 = rdList[r * 2 + 1]
    for e in 0 .. (pInfo.Elements - 1) do
      let mem1 = AST.loadLE pInfo.RtESize addr
      let mem2 = AST.loadLE pInfo.RtESize (addr .+ (numI32 pInfo.EBytes 32<rt>))
      builder <! (mem1 := elem rd1 e pInfo.ESize)
      builder <! (mem2 := elem rd2 e pInfo.ESize)
      builder <! (addr := addr .+ (numI32 (2 * pInfo.EBytes) 32<rt>))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst2Single (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (16 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (addr .+ (numI32 pInfo.EBytes 32<rt>))
  builder <! (mem1 := elem rdList[0] index pInfo.ESize)
  builder <! (mem2 := elem rdList[1] index pInfo.ESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst2 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (TwoRegs (Scalar (_, Some index), _)), _) ->
    vst2Single ins ctxt (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst2Multi ins ctxt
  | _ -> raise InvalidOperandException

let vst3Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm 24 pInfo.RegIndex)
  for e in 0 .. (pInfo.Elements - 1) do
    let mem1 = AST.loadLE pInfo.RtESize addr
    let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
    let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
    builder <! (mem1 := elem rdList[0] e pInfo.ESize)
    builder <! (mem2 := elem rdList[1] e pInfo.ESize)
    builder <! (mem3 := elem rdList[2] e pInfo.ESize)
    builder <! (addr := incAddr addr (3 * pInfo.EBytes))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst3Single (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (3 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
  builder <! (mem1 := elem rdList[0] index pInfo.ESize)
  builder <! (mem2 := elem rdList[1] index pInfo.ESize)
  builder <! (mem3 := elem rdList[2] index pInfo.ESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst3 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, Some index), _, _)), _) ->
    vst3Single ins ctxt (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst3Multi ins ctxt
  | _ -> raise InvalidOperandException

let vst4Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm 32 pInfo.RegIndex)
  for e in 0 .. (pInfo.Elements - 1) do
    let mem1 = AST.loadLE pInfo.RtESize addr
    let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
    let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
    let mem4 = AST.loadLE pInfo.RtESize (incAddr addr (3 * pInfo.EBytes))
    builder <! (mem1 := elem rdList[0] e pInfo.ESize)
    builder <! (mem2 := elem rdList[1] e pInfo.ESize)
    builder <! (mem3 := elem rdList[2] e pInfo.ESize)
    builder <! (mem4 := elem rdList[3] e pInfo.ESize)
    builder <! (addr := incAddr addr (4 * pInfo.EBytes))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst4Single (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (4 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
  let mem4 = AST.loadLE pInfo.RtESize (incAddr addr (3 * pInfo.EBytes))
  builder <! (mem1 := elem rdList[0] index pInfo.ESize)
  builder <! (mem2 := elem rdList[1] index pInfo.ESize)
  builder <! (mem3 := elem rdList[2] index pInfo.ESize)
  builder <! (mem4 := elem rdList[3] index pInfo.ESize)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vst4 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, Some index), _, _, _)), _) ->
    vst4Single ins ctxt (int32 index)
  | TwoOperands (OprSIMD (OneReg _), _)
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (ThreeRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vst4Multi ins ctxt
  | _ -> raise InvalidOperandException

let vld2SingleOne (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (2 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  builder <! (elem rdList[0] (int32 index) pInfo.ESize := mem1)
  builder <! (elem rdList[1] (int32 index) pInfo.ESize := mem2)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld2SingleAll (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (2 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let repElem1 = Array.replicate pInfo.Elements mem1 |> AST.concatArr
  let repElem2 = Array.replicate pInfo.Elements mem2 |> AST.concatArr
  builder <! (rdList[0] := repElem1)
  builder <! (rdList[1] := repElem2)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld2Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let regs = getRegs ins.Operands / 2
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (16 * regs) pInfo.RegIndex)
  for r in 0 .. (regs - 1) do
    let rd1 = rdList[r * 2]
    let rd2 = rdList[r * 2 + 1]
    for e in 0 .. (pInfo.Elements - 1) do
      let mem1 = AST.loadLE pInfo.RtESize addr
      let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
      builder <! (elem rd1 e pInfo.ESize := mem1)
      builder <! (elem rd2 e pInfo.ESize := mem2)
      builder <! (addr := incAddr addr (2 * pInfo.EBytes))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld2 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (TwoRegs (Scalar (_, Some index), _)), _) ->
    vld2SingleOne ins ctxt index
  | TwoOperands (OprSIMD (TwoRegs (Scalar _, Scalar _)), _) ->
    vld2SingleAll ins ctxt
  | TwoOperands (OprSIMD (TwoRegs _), _)
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld2Multi ins ctxt
  | _ -> raise InvalidOperandException

let vld3SingleOne (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (3 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
  builder <! (elem rdList[0] (int32 index) pInfo.ESize := mem1)
  builder <! (elem rdList[1] (int32 index) pInfo.ESize := mem2)
  builder <! (elem rdList[2] (int32 index) pInfo.ESize := mem3)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld3SingleAll (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (3 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
  let repElem1 = Array.replicate pInfo.Elements mem1 |> AST.concatArr
  let repElem2 = Array.replicate pInfo.Elements mem2 |> AST.concatArr
  let repElem3 = Array.replicate pInfo.Elements mem3 |> AST.concatArr
  builder <! (rdList[0] := repElem1)
  builder <! (rdList[1] := repElem2)
  builder <! (rdList[2] := repElem3)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld3Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm 24 pInfo.RegIndex)
  for e in 0 .. (pInfo.Elements - 1) do
    let mem1 = AST.loadLE pInfo.RtESize addr
    let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
    let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
    builder <! (elem rdList[0] e pInfo.ESize := mem1)
    builder <! (elem rdList[1] e pInfo.ESize := mem2)
    builder <! (elem rdList[2] e pInfo.ESize := mem3)
    builder <! (addr := addr .+ (numI32 (3 * pInfo.EBytes) 32<rt>))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld3 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, Some index), _, _)), _) ->
    vld3SingleOne ins ctxt index
  | TwoOperands (OprSIMD (ThreeRegs (Scalar (_, None), _, _)), _) ->
    vld3SingleAll ins ctxt
  | TwoOperands (OprSIMD (ThreeRegs _), _) -> vld3Multi ins ctxt
  | _ -> raise InvalidOperandException

let vld4SingleOne (ins: InsInfo) ctxt index =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (4 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
  let mem4 = AST.loadLE pInfo.RtESize (incAddr addr (3 * pInfo.EBytes))
  builder <! (elem rdList[0] (int32 index) pInfo.ESize := mem1)
  builder <! (elem rdList[1] (int32 index) pInfo.ESize := mem2)
  builder <! (elem rdList[2] (int32 index) pInfo.ESize := mem3)
  builder <! (elem rdList[3] (int32 index) pInfo.ESize := mem4)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld4SingleAll (ins: InsInfo) ctxt =
  let builder = IRBuilder (8)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm (4 * pInfo.EBytes) pInfo.RegIndex)
  let mem1 = AST.loadLE pInfo.RtESize addr
  let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
  let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
  let mem4 = AST.loadLE pInfo.RtESize (incAddr addr (3 * pInfo.EBytes))
  let repElem1 = Array.replicate pInfo.Elements mem1 |> AST.concatArr
  let repElem2 = Array.replicate pInfo.Elements mem2 |> AST.concatArr
  let repElem3 = Array.replicate pInfo.Elements mem3 |> AST.concatArr
  let repElem4 = Array.replicate pInfo.Elements mem4 |> AST.concatArr
  builder <! (rdList[0] := repElem1)
  builder <! (rdList[1] := repElem2)
  builder <! (rdList[2] := repElem3)
  builder <! (rdList[3] := repElem4)
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld4Multi (ins: InsInfo) ctxt =
  let builder = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  startMark ins builder
  let lblIgnore = checkCondition ins ctxt isUnconditional builder
  let rdList, rn, rm = parseOprOfVecStAndLd ctxt ins
  let pInfo = getParsingInfo ins
  let addr = builder.NewTempVar 32<rt>
  builder <! (addr := rn)
  builder <! (rn := updateRn ins rn rm 24 pInfo.RegIndex)
  for e in 0 .. (pInfo.Elements - 1) do
    let mem1 = AST.loadLE pInfo.RtESize addr
    let mem2 = AST.loadLE pInfo.RtESize (incAddr addr pInfo.EBytes)
    let mem3 = AST.loadLE pInfo.RtESize (incAddr addr (2 * pInfo.EBytes))
    let mem4 = AST.loadLE pInfo.RtESize (incAddr addr (3 * pInfo.EBytes))
    builder <! (elem rdList[0] e pInfo.ESize := mem1)
    builder <! (elem rdList[1] e pInfo.ESize := mem2)
    builder <! (elem rdList[2] e pInfo.ESize := mem3)
    builder <! (elem rdList[3] e pInfo.ESize := mem4)
    builder <! (addr := addr .+ (numI32 (4 * pInfo.EBytes) 32<rt>))
  putEndLabel ctxt lblIgnore isUnconditional None builder
  endMark ins builder

let vld4 (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, Some index), _, _, _)), _) ->
    vld4SingleOne ins ctxt index
  | TwoOperands (OprSIMD (FourRegs (Scalar (_, None), _, _, _)), _) ->
    vld4SingleAll ins ctxt
  | TwoOperands (OprSIMD (FourRegs _), _) -> vld4Multi ins ctxt
  | _ -> raise InvalidOperandException

let udf (ins: InsInfo) =
  match ins.Operands with
  | OneOperand (OprImm n) -> sideEffects ins (Interrupt (int n))
  | _ ->  raise InvalidOperandException

let uasx (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
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
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let uhsub16 (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let struct (diff1, diff2) = tmpVars2 ir 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  let n1 = AST.num1 32<rt>
  !!ir (diff1 := xtlo src1 .- xtlo src2)
  !!ir (diff2 := xthi src1 .- xthi src2)
  !!ir (dst :=
    AST.concat (AST.xtlo 16<rt> (diff2 >> n1)) (AST.xtlo 16<rt> (diff1 >> n1)))
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let uqsax (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let struct (sum, diff) = tmpVars2 ir 32<rt>
  let xtlo src = AST.xtlo 16<rt> src |> AST.zext 32<rt>
  let xthi src = AST.xthi 16<rt> src |> AST.zext 32<rt>
  !!ir (sum := xtlo src1 .+ xthi src2)
  !!ir (diff := xthi src1 .- xtlo src2)
  !!ir (dst := AST.concat (AST.xtlo 16<rt> diff) (AST.xtlo 16<rt> sum))
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let usax (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
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
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let vext (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2, imm = transFourOprs ins ctxt
  let oprSize = TypeCheck.typeOf dst
  let position = !*ir (oprSize * 2)
  !!ir (position := imm .* (numI32 8 32<rt>) |> AST.zext (oprSize * 2))
  !!ir (dst := AST.concat src2 src1 >> position |> AST.xtlo oprSize)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let vhadd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let esize = 8 * (getEBytes ins.SIMDTyp)
  let rtEsize = RegType.fromBitWidth esize
  let oprSize = TypeCheck.typeOf dst
  let elements = oprSize / esize |> int
  let struct (op1, op2, result) = tmpVars3 ir rtEsize
  for e in 0 .. elements - 1 do
    !!ir (op1 := elem src1 e esize)
    !!ir (op2 := elem src2 e esize)
    !!ir (result := op1 .+ op2)
    !!ir (elem dst e esize := result >> (AST.num1 rtEsize))
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let vhsub (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let esize = 8 * (getEBytes ins.SIMDTyp)
  let rtEsize = RegType.fromBitWidth esize
  let oprSize = TypeCheck.typeOf dst
  let elements = oprSize / esize |> int
  let struct (op1, op2, result) = tmpVars3 ir rtEsize
  for e in 0 .. elements - 1 do
    !!ir (op1 := elem src1 e esize)
    !!ir (op2 := elem src2 e esize)
    !!ir (result := op1 .- op2)
    !!ir (elem dst e esize := result >> (AST.num1 rtEsize))
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let vrhadd (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src1, src2 = transThreeOprs ins ctxt
  let esize = 8 * (getEBytes ins.SIMDTyp)
  let rtEsize = RegType.fromBitWidth esize
  let oprSize = TypeCheck.typeOf dst
  let elements = oprSize / esize |> int
  let struct (op1, op2) = tmpVars2 ir rtEsize
  for e in 0 .. elements - 1 do
    !!ir (op1 := elem src1 e esize)
    !!ir (op2 := elem src2 e esize)
    let result = op1 .+ op2 .+ AST.num1 rtEsize
    !!ir (elem dst e esize := AST.xtlo rtEsize (result >> (AST.num1 rtEsize)))
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let vsra (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src, amt = transThreeOprs ins ctxt
  let esize = 8 * (getEBytes ins.SIMDTyp)
  let rtEsize = RegType.fromBitWidth esize
  let oprSize = TypeCheck.typeOf dst
  let elements = oprSize / esize |> int
  let struct (result, shfAmt) = tmpVars2 ir rtEsize
  !!ir (shfAmt :=
    if rtEsize = 64<rt> then AST.zext rtEsize amt else AST.xtlo rtEsize amt)
  for e in 0 .. elements - 1 do
    !!ir (result := (elem src e esize) >> shfAmt)
    !!ir (elem dst e esize := elem dst e esize .+ result)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

let vuzp (ins: InsInfo) insLen ctxt =
  let ir = IRBuilder (16)
  let isUnconditional = ParseUtils.isUnconditional ins.Condition
  !<ir insLen
  let lblIgnore = checkCondition ins ctxt isUnconditional ir
  let dst, src = transTwoOprs ins ctxt
  let esize = 8 * (getEBytes ins.SIMDTyp)
  let oprSize = TypeCheck.typeOf dst
  let zipped = !*ir (oprSize * 2)
  if dst = src then
    !!ir (dst := AST.undef oprSize "UNKNOWN")
    !!ir (src := AST.undef oprSize "UNKNOWN")
  else
    !!ir (zipped := AST.concat src dst)
    for e in 0 .. ((int oprSize) / esize) - 1 do
      !!ir (elem dst e esize := elem zipped (e * 2) esize)
      !!ir (elem src e esize := elem zipped (e * 2 + 1) esize)
  putEndLabel ctxt lblIgnore isUnconditional None ir
  !>ir insLen

/// Translate IR.
let translate (ins: ARM32InternalInstruction) insLen ctxt =
  match ins.Opcode with
  | Op.ADC -> adc false ins ctxt
  | Op.ADCS -> adcs true ins ctxt
  | Op.ADD | Op.ADDW -> add false ins ctxt
  | Op.ADDS -> adds true ins ctxt
  | Op.ADR -> adr ins ctxt // for Thumb mode
  | Op.AND -> logicalAnd false ins ctxt
  | Op.ANDS -> ands true ins ctxt
  | Op.ASR -> shiftInstr false ins SRTypeASR ctxt
  | Op.ASRS -> asrs true ins ctxt
  | Op.B -> b ins ctxt
  | Op.BFC -> bfc ins ctxt
  | Op.BFI -> bfi ins ctxt
  | Op.BIC -> bic false ins ctxt
  | Op.BICS -> bics true ins ctxt
  | Op.BKPT -> sideEffects ins Breakpoint
  | Op.BL -> bl ins ctxt
  | Op.BLX -> branchWithLink ins ctxt
  | Op.BX -> bx ins ctxt
  | Op.BXJ -> bx ins ctxt
  | Op.CBNZ -> cbz true ins ctxt
  | Op.CBZ -> cbz false ins ctxt
  | Op.CDP | Op.CDP2 | Op.LDC | Op.LDC2 | Op.LDC2L | Op.LDCL | Op.MCR | Op.MCR2
  | Op.MCRR | Op.MCRR2 | Op.MRC | Op.MRC2 | Op.MRRC | Op.MRRC2 | Op.STC
  | Op.STC2 | Op.STC2L | Op.STCL ->
    sideEffects ins UnsupportedExtension (* coprocessor instructions *)
  | Op.CLZ -> clz ins ctxt
  | Op.CMN -> cmn ins ctxt
  | Op.CMP -> cmp ins ctxt
  | Op.DMB | Op.DSB | Op.ISB | Op.PLD -> nop ins
  | Op.EOR -> eor false ins ctxt
  | Op.EORS -> eors true ins ctxt
  | Op.ERET -> sideEffects ins UnsupportedExtension
  | Op.IT | Op.ITT | Op.ITE | Op.ITTT | Op.ITET | Op.ITTE | Op.ITEE | Op.ITTTT
  | Op.ITETT | Op.ITTET | Op.ITEET | Op.ITTTE | Op.ITETE | Op.ITTEE
  | Op.ITEEE -> it ins ctxt
  | Op.LDM -> ldm Op.LDM ins ctxt (.+)
  | Op.LDMDA -> ldm Op.LDMDA ins ctxt (.-)
  | Op.LDMDB -> ldm Op.LDMDB ins ctxt (.-)
  | Op.LDMIA -> ldm Op.LDMIA ins ctxt (.+)
  | Op.LDMIB -> ldm Op.LDMIB ins ctxt (.+)
  | Op.LDR -> ldr ins ctxt 32<rt> AST.zext
  | Op.LDRB -> ldr ins ctxt 8<rt> AST.zext
  | Op.LDRBT -> ldr ins ctxt 8<rt> AST.zext
  | Op.LDRD -> ldrd ins ctxt
  | Op.LDREX -> ldr ins ctxt 32<rt> AST.zext
  | Op.LDRH -> ldr ins ctxt 16<rt> AST.zext
  | Op.LDRHT -> ldr ins ctxt 16<rt> AST.zext
  | Op.LDRSB -> ldr ins ctxt 8<rt> AST.sext
  | Op.LDRSBT -> ldr ins ctxt 8<rt> AST.sext
  | Op.LDRSH -> ldr ins ctxt 16<rt> AST.sext
  | Op.LDRSHT -> ldr ins ctxt 16<rt> AST.sext
  | Op.LDRT -> ldr ins ctxt 32<rt> AST.zext
  | Op.LSL -> shiftInstr false ins SRTypeLSL ctxt
  | Op.LSLS -> lsls true ins ctxt
  | Op.LSR -> shiftInstr false ins SRTypeLSR ctxt
  | Op.LSRS -> lsrs true ins ctxt
  | Op.MLA -> mla false ins ctxt
  | Op.MLAS -> mla true ins ctxt
  | Op.MLS -> mls ins ctxt
  | Op.MOV | Op.MOVW -> mov false ins ctxt
  | Op.MOVS -> movs true ins ctxt
  | Op.MOVT -> movt ins ctxt
  | Op.MUL -> mul false ins ctxt
  | Op.MULS -> mul true ins ctxt
  | Op.MVN -> mvn false ins ctxt
  | Op.MVNS -> mvns true ins ctxt
  | Op.NOP -> nop ins
  | Op.ORN -> orn false ins ctxt
  | Op.ORNS -> orns true ins ctxt
  | Op.ORR -> orr false ins ctxt
  | Op.ORRS -> orrs true ins ctxt
  | Op.POP -> pop ins ctxt
  | Op.PUSH -> push ins ctxt
  | Op.QDADD -> qdadd ins insLen ctxt
  | Op.QDSUB -> qdsub ins insLen ctxt
  | Op.QSAX -> qsax ins insLen ctxt
  | Op.QSUB16 -> qsub16 ins insLen ctxt
  | Op.RBIT -> rbit ins ctxt
  | Op.REV -> rev ins ctxt
  | Op.ROR -> shiftInstr false ins SRTypeROR ctxt
  | Op.RORS -> rors true ins ctxt
  | Op.RRX -> shiftInstr false ins SRTypeRRX ctxt
  | Op.RRXS -> rrxs true ins ctxt
  | Op.RSB -> rsb false ins ctxt
  | Op.RSBS -> rsbs true ins ctxt
  | Op.RSC -> rsc false ins ctxt
  | Op.RSCS -> rscs true ins ctxt
  | Op.SBC -> sbc false ins ctxt
  | Op.SBCS -> sbcs true ins ctxt
  | Op.SBFX -> bfx ins ctxt true
  | Op.SEL -> sel ins ctxt
  | Op.SMLABB -> smulacchalf ins ctxt false false
  | Op.SMLABT -> smulacchalf ins ctxt false true
  | Op.SMLAL -> smulandacc false true ins ctxt
  | Op.SMLALS -> smulandacc true true ins ctxt
  | Op.SMLATB -> smulacchalf ins ctxt true false
  | Op.SMLATT -> smulacchalf ins ctxt true true
  | Op.SMULBB -> smulhalf ins ctxt false false
  | Op.SMULBT -> smulhalf ins ctxt false true
  | Op.SMULL -> smulandacc false false ins ctxt
  | Op.SMULLS -> smulandacc true false ins ctxt
  | Op.SMULTB -> smulhalf ins ctxt true false
  | Op.SMULTT -> smulhalf ins ctxt true true
  | Op.STM -> stm Op.STM ins ctxt (.+)
  | Op.STMDA -> stm Op.STMDA ins ctxt (.-)
  | Op.STMDB -> stm Op.STMDB ins ctxt (.-)
  | Op.STMEA -> stm Op.STMIA ins ctxt (.+)
  | Op.STMIA -> stm Op.STMIA ins ctxt (.+)
  | Op.STMIB -> stm Op.STMIB ins ctxt (.+)
  | Op.STR -> str ins ctxt 32<rt>
  | Op.STRB -> str ins ctxt 8<rt>
  | Op.STRBT -> str ins ctxt 8<rt>
  | Op.STRD -> strd ins ctxt
  | Op.STREX -> strex ins ctxt
  | Op.STRH -> str ins ctxt 16<rt>
  | Op.STRHT -> str ins ctxt 16<rt>
  | Op.STRT -> str ins ctxt 32<rt>
  | Op.SUB | Op.SUBW -> sub false ins ctxt
  | Op.SUBS -> subs true ins ctxt
  | Op.SVC -> svc ins ctxt
  | Op.SXTB -> extend ins ctxt AST.sext 8<rt>
  | Op.SXTH -> extend ins ctxt AST.sext 16<rt>
  | Op.TBH | Op.TBB -> tableBranch ins ctxt
  | Op.TEQ -> teq ins ctxt
  | Op.TST -> tst ins ctxt
  | Op.UADD8 -> uadd8 ins ctxt
  | Op.UASX -> uasx ins insLen ctxt
  | Op.UBFX -> bfx ins ctxt false
  | Op.UDF -> udf ins
  | Op.UHSUB16 -> uhsub16 ins insLen ctxt
  | Op.UMLAL -> umlal false ins ctxt
  | Op.UMLALS -> umlal true ins ctxt
  | Op.UMULL -> umull false ins ctxt
  | Op.UMULLS -> umull true ins ctxt
  | Op.UQADD16 -> uqopr ins ctxt 16 (.+)
  | Op.UQADD8 -> uqopr ins ctxt 8 (.+)
  | Op.UQSAX -> uqsax ins insLen ctxt
  | Op.UQSUB16 -> uqopr ins ctxt 16 (.-)
  | Op.UQSUB8 -> uqopr ins ctxt 8 (.-)
  | Op.USAX -> usax ins insLen ctxt
  | Op.UXTAB -> extendAndAdd ins ctxt 8<rt>
  | Op.UXTAH -> extendAndAdd ins ctxt 16<rt>
  | Op.UXTB -> extend ins ctxt AST.zext 8<rt>
  | Op.UXTH -> extend ins ctxt AST.zext 16<rt>
  | Op.VABS when isF32orF64 ins.SIMDTyp -> sideEffects ins UnsupportedFP
  | Op.VABS -> vabs ins ctxt
  | Op.VADD when isF32orF64 ins.SIMDTyp -> sideEffects ins UnsupportedFP
  | Op.VADD -> vadd ins ctxt
  | Op.VADDL -> vaddl ins insLen ctxt
  | Op.VAND -> vand ins ctxt
  | Op.VCEQ | Op.VCGE | Op.VCGT | Op.VCLE | Op.VCLT
    when isF32orF64 ins.SIMDTyp -> sideEffects ins UnsupportedFP
  | Op.VCEQ -> vceq ins ctxt
  | Op.VCGE -> vcge ins ctxt
  | Op.VCGT -> vcgt ins ctxt
  | Op.VCLE -> vcle ins ctxt
  | Op.VCLT -> vclt ins ctxt
  | Op.VCLZ -> vclz ins ctxt
  | Op.VCMLA -> sideEffects ins UnsupportedFP
  | Op.VCMP | Op.VCMPE | Op.VACGE | Op.VACGT | Op.VACLE | Op.VACLT | Op.VCVT
  | Op.VCVTR | Op.VDIV | Op.VFMA | Op.VFMS | Op.VFNMA | Op.VFNMS | Op.VMSR
  | Op.VNMLA | Op.VNMLS | Op.VNMUL | Op.VSQRT -> sideEffects ins UnsupportedFP
  | Op.VDUP -> vdup ins ctxt
  | Op.VEXT -> vext ins insLen ctxt
  | Op.VHADD -> vhadd ins insLen ctxt
  | Op.VHSUB -> vhsub ins insLen ctxt
  | Op.VLD1 -> vld1 ins ctxt
  | Op.VLD2 -> vld2 ins ctxt
  | Op.VLD3 -> vld3 ins ctxt
  | Op.VLD4 -> vld4 ins ctxt
  | Op.VLDM | Op.VLDMIA | Op.VLDMDB -> vldm ins ctxt
  | Op.VLDR -> vldr ins ctxt
  | Op.VMAX | Op.VMIN when isF32orF64 ins.SIMDTyp ->
    sideEffects ins UnsupportedFP
  | Op.VMAX -> vmaxmin ins ctxt true
  | Op.VMIN -> vmaxmin ins ctxt false
  | Op.VMLA | Op.VMLS when isF32orF64 ins.SIMDTyp ->
    sideEffects ins UnsupportedFP
  | Op.VMLA -> vmla ins ctxt
  | Op.VMLAL -> vmlal ins ctxt
  | Op.VMLS -> vmls ins ctxt
  | Op.VMLSL -> vmlsl ins ctxt
  | Op.VMOV when Operators.not (isAdvancedSIMD ins) ->
    sideEffects ins UnsupportedFP
  | Op.VMOV -> vmov ins ctxt
  | Op.VMOVN -> vmovn ins ctxt
  | Op.VMRS -> vmrs ins ctxt
  | Op.VMUL | Op.VMULL when isF32orF64 ins.SIMDTyp ->
    sideEffects ins UnsupportedFP
  | Op.VMUL -> vmul ins ctxt
  | Op.VMULL -> vmull ins ctxt
  | Op.VNEG when isF32orF64 ins.SIMDTyp -> sideEffects ins UnsupportedFP
  | Op.VNEG -> vneg ins ctxt
  | Op.VORN -> vorn ins ctxt
  | Op.VORR -> vorr ins ctxt
  | Op.VPADD when isF32orF64 ins.SIMDTyp -> sideEffects ins UnsupportedFP
  | Op.VPADD -> vpadd ins ctxt
  | Op.VPOP -> vpop ins ctxt
  | Op.VPUSH -> vpush ins ctxt
  | Op.VRHADD -> vrhadd ins insLen ctxt
  | Op.VRINTP -> sideEffects ins UnsupportedFP
  | Op.VRSHR -> vrshr ins ctxt
  | Op.VRSHRN -> vrshrn ins ctxt
  | Op.VSHL -> vshl ins ctxt
  | Op.VSHR -> vshr ins ctxt
  | Op.VSRA -> vsra ins insLen ctxt
  | Op.VST1 -> vst1 ins ctxt
  | Op.VST2 -> vst2 ins ctxt
  | Op.VST3 -> vst3 ins ctxt
  | Op.VST4 -> vst4 ins ctxt
  | Op.VSTM | Op.VSTMIA | Op.VSTMDB -> vstm ins ctxt
  | Op.VSTR -> vstr ins ctxt
  | Op.VSUB when isF32orF64 ins.SIMDTyp -> sideEffects ins UnsupportedFP
  | Op.VSUB -> vsub ins ctxt
  | Op.VTBL -> vecTbl ins ctxt true
  | Op.VTBX -> vecTbl ins ctxt false
  | Op.VTST -> vtst ins ctxt
  | Op.VUZP -> vuzp ins insLen ctxt
  | Op.InvalidOP -> raise InvalidOpcodeException
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
