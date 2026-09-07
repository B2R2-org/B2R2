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

module internal B2R2.FrontEnd.ARM32.GeneralLifter

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

let transShiftOprs ins bld opr1 opr2 =
  match opr1, opr2 with
  | OprReg _, OprShift(typ, Imm imm) ->
    let e = transOpr ins bld opr1
    shift e 32<rt> typ imm (getCarryFlag bld)
  | OprReg _, OprRegShift(typ, reg) ->
    let e = transOpr ins bld opr1
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    shiftForRegAmount e 32<rt> typ amount (getCarryFlag bld)
  | _ ->
    raise InvalidOperandException

let parseOprOfMVNS (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    transTwoOprs ins bld
  | ThreeOperands(opr1, opr2, opr3) ->
    struct (transOpr ins bld opr1, transShiftOprs ins bld opr2 opr3)
  | _ ->
    raise InvalidOperandException

let transTwoOprsOfADC (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, shift e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfADC (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    transThreeOprs ins bld
  | ThreeOperands(OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2, e3) = transThreeOprs ins bld
    e1, e2, shift e3 32<rt> ShiftOp.LSL 0u carryIn
  | _ ->
    raise InvalidOperandException

let transFourOprsOfADC (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(opr1, opr2, opr3, (OprShift(_, Imm _) as opr4)) ->
    let e1, e2 = transOpr ins bld opr1, transOpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands(opr1, opr2, opr3, OprRegShift(typ, reg)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    let e3 = transOpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let parseOprOfADC (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADC ins bld
  | ThreeOperands _ -> transThreeOprsOfADC ins bld
  | FourOperands _ -> transFourOprsOfADC ins bld
  | _ -> raise InvalidOperandException

let checkCondition (ins: Instruction) bld isUnconditional =
  if isUnconditional then
    None
  else
    let lblIgnore = label bld "IgnoreExec"
    let lblPass = label bld "NeedToExec"
    let cond = conditionPassed bld ins.Condition
    append bld {
      AST.cjmp cond (AST.jmpDest lblPass) (AST.jmpDest lblIgnore)
      AST.lmark lblPass
    }
    Some lblIgnore

/// Update ITState after normal execution of an IT-block instruction. See A2-52
/// function: ITAdvance().
let itAdvance bld =
  append bld {
    let cond = tmpVar bld 1<rt>
    let struct (itstate, nextstate) = tmpVars2 bld 32<rt>
    let lblThen = label bld "LThen"
    let lblElse = label bld "LElse"
    let lblEnd = label bld "LEnd"
    let cpsr = regVar bld R.CPSR
    let cpsrIT10 = getPSR bld R.CPSR PSR.IT10 >> (numI32 25 32<rt>)
    let cpsrIT72 = getPSR bld R.CPSR PSR.IT72 >> (numI32 8 32<rt>)
    let mask10 = numI32 0x3 32<rt> (* For ITSTATE[1:0] *)
    let mask20 = numI32 0x7 32<rt> (* For ITSTATE[2:0] *)
    let mask40 = numI32 0x1f 32<rt> (* For ITSTATE[4:0] *)
    let mask42 = numI32 0x1c 32<rt> (* For ITSTATE[4:2] *)
    let cpsrIT42 = cpsr .& (numI32 0xffffe3ff 32<rt>)
    let num8 = numI32 8 32<rt>
    itstate := cpsrIT72 .| cpsrIT10
    cond := ((itstate .& mask20) == AST.num0 32<rt>)
    AST.cjmp cond (AST.jmpDest lblThen) (AST.jmpDest lblElse)
    AST.lmark lblThen
    cpsr := disablePSRBits bld R.CPSR PSR.IT10
    cpsr := disablePSRBits bld R.CPSR PSR.IT72
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblElse
    nextstate := (itstate .& mask40 << AST.num1 32<rt>)
    cpsr := nextstate .& mask10 |> setPSR bld R.CPSR PSR.IT10
    cpsr := cpsrIT42 .| ((nextstate .& mask42) << num8)
    AST.lmark lblEnd
  }

let putEndLabel bld lblIgnore =
  match lblIgnore with
  | Some lblIgnore ->
    append bld {
      AST.lmark lblIgnore
    }
    itAdvance bld
  | None ->
    ()

let putEndLabelForBranch bld lblIgnore (brIns: Instruction) =
  match lblIgnore with
  | Some lblIgnore ->
    append bld {
      AST.lmark lblIgnore
    }
    itAdvance bld
    let target = numU64 (brIns.Address + uint64 brIns.Length) 32<rt>
    append bld {
      AST.interjmp target InterJmpKind.Base
    }
  | None ->
    ()

let sideEffects (ins: Instruction) bld name =
  lift bld ins {
    AST.sideEffect name
  }

/// An instruction that is valid but outside what this lifter models, left to
/// the emulator to report rather than silently mis-executed.
let unsupported ins bld = sideEffects ins bld UnsupportedInstruction

/// An encoding the architecture itself leaves undefined, illegal, or
/// reserved, so faulting is what the instruction means.
let undefined ins bld = sideEffects ins bld UndefinedInstruction

let nop (ins: Instruction) bld =
  lift bld ins {
  }

let convertPCOpr (ins: Instruction) bld opr =
  if opr = getPC bld then
    let rel = if not ins.IsThumb then 8 else 4
    opr .+ (numI32 rel 32<rt>)
  else
    opr

let adc isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = parseOprOfADC ins bld
    let src1 = convertPCOpr ins bld src1
    let src2 = convertPCOpr ins bld src2
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSetFlags then
      let struct (t1, t2) = tmpVars2 bld 32<rt>
      t1 := src1
      t2 := src2
      let struct (result, carryOut, overflow, rHigh) =
        addWithCarry t1 t2 (getCarryFlag bld) bld
      dst := result
      let cpsr = regVar bld R.CPSR
      cpsr := rHigh |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      cpsr := overflow |> setPSR bld R.CPSR PSR.V
    else
      let result = tmpVar bld 32<rt>
      result := addWithCarryOnlyResult src1 src2 (getCarryFlag bld)
      if dst = getPC bld then aluWritePC bld ins isUnconditional result
      else append bld { dst := result }
    putEndLabel bld lblIgnore
  }

let transTwoOprsOfADD (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, e2)
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, shift e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfADD (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    transThreeOprs ins bld
  | ThreeOperands(OprReg _, OprReg _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2, e3) = transThreeOprs ins bld
    struct (e1, e2, shift e3 32<rt> ShiftOp.LSL 0u carryIn)
  | _ ->
    raise InvalidOperandException

let transFourOprsOfADD (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(opr1, opr2, opr3, (OprShift(_, Imm _) as opr4)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands(opr1, opr2, opr3, OprRegShift(typ, reg)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    let e3 = transOpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let parseOprOfADD (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfADD ins bld
  | ThreeOperands _ -> transThreeOprsOfADD ins bld
  | FourOperands _ -> transFourOprsOfADD ins bld
  | _ -> raise InvalidOperandException

let add isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = parseOprOfADD ins bld
    let src1 = convertPCOpr ins bld src1
    let src2 = convertPCOpr ins bld src2
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSetFlags then
      let struct (t1, t2) = tmpVars2 bld 32<rt>
      t1 := src1
      t2 := src2
      let struct (result, carryOut, overflow, rHigh) =
        addWithCarry t1 t2 (AST.num0 32<rt>) bld
      dst := result
      let cpsr = regVar bld R.CPSR
      cpsr := rHigh |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      cpsr := overflow |> setPSR bld R.CPSR PSR.V
    else
      let result = tmpVar bld 32<rt>
      result := addWithCarryOnlyResult src1 src2 (AST.num0 32<rt>)
      if dst = getPC bld then aluWritePC bld ins isUnconditional result
      else append bld { dst := result }
      putEndLabel bld lblIgnore
  }

/// Align integer or bitstring to multiple of an integer, on page AppxP-2655
/// function : Align()
let align e1 e2 = e2 .* (e1 ./ e2)

let pcOffset (ins: Instruction) = if not ins.IsThumb then 8UL else 4UL

let transLabelOprsOfBL ins isThumb imm =
  let offset = pcOffset ins
  let pc =
    if isThumb then
      bvOfBaseAddr (ins.Address + offset)
    else
      let addr = bvOfBaseAddr (ins.Address + offset)
      align addr (numI32 4 32<rt>)
  pc .+ (numI64 imm 32<rt>)

let targetModeOfBL (ins: Instruction) =
  match ins.Opcode, ins.IsThumb with
  | Op.BL, isThumb -> struct (isThumb, InterJmpKind.IsCall)
  | Op.BLX, false -> struct (true, InterJmpKind.SwitchToThumb)
  | Op.BLX, true -> struct (false, InterJmpKind.SwitchToARM)
  | _ -> raise InvalidOpcodeException

let parseOprOfBL ins =
  let struct (isThumb, callKind) = targetModeOfBL ins
  match ins.Operands with
  | OneOperand(OprMemory(LiteralMode imm)) ->
    struct (transLabelOprsOfBL ins isThumb imm, isThumb, callKind)
  | _ ->
    raise InvalidOperandException

let bl ins bld =
  lift bld ins {
    let struct (alignedAddr, isThumb, callKind) = parseOprOfBL ins
    let lr = regVar bld R.LR
    let retAddr = bvOfBaseAddr ins.Address .+ (numI32 4 32<rt>)
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if not ins.IsThumb then append bld { lr := retAddr }
    else append bld { lr := maskAndOR retAddr (AST.num1 32<rt>) 32<rt> 1 }
    selectInstrSet bld isThumb
    branchWritePC alignedAddr callKind
    putEndLabelForBranch bld lblIgnore ins
    return NoEndMark
  }

let blxWithReg (ins: Instruction) reg bld =
  lift bld ins {
    let lr = regVar bld R.LR
    let addr = bvOfBaseAddr ins.Address
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if not ins.IsThumb then
      lr := addr .+ (numI32 4 32<rt>)
    else
      let addr = addr .+ (numI32 2 32<rt>)
      lr := maskAndOR addr (AST.num1 32<rt>) 32<rt> 1
    bxWritePC bld isUnconditional (regVar bld reg)
    putEndLabelForBranch bld lblIgnore ins
    return NoEndMark
  }

let branchWithLink (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand(OprReg reg) -> blxWithReg ins reg bld
  | _ -> bl ins bld

let parseOprOfPUSHPOP (ins: Instruction) =
  match ins.Operands with
  | OneOperand(OprReg r) -> regsToUInt32 [ r ]
  | OneOperand(OprRegList regs) -> regsToUInt32 regs
  | _ -> raise InvalidOperandException

let pushLoop bld numOfReg addr =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let t = tmpVar bld 32<rt>
      append bld {
        t := addr
      }
      if count = 13 && count <> lowestSetBit numOfReg 32 then
        append bld {
          AST.loadLE 32<rt> t := (AST.undef 32<rt> "UNKNOWN")
        }
      else
        let reg = count |> uint32 |> OperandHelper.getRegister
        append bld {
          AST.loadLE 32<rt> t := regVar bld reg
        }
      t .+ (numI32 4 32<rt>)
    else
      addr
  List.fold loop addr [ 0 .. 14 ]

let push ins bld =
  lift bld ins {
    let t0 = tmpVar bld 32<rt>
    let sp = regVar bld R.SP
    let numOfReg = parseOprOfPUSHPOP ins
    let stackWidth = 4 * bitCount numOfReg 16
    let addr = sp .- (numI32 stackWidth 32<rt>)
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t0 := addr
    let addr = pushLoop bld numOfReg t0
    if (numOfReg >>> 15 &&& 1u) = 1u then
      AST.loadLE 32<rt> addr := pcStoreValue bld
    else
      ()
    sp := t0
    putEndLabel bld lblIgnore
  }

/// shared/functions/vector/SignedSatQ, on page Armv8 Pseudocode-7927
let sSatQ bld i n =
  let n1 = AST.num1 n
  let cond = n1 << (numI32 (RegType.toBitWidth n) n .- n1)
  let struct (t1, t2) = tmpVars2 bld n
  append bld {
    t1 := i
    t2 := cond
  }
  let cond1 = t1 .> (t2 .- n1)
  let cond2 = t1 .< AST.not t2
  let r = (AST.ite cond1 (t2 .- n1) (AST.ite cond2 (AST.not t2) t1))
  let r = AST.xtlo n r
  let sat = AST.ite cond1 AST.b1 (AST.ite cond2 AST.b1 (AST.num0 1<rt>))
  struct (r, sat)

let sSat bld i n =
  let struct (r, _) = sSatQ bld i n
  r

let qdadd (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (sat1, sat2) = tmpVars2 bld 1<rt>
    let struct (dou, sat) =
      sSatQ bld (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
    sat1 := sat
    let struct (r, sat) = sSatQ bld (src1 .+ dou) (RegType.fromBitWidth 32)
    dst := r
    sat2 := sat
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite (sat1 .| sat2) (enablePSRBits bld R.CPSR PSR.Q) cpsr
    putEndLabel bld lblIgnore
  }

let qdsub (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (sat1, sat2) = tmpVars2 bld 1<rt>
    let struct (dou, sat) =
      sSatQ bld (numI32 2 32<rt> .* src2) (RegType.fromBitWidth 32)
    sat1 := sat
    let struct (r, sat) = sSatQ bld (src1 .- dou) (RegType.fromBitWidth 32)
    dst := r
    sat2 := sat
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite (sat1 .| sat2) (enablePSRBits bld R.CPSR PSR.Q) cpsr
    putEndLabel bld lblIgnore
  }

let qsax (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (sum, diff) = tmpVars2 bld 16<rt>
    let xtlo src = AST.xtlo 16<rt> src
    let xthi src = AST.xthi 16<rt> src
    sum := xtlo src1 .+ xthi src2
    diff := xthi src1 .- xtlo src2
    sum := sSat bld sum (RegType.fromBitWidth 16)
    diff := sSat bld diff (RegType.fromBitWidth 16)
    dst := AST.concat diff sum
    putEndLabel bld lblIgnore
  }

let qsub16 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (diff1, diff2) = tmpVars2 bld 16<rt>
    let xtlo src = AST.xtlo 16<rt> src
    let xthi src = AST.xthi 16<rt> src
    diff1 := xtlo src1 .- xtlo src2
    diff2 := xthi src1 .- xthi src2
    diff1 := sSat bld diff1 (RegType.fromBitWidth 16)
    diff2 := sSat bld diff2 (RegType.fromBitWidth 16)
    dst := AST.concat diff2 diff1
    putEndLabel bld lblIgnore
  }

let sub isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = parseOprOfADD ins bld
    let src1 = convertPCOpr ins bld src1
    let src2 = convertPCOpr ins bld src2
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSetFlags then
      let struct (t1, t2) = tmpVars2 bld 32<rt>
      t1 := src1
      t2 := src2
      let struct (result, carryOut, overflow, rHigh) =
        addWithCarry t1 (AST.not t2) (AST.num1 32<rt>) bld
      dst := result
      let cpsr = regVar bld R.CPSR
      cpsr := rHigh |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      cpsr := overflow |> setPSR bld R.CPSR PSR.V
    else
      let result = tmpVar bld 32<rt>
      result :=
        addWithCarryOnlyResult src1 (AST.not src2) (AST.num1 32<rt>)
      if dst = getPC bld then aluWritePC bld ins isUnconditional result
      else append bld { dst := result }
    putEndLabel bld lblIgnore
  }

/// B9.3.19 SUBS R.PC, R.LR (Thumb), on page B9-2008
let subsPCLRThumb ins bld =
  lift bld ins {
    let struct (_, _, src2) = parseOprOfADD ins bld
    let pc = getPC bld
    let struct (result, _, _, _) =
      addWithCarry pc (AST.not src2) (AST.num1 32<rt>) bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    branchWritePC result InterJmpKind.IsRet
    putEndLabel bld lblIgnore
  }

let parseResultOfSUBAndRela (ins: Instruction) bld =
  match ins.Opcode with
  | Op.ANDS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    src1 .& src2
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
    shiftForRegAmount src1 32<rt> ShiftOp.ASR src2 (getCarryFlag bld)
  | Op.LSLS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> ShiftOp.LSL src2 (getCarryFlag bld)
  | Op.LSRS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> ShiftOp.LSR src2 (getCarryFlag bld)
  | Op.RORS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    shiftForRegAmount src1 32<rt> ShiftOp.ROR src2 (getCarryFlag bld)
  | Op.RRXS ->
    let struct (_, src) = transTwoOprs ins bld
    let carryFlag = getCarryFlag bld
    shiftForRegAmount src 32<rt> ShiftOp.RRX (AST.num1 32<rt>) carryFlag
  | Op.BICS ->
    let struct (_, src1, src2) = parseOprOfADC ins bld
    src1 .& (AST.not src2)
  | Op.MVNS ->
    let struct (_, src) = parseOprOfMVNS ins bld
    AST.not src
  | _ ->
    raise InvalidOperandException

/// B9.3.20 SUBS R.PC, R.LR and related instruction (ARM), on page B9-2010
let subsAndRelatedInstr (ins: Instruction) bld =
  lift bld ins {
    let result = tmpVar bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := parseResultOfSUBAndRela ins bld
    branchWritePC result InterJmpKind.IsRet
    putEndLabel bld lblIgnore
  }

let computeCarryOutFromImmCflag (ins: Instruction) bld =
  match ins.Cflag with
  | Some v ->
    if v then BitVector.One 1<rt> |> AST.num
    else BitVector.Zero 1<rt> |> AST.num
  | None ->
    getCarryFlag bld

let translateLogicOp (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprReg _) ->
    let t = tmpVar bld 32<rt>
    let struct (e1, e2) = transTwoOprs ins bld
    append bld {
      t := e2
    }
    let shifted, carryOut = shiftC t 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    e1, e1, shifted, carryOut
  | ThreeOperands(_, _, OprImm _) ->
    let struct (e1, e2, e3) = transThreeOprs ins bld
    let carryOut = computeCarryOutFromImmCflag ins bld
    e1, e2, e3, carryOut
  | ThreeOperands(OprReg _, OprReg _, OprReg _) ->
    let t = tmpVar bld 32<rt>
    let struct (e1, e2, e3) = transThreeOprs ins bld
    append bld {
      t := e3
    }
    let shifted, carryOut = shiftC t 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    e1, e2, shifted, carryOut
  | FourOperands(opr1, opr2, opr3, OprShift(typ, Imm imm)) ->
    let t = tmpVar bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src1 = transOpr ins bld opr2
    let rm = transOpr ins bld opr3
    append bld {
      t := rm
    }
    let shifted, carryOut = shiftC t 32<rt> typ imm carryIn
    dst, src1, shifted, carryOut
  | FourOperands(opr1, opr2, opr3, OprRegShift(typ, reg)) ->
    let t = tmpVar bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src1 = transOpr ins bld opr2
    let rm = transOpr ins bld opr3
    append bld {
      t := rm
    }
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount t 32<rt> typ amount carryIn
    dst, src1, shifted, carryOut
  | _ ->
    raise InvalidOperandException

let logicalAnd isSetFlags (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let dst, src1, src2, carryOut = translateLogicOp ins bld
    let result = tmpVar bld 32<rt>
    result := src1 .& src2
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let parseOprsOfMOV (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ ->
    transTwoOprs ins bld
  | ThreeOperands(opr1, opr2, opr3) ->
    struct (transOpr ins bld opr1, transShiftOprs ins bld opr2 opr3)
  | _ ->
    raise InvalidOperandException

let mov isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src) = parseOprsOfMOV ins bld
    let result = tmpVar bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let pc = getPC bld
    let lblIgnore = checkCondition ins bld isUnconditional
    if src = pc then
      append bld { result := src .+ (numU64 (pcOffset ins) 32<rt>) }
    else
      append bld { result := src }
    if dst = pc then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      else
        ()
    putEndLabel bld lblIgnore
  }

let eor isSetFlags (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let dst, src1, src2, carryOut = translateLogicOp ins bld
    let result = tmpVar bld 32<rt>
    result := src1 <+> src2
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let transFourOprsOfRSB (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(opr1, opr2, opr3, (OprShift(_, Imm _) as opr4)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands(opr1, opr2, opr3, OprRegShift(typ, reg)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    let e3 = transOpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let parseOprOfRSB (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsOfRSB ins bld
  | _ -> raise InvalidOperandException

let rsb isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = parseOprOfRSB ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSetFlags then
      t1 := src1
      t2 := src2
      let struct (result, carryOut, overflow, rHigh) =
        addWithCarry (AST.not t1) t2 (AST.num1 32<rt>) bld
      dst := result
      let cpsr = regVar bld R.CPSR
      cpsr := rHigh |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      cpsr := overflow |> setPSR bld R.CPSR PSR.V
    else
      let result = tmpVar bld 32<rt>
      result :=
        addWithCarryOnlyResult (AST.not src1) src2 (AST.num1 32<rt>)
      if dst = getPC bld then aluWritePC bld ins isUnconditional result
      else append bld { dst := result }
    putEndLabel bld lblIgnore
  }

let transTwoOprsOfSBC (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e1, shift e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let transFourOprsOfSBC (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(opr1, opr2, opr3, (OprShift(_, Imm _) as opr4)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    struct (e1, e2, transShiftOprs ins bld opr3 opr4)
  | FourOperands(opr1, opr2, opr3, OprRegShift(typ, reg)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    let e3 = transOpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    struct (e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let parseOprOfSBC (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfSBC ins bld
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsOfSBC ins bld
  | _ -> raise InvalidOperandException

let sbc isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = parseOprOfSBC ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSetFlags then
      t1 := src1
      t2 := src2
      let struct (result, carryOut, overflow, rHigh) =
        addWithCarry t1 (AST.not t2) (getCarryFlag bld) bld
      dst := result
      let cpsr = regVar bld R.CPSR
      cpsr := rHigh |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      cpsr := overflow |> setPSR bld R.CPSR PSR.V
    else
      let result = tmpVar bld 32<rt>
      result :=
        addWithCarryOnlyResult src1 (AST.not src2) (getCarryFlag bld)
      if dst = getPC bld then aluWritePC bld ins isUnconditional result
      else append bld { dst := result }
    putEndLabel bld lblIgnore
  }

let transFourOprsOfRSC (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(opr1, opr2, opr3, (OprShift(_, Imm _) as opr4)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    e1, e2, transShiftOprs ins bld opr3 opr4
  | FourOperands(opr1, opr2, opr3, OprRegShift(typ, reg)) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    let e3 = transOpr ins bld opr3
    let amount = AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    e1, e2, shiftForRegAmount e3 32<rt> typ amount (getCarryFlag bld)
  | _ ->
    raise InvalidOperandException

let parseOprOfRSC (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands _ -> transThreeOprs ins bld
  | FourOperands _ -> transFourOprsOfRSB ins bld
  | _ -> raise InvalidOperandException

let rsc isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src1, src2) = parseOprOfRSC ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if isSetFlags then
      t1 := src1
      t2 := src2
      let struct (result, carryOut, overflow, rHigh) =
        addWithCarry (AST.not t1) t2 (getCarryFlag bld) bld
      dst := result
      let cpsr = regVar bld R.CPSR
      cpsr := rHigh |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
      cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      cpsr := overflow |> setPSR bld R.CPSR PSR.V
    else
      let result = tmpVar bld 32<rt>
      result :=
        addWithCarryOnlyResult (AST.not src1) src2 (getCarryFlag bld)
      if dst = getPC bld then aluWritePC bld ins isUnconditional result
      else append bld { dst := result }
    putEndLabel bld lblIgnore
  }

let orr isSetFlags (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let dst, src1, src2, carryOut = translateLogicOp ins bld
    let result = tmpVar bld 32<rt>
    result := src1 .| src2
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let orn isSetFlags (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let dst, src1, src2, carryOut = translateLogicOp ins bld
    let result = tmpVar bld 32<rt>
    result := src1 .| AST.not src2
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let bic isSetFlags (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let dst, src1, src2, carryOut = translateLogicOp ins bld
    let result = tmpVar bld 32<rt>
    result := src1 .& (AST.not src2)
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let transTwoOprsOfMVN (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, e2, getCarryFlag bld)
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted, carryOut = shiftC e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    struct (e1, shifted, carryOut)
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfMVN (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(opr1, opr2, OprShift(typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src = transOpr ins bld opr2
    let shifted, carryOut = shiftC src 32<rt> typ imm carryIn
    struct (dst, shifted, carryOut)
  | ThreeOperands(opr1, opr2, OprRegShift(typ, rs)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src = transOpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount src 32<rt> typ amount carryIn
    struct (dst, shifted, carryOut)
  | _ ->
    raise InvalidOperandException

let parseOprOfMVN (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfMVN ins bld
  | ThreeOperands _ -> transThreeOprsOfMVN ins bld
  | _ -> raise InvalidOperandException

let mvn isSetFlags ins bld =
  lift bld ins {
    let struct (dst, src, carryOut) = parseOprOfMVN ins bld
    let result = tmpVar bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := AST.not src
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let svc (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand(OprImm n) -> sideEffects ins bld (Interrupt(int n))
  | _ -> raise InvalidOperandException

let getImmShiftFromShiftType imm = function
  | ShiftOp.LSL | ShiftOp.ROR -> imm
  | ShiftOp.LSR -> if imm = 0ul then 32ul else imm
  | ShiftOp.ASR -> if imm = 0ul then 32ul else imm
  | ShiftOp.RRX -> 1ul

let transTwoOprsOfShiftInstr (ins: Instruction) shiftTyp bld tmp =
  match ins.Operands with
  | TwoOperands(OprReg _, OprReg _) when shiftTyp = ShiftOp.RRX ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2) = transTwoOprs ins bld
    let result, carryOut = shiftC tmp 32<rt> shiftTyp 1ul carryIn
    e1, e2, result, carryOut
  | TwoOperands(OprReg _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2) = transTwoOprs ins bld
    let shiftN = AST.xtlo 8<rt> e2 |> AST.zext 32<rt>
    let result, carryOut = shiftCForRegAmount tmp 32<rt> shiftTyp shiftN carryIn
    e1, e1, result, carryOut
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfShiftInstr (ins: Instruction) shiftTyp bld tmp =
  match ins.Operands with
  | ThreeOperands(opr1, opr2, OprImm imm) ->
    let e1 = transOpr ins bld opr1
    let e2 = transOpr ins bld opr2
    let shiftN = getImmShiftFromShiftType (uint32 imm) shiftTyp
    let shifted, carryOut = shiftC tmp 32<rt> shiftTyp shiftN (getCarryFlag bld)
    e1, e2, shifted, carryOut
  | ThreeOperands(_, _, OprReg _) ->
    let carryIn = getCarryFlag bld
    let struct (e1, e2, e3) = transThreeOprs ins bld
    let amount = AST.xtlo 8<rt> e3 |> AST.zext 32<rt>
    let shifted, carryOut =
      shiftCForRegAmount tmp 32<rt> shiftTyp amount carryIn
    e1, e2, shifted, carryOut
  | _ ->
    raise InvalidOperandException

let parseOprOfShiftInstr (ins: Instruction) shiftTyp bld tmp =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfShiftInstr ins shiftTyp bld tmp
  | ThreeOperands _ -> transThreeOprsOfShiftInstr ins shiftTyp bld tmp
  | _ -> raise InvalidOperandException

let shiftInstr isSetFlags ins typ bld =
  lift bld ins {
    let struct (srcTmp, result) = tmpVars2 bld 32<rt>
    let dst, src, res, carryOut = parseOprOfShiftInstr ins typ bld srcTmp
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    srcTmp := src
    result := res
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carryOut |> setPSR bld R.CPSR PSR.C
      else
        ()
    putEndLabel bld lblIgnore
  }

let subs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _) when ins.IsThumb ->
    subsPCLRThumb ins bld
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) ->
    subsAndRelatedInstr ins bld
  | _ ->
    sub isSetFlags ins bld

let adds isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> add isSetFlags ins bld

let adcs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> adc isSetFlags ins bld

let ands isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> logicalAnd isSetFlags ins bld

let movs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg R.PC, _) -> subsAndRelatedInstr ins bld
  | _ -> mov isSetFlags ins bld

let eors isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> eor isSetFlags ins bld

let rsbs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> rsb isSetFlags ins bld

let sbcs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> sbc isSetFlags ins bld

let rscs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> rsc isSetFlags ins bld

let orrs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> orr isSetFlags ins bld

let orns isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> orn isSetFlags ins bld

let bics isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _)
  | FourOperands(OprReg R.PC, _, _, _) -> subsAndRelatedInstr ins bld
  | _ -> bic isSetFlags ins bld

let mvns isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg R.PC, _)
  | ThreeOperands(OprReg R.PC, _, _) -> subsAndRelatedInstr ins bld
  | _ -> mvn isSetFlags ins bld

let asrs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _) -> subsAndRelatedInstr ins bld
  | _ -> shiftInstr isSetFlags ins ShiftOp.ASR bld

let lsls isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _) -> subsAndRelatedInstr ins bld
  | _ -> shiftInstr isSetFlags ins ShiftOp.LSL bld

let lsrs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _) -> subsAndRelatedInstr ins bld
  | _ -> shiftInstr isSetFlags ins ShiftOp.LSR bld

let rors isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg R.PC, _, _) -> subsAndRelatedInstr ins bld
  | _ -> shiftInstr isSetFlags ins ShiftOp.ROR bld

let rrxs isSetFlags (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg R.PC, _) -> subsAndRelatedInstr ins bld
  | _ -> shiftInstr isSetFlags ins ShiftOp.RRX bld

let clz ins bld =
  lift bld ins {
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
    let lblIgnore = checkCondition ins bld isUnconditional
    t1 := numSize
    AST.lmark lblBoundCheck
    AST.cjmp cond1 (AST.jmpDest lblEnd) (AST.jmpDest lblZeroCheck)
    AST.lmark lblZeroCheck
    AST.cjmp cond2 (AST.jmpDest lblEnd) (AST.jmpDest lblCount)
    AST.lmark lblCount
    t1 := t1 .- (AST.num1 32<rt>)
    AST.jmp (AST.jmpDest lblBoundCheck)
    AST.lmark lblEnd
    dst := numSize .- t1
    putEndLabel bld lblIgnore
  }

let transTwoOprsOfCMN (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    transTwoOprs ins bld
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted = shift e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    struct (e1, shifted)
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfCMN (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(opr1, opr2, OprShift(typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src = transOpr ins bld opr2
    let shifted = shift src 32<rt> typ imm carryIn
    struct (dst, shifted)
  | ThreeOperands(opr1, opr2, OprRegShift(typ, rs)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src = transOpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted = shiftForRegAmount src 32<rt> typ amount carryIn
    struct (dst, shifted)
  | _ ->
    raise InvalidOperandException

let parseOprOfCMN (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMN ins bld
  | ThreeOperands _ -> transThreeOprsOfCMN ins bld
  | _ -> raise InvalidOperandException

let cmn ins bld =
  lift bld ins {
    let struct (dst, src) = parseOprOfCMN ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let cpsr = regVar bld R.CPSR
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t1 := dst
    t2 := src
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 t2 (AST.num0 32<rt>) bld
    cpsr := rHigh |> setPSR bld R.CPSR PSR.N
    cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
    cpsr := carryOut |> setPSR bld R.CPSR PSR.C
    cpsr := overflow |> setPSR bld R.CPSR PSR.V
    putEndLabel bld lblIgnore
  }

let mla isSetFlags ins bld =
  lift bld ins {
    let struct (rd, rn, rm, ra) = transFourOprs ins bld
    let r = tmpVar bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    r := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+
                               AST.zext 64<rt> ra)
    rd := r
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      cpsr := AST.xthi 1<rt> r |> setPSR bld R.CPSR PSR.N
      cpsr := r == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
    else
      ()
    putEndLabel bld lblIgnore
  }

let transTwoOprsOfCMP (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    transTwoOprs ins bld
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    struct (e1, shift e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld))
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfCMP (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(opr1, opr2, OprShift(typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src = transOpr ins bld opr2
    struct (dst, shift src 32<rt> typ imm carryIn)
  | ThreeOperands(opr1, opr2, OprRegShift(typ, rs)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src = transOpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    struct (dst, shiftForRegAmount src 32<rt> typ amount carryIn)
  | _ ->
    raise InvalidOperandException

let parseOprOfCMP (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands _ -> transTwoOprsOfCMP ins bld
  | ThreeOperands _ -> transThreeOprsOfCMP ins bld
  | _ -> raise InvalidOperandException

let cmp ins bld =
  lift bld ins {
    let struct (rn, rm) = parseOprOfCMP ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let cpsr = regVar bld R.CPSR
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t1 := rn
    t2 := rm
    let struct (result, carryOut, overflow, rHigh) =
      addWithCarry t1 (AST.not t2) (AST.num1 32<rt>) bld
    cpsr := rHigh |> setPSR bld R.CPSR PSR.N
    cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
    cpsr := carryOut |> setPSR bld R.CPSR PSR.C
    cpsr := overflow |> setPSR bld R.CPSR PSR.V
    putEndLabel bld lblIgnore
  }

let umaal (ins: Instruction) bld =
  lift bld ins {
    let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let res = tmpVar bld 64<rt>
    let mul = AST.zext 64<rt> rn .* AST.zext 64<rt> rm
    res := mul .+ AST.zext 64<rt> rdHi .+ AST.zext 64<rt> rdLo
    rdHi := AST.xthi 32<rt> res
    rdLo := AST.xtlo 32<rt> res
    putEndLabel bld lblIgnore
  }

let umlal isSetFlags ins bld =
  lift bld ins {
    let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
    let result = tmpVar bld 64<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    append bld {
      result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm .+ AST.concat rdHi rdLo
    }
    rdHi := AST.xthi 32<rt> result
    rdLo := AST.xtlo 32<rt> result
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 64<rt> |> setPSR bld R.CPSR PSR.Z
    else
      ()
    putEndLabel bld lblIgnore
  }

let umull isSetFlags ins bld =
  lift bld ins {
    let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
    let result = tmpVar bld 64<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := AST.zext 64<rt> rn .* AST.zext 64<rt> rm
    rdHi := AST.xthi 32<rt> result
    rdLo := AST.xtlo 32<rt> result
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 64<rt> |> setPSR bld R.CPSR PSR.Z
    else
      ()
    putEndLabel bld lblIgnore
  }

let transOprsOfTEQ (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    let struct (rn, imm) = transTwoOprs ins bld
    rn, imm, getCarryFlag bld
  | ThreeOperands(opr1, opr2, OprShift(typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let rn = transOpr ins bld opr1
    let rm = transOpr ins bld opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    rn, shifted, carryOut
  | ThreeOperands(opr1, opr2, OprRegShift(typ, rs)) ->
    let carryIn = getCarryFlag bld
    let rn = transOpr ins bld opr1
    let rm = transOpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    rn, shifted, carryOut
  | _ ->
    raise InvalidOperandException

let teq ins bld =
  lift bld ins {
    let src1, src2, carryOut = transOprsOfTEQ ins bld
    let result = tmpVar bld 32<rt>
    let cpsr = regVar bld R.CPSR
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := src1 <+> src2
    cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
    cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
    cpsr := carryOut |> setPSR bld R.CPSR PSR.C
    putEndLabel bld lblIgnore
  }

let mul isSetFlags ins bld =
  lift bld ins {
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let result = tmpVar bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := AST.xtlo 32<rt> (AST.zext 64<rt> rn .* AST.zext 64<rt> rm)
    rd := result
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
    else
      ()
    putEndLabel bld lblIgnore
  }

let transOprsOfTST (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) ->
    let struct (rn, imm) = transTwoOprs ins bld
    let carryOut = computeCarryOutFromImmCflag ins bld
    struct (rn, imm, carryOut)
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted, carryOut = shiftC e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    struct (e1, shifted, carryOut)
  | ThreeOperands(opr1, opr2, OprShift(typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let rn = transOpr ins bld opr1
    let rm = transOpr ins bld opr2
    let shifted, carryOut = shiftC rm 32<rt> typ imm carryIn
    struct (rn, shifted, carryOut)
  | ThreeOperands(opr1, opr2, OprRegShift(typ, rs)) ->
    let carryIn = getCarryFlag bld
    let rn = transOpr ins bld opr1
    let rm = transOpr ins bld opr2
    let amount = AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    let shifted, carryOut = shiftCForRegAmount rm 32<rt> typ amount carryIn
    struct (rn, shifted, carryOut)
  | _ ->
    raise InvalidOperandException

let tst ins bld =
  lift bld ins {
    let struct (src1, src2, carryOut) = transOprsOfTST ins bld
    let result = tmpVar bld 32<rt>
    let cpsr = regVar bld R.CPSR
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := src1 .& src2
    cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
    cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
    cpsr := carryOut |> setPSR bld R.CPSR PSR.C
    putEndLabel bld lblIgnore
  }

let smulhalf ins bld s1top s2top =
  lift bld ins {
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if s1top then append bld { t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt> }
    else append bld { t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt> }
    if s2top then append bld { t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt> }
    else append bld { t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt> }
    rd := t1 .* t2
    putEndLabel bld lblIgnore
  }

let smmla (ins: Instruction) bld isRound =
  lift bld ins {
    let struct (dst, src1, src2, src3) = transFourOprs ins bld
    let result = tmpVar bld 64<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let ra = (AST.sext 64<rt> src3) << numI32 32 64<rt>
    result := ra .+ AST.sext 64<rt> src1 .* AST.sext 64<rt> src2
    if isRound then
      append bld { result := result .+ numU32 0x80000000u 64<rt> }
    else
      ()
    dst := AST.xthi 32<rt> result
    putEndLabel bld lblIgnore
  }

let smmul (ins: Instruction) bld isRound =
  lift bld ins {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    result := AST.sext 64<rt> src1 .* AST.sext 64<rt> src2
    if isRound then
      append bld { result := result .+ numU32 0x80000000u 64<rt> }
    else
      ()
    dst := AST.xthi 32<rt> result
    putEndLabel bld lblIgnore
  }

/// SMULL, SMLAL, etc.
let smulandacc isSetFlags doAcc ins bld =
  lift bld ins {
    let struct (rdLo, rdHi, rn, rm) = transFourOprs ins bld
    let struct (tmpresult, result) = tmpVars2 bld 64<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    tmpresult := AST.sext 64<rt> rn .* AST.sext 64<rt> rm
    if doAcc then append bld { result := tmpresult .+ AST.concat rdHi rdLo }
    else append bld { result := tmpresult }
    rdHi := AST.xthi 32<rt> result
    rdLo := AST.xtlo 32<rt> result
    if isSetFlags then
      let cpsr = regVar bld R.CPSR
      cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
      cpsr := result == AST.num0 64<rt> |> setPSR bld R.CPSR PSR.Z
    else
      ()
    putEndLabel bld lblIgnore
  }

let smulacclongdual (ins: Instruction) bld sign =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
    let o = tmpVar bld 32<rt>
    let struct (p1, p2, result) = tmpVars3 bld 64<rt>
    let rotated = shiftROR src2 32<rt> 16u
    let xtlo src = AST.xtlo 16<rt> src |> AST.sext 64<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.sext 64<rt>
    if sign then append bld { o := rotated } else append bld { o := src2 }
    p1 := xtlo src1 .* xtlo o
    p2 := xthi src1 .* xthi o
    result := p1 .+ p2 .+ AST.concat dst2 dst1
    dst2 := AST.xthi 32<rt> result
    dst1 := AST.xtlo 32<rt> result
    putEndLabel bld lblIgnore
  }

let smulaccwordbyhalf (ins: Instruction) bld sign =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2, src3) = transFourOprs ins bld
    let o = tmpVar bld 32<rt>
    let result = tmpVar bld 64<rt>
    let sext src = AST.sext 64<rt> src
    if sign then append bld { o := AST.xthi 16<rt> src2 |> AST.sext 32<rt> }
    else append bld { o := AST.xtlo 16<rt> src2 |> AST.sext 32<rt> }
    result := sext src1 .* sext o .+ sext (src3 << numI32 16 32<rt>)
    dst := AST.extract result 32<rt> 16
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite ((result >> numI32 16 64<rt>) != sext dst)
                    (enablePSRBits bld R.CPSR PSR.Q)
                    cpsr
    putEndLabel bld lblIgnore
  }

let smulacchalf ins bld s1top s2top =
  lift bld ins {
    let struct (rd, rn, rm, ra) = transFourOprs ins bld
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if s1top then append bld { t1 := AST.xthi 16<rt> rn |> AST.zext 32<rt> }
    else append bld { t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt> }
    if s2top then append bld { t2 := AST.xthi 16<rt> rm |> AST.zext 32<rt> }
    else append bld { t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt> }
    rd := (t1 .* t2) .+ AST.sext 32<rt> ra
    putEndLabel bld lblIgnore
  }

let smulacclonghalf (ins: Instruction) bld s1top s2top =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
    let struct (o1, o2, result) = tmpVars3 bld 64<rt>
    if s1top then append bld { o1 := AST.xthi 16<rt> src1 |> AST.sext 64<rt> }
    else append bld { o1 := AST.xtlo 16<rt> src1 |> AST.sext 64<rt> }
    if s2top then append bld { o2 := AST.xthi 16<rt> src2 |> AST.sext 64<rt> }
    else append bld { o2 := AST.xtlo 16<rt> src2 |> AST.sext 64<rt> }
    result := o1 .* o2 .+ AST.concat dst2 dst1
    dst2 := AST.xthi 32<rt> result
    dst1 := AST.xtlo 32<rt> result
    putEndLabel bld lblIgnore
  }

let parseOprOfB (ins: Instruction) =
  let addr = bvOfBaseAddr (ins.Address + pcOffset ins)
  match ins.Operands with
  | OneOperand(OprMemory(LiteralMode imm)) -> addr .+ (numI64 imm 32<rt>)
  | _ -> raise InvalidOperandException

let b ins bld =
  lift bld ins {
    let e = parseOprOfB ins
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    branchWritePC e InterJmpKind.Base
    putEndLabelForBranch bld lblIgnore ins
    return NoEndMark
  }

let bx ins bld =
  lift bld ins {
    let rm = transOneOpr ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rm = convertPCOpr ins bld rm
    bxWritePC bld isUnconditional rm
    putEndLabelForBranch bld lblIgnore ins
    return NoEndMark
  }

let movtAssign dst src =
  let maskHigh16In32 = AST.num <| BitVector(4294901760I, 32<rt>)
  let clearHigh16In32 expr = expr .& AST.not maskHigh16In32
  dst := clearHigh16In32 dst .|
         (src << (numI32 16 32<rt>))

let movt ins bld =
  lift bld ins {
    let struct (dst, res) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    movtAssign dst res
    putEndLabel bld lblIgnore
  }

let transFourOprsWithBarrelShift (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(opr1, opr2, opr3, OprShift(typ, Imm imm)) ->
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src1 = transOpr ins bld opr2
    let src2 = transOpr ins bld opr3
    let shifted = shift src2 32<rt> typ imm carryIn
    struct (dst, src1, shifted)
  | _ ->
    raise InvalidOperandException

let pkh (ins: Instruction) bld isTbform =
  lift bld ins {
    let struct (dst, src1, src2) = transFourOprsWithBarrelShift ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let src1H, src1L = AST.xthi 16<rt> src1, AST.xtlo 16<rt> src1
    let src2H, src2L = AST.xthi 16<rt> src2, AST.xtlo 16<rt> src2
    let res =
      if isTbform then AST.concat src1H src2L else AST.concat src2H src1L
    dst := res
    putEndLabel bld lblIgnore
  }

let popLoop bld numOfReg addr =
  let loop addr count =
    if (numOfReg >>> count) &&& 1u = 1u then
      let reg = count |> uint32 |> OperandHelper.getRegister
      append bld {
        regVar bld reg := AST.loadLE 32<rt> addr
      }
      (addr .+ (numI32 4 32<rt>))
    else
      addr
  List.fold loop addr [ 0 .. 14 ]

let pop ins bld =
  lift bld ins {
    let t0 = tmpVar bld 32<rt>
    let sp = regVar bld R.SP
    let numOfReg = parseOprOfPUSHPOP ins
    let stackWidth = 4 * bitCount numOfReg 16
    let addr = sp
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t0 := addr
    let addr = popLoop bld numOfReg t0
    if (numOfReg >>> 13 &&& 1u) = 0u then
      sp := sp .+ (numI32 stackWidth 32<rt>)
    else
      sp := (AST.undef 32<rt> "UNKNOWN")
    if (numOfReg >>> 15 &&& 1u) = 1u then
      AST.loadLE 32<rt> addr |> loadWritePC bld isUnconditional
    else
      ()
    putEndLabelForBranch bld lblIgnore ins
  }

let parseOprOfLDM (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprRegList regs) ->
    struct (regVar bld reg, getRegNum reg, regsToUInt32 regs)
  | _ ->
    raise InvalidOperandException

let getLDMStartAddr rn stackWidth = function
  | Op.LDM | Op.LDMIA -> rn
  | Op.LDMDA -> rn .- (numI32 stackWidth 32<rt>) .+ (numI32 4 32<rt>)
  | Op.LDMDB -> rn .- (numI32 stackWidth 32<rt>)
  | Op.LDMIB -> rn .+ (numI32 4 32<rt>)
  | _ -> raise InvalidOpcodeException

let ldm opcode ins bld wbackop =
  lift bld ins {
    let struct (t0, t1) = tmpVars2 bld 32<rt>
    let struct (rn, numOfRn, numOfReg) = parseOprOfLDM ins bld
    let wback = ins.WriteBack
    let stackWidth = 4 * bitCount numOfReg 16
    let addr = getLDMStartAddr t0 stackWidth opcode
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t0 := rn
    t1 := addr
    let addr = popLoop bld numOfReg t1
    if wback && (numOfReg &&& numOfRn) = 0u then
      rn := wbackop t0 (numI32 stackWidth 32<rt>)
    else
      ()
    if wback && (numOfReg &&& numOfRn) = numOfRn then
      rn := (AST.undef 32<rt> "UNKNOWN")
    else
      ()
    if (numOfReg >>> 15 &&& 1u) = 1u then
      AST.loadLE 32<rt> addr |> loadWritePC bld isUnconditional
    else
      ()
    putEndLabel bld lblIgnore
  }

let getOffAddrWithExpr s r e = if s = Some Plus then r .+ e else r .- e

let getOffAddrWithImm s r imm =
  match s, imm with
  | Some Plus, Some i -> r .+ (numI64 i 32<rt>)
  | Some Minus, Some i -> r .- (numI64 i 32<rt>)
  | _, _ -> r

let parseMemOfLDR ins bld = function
  | OprMemory(OffsetMode(ImmOffset(rn, s, imm))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    struct (getOffAddrWithImm s rn imm, None)
  | OprMemory(PreIdxMode(ImmOffset(rn, s, imm))) ->
    let rn = regVar bld rn
    struct (getOffAddrWithImm s rn imm, Some(rn, None))
  | OprMemory(PostIdxMode(ImmOffset(rn, s, imm))) ->
    let rn = regVar bld rn
    struct (rn, Some(rn, Some(getOffAddrWithImm s rn imm)))
  | OprMemory(LiteralMode imm) ->
    let addr = bvOfBaseAddr ins.Address
    let pc = align addr (numI32 4 32<rt>)
    let rel = if not ins.IsThumb then 8u else 4u
    struct (pc .+ (numU32 rel 32<rt>) .+ (numI64 imm 32<rt>), None)
  | OprMemory(OffsetMode(RegOffset(n, _, m, None))) ->
    let m = regVar bld m |> convertPCOpr ins bld
    let n = regVar bld n |> convertPCOpr ins bld
    struct (n .+ shift m 32<rt> ShiftOp.LSL 0u (getCarryFlag bld), None)
  | OprMemory(PreIdxMode(RegOffset(n, s, m, None))) ->
    let rn = regVar bld n
    let offset = shift (regVar bld m) 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    struct (getOffAddrWithExpr s rn offset, Some(rn, None))
  | OprMemory(PostIdxMode(RegOffset(n, s, m, None))) ->
    let rn = regVar bld n
    let offset = shift (regVar bld m) 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    struct (rn, Some(rn, Some(getOffAddrWithExpr s rn offset)))
  | OprMemory(OffsetMode(RegOffset(n, s, m, Some(t, Imm i)))) ->
    let rn = regVar bld n |> convertPCOpr ins bld
    let rm = regVar bld m |> convertPCOpr ins bld
    let offset = shift rm 32<rt> t i (getCarryFlag bld)
    struct (getOffAddrWithExpr s rn offset, None)
  | OprMemory(PreIdxMode(RegOffset(n, s, m, Some(t, Imm i)))) ->
    let rn = regVar bld n
    let offset = shift (regVar bld m) 32<rt> t i (getCarryFlag bld)
    struct (getOffAddrWithExpr s rn offset, Some(rn, None))
  | OprMemory(PostIdxMode(RegOffset(n, s, m, Some(t, Imm i)))) ->
    let rn = regVar bld n
    let offset = shift (regVar bld m) 32<rt> t i (getCarryFlag bld)
    struct (rn, Some(rn, Some(getOffAddrWithExpr s rn offset)))
  | _ ->
    raise InvalidOperandException

let parseOprOfLDR (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg rt, (OprMemory _ as mem)) ->
    let struct (addr, writeback) = parseMemOfLDR ins bld mem
    struct (regVar bld rt, addr, writeback)
  | _ ->
    raise InvalidOperandException

/// Load register
let ldr ins bld size ext =
  lift bld ins {
    let data = tmpVar bld 32<rt>
    let struct (rt, addr, writeback) = parseOprOfLDR ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    match writeback with
    | Some(basereg, Some newoffset) ->
      let struct (taddr, twriteback) = tmpVars2 bld 32<rt>
      taddr := addr
      twriteback := newoffset
      data := AST.loadLE size taddr |> ext 32<rt>
      basereg := twriteback
    | Some(basereg, None) ->
      let taddr = tmpVar bld 32<rt>
      taddr := addr
      data := AST.loadLE size taddr |> ext 32<rt>
      basereg := taddr
    | None ->
      data := AST.loadLE size addr |> ext 32<rt>
    if rt = getPC bld then loadWritePC bld isUnconditional data
    else append bld { rt := data }
    putEndLabel bld lblIgnore
  }

let parseMemOfLDRD ins bld = function
  | OprMemory(OffsetMode(RegOffset(n, s, m, None))) ->
    struct (getOffAddrWithExpr s (regVar bld n) (regVar bld m), None)
  | OprMemory(PreIdxMode(RegOffset(n, s, m, None))) ->
    let rn = regVar bld n
    struct (getOffAddrWithExpr s rn (regVar bld m), Some(rn, None))
  | OprMemory(PostIdxMode(RegOffset(n, s, m, None))) ->
    let rn = regVar bld n
    struct (rn, Some(rn, Some(getOffAddrWithExpr s rn (regVar bld m))))
  | mem ->
    parseMemOfLDR ins bld mem

let parseOprOfLDRD (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg t, OprReg t2, (OprMemory _ as mem)) ->
    let struct (addr, stmt) = parseMemOfLDRD ins bld mem
    struct (regVar bld t, regVar bld t2, addr, stmt)
  | _ ->
    raise InvalidOperandException

let ldrd ins bld =
  lift bld ins {
    let taddr = tmpVar bld 32<rt>
    let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let n4 = numI32 4 32<rt>
    match writeback with
    | Some(basereg, Some newoffset) ->
      let twriteback = tmpVar bld 32<rt>
      taddr := addr
      twriteback := newoffset
      rt := AST.loadLE 32<rt> taddr
      rt2 := AST.loadLE 32<rt> (taddr .+ n4)
      basereg := twriteback
    | Some(basereg, None) ->
      taddr := addr
      rt := AST.loadLE 32<rt> taddr
      rt2 := AST.loadLE 32<rt> (taddr .+ n4)
      basereg := taddr
    | None ->
      taddr := addr
      rt := AST.loadLE 32<rt> taddr
      rt2 := AST.loadLE 32<rt> (taddr .+ n4)
    putEndLabel bld lblIgnore
  }

let sel8Bits r offset = AST.extract r 8<rt> offset |> AST.zext 32<rt>

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

let uadd8 ins bld =
  lift bld ins {
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let struct (sum1, sum2, sum3, sum4) = tmpVars4 bld 32<rt>
    let struct (ge0, ge1, ge2, ge3) = tmpVars4 bld 32<rt>
    let cpsr = regVar bld R.CPSR
    let n100 = numI32 0x100 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    sum1 := sel8Bits rn 0 .+ sel8Bits rm 0
    sum2 := sel8Bits rn 8 .+ sel8Bits rm 8
    sum3 := sel8Bits rn 16 .+ sel8Bits rm 16
    sum4 := sel8Bits rn 24 .+ sel8Bits rm 24
    rd := combine8bitResults sum1 sum2 sum3 sum4
    ge0 := AST.zext 32<rt> (AST.ge sum1 n100)
    ge1 := AST.zext 32<rt> (AST.ge sum2 n100)
    ge2 := AST.zext 32<rt> (AST.ge sum3 n100)
    ge3 := AST.zext 32<rt> (AST.ge sum4 n100)
    cpsr := combineGEs ge0 ge1 ge2 ge3 |> setPSR bld R.CPSR PSR.GE
    putEndLabel bld lblIgnore
  }

let sel ins bld =
  lift bld ins {
    let struct (t1, t2, t3, t4) = tmpVars4 bld 32<rt>
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let n1 = AST.num1 32<rt>
    let n2 = numI32 2 32<rt>
    let n4 = numI32 4 32<rt>
    let n8 = numI32 8 32<rt>
    let ge = getPSR bld R.CPSR PSR.GE >> (numI32 16 32<rt>)
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t1 := AST.ite ((ge .& n1) == n1) (sel8Bits rn 0) (sel8Bits rm 0)
    t2 := AST.ite ((ge .& n2) == n2) (sel8Bits rn 8) (sel8Bits rm 8)
    t3 := AST.ite ((ge .& n4) == n4) (sel8Bits rn 16) (sel8Bits rm 16)
    t4 := AST.ite ((ge .& n8) == n8) (sel8Bits rn 24) (sel8Bits rm 24)
    rd := combine8bitResults t1 t2 t3 t4
    putEndLabel bld lblIgnore
  }

let rbit ins bld =
  lift bld ins {
    let struct (t1, t2) = tmpVars2 bld 32<rt>
    let struct (rd, rm) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t1 := rm
    rd := rd <+> rd
    for i = 0 to 31 do
      t2 := (AST.extract t1 1<rt> i) |> AST.zext 32<rt>
      rd := rd .| (t2 << (numI32 (31 - i) 32<rt>))
    putEndLabel bld lblIgnore
  }

let rev ins bld =
  lift bld ins {
    let struct (t1, t2, t3, t4) = tmpVars4 bld 32<rt>
    let struct (rd, rm) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t1 := sel8Bits rm 0
    t2 := sel8Bits rm 8
    t3 := sel8Bits rm 16
    t4 := sel8Bits rm 24
    rd := combine8bitResults t4 t3 t2 t1
    putEndLabel bld lblIgnore
  }

let rev16 ins bld =
  lift bld ins {
    let struct (rd, rm) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let r1 = AST.extract rm 8<rt> 16
    let r2 = AST.extract rm 8<rt> 24
    let r3 = AST.extract rm 8<rt> 0
    let r4 = AST.extract rm 8<rt> 8
    rd := AST.revConcat [| r4; r3; r2; r1 |]
    putEndLabel bld lblIgnore
  }

let revsh ins bld =
  lift bld ins {
    let struct (rd, rm) = transTwoOprs ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let r1 = (AST.xtlo 8<rt> rm |> AST.sext 32<rt>) << numI32 8 32<rt>
    let r2 = AST.extract rm 8<rt> 8 |> AST.zext 32<rt>
    rd := r1 .| r2
    putEndLabel bld lblIgnore
  }

let rfedb (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let dst = transOneOpr ins bld
    let wback = ins.WriteBack
    let struct (addr, newPcValue, spsr) = tmpVars3 bld 32<rt>
    addr := dst .- numI32 8 32<rt>
    newPcValue := AST.loadLE 32<rt> addr
    spsr := AST.loadLE 32<rt> (addr .+ numI32 4 32<rt>)
    match wback with
    | true -> append bld { dst := dst .- numI32 8 32<rt> }
    | _ -> append bld { dst := dst }
    putEndLabel bld lblIgnore
  }

/// Store register.
let str ins bld size =
  lift bld ins {
    let struct (rt, addr, writeback) = parseOprOfLDR ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if rt = getPC bld then
      append bld { AST.loadLE 32<rt> addr := pcStoreValue bld }
    elif size = 32<rt> then
      append bld { AST.loadLE 32<rt> addr := rt }
    else
      append bld { AST.loadLE size addr := AST.xtlo size rt }
    match writeback with
    | Some(basereg, Some newoffset) -> append bld { basereg := newoffset }
    | Some(basereg, None) -> append bld { basereg := addr }
    | None -> ()
    putEndLabel bld lblIgnore
  }

/// Load-exclusive (LDREX/LDREXB/LDREXH, and the acquire forms LDAEX*): records
/// an exclusive reservation -- the reserved address and the value read there --
/// so a later store-exclusive can tell, by value comparison, whether the
/// location was written in between. Under single-observer emulation this needs
/// no external call and no per-store instrumentation.
let ldrex ins bld size =
  lift bld ins {
    let struct (rt, addr, _) = parseOprOfLDR ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let taddr = tmpVar bld 32<rt>
    let raw = tmpVar bld size
    taddr := addr
    raw := AST.loadLE size taddr
    regVar bld R.ExMonAddr := taddr
    regVar bld R.ExMonVal := AST.zext 32<rt> raw
    rt := AST.zext 32<rt> raw
    putEndLabel bld lblIgnore
  }

/// Load-exclusive pair (LDREXD/LDAEXD): loads both words and reserves the
/// block, recording the low word for a later store-exclusive pair to verify.
let ldrexd ins bld =
  lift bld ins {
    let struct (rt, rt2, addr, _) = parseOprOfLDRD ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let taddr = tmpVar bld 32<rt>
    let lo = tmpVar bld 32<rt>
    let hi = tmpVar bld 32<rt>
    taddr := addr
    lo := AST.loadLE 32<rt> taddr
    hi := AST.loadLE 32<rt> (taddr .+ numI32 4 32<rt>)
    regVar bld R.ExMonAddr := taddr
    regVar bld R.ExMonVal := lo
    rt := lo
    rt2 := hi
    putEndLabel bld lblIgnore
  }

/// Store-exclusive (STREX/STREXB/STREXH, and the release forms STLEX*): stores
/// and reports success (Rd = 0) only if the reservation still holds -- the
/// address matches and memory still holds the reserved value; otherwise memory
/// is left unchanged and it reports failure (Rd = 1). The conditional store is
/// expressed as a store of ite(matched, data, old), so no branch is emitted.
let strex ins bld size =
  lift bld ins {
    let struct (rd, rt, addr, _) = parseOprOfLDRD ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let taddr = tmpVar bld 32<rt>
    let cur = tmpVar bld size
    let matched = tmpVar bld 1<rt>
    taddr := addr
    cur := AST.loadLE size taddr
    matched := (taddr == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo size (regVar bld R.ExMonVal))
    AST.loadLE size taddr := AST.ite matched (AST.xtlo size rt) cur
    rd := AST.ite matched (AST.num0 32<rt>) (AST.num1 32<rt>)
    putEndLabel bld lblIgnore
  }

let parseOprOfSTREXD (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg t, OprReg t2, (OprMemory _ as mem)) ->
    let struct (addr, stmt) = parseMemOfLDRD ins bld mem
    struct (regVar bld rd, regVar bld t, regVar bld t2, addr, stmt)
  | _ ->
    raise InvalidOperandException

/// Store-exclusive pair (STREXD/STLEXD): as strex, verifying the reserved low
/// word; on success both words are stored.
let strexd ins bld =
  lift bld ins {
    let struct (rd, rt, rt2, addr, _) = parseOprOfSTREXD ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let taddr = tmpVar bld 32<rt>
    let cur = tmpVar bld 32<rt>
    let matched = tmpVar bld 1<rt>
    taddr := addr
    cur := AST.loadLE 32<rt> taddr
    matched := (taddr == regVar bld R.ExMonAddr)
               .& (cur == regVar bld R.ExMonVal)
    AST.loadLE 32<rt> taddr := AST.ite matched rt cur
    AST.loadLE 32<rt> (taddr .+ numI32 4 32<rt>) :=
      AST.ite matched rt2 (AST.loadLE 32<rt> (taddr .+ numI32 4 32<rt>))
    rd := AST.ite matched (AST.num0 32<rt>) (AST.num1 32<rt>)
    putEndLabel bld lblIgnore
  }

let strd ins bld =
  lift bld ins {
    let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    AST.loadLE 32<rt> addr := rt
    AST.loadLE 32<rt> (addr .+ (numI32 4 32<rt>)) := rt2
    match writeback with
    | Some(basereg, Some newoffset) -> append bld { basereg := newoffset }
    | Some(basereg, None) -> append bld { basereg := addr }
    | None -> ()
    putEndLabel bld lblIgnore
  }

let parseOprOfSTM (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprRegList regs) ->
    regVar bld reg, regsToUInt32 regs
  | _ ->
    raise InvalidOperandException

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
        append bld {
          AST.loadLE 32<rt> addr := (AST.undef 32<rt> "UNKNOWN")
        }
      else
        append bld {
          AST.loadLE 32<rt> addr := ri
        }
      addr .+ (numI32 4 32<rt>)
    else
      addr
  List.fold loop addr [ 0 .. 14 ]

let stm opcode ins bld wbop =
  lift bld ins {
    let taddr = tmpVar bld 32<rt>
    let rn, regs = parseOprOfSTM ins bld
    let wback = ins.WriteBack
    let msize = numI32 (4 * bitCount regs 16) 32<rt>
    let addr = getSTMStartAddr rn msize opcode
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    taddr := addr
    let addr = stmLoop bld regs wback rn taddr
    if (regs >>> 15 &&& 1u) = 1u then
      AST.loadLE 32<rt> addr := pcStoreValue bld
    else
      ()
    if wback then append bld { rn := wbop rn msize } else ()
    putEndLabel bld lblIgnore
  }

let parseOprOfCBZ (ins: Instruction) bld =
  let pc = bvOfBaseAddr ins.Address
  let offset = pcOffset ins |> int64
  match ins.Operands with
  | TwoOperands(OprReg rn, (OprMemory(LiteralMode imm))) ->
    regVar bld rn, pc .+ (numI64 (imm + offset) 32<rt>)
  | _ ->
    raise InvalidOperandException

let cbz nonZero ins bld =
  lift bld ins {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let n = if nonZero then AST.num1 1<rt> else AST.num0 1<rt>
    let rn, pc = parseOprOfCBZ ins bld
    let cond = n <+> (rn == AST.num0 32<rt>)
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    branchWritePC pc InterJmpKind.Base
    AST.lmark lblL1
    let fallAddr = ins.Address + uint64 ins.Length
    let fallAddrExp = numU64 fallAddr 32<rt>
    AST.interjmp fallAddrExp InterJmpKind.Base
    putEndLabelForBranch bld lblIgnore ins
    return NoEndMark
  }

let parseOprOfTableBranch (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand(OprMemory(OffsetMode(RegOffset(rn, None, rm, None)))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    let rm = regVar bld rm |> convertPCOpr ins bld
    let addr = rn .+ rm
    AST.loadLE 8<rt> addr |> AST.zext 32<rt>
  | OneOperand(OprMemory(OffsetMode(RegOffset(rn,
                                              None,
                                              rm,
                                              Some(_, Imm i))))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    let rm = regVar bld rm |> convertPCOpr ins bld
    let addr = rn .+ (shiftLSL rm 32<rt> i)
    AST.loadLE 16<rt> addr |> AST.zext 32<rt>
  | _ ->
    raise InvalidOperandException

let tableBranch (ins: Instruction) bld =
  lift bld ins {
    let offset = if not ins.IsThumb then 8 else 4
    let pc = bvOfBaseAddr ins.Address .+ (numI32 offset 32<rt>)
    let halfwords = parseOprOfTableBranch ins bld
    let numTwo = numI32 2 32<rt>
    let result = pc .+ (numTwo .* halfwords)
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    branchWritePC result InterJmpKind.Base
    putEndLabel bld lblIgnore
    return NoEndMark
  }

let parseOprOfBFC (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprImm lsb, OprImm width) ->
    regVar bld rd, Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ ->
    raise InvalidOperandException

let bfc (ins: Instruction) bld =
  lift bld ins {
    let rd, lsb, width = parseOprOfBFC ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    rd := replicate rd 32<rt> lsb width 0
    putEndLabel bld lblIgnore
  }

let parseOprOfRdRnLsbWidth (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    regVar bld rd, regVar bld rn, Convert.ToInt32 lsb, Convert.ToInt32 width
  | _ ->
    raise InvalidOperandException

let bfi ins bld =
  lift bld ins {
    let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins bld
    let struct (t0, t1) = tmpVars2 bld 32<rt>
    let n = rn .& (BitVector(BigInteger.makeMask width, 32<rt>) |> AST.num)
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    t0 := n << (numI32 lsb 32<rt>)
    t1 := replicate rd 32<rt> lsb width 0
    rd := t0 .| t1
    putEndLabel bld lblIgnore
  }

let bfx ins bld signExtend =
  lift bld ins {
    let rd, rn, lsb, width = parseOprOfRdRnLsbWidth ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if lsb + width - 1 > 31 || width < 0 then raise InvalidOperandException
    else ()
    let v = BitVector(BigInteger.makeMask width, 32<rt>) |> AST.num
    rd := (rn >> (numI32 lsb 32<rt>)) .& v
    if signExtend && width > 1 then
      let struct (msb, mask) = tmpVars2 bld 32<rt>
      let msboffset = numI32 (lsb + width - 1) 32<rt>
      let shift = numI32 width 32<rt>
      msb := (rn >> msboffset) .& AST.num1 32<rt>
      mask := (AST.not (msb .- AST.num1 32<rt>)) << shift
      rd := rd .| mask
    else
      ()
    putEndLabel bld lblIgnore
  }

let parseOprOfUqOpr bld = function
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    regVar bld rd, regVar bld rn, regVar bld rm
  | _ ->
    raise InvalidOperandException

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
  AST.ite (AST.sgt e max32)
    (AST.xtlo resultType max32)
    (AST.ite (AST.slt e zero) (AST.num0 resultType) (AST.xtlo resultType e))

let getUQAssignment tmps width =
  tmps
  |> Array.mapi (fun idx t ->
       (AST.zext 32<rt> t) << (numI32 (idx * width) 32<rt>))
  |> Array.reduce (.|)

let uqopr (ins: Instruction) bld width opr =
  lift bld ins {
    let rd, rn, rm = parseOprOfUqOpr bld ins.Operands
    let tmps = createTemporaries bld (32 / width) 32<rt>
    let sats = createTemporaries bld (32 / width) (RegType.fromBitWidth width)
    let rns = extractUQOps rn width
    let rms = extractUQOps rm width
    let diffs = Array.map2 opr rns rms
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    Array.iter2 (fun tmp diff -> append bld { tmp := diff }) tmps diffs
    Array.iter2 (fun s t -> append bld { s := saturate t width }) sats tmps
    rd := getUQAssignment sats width
    putEndLabel bld lblIgnore
  }

/// ADR For ThumbMode (T1 case)
let parseOprOfADR (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprMemory(LiteralMode imm)) ->
    let addr = bvOfBaseAddr ins.Address
    let rel = if not ins.IsThumb then 8 else 4
    let addr = addr .+ (numI32 rel 32<rt>)
    let pc = align addr (numI32 4 32<rt>)
    let imm = numI64 imm 32<rt>
    let pc = if ins.IsAdd then pc .+ imm else pc .- imm
    regVar bld rd, pc
  | _ ->
    raise InvalidOperandException

let it (ins: Instruction) bld =
  lift bld ins {
    let cpsr = regVar bld R.CPSR
    let itState = numI32 (int ins.ITState) 32<rt>
    let mask10 = numI32 0b11 32<rt>
    let mask72 = (numI32 0b11111100 32<rt>)
    let itState10 = itState .& mask10
    let itState72 = (itState .& mask72) >> (numI32 2 32<rt>)
    cpsr := itState10 |> setPSR bld R.CPSR PSR.IT10
    cpsr := itState72 |> setPSR bld R.CPSR PSR.IT72
  }

let adr ins bld =
  lift bld ins {
    let rd, result = parseOprOfADR ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    if rd = getPC bld then aluWritePC bld ins isUnconditional result
    else append bld { rd := result }
    putEndLabel bld lblIgnore
  }

let mls ins bld =
  lift bld ins {
    let struct (rd, rn, rm, ra) = transFourOprs ins bld
    let r = tmpVar bld 32<rt>
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    r := AST.xtlo 32<rt> (AST.zext 64<rt> ra .- AST.zext 64<rt> rn .*
                               AST.zext 64<rt> rm)
    rd := r
    putEndLabel bld lblIgnore
  }

let parseOprOfExtend (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg rm) ->
    regVar bld rd, regVar bld rm, 0u
  | ThreeOperands(OprReg rd, OprReg rm, OprShift(_, Imm i)) ->
    regVar bld rd, regVar bld rm, i
  | _ ->
    raise InvalidOperandException

let extend (ins: Instruction) bld extractfn amount =
  lift bld ins {
    let rd, rm, rotation = parseOprOfExtend ins bld
    let rotated = shiftROR rm 32<rt> rotation
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    rd := extractfn 32<rt> (AST.xtlo amount rotated)
    putEndLabel bld lblIgnore
  }

let uxtb16 ins bld =
  lift bld ins {
    let rd, rm, rotation = parseOprOfExtend ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rotated = shiftROR rm 32<rt> rotation
    let r1 = AST.xtlo 8<rt> rotated |> AST.zext 32<rt>
    let r2 =
      (AST.extract rotated 8<rt> 16 |> AST.zext 32<rt>) << numI32 16 32<rt>
    rd := r2 .| r1
    putEndLabel bld lblIgnore
  }

let parseOprOfXTA (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprShift(_, Imm i)) ->
    regVar bld rd, regVar bld rn, regVar bld rm, i
  | _ ->
    raise InvalidOperandException

let extendAndAdd (ins: Instruction) bld extractfn amount =
  lift bld ins {
    let rd, rn, rm, rotation = parseOprOfXTA ins bld
    let rotated = shiftROR rm 32<rt> rotation
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    rd := rn .+ extractfn 32<rt> (AST.xtlo amount rotated)
    putEndLabel bld lblIgnore
  }
