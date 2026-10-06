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
    (* Outside the `else`, where every sibling in this file puts it. It sat
       inside, and Op.ADDS always takes the flag-setting arm -- so a
       conditional ADDS emitted its cjmp to the skip label and never marked
       it. The evaluator failed on the missing label rather than producing a
       wrong value, and in Thumb the ITSTATE advance went with it. *)
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
          loadNative bld 32<rt> t := (AST.undef 32<rt> "UNKNOWN")
        }
      else
        let reg = count |> uint32 |> OperandHelper.getRegister
        append bld {
          loadNative bld 32<rt> t := regVar bld reg
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
      loadNative bld 32<rt> addr := pcStoreValue bld
    else
      ()
    sp := t0
    putEndLabel bld lblIgnore
  }

/// shared/functions/vector/SignedSatQ, on page Armv8 Pseudocode-7927
///
/// `oprSz` is the width the incoming value is held at and `n` the width to
/// saturate to, and oprSz has to be the WIDER of the two. The definition is
/// "if the value falls outside the n-bit signed range, clamp it to the nearer
/// end", and a value already narrowed to n bits cannot fall outside it -- it
/// has wrapped instead, and the information the saturation exists to catch is
/// gone before it is asked. So every caller computes at a wider width and
/// passes that width in.
///
/// Both comparisons are signed. An unsigned one reads every negative value as
/// larger than the positive limit and clamps it to the top of the range, which
/// turned a QSAX lane of -3704 into 32767.
let sSatQ bld i oprSz n =
  let shift = RegType.toBitWidth n - 1
  let maxV = numI64 ((1L <<< shift) - 1L) oprSz
  let minV = numI64 (-(1L <<< shift)) oprSz
  let t = tmpVar bld oprSz
  append bld {
    t := i
  }
  let tooHigh = t ?> maxV
  let tooLow = t ?< minV
  let r = AST.xtlo n (AST.ite tooHigh maxV (AST.ite tooLow minV t))
  let sat = AST.ite tooHigh AST.b1 (AST.ite tooLow AST.b1 (AST.num0 1<rt>))
  struct (r, sat)

let sSat bld i oprSz n =
  let struct (r, _) = sSatQ bld i oprSz n
  r

/// <summary>
/// QADD and QSUB, the scalar saturating pair.
///
/// The arithmetic is done at sixty-four bits because that is where a sum of
/// two thirty-two bit values that went out of range still exists; a thirty-two
/// bit addition has wrapped, and SignedSat asked after it has nothing left to
/// clamp. Q is set where the answer was clamped and is never cleared.
///
/// These are not the doubling forms below, which clamp twice.
/// </summary>
let qaddsub (ins: Instruction) bld isSub =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let wide e = AST.sext 64<rt> e
    let value = if isSub then wide src1 .- wide src2 else wide src1 .+ wide src2
    let struct (r, sat) = sSatQ bld value 64<rt> 32<rt>
    dst := r
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite sat (enablePSRBits bld R.CPSR PSR.Q) cpsr
    putEndLabel bld lblIgnore
  }

let qdadd (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (sat1, sat2) = tmpVars2 bld 1<rt>
    (* Both saturations are to 32 bits, so both operations are done at 64:
       2 * Rm overflows a 32-bit register for half of all inputs, and that
       overflow is exactly what the first SignedSat is there to catch. *)
    let wide e = AST.sext 64<rt> e
    let struct (dou, sat) =
      sSatQ bld (numI32 2 64<rt> .* wide src2) 64<rt> 32<rt>
    sat1 := sat
    let struct (r, sat) =
      sSatQ bld (wide src1 .+ wide dou) 64<rt> 32<rt>
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
    (* Both saturations are to 32 bits, so both operations are done at 64:
       2 * Rm overflows a 32-bit register for half of all inputs, and that
       overflow is exactly what the first SignedSat is there to catch. *)
    let wide e = AST.sext 64<rt> e
    let struct (dou, sat) =
      sSatQ bld (numI32 2 64<rt> .* wide src2) 64<rt> 32<rt>
    sat1 := sat
    let struct (r, sat) =
      sSatQ bld (wide src1 .- wide dou) 64<rt> 32<rt>
    dst := r
    sat2 := sat
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite (sat1 .| sat2) (enablePSRBits bld R.CPSR PSR.Q) cpsr
    putEndLabel bld lblIgnore
  }

/// <summary>
/// UnsignedSat: what an n-bit unsigned lane holds, clamped.
///
/// Both comparisons are signed, because the value arrives WIDER than the lane
/// and a borrow has already left it negative there; an unsigned comparison
/// reads that as an enormous number and clamps it to the top of the range
/// instead of to the bottom.
/// </summary>
let private uSat i oprSz n =
  let maxV = numI64 ((1L <<< RegType.toBitWidth n) - 1L) oprSz
  let zero = AST.num0 oprSz
  AST.xtlo n (AST.ite (i ?> maxV) maxV (AST.ite (i ?< zero) zero i))

/// <summary>
/// How a lane of a parallel add or subtract is finished.
///
/// The family is written with six prefixes, which are three treatments of a
/// lane crossed with the two signednesses. A WRAPPING lane keeps the low bits
/// and says in the GE flags what went over; a SATURATING one clamps to the
/// lane's range; a HALVING one shifts the answer down a place, which is why
/// it cannot go over at all.
/// </summary>
type ParallelLane =
  | WrappingLane
  | SaturatingLane
  | HalvingLane

/// <summary>
/// Which lane of the second operand each result lane reads, and whether it is
/// added or subtracted.
///
/// The plain forms read the lanes across from one another and do the same
/// thing to every one. The two exchanging forms cross the second operand's
/// halfwords over and do one of each, which is what their names say: ASX
/// subtracts in the low half and adds in the high one, SAX the other way
/// round.
/// </summary>
type ParallelPattern =
  | ParallelAdd
  | ParallelSub
  | AddSubExchange
  | SubAddExchange

/// Which lane of the second operand a lane of the first is paired with, and
/// whether the two are added. The exchanging forms cross the halves over and
/// add on one side while subtracting on the other.
let private parallelSource pattern i =
  match pattern with
  | ParallelAdd -> i, true
  | ParallelSub -> i, false
  | AddSubExchange -> 1 - i, i = 1
  | SubAddExchange -> 1 - i, i = 0

/// One lane's answer, narrowed back to the lane's own width the way the kind
/// of instruction says: by dropping the bits above it, by clamping to them,
/// or by keeping the bits one place up.
let private parallelLane bld kind unsigned wide rt value =
  match kind with
  | WrappingLane ->
    AST.xtlo rt value
  | SaturatingLane ->
    if unsigned then uSat value wide rt else sSat bld value wide rt
  | HalvingLane ->
    (* The shift is logical for both signednesses: only the low bits are
       kept, and the bit that lands in the top of them is the one above the
       lane either way. *)
    AST.xtlo rt (value >> AST.num1 wide)

/// The GE bits a wrapping form leaves behind, one for each byte of the answer
/// and a pair for each halfword.
let private parallelGE pattern unsigned eSize wide lanes (values: Expr[]) =
  let bits = 4 / lanes
  let geOf i =
    let _, isAdd = parallelSource pattern i
    if unsigned && isAdd then values[i] ?>= numI32 (1 <<< eSize) wide
    else values[i] ?>= AST.num0 wide
  Array.init lanes (fun i ->
    let m = numI32 (((1 <<< bits) - 1) <<< (i * bits)) 32<rt>
    AST.ite (geOf i) m (AST.num0 32<rt>))
  |> Array.reduce (.|)

/// <summary>
/// The parallel additions and subtractions, which are thirty-six mnemonics
/// over one instruction with three fields.
///
/// Every lane is computed at twice its own width, because that is where what
/// the three treatments need still exists: the bit a wrapping lane reports in
/// GE, the range a saturating lane is clamped to and the bit a halving lane
/// shifts back down all sit above the lane's own top bit, and an arithmetic
/// done at the lane's width has thrown them away before anything can read
/// them.
///
/// The GE flags belong to the wrapping forms alone. A saturating or a halving
/// lane cannot overflow, so it has nothing to report, and the manual leaves
/// the flags alone for them. What the bit means does change with the
/// operation: for a subtraction, and for a signed addition, it is that the
/// answer came out at or above zero; for an unsigned addition it is the carry
/// out, which is the answer reaching the lane's width.
/// </summary>
let parallelAddSub (ins: Instruction) bld eSize unsigned kind pattern =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let lanes = 32 / eSize
    let rt = RegType.fromBitWidth eSize
    let wide = RegType.fromBitWidth (eSize * 2)
    let ext e = if unsigned then AST.zext wide e else AST.sext wide e
    let lane src i = ext (AST.extract src rt (i * eSize))
    let values = Array.init lanes (fun _ -> tmpVar bld wide)
    let results = Array.init lanes (fun _ -> tmpVar bld rt)
    for i in 0 .. lanes - 1 do
      let j, isAdd = parallelSource pattern i
      let a = lane rn i
      let b = lane rm j
      values[i] := if isAdd then a .+ b else a .- b
      results[i] := parallelLane bld kind unsigned wide rt values[i]
    rd :=
      (results
       |> Array.mapi (fun i r -> AST.zext 32<rt> r << numI32 (i * eSize) 32<rt>)
       |> Array.reduce (.|))
    match kind with
    | WrappingLane ->
      let ge = parallelGE pattern unsigned eSize wide lanes values
      regVar bld R.CPSR := ge |> setPSR bld R.CPSR PSR.GE
    | _ ->
      ()
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
    let struct (t, amount) = tmpVars2 bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    let src1 = transOpr ins bld opr2
    let rm = transOpr ins bld opr3
    (* The amount register can be the destination, so it is read first too. *)
    append bld {
      t := rm
      amount := AST.xtlo 8<rt> (regVar bld reg) |> AST.zext 32<rt>
    }
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
        (* A rotated immediate carries out its top bit; anything else keeps
           C as it was. *)
        if ins.Cflag.IsSome then
          let carry = computeCarryOutFromImmCflag ins bld
          cpsr := carry |> setPSR bld R.CPSR PSR.C
        else
          ()
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
    struct (e1, e2, computeCarryOutFromImmCflag ins bld)
  | TwoOperands(OprReg _, OprReg _) ->
    let struct (e1, e2) = transTwoOprs ins bld
    let shifted, carryOut = shiftC e2 32<rt> ShiftOp.LSL 0u (getCarryFlag bld)
    struct (e1, shifted, carryOut)
  | _ ->
    raise InvalidOperandException

let transThreeOprsOfMVN (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(opr1, opr2, OprShift(typ, Imm imm)) ->
    let t = tmpVar bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    (* Rd can be the shifted register, whose bits C is taken from. *)
    append bld { t := transOpr ins bld opr2 }
    let shifted, carryOut = shiftC t 32<rt> typ imm carryIn
    struct (dst, shifted, carryOut)
  | ThreeOperands(opr1, opr2, OprRegShift(typ, rs)) ->
    let struct (t, amount) = tmpVars2 bld 32<rt>
    let carryIn = getCarryFlag bld
    let dst = transOpr ins bld opr1
    (* Rd can be the shifted register or the amount register. *)
    append bld {
      t := transOpr ins bld opr2
      amount := AST.xtlo 8<rt> (regVar bld rs) |> AST.zext 32<rt>
    }
    let shifted, carryOut = shiftCForRegAmount t 32<rt> typ amount carryIn
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
    let carry = tmpVar bld 1<rt>
    let dst, src, res, carryOut = parseOprOfShiftInstr ins typ bld srcTmp
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    srcTmp := src
    result := res
    (* The amount register can be the destination: take the carry first. *)
    if isSetFlags then carry := carryOut else ()
    if dst = getPC bld then
      aluWritePC bld ins isUnconditional result
    else
      dst := result
      if isSetFlags then
        let cpsr = regVar bld R.CPSR
        cpsr := AST.xthi 1<rt> result |> setPSR bld R.CPSR PSR.N
        cpsr := result == AST.num0 32<rt> |> setPSR bld R.CPSR PSR.Z
        cpsr := carry |> setPSR bld R.CPSR PSR.C
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
    rn, imm, computeCarryOutFromImmCflag ins bld
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
    if s1top then append bld { t1 := AST.xthi 16<rt> rn |> AST.sext 32<rt> }
    else append bld { t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt> }
    if s2top then append bld { t2 := AST.xthi 16<rt> rm |> AST.sext 32<rt> }
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

/// <summary>
/// SMLALD and SMLSLD, which take two halfword products at once and carry them
/// into a sixty-four bit accumulator.
///
/// The X in a name exchanges the second operand's halves before the products
/// are taken, which is a rotation by sixteen. Neither form touches the Q
/// flag: an accumulator this wide cannot be overflowed by two products of
/// halfwords.
/// </summary>
let smulacclongdual (ins: Instruction) bld swap isSub =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst1, dst2, src1, src2) = transFourOprs ins bld
    let o = tmpVar bld 32<rt>
    let struct (p1, p2, result) = tmpVars3 bld 64<rt>
    let rotated = shiftROR src2 32<rt> 16u
    let xtlo src = AST.xtlo 16<rt> src |> AST.sext 64<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.sext 64<rt>
    if swap then append bld { o := rotated } else append bld { o := src2 }
    p1 := xtlo src1 .* xtlo o
    p2 := xthi src1 .* xthi o
    result :=
      (if isSub then p1 .- p2 else p1 .+ p2) .+ AST.concat dst2 dst1
    dst2 := AST.xthi 32<rt> result
    dst1 := AST.xtlo 32<rt> result
    putEndLabel bld lblIgnore
  }

/// <summary>
/// SMUAD, SMUSD and the two that accumulate a third register into them.
///
/// Both halfword products are taken and then added or subtracted, and the sum
/// is kept at sixty-four bits because that is where the overflow the Q flag
/// reports still exists -- an addition done at thirty-two has already wrapped
/// and left nothing to compare against.
///
/// SMUSD is the one form here that cannot overflow: the difference of two
/// products of halfwords always fits in thirty-two bits, and the manual
/// leaves Q alone for it. The other three set it, the accumulating ones
/// because the third operand can carry the sum out of range.
/// </summary>
let smuldual (ins: Instruction) bld swap isSub =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2, acc) =
      match ins.Operands with
      | FourOperands _ ->
        let struct (d, n, m, a) = transFourOprs ins bld
        struct (d, n, m, AST.sext 64<rt> a)
      | _ ->
        let struct (d, n, m) = transThreeOprs ins bld
        struct (d, n, m, AST.num0 64<rt>)
    let o = tmpVar bld 32<rt>
    let struct (p1, p2, result) = tmpVars3 bld 64<rt>
    let rotated = shiftROR src2 32<rt> 16u
    let xtlo src = AST.xtlo 16<rt> src |> AST.sext 64<rt>
    let xthi src = AST.xthi 16<rt> src |> AST.sext 64<rt>
    if swap then append bld { o := rotated } else append bld { o := src2 }
    p1 := xtlo src1 .* xtlo o
    p2 := xthi src1 .* xthi o
    result := (if isSub then p1 .- p2 else p1 .+ p2) .+ acc
    dst := AST.xtlo 32<rt> result
    let setsQ =
      match ins.Operands with
      | FourOperands _ -> true
      | _ -> not isSub
    if setsQ then
      let cpsr = regVar bld R.CPSR
      let fits = AST.sext 64<rt> (AST.xtlo 32<rt> result)
      append bld {
        cpsr :=
          AST.ite (result != fits) (enablePSRBits bld R.CPSR PSR.Q) cpsr
      }
    else
      ()
    putEndLabel bld lblIgnore
  }

/// <summary>
/// SMMLS, which subtracts the whole product from an accumulator that sits in
/// the top half, and keeps that half.
///
/// The accumulator is shifted up by thirty-two rather than the product being
/// shifted down, so that the bits the subtraction borrows from are still
/// there. The rounding form adds a half of the discarded half before the top
/// is taken, which is what R means throughout this family.
/// </summary>
let smmls (ins: Instruction) bld isRound =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2, src3) = transFourOprs ins bld
    let result = tmpVar bld 64<rt>
    let ra = (AST.sext 64<rt> src3) << numI32 32 64<rt>
    result := ra .- AST.sext 64<rt> src1 .* AST.sext 64<rt> src2
    if isRound then
      append bld { result := result .+ numU32 0x80000000u 64<rt> }
    else
      ()
    dst := AST.xthi 32<rt> result
    putEndLabel bld lblIgnore
  }

/// <summary>
/// SMULWB and SMULWT: a whole word by one halfword, keeping the middle
/// thirty-two bits of the forty-eight the product has.
///
/// It is SMLAWB without the accumulate, and it does not touch Q. The
/// accumulating form can carry the answer out of range and reports that;
/// nothing a word times a halfword produces can leave the thirty-two bits
/// starting at bit sixteen.
/// </summary>
let smulwordbyhalf (ins: Instruction) bld isTop =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let o = tmpVar bld 32<rt>
    let result = tmpVar bld 64<rt>
    let sext src = AST.sext 64<rt> src
    if isTop then append bld { o := AST.xthi 16<rt> src2 |> AST.sext 32<rt> }
    else append bld { o := AST.xtlo 16<rt> src2 |> AST.sext 32<rt> }
    result := sext src1 .* sext o
    dst := AST.extract result 32<rt> 16
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
    result := sext src1 .* sext o .+ (sext src3 << numI32 16 64<rt>)
    dst := AST.extract result 32<rt> 16
    let cpsr = regVar bld R.CPSR
    (* The overflow test compares the arithmetic value of result >> 16 against
       the 32 bits actually stored, so the shift has to be arithmetic: a
       logical one clears the sign of every negative result and reports an
       overflow that did not happen. *)
    cpsr := AST.ite ((result ?>> numI32 16 64<rt>) != sext dst)
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
    if s1top then append bld { t1 := AST.xthi 16<rt> rn |> AST.sext 32<rt> }
    else append bld { t1 := AST.xtlo 16<rt> rn |> AST.sext 32<rt> }
    if s2top then append bld { t2 := AST.xthi 16<rt> rm |> AST.sext 32<rt> }
    else append bld { t2 := AST.xtlo 16<rt> rm |> AST.sext 32<rt> }
    (* A8-621: the accumulation is a mathematical sum, and Q is set when it
       does not fit the 32 bits actually written. The product of two
       sign-extended halfwords is exact at 32 bits, so only the accumulate
       can overflow -- which is why doing the whole thing at 32 bits looks
       right and silently drops the flag. smulaccwordbyhalf next door already
       does the 64-bit comparison. *)
    let result = tmpVar bld 64<rt>
    result := AST.sext 64<rt> (t1 .* t2) .+ AST.sext 64<rt> ra
    rd := AST.xtlo 32<rt> result
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite (result != AST.sext 64<rt> (AST.xtlo 32<rt> result))
                    (enablePSRBits bld R.CPSR PSR.Q)
                    cpsr
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
        regVar bld reg := loadNative bld 32<rt> addr
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
      loadNative bld 32<rt> addr |> loadWritePC bld isUnconditional
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
      loadNative bld 32<rt> addr |> loadWritePC bld isUnconditional
    else
      ()
    putEndLabel bld lblIgnore
  }

let getOffAddrWithExpr s r e = if s = Some Plus then r .+ e else r .- e

/// The address an immediate offset names. An offset with no sign is one an
/// encoding only ever adds (T32's LDRT family, LDREX and STREX).
let getOffAddrWithImm s r imm =
  match s, imm with
  | (Some Plus | None), Some i -> r .+ (numI64 i 32<rt>)
  | Some Minus, Some i -> r .- (numI64 i 32<rt>)
  | _, None -> r

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
      data := loadNative bld size taddr |> ext 32<rt>
      basereg := twriteback
    | Some(basereg, None) ->
      let taddr = tmpVar bld 32<rt>
      taddr := addr
      data := loadNative bld size taddr |> ext 32<rt>
      basereg := taddr
    | None ->
      data := loadNative bld size addr |> ext 32<rt>
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
      rt := loadNative bld 32<rt> taddr
      rt2 := loadNative bld 32<rt> (taddr .+ n4)
      basereg := twriteback
    | Some(basereg, None) ->
      taddr := addr
      rt := loadNative bld 32<rt> taddr
      rt2 := loadNative bld 32<rt> (taddr .+ n4)
      basereg := taddr
    | None ->
      taddr := addr
      rt := loadNative bld 32<rt> taddr
      rt2 := loadNative bld 32<rt> (taddr .+ n4)
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
    newPcValue := loadNative bld 32<rt> addr
    spsr := loadNative bld 32<rt> (addr .+ numI32 4 32<rt>)
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
      append bld { loadNative bld 32<rt> addr := pcStoreValue bld }
    elif size = 32<rt> then
      append bld { loadNative bld 32<rt> addr := rt }
    else
      append bld { loadNative bld size addr := AST.xtlo size rt }
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
    raw := loadNative bld size taddr
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
    lo := loadNative bld 32<rt> taddr
    hi := loadNative bld 32<rt> (taddr .+ numI32 4 32<rt>)
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
    cur := loadNative bld size taddr
    matched := (taddr == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo size (regVar bld R.ExMonVal))
    loadNative bld size taddr := AST.ite matched (AST.xtlo size rt) cur
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
    cur := loadNative bld 32<rt> taddr
    matched := (taddr == regVar bld R.ExMonAddr)
               .& (cur == regVar bld R.ExMonVal)
    loadNative bld 32<rt> taddr := AST.ite matched rt cur
    loadNative bld 32<rt> (taddr .+ numI32 4 32<rt>) :=
      AST.ite matched rt2 (loadNative bld 32<rt> (taddr .+ numI32 4 32<rt>))
    rd := AST.ite matched (AST.num0 32<rt>) (AST.num1 32<rt>)
    putEndLabel bld lblIgnore
  }

let strd ins bld =
  lift bld ins {
    let struct (rt, rt2, addr, writeback) = parseOprOfLDRD ins bld
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    loadNative bld 32<rt> addr := rt
    loadNative bld 32<rt> (addr .+ (numI32 4 32<rt>)) := rt2
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
          loadNative bld 32<rt> addr := (AST.undef 32<rt> "UNKNOWN")
        }
      else
        append bld {
          loadNative bld 32<rt> addr := ri
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
      loadNative bld 32<rt> addr := pcStoreValue bld
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
    loadNative bld 8<rt> addr |> AST.zext 32<rt>
  | OneOperand(OprMemory(OffsetMode(RegOffset(rn,
                                              None,
                                              rm,
                                              Some(_, Imm i))))) ->
    let rn = regVar bld rn |> convertPCOpr ins bld
    let rm = regVar bld rm |> convertPCOpr ins bld
    let addr = rn .+ (shiftLSL rm 32<rt> i)
    loadNative bld 16<rt> addr |> AST.zext 32<rt>
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
    let field = (rn >> (numI32 lsb 32<rt>)) .& v
    (* No width is excluded. The expression below sign-extends a field of any
       width, one included: at width 1 the msb IS the field, msb - 1 is 0 when
       it is set, and the complement shifted left by the width fills every bit
       above it. The guard that used to exclude width 1 was the whole defect --
       SBFX of a one-bit field came back zero-extended. The sign is read from
       Rn before Rd is written, as the two may be one register. *)
    if signExtend then
      let struct (msb, mask) = tmpVars2 bld 32<rt>
      let msboffset = numI32 (lsb + width - 1) 32<rt>
      let shift = numI32 width 32<rt>
      msb := (rn >> msboffset) .& AST.num1 32<rt>
      mask := (AST.not (msb .- AST.num1 32<rt>)) << shift
      rd := field .| mask
    else
      rd := field
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

let parseOprOfXTA (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprShift(_, Imm i)) ->
    regVar bld rd, regVar bld rn, regVar bld rm, i
  | _ ->
    raise InvalidOperandException

/// <summary>
/// SXTB16 and UXTB16, and the two that accumulate.
///
/// Two bytes are extended into two halfwords at once: the low byte of each
/// halfword of the rotated operand, each landing in the halfword it came out
/// of. The accumulating forms add the first operand's halfwords on top, each
/// to its own, and the two additions do not carry into one another.
/// </summary>
let extendHalves (ins: Instruction) bld extractfn =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rd, rn, rm, rotation) =
      match ins.Operands with
      | FourOperands _ ->
        let rd, rn, rm, rot = parseOprOfXTA ins bld
        struct (rd, rn, rm, rot)
      | _ ->
        let rd, rm, rot = parseOprOfExtend ins bld
        struct (rd, AST.num0 32<rt>, rm, rot)
    let rotated = shiftROR rm 32<rt> rotation
    let lo = AST.xtlo 8<rt> rotated |> extractfn 16<rt>
    let hi = AST.extract rotated 8<rt> 16 |> extractfn 16<rt>
    rd := AST.concat (AST.xthi 16<rt> rn .+ hi) (AST.xtlo 16<rt> rn .+ lo)
    putEndLabel bld lblIgnore
  }

/// <summary>
/// A value clamped into a field of the given width, and whether it had to be.
///
/// The value arrives WIDER than the field, which is the whole point: a clamp
/// asked of a value already narrowed to the field has nothing to catch,
/// because the value has wrapped instead. Both comparisons are signed, for
/// the unsigned form as well -- the manual reads the operand as signed there
/// too, and clamps a negative one to zero rather than to the top.
/// </summary>
let private clampTo bld wide unsigned bits value =
  let maxV =
    if unsigned then numI64 ((1L <<< bits) - 1L) wide
    else numI64 ((1L <<< (bits - 1)) - 1L) wide
  let minV =
    if unsigned then AST.num0 wide else numI64 (-(1L <<< (bits - 1))) wide
  let t = tmpVar bld wide
  append bld {
    t := value
  }
  let tooHigh = t ?> maxV
  let tooLow = t ?< minV
  struct (AST.ite tooHigh maxV (AST.ite tooLow minV t), tooHigh .| tooLow)

/// The operands of a saturating instruction: the destination, the width to
/// clamp to, the source, and the shift the word forms may carry.
let private parseOprOfSat (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprImm n, OprReg rm) ->
    regVar bld rd, int n, regVar bld rm, None
  | FourOperands(OprReg rd, OprImm n, OprReg rm, OprShift(typ, Imm i)) ->
    regVar bld rd, int n, regVar bld rm, Some(typ, i)
  | _ ->
    raise InvalidOperandException

/// <summary>
/// SSAT and USAT: the whole register shifted and then clamped.
///
/// The shift belongs to the instruction and not to the operand, so what is
/// clamped is what the shift produced -- and the shift wraps at thirty-two
/// bits before the clamp sees it, which is what the manual says as
/// SInt(operand). The clamp itself is done wider, because the field is
/// narrower than the register and the value that went out of range has to
/// still be there.
///
/// Q is set where the value was clamped and is never cleared here.
/// </summary>
let satWord (ins: Instruction) bld unsigned =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rd, bits, rm, shf = parseOprOfSat ins bld
    let carry = getCarryFlag bld
    let operand =
      match shf with
      | Some(typ, amount) -> shift rm 32<rt> typ (uint32 amount) carry
      | None -> rm
    let struct (clamped, sat) =
      clampTo bld 64<rt> unsigned bits (AST.sext 64<rt> operand)
    rd := AST.xtlo 32<rt> clamped
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite sat (enablePSRBits bld R.CPSR PSR.Q) cpsr
    putEndLabel bld lblIgnore
  }

/// <summary>
/// SSAT16 and USAT16, which clamp each halfword on its own.
///
/// There is no shift here, and each half is read as a signed halfword before
/// it is clamped. Q is set if either half was clamped.
/// </summary>
let satHalves (ins: Instruction) bld unsigned =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let rd, bits, rm, _ = parseOprOfSat ins bld
    let half e = AST.sext 32<rt> e
    let struct (lo, satLo) =
      clampTo bld 32<rt> unsigned bits (half (AST.xtlo 16<rt> rm))
    let struct (hi, satHi) =
      clampTo bld 32<rt> unsigned bits (half (AST.xthi 16<rt> rm))
    rd := AST.concat (AST.xtlo 16<rt> hi) (AST.xtlo 16<rt> lo)
    let cpsr = regVar bld R.CPSR
    cpsr := AST.ite (satLo .| satHi) (enablePSRBits bld R.CPSR PSR.Q) cpsr
    putEndLabel bld lblIgnore
  }

/// <summary>
/// USAD8 and USADA8: the sum of the four absolute differences of the bytes.
///
/// Each byte is read unsigned and widened before the subtraction, so the
/// difference is a number rather than a wrapped byte, and the magnitude is
/// taken by choosing which way round to subtract. USADA8 adds a fourth
/// register on top; USAD8 is the same instruction with nothing to add.
/// </summary>
let usad8 (ins: Instruction) bld =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rd, rn, rm, acc) =
      match ins.Operands with
      | FourOperands _ ->
        let struct (d, n, m, a) = transFourOprs ins bld
        struct (d, n, m, a)
      | _ ->
        let struct (d, n, m) = transThreeOprs ins bld
        struct (d, n, m, AST.num0 32<rt>)
    let diff i =
      let a = AST.extract rn 8<rt> (i * 8) |> AST.zext 32<rt>
      let b = AST.extract rm 8<rt> (i * 8) |> AST.zext 32<rt>
      AST.ite (a .> b) (a .- b) (b .- a)
    rd := acc .+ diff 0 .+ diff 1 .+ diff 2 .+ diff 3
    putEndLabel bld lblIgnore
  }

/// <summary>
/// SDIV and UDIV.
///
/// A divisor of zero answers zero rather than trapping, which is what the
/// architecture does with integer zero-divide trapping turned off, and what
/// a system running user code has. It is a branch and not a select because a
/// select computes both arms, and the arm that divides by zero is the one
/// that must not run.
///
/// The signed overflow needs the same treatment for the same reason: there
/// is no thirty-two bit answer to the most negative number over minus one,
/// and the architecture answers with the low thirty-two bits of the one it
/// cannot hold.
/// </summary>
let divide (ins: Instruction) bld unsigned =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rd, rn, rm) = transThreeOprs ins bld
    let res = tmpVar bld 32<rt>
    let intMin = numU32 0x80000000u 32<rt>
    let lblSpecial = label bld "NoQuotient"
    let lblDivide = label bld "Divide"
    let lblEnd = label bld "EndDiv"
    let noQuotient =
      if unsigned then rm == AST.num0 32<rt>
      else (rm == AST.num0 32<rt>) .| ((rn == intMin) .& (rm == AST.not
                                                                (AST.num0
                                                                  32<rt>)))
    AST.cjmp noQuotient (AST.jmpDest lblSpecial) (AST.jmpDest lblDivide)
    AST.lmark lblSpecial
    res := AST.ite (rm == AST.num0 32<rt>) (AST.num0 32<rt>) intMin
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblDivide
    res := if unsigned then rn ./ rm else rn ?/ rm
    AST.lmark lblEnd
    rd := res
    putEndLabel bld lblIgnore
  }

/// The base register a swap addresses through, which is the whole of its
/// memory operand: there is no offset and no writeback to read.
let private parseOprOfSwapAddr (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(_, _, OprMemory(OffsetMode(RegOffset(rn, None, _, None)))) ->
    regVar bld rn
  | ThreeOperands(_, _, OprMemory(OffsetMode(ImmOffset(rn, _, _)))) ->
    regVar bld rn
  | _ ->
    raise InvalidOperandException

/// <summary>
/// SWP and SWPB, which read a word or a byte, write another in its place and
/// hand back what was there.
///
/// The old value is latched first because the two registers the instruction
/// names may be the same one, and because the value written must not be the
/// one just read back.
/// </summary>
let swap (ins: Instruction) bld accSz =
  lift bld ins {
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    let struct (rt, rt2, _) = getThreeOprs ins
    let rt = transOpr ins bld rt
    let rt2 = transOpr ins bld rt2
    let address = tmpVar bld 32<rt>
    let old = tmpVar bld accSz
    address := parseOprOfSwapAddr ins bld
    old := loadNative bld accSz address
    loadNative bld accSz address := AST.xtlo accSz rt2
    rt := AST.zext 32<rt> old
    putEndLabel bld lblIgnore
  }

let extendAndAdd (ins: Instruction) bld extractfn amount =
  lift bld ins {
    let rd, rn, rm, rotation = parseOprOfXTA ins bld
    let rotated = shiftROR rm 32<rt> rotation
    let isUnconditional = ParseUtils.isUnconditional ins.Condition
    let lblIgnore = checkCondition ins bld isUnconditional
    rd := rn .+ extractfn 32<rt> (AST.xtlo amount rotated)
    putEndLabel bld lblIgnore
  }
