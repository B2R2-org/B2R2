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

module internal B2R2.FrontEnd.MIPS.LiftingUtils

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS

let inline (:=) dst src =
  match dst with
  | Var(RegisterID = rid) when rid = Register.toRegID Register.R0 ->
    dst := dst (* Prevent setting r0. Our optimizer will remove this anyways. *)
  | _ ->
    dst := src

let transOpr (ins: Instruction) bld = function
  | OpReg reg ->
    regVar bld reg
  | OpImm imm
  | OpShiftAmount imm ->
    numU64 imm bld.RegType
  | OpMem(b, Imm o, sz) ->
    loadNative bld sz (regVar bld b .+ numI64 o bld.RegType)
  | OpMem(b, Reg o, sz) ->
    loadNative bld sz (regVar bld b .+ regVar bld o)
  | OpAddr(Relative o) ->
    numI64 (int64 ins.Address + o) bld.RegType
  | OpAddr(Region idx) ->
    numU64 (JumpTarget.regionTarget ins.Address ins.WordSize idx) bld.RegType
  | GoToLabel _ ->
    raise InvalidOperandException

let inline is32Bit (bld: ILowUIRBuilder) = bld.RegType = 32<rt>

let transOprToFPConvert (ins: Instruction) bld = function
  | OpReg reg ->
    if is32Bit bld then
      regVar bld reg
    else
      match ins.Fmt with
      | Some Fmt.S | Some Fmt.W -> regVar bld reg |> AST.xtlo 32<rt>
      | Some Fmt.D | Some Fmt.L -> regVar bld reg
      | _ -> raise InvalidOperandException
  | _ ->
    raise InvalidOperandException

let transOprToSingleFP bld = function
  | OpReg reg ->
    if is32Bit bld then regVar bld reg else regVar bld reg |> AST.xtlo 32<rt>
  | _ ->
    raise InvalidOperandException

let transTwoSingleFP bld (o1, o2) =
  transOprToSingleFP bld o1, transOprToSingleFP bld o2

let transThreeSingleFP bld (o1, o2, o3) =
  let o1 = transOprToSingleFP bld o1
  let o2 = transOprToSingleFP bld o2
  let o3 = transOprToSingleFP bld o3
  o1, o2, o3

let transFourSingleFP bld (o1, o2, o3, o4) =
  let o1 = transOprToSingleFP bld o1
  let o2 = transOprToSingleFP bld o2
  let o3 = transOprToSingleFP bld o3
  let o4 = transOprToSingleFP bld o4
  o1, o2, o3, o4

let transTwoOprFPConvert ins bld (o1, o2) =
  transOprToFPConvert ins bld o1, transOprToFPConvert ins bld o2

let transOprToFPPair bld = function
  | OpReg reg ->
    if is32Bit bld then
      regVar bld (RegisterHelper.getFPPairReg reg), regVar bld reg
    else
      AST.b0, regVar bld reg
  | _ ->
    raise InvalidOperandException

let transOprToFPPairConcat bld = function
  | OpReg reg ->
    if is32Bit bld then
      AST.concat (regVar bld (RegisterHelper.getFPPairReg reg)) (regVar bld reg)
    else
      regVar bld reg
  | _ ->
    raise InvalidOperandException

/// Commit a double-precision result to its destination.
///
/// On o32 that destination is a PAIR of 32-bit registers, and the value goes
/// through a temporary first because the pair is very often the source as well
/// -- `sqrt.d $f12, $f12` is what a compiler emits for x = sqrt(x). Assigning
/// the low half straight from the result would change what the expression for
/// the high half then reads, and the answer would come back with its low
/// thirty-two bits right and its top ones computed from a value nobody wrote.
let writeFPResult dstB dstA result bld =
  if is32Bit bld then
    let value = tmpVar bld 64<rt>
    append bld {
      value := result
      dstA := AST.xtlo 32<rt> value
      dstB := AST.xthi 32<rt> value
    }
  else
    append bld { dstA := result }

let private fpneg bld oprSz reg =
  append bld {
    let mask =
      if oprSz = 32<rt> then numU64 0x80000000UL oprSz
      else numU64 0x8000000000000000UL oprSz
    reg := reg <+> mask
  }

let transOprToImm = function
  | OpImm imm
  | OpShiftAmount imm -> imm
  | _ -> raise InvalidOperandException

let transOprToImmToInt = function
  | OpImm imm
  | OpShiftAmount imm -> int imm
  | _ -> raise InvalidOperandException

let transOprToBaseOffset bld = function
  | OpMem(b, Imm o, _) -> regVar bld b .+ numI64 o bld.RegType
  | OpMem(b, Reg o, _) -> regVar bld b .+ regVar bld o
  | _ -> raise InvalidOperandException

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> o1, o2, o3, o4
  | _ -> raise InvalidOperandException

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o -> transOpr ins bld o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) -> transOpr ins bld o1, transOpr ins bld o2
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    o1, o2, o3
  | _ ->
    raise InvalidOperandException

let transFourOprs (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    let o1 = transOpr ins bld o1
    let o2 = transOpr ins bld o2
    let o3 = transOpr ins bld o3
    let o4 = transOpr ins bld o4
    o1, o2, o3, o4
  | _ ->
    raise InvalidOperandException

let transFPConcatTwoOprs bld (o1, o2) =
  transOprToFPPairConcat bld o1, transOprToFPPairConcat bld o2

let transFPConcatThreeOprs bld (o1, o2, o3) =
  let o1 = transOprToFPPairConcat bld o1
  let o2 = transOprToFPPairConcat bld o2
  let o3 = transOprToFPPairConcat bld o3
  o1, o2, o3

/// <summary>
/// The source converted to an integer in whichever direction FCSR.RM names,
/// which is what a bare conversion is: an expression no <c>RoundCtrl</c>
/// encloses rounds by the target's own control register. The four directions
/// the field can name therefore need not be spelled out, nor the conversion
/// built four times over.
/// </summary>
let roundToInt src oprSz = AST.cast CastKind.FloatToSInt oprSz src

let private isSNaN32 signalBit nanCheck =
  nanCheck .& (signalBit == AST.num0 32<rt>)

let private isSNaN64 signalBit nanCheck =
  nanCheck .& (signalBit == AST.num0 64<rt>)

let private isQNaN32 signalBit nanCheck =
  nanCheck .& (signalBit != AST.num0 32<rt>)

let private isQNaN64 signalBit nanCheck =
  nanCheck .& (signalBit != AST.num0 64<rt>)

let isNaN oprSz fullExpo mantissa =
  match oprSz with
  | 32<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa != AST.num0 32<rt>))
  | 64<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa != AST.num0 64<rt>))
  | _ -> Terminator.impossible ()

let private isSNaN oprSz signalBit isNaN =
  match oprSz with
  | 32<rt> -> isSNaN32 signalBit isNaN
  | 64<rt> -> isSNaN64 signalBit isNaN
  | _ -> Terminator.impossible ()

let private isQNaN oprSz signalBit isNaN =
  match oprSz with
  | 32<rt> -> isQNaN32 signalBit isNaN
  | 64<rt> -> isQNaN64 signalBit isNaN
  | _ -> Terminator.impossible ()

let isInfinity oprSz fullExpo mantissa =
  match oprSz with
  | 32<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa == AST.num0 32<rt>))
  | 64<rt> -> AST.xtlo 1<rt> (fullExpo .& (mantissa == AST.num0 64<rt>))
  | _ -> Terminator.impossible ()

let private isZero oprSz baseExpr =
  match oprSz with
  | 32<rt> ->
    let mask = numU32 0x7fffffffu 32<rt>
    AST.eq (baseExpr .& mask) (AST.num0 32<rt>)
  | 64<rt> ->
    let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
    AST.eq (baseExpr .& mask) (AST.num0 64<rt>)
  | _ ->
    Terminator.impossible ()

let transBigEndianCPU (bld: ILowUIRBuilder) opSz =
  match bld.Endianness, opSz with
  | Endian.Little, 32<rt> -> AST.num0 32<rt>
  | Endian.Big, 32<rt> -> numI32 0b11 32<rt>
  | Endian.Little, 64<rt> -> AST.num0 64<rt>
  | Endian.Big, 64<rt> -> numI32 0b111 64<rt>
  | _ -> raise InvalidOperandException

let checkOverflowOnAdd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High == e2High) .& (e1High <+> rHigh)

let checkOverflowOnDadd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 63
  let e2High = AST.extract e2 1<rt> 63
  let rHigh = AST.extract r 1<rt> 63
  (e1High == e2High) .& (e1High <+> rHigh)

let getExponentFull src oprSz =
  if oprSz = 32<rt> then
    ((src >> numI32 23 32<rt>) .& numI32 0xff 32<rt>) == numI32 0xff 32<rt>
  else
    ((src >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>) == numI32 0x7ff 64<rt>

let getMantissa src oprSz =
  if oprSz = 32<rt> then src .& numU32 0x7fffffu 32<rt>
  else src .& numU64 0xfffff_ffffffffUL 64<rt>

let private getSignalBit src oprSz =
  if oprSz = 32<rt> then src .& numU32 (1u <<< 22) 32<rt>
  else src .& numU64 (1UL <<< 51) 64<rt>

/// The NaN a floating-point result normalizes to.
///
/// MIPS in its legacy NaN encoding -- the one this port uses -- answers with a
/// single value wherever an operation is invalid or has met a NaN: 0x7fbfffff
/// at single precision and 0x7ff7ffffffffffff at double. It is that value
/// whatever the operands were, and it is positive, so this is a replacement
/// rather than a propagation: both the payload and the sign of whatever NaN
/// the host arithmetic produced are discarded.
let normalizeNaN oprSz result bld =
  append bld {
    let struct (exponent, isNaNCheck) = tmpVars2 bld 1<rt>
    let mantissa = tmpVar bld oprSz
    let defaultNaN =
      if oprSz = 32<rt> then numU32 0x7fbfffffu 32<rt>
      else numU64 0x7ff7ffffffffffffUL 64<rt>
    mantissa := getMantissa result oprSz
    exponent := getExponentFull result oprSz
    isNaNCheck := isNaN oprSz exponent mantissa
    result := AST.ite isNaNCheck defaultNaN result
  }

let advancePC (bld: LowUIRBuilder) insLen =
  if bld.DelayedBranch = InterJmpKind.NotAJmp then
    (* Do nothing, because IEMark will advance PC. *)
    (bld :> ILowUIRBuilder).Stream.MarkEnd insLen
  else
    let nPC = regVar bld R.NPC
    append bld { AST.interjmp nPC bld.DelayedBranch }
    bld.DelayedBranch <- InterJmpKind.NotAJmp

let updatePCCond (bld: LowUIRBuilder) offset cond kind =
  append bld {
    let lblTrueCase = label bld "TrueCase"
    let lblFalseCase = label bld "FalseCase"
    let lblEnd = label bld "End"
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- kind
    AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase)
    AST.lmark lblTrueCase
    nPC := offset
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblFalseCase
    nPC := pc .+ numI32 8 bld.RegType
    AST.lmark lblEnd
  }

/// A likely branch executes its delay slot only when the branch is taken, and
/// nullifies it otherwise. Nothing in the IR can reach forward and suppress the
/// next instruction, so the not-taken path leaves for PC+8 immediately: the
/// delay slot sits at PC+4 and is stepped over rather than executed, which is
/// what nullification means. The taken path arms the delayed branch exactly as
/// an ordinary branch does, so the slot runs and the transfer follows it.
///
/// This is why the two paths are not symmetric. `updatePCCond` can write NPC on
/// both arms and let the delay slot carry the transfer, because there the slot
/// runs either way; here it must not.
let updatePCCondLikely (bld: LowUIRBuilder) offset cond kind =
  append bld {
    let lblTrueCase = label bld "TrueCase"
    let lblFalseCase = label bld "FalseCase"
    let lblEnd = label bld "End"
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- kind
    AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase)
    AST.lmark lblTrueCase
    nPC := offset
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblFalseCase
    nPC := pc .+ numI32 8 bld.RegType
    AST.interjmp nPC kind
    AST.lmark lblEnd
  }

let updateRAPCCond (bld: LowUIRBuilder) nAddr offset cond kind =
  append bld {
    let lblTrueCase = label bld "TrueCase"
    let lblFalseCase = label bld "FalseCase"
    let lblEnd = label bld "End"
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- kind
    AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase)
    AST.lmark lblTrueCase
    nPC := offset
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblFalseCase
    nPC := nAddr
    AST.lmark lblEnd
  }

let signExtLo64 expr = AST.xtlo 32<rt> expr |> AST.sext 64<rt>

let signExtHi64 expr = AST.xthi 32<rt> expr |> AST.sext 64<rt>

let getMask size = (1L <<< size) - 1L

let shifterLoad fstShf sndShf rRt t1 t2 t3 =
  (sndShf (fstShf rRt t1) t1) .| (fstShf t3 t2)

let shifterStore fstShf sndShf rRt t1 t2 t3 =
  (fstShf (sndShf t3 t2) t2) .| (sndShf rRt t1)

let mul64BitReg src1 src2 bld isSign =
  (* The full 64x64->128 product held in one wide temp, from which HI and LO
     are the high and low halves. The evaluator holds the 128-bit value, so the
     former hand-rolled 32-bit decomposition is unnecessary. *)
  let prod = tmpVar bld 128<rt>
  let ext = if isSign then AST.sext 128<rt> else AST.zext 128<rt>
  append bld {
    prod := ext src1 .* ext src2
  }
  struct (AST.xthi 64<rt> prod, AST.xtlo 64<rt> prod)

/// Provides the `lift` computation expression for MIPS, which closes an
/// instruction by advancing the PC rather than with a plain IEMark: an
/// ordinary instruction ends with an IEMark, and one sitting in the delay slot
/// of an armed branch ends with the transfer that branch deferred. It shadows
/// the one from LiftingUtils, so a lifter in this module gets the MIPS closing
/// without asking for it.
[<Struct>]
type LiftBuilder =
  /// Builder that the statements are emitted into.
  val Bld: ILowUIRBuilder

  /// Address of the instruction being lifted.
  val Address: Addr

  /// Length of the instruction being lifted.
  val InsLen: uint32

  /// Whether the instruction arms the delay slot that follows it.
  val ArmsDelaySlot: bool

  /// Creates a lift builder for the instruction at the given address.
  new(bld, addr, insLen, arms) =
    { Bld = bld
      Address = addr
      InsLen = insLen
      ArmsDelaySlot = arms }

  member inline _.Zero() = ()

  member inline _.Delay([<InlineIfLambda>] f: unit -> unit) = f

  member inline _.Combine((), [<InlineIfLambda>] f: unit -> unit) = f ()

  member inline this.Yield(stmt: Stmt) = this.Bld.Stream.Append stmt

  member inline _.For(xs: seq<'T>, [<InlineIfLambda>] f: 'T -> unit) =
    for x in xs do f x

  member inline _.While([<InlineIfLambda>] cond, [<InlineIfLambda>] body) =
    while cond () do body ()

  member inline this.Run([<InlineIfLambda>] f: unit -> unit) =
    this.Bld.Stream.MarkStart(this.Address, this.InsLen)
    f ()
    if this.ArmsDelaySlot then this.Bld.Stream.MarkEnd this.InsLen
    else advancePC (this.Bld :?> LowUIRBuilder) this.InsLen
    this.Bld

/// Starts lifting an ordinary instruction, closing it by advancing the PC.
let inline lift bld (ins: Instruction) =
  LiftBuilder(bld, ins.Address, ins.Length, false)

/// Starts lifting a branch, which arms the delay slot that follows it. The
/// transfer belongs to that slot, so this one closes with a plain IEMark.
let inline liftTransfer bld (ins: Instruction) =
  LiftBuilder(bld, ins.Address, ins.Length, true)

let sideEffects (ins: Instruction) bld name =
  lift bld ins {
    AST.sideEffect name
  }

/// An instruction that is valid but outside what this lifter models, left to
/// the emulator to report rather than silently mis-executed.
let unsupported ins bld = sideEffects ins bld UnsupportedInstruction
