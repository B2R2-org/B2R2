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
  | OpRegList _
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
      (* On a 64-bit FPU the high half is a FIELD of the one register, not a
         register of its own. AST.b0 stood in for it, which broke both
         directions: MFHC1 read the high half as the constant zero, and MTHC1
         assigned to it -- an assignment to a constant, which AST.assign
         rejects outright. An Extract is both readable and assignable, and
         AST.assign rewrites `Extract(Var, 32, 32) := v` into the
         read-modify-write that MTHC1's own `newdata || olddata` asks for. *)
      AST.xthi 32<rt> (regVar bld reg), regVar bld reg
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

/// Subtract overflows when the operands' signs DIFFER and the result takes
/// the subtrahend's. The add test asks the opposite of its first question,
/// which is the whole difference between the two.
let checkOverflowOnSub e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High <+> e2High) .& (e1High <+> rHigh)

let checkOverflowOnDsub e1 e2 r =
  let e1High = AST.extract e1 1<rt> 63
  let e2High = AST.extract e2 1<rt> 63
  let rHigh = AST.extract r 1<rt> 63
  (e1High <+> e2High) .& (e1High <+> rHigh)

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

/// <summary>
/// The jump a delay slot ends with, where the address it jumps to says which
/// encoding to read there.
///
/// Two jumps with the same target and different kinds, chosen on the bit an
/// instruction address cannot use. Nothing in the words at the target says
/// which encoding they belong to, so the kind is the only way an evaluator
/// following the program can be told -- and the address itself is handed over
/// with that bit cleared, which MD00076 requires: "Bit 0 of PC is loaded with
/// a 0, and no Address exception can occur".
/// </summary>
let interJmpByMode (bld: LowUIRBuilder) target kind =
  append bld {
    let lblCompressed = label bld "ToCompressed"
    let lblWide = label bld "ToMIPS32"
    let addr = target .& AST.not (AST.num1 bld.RegType)
    let compressed = AST.xtlo 1<rt> target
    AST.cjmp compressed (AST.jmpDest lblCompressed) (AST.jmpDest lblWide)
    AST.lmark lblCompressed
    AST.interjmp addr (kind ||| InterJmpKind.SwitchToMicroMIPS)
    AST.lmark lblWide
    AST.interjmp addr (kind ||| InterJmpKind.SwitchToMIPS)
  }

let advancePC (bld: LowUIRBuilder) insLen =
  if bld.DelayedBranch = InterJmpKind.NotAJmp then
    (* Do nothing, because IEMark will advance PC. *)
    (bld :> ILowUIRBuilder).Stream.MarkEnd insLen
  else
    let nPC = regVar bld R.NPC
    if bld.BranchCarriesMode then
      interJmpByMode bld nPC bld.DelayedBranch
    else
      append bld { AST.interjmp nPC bld.DelayedBranch }
    bld.DelayedBranch <- InterJmpKind.NotAJmp
    bld.BranchCarriesMode <- false

/// The Release 6 compact branches. A compact branch has no delay slot:
/// it takes effect at the branch itself, so the not-taken path is the
/// very next instruction rather than the one after a slot, and there is
/// nothing left armed for advancePC to consume. That is the whole of the
/// difference from updatePCCond below, which is why the two share a
/// shape and not a body.
let updatePCCondCompact (bld: LowUIRBuilder) offset cond =
  let pc = regVar bld R.PC
  append bld {
    AST.intercjmp cond offset (pc .+ numI32 4 bld.RegType)
  }

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
///
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

/// <summary>
/// A fused multiply-add: <c>x * y + z</c> with a SINGLE rounding.
///
/// It is one operation and not a multiply followed by an add. The product is
/// kept exact and rounded once with the sum, where a multiply and an add
/// round twice, and the two answers differ whenever the product is not
/// exactly representable -- by a unit in the last place usually, and by far
/// more where the addition cancels. This architecture carries both a fused
/// and an unfused multiply-add, so it is telling the two apart, and writing
/// the fused one as the unfused pair lifts the wrong instruction.
///
/// It goes out as a named call because that is what the IR already offers for
/// an operation of three arguments. The negations ride along as a flag rather
/// than being applied to the operands: a negation flips a sign bit, and
/// flipping a NaN operand's sign before the operation would change which NaN
/// the answer carries. Bit 0 of the flag negates the product and bit 1 the
/// addend.
/// </summary>
let fma sz negProduct negAddend x y z =
  let prodBit = if negProduct then 1UL else 0UL
  let addBit = if negAddend then 2UL else 0UL
  let args = [ x; y; z; numU64 (prodBit ||| addBit) 8<rt> ]
  let name =
    match sz with
    | 32<rt> -> "FMA32"
    | 64<rt> -> "FMA64"
    | _ -> raise InvalidRegTypeException
  AST.app name args sz

/// <summary>
/// The arithmetic an IEEE exception can be raised by.
///
/// Which operation it was decides how the exact answer is recovered, and the
/// divide is the only one of the five that can raise the zero divide.
/// </summary>
type FPArith =
  | FPAdd
  | FPSub
  | FPMul
  | FPDiv
  | FPSqrt

/// The sign bit of a width.
let private signBitOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x80000000u 32<rt>
  else numU64 0x8000000000000000UL 64<rt>

/// Everything below the sign bit, which is the magnitude.
let private magnitudeOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x7fffffffu 32<rt>
  else numU64 0x7fffffff_ffffffffUL 64<rt>

/// The biased exponent as a number, which is zero for a subnormal and for a
/// zero, and all ones for an infinity and for a NaN.
let private biasedExponent oprSz v =
  if oprSz = 32<rt> then (v >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
  else (v >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>

/// The value that exponent holds for an infinity and for a NaN.
let private exponentAllOnes oprSz =
  if oprSz = 32<rt> then numI32 0xff 32<rt> else numI32 0x7ff 64<rt>

/// The leading mantissa bit, which is the one that tells a quiet NaN from a
/// signalling one -- in whichever direction the guest has selected.
let private quietBitOfWidth oprSz =
  if oprSz = 32<rt> then numU32 0x400000u 32<rt>
  else numU64 0x8000000000000UL 64<rt>

/// A NaN by its bits: the exponent all ones and a mantissa that is not zero.
let private fpIsNaN oprSz v =
  (biasedExponent oprSz v == exponentAllOnes oprSz)
  .& (getMantissa v oprSz != AST.num0 oprSz)

/// An infinity by its bits: the same exponent and a mantissa that is zero.
let private fpIsInfinite oprSz v =
  (biasedExponent oprSz v == exponentAllOnes oprSz)
  .& (getMantissa v oprSz == AST.num0 oprSz)

/// Either zero, whose sign this does not ask about.
let private fpIsZero oprSz v =
  (v .& magnitudeOfWidth oprSz) == AST.num0 oprSz

/// <summary>
/// Whether the value is a NaN this guest reads as signalling.
///
/// Which leading mantissa bit means which is not fixed. IEEE-2008 reads a set
/// bit as quiet; MIPS before that release read it the other way round, its
/// default NaN being 0x7fbfffff, whose leading mantissa bit is clear.
///
/// Release 6 settled it: NAN2008 is read-only ONE there, so the question has
/// an answer before the register is read and the bit cannot say otherwise.
/// Earlier releases leave it to the processor, and there FCSR bit 18 is what
/// says which side the guest is on.
/// </summary>
let private fpIsSignalling (bld: ILowUIRBuilder) oprSz v =
  let quiet = (v .& quietBitOfWidth oprSz) != AST.num0 oprSz
  if bld.ISA.MIPSRelease = MIPSRelease.R6 then
    fpIsNaN oprSz v .& AST.not quiet
  else
    let nan2008 =
      (regVar bld R.FCSR .& numU32 0x40000u 32<rt>) != AST.num0 32<rt>
    fpIsNaN oprSz v .& AST.ite nan2008 (AST.not quiet) quiet

/// Two to the six hundredth, and its own square root. A residual that would
/// otherwise be denormal is computed on operands scaled by one of these.
let private scale600 = numU64 0x6570000000000000UL 64<rt>

let private scale300 = numU64 0x52b0000000000000UL 64<rt>

/// <summary>
/// Whether the value sits low enough in the exponent range that an error at
/// its own scale would be denormal.
///
/// The error of a rounded operation is about two to the minus fifty-third of
/// the value the rounding happened at, so it falls below the smallest
/// denormal once that value is within about fifty-three of the bottom. The
/// bottom few binades are what this asks about, with room to spare.
/// </summary>
let private fpIsTiny oprSz v =
  (biasedExponent oprSz v >> numI32 2 oprSz) == AST.num0 oprSz

/// <summary>
/// The exact error of the result, computed in the format the operation was
/// computed in: what added to it gives the answer the operation would have
/// had with no rounding at all.
///
/// The sum uses Knuth's two-sum and the other three a fused multiply-add,
/// both of which are exact by construction. Subtracting is adding the second
/// operand with its sign flipped, and flipping it here rather than before the
/// operation is what keeps a NaN operand's own sign out of the answer.
/// </summary>
let private fpErrorTerm wide op a b r =
  match op with
  | FPAdd | FPSub ->
    let b = if op = FPSub then b <+> signBitOfWidth wide else b
    let bb = AST.fsub r a
    AST.fadd (AST.fsub a (AST.fsub r bb)) (AST.fsub b bb)
  | FPMul ->
    fma wide false true a b r
  | FPDiv ->
    fma wide false true r b a
  | FPSqrt ->
    fma wide false true r r a

/// <summary>
/// The same error, taken on operands scaled up by a power of two.
///
/// Exact is not the same as representable: an error small enough to be
/// denormal is itself rounded, and then it comes back zero and the operation
/// is called exact. Scaling by a power of two is exact, so the error comes
/// back scaled by the same amount -- zero exactly when it was zero.
///
/// Where each operation is scaled is where its error lives. A product's and a
/// square root's error is at the scale of the ANSWER; a quotient's is at the
/// scale of the DIVIDEND, because it is what rounding a over b lost
/// multiplied back by b, so a quotient of perfectly ordinary size can still
/// have an error that no format can hold.
/// </summary>
let private fpScaledErrorTerm wide op a b r =
  match op with
  | FPMul ->
    let scaledR = AST.fmul (AST.fmul r scale600) scale600
    fma wide false true (AST.fmul a scale600) (AST.fmul b scale600) scaledR
  | FPDiv ->
    fma wide false true (AST.fmul r scale600) b (AST.fmul a scale600)
  | FPSqrt ->
    let scaledR = AST.fmul r scale300
    fma wide false true scaledR scaledR (AST.fmul a scale600)
  | _ ->
    fpErrorTerm wide op a b r

/// <summary>
/// The error, at a width that can hold it, and zero exactly when the result
/// is exact -- which is the whole of what Inexact means.
///
/// A single-precision operation is recovered at double precision, where every
/// exact answer it can produce fits and nothing is too small to represent. A
/// double-precision one has no wider format to fall back on, so where its
/// error could be denormal the scaled form is taken instead. The bounds that
/// make the scaling safe hold under exactly that condition: a denormal
/// product has both operands under two to the fifty-fifth unless one of them
/// is zero, which makes the product exact anyway; a denormal dividend leaves
/// a quotient under two to the fifty-fifth; and a square root is small only
/// where its operand is.
/// </summary>
let private fpResidual oprSz op src1 src2 res =
  let wide = if oprSz = 32<rt> then 64<rt> else oprSz
  let up e = AST.cast CastKind.FloatCast wide e
  let a, b, r = up src1, up src2, up res
  let plain = fpErrorTerm wide op a b r
  if wide <> oprSz then
    plain
  else
    let scaled = fpScaledErrorTerm wide op a b r
    let zeroIn = fpIsZero oprSz src1 .| fpIsZero oprSz src2
    match op with
    | FPAdd | FPSub ->
      plain
    | FPMul ->
      AST.ite (fpIsTiny oprSz res .& AST.not zeroIn) scaled plain
    | FPDiv | FPSqrt ->
      AST.ite (fpIsTiny oprSz src1) scaled plain

/// The five exceptions as the bits FCSR keeps them in -- Invalid highest and
/// Inexact lowest -- from one-bit conditions.
let private fpBits invalid divZero overflow underflow inexact =
  (AST.zext 32<rt> invalid << numI32 4 32<rt>)
  .| (AST.zext 32<rt> divZero << numI32 3 32<rt>)
  .| (AST.zext 32<rt> overflow << numI32 2 32<rt>)
  .| (AST.zext 32<rt> underflow << numI32 1 32<rt>)
  .| AST.zext 32<rt> inexact

/// Nothing raised, for the exceptions an operation cannot have.
let private fpNone = AST.num0 1<rt>

/// <summary>
/// The exceptions an arithmetic operation raised, as the five bits FCSR
/// keeps them in: Invalid highest and Inexact lowest.
///
/// Four of the five are read off the operands and the result. Inexact cannot
/// be: it is whether the answer was rounded, which only the exact answer
/// says. It is also what makes a small result an underflow rather than merely
/// small -- a tiny answer that lost nothing did not underflow.
///
/// The square root reads one operand, and its caller passes that one twice.
/// </summary>
let fpRaised bld oprSz op src1 src2 result =
  let struct (invalid, divZero, overflow) = tmpVars3 bld 1<rt>
  let struct (underflow, inexact, special) = tmpVars3 bld 1<rt>
  let struct (exact, finiteIn) = tmpVars2 bld 1<rt>
  let raised = tmpVar bld 32<rt>
  let nanIn = fpIsNaN oprSz src1 .| fpIsNaN oprSz src2
  let infIn = fpIsInfinite oprSz src1 .| fpIsInfinite oprSz src2
  let divZeroCond =
    if op = FPDiv then
      fpIsZero oprSz src2 .& AST.not (fpIsZero oprSz src1) .& finiteIn
    else
      AST.num0 1<rt>
  append bld {
    finiteIn := AST.not (nanIn .| infIn)
    (* A NaN nothing brought in is one the operation manufactured, which is
       what Invalid means: zero over zero, infinity less infinity, the square
       root of a negative. *)
    invalid :=
      fpIsSignalling bld oprSz src1 .| fpIsSignalling bld oprSz src2
      .| (fpIsNaN oprSz result .& AST.not nanIn)
    divZero := divZeroCond
    special := fpIsNaN oprSz result .| invalid .| divZero
    overflow := AST.not special .& finiteIn .& fpIsInfinite oprSz result
    exact :=
      (fpResidual oprSz op src1 src2 result .& magnitudeOfWidth 64<rt>)
      == AST.num0 64<rt>
    (* An infinite operand gives an exact answer -- infinity plus a finite is
       that infinity, and a finite over an infinity is zero -- so only an
       overflow makes an infinite RESULT inexact. *)
    inexact := AST.not special .& finiteIn .& (overflow .| AST.not exact)
    underflow :=
      inexact .& AST.not overflow
      .& (biasedExponent oprSz result == AST.num0 oprSz)
    raised := fpBits invalid divZero overflow underflow inexact
  }
  raised

/// <summary>
/// Records in FCSR the IEEE exceptions an arithmetic operation raised.
///
/// MIPS keeps them three times over. Cause holds what THIS instruction
/// raised and is written whole by every one of them; Enables says which of
/// the five trap; Flags accumulates the ones that did not, until software
/// clears it. An instruction that traps never reaches the next one, so what
/// is modelled here is the untrapped case -- Cause takes everything raised,
/// and Flags takes what is not enabled.
/// </summary>
let fpRecord bld raised =
  let fcsr = regVar bld R.FCSR
  let enabled = (fcsr >> numI32 7 32<rt>) .& numI32 0x1f 32<rt>
  append bld {
    fcsr :=
      (fcsr .& numU32 0xfffc0fffu 32<rt>)
      .| (raised << numI32 12 32<rt>)
      .| ((raised .& AST.not enabled) << numI32 2 32<rt>)
  }

let fpExceptions bld oprSz op src1 src2 result =
  fpRecord bld (fpRaised bld oprSz op src1 src2 result)

/// <summary>
/// What a conversion to an INTEGER raises, which is two of the five and
/// neither of them a rounding of the kind the arithmetic does.
///
/// Invalid is the operand having no integer at all -- a NaN, an infinity, or
/// a magnitude the destination cannot hold -- which the architecture answers
/// with a default result rather than with a number, and which the caller has
/// already worked out to choose that result.
///
/// Inexact is the operand having a fraction for the conversion to discard,
/// and it is asked of the OPERAND rather than of the answer: every rounding
/// leaves an exact integer alone, so which direction the instruction rounds
/// in does not come into it.
/// </summary>
let fpExceptionsToInt bld oprSz src noInteger =
  let struct (invalid, inexact) = tmpVars2 bld 1<rt>
  append bld {
    invalid := noInteger
    inexact :=
      AST.not invalid
      .& (AST.roundToIntegral RoundingMode.TowardZero oprSz src != src)
  }
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)

/// <summary>
/// What a conversion between two FORMATS raises.
///
/// The answer is the operand in another format, so the only thing that can be
/// lost is the rounding into it -- and whether anything was is asked by
/// converting the answer back and seeing whether the operand comes out. A
/// widening conversion always passes that; a narrowing one passes it exactly
/// when it lost nothing, which is what Inexact means.
///
/// Overflow and Underflow go with it: a narrowing that ran out of exponent
/// answers an infinity where the operand was finite, or a denormal where it
/// was not.
/// </summary>
let fpExceptionsConvert bld srcSz dstSz back src result =
  let struct (invalid, overflow, underflow, inexact) = tmpVars4 bld 1<rt>
  let finiteIn = AST.not (fpIsNaN srcSz src .| fpIsInfinite srcSz src)
  append bld {
    invalid :=
      fpIsSignalling bld srcSz src
      .| (fpIsNaN dstSz result .& AST.not (fpIsNaN srcSz src))
    overflow := AST.not invalid .& finiteIn .& fpIsInfinite dstSz result
    inexact :=
      AST.not invalid
      .& (overflow .| (finiteIn .& (back != src)))
    underflow :=
      inexact .& AST.not overflow
      .& (biasedExponent dstSz result == AST.num0 dstSz)
  }
  fpRecord bld (fpBits invalid fpNone overflow underflow inexact)

/// <summary>
/// What a conversion FROM an integer raises, which is Inexact and nothing
/// else.
///
/// An integer is never a NaN and never an infinity, and every one of them is
/// inside the range of both floating formats, so the only thing such a
/// conversion can do is round -- and whether it did is asked by converting
/// the answer back and seeing whether the integer comes out.
/// </summary>
let fpExceptionsFromInt bld src back =
  let inexact = tmpVar bld 1<rt>
  append bld {
    inexact := back != src
  }
  fpRecord bld (fpBits fpNone fpNone fpNone fpNone inexact)

/// <summary>
/// Whether a comparison of these two operands raises Invalid.
///
/// A signalling NaN always does. A quiet one does only where the predicate is
/// one of the signalling half -- the manual gives every condition two
/// spellings for exactly this, one that signals on an unordered comparison
/// and one that does not -- which is what the caller passes here.
/// </summary>
let fpCompareInvalid bld oprSz signalsOnQuiet a b =
  if signalsOnQuiet then fpIsNaN oprSz a .| fpIsNaN oprSz b
  else fpIsSignalling bld oprSz a .| fpIsSignalling bld oprSz b

/// Whether either operand is a NaN this guest reads as signalling, which is
/// the one thing an operation that does not round can still raise.
let fpEitherSignalling bld oprSz a b =
  fpIsSignalling bld oprSz a .| fpIsSignalling bld oprSz b

/// Whether the value was changed by being rounded to an integer, which is
/// what RINT can lose. An operand that is already one loses nothing whichever
/// direction the rounding goes in.
let fpRoundChanged bld oprSz src result =
  AST.not (fpIsNaN oprSz src .| fpIsInfinite oprSz src) .& (result != src)

/// <summary>
/// What a FUSED multiply-add raised.
///
/// It is one operation with one rounding, so it is not the union of a
/// multiply's exceptions and an add's -- an intermediate product that would
/// have overflowed on its own does not overflow here, because there is no
/// intermediate product. What it can lose is the single rounding at the end,
/// and finding out whether it did means the exact value of a times b plus d,
/// which no format holds.
///
/// It is held as a sum of pieces instead. The product is exact as p plus its
/// own error, which a multiply-add recovers; adding d to p is exact as s plus
/// the error Knuth's two-sum gives; and the answer is the rounding of those
/// three together. So the error of the whole is what is left after taking the
/// answer off the largest piece, plus the two small ones -- and s and the
/// answer are within one step of each other, which makes that subtraction
/// exact.
/// </summary>
let fpExceptionsFused bld oprSz negProduct src1 src2 addend result =
  let struct (invalid, overflow, underflow) = tmpVars3 bld 1<rt>
  let struct (inexact, finiteIn) = tmpVars2 bld 1<rt>
  let struct (a, p, pe) = tmpVars3 bld oprSz
  let struct (s, bb, se) = tmpVars3 bld oprSz
  let err = tmpVar bld oprSz
  let b, d = src2, addend
  let anyNaN =
    fpIsNaN oprSz src1 .| fpIsNaN oprSz b .| fpIsNaN oprSz d
  let anyInf =
    fpIsInfinite oprSz src1 .| fpIsInfinite oprSz b .| fpIsInfinite oprSz d
  append bld {
    (* Subtracting the product is asked for by flipping the multiplicand's
       sign, which is safe here because a NaN operand never reaches the
       arithmetic below: everything it decides is gated on there being none. *)
    a :=
      if negProduct then src1 <+> signBitOfWidth oprSz else src1
    finiteIn := AST.not (anyNaN .| anyInf)
    invalid :=
      fpIsSignalling bld oprSz src1 .| fpIsSignalling bld oprSz b
      .| fpIsSignalling bld oprSz d
      .| (fpIsNaN oprSz result .& AST.not anyNaN)
    overflow :=
      AST.not invalid .& finiteIn .& fpIsInfinite oprSz result
    p := AST.fmul a b
    pe := fma oprSz false true a b p
    s := AST.fadd p d
    bb := AST.fsub s p
    se := AST.fadd (AST.fsub p (AST.fsub s bb)) (AST.fsub d bb)
    err := AST.fadd (AST.fadd (AST.fsub s result) se) pe
    inexact :=
      AST.not invalid .& finiteIn
      .& (overflow
          .| ((err .& magnitudeOfWidth oprSz) != AST.num0 oprSz))
    underflow :=
      inexact .& AST.not overflow
      .& (biasedExponent oprSz result == AST.num0 oprSz)
  }
  fpRecord bld (fpBits invalid fpNone overflow underflow inexact)

/// What an operation raises where rounding is all it can lose: Invalid for a
/// signalling operand and Inexact for a result that was rounded. Nothing it
/// answers can overflow or be denormal, so the other three cannot happen.
let fpExceptionsRounded bld invalid inexact =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone inexact)

/// <summary>
/// What an operation raises where the only thing it can raise is Invalid.
///
/// The comparisons are the family: they answer a condition rather than a
/// number, so nothing is rounded and nothing overflows, and the one thing
/// that can go wrong is being asked to order a NaN. A signalling one always
/// signals; a quiet one signals only where the predicate is one of the
/// signalling half, which is what the manual's ordered conditions are.
/// </summary>
let fpExceptionsInvalidOnly bld invalid =
  fpRecord bld (fpBits invalid fpNone fpNone fpNone fpNone)
