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
  | Var(_, rid, _, _) when rid = Register.toRegID Register.R0 ->
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
    if bld.Endianness = Endian.Little then
      AST.loadLE sz (regVar bld b .+ numI64 o bld.RegType)
    else
      AST.loadBE sz (regVar bld b .+ numI64 o bld.RegType)
  | OpMem(b, Reg o, sz) ->
    if bld.Endianness = Endian.Little then
      AST.loadLE sz (regVar bld b .+ regVar bld o)
    else
      AST.loadBE sz (regVar bld b .+ regVar bld o)
  | OpAddr(Relative o) ->
    numI64 (int64 ins.Address + o) bld.RegType
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

let writeFPResult dstB dstA result bld =
  append bld {
    if is32Bit bld then
      let srcB = AST.xthi 32<rt> result
      let srcA = AST.xtlo 32<rt> result
      dstA := srcA
      dstB := srcB
    else
      dstA := result
  }

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

let roundToInt bld src oprSz =
  let fcsr = regVar bld R.FCSR
  let rm = fcsr .& (numI32 0b11 32<rt>)
  AST.ite (rm == numI32 0 32<rt>)
    (AST.cast CastKind.FtoIRound oprSz src) // 0 RN
    (AST.ite (rm == numI32 1 32<rt>)
      (AST.cast CastKind.FtoITrunc oprSz src) // 1 RZ
      (AST.ite (rm == numI32 2 32<rt>)
        (AST.cast CastKind.FtoICeil oprSz src) // 2 RP
        (AST.cast CastKind.FtoIFloor oprSz src))) // 3 RM

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

let subNormal oprSz src1 src2 result bld =
  append bld {
    let struct (qNaNBox, sNaNBox, sqNaNBox, exponent) = tmpVars4 bld 1<rt>
    let struct (sign, isNaNCheck) = tmpVars2 bld 1<rt>
    let struct (mantissa, signalBit) = tmpVars2 bld oprSz
    mantissa := getMantissa result oprSz
    exponent := getExponentFull result oprSz
    signalBit := getSignalBit result oprSz
    isNaNCheck := isNaN oprSz exponent mantissa
    qNaNBox := isQNaN oprSz signalBit isNaNCheck
    sNaNBox := isSNaN oprSz signalBit isNaNCheck
    let mantissa1 = getMantissa src1 oprSz
    let mantissa2 = getMantissa src2 oprSz
    let infChk =
      AST.not (isInfinity oprSz (getExponentFull src1 oprSz) mantissa1
      .| isInfinity oprSz (getExponentFull src2 oprSz) mantissa2)
    sign := AST.xthi 1<rt> result .& infChk
    sqNaNBox := qNaNBox .| sNaNBox
    result :=
      AST.ite sqNaNBox (
        let struct (sNaNVal, negSNaNVal, qNaNVal, negQNaNVal) =
          match oprSz with
          | 32<rt> ->
            let sVal = numU32 0x7fffffffu 32<rt>
            let negSVal = numU32 0xffffffffu 32<rt>
            let qVal = numU32 0x7fbfffffu 32<rt>
            let negQVal = numU32 0xffbfffffu 32<rt>
            struct (sVal, negSVal, qVal, negQVal)
          | _ ->
            let sVal = numU64 0x7fffffffffffffffUL 64<rt>
            let negSVal = numU64 0xffffffffffffffffUL 64<rt>
            let qVal = numU64 0x7ff7ffffffffffffUL 64<rt>
            let negQVal = numU64 0xfff7ffffffffffffUL 64<rt>
            struct (sVal, negSVal, qVal, negQVal)
        let qNaNWithSign = AST.ite sign negQNaNVal qNaNVal
        let sNaNWithSign = AST.ite sign negSNaNVal sNaNVal
        AST.ite qNaNBox qNaNWithSign (AST.ite sNaNBox sNaNWithSign result))
        result
  }

let divNormal oprSz src1 src2 result bld =
  append bld {
    let struct (exponent, isNaNCheck, sign) = tmpVars3 bld 1<rt>
    let struct (mantissa, signalBit) = tmpVars2 bld oprSz
    sign := AST.xthi 1<rt> result
    mantissa := getMantissa result oprSz
    signalBit := getSignalBit result oprSz
    exponent := getExponentFull result oprSz
    isNaNCheck := isNaN oprSz exponent mantissa
    let src1Zero = src1 == AST.num0 oprSz
    let src2Zero = src2 == AST.num0 oprSz
    let qNan = isQNaN oprSz signalBit isNaNCheck
    let sNan = isSNaN oprSz signalBit isNaNCheck
    let struct (sNaNVal, negSNaNVal, qNaNVal, negQNaNVal) =
      match oprSz with
      | 32<rt> ->
        let sVal = numU32 0x7fffffffu 32<rt>
        let negSVal = numU32 0xffffffffu 32<rt>
        let qVal = numU32 0x7fbfffffu 32<rt>
        let negQVal = numU32 0xffbfffffu 32<rt>
        struct (sVal, negSVal, qVal, negQVal)
      | _ ->
        let sVal = numU64 0x7fffffffffffffffUL 64<rt>
        let negSVal = numU64 0xffffffffffffffffUL 64<rt>
        let qVal = numU64 0x7ff7ffffffffffffUL 64<rt>
        let negQVal = numU64 0xfff7ffffffffffffUL 64<rt>
        struct (sVal, negSVal, qVal, negQVal)
    let qNaNWithSign = AST.ite sign negQNaNVal qNaNVal
    let sNaNWithSign = AST.ite sign negSNaNVal sNaNVal
    result := AST.ite (src1Zero .& src2Zero)
                qNaNVal
                (AST.ite qNan
                  qNaNWithSign
                  (AST.ite sNan sNaNWithSign result))
  }

/// The signalling and the quiet NaN a width normalizes to, each followed by
/// its negative.
let private nanValuesOf oprSz =
  match oprSz with
  | 32<rt> ->
    let sVal = numU32 0x7fffffffu 32<rt>
    let negSVal = numU32 0xffffffffu 32<rt>
    let qVal = numU32 0x7fbfffffu 32<rt>
    let negQVal = numU32 0xffbfffffu 32<rt>
    struct (sVal, negSVal, qVal, negQVal)
  | _ ->
    let sVal = numU64 0x7fffffffffffffffUL 64<rt>
    let negSVal = numU64 0xffffffffffffffffUL 64<rt>
    let qVal = numU64 0x7ff7ffffffffffffUL 64<rt>
    let negQVal = numU64 0xfff7ffffffffffffUL 64<rt>
    struct (sVal, negSVal, qVal, negQVal)

/// Positive and negative infinity in the same width.
let private infinitiesOf oprSz =
  match oprSz with
  | 32<rt> ->
    struct (numU32 0x7f800000u 32<rt>, numU32 0xff800000u 32<rt>)
  | _ ->
    let p = numU64 0x7ff0000000000000UL 64<rt>
    let m = numU64 0xfff0000000000000UL 64<rt>
    struct (p, m)

let normalizeValue oprSz result bld =
  append bld {
    let struct (qNaNBox, sNaNBox, infBox, exponent) = tmpVars4 bld 1<rt>
    let struct (isNaNCheck, sign) = tmpVars2 bld 1<rt>
    exponent := getExponentFull result oprSz
    let struct (mantissa, signalBit) = tmpVars2 bld oprSz
    mantissa := getMantissa result oprSz
    isNaNCheck := isNaN oprSz exponent mantissa
    signalBit := getSignalBit result oprSz
    qNaNBox := isQNaN oprSz signalBit isNaNCheck
    sNaNBox := isSNaN oprSz signalBit isNaNCheck
    infBox := isInfinity oprSz exponent mantissa
    sign := AST.xthi 1<rt> result
    let condBox = qNaNBox .| sNaNBox .| infBox
    result :=
      AST.ite condBox (
        let struct (sNaNVal, negSNaNVal, qNaNVal, negQNaNVal) =
          nanValuesOf oprSz
        let struct (pInf, mInf) = infinitiesOf oprSz
        let qNanWithSign = AST.ite sign negQNaNVal qNaNVal
        let sNanWithSign = AST.ite sign negSNaNVal sNaNVal
        let infWithSign = AST.ite sign mInf pInf
        AST.ite qNaNBox
          qNanWithSign
          (AST.ite sNaNBox sNanWithSign (AST.ite infBox infWithSign result)))
            result
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
