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

module internal B2R2.FrontEnd.MIPS.Lifter

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

let transOprToExpr (ins: Instruction) bld = function
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

let inline private is32Bit (bld: ILowUIRBuilder) = bld.RegType = 32<rt>

let private transOprToFPConvert (ins: Instruction) bld = function
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

let private transOprToSingleFP bld = function
  | OpReg reg ->
    if is32Bit bld then regVar bld reg else regVar bld reg |> AST.xtlo 32<rt>
  | _ ->
    raise InvalidOperandException

let private transTwoSingleFP bld (o1, o2) =
  transOprToSingleFP bld o1, transOprToSingleFP bld o2

let private transThreeSingleFP bld (o1, o2, o3) =
  let o1 = transOprToSingleFP bld o1
  let o2 = transOprToSingleFP bld o2
  let o3 = transOprToSingleFP bld o3
  o1, o2, o3

let private transFourSingleFP bld (o1, o2, o3, o4) =
  let o1 = transOprToSingleFP bld o1
  let o2 = transOprToSingleFP bld o2
  let o3 = transOprToSingleFP bld o3
  let o4 = transOprToSingleFP bld o4
  o1, o2, o3, o4

let transTwoOprFPConvert ins bld (o1, o2) =
  transOprToFPConvert ins bld o1, transOprToFPConvert ins bld o2

let private transOprToFPPair bld = function
  | OpReg reg ->
    if is32Bit bld then
      regVar bld (RegisterHelper.getFPPairReg reg), regVar bld reg
    else
      AST.b0, regVar bld reg
  | _ ->
    raise InvalidOperandException

let private transOprToFPPairConcat bld = function
  | OpReg reg ->
    if is32Bit bld then
      AST.concat (regVar bld (RegisterHelper.getFPPairReg reg)) (regVar bld reg)
    else
      regVar bld reg
  | _ ->
    raise InvalidOperandException

let private dstAssignForFP dstB dstA result bld =
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

let transOneOpr ins bld opr = transOprToExpr ins bld opr

let transTwoOprs ins bld (o1, o2) =
  transOprToExpr ins bld o1, transOprToExpr ins bld o2

let transThreeOprs ins bld (o1, o2, o3) =
  let o1 = transOprToExpr ins bld o1
  let o2 = transOprToExpr ins bld o2
  let o3 = transOprToExpr ins bld o3
  o1, o2, o3

let transFourOprs ins bld (o1, o2, o3, o4) =
  let o1 = transOprToExpr ins bld o1
  let o2 = transOprToExpr ins bld o2
  let o3 = transOprToExpr ins bld o3
  let o4 = transOprToExpr ins bld o4
  o1, o2, o3, o4

let private transFPConcatTwoOprs bld (o1, o2) =
  transOprToFPPairConcat bld o1, transOprToFPPairConcat bld o2

let private transFPConcatThreeOprs bld (o1, o2, o3) =
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

let private isNaN oprSz fullExpo mantissa =
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

let private isInfinity oprSz fullExpo mantissa =
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

let private transBigEndianCPU (bld: ILowUIRBuilder) opSz =
  match bld.Endianness, opSz with
  | Endian.Little, 32<rt> -> AST.num0 32<rt>
  | Endian.Big, 32<rt> -> numI32 0b11 32<rt>
  | Endian.Little, 64<rt> -> AST.num0 64<rt>
  | Endian.Big, 64<rt> -> numI32 0b111 64<rt>
  | _ -> raise InvalidOperandException

let checkOverfolwOnAdd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 31
  let e2High = AST.extract e2 1<rt> 31
  let rHigh = AST.extract r 1<rt> 31
  (e1High == e2High) .& (e1High <+> rHigh)

let checkOverfolwOnDadd e1 e2 r =
  let e1High = AST.extract e1 1<rt> 63
  let e2High = AST.extract e2 1<rt> 63
  let rHigh = AST.extract r 1<rt> 63
  (e1High == e2High) .& (e1High <+> rHigh)

let private getExponentFull src oprSz =
  if oprSz = 32<rt> then
    ((src >> numI32 23 32<rt>) .& numI32 0xff 32<rt>) == numI32 0xff 32<rt>
  else
    ((src >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>) == numI32 0x7ff 64<rt>

let private getMantissa src oprSz =
  if oprSz = 32<rt> then src .& numU32 0x7fffffu 32<rt>
  else src .& numU64 0xfffff_ffffffffUL 64<rt>

let private getSignalBit src oprSz =
  if oprSz = 32<rt> then src .& numU32 (1u <<< 22) 32<rt>
  else src .& numU64 (1UL <<< 51) 64<rt>

let private subNormal oprSz src1 src2 result bld =
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

let private normalizeValue oprSz result bld =
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

let private signExtLo64 expr = AST.xtlo 32<rt> expr |> AST.sext 64<rt>

let private signExtHi64 expr = AST.xthi 32<rt> expr |> AST.sext 64<rt>

let private getMask size = (1L <<< size) - 1L

let private shifterLoad fstShf sndShf rRt t1 t2 t3 =
  (sndShf (fstShf rRt t1) t1) .| (fstShf t3 t2)

let private shifterStore fstShf sndShf rRt t1 t2 t3 =
  (fstShf (sndShf t3 t2) t2) .| (sndShf rRt t1)

let private mul64BitReg src1 src2 bld isSign =
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
let inline lift bld (ins: Instruction) insLen =
  LiftBuilder(bld, ins.Address, insLen, false)

/// Starts lifting a branch, which arms the delay slot that follows it. The
/// transfer belongs to that slot, so this one closes with a plain IEMark.
let inline liftTransfer bld (ins: Instruction) insLen =
  LiftBuilder(bld, ins.Address, insLen, true)

let sideEffects (ins: Instruction) insLen bld name =
  lift bld ins insLen {
    AST.sideEffect name
  }

let abs ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let is32Bit = is32Bit bld
    match ins.Fmt with
    | Some Fmt.D when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x7FFFFFFFFFFFFFFFUL 64<rt>
      let res = (AST.concat fsB fsA) .& mask
      dstAssignForFP fdB fdA res bld
    | Some Fmt.PS when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x7FFFFFFFUL 32<rt>
      let resA = fsA .& mask
      let resB = fsB .& mask
      dstAssignForFP fdB fdA (AST.concat resB resA) bld
    | Some Fmt.PS ->
      let fd, fs = transTwoOprs ins bld (fd, fs)
      let mask = numU64 0x7FFFFFFFUL 32<rt>
      let resA = (AST.xtlo 32<rt> fs) .& mask
      let resB = (AST.xthi 32<rt> fs) .& mask
      fd := AST.concat resB resA
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      fd := fs .& numU64 0x7FFFFFFFUL 32<rt>
    | _ ->
      let fd, fs = transTwoOprs ins bld (fd, fs)
      let mask =
        if is32Bit then numU64 0x7FFFFFFFUL 32<rt>
        else numU64 0x7FFFFFFFFFFFFFFFUL 64<rt>
      fd := fs .& mask
  }

let private reDupSrc opr1 opr2 expr1 expr2 tmp1 tmp2 bld =
  append bld {
    if opr1 = opr2 then
      tmp1 := expr1
      tmp2 := tmp1
    else
      tmp1 := expr1
      tmp2 := expr2
  }

let private reDupSrc3 opr1 opr2 opr3 expr1 expr2 expr3 tmp1 tmp2 tmp3 bld =
  append bld {
    if opr1 = opr2 && opr2 = opr3 then
      tmp1 := expr1
      tmp2 := tmp1
      tmp3 := tmp1
    elif opr1 = opr2 then
      tmp1 := expr1
      tmp2 := tmp1
      tmp3 := expr3
    elif opr1 = opr3 then
      tmp1 := expr1
      tmp3 := tmp1
      tmp2 := expr2
    elif opr2 = opr3 then
      tmp2 := expr2
      tmp3 := tmp2
      tmp1 := expr1
    else
      tmp1 := expr1
      tmp2 := expr2
      tmp3 := expr3
  }

let add (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | None ->
      let lblL0 = label bld "L0"
      let lblL1 = label bld "L1"
      let lblEnd = label bld "End"
      let rd, rs, rt = transThreeOprs ins bld (dst, src1, src2)
      let result = if is32Bit bld then rs .+ rt else signExtLo64 (rs .+ rt)
      let cond = checkOverfolwOnAdd rs rt result
      AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
      AST.lmark lblL0
      AST.sideEffect (Exception IntegerOverflow)
      AST.jmp (AST.jmpDest lblEnd)
      AST.lmark lblL1
      rd := result
      AST.lmark lblEnd
    | Some Fmt.S ->
      let fd, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fadd tSrc1 tSrc2
      normalizeValue 32<rt> result bld
      fd := result
    | _ ->
      let fdB, fdA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fadd tSrc1 tSrc2
      normalizeValue 64<rt> result bld
      dstAssignForFP fdB fdA result bld
  }

let addiu ins insLen bld =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    let result = if is32Bit bld then rs .+ imm else signExtLo64 (rs .+ imm)
    rt := result
  }

let addu ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    let result = if is32Bit bld then rs .+ rt else signExtLo64 (rs .+ rt)
    rd := result
  }

let logAnd ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs .& rt
  }

let andi ins insLen bld =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    rt := rs .& imm
  }

let aui ins insLen bld =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    let imm = imm << numI32 16 bld.RegType
    let result = if is32Bit bld then rs .+ imm else signExtLo64 (rs .+ imm)
    rt := result
  }

let b ins insLen (bld: LowUIRBuilder) =
  liftTransfer bld ins insLen {
    let nPC = regVar bld R.NPC
    let offset = getOneOpr ins |> transOneOpr ins bld
    bld.DelayedBranch <- InterJmpKind.Base
    nPC := offset
  }

let bal ins insLen (bld: LowUIRBuilder) =
  liftTransfer bld ins insLen {
    let offset = getOneOpr ins |> transOneOpr ins bld
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    bld.DelayedBranch <- InterJmpKind.IsCall
    regVar bld R.R31 := pc .+ numI32 8 bld.RegType
    nPC := offset
  }

let private fpConditionCode cc bld =
  let fcsr = regVar bld R.FCSR
  if cc = 0 then
    (fcsr .& numU32 0x800000u 32<rt>) == numU32 0x800000u 32<rt>
  else
    let num = numU32 0x1000000u 32<rt> << numI32 cc 32<rt>
    (fcsr .& num) == num

let bc1f (ins: Instruction) insLen bld =
  liftTransfer bld ins insLen {
    match ins.Operands with
    | OneOperand off ->
      let offset = transOneOpr ins bld off
      let cond = AST.not (fpConditionCode 0 bld)
      updatePCCond bld offset cond InterJmpKind.Base
    | _ ->
      let cc, offset = getTwoOprs ins
      let offset = transOprToExpr ins bld offset
      let cc = transOprToImmToInt cc
      let cond = AST.not (fpConditionCode cc bld)
      updatePCCond bld offset cond InterJmpKind.Base
  }

let bc1t (ins: Instruction) insLen bld =
  liftTransfer bld ins insLen {
    match ins.Operands with
    | OneOperand off ->
      let offset = transOneOpr ins bld off
      let cond = fpConditionCode 0 bld
      updatePCCond bld offset cond InterJmpKind.Base
    | _ ->
      let cc, offset = getTwoOprs ins
      let offset = transOprToExpr ins bld offset
      let cc = transOprToImmToInt cc
      let cond = fpConditionCode cc bld
      updatePCCond bld offset cond InterJmpKind.Base
  }

let beq ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, rt, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs == rt
    updatePCCond bld offset cond InterJmpKind.Base
  }

let blez ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
    let cond = AST.sle rs (AST.num0 bld.RegType)
    updatePCCond bld offset cond InterJmpKind.Base
  }

let bltz ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
    let cond = AST.slt rs (AST.num0 bld.RegType)
    updatePCCond bld offset cond InterJmpKind.Base
  }

let bltzal ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
    let pc = regVar bld R.PC
    let nAddr = tmpVar bld bld.RegType
    let cond = AST.slt rs (AST.num0 bld.RegType)
    nAddr := pc .+ numI32 8 bld.RegType
    regVar bld R.R31 := nAddr
    updateRAPCCond bld nAddr offset cond InterJmpKind.IsCall
  }

let bgez ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
    let cond = AST.sge rs (AST.num0 bld.RegType)
    updatePCCond bld offset cond InterJmpKind.Base
  }

let bgezal ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
    let pc = regVar bld R.PC
    let nAddr = tmpVar bld bld.RegType
    let cond = AST.sge rs (AST.num0 bld.RegType)
    nAddr := pc .+ numI32 8 bld.RegType
    regVar bld R.R31 := nAddr
    updateRAPCCond bld nAddr offset cond InterJmpKind.IsCall
  }

let bgtz ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
    let cond = AST.sgt rs (AST.num0 bld.RegType)
    updatePCCond bld offset cond InterJmpKind.Base
  }

let bne ins insLen bld =
  liftTransfer bld ins insLen {
    let rs, rt, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs != rt
    updatePCCond bld offset cond InterJmpKind.Base
  }

let setFPConditionCode bld cc tf =
  append bld {
    let insertBit = AST.xtlo 32<rt> tf
    let fcsr = regVar bld R.FCSR
    if cc = 0 then
      let shf1 = numI32 23 32<rt>
      let mask1 = numU32 0xFF000000u 32<rt>
      let mask2 = numU32 0x7FFFFFu 32<rt>
      let insertBit = AST.xtlo 32<rt> tf
      fcsr := (fcsr .& mask1) .| (insertBit << shf1) .| (fcsr .& mask2)
    else
      let shf2 = numI32 (24 + cc) 32<rt>
      let mask1 = numU32 0xFE000000u 32<rt> << numI32 cc 32<rt>
      let mask2 =
        (numU32 0xFFFFFFu 32<rt> << numI32 cc 32<rt>) .| numU32 0xFFu 32<rt>
      fcsr := (fcsr .& mask1) .| (insertBit << shf2) .| (fcsr .& mask2)
  }

let private getCCondOpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(fs, ft) ->
    let sameReg = fs = ft
    match ins.Fmt with
    | Some Fmt.PS | Some Fmt.D ->
      let fs, ft = transFPConcatTwoOprs bld (fs, ft)
      64<rt>, 0, fs, ft, sameReg
    | _ ->
      let fs, ft = transTwoSingleFP bld (fs, ft)
      32<rt>, 0, fs, ft, sameReg
  | ThreeOperands(cc, fs, ft) ->
    let sameReg = fs = ft
    match ins.Fmt with
    | Some Fmt.PS | Some Fmt.D ->
      let cc = transOprToImmToInt cc
      let fs, ft = transFPConcatTwoOprs bld (fs, ft)
      64<rt>, cc, fs, ft, sameReg
    | _ ->
      let cc = transOprToImmToInt cc
      let fs, ft = transTwoSingleFP bld (fs, ft)
      32<rt>, cc, fs, ft, sameReg
  | _ ->
    raise InvalidOperandException

/// Which of the three comparison outcomes the condition asks about: unordered,
/// equal and less, one bit each. A signalling form asks the same question as
/// the quiet form beside it, and differs only in the trap it would raise.
let private conditionBitsOf condition num0 num1 =
  match condition with
  | Some Condition.F | Some Condition.SF -> num0, num0, num0
  | Some Condition.UN | Some Condition.NGLE -> num1, num0, num0
  | Some Condition.EQ | Some Condition.SEQ -> num0, num1, num0
  | Some Condition.UEQ | Some Condition.NGL -> num1, num1, num0
  | Some Condition.OLT | Some Condition.LT -> num0, num0, num1
  | Some Condition.ULT | Some Condition.NGE -> num1, num0, num1
  | Some Condition.OLE | Some Condition.LE -> num0, num1, num1
  | Some Condition.ULE | Some Condition.NGT -> num1, num1, num1
  | _ -> raise InvalidOperandException

let cCond ins insLen bld =
  lift bld ins insLen {
    let oprSz, cc, fs, ft, sameReg = getCCondOpr ins bld
    let num0 = AST.num0 oprSz
    let num1 = AST.num1 oprSz
    let struct (tFs, tFt, mantissa) = tmpVars3 bld oprSz
    let struct (less, equal, unordered, condition) = tmpVars4 bld oprSz
    let struct (condNaN, exponent) = tmpVars2 bld 1<rt>
    let bit0, bit1, bit2 = conditionBitsOf ins.Condition num0 num1
    if sameReg then
      tFs := fs
      tFt := tFs
    else
      tFs := fs
      tFt := ft
    let zeroSameCondWithEqaul =
      if sameReg then AST.b1
      else ((tFs << num1) >> num1) == ((tFt << num1) >> num1)
    condNaN :=
      if sameReg then
        append bld {
          mantissa := getMantissa tFt oprSz
          exponent := getExponentFull tFt oprSz
        }
        AST.xtlo 1<rt> (exponent .& (mantissa != AST.num0 oprSz))
      else
        let src1Mantissa = getMantissa tFs oprSz
        let src2Mantissa = getMantissa tFt oprSz
        let src1Exponent = getExponentFull tFs oprSz
        let src2Exponent = getExponentFull tFt oprSz
        AST.xtlo 1<rt> (src1Exponent .& (src1Mantissa != AST.num0 oprSz)) .|
        AST.xtlo 1<rt> (src2Exponent .& (src2Mantissa != AST.num0 oprSz))
    less := AST.ite condNaN num0 (AST.ite (AST.flt tFs tFt) num1 num0)
    equal :=
      AST.ite condNaN num0 (AST.ite zeroSameCondWithEqaul num1 num0)
    unordered := AST.ite condNaN num1 num0
    condition := (bit2 .& less) .| (bit1 .& equal) .| (bit0 .& unordered)
    setFPConditionCode bld cc condition
  }

let ctc1 ins insLen bld =
  lift bld ins insLen {
    let rt, _ = getTwoOprs ins |> transTwoOprs ins bld
    let fcsr = regVar bld R.FCSR
    fcsr := AST.xtlo 32<rt> rt
  }

let cfc1 ins insLen bld =
  lift bld ins insLen {
    let rt, _ = getTwoOprs ins |> transTwoOprs ins bld
    let fcsr = regVar bld R.FCSR
    rt := AST.sext bld.RegType fcsr
  }

let clz ins insLen bld =
  lift bld ins insLen {
    let lblLoop = label bld "Loop"
    let lblContinue = label bld "Continue"
    let lblEnd = label bld "End"
    let wordSz = bld.RegType
    let rd, rs = getTwoOprs ins |> transTwoOprs ins bld
    (* CLZ counts leading zeros of the 32-bit word, so on a 64-bit machine it
       must look at the low 32 bits only -- zero-extend them so upper bits (e.g.
       a sign-extended negative word) do not skew the scan. *)
    let rs = if is32Bit bld then rs else AST.zext wordSz (AST.xtlo 32<rt> rs)
    let t = tmpVar bld wordSz
    let n31 = numI32 31 wordSz
    t := n31
    AST.lmark lblLoop
    let cond1 = rs >> t == AST.num1 wordSz
    AST.cjmp cond1 (AST.jmpDest lblEnd) (AST.jmpDest lblContinue)
    AST.lmark lblContinue
    t := t .- AST.num1 wordSz
    let cond2 = t == numI32 -1 wordSz
    AST.cjmp cond2 (AST.jmpDest lblEnd) (AST.jmpDest lblLoop)
    AST.lmark lblEnd
    rd := n31 .- t
  }

let cvtd ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let result = tmpVar bld 64<rt>
    match ins.Fmt with
    | Some Fmt.W ->
      let fs = transOprToFPConvert ins bld fs
      result := AST.cast CastKind.SIntToFloat 64<rt> fs
    | Some Fmt.S ->
      let fs = transOprToFPConvert ins bld fs
      result := AST.cast CastKind.FloatCast 64<rt> fs
    | _ ->
      let fs = transOprToFPPairConcat bld fs
      result := AST.cast CastKind.SIntToFloat 64<rt> fs
    normalizeValue 64<rt> result bld
    dstAssignForFP fdB fdA result bld
  }

let cvtw ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let intMax = numI32 0x7fffffff 32<rt>
    let intMin = numI32 0x80000000 32<rt>
    let exponent = tmpVar bld 1<rt>
    let struct (dst, src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let dst, src = transTwoOprFPConvert ins bld (fd, fs)
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        dst, src, inf, nan
      | _ ->
        let dst = transOprToFPConvert ins bld fd
        let src = transOprToFPPairConcat bld fs
        append bld {
          exponent := getExponentFull src 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa src 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        dst, src, inf, nan
    dst := roundToInt bld src 32<rt>
    let outOfRange = AST.sgt dst intMax .| AST.slt dst intMin
    dst := AST.ite (outOfRange .| inf .| nan) intMax dst
  }

let cvtl ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let eval = tmpVar bld 64<rt>
    let exponent = tmpVar bld 1<rt>
    let intMax = numI64 0x7fffffffffffffffL 64<rt>
    let intMin = numI64 0x8000000000000000L 64<rt>
    let struct (src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let src = transOprToFPConvert ins bld fs
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        src, inf, nan
      | _ ->
        let src = transOprToFPPairConcat bld fs
        append bld {
          exponent := getExponentFull src 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa src 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        src, inf, nan
    eval := roundToInt bld src 64<rt>
    let outOfRange = AST.sgt eval intMax .| AST.slt eval intMin
    eval := AST.ite (outOfRange .| inf .| nan) intMax eval
    dstAssignForFP fdB fdA eval bld
  }

let cvts ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let fd = transOprToFPConvert ins bld fd
    let dst = if is32Bit bld then fd else AST.xtlo 32<rt> fd
    let result = tmpVar bld 32<rt>
    match ins.Fmt with
    | Some Fmt.L ->
      let fs = transOprToFPPairConcat bld fs
      result := AST.cast CastKind.SIntToFloat 32<rt> fs
    | Some Fmt.D ->
      let fs = transOprToFPPairConcat bld fs
      result := AST.cast CastKind.FloatCast 32<rt> fs
    | _ ->
      let fs = transOprToFPConvert ins bld fs
      result := AST.cast CastKind.SIntToFloat 32<rt> fs
    normalizeValue 32<rt> result bld
    dst := result
  }

let dadd ins insLen bld =
  lift bld ins insLen {
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    let cond = checkOverfolwOnDadd rs rt (rs .+ rt)
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect (Exception IntegerOverflow)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs .+ rt
    AST.lmark lblEnd
  }

let daddu ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    result := rs .+ rt
    rd := result
  }

let daddiu ins insLen bld =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    result := rs .+ imm
    rt := result
  }

let dclz ins insLen bld =
  lift bld ins insLen {
    let lblLoop = label bld "Loop"
    let lblContinue = label bld "Continue"
    let lblEnd = label bld "End"
    let wordSz = bld.RegType
    let rd, rs = getTwoOprs ins |> transTwoOprs ins bld
    let t = tmpVar bld wordSz
    let n63 = numI32 63 wordSz
    t := n63
    AST.lmark lblLoop
    AST.cjmp (rs >> t == AST.num1 wordSz)
             (AST.jmpDest lblEnd)
             (AST.jmpDest lblContinue)
    AST.lmark lblContinue
    t := t .- AST.num1 wordSz
    AST.cjmp (t == numI64 -1L wordSz)
             (AST.jmpDest lblEnd)
             (AST.jmpDest lblLoop)
    AST.lmark lblEnd
    rd := n63 .- t
  }

let ddiv ins insLen bld =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let struct (q, r) = tmpVars2 bld 64<rt>
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    rt := AST.ite (rt == numI64 0L bld.RegType)
                  (AST.undef bld.RegType "UNPREDICTABLE")
                  rt
    q := AST.sdiv rs rt
    r := AST.smod rs rt
    lo := q
    hi := r
  }

let dmfc1 ins insLen bld =
  lift bld ins insLen {
    let rt, fs = getTwoOprs ins
    let rt = transOprToExpr ins bld rt
    let fs = transOprToFPPairConcat bld fs
    rt := fs
  }

let dmtc1 ins insLen bld =
  lift bld ins insLen {
    let rt, fs = getTwoOprs ins
    let rt = transOprToExpr ins bld rt
    let fsB, fsA = transOprToFPPair bld fs
    dstAssignForFP fsB fsA rt bld
  }

let ddivu ins insLen bld =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let struct (q, r) = tmpVars2 bld 64<rt>
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    q := AST.div rs rt
    r := AST.(mod) rs rt
    lo := q
    hi := r
  }

let checkDEXTPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 0 < size
    && size <= 32
    && 0 < posSize
    && posSize <= 63 then ()
  else raise InvalidOperandException

let dext ins insLen bld =
  lift bld ins insLen {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOprToExpr ins bld rt
    let rs = transOprToExpr ins bld rs
    let pos = transOprToImm pos |> int
    let size = transOprToImm size |> int
    checkDEXTPosSize pos size
    let mask = numI64 (getMask size) bld.RegType
    let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
    rt := mask .& rs |> AST.zext 64<rt>
  }

let checkDEXTMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 32 < size
    && size <= 64
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDEXTUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos
    && pos < 64
    && 0 < size
    && size <= 32
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let dextx ins insLen posSizeCheckFn bld =
  lift bld ins insLen {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOprToExpr ins bld rt
    let rs = transOprToExpr ins bld rs
    let pos = transOprToImm pos |> int
    let sz = transOprToImm size |> int
    posSizeCheckFn pos sz
    if sz = 64 then
      if rt = rs then () else append bld { rt := rs }
    else
      let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
      let result = rs .& numI64 (getMask sz) bld.RegType
      rt := result
  }

let checkINSorExtPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 0 < size
    && size <= 32
    && 0 < posSize
    && posSize <= 32 then ()
  else raise InvalidOperandException

let dins ins insLen bld =
  lift bld ins insLen {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOprToExpr ins bld rt
    let rs = transOprToExpr ins bld rs
    let pos = int32 (transOprToImm pos)
    let size = int32 (transOprToImm size)
    checkINSorExtPosSize pos size
    if pos = 0 && rt = rs then
      ()
    else
      let posExpr = numI32 pos bld.RegType
      let mask = numI64 (getMask size) bld.RegType
      let rs', rt' =
        if pos = 0 then rs .& mask, rt .& (AST.not mask)
        else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
      rt := rt' .| rs'
  }

let checkDINSMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos
    && pos < 32
    && 2 < size
    && size <= 64
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDINSUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos
    && pos < 64
    && 1 <= size
    && size <= 32
    && 32 < posSize
    && posSize <= 64 then ()
  else raise InvalidOperandException

let dinsx ins insLen posSizeCheckFn bld =
  lift bld ins insLen {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOprToExpr ins bld rt
    let rs = transOprToExpr ins bld rs
    let pos = int32 (transOprToImm pos)
    let size = int32 (transOprToImm size)
    posSizeCheckFn pos size
    if size = 64 then
      if rt = rs then () else append bld { rt := rs }
    else
      let posExpr = numI32 pos bld.RegType
      let mask = numI64 (getMask size) bld.RegType
      let rs', rt' =
        if pos = 0 then rs .& mask, rt .& (AST.not mask)
        else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
      rt := rt' .| rs'
  }

let div (ins: Instruction) insLen bld =
  lift bld ins insLen {
    match ins.Fmt with
    | None ->
      let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
      let hi = regVar bld R.HI
      let lo = regVar bld R.LO
      rt := AST.ite (rt == numI64 0L bld.RegType)
                    (AST.undef bld.RegType "UNPREDICTABLE")
                    rt
      if is32Bit bld then
        lo :=
          (AST.sext 64<rt> rs ?/ AST.sext 64<rt> rt) |> AST.xtlo 32<rt>
        hi :=
          (AST.sext 64<rt> rs ?% AST.sext 64<rt> rt) |> AST.xtlo 32<rt>
      else
        lo := signExtLo64 (signExtLo64 rs ?/ signExtLo64 rt)
        hi := signExtLo64 (signExtLo64 rs ?% signExtLo64 rt)
    | Some Fmt.D ->
      let fd, fs, ft = getThreeOprs ins
      let fdB, fdA = transOprToFPPair bld fd
      let src1, src2 = transFPConcatTwoOprs bld (fs, ft)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc fs ft src1 src2 tSrc1 tSrc2 bld
      result := AST.fdiv tSrc1 tSrc2
      divNormal 64<rt> tSrc1 tSrc2 result bld
      dstAssignForFP fdB fdA result bld
    | _ ->
      let fd, fs, ft = getThreeOprs ins
      let dst, src1, src2 = transThreeSingleFP bld (fd, fs, ft)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc fs ft src1 src2 tSrc1 tSrc2 bld
      result := AST.fdiv tSrc1 tSrc2
      divNormal 32<rt> tSrc1 tSrc2 result bld
      dst := result
  }

let divu ins insLen bld =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    rt := AST.ite (rt == numI64 0L bld.RegType)
                  (AST.undef bld.RegType "UNPREDICTABLE")
                  rt
    if is32Bit bld then
      let struct (extendRs, extendRt) = tmpVars2 bld 64<rt>
      extendRs := AST.zext 64<rt> rs
      extendRt := AST.zext 64<rt> rt
      lo := (extendRs ./ extendRt) |> AST.xtlo 32<rt>
      hi := (extendRs .% extendRt) |> AST.xtlo 32<rt>
    else
      let struct (maskRs, maskRt) = tmpVars2 bld 64<rt>
      let mask = numI64 0xFFFFFFFFL 64<rt>
      maskRs := rs .& mask
      maskRt := rt .& mask
      lo := signExtLo64 (maskRs ./ maskRt)
      hi := signExtLo64 (maskRs .% maskRt)
  }

let dmul ins insLen bld isSign =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let struct (high, low) = mul64BitReg rs rt bld isSign
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    lo := low
    hi := high
  }

let drotr ins insLen bld =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins
    let rd, rt = transTwoOprs ins bld (rd, rt)
    let sa = numU64 (transOprToImm sa) 64<rt>
    let size = numI32 64 64<rt>
    rd := (rt << (size .- sa)) .| (rt >> sa)
  }

let drotr32 ins insLen bld =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins
    let rd, rt = transTwoOprs ins bld (rd, rt)
    let sa = numU64 (transOprToImm sa) 64<rt> .+ numI32 32 64<rt>
    let size = numI32 64 64<rt>
    rd := (rt << (size .- sa)) .| (rt >> sa)
  }

let drotrv ins insLen bld =
  lift bld ins insLen {
    let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
    let sa = tmpVar bld 64<rt>
    let size = numI32 64 64<rt>
    sa := rs .& numI32 0x3F 64<rt>
    rd := (rt << (size .- sa)) .| (rt >> sa)
  }

let dsra ins insLen bld =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
    rd := rt ?>> sa |> AST.sext 64<rt>
  }

let dsrav ins insLen bld =
  lift bld ins insLen {
    let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
    rd := rt ?>> (rs .& numI32 63 64<rt>) |> AST.sext 64<rt>
  }

let dsra32 ins insLen bld =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
    let sa = sa .+ numI32 32 64<rt>
    rd := rt ?>> sa |> AST.sext 64<rt>
  }

let dShiftLeftRight32 ins insLen bld shf =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
    let sa = sa .+ numI32 32 64<rt>
    rd := shf rt sa |> AST.zext 64<rt>
  }

let dShiftLeftRight ins insLen bld shf =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
    rd := shf rt sa |> AST.zext 64<rt>
  }

let dShiftLeftRightVar ins insLen bld shf =
  lift bld ins insLen {
    let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
    rd := shf rt (rs .& numI32 63 64<rt>) |> AST.zext 64<rt>
  }

let dsubu ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    let result = tmpVar bld 64<rt>
    result := rs .- rt
    rd := result
  }

let insert ins insLen bld =
  lift bld ins insLen {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOprToExpr ins bld rt
    let rs = transOprToExpr ins bld rs
    let pos = transOprToImm pos |> int
    let size = transOprToImm size |> int
    let msb = pos + size - 1
    let lsb = pos
    checkINSorExtPosSize pos size
    if lsb > msb then raise InvalidOperandException else ()
    let mask = numI64 (getMask size) bld.RegType
    let posExpr = numI32 pos bld.RegType
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    rt := rt' .| rs'
  }

let getJALROprs (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand opr ->
    struct (regVar bld R.R31, transOprToExpr ins bld opr)
  | TwoOperands(o1, o2) ->
    struct (transOprToExpr ins bld o1, transOprToExpr ins bld o2)
  | _ ->
    raise InvalidOperandException

let j ins insLen (bld: LowUIRBuilder) =
  liftTransfer bld ins insLen {
    let nPC = regVar bld R.NPC
    let dest = getOneOpr ins |> transOprToExpr ins bld
    bld.DelayedBranch <- InterJmpKind.Base
    nPC := dest
  }

let jal ins insLen (bld: LowUIRBuilder) =
  liftTransfer bld ins insLen {
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    let lr = regVar bld R.R31
    let dest = getOneOpr ins |> transOprToExpr ins bld
    bld.DelayedBranch <- InterJmpKind.IsCall
    lr := pc .+ numI32 8 bld.RegType
    nPC := dest
  }

let jalr ins insLen (bld: LowUIRBuilder) =
  liftTransfer bld ins insLen {
    let pc = regVar bld R.PC
    let nPC = regVar bld R.NPC
    let struct (lr, rs) = getJALROprs ins bld
    bld.DelayedBranch <- InterJmpKind.IsCall
    lr := pc .+ numI32 8 bld.RegType
    nPC := rs
  }

let jr ins insLen (bld: LowUIRBuilder) =
  liftTransfer bld ins insLen {
    let nPC = regVar bld R.NPC
    let rs = getOneOpr ins |> transOneOpr ins bld
    bld.DelayedBranch <- InterJmpKind.Base
    nPC := rs
  }

let loadSigned ins insLen bld =
  lift bld ins insLen {
    let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
    rt := AST.sext bld.RegType mem
  }

let loadUnsigned ins insLen bld =
  lift bld ins insLen {
    let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
    rt := AST.zext bld.RegType mem
  }

let readHWR ins insLen bld =
  lift bld ins insLen {
    let rtOpr, rdOpr, _ = getThreeOprs ins
    let rt = transOprToExpr ins bld rtOpr
    let value =
      match rdOpr with
      | OpReg R.R29 -> regVar bld R.ULR      (* HWR 29: TLS pointer *)
      | OpReg R.R3 -> numI32 1 bld.RegType   (* CCRes: nonzero resolution *)
      | _ -> numI32 0 bld.RegType            (* CPUNum, SYNCI_Step, CC *)
    rt := value
  }

let loadLinked ins insLen bld =
  lift bld ins insLen {
    let rtOpr, memOpr = getTwoOprs ins
    let rt = transOprToExpr ins bld rtOpr
    let mem = transOprToExpr ins bld memOpr
    let addr = transOprToBaseOffset bld memOpr
    let sz = match memOpr with
             | OpMem(_, _, sz) -> sz
             | _ -> raise InvalidOperandException
    let v = tmpVar bld sz
    v := mem
    regVar bld R.ExMonAddr := addr
    regVar bld R.ExMonVal := AST.zext bld.RegType v
    rt := AST.sext bld.RegType v
  }

let sldc1 ins insLen bld stORld =
  lift bld ins insLen {
    let ft, mem = getTwoOprs ins
    let ftB, ftA = transOprToFPPair bld ft
    let baseOffset = transOprToBaseOffset bld mem
    let bOff = tmpVar bld bld.RegType
    let memory = tmpVar bld 64<rt>
    bOff := baseOffset
    let loadMem =
      if bld.Endianness = Endian.Little then AST.loadLE 64<rt> bOff
      else AST.loadBE 64<rt> bOff
    memory := loadMem
    if stORld then
      loadMem := if is32Bit bld then AST.concat ftB ftA else ftA
    else
      dstAssignForFP ftB ftA memory bld
  }

let slwc1 ins insLen bld stORld =
  lift bld ins insLen {
    let ft, mem = getTwoOprs ins
    let ft = transOprToSingleFP bld ft
    let mem = transOprToExpr ins bld mem
    let ft = if is32Bit bld then ft else AST.xtlo 32<rt> ft
    if stORld then append bld { mem := ft } else append bld { ft := mem }
  }

let ext ins insLen bld =
  lift bld ins insLen {
    let rt, rs, pos, size = getFourOprs ins
    let rt = transOprToExpr ins bld rt
    let rs = transOprToExpr ins bld rs
    let pos = transOprToImm pos |> int
    let size = transOprToImm size |> int
    let msbd = size - 1
    let lsb = pos
    checkINSorExtPosSize pos size
    if lsb + msbd > 31 then raise InvalidOperandException else ()
    let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
    rt := rs .& numI64 (getMask size) bld.RegType
  }

let lui ins insLen bld =
  lift bld ins insLen {
    let rt, imm = getTwoOprs ins |> transTwoOprs ins bld
    if is32Bit bld then
      rt := AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>)
    else
      rt := AST.sext 64<rt>
            (AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>))
  }

let mAddSub (ins: Instruction) insLen bld opFn =
  lift bld ins insLen {
    match ins.Fmt with
    | None ->
      let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
      let op = if opFn then AST.add else AST.sub
      let result = tmpVar bld 64<rt>
      let hi = regVar bld R.HI
      let lo = regVar bld R.LO
      if is32Bit bld then
        result :=
          op (AST.concat hi lo) (AST.sext 64<rt> rs .* AST.sext 64<rt> rt)
        hi := AST.xthi 32<rt> result
        lo := AST.xtlo 32<rt> result
      else
        let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
        let rs = AST.sext 64<rt> (AST.xtlo 32<rt> rs)
        let rt = AST.sext 64<rt> (AST.xtlo 32<rt> rt)
        result := op hilo (rs .* rt)
        hi := signExtHi64 result
        lo := signExtLo64 result
    | Some Fmt.PS | Some Fmt.D ->
      let op = if opFn then AST.fadd else AST.fsub
      let fd, fr, fs, ft = getFourOprs ins
      let fdB, fdA = transOprToFPPair bld fd
      let fr, fs, ft = transFPConcatThreeOprs bld (fr, fs, ft)
      let result = op (AST.fmul fs ft) fr
      dstAssignForFP fdB fdA result bld
    | _ ->
      let op = if opFn then AST.fadd else AST.fsub
      let fd, fr, fs, ft = getFourOprs ins |> transFourSingleFP bld
      let result = op (AST.fmul fs ft) fr
      fd := result
  }

let mAdduSubu ins insLen bld opFn =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let result = tmpVar bld 64<rt>
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let op = if opFn then AST.add else AST.sub
    if is32Bit bld then
      result :=
        op (AST.concat hi lo) (AST.zext 64<rt> rs .* AST.zext 64<rt> rt)
      hi := AST.xthi 32<rt> result
      lo := AST.xtlo 32<rt> result
    else
      let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
      let rs = AST.zext 64<rt> (AST.xtlo 32<rt> rs)
      let rt = AST.zext 64<rt> (AST.xtlo 32<rt> rt)
      result := op hilo (rs .* rt)
      hi := AST.xthi 32<rt> result |> AST.zext 64<rt>
      lo := AST.xtlo 32<rt> result |> AST.zext 64<rt>
  }

let mfhi ins insLen bld =
  lift bld ins insLen {
    let rd = getOneOpr ins |> transOneOpr ins bld
    rd := regVar bld R.HI
  }

let mflo ins insLen bld =
  lift bld ins insLen {
    let rd = getOneOpr ins |> transOneOpr ins bld
    rd := regVar bld R.LO
  }

let mfhc1 ins insLen bld =
  lift bld ins insLen {
    let rt, fs = getTwoOprs ins
    let rt = transOprToExpr ins bld rt
    let fsB, _ = transOprToFPPair bld fs
    rt := AST.sext bld.RegType fsB
  }

let mthc1 ins insLen bld =
  lift bld ins insLen {
    let rt, fs = getTwoOprs ins
    let rt = transOprToExpr ins bld rt
    let fsB, _ = transOprToFPPair bld fs
    fsB := AST.xtlo 32<rt> rt
  }

let mthi ins insLen bld =
  lift bld ins insLen {
    let rs = getOneOpr ins |> transOneOpr ins bld
    let hi = regVar bld R.HI
    hi := rs
  }

let mtlo ins insLen bld =
  lift bld ins insLen {
    let rs = getOneOpr ins |> transOneOpr ins bld
    let lo = regVar bld R.LO
    lo := rs
  }

let mfc1 ins insLen bld =
  lift bld ins insLen {
    let rt, fs = getTwoOprs ins
    let rt = transOprToExpr ins bld rt
    let fs = transOprToSingleFP bld fs
    rt := AST.sext bld.RegType fs
  }

let mov ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      fd := fs
    | Some Fmt.D ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let result = tmpVar bld 64<rt>
      result := fs
      dstAssignForFP fdB fdA result bld
    | _ ->
      raise InvalidOperandException
  }

let movt ins insLen bld =
  lift bld ins insLen {
    let dst, src, cc = getThreeOprs ins
    let cc = transOprToImmToInt cc
    let cond = fpConditionCode cc bld
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (dst, src)
      dst := AST.ite cond src dst
    | Some Fmt.D when is32Bit bld ->
      let dstB, dstA = transOprToFPPair bld dst
      let srcB, srcA = transOprToFPPair bld src
      dstB := AST.ite cond srcB dstB
      dstA := AST.ite cond srcA dstA
    | _ ->
      let dst, src = transTwoOprs ins bld (dst, src)
      dst := AST.ite cond src dst
  }

let movf ins insLen bld =
  lift bld ins insLen {
    let dst, src, cc = getThreeOprs ins
    let cc = transOprToImmToInt cc
    let cond = AST.not (fpConditionCode cc bld)
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (dst, src)
      dst := AST.ite cond src dst
    | Some Fmt.D when is32Bit bld ->
      let dstB, dstA = transOprToFPPair bld dst
      let srcB, srcA = transOprToFPPair bld src
      dstB := AST.ite cond srcB dstB
      dstA := AST.ite cond srcA dstA
    | _ ->
      let dst, src = transTwoOprs ins bld (dst, src)
      dst := AST.ite cond src dst
  }

let movzOrn ins insLen bld opFn =
  lift bld ins insLen {
    let dst, src, compare = getThreeOprs ins
    let compare = transOprToExpr ins bld compare
    let cond = opFn compare (AST.num0 bld.RegType)
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (dst, src)
      dst := AST.ite cond src dst
    | Some Fmt.D when is32Bit bld ->
      let dstB, dstA = transOprToFPPair bld dst
      let src = transOprToFPPairConcat bld src
      dstB := AST.ite cond (AST.xthi 32<rt> src) dstB
      dstA := AST.ite cond (AST.xtlo 32<rt> src) dstA
    | _ ->
      let dst, src = transTwoOprs ins bld (dst, src)
      dst := AST.ite cond src dst
  }

let mtc1 ins insLen bld =
  lift bld ins insLen {
    let rt, fs = getTwoOprs ins
    let rt = transOprToExpr ins bld rt
    let fs = transOprToSingleFP bld fs
    fs := AST.xtlo 32<rt> rt
  }

let mul ins insLen bld =
  lift bld ins insLen {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | None ->
      let dst, src1, src2 = transThreeOprs ins bld (dst, src1, src2)
      let hi = regVar bld R.HI
      let lo = regVar bld R.LO
      let result =
        if is32Bit bld then
          (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2) |> AST.xtlo 32<rt>
        else
          signExtLo64 (src1 .* src2)
      dst := result
      hi := AST.undef bld.RegType "UNPREDICTABLE"
      lo := AST.undef bld.RegType "UNPREDICTABLE"
    | Some Fmt.S ->
      let dst, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fmul tSrc1 tSrc2
      normalizeValue 32<rt> result bld
      dst := result
    | Some Fmt.D ->
      let dstB, dstA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fmul tSrc1 tSrc2
      normalizeValue 64<rt> result bld
      dstAssignForFP dstB dstA result bld
    | _ ->
      raise InvalidOperandException
  }

let mult ins insLen bld =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let result = tmpVar bld 64<rt>
    let struct (low, high) =
      if is32Bit bld then
        append bld {
          result := AST.sext 64<rt> rs .* AST.sext 64<rt> rt
        }
        result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
      else
        append bld {
          result := signExtLo64 rs .* signExtLo64 rt
        }
        signExtLo64 result, signExtHi64 result
    lo := low
    hi := high
  }

let multu ins insLen bld =
  lift bld ins insLen {
    let rs, rt = getTwoOprs ins
    let src1, src2 = transTwoOprs ins bld (rs, rt)
    let struct (tRs, tRt) = tmpVars2 bld bld.RegType
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let mask = numI64 0xFFFFFFFFL 64<rt>
    let result = tmpVar bld 64<rt>
    reDupSrc rs rt src1 src2 tRs tRt bld
    let struct (low, high) =
      if is32Bit bld then
        append bld {
          result := AST.zext 64<rt> tRs .* AST.zext 64<rt> tRt
        }
        result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
      else
        append bld {
          result := (tRs .& mask) .* (tRt .& mask)
        }
        signExtLo64 result, signExtHi64 result
    lo := low
    hi := high
  }

let neg ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let is32Bit = is32Bit bld
    match ins.Fmt with
    | Some Fmt.D when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x8000000000000000UL 64<rt>
      let res = (AST.concat fsB fsA) <+> mask
      dstAssignForFP fdB fdA res bld
    | Some Fmt.PS when is32Bit ->
      let fdB, fdA = transOprToFPPair bld fd
      let fsB, fsA = transOprToFPPair bld fs
      let mask = numU64 0x80000000UL 32<rt>
      let resA = fsA <+> mask
      let resB = fsB <+> mask
      dstAssignForFP fdB fdA (AST.concat resB resA) bld
    | Some Fmt.PS ->
      let fd, fs = transTwoOprs ins bld (fd, fs)
      let mask = numU64 0x80000000UL 32<rt>
      let resA = (AST.xtlo 32<rt> fs) <+> mask
      let resB = (AST.xthi 32<rt> fs) <+> mask
      fd := AST.concat resB resA
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      fd := fs <+> numU64 0x80000000UL 32<rt>
    | _ ->
      let fd, fs = transTwoOprs ins bld (fd, fs)
      let mask =
        if bld.RegType = 32<rt> then numU64 0x80000000UL bld.RegType
        else numU64 0x8000000000000000UL bld.RegType
      fd := fs <+> mask
  }

let nmadd ins insLen bld =
  lift bld ins insLen {
    let fd, src1, src2, src3 = getFourOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, fr, fs, ft = transFourSingleFP bld (fd, src1, src2, src3)
      let struct (tSrc1, tSrc2, tSrc3, result) = tmpVars4 bld 32<rt>
      reDupSrc3 src1 src2 src3 fr fs ft tSrc1 tSrc2 tSrc3 bld
      result := numU64 0x80000000UL 32<rt> <+>
        (AST.fadd tSrc1 <| AST.fmul tSrc2 tSrc3)
      normalizeValue 32<rt> result bld
      dst := result
    | Some Fmt.D ->
      let fdB, fdA = transOprToFPPair bld fd
      let fr, fs, ft = transFPConcatThreeOprs bld (src1, src2, src3)
      let struct (tSrc1, tSrc2, tSrc3, result) = tmpVars4 bld 64<rt>
      reDupSrc3 src1 src2 src3 fr fs ft tSrc1 tSrc2 tSrc3 bld
      result := numU64 0x8000000000000000UL 64<rt> <+>
        (AST.fadd tSrc1 <| AST.fmul tSrc2 tSrc3)
      normalizeValue 64<rt> result bld
      dstAssignForFP fdB fdA result bld
    | _ ->
      raise InvalidOperandException
  }

let nop (ins: Instruction) insLen bld =
  lift bld ins insLen {
  }

let nor ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    rd := AST.not (rs .| rt)
  }

let logOr ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs .| rt
  }

let ori ins insLen bld =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    rt := rs .| imm
  }

let rotr ins insLen bld =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins
    let rd, rt = transTwoOprs ins bld (rd, rt)
    let sa = numU64 (transOprToImm sa) 32<rt>
    let size = numI32 32 32<rt>
    if is32Bit bld then
      rd := (rt << (size .- sa)) .| (rt >> sa)
    else
      rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
            (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>
  }

let rotrv ins insLen bld =
  lift bld ins insLen {
    let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
    let sa = tmpVar bld 32<rt>
    let size = numI32 32 32<rt>
    sa := AST.xtlo 32<rt> rs .& numI32 0x1F 32<rt>
    if is32Bit bld then
      rd := (rt << (size .- sa)) .| (rt >> sa)
    else
      rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
            (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>
  }

let store ins insLen width bld =
  lift bld ins insLen {
    let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
    mem := AST.xtlo width rt
  }

let sqrt ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      let cond = fs == numU32 0x80000000u 32<rt>
      fd := AST.ite cond (numU32 0x80000000u 32<rt>) (AST.fsqrt fs)
    | _ ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let cond = fs == numU64 0x8000000000000000UL 64<rt>
      let result =
        AST.ite cond (numU64 0x8000000000000000UL 64<rt>) (AST.fsqrt fs)
      dstAssignForFP fdB fdA result bld
  }

let storeConditional ins insLen width bld =
  lift bld ins insLen {
    let rtOpr, memOpr = getTwoOprs ins
    let rt = transOprToExpr ins bld rtOpr
    let mem = transOprToExpr ins bld memOpr
    let addr = transOprToBaseOffset bld memOpr
    let cur = tmpVar bld width
    let matched = tmpVar bld 1<rt>
    cur := mem
    matched := (addr == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo width (regVar bld R.ExMonVal))
    mem := AST.ite matched (AST.xtlo width rt) cur
    rt := AST.zext bld.RegType matched
  }

let storeLeftRight ins insLen bld memShf regShf amtOp oprSz =
  lift bld ins insLen {
    let rt, mem = getTwoOprs ins
    let baseOffset = transOprToBaseOffset bld mem
    let rt = transOprToExpr ins bld rt
    let rRt, baseOffset =
      if oprSz = 32<rt> then
        if is32Bit bld then rt, baseOffset else AST.xtlo 32<rt> rt, baseOffset
      else
        rt, baseOffset
    let baseOff = tmpVar bld bld.RegType
    let maskLd = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
    let struct (t1, t2, t3) = tmpVars3 bld oprSz
    let baseMask = tmpVar bld bld.RegType
    let mask = numI32 (((int oprSz) >>> 3) - 1) bld.RegType
    let mask32 = numI32 (((int oprSz) >>> 3) - 1) oprSz
    let vaddr0To2 = (baseOff .& mask) <+> (transBigEndianCPU bld bld.RegType)
    let baseAddress =
      if bld.Endianness = Endian.Little then AST.loadLE oprSz baseMask
      else AST.loadBE oprSz baseMask
    baseOff := baseOffset
    baseMask := baseOff .& numI32 maskLd bld.RegType
    t1 := if is32Bit bld then vaddr0To2 else AST.xtlo oprSz vaddr0To2
    t2 := (amtOp (mask32 .- t1) mask32) .* numI32 8 oprSz
    t3 := ((amtOp t1 mask32) .+ AST.num1 oprSz) .* numI32 8 oprSz
    baseAddress := shifterStore memShf regShf rRt t2 t3 baseAddress
  }

let syscall (ins: Instruction) insLen bld =
  lift bld ins insLen {
    AST.sideEffect SysCall
  }

let seb ins insLen bld =
  lift bld ins insLen {
    let rd, rt = getTwoOprs ins |> transTwoOprs ins bld
    rd := AST.sext bld.RegType (AST.extract rt 8<rt> 0)
  }

let seh ins insLen bld =
  lift bld ins insLen {
    let rd, rt = getTwoOprs ins |> transTwoOprs ins bld
    rd := AST.sext bld.RegType (AST.extract rt 16<rt> 0)
  }

let shiftLeftRight ins insLen bld shf =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
    if is32Bit bld then
      rd := shf rt sa
    else
      let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
      rd := shf rt sa |> AST.sext 64<rt>
  }

let sra ins insLen bld =
  lift bld ins insLen {
    let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
    if is32Bit bld then
      rd := rt ?>> sa |> AST.sext 32<rt>
    else
      let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
      rd := rt ?>> sa |> AST.sext 64<rt>
  }

let srav ins insLen bld =
  lift bld ins insLen {
    let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
    let mask = numI32 31 32<rt>
    if is32Bit bld then
      rd := rt ?>> (rs .& mask) |> AST.sext 32<rt>
    else
      let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
      rd := rt ?>> (rs .& mask) |> AST.sext 64<rt>
  }

let shiftLeftRightVar ins insLen bld shf =
  lift bld ins insLen {
    let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
    let mask = numI32 31 32<rt>
    if is32Bit bld then
      rd := shf rt (rs .& mask)
    else
      let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
      rd := shf rt (rs .& mask) |> AST.sext 64<rt>
  }

let sltAndU ins insLen bld amtOp =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    let cond = amtOp rs rt
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rd := rtVal
  }

let sltiAndU ins insLen bld amtOp =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    let cond = amtOp rs imm
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rt := rtVal
  }

let sub ins insLen bld =
  lift bld ins insLen {
    let dst, src1, src2 = getThreeOprs ins
    match ins.Fmt with
    | None ->
      let dst, src1, src2 = transThreeOprs ins bld (dst, src1, src2)
      dst := src1 .- src2
    | Some Fmt.S ->
      let dst, fs, ft = transThreeSingleFP bld (dst, src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fsub tSrc1 tSrc2
      subNormal 32<rt> tSrc1 tSrc2 result bld
      dst := result
    | Some Fmt.D ->
      let dstB, dstA = transOprToFPPair bld dst
      let fs, ft = transFPConcatTwoOprs bld (src1, src2)
      let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
      reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
      result := AST.fsub tSrc1 tSrc2
      subNormal 64<rt> tSrc1 tSrc2 result bld
      dstAssignForFP dstB dstA result bld
    | _ ->
      raise InvalidOperandException
  }

let subu ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    let result = if is32Bit bld then rs .- rt else signExtLo64 (rs .- rt)
    rd := result
  }

let teq ins insLen bld =
  lift bld ins insLen {
    let lblL0 = label bld "L0"
    let lblEnd = label bld "End"
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    AST.cjmp (rs == rt) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
    AST.lmark lblL0
    AST.sideEffect UndefinedInstruction (* FIXME: Trap *)
    AST.lmark lblEnd
  }

let teqi ins insLen bld =
  lift bld ins insLen {
    let lblL0 = label bld "L0"
    let lblEnd = label bld "End"
    let rs, imm = getTwoOprs ins |> transTwoOprs ins bld
    AST.cjmp (rs == imm) (AST.jmpDest lblL0) (AST.jmpDest lblEnd)
    AST.lmark lblL0
    AST.sideEffect UndefinedInstruction
    AST.lmark lblEnd
  }

let truncw ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let intMax = numI32 0x7fffffff 32<rt>
    let intMin = numI32 0x80000000 32<rt>
    let exponent = tmpVar bld 1<rt>
    let dstTmp = tmpVar bld 32<rt>
    let struct (dst, src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let dst, src = transTwoSingleFP bld (fd, fs)
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        dst, src, inf, nan
      | _ ->
        let dst = transOprToSingleFP bld fd
        let src = transOprToFPPairConcat bld fs
        let tSrc = tmpVar bld 64<rt>
        append bld {
          tSrc := src
          exponent := getExponentFull tSrc 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa tSrc 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        dst, tSrc, inf, nan
    dst := AST.cast CastKind.FtoITrunc 32<rt> src
    dstTmp := dst
    let outOfRange = AST.sgt dstTmp intMax .| AST.slt dstTmp intMin
    dst := AST.ite (outOfRange .| inf .| nan) intMax dstTmp
  }

let truncl ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let eval = tmpVar bld 64<rt>
    let exponent = tmpVar bld 1<rt>
    let intMax = numI64 0x7fffffffffffffffL 64<rt>
    let intMin = numI64 0x8000000000000000L 64<rt>
    let struct (src, inf, nan) =
      match ins.Fmt with
      | Some Fmt.S ->
        let src = transOprToSingleFP bld fs
        append bld {
          exponent := getExponentFull src 32<rt>
        }
        let mantissa = tmpVar bld 32<rt>
        append bld {
          mantissa := getMantissa src 32<rt>
        }
        let inf = isInfinity 32<rt> exponent mantissa
        let nan = isNaN 32<rt> exponent mantissa
        src, inf, nan
      | _ ->
        let src = transOprToFPPairConcat bld fs
        append bld {
          exponent := getExponentFull src 64<rt>
        }
        let mantissa = tmpVar bld 64<rt>
        append bld {
          mantissa := getMantissa src 64<rt>
        }
        let inf = isInfinity 64<rt> exponent mantissa
        let nan = isNaN 64<rt> exponent mantissa
        src, inf, nan
    eval := AST.cast CastKind.FtoITrunc 64<rt> src
    let outOfRange = AST.sgt eval intMax .| AST.slt eval intMin
    eval := AST.ite (outOfRange .| inf .| nan) intMax eval
    dstAssignForFP fdB fdA eval bld
  }

let logXor ins insLen bld =
  lift bld ins insLen {
    let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs <+> rt
  }

let wsbh ins insLen bld =
  lift bld ins insLen {
    let dst, src = getTwoOprs ins |> transTwoOprs ins bld
    let rt = AST.xtlo 32<rt> src
    let elements =
      Array.init 4 (fun x -> AST.extract rt 8<rt> ((2 + x) % 4 * 8))
      |> Array.rev
    dst := AST.sext bld.RegType (AST.revConcat elements)
  }

let dsbh ins insLen bld =
  lift bld ins insLen {
    let dst, src = getTwoOprs ins |> transTwoOprs ins bld
    let lo = AST.xtlo 32<rt> src
    let hi = AST.xthi 32<rt> src
    let hiResult =
      Array.init 4 (fun x -> AST.extract hi 8<rt> ((2 + x) % 4 * 8))
      |> Array.rev
    let lowResult =
      Array.init 4 (fun x -> AST.extract lo 8<rt> ((2 + x) % 4 * 8))
      |> Array.rev
    dst := AST.revConcat (Array.append lowResult hiResult)
  }

let dshd ins insLen bld =
  lift bld ins insLen {
    let dst, src = getTwoOprs ins |> transTwoOprs ins bld
    let result =
      Array.init 4 (fun idx -> AST.extract src 16<rt> (idx * 16)) |> Array.rev
    dst := AST.revConcat result
  }

let xori ins insLen bld =
  lift bld ins insLen {
    let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
    rt := rs <+> imm
  }

let loadLeftRight ins insLen bld memShf regShf amtOp oprSz =
  lift bld ins insLen {
    let rt, mem = getTwoOprs ins
    let baseOffset = transOprToBaseOffset bld mem
    let rt = transOprToExpr ins bld rt
    let rRt =
      if oprSz = 32<rt> && not (is32Bit bld) then AST.xtlo 32<rt> rt else rt
    let baseOff = tmpVar bld bld.RegType
    let maskLd = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
    let struct (t1, t2, t3) = tmpVars3 bld oprSz
    let baseMask = tmpVar bld bld.RegType
    let mask = numI32 (((int oprSz) >>> 3) - 1) bld.RegType
    let mask32 = numI32 (((int oprSz) >>> 3) - 1) oprSz
    let vaddr0To2 = (baseOff .& mask) <+> (transBigEndianCPU bld bld.RegType)
    let baseAddress =
      if bld.Endianness = Endian.Little then AST.loadLE oprSz baseMask
      else AST.loadBE oprSz baseMask
    baseOff := baseOffset
    baseMask := baseOff .& numI32 maskLd bld.RegType
    t1 := if is32Bit bld then vaddr0To2 else AST.xtlo oprSz vaddr0To2
    t2 := ((amtOp t1 mask32) .+ AST.num1 oprSz) .* numI32 8 oprSz
    t3 := (amtOp (mask32 .- t1) mask32) .* numI32 8 oprSz
    let result = shifterLoad memShf regShf rRt t2 t3 baseAddress
    rt := if is32Bit bld then result else result |> AST.sext 64<rt>
  }

let recip ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      let fnum = AST.cast CastKind.SIntToFloat 32<rt> (AST.num1 32<rt>)
      fd := AST.fdiv fnum fs
    | _ ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let fnum = AST.cast CastKind.SIntToFloat 64<rt> (AST.num1 64<rt>)
      dstAssignForFP fdB fdA (AST.fdiv fnum fs) bld
  }

let rsqrt ins insLen bld =
  lift bld ins insLen {
    let fd, fs = getTwoOprs ins
    match ins.Fmt with
    | Some Fmt.S ->
      let fd, fs = transTwoSingleFP bld (fd, fs)
      let fnum = AST.cast CastKind.SIntToFloat 32<rt> (AST.num1 32<rt>)
      fd := AST.fdiv fnum (AST.fsqrt fs)
    | _ ->
      let fdB, fdA = transOprToFPPair bld fd
      let fs = transOprToFPPairConcat bld fs
      let fnum = AST.cast CastKind.SIntToFloat 64<rt> (AST.num1 64<rt>)
      let result = AST.fdiv fnum (AST.fsqrt fs)
      dstAssignForFP fdB fdA result bld
  }

let translate (ins: Instruction) insLen (bld: LowUIRBuilder) =
  match ins.Opcode with
  | Op.ABS ->
    abs ins insLen bld
  | Op.ADD ->
    add ins insLen bld
  | Op.ADDIU ->
    addiu ins insLen bld
  | Op.ADDU ->
    addu ins insLen bld
  | Op.AND ->
    logAnd ins insLen bld
  | Op.ANDI ->
    andi ins insLen bld
  | Op.AUI ->
    aui ins insLen bld
  | Op.B ->
    b ins insLen bld
  | Op.BAL ->
    bal ins insLen bld
  | Op.BC1F ->
    bc1f ins insLen bld
  | Op.BC1T ->
    bc1t ins insLen bld
  | Op.BEQ | Op.BEQL ->
    beq ins insLen bld
  | Op.BGEZ ->
    bgez ins insLen bld
  | Op.BGEZAL ->
    bgezal ins insLen bld
  | Op.BGTZ ->
    bgtz ins insLen bld
  | Op.BLEZ ->
    blez ins insLen bld
  | Op.BLTZ ->
    bltz ins insLen bld
  | Op.BLTZAL ->
    bltzal ins insLen bld
  | Op.BNE | Op.BNEL ->
    bne ins insLen bld
  | Op.BREAK ->
    sideEffects ins insLen bld Breakpoint
  | Op.C ->
    cCond ins insLen bld
  | Op.CFC1 ->
    cfc1 ins insLen bld
  | Op.CTC1 ->
    ctc1 ins insLen bld
  | Op.CLZ ->
    clz ins insLen bld
  | Op.CVTD ->
    cvtd ins insLen bld
  | Op.CVTL ->
    cvtl ins insLen bld
  | Op.CVTS ->
    cvts ins insLen bld
  | Op.CVTW ->
    cvtw ins insLen bld
  | Op.DADD ->
    dadd ins insLen bld
  | Op.DADDU ->
    daddu ins insLen bld
  | Op.DADDIU ->
    daddiu ins insLen bld
  | Op.DCLZ ->
    dclz ins insLen bld
  | Op.DDIV ->
    ddiv ins insLen bld
  | Op.DMFC1 ->
    dmfc1 ins insLen bld
  | Op.DMTC1 ->
    dmtc1 ins insLen bld
  | Op.DEXT ->
    dext ins insLen bld
  | Op.DEXTM ->
    dextx ins insLen checkDEXTMPosSize bld
  | Op.DEXTU ->
    dextx ins insLen checkDEXTUPosSize bld
  | Op.DINS ->
    dins ins insLen bld
  | Op.DINSM ->
    dinsx ins insLen checkDINSMPosSize bld
  | Op.DINSU ->
    dinsx ins insLen checkDINSUPosSize bld
  | Op.DIV ->
    div ins insLen bld
  | Op.DIVU ->
    divu ins insLen bld
  | Op.DDIVU ->
    ddivu ins insLen bld
  | Op.DMULT ->
    dmul ins insLen bld true
  | Op.DMULTU ->
    dmul ins insLen bld false
  | Op.DROTR ->
    drotr ins insLen bld
  | Op.DROTR32 ->
    drotr32 ins insLen bld
  | Op.DROTRV ->
    drotrv ins insLen bld
  | Op.DSBH ->
    dsbh ins insLen bld
  | Op.DSHD ->
    dshd ins insLen bld
  | Op.DSLL ->
    dShiftLeftRight ins insLen bld (<<)
  | Op.DSLL32 ->
    dShiftLeftRight32 ins insLen bld (<<)
  | Op.DSLLV ->
    dShiftLeftRightVar ins insLen bld (<<)
  | Op.DSRA ->
    dsra ins insLen bld
  | Op.DSRAV ->
    dsrav ins insLen bld
  | Op.DSRA32 ->
    dsra32 ins insLen bld
  | Op.DSRL ->
    dShiftLeftRight ins insLen bld (>>)
  | Op.DSRL32 ->
    dShiftLeftRight32 ins insLen bld (>>)
  | Op.DSRLV ->
    dShiftLeftRightVar ins insLen bld (>>)
  | Op.DSUBU ->
    dsubu ins insLen bld
  | Op.EHB ->
    nop ins insLen bld
  | Op.EXT ->
    ext ins insLen bld
  | Op.INS ->
    insert ins insLen bld
  | Op.J ->
    j ins insLen bld
  | Op.JAL ->
    jal ins insLen bld
  | Op.JALR | Op.JALRHB ->
    jalr ins insLen bld
  | Op.JR | Op.JRHB ->
    jr ins insLen bld
  | Op.LD | Op.LB | Op.LH | Op.LW ->
    loadSigned ins insLen bld
  | Op.LBU | Op.LHU | Op.LWU ->
    loadUnsigned ins insLen bld
  | Op.LL | Op.LLD ->
    loadLinked ins insLen bld
  | Op.SDC1 | Op.SDXC1 ->
    sldc1 ins insLen bld true
  | Op.LDC1 | Op.LDXC1 ->
    sldc1 ins insLen bld false
  | Op.SWC1 | Op.SWXC1 ->
    slwc1 ins insLen bld true
  | Op.LWC1 | Op.LWXC1 ->
    slwc1 ins insLen bld false
  | Op.LUI ->
    lui ins insLen bld
  | Op.LDL ->
    loadLeftRight ins insLen bld (<<) (>>) (.&) 64<rt>
  | Op.LDR ->
    loadLeftRight ins insLen bld (>>) (<<) (<+>) 64<rt>
  | Op.LWL ->
    loadLeftRight ins insLen bld (<<) (>>) (.&) 32<rt>
  | Op.LWR ->
    loadLeftRight ins insLen bld (>>) (<<) (<+>) 32<rt>
  | Op.MADD ->
    mAddSub ins insLen bld true
  | Op.MADDU ->
    mAdduSubu ins insLen bld true
  | Op.MFHI ->
    mfhi ins insLen bld
  | Op.MFLO ->
    mflo ins insLen bld
  | Op.MFHC1 ->
    mfhc1 ins insLen bld
  | Op.MTHC1 ->
    mthc1 ins insLen bld
  | Op.MTHI ->
    mthi ins insLen bld
  | Op.MTLO ->
    mtlo ins insLen bld
  | Op.MFC1 ->
    mfc1 ins insLen bld
  | Op.MOV ->
    mov ins insLen bld
  | Op.MOVT ->
    movt ins insLen bld
  | Op.MOVF ->
    movf ins insLen bld
  | Op.MOVZ ->
    movzOrn ins insLen bld (==)
  | Op.MOVN ->
    movzOrn ins insLen bld (!=)
  | Op.MSUB ->
    mAddSub ins insLen bld false
  | Op.MSUBU ->
    mAdduSubu ins insLen bld false
  | Op.MTC1 ->
    mtc1 ins insLen bld
  | Op.MUL ->
    mul ins insLen bld
  | Op.MULT ->
    mult ins insLen bld
  | Op.MULTU ->
    multu ins insLen bld
  | Op.NEG ->
    neg ins insLen bld
  | Op.NMADD ->
    nmadd ins insLen bld
  | Op.NOP ->
    nop ins insLen bld
  | Op.NOR ->
    nor ins insLen bld
  | Op.OR ->
    logOr ins insLen bld
  | Op.ORI ->
    ori ins insLen bld
  | Op.PAUSE ->
    nop ins insLen bld
  | Op.PREF | Op.PREFE | Op.PREFX ->
    nop ins insLen bld
  | Op.RDHWR ->
    readHWR ins insLen bld
  | Op.ROTR ->
    rotr ins insLen bld
  | Op.ROTRV ->
    rotrv ins insLen bld
  | Op.RECIP ->
    recip ins insLen bld
  | Op.RSQRT ->
    rsqrt ins insLen bld
  | Op.SLL ->
    shiftLeftRight ins insLen bld (<<)
  | Op.SLLV ->
    shiftLeftRightVar ins insLen bld (<<)
  | Op.SLT ->
    sltAndU ins insLen bld (?<)
  | Op.SLTU ->
    sltAndU ins insLen bld (.<)
  | Op.SLTI ->
    sltiAndU ins insLen bld (?<)
  | Op.SLTIU ->
    sltiAndU ins insLen bld (.<)
  | Op.SSNOP ->
    nop ins insLen bld
  | Op.SB ->
    store ins insLen 8<rt> bld
  | Op.SC ->
    storeConditional ins insLen 32<rt> bld
  | Op.SCD ->
    storeConditional ins insLen 64<rt> bld
  | Op.SD ->
    store ins insLen 64<rt> bld
  | Op.SEB ->
    seb ins insLen bld
  | Op.SEH ->
    seh ins insLen bld
  | Op.SH ->
    store ins insLen 16<rt> bld
  | Op.SQRT ->
    sqrt ins insLen bld
  | Op.SRA ->
    sra ins insLen bld
  | Op.SRAV ->
    srav ins insLen bld
  | Op.SRL ->
    shiftLeftRight ins insLen bld (>>)
  | Op.SRLV ->
    shiftLeftRightVar ins insLen bld (>>)
  | Op.SUB ->
    sub ins insLen bld
  | Op.SUBU ->
    subu ins insLen bld
  | Op.SW ->
    store ins insLen 32<rt> bld
  | Op.SDL ->
    storeLeftRight ins insLen bld (<<) (>>) (.&) 64<rt>
  | Op.SDR ->
    storeLeftRight ins insLen bld (>>) (<<) (<+>) 64<rt>
  | Op.SWL ->
    storeLeftRight ins insLen bld (<<) (>>) (.&) 32<rt>
  | Op.SWR ->
    storeLeftRight ins insLen bld (>>) (<<) (<+>) 32<rt>
  | Op.SYNC | Op.SYNCI ->
    nop ins insLen bld
  | Op.SYSCALL ->
    syscall ins insLen bld
  | Op.TEQ ->
    teq ins insLen bld
  | Op.TEQI ->
    teqi ins insLen bld
  | Op.TRUNCW ->
    truncw ins insLen bld
  | Op.TRUNCL ->
    truncl ins insLen bld
  | Op.XOR ->
    logXor ins insLen bld
  | Op.XORI ->
    xori ins insLen bld
  | Op.WSBH ->
    wsbh ins insLen bld
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL ->
    sideEffects ins insLen bld UnsupportedInstruction
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)
