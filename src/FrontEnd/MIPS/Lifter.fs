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
  | OpReg reg -> regVar bld reg
  | OpImm imm
  | OpShiftAmount imm -> numU64 imm bld.RegType
  | OpMem(b, Imm o, sz) ->
    if bld.Endianness = Endian.Little then
      AST.loadLE sz (regVar bld b .+ numI64 o bld.RegType)
    else AST.loadBE sz (regVar bld b .+ numI64 o bld.RegType)
  | OpMem(b, Reg o, sz) ->
    if bld.Endianness = Endian.Little then
      AST.loadLE sz (regVar bld b .+ regVar bld o)
    else AST.loadBE sz (regVar bld b .+ regVar bld o)
  | OpAddr(Relative o) ->
    numI64 (int64 ins.Address + o) bld.RegType
  | GoToLabel _ -> raise InvalidOperandException

let inline private is32Bit (bld: ILowUIRBuilder) = bld.RegType = 32<rt>

let private transOprToFPConvert (ins: Instruction) bld = function
  | OpReg reg ->
    if is32Bit bld then regVar bld reg
    else
      match ins.Fmt with
      | Some Fmt.S | Some Fmt.W -> regVar bld reg |> AST.xtlo 32<rt>
      | Some Fmt.D | Some Fmt.L -> regVar bld reg
      | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandException

let private transOprToSingleFP bld = function
  | OpReg reg ->
    if is32Bit bld then regVar bld reg
    else regVar bld reg |> AST.xtlo 32<rt>
  | _ -> raise InvalidOperandException

let private transTwoSingleFP bld (o1, o2) =
  transOprToSingleFP bld o1, transOprToSingleFP bld o2

let private transThreeSingleFP bld (o1, o2, o3) =
  transOprToSingleFP bld o1, transOprToSingleFP bld o2,
  transOprToSingleFP bld o3

let private transFourSingleFP bld (o1, o2, o3, o4) =
  transOprToSingleFP bld o1, transOprToSingleFP bld o2,
  transOprToSingleFP bld o3, transOprToSingleFP bld o4

let transTwoOprFPConvert ins bld (o1, o2) =
  transOprToFPConvert ins bld o1, transOprToFPConvert ins bld o2

let private transOprToFPPair bld = function
  | OpReg reg ->
    if is32Bit bld then
      regVar bld (Register.getFPPairReg reg), regVar bld reg
    else AST.b0, regVar bld reg
  | _ -> raise InvalidOperandException

let private transOprToFPPairConcat bld = function
  | OpReg reg ->
    if is32Bit bld then
      AST.concat (regVar bld (Register.getFPPairReg reg)) (regVar bld reg)
    else regVar bld reg
  | _ -> raise InvalidOperandException

let private dstAssignForFP dstB dstA result bld =
  if is32Bit bld then
    let srcB = AST.xthi 32<rt> result
    let srcA = AST.xtlo 32<rt> result
    bld <+ (dstA := srcA)
    bld <+ (dstB := srcB)
  else
    bld <+ (dstA := result)

let private fpneg bld oprSz reg =
  let mask =
    if oprSz = 32<rt> then numU64 0x80000000UL oprSz
    else numU64 0x8000000000000000UL oprSz
  bld <+ (reg := reg <+> mask)

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

let transOneOpr ins bld opr =
  transOprToExpr ins bld opr

let transTwoOprs ins bld (o1, o2) =
  transOprToExpr ins bld o1, transOprToExpr ins bld o2

let transThreeOprs ins bld (o1, o2, o3) =
  transOprToExpr ins bld o1,
  transOprToExpr ins bld o2,
  transOprToExpr ins bld o3

let transFourOprs ins bld (o1, o2, o3, o4) =
  transOprToExpr ins bld o1,
  transOprToExpr ins bld o2,
  transOprToExpr ins bld o3,
  transOprToExpr ins bld o4

let private transFPConcatTwoOprs bld (o1, o2) =
  transOprToFPPairConcat bld o1, transOprToFPPairConcat bld o2

let private transFPConcatThreeOprs bld (o1, o2, o3) =
  transOprToFPPairConcat bld o1,
  transOprToFPPairConcat bld o2,
  transOprToFPPairConcat bld o3

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
  | _ -> Terminator.impossible ()

let private transBigEndianCPU (bld: ILowUIRBuilder) opSz =
  match bld.Endianness, opSz with
  | Endian.Little, 32<rt> -> AST.num0 32<rt>
  | Endian.Big, 32<rt> -> numI32 0b11 32<rt>
  | Endian.Little, 64<rt> -> AST.num0 64<rt>
  | Endian.Big, 64<rt> -> numI32 0b111 64<rt>
  | _ -> raise InvalidOperandException

let sideEffects (ins: Instruction) insLen bld name =
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect name)
  bld --!> insLen

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

let private checkOverfolwOnDMul e1 e2 =
  let mask64 = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
  let bit32 = numI64 0x100000000L 64<rt>
  let cond = mask64 .- e1 .< e2
  AST.ite cond bit32 (AST.num0 64<rt>)

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
  let struct (qNaNBox, sNaNBox, sqNaNBox, exponent) = tmpVars4 bld 1<rt>
  let struct (sign, isNaNCheck) = tmpVars2 bld 1<rt>
  let struct (mantissa, signalBit) = tmpVars2 bld oprSz
  bld <+ (mantissa := getMantissa result oprSz)
  bld <+ (exponent := getExponentFull result oprSz)
  bld <+ (signalBit := getSignalBit result oprSz)
  bld <+ (isNaNCheck := isNaN oprSz exponent mantissa)
  bld <+ (qNaNBox := isQNaN oprSz signalBit isNaNCheck)
  bld <+ (sNaNBox := isSNaN oprSz signalBit isNaNCheck)
  let mantissa1 = getMantissa src1 oprSz
  let mantissa2 = getMantissa src2 oprSz
  let infChk =
    AST.not (isInfinity oprSz (getExponentFull src1 oprSz) mantissa1
    .| isInfinity oprSz (getExponentFull src2 oprSz) mantissa2)
  bld <+ (sign := AST.xthi 1<rt> result .& infChk)
  bld <+ (sqNaNBox := qNaNBox .| sNaNBox)
  bld <+ (result :=
    AST.ite sqNaNBox (
      let struct (sNaNVal, negSNaNVal, qNaNVal, negQNaNVal) =
        match oprSz with
        | 32<rt> ->
          struct (numU32 0x7fffffffu 32<rt>, numU32 0xffffffffu 32<rt>,
                  numU32 0x7fbfffffu 32<rt>, numU32 0xffbfffffu 32<rt>)
        | _ -> struct (numU64 0x7fffffffffffffffUL 64<rt>,
                       numU64 0xffffffffffffffffUL 64<rt>,
                       numU64 0x7ff7ffffffffffffUL 64<rt>,
                       numU64 0xfff7ffffffffffffUL 64<rt>)
      let qNaNWithSign = AST.ite sign negQNaNVal qNaNVal
      let sNaNWithSign = AST.ite sign negSNaNVal sNaNVal
      AST.ite qNaNBox qNaNWithSign (AST.ite sNaNBox sNaNWithSign result))
        result)

let divNormal oprSz src1 src2 result bld =
  let struct (exponent, isNaNCheck, sign) = tmpVars3 bld 1<rt>
  let struct (mantissa, signalBit) = tmpVars2 bld oprSz
  bld <+ (sign := AST.xthi 1<rt> result)
  bld <+ (mantissa := getMantissa result oprSz)
  bld <+ (signalBit := getSignalBit result oprSz)
  bld <+ (exponent := getExponentFull result oprSz)
  bld <+ (isNaNCheck := isNaN oprSz exponent mantissa)
  let src1Zero = src1 == AST.num0 oprSz
  let src2Zero = src2 == AST.num0 oprSz
  let qNan = isQNaN oprSz signalBit isNaNCheck
  let sNan = isSNaN oprSz signalBit isNaNCheck
  let struct (sNaNVal, negSNaNVal, qNaNVal, negQNaNVal) =
    match oprSz with
    | 32<rt> ->
      struct (numU32 0x7fffffffu 32<rt>, numU32 0xffffffffu 32<rt>,
              numU32 0x7fbfffffu 32<rt>, numU32 0xffbfffffu 32<rt>)
    | _ -> struct (numU64 0x7fffffffffffffffUL 64<rt>,
                   numU64 0xffffffffffffffffUL 64<rt>,
                   numU64 0x7ff7ffffffffffffUL 64<rt>,
                   numU64 0xfff7ffffffffffffUL 64<rt>)
  let qNaNWithSign = AST.ite sign negQNaNVal qNaNVal
  let sNaNWithSign = AST.ite sign negSNaNVal sNaNVal
  bld <+ (result := AST.ite (src1Zero .& src2Zero) qNaNVal
                    (AST.ite qNan qNaNWithSign
                      (AST.ite sNan sNaNWithSign result)))

let private normalizeValue oprSz result bld =
  let struct (qNaNBox, sNaNBox, infBox, exponent) = tmpVars4 bld 1<rt>
  let struct (isNaNCheck, sign) = tmpVars2 bld 1<rt>
  bld <+ (exponent := getExponentFull result oprSz)
  let struct (mantissa, signalBit) = tmpVars2 bld oprSz
  bld <+ (mantissa := getMantissa result oprSz)
  bld <+ (isNaNCheck := isNaN oprSz exponent mantissa)
  bld <+ (signalBit := getSignalBit result oprSz)
  bld <+ (qNaNBox := isQNaN oprSz signalBit isNaNCheck)
  bld <+ (sNaNBox := isSNaN oprSz signalBit isNaNCheck)
  bld <+ (infBox := isInfinity oprSz exponent mantissa)
  bld <+ (sign := AST.xthi 1<rt> result)
  let condBox = qNaNBox .| sNaNBox .| infBox
  bld <+ (result :=
    AST.ite condBox (
      let struct (sNaNVal, negSNaNVal, qNaNVal, negQNaNVal) =
        match oprSz with
        | 32<rt> ->
          struct (numU32 0x7fffffffu 32<rt>, numU32 0xffffffffu 32<rt>,
                  numU32 0x7fbfffffu 32<rt>, numU32 0xffbfffffu 32<rt>)
        | _ -> struct (numU64 0x7fffffffffffffffUL 64<rt>,
                       numU64 0xffffffffffffffffUL 64<rt>,
                       numU64 0x7ff7ffffffffffffUL 64<rt>,
                       numU64 0xfff7ffffffffffffUL 64<rt>)
      let struct (pInf, mInf) =
        match oprSz with
        | 32<rt> ->
          struct (numU32 0x7f800000u 32<rt>, numU32 0xff800000u 32<rt>)
        | _ -> struct (numU64 0x7ff0000000000000UL 64<rt>,
                       numU64 0xfff0000000000000UL 64<rt>)
      let qNanWithSign = AST.ite sign negQNaNVal qNaNVal
      let sNanWithSign = AST.ite sign negSNaNVal sNaNVal
      let infWithSign = AST.ite sign mInf pInf
      AST.ite qNaNBox qNanWithSign (AST.ite sNaNBox sNanWithSign
        (AST.ite infBox infWithSign result)))
          result)

let advancePC (bld: LowUIRBuilder) =
  if bld.DelayedBranch = InterJmpKind.NotAJmp then
    () (* Do nothing, because IEMark will advance PC. *)
  else
    let nPC = regVar bld R.NPC
    bld <+ (AST.interjmp nPC bld.DelayedBranch)
    bld.DelayedBranch <- InterJmpKind.NotAJmp

let updatePCCond (bld: LowUIRBuilder) offset cond kind =
  let lblTrueCase = label bld "TrueCase"
  let lblFalseCase = label bld "FalseCase"
  let lblEnd = label bld "End"
  let pc = regVar bld R.PC
  let nPC = regVar bld R.NPC
  bld.DelayedBranch <- kind
  bld <+ (AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase))
  bld <+ (AST.lmark lblTrueCase)
  bld <+ (nPC := offset)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblFalseCase)
  bld <+ (nPC := pc .+ numI32 8 bld.RegType)
  bld <+ (AST.lmark lblEnd)

let updateRAPCCond (bld: LowUIRBuilder) nAddr offset cond kind =
  let lblTrueCase = label bld "TrueCase"
  let lblFalseCase = label bld "FalseCase"
  let lblEnd = label bld "End"
  let pc = regVar bld R.PC
  let nPC = regVar bld R.NPC
  bld.DelayedBranch <- kind
  bld <+ (AST.cjmp cond (AST.jmpDest lblTrueCase) (AST.jmpDest lblFalseCase))
  bld <+ (AST.lmark lblTrueCase)
  bld <+ (nPC := offset)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblFalseCase)
  bld <+ (nPC := nAddr)
  bld <+ (AST.lmark lblEnd)

let private signExtLo64 expr = AST.xtlo 32<rt> expr |> AST.sext 64<rt>

let private signExtHi64 expr = AST.xthi 32<rt> expr |> AST.sext 64<rt>

let private getMask size = (1L <<< size) - 1L

let private shifterLoad fstShf sndShf rRt t1 t2 t3 =
  (sndShf (fstShf rRt t1) t1) .| (fstShf t3 t2)

let private shifterStore fstShf sndShf rRt t1 t2 t3 =
  (fstShf (sndShf t3 t2) t2) .| (sndShf rRt t1)

let private mul64BitReg src1 src2 bld isSign =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 bld 64<rt>
  let struct (tHigh, tLow) = tmpVars2 bld 64<rt>
  let struct (src1IsNeg, src2IsNeg, signBit) = tmpVars3 bld 1<rt>
  let n32 = numI32 32 64<rt>
  let mask32 = numI64 0xFFFFFFFFL 64<rt>
  if isSign then
    bld <+ (src1IsNeg := AST.xthi 1<rt> src1)
    bld <+ (src2IsNeg := AST.xthi 1<rt> src2)
    bld <+ (src1 := AST.ite src1IsNeg (AST.neg src1) src1)
    bld <+ (src2 := AST.ite src2IsNeg (AST.neg src2) src2)
  else ()
  bld <+ (hiSrc1 := (src1 >> n32) .& mask32) (* SRC1[63:32] *)
  bld <+ (loSrc1 := src1 .& mask32) (* SRC1[31:0] *)
  bld <+ (hiSrc2 := (src2 >> n32) .& mask32) (* SRC2[63:32] *)
  bld <+ (loSrc2 := src2 .& mask32) (* SRC2[31:0] *)
  let pHigh = hiSrc1 .* hiSrc2
  let pMid = (hiSrc1 .* loSrc2) .+ (loSrc1 .* hiSrc2)
  let pLow = loSrc1 .* loSrc2
  let overFlowBit = checkOverfolwOnDMul (hiSrc1 .* loSrc2) (loSrc1 .* hiSrc2)
  let high = pHigh .+ ((pMid .+ (pLow >> n32)) >> n32) .+ overFlowBit
  let low = pLow .+ ((pMid .& mask32) << n32)
  if isSign then
    bld <+ (signBit := src1IsNeg <+> src2IsNeg)
    bld <+ (tHigh := AST.ite signBit (AST.not high) high)
    bld <+ (tLow := AST.ite signBit (AST.neg low) low)
  else
    bld <+ (tHigh := high)
    bld <+ (tLow := low)
  struct (tHigh, tLow)

let abs ins insLen bld =
  let fd, fs = getTwoOprs ins
  let is32Bit = is32Bit bld
  bld <!-- (ins.Address, insLen)
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
    bld <+ (fd := AST.concat resB resA)
  | _ ->
    let fd, fs = transTwoOprs ins bld (fd, fs)
    let mask =
      if is32Bit then numU64 0x7FFFFFFFUL 32<rt>
      else numU64 0x7FFFFFFFFFFFFFFFUL 64<rt>
    bld <+ (fd := fs .& mask)
  advancePC bld
  bld --!> insLen

let private reDupSrc opr1 opr2 expr1 expr2 tmp1 tmp2 bld =
  if opr1 = opr2 then
    bld <+ (tmp1 := expr1)
    bld <+ (tmp2 := tmp1)
  else
    bld <+ (tmp1 := expr1)
    bld <+ (tmp2 := expr2)

let add (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  let dst, src1, src2 = getThreeOprs ins
  match ins.Fmt with
  | None ->
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let rd, rs, rt = transThreeOprs ins bld (dst, src1, src2)
    let result = if is32Bit bld then rs .+ rt else signExtLo64 (rs .+ rt)
    let cond = checkOverfolwOnAdd rs rt result
    bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "int overflow"))
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL1)
    bld <+ (rd := result)
    bld <+ (AST.lmark lblEnd)
  | Some Fmt.S ->
    let fd, fs, ft = transThreeSingleFP bld (dst, src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
    bld <+ (result := AST.fadd tSrc1 tSrc2)
    normalizeValue 32<rt> result bld
    bld <+ (fd := result)
  | _ ->
    let fdB, fdA = transOprToFPPair bld dst
    let fs, ft = transFPConcatTwoOprs bld (src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
    bld <+ (result := AST.fadd tSrc1 tSrc2)
    normalizeValue 64<rt> result bld
    dstAssignForFP fdB fdA result bld
  advancePC bld
  bld --!> insLen

let addiu ins insLen bld =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  let result = if is32Bit bld then rs .+ imm else signExtLo64 (rs .+ imm)
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := result)
  advancePC bld
  bld --!> insLen

let addu ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  let result = if is32Bit bld then rs .+ rt else signExtLo64 (rs .+ rt)
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := result)
  advancePC bld
  bld --!> insLen

let logAnd ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs .& rt)
  advancePC bld
  bld --!> insLen

let andi ins insLen bld =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := rs .& imm)
  advancePC bld
  bld --!> insLen

let aui ins insLen bld =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  let imm = imm << numI32 16 bld.RegType
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := rs .+ imm)
  advancePC bld
  bld --!> insLen

let b ins insLen (bld: LowUIRBuilder) =
  let nPC = regVar bld R.NPC
  let offset = getOneOpr ins |> transOneOpr ins bld
  bld.DelayedBranch <- InterJmpKind.Base
  bld <!-- (ins.Address, insLen)
  bld <+ (nPC := offset)
  bld --!> insLen

let bal ins insLen (bld: LowUIRBuilder) =
  let offset = getOneOpr ins |> transOneOpr ins bld
  let pc = regVar bld R.PC
  let nPC = regVar bld R.NPC
  bld.DelayedBranch <- InterJmpKind.IsCall
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld R.R31 := pc .+ numI32 8 bld.RegType)
  bld <+ (nPC := offset)
  bld --!> insLen

let private fpConditionCode cc bld =
  let fcsr = regVar bld R.FCSR
  if cc = 0 then (fcsr .& numU32 0x800000u 32<rt>) == numU32 0x800000u 32<rt>
  else
    let num = numU32 0x1000000u 32<rt> << numI32 cc 32<rt>
    (fcsr .& num) == num

let bc1f (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
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
  bld --!> insLen

let bc1t (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
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
  bld --!> insLen

let beq ins insLen bld =
  let rs, rt, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs == rt
  bld <!-- (ins.Address, insLen)
  updatePCCond bld offset cond InterJmpKind.Base
  bld --!> insLen

let blez ins insLen bld =
  let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
  let cond = AST.sle rs (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  updatePCCond bld offset cond InterJmpKind.Base
  bld --!> insLen

let bltz ins insLen bld =
  let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
  let cond = AST.slt rs (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  updatePCCond bld offset cond InterJmpKind.Base
  bld --!> insLen

let bltzal ins insLen bld =
  let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
  let pc = regVar bld R.PC
  let nAddr = tmpVar bld bld.RegType
  let cond = AST.slt rs (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  bld <+ (nAddr := pc .+ numI32 8 bld.RegType)
  bld <+ (regVar bld R.R31 := nAddr)
  updateRAPCCond bld nAddr offset cond InterJmpKind.IsCall
  bld --!> insLen

let bgez ins insLen bld =
  let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
  let cond = AST.sge rs (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  updatePCCond bld offset cond InterJmpKind.Base
  bld --!> insLen

let bgezal ins insLen bld =
  let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
  let pc = regVar bld R.PC
  let nAddr = tmpVar bld bld.RegType
  let cond = AST.sge rs (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  bld <+ (nAddr := pc .+ numI32 8 bld.RegType)
  bld <+ (regVar bld R.R31 := nAddr)
  updateRAPCCond bld nAddr offset cond InterJmpKind.IsCall
  bld --!> insLen

let bgtz ins insLen bld =
  let rs, offset = getTwoOprs ins |> transTwoOprs ins bld
  let cond = AST.sgt rs (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  updatePCCond bld offset cond InterJmpKind.Base
  bld --!> insLen

let bne ins insLen bld =
  let rs, rt, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs != rt
  bld <!-- (ins.Address, insLen)
  updatePCCond bld offset cond InterJmpKind.Base
  bld --!> insLen

let setFPConditionCode bld cc tf =
  let insertBit = AST.xtlo 32<rt> tf
  let fcsr = regVar bld R.FCSR
  if cc = 0 then
    let shf1 = numI32 23 32<rt>
    let mask1 = numU32 0xFF000000u 32<rt>
    let mask2 = numU32 0x7FFFFFu 32<rt>
    let insertBit = AST.xtlo 32<rt> tf
    bld <+ (fcsr := (fcsr .& mask1) .| (insertBit << shf1) .| (fcsr .& mask2))
  else
    let shf2 = numI32 (24 + cc) 32<rt>
    let mask1 = numU32 0xFE000000u 32<rt> << numI32 cc 32<rt>
    let mask2 =
      (numU32 0xFFFFFFu 32<rt> << numI32 cc 32<rt>) .| numU32 0xFFu 32<rt>
    bld <+ (fcsr := (fcsr .& mask1) .| (insertBit << shf2) .| (fcsr .& mask2))

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
  | _ -> raise InvalidOperandException

let cCond ins insLen bld =
  let oprSz, cc, fs, ft, sameReg = getCCondOpr ins bld
  let num0 = AST.num0 oprSz
  let num1 = AST.num1 oprSz
  let struct (tFs , tFt, mantissa) = tmpVars3 bld oprSz
  let struct (less, equal, unordered, condition) = tmpVars4 bld oprSz
  let struct (condNaN, exponent) = tmpVars2 bld 1<rt>
  let bit0, bit1, bit2 =
    match ins.Condition with
    | Some Condition.F | Some Condition.SF -> num0, num0, num0
    | Some Condition.UN | Some Condition.NGLE -> num1, num0, num0
    | Some Condition.EQ | Some Condition.SEQ -> num0, num1, num0
    | Some Condition.UEQ | Some Condition.NGL -> num1, num1, num0
    | Some Condition.OLT | Some Condition.LT -> num0, num0, num1
    | Some Condition.ULT | Some Condition.NGE -> num1, num0, num1
    | Some Condition.OLE | Some Condition.LE -> num0, num1, num1
    | Some Condition.ULE | Some Condition.NGT -> num1, num1, num1
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, insLen)
  if sameReg then
    bld <+ (tFs := fs)
    bld <+ (tFt := tFs)
  else
    bld <+ (tFs := fs)
    bld <+ (tFt := ft)
  let zeroSameCondWithEqaul =
    if sameReg then AST.b1
    else ((tFs << num1) >> num1) == ((tFt << num1) >> num1)
  bld <+ (condNaN :=
    if sameReg then
      bld <+ (mantissa := getMantissa tFt oprSz)
      bld <+ (exponent := getExponentFull tFt oprSz)
      AST.xtlo 1<rt> (exponent .& (mantissa != AST.num0 oprSz))
    else
      let src1Mantissa = getMantissa tFs oprSz
      let src2Mantissa = getMantissa tFt oprSz
      let src1Exponent = getExponentFull tFs oprSz
      let src2Exponent = getExponentFull tFt oprSz
      AST.xtlo 1<rt> (src1Exponent .& (src1Mantissa != AST.num0 oprSz)) .|
      AST.xtlo 1<rt> (src2Exponent .& (src2Mantissa != AST.num0 oprSz)))
  bld <+ (less := AST.ite condNaN num0 (AST.ite (AST.flt tFs tFt) num1 num0))
  bld <+ (equal :=
    AST.ite condNaN num0 (AST.ite zeroSameCondWithEqaul num1 num0))
  bld <+ (unordered := AST.ite condNaN num1 num0)
  bld <+ (condition := (bit2 .& less) .| (bit1 .& equal) .| (bit0 .& unordered))
  setFPConditionCode bld cc condition
  advancePC bld
  bld --!> insLen

let ctc1 ins insLen bld =
  let rt, _ = getTwoOprs ins |> transTwoOprs ins bld
  let fcsr = regVar bld R.FCSR
  bld <!-- (ins.Address, insLen)
  bld <+ (fcsr := AST.xtlo 32<rt> rt)
  advancePC bld
  bld --!> insLen

let cfc1 ins insLen bld =
  let rt, _ = getTwoOprs ins |> transTwoOprs ins bld
  let fcsr = regVar bld R.FCSR
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.sext bld.RegType fcsr)
  advancePC bld
  bld --!> insLen

let clz ins insLen bld =
  let lblLoop = label bld "Loop"
  let lblContinue = label bld "Continue"
  let lblEnd = label bld "End"
  let wordSz = bld.RegType
  let rd, rs = getTwoOprs ins |> transTwoOprs ins bld
  let t = tmpVar bld wordSz
  let n31 = numI32 31 wordSz
  bld <!-- (ins.Address, insLen)
  bld <+ (t := n31)
  bld <+ (AST.lmark lblLoop)
  let cond1 = rs >> t == AST.num1 wordSz
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblEnd) (AST.jmpDest lblContinue))
  bld <+ (AST.lmark lblContinue)
  bld <+ (t := t .- AST.num1 wordSz)
  let cond2 = t == numI32 -1 wordSz
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblEnd) (AST.jmpDest lblLoop))
  bld <+ (AST.lmark lblEnd)
  bld <+ (rd := n31 .- t)
  advancePC bld
  bld --!> insLen

let cvtd ins insLen bld =
  let fd, fs = getTwoOprs ins
  let fdB, fdA = transOprToFPPair bld fd
  let result = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | Some Fmt.W ->
    let fs = transOprToFPConvert ins bld fs
    bld <+ (result := AST.cast CastKind.SIntToFloat 64<rt> fs)
  | Some Fmt.S ->
    let fs = transOprToFPConvert ins bld fs
    bld <+ (result := AST.cast CastKind.FloatCast 64<rt> fs)
  | _ ->
    let fs = transOprToFPPairConcat bld fs
    bld <+ (result := AST.cast CastKind.SIntToFloat 64<rt> fs)
  normalizeValue 64<rt> result bld
  dstAssignForFP fdB fdA result bld
  advancePC bld
  bld --!> insLen

let cvtw ins insLen bld =
  let fd, fs = getTwoOprs ins
  let intMax = numI32 0x7fffffff 32<rt>
  let intMin = numI32 0x80000000 32<rt>
  let exponent = tmpVar bld 1<rt>
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, inf, nan) =
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoOprFPConvert ins bld (fd, fs)
      bld <+ (exponent := getExponentFull src 32<rt>)
      let mantissa = tmpVar bld 32<rt>
      bld <+ (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      dst, src, inf, nan
    | _ ->
      let dst = transOprToFPConvert ins bld fd
      let src = transOprToFPPairConcat bld fs
      bld <+ (exponent := getExponentFull src 64<rt>)
      let mantissa = tmpVar bld 64<rt>
      bld <+ (mantissa := getMantissa src 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      dst, src, inf, nan
  bld <+ (dst := roundToInt bld src 32<rt>)
  let outOfRange = AST.sgt dst intMax .| AST.slt dst intMin
  bld <+ (dst := AST.ite (outOfRange .| inf .| nan) intMax dst)
  advancePC bld
  bld --!> insLen

let cvtl ins insLen bld =
  let fd, fs = getTwoOprs ins
  let fdB, fdA = transOprToFPPair bld fd
  let eval = tmpVar bld 64<rt>
  let exponent = tmpVar bld 1<rt>
  let intMax = numI64 0x7fffffffffffffffL 64<rt>
  let intMin = numI64 0x8000000000000000L 64<rt>
  bld <!-- (ins.Address, insLen)
  let struct (src, inf, nan) =
    match ins.Fmt with
    | Some Fmt.S ->
      let src = transOprToFPConvert ins bld fs
      bld <+ (exponent := getExponentFull src 32<rt>)
      let mantissa = tmpVar bld 32<rt>
      bld <+ (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      src, inf, nan
    | _ ->
      let src = transOprToFPPairConcat bld fs
      bld <+ (exponent := getExponentFull src 64<rt>)
      let mantissa = tmpVar bld 64<rt>
      bld <+ (mantissa := getMantissa src 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      src, inf, nan
  bld <+ (eval := roundToInt bld src 64<rt>)
  let outOfRange = AST.sgt eval intMax .| AST.slt eval intMin
  bld <+ (eval := AST.ite (outOfRange .| inf .| nan) intMax eval)
  dstAssignForFP fdB fdA eval bld
  advancePC bld
  bld --!> insLen

let cvts ins insLen bld =
  let fd, fs = getTwoOprs ins
  let fd = transOprToFPConvert ins bld fd
  let dst = if is32Bit bld then fd else AST.xtlo 32<rt> fd
  let result = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | Some Fmt.L ->
    let fs = transOprToFPPairConcat bld fs
    bld <+ (result := AST.cast CastKind.SIntToFloat 32<rt> fs)
  | Some Fmt.D ->
    let fs = transOprToFPPairConcat bld fs
    bld <+ (result := AST.cast CastKind.FloatCast 32<rt> fs)
  | _ ->
    let fs = transOprToFPConvert ins bld fs
    bld <+ (result := AST.cast CastKind.SIntToFloat 32<rt> fs)
  normalizeValue 32<rt> result bld
  bld <+ (dst := result)
  advancePC bld
  bld --!> insLen

let dadd ins insLen bld =
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  let cond = checkOverfolwOnDadd rs rt (rs .+ rt)
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect (Exception "int overflow"))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := rs .+ rt)
  bld <+ (AST.lmark lblEnd)
  advancePC bld
  bld --!> insLen

let daddu ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  let result = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (result := rs .+ rt)
  bld <+ (rd := result)
  advancePC bld
  bld --!> insLen

let daddiu ins insLen bld =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  let result = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (result := rs .+ imm)
  bld <+ (rt := result)
  advancePC bld
  bld --!> insLen

let dclz ins insLen bld =
  let lblLoop = label bld "Loop"
  let lblContinue = label bld "Continue"
  let lblEnd = label bld "End"
  let wordSz = bld.RegType
  let rd, rs = getTwoOprs ins |> transTwoOprs ins bld
  let t = tmpVar bld wordSz
  let n63 = numI32 63 wordSz
  bld <!-- (ins.Address, insLen)
  bld <+ (t := n63)
  bld <+ (AST.lmark lblLoop)
  bld <+ (AST.cjmp (rs >> t == AST.num1 wordSz)
                 (AST.jmpDest lblEnd) (AST.jmpDest lblContinue))
  bld <+ (AST.lmark lblContinue)
  bld <+ (t := t .- AST.num1 wordSz)
  bld <+ (AST.cjmp (t == numI64 -1 wordSz)
                 (AST.jmpDest lblEnd) (AST.jmpDest lblLoop))
  bld <+ (AST.lmark lblEnd)
  bld <+ (rd := n63 .- t)
  advancePC bld
  bld --!> insLen

let ddiv ins insLen bld =
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  let struct (q, r) = tmpVars2 bld 64<rt>
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.ite (rt == numI64 0 bld.RegType)
                (AST.undef bld.RegType "UNPREDICTABLE") rt)
  bld <+ (q := AST.sdiv rs rt)
  bld <+ (r := AST.smod rs rt)
  bld <+ (lo := q)
  bld <+ (hi := r)
  advancePC bld
  bld --!> insLen

let dmfc1 ins insLen bld =
  let rt, fs = getTwoOprs ins
  let rt = transOprToExpr ins bld rt
  let fs = transOprToFPPairConcat bld fs
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := fs)
  advancePC bld
  bld --!> insLen

let dmtc1 ins insLen bld =
  let rt, fs = getTwoOprs ins
  let rt = transOprToExpr ins bld rt
  let fsB, fsA = transOprToFPPair bld fs
  bld <!-- (ins.Address, insLen)
  dstAssignForFP fsB fsA rt bld
  advancePC bld
  bld --!> insLen

let ddivu ins insLen bld =
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  let struct (q, r) = tmpVars2 bld 64<rt>
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  bld <!-- (ins.Address, insLen)
  bld <+ (q := AST.div rs rt)
  bld <+ (r := AST.(mod) rs rt)
  bld <+ (lo := q)
  bld <+ (hi := r)
  advancePC bld
  bld --!> insLen

let checkDEXTPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 63 then ()
  else raise InvalidOperandException

let dext ins insLen bld =
  let rt, rs, pos, size = getFourOprs ins
  let rt = transOprToExpr ins bld rt
  let rs = transOprToExpr ins bld rs
  let pos = transOprToImm pos |> int
  let size = transOprToImm size |> int
  checkDEXTPosSize pos size
  let mask = numI64 (getMask size) bld.RegType
  let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := mask .& rs |> AST.zext 64<rt>)
  advancePC bld
  bld --!> insLen

let checkDEXTMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     32 < size && size <= 64 &&
     32 < posSize && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDEXTUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos && pos < 64 &&
     0 < size && size <= 32 &&
     32 < posSize && posSize <= 64 then ()
  else raise InvalidOperandException

let dextx ins insLen posSizeCheckFn bld =
  let rt, rs, pos, size = getFourOprs ins
  let rt = transOprToExpr ins bld rt
  let rs = transOprToExpr ins bld rs
  let pos = transOprToImm pos |> int
  let sz = transOprToImm size |> int
  posSizeCheckFn pos sz
  bld <!-- (ins.Address, insLen)
  if sz = 64 then if rt = rs then () else bld <+ (rt := rs)
  else
    let rs = if pos = 0 then rs else rs >> numI32 pos bld.RegType
    let result = rs .& numI64 (getMask sz) bld.RegType
    bld <+ (rt := result)
  advancePC bld
  bld --!> insLen

let checkINSorExtPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 32 then ()
  else raise InvalidOperandException

let dins ins insLen bld =
  let rt, rs, pos, size = getFourOprs ins
  let rt = transOprToExpr ins bld rt
  let rs = transOprToExpr ins bld rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  bld <!-- (ins.Address, insLen)
  if pos = 0 && rt = rs then ()
  else
    let posExpr = numI32 pos bld.RegType
    let mask = numI64 (getMask size) bld.RegType
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    bld <+ (rt := rt' .| rs')
  advancePC bld
  bld --!> insLen

let checkDINSMPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     2 < size && size <= 64 &&
     32 < posSize && posSize <= 64 then ()
  else raise InvalidOperandException

let checkDINSUPosSize pos size =
  let posSize = pos + size
  if 32 <= pos && pos < 64 &&
     1 <= size && size <= 32 &&
     32 < posSize && posSize <= 64 then ()
  else raise InvalidOperandException

let dinsx ins insLen posSizeCheckFn bld =
  let rt, rs, pos, size = getFourOprs ins
  let rt = transOprToExpr ins bld rt
  let rs = transOprToExpr ins bld rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  posSizeCheckFn pos size
  bld <!-- (ins.Address, insLen)
  if size = 64 then if rt = rs then () else bld <+ (rt := rs)
  else
    let posExpr = numI32 pos bld.RegType
    let mask = numI64 (getMask size) bld.RegType
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    bld <+ (rt := rt' .| rs')
  advancePC bld
  bld --!> insLen

let div (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    bld <+ (rt := AST.ite (rt == numI64 0 bld.RegType)
                  (AST.undef bld.RegType "UNPREDICTABLE") rt)
    if is32Bit bld then
      bld <+ (lo :=
        (AST.sext 64<rt> rs ?/ AST.sext 64<rt> rt) |> AST.xtlo 32<rt>)
      bld <+ (hi :=
        (AST.sext 64<rt> rs ?% AST.sext 64<rt> rt) |> AST.xtlo 32<rt>)
    else
      let mask = numI64 0xFFFFFFFFL 64<rt>
      let q = (rs .& mask) ?/ (rt .& mask)
      let r = (rs .& mask) ?% (rt .& mask)
      bld <+ (lo := signExtLo64 q)
      bld <+ (hi := signExtLo64 r)
  | Some Fmt.D ->
    let fd, fs, ft = getThreeOprs ins
    let fdB, fdA = transOprToFPPair bld fd
    let src1, src2 = transFPConcatTwoOprs bld (fs, ft)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
    reDupSrc fs ft src1 src2 tSrc1 tSrc2 bld
    bld <+ (result := AST.fdiv tSrc1 tSrc2)
    divNormal 64<rt> tSrc1 tSrc2 result bld
    dstAssignForFP fdB fdA result bld
  | _ ->
    let fd, fs, ft = getThreeOprs ins
    let dst, src1, src2 = transThreeSingleFP bld (fd, fs, ft)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
    reDupSrc fs ft src1 src2 tSrc1 tSrc2 bld
    bld <+ (result := AST.fdiv tSrc1 tSrc2)
    divNormal 32<rt> tSrc1 tSrc2 result bld
    bld <+ (dst := result)
  advancePC bld
  bld --!> insLen

let divu ins insLen bld =
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.ite (rt == numI64 0 bld.RegType)
                (AST.undef bld.RegType "UNPREDICTABLE") rt)
  if is32Bit bld then
    let struct (extendRs, extendRt) = tmpVars2 bld 64<rt>
    bld <+ (extendRs := AST.zext 64<rt> rs)
    bld <+ (extendRt := AST.zext 64<rt> rt)
    bld <+ (lo := (extendRs ./ extendRt) |> AST.xtlo 32<rt>)
    bld <+ (hi := (extendRs .% extendRt) |> AST.xtlo 32<rt>)
  else
    let struct (maskRs, maskRt) = tmpVars2 bld 64<rt>
    let mask = numI64 0xFFFFFFFFL 64<rt>
    bld <+ (maskRs := rs .& mask)
    bld <+ (maskRt := rt .& mask)
    bld <+ (lo := signExtLo64 (maskRs ./ maskRt))
    bld <+ (hi := signExtLo64 (maskRs .% maskRt))
  advancePC bld
  bld --!> insLen

let dmul ins insLen bld isSign =
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  let struct (high, low) = mul64BitReg rs rt bld isSign
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  bld <!-- (ins.Address, insLen)
  bld <+ (lo := low)
  bld <+ (hi := high)
  advancePC bld
  bld --!> insLen

let drotr ins insLen bld =
  let rd, rt, sa = getThreeOprs ins
  let rd, rt = transTwoOprs ins bld (rd, rt)
  let sa = numU64 (transOprToImm sa) 64<rt>
  let size = numI32 64 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC bld
  bld --!> insLen

let drotr32 ins insLen bld =
  let rd, rt, sa = getThreeOprs ins
  let rd, rt = transTwoOprs ins bld (rd, rt)
  let sa = numU64 (transOprToImm sa) 64<rt> .+ numI32 32 64<rt>
  let size = numI32 64 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC bld
  bld --!> insLen

let drotrv ins insLen bld =
  let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
  let sa = tmpVar bld 64<rt>
  let size = numI32 64 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (sa := rs .& numI32 0x3F 64<rt>)
  bld <+ (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC bld
  bld --!> insLen

let dsra ins insLen bld =
  let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rt ?>> sa |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let dsrav ins insLen bld =
  let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rt ?>> (rs .& numI32 63 64<rt>) |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let dsra32 ins insLen bld =
  let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
  let sa = sa .+ numI32 32 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rt ?>> sa |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let dShiftLeftRight32 ins insLen bld shf =
  let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
  let sa = sa .+ numI32 32 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := shf rt sa |> AST.zext 64<rt>)
  advancePC bld
  bld --!> insLen

let dShiftLeftRight ins insLen bld shf =
  let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := shf rt sa |> AST.zext 64<rt>)
  advancePC bld
  bld --!> insLen

let dShiftLeftRightVar ins insLen bld shf =
  let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := shf rt (rs .& numI32 63 64<rt>) |> AST.zext 64<rt>)
  advancePC bld
  bld --!> insLen

let dsubu ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  let result = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (result := rs .- rt)
  bld <+ (rd := result)
  advancePC bld
  bld --!> insLen

let insert ins insLen bld =
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
  bld <!-- (ins.Address, insLen)
  let rs', rt' =
    if pos = 0 then rs .& mask, rt .& (AST.not mask)
    else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
  bld <+ (rt := rt' .| rs')
  advancePC bld
  bld --!> insLen

let getJALROprs (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand opr ->
    struct (regVar bld R.R31, transOprToExpr ins bld opr)
  | TwoOperands(o1, o2) ->
    struct (transOprToExpr ins bld o1, transOprToExpr ins bld o2)
  | _ -> raise InvalidOperandException

let j ins insLen (bld: LowUIRBuilder) =
  let nPC = regVar bld R.NPC
  let dest = getOneOpr ins |> transOprToExpr ins bld
  bld.DelayedBranch <- InterJmpKind.Base
  bld <!-- (ins.Address, insLen)
  bld <+ (nPC := dest)
  bld --!> insLen

let jal ins insLen (bld: LowUIRBuilder) =
  let pc = regVar bld R.PC
  let nPC = regVar bld R.NPC
  let lr = regVar bld R.R31
  let dest = getOneOpr ins |> transOprToExpr ins bld
  bld.DelayedBranch <- InterJmpKind.IsCall
  bld <!-- (ins.Address, insLen)
  bld <+ (lr := pc .+ numI32 8 bld.RegType)
  bld <+ (nPC := dest)
  bld --!> insLen

let jalr ins insLen (bld: LowUIRBuilder) =
  let pc = regVar bld R.PC
  let nPC = regVar bld R.NPC
  let struct (lr, rs) = getJALROprs ins bld
  bld.DelayedBranch <- InterJmpKind.IsCall
  bld <!-- (ins.Address, insLen)
  bld <+ (lr := pc .+ numI32 8 bld.RegType)
  bld <+ (nPC := rs)
  bld --!> insLen

let jr ins insLen (bld: LowUIRBuilder) =
  let nPC = regVar bld R.NPC
  let rs = getOneOpr ins |> transOneOpr ins bld
  bld.DelayedBranch <- InterJmpKind.Base
  bld <!-- (ins.Address, insLen)
  bld <+ (nPC := rs)
  bld --!> insLen

let loadSigned ins insLen bld =
  let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.sext bld.RegType mem)
  advancePC bld
  bld --!> insLen

let loadUnsigned ins insLen bld =
  let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.zext bld.RegType mem)
  advancePC bld
  bld --!> insLen

let loadLinked ins insLen bld =
  let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.sext bld.RegType mem)
  bld <+ (AST.extCall <| AST.app "SetLLBit" [] bld.RegType)
  advancePC bld
  bld --!> insLen

let sldc1 ins insLen bld stORld =
  let ft, mem = getTwoOprs ins
  let ftB, ftA = transOprToFPPair bld ft
  let baseOffset = transOprToBaseOffset bld mem
  let bOff = tmpVar bld bld.RegType
  let memory = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (bOff := baseOffset)
  bld <+ (memory := AST.loadLE 64<rt> bOff)
  if stORld then
    bld <+ (AST.loadLE 64<rt> bOff :=
      if is32Bit bld then AST.concat ftB ftA else ftA)
  else dstAssignForFP ftB ftA memory bld
  advancePC bld
  bld --!> insLen

let slwc1 ins insLen bld stORld =
  let ft, mem = getTwoOprs ins
  let ft = transOprToSingleFP bld ft
  let mem = transOprToExpr ins bld mem
  let ft = if is32Bit bld then ft else AST.xtlo 32<rt> ft
  bld <!-- (ins.Address, insLen)
  if stORld then bld <+ (mem := ft)
  else bld <+ (ft := mem)
  advancePC bld
  bld --!> insLen

let ext ins insLen bld =
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
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := rs .& numI64 (getMask size) bld.RegType)
  advancePC bld
  bld --!> insLen

let lui ins insLen bld =
  let rt, imm = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (rt := AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>))
  else
    bld <+ (rt := AST.sext 64<rt>
                  (AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>)))
  advancePC bld
  bld --!> insLen

let mAddSub (ins: Instruction) insLen bld opFn =
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
    let op = if opFn then AST.add else AST.sub
    let result = tmpVar bld 64<rt>
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    if is32Bit bld then
      bld <+ (result :=
        op (AST.concat hi lo) (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
      bld <+ (hi := AST.xthi 32<rt> result)
      bld <+ (lo := AST.xtlo 32<rt> result)
    else
      let mask = numU32 0xFFFFu 64<rt>
      let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
      bld <+ (result := op hilo ((rs .& mask) .* (rt .& mask)))
      bld <+ (hi := signExtHi64 result)
      bld <+ (lo := signExtLo64 result)
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
    bld <+ (fd := result)
  advancePC bld
  bld --!> insLen

let mAdduSubu ins insLen bld opFn =
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  let result = tmpVar bld 64<rt>
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  let op = if opFn then AST.add else AST.sub
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (result :=
      op (AST.concat hi lo) (AST.zext 64<rt> rs .* AST.zext 64<rt> rt))
    bld <+ (hi := AST.xthi 32<rt> result)
    bld <+ (lo := AST.xtlo 32<rt> result)
  else
    let mask = numU32 0xFFFFu 64<rt>
    let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
    bld <+ (result := op hilo ((rs .& mask) .* (rt .& mask)))
    bld <+ (hi := AST.xthi 32<rt> result |> AST.zext 64<rt>)
    bld <+ (lo := AST.xtlo 32<rt> result |> AST.zext 64<rt>)
  advancePC bld
  bld --!> insLen

let mfhi ins insLen bld =
  let rd = getOneOpr ins |> transOneOpr ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := regVar bld R.HI)
  advancePC bld
  bld --!> insLen

let mflo ins insLen bld =
  let rd = getOneOpr ins |> transOneOpr ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := regVar bld R.LO)
  advancePC bld
  bld --!> insLen

let mfhc1 ins insLen bld =
  let rt, fs = getTwoOprs ins
  let rt = transOprToExpr ins bld rt
  let fsB, _ = transOprToFPPair bld fs
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.sext bld.RegType fsB)
  advancePC bld
  bld --!> insLen

let mthc1 ins insLen bld =
  let rt, fs = getTwoOprs ins
  let rt = transOprToExpr ins bld rt
  let fsB, _ = transOprToFPPair bld fs
  bld <!-- (ins.Address, insLen)
  bld <+ (fsB := AST.xtlo 32<rt> rt)
  advancePC bld
  bld --!> insLen

let mthi ins insLen bld =
  let rs = getOneOpr ins |> transOneOpr ins bld
  let hi = regVar bld R.HI
  bld <!-- (ins.Address, insLen)
  bld <+ (hi := rs)
  advancePC bld
  bld --!> insLen

let mtlo ins insLen bld =
  let rs = getOneOpr ins |> transOneOpr ins bld
  let lo = regVar bld R.LO
  bld <!-- (ins.Address, insLen)
  bld <+ (lo := rs)
  advancePC bld
  bld --!> insLen

let mfc1 ins insLen bld =
  let rt, fs = getTwoOprs ins
  let rt = transOprToExpr ins bld rt
  let fs = transOprToSingleFP bld fs
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := AST.sext bld.RegType fs)
  advancePC bld
  bld --!> insLen

let mov ins insLen bld =
  let fd, fs = getTwoOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoSingleFP bld (fd, fs)
    bld <+ (fd := fs)
  | Some Fmt.D ->
    let fdB, fdA = transOprToFPPair bld fd
    let fs = transOprToFPPairConcat bld fs
    let result = tmpVar bld 64<rt>
    bld <+ (result := fs)
    dstAssignForFP fdB fdA result bld
  | _ -> raise InvalidOperandException
  advancePC bld
  bld --!> insLen

let movt ins insLen bld =
  let dst, src, cc = getThreeOprs ins
  let cc = transOprToImmToInt cc
  let cond = fpConditionCode cc bld
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let dst, src = transTwoOprs ins bld (dst, src)
    bld <+ (dst := AST.ite cond src dst)
  | Some Fmt.S ->
    let dst, src = transTwoSingleFP bld (dst, src)
    bld <+ (dst := AST.ite cond src dst)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair bld dst
    let srcB, srcA = transOprToFPPair bld src
    bld <+ (dstB := AST.ite cond srcB dstB)
    bld <+ (dstA := AST.ite cond srcA dstA)
  | _ -> raise InvalidOperandException
  advancePC bld
  bld --!> insLen

let movf ins insLen bld =
  let dst, src, cc = getThreeOprs ins
  let cc = transOprToImmToInt cc
  let cond = AST.not (fpConditionCode cc bld)
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let dst, src = transTwoOprs ins bld (dst, src)
    bld <+ (dst := AST.ite cond src dst)
  | Some Fmt.S ->
    let dst, src = transTwoSingleFP bld (dst, src)
    bld <+ (dst := AST.ite cond src dst)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair bld dst
    let srcB, srcA = transOprToFPPair bld src
    bld <+ (dstB := AST.ite cond srcB dstB)
    bld <+ (dstA := AST.ite cond srcA dstA)
  | _ -> raise InvalidOperandException
  advancePC bld
  bld --!> insLen

let movzOrn ins insLen bld opFn =
  let dst, src, compare = getThreeOprs ins
  let compare = transOprToExpr ins bld compare
  let cond = opFn compare (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let dst, src = transTwoOprs ins bld (dst, src)
    bld <+ (dst := AST.ite cond src dst)
  | Some Fmt.S ->
    let dst, src = transTwoSingleFP bld (dst, src)
    bld <+ (dst := AST.ite cond src dst)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair bld dst
    let src = transOprToFPPairConcat bld src
    bld <+ (dstB := AST.ite cond (AST.xthi 32<rt> src) dstB)
    bld <+ (dstA := AST.ite cond (AST.xtlo 32<rt> src) dstA)
  | _ -> raise InvalidOperandException
  advancePC bld
  bld --!> insLen

let mtc1 ins insLen bld =
  let rt, fs = getTwoOprs ins
  let rt = transOprToExpr ins bld rt
  let fs = transOprToSingleFP bld fs
  bld <!-- (ins.Address, insLen)
  bld <+ (fs := AST.xtlo 32<rt> rt)
  advancePC bld
  bld --!> insLen

let mul ins insLen bld =
  let dst, src1, src2 = getThreeOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let dst, src1, src2 = transThreeOprs ins bld (dst, src1, src2)
    let hi = regVar bld R.HI
    let lo = regVar bld R.LO
    let result =
      if is32Bit bld then
        (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2) |> AST.xtlo 32<rt>
      else signExtLo64 (src1 .* src2)
    bld <+ (dst := result)
    bld <+ (hi := AST.undef bld.RegType "UNPREDICTABLE")
    bld <+ (lo := AST.undef bld.RegType "UNPREDICTABLE")
  | Some Fmt.S ->
    let dst, fs, ft = transThreeSingleFP bld (dst, src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
    bld <+ (result := AST.fmul tSrc1 tSrc2)
    normalizeValue 32<rt> result bld
    bld <+ (dst := result)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair bld dst
    let fs, ft = transFPConcatTwoOprs bld (src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
    bld <+ (result := AST.fmul tSrc1 tSrc2)
    normalizeValue 64<rt> result bld
    dstAssignForFP dstB dstA result bld
  | _ -> raise InvalidOperandException
  advancePC bld
  bld --!> insLen

let mult ins insLen bld =
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let result = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  let struct (low, high) =
    if is32Bit bld then
      bld <+ (result := AST.sext 64<rt> rs .* AST.sext 64<rt> rt)
      result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
    else
      bld <+ (result := (rs .& mask) .* (rt .& mask))
      signExtLo64 result, signExtHi64 result
  bld <+ (lo := low)
  bld <+ (hi := high)
  advancePC bld
  bld --!> insLen

let multu ins insLen bld =
  let rs, rt = getTwoOprs ins
  let src1, src2 = transTwoOprs ins bld (rs, rt)
  let struct (tRs , tRt) = tmpVars2 bld bld.RegType
  let hi = regVar bld R.HI
  let lo = regVar bld R.LO
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let result = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  reDupSrc rs rt src1 src2 tRs tRt bld
  let struct (low, high) =
    if is32Bit bld then
      bld <+ (result := AST.zext 64<rt> tRs .* AST.zext 64<rt> tRt)
      result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
    else
      bld <+ (result := (tRs .& mask) .* (tRt .& mask))
      signExtLo64 result, signExtHi64 result
  bld <+ (lo := low)
  bld <+ (hi := high)
  advancePC bld
  bld --!> insLen

let neg ins insLen bld =
  let fd, fs = getTwoOprs ins
  let is32Bit = is32Bit bld
  bld <!-- (ins.Address, insLen)
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
    bld <+ (fd := AST.concat resB resA)
  | _ ->
    let fd, fs = transTwoOprs ins bld (fd, fs)
    let mask =
      if bld.RegType = 32<rt> then numU64 0x80000000UL bld.RegType
      else numU64 0x8000000000000000UL bld.RegType
    bld <+ (fd := fs <+> mask)
  advancePC bld
  bld --!> insLen

let nop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  advancePC bld
  bld --!> insLen

let nor ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.not (rs .| rt))
  advancePC bld
  bld --!> insLen

let logOr ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs .| rt)
  advancePC bld
  bld --!> insLen

let ori ins insLen bld =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := rs .| imm)
  advancePC bld
  bld --!> insLen

let pause (ins: Instruction) insLen bld =
  let llbit = regVar bld R.LLBit
  let lblSpin = label bld "Spin"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.lmark lblSpin)
  bld <+ (AST.extCall <| AST.app "GetLLBit" [] bld.RegType)
  bld <+ (AST.cjmp (llbit == AST.b1) (AST.jmpDest lblSpin) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblEnd)
  advancePC bld
  bld --!> insLen

let rotr ins insLen bld =
  let rd, rt, sa = getThreeOprs ins
  let rd, rt = transTwoOprs ins bld (rd, rt)
  let sa = numU64 (transOprToImm sa) 32<rt>
  let size = numI32 32 32<rt>
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (rd := (rt << (size .- sa)) .| (rt >> sa))
  else
    bld <+ (rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
                  (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let rotrv ins insLen bld =
  let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
  let sa = tmpVar bld 32<rt>
  let size = numI32 32 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (sa := AST.xtlo 32<rt> rs .& numI32 0x1F 32<rt>)
  if is32Bit bld then
    bld <+ (rd := (rt << (size .- sa)) .| (rt >> sa))
  else
    bld <+ (rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
                  (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let store ins insLen width bld =
  let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (mem := AST.xtlo width rt)
  advancePC bld
  bld --!> insLen

let sqrt ins insLen bld =
  let fd, fs = getTwoOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoSingleFP bld (fd, fs)
    let cond = fs == numU32 0x80000000u 32<rt>
    bld <+ (fd := AST.ite cond (numU32 0x80000000u 32<rt>) (AST.fsqrt fs))
  | _ ->
    let fdB, fdA = transOprToFPPair bld fd
    let fs = transOprToFPPairConcat bld fs
    let cond = fs == numU64 0x8000000000000000UL 64<rt>
    let result =
      AST.ite cond (numU64 0x8000000000000000UL 64<rt>) (AST.fsqrt fs)
    dstAssignForFP fdB fdA result bld
  advancePC bld
  bld --!> insLen

let storeConditional ins insLen width bld =
  let lblInRMW = label bld "InRMW"
  let lblEnd = label bld "End"
  let rt, mem = getTwoOprs ins |> transTwoOprs ins bld
  let llbit = regVar bld R.LLBit
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.extCall <| AST.app "GetLLBit" [] bld.RegType)
  bld <+ (AST.cjmp (llbit == AST.b1)
                   (AST.jmpDest lblInRMW) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblInRMW)
  bld <+ (mem := AST.xtlo width rt)
  bld <+ (AST.lmark lblEnd)
  bld <+ (rt := AST.zext bld.RegType llbit)
  bld <+ (AST.extCall <| AST.app "ClearLLBit" [] bld.RegType)
  advancePC bld
  bld --!> insLen

let storeLeftRight ins insLen bld memShf regShf amtOp oprSz =
  let rt, mem = getTwoOprs ins
  let baseOffset = transOprToBaseOffset bld mem
  let rt = transOprToExpr ins bld rt
  let rRt, baseOffset =
    if oprSz = 32<rt> then
      if is32Bit bld then rt, baseOffset
      else AST.xtlo 32<rt> rt, AST.xtlo 32<rt> baseOffset
    else rt, baseOffset
  let baseOff = tmpVar bld bld.RegType
  let maskLd = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
  let struct (t1, t2, t3, baseMask) = tmpVars4 bld oprSz
  let mask = numI32 (((int oprSz) >>> 3) - 1) oprSz
  let vaddr0To2 = (baseOff .& mask) <+> (transBigEndianCPU bld oprSz)
  let baseAddress = AST.loadLE oprSz baseMask
  bld <!-- (ins.Address, insLen)
  bld <+ (baseOff := baseOffset)
  bld <+ (baseMask := baseOff .& numI32 maskLd oprSz)
  bld <+ (t1 := vaddr0To2)
  bld <+ (t2 := (amtOp (mask .- t1) mask) .* numI32 8 oprSz)
  bld <+ (t3 := ((amtOp t1 mask) .+ AST.num1 oprSz) .* numI32 8 oprSz)
  bld <+ (baseAddress := shifterStore memShf regShf rRt t2 t3 baseAddress)
  advancePC bld
  bld --!> insLen

let syscall (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect SysCall)
  bld --!> insLen

let seb ins insLen bld =
  let rd, rt = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext bld.RegType (AST.extract rt 8<rt> 0))
  advancePC bld
  bld --!> insLen

let seh ins insLen bld =
  let rd, rt = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext bld.RegType (AST.extract rt 16<rt> 0))
  advancePC bld
  bld --!> insLen

let shiftLeftRight ins insLen bld shf =
  let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (rd := shf rt sa)
  else
    let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
    bld <+ (rd := shf rt sa |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let sra ins insLen bld =
  let rd, rt, sa = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (rd := rt ?>> sa |> AST.sext 32<rt>)
  else
    let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
    bld <+ (rd := rt ?>> sa |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let srav ins insLen bld =
  let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
  let mask = numI32 31 32<rt>
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (rd := rt ?>> (rs .& mask) |> AST.sext 32<rt>)
  else
    let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
    bld <+ (rd := rt ?>> (rs .& mask) |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let shiftLeftRightVar ins insLen bld shf =
  let rd, rt, rs = getThreeOprs ins |> transThreeOprs ins bld
  let mask = numI32 31 32<rt>
  bld <!-- (ins.Address, insLen)
  if is32Bit bld then
    bld <+ (rd := shf rt (rs .& mask))
  else
    let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
    bld <+ (rd := shf rt (rs .& mask) |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let sltAndU ins insLen bld amtOp =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  let cond = amtOp rs rt
  let rtVal =
    AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rtVal)
  advancePC bld
  bld --!> insLen

let sltiAndU ins insLen bld amtOp =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  let cond = amtOp rs imm
  let rtVal =
    AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := rtVal)
  advancePC bld
  bld --!> insLen

let sub ins insLen bld =
  let dst, src1, src2 = getThreeOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | None ->
    let dst, src1, src2 = transThreeOprs ins bld (dst, src1, src2)
    bld <+ (dst := src1 .- src2)
  | Some Fmt.S ->
    let dst, fs, ft = transThreeSingleFP bld (dst, src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 32<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
    bld <+ (result := AST.fsub tSrc1 tSrc2)
    subNormal 32<rt> tSrc1 tSrc2 result bld
    bld <+ (dst := result)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair bld dst
    let fs, ft = transFPConcatTwoOprs bld (src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 bld 64<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 bld
    bld <+ (result := AST.fsub tSrc1 tSrc2)
    subNormal 64<rt> tSrc1 tSrc2 result bld
    dstAssignForFP dstB dstA result bld
  | _ -> raise InvalidOperandException
  advancePC bld
  bld --!> insLen

let subu ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  let result = if is32Bit bld then rs .- rt else signExtLo64 (rs .- rt)
  bld <+ (rd := result)
  advancePC bld
  bld --!> insLen

let teq ins insLen bld =
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  let rs, rt = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp (rs == rt) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect UndefinedInstr) (* FIXME: Trap *)
  bld <+ (AST.lmark lblEnd)
  advancePC bld
  bld --!> insLen

let teqi ins insLen bld =
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  let rs, imm = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp (rs == imm) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect UndefinedInstr)
  bld <+ (AST.lmark lblEnd)
  advancePC bld
  bld --!> insLen

let truncw ins insLen bld =
  let fd, fs = getTwoOprs ins
  let intMax = numI32 0x7fffffff 32<rt>
  let intMin = numI32 0x80000000 32<rt>
  let exponent = tmpVar bld 1<rt>
  let dstTmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  let struct (dst, src, inf, nan) =
    match ins.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoSingleFP bld (fd, fs)
      bld <+ (exponent := getExponentFull src 32<rt>)
      let mantissa = tmpVar bld 32<rt>
      bld <+ (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      dst, src, inf, nan
    | _ ->
      let dst = transOprToSingleFP bld fd
      let src = transOprToFPPairConcat bld fs
      let tSrc = tmpVar bld 64<rt>
      bld <+ (tSrc := src)
      bld <+ (exponent := getExponentFull tSrc 64<rt>)
      let mantissa = tmpVar bld 64<rt>
      bld <+ (mantissa := getMantissa tSrc 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      dst, tSrc, inf, nan
  bld <+ (dst := AST.cast CastKind.FtoITrunc 32<rt> src)
  bld <+ (dstTmp := dst)
  let outOfRange = AST.sgt dstTmp intMax .| AST.slt dstTmp intMin
  bld <+ (dst := AST.ite (outOfRange .| inf .| nan) intMax dstTmp)
  advancePC bld
  bld --!> insLen

let truncl ins insLen bld =
  let fd, fs = getTwoOprs ins
  let fdB, fdA = transOprToFPPair bld fd
  let eval = tmpVar bld 64<rt>
  let exponent = tmpVar bld 1<rt>
  let intMax = numI64 0x7fffffffffffffffL 64<rt>
  let intMin = numI64 0x8000000000000000L 64<rt>
  bld <!-- (ins.Address, insLen)
  let struct (src, inf, nan) =
    match ins.Fmt with
    | Some Fmt.S ->
      let src = transOprToSingleFP bld fs
      bld <+ (exponent := getExponentFull src 32<rt>)
      let mantissa = tmpVar bld 32<rt>
      bld <+ (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      src, inf, nan
    | _ ->
      let src = transOprToFPPairConcat bld fs
      bld <+ (exponent := getExponentFull src 64<rt>)
      let mantissa = tmpVar bld 64<rt>
      bld <+ (mantissa := getMantissa src 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      src, inf, nan
  bld <+ (eval := AST.cast CastKind.FtoITrunc 64<rt> src)
  let outOfRange = AST.sgt eval intMax .| AST.slt eval intMin
  bld <+ (eval := AST.ite (outOfRange .| inf .| nan) intMax eval)
  dstAssignForFP fdB fdA eval bld
  advancePC bld
  bld --!> insLen

let logXor ins insLen bld =
  let rd, rs, rt = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs <+> rt)
  advancePC bld
  bld --!> insLen

let wsbh ins insLen bld =
  let dst, src = getTwoOprs ins |> transTwoOprs ins bld
  let rt = AST.xtlo 32<rt> src
  let elements =
    Array.init 4 (fun x -> AST.extract rt 8<rt> ((2 + x) % 4 * 8)) |> Array.rev
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.sext bld.RegType (AST.revConcat elements))
  advancePC bld
  bld --!> insLen

let dsbh ins insLen bld =
  let dst, src = getTwoOprs ins |> transTwoOprs ins bld
  let lo = AST.xtlo 32<rt> src
  let hi = AST.xthi 32<rt> src
  let hiResult =
    Array.init 4 (fun x -> AST.extract hi 8<rt> ((2 + x) % 4 * 8)) |> Array.rev
  let lowResult =
    Array.init 4 (fun x -> AST.extract lo 8<rt> ((2 + x) % 4 * 8)) |> Array.rev
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.revConcat (Array.append lowResult hiResult))
  advancePC bld
  bld --!> insLen

let dshd ins insLen bld =
  let dst, src = getTwoOprs ins |> transTwoOprs ins bld
  let result =
    Array.init 4 (fun idx -> AST.extract src 16<rt> (idx * 16)) |> Array.rev
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.revConcat result)
  advancePC bld
  bld --!> insLen

let xori ins insLen bld =
  let rt, rs, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rt := rs <+> imm)
  advancePC bld
  bld --!> insLen

let loadLeftRight ins insLen bld memShf regShf amtOp oprSz =
  let rt, mem = getTwoOprs ins
  let baseOffset = transOprToBaseOffset bld mem
  let rt = transOprToExpr ins bld rt
  let rRt, baseOffset =
    if oprSz = 32<rt> then
      if is32Bit bld then rt, baseOffset
      else AST.xtlo 32<rt> rt, AST.xtlo 32<rt> baseOffset
    else rt, baseOffset
  let struct (vaddr0To2, t1, t2, t3) = tmpVars4 bld oprSz
  let mask = numI32 (((int oprSz) >>> 3) - 1) oprSz
  let inline loadBaseAddr oprSz baseOffset =
    let maskLoad = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
    AST.loadLE oprSz (baseOffset .& numI32 maskLoad oprSz)
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := baseOffset)
  bld <+ (vaddr0To2 := t1 .& mask <+> (transBigEndianCPU bld oprSz))
  bld <+ (t2 := ((amtOp vaddr0To2 mask) .+ AST.num1 oprSz) .* numI32 8 oprSz)
  bld <+ (t3 := (amtOp (mask .- vaddr0To2) mask) .* numI32 8 oprSz)
  let result = shifterLoad memShf regShf rRt t2 t3 (loadBaseAddr oprSz t1)
  bld <+ (rt := if is32Bit bld then result else result |> AST.sext 64<rt>)
  advancePC bld
  bld --!> insLen

let recip ins insLen bld =
  let fd, fs = getTwoOprs ins |> transTwoOprs ins bld
  let sz = bld.RegType
  let fnum = AST.cast CastKind.SIntToFloat sz (AST.num1 sz)
  bld <!-- (ins.Address, insLen)
  bld <+ (fd := AST.fdiv fnum fs)
  bld --!> insLen

let rsqrt ins insLen bld =
  let fd, fs = getTwoOprs ins
  bld <!-- (ins.Address, insLen)
  match ins.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoSingleFP bld (fd, fs)
    let fnum = AST.cast CastKind.SIntToFloat 32<rt> (AST.num1 32<rt>)
    bld <+ (fd := AST.fdiv fnum (AST.fsqrt fs))
  | _ ->
    let fdB, fdA = transOprToFPPair bld fd
    let fs = transOprToFPPairConcat bld fs
    let fnum = AST.cast CastKind.SIntToFloat 64<rt> (AST.num1 64<rt>)
    let result = AST.fdiv fnum (AST.fsqrt fs)
    dstAssignForFP fdB fdA result bld
  advancePC bld
  bld --!> insLen

let translate (ins: Instruction) insLen (bld: LowUIRBuilder) =
  match ins.Opcode with
  | Op.ABS -> abs ins insLen bld
  | Op.ADD -> add ins insLen bld
  | Op.ADDIU -> addiu ins insLen bld
  | Op.ADDU -> addu ins insLen bld
  | Op.AND -> logAnd ins insLen bld
  | Op.ANDI -> andi ins insLen bld
  | Op.AUI -> aui ins insLen bld
  | Op.B -> b ins insLen bld
  | Op.BAL -> bal ins insLen bld
  | Op.BC1F -> bc1f ins insLen bld
  | Op.BC1T -> bc1t ins insLen bld
  | Op.BEQ | Op.BEQL -> beq ins insLen bld
  | Op.BGEZ -> bgez ins insLen bld
  | Op.BGEZAL -> bgezal ins insLen bld
  | Op.BGTZ -> bgtz ins insLen bld
  | Op.BLEZ -> blez ins insLen bld
  | Op.BLTZ -> bltz ins insLen bld
  | Op.BLTZAL -> bltzal ins insLen bld
  | Op.BNE | Op.BNEL -> bne ins insLen bld
  | Op.BREAK -> sideEffects ins insLen bld Breakpoint
  | Op.C -> cCond ins insLen bld
  | Op.CFC1 -> cfc1 ins insLen bld
  | Op.CTC1 -> ctc1 ins insLen bld
  | Op.CLZ -> clz ins insLen bld
  | Op.CVTD -> cvtd ins insLen bld
  | Op.CVTL -> cvtl ins insLen bld
  | Op.CVTS -> cvts ins insLen bld
  | Op.CVTW -> cvtw ins insLen bld
  | Op.DADD -> dadd ins insLen bld
  | Op.DADDU -> daddu ins insLen bld
  | Op.DADDIU -> daddiu ins insLen bld
  | Op.DCLZ -> dclz ins insLen bld
  | Op.DDIV -> ddiv ins insLen bld
  | Op.DMFC1 -> dmfc1 ins insLen bld
  | Op.DMTC1 -> dmtc1 ins insLen bld
  | Op.DEXT -> dext ins insLen bld
  | Op.DEXTM -> dextx ins insLen checkDEXTMPosSize bld
  | Op.DEXTU -> dextx ins insLen checkDEXTUPosSize bld
  | Op.DINS -> dins ins insLen bld
  | Op.DINSM -> dinsx ins insLen checkDINSMPosSize bld
  | Op.DINSU -> dinsx ins insLen checkDINSUPosSize bld
  | Op.DIV -> div ins insLen bld
  | Op.DIVU -> divu ins insLen bld
  | Op.DDIVU -> ddivu ins insLen bld
  | Op.DMULT -> dmul ins insLen bld true
  | Op.DMULTU -> dmul ins insLen bld false
  | Op.DROTR -> drotr ins insLen bld
  | Op.DROTR32 -> drotr32 ins insLen bld
  | Op.DROTRV -> drotrv ins insLen bld
  | Op.DSBH -> dsbh ins insLen bld
  | Op.DSHD -> dshd ins insLen bld
  | Op.DSLL -> dShiftLeftRight ins insLen bld (<<)
  | Op.DSLL32 -> dShiftLeftRight32 ins insLen bld (<<)
  | Op.DSLLV -> dShiftLeftRightVar ins insLen bld (<<)
  | Op.DSRA -> dsra ins insLen bld
  | Op.DSRAV -> dsrav ins insLen bld
  | Op.DSRA32 -> dsra32 ins insLen bld
  | Op.DSRL -> dShiftLeftRight ins insLen bld (>>)
  | Op.DSRL32 -> dShiftLeftRight32 ins insLen bld (>>)
  | Op.DSRLV -> dShiftLeftRightVar ins insLen bld (>>)
  | Op.DSUBU -> dsubu ins insLen bld
  | Op.EHB -> nop ins insLen bld
  | Op.EXT -> ext ins insLen bld
  | Op.INS -> insert ins insLen bld
  | Op.J -> j ins insLen bld
  | Op.JAL -> jal ins insLen bld
  | Op.JALR | Op.JALRHB -> jalr ins insLen bld
  | Op.JR | Op.JRHB -> jr ins insLen bld
  | Op.LD | Op.LB | Op.LH | Op.LW -> loadSigned ins insLen bld
  | Op.LBU | Op.LHU | Op.LWU -> loadUnsigned ins insLen bld
  | Op.LL | Op.LLD -> loadLinked ins insLen bld
  | Op.SDC1 | Op.SDXC1 -> sldc1 ins insLen bld true
  | Op.LDC1 | Op.LDXC1 -> sldc1 ins insLen bld false
  | Op.SWC1 | Op.SWXC1 -> slwc1 ins insLen bld true
  | Op.LWC1 | Op.LWXC1 -> slwc1 ins insLen bld false
  | Op.LUI -> lui ins insLen bld
  | Op.LDL -> loadLeftRight ins insLen bld (<<) (>>) (.&) 64<rt>
  | Op.LDR -> loadLeftRight ins insLen bld (>>) (<<) (<+>) 64<rt>
  | Op.LWL -> loadLeftRight ins insLen bld (<<) (>>) (.&) 32<rt>
  | Op.LWR -> loadLeftRight ins insLen bld (>>) (<<) (<+>) 32<rt>
  | Op.MADD -> mAddSub ins insLen bld true
  | Op.MADDU -> mAdduSubu ins insLen bld true
  | Op.MFHI -> mfhi ins insLen bld
  | Op.MFLO -> mflo ins insLen bld
  | Op.MFHC1 -> mfhc1 ins insLen bld
  | Op.MTHC1 -> mthc1 ins insLen bld
  | Op.MTHI -> mthi ins insLen bld
  | Op.MTLO -> mtlo ins insLen bld
  | Op.MFC1 -> mfc1 ins insLen bld
  | Op.MOV -> mov ins insLen bld
  | Op.MOVT -> movt ins insLen bld
  | Op.MOVF -> movf ins insLen bld
  | Op.MOVZ -> movzOrn ins insLen bld (==)
  | Op.MOVN -> movzOrn ins insLen bld (!=)
  | Op.MSUB ->  mAddSub ins insLen bld false
  | Op.MSUBU -> mAdduSubu ins insLen bld false
  | Op.MTC1 -> mtc1 ins insLen bld
  | Op.MUL -> mul ins insLen bld
  | Op.MULT -> mult ins insLen bld
  | Op.MULTU -> multu ins insLen bld
  | Op.NEG -> neg ins insLen bld
  | Op.NOP -> nop ins insLen bld
  | Op.NOR -> nor ins insLen bld
  | Op.OR -> logOr ins insLen bld
  | Op.ORI -> ori ins insLen bld
  | Op.PAUSE -> pause ins insLen bld
  | Op.PREF | Op.PREFE | Op.PREFX -> nop ins insLen bld
  | Op.RDHWR -> sideEffects ins insLen bld ProcessorID
  | Op.ROTR -> rotr ins insLen bld
  | Op.ROTRV -> rotrv ins insLen bld
  | Op.RECIP -> recip ins insLen bld
  | Op.RSQRT -> rsqrt ins insLen bld
  | Op.SLL -> shiftLeftRight ins insLen bld (<<)
  | Op.SLLV -> shiftLeftRightVar ins insLen bld (<<)
  | Op.SLT -> sltAndU ins insLen bld (?<)
  | Op.SLTU -> sltAndU ins insLen bld (.<)
  | Op.SLTI -> sltiAndU ins insLen bld (?<)
  | Op.SLTIU -> sltiAndU ins insLen bld (.<)
  | Op.SSNOP -> nop ins insLen bld
  | Op.SB -> store ins insLen 8<rt> bld
  | Op.SC -> storeConditional ins insLen 32<rt> bld
  | Op.SCD -> storeConditional ins insLen 64<rt> bld
  | Op.SD -> store ins insLen 64<rt> bld
  | Op.SEB -> seb ins insLen bld
  | Op.SEH -> seh ins insLen bld
  | Op.SH -> store ins insLen 16<rt> bld
  | Op.SQRT -> sqrt ins insLen bld
  | Op.SRA -> sra ins insLen bld
  | Op.SRAV -> srav ins insLen bld
  | Op.SRL -> shiftLeftRight ins insLen bld (>>)
  | Op.SRLV -> shiftLeftRightVar ins insLen bld (>>)
  | Op.SUB -> sub ins insLen bld
  | Op.SUBU -> subu ins insLen bld
  | Op.SW -> store ins insLen 32<rt> bld
  | Op.SDL -> storeLeftRight ins insLen bld (<<) (>>) (.&) 64<rt>
  | Op.SDR -> storeLeftRight ins insLen bld (>>) (<<) (<+>) 64<rt>
  | Op.SWL -> storeLeftRight ins insLen bld (<<) (>>) (.&) 32<rt>
  | Op.SWR -> storeLeftRight ins insLen bld (>>) (<<) (<+>) 32<rt>
  | Op.SYNC | Op.SYNCI -> nop ins insLen bld
  | Op.SYSCALL -> syscall ins insLen bld
  | Op.TEQ -> teq ins insLen bld
  | Op.TEQI -> teqi ins insLen bld
  | Op.TRUNCW -> truncw ins insLen bld
  | Op.TRUNCL -> truncl ins insLen bld
  | Op.XOR -> logXor ins insLen bld
  | Op.XORI -> xori ins insLen bld
  | Op.WSBH -> wsbh ins insLen bld
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL ->
    sideEffects ins insLen bld UnsupportedExtension
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)
