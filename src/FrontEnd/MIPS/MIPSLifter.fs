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
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS

let inline getRegVar (ctxt: TranslationContext) reg =
  Register.toRegID reg |> ctxt.GetRegVar

let inline (:=) dst src =
  match dst with
  | { E = Var (_, rid, _) } when rid = Register.toRegID Register.R0 ->
    dst := dst (* Prevent setting r0. Our optimizer will remove this anyways. *)
  | _ ->
    dst := src

let transOprToExpr insInfo ctxt = function
  | OpReg reg -> getRegVar ctxt reg
  | OpImm imm
  | OpShiftAmount imm -> numU64 imm ctxt.WordBitSize
  | OpMem (b, Imm o, sz) ->
    if ctxt.Endianness = Endian.Little then
      AST.loadLE sz (getRegVar ctxt b .+ numI64 o ctxt.WordBitSize)
    else AST.loadBE sz (getRegVar ctxt b .+ numI64 o ctxt.WordBitSize)
  | OpMem (b, Reg o, sz) ->
    if ctxt.Endianness = Endian.Little then
      AST.loadLE sz (getRegVar ctxt b .+ getRegVar ctxt o)
    else AST.loadBE sz (getRegVar ctxt b .+ getRegVar ctxt o)
  | OpAddr (Relative o) ->
    numI64 (int64 insInfo.Address + o) ctxt.WordBitSize
  | GoToLabel _ -> raise InvalidOperandException

let private is32Bit (ctxt: TranslationContext) = ctxt.WordBitSize = 32<rt>

let private transOprToFPConvert (dstFmt: InsInfo) ctxt = function
  | OpReg reg ->
    if is32Bit ctxt then getRegVar ctxt reg
    else
      match dstFmt.Fmt with
      | Some Fmt.S | Some Fmt.W -> getRegVar ctxt reg |> AST.xtlo 32<rt>
      | Some Fmt.D | Some Fmt.L -> getRegVar ctxt reg
      | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandException

let private transOprToFP ctxt = function
  | OpReg reg ->
    if is32Bit ctxt then getRegVar ctxt reg
    else getRegVar ctxt reg |> AST.xtlo 32<rt>
  | _ -> raise InvalidOperandException

let private transTwoFP ctxt (o1, o2) =
  transOprToFP ctxt o1, transOprToFP ctxt o2

let private transThreeFP ctxt (o1, o2, o3) =
  transOprToFP ctxt o1, transOprToFP ctxt o2, transOprToFP ctxt o3

let private transFourFP ctxt (o1, o2, o3, o4) =
  transOprToFP ctxt o1, transOprToFP ctxt o2, transOprToFP ctxt o3,
  transOprToFP ctxt o4

let transTwoOprFPConvert insInfo ctxt (o1, o2) =
  transOprToFPConvert insInfo ctxt o1, transOprToFPConvert insInfo ctxt o2

let private transOprToFPPair ctxt = function
  | OpReg reg ->
    if is32Bit ctxt then
      getRegVar ctxt (Register.getFPPairReg reg), getRegVar ctxt reg
    else AST.b0, getRegVar ctxt reg
  | _ -> raise InvalidOperandException

let private transOprToFPPairConcat ctxt = function
  | OpReg reg ->
    if is32Bit ctxt then
      AST.concat (getRegVar ctxt (Register.getFPPairReg reg))
        (getRegVar ctxt reg)
    else getRegVar ctxt reg
  | _ -> raise InvalidOperandException

let private dstAssignForFP dstB dstA result ctxt ir =
  if is32Bit ctxt then
    let srcB = AST.xthi 32<rt> result
    let srcA = AST.xtlo 32<rt> result
    !!ir (dstA := srcA)
    !!ir (dstB := srcB)
  else
    !!ir (dstA := result)

let private fpneg ir oprSz reg =
  let mask =
    if oprSz = 32<rt> then numU64 0x80000000UL oprSz
    else numU64 0x8000000000000000UL oprSz
  !!ir (reg := reg <+> mask)

let transOprToImm = function
  | OpImm imm
  | OpShiftAmount imm -> imm
  | _ -> raise InvalidOperandException

let transOprToImmToInt = function
  | OpImm imm
  | OpShiftAmount imm -> int imm
  | _ -> raise InvalidOperandException

let transOprToBaseOffset ctxt = function
  | OpMem (b, Imm o, _) -> getRegVar ctxt b .+ numI64 o ctxt.WordBitSize
  | OpMem (b, Reg o, _) -> getRegVar ctxt b .+ getRegVar ctxt o
  | _ -> raise InvalidOperandException

let getOneOpr insInfo =
  match insInfo.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs insInfo =
  match insInfo.Operands with
  | TwoOperands (o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs insInfo =
  match insInfo.Operands with
  | ThreeOperands (o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let getFourOprs insInfo =
  match insInfo.Operands with
  | FourOperands (o1, o2, o3, o4) -> o1, o2, o3, o4
  | _ -> raise InvalidOperandException

let transOneOpr insInfo ctxt opr =
  transOprToExpr insInfo ctxt opr

let transTwoOprs insInfo ctxt (o1, o2) =
  transOprToExpr insInfo ctxt o1, transOprToExpr insInfo ctxt o2

let transThreeOprs insInfo ctxt (o1, o2, o3) =
  transOprToExpr insInfo ctxt o1,
  transOprToExpr insInfo ctxt o2,
  transOprToExpr insInfo ctxt o3

let transFourOprs insInfo ctxt (o1, o2, o3, o4) =
  transOprToExpr insInfo ctxt o1,
  transOprToExpr insInfo ctxt o2,
  transOprToExpr insInfo ctxt o3,
  transOprToExpr insInfo ctxt o4

let private transFPConcatTwoOprs ctxt (o1, o2) =
  transOprToFPPairConcat ctxt o1, transOprToFPPairConcat ctxt o2

let private transFPConcatThreeOprs ctxt (o1, o2, o3) =
  transOprToFPPairConcat ctxt o1,
  transOprToFPPairConcat ctxt o2,
  transOprToFPPairConcat ctxt o3

let roundToInt ctxt src oprSz =
  let fcsr = getRegVar ctxt R.FCSR
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

let private transBigEndianCPU (ctxt: TranslationContext) opSz =
  match ctxt.Endianness, opSz with
  | Endian.Little, 32<rt> -> AST.num0 32<rt>
  | Endian.Big, 32<rt> -> numI32 0b11 32<rt>
  | Endian.Little, 64<rt> -> AST.num0 64<rt>
  | Endian.Big, 64<rt> -> numI32 0b111 64<rt>
  | _ -> raise InvalidOperandException

let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

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

let private subNormal oprSz src1 src2 result ir =
  let struct (qNaNBox, sNaNBox, sqNaNBox, exponent) = tmpVars4 ir 1<rt>
  let struct (sign, isNaNCheck) = tmpVars2 ir 1<rt>
  let struct (mantissa, signalBit) = tmpVars2 ir oprSz
  !!ir (mantissa := getMantissa result oprSz)
  !!ir (exponent := getExponentFull result oprSz)
  !!ir (signalBit := getSignalBit result oprSz)
  !!ir (isNaNCheck := isNaN oprSz exponent mantissa)
  !!ir (qNaNBox := isQNaN oprSz signalBit isNaNCheck)
  !!ir (sNaNBox := isSNaN oprSz signalBit isNaNCheck)
  let mantissa1 = getMantissa src1 oprSz
  let mantissa2 = getMantissa src2 oprSz
  let infChk =
    AST.not (isInfinity oprSz (getExponentFull src1 oprSz) mantissa1
    .| isInfinity oprSz (getExponentFull src2 oprSz) mantissa2)
  !!ir (sign := AST.xthi 1<rt> result .& infChk)
  !!ir (sqNaNBox := qNaNBox .| sNaNBox)
  !!ir (result :=
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

let divNormal oprSz src1 src2 result ir =
  let struct (exponent, isNaNCheck, sign) = tmpVars3 ir 1<rt>
  let struct (mantissa, signalBit) = tmpVars2 ir oprSz
  !!ir (sign := AST.xthi 1<rt> result)
  !!ir (mantissa := getMantissa result oprSz)
  !!ir (signalBit := getSignalBit result oprSz)
  !!ir (exponent := getExponentFull result oprSz)
  !!ir (isNaNCheck := isNaN oprSz exponent mantissa)
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
  !!ir (result := AST.ite (src1Zero .& src2Zero) qNaNVal
                    (AST.ite qNan qNaNWithSign
                      (AST.ite sNan sNaNWithSign result)))

let private normalizeValue oprSz result ir =
  let struct (qNaNBox, sNaNBox, infBox, exponent) = tmpVars4 ir 1<rt>
  let struct (isNaNCheck, sign) = tmpVars2 ir 1<rt>
  !!ir (exponent := getExponentFull result oprSz)
  let struct (mantissa, signalBit) = tmpVars2 ir oprSz
  !!ir (mantissa := getMantissa result oprSz)
  !!ir (isNaNCheck := isNaN oprSz exponent mantissa)
  !!ir (signalBit := getSignalBit result oprSz)
  !!ir (qNaNBox := isQNaN oprSz signalBit isNaNCheck)
  !!ir (sNaNBox := isSNaN oprSz signalBit isNaNCheck)
  !!ir (infBox := isInfinity oprSz exponent mantissa)
  !!ir (sign := AST.xthi 1<rt> result)
  let condBox = qNaNBox .| sNaNBox .| infBox
  !!ir (result :=
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

let advancePC (ctxt: TranslationContext) ir =
  if ctxt.DelayedBranch = InterJmpKind.NotAJmp then
    () (* Do nothing, because IEMark will advance PC. *)
  else
    let nPC = getRegVar ctxt R.NPC
    !!ir (AST.interjmp nPC ctxt.DelayedBranch)
    ctxt.DelayedBranch <- InterJmpKind.NotAJmp

let updatePCCond ctxt offset cond kind ir =
  let lblTrueCase = !%ir "TrueCase"
  let lblFalseCase = !%ir "FalseCase"
  let lblEnd = !%ir "End"
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  ctxt.DelayedBranch <- kind
  !!ir (AST.cjmp cond (AST.name lblTrueCase) (AST.name lblFalseCase))
  !!ir (AST.lmark lblTrueCase)
  !!ir (nPC := offset)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblFalseCase)
  !!ir (nPC := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (AST.lmark lblEnd)

let updateRAPCCond ctxt nAddr offset cond kind ir =
  let lblTrueCase = !%ir "TrueCase"
  let lblFalseCase = !%ir "FalseCase"
  let lblEnd = !%ir "End"
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  ctxt.DelayedBranch <- kind
  !!ir (AST.cjmp cond (AST.name lblTrueCase) (AST.name lblFalseCase))
  !!ir (AST.lmark lblTrueCase)
  !!ir (nPC := offset)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblFalseCase)
  !!ir (nPC := nAddr)
  !!ir (AST.lmark lblEnd)

let private signExtLo64 expr = AST.xtlo 32<rt> expr |> AST.sext 64<rt>

let private signExtHi64 expr = AST.xthi 32<rt> expr |> AST.sext 64<rt>

let private getMask size = (1L <<< size) - 1L

let private shifterLoad fstShf sndShf rRt t1 t2 t3 =
  (sndShf (fstShf rRt t1) t1) .| (fstShf t3 t2)

let private shifterStore fstShf sndShf rRt t1 t2 t3 =
  (fstShf (sndShf t3 t2) t2) .| (sndShf rRt t1)

let private mul64BitReg src1 src2 ir isSign =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 ir 64<rt>
  let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
  let struct (src1IsNeg, src2IsNeg, signBit) = tmpVars3 ir 1<rt>
  let n32 = numI32 32 64<rt>
  let mask32 = numI64 0xFFFFFFFFL 64<rt>
  if isSign then
    !!ir (src1IsNeg := AST.xthi 1<rt> src1)
    !!ir (src2IsNeg := AST.xthi 1<rt> src2)
    !!ir (src1 := AST.ite src1IsNeg (AST.neg src1) src1)
    !!ir (src2 := AST.ite src2IsNeg (AST.neg src2) src2)
  else ()
  !!ir (hiSrc1 := (src1 >> n32) .& mask32) (* SRC1[63:32] *)
  !!ir (loSrc1 := src1 .& mask32) (* SRC1[31:0] *)
  !!ir (hiSrc2 := (src2 >> n32) .& mask32) (* SRC2[63:32] *)
  !!ir (loSrc2 := src2 .& mask32) (* SRC2[31:0] *)
  let pHigh = hiSrc1 .* hiSrc2
  let pMid= (hiSrc1 .* loSrc2) .+ (loSrc1 .* hiSrc2)
  let pLow = loSrc1 .* loSrc2
  let overFlowBit = checkOverfolwOnDMul (hiSrc1 .* loSrc2) (loSrc1 .* hiSrc2)
  let high = pHigh .+ ((pMid .+ (pLow >> n32)) >> n32) .+ overFlowBit
  let low = pLow .+ ((pMid .& mask32) << n32)
  if isSign then
    !!ir (signBit := src1IsNeg <+> src2IsNeg)
    !!ir (tHigh := AST.ite signBit (AST.not high) high)
    !!ir (tLow := AST.ite signBit (AST.neg low) low)
  else
    !!ir (tHigh := high)
    !!ir (tLow := low)
  struct (tHigh, tLow)

let abs insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.D | Some Fmt.PS ->
    let fdB, fdA = transOprToFPPair ctxt fd
    let fs = transOprToFPPairConcat ctxt fs
    fpneg ir 64<rt> fs
    dstAssignForFP fdB fdA fs ctxt ir
  | _ ->
    let fd, fs = transTwoFP ctxt (fd, fs)
    fpneg ir 32<rt> fs
    !!ir (fd := fs)
  advancePC ctxt ir
  !>ir insLen

let private reDupSrc opr1 opr2 expr1 expr2 tmp1 tmp2 ir =
  if opr1 = opr2 then
    !!ir (tmp1 := expr1)
    !!ir (tmp2 := tmp1)
  else
    !!ir (tmp1 := expr1)
    !!ir (tmp2 := expr2)

let add insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let dst, src1, src2 = getThreeOprs insInfo
  match insInfo.Fmt with
  | None ->
    let lblL0 = !%ir "L0"
    let lblL1 = !%ir "L1"
    let lblEnd = !%ir "End"
    let rd, rs, rt = transThreeOprs insInfo ctxt (dst, src1, src2)
    let result = if is32Bit ctxt then rs .+ rt else signExtLo64 (rs .+ rt)
    let cond = checkOverfolwOnAdd rs rt result
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "int overflow"))
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (rd := result)
    !!ir (AST.lmark lblEnd)
  | Some Fmt.S ->
    let fd, fs, ft = transThreeFP ctxt (dst, src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 32<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 ir
    !!ir (result := AST.fadd tSrc1 tSrc2)
    normalizeValue 32<rt> result ir
    !!ir (fd := result)
  | _ ->
    let fdB, fdA = transOprToFPPair ctxt dst
    let fs, ft = transFPConcatTwoOprs ctxt (src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 64<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 ir
    !!ir (result := AST.fadd tSrc1 tSrc2)
    normalizeValue 64<rt> result ir
    dstAssignForFP fdB fdA result ctxt ir
  advancePC ctxt ir
  !>ir insLen

let addiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = if is32Bit ctxt then rs .+ imm else signExtLo64 (rs .+ imm)
  !<ir insLen
  !!ir (rt := result)
  advancePC ctxt ir
  !>ir insLen

let addu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = if is32Bit ctxt then rs .+ rt else signExtLo64 (rs .+ rt)
  !<ir insLen
  !!ir (rd := result)
  advancePC ctxt ir
  !>ir insLen

let logAnd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs .& rt)
  advancePC ctxt ir
  !>ir insLen

let andi insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := rs .& imm)
  advancePC ctxt ir
  !>ir insLen

let aui insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let imm = imm << numI32 16 ctxt.WordBitSize
  !<ir insLen
  !!ir (rt := rs .+ imm)
  advancePC ctxt ir
  !>ir insLen

let b insInfo insLen ctxt =
  let ir = !*ctxt
  let nPC = getRegVar ctxt R.NPC
  let offset = getOneOpr insInfo |> transOneOpr insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.Base
  !<ir insLen
  !!ir (nPC := offset)
  !>ir insLen

let bal insInfo insLen ctxt =
  let ir = !*ctxt
  let offset = getOneOpr insInfo |> transOneOpr insInfo ctxt
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  ctxt.DelayedBranch <- InterJmpKind.IsCall
  !<ir insLen
  !!ir (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (nPC := offset)
  !>ir insLen

let private fpConditionCode cc ctxt =
  let fcsr = getRegVar ctxt R.FCSR
  if cc = 0 then (fcsr .& numU32 0x800000u 32<rt>) == numU32 0x800000u 32<rt>
  else
    let num = numU32 0x1000000u 32<rt> << numI32 cc 32<rt>
    (fcsr .& num) == num

let bc1f insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match insInfo.Operands with
  | OneOperand off ->
    let offset = transOneOpr insInfo ctxt off
    let cond = AST.not (fpConditionCode 0 ctxt)
    updatePCCond ctxt offset cond InterJmpKind.Base ir
  | _ ->
    let cc, offset = getTwoOprs insInfo
    let offset = transOprToExpr insInfo ctxt offset
    let cc = transOprToImmToInt cc
    let cond = AST.not (fpConditionCode cc ctxt)
    updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bc1t insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match insInfo.Operands with
  | OneOperand off ->
    let offset = transOneOpr insInfo ctxt off
    let cond = fpConditionCode 0 ctxt
    updatePCCond ctxt offset cond InterJmpKind.Base ir
  | _ ->
    let cc, offset = getTwoOprs insInfo
    let offset = transOprToExpr insInfo ctxt offset
    let cc = transOprToImmToInt cc
    let cond = fpConditionCode cc ctxt
    updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let beq insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs == rt
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let blez insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.sle rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bltz insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.slt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bltzal insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let pc = getRegVar ctxt R.PC
  let nAddr = !+ir ctxt.WordBitSize
  let cond = AST.slt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (nAddr := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (getRegVar ctxt R.R31 := nAddr)
  updateRAPCCond ctxt nAddr offset cond InterJmpKind.IsCall ir
  !>ir insLen

let bgez insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.sge rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bgezal insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let pc = getRegVar ctxt R.PC
  let nAddr = !+ir ctxt.WordBitSize
  let cond = AST.sge rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (nAddr := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (getRegVar ctxt R.R31 := nAddr)
  updateRAPCCond ctxt nAddr offset cond InterJmpKind.IsCall ir
  !>ir insLen

let bgtz insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, offset = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let cond = AST.sgt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let bne insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs != rt
  !<ir insLen
  updatePCCond ctxt offset cond InterJmpKind.Base ir
  !>ir insLen

let setFPConditionCode ctxt cc tf ir =
  let insertBit = AST.xtlo 32<rt> tf
  let fcsr = getRegVar ctxt R.FCSR
  if cc = 0 then
    let shf1 = numI32 23 32<rt>
    let mask1 = numU32 0xFF000000u 32<rt>
    let mask2 = numU32 0x7FFFFFu 32<rt>
    let insertBit = AST.xtlo 32<rt> tf
    !!ir (fcsr := (fcsr .& mask1) .| (insertBit << shf1) .| (fcsr .& mask2))
  else
    let shf2 = numI32 (24 + cc) 32<rt>
    let mask1 = numU32 0xFE000000u 32<rt> << numI32 cc 32<rt>
    let mask2 =
      (numU32 0xFFFFFFu 32<rt> << numI32 cc 32<rt>) .| numU32 0xFFu 32<rt>
    !!ir (fcsr := (fcsr .& mask1) .| (insertBit << shf2) .| (fcsr .& mask2))

let private getCCondOpr insInfo ctxt =
  match insInfo.Operands with
  | TwoOperands (fs, ft) ->
    let sameReg = fs = ft
    match insInfo.Fmt with
    | Some Fmt.PS | Some Fmt.D ->
      let fs, ft = transFPConcatTwoOprs ctxt (fs, ft)
      64<rt>, 0, fs, ft, sameReg
    | _ ->
      let fs, ft = transTwoFP ctxt (fs, ft)
      32<rt>, 0, fs, ft, sameReg
  | ThreeOperands (cc, fs, ft) ->
    let sameReg = fs = ft
    match insInfo.Fmt with
    | Some Fmt.PS | Some Fmt.D ->
      let cc = transOprToImmToInt cc
      let fs, ft = transFPConcatTwoOprs ctxt (fs ,ft)
      64<rt>, cc, fs, ft, sameReg
    | _ ->
      let cc = transOprToImmToInt cc
      let fs, ft = transTwoFP ctxt (fs, ft)
      32<rt>, cc, fs, ft, sameReg
  | _ -> raise InvalidOperandException

let cCond insInfo insLen ctxt =
  let ir = !*ctxt
  let oprSz, cc, fs, ft, sameReg = getCCondOpr insInfo ctxt
  let num0 = AST.num0 oprSz
  let num1 = AST.num1 oprSz
  let struct (tFs , tFt, mantissa) = tmpVars3 ir oprSz
  let struct (less, equal, unordered, condition) = tmpVars4 ir oprSz
  let struct (condNaN, exponent) = tmpVars2 ir 1<rt>
  let bit0, bit1, bit2 =
    match insInfo.Condition with
    | Some Condition.F | Some Condition.SF -> num0, num0, num0
    | Some Condition.UN | Some Condition.NGLE -> num1, num0, num0
    | Some Condition.EQ | Some Condition.SEQ -> num0, num1, num0
    | Some Condition.UEQ | Some Condition.NGL -> num1, num1, num0
    | Some Condition.OLT | Some Condition.LT -> num0, num0, num1
    | Some Condition.ULT | Some Condition.NGE -> num1, num0, num1
    | Some Condition.OLE | Some Condition.LE -> num0, num1, num1
    | Some Condition.ULE | Some Condition.NGT -> num1, num1, num1
    | _ -> raise InvalidOperandException
  !<ir insLen
  if sameReg then
    !!ir (tFs := fs)
    !!ir (tFt := tFs)
  else
    !!ir (tFs := fs)
    !!ir (tFt := ft)
  let zeroSameCondWithEqaul =
    if sameReg then AST.b1
    else ((tFs << num1) >> num1) == ((tFt << num1) >> num1)
  !!ir (condNaN :=
    if sameReg then
      !!ir (mantissa := getMantissa tFt oprSz)
      !!ir (exponent := getExponentFull tFt oprSz)
      AST.xtlo 1<rt> (exponent .& (mantissa != AST.num0 oprSz))
    else
      let src1Mantissa = getMantissa tFs oprSz
      let src2Mantissa = getMantissa tFt oprSz
      let src1Exponent = getExponentFull tFs oprSz
      let src2Exponent = getExponentFull tFt oprSz
      AST.xtlo 1<rt> (src1Exponent .& (src1Mantissa != AST.num0 oprSz)) .|
      AST.xtlo 1<rt> (src2Exponent .& (src2Mantissa != AST.num0 oprSz)))
  !!ir (less := AST.ite condNaN num0 (AST.ite (AST.flt tFs tFt) num1 num0))
  !!ir (equal :=
    AST.ite condNaN num0 (AST.ite zeroSameCondWithEqaul num1 num0))
  !!ir (unordered := AST.ite condNaN num1 num0)
  !!ir (condition := (bit2 .& less) .| (bit1 .& equal) .| (bit0 .& unordered))
  setFPConditionCode ctxt cc condition ir
  advancePC ctxt ir
  !>ir insLen

let ctc1 insInfo insLen ctxt=
  let ir = !*ctxt
  let rt, _ = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let fcsr = getRegVar ctxt R.FCSR
  !<ir insLen
  !!ir (fcsr := AST.xtlo 32<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let cfc1 insInfo insLen ctxt=
  let ir = !*ctxt
  let rt, _ = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let fcsr = getRegVar ctxt R.FCSR
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize fcsr)
  advancePC ctxt ir
  !>ir insLen

let clz insInfo insLen ctxt =
  let ir = !*ctxt
  let lblLoop = !%ir "Loop"
  let lblContinue = !%ir "Continue"
  let lblEnd = !%ir "End"
  let wordSz = ctxt.WordBitSize
  let rd, rs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let t = !+ir wordSz
  let n31 = numI32 31 wordSz
  !<ir insLen
  !!ir (t := n31)
  !!ir (AST.lmark lblLoop)
  let cond1 = rs >> t == AST.num1 wordSz
  !!ir (AST.cjmp cond1 (AST.name lblEnd) (AST.name lblContinue))
  !!ir (AST.lmark lblContinue)
  !!ir (t := t .- AST.num1 wordSz)
  let cond2 = t == numI32 -1 wordSz
  !!ir (AST.cjmp cond2 (AST.name lblEnd) (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (rd := n31 .- t)
  advancePC ctxt ir
  !>ir insLen

let cvtd insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let fdB, fdA = transOprToFPPair ctxt fd
  let result = !+ir 64<rt>
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.W ->
    let fs = transOprToFPConvert insInfo ctxt fs
    !!ir (result := AST.cast CastKind.SIntToFloat 64<rt> fs)
  | Some Fmt.S ->
    let fs = transOprToFPConvert insInfo ctxt fs
    !!ir (result := AST.cast CastKind.FloatCast 64<rt> fs)
  | _ ->
    let fs = transOprToFPPairConcat ctxt fs
    !!ir (result := AST.cast CastKind.SIntToFloat 64<rt> fs)
  normalizeValue 64<rt> result ir
  dstAssignForFP fdB fdA result ctxt ir
  advancePC ctxt ir
  !>ir insLen

let cvtw insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let intMax = numI32 0x7fffffff 32<rt>
  let intMin = numI32 0x80000000 32<rt>
  let exponent = !+ir 1<rt>
  !<ir insLen
  let struct (dst, src, inf, nan) =
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoOprFPConvert insInfo ctxt (fd, fs)
      !!ir (exponent := getExponentFull src 32<rt>)
      let mantissa = !+ir 32<rt>
      !!ir (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      dst, src, inf, nan
    | _ ->
      let dst = transOprToFPConvert insInfo ctxt fd
      let src = transOprToFPPairConcat ctxt fs
      !!ir (exponent := getExponentFull src 64<rt>)
      let mantissa = !+ir 64<rt>
      !!ir (mantissa := getMantissa src 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      dst, src, inf, nan
  !!ir (dst := roundToInt ctxt src 32<rt>)
  let outOfRange = AST.sgt dst intMax .| AST.slt dst intMin
  !!ir (dst := AST.ite (outOfRange .| inf .| nan) intMax dst)
  advancePC ctxt ir
  !>ir insLen

let cvtl insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let fdB, fdA = transOprToFPPair ctxt fd
  let eval = !+ir 64<rt>
  let exponent = !+ir 1<rt>
  let intMax = numI64 0x7fffffffffffffffL 64<rt>
  let intMin = numI64 0x8000000000000000L 64<rt>
  !<ir insLen
  let struct (src, inf, nan) =
    match insInfo.Fmt with
    | Some Fmt.S ->
      let src = transOprToFPConvert insInfo ctxt fs
      !!ir (exponent := getExponentFull src 32<rt>)
      let mantissa = !+ir 32<rt>
      !!ir (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      src, inf, nan
    | _ ->
      let src = transOprToFPPairConcat ctxt fs
      !!ir (exponent := getExponentFull src 64<rt>)
      let mantissa = !+ir 64<rt>
      !!ir (mantissa := getMantissa src 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      src, inf, nan
  !!ir (eval := roundToInt ctxt src 64<rt>)
  let outOfRange = AST.sgt eval intMax .| AST.slt eval intMin
  !!ir (eval := AST.ite (outOfRange .| inf .| nan) intMax eval)
  dstAssignForFP fdB fdA eval ctxt ir
  advancePC ctxt ir
  !>ir insLen

let cvts insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let fd = transOprToFPConvert insInfo ctxt fd
  let dst = if is32Bit ctxt then fd else AST.xtlo 32<rt> fd
  let result = !+ir 32<rt>
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.L ->
    let fs = transOprToFPPairConcat ctxt fs
    !!ir (result := AST.cast CastKind.SIntToFloat 32<rt> fs)
  | Some Fmt.D ->
    let fs = transOprToFPPairConcat ctxt fs
    !!ir (result := AST.cast CastKind.FloatCast 32<rt> fs)
  | _ ->
    let fs = transOprToFPConvert insInfo ctxt fs
    !!ir (result := AST.cast CastKind.SIntToFloat 32<rt> fs)
  normalizeValue 32<rt> result ir
  !!ir (dst := result)
  advancePC ctxt ir
  !>ir insLen

let dadd insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = checkOverfolwOnDadd rs rt (rs .+ rt)
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect (Exception "int overflow"))
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := rs .+ rt)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let daddu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs .+ rt)
  !!ir (rd := result)
  advancePC ctxt ir
  !>ir insLen

let daddiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs .+ imm)
  !!ir (rt := result)
  advancePC ctxt ir
  !>ir insLen

let dclz insInfo insLen ctxt =
  let ir = !*ctxt
  let lblLoop = !%ir "Loop"
  let lblContinue = !%ir "Continue"
  let lblEnd = !%ir "End"
  let wordSz = ctxt.WordBitSize
  let rd, rs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let t = !+ir wordSz
  let n63 = numI32 63 wordSz
  !<ir insLen
  !!ir (t := n63)
  !!ir (AST.lmark lblLoop)
  !!ir (AST.cjmp (rs >> t == AST.num1 wordSz)
                   (AST.name lblEnd) (AST.name lblContinue))
  !!ir (AST.lmark lblContinue)
  !!ir (t := t .- AST.num1 wordSz)
  !!ir (AST.cjmp (t == numI64 -1 wordSz)
                   (AST.name lblEnd) (AST.name lblLoop))
  !!ir (AST.lmark lblEnd)
  !!ir (rd := n63 .- t)
  advancePC ctxt ir
  !>ir insLen

let ddiv insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let struct (q, r) = tmpVars2 ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !<ir insLen
  !!ir (rt := AST.ite (rt == numI64 0 ctxt.WordBitSize)
                (AST.undef ctxt.WordBitSize "UNPREDICTABLE") rt)
  !!ir (q := AST.sdiv rs rt)
  !!ir (r := AST.smod rs rt)
  !!ir (lo := q)
  !!ir (hi := r)
  advancePC ctxt ir
  !>ir insLen

let dmfc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fs = transOprToFPPairConcat ctxt fs
  !<ir insLen
  !!ir (rt := fs)
  advancePC ctxt ir
  !>ir insLen

let dmtc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fsB, fsA = transOprToFPPair ctxt fs
  !<ir insLen
  dstAssignForFP fsB fsA rt ctxt ir
  advancePC ctxt ir
  !>ir insLen

let ddivu insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let struct (q, r) = tmpVars2 ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !<ir insLen
  !!ir (q := AST.div rs rt)
  !!ir (r := AST.(mod) rs rt)
  !!ir (lo := q)
  !!ir (hi := r)
  advancePC ctxt ir
  !>ir insLen

let checkDEXTPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 63 then ()
  else raise InvalidOperandException

let dext insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = transOprToImm pos |> int
  let size = transOprToImm size |> int
  checkDEXTPosSize pos size
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
  !<ir insLen
  !!ir (rt := mask .& rs |> AST.zext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

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

let dextx insInfo insLen posSizeCheckFn ctxt =
  let ir = !*ctxt
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = transOprToImm pos |> int
  let sz = transOprToImm size |> int
  posSizeCheckFn pos sz
  !<ir insLen
  if sz = 64 then if rt = rs then () else !!ir (rt := rs)
  else
    let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
    let result = rs .& numI64 (getMask sz) ctxt.WordBitSize
    !!ir (rt := result)
  advancePC ctxt ir
  !>ir insLen

let checkINSorExtPosSize pos size =
  let posSize = pos + size
  if 0 <= pos && pos < 32 &&
     0 < size && size <= 32 &&
     0 < posSize && posSize <= 32 then ()
  else raise InvalidOperandException

let dins insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
  !<ir insLen
  if pos = 0 && rt = rs then ()
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    !!ir (rt := rt' .| rs')
  advancePC ctxt ir
  !>ir insLen

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

let dinsx insInfo insLen posSizeCheckFn ctxt =
  let ir = !*ctxt
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  posSizeCheckFn pos size
  !<ir insLen
  if size = 64 then if rt = rs then () else !!ir (rt := rs)
  else
    let posExpr = numI32 pos ctxt.WordBitSize
    let mask = numI64 (getMask size) ctxt.WordBitSize
    let rs', rt' =
      if pos = 0 then rs .& mask, rt .& (AST.not mask)
      else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
    !!ir (rt := rt' .| rs')
  advancePC ctxt ir
  !>ir insLen

let div insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
    let hi = getRegVar ctxt R.HI
    let lo = getRegVar ctxt R.LO
    !!ir (rt := AST.ite (rt == numI64 0 ctxt.WordBitSize)
                  (AST.undef ctxt.WordBitSize "UNPREDICTABLE") rt)
    if is32Bit ctxt then
      !!ir (lo :=
        (AST.sext 64<rt> rs ?/ AST.sext 64<rt> rt) |> AST.xtlo 32<rt>)
      !!ir (hi :=
        (AST.sext 64<rt> rs ?% AST.sext 64<rt> rt) |> AST.xtlo 32<rt>)
    else
      let mask = numI64 0xFFFFFFFFL 64<rt>
      let q = (rs .& mask) ?/ (rt .& mask)
      let r = (rs .& mask) ?% (rt .& mask)
      !!ir (lo := signExtLo64 q)
      !!ir (hi := signExtLo64 r)
  | Some Fmt.D ->
    let fd, fs, ft = getThreeOprs insInfo
    let fdB, fdA = transOprToFPPair ctxt fd
    let src1, src2 = transFPConcatTwoOprs ctxt (fs, ft)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 64<rt>
    reDupSrc fs ft src1 src2 tSrc1 tSrc2 ir
    !!ir (result := AST.fdiv tSrc1 tSrc2)
    divNormal 64<rt> tSrc1 tSrc2 result ir
    dstAssignForFP fdB fdA result ctxt ir
  | _ ->
    let fd, fs, ft = getThreeOprs insInfo
    let dst, src1, src2 = transThreeFP ctxt (fd, fs, ft)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 32<rt>
    reDupSrc fs ft src1 src2 tSrc1 tSrc2 ir
    !!ir (result := AST.fdiv tSrc1 tSrc2)
    divNormal 32<rt> tSrc1 tSrc2 result ir
    !!ir (dst := result)
  advancePC ctxt ir
  !>ir insLen

let divu insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !<ir insLen
  !!ir (rt := AST.ite (rt == numI64 0 ctxt.WordBitSize)
                (AST.undef ctxt.WordBitSize "UNPREDICTABLE") rt)
  if is32Bit ctxt then
    let struct (extendRs, extendRt) = tmpVars2 ir 64<rt>
    !!ir (extendRs := AST.zext 64<rt> rs)
    !!ir (extendRt := AST.zext 64<rt> rt)
    !!ir (lo := (extendRs ./ extendRt) |> AST.xtlo 32<rt>)
    !!ir (hi := (extendRs .% extendRt) |> AST.xtlo 32<rt>)
  else
    let struct (maskRs, maskRt) = tmpVars2 ir 64<rt>
    let mask = numI64 0xFFFFFFFFL 64<rt>
    !!ir (maskRs := rs .& mask)
    !!ir (maskRt := rt .& mask)
    !!ir (lo := signExtLo64 (maskRs ./ maskRt))
    !!ir (hi := signExtLo64 (maskRs .% maskRt))
  advancePC ctxt ir
  !>ir insLen

let dmul insInfo insLen ctxt isSign =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let struct (high, low) = mul64BitReg rs rt ir isSign
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !<ir insLen
  !!ir (lo := low)
  !!ir (hi := high)
  advancePC ctxt ir
  !>ir insLen

let drotr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numU64 (transOprToImm sa) 64<rt>
  let size = numI32 64 64<rt>
  !<ir insLen
  !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC ctxt ir
  !>ir insLen

let drotr32 insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numU64 (transOprToImm sa) 64<rt> .+ numI32 32 64<rt>
  let size = numI32 64 64<rt>
  !<ir insLen
  !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC ctxt ir
  !>ir insLen

let drotrv insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = !+ir 64<rt>
  let size = numI32 64 64<rt>
  !<ir insLen
  !!ir (sa := rs .& numI32 0x3F 64<rt>)
  !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  advancePC ctxt ir
  !>ir insLen

let dsra insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rt ?>> sa |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let dsrav insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rt ?>> (rs .& numI32 63 64<rt>) |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let dsra32 insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  !<ir insLen
  !!ir (rd := rt ?>> sa |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let dShiftLeftRight32 insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = sa .+ numI32 32 64<rt>
  !<ir insLen
  !!ir (rd := shf rt sa |> AST.zext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let dShiftLeftRight insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := shf rt sa |> AST.zext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let dShiftLeftRightVar insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := shf rt (rs .& numI32 63 64<rt>) |> AST.zext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let dsubu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs .- rt)
  !!ir (rd := result)
  advancePC ctxt ir
  !>ir insLen

let ins insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = transOprToImm pos |> int
  let size = transOprToImm size |> int
  let msb = pos + size - 1
  let lsb = pos
  checkINSorExtPosSize pos size
  if lsb > msb then raise InvalidOperandException else ()
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let posExpr = numI32 pos ctxt.WordBitSize
  !<ir insLen
  let rs', rt' =
    if pos = 0 then rs .& mask, rt .& (AST.not mask)
    else (rs .& mask) << posExpr, rt .& (AST.not (mask << posExpr))
  !!ir (rt := rt' .| rs')
  advancePC ctxt ir
  !>ir insLen

let getJALROprs insInfo ctxt =
  match insInfo.Operands with
  | OneOperand opr ->
    struct (getRegVar ctxt R.R31, transOprToExpr insInfo ctxt opr)
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr insInfo ctxt o1, transOprToExpr insInfo ctxt o2)
  | _ -> raise InvalidOperandException

let j insInfo insLen ctxt =
  let ir = !*ctxt
  let nPC = getRegVar ctxt R.NPC
  let dest = getOneOpr insInfo |> transOprToExpr insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.Base
  !<ir insLen
  !!ir (nPC := dest)
  !>ir insLen

let jal insInfo insLen ctxt =
  let ir = !*ctxt
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  let lr = getRegVar ctxt R.R31
  let dest = getOneOpr insInfo |> transOprToExpr insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.IsCall
  !<ir insLen
  !!ir (lr := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (nPC := dest)
  !>ir insLen

let jalr insInfo insLen ctxt =
  let ir = !*ctxt
  let pc = getRegVar ctxt R.PC
  let nPC = getRegVar ctxt R.NPC
  let struct (lr, rs) = getJALROprs insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.IsCall
  !<ir insLen
  !!ir (lr := pc .+ numI32 8 ctxt.WordBitSize)
  !!ir (nPC := rs)
  !>ir insLen

let jr insInfo insLen ctxt =
  let ir = !*ctxt
  let nPC = getRegVar ctxt R.NPC
  let rs = getOneOpr insInfo |> transOneOpr insInfo ctxt
  ctxt.DelayedBranch <- InterJmpKind.Base
  !<ir insLen
  !!ir (nPC := rs)
  !>ir insLen

let loadSigned insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize mem)
  advancePC ctxt ir
  !>ir insLen

let loadUnsigned insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := AST.zext ctxt.WordBitSize mem)
  advancePC ctxt ir
  !>ir insLen

let loadLinked insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize mem)
  !!ir (AST.extCall <| AST.app "SetLLBit" [] ctxt.WordBitSize)
  advancePC ctxt ir
  !>ir insLen

let sldc1 insInfo insLen ctxt stORld =
  let ir = !*ctxt
  let ft, mem = getTwoOprs insInfo
  let ftB, ftA = transOprToFPPair ctxt ft
  let baseOffset = transOprToBaseOffset ctxt mem
  let bOff = !+ir ctxt.WordBitSize
  let memory = !+ir 64<rt>
  !<ir insLen
  !!ir (bOff := baseOffset)
  !!ir (memory := AST.loadLE 64<rt> bOff)
  if stORld then
    !!ir (AST.loadLE 64<rt> bOff :=
      if is32Bit ctxt then AST.concat ftB ftA else ftA)
  else dstAssignForFP ftB ftA memory ctxt ir
  advancePC ctxt ir
  !>ir insLen

let slwc1 insInfo insLen ctxt stORld =
  let ir = !*ctxt
  let ft, mem = getTwoOprs insInfo
  let ft = transOprToFP ctxt ft
  let mem = transOprToExpr insInfo ctxt mem
  let ft = if is32Bit ctxt then ft else AST.xtlo 32<rt> ft
  !<ir insLen
  if stORld then !!ir (mem := ft) else !!ir (ft := mem)
  advancePC ctxt ir
  !>ir insLen

let ext insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = transOprToImm pos |> int
  let size = transOprToImm size |> int
  let msbd = size - 1
  let lsb = pos
  checkINSorExtPosSize pos size
  if lsb + msbd > 31 then raise InvalidOperandException else ()
  let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
  !<ir insLen
  !!ir (rt := rs .& numI64 (getMask size) ctxt.WordBitSize)
  advancePC ctxt ir
  !>ir insLen

let lui insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  if is32Bit ctxt then
    !!ir (rt := AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>))
  else
    !!ir (rt := AST.sext 64<rt>
                  (AST.concat (AST.xtlo 16<rt> imm) (AST.num0 16<rt>)))
  advancePC ctxt ir
  !>ir insLen

let mAddSub insInfo insLen ctxt opFn =
  let ir = !*ctxt
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
    let op = if opFn then AST.add else AST.sub
    let result = !+ir 64<rt>
    let hi = getRegVar ctxt R.HI
    let lo = getRegVar ctxt R.LO
    if is32Bit ctxt then
      !!ir (result :=
        op (AST.concat hi lo) (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
      !!ir (hi := AST.xthi 32<rt> result)
      !!ir (lo := AST.xtlo 32<rt> result)
    else
      let mask = numU32 0xFFFFu 64<rt>
      let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
      !!ir (result := op hilo ((rs .& mask) .* (rt .& mask)))
      !!ir (hi := signExtHi64 result)
      !!ir (lo := signExtLo64 result)
  | Some Fmt.PS | Some Fmt.D ->
    let op = if opFn then AST.fadd else AST.fsub
    let fd, fr, fs, ft = getFourOprs insInfo
    let fdB, fdA = transOprToFPPair ctxt fd
    let fr, fs, ft = transFPConcatThreeOprs ctxt (fr, fs, ft)
    let result = op (AST.fmul fs ft) fr
    dstAssignForFP fdB fdA result ctxt ir
  | _ ->
    let op = if opFn then AST.fadd else AST.fsub
    let fd, fr, fs, ft = getFourOprs insInfo |> transFourFP ctxt
    let result = op (AST.fmul fs ft) fr
    !!ir (fd := result)
  advancePC ctxt ir
  !>ir insLen

let mAdduSubu insInfo insLen ctxt opFn =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result = !+ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let op = if opFn then AST.add else AST.sub
  !<ir insLen
  if is32Bit ctxt then
    !!ir (result :=
      op (AST.concat hi lo) (AST.zext 64<rt> rs .* AST.zext 64<rt> rt))
    !!ir (hi := AST.xthi 32<rt> result)
    !!ir (lo := AST.xtlo 32<rt> result)
  else
    let mask = numU32 0xFFFFu 64<rt>
    let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
    !!ir (result := op hilo ((rs .& mask) .* (rt .& mask)))
    !!ir (hi := AST.xthi 32<rt> result |> AST.zext 64<rt>)
    !!ir (lo := AST.xtlo 32<rt> result |> AST.zext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let mfhi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd = getOneOpr insInfo |> transOneOpr insInfo ctxt
  !<ir insLen
  !!ir (rd := getRegVar ctxt R.HI)
  advancePC ctxt ir
  !>ir insLen

let mflo insInfo insLen ctxt =
  let ir = !*ctxt
  let rd = getOneOpr insInfo |> transOneOpr insInfo ctxt
  !<ir insLen
  !!ir (rd := getRegVar ctxt R.LO)
  advancePC ctxt ir
  !>ir insLen

let mfhc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fsB, _ = transOprToFPPair ctxt fs
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize fsB)
  advancePC ctxt ir
  !>ir insLen

let mthc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fsB, _ = transOprToFPPair ctxt fs
  !<ir insLen
  !!ir (fsB := AST.xtlo 32<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let mthi insInfo insLen ctxt =
  let ir = !*ctxt
  let rs = getOneOpr insInfo |> transOneOpr insInfo ctxt
  let hi = getRegVar ctxt R.HI
  !<ir insLen
  !!ir (hi := rs)
  advancePC ctxt ir
  !>ir insLen

let mtlo insInfo insLen ctxt =
  let ir = !*ctxt
  let rs = getOneOpr insInfo |> transOneOpr insInfo ctxt
  let lo = getRegVar ctxt R.LO
  !<ir insLen
  !!ir (lo := rs)
  advancePC ctxt ir
  !>ir insLen

let mfc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fs = transOprToFP ctxt fs
  !<ir insLen
  !!ir (rt := AST.sext ctxt.WordBitSize fs)
  advancePC ctxt ir
  !>ir insLen

let mov insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoFP ctxt (fd, fs)
    !!ir (fd := fs)
  | Some Fmt.D ->
    let fdB, fdA = transOprToFPPair ctxt fd
    let fs = transOprToFPPairConcat ctxt fs
    let result = !+ir 64<rt>
    !!ir (result := fs)
    dstAssignForFP fdB fdA result ctxt ir
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let movt insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src, cc = getThreeOprs insInfo
  let cc = transOprToImmToInt cc
  let cond = fpConditionCode cc ctxt
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let dst, src = transTwoOprs insInfo ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  | Some Fmt.S ->
    let dst, src = transTwoFP ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair ctxt dst
    let srcB, srcA = transOprToFPPair ctxt src
    !!ir (dstB := AST.ite cond srcB dstB)
    !!ir (dstA := AST.ite cond srcA dstA)
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let movf insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src, cc = getThreeOprs insInfo
  let cc = transOprToImmToInt cc
  let cond = AST.not (fpConditionCode cc ctxt)
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let dst, src = transTwoOprs insInfo ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  | Some Fmt.S ->
    let dst, src = transTwoFP ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair ctxt dst
    let srcB, srcA = transOprToFPPair ctxt src
    !!ir (dstB := AST.ite cond srcB dstB)
    !!ir (dstA := AST.ite cond srcA dstA)
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let movzOrn insInfo insLen ctxt opFn =
  let ir = !*ctxt
  let dst, src, compare = getThreeOprs insInfo
  let compare = transOprToExpr insInfo ctxt compare
  let cond = opFn compare (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let dst, src = transTwoOprs insInfo ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  | Some Fmt.S ->
    let dst, src = transTwoFP ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair ctxt dst
    let src = transOprToFPPairConcat ctxt src
    !!ir (dstB := AST.ite cond (AST.xthi 32<rt> src) dstB)
    !!ir (dstA := AST.ite cond (AST.xtlo 32<rt> src) dstA)
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let mtc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fs = transOprToFP ctxt fs
  !<ir insLen
  !!ir (fs := AST.xtlo 32<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let mul insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src1, src2 = getThreeOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let dst, src1, src2 = transThreeOprs insInfo ctxt (dst, src1, src2)
    let hi = getRegVar ctxt R.HI
    let lo = getRegVar ctxt R.LO
    let result =
      if is32Bit ctxt then
        (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2) |> AST.xtlo 32<rt>
      else signExtLo64 (src1 .* src2)
    !!ir (dst := result)
    !!ir (hi := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
    !!ir (lo := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
  | Some Fmt.S ->
    let dst, fs, ft = transThreeFP ctxt (dst, src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 32<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 ir
    !!ir (result := AST.fmul tSrc1 tSrc2)
    normalizeValue 32<rt> result ir
    !!ir (dst := result)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair ctxt dst
    let fs, ft = transFPConcatTwoOprs ctxt (src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 64<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 ir
    !!ir (result := AST.fmul tSrc1 tSrc2)
    normalizeValue 64<rt> result ir
    dstAssignForFP dstB dstA result ctxt ir
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let mult insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let result = !+ir 64<rt>
  !<ir insLen
  let struct (low, high) =
    if is32Bit ctxt then
      !!ir (result := AST.sext 64<rt> rs .* AST.sext 64<rt> rt)
      result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
    else
      !!ir (result := (rs .& mask) .* (rt .& mask))
      signExtLo64 result, signExtHi64 result
  !!ir (lo := low)
  !!ir (hi := high)
  advancePC ctxt ir
  !>ir insLen

let multu insInfo insLen ctxt =
  let ir = !*ctxt
  let rs, rt = getTwoOprs insInfo
  let src1, src2 = transTwoOprs insInfo ctxt (rs ,rt)
  let struct (tRs , tRt) = tmpVars2 ir ctxt.WordBitSize
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let result = !+ir 64<rt>
  !<ir insLen
  reDupSrc rs rt src1 src2 tRs tRt ir
  let struct (low, high) =
    if is32Bit ctxt then
      !!ir (result := AST.zext 64<rt> tRs .* AST.zext 64<rt> tRt)
      result |> AST.xtlo 32<rt>, result |> AST.xthi 32<rt>
    else
      !!ir (result := (tRs .& mask) .* (tRt .& mask))
      signExtLo64 result, signExtHi64 result
  !!ir (lo := low)
  !!ir (hi := high)
  advancePC ctxt ir
  !>ir insLen

let neg insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.D | Some Fmt.PS ->
    let fd, fs = transFPConcatTwoOprs ctxt (fd, fs)
    fpneg ir 64<rt> fs
    !!ir (fd := fs)
  | _ ->
    let fd, fs = transTwoFP ctxt (fd, fs)
    fpneg ir 32<rt> fs
    !!ir (fd := fs)
  advancePC ctxt ir
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  advancePC ctxt ir
  !>ir insLen

let nor insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.not (rs .| rt))
  advancePC ctxt ir
  !>ir insLen

let logOr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs .| rt)
  advancePC ctxt ir
  !>ir insLen

let ori insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := rs .| imm)
  advancePC ctxt ir
  !>ir insLen

let pause insLen ctxt =
  let ir = !*ctxt
  let llbit = getRegVar ctxt R.LLBit
  let lblSpin = !%ir "Spin"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.lmark lblSpin)
  !!ir (AST.extCall <| AST.app "GetLLBit" [] ctxt.WordBitSize)
  !!ir (AST.cjmp (llbit == AST.b1) (AST.name lblSpin) (AST.name lblEnd))
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let rotr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo
  let rd, rt = transTwoOprs insInfo ctxt (rd, rt)
  let sa = numU64 (transOprToImm sa) 32<rt>
  let size = numI32 32 32<rt>
  !<ir insLen
  if is32Bit ctxt then
    !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  else
    !!ir (rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
                  (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let rotrv insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let sa = !+ir 32<rt>
  let size = numI32 32 32<rt>
  !<ir insLen
  !!ir (sa := AST.xtlo 32<rt> rs .& numI32 0x1F 32<rt>)
  if is32Bit ctxt then
    !!ir (rd := (rt << (size .- sa)) .| (rt >> sa))
  else
    !!ir (rd := ((AST.xtlo 32<rt> rt << (size .- sa)) .|
                  (AST.xtlo 32<rt> rt >> sa)) |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let store insInfo insLen width ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo width rt)
  advancePC ctxt ir
  !>ir insLen

let sqrt insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoFP ctxt (fd, fs)
    let cond = fs == numU32 0x80000000u 32<rt>
    !!ir (fd := AST.ite cond (numU32 0x80000000u 32<rt>) (AST.fsqrt fs))
  | _ ->
    let fdB, fdA = transOprToFPPair ctxt fd
    let fs = transOprToFPPairConcat ctxt fs
    let cond = fs == numU64 0x8000000000000000UL 64<rt>
    let result =
      AST.ite cond (numU64 0x8000000000000000UL 64<rt>) (AST.fsqrt fs)
    dstAssignForFP fdB fdA result ctxt ir
  advancePC ctxt ir
  !>ir insLen

let storeConditional insInfo insLen width ctxt =
  let ir = !*ctxt
  let lblInRMW = !%ir "InRMW"
  let lblEnd = !%ir "End"
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let llbit = getRegVar ctxt R.LLBit
  !<ir insLen
  !!ir (AST.extCall <| AST.app "GetLLBit" [] ctxt.WordBitSize)
  !!ir (AST.cjmp (llbit == AST.b1) (AST.name lblInRMW) (AST.name lblEnd))
  !!ir (AST.lmark lblInRMW)
  !!ir (mem := AST.xtlo width rt)
  !!ir (AST.lmark lblEnd)
  !!ir (rt := AST.zext ctxt.WordBitSize llbit)
  !!ir (AST.extCall <| AST.app "ClearLLBit" [] ctxt.WordBitSize)
  advancePC ctxt ir
  !>ir insLen

let storeLeftRight insInfo insLen ctxt memShf regShf amtOp oprSz =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt = transOprToExpr insInfo ctxt rt
  let rRt, baseOffset =
    if oprSz = 32<rt> then
      if is32Bit ctxt then rt, baseOffset
      else AST.xtlo 32<rt> rt, AST.xtlo 32<rt> baseOffset
    else rt, baseOffset
  let baseOff = !+ir ctxt.WordBitSize
  let maskLd = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
  let struct (t1, t2, t3, baseMask) = tmpVars4 ir oprSz
  let mask = numI32 (((int oprSz) >>> 3) - 1) oprSz
  let vaddr0To2 = (baseOff .& mask) <+> (transBigEndianCPU ctxt oprSz)
  let baseAddress = AST.loadLE oprSz baseMask
  !<ir insLen
  !!ir (baseOff := baseOffset)
  !!ir (baseMask := baseOff .& numI32 maskLd oprSz)
  !!ir (t1 := vaddr0To2)
  !!ir (t2 := (amtOp (mask .- t1) mask) .* numI32 8 oprSz)
  !!ir (t3 := ((amtOp t1 mask) .+ AST.num1 oprSz) .* numI32 8 oprSz)
  !!ir (baseAddress := shifterStore memShf regShf rRt t2 t3 baseAddress)
  advancePC ctxt ir
  !>ir insLen

let syscall insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect SysCall)
  !>ir insLen

let seb insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.sext ctxt.WordBitSize (AST.extract rt 8<rt> 0))
  advancePC ctxt ir
  !>ir insLen

let seh insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.sext ctxt.WordBitSize (AST.extract rt 16<rt> 0))
  advancePC ctxt ir
  !>ir insLen

let shiftLeftRight insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  if is32Bit ctxt then
    !!ir (rd := shf rt sa)
  else
    let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
    !!ir (rd := shf rt sa |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let sra insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  if is32Bit ctxt then
    !!ir (rd := rt ?>> sa |> AST.sext 32<rt>)
  else
    let struct (rt, sa) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> sa
    !!ir (rd := rt ?>> sa |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let srav insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let mask = numI32 31 32<rt>
  !<ir insLen
  if is32Bit ctxt then
    !!ir (rd := rt ?>> (rs .& mask) |> AST.sext 32<rt>)
  else
    let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
    !!ir (rd := rt ?>> (rs .& mask) |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let shiftLeftRightVar insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let mask = numI32 31 32<rt>
  !<ir insLen
  if is32Bit ctxt then
    !!ir (rd := shf rt (rs .& mask))
  else
    let struct (rt, rs) = AST.xtlo 32<rt> rt, AST.xtlo 32<rt> rs
    !!ir (rd := shf rt (rs .& mask) |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let sltAndU insInfo insLen ctxt amtOp =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = amtOp rs rt
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (rd := rtVal)
  advancePC ctxt ir
  !>ir insLen

let sltiAndU insInfo insLen ctxt amtOp =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = amtOp rs imm
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (rt := rtVal)
  advancePC ctxt ir
  !>ir insLen

let sub insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src1, src2 = getThreeOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | None ->
    let dst, src1, src2 = transThreeOprs insInfo ctxt (dst, src1, src2)
    !!ir (dst := src1 .- src2)
  | Some Fmt.S ->
    let dst, fs, ft = transThreeFP ctxt (dst, src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 32<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 ir
    !!ir (result := AST.fsub tSrc1 tSrc2)
    subNormal 32<rt> tSrc1 tSrc2 result ir
    !!ir (dst := result)
  | Some Fmt.D ->
    let dstB, dstA = transOprToFPPair ctxt dst
    let fs, ft = transFPConcatTwoOprs ctxt (src1, src2)
    let struct (tSrc1, tSrc2, result) = tmpVars3 ir 64<rt>
    reDupSrc src1 src2 fs ft tSrc1 tSrc2 ir
    !!ir (result := AST.fsub tSrc1 tSrc2)
    subNormal 64<rt> tSrc1 tSrc2 result ir
    dstAssignForFP dstB dstA result ctxt ir
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let subu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let result = if is32Bit ctxt then rs .- rt else signExtLo64 (rs .- rt)
  !!ir (rd := result)
  advancePC ctxt ir
  !>ir insLen

let teq insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (AST.cjmp (rs == rt) (AST.name lblL0) (AST.name lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr) (* FIXME: Trap *)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let teqi insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let rs, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (AST.cjmp (rs == imm) (AST.name lblL0) (AST.name lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect UndefinedInstr)
  !!ir (AST.lmark lblEnd)
  advancePC ctxt ir
  !>ir insLen

let truncw insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let intMax = numI32 0x7fffffff 32<rt>
  let intMin = numI32 0x80000000 32<rt>
  let exponent = !+ir 1<rt>
  let dstTmp = !+ir 32<rt>
  !<ir insLen
  let struct (dst, src, inf, nan) =
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoFP ctxt (fd, fs)
      !!ir (exponent := getExponentFull src 32<rt>)
      let mantissa = !+ir 32<rt>
      !!ir (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      dst, src, inf, nan
    | _ ->
      let dst = transOprToFP ctxt fd
      let src = transOprToFPPairConcat ctxt fs
      let tSrc = !+ir 64<rt>
      !!ir (tSrc := src)
      !!ir (exponent := getExponentFull tSrc 64<rt>)
      let mantissa = !+ir 64<rt>
      !!ir (mantissa := getMantissa tSrc 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      dst, tSrc, inf, nan
  !!ir (dst := AST.cast CastKind.FtoITrunc 32<rt> src)
  !!ir (dstTmp := dst)
  let outOfRange = AST.sgt dstTmp intMax .| AST.slt dstTmp intMin
  !!ir (dst := AST.ite (outOfRange .| inf .| nan) intMax dstTmp)
  advancePC ctxt ir
  !>ir insLen

let truncl insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let fdB, fdA = transOprToFPPair ctxt fd
  let eval = !+ir 64<rt>
  let exponent = !+ir 1<rt>
  let intMax = numI64 0x7fffffffffffffffL 64<rt>
  let intMin = numI64 0x8000000000000000L 64<rt>
  !<ir insLen
  let struct (src, inf, nan) =
    match insInfo.Fmt with
    | Some Fmt.S ->
      let src = transOprToFP ctxt fs
      !!ir (exponent := getExponentFull src 32<rt>)
      let mantissa = !+ir 32<rt>
      !!ir (mantissa := getMantissa src 32<rt>)
      let inf = isInfinity 32<rt> exponent mantissa
      let nan = isNaN 32<rt> exponent mantissa
      src, inf, nan
    | _ ->
      let src = transOprToFPPairConcat ctxt fs
      !!ir (exponent := getExponentFull src 64<rt>)
      let mantissa = !+ir 64<rt>
      !!ir (mantissa := getMantissa src 64<rt>)
      let inf = isInfinity 64<rt> exponent mantissa
      let nan = isNaN 64<rt> exponent mantissa
      src, inf, nan
  !!ir (eval := AST.cast CastKind.FtoITrunc 64<rt> src)
  let outOfRange = AST.sgt eval intMax .| AST.slt eval intMin
  !!ir (eval := AST.ite (outOfRange .| inf .| nan) intMax eval)
  dstAssignForFP fdB fdA eval ctxt ir
  advancePC ctxt ir
  !>ir insLen

let logXor insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs <+> rt)
  advancePC ctxt ir
  !>ir insLen

let wsbh insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let rt = AST.xtlo 32<rt> src
  let elements =
    Array.init 4 (fun x -> AST.extract rt 8<rt> ((2 + x) % 4 * 8)) |> Array.rev
  !<ir insLen
  !!ir (dst := AST.sext ctxt.WordBitSize (AST.revConcat elements))
  advancePC ctxt ir
  !>ir insLen

let dsbh insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let lo = AST.xtlo 32<rt> src
  let hi = AST.xthi 32<rt> src
  let hiResult =
    Array.init 4 (fun x -> AST.extract hi 8<rt> ((2 + x) % 4 * 8)) |> Array.rev
  let lowResult =
    Array.init 4 (fun x -> AST.extract lo 8<rt> ((2 + x) % 4 * 8)) |> Array.rev
  !<ir insLen
  !!ir (dst := AST.revConcat (Array.append lowResult hiResult))
  advancePC ctxt ir
  !>ir insLen

let dshd insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let result =
    Array.init 4 (fun idx -> AST.extract src 16<rt> (idx * 16)) |> Array.rev
  !<ir insLen
  !!ir (dst := AST.revConcat result)
  advancePC ctxt ir
  !>ir insLen

let xori insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rt := rs <+> imm)
  advancePC ctxt ir
  !>ir insLen

let loadLeftRight insInfo insLen ctxt memShf regShf amtOp oprSz =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo
  let baseOffset = transOprToBaseOffset ctxt mem
  let rt = transOprToExpr insInfo ctxt rt
  let rRt, baseOffset =
    if oprSz = 32<rt> then
      if is32Bit ctxt then rt, baseOffset
      else AST.xtlo 32<rt> rt, AST.xtlo 32<rt> baseOffset
    else rt, baseOffset
  let struct (vaddr0To2, t1, t2, t3) = tmpVars4 ir oprSz
  let mask = numI32 (((int oprSz) >>> 3) - 1) oprSz
  let inline loadBaseAddr oprSz baseOffset =
    let maskLoad = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
    AST.loadLE oprSz (baseOffset .& numI32 maskLoad oprSz)
  !<ir insLen
  !!ir (t1 := baseOffset)
  !!ir (vaddr0To2 := t1 .& mask <+> (transBigEndianCPU ctxt oprSz))
  !!ir (t2 := ((amtOp vaddr0To2 mask) .+ AST.num1 oprSz) .* numI32 8 oprSz)
  !!ir (t3 := (amtOp (mask .- vaddr0To2) mask) .* numI32 8 oprSz)
  let result = shifterLoad memShf regShf rRt t2 t3 (loadBaseAddr oprSz t1)
  !!ir (rt := if is32Bit ctxt then result else result |> AST.sext 64<rt>)
  advancePC ctxt ir
  !>ir insLen

let recip insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let sz = ctxt.WordBitSize
  let fnum = AST.cast CastKind.SIntToFloat sz (AST.num1 sz)
  !<ir insLen
  !!ir (fd := AST.fdiv fnum fs)
  !>ir insLen

let rsqrt insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoFP ctxt (fd, fs)
    let fnum = AST.cast CastKind.SIntToFloat 32<rt> (AST.num1 32<rt>)
    !!ir (fd := AST.fdiv fnum (AST.fsqrt fs))
  | _ ->
    let fdB, fdA = transOprToFPPair ctxt fd
    let fs = transOprToFPPairConcat ctxt fs
    let fnum = AST.cast CastKind.SIntToFloat 64<rt> (AST.num1 64<rt>)
    let result = AST.fdiv fnum (AST.fsqrt fs)
    dstAssignForFP fdB fdA result ctxt ir
  advancePC ctxt ir
  !>ir insLen

let translate insInfo insLen (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | Op.ABS -> abs insInfo insLen ctxt
  | Op.ADD -> add insInfo insLen ctxt
  | Op.ADDIU -> addiu insInfo insLen ctxt
  | Op.ADDU -> addu insInfo insLen ctxt
  | Op.AND -> logAnd insInfo insLen ctxt
  | Op.ANDI -> andi insInfo insLen ctxt
  | Op.AUI -> aui insInfo insLen ctxt
  | Op.B -> b insInfo insLen ctxt
  | Op.BAL -> bal insInfo insLen ctxt
  | Op.BC1F -> bc1f insInfo insLen ctxt
  | Op.BC1T -> bc1t insInfo insLen ctxt
  | Op.BEQ | Op.BEQL -> beq insInfo insLen ctxt
  | Op.BGEZ -> bgez insInfo insLen ctxt
  | Op.BGEZAL -> bgezal insInfo insLen ctxt
  | Op.BGTZ -> bgtz insInfo insLen ctxt
  | Op.BLEZ -> blez insInfo insLen ctxt
  | Op.BLTZ -> bltz insInfo insLen ctxt
  | Op.BLTZAL -> bltzal insInfo insLen ctxt
  | Op.BNE | Op.BNEL -> bne insInfo insLen ctxt
  | Op.BREAK -> sideEffects insLen ctxt Breakpoint
  | Op.C -> cCond insInfo insLen ctxt
  | Op.CFC1 -> cfc1 insInfo insLen ctxt
  | Op.CTC1 -> ctc1 insInfo insLen ctxt
  | Op.CLZ -> clz insInfo insLen ctxt
  | Op.CVTD -> cvtd insInfo insLen ctxt
  | Op.CVTL -> cvtl insInfo insLen ctxt
  | Op.CVTS -> cvts insInfo insLen ctxt
  | Op.CVTW -> cvtw insInfo insLen ctxt
  | Op.DADD -> dadd insInfo insLen ctxt
  | Op.DADDU -> daddu insInfo insLen ctxt
  | Op.DADDIU -> daddiu insInfo insLen ctxt
  | Op.DCLZ -> dclz insInfo insLen ctxt
  | Op.DDIV -> ddiv insInfo insLen ctxt
  | Op.DMFC1 -> dmfc1 insInfo insLen ctxt
  | Op.DMTC1 -> dmtc1 insInfo insLen ctxt
  | Op.DEXT -> dext insInfo insLen ctxt
  | Op.DEXTM -> dextx insInfo insLen checkDEXTMPosSize ctxt
  | Op.DEXTU -> dextx insInfo insLen checkDEXTUPosSize ctxt
  | Op.DINS -> dins insInfo insLen ctxt
  | Op.DINSM -> dinsx insInfo insLen checkDINSMPosSize ctxt
  | Op.DINSU -> dinsx insInfo insLen checkDINSUPosSize ctxt
  | Op.DIV -> div insInfo insLen ctxt
  | Op.DIVU -> divu insInfo insLen ctxt
  | Op.DDIVU -> ddivu insInfo insLen ctxt
  | Op.DMULT -> dmul insInfo insLen ctxt true
  | Op.DMULTU -> dmul insInfo insLen ctxt false
  | Op.DROTR -> drotr insInfo insLen ctxt
  | Op.DROTR32 -> drotr32 insInfo insLen ctxt
  | Op.DROTRV -> drotrv insInfo insLen ctxt
  | Op.DSBH -> dsbh insInfo insLen ctxt
  | Op.DSHD -> dshd insInfo insLen ctxt
  | Op.DSLL -> dShiftLeftRight insInfo insLen ctxt (<<)
  | Op.DSLL32 -> dShiftLeftRight32 insInfo insLen ctxt (<<)
  | Op.DSLLV -> dShiftLeftRightVar insInfo insLen ctxt (<<)
  | Op.DSRA -> dsra insInfo insLen ctxt
  | Op.DSRAV -> dsrav insInfo insLen ctxt
  | Op.DSRA32 -> dsra32 insInfo insLen ctxt
  | Op.DSRL -> dShiftLeftRight insInfo insLen ctxt (>>)
  | Op.DSRL32 -> dShiftLeftRight32 insInfo insLen ctxt (>>)
  | Op.DSRLV -> dShiftLeftRightVar insInfo insLen ctxt (>>)
  | Op.DSUBU -> dsubu insInfo insLen ctxt
  | Op.EHB -> nop insLen ctxt
  | Op.EXT -> ext insInfo insLen ctxt
  | Op.INS -> ins insInfo insLen ctxt
  | Op.J -> j insInfo insLen ctxt
  | Op.JAL -> jal insInfo insLen ctxt
  | Op.JALR | Op.JALRHB -> jalr insInfo insLen ctxt
  | Op.JR | Op.JRHB -> jr insInfo insLen ctxt
  | Op.LD | Op.LB | Op.LH | Op.LW -> loadSigned insInfo insLen ctxt
  | Op.LBU | Op.LHU | Op.LWU -> loadUnsigned insInfo insLen ctxt
  | Op.LL | Op.LLD -> loadLinked insInfo insLen ctxt
  | Op.SDC1 | Op.SDXC1 -> sldc1 insInfo insLen ctxt true
  | Op.LDC1 | Op.LDXC1 -> sldc1 insInfo insLen ctxt false
  | Op.SWC1 | Op.SWXC1 -> slwc1 insInfo insLen ctxt true
  | Op.LWC1 | Op.LWXC1 -> slwc1 insInfo insLen ctxt false
  | Op.LUI -> lui insInfo insLen ctxt
  | Op.LDL -> loadLeftRight insInfo insLen ctxt (<<) (>>) (.&) 64<rt>
  | Op.LDR -> loadLeftRight insInfo insLen ctxt (>>) (<<) (<+>) 64<rt>
  | Op.LWL -> loadLeftRight insInfo insLen ctxt (<<) (>>) (.&) 32<rt>
  | Op.LWR -> loadLeftRight insInfo insLen ctxt (>>) (<<) (<+>) 32<rt>
  | Op.MADD -> mAddSub insInfo insLen ctxt true
  | Op.MADDU -> mAdduSubu insInfo insLen ctxt true
  | Op.MFHI -> mfhi insInfo insLen ctxt
  | Op.MFLO -> mflo insInfo insLen ctxt
  | Op.MFHC1 -> mfhc1 insInfo insLen ctxt
  | Op.MTHC1 -> mthc1 insInfo insLen ctxt
  | Op.MTHI -> mthi insInfo insLen ctxt
  | Op.MTLO -> mtlo insInfo insLen ctxt
  | Op.MFC1 -> mfc1 insInfo insLen ctxt
  | Op.MOV -> mov insInfo insLen ctxt
  | Op.MOVT -> movt insInfo insLen ctxt
  | Op.MOVF -> movf insInfo insLen ctxt
  | Op.MOVZ -> movzOrn insInfo insLen ctxt (==)
  | Op.MOVN -> movzOrn insInfo insLen ctxt (!=)
  | Op.MSUB ->  mAddSub insInfo insLen ctxt false
  | Op.MSUBU -> mAdduSubu insInfo insLen ctxt false
  | Op.MTC1 -> mtc1 insInfo insLen ctxt
  | Op.MUL -> mul insInfo insLen ctxt
  | Op.MULT -> mult insInfo insLen ctxt
  | Op.MULTU -> multu insInfo insLen ctxt
  | Op.NEG -> neg insInfo insLen ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.NOR -> nor insInfo insLen ctxt
  | Op.OR -> logOr insInfo insLen ctxt
  | Op.ORI -> ori insInfo insLen ctxt
  | Op.PAUSE -> pause insLen ctxt
  | Op.PREF | Op.PREFE | Op.PREFX -> nop insLen ctxt
  | Op.RDHWR -> sideEffects insLen ctxt ProcessorID
  | Op.ROTR -> rotr insInfo insLen ctxt
  | Op.ROTRV -> rotrv insInfo insLen ctxt
  | Op.RECIP -> recip insInfo insLen ctxt
  | Op.RSQRT -> rsqrt insInfo insLen ctxt
  | Op.SLL -> shiftLeftRight insInfo insLen ctxt (<<)
  | Op.SLLV -> shiftLeftRightVar insInfo insLen ctxt (<<)
  | Op.SLT -> sltAndU insInfo insLen ctxt (?<)
  | Op.SLTU -> sltAndU insInfo insLen ctxt (.<)
  | Op.SLTI -> sltiAndU insInfo insLen ctxt (?<)
  | Op.SLTIU -> sltiAndU insInfo insLen ctxt (.<)
  | Op.SSNOP -> nop insLen ctxt
  | Op.SB -> store insInfo insLen 8<rt> ctxt
  | Op.SC -> storeConditional insInfo insLen 32<rt> ctxt
  | Op.SCD -> storeConditional insInfo insLen 64<rt> ctxt
  | Op.SD -> store insInfo insLen 64<rt> ctxt
  | Op.SEB -> seb insInfo insLen ctxt
  | Op.SEH -> seh insInfo insLen ctxt
  | Op.SH -> store insInfo insLen 16<rt> ctxt
  | Op.SQRT -> sqrt insInfo insLen ctxt
  | Op.SRA -> sra insInfo insLen ctxt
  | Op.SRAV -> srav insInfo insLen ctxt
  | Op.SRL -> shiftLeftRight insInfo insLen ctxt (>>)
  | Op.SRLV -> shiftLeftRightVar insInfo insLen ctxt (>>)
  | Op.SUB -> sub insInfo insLen ctxt
  | Op.SUBU -> subu insInfo insLen ctxt
  | Op.SW -> store insInfo insLen 32<rt> ctxt
  | Op.SDL -> storeLeftRight insInfo insLen ctxt (<<) (>>) (.&) 64<rt>
  | Op.SDR -> storeLeftRight insInfo insLen ctxt (>>) (<<) (<+>) 64<rt>
  | Op.SWL -> storeLeftRight insInfo insLen ctxt (<<) (>>) (.&) 32<rt>
  | Op.SWR -> storeLeftRight insInfo insLen ctxt (>>) (<<) (<+>) 32<rt>
  | Op.SYNC | Op.SYNCI -> nop insLen ctxt
  | Op.SYSCALL -> syscall insLen ctxt
  | Op.TEQ -> teq insInfo insLen ctxt
  | Op.TEQI -> teqi insInfo insLen ctxt
  | Op.TRUNCW -> truncw insInfo insLen ctxt
  | Op.TRUNCL -> truncl insInfo insLen ctxt
  | Op.XOR -> logXor insInfo insLen ctxt
  | Op.XORI -> xori insInfo insLen ctxt
  | Op.WSBH -> wsbh insInfo insLen ctxt
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL ->
    sideEffects insLen ctxt UnsupportedExtension // XXX this is a temporary fix
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
