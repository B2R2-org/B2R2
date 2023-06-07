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

module internal B2R2.FrontEnd.BinLifter.MIPS.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.MIPS

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline (:=) dst src =
  match dst with
  | { E = Var (_, rid, _, _) } when rid = Register.toRegID Register.R0 ->
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

let private transOprToFPPair ctxt = function
  | OpReg reg -> getRegVar ctxt (Register.getFPPairReg reg), getRegVar ctxt reg
  | _ -> raise InvalidOperandException

let private transOprToFPPairConcat ctxt = function
  | OpReg reg ->
    AST.concat (getRegVar ctxt (Register.getFPPairReg reg)) (getRegVar ctxt reg)
  | _ -> raise InvalidOperandException

let dstAssignForFP dstB dstA result ir =
  let srcB = AST.xthi 32<rt> result
  let srcA = AST.xtlo 32<rt> result
  !!ir (dstA := srcA)
  !!ir (dstB := srcB)

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

let private isNaN32 expr =
  let exponent = (expr >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
  let e = numI32 0xff 32<rt>
  AST.xtlo 1<rt>
    ((exponent == e) .& ((expr .& numU32 0x7fffffu 32<rt>) != AST.num0 32<rt>))

let private isSNaN32 expr =
  let nanChecker = isNaN32 expr
  let signalBit = numU32 (1u <<< 22) 32<rt>
  nanChecker .& ((expr .& signalBit) == AST.num0 32<rt>)

let private isQNaN32 expr =
  let nanChecker = isNaN32 expr
  let signalBit = numU32 (1u <<< 22) 32<rt>
  nanChecker .& ((expr .& signalBit) != AST.num0 32<rt>)

let private isInfinity32 expr =
  let exponent = (expr >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
  let fraction = expr .& numU32 0x7fffffu 32<rt>
  let e = numI32 0xff 32<rt>
  let zero = AST.num0 32<rt>
  AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

let private isZero32 expr =
  let mask = numU32 0x7fffffffu 32<rt>
  AST.eq (expr .& mask) (AST.num0 32<rt>)

let private isNaN64 expr =
  let exponent = (expr >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
  let e = numI32 0x7ff 64<rt>
  AST.xtlo 1<rt> ((exponent == e) .&
    ((expr .& numU64 0xfffff_ffffffffUL 64<rt>) != AST.num0 64<rt>))

let private isSNaN64 expr =
  let nanChecker = isNaN64 expr
  let signalBit = numU64 (1UL <<< 51) 64<rt>
  nanChecker .& ((expr .& signalBit) == AST.num0 64<rt>)

let private isQNaN64 expr =
  let nanChecker = isNaN64 expr
  let signalBit = numU64 (1UL <<< 51) 64<rt>
  nanChecker .& ((expr .& signalBit) != AST.num0 64<rt>)

let private isInfinity64 expr =
  let exponent = (expr >> numI32 52 64<rt>) .& numI32 0x7ff 64<rt>
  let fraction = expr .& numU64 0xfffff_ffffffffUL 64<rt>
  let e = numI32 0x7ff 64<rt>
  let zero = AST.num0 64<rt>
  AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

let private isZero64 expr =
  let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
  AST.eq (expr .& mask) (AST.num0 64<rt>)

let private isNaN oprSz expr =
  match oprSz with
  | 32<rt> -> isNaN32 expr
  | 64<rt> -> isNaN64 expr
  | _ -> Utils.impossible ()

let private isSNaN oprSz expr =
  match oprSz with
  | 32<rt> -> isSNaN32 expr
  | 64<rt> -> isSNaN64 expr
  | _ -> Utils.impossible ()

let private isQNaN oprSz expr =
  match oprSz with
  | 32<rt> -> isQNaN32 expr
  | 64<rt> -> isQNaN64 expr
  | _ -> Utils.impossible ()

let private isInfinity oprSz expr =
  match oprSz with
  | 32<rt> -> isInfinity32 expr
  | 64<rt> -> isInfinity64 expr
  | _ -> Utils.impossible ()

let private isZero oprSz expr =
  match oprSz with
  | 32<rt> -> isZero32 expr
  | 64<rt> -> isZero64 expr
  | _ -> Utils.impossible ()

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

let private elem vector e size =
  AST.extract vector (RegType.fromBitWidth size) (e * size)

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

let private subNormal oprSz src1 src2 result ir =
  let struct (qNaNBox, sNaNBox, nanBox) = tmpVars3 ir 1<rt>
  !!ir (qNaNBox := isQNaN oprSz result)
  !!ir (sNaNBox := isSNaN oprSz result)
  !!ir (nanBox := qNaNBox .| sNaNBox)
  !!ir (result :=
    AST.ite nanBox (
      let sign = AST.xthi 1<rt> result .&
                   (AST.not (isInfinity oprSz src1 .| isInfinity oprSz src2))
      let struct (sNanVal, msNanVal, qNanVal, mqNanVal) =
        match oprSz with
        | 32<rt> ->
          struct (numU32 0x7fffffffu 32<rt>, numU32 0xffffffffu 32<rt>,
                  numU32 0x7fbfffffu 32<rt>, numU32 0xffbfffffu 32<rt>)
        | _ -> struct (numU64 0x7fffffffffffffffUL 64<rt>,
                       numU64 0xffffffffffffffffUL 64<rt>,
                       numU64 0x7ff7ffffffffffffUL 64<rt>,
                       numU64 0xfff7ffffffffffffUL 64<rt>)
      let qNanWithSign = AST.ite sign mqNanVal qNanVal
      let sNanWithSign = AST.ite sign msNanVal sNanVal
      AST.ite qNaNBox qNanWithSign (AST.ite sNaNBox sNanWithSign result))
        result)

let divNormal oprSz src1 src2 result ir =
  let sign = AST.xthi 1<rt> result
  let src1Zero = src1 == AST.num0 oprSz
  let src2Zero = src2 == AST.num0 oprSz
  let qNan = isQNaN oprSz result
  let sNan = isSNaN oprSz result
  let struct (sNanVal, msNanVal, qNanVal, mqNanVal) =
    match oprSz with
    | 32<rt> ->
      struct (numU32 0x7fffffffu 32<rt>, numU32 0xffffffffu 32<rt>,
              numU32 0x7fbfffffu 32<rt>, numU32 0xffbfffffu 32<rt>)
    | _ -> struct (numU64 0x7fffffffffffffffUL 64<rt>,
                   numU64 0xffffffffffffffffUL 64<rt>,
                   numU64 0x7ff7ffffffffffffUL 64<rt>,
                   numU64 0xfff7ffffffffffffUL 64<rt>)
  let qNanWithSign = AST.ite sign mqNanVal qNanVal
  let sNanWithSign = AST.ite sign msNanVal sNanVal
  !!ir (result := AST.ite (src1Zero .& src2Zero) qNanVal
                    (AST.ite qNan qNanWithSign
                      (AST.ite sNan sNanWithSign result)))

let private normalizeValue oprSz result ir =
  let struct (qNaNBox, sNaNBox, infBox, condBox) = tmpVars4 ir 1<rt>
  !!ir (qNaNBox := isQNaN oprSz result)
  !!ir (sNaNBox := isSNaN oprSz result)
  !!ir (infBox := isInfinity oprSz result)
  !!ir (condBox := qNaNBox .| sNaNBox .| infBox)
  !!ir (result :=
    AST.ite condBox (
      let sign = AST.xthi 1<rt> result
      let struct (sNanVal, msNanVal, qNanVal, mqNanVal) =
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
      let qNanWithSign = AST.ite sign mqNanVal qNanVal
      let sNanWithSign = AST.ite sign msNanVal sNanVal
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

let private is32Bit (ctxt: TranslationContext) = ctxt.WordBitSize = 32<rt>

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
    let fs = transOprToFPPairConcat ctxt fs |> AST.fneg
    dstAssignForFP fdB fdA fs ir
  | _ ->
    let fd, fs = transTwoOprs insInfo ctxt (fd, fs)
    !!ir (fd := AST.fneg fs)
  advancePC ctxt ir
  !>ir insLen

let add insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  if insInfo.Fmt.IsNone then
    let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
    let result = if is32Bit ctxt then rs .+ rt else signExtLo64 (rs .+ rt)
    let cond = checkOverfolwOnAdd rs rt result
    !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "int overflow"))
    !!ir (AST.jmp (AST.name lblEnd))
    !!ir (AST.lmark lblL1)
    !!ir (rd := result)
    !!ir (AST.lmark lblEnd)
  else
    let fd, fs, ft = getThreeOprs insInfo
    match insInfo.Fmt with
    | Some Fmt.S ->
      let fd, fs, ft = transThreeOprs insInfo ctxt (fd, fs, ft)
      let result = !+ir 32<rt>
      !!ir (result := AST.fadd ft fs)
      normalizeValue 32<rt> result ir
      !!ir (fd := AST.fadd ft fs)
    | _ ->
      let fdB, fdA = transOprToFPPair ctxt fd
      let fs, ft = transFPConcatTwoOprs ctxt (fs, ft)
      let result = !+ir 64<rt>
      !!ir (result := AST.fadd fs ft)
      normalizeValue 64<rt> result ir
      dstAssignForFP fdB fdA result ir
  advancePC ctxt ir
  !>ir insLen

let addiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, rs, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let result = if is32Bit ctxt then rs .+ imm else signExtLo64 (rs .+ imm)
  !!ir (rt := result)
  advancePC ctxt ir
  !>ir insLen

let addu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let result = if is32Bit ctxt then rs .+ rt else signExtLo64 (rs .+ rt)
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

let fpConditionCode cc ctxt =
  let ir = !*ctxt
  let fcsr = getRegVar ctxt R.FCSR
  if cc = 0 then (fcsr .& numU32 0x800000u 32<rt>) == numU32 0x800000u 32<rt>
  else
    let andVal = !+ir 32<rt>
    !!ir (andVal := numU32 0x1000000u 32<rt> << numI32 cc 32<rt>)
    (fcsr .& andVal) == andVal

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
  let cond = AST.slt rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  updatePCCond ctxt offset cond InterJmpKind.IsCall ir
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
  let cond = AST.sge rs (AST.num0 ctxt.WordBitSize)
  !<ir insLen
  !!ir (getRegVar ctxt R.R31 := pc .+ numI32 8 ctxt.WordBitSize)
  updatePCCond ctxt offset cond InterJmpKind.IsCall ir
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

let cCond insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblEnd = !%ir "End"
  !<ir insLen
  let wordSz, cc, fs, ft =
    match insInfo.Operands with
    | TwoOperands (fs, ft) ->
      match insInfo.Fmt with
      | Some Fmt.PS | Some Fmt.D ->
        let fs, ft = transFPConcatTwoOprs ctxt (fs, ft)
        64<rt>, 0, fs, ft
      | _ ->
        let fs, ft = transTwoOprs insInfo ctxt (fs, ft)
        32<rt>, 0, fs, ft
    | ThreeOperands (cc, fs, ft) ->
      match insInfo.Fmt with
      | Some Fmt.PS | Some Fmt.D ->
        let cc = transOprToImmToInt cc
        let fs, ft = transFPConcatTwoOprs ctxt (fs ,ft)
        64<rt>, cc, fs, ft
      | _ ->
        let cc = transOprToImmToInt cc
        let fs, ft = transTwoOprs insInfo ctxt (fs, ft)
        32<rt>, cc, fs, ft
    | _ -> raise InvalidOperandException
  let num0 = AST.num0 wordSz
  let num1 = AST.num1 wordSz
  let zeroSameCondWithEqaul =
    let cond1 = AST.eq fs ft
    let cond2 = isZero wordSz fs .& (ft == num0)
    let cond3 = isZero wordSz ft .& (fs == num0)
    cond1 .| cond2 .| cond3
  let struct (less, equal, unordered, condition) = tmpVars4 ir wordSz
  let condZeroToTwo = !+ir wordSz
  let condBit3 =
    match insInfo.Condition with
    | Some Condition.SF -> AST.b1
    | Some Condition.NGLE -> AST.b1
    | Some Condition.SEQ -> AST.b1
    | Some Condition.NGL -> AST.b1
    | Some Condition.LT -> AST.b1
    | Some Condition.NGE -> AST.b1
    | Some Condition.LE -> AST.b1
    | Some Condition.NGT -> AST.b1
    | _ -> AST.b0
  let inline conditionToSz wordSz =
    match insInfo.Condition with
    | Some Condition.F | Some Condition.SF -> numU64 0b000UL wordSz
    | Some Condition.UN | Some Condition.NGLE -> numU64 0b001UL wordSz
    | Some Condition.EQ | Some Condition.SEQ -> numU64 0b010UL wordSz
    | Some Condition.UEQ | Some Condition.NGL -> numU64 0b011UL wordSz
    | Some Condition.OLT | Some Condition.LT -> numU64 0b100UL wordSz
    | Some Condition.ULT | Some Condition.NGE -> numU64 0b101UL wordSz
    | Some Condition.OLE | Some Condition.LE -> numU64 0b110UL wordSz
    | Some Condition.ULE | Some Condition.NGT -> numU64 0b111UL wordSz
    | _ -> raise InvalidOperandException
  !!ir (condZeroToTwo := conditionToSz wordSz)
  let cond0 = condZeroToTwo .& numU64 0b001UL wordSz
  let cond1 = (condZeroToTwo .& numU64 0b010UL wordSz) >> numU64 1UL wordSz
  let cond2 = (condZeroToTwo .& numU64 0b100UL wordSz) >> numU64 2UL wordSz
  let struct (is2SNan, is2QNan) = tmpVars2 ir 1<rt>
  !!ir (is2SNan := isSNaN wordSz fs .| isSNaN wordSz ft)
  !!ir (is2QNan := isQNaN wordSz fs .| isQNaN wordSz ft)
  let nanCond = is2SNan .| is2QNan
  let fieldCond = is2SNan .| (condBit3 .& is2QNan)
  !!ir (AST.cjmp nanCond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (less := num0)
  !!ir (equal := num0)
  !!ir (unordered := num1)
  !!ir (AST.cjmp fieldCond (AST.name lblL2) (AST.name lblEnd))
  !!ir (AST.lmark lblL2)
  (* FIXME InvalidOperation *)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (less := AST.ite (AST.flt fs ft) num1 num0)
  !!ir (equal := AST.ite zeroSameCondWithEqaul num1 num0)
  !!ir (unordered := num0)
  !!ir (AST.lmark lblEnd)
  !!ir (condition := (cond2 .& less) .| (cond1 .& equal)
                       .| (cond0 .& unordered))
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
  !!ir (rt := fcsr)
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
    let fs = transOprToExpr insInfo ctxt fs
    !!ir (result := AST.cast CastKind.SIntToFloat 64<rt> fs)
  | Some Fmt.S ->
    let fs = transOprToExpr insInfo ctxt fs
    !!ir (result := AST.cast CastKind.FloatCast 64<rt> fs)
  | _ ->
    let fs = transOprToFPPairConcat ctxt fs
    !!ir (result := fs)
  normalizeValue 64<rt> result ir
  dstAssignForFP fdB fdA result ir
  advancePC ctxt ir
  !>ir insLen

let cvts insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let fd = transOprToExpr insInfo ctxt fd
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
    let fs = transOprToExpr insInfo ctxt fs
    !!ir (result := AST.cast CastKind.SIntToFloat 32<rt> fs)
  normalizeValue 32<rt> result ir
  !!ir (fd := result)
  advancePC ctxt ir
  !>ir insLen

let dadd insInfo insLen ctxt =
  let ir = !*ctxt
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let cond = checkOverfolwOnDadd rs rt (rs .+ rt)
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

let dmfc1 insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, fs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !!ir (rt := fs)
  advancePC ctxt ir
  !>ir insLen

let dmtc1 insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rt, fs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !!ir (fs := rt)
  advancePC ctxt ir
  !>ir insLen

let ddivu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let struct (q, r) = tmpVars2 ir 64<rt>
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
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
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkDEXTPosSize pos size
  let mask = numI64 (getMask size) ctxt.WordBitSize
  let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
  !!ir (rt := mask .& rs)
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
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let sz = int32 (transOprToImm size)
  posSizeCheckFn pos sz
  if sz = 64 then if rt = rs then () else !!ir (rt := rs)
  else
    let rs = if pos = 0 then rs else rs >> numI32 pos ctxt.WordBitSize
    let rs = if sz = 64 then rs else rs .& numI64 (getMask sz) ctxt.WordBitSize
    !!ir (rt := rs)
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
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  checkINSorExtPosSize pos size
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
  !<ir insLen
  let rt, rs, pos, size = getFourOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let rs = transOprToExpr insInfo ctxt rs
  let pos = int32 (transOprToImm pos)
  let size = int32 (transOprToImm size)
  posSizeCheckFn pos size
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

let divdotsdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs, ft = getThreeOprs insInfo
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.D ->
    let fdB, fdA = transOprToFPPair ctxt fd
    let fs, ft = transFPConcatTwoOprs ctxt (fs, ft)
    let result = !+ir 64<rt>
    !!ir (result := AST.fdiv fs ft)
    divNormal 64<rt> fs ft result ir
    dstAssignForFP fdB fdA result ir
  | _ ->
    let fd, fs, ft = transThreeOprs insInfo ctxt (fd, fs, ft)
    let result = !+ir 32<rt>
    !!ir (result := AST.fdiv fs ft)
    divNormal 32<rt> fs ft result ir
    !!ir (fd := result)
  advancePC ctxt ir
  !>ir insLen

let divu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !!ir (rt := AST.ite (rt == numI64 0 ctxt.WordBitSize)
                (AST.undef ctxt.WordBitSize "UNPREDICTABLE") rt)
  if is32Bit ctxt then
    !!ir (lo := (AST.zext 64<rt> rs ./ AST.zext 64<rt> rt) |> AST.xtlo 32<rt>)
    !!ir (hi := (AST.zext 64<rt> rs .% AST.zext 64<rt> rt) |> AST.xtlo 32<rt>)
  else
    let mask = numI64 0xFFFFFFFFL 64<rt>
    let q = (rs .& mask) ./ (rt .& mask)
    let r = (rs .& mask) .% (rt .& mask)
    !!ir (lo := signExtLo64 q)
    !!ir (hi := signExtLo64 r)
  advancePC ctxt ir
  !>ir insLen

let dmul insInfo insLen ctxt isSign =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let struct (high, low) = mul64BitReg rs rt ir isSign
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  !!ir (lo := low)
  !!ir (hi := high)
  advancePC ctxt ir
  !>ir insLen

let drotr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let size = numI32 64 64<rt>
  !<ir insLen
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
  !!ir (rd := shf rt sa)
  advancePC ctxt ir
  !>ir insLen

let dShiftLeftRight insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, sa = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := shf rt sa)
  advancePC ctxt ir
  !>ir insLen

let dShiftLeftRightVar insInfo insLen ctxt shf =
  let ir = !*ctxt
  let rd, rt, rs = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := shf rt (rs .& numI32 63 64<rt>))
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
  !<ir insLen
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

(* FIXME *)
let private transMem64 (ctxt: TranslationContext) = function
  | OpMem (b, Imm o, _) ->
    if ctxt.Endianness = Endian.Little then
      AST.loadLE 64<rt> (getRegVar ctxt b .+ numI64 o ctxt.WordBitSize)
    else AST.loadBE 64<rt> (getRegVar ctxt b .+ numI64 o ctxt.WordBitSize)
  | OpMem (b, Reg o, _) ->
    if ctxt.Endianness = Endian.Little then
      AST.loadLE 64<rt> (getRegVar ctxt b .+ getRegVar ctxt o)
    else AST.loadBE 64<rt> (getRegVar ctxt b .+ getRegVar ctxt o)
  | _ -> raise InvalidOperandException

let sldc1 insInfo insLen ctxt stORld =
  let ir = !*ctxt
  let ft, mem = getTwoOprs insInfo
  let ftB, ftA = transOprToFPPair ctxt ft
  let mem = transMem64 ctxt mem (* FIXME *)
  !<ir insLen
  if stORld then !!ir (mem := AST.concat ftB ftA)
  else
    !!ir (ftB := AST.xthi 32<rt> mem)
    !!ir (ftA := AST.xtlo 32<rt> mem)
  advancePC ctxt ir
  !>ir insLen

let slwc1 insInfo insLen ctxt stORld =
  let ir = !*ctxt
  let ft, mem = getTwoOprs insInfo
  let ft, mem = transTwoOprs insInfo ctxt (ft, mem)
  !<ir insLen
  if stORld then !!ir (mem := ft) else !!ir (ft := mem)
  advancePC ctxt ir
  !>ir insLen

let ext insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
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

let madd insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if insInfo.Fmt.IsNone then
    let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
    let result = !+ir 64<rt>
    let hi = getRegVar ctxt R.HI
    let lo = getRegVar ctxt R.LO
    if is32Bit ctxt then
      !!ir (result := (AST.concat hi lo)
                        .+ (AST.sext 64<rt> rs .* AST.sext 64<rt> rt))
      !!ir (hi := AST.xthi 32<rt> result)
      !!ir (lo := AST.xtlo 32<rt> result)
    else
      let mask = numU32 0xFFFFu 64<rt>
      let hilo = AST.concat (AST.xtlo 32<rt> hi) (AST.xtlo 32<rt> lo)
      !!ir (result := hilo .+ ((rs .& mask) .* (rt .& mask)))
      !!ir (hi := signExtHi64 result)
      !!ir (lo := signExtLo64 result)
  else
    let fd, fr, fs, ft = getFourOprs insInfo
    match insInfo.Fmt with
    | Some Fmt.PS ->
      let fdB, fdA = transOprToFPPair ctxt fd
      let fr, fs, ft = transFPConcatThreeOprs ctxt (fr, fs, ft)
      let result = AST.fadd (AST.fmul fs ft) fr
      dstAssignForFP fdB fdA result ir
    | Some Fmt.D ->
      let fdB, fdA = transOprToFPPair ctxt fd
      let fr, fs, ft = transThreeOprs insInfo ctxt (fr, fs, ft)
      let tfr = AST.cast CastKind.FloatCast 64<rt> fr
      let tfs = AST.cast CastKind.FloatCast 64<rt> fs
      let tft = AST.cast CastKind.FloatCast 64<rt> ft
      let result = AST.fadd (AST.fmul tfs tft) tfr
      dstAssignForFP fdB fdA result ir
    | _ ->
      let fd, fr, fs, ft = transFourOprs insInfo ctxt (fd, fr, fs, ft)
      let result = AST.fadd (AST.fmul fs ft) fr
      !!ir (fd := result)
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
  !!ir (rt := fsB)
  advancePC ctxt ir
  !>ir insLen

let mthc1 insInfo insLen ctxt =
  let ir = !*ctxt
  let rt, fs = getTwoOprs insInfo
  let rt = transOprToExpr insInfo ctxt rt
  let fsB, _ = transOprToFPPair ctxt fs
  !<ir insLen
  !!ir (fsB := rt)
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
  let fs = transOprToExpr insInfo ctxt fs
  !<ir insLen
  !!ir (rt := fs)
  advancePC ctxt ir
  !>ir insLen

let mov insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let fd, fs = getTwoOprs insInfo
  match insInfo.Fmt with
  | Some Fmt.S ->
    let fd, fs = transTwoOprs insInfo ctxt (fd, fs)
    !!ir (fd := fs)
  | Some Fmt.D ->
    let fdB, fdA = transOprToFPPair ctxt fd
    let fs = transOprToFPPairConcat ctxt fs
    dstAssignForFP fdB fdA fs ir
  | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let movt insInfo insLen ctxt =
  let ir = !*ctxt
  let dst, src, cc = getThreeOprs insInfo
  let cc = transOprToImmToInt cc
  let cond = !+ir 1<rt>
  !!ir (cond := fpConditionCode cc ctxt)
  !<ir insLen
  if insInfo.Fmt.IsNone then
    let dst, src = transTwoOprs insInfo ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  else
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoOprs insInfo ctxt (dst, src)
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
  let cond = !+ir 1<rt>
  !!ir (cond := AST.not (fpConditionCode cc ctxt))
  !<ir insLen
  if insInfo.Fmt.IsNone then
    let dst, src = transTwoOprs insInfo ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  else
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoOprs insInfo ctxt (dst, src)
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
  let cond = !+ir 1<rt>
  !!ir (cond := opFn compare (AST.num0 ctxt.WordBitSize))
  !<ir insLen
  if insInfo.Fmt.IsNone then
    let dst, src = transTwoOprs insInfo ctxt (dst, src)
    !!ir (dst := AST.ite cond src dst)
  else
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src = transTwoOprs insInfo ctxt (dst, src)
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
  let rt, fs = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (fs := AST.xtlo 32<rt> rt)
  advancePC ctxt ir
  !>ir insLen

let mul insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  if insInfo.Fmt.IsNone then
    let rd, rs, rt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
    let hi = getRegVar ctxt R.HI
    let lo = getRegVar ctxt R.LO
    let result =
      if is32Bit ctxt then
        (AST.sext 64<rt> rs .* AST.sext 64<rt> rt) |> AST.xtlo 32<rt>
      else signExtLo64 (rs .* rt)
    !!ir (rd := result)
    !!ir (hi := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
    !!ir (lo := AST.undef ctxt.WordBitSize "UNPREDICTABLE")
  else
    let fd, fs, ft = getThreeOprs insInfo
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src1, src2 = transThreeOprs insInfo ctxt (fd, fs, ft)
      let result = !+ir 32<rt>
      !!ir (result := AST.fmul src1 src2)
      normalizeValue 32<rt> result ir
      !!ir (dst := result)
    | Some Fmt.D ->
      let dstB, dstA = transOprToFPPair ctxt fd
      let src1, src2 = transFPConcatTwoOprs ctxt (fs, ft)
      let result = !+ir 64<rt>
      !!ir (result := AST.fmul src1 src2)
      normalizeValue 64<rt> result ir
      dstAssignForFP dstB dstA result ir
    | _ -> raise InvalidOperandException
  advancePC ctxt ir
  !>ir insLen

let mult insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let struct (result1, result2) =
    if is32Bit ctxt then
      (AST.sext 64<rt> rs .* AST.sext 64<rt> rt) |> AST.xtlo 32<rt>,
      (AST.sext 64<rt> rs .* AST.sext 64<rt> rt) |> AST.xthi 32<rt>
    else
      signExtLo64 ((rs .& mask) .* (rt .& mask)),
      signExtHi64 ((rs .& mask) .* (rt .& mask))
  !!ir (lo := result1)
  !!ir (hi := result2)
  advancePC ctxt ir
  !>ir insLen

let multu insInfo insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  let rs, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let hi = getRegVar ctxt R.HI
  let lo = getRegVar ctxt R.LO
  let mask = numI64 0xFFFFFFFFL 64<rt>
  let struct (result1, result2) =
    if is32Bit ctxt then
      AST.zext 64<rt> rs .* AST.zext 64<rt> rt |> AST.xtlo 32<rt>,
      AST.zext 64<rt> rs .* AST.zext 64<rt> rt |> AST.xthi 32<rt>
    else
      signExtLo64 ((rs .& mask) .* (rt .& mask)),
      signExtHi64 ((rs .& mask) .* (rt .& mask))
  !!ir (lo := result1)
  !!ir (hi := result2)
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

let store insInfo insLen width ctxt =
  let ir = !*ctxt
  let rt, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo width rt)
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

let private loadBaseAddr oprSz baseOffset =
  let mask = if oprSz = 64<rt> then 0xFFFFFFF8 else 0xFFFFFFFC
  AST.loadLE oprSz (baseOffset .& numI32 mask oprSz)

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
  let struct (t1, t2, t3) = tmpVars3 ir oprSz
  let mask = numI32 (((int oprSz) >>> 3) - 1) oprSz
  let vaddr0To2 = (baseOffset .& mask) <+> (transBigEndianCPU ctxt oprSz)
  let baseAddress = loadBaseAddr oprSz baseOffset
  !<ir insLen
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
  if insInfo.Fmt.IsNone then
    let dst, src1, src2 = transThreeOprs insInfo ctxt (dst, src1, src2)
    !!ir (dst := src1 .- src2)
  else
    match insInfo.Fmt with
    | Some Fmt.S ->
      let dst, src1, src2 = transThreeOprs insInfo ctxt (dst, src1, src2)
      let result = !+ir 32<rt>
      !!ir (result := AST.fsub src1 src2)
      subNormal 32<rt> src1 src2 result ir
      !!ir (dst := result)
    | Some Fmt.D ->
      let dstB, dstA = transOprToFPPair ctxt dst
      let src1, src2 = transFPConcatTwoOprs ctxt (src1, src2)
      let result = !+ir 64<rt>
      !!ir (result := AST.fsub src1 src2)
      subNormal 64<rt> src1 src2 result ir
      dstAssignForFP dstB dstA result ir
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

(* FIXME *)
let truncw insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let intMax = numU32 0x7fffffffu 32<rt>
  let intMin = numU32 0x80000000u 32<rt>
  let chooseSign32 sign = AST.ite sign intMin intMax
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.S ->
    let dst, src = transTwoOprs insInfo ctxt (fd, fs)
    let condInf = isInfinity32 src
    let condNaN = isNaN32 src
    let sign = AST.xthi 1<rt> src
    let eval = !+ir 32<rt>
    !!ir (eval := AST.cast CastKind.FtoFTrunc 32<rt> src)
    !!ir (dst := AST.cast CastKind.FtoITrunc 32<rt> eval)
    !!ir (dst := AST.ite condNaN (chooseSign32 sign) dst)
    !!ir (dst := AST.ite (condInf .& (AST.not sign)) intMax dst)
    !!ir (dst := AST.ite (condInf .& sign) intMin dst)
  | _ ->
    let dst = transOprToExpr insInfo ctxt fd
    let src = transOprToFPPairConcat ctxt fs
    let truncVal = AST.cast CastKind.FtoFTrunc 64<rt> src
    !!ir (dst := AST.cast CastKind.FloatCast 32<rt> truncVal
                    |> AST.cast CastKind.FtoITrunc 32<rt>)
    let outOfRange = AST.sgt dst intMax .| AST.slt dst intMin
    let sign = AST.xthi 1<rt> src
    let condInf = (isInfinity64 src .& sign)
                    .| (isInfinity64 src .& (AST.not sign))
    let condNaN = isNaN64 src
    !!ir (dst := AST.ite outOfRange intMax dst)
    !!ir (dst := AST.ite condInf intMax dst)
    !!ir (dst := AST.ite condNaN intMax dst)
  advancePC ctxt ir
  !>ir insLen

(* FIXME *)
let truncl insInfo insLen ctxt =
  let ir = !*ctxt
  let fd, fs = getTwoOprs insInfo
  let fdB, fdA = transOprToFPPair ctxt fd
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  !<ir insLen
  match insInfo.Fmt with
  | Some Fmt.S ->
    let fs = transOprToExpr insInfo ctxt fs
    let condInf = isInfinity 32<rt> fs
    let condNaN = isNaN32 fs
    let sign = AST.xthi 1<rt> fs
    let t0 = !+ir 32<rt>
    let eval = !+ir 64<rt>
    !!ir (t0 := AST.cast CastKind.FtoFTrunc 32<rt> fs)
    !!ir (eval := AST.cast CastKind.FloatCast 64<rt> t0)
    !!ir (eval := AST.ite (AST.fle eval llMinInFloat) llMinInFloat eval)
    !!ir (eval := AST.ite (AST.fge eval llMaxInFloat) llMaxInFloat eval)
    !!ir (eval := AST.ite condNaN llMaxInFloat eval)
    !!ir (eval := AST.ite (condInf .& (AST.not sign)) llMaxInFloat eval)
    !!ir (eval := AST.ite (condInf .& sign) llMinInFloat eval)
    dstAssignForFP fdB fdA (AST.cast CastKind.FtoITrunc 64<rt> eval) ir
  | _ ->
    let fs = transOprToFPPairConcat ctxt fs
    let llMax = numU64 0x7fffffffffffffffuL 64<rt>
    let llMin = numU64 0x8000000000000000uL 64<rt>
    let condInf = isInfinity 64<rt> fs
    let condNaN = isNaN64 fs
    let sign = AST.xthi 1<rt> fs
    let eval = !+ir 64<rt>
    !!ir (eval := AST.cast CastKind.FtoFTrunc 64<rt> fs)
    let inline conditionAssign cond result ir =
      !!ir (fdB := AST.ite cond (AST.xthi 32<rt> result) fdB)
      !!ir (fdA := AST.ite cond (AST.xtlo 32<rt> result) fdA)
    conditionAssign AST.b1 (AST.cast CastKind.FtoITrunc 64<rt> eval) ir
    conditionAssign (AST.fle eval llMinInFloat) llMin ir
    conditionAssign (AST.fge eval llMaxInFloat) llMax ir
    conditionAssign condNaN llMin ir
    conditionAssign (condInf .& (AST.not sign)) llMin ir
    conditionAssign (condInf .& sign) llMin ir
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
  let rd, rt = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let struct (t, eSize) = !+ir 32<rt>, int 8<rt>
  !<ir insLen
  !!ir (t := numI32 0 32<rt>)
  for e in 0 .. 3 do
    !!ir (elem t e eSize := AST.extract rt 8<rt> (eSize * (1 ^^^ e)))
  done
  !!ir (rd := AST.sext ctxt.WordBitSize t)
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
  | Op.CVTW | Op.CVTL -> sideEffects insLen ctxt UnsupportedFP
  | Op.CVTS -> cvts insInfo insLen ctxt
  | Op.DADD -> dadd insInfo insLen ctxt
  | Op.DADDU -> daddu insInfo insLen ctxt
  | Op.DADDIU -> daddiu insInfo insLen ctxt
  | Op.DCLZ -> dclz insInfo insLen ctxt
  | Op.DMFC1 -> dmfc1 insInfo insLen ctxt
  | Op.DMTC1 -> dmtc1 insInfo insLen ctxt
  | Op.DEXT -> dext insInfo insLen ctxt
  | Op.DEXTM -> dextx insInfo insLen checkDEXTMPosSize ctxt
  | Op.DEXTU -> dextx insInfo insLen checkDEXTUPosSize ctxt
  | Op.DINS -> dins insInfo insLen ctxt
  | Op.DINSM -> dinsx insInfo insLen checkDINSMPosSize ctxt
  | Op.DINSU -> dinsx insInfo insLen checkDINSUPosSize ctxt
  | Op.DIV when insInfo.Fmt.IsSome -> divdotsdotd insInfo insLen ctxt
  | Op.DIVU -> divu insInfo insLen ctxt
  | Op.DDIVU -> ddivu insInfo insLen ctxt
  | Op.DMULT -> dmul insInfo insLen ctxt true
  | Op.DMULTU -> dmul insInfo insLen ctxt false
  | Op.DROTR -> drotr insInfo insLen ctxt
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
  | Op.LL -> loadLinked insInfo insLen ctxt
  | Op.SDC1 -> sldc1 insInfo insLen ctxt true
  | Op.LDC1 -> sldc1 insInfo insLen ctxt false
  | Op.SWC1 -> slwc1 insInfo insLen ctxt true
  | Op.LWC1 -> slwc1 insInfo insLen ctxt false
  | Op.LUI -> lui insInfo insLen ctxt
  | Op.LDL -> loadLeftRight insInfo insLen ctxt (<<) (>>) (.&) 64<rt>
  | Op.LDR -> loadLeftRight insInfo insLen ctxt (>>) (<<) (<+>) 64<rt>
  | Op.LWL -> loadLeftRight insInfo insLen ctxt (<<) (>>) (.&) 32<rt>
  | Op.LWR -> loadLeftRight insInfo insLen ctxt (>>) (<<) (<+>) 32<rt>
  | Op.MADD -> madd insInfo insLen ctxt
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
  | Op.MTC1 -> mtc1 insInfo insLen ctxt
  | Op.MUL -> mul insInfo insLen ctxt
  | Op.MULT -> mult insInfo insLen ctxt
  | Op.MULTU -> multu insInfo insLen ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.NOR -> nor insInfo insLen ctxt
  | Op.OR -> logOr insInfo insLen ctxt
  | Op.ORI -> ori insInfo insLen ctxt
  | Op.PAUSE -> pause insLen ctxt
  | Op.PREF | Op.PREFE | Op.PREFX -> nop insLen ctxt
  | Op.RDHWR -> sideEffects insLen ctxt ProcessorID
  | Op.ROTR -> rotr insInfo insLen ctxt
  | Op.RECIP -> recip insInfo insLen ctxt
  | Op.SLL -> shiftLeftRight insInfo insLen ctxt (<<)
  | Op.SLLV -> shiftLeftRightVar insInfo insLen ctxt (<<)
  | Op.SLT -> sltAndU insInfo insLen ctxt (?<)
  | Op.SLTU -> sltAndU insInfo insLen ctxt (.<)
  | Op.SLTI -> sltiAndU insInfo insLen ctxt (?<)
  | Op.SLTIU -> sltiAndU insInfo insLen ctxt (.<)
  | Op.SSNOP -> nop insLen ctxt
  | Op.SB -> store insInfo insLen 8<rt> ctxt
  | Op.SC -> storeConditional insInfo insLen 32<rt> ctxt
  | Op.SD -> store insInfo insLen 64<rt> ctxt
  | Op.SEB -> seb insInfo insLen ctxt
  | Op.SEH -> seh insInfo insLen ctxt
  | Op.SH -> store insInfo insLen 16<rt> ctxt
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
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL | Op.DDIV | Op.DIV
  | Op.DROTR32 | Op.DROTRV | Op.DSBH | Op.DSHD | Op.J | Op.JAL | Op.LDXC1
  | Op.LWXC1 | Op.MADDU | Op.MSUB
  | Op.NEG | Op.ROTRV | Op.SDXC1 | Op.SQRT | Op.SWXC1 ->
    sideEffects insLen ctxt UnsupportedExtension // XXX this is a temporary fix
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)
