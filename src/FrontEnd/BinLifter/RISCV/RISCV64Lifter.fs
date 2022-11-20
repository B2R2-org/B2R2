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

module internal B2R2.FrontEnd.BinLifter.RISCV.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.RISCV

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline (:=) dst src =
  match dst with
  | { E = Var (_, rid, _, _) } when rid = Register.toRegID Register.X0 ->
    dst := dst (* Prevent setting x0. Our optimizer will remove this anyways. *)
  | _ ->
    dst := src

let inline getCSRReg (ctxt: TranslationContext) csr =
  let csrReg =
    match csr with
    | 0768us -> Register.CSR0768
    | 0769us -> Register.CSR0769
    | 0770us -> Register.CSR0770
    | 0771us -> Register.CSR0771
    | 0772us -> Register.CSR0772
    | 0773us -> Register.CSR0773
    | 0784us -> Register.CSR0784
    | 0832us -> Register.CSR0832
    | 0833us -> Register.CSR0833
    | 0834us -> Register.CSR0834
    | 0835us -> Register.CSR0835
    | 0836us -> Register.CSR0836
    | 0842us -> Register.CSR0842
    | 0843us -> Register.CSR0843
    | 3857us -> Register.CSR3857
    | 3858us -> Register.CSR3858
    | 3859us -> Register.CSR3859
    | 3860us -> Register.CSR3860
    | 0928us -> Register.CSR0928
    | 0930us -> Register.CSR0930
    | 0932us -> Register.CSR0932
    | 0934us -> Register.CSR0934
    | 0936us -> Register.CSR0936
    | 0938us -> Register.CSR0938
    | 0940us -> Register.CSR0940
    | 0942us -> Register.CSR0942
    | 0944us -> Register.CSR0944
    | 0945us -> Register.CSR0945
    | 0946us -> Register.CSR0946
    | 0947us -> Register.CSR0947
    | 0948us -> Register.CSR0948
    | 0949us -> Register.CSR0949
    | 0950us -> Register.CSR0950
    | 0951us -> Register.CSR0951
    | 0952us -> Register.CSR0952
    | 0953us -> Register.CSR0953
    | 0954us -> Register.CSR0954
    | 0955us -> Register.CSR0955
    | 0956us -> Register.CSR0956
    | 0957us -> Register.CSR0957
    | 0958us -> Register.CSR0958
    | 0959us -> Register.CSR0959
    | 0960us -> Register.CSR0960
    | 0961us -> Register.CSR0961
    | 0962us -> Register.CSR0962
    | 0963us -> Register.CSR0963
    | 0964us -> Register.CSR0964
    | 0965us -> Register.CSR0965
    | 0966us -> Register.CSR0966
    | 0967us -> Register.CSR0967
    | 0968us -> Register.CSR0968
    | 0969us -> Register.CSR0969
    | 0970us -> Register.CSR0970
    | 0971us -> Register.CSR0971
    | 0972us -> Register.CSR0972
    | 0973us -> Register.CSR0973
    | 0974us -> Register.CSR0974
    | 0975us -> Register.CSR0975
    | 0976us -> Register.CSR0976
    | 0977us -> Register.CSR0977
    | 0978us -> Register.CSR0978
    | 0979us -> Register.CSR0979
    | 0980us -> Register.CSR0980
    | 0981us -> Register.CSR0981
    | 0982us -> Register.CSR0982
    | 0983us -> Register.CSR0983
    | 0984us -> Register.CSR0984
    | 0985us -> Register.CSR0985
    | 0986us -> Register.CSR0986
    | 0987us -> Register.CSR0987
    | 0988us -> Register.CSR0988
    | 0989us -> Register.CSR0989
    | 0990us -> Register.CSR0990
    | 0991us -> Register.CSR0991
    | 0992us -> Register.CSR0992
    | 0993us -> Register.CSR0993
    | 0994us -> Register.CSR0994
    | 0995us -> Register.CSR0995
    | 0996us -> Register.CSR0996
    | 0997us -> Register.CSR0997
    | 0998us -> Register.CSR0998
    | 0999us -> Register.CSR0999
    | 1000us -> Register.CSR1000
    | 1001us -> Register.CSR1001
    | 1002us -> Register.CSR1002
    | 1003us -> Register.CSR1003
    | 1004us -> Register.CSR1004
    | 1005us -> Register.CSR1005
    | 1006us -> Register.CSR1006
    | 1007us -> Register.CSR1007
    | 2816us -> Register.CSR2816
    | 2818us -> Register.CSR2818
    | 2819us -> Register.CSR2819
    | 2820us -> Register.CSR2820
    | 2821us -> Register.CSR2821
    | 2822us -> Register.CSR2822
    | 2823us -> Register.CSR2823
    | 2824us -> Register.CSR2824
    | 2825us -> Register.CSR2825
    | 2826us -> Register.CSR2826
    | 2827us -> Register.CSR2827
    | 2828us -> Register.CSR2828
    | 2829us -> Register.CSR2829
    | 2830us -> Register.CSR2830
    | 2831us -> Register.CSR2831
    | 2832us -> Register.CSR2832
    | 2833us -> Register.CSR2833
    | 2834us -> Register.CSR2834
    | 2835us -> Register.CSR2835
    | 2836us -> Register.CSR2836
    | 2837us -> Register.CSR2837
    | 2838us -> Register.CSR2838
    | 2839us -> Register.CSR2839
    | 2840us -> Register.CSR2840
    | 2841us -> Register.CSR2841
    | 2842us -> Register.CSR2842
    | 2843us -> Register.CSR2843
    | 2844us -> Register.CSR2844
    | 2845us -> Register.CSR2845
    | 2846us -> Register.CSR2846
    | 2847us -> Register.CSR2847
    | 0800us -> Register.CSR0800
    | 0803us -> Register.CSR0803
    | 0804us -> Register.CSR0804
    | 0805us -> Register.CSR0805
    | 0806us -> Register.CSR0806
    | 0807us -> Register.CSR0807
    | 0808us -> Register.CSR0808
    | 0809us -> Register.CSR0809
    | 0810us -> Register.CSR0810
    | 0811us -> Register.CSR0811
    | 0812us -> Register.CSR0812
    | 0813us -> Register.CSR0813
    | 0814us -> Register.CSR0814
    | 0815us -> Register.CSR0815
    | 0816us -> Register.CSR0816
    | 0817us -> Register.CSR0817
    | 0818us -> Register.CSR0818
    | 0819us -> Register.CSR0819
    | 0820us -> Register.CSR0820
    | 0821us -> Register.CSR0821
    | 0822us -> Register.CSR0822
    | 0823us -> Register.CSR0823
    | 0824us -> Register.CSR0824
    | 0825us -> Register.CSR0825
    | 0826us -> Register.CSR0826
    | 0827us -> Register.CSR0827
    | 0828us -> Register.CSR0828
    | 0829us -> Register.CSR0829
    | 0830us -> Register.CSR0830
    | 0831us -> Register.CSR0831
    | 1952us -> Register.CSR1952
    | 1953us -> Register.CSR1953
    | 1954us -> Register.CSR1954
    | 1955us -> Register.CSR1955
    | 1968us -> Register.CSR1968
    | 1969us -> Register.CSR1969
    | 1970us -> Register.CSR1970
    | 1971us -> Register.CSR1971
    | _ -> raise InvalidRegisterException
  Register.toRegID csrReg |> ctxt.GetRegVar

let bvOfBaseAddr (ctxt: TranslationContext) addr = numU64 addr ctxt.WordBitSize

let bvOfInstrLen (ctxt: TranslationContext) insInfo =
  numU32 insInfo.NumBytes ctxt.WordBitSize

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

let getFiveOprs insInfo =
  match insInfo.Operands with
  | FiveOperands (o1, o2, o3, o4, o5) -> o1, o2, o3, o4, o5
  | _ -> raise InvalidOperandException

let transOprToExpr insInfo ctxt = function
  | OpReg reg -> getRegVar ctxt reg
  | OpImm imm
  | OpShiftAmount imm -> numU64 imm ctxt.WordBitSize
  | OpMem (b, Some (Imm o), sz) ->
    AST.loadLE sz (getRegVar ctxt b .+ numI64 o ctxt.WordBitSize)
  | OpAddr (Relative o) ->
    numI64 (int64 insInfo.Address + o) ctxt.WordBitSize
  | OpAddr (RelativeBase (b, imm)) ->
    if b = Register.X0 then AST.num0 ctxt.WordBitSize else
    (getRegVar ctxt b .+ numI64 (int64 imm) ctxt.WordBitSize)
  | OpMem (b, None, sz) ->
    AST.loadLE sz (getRegVar ctxt b)
  | OpAtomMemOper (aq, rl) ->
    numU32 0u 32<rt> //to fix
  | OpCSR (csr) -> getCSRReg ctxt csr
  | _ -> raise InvalidOperandException

let roundingToCastFloat x =
  match x with
  | OpRoundMode (rm) ->
    match rm with
    | RoundMode.RNE
    | RoundMode.RMM -> CastKind.FtoFRound
    | RoundMode.RTZ -> CastKind.FtoFTrunc
    | RoundMode.RDN -> CastKind.FtoFFloor
    | RoundMode.RUP -> CastKind.FtoFCeil
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandException

let roundingToCastInt x =
  match x with
  | OpRoundMode (rm) ->
    match rm with
    | RoundMode.RNE
    | RoundMode.RMM -> CastKind.FtoIRound
    | RoundMode.RTZ -> CastKind.FtoITrunc
    | RoundMode.RDN -> CastKind.FtoIFloor
    | RoundMode.RUP -> CastKind.FtoICeil
    | _ -> raise InvalidOperandException
  | _ -> raise InvalidOperandException

let dynamicRoundingFl ir ctxt rt res =
  let tmpVar = !+ir rt
  let fscr =
    (AST.extract (getRegVar ctxt Register.FCSR) 4<rt> 6) .& (numI32 7 4<rt>)
  let condRNERMM = (fscr == numI32 0 4<rt>) .| (fscr == numI32 4 4<rt>)
  let condRTZ = (fscr == numI32 1 4<rt>)
  let condRDN = (fscr == numI32 2 4<rt>)
  let condRUP = (fscr == numI32 3 4<rt>)
  let lblD0 = !%ir "D0"
  let lblD1 = !%ir "D1"
  let lblD2 = !%ir "D2"
  let lblD3 = !%ir "D3"
  let lblD4 = !%ir "D4"
  let lblD5 = !%ir "D6"
  let lblD6 = !%ir "D7"
  let lblDException = !%ir "DException"
  let lblDEnd = !%ir "DEnd"
  !!ir (AST.cjmp condRNERMM (AST.name lblD0) (AST.name lblD1))
  !!ir (AST.lmark lblD0)
  !!ir (tmpVar := AST.cast (CastKind.FtoFRound) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD1)
  !!ir (AST.cjmp condRTZ (AST.name lblD2) (AST.name lblD3))
  !!ir (AST.lmark lblD2)
  !!ir (tmpVar := AST.cast (CastKind.FtoFTrunc) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD3)
  !!ir (AST.cjmp condRDN (AST.name lblD4) (AST.name lblD5))
  !!ir (AST.lmark lblD4)
  !!ir (tmpVar := AST.cast (CastKind.FtoFFloor) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD5)
  !!ir (AST.cjmp condRUP (AST.name lblD6) (AST.name lblDException))
  !!ir (AST.lmark lblD6)
  !!ir (tmpVar := AST.cast (CastKind.FtoFCeil) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblDException)
  !!ir (AST.sideEffect (Exception "illegal instruction"))
  !!ir (AST.lmark lblDEnd)
  tmpVar

let dynamicRoundingInt ir ctxt rt res =
  let tmpVar = !+ir rt
  let fscr =
    (AST.extract (getRegVar ctxt Register.FCSR) 4<rt> 6) .& (numI32 7 4<rt>)
  let condRNERMM = (fscr == numI32 0 4<rt>) .| (fscr == numI32 4 4<rt>)
  let condRTZ = (fscr == numI32 1 4<rt>)
  let condRDN = (fscr == numI32 2 4<rt>)
  let condRUP = (fscr == numI32 3 4<rt>)
  let lblD0 = !%ir "D0"
  let lblD1 = !%ir "D1"
  let lblD2 = !%ir "D2"
  let lblD3 = !%ir "D3"
  let lblD4 = !%ir "D4"
  let lblD5 = !%ir "D6"
  let lblD6 = !%ir "D7"
  let lblDException = !%ir "DException"
  let lblDEnd = !%ir "DEnd"
  !!ir (AST.cjmp condRNERMM (AST.name lblD0) (AST.name lblD1))
  !!ir (AST.lmark lblD0)
  !!ir (tmpVar := AST.cast (CastKind.FtoIRound) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD1)
  !!ir (AST.cjmp condRTZ (AST.name lblD2) (AST.name lblD3))
  !!ir (AST.lmark lblD2)
  !!ir (tmpVar := AST.cast (CastKind.FtoITrunc) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD3)
  !!ir (AST.cjmp condRDN (AST.name lblD4) (AST.name lblD5))
  !!ir (AST.lmark lblD4)
  !!ir (tmpVar := AST.cast (CastKind.FtoIFloor) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD5)
  !!ir (AST.cjmp condRUP (AST.name lblD6) (AST.name lblDException))
  !!ir (AST.lmark lblD6)
  !!ir (tmpVar := AST.cast (CastKind.FtoICeil) rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblDException)
  !!ir (AST.sideEffect (Exception "illegal instruction"))
  !!ir (AST.lmark lblDEnd)
  tmpVar

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

let getAddrFromMem x =
  match x.E with
  | Load (_, _, addr, _) -> addr
  | _ -> raise InvalidExprException

let isAligned rt expr =
  match rt with
  | 32<rt> ->
    (expr .& (numU32 0x3u 64<rt>) == AST.num0 64<rt>)
  | 64<rt> ->
    ((expr .& (numU32 0x7u 64<rt>)) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let getAccessLength = function
  | OpMem (_, _, sz) -> sz
  | _ -> raise InvalidOperandException

let checkInf rt e =
  match rt with
  | 32<rt> ->
    let fullExponent = numU32 0x7F800000u 32<rt>
    let fullMantissa = numU32 0x7FFFFFu 32<rt>
    ((e .& fullExponent) == fullExponent) .&
    ((e .& fullMantissa) == AST.num0 32<rt>)
  | 64<rt> ->
    let fullExponent = numU64 0x7FF0000000000000uL 64<rt>
    let fullMantissa = numU64 0xFFFFFFFFFFFFFuL 64<rt>
    ((e .& fullExponent) == fullExponent) .&
    ((e .& fullMantissa) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let checkNan rt e =
  match rt with
  | 32<rt> ->
    let fullExponent = numU32 0x7F800000u 32<rt>
    let fullMantissa = numU32 0x7FFFFFu 32<rt>
    ((e .& fullExponent) == fullExponent) .&
    ((e .& fullMantissa) != AST.num0 32<rt>)
  | 64<rt> ->
    let fullExponent = numU64 0x7FF0000000000000uL 64<rt>
    let fullMantissa = numU64 0xFFFFFFFFFFFFFuL 64<rt>
    ((e .& fullExponent) == fullExponent) .&
    ((e .& fullMantissa) != AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let checkSNan rt e =
  let nanChecker = checkNan rt e
  match rt with
  | 32<rt> ->
    let signalBit = numU32 (1u <<< 22) 32<rt>
    nanChecker .& ((e .& signalBit) == AST.num0 32<rt>)
  | 64<rt> ->
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    nanChecker .& ((e .& signalBit) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let checkQNan rt e =
  let nanChecker = checkNan rt e
  match rt with
  | 32<rt> ->
    let signalBit = numU32 (1u <<< 22) 32<rt>
    nanChecker .& ((e .& signalBit) != AST.num0 32<rt>)
  | 64<rt> ->
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    nanChecker .& ((e .& signalBit) != AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let getSignFloat rt e =
  match rt with
  | 32<rt> ->
    e .& (numU32 0x80000000u 32<rt>)
  | 64<rt> ->
    e .& (numU64 0x8000000000000000uL 32<rt>)
  | _ -> raise InvalidRegTypeException

let checkSubnormal rt e =
  match rt with
  | 32<rt> ->
    let fullExponent = numU32 0x7F800000u 32<rt>
    let fullMantissa = numU32 0x7FFFFFu 32<rt>
    ((e .& fullExponent) == AST.num0 32<rt>) .&
    (e .& fullMantissa != AST.num0 32<rt>)
  | 64<rt> ->
    let fullExponent = numU64 0x7FF0000000000000uL 64<rt>
    let fullMantissa = numU64 0xFFFFFFFFFFFFFuL 64<rt>
    ((e .& fullExponent) == AST.num0 64<rt>) .&
    (e .& fullMantissa != AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let private checkOverfolwOnDMul e1 e2 =
  let mask64 = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
  let bit32 = numI64 0x100000000L 64<rt>
  let cond = mask64 .- e1 .< e2
  AST.ite cond bit32 (AST.num0 64<rt>)

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

let add insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs1 .+ rs2)
  !!ir (rd := result)
  !>ir insLen

let addw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  !!ir (rd := AST.sext 64<rt> (rs1 .+ rs2))
  !>ir insLen

let subw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  !!ir (rd := AST.sext 64<rt> (rs1 .- rs2))
  !>ir insLen

let sub insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs1 .- rs2)
  !!ir (rd := result)
  !>ir insLen

let ``and`` insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs1 .& rs2)
  !!ir (rd := result)
  !>ir insLen

let ``or`` insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs1 .| rs2)
  !!ir (rd := result)
  !>ir insLen

let xor insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = !+ir 64<rt>
  !<ir insLen
  !!ir (result := rs1 <+> rs2)
  !!ir (rd := result)
  !>ir insLen

let slt insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = (rs1 ?< rs2)
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let sltu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let sll insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = (rs2 .& numU64 0x3fUL 64<rt>)
  !<ir insLen
  !!ir (rd := rs1 << shiftAmm)
  !>ir insLen

let sllw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let shiftAmm = (rs2 .& numU32 0x1fu 32<rt>)
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (rs1 << shiftAmm))
  !>ir insLen

let srl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = (rs2 .& numU64 0x3fUL 64<rt>)
  !<ir insLen
  !!ir (rd := rs1 >> shiftAmm)
  !>ir insLen

let srlw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let shiftAmm = (rs2 .& numU32 0x1fu 32<rt>)
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (rs1 >> shiftAmm))
  !>ir insLen

let sra insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = (rs2 .& numU64 0x3fUL 64<rt>)
  !<ir insLen
  !!ir (rd := rs1 ?>> shiftAmm)
  !>ir insLen

let sraw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let shiftAmm = (rs2 .& numU32 0x1fu 32<rt>)
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (rs1 ?>> shiftAmm))
  !>ir insLen

let srai insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shiftAmm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 ?>> shiftAmm)
  !>ir insLen

let srli insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shiftAmm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 >> shiftAmm)
  !>ir insLen

let slli insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shiftAmm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 << shiftAmm)
  !>ir insLen

let andi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 .& imm)
  !>ir insLen

let addi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 .+ imm)
  !>ir insLen

let ori insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 .| imm)
  !>ir insLen

let xori insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 <+> imm)
  !>ir insLen

let slti insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = (rs1 ?< imm)
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let sltiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs1 imm
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let jal insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, jumpTarget = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let r = bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (rd := r)
  !!ir (AST.interjmp jumpTarget InterJmpKind.Base)
  !>ir insLen

let jalr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, jumpTarget = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let r = bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (rd := r)
  !!ir (AST.interjmp (if jumpTarget = AST.num0 ctxt.WordBitSize
                      then rd else jumpTarget) InterJmpKind.Base)
  !>ir insLen

let beq insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 == rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let bne insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 != rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let blt insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 ?< rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let bge insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 ?>= rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let bltu insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs1 rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let bgeu insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.ge rs1 rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let load insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.sext ctxt.WordBitSize mem)
  !>ir insLen

let loadu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.zext ctxt.WordBitSize mem)
  !>ir insLen

let store insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let accessLength = getAccessLength (snd (getTwoOprs insInfo))
  !<ir insLen
  !!ir (mem := AST.xtlo accessLength rd)
  !>ir insLen

let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let lui insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let imm = imm << numI32 12 ctxt.WordBitSize
  !<ir insLen
  !!ir (rd := imm)
  !>ir insLen

let auipc insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let imm = imm << numI32 12 ctxt.WordBitSize
  let pc = bvOfBaseAddr ctxt insInfo.Address
  !<ir insLen
  !!ir (rd := pc .+ imm)
  !>ir insLen

let addiw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = !+ir 32<rt>
  !<ir insLen
  !!ir (retValue := lowBitsRs1 .+ AST.xtlo 32<rt> imm)
  !!ir (rd := AST.sext 64<rt> retValue)
  !>ir insLen

let slliw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = !+ir 32<rt>
  !<ir insLen
  !!ir (retValue := lowBitsRs1 << AST.xtlo 32<rt> shamt)
  !!ir (rd := AST.sext 64<rt> retValue)
  !>ir insLen

let srliw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = !+ir 32<rt>
  !<ir insLen
  !!ir (retValue := lowBitsRs1 >> AST.xtlo 32<rt> shamt)
  !!ir (rd := AST.sext 64<rt> retValue)
  !>ir insLen

let sraiw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = !+ir 32<rt>
  !<ir insLen
  !!ir (retValue := lowBitsRs1 ?>> AST.xtlo 32<rt> shamt)
  !!ir (rd := AST.sext 64<rt> retValue)
  !>ir insLen

let mul insInfo insLen ctxt isSign =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let struct (_, low) = mul64BitReg rs1 rs2 ir isSign
  !<ir insLen
  !!ir (rd := low)
  !>ir insLen

let mulhSignOrUnsign insInfo insLen ctxt isSign =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let struct (high, _) = mul64BitReg rs1 rs2 ir isSign
  !<ir insLen
  !!ir (rd := high)
  !>ir insLen

let mulw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let lowBitsRs2 = AST.xtlo 32<rt> rs2
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (lowBitsRs1 .* lowBitsRs2))
  !>ir insLen

let div insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let condOverflow
    = ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rd := rs1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (rd := rs1 ?/ rs2)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let divw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let condOverflow =
    ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rd := AST.sext 64<rt> rs1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (rd := AST.sext 64<rt> (rs1 ?/ rs2))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let divuw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := AST.sext 64<rt> (rs1 ./ rs2))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let divu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := rs1 ./ rs2)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let remu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rs1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := rs1 .% rs2)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let rem insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let condOverflow =
    ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rs1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rd := AST.num0 64<rt>)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (rd := rs1 ?% rs2)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let remw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let condOverflow =
    ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := AST.sext 64<rt> rs1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rd := AST.num0 64<rt>)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (rd := AST.sext 64<rt> (rs1 ?% rs2))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let remuw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rd := AST.sext 64<rt> rs1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := AST.sext 64<rt> (rs1 .% rs2))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fld insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let condAlign = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (rd := AST.sext ctxt.WordBitSize mem)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := AST.sext ctxt.WordBitSize mem)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fsd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let condAlign = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (mem := rd)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (mem := rd)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fltdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let checkNan = (checkNan 32<rt> rs1 .| checkNan 32<rt> rs2)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.flt rs1 rs2
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  let fscr = getRegVar ctxt R.FCSR
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fscr := fscr .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fledots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let checkNan = (checkNan 32<rt> rs1 .| checkNan 32<rt> rs2)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fscr := fscr .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let feqdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let checkSNan = (checkSNan 32<rt> rs1 .| checkSNan 32<rt> rs2)
  let checkNan = (checkNan 32<rt> rs1 .| checkNan 32<rt> rs2)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.feq rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  let flagFscr = (AST.ite (checkSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>))
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fscr := fscr .| flagFscr)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fclassdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1

  let plusZero = numU32 0u 32<rt>
  let negZero = numU32 0x80000000u 32<rt>
  let sign = AST.extract rs1 1<rt> 31

  let lblPos = !%ir "Pos"
  let lblNeg = !%ir "Neg"
  let lblEnd = !%ir "End"

  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = checkInf 32<rt> rs1
  let condSubnormal = checkSubnormal 32<rt> rs1
  let condSNan = checkSNan 32<rt> rs1
  let condQNan = checkQNan 32<rt> rs1

  let rdOr f = (rd := rd .| f)

  !<ir insLen
  !!ir (rd := AST.num0 64<rt>)
  !!ir (AST.cjmp sign (AST.name lblNeg) (AST.name lblPos))
  !!ir (AST.lmark lblPos)
  !!ir
    (rdOr (AST.ite condInf (numU32 (1u <<< 7) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condZero (numU32 (1u <<< 4) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) (AST.num0 64<rt>)))
  !!ir (rdOr (AST.ite (rd == AST.num0 64<rt>)
    (numU32 (1u <<< 6) 64<rt>) (AST.num0 64<rt>)))
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblNeg)
  !!ir
    (rdOr (AST.ite condInf (numU32 (1u <<< 0) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condZero (numU32 (1u <<< 3) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) (AST.num0 64<rt>)))
  !!ir (rdOr (AST.ite (rd == AST.num0 64<rt>)
    (numU32 (1u <<< 1) 64<rt>) (AST.num0 64<rt>)))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fclassdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt

  let plusZero = numU64 0uL 64<rt>
  let negZero = numU64 0x8000000000000000uL 64<rt>
  let sign = AST.extract rs1 1<rt> 63

  let lblPos = !%ir "Pos"
  let lblNeg = !%ir "Neg"
  let lblEnd = !%ir "End"

  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = checkInf 64<rt> rs1
  let condSubnormal = checkSubnormal 64<rt> rs1
  let condSNan = checkSNan 64<rt> rs1
  let condQNan = checkQNan 64<rt> rs1

  let rdOr f = (rd := rd .| f)

  !<ir insLen
  !!ir (rd := AST.num0 64<rt>)
  !!ir (AST.cjmp sign (AST.name lblNeg) (AST.name lblPos))
  !!ir (AST.lmark lblPos)
  !!ir
    (rdOr (AST.ite condInf (numU32 (1u <<< 7) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condZero (numU32 (1u <<< 4) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) (AST.num0 64<rt>)))
  !!ir (rdOr (AST.ite (rd == AST.num0 64<rt>)
    (numU32 (1u <<< 6) 64<rt>) (AST.num0 64<rt>)))
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblNeg)
  !!ir
    (rdOr (AST.ite condInf (numU32 (1u <<< 0) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condZero (numU32 (1u <<< 3) 64<rt>) (AST.num0 64<rt>)))
  !!ir
    (rdOr (AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) (AST.num0 64<rt>)))
  !!ir (rdOr (AST.ite (rd == AST.num0 64<rt>)
    (numU32 (1u <<< 1) 64<rt>) (AST.num0 64<rt>)))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let flw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let tmp = !+ir 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (tmp := mem)
  !!ir (rd := (AST.zext 64<rt> tmp) .| upperBitOne)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (tmp := mem)
  !!ir (rd := (AST.zext 64<rt> tmp) .| upperBitOne)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fsw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (mem := AST.xtlo 32<rt> rd)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (mem := AST.xtlo 32<rt> rd)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fltdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkNan = (checkNan 64<rt> rs1 .| checkNan 64<rt> rs2)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.flt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fscr := fscr .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fledotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkNan = (checkNan 64<rt> rs1 .| checkNan 64<rt> rs2)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fscr := fscr .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let feqdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkSNan = (checkSNan 64<rt> rs1 .| checkSNan 64<rt> rs2)
  let checkNan = (checkNan 64<rt> rs1 .| checkNan 64<rt> rs2)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.feq rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  let flagFscr = (AST.ite (checkSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>))
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fscr := fscr .| flagFscr)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fadddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> (AST.fadd rs1 rs2))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> (AST.fadd rs1 rs2)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fadddotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> (AST.fadd rs1 rs2))
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> (AST.fadd rs1 rs2)
    !!ir (rd := rtVal)
    !>ir insLen

let fsubdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> (AST.fsub rs1 rs2))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> (AST.fsub rs1 rs2)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fsubdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> (AST.fsub rs1 rs2))
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> (AST.fsub rs1 rs2)
    !!ir (rd := rtVal)
    !>ir insLen

let fmuldots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> (AST.fmul rs1 rs2))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> (AST.fmul rs1 rs2)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fmuldotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> (AST.fmul rs1 rs2))
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> (AST.mul rs1 rs2)
    !!ir (rd := rtVal)
    !>ir insLen

let fdivdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> (AST.fdiv rs1 rs2))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> (AST.fdiv rs1 rs2)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fdivdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rounding = roundingToCastFloat rm
  let rtVal = !+ir 64<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast rounding 64<rt> (AST.fdiv rs1 rs2))
  !!ir (rd := rtVal)
  !>ir insLen

let fsqrtdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> (AST.fsqrt rs1))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> (AST.fsqrt rs1)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fsqrtdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> (AST.fsqrt rs1))
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> (AST.fsqrt rs1)
    !!ir (rd := rtVal)
    !>ir insLen

let fmindots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = !+ir 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let cond = AST.flt rs1 rs2
  !<ir insLen
  !!ir (rtVal := AST.ite cond rs1 rs2)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fmindotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = !+ir 64<rt>
  let cond = AST.flt rs1 rs2
  !<ir insLen
  !!ir (rtVal := AST.ite cond rs1 rs2)
  !!ir (rd := rtVal)
  !>ir insLen

let fmaxdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = !+ir 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let cond = AST.flt rs1 rs2
  !<ir insLen
  !!ir (rtVal := AST.ite cond rs2 rs1)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fmaxdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = !+ir 64<rt>
  let cond = AST.flt rs1 rs2
  !<ir insLen
  !!ir (rtVal := AST.ite cond rs2 rs1)
  !!ir (rd := rtVal)
  !>ir insLen

let fmadddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = numU64 0xFFFFFFFF00000000uL 64<rt>
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir
      (rtVal := AST.cast rounding 32<rt> (AST.fadd (AST.fmul rs1 rs2) rs3))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal =
      dynamicRoundingFl ir ctxt 32<rt> (AST.fadd (AST.fmul rs1 rs2) rs3)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fmadddotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir
      (rtVal := AST.cast rounding 64<rt> (AST.fadd (AST.fmul rs1 rs2) rs3))
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal =
      dynamicRoundingFl ir ctxt 64<rt> (AST.fadd (AST.fmul rs1 rs2) rs3)
    !!ir (rd := rtVal)
    !>ir insLen

let fmsubdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir
      (rtVal := AST.cast rounding 32<rt> (AST.fsub (AST.fmul rs1 rs2) rs3))
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal =
      dynamicRoundingFl ir ctxt 32<rt> (AST.fsub (AST.fmul rs1 rs2) rs3)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fmsubdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir
      (rtVal := AST.cast rounding 64<rt> (AST.fsub (AST.fmul rs1 rs2) rs3))
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal =
      dynamicRoundingFl ir ctxt 64<rt> (AST.fsub (AST.fmul rs1 rs2) rs3)
    !!ir (rd := rtVal)
    !>ir insLen

let fnmsubdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let res = (AST.fsub (AST.neg rs3) (AST.fmul rs1 rs2))
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> res)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> res
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fnmsubdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let res = (AST.fsub (AST.neg rs3) (AST.fmul rs1 rs2))
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> res)
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> res
    !!ir (rd := rtVal)
    !>ir insLen

let fnmadddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let res = (AST.fsub rs3 (AST.fmul rs1 rs2))
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> res)
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> res
    !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    !>ir insLen

let fnmadddotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let res = (AST.fsub rs3 (AST.fmul rs1 rs2))
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> res)
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> res
    !!ir (rd := rtVal)
    !>ir insLen

let fsgnjdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = !+ir 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fsgnjdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = !+ir 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := rtVal)
  !>ir insLen

let fsgnjndots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = !+ir 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2 <+> numU32 0x80000000u 32<rt>
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fsgnjndotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = !+ir 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2 <+> numU64 0x8000000000000000uL 64<rt>
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := rtVal)
  !>ir insLen

let fsgnjxdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = !+ir 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = (getSignFloat 32<rt> rs2) <+> (getSignFloat 32<rt> rs1)
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fsgnjxdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = !+ir 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2 <+> getSignFloat 64<rt> rs1
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := rtVal)
  !>ir insLen

(* FIX ME: AQRL *)
let amod insInfo insLen ctxt op =
  let ir = !*ctxt
  let rd, mem, rs2, aqrl = getFourOprs insInfo |> transFourOprs insInfo ctxt
  let cond = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (tmp := mem)
  !!ir (mem := op tmp rs2)
  !!ir (rd := tmp)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.sideEffect (Exception "Address-misaligned exception"))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let amow insInfo insLen ctxt op =
  let ir = !*ctxt
  let rd, mem, rs2, aqrl = getFourOprs insInfo |> transFourOprs insInfo ctxt
  let rs2 = AST.xtlo 32<rt> rs2
  let cond = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (tmp := mem)
  !!ir (mem := AST.sext 64<rt> (op tmp rs2))
  !!ir (rd := AST.sext 64<rt> tmp)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.sideEffect (Exception "Address-misaligned exception"))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fmvdotxdotw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (AST.xtlo 32<rt> rs1))
  !>ir insLen

let fmvdotwdotx insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.xtlo 32<rt> rs1)
  !>ir insLen

let fmvdotxdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1)
  !>ir insLen

let fmvdotddotx insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1)
  !>ir insLen

(* TODO: x0 and 0 change write csr *)
let csrrw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := rs1)
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrwi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := AST.zext 64<rt> imm)
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrs insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .| rs1)
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrsi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .| (AST.zext 64<rt> imm))
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrc insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .& (AST.neg rs1))
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrci insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 64<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .& (AST.neg (AST.zext 64<rt> imm)))
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

(* TODO: RM and overflow *)
let fcvtdotldotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> rs1)
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingInt ir ctxt 64<rt> rs1
    !!ir (rd := rtVal)
    !>ir insLen

let fcvtdotwdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> rs1)
    !!ir (rd := rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingInt ir ctxt 32<rt> rs1
    !!ir (rd := rtVal)
    !>ir insLen

let fcvtdotwdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 32<rt> rs1)
    !!ir (rd := AST.sext 64<rt> rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingInt ir ctxt 32<rt> rs1
    !!ir (rd := AST.sext 64<rt> rtVal)
    !>ir insLen

let fcvtdotldots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    !!ir (rtVal := AST.cast rounding 64<rt> rs1)
    !!ir (rd := AST.sext 64<rt> rtVal)
    !>ir insLen
  else
    !<ir insLen
    let rtVal = dynamicRoundingInt ir ctxt 64<rt> rs1
    !!ir (rd := AST.sext 64<rt> rtVal)
    !>ir insLen

let fcvtdotsdotw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.IntToFloat 32<rt> rs1)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fcvtdotsdotl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.IntToFloat 32<rt> rs1)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fcvtdotddotw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.IntToFloat 64<rt> (AST.xtlo 32<rt> rs1))
  !>ir insLen

let fcvtdotddotl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.IntToFloat 64<rt> rs1)
  !>ir insLen

let fcvtdotsdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.FloatCast 32<rt> rs1)
  !!ir (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  !>ir insLen

let fcvtdotddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.FloatCast 64<rt> (AST.xtlo 32<rt> rs1))
  !>ir insLen

(* TODO: Add reservation check *)
let lr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem, aqrl = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.sext ctxt.WordBitSize mem)
  !>ir insLen

(* TODO: Add reservation check *)
let sc insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem, aqrl = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let accessLength = getAccessLength (snd (getTwoOprs insInfo))
  !<ir insLen
  !!ir (mem := AST.xtlo accessLength rd)
  !!ir (rd := numI32 0 64<rt>)
  !>ir insLen

let translate insInfo insLen (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | Op.CdotMV
  | Op.CdotADD
  | Op.ADD -> add insInfo insLen ctxt
  | Op.CdotADDW
  | Op.ADDW -> addw insInfo insLen ctxt
  | Op.CdotSUBW
  | Op.SUBW -> subw insInfo insLen ctxt
  | Op.CdotAND
  | Op.AND -> ``and`` insInfo insLen ctxt
  | Op.CdotOR
  | Op.OR -> ``or`` insInfo insLen ctxt
  | Op.CdotXOR
  | Op.XOR -> xor insInfo insLen ctxt
  | Op.CdotSUB
  | Op.SUB -> sub insInfo insLen ctxt
  | Op.SLT -> slt insInfo insLen ctxt
  | Op.SLTU -> sltu insInfo insLen ctxt
  | Op.SLL -> sll insInfo insLen ctxt
  | Op.SLLW -> sllw insInfo insLen ctxt
  | Op.SRA -> sra insInfo insLen ctxt
  | Op.SRAW -> sraw insInfo insLen ctxt
  | Op.SRL -> srl insInfo insLen ctxt
  | Op.SRLW -> srlw insInfo insLen ctxt
  | Op.CdotANDI
  | Op.ANDI -> andi insInfo insLen ctxt
  | Op.CdotADDI16SP
  | Op.CdotLI
  | Op.CdotADDI
  | Op.CdotADDI4SPN
  | Op.ADDI -> addi insInfo insLen ctxt
  | Op.ORI -> ori insInfo insLen ctxt
  | Op.XORI -> xori insInfo insLen ctxt
  | Op.SLTI -> slti insInfo insLen ctxt
  | Op.SLTIU -> sltiu insInfo insLen ctxt
  | Op.CdotJ
  | Op.JAL -> jal insInfo insLen ctxt
  | Op.CdotJR
  | Op.CdotJALR
  | Op.JALR -> jalr insInfo insLen ctxt
  | Op.CdotBEQZ
  | Op.BEQ -> beq insInfo insLen ctxt
  | Op.CdotBNEZ
  | Op.BNE -> bne insInfo insLen ctxt
  | Op.BLT -> blt insInfo insLen ctxt
  | Op.BGE -> bge insInfo insLen ctxt
  | Op.BLTU -> bltu insInfo insLen ctxt
  | Op.BGEU -> bgeu insInfo insLen ctxt
  | Op.CdotLW
  | Op.CdotLD
  | Op.CdotLWSP
  | Op.CdotLDSP
  | Op.LB
  | Op.LH
  | Op.LW
  | Op.LD -> load insInfo insLen ctxt
  | Op.LBU
  | Op.LHU
  | Op.LWU -> loadu insInfo insLen ctxt
  | Op.CdotSW
  | Op.CdotSD
  | Op.CdotSWSP
  | Op.CdotSDSP
  | Op.SB
  | Op.SH
  | Op.SW
  | Op.SD -> store insInfo insLen ctxt
  | Op.CdotEBREAK
  | Op.EBREAK -> sideEffects insLen ctxt Breakpoint
  | Op.ECALL -> sideEffects insLen ctxt SysCall
  | Op.CdotSRAI
  | Op.SRAI -> srai insInfo insLen ctxt
  | Op.CdotSLLI
  | Op.SLLI -> slli insInfo insLen ctxt
  | Op.CdotSRLI
  | Op.SRLI -> srli insInfo insLen ctxt
  | Op.CdotLUI
  | Op.LUI -> lui insInfo insLen ctxt
  | Op.AUIPC -> auipc insInfo insLen ctxt
  | Op.CdotADDIW
  | Op.ADDIW -> addiw insInfo insLen ctxt
  | Op.SLLIW -> slliw insInfo insLen ctxt
  | Op.SRLIW -> srliw insInfo insLen ctxt
  | Op.SRAIW -> sraiw insInfo insLen ctxt
  | Op.MUL -> mul insInfo insLen ctxt true
  | Op.MULH -> mulhSignOrUnsign insInfo insLen ctxt true
  | Op.MULHU -> mulhSignOrUnsign insInfo insLen ctxt false
  | Op.MULHSU -> mulhSignOrUnsign insInfo insLen ctxt true
  | Op.MULW -> mulw insInfo insLen ctxt
  | Op.CdotNOP -> nop insLen ctxt
  | Op.CdotFLD
  | Op.CdotFLDSP
  | Op.FLD -> fld insInfo insLen ctxt
  | Op.CdotFSD
  | Op.CdotFSDSP
  | Op.FSD -> fsd insInfo insLen ctxt
  | Op.FLTdotS -> fltdots insInfo insLen ctxt
  | Op.FLTdotD -> fltdotd insInfo insLen ctxt
  | Op.FLEdotS -> fledots insInfo insLen ctxt
  | Op.FLEdotD -> fledotd insInfo insLen ctxt
  | Op.FEQdotS -> feqdots insInfo insLen ctxt
  | Op.FEQdotD -> feqdotd insInfo insLen ctxt
  | Op.FLW -> flw insInfo insLen ctxt
  | Op.FSW -> fsw insInfo insLen ctxt
  | Op.FADDdotS -> fadddots insInfo insLen ctxt
  | Op.FADDdotD -> fadddotd insInfo insLen ctxt
  | Op.FSUBdotS -> fsubdots insInfo insLen ctxt
  | Op.FSUBdotD -> fsubdotd insInfo insLen ctxt
  | Op.FDIVdotS -> fdivdots insInfo insLen ctxt
  | Op.FDIVdotD -> fdivdotd insInfo insLen ctxt
  | Op.FMULdotS -> fmuldots insInfo insLen ctxt
  | Op.FMULdotD -> fmuldotd insInfo insLen ctxt
  | Op.FMINdotS -> fmindots insInfo insLen ctxt
  | Op.FMINdotD -> fmindotd insInfo insLen ctxt
  | Op.FMAXdotS -> fmaxdots insInfo insLen ctxt
  | Op.FMAXdotD -> fmaxdotd insInfo insLen ctxt
  | Op.FNMADDdotS -> fnmadddots insInfo insLen ctxt
  | Op.FNMADDdotD -> fnmadddotd insInfo insLen ctxt
  | Op.FNMSUBdotS -> fnmsubdots insInfo insLen ctxt
  | Op.FNMSUBdotD -> fnmsubdotd insInfo insLen ctxt
  | Op.FMADDdotS -> fmadddots insInfo insLen ctxt
  | Op.FMADDdotD -> fmadddotd insInfo insLen ctxt
  | Op.FMSUBdotS -> fmsubdots insInfo insLen ctxt
  | Op.FMSUBdotD -> fmsubdotd insInfo insLen ctxt
  | Op.FSQRTdotS -> fsqrtdots insInfo insLen ctxt
  | Op.FSQRTdotD -> fsqrtdotd insInfo insLen ctxt
  | Op.FCLASSdotS -> fclassdots insInfo insLen ctxt
  | Op.FCLASSdotD -> fclassdotd insInfo insLen ctxt
  | Op.FSGNJdotS -> fsgnjdots insInfo insLen ctxt
  | Op.FSGNJdotD -> fsgnjdotd insInfo insLen ctxt
  | Op.FSGNJNdotS -> fsgnjndots insInfo insLen ctxt
  | Op.FSGNJNdotD -> fsgnjndotd insInfo insLen ctxt
  | Op.FSGNJXdotS -> fsgnjxdots insInfo insLen ctxt
  | Op.FSGNJXdotD -> fsgnjxdotd insInfo insLen ctxt
  | Op.AMOADDdotW -> amow insInfo insLen ctxt (.+)
  | Op.AMOADDdotD -> amod insInfo insLen ctxt (.+)
  | Op.AMOANDdotW -> amow insInfo insLen ctxt (.&)
  | Op.AMOANDdotD -> amod insInfo insLen ctxt (.&)
  | Op.AMOXORdotW -> amow insInfo insLen ctxt (<+>)
  | Op.AMOXORdotD -> amod insInfo insLen ctxt (<+>)
  | Op.AMOORdotW -> amow insInfo insLen ctxt (.|)
  | Op.AMOORdotD -> amod insInfo insLen ctxt (.|)
  | Op.AMOMINdotW ->
    amow insInfo insLen ctxt (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINdotD ->
    amod insInfo insLen ctxt (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINUdotW ->
    amow insInfo insLen ctxt (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMINUdotD ->
    amod insInfo insLen ctxt (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMAXdotW ->
    amow insInfo insLen ctxt (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXdotD ->
    amod insInfo insLen ctxt (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXUdotW ->
    amow insInfo insLen ctxt (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOMAXUdotD ->
    amod insInfo insLen ctxt (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOSWAPdotW -> amow insInfo insLen ctxt (fun _ b -> b)
  | Op.AMOSWAPdotD -> amod insInfo insLen ctxt (fun _ b -> b)
  | Op.FMVdotXdotW -> fmvdotxdotw insInfo insLen ctxt
  | Op.FMVdotXdotD -> fmvdotxdotd insInfo insLen ctxt
  | Op.FMVdotWdotX -> fmvdotwdotx insInfo insLen ctxt
  | Op.FMVdotDdotX -> fmvdotddotx insInfo insLen ctxt
  | Op.DIVW -> divw insInfo insLen ctxt
  | Op.DIV -> div insInfo insLen ctxt
  | Op.DIVU -> divu insInfo insLen ctxt
  | Op.REM -> rem insInfo insLen ctxt
  | Op.REMU -> remu insInfo insLen ctxt
  | Op.REMW -> remw insInfo insLen ctxt
  | Op.DIVUW -> divuw insInfo insLen ctxt
  | Op.REMUW -> remuw insInfo insLen ctxt
  | Op.FCVTdotWdotD -> fcvtdotwdotd insInfo insLen ctxt
  | Op.FCVTdotLdotD -> fcvtdotldotd insInfo insLen ctxt
  | Op.FCVTdotWdotS -> fcvtdotwdots insInfo insLen ctxt
  | Op.FCVTdotLdotS -> fcvtdotldots insInfo insLen ctxt
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO -> nop insLen ctxt
  | Op.LRdotW
  | Op.LRdotD -> lr insInfo insLen ctxt
  | Op.SCdotW
  | Op.SCdotD -> sc insInfo insLen ctxt
  | Op.CSRRW -> csrrw insInfo insLen ctxt
  | Op.CSRRWI -> csrrwi insInfo insLen ctxt
  | Op.CSRRS -> csrrs insInfo insLen ctxt
  | Op.CSRRSI -> csrrsi insInfo insLen ctxt
  | Op.CSRRC -> csrrc insInfo insLen ctxt
  | Op.CSRRCI -> csrrci insInfo insLen ctxt
  | Op.FCVTdotSdotW -> fcvtdotsdotw insInfo insLen ctxt
  | Op.FCVTdotSdotL -> fcvtdotsdotl insInfo insLen ctxt
  | Op.FCVTdotSdotD -> fcvtdotsdotd insInfo insLen ctxt
  | Op.FCVTdotDdotS -> fcvtdotddots insInfo insLen ctxt
  | Op.FCVTdotDdotW -> fcvtdotddotw insInfo insLen ctxt
  | Op.FCVTdotDdotL -> fcvtdotddotl insInfo insLen ctxt
  | Op.FCVTdotLUdotD
  | Op.FCVTdotDdotLU
  | Op.FCVTdotWUdotD
  | Op.FCVTdotDdotWU
  | Op.FCVTdotWUdotS
  | Op.FCVTdotSdotWU
  | Op.FCVTdotLUdotS
  | Op.FCVTdotSdotLU
    -> raise <| NotImplementedIRException (Disasm.opCodeToString insInfo.Opcode)
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException (Disasm.opCodeToString o)
