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
    | 0001us -> Register.FFLAGS
    | 0002us -> Register.FRM
    | 0003us -> Register.FCSR
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
    | _ ->
      eprintfn "%A" csr
      raise InvalidRegisterException
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
    let reg = getRegVar ctxt b
    let offset = numI64 o ctxt.WordBitSize
    AST.loadLE sz (reg .+ offset)
  | OpAddr (Relative o) -> numI64 (int64 insInfo.Address + o) ctxt.WordBitSize
  | OpAddr (RelativeBase (b, imm)) ->
    if b = Register.X0 then
      AST.num0 ctxt.WordBitSize
    else
      let target = getRegVar ctxt b .+ numI64 (int64 imm) ctxt.WordBitSize
      let mask = numI64 0xFFFFFFFF_FFFFFFFEL 64<rt>
      target .& mask
  | OpMem (b, None, sz) -> AST.loadLE sz (getRegVar ctxt b)
  | OpAtomMemOper (_) -> numU32 0u 32<rt> // FIXME:
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
  let frm = (getRegVar ctxt Register.FRM) .& (numI32 7 8<rt>)
  let condRNERMM = (frm == numI32 0 8<rt>) .| (frm == numI32 4 8<rt>)
  let condRTZ = frm == numI32 1 8<rt>
  let condRDN = frm == numI32 2 8<rt>
  let condRUP = frm == numI32 3 8<rt>
  let lblD0 = !%ir "DF0"
  let lblD1 = !%ir "DF1"
  let lblD2 = !%ir "DF2"
  let lblD3 = !%ir "DF3"
  let lblD4 = !%ir "DF4"
  let lblD5 = !%ir "DF6"
  let lblD6 = !%ir "DF7"
  let lblDException = !%ir "DFException"
  let lblDEnd = !%ir "DFEnd"
  !!ir (AST.cjmp condRNERMM (AST.name lblD0) (AST.name lblD1))
  !!ir (AST.lmark lblD0)
  !!ir (tmpVar := AST.cast CastKind.FtoFRound rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD1)
  !!ir (AST.cjmp condRTZ (AST.name lblD2) (AST.name lblD3))
  !!ir (AST.lmark lblD2)
  !!ir (tmpVar := AST.cast CastKind.FtoFTrunc rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD3)
  !!ir (AST.cjmp condRDN (AST.name lblD4) (AST.name lblD5))
  !!ir (AST.lmark lblD4)
  !!ir (tmpVar := AST.cast CastKind.FtoFFloor rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblD5)
  !!ir (AST.cjmp condRUP (AST.name lblD6) (AST.name lblDException))
  !!ir (AST.lmark lblD6)
  !!ir (tmpVar := AST.cast CastKind.FtoFCeil rt res)
  !!ir (AST.jmp (AST.name lblDEnd))
  !!ir (AST.lmark lblDException)
  !!ir (AST.sideEffect (Exception "illegal instruction"))
  !!ir (AST.lmark lblDEnd)
  tmpVar

let dynamicRoundingInt ir ctxt rt res =
  let tmpVar = !+ir rt
  let frm = (getRegVar ctxt Register.FRM) .& (numI32 7 8<rt>)
  let condRNERMM = (frm == numI32 0 8<rt>) .| (frm == numI32 4 8<rt>)
  let condRTZ = frm == numI32 1 8<rt>
  let condRDN = frm == numI32 2 8<rt>
  let condRUP = frm == numI32 3 8<rt>
  let lblD0 = !%ir "DI0"
  let lblD1 = !%ir "DI1"
  let lblD2 = !%ir "DI2"
  let lblD3 = !%ir "DI3"
  let lblD4 = !%ir "DI4"
  let lblD5 = !%ir "DI6"
  let lblD6 = !%ir "DI7"
  let lblDException = !%ir "DIException"
  let lblDEnd = !%ir "DIEnd"
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

let transOneOpr insInfo ctxt opr = transOprToExpr insInfo ctxt opr

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
  | 32<rt> -> ((expr .& (numU32 0x3u 64<rt>)) == AST.num0 64<rt>)
  | 64<rt> -> ((expr .& (numU32 0x7u 64<rt>)) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let getAccessLength = function
  | OpMem (_, _, sz) -> sz
  | _ -> raise InvalidOperandException

let isInf rt e =
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

let isNan rt e =
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

let isSNan rt e =
  match rt with
  | 32<rt> ->
    let signalBit = numU32 (1u <<< 22) 32<rt>
    (isNan rt e) .& ((e .& signalBit) == AST.num0 32<rt>)
  | 64<rt> ->
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    (isNan rt e) .& ((e .& signalBit) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let isQNan rt e =
  match rt with
  | 32<rt> ->
    let signalBit = numU32 (1u <<< 22) 32<rt>
    (isNan rt e) .& ((e .& signalBit) != AST.num0 32<rt>)
  | 64<rt> ->
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    (isNan rt e) .& ((e .& signalBit) != AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let getSignFloat rt e =
  match rt with
  | 32<rt> -> e .& (numU32 0x80000000u 32<rt>)
  | 64<rt> -> e .& (numU64 0x8000000000000000uL 64<rt>)
  | _ -> raise InvalidRegTypeException

let getFloat32FromReg e =
  let mask = numU64 0xFFFFFFFF_00000000uL 64<rt>
  AST.ite (e .& mask == mask) (AST.xtlo 32<rt> e) (numI32 0x7fc00000 32<rt>)

let getNanBoxed e = (numU64 0xFFFFFFFF_00000000uL 64<rt>) .| (AST.zext 64<rt> e)

let isSubnormal rt e =
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

let private checkOverflowOnDMul e1 e2 =
  let mask64 = numI64 0xFFFFFFFFFFFFFFFFL 64<rt>
  let bit32 = numI64 0x100000000L 64<rt>
  let cond = mask64 .- e1 .< e2
  AST.ite cond bit32 (AST.num0 64<rt>)

let private mul64BitReg src1 src2 ir isSign =
  let struct (hiSrc1, loSrc1, hiSrc2, loSrc2) = tmpVars4 ir 64<rt>
  let struct (tHigh, tLow) = tmpVars2 ir 64<rt>
  let struct (tSrc1, tSrc2) = tmpVars2 ir 64<rt>
  let struct (src1IsNeg, src2IsNeg, signBit) = tmpVars3 ir 1<rt>
  let struct (pHigh, pMid, pLow) = tmpVars3 ir 64<rt>
  let struct (pMid1, pMid2) = tmpVars2 ir 64<rt>
  let struct (high, low) = tmpVars2 ir 64<rt>
  let n32 = numI32 32 64<rt>
  let mask32 = numI64 0xFFFFFFFFL 64<rt>
  let zero = numI32 0 64<rt>
  let one = numI32 1 64<rt>
  if isSign then
    !!ir (src1IsNeg := AST.xthi 1<rt> src1)
    !!ir (src2IsNeg := AST.xthi 1<rt> src2)
    !!ir (tSrc1 := AST.ite src1IsNeg (AST.neg src1) src1)
    !!ir (tSrc2 := AST.ite src2IsNeg (AST.neg src2) src2)
  else
    !!ir (tSrc1 := src1)
    !!ir (tSrc2 := src2)
  !!ir (hiSrc1 := (tSrc1 >> n32) .& mask32) (* SRC1[63:32] *)
  !!ir (loSrc1 := tSrc1 .& mask32) (* SRC1[31:0] *)
  !!ir (hiSrc2 := (tSrc2 >> n32) .& mask32) (* SRC2[63:32] *)
  !!ir (loSrc2 := tSrc2 .& mask32) (* SRC2[31:0] *)
  !!ir (pHigh := hiSrc1 .* hiSrc2)
  !!ir (pMid1 := hiSrc1 .* loSrc2)
  !!ir (pMid2 := loSrc1 .* hiSrc2)
  !!ir (pMid := pMid1 .+ pMid2)
  !!ir (pLow := loSrc1 .* loSrc2)
  let overFlowBit = checkOverflowOnDMul pMid1 pMid2
  !!ir (high := pHigh .+ ((pMid .+ (pLow >> n32)) >> n32) .+ overFlowBit)
  !!ir (low := pLow .+ ((pMid .& mask32) << n32))
  if isSign then
    !!ir (signBit := src1IsNeg <+> src2IsNeg)
    !!ir (tHigh := AST.ite signBit (AST.not high) high)
    !!ir (tLow := AST.ite signBit (AST.neg low) low)
    let carry = AST.ite (AST.``and`` signBit (tLow == zero)) one zero
    !!ir (tHigh := tHigh .+ carry)
  else
    !!ir (tHigh := high)
    !!ir (tLow := low)
  struct (tHigh, tLow)

let add insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 .+ rs2)
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
  !<ir insLen
  !!ir (rd := rs1 .- rs2)
  !>ir insLen

let ``and`` insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 .& rs2)
  !>ir insLen

let ``or`` insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 .| rs2)
  !>ir insLen

let xor insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := rs1 <+> rs2)
  !>ir insLen

let slt insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 ?< rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let sltu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 .< rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let sll insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
  !<ir insLen
  !!ir (rd := rs1 << shiftAmm)
  !>ir insLen

let sllw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (rs1 << shiftAmm))
  !>ir insLen

let srl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
  !<ir insLen
  !!ir (rd := rs1 >> shiftAmm)
  !>ir insLen

let srlw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (rs1 >> shiftAmm))
  !>ir insLen

let sra insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
  !<ir insLen
  !!ir (rd := rs1 ?>> shiftAmm)
  !>ir insLen

let sraw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
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
  let cond = rs1 ?< imm
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  !<ir insLen
  !!ir (rd := rtVal)
  !>ir insLen

let sltiu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 .< imm
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
  let target = !+ir 64<rt>
  let actualTarget = if target = AST.num0 ctxt.WordBitSize then rd else target
  !<ir insLen
  !!ir (target := jumpTarget)
  !!ir (rd := r)
  !!ir (AST.interjmp actualTarget InterJmpKind.Base)
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
  let cond = rs1 .< rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  !<ir insLen
  !!ir (AST.intercjmp cond offset fallThrough)
  !>ir insLen

let bgeu insInfo insLen ctxt =
  let ir = !*ctxt
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 .>= rs2
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
  if accessLength = 64<rt> then !!ir (mem := rd)
  else !!ir (mem := AST.xtlo accessLength rd)
  !>ir insLen

let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let lui insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := imm << numI32 12 ctxt.WordBitSize)
  !>ir insLen

let auipc insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let pc = bvOfBaseAddr ctxt insInfo.Address
  !<ir insLen
  !!ir (rd := pc .+ (imm << numI32 12 ctxt.WordBitSize))
  !>ir insLen

let addiw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (lowBitsRs1 .+ AST.xtlo 32<rt> imm))
  !>ir insLen

let slliw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (lowBitsRs1 << AST.xtlo 32<rt> shamt))
  !>ir insLen
let srliw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (lowBitsRs1 >> AST.xtlo 32<rt> shamt))
  !>ir insLen
let sraiw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> (lowBitsRs1 ?>> AST.xtlo 32<rt> shamt))
  !>ir insLen
let mul insInfo insLen ctxt isSign =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let struct (_, low) = mul64BitReg rs1 rs2 ir isSign
  !!ir (rd := low)
  !>ir insLen
let mulhSignOrUnsign insInfo insLen ctxt isSign =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  let struct (high, _) = mul64BitReg rs1 rs2 ir isSign
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
  let condZero = rs2 == AST.num0 64<rt>
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
  let condZero = rs2 == AST.num0 32<rt>
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
  let condZero = rs2 == AST.num0 32<rt>
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
  let condZero = rs2 == AST.num0 64<rt>
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
  let condZero = rs2 == AST.num0 64<rt>
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
  let condZero = rs2 == AST.num0 64<rt>
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
  let condZero = rs2 == AST.num0 32<rt>
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
  let condZero = rs2 == AST.num0 32<rt>
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
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.flt rs1 rs2
  let rtVal =
    AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  let fflags = getRegVar ctxt R.FFLAGS
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fflags := fflags .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fledots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = getRegVar ctxt R.FFLAGS
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fflags := fflags .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let feqdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let isSNan = isSNan 32<rt> rs1 .| isSNan 32<rt> rs2
  let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = rs1 == rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = getRegVar ctxt R.FFLAGS
  let flagFscr = AST.ite (isSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>)
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fflags := fflags .| flagFscr)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fclassdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let plusZero = numU32 0u 32<rt>
  let negZero = numU32 0x80000000u 32<rt>
  let sign = AST.extract rs1 1<rt> 31
  let lblPos = !%ir "Pos"
  let lblNeg = !%ir "Neg"
  let lblEnd = !%ir "End"
  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = isInf 32<rt> rs1
  let condSubnormal = isSubnormal 32<rt> rs1
  let condSNan = isSNan 32<rt> rs1
  let condQNan = isQNan 32<rt> rs1
  !<ir insLen
  !!ir (rd := AST.num0 64<rt>)
  !!ir (AST.cjmp sign (AST.name lblNeg) (AST.name lblPos))
  !!ir (AST.lmark lblPos)
  !!ir (rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd)
  !!ir (rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd)
  !!ir (rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd)
  !!ir (rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd)
  !!ir (rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd)
  !!ir (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblNeg)
  !!ir (rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd)
  !!ir (rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd)
  !!ir (rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd)
  !!ir (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd)
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
  let condInf = isInf 64<rt> rs1
  let condSubnormal = isSubnormal 64<rt> rs1
  let condSNan = isSNan 64<rt> rs1
  let condQNan = isQNan 64<rt> rs1
  !<ir insLen
  !!ir (rd := AST.num0 64<rt>)
  !!ir (AST.cjmp sign (AST.name lblNeg) (AST.name lblPos))
  !!ir (AST.lmark lblPos)
  !!ir (rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd)
  !!ir (rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd)
  !!ir (rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd)
  !!ir (rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd)
  !!ir (rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd)
  !!ir (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblNeg)
  !!ir (rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd)
  !!ir (rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd)
  !!ir (rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd)
  !!ir (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let flw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let tmp = !+ir 32<rt>
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (tmp := mem)
  !!ir (rd := getNanBoxed tmp)
  !!ir (AST.sideEffect Unlock)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (tmp := mem)
  !!ir (rd := getNanBoxed tmp)
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
  let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.flt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = getRegVar ctxt R.FFLAGS
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fflags := fflags .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fledotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = getRegVar ctxt R.FFLAGS
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fflags := fflags .| numU32 16u 32<rt>)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let feqdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let isSNan = isSNan 64<rt> rs1 .| isSNan 64<rt> rs2
  let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let cond = rs1 == rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = getRegVar ctxt R.FFLAGS
  let flagFscr = AST.ite isSNan (numU32 16u 32<rt>) (AST.num0 32<rt>)
  !<ir insLen
  !!ir (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  !!ir (AST.lmark lblL0)
  !!ir (rd := rtVal)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (rd := numU64 0uL 64<rt>)
  !!ir (fflags := fflags .| flagFscr)
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fadddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  !<ir insLen
  let rtVal = AST.fadd rs1 rs2
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fadddotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fadd rs1 rs2
  !!ir (rd := rtVal)
  !>ir insLen

let fsubdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  !<ir insLen
  let rtVal = AST.fsub rs1 rs2
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fsubdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fsub rs1 rs2
  !!ir (rd := rtVal)
  !>ir insLen

let fmuldots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  !<ir insLen
  let rtVal = AST.fmul rs1 rs2
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fmuldotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fmul rs1 rs2
  !!ir (rd := rtVal)
  !>ir insLen

let fdivdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  !<ir insLen
  let rtVal = AST.fdiv rs1 rs2
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fdivdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, _ = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fdiv rs1 rs2
  !!ir (rd := rtVal)
  !>ir insLen

let fsqrtdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  !<ir insLen
  let rtVal = AST.fsqrt rs1
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fsqrtdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fsqrt rs1
  !!ir (rd := rtVal)
  !>ir insLen

let fmindots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = !+ir 32<rt>
  let cond = AST.flt rs1 rs2
  !<ir insLen
  !!ir (rtVal := AST.ite cond rs1 rs2)
  !!ir (rd := getNanBoxed rtVal)
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
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = !+ir 32<rt>
  let cond = AST.flt rs1 rs2
  !<ir insLen
  !!ir (rtVal := AST.ite cond rs2 rs1)
  !!ir (rd := getNanBoxed rtVal)
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
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  !<ir insLen
  let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fmadddotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
  !!ir (rd := rtVal)
  !>ir insLen

let fmsubdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  !<ir insLen
  let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fmsubdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  !<ir insLen
  let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
  !!ir (rd := rtVal)
  !>ir insLen

let fnmsubdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  let res = AST.fsub rs3 (AST.fmul rs1 rs2)
  !<ir insLen
  let rtVal = res
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fnmsubdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let res = AST.fsub rs3 (AST.fmul rs1 rs2)
  !<ir insLen
  let rtVal = res
  !!ir (rd := rtVal)
  !>ir insLen

let fnmadddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  let res = AST.fsub rs3 (AST.fmul rs1 rs2)
  !<ir insLen
  let rtVal = res
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fnmadddotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2, rs3, _ = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let res = AST.fsub rs3 (AST.fmul rs1 rs2)
  !<ir insLen
  let rtVal = res
  !!ir (rd := rtVal)
  !>ir insLen

let fsgnjdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = !+ir 32<rt>
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := getNanBoxed rtVal)
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
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = !+ir 32<rt>
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2 <+> numU32 0x80000000u 32<rt>
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := getNanBoxed rtVal)
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
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = !+ir 32<rt>
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = (getSignFloat 32<rt> rs2) <+> (getSignFloat 32<rt> rs1)
  !<ir insLen
  !!ir (rtVal := (rs1 .& mask) .| sign)
  !!ir (rd := getNanBoxed rtVal)
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
  let rd, rs2, mem, _ = getFourOprs insInfo |> transFourOprs insInfo ctxt
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
  let rd, rs2, mem, _ = getFourOprs insInfo |> transFourOprs insInfo ctxt
  let rs2 = AST.xtlo 32<rt> rs2
  let cond = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (AST.sideEffect Lock)
  !!ir (tmp := mem)
  !!ir (mem := op tmp rs2)
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
  let rs1 = getFloat32FromReg rs1
  !<ir insLen
  !!ir (rd := AST.sext 64<rt> rs1)
  !>ir insLen

let fmvdotwdotx insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := getNanBoxed (AST.xtlo 32<rt> rs1))
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
  let tmpVar = !+ir 32<rt>
  let r = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := r)
  !!ir (rd := AST.zext 64<rt> tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrwi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 32<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := AST.zext 32<rt> imm)
  !!ir (rd := AST.zext 64<rt> tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrs insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 32<rt>
  let r = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .| r)
  !!ir (rd := AST.zext 64<rt> tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrsi insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 32<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .| (AST.zext 32<rt> imm))
  !!ir (rd := AST.zext 64<rt> tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrc insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 32<rt>
  let r = AST.xtlo 32<rt> rs1
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .& (AST.neg r))
  !!ir (rd := AST.zext 64<rt> tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let csrrci insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = !+ir 32<rt>
  !<ir insLen
  !!ir (AST.sideEffect Lock)
  !!ir (tmpVar := csr)
  !!ir (csr := tmpVar .& (AST.neg (AST.zext 32<rt> imm)))
  !!ir (rd := tmpVar)
  !!ir (AST.sideEffect Unlock)
  !>ir insLen

let fcvtdotldotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  let llMax = numU64 0x7fffffffffffffffuL 64<rt>
  let llMin = numU64 0x8000000000000000uL 64<rt>
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (rtVal := AST.cast rounding 64<rt> rs1)
    !!ir (rd := AST.cast roundingInt 64<rt> rtVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN llMin rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) llMin rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) llMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> rs1
    let rdVal = dynamicRoundingInt ir ctxt 64<rt> rtVal
    !!ir (rd := rdVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) llMin rd)
    !>ir insLen

let fcvtdotludotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let ullMaxInFloat = numU64 0x43f0000000000000uL 64<rt>
  let ullMinInFloat = numU64 0uL 64<rt>
  let ullMax = numU64 0xffffffffffffffffuL 64<rt>
  let ullMin = numI32 0 64<rt>
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (rtVal := AST.cast rounding 64<rt> rs1)
    !!ir (rd := AST.cast roundingInt 64<rt> rtVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal ullMinInFloat) ullMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal ullMaxInFloat) ullMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN ullMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) ullMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) ullMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> rs1
    let rdVal = dynamicRoundingInt ir ctxt 64<rt> rtVal
    !!ir (rd := rdVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal ullMinInFloat) ullMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal ullMaxInFloat) ullMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN ullMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) ullMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) ullMin rd)
    !>ir insLen

let fcvtdotwdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
  let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
  let intMax = AST.sext 64<rt> (numU32 0x7fffffffu 32<rt>)
  let intMin = AST.sext 64<rt> (numU32 0x80000000u 32<rt>)
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (rtVal := AST.cast rounding 64<rt> rs1)
    !!ir (rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal))
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN intMin rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) intMin rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) intMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> rs1
    let rdVal = dynamicRoundingInt ir ctxt 32<rt> rtVal
    !!ir (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) intMin rd)
    !>ir insLen

let fcvtdotwudotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let uintMaxInFloat = numU64 0x41efffffffe00000uL 64<rt>
  let uintMinInFloat = numU64 0uL 64<rt>
  let uintMax = numU64 0xffffffffffffffffuL 64<rt>
  let uintMin = numU64 0uL 64<rt>
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = !+ir 64<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (rtVal := AST.cast rounding 64<rt> rs1)
    !!ir (rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal))
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) uintMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let rtVal = dynamicRoundingFl ir ctxt 64<rt> rs1
    let rdVal = dynamicRoundingInt ir ctxt 32<rt> rtVal
    !!ir (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) uintMin rd)
    !>ir insLen

let fcvtdotwdots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let intMaxInFloat = numU32 0x4f000000u 32<rt>
  let intMinInFloat = numU32 0xcf000000u 32<rt>
  let intMax = numU32 0x7fffffffu 64<rt>
  let intMin = numU64 0xffffffff80000000uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (rtVal := AST.cast rounding 32<rt> rs1)
    !!ir (rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal))
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) intMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> rs1
    let rdVal = dynamicRoundingInt ir ctxt 32<rt> rtVal
    !!ir (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) intMin rd)
    !>ir insLen

let fcvtdotwudots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let uintMaxInFloat = numU32 0x4f800000u 32<rt>
  let uintMinInFloat = numU32 0x0u 32<rt>
  let uintMax = numU64 0xffffffffffffffffUL 64<rt>
  let uintMin = numU32 0x0u 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = !+ir 32<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (rtVal := AST.cast rounding 32<rt> rs1)
    !!ir (rd := AST.cast roundingInt 32<rt> rtVal)
    !!ir (rd := AST.sext 64<rt> rd)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) uintMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let rtVal = dynamicRoundingFl ir ctxt 32<rt> rs1
    let rdVal = dynamicRoundingInt ir ctxt 32<rt> rtVal
    !!ir (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    !!ir (rd := AST.ite (condInf .& sign) uintMin rd)
    (* -inf *)
    !>ir insLen

let fcvtdotldots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = !+ir 32<rt>
    let rtVal = !+ir 64<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (t0 := AST.cast rounding 32<rt> rs1)
    !!ir (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    (* check for out-of-range *)
    !!ir (rtVal := AST.ite (AST.fle rtVal llMinInFloat) llMinInFloat rtVal)
    !!ir (rtVal := AST.ite (AST.fge rtVal llMaxInFloat) llMaxInFloat rtVal)
    (* NaN Check *)
    !!ir (rtVal := AST.ite condNaN llMaxInFloat rtVal)
    (* +inf *)
    !!ir (rtVal := AST.ite (condInf .& (AST.not sign)) llMaxInFloat rtVal)
    (* -inf *)
    !!ir (rtVal := AST.ite (condInf .& sign) llMinInFloat rtVal)
    !!ir (rd := AST.cast roundingInt 64<rt> rtVal)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let t0 = dynamicRoundingFl ir ctxt 32<rt> rs1
    let rtVal = !+ir 64<rt>
    (* check for out-of-range *)
    !!ir (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    !!ir (rtVal := AST.ite (AST.fle rtVal llMinInFloat) llMinInFloat rtVal)
    !!ir (rtVal := AST.ite (AST.fge rtVal llMaxInFloat) llMaxInFloat rtVal)
    (* NaN Check *)
    !!ir (rtVal := AST.ite condNaN llMaxInFloat rtVal)
    (* +inf *)
    !!ir (rtVal := AST.ite (condInf .& (AST.not sign)) llMaxInFloat rtVal)
    (* -inf *)
    !!ir (rtVal := AST.ite (condInf .& sign) llMinInFloat rtVal)
    let rdVal = dynamicRoundingInt ir ctxt 64<rt> rtVal
    !!ir (rd := rdVal)
    !>ir insLen

let fcvtdotludots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0uL 64<rt>
  let llMax = numU64 0xffffffffffffffffuL 64<rt>
  let llMin = numU64 0uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = !+ir 32<rt>
    let rtVal = !+ir 64<rt>
    !<ir insLen
    (* rounded value *)
    !!ir (t0 := AST.cast rounding 32<rt> rs1)
    !!ir (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    !!ir (rd := AST.cast roundingInt 64<rt> rtVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) llMin rd)
    !>ir insLen
  else
    !<ir insLen
    (* rounded value *)
    let t0 = dynamicRoundingFl ir ctxt 32<rt> rs1
    let rtVal = !+ir 64<rt>
    (* check for out-of-range *)
    !!ir (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    !!ir (rd := AST.cast CastKind.FloatCast 64<rt> rtVal)
    (* check for out-of-range *)
    !!ir (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    !!ir (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    !!ir (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    !!ir (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    !!ir (rd := AST.ite (condInf .& sign) llMin rd)
    !>ir insLen

let fcvtdotsdotw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1)
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fcvtdotsdotwu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1)
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fcvtdotsdotl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1)
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fcvtdotsdotlu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1)
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fcvtdotddotw insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.SIntToFloat 64<rt> (AST.xtlo 32<rt> rs1))
  !>ir insLen

let fcvtdotddotwu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.UIntToFloat 64<rt> (AST.xtlo 32<rt> rs1))
  !>ir insLen

let fcvtdotddotl insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.SIntToFloat 64<rt> rs1)
  !>ir insLen

let fcvtdotddotlu insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.cast CastKind.UIntToFloat 64<rt> rs1)
  !>ir insLen

// (* TODO: add rounding mode *)
let fcvtdotsdotd insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rtVal = !+ir 32<rt>
  !<ir insLen
  !!ir (rtVal := AST.cast CastKind.FloatCast 32<rt> rs1)
  !!ir (rd := getNanBoxed rtVal)
  !>ir insLen

let fcvtdotddots insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = getFloat32FromReg rs1
  !<ir insLen
  !!ir (rd := AST.cast CastKind.FloatCast 64<rt> rs1)
  !>ir insLen

(* TODO: Add reservation check *)
let lr insInfo insLen ctxt =
  let ir = !*ctxt
  let rd, mem, _ = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  !<ir insLen
  !!ir (rd := AST.sext ctxt.WordBitSize mem)
  !>ir insLen

(* TODO: Add reservation check *)
let sc insInfo insLen ctxt oprSz =
  let ir = !*ctxt
  let rd, mem, rs2, _ = getFourOprs insInfo |> transFourOprs insInfo ctxt
  !<ir insLen
  !!ir (mem := AST.xtlo oprSz rs2)
  !!ir (rd := numI32 0 ctxt.WordBitSize)
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
  | Op.FCVTdotWUdotD -> fcvtdotwudotd insInfo insLen ctxt
  | Op.FCVTdotLdotD -> fcvtdotldotd insInfo insLen ctxt
  | Op.FCVTdotLUdotD -> fcvtdotludotd insInfo insLen ctxt
  | Op.FCVTdotWdotS -> fcvtdotwdots insInfo insLen ctxt
  | Op.FCVTdotWUdotS -> fcvtdotwudots insInfo insLen ctxt
  | Op.FCVTdotLdotS -> fcvtdotldots insInfo insLen ctxt
  | Op.FCVTdotLUdotS -> fcvtdotludots insInfo insLen ctxt
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO -> nop insLen ctxt
  | Op.LRdotW
  | Op.LRdotD -> lr insInfo insLen ctxt
  | Op.SCdotW -> sc insInfo insLen ctxt 32<rt>
  | Op.SCdotD -> sc insInfo insLen ctxt 64<rt>
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
  | Op.FCVTdotDdotWU -> fcvtdotddotwu insInfo insLen ctxt
  | Op.FCVTdotDdotLU -> fcvtdotddotlu insInfo insLen ctxt
  | Op.FCVTdotSdotWU -> fcvtdotsdotwu insInfo insLen ctxt
  | Op.FCVTdotSdotLU -> fcvtdotsdotlu insInfo insLen ctxt
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException (Disasm.opCodeToString o)
