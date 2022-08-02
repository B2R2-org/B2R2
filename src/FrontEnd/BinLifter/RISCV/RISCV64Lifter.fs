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
open B2R2.FrontEnd.BinLifter.RISCV


let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

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

let inline private (<!) (builder: IRBuilder) (s) = builder.Append (s)

let startMark insInfo (builder: IRBuilder) =
  builder <! (AST.ismark (insInfo.NumBytes))

let endMark insInfo (builder: IRBuilder) =
  builder <! (AST.iemark (insInfo.NumBytes)); builder

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
  | OpShiftAmount imm -> numU32 imm ctxt.WordBitSize
  | OpMem (b, Some (Imm o), sz) ->
    AST.loadLE sz (getRegVar ctxt b .+ numU32 o ctxt.WordBitSize)
  | OpAddr (Relative o) ->
    numI64 (int64 insInfo.Address + o) ctxt.WordBitSize
  | OpAddr (RelativeBase (b, imm)) ->
    (getRegVar ctxt b .+ numI64 (int64 imm) ctxt.WordBitSize) .&
    (numU64 0xfffffffffffffffeUL 64<rt>)
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

let dynamicRoundingFl (builder: IRBuilder) ctxt rt res =
  let tmpVar = builder.NewTempVar rt
  let fscr =
    (AST.extract (getRegVar ctxt Register.FCSR) 4<rt> 6) .& (numI32 7 4<rt>)
  let condRNE_RMM = (fscr == numI32 0 4<rt>) .| (fscr == numI32 4 4<rt>)
  let condRTZ = (fscr == numI32 1 4<rt>)
  let condRDN = (fscr == numI32 2 4<rt>)
  let condRUP = (fscr == numI32 3 4<rt>)
  let lblD0 = builder.NewSymbol "D0"
  let lblD1 = builder.NewSymbol "D1"
  let lblD2 = builder.NewSymbol "D2"
  let lblD3 = builder.NewSymbol "D3"
  let lblD4 = builder.NewSymbol "D4"
  let lblD5 = builder.NewSymbol "D6"
  let lblD6 = builder.NewSymbol "D7"
  let lblDException = builder.NewSymbol "DException"
  let lblDEnd = builder.NewSymbol "DEnd"
  builder <! (AST.cjmp condRNE_RMM (AST.name lblD0) (AST.name lblD1))
  builder <! (AST.lmark lblD0)
  builder <! (tmpVar := AST.cast (CastKind.FtoFRound) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblD1)
  builder <! (AST.cjmp condRTZ (AST.name lblD2) (AST.name lblD3))
  builder <! (AST.lmark lblD2)
  builder <! (tmpVar := AST.cast (CastKind.FtoFTrunc) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblD3)
  builder <! (AST.cjmp condRDN (AST.name lblD4) (AST.name lblD5))
  builder <! (AST.lmark lblD4)
  builder <! (tmpVar := AST.cast (CastKind.FtoFFloor) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblD5)
  builder <! (AST.cjmp condRUP (AST.name lblD6) (AST.name lblDException))
  builder <! (AST.lmark lblD6)
  builder <! (tmpVar := AST.cast (CastKind.FtoFCeil) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblDException)
  builder <! (AST.sideEffect (Exception "illegal instruction"))
  builder <! (AST.lmark lblDEnd)
  tmpVar

let dynamicRoundingInt (builder: IRBuilder) ctxt rt res =
  let tmpVar = builder.NewTempVar rt
  let fscr =
    (AST.extract (getRegVar ctxt Register.FCSR) 4<rt> 6) .& (numI32 7 4<rt>)
  let condRNE_RMM = (fscr == numI32 0 4<rt>) .| (fscr == numI32 4 4<rt>)
  let condRTZ = (fscr == numI32 1 4<rt>)
  let condRDN = (fscr == numI32 2 4<rt>)
  let condRUP = (fscr == numI32 3 4<rt>)
  let lblD0 = builder.NewSymbol "D0"
  let lblD1 = builder.NewSymbol "D1"
  let lblD2 = builder.NewSymbol "D2"
  let lblD3 = builder.NewSymbol "D3"
  let lblD4 = builder.NewSymbol "D4"
  let lblD5 = builder.NewSymbol "D6"
  let lblD6 = builder.NewSymbol "D7"
  let lblDException = builder.NewSymbol "DException"
  let lblDEnd = builder.NewSymbol "DEnd"
  builder <! (AST.cjmp condRNE_RMM (AST.name lblD0) (AST.name lblD1))
  builder <! (AST.lmark lblD0)
  builder <! (tmpVar := AST.cast (CastKind.FtoIRound) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblD1)
  builder <! (AST.cjmp condRTZ (AST.name lblD2) (AST.name lblD3))
  builder <! (AST.lmark lblD2)
  builder <! (tmpVar := AST.cast (CastKind.FtoITrunc) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblD3)
  builder <! (AST.cjmp condRDN (AST.name lblD4) (AST.name lblD5))
  builder <! (AST.lmark lblD4)
  builder <! (tmpVar := AST.cast (CastKind.FtoIFloor) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblD5)
  builder <! (AST.cjmp condRUP (AST.name lblD6) (AST.name lblDException))
  builder <! (AST.lmark lblD6)
  builder <! (tmpVar := AST.cast (CastKind.FtoICeil) rt res)
  builder <! (AST.jmp (AST.name lblDEnd))
  builder <! (AST.lmark lblDException)
  builder <! (AST.sideEffect (Exception "illegal instruction"))
  builder <! (AST.lmark lblDEnd)
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

let add insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (result := rs1 .+ rs2)
  builder <! (rd := result)
  endMark insInfo builder

let addw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  builder <! (rd := AST.sext 64<rt> (rs1 .+ rs2))
  endMark insInfo builder

let subw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  builder <! (rd := AST.sext 64<rt> (rs1 .- rs2))
  endMark insInfo builder


let sub insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (result := rs1 .- rs2)
  builder <! (rd := result)
  endMark insInfo builder

let ``and`` insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (result := rs1 .& rs2)
  builder <! (rd := result)
  endMark insInfo builder

let ``or`` insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (result := rs1 .| rs2)
  builder <! (rd := result)
  endMark insInfo builder

let xor insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let result = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (result := rs1 <+> rs2)
  builder <! (rd := result)
  endMark insInfo builder

let slt insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = (rs1 ?< rs2)
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  startMark insInfo builder
  builder <! (rd := rtVal)
  endMark insInfo builder

let sltu insInfo (ctxt: TranslationContext) =
  let builder = IRBuilder (4)
  let wordSz = ctxt.WordBitSize
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  startMark insInfo builder
  builder <! (rd := rtVal)
  endMark insInfo builder

let sll insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = (rs2 .& numU64 0x3fUL 64<rt>)
  startMark insInfo builder
  builder <! (rd := rs1 << shiftAmm)
  endMark insInfo builder

let sllw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let shiftAmm = (rs2 .& numU32 0x1fu 32<rt>)
  startMark insInfo builder
  builder <! (rd := AST.sext 64<rt> (rs1 << shiftAmm))
  endMark insInfo builder


let srl insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = (rs2 .& numU64 0x3fUL 64<rt>)
  startMark insInfo builder
  builder <! (rd := rs1 >> shiftAmm)
  endMark insInfo builder

let srlw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let shiftAmm = (rs2 .& numU32 0x1fu 32<rt>)
  startMark insInfo builder
  builder <! (rd := AST.sext 64<rt> (rs1 >> shiftAmm))
  endMark insInfo builder

let sra insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let shiftAmm = (rs2 .& numU64 0x3fUL 64<rt>)
  startMark insInfo builder
  builder <! (rd := rs1 ?>> shiftAmm)
  endMark insInfo builder

let sraw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let shiftAmm = (rs2 .& numU32 0x1fu 32<rt>)
  startMark insInfo builder
  builder <! (rd := AST.sext 64<rt> (rs1 ?>> shiftAmm))
  endMark insInfo builder

let srai insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, shiftAmm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 ?>> shiftAmm)
  endMark insInfo builder

let srli insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, shiftAmm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 >> shiftAmm)
  endMark insInfo builder

let slli insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, shiftAmm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 << shiftAmm)
  endMark insInfo builder

let andi insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 .& imm)
  endMark insInfo builder

let addi insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 .+ imm)
  endMark insInfo builder

let ori insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 .| imm)
  endMark insInfo builder

let xori insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1 <+> imm)
  endMark insInfo builder

let slti insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = (rs1 ?< imm)
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  startMark insInfo builder
  builder <! (rd := rtVal)
  endMark insInfo builder

let sltiu insInfo (ctxt: TranslationContext) =
  let builder = IRBuilder (4)
  let wordSz = ctxt.WordBitSize
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = AST.lt rs1 imm
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  startMark insInfo builder
  builder <! (rd := rtVal)
  endMark insInfo builder

let nop insInfo =
  let builder = IRBuilder (4)
  startMark insInfo builder
  endMark insInfo builder


let jal insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, jumpTarget = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let r = bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (rd := r)
  builder <! (AST.interjmp jumpTarget InterJmpKind.Base)
  endMark insInfo builder

let jalr insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, jumpTarget = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let r = bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  let jumpT = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (rd := r)
  builder <! (AST.interjmp jumpTarget InterJmpKind.Base)
  endMark insInfo builder

let beq insInfo ctxt =
  let builder = IRBuilder (4)
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 == rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bne insInfo ctxt =
  let builder = IRBuilder (4)
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 != rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let blt insInfo ctxt =
  let builder = IRBuilder (4)
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 ?< rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bge insInfo ctxt =
  let builder = IRBuilder (4)
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let cond = rs1 .>= rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bltu insInfo ctxt =
  let builder = IRBuilder (4)
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let wordSz = ctxt.WordBitSize
  let cond = AST.lt rs1 rs2
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let bgeu insInfo ctxt =
  let builder = IRBuilder (4)
  let rs1, rs2, offset = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let wordSz = ctxt.WordBitSize
  let cond = AST.ge (AST.zext (wordSz * 2) rs1) (AST.zext (wordSz * 2) rs2)
  let fallThrough =
    bvOfBaseAddr ctxt insInfo.Address .+ bvOfInstrLen ctxt insInfo
  startMark insInfo builder
  builder <! (AST.intercjmp cond offset fallThrough)
  endMark insInfo builder

let load insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.sext ctxt.WordBitSize mem)
  endMark insInfo builder

let loadu insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.zext ctxt.WordBitSize mem)
  endMark insInfo builder

let store insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let accessLength = getAccessLength (snd (getTwoOprs insInfo))
  startMark insInfo builder
  builder <! (mem := AST.xtlo accessLength rd)
  endMark insInfo builder

let sideEffects insInfo name =
  let builder = IRBuilder (4)
  startMark insInfo builder
  builder <! (AST.sideEffect name)
  endMark insInfo builder

let lui insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.sext 64<rt> imm)
  endMark insInfo builder

let auipc insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, imm = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let pc = bvOfBaseAddr ctxt insInfo.Address
  let tmpImm = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (tmpImm := AST.sext 64<rt> imm)
  builder <! (rd := tmpImm .+ pc)
  endMark insInfo builder

let addiw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (retValue := lowBitsRs1 .+ AST.xtlo 32<rt> imm)
  builder <! (rd := AST.sext 64<rt> retValue)
  endMark insInfo builder

let slliw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (retValue := lowBitsRs1 << AST.xtlo 32<rt> shamt)
  builder <! (rd := AST.sext 64<rt> retValue)
  endMark insInfo builder

let srliw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (retValue := lowBitsRs1 >> AST.xtlo 32<rt> shamt)
  builder <! (rd := AST.sext 64<rt> retValue)
  endMark insInfo builder

let sraiw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, shamt = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let retValue = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (retValue := lowBitsRs1 ?>> AST.xtlo 32<rt> shamt)
  builder <! (rd := AST.sext 64<rt> retValue)
  endMark insInfo builder

let mul insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let extendedRs1 = AST.sext 128<rt> rs1
  let extendedRs2 = AST.sext 128<rt> rs2
  let retValue = builder.NewTempVar 128<rt>
  startMark insInfo builder
  builder <! (retValue := extendedRs1 .* extendedRs2)
  builder <! (rd := AST.xtlo 64<rt> retValue)
  endMark insInfo builder

let mulh insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let extendedRs1 = AST.sext 128<rt> rs1
  let extendedRs2 = AST.sext 128<rt> rs2
  let retValue = builder.NewTempVar 128<rt>
  startMark insInfo builder
  builder <! (retValue := extendedRs1 .* extendedRs2)
  builder <! (rd := AST.xthi 64<rt> retValue)
  endMark insInfo builder

let mulhu insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let extendedRs1 = AST.zext 128<rt> rs1
  let extendedRs2 = AST.zext 128<rt> rs2
  let retValue = builder.NewTempVar 128<rt>
  startMark insInfo builder
  builder <! (retValue := extendedRs1 .* extendedRs2)
  builder <! (rd := AST.xthi 64<rt> retValue)
  endMark insInfo builder

let mulhsu insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let extendedRs1 = AST.sext 128<rt> rs1
  let extendedRs2 = AST.zext 128<rt> rs2
  let retValue = builder.NewTempVar 128<rt>
  startMark insInfo builder
  builder <! (retValue := extendedRs1 .* extendedRs2)
  builder <! (rd := AST.xthi 64<rt> retValue)
  endMark insInfo builder

let mulw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let lowBitsRs2 = AST.xtlo 32<rt> rs2
  startMark insInfo builder
  builder <! (rd := AST.sext 64<rt> (lowBitsRs1 .* lowBitsRs2))
  endMark insInfo builder

let div insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let condOverflow
    = ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblL2 = builder.NewSymbol "L2"
  let lblL3 = builder.NewSymbol "L3"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  builder <! (AST.lmark lblL2)
  builder <! (rd := rs1)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL3)
  builder <! (rd := rs1 ?/ rs2)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let divw insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let condOverflow =
    ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblL2 = builder.NewSymbol "L2"
  let lblL3 = builder.NewSymbol "L3"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  builder <! (AST.lmark lblL2)
  builder <! (rd := AST.sext 64<rt> rs1)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL3)
  builder <! (rd := AST.sext 64<rt> (rs1 ?/ rs2))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let divuw insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := AST.sext 64<rt> (rs1 ./ rs2))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let divu insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := rs1 ./ rs2)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let remu insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rs1)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := rs1 .% rs2)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let rem insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let condZero = (rs2 == AST.num0 64<rt>)
  let condOverflow =
    ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblL2 = builder.NewSymbol "L2"
  let lblL3 = builder.NewSymbol "L3"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rs1)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  builder <! (AST.lmark lblL2)
  builder <! (rd := AST.num0 64<rt>)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL3)
  builder <! (rd := rs1 ?% rs2)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let remw insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let condOverflow =
    ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblL2 = builder.NewSymbol "L2"
  let lblL3 = builder.NewSymbol "L3"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := AST.sext 64<rt> rs1)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (AST.cjmp condOverflow (AST.name lblL2) (AST.name lblL3))
  builder <! (AST.lmark lblL2)
  builder <! (rd := AST.num0 64<rt>)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL3)
  builder <! (rd := AST.sext 64<rt> (rs1 ?% rs2))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let remuw insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = (rs2 == AST.num0 32<rt>)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condZero (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (rd := AST.sext 64<rt> rs1)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := AST.sext 64<rt> (rs1 .% rs2))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fld insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let condAlign = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect Lock)
  builder <! (rd := AST.sext ctxt.WordBitSize mem)
  builder <! (AST.sideEffect Unlock)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := AST.sext ctxt.WordBitSize mem)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fsd insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let condAlign = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect Lock)
  builder <! (mem := rd)
  builder <! (AST.sideEffect Unlock)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (mem := rd)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fltdots insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let checkNan = (checkNan 32<rt> rs1 .| checkNan 32<rt> rs2)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = AST.flt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 ctxt.WordBitSize) (AST.num0 ctxt.WordBitSize)
  let fscr = getRegVar ctxt R.FCSR
  startMark insInfo builder
  builder <! (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rtVal)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := numU64 0uL 64<rt>)
  builder <! (fscr := fscr .| numU32 16u 32<rt>)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fledots insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let checkNan = (checkNan 32<rt> rs1 .| checkNan 32<rt> rs2)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  startMark insInfo builder
  builder <! (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rtVal)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := numU64 0uL 64<rt>)
  builder <! (fscr := fscr .| numU32 16u 32<rt>)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let feqdots insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = (AST.xtlo 32<rt> rs1)
  let rs2 = (AST.xtlo 32<rt> rs2)
  let checkSNan = (checkSNan 32<rt> rs1 .| checkSNan 32<rt> rs2)
  let checkNan = (checkNan 32<rt> rs1 .| checkNan 32<rt> rs2)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = AST.feq rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  let flagFscr = (AST.ite (checkSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>))
  startMark insInfo builder
  builder <! (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rtVal)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := numU64 0uL 64<rt>)
  builder <! (fscr := fscr .| flagFscr)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fclassdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1

  let plusZero = numU32 0u 32<rt>
  let negZero = numU32 0x80000000u 32<rt>
  let sign = AST.extract rs1 1<rt> 31

  let lblPos = builder.NewSymbol "Pos"
  let lblNeg = builder.NewSymbol "Neg"
  let lblEnd = builder.NewSymbol "End"

  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = checkInf 32<rt> rs1
  let condSubnormal = checkSubnormal 32<rt> rs1
  let condSNan = checkSNan 32<rt> rs1
  let condQNan = checkQNan 32<rt> rs1

  let rdOr f = (rd := rd .| f)

  startMark insInfo builder
  builder <! (rd := AST.num0 64<rt>)
  builder <! (AST.cjmp sign (AST.name lblNeg) (AST.name lblPos))
  builder <! (AST.lmark lblPos)
  builder <! (rdOr (AST.ite condInf (numU32 (1u <<< 7) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condZero (numU32 (1u <<< 4) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) (AST.num0 64<rt>)))
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblNeg)
  builder <! (rdOr (AST.ite condInf (numU32 (1u <<< 0) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condZero (numU32 (1u <<< 3) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) (AST.num0 64<rt>)))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fclassdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt

  let plusZero = numU64 0uL 64<rt>
  let negZero = numU64 0x8000000000000000uL 64<rt>
  let sign = AST.extract rs1 1<rt> 63

  let lblPos = builder.NewSymbol "Pos"
  let lblNeg = builder.NewSymbol "Neg"
  let lblEnd = builder.NewSymbol "End"

  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = checkInf 64<rt> rs1
  let condSubnormal = checkSubnormal 64<rt> rs1
  let condSNan = checkSNan 64<rt> rs1
  let condQNan = checkQNan 64<rt> rs1

  let rdOr f = (rd := rd .| f)

  startMark insInfo builder
  builder <! (rd := AST.num0 64<rt>)
  builder <! (AST.cjmp sign (AST.name lblNeg) (AST.name lblPos))
  builder <! (AST.lmark lblPos)
  builder <! (rdOr (AST.ite condInf (numU32 (1u <<< 7) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condZero (numU32 (1u <<< 4) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) (AST.num0 64<rt>)))
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblNeg)
  builder <! (rdOr (AST.ite condInf (numU32 (1u <<< 0) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condZero (numU32 (1u <<< 3) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) (AST.num0 64<rt>)))
  builder <! (rdOr (AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) (AST.num0 64<rt>)))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let flw insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let tmp = builder.NewTempVar 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect Lock)
  builder <! (tmp := mem)
  builder <! (rd := (AST.zext 64<rt> tmp) .| upperBitOne)
  builder <! (AST.sideEffect Unlock)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (tmp := mem)
  builder <! (rd := (AST.zext 64<rt> tmp) .| upperBitOne)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fsw insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, mem = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  startMark insInfo builder
  builder <! (AST.cjmp condAlign (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect Lock)
  builder <! (mem := AST.xtlo 32<rt> rd)
  builder <! (AST.sideEffect Unlock)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (mem := AST.xtlo 32<rt> rd)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder


let fltdotd insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkNan = (checkNan 64<rt> rs1 .| checkNan 64<rt> rs2)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = AST.flt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  startMark insInfo builder
  builder <! (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rtVal)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := numU64 0uL 64<rt>)
  builder <! (fscr := fscr .| numU32 16u 32<rt>)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fledotd insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkNan = (checkNan 64<rt> rs1 .| checkNan 64<rt> rs2)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  startMark insInfo builder
  builder <! (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rtVal)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := numU64 0uL 64<rt>)
  builder <! (fscr := fscr .| numU32 16u 32<rt>)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let feqdotd insInfo ctxt =
  let builder = IRBuilder (16)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let checkSNan = (checkSNan 64<rt> rs1 .| checkSNan 64<rt> rs2)
  let checkNan = (checkNan 64<rt> rs1 .| checkNan 64<rt> rs2)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let cond = AST.feq rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fscr = getRegVar ctxt R.FCSR
  let flagFscr = (AST.ite (checkSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>))
  startMark insInfo builder
  builder <! (AST.cjmp checkNan (AST.name lblL1) (AST.name lblL0))
  builder <! (AST.lmark lblL0)
  builder <! (rd := rtVal)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (rd := numU64 0uL 64<rt>)
  builder <! (fscr := fscr .| flagFscr)
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fadddots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fadd rs1 rs2))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fadd rs1 rs2)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder


let fadddotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fadd rs1 rs2))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fadd rs1 rs2)
    builder <! (rd := rtVal)
    endMark insInfo builder

let fsubdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fsub rs1 rs2))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fsub rs1 rs2)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fsubdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fsub rs1 rs2))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fsub rs1 rs2)
    builder <! (rd := rtVal)
    endMark insInfo builder

let fmuldots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fmul rs1 rs2))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fmul rs1 rs2)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fmuldotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fmul rs1 rs2))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.mul rs1 rs2)
    builder <! (rd := rtVal)
    endMark insInfo builder

let fdivdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fdiv rs1 rs2))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fdiv rs1 rs2)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fdivdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rm = getFourOprs insInfo
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs insInfo ctxt
  let rounding = roundingToCastFloat rm
  let rtVal = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (rtVal := AST.cast rounding 64<rt> (AST.fdiv rs1 rs2))
  builder <! (rd := rtVal)
  endMark insInfo builder

let fsqrtdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fsqrt rs1))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fsqrt rs1)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fsqrtdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fsqrt rs1))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fsqrt rs1)
    builder <! (rd := rtVal)
    endMark insInfo builder

let fmindots insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = builder.NewTempVar 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let cond = AST.flt rs1 rs2
  startMark insInfo builder
  builder <! (rtVal := AST.ite cond rs1 rs2)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fmindotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = builder.NewTempVar 64<rt>
  let cond = AST.flt rs1 rs2
  startMark insInfo builder
  builder <! (rtVal := AST.ite cond rs1 rs2)
  builder <! (rd := rtVal)
  endMark insInfo builder

let fmaxdots insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = builder.NewTempVar 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let cond = AST.flt rs1 rs2
  startMark insInfo builder
  builder <! (rtVal := AST.ite cond rs2 rs1)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fmaxdotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = builder.NewTempVar 64<rt>
  let cond = AST.flt rs1 rs2
  startMark insInfo builder
  builder <! (rtVal := AST.ite cond rs2 rs1)
  builder <! (rd := rtVal)
  endMark insInfo builder

let fmadddots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = numU64 0xFFFFFFFF00000000uL 64<rt>
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fadd (AST.fmul rs1 rs2) rs3))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fadd (AST.fmul rs1 rs2) rs3)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fmadddotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fadd (AST.fmul rs1 rs2) rs3))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fadd (AST.fmul rs1 rs2) rs3)
    builder <! (rd := rtVal)
    endMark insInfo builder

let fmsubdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fsub (AST.fmul rs1 rs2) rs3))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fsub (AST.fmul rs1 rs2) rs3)
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fmsubdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fsub (AST.fmul rs1 rs2) rs3))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fsub (AST.fmul rs1 rs2) rs3)
    builder <! (rd := rtVal)
    endMark insInfo builder

let fnmsubdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fsub (AST.neg rs3) (AST.fmul rs1 rs2)))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fsub (AST.neg rs3) (AST.fmul rs1 rs2))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fnmsubdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fsub (AST.neg rs3) (AST.fmul rs1 rs2)))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fsub (AST.neg rs3) (AST.fmul rs1 rs2))
    builder <! (rd := rtVal)
    endMark insInfo builder

let fnmadddots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rs3 = AST.xtlo 32<rt> rs3
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> (AST.fsub rs3 (AST.fmul rs1 rs2)))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 32<rt> (AST.fsub rs3 (AST.fmul rs1 rs2))
    builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
    endMark insInfo builder

let fnmadddotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2, rs3, rm = getFiveOprs insInfo
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> (AST.fsub rs3 (AST.fmul rs1 rs2)))
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingFl builder ctxt 64<rt> (AST.fsub rs3 (AST.fmul rs1 rs2))
    builder <! (rd := rtVal)
    endMark insInfo builder

let fsgnjdots insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = builder.NewTempVar 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2
  startMark insInfo builder
  builder <! (rtVal := (rs1 .& mask) .| sign)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fsgnjdotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = builder.NewTempVar 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2
  startMark insInfo builder
  builder <! (rtVal := (rs1 .& mask) .| sign)
  builder <! (rd := rtVal)
  endMark insInfo builder

let fsgnjndots insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = builder.NewTempVar 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2 <+> numU32 0x80000000u 32<rt>
  startMark insInfo builder
  builder <! (rtVal := (rs1 .& mask) .| sign)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fsgnjndotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = builder.NewTempVar 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2 <+> numU64 0x8000000000000000uL 64<rt>
  startMark insInfo builder
  builder <! (rtVal := (rs1 .& mask) .| sign)
  builder <! (rd := rtVal)
  endMark insInfo builder

let fsgnjxdots insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let rtVal = builder.NewTempVar 32<rt>
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = (getSignFloat 32<rt> rs2) <+> (getSignFloat 32<rt> rs1)
  startMark insInfo builder
  builder <! (rtVal := (rs1 .& mask) .| sign)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fsgnjxdotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rs2 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let rtVal = builder.NewTempVar 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2 <+> getSignFloat 64<rt> rs1
  startMark insInfo builder
  builder <! (rtVal := (rs1 .& mask) .| sign)
  builder <! (rd := rtVal)
  endMark insInfo builder

(* FIX ME: AQRL *)
let amod insInfo ctxt op =
  let builder = IRBuilder (16)
  let rd, mem, rs2, aqrl = getFourOprs insInfo |> transFourOprs insInfo ctxt
  let cond = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let tmp = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect Lock)
  builder <! (tmp := mem)
  builder <! (mem := op tmp rs2)
  builder <! (rd := tmp)
  builder <! (AST.sideEffect Unlock)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (AST.sideEffect (Exception "Address-misaligned exception"))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let amow insInfo ctxt op =
  let builder = IRBuilder (16)
  let rd, mem, rs2, aqrl = getFourOprs insInfo |> transFourOprs insInfo ctxt
  let rs2 = AST.xtlo 32<rt> rs2
  let cond = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = builder.NewSymbol "L0"
  let lblL1 = builder.NewSymbol "L1"
  let lblEnd = builder.NewSymbol "End"
  let tmp = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (AST.cjmp cond (AST.name lblL0) (AST.name lblL1))
  builder <! (AST.lmark lblL0)
  builder <! (AST.sideEffect Lock)
  builder <! (tmp := mem)
  builder <! (mem := AST.sext 64<rt> (op tmp rs2))
  builder <! (rd := AST.sext 64<rt> tmp)
  builder <! (AST.sideEffect Unlock)
  builder <! (AST.jmp (AST.name lblEnd))
  builder <! (AST.lmark lblL1)
  builder <! (AST.sideEffect (Exception "Address-misaligned exception"))
  builder <! (AST.lmark lblEnd)
  endMark insInfo builder

let fmvdotxdotw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.sext 64<rt> (AST.xtlo 32<rt> rs1))
  endMark insInfo builder

let fmvdotwdotx insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.xtlo 32<rt> rs1)
  endMark insInfo builder

let fmvdotxdotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1)
  endMark insInfo builder

let fmvdotddotx insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1 = getTwoOprs insInfo |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := rs1)
  endMark insInfo builder

(* TODO: x0 and 0 change write csr *)
let csrrw insInfo ctxt =
  let builder = IRBuilder(8)
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.sideEffect Lock)
  builder <! (tmpVar := csr)
  builder <! (csr := rs1)
  builder <! (rd := tmpVar)
  builder <! (AST.sideEffect Unlock)
  endMark insInfo builder

let csrrwi insInfo ctxt =
  let builder = IRBuilder(8)
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.sideEffect Lock)
  builder <! (tmpVar := csr)
  builder <! (csr := AST.zext 64<rt> imm)
  builder <! (rd := tmpVar)
  builder <! (AST.sideEffect Unlock)
  endMark insInfo builder

let csrrs insInfo ctxt =
  let builder = IRBuilder(8)
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.sideEffect Lock)
  builder <! (tmpVar := csr)
  builder <! (csr := tmpVar .| rs1)
  builder <! (rd := tmpVar)
  builder <! (AST.sideEffect Unlock)
  endMark insInfo builder

let csrrsi insInfo ctxt =
  let builder = IRBuilder(8)
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.sideEffect Lock)
  builder <! (tmpVar := csr)
  builder <! (csr := tmpVar .| (AST.zext 64<rt> imm))
  builder <! (rd := tmpVar)
  builder <! (AST.sideEffect Unlock)
  endMark insInfo builder

let csrrc insInfo ctxt =
  let builder = IRBuilder(8)
  let rd, csr, rs1 = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.sideEffect Lock)
  builder <! (tmpVar := csr)
  builder <! (csr := tmpVar .& (AST.neg rs1))
  builder <! (rd := tmpVar)
  builder <! (AST.sideEffect Unlock)
  endMark insInfo builder

let csrrci insInfo ctxt =
  let builder = IRBuilder(8)
  let rd, csr, imm = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let tmpVar = builder.NewTempVar 64<rt>
  startMark insInfo builder
  builder <! (AST.sideEffect Lock)
  builder <! (tmpVar := csr)
  builder <! (csr := tmpVar .& (AST.neg (AST.zext 64<rt> imm)))
  builder <! (rd := tmpVar)
  builder <! (AST.sideEffect Unlock)
  endMark insInfo builder

(* TODO: RM and overflow *)
let fcvtdotldotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> rs1)
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingInt builder ctxt 64<rt> rs1
    builder <! (rd := rtVal)
    endMark insInfo builder

let fcvtdotwdotd insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> rs1)
    builder <! (rd := rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingInt builder ctxt 32<rt> rs1
    builder <! (rd := rtVal)
    endMark insInfo builder

let fcvtdotwdots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = builder.NewTempVar 32<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 32<rt> rs1)
    builder <! (rd := AST.sext 64<rt> rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingInt builder ctxt 32<rt> rs1
    builder <! (rd := AST.sext 64<rt> rtVal)
    endMark insInfo builder

let fcvtdotldots insInfo ctxt =
  let builder = IRBuilder (32)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastInt rm
    let rtVal = builder.NewTempVar 64<rt>
    startMark insInfo builder
    builder <! (rtVal := AST.cast rounding 64<rt> rs1)
    builder <! (rd := AST.sext 64<rt> rtVal)
    endMark insInfo builder
  else
    startMark insInfo builder
    let rtVal = dynamicRoundingInt builder ctxt 64<rt> rs1
    builder <! (rd := AST.sext 64<rt> rtVal)
    endMark insInfo builder

let fcvtdotsdotw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let rs1 = AST.xtlo 32<rt> rs1
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let rtVal = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (rtVal := AST.cast CastKind.IntToFloat 32<rt> rs1)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fcvtdotsdotl insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let rtVal = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (rtVal := AST.cast CastKind.IntToFloat 32<rt> rs1)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fcvtdotddotw insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.cast CastKind.IntToFloat 64<rt> (AST.xtlo 32<rt> rs1))
  endMark insInfo builder

let fcvtdotddotl insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.cast CastKind.IntToFloat 64<rt> rs1)
  endMark insInfo builder

let fcvtdotsdotd insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, rm = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  let upperBitOne = (numU64 0xFFFFFFFF00000000uL 64<rt>)
  let rtVal = builder.NewTempVar 32<rt>
  startMark insInfo builder
  builder <! (rtVal := AST.cast CastKind.FloatCast 32<rt> rs1)
  builder <! (rd := (AST.zext 64<rt> rtVal) .| upperBitOne)
  endMark insInfo builder

let fcvtdotddots insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, rs1, _ = getThreeOprs insInfo
  let rd, rs1 = (rd, rs1) |> transTwoOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.cast CastKind.FloatCast 64<rt> (AST.xtlo 32<rt> rs1))
  endMark insInfo builder


// TODO: Add reservation check
let lr insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, mem, aqrl = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  startMark insInfo builder
  builder <! (rd := AST.sext ctxt.WordBitSize mem)
  endMark insInfo builder

// TODO: Add reservation check
let sc insInfo ctxt =
  let builder = IRBuilder (4)
  let rd, mem, aqrl = getThreeOprs insInfo |> transThreeOprs insInfo ctxt
  let accessLength = getAccessLength (snd (getTwoOprs insInfo))
  startMark insInfo builder
  builder <! (mem := AST.xtlo accessLength rd)
  builder <! (rd := numI32 0 64<rt>)
  endMark insInfo builder

let translate insInfo (ctxt: TranslationContext) =
  match insInfo.Opcode with
  | Op.CdotMV
  | Op.CdotADD
  | Op.ADD -> add insInfo ctxt
  | Op.CdotADDW
  | Op.ADDW -> addw insInfo ctxt
  | Op.CdotSUBW
  | Op.SUBW -> subw insInfo ctxt
  | Op.CdotAND
  | Op.AND -> ``and`` insInfo ctxt
  | Op.CdotOR
  | Op.OR -> ``or`` insInfo ctxt
  | Op.CdotXOR
  | Op.XOR -> xor insInfo ctxt
  | Op.CdotSUB
  | Op.SUB -> sub insInfo ctxt
  | Op.SLT -> slt insInfo ctxt
  | Op.SLTU -> sltu insInfo ctxt
  | Op.SLL -> sll insInfo ctxt
  | Op.SLLW -> sllw insInfo ctxt
  | Op.SRA -> sra insInfo ctxt
  | Op.SRAW -> sraw insInfo ctxt
  | Op.SRL -> srl insInfo ctxt
  | Op.SRLW -> srlw insInfo ctxt
  | Op.CdotANDI
  | Op.ANDI -> andi insInfo ctxt
  | Op.CdotADDI16SP
  | Op.CdotLI
  | Op.CdotADDI
  | Op.CdotADDI4SPN
  | Op.ADDI -> addi insInfo ctxt
  | Op.ORI -> ori insInfo ctxt
  | Op.XORI -> xori insInfo ctxt
  | Op.SLTI -> slti insInfo ctxt
  | Op.SLTIU -> sltiu insInfo ctxt
  | Op.CdotJ
  | Op.JAL -> jal insInfo ctxt
  | Op.CdotJR
  | Op.CdotJALR
  | Op.JALR -> jalr insInfo ctxt
  | Op.CdotBEQZ
  | Op.BEQ -> beq insInfo ctxt
  | Op.CdotBNEZ
  | Op.BNE -> bne insInfo ctxt
  | Op.BLT -> blt insInfo ctxt
  | Op.BGE -> bge insInfo ctxt
  | Op.BLTU -> bltu insInfo ctxt
  | Op.BGEU -> bgeu insInfo ctxt
  | Op.CdotLW
  | Op.CdotLD
  | Op.CdotLWSP
  | Op.CdotLDSP
  | Op.LB
  | Op.LH
  | Op.LW
  | Op.LD -> load insInfo ctxt
  | Op.LBU
  | Op.LHU
  | Op.LWU -> loadu insInfo ctxt
  | Op.CdotSW
  | Op.CdotSD
  | Op.CdotSWSP
  | Op.CdotSDSP
  | Op.SB
  | Op.SH
  | Op.SW
  | Op.SD -> store insInfo ctxt
  | Op.CdotEBREAK
  | Op.EBREAK -> sideEffects insInfo Breakpoint
  | Op.ECALL -> sideEffects insInfo SysCall
  | Op.CdotSRAI
  | Op.SRAI -> srai insInfo ctxt
  | Op.CdotSLLI
  | Op.SLLI -> slli insInfo ctxt
  | Op.CdotSRLI
  | Op.SRLI -> srli insInfo ctxt
  | Op.CdotLUI
  | Op.LUI -> lui insInfo ctxt
  | Op.AUIPC -> auipc insInfo ctxt
  | Op.CdotADDIW
  | Op.ADDIW -> addiw insInfo ctxt
  | Op.SLLIW -> slliw insInfo ctxt
  | Op.SRLIW -> srliw insInfo ctxt
  | Op.SRAIW -> sraiw insInfo ctxt
  | Op.MUL -> mul insInfo ctxt
  | Op.MULH -> mulh insInfo ctxt
  | Op.MULHSU -> mulhsu insInfo ctxt
  | Op.MULHU -> mulhu insInfo ctxt
  | Op.MULW -> mulw insInfo ctxt
  | Op.CdotNOP -> nop insInfo
  | Op.CdotFLD
  | Op.CdotFLDSP
  | Op.FLD -> fld insInfo ctxt
  | Op.CdotFSD
  | Op.CdotFSDSP
  | Op.FSD -> fsd insInfo ctxt
  | Op.FLTdotS -> fltdots insInfo ctxt
  | Op.FLTdotD -> fltdotd insInfo ctxt
  | Op.FLEdotS -> fledots insInfo ctxt
  | Op.FLEdotD -> fledotd insInfo ctxt
  | Op.FEQdotS -> feqdots insInfo ctxt
  | Op.FEQdotD -> feqdotd insInfo ctxt
  | Op.FLW -> flw insInfo ctxt
  | Op.FSW -> fsw insInfo ctxt
  | Op.FADDdotS -> fadddots insInfo ctxt
  | Op.FADDdotD -> fadddotd insInfo ctxt
  | Op.FSUBdotS -> fsubdots insInfo ctxt
  | Op.FSUBdotD -> fsubdotd insInfo ctxt
  | Op.FDIVdotS -> fdivdots insInfo ctxt
  | Op.FDIVdotD -> fdivdotd insInfo ctxt
  | Op.FMULdotS -> fmuldots insInfo ctxt
  | Op.FMULdotD -> fmuldotd insInfo ctxt
  | Op.FMINdotS -> fmindots insInfo ctxt
  | Op.FMINdotD -> fmindotd insInfo ctxt
  | Op.FMAXdotS -> fmaxdots insInfo ctxt
  | Op.FMAXdotD -> fmaxdotd insInfo ctxt
  | Op.FNMADDdotS -> fnmadddots insInfo ctxt
  | Op.FNMADDdotD -> fnmadddotd insInfo ctxt
  | Op.FNMSUBdotS -> fnmsubdots insInfo ctxt
  | Op.FNMSUBdotD -> fnmsubdotd insInfo ctxt
  | Op.FMADDdotS -> fmadddots insInfo ctxt
  | Op.FMADDdotD -> fmadddotd insInfo ctxt
  | Op.FMSUBdotS -> fmsubdots insInfo ctxt
  | Op.FMSUBdotD -> fmsubdotd insInfo ctxt
  | Op.FSQRTdotS -> fsqrtdots insInfo ctxt
  | Op.FSQRTdotD -> fsqrtdotd insInfo ctxt
  | Op.FCLASSdotS -> fclassdots insInfo ctxt
  | Op.FCLASSdotD -> fclassdotd insInfo ctxt
  | Op.FSGNJdotS -> fsgnjdots insInfo ctxt
  | Op.FSGNJdotD -> fsgnjdotd insInfo ctxt
  | Op.FSGNJNdotS -> fsgnjndots insInfo ctxt
  | Op.FSGNJNdotD -> fsgnjndotd insInfo ctxt
  | Op.FSGNJXdotS -> fsgnjxdots insInfo ctxt
  | Op.FSGNJXdotD -> fsgnjxdotd insInfo ctxt
  | Op.AMOADDdotW -> amow insInfo ctxt (.+)
  | Op.AMOADDdotD -> amod insInfo ctxt (.+)
  | Op.AMOANDdotW -> amow insInfo ctxt (.&)
  | Op.AMOANDdotD -> amod insInfo ctxt (.&)
  | Op.AMOXORdotW -> amow insInfo ctxt (<+>)
  | Op.AMOXORdotD -> amod insInfo ctxt (<+>)
  | Op.AMOORdotW -> amow insInfo ctxt (.|)
  | Op.AMOORdotD -> amod insInfo ctxt (.|)
  | Op.AMOMINdotW -> amow insInfo ctxt (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINdotD -> amod insInfo ctxt (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINUdotW -> amow insInfo ctxt (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMINUdotD -> amod insInfo ctxt (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMAXdotW -> amow insInfo ctxt (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXdotD -> amod insInfo ctxt (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXUdotW -> amow insInfo ctxt (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOMAXUdotD -> amod insInfo ctxt (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOSWAPdotW -> amow insInfo ctxt (fun _ b -> b)
  | Op.AMOSWAPdotD -> amod insInfo ctxt (fun _ b -> b)
  | Op.FMVdotXdotW -> fmvdotxdotw insInfo ctxt
  | Op.FMVdotXdotD -> fmvdotxdotd insInfo ctxt
  | Op.FMVdotWdotX -> fmvdotwdotx insInfo ctxt
  | Op.FMVdotDdotX -> fmvdotddotx insInfo ctxt
  | Op.DIVW -> divw insInfo ctxt
  | Op.DIV -> div insInfo ctxt
  | Op.DIVU -> divu insInfo ctxt
  | Op.REM -> rem insInfo ctxt
  | Op.REMU -> remu insInfo ctxt
  | Op.REMW -> remw insInfo ctxt
  | Op.DIVUW -> divuw insInfo ctxt
  | Op.REMUW -> remuw insInfo ctxt
  | Op.FCVTdotWdotD -> fcvtdotwdotd insInfo ctxt
  | Op.FCVTdotLdotD -> fcvtdotldotd insInfo ctxt
  | Op.FCVTdotWdotS -> fcvtdotwdots insInfo ctxt
  | Op.FCVTdotLdotS -> fcvtdotldots insInfo ctxt
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO -> nop insInfo
  | Op.LRdotW
  | Op.LRdotD -> lr insInfo ctxt
  | Op.SCdotW
  | Op.SCdotD -> sc insInfo ctxt
  | Op.CSRRW -> csrrw insInfo ctxt
  | Op.CSRRWI -> csrrwi insInfo ctxt
  | Op.CSRRS -> csrrs insInfo ctxt
  | Op.CSRRSI -> csrrsi insInfo ctxt
  | Op.CSRRC -> csrrc insInfo ctxt
  | Op.CSRRCI -> csrrci insInfo ctxt
  | Op.FCVTdotSdotW -> fcvtdotsdotw insInfo ctxt
  | Op.FCVTdotSdotL -> fcvtdotsdotl insInfo ctxt
  | Op.FCVTdotSdotD -> fcvtdotsdotd insInfo ctxt
  | Op.FCVTdotDdotS -> fcvtdotddots insInfo ctxt
  | Op.FCVTdotDdotW -> fcvtdotddotw insInfo ctxt
  | Op.FCVTdotDdotL -> fcvtdotddotl insInfo ctxt
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
