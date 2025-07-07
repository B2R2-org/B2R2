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

module internal B2R2.FrontEnd.RISCV64.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

let inline (:=) dst src =
  match dst with
  | Var (_, rid, _, _) when rid = Register.toRegID Register.X0 ->
    dst := dst (* Prevent setting x0. Our optimizer will remove this anyways. *)
  | _ ->
    dst := src

let inline getCSRReg (bld: ILowUIRBuilder) csr =
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
    | 3114us -> Register.CSR3114
    | 3787us -> Register.CSR3787
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
    | 2145us -> Register.CSR2145
    | 2617us -> Register.CSR2617
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
    | 2945us -> Register.CSR2945
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
  Register.toRegID csrReg |> bld.GetRegVar

let bvOfBaseAddr (bld: ILowUIRBuilder) addr =
  numU64 addr bld.RegType

let bvOfInstrLen (bld: ILowUIRBuilder) (ins: Instruction) =
  numU32 ins.Length bld.RegType

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand opr -> opr
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> o1, o2
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> o1, o2, o3
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) -> o1, o2, o3, o4
  | _ -> raise InvalidOperandException

let getFiveOprs (ins: Instruction) =
  match ins.Operands with
  | FiveOperands (o1, o2, o3, o4, o5) -> o1, o2, o3, o4, o5
  | _ -> raise InvalidOperandException

let transOprToExpr (ins: Instruction) bld = function
  | OpReg reg -> regVar bld reg
  | OpImm imm
  | OpShiftAmount imm -> numU64 imm bld.RegType
  | OpMem (b, Some (Imm o), sz) ->
    let reg = regVar bld b
    let offset = numI64 o bld.RegType
    AST.loadLE sz (reg .+ offset)
  | OpAddr (Relative o) -> numI64 (int64 ins.Address + o) bld.RegType
  | OpAddr (RelativeBase (b, imm)) ->
    if b = Register.X0 then
      AST.num0 bld.RegType
    else
      let target = regVar bld b .+ numI64 (int64 imm) bld.RegType
      let mask = numI64 0xFFFFFFFF_FFFFFFFEL 64<rt>
      target .& mask
  | OpMem (b, None, sz) -> AST.loadLE sz (regVar bld b)
  | OpAtomMemOper (_) -> numU32 0u 32<rt> // FIXME:
  | OpCSR (csr) -> getCSRReg bld csr
  | _ -> raise InvalidOperandException

let private maskForFCSR csr (opr1, opr2) =
  let lowSrc = AST.xtlo 32<rt> opr2
  let mask =
    match csr with
    | OpCSR csr when csr = 0001us -> lowSrc .& numU32 0b11111u 32<rt>
    | OpCSR csr when csr = 0002us -> lowSrc .& numU32 0b111u 32<rt>
    | _ -> opr2
  opr1, mask

let private assignFCSR dst src bld =
  match dst with
  | BinOp _ ->
    let lowSrc = AST.xtlo 32<rt> src
    bld <+ (regVar bld R.FRM :=
      (lowSrc .& numU32 0b11100000u 32<rt>) >> numI32 5 32<rt>)
    bld <+ (regVar bld R.FFLAGS := lowSrc .& numU32 0b11111u 32<rt>)
  | _ -> bld <+ (dst := src)

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

let dynamicRoundingFl bld rt res =
  let tmpVar = tmpVar bld rt
  let frm = (regVar bld Register.FRM) .& (numI32 7 32<rt>)
  let condRNERMM = (frm == numI32 0 32<rt>) .| (frm == numI32 4 32<rt>)
  let condRTZ = frm == numI32 1 32<rt>
  let condRDN = frm == numI32 2 32<rt>
  let condRUP = frm == numI32 3 32<rt>
  let lblD0 = label bld "DF0"
  let lblD1 = label bld "DF1"
  let lblD2 = label bld "DF2"
  let lblD3 = label bld "DF3"
  let lblD4 = label bld "DF4"
  let lblD5 = label bld "DF6"
  let lblD6 = label bld "DF7"
  let lblDException = label bld "DFException"
  let lblDEnd = label bld "DFEnd"
  bld <+ (AST.cjmp condRNERMM (AST.jmpDest lblD0) (AST.jmpDest lblD1))
  bld <+ (AST.lmark lblD0)
  bld <+ (tmpVar := AST.cast CastKind.FtoFRound rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblD1)
  bld <+ (AST.cjmp condRTZ (AST.jmpDest lblD2) (AST.jmpDest lblD3))
  bld <+ (AST.lmark lblD2)
  bld <+ (tmpVar := AST.cast CastKind.FtoFTrunc rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblD3)
  bld <+ (AST.cjmp condRDN (AST.jmpDest lblD4) (AST.jmpDest lblD5))
  bld <+ (AST.lmark lblD4)
  bld <+ (tmpVar := AST.cast CastKind.FtoFFloor rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblD5)
  bld <+ (AST.cjmp condRUP (AST.jmpDest lblD6) (AST.jmpDest lblDException))
  bld <+ (AST.lmark lblD6)
  bld <+ (tmpVar := AST.cast CastKind.FtoFCeil rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblDException)
  bld <+ (AST.sideEffect (Exception "illegal instruction"))
  bld <+ (AST.lmark lblDEnd)
  tmpVar

let dynamicRoundingInt bld rt res =
  let tmpVar = tmpVar bld rt
  let frm = (regVar bld Register.FRM) .& (numI32 7 32<rt>)
  let condRNERMM = (frm == numI32 0 32<rt>) .| (frm == numI32 4 32<rt>)
  let condRTZ = frm == numI32 1 32<rt>
  let condRDN = frm == numI32 2 32<rt>
  let condRUP = frm == numI32 3 32<rt>
  let lblD0 = label bld "DI0"
  let lblD1 = label bld "DI1"
  let lblD2 = label bld "DI2"
  let lblD3 = label bld "DI3"
  let lblD4 = label bld "DI4"
  let lblD5 = label bld "DI6"
  let lblD6 = label bld "DI7"
  let lblDException = label bld "DIException"
  let lblDEnd = label bld "DIEnd"
  bld <+ (AST.cjmp condRNERMM (AST.jmpDest lblD0) (AST.jmpDest lblD1))
  bld <+ (AST.lmark lblD0)
  bld <+ (tmpVar := AST.cast (CastKind.FtoIRound) rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblD1)
  bld <+ (AST.cjmp condRTZ (AST.jmpDest lblD2) (AST.jmpDest lblD3))
  bld <+ (AST.lmark lblD2)
  bld <+ (tmpVar := AST.cast (CastKind.FtoITrunc) rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblD3)
  bld <+ (AST.cjmp condRDN (AST.jmpDest lblD4) (AST.jmpDest lblD5))
  bld <+ (AST.lmark lblD4)
  bld <+ (tmpVar := AST.cast (CastKind.FtoIFloor) rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblD5)
  bld <+ (AST.cjmp condRUP (AST.jmpDest lblD6) (AST.jmpDest lblDException))
  bld <+ (AST.lmark lblD6)
  bld <+ (tmpVar := AST.cast (CastKind.FtoICeil) rt res)
  bld <+ (AST.jmp (AST.jmpDest lblDEnd))
  bld <+ (AST.lmark lblDException)
  bld <+ (AST.sideEffect (Exception "illegal instruction"))
  bld <+ (AST.lmark lblDEnd)
  tmpVar

let transOneOpr ins bld opr = transOprToExpr ins bld opr

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

let getNanBoxed e = (numU64 0xFFFFFFFF_00000000uL 64<rt>) .| (AST.zext 64<rt> e)

let dstAssignSingleWithRound dst src rm bld =
  let rtVal = getNanBoxed src
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    bld <+ (dst := AST.cast rounding 64<rt> rtVal)
  else
    bld <+ (dst := dynamicRoundingFl bld 64<rt> rtVal)

let dstAssignDoubleWithRound dst src rm bld =
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    bld <+ (dst := AST.cast rounding 64<rt> src)
  else
    bld <+ (dst := dynamicRoundingFl bld 64<rt> src)

let getAddrFromMem x =
  match x with
  | Load (_, _, addr, _) -> addr
  | _ -> raise InvalidExprException

let getAddrFromMemAndSize x =
  match x with
  | Load (_, rt, addr, _) -> addr, numI32 (RegType.toByteWidth rt) 64<rt>
  | _ -> raise InvalidExprException

let isAligned rt expr =
  match rt with
  | 32<rt> -> ((expr .& (numU32 0x3u 64<rt>)) == AST.num0 64<rt>)
  | 64<rt> -> ((expr .& (numU32 0x7u 64<rt>)) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let getAccessLength = function
  | OpMem (_, _, sz) -> sz
  | _ -> raise InvalidOperandException

let fpDefaultNan oprSz =
  match oprSz with
  | 64<rt> -> numU64 0x7ff8000000000000UL 64<rt>
  | 32<rt> -> numU64 0x7fc00000UL 32<rt>
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

let isZero rt e =
  match rt with
  | 32<rt> ->
    let mask = numU32 0x7fffffffu 32<rt>
    AST.eq (e .& mask) (AST.num0 32<rt>)
  | 64<rt> ->
    let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
    AST.eq (e .& mask) (AST.num0 64<rt>)
  | _ -> Terminator.impossible ()

let fpNeg rt expr =
  let mask =
    match rt with
    | 32<rt> -> numU64 0x80000000UL rt
    | 64<rt> -> numU64 0x8000000000000000UL rt
    | _ -> raise InvalidOperandSizeException
  expr <+> mask

let getSignFloat rt e =
  match rt with
  | 32<rt> -> e .& (numU32 0x80000000u 32<rt>)
  | 64<rt> -> e .& (numU64 0x8000000000000000uL 64<rt>)
  | _ -> raise InvalidRegTypeException

let getFloat32FromReg e =
  let mask = numU64 0xFFFFFFFF_00000000uL 64<rt>
  AST.ite (e .& mask == mask) (AST.xtlo 32<rt> e) (numI32 0x7fc00000 32<rt>)

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

let private mulWithOverflow src1 src2 bld (isSign, isUnsign) isLow =
  let src1IsNeg = tmpVar bld 1<rt>
  let struct (tSrc1, tSrc2, hiSrc1, loSrc1) = tmpVars4 bld 64<rt>
  let struct (hiSrc2, loSrc2, pMid1, pMid2) = tmpVars4 bld 64<rt>
  let struct (pMid, pLow) = tmpVars2 bld 64<rt>
  let struct (low, high) = tmpVars2 bld 64<rt>
  let struct (src2IsNeg, signBit) = tmpVars2 bld 1<rt>
  let struct (tLow, tHigh) = tmpVars2 bld 64<rt>
  let n32 = numI32 32 64<rt>
  let mask32 = numI64 0xFFFFFFFFL 64<rt>
  let zero = numI32 0 64<rt>
  let one = numI32 1 64<rt>
  match isSign, isUnsign with
  | true, true ->
    bld <+ (src1IsNeg := AST.xthi 1<rt> src1)
    bld <+ (src2IsNeg := AST.xthi 1<rt> src2)
    bld <+ (tSrc1 := AST.ite src1IsNeg (AST.neg src1) src1)
    bld <+ (tSrc2 := AST.ite src2IsNeg (AST.neg src2) src2)
  | true, false ->
    bld <+ (src1IsNeg := AST.xthi 1<rt> src1)
    bld <+ (tSrc1 := AST.ite src1IsNeg (AST.neg src1) src1)
    bld <+ (tSrc2 := src2)
  | _ ->
    bld <+ (tSrc1 := src1)
    bld <+ (tSrc2 := src2)
  bld <+ (hiSrc1 := (tSrc1 >> n32) .& mask32) (* SRC1[63:32] *)
  bld <+ (loSrc1 := tSrc1 .& mask32) (* SRC1[31:0] *)
  bld <+ (hiSrc2 := (tSrc2 >> n32) .& mask32) (* SRC2[63:32] *)
  bld <+ (loSrc2 := tSrc2 .& mask32) (* SRC2[31:0] *)
  bld <+ (pMid1 := hiSrc1 .* loSrc2)
  bld <+ (pMid2 := loSrc1 .* hiSrc2)
  bld <+ (pMid := pMid1 .+ pMid2)
  bld <+ (pLow := loSrc1 .* loSrc2)
  bld <+ (low := pLow .+ ((pMid .& mask32) << n32))
  if not isLow then
    let overFlowBit = checkOverflowOnDMul pMid1 pMid2
    bld
    <+ (high := hiSrc1 .* hiSrc2
             .+ ((pMid .+ (pLow >> n32)) >> n32)
             .+ overFlowBit)
  if isSign then
    bld <+ (signBit := src1IsNeg <+> src2IsNeg)
    bld <+ (tLow := AST.ite signBit (AST.neg low) low)
    if not isLow then
      let carry = AST.ite (AST.``and`` signBit (tLow == zero)) one zero
      bld <+ (tHigh := AST.ite signBit (AST.not high) high .+ carry)
  else
    if not isLow then
      bld <+ (tHigh := high)
    bld <+ (tLow := low)
  if isLow then tLow
  else tHigh

let add ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .+ rs2)
  bld --!> insLen

let addw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  bld <+ (rd := AST.sext 64<rt> (rs1 .+ rs2))
  bld --!> insLen

let subw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  bld <+ (rd := AST.sext 64<rt> (rs1 .- rs2))
  bld --!> insLen

let sub ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .- rs2)
  bld --!> insLen

let ``and`` ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .& rs2)
  bld --!> insLen

let ``or`` ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .| rs2)
  bld --!> insLen

let xor ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 <+> rs2)
  bld --!> insLen

let slt ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 ?< rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rtVal)
  bld --!> insLen

let sltu ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 .< rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rtVal)
  bld --!> insLen

let sll ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 << shiftAmm)
  bld --!> insLen

let sllw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (rs1 << shiftAmm))
  bld --!> insLen

let srl ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 >> shiftAmm)
  bld --!> insLen

let srlw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (rs1 >> shiftAmm))
  bld --!> insLen

let sra ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 ?>> shiftAmm)
  bld --!> insLen

let sraw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (rs1 ?>> shiftAmm))
  bld --!> insLen

let srai ins insLen bld =
  let rd, rs1, shiftAmm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 ?>> shiftAmm)
  bld --!> insLen

let srli ins insLen bld =
  let rd, rs1, shiftAmm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 >> shiftAmm)
  bld --!> insLen

let slli ins insLen bld =
  let rd, rs1, shiftAmm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 << shiftAmm)
  bld --!> insLen

let andi ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .& imm)
  bld --!> insLen

let addi ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .+ imm)
  bld --!> insLen

let ori ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 .| imm)
  bld --!> insLen

let xori ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1 <+> imm)
  bld --!> insLen

let slti ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 ?< imm
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rtVal)
  bld --!> insLen

let sltiu ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 .< imm
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rtVal)
  bld --!> insLen

let nop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let jal ins insLen bld =
  let rd, jumpTarget = getTwoOprs ins |> transTwoOprs ins bld
  let r = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := r)
  bld <+ (AST.interjmp jumpTarget InterJmpKind.IsCall)
  bld --!> insLen

let jalr ins insLen bld =
  let rd, jumpTarget = getTwoOprs ins |> transTwoOprs ins bld
  let r = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  let target = tmpVar bld 64<rt>
  let actualTarget = if target = AST.num0 bld.RegType then rd else target
  bld <!-- (ins.Address, insLen)
  bld <+ (target := jumpTarget)
  bld <+ (rd := r)
  bld <+ (AST.interjmp actualTarget InterJmpKind.IsRet)
  bld --!> insLen

let beq ins insLen bld =
  let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 == rs2
  let fallThrough =
    bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond offset fallThrough)
  bld --!> insLen

let bne ins insLen bld =
  let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 != rs2
  let fallThrough =
    bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond offset fallThrough)
  bld --!> insLen

let blt ins insLen bld =
  let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 ?< rs2
  let fallThrough =
    bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond offset fallThrough)
  bld --!> insLen

let bge ins insLen bld =
  let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 ?>= rs2
  let fallThrough =
    bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond offset fallThrough)
  bld --!> insLen

let bltu ins insLen bld =
  let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 .< rs2
  let fallThrough =
    bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond offset fallThrough)
  bld --!> insLen

let bgeu ins insLen bld =
  let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
  let cond = rs1 .>= rs2
  let fallThrough =
    bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.intercjmp cond offset fallThrough)
  bld --!> insLen

let load ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext bld.RegType mem)
  bld --!> insLen

let loadu ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.zext bld.RegType mem)
  bld --!> insLen

let store ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  let accessLength = getAccessLength (snd (getTwoOprs ins))
  bld <!-- (ins.Address, insLen)
  if accessLength = 64<rt> then bld <+ (mem := rd)
  else bld <+ (mem := AST.xtlo accessLength rd)
  bld --!> insLen

let sideEffects (ins: Instruction) insLen bld name =
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect name)
  bld --!> insLen

let lui ins insLen bld =
  let rd, imm = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := imm << numI32 12 bld.RegType)
  bld --!> insLen

let auipc ins insLen bld =
  let rd, imm = getTwoOprs ins |> transTwoOprs ins bld
  let pc = bvOfBaseAddr bld ins.Address
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := pc .+ (imm << numI32 12 bld.RegType))
  bld --!> insLen

let addiw ins insLen bld =
  let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (lowBitsRs1 .+ AST.xtlo 32<rt> imm))
  bld --!> insLen

let slliw ins insLen bld =
  let rd, rs1, shamt = getThreeOprs ins |> transThreeOprs ins bld
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (lowBitsRs1 << AST.xtlo 32<rt> shamt))
  bld --!> insLen

let srliw ins insLen bld =
  let rd, rs1, shamt = getThreeOprs ins |> transThreeOprs ins bld
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (lowBitsRs1 >> AST.xtlo 32<rt> shamt))
  bld --!> insLen

let sraiw ins insLen bld =
  let rd, rs1, shamt = getThreeOprs ins |> transThreeOprs ins bld
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (lowBitsRs1 ?>> AST.xtlo 32<rt> shamt))
  bld --!> insLen

let mul ins insLen bld (isSign, isUnsign) =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  let low = mulWithOverflow rs1 rs2 bld (isSign, isUnsign) true
  bld <+ (rd := low)
  bld --!> insLen

let mulhSignOrUnsign ins insLen bld (isSign, isUnsign) =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  let high = mulWithOverflow rs1 rs2 bld (isSign, isUnsign) false
  bld <+ (rd := high)
  bld --!> insLen

let mulw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let lowBitsRs1 = AST.xtlo 32<rt> rs1
  let lowBitsRs2 = AST.xtlo 32<rt> rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> (lowBitsRs1 .* lowBitsRs2))
  bld --!> insLen

let div ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let condZero = rs2 == AST.num0 64<rt>
  let condOverflow =
    ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rd := rs1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (rd := rs1 ?/ rs2)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let divw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = rs2 == AST.num0 32<rt>
  let condOverflow =
    ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rd := AST.sext 64<rt> rs1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (rd := AST.sext 64<rt> (rs1 ?/ rs2))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let divuw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = rs2 == AST.num0 32<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := AST.sext 64<rt> (rs1 ./ rs2))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let divu ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let condZero = rs2 == AST.num0 64<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := rs1 ./ rs2)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let remu ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let condZero = rs2 == AST.num0 64<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rs1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := rs1 .% rs2)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let rem ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let condZero = rs2 == AST.num0 64<rt>
  let condOverflow =
    ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rs1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rd := AST.num0 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (rd := rs1 ?% rs2)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let remw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = rs2 == AST.num0 32<rt>
  let condOverflow =
    ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := AST.sext 64<rt> rs1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rd := AST.num0 64<rt>)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (rd := AST.sext 64<rt> (rs1 ?% rs2))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let remuw ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rs2 = AST.xtlo 32<rt> rs2
  let condZero = rs2 == AST.num0 32<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := AST.sext 64<rt> rs1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := AST.sext 64<rt> (rs1 .% rs2))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fld ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  let condAlign = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect Lock)
  bld <+ (rd := AST.sext bld.RegType mem)
  bld <+ (AST.sideEffect Unlock)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := AST.sext bld.RegType mem)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fsd ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  let condAlign = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect Lock)
  bld <+ (mem := rd)
  bld <+ (AST.sideEffect Unlock)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (mem := rd)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fltdots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let cond = AST.flt rs1 rs2
  let rtVal =
    AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
  let fflags = regVar bld R.FFLAGS
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rtVal)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := numU64 0uL 64<rt>)
  bld <+ (fflags := fflags .| numU32 16u 32<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fledots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = regVar bld R.FFLAGS
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rtVal)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := numU64 0uL 64<rt>)
  bld <+ (fflags := fflags .| numU32 16u 32<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let feqdots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let isSNan = isSNan 32<rt> rs1 .| isSNan 32<rt> rs2
  let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let cond = rs1 == rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = regVar bld R.FFLAGS
  let flagFscr = AST.ite (isSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rtVal)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := numU64 0uL 64<rt>)
  bld <+ (fflags := fflags .| flagFscr)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fclassdots ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let plusZero = numU32 0u 32<rt>
  let negZero = numU32 0x80000000u 32<rt>
  let sign = AST.extract rs1 1<rt> 31
  let lblPos = label bld "Pos"
  let lblNeg = label bld "Neg"
  let lblEnd = label bld "End"
  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = isInf 32<rt> rs1
  let condSubnormal = isSubnormal 32<rt> rs1
  let condSNan = isSNan 32<rt> rs1
  let condQNan = isQNan 32<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.num0 64<rt>)
  bld <+ (AST.cjmp sign (AST.jmpDest lblNeg) (AST.jmpDest lblPos))
  bld <+ (AST.lmark lblPos)
  bld <+ (rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd)
  bld <+ (rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd)
  bld <+ (rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd)
  bld <+ (rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd)
  bld <+ (rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd)
  bld <+ (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblNeg)
  bld <+ (rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd)
  bld <+ (rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd)
  bld <+ (rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd)
  bld <+ (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fclassdotd ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  let plusZero = numU64 0uL 64<rt>
  let negZero = numU64 0x8000000000000000uL 64<rt>
  let sign = AST.extract rs1 1<rt> 63
  let lblPos = label bld "Pos"
  let lblNeg = label bld "Neg"
  let lblEnd = label bld "End"
  let condZero = (rs1 == plusZero) .| (rs1 == negZero)
  let condInf = isInf 64<rt> rs1
  let condSubnormal = isSubnormal 64<rt> rs1
  let condSNan = isSNan 64<rt> rs1
  let condQNan = isQNan 64<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.num0 64<rt>)
  bld <+ (AST.cjmp sign (AST.jmpDest lblNeg) (AST.jmpDest lblPos))
  bld <+ (AST.lmark lblPos)
  bld <+ (rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd)
  bld <+ (rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd)
  bld <+ (rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd)
  bld <+ (rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd)
  bld <+ (rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd)
  bld <+ (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblNeg)
  bld <+ (rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd)
  bld <+ (rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd)
  bld <+ (rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd)
  bld <+ (rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let flw ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  let tmp = tmpVar bld 32<rt>
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect Lock)
  bld <+ (tmp := mem)
  bld <+ (rd := getNanBoxed tmp)
  bld <+ (AST.sideEffect Unlock)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (tmp := mem)
  bld <+ (rd := getNanBoxed tmp)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fsw ins insLen bld =
  let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
  let condAlign = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect Lock)
  bld <+ (mem := AST.xtlo 32<rt> rd)
  bld <+ (AST.sideEffect Unlock)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (mem := AST.xtlo 32<rt> rd)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fltdotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let cond = AST.flt rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = regVar bld R.FFLAGS
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rtVal)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := numU64 0uL 64<rt>)
  bld <+ (fflags := fflags .| numU32 16u 32<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fledotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let cond = AST.fle rs1 rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = regVar bld R.FFLAGS
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rtVal)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := numU64 0uL 64<rt>)
  bld <+ (fflags := fflags .| numU32 16u 32<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let feqdotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let isSNan = isSNan 64<rt> rs1 .| isSNan 64<rt> rs2
  let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let cond = rs1 == rs2
  let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
  let fflags = regVar bld R.FFLAGS
  let flagFscr = AST.ite isSNan (numU32 16u 32<rt>) (AST.num0 32<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0))
  bld <+ (AST.lmark lblL0)
  bld <+ (rd := rtVal)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (rd := numU64 0uL 64<rt>)
  bld <+ (fflags := fflags .| flagFscr)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fpArithmeticSingle ins insLen bld operator =
  let rd, rs1, rs2, _ = getFourOprs ins
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  bld <!-- (ins.Address, insLen)
  let rtVal =
    let operation = operator rs1 rs2
    AST.ite (isNan 32<rt> operation) (fpDefaultNan 32<rt>) operation
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fpArithmeticDouble ins insLen bld operator =
  let rd, rs1, rs2, _ = getFourOprs ins
  let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rtVal =
    let operation = operator rs1 rs2
    AST.ite (isNan 64<rt> operation) (fpDefaultNan 64<rt>) operation
  bld <+ (rd := rtVal)
  bld --!> insLen

let fsqrtdots ins insLen bld =
  let rd, rs1, _ = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fsqrt rs1
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fsqrtdotd ins insLen bld =
  let rd, rs1, _ = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fsqrt rs1
  bld <+ (rd := rtVal)
  bld --!> insLen

let fmindots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = tmpVar bld 32<rt>
  let cond = AST.flt rs1 rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.ite cond rs1 rs2)
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fmindotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rtVal = tmpVar bld 64<rt>
  let cond = AST.flt rs1 rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.ite cond rs1 rs2)
  bld <+ (rd := rtVal)
  bld --!> insLen

let fmaxdots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = tmpVar bld 32<rt>
  let cond = AST.flt rs1 rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.ite cond rs2 rs1)
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fmaxdotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rtVal = tmpVar bld 64<rt>
  let cond = AST.flt rs1 rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.ite cond rs2 rs1)
  bld <+ (rd := rtVal)
  bld --!> insLen

let fmadddots ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fmadddotd ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
  bld <+ (rd := rtVal)
  bld --!> insLen

let fmsubdots ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fmsubdotd ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
  bld <+ (rd := rtVal)
  bld --!> insLen

let fnmsubdots ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fadd (fpNeg 32<rt> <| AST.fmul rs1 rs2) rs3
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fnmsubdotd ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.fadd (fpNeg 64<rt> <| AST.fmul rs1 rs2) rs3)
  bld --!> insLen

let fnmadddots ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  let lblValid = label bld "Valid"
  let lblInvalid = label bld "Invalid operation"
  let lblEnd = label bld "End"
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rs3 = getFloat32FromReg rs3
  let condOfNV1 = isInf 32<rt> rs1 .| isZero 32<rt> rs2
  let condOfNV2 = isZero 32<rt> rs1 .| isInf 32<rt> rs2
  let setNV = (condOfNV1 .| condOfNV2) .& isQNan 32<rt> rs3
  let fflags = regVar bld R.FFLAGS
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.fsub (fpNeg 32<rt> <| AST.fmul rs1 rs2) rs3
  bld <+ (rd := getNanBoxed rtVal)
  bld <+ (AST.cjmp setNV (AST.jmpDest lblInvalid) (AST.jmpDest lblValid))
  bld <+ (AST.lmark lblValid)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblInvalid)
  bld <+ (fflags := fflags .| numU32 16u 32<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fnmadddotd ins insLen bld =
  let rd, rs1, rs2, rs3, _ = getFiveOprs ins
  let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
  let lblValid = label bld "Valid"
  let lblInvalid = label bld "Invalid operation"
  let lblEnd = label bld "End"
  let condOfNV1 = isInf 64<rt> rs1 .| isZero 64<rt> rs2
  let condOfNV2 = isZero 64<rt> rs1 .| isInf 64<rt> rs2
  let setNV = (condOfNV1 .| condOfNV2) .& isQNan 64<rt> rs3
  let fflags = regVar bld R.FFLAGS
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.fsub (fpNeg 64<rt> <| AST.fmul rs1 rs2) rs3)
  bld <+ (AST.cjmp setNV (AST.jmpDest lblInvalid) (AST.jmpDest lblValid))
  bld <+ (AST.lmark lblValid)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblInvalid)
  bld <+ (fflags := fflags .| numU32 16u 32<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fsgnjdots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = tmpVar bld 32<rt>
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := (rs1 .& mask) .| sign)
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fsgnjdotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rtVal = tmpVar bld 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := (rs1 .& mask) .| sign)
  bld <+ (rd := rtVal)
  bld --!> insLen

let fsgnjndots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = tmpVar bld 32<rt>
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = getSignFloat 32<rt> rs2 <+> numU32 0x80000000u 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := (rs1 .& mask) .| sign)
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fsgnjndotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rtVal = tmpVar bld 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2 <+> numU64 0x8000000000000000uL 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := (rs1 .& mask) .| sign)
  bld <+ (rd := rtVal)
  bld --!> insLen

let fsgnjxdots ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let rs2 = getFloat32FromReg rs2
  let rtVal = tmpVar bld 32<rt>
  let mask = numU32 0x7fffffffu 32<rt>
  let sign = (getSignFloat 32<rt> rs2) <+> (getSignFloat 32<rt> rs1)
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := (rs1 .& mask) .| sign)
  bld <+ (rd := getNanBoxed rtVal)
  bld --!> insLen

let fsgnjxdotd ins insLen bld =
  let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
  let rtVal = tmpVar bld 64<rt>
  let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
  let sign = getSignFloat 64<rt> rs2 <+> getSignFloat 64<rt> rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := (rs1 .& mask) .| sign)
  bld <+ (rd := rtVal)
  bld --!> insLen

(* FIX ME: AQRL *)
let amod ins insLen bld op =
  let rd, rs2, mem, _ = getFourOprs ins |> transFourOprs ins bld
  let cond = isAligned 64<rt> (getAddrFromMem mem)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let tmp = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect Lock)
  bld <+ (tmp := mem)
  bld <+ (mem := op tmp rs2)
  bld <+ (rd := tmp)
  bld <+ (AST.sideEffect Unlock)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.sideEffect (Exception "Address-misaligned exception"))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let amow ins insLen bld op =
  let rd, rs2, mem, _ = getFourOprs ins |> transFourOprs ins bld
  let rs2 = AST.xtlo 32<rt> rs2
  let cond = isAligned 32<rt> (getAddrFromMem mem)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let tmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.sideEffect Lock)
  bld <+ (tmp := mem)
  bld <+ (mem := op tmp rs2)
  bld <+ (rd := AST.sext 64<rt> tmp)
  bld <+ (AST.sideEffect Unlock)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.sideEffect (Exception "Address-misaligned exception"))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fmvdotxdotw ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  let rs1 = getFloat32FromReg rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.sext 64<rt> rs1)
  bld --!> insLen

let fmvdotwdotx ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := getNanBoxed (AST.xtlo 32<rt> rs1))
  bld --!> insLen

let fmvdotxdotd ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1)
  bld --!> insLen

let fmvdotddotx ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := rs1)
  bld --!> insLen

let csrrw ins insLen bld =
  let rd, csr, src = getThreeOprs ins
  let csr, src = transTwoOprs ins bld (csr, src) |> maskForFCSR csr
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect Lock)
  match rd with
  | OpReg Register.X0 -> assignFCSR csr src bld
  | _ ->
    let rd = transOneOpr ins bld rd
    let tmpVar = tmpVar bld 64<rt>
    bld <+ (tmpVar := AST.zext 64<rt> csr)
    assignFCSR csr src bld
    bld <+ (rd := tmpVar)
  bld <+ (AST.sideEffect Unlock)
  bld --!> insLen

let csrrs ins insLen bld =
  let rd, csr, src = getThreeOprs ins
  let rd = transOprToExpr ins bld rd
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect Lock)
  match src with
  | OpReg Register.X0 ->
    let csr = transOprToExpr ins bld csr
    bld <+ (rd := AST.zext 64<rt> csr)
  | _ ->
    let csr, src = transTwoOprs ins bld (csr, src) |> maskForFCSR csr
    let tmpVar = tmpVar bld 64<rt>
    bld <+ (tmpVar := AST.zext 64<rt> csr)
    assignFCSR csr (csr .| src) bld
    bld <+ (rd := tmpVar)
  bld <+ (AST.sideEffect Unlock)
  bld --!> insLen

let csrrc ins insLen bld =
  let rd, csr, src = getThreeOprs ins
  let rd = transOprToExpr ins bld rd
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect Lock)
  match src with
  | OpReg Register.X0 ->
    let csr = transOprToExpr ins bld csr
    bld <+ (rd := AST.zext 64<rt> csr)
  | _ ->
    let csr, src = transTwoOprs ins bld (csr, src) |> maskForFCSR csr
    let tmpVar = tmpVar bld 64<rt>
    bld <+ (tmpVar := AST.zext 64<rt> csr)
    assignFCSR csr (csr .& AST.neg src) bld
    bld <+ (rd := tmpVar)
  bld <+ (AST.sideEffect Unlock)
  bld --!> insLen

let fcvtdotldotd ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let rtVal = tmpVar bld 64<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (rtVal := AST.cast rounding 64<rt> rs1)
    bld <+ (rd := AST.cast roundingInt 64<rt> rtVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) llMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let rtVal = dynamicRoundingFl bld 64<rt> rs1
    let rdVal = dynamicRoundingInt bld 64<rt> rtVal
    bld <+ (rd := rdVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) llMin rd)
    bld --!> insLen

let fcvtdotludotd ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let rtVal = tmpVar bld 64<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (rtVal := AST.cast rounding 64<rt> rs1)
    bld <+ (rd := AST.cast roundingInt 64<rt> rtVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal ullMinInFloat) ullMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal ullMaxInFloat) ullMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN ullMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) ullMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) ullMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let rtVal = dynamicRoundingFl bld 64<rt> rs1
    let rdVal = dynamicRoundingInt bld 64<rt> rtVal
    bld <+ (rd := rdVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal ullMinInFloat) ullMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal ullMaxInFloat) ullMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN ullMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) ullMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) ullMin rd)
    bld --!> insLen

let fcvtdotwdotd ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let rtVal = tmpVar bld 64<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (rtVal := AST.cast rounding 64<rt> rs1)
    bld <+ (rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal))
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) intMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let rtVal = dynamicRoundingFl bld 64<rt> rs1
    let rdVal = dynamicRoundingInt bld 32<rt> rtVal
    bld <+ (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) intMin rd)
    bld --!> insLen

let fcvtdotwudotd ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let rtVal = tmpVar bld 64<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (rtVal := AST.cast rounding 64<rt> rs1)
    bld <+ (rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal))
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) uintMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let rtVal = dynamicRoundingFl bld 64<rt> rs1
    let rdVal = dynamicRoundingInt bld 32<rt> rtVal
    bld <+ (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) uintMin rd)
    bld --!> insLen

let fcvtdotwdots ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let rtVal = tmpVar bld 32<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (rtVal := AST.cast rounding 32<rt> rs1)
    bld <+ (rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal))
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) intMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let rtVal = dynamicRoundingFl bld 32<rt> rs1
    let rdVal = dynamicRoundingInt bld 32<rt> rtVal
    bld <+ (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal intMinInFloat) intMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal intMaxInFloat) intMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN intMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) intMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) intMin rd)
    bld --!> insLen

let fcvtdotwudots ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let rtVal = tmpVar bld 32<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (rtVal := AST.cast rounding 32<rt> rs1)
    bld <+ (rd := AST.cast roundingInt 32<rt> rtVal)
    bld <+ (rd := AST.sext 64<rt> rd)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) uintMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let rtVal = dynamicRoundingFl bld 32<rt> rs1
    let rdVal = dynamicRoundingInt bld 32<rt> rtVal
    bld <+ (rd := AST.sext 64<rt> rdVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal uintMinInFloat) uintMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal uintMaxInFloat) uintMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN uintMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) uintMax rd)
    bld <+ (rd := AST.ite (condInf .& sign) uintMin rd)
    (* -inf *)
    bld --!> insLen

let fcvtdotldots ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = tmpVar bld 32<rt>
    let rtVal = tmpVar bld 64<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (t0 := AST.cast rounding 32<rt> rs1)
    bld <+ (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    (* check for out-of-range *)
    bld <+ (rtVal := AST.ite (AST.fle rtVal llMinInFloat) llMinInFloat rtVal)
    bld <+ (rtVal := AST.ite (AST.fge rtVal llMaxInFloat) llMaxInFloat rtVal)
    (* NaN Check *)
    bld <+ (rtVal := AST.ite condNaN llMaxInFloat rtVal)
    (* +inf *)
    bld <+ (rtVal := AST.ite (condInf .& (AST.not sign)) llMaxInFloat rtVal)
    (* -inf *)
    bld <+ (rtVal := AST.ite (condInf .& sign) llMinInFloat rtVal)
    bld <+ (rd := AST.cast roundingInt 64<rt> rtVal)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let t0 = dynamicRoundingFl bld 32<rt> rs1
    let rtVal = tmpVar bld 64<rt>
    (* check for out-of-range *)
    bld <+ (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    bld <+ (rtVal := AST.ite (AST.fle rtVal llMinInFloat) llMinInFloat rtVal)
    bld <+ (rtVal := AST.ite (AST.fge rtVal llMaxInFloat) llMaxInFloat rtVal)
    (* NaN Check *)
    bld <+ (rtVal := AST.ite condNaN llMaxInFloat rtVal)
    (* +inf *)
    bld <+ (rtVal := AST.ite (condInf .& (AST.not sign)) llMaxInFloat rtVal)
    (* -inf *)
    bld <+ (rtVal := AST.ite (condInf .& sign) llMinInFloat rtVal)
    let rdVal = dynamicRoundingInt bld 64<rt> rtVal
    bld <+ (rd := rdVal)
    bld --!> insLen

let fcvtdotludots ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
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
    let t0 = tmpVar bld 32<rt>
    let rtVal = tmpVar bld 64<rt>
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    bld <+ (t0 := AST.cast rounding 32<rt> rs1)
    bld <+ (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    bld <+ (rd := AST.cast roundingInt 64<rt> rtVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) llMin rd)
    bld --!> insLen
  else
    bld <!-- (ins.Address, insLen)
    (* rounded value *)
    let t0 = dynamicRoundingFl bld 32<rt> rs1
    let rtVal = tmpVar bld 64<rt>
    (* check for out-of-range *)
    bld <+ (rtVal := AST.cast CastKind.FloatCast 64<rt> t0)
    bld <+ (rd := AST.cast CastKind.FloatCast 64<rt> rtVal)
    (* check for out-of-range *)
    bld <+ (rd := AST.ite (AST.fle rtVal llMinInFloat) llMin rd)
    bld <+ (rd := AST.ite (AST.fge rtVal llMaxInFloat) llMax rd)
    (* NaN Check *)
    bld <+ (rd := AST.ite condNaN llMax rd)
    (* +inf *)
    bld <+ (rd := AST.ite (condInf .& (AST.not sign)) llMax rd)
    (* -inf *)
    bld <+ (rd := AST.ite (condInf .& sign) llMin rd)
    bld --!> insLen

let fcvtdotsdotw ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rtVal = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1)
  dstAssignSingleWithRound rd rtVal rm bld
  bld --!> insLen

let fcvtdotsdotwu ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rs1 = AST.xtlo 32<rt> rs1
  let rtVal = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1)
  dstAssignSingleWithRound rd rtVal rm bld
  bld --!> insLen

let fcvtdotsdotl ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rtVal = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1)
  dstAssignSingleWithRound rd rtVal rm bld
  bld --!> insLen

let fcvtdotsdotlu ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rtVal = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1)
  dstAssignSingleWithRound rd rtVal rm bld
  bld --!> insLen

let fcvtdotddotw ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.cast CastKind.SIntToFloat 64<rt> (AST.xtlo 32<rt> rs1))
  bld --!> insLen

let fcvtdotddotwu ins insLen bld =
  let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.cast CastKind.UIntToFloat 64<rt> (AST.xtlo 32<rt> rs1))
  bld --!> insLen

let fcvtdotddotl ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.cast CastKind.SIntToFloat 64<rt> rs1
  dstAssignDoubleWithRound rd rtVal rm bld
  bld --!> insLen

let fcvtdotddotlu ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  let rtVal = AST.cast CastKind.UIntToFloat 64<rt> rs1
  dstAssignDoubleWithRound rd rtVal rm bld
  bld --!> insLen

let fcvtdotsdotd ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rtVal = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  let rs1 =
    AST.cast CastKind.FloatCast 32<rt> rs1
    |> fun single -> AST.ite (isNan 32<rt> single) (fpDefaultNan 32<rt>) single
  bld <+ (rtVal := getNanBoxed rs1)
  if rm <> OpRoundMode (RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    bld <+ (rd := AST.cast rounding 64<rt> rtVal)
  else
    bld <+ (rd := dynamicRoundingFl bld 64<rt> rtVal)
  bld --!> insLen

let fcvtdotddots ins insLen bld =
  let rd, rs1, _ = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rs1 = getFloat32FromReg rs1
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.cast CastKind.FloatCast 64<rt> rs1)
  bld --!> insLen

let lr ins insLen bld =
  let rd, mem, _ = getThreeOprs ins |> transThreeOprs ins bld
  let addr, size = getAddrFromMemAndSize mem
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.extCall <| AST.app "Acquire" [ addr; size ] 64<rt>)
  bld <+ (rd := AST.sext 64<rt> mem)
  bld --!> insLen

let sc ins insLen bld oprSz =
  let rd, rs2, mem, _ = getFourOprs ins |> transFourOprs ins bld
  let addr, size = getAddrFromMemAndSize mem
  let rc = regVar bld R.RC
  let lblRelease = label bld "Release"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (rd := AST.num1 64<rt>)
  bld <+ (AST.extCall <| AST.app "IsAcquired" [ addr; size ] 64<rt>)
  bld <+ (AST.cjmp rc (AST.jmpDest lblRelease) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblRelease)
  bld <+ (AST.extCall <| AST.app "Release" [ addr; size ] 64<rt>)
  bld <+ (mem := AST.xtlo oprSz rs2)
  bld <+ (rd := AST.num0 64<rt>)
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.CdotMV
  | Op.CdotADD
  | Op.ADD -> add ins insLen bld
  | Op.CdotADDW
  | Op.ADDW -> addw ins insLen bld
  | Op.CdotSUBW
  | Op.SUBW -> subw ins insLen bld
  | Op.CdotAND
  | Op.AND -> ``and`` ins insLen bld
  | Op.CdotOR
  | Op.OR -> ``or`` ins insLen bld
  | Op.CdotXOR
  | Op.XOR -> xor ins insLen bld
  | Op.CdotSUB
  | Op.SUB -> sub ins insLen bld
  | Op.SLT -> slt ins insLen bld
  | Op.SLTU -> sltu ins insLen bld
  | Op.SLL -> sll ins insLen bld
  | Op.SLLW -> sllw ins insLen bld
  | Op.SRA -> sra ins insLen bld
  | Op.SRAW -> sraw ins insLen bld
  | Op.SRL -> srl ins insLen bld
  | Op.SRLW -> srlw ins insLen bld
  | Op.CdotANDI
  | Op.ANDI -> andi ins insLen bld
  | Op.CdotADDI16SP
  | Op.CdotLI
  | Op.CdotADDI
  | Op.CdotADDI4SPN
  | Op.ADDI -> addi ins insLen bld
  | Op.ORI -> ori ins insLen bld
  | Op.XORI -> xori ins insLen bld
  | Op.SLTI -> slti ins insLen bld
  | Op.SLTIU -> sltiu ins insLen bld
  | Op.CdotJ
  | Op.JAL -> jal ins insLen bld
  | Op.CdotJR
  | Op.CdotJALR
  | Op.JALR -> jalr ins insLen bld
  | Op.CdotBEQZ
  | Op.BEQ -> beq ins insLen bld
  | Op.CdotBNEZ
  | Op.BNE -> bne ins insLen bld
  | Op.BLT -> blt ins insLen bld
  | Op.BGE -> bge ins insLen bld
  | Op.BLTU -> bltu ins insLen bld
  | Op.BGEU -> bgeu ins insLen bld
  | Op.CdotLW
  | Op.CdotLD
  | Op.CdotLWSP
  | Op.CdotLDSP
  | Op.LB
  | Op.LH
  | Op.LW
  | Op.LD -> load ins insLen bld
  | Op.LBU
  | Op.LHU
  | Op.LWU -> loadu ins insLen bld
  | Op.CdotSW
  | Op.CdotSD
  | Op.CdotSWSP
  | Op.CdotSDSP
  | Op.SB
  | Op.SH
  | Op.SW
  | Op.SD -> store ins insLen bld
  | Op.CdotEBREAK
  | Op.EBREAK -> sideEffects ins insLen bld Breakpoint
  | Op.ECALL -> sideEffects ins insLen bld SysCall
  | Op.CdotSRAI
  | Op.SRAI -> srai ins insLen bld
  | Op.CdotSLLI
  | Op.SLLI -> slli ins insLen bld
  | Op.CdotSRLI
  | Op.SRLI -> srli ins insLen bld
  | Op.CdotLUI
  | Op.LUI -> lui ins insLen bld
  | Op.AUIPC -> auipc ins insLen bld
  | Op.CdotADDIW
  | Op.ADDIW -> addiw ins insLen bld
  | Op.SLLIW -> slliw ins insLen bld
  | Op.SRLIW -> srliw ins insLen bld
  | Op.SRAIW -> sraiw ins insLen bld
  | Op.MUL -> mul ins insLen bld (true, true)
  | Op.MULH -> mulhSignOrUnsign ins insLen bld (true, true)
  | Op.MULHU -> mulhSignOrUnsign ins insLen bld (false, true)
  | Op.MULHSU -> mulhSignOrUnsign ins insLen bld (true, false)
  | Op.MULW -> mulw ins insLen bld
  | Op.CdotNOP -> nop ins insLen bld
  | Op.CdotFLD
  | Op.CdotFLDSP
  | Op.FLD -> fld ins insLen bld
  | Op.CdotFSD
  | Op.CdotFSDSP
  | Op.FSD -> fsd ins insLen bld
  | Op.FLTdotS -> fltdots ins insLen bld
  | Op.FLTdotD -> fltdotd ins insLen bld
  | Op.FLEdotS -> fledots ins insLen bld
  | Op.FLEdotD -> fledotd ins insLen bld
  | Op.FEQdotS -> feqdots ins insLen bld
  | Op.FEQdotD -> feqdotd ins insLen bld
  | Op.FLW -> flw ins insLen bld
  | Op.FSW -> fsw ins insLen bld
  | Op.FADDdotS -> fpArithmeticSingle ins insLen bld AST.fadd
  | Op.FADDdotD -> fpArithmeticDouble ins insLen bld AST.fadd
  | Op.FSUBdotS -> fpArithmeticSingle ins insLen bld AST.fsub
  | Op.FSUBdotD -> fpArithmeticDouble ins insLen bld AST.fsub
  | Op.FDIVdotS -> fpArithmeticSingle ins insLen bld AST.fdiv
  | Op.FDIVdotD -> fpArithmeticDouble ins insLen bld AST.fdiv
  | Op.FMULdotS -> fpArithmeticSingle ins insLen bld AST.fmul
  | Op.FMULdotD -> fpArithmeticDouble ins insLen bld AST.fmul
  | Op.FMINdotS -> fmindots ins insLen bld
  | Op.FMINdotD -> fmindotd ins insLen bld
  | Op.FMAXdotS -> fmaxdots ins insLen bld
  | Op.FMAXdotD -> fmaxdotd ins insLen bld
  | Op.FNMADDdotS -> fnmadddots ins insLen bld
  | Op.FNMADDdotD -> fnmadddotd ins insLen bld
  | Op.FNMSUBdotS -> fnmsubdots ins insLen bld
  | Op.FNMSUBdotD -> fnmsubdotd ins insLen bld
  | Op.FMADDdotS -> fmadddots ins insLen bld
  | Op.FMADDdotD -> fmadddotd ins insLen bld
  | Op.FMSUBdotS -> fmsubdots ins insLen bld
  | Op.FMSUBdotD -> fmsubdotd ins insLen bld
  | Op.FSQRTdotS -> fsqrtdots ins insLen bld
  | Op.FSQRTdotD -> fsqrtdotd ins insLen bld
  | Op.FCLASSdotS -> fclassdots ins insLen bld
  | Op.FCLASSdotD -> fclassdotd ins insLen bld
  | Op.FSGNJdotS -> fsgnjdots ins insLen bld
  | Op.FSGNJdotD -> fsgnjdotd ins insLen bld
  | Op.FSGNJNdotS -> fsgnjndots ins insLen bld
  | Op.FSGNJNdotD -> fsgnjndotd ins insLen bld
  | Op.FSGNJXdotS -> fsgnjxdots ins insLen bld
  | Op.FSGNJXdotD -> fsgnjxdotd ins insLen bld
  | Op.AMOADDdotW -> amow ins insLen bld (.+)
  | Op.AMOADDdotD -> amod ins insLen bld (.+)
  | Op.AMOANDdotW -> amow ins insLen bld (.&)
  | Op.AMOANDdotD -> amod ins insLen bld (.&)
  | Op.AMOXORdotW -> amow ins insLen bld (<+>)
  | Op.AMOXORdotD -> amod ins insLen bld (<+>)
  | Op.AMOORdotW -> amow ins insLen bld (.|)
  | Op.AMOORdotD -> amod ins insLen bld (.|)
  | Op.AMOMINdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINUdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMINUdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMAXdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXUdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOMAXUdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOSWAPdotW -> amow ins insLen bld (fun _ b -> b)
  | Op.AMOSWAPdotD -> amod ins insLen bld (fun _ b -> b)
  | Op.FMVdotXdotW -> fmvdotxdotw ins insLen bld
  | Op.FMVdotXdotD -> fmvdotxdotd ins insLen bld
  | Op.FMVdotWdotX -> fmvdotwdotx ins insLen bld
  | Op.FMVdotDdotX -> fmvdotddotx ins insLen bld
  | Op.DIVW -> divw ins insLen bld
  | Op.DIV -> div ins insLen bld
  | Op.DIVU -> divu ins insLen bld
  | Op.REM -> rem ins insLen bld
  | Op.REMU -> remu ins insLen bld
  | Op.REMW -> remw ins insLen bld
  | Op.DIVUW -> divuw ins insLen bld
  | Op.REMUW -> remuw ins insLen bld
  | Op.FCVTdotWdotD -> fcvtdotwdotd ins insLen bld
  | Op.FCVTdotWUdotD -> fcvtdotwudotd ins insLen bld
  | Op.FCVTdotLdotD -> fcvtdotldotd ins insLen bld
  | Op.FCVTdotLUdotD -> fcvtdotludotd ins insLen bld
  | Op.FCVTdotWdotS -> fcvtdotwdots ins insLen bld
  | Op.FCVTdotWUdotS -> fcvtdotwudots ins insLen bld
  | Op.FCVTdotLdotS -> fcvtdotldots ins insLen bld
  | Op.FCVTdotLUdotS -> fcvtdotludots ins insLen bld
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO -> nop ins insLen bld
  | Op.LRdotW
  | Op.LRdotD -> lr ins insLen bld
  | Op.SCdotW -> sc ins insLen bld 32<rt>
  | Op.SCdotD -> sc ins insLen bld 64<rt>
  | Op.CSRRW
  | Op.CSRRWI -> csrrw ins insLen bld
  | Op.CSRRS
  | Op.CSRRSI -> csrrs ins insLen bld
  | Op.CSRRC
  | Op.CSRRCI -> csrrc ins insLen bld
  | Op.FCVTdotSdotW -> fcvtdotsdotw ins insLen bld
  | Op.FCVTdotSdotL -> fcvtdotsdotl ins insLen bld
  | Op.FCVTdotSdotD -> fcvtdotsdotd ins insLen bld
  | Op.FCVTdotDdotS -> fcvtdotddots ins insLen bld
  | Op.FCVTdotDdotW -> fcvtdotddotw ins insLen bld
  | Op.FCVTdotDdotL -> fcvtdotddotl ins insLen bld
  | Op.FCVTdotDdotWU -> fcvtdotddotwu ins insLen bld
  | Op.FCVTdotDdotLU -> fcvtdotddotlu ins insLen bld
  | Op.FCVTdotSdotWU -> fcvtdotsdotwu ins insLen bld
  | Op.FCVTdotSdotLU -> fcvtdotsdotlu ins insLen bld
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException (Disasm.opCodeToString o)
