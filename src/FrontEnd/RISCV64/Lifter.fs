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
  | Var(_, rid, _, _) when rid = Register.toRegID Register.X0 ->
    dst := dst (* Prevent setting x0. Our optimizer will remove this anyways. *)
  | _ ->
    dst := src

let inline getCSRReg (bld: ILowUIRBuilder) csr =
  let csrReg =
    match csr with
    | 0001us ->
      Register.FFLAGS
    | 0002us ->
      Register.FRM
    | 0003us ->
      Register.FCSR
    | 0768us ->
      Register.CSR0768
    | 0769us ->
      Register.CSR0769
    | 0770us ->
      Register.CSR0770
    | 0771us ->
      Register.CSR0771
    | 0772us ->
      Register.CSR0772
    | 0773us ->
      Register.CSR0773
    | 0784us ->
      Register.CSR0784
    | 0832us ->
      Register.CSR0832
    | 0833us ->
      Register.CSR0833
    | 0834us ->
      Register.CSR0834
    | 0835us ->
      Register.CSR0835
    | 0836us ->
      Register.CSR0836
    | 0842us ->
      Register.CSR0842
    | 0843us ->
      Register.CSR0843
    | 3114us ->
      Register.CSR3114
    | 3787us ->
      Register.CSR3787
    | 3857us ->
      Register.CSR3857
    | 3858us ->
      Register.CSR3858
    | 3859us ->
      Register.CSR3859
    | 3860us ->
      Register.CSR3860
    | 0928us ->
      Register.CSR0928
    | 0930us ->
      Register.CSR0930
    | 0932us ->
      Register.CSR0932
    | 0934us ->
      Register.CSR0934
    | 0936us ->
      Register.CSR0936
    | 0938us ->
      Register.CSR0938
    | 0940us ->
      Register.CSR0940
    | 0942us ->
      Register.CSR0942
    | 0944us ->
      Register.CSR0944
    | 0945us ->
      Register.CSR0945
    | 0946us ->
      Register.CSR0946
    | 0947us ->
      Register.CSR0947
    | 0948us ->
      Register.CSR0948
    | 0949us ->
      Register.CSR0949
    | 0950us ->
      Register.CSR0950
    | 0951us ->
      Register.CSR0951
    | 0952us ->
      Register.CSR0952
    | 0953us ->
      Register.CSR0953
    | 0954us ->
      Register.CSR0954
    | 0955us ->
      Register.CSR0955
    | 0956us ->
      Register.CSR0956
    | 0957us ->
      Register.CSR0957
    | 0958us ->
      Register.CSR0958
    | 0959us ->
      Register.CSR0959
    | 0960us ->
      Register.CSR0960
    | 0961us ->
      Register.CSR0961
    | 0962us ->
      Register.CSR0962
    | 0963us ->
      Register.CSR0963
    | 0964us ->
      Register.CSR0964
    | 0965us ->
      Register.CSR0965
    | 0966us ->
      Register.CSR0966
    | 0967us ->
      Register.CSR0967
    | 0968us ->
      Register.CSR0968
    | 0969us ->
      Register.CSR0969
    | 0970us ->
      Register.CSR0970
    | 0971us ->
      Register.CSR0971
    | 0972us ->
      Register.CSR0972
    | 0973us ->
      Register.CSR0973
    | 0974us ->
      Register.CSR0974
    | 0975us ->
      Register.CSR0975
    | 0976us ->
      Register.CSR0976
    | 0977us ->
      Register.CSR0977
    | 0978us ->
      Register.CSR0978
    | 0979us ->
      Register.CSR0979
    | 0980us ->
      Register.CSR0980
    | 0981us ->
      Register.CSR0981
    | 0982us ->
      Register.CSR0982
    | 0983us ->
      Register.CSR0983
    | 0984us ->
      Register.CSR0984
    | 0985us ->
      Register.CSR0985
    | 0986us ->
      Register.CSR0986
    | 0987us ->
      Register.CSR0987
    | 0988us ->
      Register.CSR0988
    | 0989us ->
      Register.CSR0989
    | 0990us ->
      Register.CSR0990
    | 0991us ->
      Register.CSR0991
    | 0992us ->
      Register.CSR0992
    | 0993us ->
      Register.CSR0993
    | 0994us ->
      Register.CSR0994
    | 0995us ->
      Register.CSR0995
    | 0996us ->
      Register.CSR0996
    | 0997us ->
      Register.CSR0997
    | 0998us ->
      Register.CSR0998
    | 0999us ->
      Register.CSR0999
    | 1000us ->
      Register.CSR1000
    | 1001us ->
      Register.CSR1001
    | 1002us ->
      Register.CSR1002
    | 1003us ->
      Register.CSR1003
    | 1004us ->
      Register.CSR1004
    | 1005us ->
      Register.CSR1005
    | 1006us ->
      Register.CSR1006
    | 1007us ->
      Register.CSR1007
    | 2145us ->
      Register.CSR2145
    | 2617us ->
      Register.CSR2617
    | 2816us ->
      Register.CSR2816
    | 2818us ->
      Register.CSR2818
    | 2819us ->
      Register.CSR2819
    | 2820us ->
      Register.CSR2820
    | 2821us ->
      Register.CSR2821
    | 2822us ->
      Register.CSR2822
    | 2823us ->
      Register.CSR2823
    | 2824us ->
      Register.CSR2824
    | 2825us ->
      Register.CSR2825
    | 2826us ->
      Register.CSR2826
    | 2827us ->
      Register.CSR2827
    | 2828us ->
      Register.CSR2828
    | 2829us ->
      Register.CSR2829
    | 2830us ->
      Register.CSR2830
    | 2831us ->
      Register.CSR2831
    | 2832us ->
      Register.CSR2832
    | 2833us ->
      Register.CSR2833
    | 2834us ->
      Register.CSR2834
    | 2835us ->
      Register.CSR2835
    | 2836us ->
      Register.CSR2836
    | 2837us ->
      Register.CSR2837
    | 2838us ->
      Register.CSR2838
    | 2839us ->
      Register.CSR2839
    | 2840us ->
      Register.CSR2840
    | 2841us ->
      Register.CSR2841
    | 2842us ->
      Register.CSR2842
    | 2843us ->
      Register.CSR2843
    | 2844us ->
      Register.CSR2844
    | 2845us ->
      Register.CSR2845
    | 2846us ->
      Register.CSR2846
    | 2847us ->
      Register.CSR2847
    | 2945us ->
      Register.CSR2945
    | 0800us ->
      Register.CSR0800
    | 0803us ->
      Register.CSR0803
    | 0804us ->
      Register.CSR0804
    | 0805us ->
      Register.CSR0805
    | 0806us ->
      Register.CSR0806
    | 0807us ->
      Register.CSR0807
    | 0808us ->
      Register.CSR0808
    | 0809us ->
      Register.CSR0809
    | 0810us ->
      Register.CSR0810
    | 0811us ->
      Register.CSR0811
    | 0812us ->
      Register.CSR0812
    | 0813us ->
      Register.CSR0813
    | 0814us ->
      Register.CSR0814
    | 0815us ->
      Register.CSR0815
    | 0816us ->
      Register.CSR0816
    | 0817us ->
      Register.CSR0817
    | 0818us ->
      Register.CSR0818
    | 0819us ->
      Register.CSR0819
    | 0820us ->
      Register.CSR0820
    | 0821us ->
      Register.CSR0821
    | 0822us ->
      Register.CSR0822
    | 0823us ->
      Register.CSR0823
    | 0824us ->
      Register.CSR0824
    | 0825us ->
      Register.CSR0825
    | 0826us ->
      Register.CSR0826
    | 0827us ->
      Register.CSR0827
    | 0828us ->
      Register.CSR0828
    | 0829us ->
      Register.CSR0829
    | 0830us ->
      Register.CSR0830
    | 0831us ->
      Register.CSR0831
    | 1952us ->
      Register.CSR1952
    | 1953us ->
      Register.CSR1953
    | 1954us ->
      Register.CSR1954
    | 1955us ->
      Register.CSR1955
    | 1968us ->
      Register.CSR1968
    | 1969us ->
      Register.CSR1969
    | 1970us ->
      Register.CSR1970
    | 1971us ->
      Register.CSR1971
    | _ ->
      eprintfn "%A" csr
      raise InvalidRegisterException
  Register.toRegID csrReg |> bld.GetRegVar

let bvOfBaseAddr (bld: ILowUIRBuilder) addr = numU64 addr bld.RegType

let bvOfInstrLen (bld: ILowUIRBuilder) (ins: Instruction) =
  numU32 ins.Length bld.RegType

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

let getFiveOprs (ins: Instruction) =
  match ins.Operands with
  | FiveOperands(o1, o2, o3, o4, o5) -> o1, o2, o3, o4, o5
  | _ -> raise InvalidOperandException

let transOprToExpr (ins: Instruction) bld = function
  | OpReg reg ->
    regVar bld reg
  | OpImm imm
  | OpShiftAmount imm ->
    numU64 imm bld.RegType
  | OpMem(b, Some(Imm o), sz) ->
    let reg = regVar bld b
    let offset = numI64 o bld.RegType
    AST.loadLE sz (reg .+ offset)
  | OpAddr(Relative o) ->
    numI64 (int64 ins.Address + o) bld.RegType
  | OpAddr(RelativeBase(b, imm)) ->
    if b = Register.X0 then
      AST.num0 bld.RegType
    else
      let target = regVar bld b .+ numI64 (int64 imm) bld.RegType
      let mask = numI64 0xFFFFFFFF_FFFFFFFEL 64<rt>
      target .& mask
  | OpMem(b, None, sz) ->
    AST.loadLE sz (regVar bld b)
  | OpAtomMemOperation(_) ->
    numU32 0u 32<rt> // FIXME:
  | OpCSR(csr) ->
    getCSRReg bld csr
  | _ ->
    raise InvalidOperandException

let private maskForFCSR csr (opr1, opr2) =
  let lowSrc = AST.xtlo 32<rt> opr2
  let mask =
    match csr with
    | OpCSR csr when csr = 0001us -> lowSrc .& numU32 0b11111u 32<rt>
    | OpCSR csr when csr = 0002us -> lowSrc .& numU32 0b111u 32<rt>
    | _ -> opr2
  opr1, mask

let private assignFCSR dst src bld =
  append bld {
    match dst with
    | BinOp _ ->
      let lowSrc = AST.xtlo 32<rt> src
      regVar bld R.FRM :=
        (lowSrc .& numU32 0b11100000u 32<rt>) >> numI32 5 32<rt>
      regVar bld R.FFLAGS := lowSrc .& numU32 0b11111u 32<rt>
    | _ ->
      dst := src
  }

let roundingToCastFloat x =
  match x with
  | OpRoundMode(rm) ->
    match rm with
    | RoundMode.RNE
    | RoundMode.RMM -> CastKind.FtoFRound
    | RoundMode.RTZ -> CastKind.FtoFTrunc
    | RoundMode.RDN -> CastKind.FtoFFloor
    | RoundMode.RUP -> CastKind.FtoFCeil
    | _ -> raise InvalidOperandException
  | _ ->
    raise InvalidOperandException

let roundingToCastInt x =
  match x with
  | OpRoundMode(rm) ->
    match rm with
    | RoundMode.RNE
    | RoundMode.RMM -> CastKind.FtoIRound
    | RoundMode.RTZ -> CastKind.FtoITrunc
    | RoundMode.RDN -> CastKind.FtoIFloor
    | RoundMode.RUP -> CastKind.FtoICeil
    | _ -> raise InvalidOperandException
  | _ ->
    raise InvalidOperandException

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
  append bld {
    AST.cjmp condRNERMM (AST.jmpDest lblD0) (AST.jmpDest lblD1)
    AST.lmark lblD0
    tmpVar := AST.cast CastKind.FtoFRound rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblD1
    AST.cjmp condRTZ (AST.jmpDest lblD2) (AST.jmpDest lblD3)
    AST.lmark lblD2
    tmpVar := AST.cast CastKind.FtoFTrunc rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblD3
    AST.cjmp condRDN (AST.jmpDest lblD4) (AST.jmpDest lblD5)
    AST.lmark lblD4
    tmpVar := AST.cast CastKind.FtoFFloor rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblD5
    AST.cjmp condRUP (AST.jmpDest lblD6) (AST.jmpDest lblDException)
    AST.lmark lblD6
    tmpVar := AST.cast CastKind.FtoFCeil rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblDException
    AST.sideEffect UndefinedInstruction
    AST.lmark lblDEnd
  }
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
  append bld {
    AST.cjmp condRNERMM (AST.jmpDest lblD0) (AST.jmpDest lblD1)
    AST.lmark lblD0
    tmpVar := AST.cast (CastKind.FtoIRound) rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblD1
    AST.cjmp condRTZ (AST.jmpDest lblD2) (AST.jmpDest lblD3)
    AST.lmark lblD2
    tmpVar := AST.cast (CastKind.FtoITrunc) rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblD3
    AST.cjmp condRDN (AST.jmpDest lblD4) (AST.jmpDest lblD5)
    AST.lmark lblD4
    tmpVar := AST.cast (CastKind.FtoIFloor) rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblD5
    AST.cjmp condRUP (AST.jmpDest lblD6) (AST.jmpDest lblDException)
    AST.lmark lblD6
    tmpVar := AST.cast (CastKind.FtoICeil) rt res
    AST.jmp (AST.jmpDest lblDEnd)
    AST.lmark lblDException
    AST.sideEffect UndefinedInstruction
    AST.lmark lblDEnd
  }
  tmpVar

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

let getNanBoxed e = (numU64 0xFFFFFFFF_00000000uL 64<rt>) .| (AST.zext 64<rt> e)

let writeRoundedSingle dst src rm bld =
  append bld {
    let rtVal = getNanBoxed src
    if rm <> OpRoundMode(RoundMode.DYN) then
      let rounding = roundingToCastFloat rm
      dst := AST.cast rounding 64<rt> rtVal
    else
      dst := dynamicRoundingFl bld 64<rt> rtVal
  }

let writeRoundedDouble dst src rm bld =
  append bld {
    if rm <> OpRoundMode(RoundMode.DYN) then
      let rounding = roundingToCastFloat rm
      dst := AST.cast rounding 64<rt> src
    else
      dst := dynamicRoundingFl bld 64<rt> src
  }

let getAddrFromMem x =
  match x with
  | Load(_, _, addr, _) -> addr
  | _ -> raise InvalidExprException

let getAddrFromMemAndSize x =
  match x with
  | Load(_, rt, addr, _) -> addr, numI32 (RegType.toByteWidth rt) 64<rt>
  | _ -> raise InvalidExprException

let isAligned rt expr =
  match rt with
  | 32<rt> -> ((expr .& (numU32 0x3u 64<rt>)) == AST.num0 64<rt>)
  | 64<rt> -> ((expr .& (numU32 0x7u 64<rt>)) == AST.num0 64<rt>)
  | _ -> raise InvalidRegTypeException

let getAccessLength = function
  | OpMem(_, _, sz) -> sz
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
  | _ ->
    raise InvalidRegTypeException

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
  | _ ->
    raise InvalidRegTypeException

let isSNan rt e =
  match rt with
  | 32<rt> ->
    let signalBit = numU32 (1u <<< 22) 32<rt>
    (isNan rt e) .& ((e .& signalBit) == AST.num0 32<rt>)
  | 64<rt> ->
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    (isNan rt e) .& ((e .& signalBit) == AST.num0 64<rt>)
  | _ ->
    raise InvalidRegTypeException

let isQNan rt e =
  match rt with
  | 32<rt> ->
    let signalBit = numU32 (1u <<< 22) 32<rt>
    (isNan rt e) .& ((e .& signalBit) != AST.num0 32<rt>)
  | 64<rt> ->
    let signalBit = numU64 (1uL <<< 51) 64<rt>
    (isNan rt e) .& ((e .& signalBit) != AST.num0 64<rt>)
  | _ ->
    raise InvalidRegTypeException

let isZero rt e =
  match rt with
  | 32<rt> ->
    let mask = numU32 0x7fffffffu 32<rt>
    AST.eq (e .& mask) (AST.num0 32<rt>)
  | 64<rt> ->
    let mask = numU64 0x7fffffff_ffffffffUL 64<rt>
    AST.eq (e .& mask) (AST.num0 64<rt>)
  | _ ->
    Terminator.impossible ()

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
  | _ ->
    raise InvalidRegTypeException

let add ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .+ rs2
  }

let addw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    rd := AST.sext 64<rt> (rs1 .+ rs2)
  }

let subw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    rd := AST.sext 64<rt> (rs1 .- rs2)
  }

let sub ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .- rs2
  }

let ``and`` ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .& rs2
  }

let ``or`` ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .| rs2
  }

let xor ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 <+> rs2
  }

let slt ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 ?< rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let sltu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 .< rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let sll ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
    rd := rs1 << shiftAmm
  }

let sllw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
    rd := AST.sext 64<rt> (rs1 << shiftAmm)
  }

let srl ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
    rd := rs1 >> shiftAmm
  }

let srlw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
    rd := AST.sext 64<rt> (rs1 >> shiftAmm)
  }

let sra ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
    rd := rs1 ?>> shiftAmm
  }

let sraw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
    rd := AST.sext 64<rt> (rs1 ?>> shiftAmm)
  }

let srai ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, shiftAmm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 ?>> shiftAmm
  }

let srli ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, shiftAmm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 >> shiftAmm
  }

let slli ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, shiftAmm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 << shiftAmm
  }

let andi ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .& imm
  }

let addi ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .+ imm
  }

let ori ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 .| imm
  }

let xori ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    rd := rs1 <+> imm
  }

let slti ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 ?< imm
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let sltiu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 .< imm
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let nop (ins: Instruction) insLen bld =
  lift bld ins insLen {
  }

let jal ins insLen bld =
  lift bld ins insLen {
    let rd, jumpTarget = getTwoOprs ins |> transTwoOprs ins bld
    let r = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    rd := r
    AST.interjmp jumpTarget InterJmpKind.IsCall
  }

let jalr ins insLen bld =
  lift bld ins insLen {
    let rd, jumpTarget = getTwoOprs ins |> transTwoOprs ins bld
    let r = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    let target = tmpVar bld 64<rt>
    let actualTarget = if target = AST.num0 bld.RegType then rd else target
    target := jumpTarget
    rd := r
    AST.interjmp actualTarget InterJmpKind.IsRet
  }

let beq ins insLen bld =
  lift bld ins insLen {
    let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 == rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bne ins insLen bld =
  lift bld ins insLen {
    let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 != rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let blt ins insLen bld =
  lift bld ins insLen {
    let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 ?< rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bge ins insLen bld =
  lift bld ins insLen {
    let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 ?>= rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bltu ins insLen bld =
  lift bld ins insLen {
    let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 .< rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bgeu ins insLen bld =
  lift bld ins insLen {
    let rs1, rs2, offset = getThreeOprs ins |> transThreeOprs ins bld
    let cond = rs1 .>= rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let load ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    rd := AST.sext bld.RegType mem
  }

let loadu ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    rd := AST.zext bld.RegType mem
  }

let store ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    let accessLength = getAccessLength (snd (getTwoOprs ins))
    if accessLength = 64<rt> then append bld { mem := rd }
    else append bld { mem := AST.xtlo accessLength rd }
  }

let sideEffects (ins: Instruction) insLen bld name =
  lift bld ins insLen {
    AST.sideEffect name
  }

let lui ins insLen bld =
  lift bld ins insLen {
    let rd, imm = getTwoOprs ins |> transTwoOprs ins bld
    rd := imm << numI32 12 bld.RegType
  }

let auipc ins insLen bld =
  lift bld ins insLen {
    let rd, imm = getTwoOprs ins |> transTwoOprs ins bld
    let pc = bvOfBaseAddr bld ins.Address
    rd := pc .+ (imm << numI32 12 bld.RegType)
  }

let addiw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, imm = getThreeOprs ins |> transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 .+ AST.xtlo 32<rt> imm)
  }

let slliw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, shamt = getThreeOprs ins |> transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 << AST.xtlo 32<rt> shamt)
  }

let srliw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, shamt = getThreeOprs ins |> transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 >> AST.xtlo 32<rt> shamt)
  }

let sraiw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, shamt = getThreeOprs ins |> transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 ?>> AST.xtlo 32<rt> shamt)
  }

let mul ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    (* The low 64 bits of the product are the same for signed and unsigned,
       so a plain 64-bit multiply suffices -- no need to form the full 128-bit
       value. *)
    rd := rs1 .* rs2
  }

let mulhSignOrUnsign ins insLen bld (isSign, isUnsign) =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    (* The high 64 bits of the 64x64->128 product, from the 128-bit intermediate
       the evaluator holds: MULH signs both operands, MULHU neither, MULHSU only
       rs1 -- so the extend picks sext/zext per operand's signedness. *)
    let prod =
      match isSign, isUnsign with
      | true, true -> AST.sext 128<rt> rs1 .* AST.sext 128<rt> rs2
      | true, false -> AST.sext 128<rt> rs1 .* AST.zext 128<rt> rs2
      | _ -> AST.zext 128<rt> rs1 .* AST.zext 128<rt> rs2
    rd := AST.xthi 64<rt> prod
  }

let mulw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    let lowBitsRs2 = AST.xtlo 32<rt> rs2
    rd := AST.sext 64<rt> (lowBitsRs1 .* lowBitsRs2)
  }

let div ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let condZero = rs2 == AST.num0 64<rt>
    let condOverflow =
      ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := rs1 ?/ rs2
    AST.lmark lblEnd
  }

let divw ins insLen bld =
  lift bld ins insLen {
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
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := AST.sext 64<rt> rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := AST.sext 64<rt> (rs1 ?/ rs2)
    AST.lmark lblEnd
  }

let divuw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let condZero = rs2 == AST.num0 32<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := AST.sext 64<rt> (rs1 ./ rs2)
    AST.lmark lblEnd
  }

let divu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let condZero = rs2 == AST.num0 64<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs1 ./ rs2
    AST.lmark lblEnd
  }

let remu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let condZero = rs2 == AST.num0 64<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs1 .% rs2
    AST.lmark lblEnd
  }

let rem ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let condZero = rs2 == AST.num0 64<rt>
    let condOverflow =
      ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := AST.num0 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := rs1 ?% rs2
    AST.lmark lblEnd
  }

let remw ins insLen bld =
  lift bld ins insLen {
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
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := AST.sext 64<rt> rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := AST.num0 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := AST.sext 64<rt> (rs1 ?% rs2)
    AST.lmark lblEnd
  }

let remuw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let condZero = rs2 == AST.num0 32<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := AST.sext 64<rt> rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := AST.sext 64<rt> (rs1 .% rs2)
    AST.lmark lblEnd
  }

let fld ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    let condAlign = isAligned 64<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    rd := AST.sext bld.RegType mem
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := AST.sext bld.RegType mem
    AST.lmark lblEnd
  }

let fsd ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    let condAlign = isAligned 64<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    mem := rd
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    mem := rd
    AST.lmark lblEnd
  }

let fltdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.flt rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fledots ins insLen bld =
  lift bld ins insLen {
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
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let feqdots ins insLen bld =
  lift bld ins insLen {
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
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| flagFscr
    AST.lmark lblEnd
  }

let fclassdots ins insLen bld =
  lift bld ins insLen {
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
    rd := AST.num0 64<rt>
    AST.cjmp sign (AST.jmpDest lblNeg) (AST.jmpDest lblPos)
    AST.lmark lblPos
    rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd
    rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd
    rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeg
    rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd
    AST.lmark lblEnd
  }

let fclassdotd ins insLen bld =
  lift bld ins insLen {
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
    rd := AST.num0 64<rt>
    AST.cjmp sign (AST.jmpDest lblNeg) (AST.jmpDest lblPos)
    AST.lmark lblPos
    rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd
    rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd
    rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeg
    rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd
    AST.lmark lblEnd
  }

let flw ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    let tmp = tmpVar bld 32<rt>
    let condAlign = isAligned 32<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    tmp := mem
    rd := getNanBoxed tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    tmp := mem
    rd := getNanBoxed tmp
    AST.lmark lblEnd
  }

let fsw ins insLen bld =
  lift bld ins insLen {
    let rd, mem = getTwoOprs ins |> transTwoOprs ins bld
    let condAlign = isAligned 32<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    mem := AST.xtlo 32<rt> rd
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    mem := AST.xtlo 32<rt> rd
    AST.lmark lblEnd
  }

let fltdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.flt rs1 rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fledotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.fle rs1 rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let feqdotd ins insLen bld =
  lift bld ins insLen {
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
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| flagFscr
    AST.lmark lblEnd
  }

let fpArithmeticSingle ins insLen bld operator =
  lift bld ins insLen {
    let rd, rs1, rs2, _ = getFourOprs ins
    let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal =
      let operation = operator rs1 rs2
      AST.ite (isNan 32<rt> operation) (fpDefaultNan 32<rt>) operation
    rd := getNanBoxed rtVal
  }

let fpArithmeticDouble ins insLen bld operator =
  lift bld ins insLen {
    let rd, rs1, rs2, _ = getFourOprs ins
    let rd, rs1, rs2 = (rd, rs1, rs2) |> transThreeOprs ins bld
    let rtVal =
      let operation = operator rs1 rs2
      AST.ite (isNan 64<rt> operation) (fpDefaultNan 64<rt>) operation
    rd := rtVal
  }

let fsqrtdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rtVal = AST.fsqrt rs1
    rd := getNanBoxed rtVal
  }

let fsqrtdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rtVal = AST.fsqrt rs1
    rd := rtVal
  }

let fmindots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs1 rs2
    rd := getNanBoxed rtVal
  }

let fmindotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs1 rs2
    rd := rtVal
  }

let fmaxdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs2 rs1
    rd := getNanBoxed rtVal
  }

let fmaxdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs2 rs1
    rd := rtVal
  }

let fmadddots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
  }

let fmadddotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
    rd := rtVal
  }

let fmsubdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
  }

let fmsubdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
    rd := rtVal
  }

let fnmsubdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let rtVal = AST.fadd (fpNeg 32<rt> <| AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
  }

let fnmsubdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    rd := AST.fadd (fpNeg 64<rt> <| AST.fmul rs1 rs2) rs3
  }

let fnmadddots ins insLen bld =
  lift bld ins insLen {
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
    let rtVal = AST.fsub (fpNeg 32<rt> <| AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
    AST.cjmp setNV (AST.jmpDest lblInvalid) (AST.jmpDest lblValid)
    AST.lmark lblValid
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblInvalid
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fnmadddotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd, rs1, rs2, rs3 = (rd, rs1, rs2, rs3) |> transFourOprs ins bld
    let lblValid = label bld "Valid"
    let lblInvalid = label bld "Invalid operation"
    let lblEnd = label bld "End"
    let condOfNV1 = isInf 64<rt> rs1 .| isZero 64<rt> rs2
    let condOfNV2 = isZero 64<rt> rs1 .| isInf 64<rt> rs2
    let setNV = (condOfNV1 .| condOfNV2) .& isQNan 64<rt> rs3
    let fflags = regVar bld R.FFLAGS
    rd := AST.fsub (fpNeg 64<rt> <| AST.fmul rs1 rs2) rs3
    AST.cjmp setNV (AST.jmpDest lblInvalid) (AST.jmpDest lblValid)
    AST.lmark lblValid
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblInvalid
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fsgnjdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let mask = numU32 0x7fffffffu 32<rt>
    let sign = getSignFloat 32<rt> rs2
    rtVal := (rs1 .& mask) .| sign
    rd := getNanBoxed rtVal
  }

let fsgnjdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
    let sign = getSignFloat 64<rt> rs2
    rtVal := (rs1 .& mask) .| sign
    rd := rtVal
  }

let fsgnjndots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let mask = numU32 0x7fffffffu 32<rt>
    let sign = getSignFloat 32<rt> rs2 <+> numU32 0x80000000u 32<rt>
    rtVal := (rs1 .& mask) .| sign
    rd := getNanBoxed rtVal
  }

let fsgnjndotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
    let sign = getSignFloat 64<rt> rs2 <+> numU64 0x8000000000000000uL 64<rt>
    rtVal := (rs1 .& mask) .| sign
    rd := rtVal
  }

let fsgnjxdots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let mask = numU32 0x7fffffffu 32<rt>
    let sign = (getSignFloat 32<rt> rs2) <+> (getSignFloat 32<rt> rs1)
    rtVal := (rs1 .& mask) .| sign
    rd := getNanBoxed rtVal
  }

let fsgnjxdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rs2 = getThreeOprs ins |> transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
    let sign = getSignFloat 64<rt> rs2 <+> getSignFloat 64<rt> rs1
    rtVal := (rs1 .& mask) .| sign
    rd := rtVal
  }

(* FIX ME: AQRL *)
let amod ins insLen bld op =
  lift bld ins insLen {
    let rd, rs2, mem, _ = getFourOprs ins |> transFourOprs ins bld
    let cond = isAligned 64<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let tmp = tmpVar bld 64<rt>
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    tmp := mem
    mem := op tmp rs2
    rd := tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.sideEffect (Exception MisalignedAccess)
    AST.lmark lblEnd
  }

let amow ins insLen bld op =
  lift bld ins insLen {
    let rd, rs2, mem, _ = getFourOprs ins |> transFourOprs ins bld
    let rs2 = AST.xtlo 32<rt> rs2
    let cond = isAligned 32<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let tmp = tmpVar bld 32<rt>
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    tmp := mem
    mem := op tmp rs2
    rd := AST.sext 64<rt> tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.sideEffect (Exception MisalignedAccess)
    AST.lmark lblEnd
  }

let fmvdotxdotw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
    let rs1 = getFloat32FromReg rs1
    rd := AST.sext 64<rt> rs1
  }

let fmvdotwdotx ins insLen bld =
  lift bld ins insLen {
    let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
    rd := getNanBoxed (AST.xtlo 32<rt> rs1)
  }

let fmvdotxdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
    rd := rs1
  }

let fmvdotddotx ins insLen bld =
  lift bld ins insLen {
    let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
    rd := rs1
  }

let csrrw ins insLen bld =
  lift bld ins insLen {
    let rd, csr, src = getThreeOprs ins
    let csr, src = transTwoOprs ins bld (csr, src) |> maskForFCSR csr
    AST.sideEffect AtomicBegin
    match rd with
    | OpReg Register.X0 ->
      assignFCSR csr src bld
    | _ ->
      let rd = transOneOpr ins bld rd
      let tmpVar = tmpVar bld 64<rt>
      tmpVar := AST.zext 64<rt> csr
      assignFCSR csr src bld
      rd := tmpVar
    AST.sideEffect AtomicEnd
  }

let csrrs ins insLen bld =
  lift bld ins insLen {
    let rd, csr, src = getThreeOprs ins
    AST.sideEffect AtomicBegin
    match rd, csr, src with
    | OpReg rdReg, OpCSR(3072us | 3073us | 3074us), OpReg Register.X0 ->
      (* rdcycle/rdtime/rdinstret (csrrs rd, cycle|time|instret, x0): the
         counter has no real CSR to read, so leave the value to the emulator
         through a ClockCounterRead side effect naming rd (a whole 64-bit read
         on RV64). *)
      AST.sideEffect
        (ClockCounterRead(Some(Register.toRegID rdReg, false)))
    | _ ->
      let rd = transOprToExpr ins bld rd
      match src with
      | OpReg Register.X0 ->
        let csr = transOprToExpr ins bld csr
        rd := AST.zext 64<rt> csr
      | _ ->
        let csr, src = transTwoOprs ins bld (csr, src) |> maskForFCSR csr
        let tmpVar = tmpVar bld 64<rt>
        tmpVar := AST.zext 64<rt> csr
        assignFCSR csr (csr .| src) bld
        rd := tmpVar
    AST.sideEffect AtomicEnd
  }

let csrrc ins insLen bld =
  lift bld ins insLen {
    let rd, csr, src = getThreeOprs ins
    let rd = transOprToExpr ins bld rd
    AST.sideEffect AtomicBegin
    match src with
    | OpReg Register.X0 ->
      let csr = transOprToExpr ins bld csr
      rd := AST.zext 64<rt> csr
    | _ ->
      let csr, src = transTwoOprs ins bld (csr, src) |> maskForFCSR csr
      let tmpVar = tmpVar bld 64<rt>
      tmpVar := AST.zext 64<rt> csr
      assignFCSR csr (csr .& AST.neg src) bld
      rd := tmpVar
    AST.sideEffect AtomicEnd
  }

/// Saturates a converted value to the destination's range: past either bound
/// it clamps, a NaN gives the high end, and each infinity goes to its own.
/// Every `fcvt` below closes this way, differing only in where the bounds sit.
let private clampConversion bld rd rtVal conds bounds =
  append bld {
    let condNaN, condInf, sign = conds
    let loFl, hiFl, lo, hi = bounds
    rd := AST.ite (AST.fle rtVal loFl) lo rd
    rd := AST.ite (AST.fge rtVal hiFl) hi rd
    rd := AST.ite condNaN hi rd
    rd := AST.ite (condInf .& AST.not sign) hi rd
    rd := AST.ite (condInf .& sign) lo rd
  }

/// The same, pinning the rounded float itself instead of the register it is
/// about to be converted into. The bounds are then the float bounds, and
/// there is no separate value to clamp to.
let private clampRounded bld rtVal conds bounds =
  append bld {
    let condNaN, condInf, sign = conds
    let loFl, hiFl = bounds
    rtVal := AST.ite (AST.fle rtVal loFl) loFl rtVal
    rtVal := AST.ite (AST.fge rtVal hiFl) hiFl rtVal
    rtVal := AST.ite condNaN hiFl rtVal
    rtVal := AST.ite (condInf .& AST.not sign) hiFl rtVal
    rtVal := AST.ite (condInf .& sign) loFl rtVal
  }

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
  let conds = condNaN, condInf, sign
  let bounds = llMinInFloat, llMaxInFloat, llMin, llMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins insLen {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.cast roundingInt 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 64<rt> rtVal
      rd := rdVal
      clampConversion bld rd rtVal conds bounds
    }

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
  let conds = condNaN, condInf, sign
  let bounds = ullMinInFloat, ullMaxInFloat, ullMin, ullMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins insLen {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.cast roundingInt 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 64<rt> rtVal
      rd := rdVal
      clampConversion bld rd rtVal conds bounds
    }

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
  let conds = condNaN, condInf, sign
  let bounds = intMinInFloat, intMaxInFloat, intMin, intMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins insLen {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

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
  let conds = condNaN, condInf, sign
  let bounds = uintMinInFloat, uintMaxInFloat, uintMin, uintMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins insLen {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

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
  let conds = condNaN, condInf, sign
  let bounds = intMinInFloat, intMaxInFloat, intMin, intMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 32<rt>
    lift bld ins insLen {
      (* rounded value *)
      rtVal := AST.cast rounding 32<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 32<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

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
  let conds = condNaN, condInf, sign
  let bounds = uintMinInFloat, uintMaxInFloat, uintMin, uintMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 32<rt>
    lift bld ins insLen {
      (* rounded value *)
      rtVal := AST.cast rounding 32<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 32<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotldots ins insLen bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
  let rs1 = getFloat32FromReg rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = llMinInFloat, llMaxInFloat
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = tmpVar bld 32<rt>
    let rtVal = tmpVar bld 64<rt>
    lift bld ins insLen {
      (* rounded value *)
      t0 := AST.cast rounding 32<rt> rs1
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      clampRounded bld rtVal conds bounds
      rd := AST.cast roundingInt 64<rt> rtVal
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let t0 = dynamicRoundingFl bld 32<rt> rs1
      let rtVal = tmpVar bld 64<rt>
      (* check for out-of-range *)
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      clampRounded bld rtVal conds bounds
      let rdVal = dynamicRoundingInt bld 64<rt> rtVal
      rd := rdVal
    }

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
  let conds = condNaN, condInf, sign
  let bounds = llMinInFloat, llMaxInFloat, llMin, llMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = tmpVar bld 32<rt>
    let rtVal = tmpVar bld 64<rt>
    lift bld ins insLen {
      (* rounded value *)
      t0 := AST.cast rounding 32<rt> rs1
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      rd := AST.cast roundingInt 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins insLen {
      (* rounded value *)
      let t0 = dynamicRoundingFl bld 32<rt> rs1
      let rtVal = tmpVar bld 64<rt>
      (* check for out-of-range *)
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      rd := AST.cast CastKind.FloatCast 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotsdotw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotsdotwu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotsdotl ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotsdotlu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotddotw ins insLen bld =
  lift bld ins insLen {
    let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
    rd := AST.cast CastKind.SIntToFloat 64<rt> (AST.xtlo 32<rt> rs1)
  }

let fcvtdotddotwu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1 = getTwoOprs ins |> transTwoOprs ins bld
    rd := AST.cast CastKind.UIntToFloat 64<rt> (AST.xtlo 32<rt> rs1)
  }

let fcvtdotddotl ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rtVal = AST.cast CastKind.SIntToFloat 64<rt> rs1
    writeRoundedDouble rd rtVal rm bld
  }

let fcvtdotddotlu ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rtVal = AST.cast CastKind.UIntToFloat 64<rt> rs1
    writeRoundedDouble rd rtVal rm bld
  }

let fcvtdotsdotd ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let rs1 =
      AST.cast CastKind.FloatCast 32<rt> rs1
      |> fun single ->
           AST.ite (isNan 32<rt> single) (fpDefaultNan 32<rt>) single
    rtVal := getNanBoxed rs1
    if rm <> OpRoundMode(RoundMode.DYN) then
      let rounding = roundingToCastFloat rm
      rd := AST.cast rounding 64<rt> rtVal
    else
      rd := dynamicRoundingFl bld 64<rt> rtVal
  }

let fcvtdotddots ins insLen bld =
  lift bld ins insLen {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = (rd, rs1) |> transTwoOprs ins bld
    let rs1 = getFloat32FromReg rs1
    rd := AST.cast CastKind.FloatCast 64<rt> rs1
  }

/// Load-reserved (LR.W/LR.D): records an exclusive reservation -- the reserved
/// address and the value read there -- so a later store-conditional can tell,
/// by value comparison, whether the location was written in between.
let lr ins insLen bld =
  lift bld ins insLen {
    let rd, mem, _ = getThreeOprs ins |> transThreeOprs ins bld
    let addr = getAddrFromMem mem
    let sz =
      match mem with
      | Load(_, sz, _, _) -> sz
      | _ -> raise InvalidExprException
    let v = tmpVar bld sz
    AST.sideEffect AtomicBegin
    v := mem
    regVar bld R.ExMonAddr := addr
    regVar bld R.ExMonVal := AST.zext 64<rt> v
    rd := AST.sext 64<rt> v
    AST.sideEffect AtomicEnd
  }

/// Store-conditional (SC.W/SC.D): stores and reports success (rd = 0) only if
/// the reservation still holds -- the address matches and memory still holds
/// the reserved value; otherwise memory is left unchanged and it reports
/// failure (rd = 1). The conditional store is a store of ite(matched, data,
/// old), so no branch is emitted.
let sc ins insLen bld oprSz =
  lift bld ins insLen {
    let rd, rs2, mem, _ = getFourOprs ins |> transFourOprs ins bld
    let addr = getAddrFromMem mem
    let cur = tmpVar bld oprSz
    let matched = tmpVar bld 1<rt>
    AST.sideEffect AtomicBegin
    cur := mem
    matched := (addr == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo oprSz (regVar bld R.ExMonVal))
    mem := AST.ite matched (AST.xtlo oprSz rs2) cur
    rd := AST.ite matched (AST.num0 64<rt>) (AST.num1 64<rt>)
    AST.sideEffect AtomicEnd
  }

let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.CdotMV
  | Op.CdotADD
  | Op.ADD ->
    add ins insLen bld
  | Op.CdotADDW
  | Op.ADDW ->
    addw ins insLen bld
  | Op.CdotSUBW
  | Op.SUBW ->
    subw ins insLen bld
  | Op.CdotAND
  | Op.AND ->
    ``and`` ins insLen bld
  | Op.CdotOR
  | Op.OR ->
    ``or`` ins insLen bld
  | Op.CdotXOR
  | Op.XOR ->
    xor ins insLen bld
  | Op.CdotSUB
  | Op.SUB ->
    sub ins insLen bld
  | Op.SLT ->
    slt ins insLen bld
  | Op.SLTU ->
    sltu ins insLen bld
  | Op.SLL ->
    sll ins insLen bld
  | Op.SLLW ->
    sllw ins insLen bld
  | Op.SRA ->
    sra ins insLen bld
  | Op.SRAW ->
    sraw ins insLen bld
  | Op.SRL ->
    srl ins insLen bld
  | Op.SRLW ->
    srlw ins insLen bld
  | Op.CdotANDI
  | Op.ANDI ->
    andi ins insLen bld
  | Op.CdotADDI16SP
  | Op.CdotLI
  | Op.CdotADDI
  | Op.CdotADDI4SPN
  | Op.ADDI ->
    addi ins insLen bld
  | Op.ORI ->
    ori ins insLen bld
  | Op.XORI ->
    xori ins insLen bld
  | Op.SLTI ->
    slti ins insLen bld
  | Op.SLTIU ->
    sltiu ins insLen bld
  | Op.CdotJ
  | Op.JAL ->
    jal ins insLen bld
  | Op.CdotJR
  | Op.CdotJALR
  | Op.JALR ->
    jalr ins insLen bld
  | Op.CdotBEQZ
  | Op.BEQ ->
    beq ins insLen bld
  | Op.CdotBNEZ
  | Op.BNE ->
    bne ins insLen bld
  | Op.BLT ->
    blt ins insLen bld
  | Op.BGE ->
    bge ins insLen bld
  | Op.BLTU ->
    bltu ins insLen bld
  | Op.BGEU ->
    bgeu ins insLen bld
  | Op.CdotLW
  | Op.CdotLD
  | Op.CdotLWSP
  | Op.CdotLDSP
  | Op.LB
  | Op.LH
  | Op.LW
  | Op.LD ->
    load ins insLen bld
  | Op.LBU
  | Op.LHU
  | Op.LWU ->
    loadu ins insLen bld
  | Op.CdotSW
  | Op.CdotSD
  | Op.CdotSWSP
  | Op.CdotSDSP
  | Op.SB
  | Op.SH
  | Op.SW
  | Op.SD ->
    store ins insLen bld
  | Op.CdotEBREAK
  | Op.EBREAK ->
    sideEffects ins insLen bld Breakpoint
  | Op.ECALL ->
    sideEffects ins insLen bld SysCall
  | Op.CdotSRAI
  | Op.SRAI ->
    srai ins insLen bld
  | Op.CdotSLLI
  | Op.SLLI ->
    slli ins insLen bld
  | Op.CdotSRLI
  | Op.SRLI ->
    srli ins insLen bld
  | Op.CdotLUI
  | Op.LUI ->
    lui ins insLen bld
  | Op.AUIPC ->
    auipc ins insLen bld
  | Op.CdotADDIW
  | Op.ADDIW ->
    addiw ins insLen bld
  | Op.SLLIW ->
    slliw ins insLen bld
  | Op.SRLIW ->
    srliw ins insLen bld
  | Op.SRAIW ->
    sraiw ins insLen bld
  | Op.MUL ->
    mul ins insLen bld
  | Op.MULH ->
    mulhSignOrUnsign ins insLen bld (true, true)
  | Op.MULHU ->
    mulhSignOrUnsign ins insLen bld (false, true)
  | Op.MULHSU ->
    mulhSignOrUnsign ins insLen bld (true, false)
  | Op.MULW ->
    mulw ins insLen bld
  | Op.CdotNOP ->
    nop ins insLen bld
  | Op.CdotFLD
  | Op.CdotFLDSP
  | Op.FLD ->
    fld ins insLen bld
  | Op.CdotFSD
  | Op.CdotFSDSP
  | Op.FSD ->
    fsd ins insLen bld
  | Op.FLTdotS ->
    fltdots ins insLen bld
  | Op.FLTdotD ->
    fltdotd ins insLen bld
  | Op.FLEdotS ->
    fledots ins insLen bld
  | Op.FLEdotD ->
    fledotd ins insLen bld
  | Op.FEQdotS ->
    feqdots ins insLen bld
  | Op.FEQdotD ->
    feqdotd ins insLen bld
  | Op.FLW ->
    flw ins insLen bld
  | Op.FSW ->
    fsw ins insLen bld
  | Op.FADDdotS ->
    fpArithmeticSingle ins insLen bld AST.fadd
  | Op.FADDdotD ->
    fpArithmeticDouble ins insLen bld AST.fadd
  | Op.FSUBdotS ->
    fpArithmeticSingle ins insLen bld AST.fsub
  | Op.FSUBdotD ->
    fpArithmeticDouble ins insLen bld AST.fsub
  | Op.FDIVdotS ->
    fpArithmeticSingle ins insLen bld AST.fdiv
  | Op.FDIVdotD ->
    fpArithmeticDouble ins insLen bld AST.fdiv
  | Op.FMULdotS ->
    fpArithmeticSingle ins insLen bld AST.fmul
  | Op.FMULdotD ->
    fpArithmeticDouble ins insLen bld AST.fmul
  | Op.FMINdotS ->
    fmindots ins insLen bld
  | Op.FMINdotD ->
    fmindotd ins insLen bld
  | Op.FMAXdotS ->
    fmaxdots ins insLen bld
  | Op.FMAXdotD ->
    fmaxdotd ins insLen bld
  | Op.FNMADDdotS ->
    fnmadddots ins insLen bld
  | Op.FNMADDdotD ->
    fnmadddotd ins insLen bld
  | Op.FNMSUBdotS ->
    fnmsubdots ins insLen bld
  | Op.FNMSUBdotD ->
    fnmsubdotd ins insLen bld
  | Op.FMADDdotS ->
    fmadddots ins insLen bld
  | Op.FMADDdotD ->
    fmadddotd ins insLen bld
  | Op.FMSUBdotS ->
    fmsubdots ins insLen bld
  | Op.FMSUBdotD ->
    fmsubdotd ins insLen bld
  | Op.FSQRTdotS ->
    fsqrtdots ins insLen bld
  | Op.FSQRTdotD ->
    fsqrtdotd ins insLen bld
  | Op.FCLASSdotS ->
    fclassdots ins insLen bld
  | Op.FCLASSdotD ->
    fclassdotd ins insLen bld
  | Op.FSGNJdotS ->
    fsgnjdots ins insLen bld
  | Op.FSGNJdotD ->
    fsgnjdotd ins insLen bld
  | Op.FSGNJNdotS ->
    fsgnjndots ins insLen bld
  | Op.FSGNJNdotD ->
    fsgnjndotd ins insLen bld
  | Op.FSGNJXdotS ->
    fsgnjxdots ins insLen bld
  | Op.FSGNJXdotD ->
    fsgnjxdotd ins insLen bld
  | Op.AMOADDdotW ->
    amow ins insLen bld (.+)
  | Op.AMOADDdotD ->
    amod ins insLen bld (.+)
  | Op.AMOANDdotW ->
    amow ins insLen bld (.&)
  | Op.AMOANDdotD ->
    amod ins insLen bld (.&)
  | Op.AMOXORdotW ->
    amow ins insLen bld (<+>)
  | Op.AMOXORdotD ->
    amod ins insLen bld (<+>)
  | Op.AMOORdotW ->
    amow ins insLen bld (.|)
  | Op.AMOORdotD ->
    amod ins insLen bld (.|)
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
  | Op.AMOSWAPdotW ->
    amow ins insLen bld (fun _ b -> b)
  | Op.AMOSWAPdotD ->
    amod ins insLen bld (fun _ b -> b)
  | Op.FMVdotXdotW ->
    fmvdotxdotw ins insLen bld
  | Op.FMVdotXdotD ->
    fmvdotxdotd ins insLen bld
  | Op.FMVdotWdotX ->
    fmvdotwdotx ins insLen bld
  | Op.FMVdotDdotX ->
    fmvdotddotx ins insLen bld
  | Op.DIVW ->
    divw ins insLen bld
  | Op.DIV ->
    div ins insLen bld
  | Op.DIVU ->
    divu ins insLen bld
  | Op.REM ->
    rem ins insLen bld
  | Op.REMU ->
    remu ins insLen bld
  | Op.REMW ->
    remw ins insLen bld
  | Op.DIVUW ->
    divuw ins insLen bld
  | Op.REMUW ->
    remuw ins insLen bld
  | Op.FCVTdotWdotD ->
    fcvtdotwdotd ins insLen bld
  | Op.FCVTdotWUdotD ->
    fcvtdotwudotd ins insLen bld
  | Op.FCVTdotLdotD ->
    fcvtdotldotd ins insLen bld
  | Op.FCVTdotLUdotD ->
    fcvtdotludotd ins insLen bld
  | Op.FCVTdotWdotS ->
    fcvtdotwdots ins insLen bld
  | Op.FCVTdotWUdotS ->
    fcvtdotwudots ins insLen bld
  | Op.FCVTdotLdotS ->
    fcvtdotldots ins insLen bld
  | Op.FCVTdotLUdotS ->
    fcvtdotludots ins insLen bld
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO ->
    nop ins insLen bld
  | Op.LRdotW
  | Op.LRdotD ->
    lr ins insLen bld
  | Op.SCdotW ->
    sc ins insLen bld 32<rt>
  | Op.SCdotD ->
    sc ins insLen bld 64<rt>
  | Op.CSRRW
  | Op.CSRRWI ->
    csrrw ins insLen bld
  | Op.CSRRS
  | Op.CSRRSI ->
    csrrs ins insLen bld
  | Op.CSRRC
  | Op.CSRRCI ->
    csrrc ins insLen bld
  | Op.FCVTdotSdotW ->
    fcvtdotsdotw ins insLen bld
  | Op.FCVTdotSdotL ->
    fcvtdotsdotl ins insLen bld
  | Op.FCVTdotSdotD ->
    fcvtdotsdotd ins insLen bld
  | Op.FCVTdotDdotS ->
    fcvtdotddots ins insLen bld
  | Op.FCVTdotDdotW ->
    fcvtdotddotw ins insLen bld
  | Op.FCVTdotDdotL ->
    fcvtdotddotl ins insLen bld
  | Op.FCVTdotDdotWU ->
    fcvtdotddotwu ins insLen bld
  | Op.FCVTdotDdotLU ->
    fcvtdotddotlu ins insLen bld
  | Op.FCVTdotSdotWU ->
    fcvtdotsdotwu ins insLen bld
  | Op.FCVTdotSdotLU ->
    fcvtdotsdotlu ins insLen bld
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException(Disasm.opCodeToString o)
