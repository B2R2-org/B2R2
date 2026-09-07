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

module internal B2R2.FrontEnd.RISCV64.LiftingUtils

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

let transOpr (ins: Instruction) bld = function
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

let maskForFCSR csr (opr1, opr2) =
  let lowSrc = AST.xtlo 32<rt> opr2
  let mask =
    match csr with
    | OpCSR csr when csr = 0001us -> lowSrc .& numU32 0b11111u 32<rt>
    | OpCSR csr when csr = 0002us -> lowSrc .& numU32 0b111u 32<rt>
    | _ -> opr2
  opr1, mask

let assignFCSR dst src bld =
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
