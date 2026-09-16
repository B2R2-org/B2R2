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

module internal B2R2.FrontEnd.RISCV.LiftingUtils

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
      let mask = numI64 0xFFFFFFFF_FFFFFFFEL bld.RegType
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

let getAddrFromMem x =
  match x with
  | Load(_, _, addr, _) -> addr
  | _ -> raise InvalidExprException

let getAddrFromMemAndSize x =
  match x with
  | Load(_, rt, addr, _) ->
    addr, numI32 (RegType.toByteWidth rt) (Expr.typeOf addr)
  | _ ->
    raise InvalidExprException

/// Whether an address is one the given access may be made at. The address is
/// as wide as the XLEN, so what it is compared against is taken from it rather
/// than written out.
let isAligned rt expr =
  let addrSize = Expr.typeOf expr
  match rt with
  | 32<rt> -> ((expr .& (numU32 0x3u addrSize)) == AST.num0 addrSize)
  | 64<rt> -> ((expr .& (numU32 0x7u addrSize)) == AST.num0 addrSize)
  | _ -> raise InvalidRegTypeException

/// How far a shift by a register shifts by, which is what the register holds
/// in as many of its lowest bits as it takes to name a place within one.
let shiftMask (bld: ILowUIRBuilder) =
  numU64 (uint64 (RegType.toBitWidth bld.RegType) - 1UL) bld.RegType

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

/// <summary>
/// The direction the instruction's own rm field names, as the mode expression
/// a <c>RoundCtrl</c> takes, or None where the field says dynamic.
///
/// Dynamic -- the encoding 111, which is what a compiler emits for very nearly
/// every floating-point instruction in a real program -- names no direction of
/// its own: what is in force outside every RoundCtrl is frm, which is exactly
/// what dynamic asks for, so there is nothing to wrap.
/// </summary>
let staticRounding rm =
  match rm with
  | OpRoundMode RoundMode.DYN ->
    None
  | OpRoundMode RoundMode.RNE ->
    Some(AST.roundingMode RoundingMode.ToNearestEven)
  | OpRoundMode RoundMode.RTZ ->
    Some(AST.roundingMode RoundingMode.TowardZero)
  | OpRoundMode RoundMode.RDN ->
    Some(AST.roundingMode RoundingMode.TowardNegative)
  | OpRoundMode RoundMode.RUP ->
    Some(AST.roundingMode RoundingMode.TowardPositive)
  | OpRoundMode RoundMode.RMM ->
    Some(AST.roundingMode RoundingMode.ToNearestAway)
  | _ ->
    raise InvalidOperandException

/// One expression evaluated in the direction the instruction named, where it
/// named one. An operation with no direction of its own is left alone.
let underRounding mode value =
  match mode with
  | Some m -> AST.roundCtrl m value
  | None -> value

/// <summary>
/// The value a floating-point operation delivers, with any NaN it produced
/// replaced by the canonical quiet one.
///
/// RISC-V does not propagate payloads out of an arithmetic operation: "if the
/// result is NaN, it is the canonical NaN" (unprivileged ISA, "NaN
/// Generation and Propagation"), whatever the payloads of the operands were.
/// So an implementation built on a host's own arithmetic, which propagates,
/// has to canonicalise on the way out.
/// </summary>
let fpCanonical oprSz e = AST.ite (isNan oprSz e) (fpDefaultNan oprSz) e

/// <summary>
/// IEEE equality, which is not equality of bit patterns.
///
/// The two zeros have different patterns and compare equal, so a comparison
/// written as an integer one is wrong for exactly that pair -- and for nothing
/// else, every other value having a single encoding. The NaN cases are the
/// caller's, this being the ordering rather than the signalling half of a
/// comparison.
/// </summary>
let fpEqual oprSz a b = (a == b) .| (isZero oprSz a .& isZero oprSz b)

/// <summary>
/// FMIN or FMAX, which are not <c>a &lt; b ? a : b</c> in three separate ways.
///
/// The manual gives all three (unprivileged ISA, the single-precision
/// computational instructions): "for the purposes of these instructions only,
/// the value -0.0 is considered to be less than the value +0.0. If both inputs
/// are NaNs, the result is the canonical NaN. If only one operand is a NaN,
/// the result is the non-NaN operand."
///
/// A plain comparison gets each of those wrong. It calls the two zeros equal,
/// so FMIN(-0, +0) comes back +0; it is false when either operand is a NaN, so
/// FMIN(NaN, x) comes back x -- right by accident -- while FMIN(x, NaN) comes
/// back NaN, which is not; and with two NaNs it returns one of them rather
/// than the canonical one.
/// </summary>
let fpMinMax oprSz isMin a b =
  let signOf x = AST.extract x 1<rt> (RegType.toBitWidth oprSz - 1)
  (* Where both are zero the sign decides, and taking it from the first operand
     answers every combination: two of a kind pick either, and a mixed pair
     picks the negative one for a minimum. *)
  let aIsLess = AST.ite (isZero oprSz a .& isZero oprSz b)
                        (signOf a)
                        (AST.flt a b)
  let picked = if isMin then AST.ite aIsLess a b else AST.ite aIsLess b a
  AST.ite (isNan oprSz a .& isNan oprSz b)
          (fpDefaultNan oprSz)
          (AST.ite (isNan oprSz a) b (AST.ite (isNan oprSz b) a picked))

/// The operation a floating-point exception query names. These numbers are the
/// contract with the evaluator's FloatBits, which answers the call.
module FpExc =
  let [<Literal>] Add = 0UL
  let [<Literal>] Sub = 1UL
  let [<Literal>] Mul = 2UL
  let [<Literal>] Div = 3UL
  let [<Literal>] Sqrt = 4UL
  let [<Literal>] MinMax = 5UL
  let [<Literal>] ToSInt = 6UL
  let [<Literal>] ToUInt = 7UL
  let [<Literal>] Fma = 8UL

/// <summary>
/// The accrued exception bits an operation raises, as a named call.
///
/// fcsr's five flags -- inexact, underflow, overflow, divide-by-zero,
/// invalid -- are half of what a floating-point instruction defines, and four
/// of the five cannot be seen from the IR at all: whether a result was inexact
/// is whether anything was lost in rounding it, which only the thing that did
/// the rounding knows. So the question goes to the evaluator, which has the
/// exact residual of every operation it performs and can answer from it.
///
/// The operation is worked out a second time on the other side rather than
/// reported by the one that produced the value. That costs a multiply or a
/// divide and buys a plain contract: the flags are a function of the operands,
/// the operation and the direction in force, with no state threaded between
/// two places.
///
/// For a conversion the second operand is the destination's width in bits.
/// </summary>
let fpExceptions sz op a b =
  let args = [ numU64 op 8<rt>; a; b ]
  AST.app (if sz = 32<rt> then "FEXC32" else "FEXC64") args 32<rt>

/// The same for a fused multiply-add, which has a third operand and a pair of
/// sign flags rather than two plain ones. The negations ride along as flags
/// for the same reason they do in <c>fpFused</c>: flipping a NaN operand's
/// sign first would change what the operation is asked about.
let fpFmaExceptions sz negProduct negAddend x y z =
  let prodBit = if negProduct then 1UL else 0UL
  let addBit = if negAddend then 2UL else 0UL
  let args =
    [ numU64 FpExc.Fma 8<rt>
      x
      y
      z
      numU64 (prodBit ||| addBit) 8<rt> ]
  AST.app (if sz = 32<rt> then "FEXC32" else "FEXC64") args 32<rt>

let accrueFmaFlags bld mode sz negProduct negAddend x y z =
  let fflags = regVar bld Register.FFLAGS
  let exc = fpFmaExceptions sz negProduct negAddend x y z
  append bld { fflags := fflags .| underRounding mode exc }

/// Records what an operation raised, the way fcsr accrues it: the flags only
/// ever go on, and nothing but an explicit write to the register takes them
/// off again.
let accrueFlags bld mode sz op a b =
  let fflags = regVar bld Register.FFLAGS
  append bld { fflags := fflags .| underRounding mode (fpExceptions sz op a b) }

/// <summary>
/// The fused multiply-add, as the one operation it is.
///
/// The rounding is the instruction. Spelling FMADD out as a multiply and an
/// add rounds twice, and the two answers part company for a few per cent of
/// operands -- so this goes out as a named call the evaluator answers with its
/// host's own fused multiply-add, the same one the x86 front end reaches for.
/// Flag bit 0 negates the product and bit 1 the addend, which is how the
/// family's four members differ; the negations ride along as flags rather than
/// being applied to the operands here, a sign flip on a NaN operand changing
/// which NaN comes back out.
///
/// The result still has to go through fpCanonical: the named call propagates
/// payloads the way x86 does, where RISC-V answers every invalid operation
/// with its one canonical NaN.
///
/// The direction is the caller's to put on, with underRounding: the call has
/// no operand for one, and takes what is in force where it is evaluated.
/// </summary>
let fpFused sz negProduct negAddend x y z =
  let prodBit = if negProduct then 1UL else 0UL
  let addBit = if negAddend then 2UL else 0UL
  let args = [ x; y; z; numU64 (prodBit ||| addBit) 8<rt> ]
  AST.app (if sz = 32<rt> then "FMA32" else "FMA64") args sz

/// The ten-bit mask FCLASS writes, for a value of <c>oprSz</c> bits placed in
/// a destination of <c>rt</c> bits.
///
/// The ten kinds are mutually exclusive and exactly one bit is ever set, so
/// this is one chain of choices rather than a series of assignments into the
/// destination.
///
/// The order matters in one place. The NaN tests come first and OUTSIDE the
/// split on the sign, because a NaN's sign bit is not part of what FCLASS
/// reports: bits 8 and 9 name a signalling and a quiet NaN and neither has a
/// negative twin. A classifier that splits on the sign first and then looks
/// for a NaN only on the positive side calls every negative NaN a negative
/// normal number, which is a bug no ordinary operand reveals -- half of the
/// NaNs a generator draws are positive and classify correctly.
/// </summary>
let fclassValue oprSz rt e =
  let bit n = numU32 (1u <<< n) rt
  let sign = AST.extract e 1<rt> (RegType.toBitWidth oprSz - 1)
  (* Every kind but the two NaNs comes in a negative and a positive form, and
     the sign picks between them. *)
  let bySign neg pos = AST.ite sign (bit neg) (bit pos)
  (* The chain is built inside out: `normal` is what is left once every test
     has declined, and each line below puts one more test in front of it. So
     the order it RUNS in is the reverse of the order it is written in, and the
     two NaN tests come first -- which is the point of the function. *)
  let normal = bySign 1 6
  let subnormal = AST.ite (isSubnormal oprSz e) (bySign 2 5) normal
  let zero = AST.ite (isZero oprSz e) (bySign 3 4) subnormal
  let infinite = AST.ite (isInf oprSz e) (bySign 0 7) zero
  let quiet = AST.ite (isQNan oprSz e) (bit 9) infinite
  AST.ite (isSNan oprSz e) (bit 8) quiet
