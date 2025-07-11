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

module B2R2.FrontEnd.SPARC.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

let inline numI32PC n = BitVector.OfInt32 n 64<rt> |> AST.num

let inline getCCVar (bld: ILowUIRBuilder) name =
  ConditionCode.toRegID name |> bld.GetRegVar

let dstAssign oprSize dst src =
  match oprSize with
  | 8<rt> | 16<rt> -> dst := src (* No extension for 8- and 16-bit operands *)
  | _ -> let dst = AST.unwrap dst
         let dstOrigSz = dst |> Expr.TypeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

let transOprToExpr ins insLen bld = function
  | OprReg reg -> regVar bld reg
  | OprImm imm -> numI32 imm 64<rt>
  | OprAddr addr -> numI32PC addr
  | OprCC cc -> getCCVar bld cc
  | OprPriReg prireg -> regVar bld prireg
  | _ -> Terminator.impossible ()

let isRegOpr (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands (_, o2, _) ->
    match o2 with
    | OprReg reg -> true
    | _ -> false
  | _ -> raise InvalidOperandException

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

let transOneOpr (ins: Instruction) insLen bld =
  match ins.Operands with
  | OneOperand o1 -> transOprToExpr ins insLen bld o1
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr ins insLen bld o1,
            transOprToExpr ins insLen bld o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen bld o1,
            transOprToExpr ins insLen bld o2,
            transOprToExpr ins insLen bld o3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins insLen bld o1,
            transOprToExpr ins insLen bld o2,
            transOprToExpr ins insLen bld o3,
            transOprToExpr ins insLen bld o4)
  | _ -> raise InvalidOperandException

let transAddrThreeOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen bld o1 .+
            transOprToExpr ins insLen bld o2,
            transOprToExpr ins insLen bld o3)
  | _ -> raise InvalidOperandException

let transAddrFourOprs (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins insLen bld o1 .+
            transOprToExpr ins insLen bld o2,
            transOprToExpr ins insLen bld o3,
            transOprToExpr ins insLen bld o4)
  | _ -> raise InvalidOperandException

let transTwooprsAddr (ins: Instruction) insLen bld =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen bld o1,
            transOprToExpr ins insLen bld o2 .+
            transOprToExpr ins insLen bld o3)
  | _ -> raise InvalidOperandException

let transThroprsAddr (ins: Instruction) insLen bld =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins insLen bld o1,
            transOprToExpr ins insLen bld o2 .+
            transOprToExpr ins insLen bld o3,
            transOprToExpr ins insLen bld o4)
  | _ -> raise InvalidOperandException

let getConditionCodeAdd res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = ((sign .& sign1 .& AST.not ressign) .|
    (AST.not sign .& AST.not sign1 .& ressign))
  let xccc = (sign .& sign1) .| ((AST.not ressign) .& (sign .| sign1))
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = ((sign32 .& sign321 .& AST.not ressign32) .|
    (AST.not sign32 .& AST.not sign321 .& ressign32))
  let iccc = (sign32 .& sign321) .| ((AST.not ressign32) .& (sign32 .| sign321))
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; iccn |]

let getConditionCodeSub res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = ((sign .& AST.not sign1 .& AST.not ressign) .|
    (AST.not sign .& sign1 .& ressign))
  let xccc = (((AST.not sign) .& sign1) .|
    (ressign .& ((AST.not sign) .| sign1)))
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = ((sign32 .& AST.not sign321 .& AST.not ressign32) .|
    (AST.not sign32 .& sign321 .& ressign32))
  let iccc = (((AST.not sign32) .& sign321) .|
    (ressign32 .& ((AST.not sign32) .| sign321)))
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; iccn |]

let getConditionCodeLog res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = AST.num0 1<rt>
  let xccc = AST.num0 1<rt>
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = AST.num0 1<rt>
  let iccc = AST.num0 1<rt>
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; iccn |]

let getConditionCodeMul res src src1 =
  let sign = AST.extract src 1<rt> 63
  let sign1 = AST.extract src1 1<rt> 63
  let ressign = AST.extract res 1<rt> 63
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let xccn = ressign
  let xccz = res == AST.num0 64<rt>
  let xccv = AST.num0 1<rt>
  let xccc = AST.num0 1<rt>
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = AST.num0 1<rt>
  let iccc = AST.num0 1<rt>
  // AST.concat xccn (AST. concat xccz (AST.concat xccv (AST.concat xccc
    // (AST.concat iccn (AST.concat iccz (AST.concat iccv iccc))))))
  AST.revConcat [| iccc; iccv; iccz; iccn; xccc; xccv; xccz; iccn |]

let getConditionCodeMulscc res src src1 =
  let res32 = AST.extract res 32<rt> 0
  let sign32 = AST.extract src 1<rt> 31
  let sign321 = AST.extract src1 1<rt> 31
  let ressign32 = AST.extract res 1<rt> 31
  let iccn = ressign32
  let iccz = res32 == AST.num0 32<rt>
  let iccv = (sign32 .& sign321 .& AST.not ressign32 .|
    (AST.not sign32 .& AST.not sign321 .& ressign32))
  let iccc = (sign32 .& sign321) .| ((AST.not ressign32)
    .& (sign32 .| sign321))
  AST.revConcat [| iccc; iccv; iccz; iccn |]

let getNextReg bld reg =
  if reg = regVar bld Register.G0 then Register.G1
  elif reg = regVar bld Register.G2 then Register.G3
  elif reg = regVar bld Register.G4 then Register.G5
  elif reg = regVar bld Register.G6 then Register.G7
  elif reg = regVar bld Register.O0 then Register.O1
  elif reg = regVar bld Register.O2 then Register.O3
  elif reg = regVar bld Register.O4 then Register.O5
  elif reg = regVar bld Register.O6 then Register.O7
  elif reg = regVar bld Register.L0 then Register.L1
  elif reg = regVar bld Register.L2 then Register.L3
  elif reg = regVar bld Register.L4 then Register.L5
  elif reg = regVar bld Register.L6 then Register.L7
  elif reg = regVar bld Register.I0 then Register.I1
  elif reg = regVar bld Register.I2 then Register.I3
  elif reg = regVar bld Register.I4 then Register.I5
  elif reg = regVar bld Register.I6 then Register.I7
  else raise InvalidRegisterException

let getFloatClass bld freg =
  if (freg = regVar bld Register.F0 || freg = regVar bld Register.F2
    || freg = regVar bld Register.F4 || freg = regVar bld Register.F6
    || freg = regVar bld Register.F8|| freg = regVar bld Register.F10
    || freg = regVar bld Register.F12 || freg = regVar bld Register.F14
    || freg = regVar bld Register.F16 || freg = regVar bld Register.F18
    || freg = regVar bld Register.F20 || freg = regVar bld Register.F22
    || freg = regVar bld Register.F24 || freg = regVar bld Register.F26
    || freg = regVar bld Register.F28 || freg = regVar bld Register.F30)
  then 0
  elif (freg = regVar bld Register.F32 || freg = regVar bld Register.F34
    || freg = regVar bld Register.F36 || freg = regVar bld Register.F38
    || freg = regVar bld Register.F40 || freg = regVar bld Register.F42
    || freg = regVar bld Register.F44 || freg = regVar bld Register.F46
    || freg = regVar bld Register.F48 || freg = regVar bld Register.F50
    || freg = regVar bld Register.F52 || freg = regVar bld Register.F54
    || freg = regVar bld Register.F56 || freg = regVar bld Register.F58
    || freg = regVar bld Register.F60 || freg = regVar bld Register.F62)
  then 1
  else raise InvalidRegisterException

let getDFloatNext bld freg =
  if freg = regVar bld Register.F0 then Register.F1
  elif freg = regVar bld Register.F2 then Register.F3
  elif freg = regVar bld Register.F4 then Register.F5
  elif freg = regVar bld Register.F6 then Register.F7
  elif freg = regVar bld Register.F8 then Register.F9
  elif freg = regVar bld Register.F10 then Register.F11
  elif freg = regVar bld Register.F12 then Register.F13
  elif freg = regVar bld Register.F14 then Register.F15
  elif freg = regVar bld Register.F16 then Register.F17
  elif freg = regVar bld Register.F18 then Register.F19
  elif freg = regVar bld Register.F20 then Register.F21
  elif freg = regVar bld Register.F22 then Register.F23
  elif freg = regVar bld Register.F24 then Register.F25
  elif freg = regVar bld Register.F26 then Register.F27
  elif freg = regVar bld Register.F28 then Register.F29
  elif freg = regVar bld Register.F30 then Register.F31
  else raise InvalidRegisterException

let movFregD bld src dst =
  let sClass = getFloatClass bld src
  let dClass = getFloatClass bld dst
  match sClass, dClass with
  | 0, 0 ->
    let nextsrc = regVar bld (getDFloatNext bld src)
    let nextdst = regVar bld (getDFloatNext bld dst)
    bld <+ (dst := src)
    bld <+ (nextdst := nextsrc)
  | 0, 1 ->
    let nextsrc = regVar bld (getDFloatNext bld src)
    bld <+ (AST.extract dst 32<rt> 0 := nextsrc)
    bld <+ (AST.extract dst 32<rt> 32 := src)
  | 1, 0 ->
    let nextdst = regVar bld (getDFloatNext bld dst)
    bld <+ (dst := AST.extract src 32<rt> 32)
    bld <+ (nextdst := AST.extract src 32<rt> 0)
  | 1, 1 ->
    bld <+ (dst := src)
  | _ -> raise InvalidRegisterException

let getQFloatNext0 bld freg =
  if (freg = regVar bld Register.F0) then
    struct (Register.F1, Register.F2, Register.F3)
  elif (freg = regVar bld Register.F4) then
    struct (Register.F5, Register.F6, Register.F7)
  elif (freg = regVar bld Register.F8) then
    struct (Register.F9, Register.F10, Register.F11)
  elif (freg = regVar bld Register.F12) then
    struct (Register.F13, Register.F14, Register.F15)
  elif (freg = regVar bld Register.F16) then
    struct (Register.F17, Register.F18, Register.F19)
  elif (freg = regVar bld Register.F20) then
    struct (Register.F21, Register.F22, Register.F23)
  elif (freg = regVar bld Register.F24) then
    struct (Register.F25, Register.F26, Register.F27)
  elif (freg = regVar bld Register.F28) then
    struct (Register.F29, Register.F30, Register.F31)
  else raise InvalidRegisterException

let getQFloatNext1 bld freg =
  if (freg = regVar bld Register.F32) then Register.F34
  elif (freg = regVar bld Register.F36) then Register.F38
  elif (freg = regVar bld Register.F40) then Register.F42
  elif (freg = regVar bld Register.F44) then Register.F46
  elif (freg = regVar bld Register.F48) then Register.F50
  elif (freg = regVar bld Register.F52) then Register.F54
  elif (freg = regVar bld Register.F56) then Register.F58
  elif (freg = regVar bld Register.F60) then Register.F62
  else raise InvalidRegisterException

let movFregQ bld src dst =
  let sClass = getFloatClass bld src
  let dClass = getFloatClass bld dst
  match sClass, dClass with
  | 0, 0 ->
    let struct (s1, s2, s3) = getQFloatNext0 bld src
    let src1 = regVar bld s1
    let src2 = regVar bld s2
    let src3 = regVar bld s3
    let struct (d1, d2, d3) = getQFloatNext0 bld dst
    let dst1 = regVar bld d1
    let dst2 = regVar bld d2
    let dst3 = regVar bld d3
    bld <+ (dst := src)
    bld <+ (dst1 := src1)
    bld <+ (dst2 := src2)
    bld <+ (dst3 := src3)
  | 0, 1 ->
    let struct (s1, s2, s3) = getQFloatNext0 bld src
    let src1 = regVar bld s1
    let src2 = regVar bld s2
    let src3 = regVar bld s3
    let nextdst = regVar bld (getQFloatNext1 bld dst)
    bld <+ (AST.extract nextdst 32<rt> 0 := src3)
    bld <+ (AST.extract nextdst 32<rt> 32 := src2)
    bld <+ (AST.extract dst 32<rt> 0 := src1)
    bld <+ (AST.extract dst 32<rt> 32 := src)
  | 1, 0 ->
    let nextsrc = regVar bld (getQFloatNext1 bld src)
    let struct (d1, d2, d3) = getQFloatNext0 bld dst
    let dst1 = regVar bld d1
    let dst2 = regVar bld d2
    let dst3 = regVar bld d3
    bld <+ (dst := AST.extract src 32<rt> 32)
    bld <+ (dst1 := AST.extract src 32<rt> 0)
    bld <+ (dst2 := AST.extract nextsrc 32<rt> 32)
    bld <+ (dst3 := AST.extract nextsrc 32<rt> 0)
  | 1, 1 ->
    let nextsrc = regVar bld (getQFloatNext1 bld src)
    let nextdst = regVar bld (getQFloatNext1 bld dst)
    bld <+ (nextdst := nextsrc)
    bld <+ (dst := src)
  | _ -> raise InvalidRegisterException

let getDFloatOp bld src op =
  let regclass = getFloatClass bld src
  match regclass with
  | 0 ->
    let nextreg = regVar bld (getDFloatNext bld src)
    bld <+ ((AST.extract op 32<rt> 32) := src)
    bld <+ ((AST.extract op 32<rt> 0) := nextreg)
  | 1 ->
    bld <+ (op := src)
  | _ -> raise InvalidRegisterException

let getQFloatOp bld src op1 op2 =
  let regclass = getFloatClass bld src
  match regclass with
  | 0 ->
    let struct (r1, r2, r3) = getQFloatNext0 bld src
    let src1 = regVar bld r1
    let src2 = regVar bld r2
    let src3 = regVar bld r3
    bld <+ ((AST.extract op1 32<rt> 32) := src)
    bld <+ ((AST.extract op1 32<rt> 0) := src1)
    bld <+ ((AST.extract op2 32<rt> 32) := src2)
    bld <+ ((AST.extract op2 32<rt> 0) := src3)
  | 1 ->
    let r1 = getQFloatNext1 bld src
    let src1 = regVar bld r1
    bld <+ ((AST.extract op1 64<rt> 0) := src)
    bld <+ ((AST.extract op2 64<rt> 0) := src1)
  | _ -> raise InvalidRegisterException

let setDFloatOp bld dst res =
  let regclass = getFloatClass bld dst
  match regclass with
  | 0 ->
    let nextreg = regVar bld (getDFloatNext bld dst)
    bld <+ (dst := (AST.extract res 32<rt> 32))
    bld <+ (nextreg := (AST.extract res 32<rt> 0))
  | 1 ->
    bld <+ (dst := res)
  | _ -> raise InvalidRegisterException

let setQFloatOp bld dst res1 res2 =
  let regclass = getFloatClass bld dst
  match regclass with
  | 0 ->
    let struct (r1, r2, r3) = getQFloatNext0 bld dst
    let dst1 = regVar bld r1
    let dst2 = regVar bld r2
    let dst3 = regVar bld r3
    bld <+ (dst := (AST.extract res1 32<rt> 32))
    bld <+ (dst1 := (AST.extract res1 32<rt> 0))
    bld <+ (dst2 := (AST.extract res2 32<rt> 32))
    bld <+ (dst3 := (AST.extract res2 32<rt> 0))
  | 1 ->
    let r1 = getQFloatNext1 bld dst
    let dst1 = regVar bld r1
    bld <+ (dst := (AST.extract res1 64<rt> 0))
    bld <+ (dst1 := (AST.extract res2 64<rt> 0))
  | _ -> raise InvalidRegisterException

let cast64To128 bld src dst1 dst2 =
  let oprSize = 64<rt>
  let zero = AST.num0 64<rt>
  let tmpSrc = tmpVar bld oprSize
  let n63 = numI32 63 64<rt>
  let n15 = numI32 15 16<rt>
  let n52 = numI32 52 64<rt>
  let one = numI32 1 64<rt>
  let n60 = numI32 60 64<rt>
  let final = tmpVar bld 52<rt>
  let biasDiff = numI32 0x3c00 16<rt>
  let sign = (AST.xtlo 16<rt> (((src >> n63) .& one))) << n15
  let exponent =
    (AST.xtlo 16<rt> (((src >> n52) .& (numI32 0x7ff 64<rt>)))) .+ biasDiff
  let integerpart = numI64 0x0010000000000000L 64<rt>
  let significand = src .& numI64 0xFFFFFFFFFFFFFL 64<rt> .| integerpart
  bld <+ (AST.extract dst1 16<rt> 48 := AST.ite (AST.eq src zero)
    (AST.num0 16<rt>) (sign .| exponent))
  bld <+ (final := AST.ite (AST.eq tmpSrc zero)
    (AST.num0 52<rt>) (AST.extract significand 52<rt> 0))
  bld <+ (AST.extract dst1 48<rt> 0 := (AST.extract final 48<rt> 4))
  bld <+ (AST.extract dst2 4<rt> 60 := (AST.extract final 4<rt> 0))
  bld <+ (AST.extract dst2 60<rt> 4 := AST.num0 60<rt>)

let cast128to64 bld src1 src2 dst =
  let n48 = numI32 48 64<rt>
  let n63 = numI32 63 64<rt>
  let top16b = AST.extract src1 16<rt> 48
  let sign = (AST.zext 64<rt> top16b .& (numI32 0x8000 64<rt>)) << n48
  let biasDiff = numI32 0x3c00 64<rt>
  let tmpExp = tmpVar bld 64<rt>
  let significand = tmpVar bld 64<rt>
  let computedExp =
    (AST.zext 64<rt> (top16b .& (numI32 0x7fff 16<rt>)) .- biasDiff)
  let maxExp = numI32 0x7fe 64<rt>
  let exponent =
    AST.ite (AST.eq top16b (AST.num0 16<rt>))
      (AST.num0 64<rt>)
      (AST.ite (AST.gt tmpExp maxExp) maxExp tmpExp)
  let exponent = exponent << numI32 52 64<rt>
  let n11 = numI32 11 64<rt>
  bld <+ (AST.extract significand 16<rt> 48 := AST.extract src1 16<rt> 32)
  bld <+ (AST.extract significand 32<rt> 0 := AST.extract src2 32<rt> 32)
  bld <+ (tmpExp := computedExp)
  bld <+ (dst := (sign .| exponent .| significand))

let add ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .+ src1)
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let addcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .+ src1)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := getConditionCodeAdd res src src1)
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let addC ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .+ src1 .+ AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let addCcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .+ src1 .+ AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeAdd res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let ``and`` ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .& src1)
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let andcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let ccr = regVar bld Register.CCR
  let res = tmpVar bld oprSize
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .& src1)
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeLog res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let andn ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .& (AST.not src1))
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let andncc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let ccr = regVar bld Register.CCR
  let res = tmpVar bld oprSize
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .& (AST.not src1))
  if dst = regVar bld Register.G0 then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeLog res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let branchpr ins insLen bld =
  let oprSize = 64<rt>
  let struct (src, label, an, pr) = transFourOprs ins insLen bld
  let pc = regVar bld Register.PC
  bld <!-- (ins.Address, insLen)
  let branchCond =
    match ins.Opcode with
    | Opcode.BRZ -> (src == AST.num0 oprSize)
    | Opcode.BRLEZ ->(src ?<= AST.num0 oprSize)
    | Opcode.BRLZ -> (src ?< AST.num0 oprSize)
    | Opcode.BRNZ -> (src != AST.num0 oprSize)
    | Opcode.BRGZ -> (src ?> AST.num0 oprSize)
    | Opcode.BRGEZ -> (src ?>= AST.num0 oprSize)
    | _ -> raise InvalidOpcodeException
  let annoffset =
    if AST.extract an 1<rt> 0 = AST.b1 then numI32PC 4
    else numI32PC 0
  let fallThrough = pc .+ numI32PC 4 .+ annoffset
  let jumpTarget = pc .+ AST.zext 64<rt> label
  bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
  bld --!> insLen

let branchicc ins insLen bld =
  let oprSize = 64<rt>
  let struct (an, label) = transTwoOprs ins insLen bld
  let pc = regVar bld Register.PC
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  let branchCond =
    match ins.Opcode with
    | Opcode.BA -> (AST.b1)
    | Opcode.BN -> (AST.b0)
    | Opcode.BNE -> (AST.extract ccr 1<rt> 2 == AST.b0)
    | Opcode.BE -> (AST.extract ccr 1<rt> 2 == AST.b1)
    | Opcode.BG ->
      (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
        (AST.extract ccr 1<rt> 3))) == AST.b0)
    | Opcode.BLE ->
      (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
        (AST.extract ccr 1<rt> 3))) == AST.b1)
    | Opcode.BGE ->
      ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
    | Opcode.BL ->
      ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
    | Opcode.BGU ->
      ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b0)
    | Opcode.BLEU ->
      ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b1)
    | Opcode.BCC -> (AST.extract ccr 1<rt> 0 == AST.b0)
    | Opcode.BCS -> (AST.extract ccr 1<rt> 0 == AST.b1)
    | Opcode.BPOS -> (AST.extract ccr 1<rt> 3 == AST.b0)
    | Opcode.BNEG -> (AST.extract ccr 1<rt> 3 == AST.b1)
    | Opcode.BVC -> (AST.extract ccr 1<rt> 1 == AST.b0)
    | Opcode.BVS -> (AST.extract ccr 1<rt> 1 == AST.b1)
    | _ -> raise InvalidOpcodeException
  let annoffset =
    if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
    else numI32PC 0
  let fallThrough = pc .+ numI32PC 4 .+ annoffset
  let jumpTarget = pc .+ AST.zext 64<rt> label
  if ins.Opcode = Opcode.BA then
    bld <+ (AST.interjmp jumpTarget InterJmpKind.Base)
    bld --!> insLen
  elif ins.Opcode = Opcode.BN then
    bld --!> insLen
  else
    bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
    bld --!> insLen

let branchpcc ins insLen bld =
  let oprSize = 64<rt>
  let struct (cc, label, an, pr) = transFourOprs ins insLen bld
  let pc = regVar bld Register.PC
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  let branchCond =
    match ins.Opcode with
    | Opcode.BPA -> (AST.b1)
    | Opcode.BPN -> (AST.b0)
    | Opcode.BPNE ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 2 == AST.b0)
      else
        (AST.extract ccr 1<rt> 4 == AST.b0)
    | Opcode.BPE ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 2 == AST.b1)
      else
        (AST.extract ccr 1<rt> 6 == AST.b1)
    | Opcode.BPG ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
          (AST.extract ccr 1<rt> 3))) == AST.b0)
      else
        (((AST.extract ccr 1<rt> 6) .| ((AST.extract ccr 1<rt> 5) <+>
          (AST.extract ccr 1<rt> 7))) == AST.b0)
    | Opcode.BPLE ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
          (AST.extract ccr 1<rt> 3))) == AST.b1)
      else
        (((AST.extract ccr 1<rt> 6) .| ((AST.extract ccr 1<rt> 5) <+>
          (AST.extract ccr 1<rt> 7))) == AST.b1)
    | Opcode.BPGE ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
      else
        ((AST.extract ccr 1<rt> 5) <+> (AST.extract ccr 1<rt> 7) == AST.b1)
    | Opcode.BPL ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
      else
        ((AST.extract ccr 1<rt> 5) <+> (AST.extract ccr 1<rt> 7) == AST.b1)
    | Opcode.BPGU ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b0)
      else
        ((AST.extract ccr 1<rt> 4) .| (AST.extract ccr 1<rt> 6) == AST.b0)
    | Opcode.BPLEU ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b1)
      else
        ((AST.extract ccr 1<rt> 4) .| (AST.extract ccr 1<rt> 6) == AST.b1)
    | Opcode.BPCC ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 0 == AST.b0)
      else
        (AST.extract ccr 1<rt> 4 == AST.b0)
    | Opcode.BPCS ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 0 == AST.b1)
      else
        (AST.extract ccr 1<rt> 4 == AST.b1)
    | Opcode.BPPOS ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 3 == AST.b0)
      else
        (AST.extract ccr 1<rt> 7 == AST.b0)
    | Opcode.BPNEG ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 3 == AST.b1)
      else
        (AST.extract ccr 1<rt> 7 == AST.b1)
    | Opcode.BPVC ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 1 == AST.b0)
      else
        (AST.extract ccr 1<rt> 5 == AST.b0)
    | Opcode.BPVS ->
      if (cc = getCCVar bld ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 1 == AST.b1)
      else
        (AST.extract ccr 1<rt> 5 == AST.b1)
    | _ -> raise InvalidOpcodeException
  let annoffset =
    if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
    else numI32PC 0
  let fallThrough = pc .+ numI32PC 4 .+ annoffset
  let jumpTarget = pc .+ AST.zext 64<rt> label
  if (ins.Opcode = Opcode.BPA) then
    bld <+ (AST.interjmp jumpTarget InterJmpKind.Base)
    bld --!> insLen
  elif (ins.Opcode = Opcode.BPN) then
    bld --!> insLen
  else
    bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
    bld --!> insLen

let call ins insLen bld =
  let dst = transOneOpr ins insLen bld
  let sp = regVar bld Register.O7
  let pc = regVar bld Register.PC
  bld <!-- (ins.Address, insLen)
  bld <+ (sp := pc)
  bld <+ (pc := pc .+ dst)
  bld --!> insLen

let casa ins insLen bld =
  let struct (src, asi, src1, dst) = transFourOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  let cond = ((AST.extract src1 32<rt> 0) == (AST.loadBE 32<rt> (src .+ asi)))
  bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.loadBE 32<rt> (src .+ asi) := AST.extract src1 32<rt> 0)
  bld <+ (AST.lmark lblEnd)
  bld <+ (AST.extract dst 32<rt> 0 := AST.extract src1 32<rt> 0)
  bld <+ (AST.extract dst 32<rt> 32 := AST.num0 32<rt>)
  bld --!> insLen

let casxa ins insLen bld =
  let struct (src, asi, src1, dst) = transFourOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  let cond = (src1 == AST.loadBE 64<rt> (src .+ asi))
  bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  bld <+ (AST.loadBE 64<rt> (src .+ asi) := dst)
  bld <+ (AST.lmark lblEnd)
  bld <+ (dst := src1)
  bld --!> insLen

let ``done`` (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld Register.PC := regVar bld Register.TNPC)
  bld <+ (regVar bld Register.NPC := regVar bld Register.TNPC .+ numI32PC 4)
  bld --!> insLen

let fabss ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.extract dst 1<rt> 31 := AST.b0)
  bld <+ (AST.extract dst 31<rt> 0 := AST.extract src 31<rt> 0)
  bld --!> insLen

let fabsd ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let op = tmpVar bld oprSize
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  bld <+ (AST.extract res 1<rt> 63 := AST.b0)
  bld <+ (AST.extract res 63<rt> 0 := AST.extract op 63<rt> 0)
  setDFloatOp bld dst res
  bld --!> insLen

let fabsq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let op1 = tmpVar bld oprSize
  let op2 = tmpVar bld oprSize
  let res1 = tmpVar bld oprSize
  let res2 = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op1 op2
  bld <+ (AST.extract res1 1<rt> 63 := AST.b0)
  bld <+ (AST.extract res1 63<rt> 0 := AST.extract op1 63<rt> 0)
  bld <+ (AST.extract res2 64<rt> 0 := AST.extract op2 64<rt> 0)
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fmovs ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src)
  bld --!> insLen

let fmovd ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  movFregD bld src dst
  bld --!> insLen

let fmovq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  movFregQ bld src dst
  bld --!> insLen

let fnegs ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 32<rt>
  let sign = ((AST.extract src 1<rt> 31) <+> (AST.b1))
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.extract dst 1<rt> 31 := sign)
  bld <+ (AST.extract dst 31<rt> 0 := AST.extract src 31<rt> 0)
  bld --!> insLen

let fnegd ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let op = tmpVar bld oprSize
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  let sign = ((AST.extract op 1<rt> 63) <+> (AST.b1))
  bld <+ (AST.extract res 1<rt> 63 := sign)
  bld <+ (AST.extract res 63<rt> 0 := AST.extract op 63<rt> 0)
  setDFloatOp bld dst res
  bld --!> insLen

let fnegq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let op1 = tmpVar bld oprSize
  let op2 = tmpVar bld oprSize
  let res1 = tmpVar bld oprSize
  let res2 = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op1 op2
  let sign = ((AST.extract op1 1<rt> 63) <+> (AST.b1))
  bld <+ (AST.extract res1 1<rt> 63 := sign)
  bld <+ (AST.extract res1 63<rt> 0 := AST.extract op1 63<rt> 0)
  bld <+ (AST.extract res2 64<rt> 0 := AST.extract op2 64<rt> 0)
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fadds ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (AST.fadd src src1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let faddd ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let op = tmpVar bld regSize
  let op1 = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  getDFloatOp bld src1 op1
  bld <+ (res := (AST.fadd op op1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let faddq ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = tmpVar bld regSize
  let res2 = tmpVar bld regSize
  let op01 = tmpVar bld regSize
  let op02 = tmpVar bld regSize
  let op11 = tmpVar bld regSize
  let op12 = tmpVar bld regSize
  let op64 = tmpVar bld 64<rt>
  let op164 = tmpVar bld 64<rt>
  let res64 = tmpVar bld 64<rt>
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op01 op02
  getQFloatOp bld src1 op11 op12
  cast128to64 bld op01 op02 op64
  cast128to64 bld op11 op12 op164
  bld <+ (res64 := (AST.fadd op64 op164))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fbranchfcc ins insLen bld =
  let struct (an, label) = transTwoOprs ins insLen bld
  let pc = regVar bld Register.PC
  let fsr = regVar bld Register.FSR
  let u = ((AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>))
  let g = ((AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>))
  let l = ((AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>))
  let e = ((AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>))
  let branchCond =
    match ins.Opcode with
    | Opcode.FBA -> AST.b1
    | Opcode.FBN -> AST.b0
    | Opcode.FBU -> u
    | Opcode.FBG -> g
    | Opcode.FBUG -> (u .| g)
    | Opcode.FBL -> l
    | Opcode.FBUL -> (u .| l)
    | Opcode.FBLG -> (l .| g)
    | Opcode.FBNE -> (l .| g .| u)
    | Opcode.FBE -> e
    | Opcode.FBUE -> (e .| u)
    | Opcode.FBGE -> (g .| e)
    | Opcode.FBUGE -> (u .| g .| e)
    | Opcode.FBLE -> (l .| e)
    | Opcode.FBULE -> (u .| l .| e)
    | Opcode.FBO -> (l .| e .| g)
    | _ -> raise InvalidOpcodeException
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FBA) then
    let jumpTarget = pc .+ AST.zext 64<rt> label
    bld <+ (AST.interjmp jumpTarget InterJmpKind.Base)
    bld --!> insLen
  elif (ins.Opcode = Opcode.FBN) then
    bld --!> insLen
  else
    let annoffset =
      if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
      else numI32PC 0
    let fallThrough = pc .+ numI32PC 4 .+ annoffset
    let jumpTarget = pc .+ AST.zext 64<rt> label
    bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
    bld --!> insLen

let fbranchpfcc ins insLen bld =
  let struct (cc, label, an, pr) = transFourOprs ins insLen bld
  let pc = regVar bld Register.PC
  let fsr = regVar bld Register.FSR
  let fcc0 = getCCVar bld ConditionCode.Fcc0
  let fcc1 = getCCVar bld ConditionCode.Fcc1
  let fcc2 = getCCVar bld ConditionCode.Fcc2
  let fcc3 = getCCVar bld ConditionCode.Fcc3
  let pos =
    if (cc = fcc0) then 10
    elif (cc = fcc1) then 32
    elif (cc = fcc2) then 34
    elif (cc = fcc3) then 36
    else raise InvalidOperandException
  let u = ((AST.extract fsr 2<rt> pos) == (numI32 3 2<rt>))
  let g = ((AST.extract fsr 2<rt> pos) == (numI32 2 2<rt>))
  let l = ((AST.extract fsr 2<rt> pos) == (numI32 1 2<rt>))
  let e = ((AST.extract fsr 2<rt> pos) == (numI32 0 2<rt>))
  let branchCond =
    match ins.Opcode with
    | Opcode.FBPA -> AST.b1
    | Opcode.FBPN -> AST.b0
    | Opcode.FBPU -> u
    | Opcode.FBPG -> g
    | Opcode.FBPUG -> (u .| g)
    | Opcode.FBPL -> l
    | Opcode.FBPUL -> (u .| l)
    | Opcode.FBPLG -> (l .| g)
    | Opcode.FBPNE -> (l .| g .| u)
    | Opcode.FBPE -> e
    | Opcode.FBPUE -> (e .| u)
    | Opcode.FBPGE -> (g .| e)
    | Opcode.FBPUGE -> (u .| g .| e)
    | Opcode.FBPLE -> (l .| e)
    | Opcode.FBPULE -> (u .| l .| e)
    | Opcode.FBPO -> (l .| e .| g)
    | _ -> raise InvalidOpcodeException
  bld <!-- (ins.Address, insLen)
  let annoffset =
    if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
    else numI32PC 0
  let fallThrough = pc .+ numI32PC 4 .+ annoffset
  let jumpTarget = pc .+ AST.zext 64<rt> label
  bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
  bld --!> insLen

let fcmps ins insLen bld =
  let struct (cc, src, src1) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fcc0 = getCCVar bld ConditionCode.Fcc0
  let fcc1 = getCCVar bld ConditionCode.Fcc1
  let fcc2 = getCCVar bld ConditionCode.Fcc2
  let fcc3 = getCCVar bld ConditionCode.Fcc3
  let pos =
    if cc = fcc0 then 10
    elif cc = fcc1 then 32
    elif cc = fcc2 then 34
    elif cc = fcc3 then 36
    else raise InvalidOperandException
  let op = AST.extract src 32<rt> 0
  let op1 = AST.extract src1 32<rt> 0
  bld <!-- (ins.Address, insLen)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (AST.feq op op1)
  let cond1 = ((AST.flt op op1) == AST.b1)
  let cond2 = ((AST.fgt op op1) == AST.b1)
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 0 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 1 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 2 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 3 2<rt>))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fcmpd ins insLen bld =
  let struct (cc, src, src1) = transThreeOprs ins insLen bld
  let regSize = 64<rt>
  let fsr = regVar bld Register.FSR
  let fcc0 = getCCVar bld ConditionCode.Fcc0
  let fcc1 = getCCVar bld ConditionCode.Fcc1
  let fcc2 = getCCVar bld ConditionCode.Fcc2
  let fcc3 = getCCVar bld ConditionCode.Fcc3
  let pos =
    if cc = fcc0 then 10
    elif cc = fcc1 then 32
    elif cc = fcc2 then 34
    elif cc = fcc3 then 36
    else raise InvalidOperandException
  let op = tmpVar bld regSize
  let op1 = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  getDFloatOp bld src1 op1
  let cond0 = AST.feq op op1
  let cond1 = AST.flt op op1 == AST.b1
  let cond2 = AST.fgt op op1 == AST.b1
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 0 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 1 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 2 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 3 2<rt>))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fcmpq ins insLen bld =
  let struct (cc, src, src1) = transThreeOprs ins insLen bld
  let regSize = 64<rt>
  let fsr = regVar bld Register.FSR
  let fcc0 = getCCVar bld ConditionCode.Fcc0
  let fcc1 = getCCVar bld ConditionCode.Fcc1
  let fcc2 = getCCVar bld ConditionCode.Fcc2
  let fcc3 = getCCVar bld ConditionCode.Fcc3
  let pos =
    if (cc = fcc0) then 10
    elif (cc = fcc1) then 32
    elif (cc = fcc2) then 34
    elif (cc = fcc3) then 36
    else raise InvalidOperandException
  let op01 = tmpVar bld regSize
  let op02 = tmpVar bld regSize
  let op11 = tmpVar bld regSize
  let op12 = tmpVar bld regSize
  let op64 = tmpVar bld regSize
  let op164 = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op01 op02
  getQFloatOp bld src1 op11 op12
  cast128to64 bld op01 op02 op64
  cast128to64 bld op11 op12 op164
  let cond0 = (AST.feq op64 op164)
  let cond1 = ((AST.flt op64 op164) == AST.b1)
  let cond2 = ((AST.fgt op64 op164) == AST.b1)
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 0 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 1 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 2 2<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ ((AST.extract fsr 2<rt> pos) := (numI32 3 2<rt>))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen


let fdivs ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (AST.fdiv src src1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fdivd ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let op = tmpVar bld regSize
  let op1 = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  getDFloatOp bld src1 op1
  bld <+ (res := (AST.fdiv op op1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fdivq ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = tmpVar bld regSize
  let res2 = tmpVar bld regSize
  let op01 = tmpVar bld regSize
  let op02 = tmpVar bld regSize
  let op11 = tmpVar bld regSize
  let op12 = tmpVar bld regSize
  let op64 = tmpVar bld 64<rt>
  let op164 = tmpVar bld 64<rt>
  let res64 = tmpVar bld 64<rt>
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op01 op02
  getQFloatOp bld src1 op11 op12
  cast128to64 bld op01 op02 op64
  cast128to64 bld op11 op12 op164
  bld <+ (res64 := (AST.fdiv op64 op164))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fmovscc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let offset =
    if (cc = getCCVar bld ConditionCode.Icc) then 0
    else 4
  let n = AST.extract ccr 1<rt> (3 + offset)
  let z = AST.extract ccr 1<rt> (2 + offset)
  let v = AST.extract ccr 1<rt> (1 + offset)
  let c = AST.extract ccr 1<rt> (offset)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVsA -> AST.b1
    | Opcode.FMOVsN -> AST.b0
    | Opcode.FMOVsNE -> (z == AST.b0)
    | Opcode.FMOVsE -> (z == AST.b1)
    | Opcode.FMOVsG -> ((z .| (n <+> v)) == AST.b0)
    | Opcode.FMOVsLE -> ((z .| (n <+> v)) == AST.b1)
    | Opcode.FMOVsGE -> ((n <+> v) == AST.b0)
    | Opcode.FMOVsL -> ((n <+> v) == AST.b1)
    | Opcode.FMOVsGU -> ((c .| z) == AST.b0)
    | Opcode.FMOVsLEU -> ((c .| z) == AST.b1)
    | Opcode.FMOVsCC -> (c == AST.b0)
    | Opcode.FMOVsCS -> (c == AST.b1)
    | Opcode.FMOVsPOS -> (n == AST.b0)
    | Opcode.FMOVsNEG -> (n == AST.b1)
    | Opcode.FMOVsVC -> (v == AST.b0)
    | Opcode.FMOVsVS -> (n == AST.b1)
    | _ -> raise InvalidOpcodeException
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FMOVsA) then
    bld <+ (fdst := fsrc)
    bld --!> insLen
  elif (ins.Opcode = Opcode.FMOVsA) then
    bld --!> insLen
  else
    bld <+ (fdst := AST.ite (cond) (fsrc) (fdst))
    bld --!> insLen

let fmovdcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let offset =
    if (cc = getCCVar bld ConditionCode.Icc) then 0
    else 4
  let n = AST.extract ccr 1<rt> (3 + offset)
  let z = AST.extract ccr 1<rt> (2 + offset)
  let v = AST.extract ccr 1<rt> (1 + offset)
  let c = AST.extract ccr 1<rt> (offset)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVdA -> AST.b1
    | Opcode.FMOVdN -> AST.b0
    | Opcode.FMOVdNE -> (z == AST.b0)
    | Opcode.FMOVdE -> (z == AST.b1)
    | Opcode.FMOVdG -> ((z .| (n <+> v)) == AST.b0)
    | Opcode.FMOVdLE -> ((z .| (n <+> v)) == AST.b1)
    | Opcode.FMOVdGE -> ((n <+> v) == AST.b0)
    | Opcode.FMOVdL -> ((n <+> v) == AST.b1)
    | Opcode.FMOVdGU -> ((c .| z) == AST.b0)
    | Opcode.FMOVdLEU -> ((c .| z) == AST.b1)
    | Opcode.FMOVdCC -> (c == AST.b0)
    | Opcode.FMOVdCS -> (c == AST.b1)
    | Opcode.FMOVdPOS -> (n == AST.b0)
    | Opcode.FMOVdNEG -> (n == AST.b1)
    | Opcode.FMOVdVC -> (v == AST.b0)
    | Opcode.FMOVdVS -> (n == AST.b1)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FMOVdA) then
    movFregD bld fsrc fdst
    bld --!> insLen
  elif (ins.Opcode = Opcode.FMOVdN) then
    bld --!> insLen
  else
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    movFregD bld fsrc fdst
    bld <+ (AST.lmark lblEnd)
    bld --!> insLen

let fmovqcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let offset =
    if (cc = getCCVar bld ConditionCode.Icc) then 0
    else 4
  let n = AST.extract ccr 1<rt> (3 + offset)
  let z = AST.extract ccr 1<rt> (2 + offset)
  let v = AST.extract ccr 1<rt> (1 + offset)
  let c = AST.extract ccr 1<rt> (offset)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVqA -> AST.b1
    | Opcode.FMOVqN -> AST.b0
    | Opcode.FMOVqNE -> (z == AST.b0)
    | Opcode.FMOVqE -> (z == AST.b1)
    | Opcode.FMOVqG -> ((z .| (n <+> v)) == AST.b0)
    | Opcode.FMOVqLE -> ((z .| (n <+> v)) == AST.b1)
    | Opcode.FMOVqGE -> ((n <+> v) == AST.b0)
    | Opcode.FMOVqL -> ((n <+> v) == AST.b1)
    | Opcode.FMOVqGU -> ((c .| z) == AST.b0)
    | Opcode.FMOVqLEU -> ((c .| z) == AST.b1)
    | Opcode.FMOVqCC -> (c == AST.b0)
    | Opcode.FMOVqCS -> (c == AST.b1)
    | Opcode.FMOVqPOS -> (n == AST.b0)
    | Opcode.FMOVqNEG -> (n == AST.b1)
    | Opcode.FMOVqVC -> (v == AST.b0)
    | Opcode.FMOVqVS -> (n == AST.b1)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FMOVqA) then
    movFregQ bld fsrc fdst
    bld --!> insLen
  elif (ins.Opcode = Opcode.FMOVqN) then
    bld --!> insLen
  else
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    movFregQ bld fsrc fdst
    bld <+ (AST.lmark lblEnd)
    bld --!> insLen

let fmovfscc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let pos =
    if (cc = getCCVar bld ConditionCode.Fcc0) then 10
    elif (cc = getCCVar bld ConditionCode.Fcc1) then 32
    elif (cc = getCCVar bld ConditionCode.Fcc2) then 34
    elif (cc = getCCVar bld ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos + 1)
  let e = (fsr1 == AST.b0 .& fsr0 == AST.b0)
  let l = (fsr1 == AST.b0 .& fsr0 == AST.b1)
  let g = (fsr1 == AST.b1 .& fsr0 == AST.b0)
  let u = (fsr1 == AST.b1 .& fsr0 == AST.b1)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVFsA -> AST.b1
    | Opcode.FMOVFsN -> AST.b0
    | Opcode.FMOVFsU -> u
    | Opcode.FMOVFsG -> g
    | Opcode.FMOVFsUG -> (g .| u)
    | Opcode.FMOVFsL -> l
    | Opcode.FMOVFsUL -> (u .| l)
    | Opcode.FMOVFsLG -> (l .| g)
    | Opcode.FMOVFsNE -> (l .| g .| u)
    | Opcode.FMOVFsE -> e
    | Opcode.FMOVFsUE -> (u .| e)
    | Opcode.FMOVFsGE -> (g .| e)
    | Opcode.FMOVFsUGE -> (u .| g .| e)
    | Opcode.FMOVFsLE -> (l .| e)
    | Opcode.FMOVFsULE -> (u .| l .| e)
    | Opcode.FMOVFsO -> (e .| l .| g)
    | _ -> raise InvalidOpcodeException
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FMOVFsA) then
    bld <+ (fdst := fsrc)
    bld --!> insLen
  elif (ins.Opcode = Opcode.FMOVFsN) then
    bld --!> insLen
  else
    bld <+ (fdst := AST.ite (cond) (fsrc) (fdst))
    bld --!> insLen

let fmovfdcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let pos =
    if (cc = getCCVar bld ConditionCode.Fcc0) then 10
    elif (cc = getCCVar bld ConditionCode.Fcc1) then 32
    elif (cc = getCCVar bld ConditionCode.Fcc2) then 34
    elif (cc = getCCVar bld ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos + 1)
  let e = (fsr1 == AST.b0 .& fsr0 == AST.b0)
  let l = (fsr1 == AST.b0 .& fsr0 == AST.b1)
  let g = (fsr1 == AST.b1 .& fsr0 == AST.b0)
  let u = (fsr1 == AST.b1 .& fsr0 == AST.b1)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVFdA -> AST.b1
    | Opcode.FMOVFdN -> AST.b0
    | Opcode.FMOVFdU -> u
    | Opcode.FMOVFdG -> g
    | Opcode.FMOVFdUG -> (g .| u)
    | Opcode.FMOVFdL -> l
    | Opcode.FMOVFdUL -> (u .| l)
    | Opcode.FMOVFdLG -> (l .| g)
    | Opcode.FMOVFdNE -> (l .| g .| u)
    | Opcode.FMOVFdE -> e
    | Opcode.FMOVFdUE -> (u .| e)
    | Opcode.FMOVFdGE -> (g .| e)
    | Opcode.FMOVFdUGE -> (u .| g .| e)
    | Opcode.FMOVFdLE -> (l .| e)
    | Opcode.FMOVFdULE -> (u .| l .| e)
    | Opcode.FMOVFdO -> (e .| l .| g)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FMOVFdA) then
    movFregD bld fsrc fdst
    bld --!> insLen
  elif (ins.Opcode = Opcode.FMOVFdN) then
    bld --!> insLen
  else
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    movFregD bld fsrc fdst
    bld <+ (AST.lmark lblEnd)
    bld --!> insLen

let fmovfqcc ins insLen bld =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let pos =
    if (cc = getCCVar bld ConditionCode.Fcc0) then 10
    elif (cc = getCCVar bld ConditionCode.Fcc1) then 32
    elif (cc = getCCVar bld ConditionCode.Fcc2) then 34
    elif (cc = getCCVar bld ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos + 1)
  let e = (fsr1 == AST.b0 .& fsr0 == AST.b0)
  let l = (fsr1 == AST.b0 .& fsr0 == AST.b1)
  let g = (fsr1 == AST.b1 .& fsr0 == AST.b0)
  let u = (fsr1 == AST.b1 .& fsr0 == AST.b1)
  let cond =
    match ins.Opcode with
    | Opcode.FMOVFqA -> AST.b1
    | Opcode.FMOVFqN -> AST.b0
    | Opcode.FMOVFqU -> u
    | Opcode.FMOVFqG -> g
    | Opcode.FMOVFqUG -> (g .| u)
    | Opcode.FMOVFqL -> l
    | Opcode.FMOVFqUL -> (u .| l)
    | Opcode.FMOVFqLG -> (l .| g)
    | Opcode.FMOVFqNE -> (l .| g .| u)
    | Opcode.FMOVFqE -> e
    | Opcode.FMOVFqUE -> (u .| e)
    | Opcode.FMOVFqGE -> (g .| e)
    | Opcode.FMOVFqUGE -> (u .| g .| e)
    | Opcode.FMOVFqLE -> (l .| e)
    | Opcode.FMOVFqULE -> (u .| l .| e)
    | Opcode.FMOVFqO -> (e .| l .| g)
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  if (ins.Opcode = Opcode.FMOVFqA) then
    movFregQ bld fsrc fdst
    bld --!> insLen
  elif (ins.Opcode = Opcode.FMOVFqN) then
    bld --!> insLen
  else
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    movFregQ bld fsrc fdst
    bld <+ (AST.lmark lblEnd)
    bld --!> insLen

let fmovrs ins insLen bld =
  let struct (src, fsrc, fdst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.FMOVRsZ ->
    bld <+ (fdst := AST.ite (src == AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsLEZ ->
    bld <+ (fdst := AST.ite (src ?<= AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsLZ ->
    bld <+ (fdst := AST.ite (src ?< AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsNZ ->
    bld <+ (fdst := AST.ite (src != AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsGZ ->
    bld <+ (fdst := AST.ite (src ?> AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsGEZ ->
    bld <+ (fdst := AST.ite (src ?>= AST.num0 oprSize) (fsrc) (fdst))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let fmovrd ins insLen bld =
  let struct (src, fsrc, fdst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let cond =
    match ins.Opcode with
    | Opcode.FMOVRdZ ->
      src == AST.num0 oprSize
    | Opcode.FMOVRdLEZ ->
      src ?<= AST.num0 oprSize
    | Opcode.FMOVRdLZ ->
      src ?< AST.num0 oprSize
    | Opcode.FMOVRdNZ ->
      src != AST.num0 oprSize
    | Opcode.FMOVRdGZ ->
      src ?> AST.num0 oprSize
    | Opcode.FMOVRdGEZ ->
      src ?>= AST.num0 oprSize
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  movFregD bld fsrc fdst
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fmovrq ins insLen bld =
  let struct (src, fsrc, fdst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let cond =
    match ins.Opcode with
    | Opcode.FMOVRqZ ->
      src == AST.num0 oprSize
    | Opcode.FMOVRqLEZ ->
      src ?<= AST.num0 oprSize
    | Opcode.FMOVRqLZ ->
      src ?< AST.num0 oprSize
    | Opcode.FMOVRqNZ ->
      src != AST.num0 oprSize
    | Opcode.FMOVRqGZ ->
      src ?> AST.num0 oprSize
    | Opcode.FMOVRqGEZ ->
      src ?>= AST.num0 oprSize
    | _ -> raise InvalidOpcodeException
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  movFregQ bld fsrc fdst
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fmuls ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (AST.fmul src src1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fmuld ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let op = tmpVar bld regSize
  let op1 = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  getDFloatOp bld src1 op1
  bld <+ (res := (AST.fmul op op1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fmulq ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = tmpVar bld regSize
  let res2 = tmpVar bld regSize
  let op01 = tmpVar bld regSize
  let op02 = tmpVar bld regSize
  let op11 = tmpVar bld regSize
  let op12 = tmpVar bld regSize
  let op64 = tmpVar bld 64<rt>
  let op164 = tmpVar bld 64<rt>
  let res64 = tmpVar bld 64<rt>
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op01 op02
  getQFloatOp bld src1 op11 op12
  cast128to64 bld op01 op02 op64
  cast128to64 bld op11 op12 op164
  bld <+ (res64 := (AST.fmul op64 op164))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fsmuld ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  let op1 = AST.cast CastKind.FloatCast 64<rt> src
  let op2 = AST.cast CastKind.FloatCast 64<rt> src1
  bld <+ (res := (AST.fmul op1 op2))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fdmulq ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let res1 = tmpVar bld regSize
  let res2 = tmpVar bld regSize
  let op = tmpVar bld regSize
  let op1 = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  getDFloatOp bld src1 op1
  bld <+ (res := (AST.fmul op op1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fsqrts ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (AST.fsqrt src))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fsqrtd ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let op = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  bld <+ (res := (AST.fsqrt op))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fsqrtq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = tmpVar bld regSize
  let res2 = tmpVar bld regSize
  let op01 = tmpVar bld regSize
  let op02 = tmpVar bld regSize
  let op64 = tmpVar bld 64<rt>
  let res64 = tmpVar bld 64<rt>
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op01 op02
  cast128to64 bld op01 op02 op64
  bld <+ (res64 := (AST.fsqrt op64))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fstox ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let cst = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (cst := AST.cast CastKind.FtoITrunc oprSize src)
  setDFloatOp bld dst cst
  bld --!> insLen

let fdtox ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let op = tmpVar bld oprSize
  let cst = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  bld <+ (cst := AST.cast CastKind.FtoITrunc oprSize op)
  setDFloatOp bld dst cst
  bld --!> insLen

let fqtox ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let regSize = 64<rt>
  let op1 = tmpVar bld regSize
  let op2 = tmpVar bld regSize
  let op64 = tmpVar bld regSize
  let cst = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op1 op2
  cast128to64 bld op1 op2 op64
  bld <+ (cst := AST.cast CastKind.FtoITrunc oprSize op64)
  setDFloatOp bld dst cst
  bld --!> insLen

let fstoi ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 32<rt>
  let cst = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.cast CastKind.FtoITrunc oprSize src)
  bld --!> insLen

let fdtoi ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let regSize = 32<rt>
  let op = tmpVar bld oprSize
  let cst = tmpVar bld regSize
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  bld <+ (dst := AST.cast CastKind.FtoITrunc regSize op)
  bld --!> insLen

let fqtoi ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 32<rt>
  let regSize = 64<rt>
  let op1 = tmpVar bld regSize
  let op2 = tmpVar bld regSize
  let op64 = tmpVar bld regSize
  let cst = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op1 op2
  cast128to64 bld op1 op2 op64
  bld <+ (dst := AST.cast CastKind.FtoITrunc oprSize op64)
  bld --!> insLen

let fstod ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = tmpVar bld oprSize
  let rounded = tmpVar bld oprSize
  let regSize = 64<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := AST.cast CastKind.FloatCast oprSize src)
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize res)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fstoq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res1 = tmpVar bld oprSize
  let res2 = tmpVar bld oprSize
  let res64 = tmpVar bld oprSize
  let rounded = tmpVar bld oprSize
  let regSize = 64<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res64 := AST.cast CastKind.FloatCast oprSize src)
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fdtos ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let fdtoq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let fqtos ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let fqtod ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let fsubs ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (AST.fsub src src1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fsubd ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = tmpVar bld regSize
  let op = tmpVar bld regSize
  let op1 = tmpVar bld regSize
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  getDFloatOp bld src1 op1
  bld <+ (res := (AST.fsub op op1))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fsubq ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = tmpVar bld regSize
  let res2 = tmpVar bld regSize
  let op01 = tmpVar bld regSize
  let op02 = tmpVar bld regSize
  let op11 = tmpVar bld regSize
  let op12 = tmpVar bld regSize
  let op64 = tmpVar bld 64<rt>
  let op164 = tmpVar bld 64<rt>
  let res64 = tmpVar bld 64<rt>
  let rounded = tmpVar bld regSize
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getQFloatOp bld src op01 op02
  getQFloatOp bld src1 op11 op12
  cast128to64 bld op01 op02 op64
  cast128to64 bld op11 op12 op164
  bld <+ (res64 := (AST.fsub op64 op164))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  bld <+ (AST.lmark lblEnd)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fxtos ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 32<rt>
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = tmpVar bld oprSize
  let op = tmpVar bld 64<rt>
  let regSize = tmpVar bld 32<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  bld <+ (res := (AST.cast CastKind.SIntToFloat oprSize op))
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := (AST.cast (CastKind.FtoFRound) oprSize op))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := (AST.cast (CastKind.FtoFTrunc) oprSize (res)))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := (AST.cast (CastKind.FtoFCeil) oprSize (res)))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := (AST.cast (CastKind.FtoFFloor) oprSize (res)))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fitos ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 32<rt>
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = tmpVar bld oprSize
  let regSize = 32<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := AST.cast CastKind.SIntToFloat oprSize src)
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (dst := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (dst := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (dst := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let fxtod ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let fsr = regVar bld Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = tmpVar bld oprSize
  let rounded = tmpVar bld oprSize
  let regSize = 64<rt>
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblL2 = label bld "L2"
  let lblL3 = label bld "L3"
  let lblL4 = label bld "L4"
  let lblL5 = label bld "L5"
  let lblEnd = label bld "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  bld <!-- (ins.Address, insLen)
  bld <+ (res := AST.cast CastKind.SIntToFloat oprSize src)
  bld <+ (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  bld <+ (AST.lmark lblL0)
  bld <+ (rounded := AST.cast CastKind.FtoFRound regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL1)
  bld <+ (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  bld <+ (AST.lmark lblL2)
  bld <+ (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL3)
  bld <+ (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  bld <+ (AST.lmark lblL4)
  bld <+ (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL5)
  bld <+ (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  bld <+ (AST.lmark lblEnd)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fitod ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let rounded = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (rounded := AST.cast CastKind.SIntToFloat 64<rt> src)
  setDFloatOp bld dst rounded
  bld --!> insLen

let fxtoq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let op = tmpVar bld oprSize
  let rounded = tmpVar bld 64<rt>
  let res1 = tmpVar bld oprSize
  let res2 = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  getDFloatOp bld src op
  bld <+ (rounded := AST.cast CastKind.SIntToFloat 64<rt> op)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let fitoq ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let rounded = tmpVar bld 64<rt>
  let res1 = tmpVar bld oprSize
  let res2 = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (rounded := AST.cast CastKind.SIntToFloat oprSize src)
  cast64To128 bld rounded res1 res2
  setQFloatOp bld dst res1 res2
  bld --!> insLen

let jmpl ins insLen bld =
  let struct (addr, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.jmp addr)
  bld <+ (dst := regVar bld Register.PC)
  bld --!> insLen

let ldf ins insLen bld =
  let struct (addr, dst) = transAddrThreeOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.LDF -> bld <+ (dst := (AST.loadBE 32<rt> addr))
  | Opcode.LDDF ->
    let op = tmpVar bld oprSize
    bld <+ (op := (AST.loadBE oprSize addr))
    setDFloatOp bld dst op
  | Opcode.LDQF ->
    let op0 = tmpVar bld oprSize
    let op1 = tmpVar bld oprSize
    bld <+ (op0 := (AST.loadBE oprSize addr))
    bld <+ (op1 := (AST.loadBE oprSize (addr .+ numI64 8 64<rt>)))
    setQFloatOp bld dst op0 op1
  | Opcode.LDFSR -> bld <+ ((AST.extract dst 32<rt> 0) :=
    (AST.loadBE 32<rt> addr))
  | Opcode.LDXFSR -> bld <+ (dst := (AST.loadBE oprSize addr))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let ldfa ins insLen bld =
  let struct (addr, asi, dst) = transAddrFourOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.LDFA -> bld <+ (dst := (AST.loadBE 32<rt> (addr .+ asi)))
  | Opcode.LDDFA ->
    let op = tmpVar bld oprSize
    bld <+ (op := (AST.loadBE oprSize (addr .+ asi)))
    setDFloatOp bld dst op
  | Opcode.LDQFA ->
    let op0 = tmpVar bld oprSize
    let op1 = tmpVar bld oprSize
    bld <+ (op0 := (AST.loadBE oprSize (addr .+ asi)))
    bld <+ (op1 := (AST.loadBE oprSize ((addr .+ asi) .+ numI64 8 64<rt>)))
    setQFloatOp bld dst op0 op1
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let ld ins insLen bld =
  let struct (addr, dst) = transAddrThreeOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.LDSB -> bld <+ (dst := (AST.sext oprSize (AST.loadBE 8<rt> addr)))
  | Opcode.LDSH -> bld <+ (dst := (AST.sext oprSize (AST.loadBE 16<rt> addr)))
  | Opcode.LDSW -> bld <+ (dst := (AST.sext oprSize (AST.loadBE 32<rt> addr)))
  | Opcode.LDUB -> bld <+ (dst := (AST.zext oprSize (AST.loadBE 8<rt> addr)))
  | Opcode.LDUH -> bld <+ (dst := (AST.zext oprSize (AST.loadBE 16<rt> addr)))
  | Opcode.LDUW -> bld <+ (dst := (AST.zext oprSize (AST.loadBE 32<rt> addr)))
  | Opcode.LDX -> bld <+ (dst := AST.loadBE oprSize addr)
  | Opcode.LDD ->
    if (dst = regVar bld Register.G0) then
      let nxt = regVar bld Register.G1
      bld <+ (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize addr) 32<rt> 32)))
    else
      let nxt = regVar bld (getNextReg bld dst)
      bld <+ (dst := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize addr) 32<rt> 0)))
      bld <+ (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize addr) 32<rt> 32)))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let lda ins insLen bld =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  let addr = src .+ src1
  match ins.Opcode with
  | Opcode.LDSBA -> bld <+ (dst := (AST.sext oprSize
                          (AST.loadBE 8<rt> (addr .+ asi))))
  | Opcode.LDSHA -> bld <+ (dst := (AST.sext oprSize
                          (AST.loadBE 16<rt> (addr .+ asi))))
  | Opcode.LDSWA -> bld <+ (dst := (AST.sext oprSize
                          (AST.loadBE 32<rt> (addr .+ asi))))
  | Opcode.LDUBA -> bld <+ (dst := (AST.zext oprSize
                          (AST.loadBE 8<rt> (addr .+ asi))))
  | Opcode.LDUHA -> bld <+ (dst := (AST.zext oprSize
                          (AST.loadBE 16<rt> (addr .+ asi))))
  | Opcode.LDUWA -> bld <+ (dst := (AST.zext oprSize
                          (AST.loadBE 32<rt> (addr .+ asi))))
  | Opcode.LDXA -> bld <+ (dst := AST.loadBE oprSize (addr .+ asi))
  | Opcode.LDDA ->
    if (dst = regVar bld Register.G0) then
      let nxt = regVar bld Register.G1
      bld <+ (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize (addr .+ asi)) 32<rt> 32)))
    else
      let nxt = regVar bld (getNextReg bld dst)
      bld <+ (dst := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize (addr .+ asi)) 32<rt> 0)))
      bld <+ (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize (addr .+ asi)) 32<rt> 32)))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let ldstub ins insLen bld =
  let struct (addr, dst) = transAddrThreeOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := (AST.zext oprSize (AST.loadBE 8<rt> addr)))
  bld <+ ((AST.loadBE 8<rt> addr) := (numI32 0xff 8<rt>))
  bld --!> insLen

let ldstuba ins insLen bld =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  let addr = src .+ src1
  bld <+ (dst := (AST.zext oprSize (AST.loadBE 8<rt> (addr .+ asi))))
  bld <+ ((AST.loadBE 8<rt> (addr .+ asi)) := (numI32 0xff 8<rt>))
  bld --!> insLen

let membar ins insLen bld = (* FIXME *)
  let mask = transOneOpr ins insLen bld
  let oprSize = 64<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := mask)
  bld --!> insLen

let movcc ins insLen bld =
  let struct (cc, src, dst) = transThreeOprs ins insLen bld
  let ccr = regVar bld Register.CCR
  let fsr = regVar bld Register.FSR
  bld <!-- (ins.Address, insLen)
  if (dst <> regVar bld Register.G0) then
    match ins.Opcode with
      | Opcode.MOVA | Opcode.MOVFA ->
        bld <+ (dst := src)
      | Opcode.MOVN | Opcode.MOVFN ->
        ()
      | Opcode.MOVNE ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let cond = (AST.extract ccr 1<rt> 2 == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract ccr 1<rt> 6 == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVE ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let cond = (AST.extract ccr 1<rt> 2 == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract ccr 1<rt> 6 == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVG ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let z = AST.extract ccr 1<rt> 2
          let v = AST.extract ccr 1<rt> 1
          let cond = ((z .| (n <+> v)) == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let z = AST.extract ccr 1<rt> 6
          let v = AST.extract ccr 1<rt> 5
          let cond = ((z .| (n <+> v)) == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVLE ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let z = AST.extract ccr 1<rt> 2
          let v = AST.extract ccr 1<rt> 1
          let cond = ((z .| (n <+> v)) == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let z = AST.extract ccr 1<rt> 6
          let v = AST.extract ccr 1<rt> 5
          let cond = ((z .| (n <+> v)) == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVGE ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let v = AST.extract ccr 1<rt> 1
          let cond = ((n <+> v) == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let v = AST.extract ccr 1<rt> 5
          let cond = ((n <+> v) == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVL ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let v = AST.extract ccr 1<rt> 1
          let cond = ((n <+> v) == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let v = AST.extract ccr 1<rt> 5
          let cond = ((n <+> v) == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVGU ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let z = AST.extract ccr 1<rt> 2
          let c = AST.extract ccr 1<rt> 0
          let cond = ((c .| z) == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let z = AST.extract ccr 1<rt> 6
          let c = AST.extract ccr 1<rt> 4
          let cond = ((c .| z) == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVLEU ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let z = AST.extract ccr 1<rt> 2
          let c = AST.extract ccr 1<rt> 0
          let cond = ((c .| z) == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let z = AST.extract ccr 1<rt> 6
          let c = AST.extract ccr 1<rt> 4
          let cond = ((c .| z) == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVCC ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let c = AST.extract ccr 1<rt> 0
          let cond = (c == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let c = AST.extract ccr 1<rt> 4
          let cond = (c == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVCS ->
        let ccr = regVar bld Register.CCR
        if (cc = getCCVar bld ConditionCode.Icc) then
          let c = AST.extract ccr 1<rt> 0
          let cond = (c == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let c = AST.extract ccr 1<rt> 4
          let cond = (c == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVPOS ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let cond = (n == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let cond = (n == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVNEG ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let cond = (n == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let cond = (n == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVVC ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let v = AST.extract ccr 1<rt> 1
          let cond = (v == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let v = AST.extract ccr 1<rt> 5
          let cond = (v == AST.b0)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVVS ->
        if (cc = getCCVar bld ConditionCode.Icc) then
          let v = AST.extract ccr 1<rt> 1
          let cond = (v == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let v = AST.extract ccr 1<rt> 5
          let cond = (v == AST.b1)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFU ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>))
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFG ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>))
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFUG ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFL ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>))
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFUL ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFLG ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFNE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | Opcode.MOVFE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>))
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFUE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFGE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFUGE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | Opcode.MOVFLE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFULE ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | Opcode.MOVFO ->
        if (cc = getCCVar bld ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar bld ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          bld <+ (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | _ ->
        raise InvalidOpcodeException
  bld --!> insLen

let movr ins insLen bld = (* TODO : check that destination is not g0*)
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.MOVRZ ->
    bld <+ (dst := AST.ite (src == AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRLEZ ->
    bld <+ (dst := AST.ite (src ?<= AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRLZ ->
    bld <+ (dst := AST.ite (src ?< AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRNZ ->
    bld <+ (dst := AST.ite (src != AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRGZ ->
    bld <+ (dst := AST.ite (src ?> AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRGEZ ->
    bld <+ (dst := AST.ite (src ?>= AST.num0 oprSize) (src1) (dst))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let mulscc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let src32 = tmpVar bld 32<rt>
  let y = regVar bld Register.Y
  let ccr = regVar bld Register.CCR
  let src2 = tmpVar bld 32<rt>
  let hbyte = tmpVar bld 4<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (src32 := AST.concat ((AST.extract ccr 1<rt> 3) <+>
    (AST.extract ccr 1<rt> 1)) (AST.extract src 31<rt> 1))
  bld <+ (src2 := AST.ite ((AST.extract y 1<rt> 0) == AST.b0)
    (AST.num0 32<rt>) (AST.extract src1 32<rt> 0))
  bld <+ (res := AST.zext 64<rt> (src32 .+ src2))
  if (dst <> regVar bld Register.G0) then
    bld <+ (dst := res)
  bld <+ ((AST.extract y 32<rt> 0) := AST.concat (AST.extract src 1<rt> 0)
    (AST.extract y 31<rt> 1))
  bld <+ (hbyte := getConditionCodeMulscc res src src1)
  bld <+ (AST.extract ccr 4<rt> 0 := hbyte)
  bld --!> insLen

let mulx ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := src .* src1)
  bld --!> insLen

let nop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let ``or`` ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .| src1)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen


let orcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .| src1)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeLog res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let orn ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (src .| AST.not (src1)))
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let orncc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := (src .| AST.not (src1)))
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeLog res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let popc ins insLen bld =
  let struct (src, dst) = transTwoOprs ins insLen bld
  let oprSize = 64<rt>
  let max = numI32 (RegType.toBitWidth oprSize) 64<rt>
  let lblLoop = label bld "Loop"
  let lblExit = label bld "Exit"
  let lblLoopCond = label bld "LoopCond"
  let struct (i, count) = tmpVars2 bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (i := AST.num0 oprSize)
  bld <+ (count := AST.num0 oprSize)
  bld <+ (AST.lmark lblLoopCond)
  bld <+ (AST.cjmp (AST.lt i max) (AST.jmpDest lblLoop) (AST.jmpDest lblExit))
  bld <+ (AST.lmark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  bld <+ (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  bld <+ (i := i .+ AST.num1 oprSize)
  bld <+ (AST.jmp (AST.jmpDest lblLoopCond))
  bld <+ (AST.lmark lblExit)
  bld <+ (dst := count)
  bld --!> insLen

let rd ins insLen bld =
  let struct (reg, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := reg)
  bld --!> insLen

let restore ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .+ src1)
  bld --!> insLen

let restored (ins: Instruction) insLen bld =
  let cs = regVar bld Register.CANSAVE
  let cr = regVar bld Register.CANRESTORE
  let ow = regVar bld Register.OTHERWIN
  bld <!-- (ins.Address, insLen)
  bld <+ (cs := (cs .+ AST.num1 64<rt>))
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  let cond = (ow == AST.num0 64<rt>)
  bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  bld <+ (cr := (cs .- AST.num1 64<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (ow := (ow .- AST.num1 64<rt>))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let ret ins insLen bld =
  let struct (src, src1) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld Register.PC := (src .+ src1))
  bld --!> insLen

let retry (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld <+ (regVar bld Register.PC := regVar bld Register.TPC)
  bld <+ (regVar bld Register.NPC := regVar bld Register.TNPC)
  bld --!> insLen

let save ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .+ src1)
  bld --!> insLen

let saved (ins: Instruction) insLen bld =
  let cs = regVar bld Register.CANSAVE
  let cr = regVar bld Register.CANRESTORE
  let ow = regVar bld Register.OTHERWIN
  bld <!-- (ins.Address, insLen)
  bld <+ (cs := (cs .+ AST.num1 64<rt>))
  let lblL0 = label bld "L0"
  let lblEnd = label bld "End"
  let cond = (ow == AST.num0 64<rt>)
  bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblL0)
  bld <+ (cr := (cr .- AST.num1 64<rt>))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (ow := (ow .- AST.num1 64<rt>))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let sdiv ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let divisor = tmpVar bld 32<rt>
  let dividend = tmpVar bld 64<rt>
  let quotient = tmpVar bld 64<rt>
  let y = regVar bld Register.Y
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  bld <+ (divisor := AST.extract src1 32<rt> 0)
  bld <+ (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen bld) then
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL1)
    if (dst <> regVar bld Register.G0) then
      bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
    bld <+ (AST.lmark lblEnd)
  else
    bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
  bld <+ (AST.extract ccr 4<rt> 4 := AST.num0 4<rt>)
  bld <+ (AST.extract ccr 1<rt> 3 := AST.ite
    ((AST.extract quotient 1<rt> 31) == AST.b1) (AST.b1) (AST.b0))
  bld <+ (AST.extract ccr 1<rt> 2 := AST.ite
    ((AST.extract quotient 32<rt> 0) == AST.num0 32<rt>) (AST.b1) (AST.b0))
  bld <+ (AST.extract ccr 1<rt> 0 := AST.b0)
  bld --!> insLen

let sdivcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let divisor = tmpVar bld 32<rt>
  let dividend = tmpVar bld 64<rt>
  let quotient = tmpVar bld 64<rt>
  let y = regVar bld Register.Y
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  bld <+ (divisor := AST.extract src1 32<rt> 0)
  bld <+ (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen bld) then
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL1)
    if (dst <> regVar bld Register.G0) then
      bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
    bld <+ (AST.lmark lblEnd)
  else
    bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
  bld <+ (AST.extract ccr 4<rt> 4 := AST.num0 4<rt>)
  bld <+ (AST.extract ccr 1<rt> 3 := AST.ite
    ((AST.extract quotient 1<rt> 31) == AST.b1) (AST.b1) (AST.b0))
  bld <+ (AST.extract ccr 1<rt> 2 := AST.ite
    ((AST.extract quotient 32<rt> 0) == AST.num0 32<rt>) (AST.b1) (AST.b0))
  bld <+ (AST.extract ccr 1<rt> 0 := AST.b0)
  bld --!> insLen

let sdivx ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let cond = (src1 == AST.num0 64<rt>)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  if (src1 = AST.num0 64<rt> || src1 = regVar bld Register.G0) then
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen bld) then
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL1)
    if (dst = regVar bld Register.G0) then
      bld <+ (dst := AST.num0 64<rt>)
    else
      bld <+ (dst := src ?/ src1)
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
    bld <+ (AST.lmark lblEnd)
  else
    if (dst = regVar bld Register.G0) then
      bld <+ (dst := AST.num0 64<rt>)
    else
      bld <+ (dst := src ?/ src1)
  bld --!> insLen

let sethi ins insLen bld =
  let struct (imm, dst) = transTwoOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  if (dst <> regVar bld Register.G0) then
    bld <+ (dst := AST.concat (AST.zext 32<rt> AST.b0)
      (AST.extract imm 32<rt> 0))
  bld --!> insLen

let sll ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := src << src1)
  bld --!> insLen

let smul ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let yreg  = regVar bld Register.Y
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := AST.sext 64<rt> ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    bld <+ (AST.extract yreg 64<rt> 0 := AST.zext 64<rt>
      (AST.extract dst 32<rt> 32))
  bld --!> insLen

let smulcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let yreg  = regVar bld Register.Y
  let ccr  = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := AST.sext 64<rt> ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    bld <+ (AST.extract yreg 64<rt> 0 := AST.zext 64<rt>
      (AST.extract dst 32<rt> 32))
    bld <+ (byte := (getConditionCodeMul dst src src1))
    bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let sra ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := src ?>> src1)
  bld --!> insLen

let srl ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := src >> src1)
  bld --!> insLen

let st ins insLen bld =
  let struct (src, addr) = transTwooprsAddr ins insLen bld
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.STB ->
    bld <+ ((AST.loadBE 8<rt> addr) := (AST.extract src 8<rt> 0))
  | Opcode.STH ->
    bld <+ ((AST.loadBE 16<rt> addr) := (AST.extract src 16<rt> 0))
  | Opcode.STW ->
    bld <+ ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
  | Opcode.STX ->
    bld <+ ((AST.loadBE 64<rt> addr) := (AST.extract src 64<rt> 0))
  | Opcode.STD ->
    if (src = regVar bld Register.G0) then
      bld <+ ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
    else
      let nxt = regVar bld (getNextReg bld src)
      bld <+ ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
      bld <+ ((AST.loadBE 32<rt> (addr .+ numI64 4 64<rt>)) :=
        (AST.extract nxt 32<rt> 0))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let sta ins insLen bld =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  let addr = src .+ src1
  match ins.Opcode with
  | Opcode.STBA ->
    bld <+ ((AST.loadBE 8<rt> (addr .+ asi)) := (AST.extract src 8<rt> 0))
  | Opcode.STHA ->
    bld <+ ((AST.loadBE 16<rt> (addr .+ asi)) := (AST.extract src 16<rt> 0))
  | Opcode.STWA ->
    bld <+ ((AST.loadBE 32<rt> (addr .+ asi)) := (AST.extract src 32<rt> 0))
  | Opcode.STXA ->
    bld <+ ((AST.loadBE 64<rt> (addr .+ asi)) := (AST.extract src 64<rt> 0))
  | Opcode.STDA ->
    if (src = regVar bld Register.G0) then
      bld <+ ((AST.loadBE 32<rt> (addr .+ asi)) := (AST.extract src 32<rt> 0))
    else
      let nxt = regVar bld (getNextReg bld src)
      bld <+ ((AST.loadBE 32<rt> (addr .+ asi)) := (AST.extract src 32<rt> 0))
      bld <+ ((AST.loadBE 32<rt> ((addr .+ asi) .+ numI64 4 64<rt>)) :=
        (AST.extract nxt 32<rt> 0))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let stf ins insLen bld =
  let struct (src, addr) = transTwooprsAddr ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  match ins.Opcode with
  | Opcode.STF ->
    bld <+ ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
  | Opcode.STDF ->
    let op = tmpVar bld oprSize
    getDFloatOp bld src op
    bld <+ ((AST.loadBE 64<rt> addr) := (AST.extract op 64<rt> 0))
  | Opcode.STQF ->
    let op0 = tmpVar bld oprSize
    let op1 = tmpVar bld oprSize
    getQFloatOp bld src op0 op1
    bld <+ ((AST.loadBE 64<rt> addr) := (AST.extract op0 64<rt> 0))
    bld <+ ((AST.loadBE 64<rt> (addr .+ numI64 8 64<rt>)) :=
      (AST.extract op1 64<rt> 0))
  | Opcode.STFSR ->
    bld <+ ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
  | Opcode.STXFSR ->
    bld <+ ((AST.loadBE 64<rt> addr) := src)
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let stfa ins insLen bld =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen bld
  let oprSize = 64<rt>
  bld <!-- (ins.Address, insLen)
  let addr = dst .+ src1 .+ asi
  match ins.Opcode with
  | Opcode.STFA -> bld <+ ((AST.loadBE 32<rt> (addr)) :=
                        (AST.extract src 32<rt> 0))
  | Opcode.STDFA ->
    let op = tmpVar bld oprSize
    getDFloatOp bld src op
    bld <+ ((AST.loadBE 64<rt> (addr)) :=
          (AST.extract op 64<rt> 0))
  | Opcode.STQFA ->
    let op0 = tmpVar bld oprSize
    let op1 = tmpVar bld oprSize
    getQFloatOp bld src op0 op1
    bld <+ ((AST.loadBE 64<rt> (addr)) := (AST.extract op0 64<rt> 0))
    bld <+ ((AST.loadBE 64<rt> ((addr) .+ numI64 8 64<rt>)) :=
      (AST.extract op1 64<rt> 0))
  | _ -> raise InvalidOpcodeException
  bld --!> insLen

let sub ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .- src1)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let subcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .- src1)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeSub res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen


let subC ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .- src1 .- AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let subCcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src .- src1 .- AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeSub res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let swap ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let addr = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (addr := (src .+ src1))
  bld <+ (dst := (AST.zext oprSize (AST.loadBE 32<rt> addr)))
  bld --!> insLen

let swapa ins insLen bld =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen bld
  let oprSize = 64<rt>
  let struct (t1, t2) = tmpVars2 bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := (AST.zext oprSize (AST.loadBE 32<rt> (src .+ src1 .+ asi))))
  bld --!> insLen

let udiv ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let divisor = tmpVar bld 32<rt>
  let dividend = tmpVar bld 64<rt>
  let quotient = tmpVar bld 64<rt>
  let y = regVar bld Register.Y
  bld <!-- (ins.Address, insLen)
  bld <+ (divisor := AST.extract src1 32<rt> 0)
  bld <+ (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen bld) then
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL1)
    if (dst <> regVar bld Register.G0) then
      bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
    bld <+ (AST.lmark lblEnd)
  else
    bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
  bld --!> insLen

let udivcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  let divisor = tmpVar bld 32<rt>
  let dividend = tmpVar bld 64<rt>
  let quotient = tmpVar bld 64<rt>
  let y = regVar bld Register.Y
  let ccr = regVar bld Register.CCR
  bld <!-- (ins.Address, insLen)
  bld <+ (divisor := AST.extract src1 32<rt> 0)
  bld <+ (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1 = regVar bld Register.G0) then
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen bld) then
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL1)
    if (dst <> regVar bld Register.G0) then
      bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
    bld <+ (AST.lmark lblEnd)
  else
    bld <+ (quotient := dividend ./ (AST.zext 64<rt> divisor))
    bld <+ (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    bld <+ (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
  bld <+ (AST.extract ccr 4<rt> 4 := AST.num0 4<rt>)
  bld <+ (AST.extract ccr 1<rt> 3 := AST.ite
    ((AST.extract quotient 1<rt> 31) == AST.b1) (AST.b1) (AST.b0))
  bld <+ (AST.extract ccr 1<rt> 2 := AST.ite
    ((AST.extract quotient 32<rt> 0) == AST.num0 32<rt>) (AST.b1) (AST.b0))
  bld <+ (AST.extract ccr 1<rt> 0 := AST.b0)
  bld --!> insLen

let udivx ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let cond = (src1 == AST.num0 64<rt>)
  let lblL0 = label bld "L0"
  let lblL1 = label bld "L1"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  if (src1 = AST.num0 64<rt> || src1 = regVar bld Register.G0) then
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen bld) then
    bld <+ (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    bld <+ (AST.lmark lblL1)
    if (dst = regVar bld Register.G0) then
      bld <+ (dst := AST.num0 64<rt>)
    else
      bld <+ (dst := src ./ src1)
    bld <+ (AST.jmp (AST.jmpDest lblEnd))
    bld <+ (AST.lmark lblL0)
    bld <+ (AST.sideEffect (Exception "Division by zero exception"))
    bld <+ (AST.lmark lblEnd)
  else
    if (dst = regVar bld Register.G0) then
      bld <+ (dst := AST.num0 64<rt>)
    else
      bld <+ (dst := src ./ src1)
  bld --!> insLen

let umul ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let yreg  = regVar bld Register.Y
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := AST.zext 64<rt> ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    bld <+ (AST.extract yreg 64<rt> 0 :=
      AST.zext 64<rt> (AST.extract dst 32<rt> 32))
  bld --!> insLen

let umulcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let yreg  = regVar bld Register.Y
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := AST.zext 64<rt> ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    bld <+ (AST.extract yreg 64<rt> 0 :=
      AST.zext 64<rt> (AST.extract dst 32<rt> 32))
    bld <+ (byte := (getConditionCodeMul dst src src1))
    bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let wr ins insLen bld =
  let struct (src, src1, reg) = transThreeOprs ins insLen bld
  bld <!-- (ins.Address, insLen)
  bld <+ (reg := src <+> src1)
  bld --!> insLen

let xor ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src <+> src1)
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let xorcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src <+> src1)
  bld <+ (byte := (getConditionCodeLog res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen

let xnor ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src <+> AST.not (src1))
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld --!> insLen

let xnorcc ins insLen bld =
  let struct (src, src1, dst) = transThreeOprs ins insLen bld
  let oprSize = 64<rt>
  let res = tmpVar bld oprSize
  let ccr = regVar bld Register.CCR
  let byte = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (res := src <+> AST.not (src1))
  if (dst = regVar bld Register.G0) then
    bld <+ (dst := AST.num0 64<rt>)
  else
    bld <+ (dst := res)
  bld <+ (byte := (getConditionCodeLog res src src1))
  bld <+ (AST.extract ccr 8<rt> 0 := byte)
  bld --!> insLen
