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
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.SPARC

let inline getRegVar (ctxt: TranslationContext) reg =
  Register.toRegID reg |> ctxt.GetRegVar

let inline numI32 n t = BitVector.OfInt32 n t |> AST.num

let inline numI32PC n = BitVector.OfInt32 n 64<rt> |> AST.num

let inline numU32 n t = BitVector.OfUInt32 n t |> AST.num

let inline numU64 n t = BitVector.OfUInt64 n t |> AST.num

let inline numI64 n t = BitVector.OfInt64 n t |> AST.num

let inline tmpVars2 ir t =
  struct (!+ir t, !+ir t)

let inline ( !. ) (ctxt: TranslationContext) reg =
  Register.toRegID reg |> ctxt.GetRegVar

let inline getCCVar (ctxt: TranslationContext) name =
  ConditionCode.toRegID name |> ctxt.GetRegVar

let dstAssign oprSize dst src =
  match oprSize with
  | 8<rt> | 16<rt> -> dst := src (* No extension for 8- and 16-bit operands *)
  | _ -> let dst = AST.unwrap dst
         let dstOrigSz = dst |> TypeCheck.typeOf
         let oprBitSize = RegType.toBitWidth oprSize
         let dstBitSize = RegType.toBitWidth dstOrigSz
         if dstBitSize > oprBitSize then dst := AST.zext dstOrigSz src
         elif dstBitSize = oprBitSize then dst := src
         else raise InvalidOperandSizeException

let private cfOnAdd e1 r = AST.lt r e1

let private ofOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  (e1High .& e2High .& (AST.neg rHigh))
    .| ((AST.neg e1High) .& (AST.neg e2High) .& rHigh)

let transOprToExpr ins insLen ctxt = function
  | OprReg reg -> !.ctxt reg
  | OprImm imm -> numI32 imm 64<rt>
  | OprAddr addr -> numI32PC addr
  | OprCC cc -> getCCVar ctxt cc
  | OprPriReg prireg -> !.ctxt prireg
  | _ -> Terminator.impossible ()

let isRegOpr ins insLen ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    match o2 with
    | OprReg reg -> true
    | _ -> false
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

let transOneOpr (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | OneOperand o1 -> transOprToExpr ins insLen ctxt o1
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2,
            transOprToExpr ins insLen ctxt o3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2,
            transOprToExpr ins insLen ctxt o3,
            transOprToExpr ins insLen ctxt o4)
  | _ -> raise InvalidOperandException

let transAddrThreeOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen ctxt o1 .+
            transOprToExpr ins insLen ctxt o2,
            transOprToExpr ins insLen ctxt o3)
  | _ -> raise InvalidOperandException

let transAddrFourOprs (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins insLen ctxt o1 .+
            transOprToExpr ins insLen ctxt o2,
            transOprToExpr ins insLen ctxt o3,
            transOprToExpr ins insLen ctxt o4)
  | _ -> raise InvalidOperandException

let transTwooprsAddr (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2 .+
            transOprToExpr ins insLen ctxt o3)
  | _ -> raise InvalidOperandException

let transThroprsAddr (ins: InsInfo) insLen ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins insLen ctxt o1,
            transOprToExpr ins insLen ctxt o2 .+
            transOprToExpr ins insLen ctxt o3,
            transOprToExpr ins insLen ctxt o4)
  | _ -> raise InvalidOperandException

let inline tmpVars3 ir t =
  struct (!+ir t, !+ir t, !+ir t)

let inline tmpVars4 ir t =
  struct (!+ir t, !+ir t, !+ir t, !+ir t)

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
  let iccn = (ressign32)
  let iccz = ((res32) == AST.num0 32<rt>)
  let iccv = ((sign32 .& sign321 .& AST.not ressign32) .|
    (AST.not sign32 .& AST.not sign321 .& ressign32))
  let iccc = (sign32 .& sign321) .| ((AST.not ressign32)
    .& (sign32 .| sign321))
  AST.revConcat [| iccc; iccv; iccz; iccn |]

let getNextReg ctxt reg =
  if (reg = getRegVar ctxt Register.G0) then Register.G1
  elif (reg = getRegVar ctxt Register.G2) then Register.G3
  elif (reg = getRegVar ctxt Register.G4) then Register.G5
  elif (reg = getRegVar ctxt Register.G6) then Register.G7
  elif (reg = getRegVar ctxt Register.O0) then Register.O1
  elif (reg = getRegVar ctxt Register.O2) then Register.O3
  elif (reg = getRegVar ctxt Register.O4) then Register.O5
  elif (reg = getRegVar ctxt Register.O6) then Register.O7
  elif (reg = getRegVar ctxt Register.L0) then Register.L1
  elif (reg = getRegVar ctxt Register.L2) then Register.L3
  elif (reg = getRegVar ctxt Register.L4) then Register.L5
  elif (reg = getRegVar ctxt Register.L6) then Register.L7
  elif (reg = getRegVar ctxt Register.I0) then Register.I1
  elif (reg = getRegVar ctxt Register.I2) then Register.I3
  elif (reg = getRegVar ctxt Register.I4) then Register.I5
  elif (reg = getRegVar ctxt Register.I6) then Register.I7
  else raise InvalidRegisterException

let getFloatClass ctxt freg =
  if (freg = getRegVar ctxt Register.F0 || freg = getRegVar ctxt Register.F2
    || freg = getRegVar ctxt Register.F4 || freg = getRegVar ctxt Register.F6
    || freg = getRegVar ctxt Register.F8|| freg = getRegVar ctxt Register.F10
    || freg = getRegVar ctxt Register.F12 || freg = getRegVar ctxt Register.F14
    || freg = getRegVar ctxt Register.F16 || freg = getRegVar ctxt Register.F18
    || freg = getRegVar ctxt Register.F20 || freg = getRegVar ctxt Register.F22
    || freg = getRegVar ctxt Register.F24 || freg = getRegVar ctxt Register.F26
    || freg = getRegVar ctxt Register.F28 || freg = getRegVar ctxt Register.F30)
  then 0
  elif (freg = getRegVar ctxt Register.F32 || freg = getRegVar ctxt Register.F34
  || freg = getRegVar ctxt Register.F36 || freg = getRegVar ctxt Register.F38
    || freg = getRegVar ctxt Register.F40 || freg = getRegVar ctxt Register.F42
    || freg = getRegVar ctxt Register.F44 || freg = getRegVar ctxt Register.F46
    || freg = getRegVar ctxt Register.F48 || freg = getRegVar ctxt Register.F50
    || freg = getRegVar ctxt Register.F52 || freg = getRegVar ctxt Register.F54
    || freg = getRegVar ctxt Register.F56 || freg = getRegVar ctxt Register.F58
    || freg = getRegVar ctxt Register.F60 || freg = getRegVar ctxt Register.F62)
  then 1
  else raise InvalidRegisterException

let getDFloatNext ctxt freg =
  if (freg = getRegVar ctxt Register.F0) then Register.F1
  elif (freg = getRegVar ctxt Register.F2) then Register.F3
  elif (freg = getRegVar ctxt Register.F4) then Register.F5
  elif (freg = getRegVar ctxt Register.F6) then Register.F7
  elif (freg = getRegVar ctxt Register.F8) then Register.F9
  elif (freg = getRegVar ctxt Register.F10) then Register.F11
  elif (freg = getRegVar ctxt Register.F12) then Register.F13
  elif (freg = getRegVar ctxt Register.F14) then Register.F15
  elif (freg = getRegVar ctxt Register.F16) then Register.F17
  elif (freg = getRegVar ctxt Register.F18) then Register.F19
  elif (freg = getRegVar ctxt Register.F20) then Register.F21
  elif (freg = getRegVar ctxt Register.F22) then Register.F23
  elif (freg = getRegVar ctxt Register.F24) then Register.F25
  elif (freg = getRegVar ctxt Register.F26) then Register.F27
  elif (freg = getRegVar ctxt Register.F28) then Register.F29
  elif (freg = getRegVar ctxt Register.F30) then Register.F31
  else raise InvalidRegisterException

let movFregD ctxt ir src dst =
  let sClass = getFloatClass ctxt src
  let dClass = getFloatClass ctxt dst
  match sClass, dClass with
  | 0, 0 ->
    let nextsrc = getRegVar ctxt (getDFloatNext ctxt src)
    let nextdst = getRegVar ctxt (getDFloatNext ctxt dst)
    !!ir (dst := src)
    !!ir (nextdst := nextsrc)
  | 0, 1 ->
    let nextsrc = getRegVar ctxt (getDFloatNext ctxt src)
    !!ir (AST.extract dst 32<rt> 0 := nextsrc)
    !!ir (AST.extract dst 32<rt> 32 := src)
  | 1, 0 ->
    let nextdst = getRegVar ctxt (getDFloatNext ctxt dst)
    !!ir (dst := AST.extract src 32<rt> 32)
    !!ir (nextdst := AST.extract src 32<rt> 0)
  | 1, 1 ->
    !!ir (dst := src)
  | _ -> raise InvalidRegisterException

let getQFloatNext0 ctxt freg =
  if (freg = getRegVar ctxt Register.F0) then
    struct (Register.F1, Register.F2, Register.F3)
  elif (freg = getRegVar ctxt Register.F4) then
    struct (Register.F5, Register.F6, Register.F7)
  elif (freg = getRegVar ctxt Register.F8) then
    struct (Register.F9, Register.F10, Register.F11)
  elif (freg = getRegVar ctxt Register.F12) then
    struct (Register.F13, Register.F14, Register.F15)
  elif (freg = getRegVar ctxt Register.F16) then
    struct (Register.F17, Register.F18, Register.F19)
  elif (freg = getRegVar ctxt Register.F20) then
    struct (Register.F21, Register.F22, Register.F23)
  elif (freg = getRegVar ctxt Register.F24) then
    struct (Register.F25, Register.F26, Register.F27)
  elif (freg = getRegVar ctxt Register.F28) then
    struct (Register.F29, Register.F30, Register.F31)
  else raise InvalidRegisterException

let getQFloatNext1 ctxt freg =
  if (freg = getRegVar ctxt Register.F32) then Register.F34
  elif (freg = getRegVar ctxt Register.F36) then Register.F38
  elif (freg = getRegVar ctxt Register.F40) then Register.F42
  elif (freg = getRegVar ctxt Register.F44) then Register.F46
  elif (freg = getRegVar ctxt Register.F48) then Register.F50
  elif (freg = getRegVar ctxt Register.F52) then Register.F54
  elif (freg = getRegVar ctxt Register.F56) then Register.F58
  elif (freg = getRegVar ctxt Register.F60) then Register.F62
  else raise InvalidRegisterException

let movFregQ ctxt ir src dst =
  let sClass = getFloatClass ctxt src
  let dClass = getFloatClass ctxt dst
  match sClass, dClass with
  | 0, 0 ->
    let struct (s1, s2, s3) = getQFloatNext0 ctxt src
    let src1 = getRegVar ctxt s1
    let src2 = getRegVar ctxt s2
    let src3 = getRegVar ctxt s3
    let struct (d1, d2, d3) = getQFloatNext0 ctxt dst
    let dst1 = getRegVar ctxt d1
    let dst2 = getRegVar ctxt d2
    let dst3 = getRegVar ctxt d3
    !!ir (dst := src)
    !!ir (dst1 := src1)
    !!ir (dst2 := src2)
    !!ir (dst3 := src3)
  | 0, 1 ->
    let struct (s1, s2, s3) = getQFloatNext0 ctxt src
    let src1 = getRegVar ctxt s1
    let src2 = getRegVar ctxt s2
    let src3 = getRegVar ctxt s3
    let nextdst = getRegVar ctxt (getQFloatNext1 ctxt dst)
    !!ir (AST.extract nextdst 32<rt> 0 := src3)
    !!ir (AST.extract nextdst 32<rt> 32 := src2)
    !!ir (AST.extract dst 32<rt> 0 := src1)
    !!ir (AST.extract dst 32<rt> 32 := src)
  | 1, 0 ->
    let nextsrc = getRegVar ctxt (getQFloatNext1 ctxt src)
    let struct (d1, d2, d3) = getQFloatNext0 ctxt dst
    let dst1 = getRegVar ctxt d1
    let dst2 = getRegVar ctxt d2
    let dst3 = getRegVar ctxt d3
    !!ir (dst := AST.extract src 32<rt> 32)
    !!ir (dst1 := AST.extract src 32<rt> 0)
    !!ir (dst2 := AST.extract nextsrc 32<rt> 32)
    !!ir (dst3 := AST.extract nextsrc 32<rt> 0)
  | 1, 1 ->
    let nextsrc = getRegVar ctxt (getQFloatNext1 ctxt src)
    let nextdst = getRegVar ctxt (getQFloatNext1 ctxt dst)
    !!ir (nextdst := nextsrc)
    !!ir (dst := src)
  | _ -> raise InvalidRegisterException

let getDFloatOp ctxt ir src op =
  let regclass = getFloatClass ctxt src
  match regclass with
  | 0 ->
    let nextreg = getRegVar ctxt (getDFloatNext ctxt src)
    !!ir ((AST.extract op 32<rt> 32) := src)
    !!ir ((AST.extract op 32<rt> 0) := nextreg)
  | 1 ->
    !!ir (op := src)
  | _ -> raise InvalidRegisterException

let getQFloatOp ctxt ir src op1 op2 =
  let regclass = getFloatClass ctxt src
  match regclass with
  | 0 ->
    let struct (r1, r2, r3) = getQFloatNext0 ctxt src
    let src1 = getRegVar ctxt r1
    let src2 = getRegVar ctxt r2
    let src3 = getRegVar ctxt r3
    !!ir ((AST.extract op1 32<rt> 32) := src)
    !!ir ((AST.extract op1 32<rt> 0) := src1)
    !!ir ((AST.extract op2 32<rt> 32) := src2)
    !!ir ((AST.extract op2 32<rt> 0) := src3)
  | 1 ->
    let r1 = getQFloatNext1 ctxt src
    let src1 = getRegVar ctxt r1
    !!ir ((AST.extract op1 64<rt> 0) := src)
    !!ir ((AST.extract op2 64<rt> 0) := src1)
  | _ -> raise InvalidRegisterException

let setDFloatOp ctxt ir dst res =
  let regclass = getFloatClass ctxt dst
  match regclass with
  | 0 ->
    let nextreg = getRegVar ctxt (getDFloatNext ctxt dst)
    !!ir (dst := (AST.extract res 32<rt> 32))
    !!ir (nextreg := (AST.extract res 32<rt> 0))
  | 1 ->
    !!ir (dst := res)
  | _ -> raise InvalidRegisterException

let setQFloatOp ctxt ir dst res1 res2 =
  let regclass = getFloatClass ctxt dst
  match regclass with
  | 0 ->
    let struct (r1, r2, r3) = getQFloatNext0 ctxt dst
    let dst1 = getRegVar ctxt r1
    let dst2 = getRegVar ctxt r2
    let dst3 = getRegVar ctxt r3
    !!ir (dst := (AST.extract res1 32<rt> 32))
    !!ir (dst1 := (AST.extract res1 32<rt> 0))
    !!ir (dst2 := (AST.extract res2 32<rt> 32))
    !!ir (dst3 := (AST.extract res2 32<rt> 0))
  | 1 ->
    let r1 = getQFloatNext1 ctxt dst
    let dst1 = getRegVar ctxt r1
    !!ir (dst := (AST.extract res1 64<rt> 0))
    !!ir (dst1 := (AST.extract res2 64<rt> 0) )
  | _ -> raise InvalidRegisterException

let cast64To128 ctxt ir src dst1 dst2 =
  let oprSize = 64<rt>
  let zero = AST.num0 64<rt>
  let tmpSrc = !+ir oprSize
  let n63 = numI32 63 64<rt>
  let n15 = numI32 15 16<rt>
  let n52 = numI32 52 64<rt>
  let one = numI32 1 64<rt>
  let n60 = numI32 60 64<rt>
  let final = !+ir 52<rt>
  let biasDiff = numI32 0x3c00 16<rt>
  let sign = (AST.xtlo 16<rt> (((src >> n63) .& one))) << n15
  let exponent =
    (AST.xtlo 16<rt> (((src>> n52) .& (numI32 0x7ff 64<rt>)))) .+ biasDiff
  let integerpart = numI64 0x0010000000000000L 64<rt>
  let significand = src .& numI64 0xFFFFFFFFFFFFFL 64<rt> .| integerpart
  !!ir (AST.extract dst1 16<rt> 48 := AST.ite (AST.eq src zero)
    (AST.num0 16<rt>) (sign .| exponent))
  !!ir (final := AST.ite (AST.eq tmpSrc zero)
    (AST.num0 52<rt>) (AST.extract significand 52<rt> 0))
  !!ir (AST.extract dst1 48<rt> 0 := (AST.extract final 48<rt> 4))
  !!ir (AST.extract dst2 4<rt> 60 := (AST.extract final 4<rt> 0))
  !!ir (AST.extract dst2 60<rt> 4 := AST.num0 60<rt>)

let cast128to64 ctxt ir src1 src2 dst =
  let n48 = numI32 48 64<rt>
  let n63 = numI32 63 64<rt>
  let top16b = AST.extract src1 16<rt> 48
  let sign = (AST.zext 64<rt> top16b .& (numI32 0x8000 64<rt>)) << n48
  let biasDiff = numI32 0x3c00 64<rt>
  let tmpExp = !+ir 64<rt>
  let significand = !+ir 64<rt>
  let computedExp =
    (AST.zext 64<rt> (top16b .& (numI32 0x7fff 16<rt>)) .- biasDiff)
  let maxExp = numI32 0x7fe 64<rt>
  let exponent =
    AST.ite (AST.eq top16b (AST.num0 16<rt>))
      (AST.num0 64<rt>)
      (AST.ite (AST.gt tmpExp maxExp) maxExp tmpExp)
  let exponent = exponent << numI32 52 64<rt>
  let n11 = numI32 11 64<rt>
  !!ir (AST.extract significand 16<rt> 48 := AST.extract src1 16<rt> 32)
  !!ir (AST.extract significand 32<rt> 0 := AST.extract src2 32<rt> 32)
  !!ir (tmpExp := computedExp)
  !!ir (dst := (sign .| exponent .| significand))

let add ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src .+ src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let addcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .+ src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeAdd res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let addC ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  !<ir insLen
  !!ir (res := src .+ src1 .+ AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let addCcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .+ src1 .+ AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeAdd res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let ``and`` ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src .& src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let andcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = !.ctxt Register.CCR
  let res = !+ir oprSize
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .& src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeLog res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let andn ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src .& (AST.not src1))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let andncc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = !.ctxt Register.CCR
  let res = !+ir oprSize
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .& (AST.not src1))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeLog res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let branchpr ins insLen ctxt =
  let ir = IRBuilder (16)
  let oprSize = 64<rt>
  let struct (src, label, an, pr) = transFourOprs ins insLen ctxt
  let pc = !.ctxt Register.PC
  !<ir insLen
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
    if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
    else numI32PC 0
  let fallThrough = pc .+ numI32PC 4 .+ annoffset
  let jumpTarget = pc .+ AST.zext 64<rt> label
  !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir insLen

let branchicc ins insLen ctxt =
  let ir = IRBuilder (16)
  let oprSize = 64<rt>
  let struct (an, label) = transTwoOprs ins insLen ctxt
  let pc = !.ctxt Register.PC
  let ccr = !.ctxt Register.CCR
  !<ir insLen
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
  if (ins.Opcode = Opcode.BA) then
    !!ir (AST.interjmp jumpTarget InterJmpKind.Base)
    !>ir insLen
  elif (ins.Opcode = Opcode.BN) then
    !>ir insLen
  else
    !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
    !>ir insLen

let branchpcc ins insLen ctxt =
  let ir = IRBuilder (16)
  let oprSize = 64<rt>
  let struct (cc, label, an, pr) = transFourOprs ins insLen ctxt
  let pc = !.ctxt Register.PC
  let ccr = !.ctxt Register.CCR
  !<ir insLen
  let branchCond =
    match ins.Opcode with
    | Opcode.BPA -> (AST.b1)
    | Opcode.BPN -> (AST.b0)
    | Opcode.BPNE ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 2 == AST.b0)
      else
        (AST.extract ccr 1<rt> 4 == AST.b0)
    | Opcode.BPE ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 2 == AST.b1)
      else
        (AST.extract ccr 1<rt> 6 == AST.b1)
    | Opcode.BPG ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
          (AST.extract ccr 1<rt> 3))) == AST.b0)
      else
        (((AST.extract ccr 1<rt> 6) .| ((AST.extract ccr 1<rt> 5) <+>
          (AST.extract ccr 1<rt> 7))) == AST.b0)
    | Opcode.BPLE ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (((AST.extract ccr 1<rt> 2) .| ((AST.extract ccr 1<rt> 1) <+>
          (AST.extract ccr 1<rt> 3))) == AST.b1)
      else
        (((AST.extract ccr 1<rt> 6) .| ((AST.extract ccr 1<rt> 5) <+>
          (AST.extract ccr 1<rt> 7))) == AST.b1)
    | Opcode.BPGE ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
      else
        ((AST.extract ccr 1<rt> 5) <+> (AST.extract ccr 1<rt> 7) == AST.b1)
    | Opcode.BPL ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 1) <+> (AST.extract ccr 1<rt> 3) == AST.b1)
      else
        ((AST.extract ccr 1<rt> 5) <+> (AST.extract ccr 1<rt> 7) == AST.b1)
    | Opcode.BPGU ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b0)
      else
        ((AST.extract ccr 1<rt> 4) .| (AST.extract ccr 1<rt> 6) == AST.b0)
    | Opcode.BPLEU ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        ((AST.extract ccr 1<rt> 0) .| (AST.extract ccr 1<rt> 2) == AST.b1)
      else
        ((AST.extract ccr 1<rt> 4) .| (AST.extract ccr 1<rt> 6) == AST.b1)
    | Opcode.BPCC ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 0 == AST.b0)
      else
        (AST.extract ccr 1<rt> 4 == AST.b0)
    | Opcode.BPCS ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 0 == AST.b1)
      else
        (AST.extract ccr 1<rt> 4 == AST.b1)
    | Opcode.BPPOS ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 3 == AST.b0)
      else
        (AST.extract ccr 1<rt> 7 == AST.b0)
    | Opcode.BPNEG ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 3 == AST.b1)
      else
        (AST.extract ccr 1<rt> 7 == AST.b1)
    | Opcode.BPVC ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
        (AST.extract ccr 1<rt> 1 == AST.b0)
      else
        (AST.extract ccr 1<rt> 5 == AST.b0)
    | Opcode.BPVS ->
      if (cc = getCCVar ctxt ConditionCode.Icc) then
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
    !!ir (AST.interjmp jumpTarget InterJmpKind.Base)
    !>ir insLen
  elif (ins.Opcode = Opcode.BPN) then
    !>ir insLen
  else
    !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
    !>ir insLen

let call ins insLen ctxt =
  let ir = IRBuilder (16)
  let dst = transOneOpr ins insLen ctxt
  let sp = !.ctxt Register.O7
  let pc = !.ctxt Register.PC
  !<ir insLen
  !!ir (sp := pc)
  !!ir (pc := pc .+ dst)
  !>ir insLen

let casa ins insLen ctxt =
  let struct (src, asi, src1, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let cond = ((AST.extract src1 32<rt> 0) == (AST.loadBE 32<rt> (src .+ asi)))
  !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (AST.loadBE 32<rt> (src .+ asi) := AST.extract src1 32<rt> 0)
  !!ir (AST.lmark lblEnd)
  !!ir (AST.extract dst 32<rt> 0 := AST.extract src1 32<rt> 0)
  !!ir (AST.extract dst 32<rt> 32 := AST.num0 32<rt>)
  !>ir insLen

let casxa ins insLen ctxt =
  let struct (src, asi, src1, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let cond = (src1 == AST.loadBE 64<rt> (src .+ asi))
  !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (AST.loadBE 64<rt> (src .+ asi) := dst)
  !!ir (AST.lmark lblEnd)
  !!ir (dst := src1)
  !>ir insLen

let ``done`` ins insLen ctxt =
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (!.ctxt Register.PC := !.ctxt Register.TNPC)
  !!ir (!.ctxt Register.NPC := !.ctxt Register.TNPC .+ numI32PC 4)
  !>ir insLen

let fabss ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (AST.extract dst 1<rt> 31 := AST.b0)
  !!ir (AST.extract dst 31<rt> 0 := AST.extract src 31<rt> 0)
  !>ir insLen

let fabsd ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let op = !+ir oprSize
  let res = !+ir oprSize
  !<ir insLen
  getDFloatOp ctxt ir src op
  !!ir (AST.extract res 1<rt> 63 := AST.b0)
  !!ir (AST.extract res 63<rt> 0 := AST.extract op 63<rt> 0)
  setDFloatOp ctxt ir dst res
  !>ir insLen

let fabsq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let op1 = !+ir oprSize
  let op2 = !+ir oprSize
  let res1 = !+ir oprSize
  let res2 = !+ir oprSize
  !<ir insLen
  getQFloatOp ctxt ir src op1 op2
  !!ir (AST.extract res1 1<rt> 63 := AST.b0)
  !!ir (AST.extract res1 63<rt> 0 := AST.extract op1 63<rt> 0)
  !!ir (AST.extract res2 64<rt> 0 := AST.extract op2 64<rt> 0)
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fmovs ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let fmovd ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  !<ir insLen
  movFregD ctxt ir src dst
  !>ir insLen

let fmovq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  !<ir insLen
  movFregQ ctxt ir src dst
  !>ir insLen

let fnegs ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (16)
  let sign = ((AST.extract src 1<rt> 31) <+> (AST.b1))
  !<ir insLen
  !!ir (AST.extract dst 1<rt> 31 := sign)
  !!ir (AST.extract dst 31<rt> 0 := AST.extract src 31<rt> 0)
  !>ir insLen

let fnegd ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let op = !+ir oprSize
  let res = !+ir oprSize
  !<ir insLen
  getDFloatOp ctxt ir src op
  let sign = ((AST.extract op 1<rt> 63) <+> (AST.b1))
  !!ir (AST.extract res 1<rt> 63 := sign)
  !!ir (AST.extract res 63<rt> 0 := AST.extract op 63<rt> 0)
  setDFloatOp ctxt ir dst res
  !>ir insLen

let fnegq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let op1 = !+ir oprSize
  let op2 = !+ir oprSize
  let res1 = !+ir oprSize
  let res2 = !+ir oprSize
  !<ir insLen
  getQFloatOp ctxt ir src op1 op2
  let sign = ((AST.extract op1 1<rt> 63) <+> (AST.b1))
  !!ir (AST.extract res1 1<rt> 63 := sign)
  !!ir (AST.extract res1 63<rt> 0 := AST.extract op1 63<rt> 0)
  !!ir (AST.extract res2 64<rt> 0 := AST.extract op2 64<rt> 0)
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fadds ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := (AST.fadd src src1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let faddd ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let op = !+ir regSize
  let op1 = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  getDFloatOp ctxt ir src1 op1
  !!ir (res := (AST.fadd op op1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let faddq ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = !+ir regSize
  let res2 = !+ir regSize
  let op01 = !+ir regSize
  let op02 = !+ir regSize
  let op11 = !+ir regSize
  let op12 = !+ir regSize
  let op64 = !+ir 64<rt>
  let op164 = !+ir 64<rt>
  let res64 = !+ir 64<rt>
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getQFloatOp ctxt ir src op01 op02
  getQFloatOp ctxt ir src1 op11 op12
  cast128to64 ctxt ir op01 op02 op64
  cast128to64 ctxt ir op11 op12 op164
  !!ir (res64 := (AST.fadd op64 op164))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fbranchfcc ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (an, label) = transTwoOprs ins insLen ctxt
  let pc = !.ctxt Register.PC
  let fsr = getRegVar ctxt Register.FSR
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
  !<ir insLen
  if (ins.Opcode = Opcode.FBA) then
    let jumpTarget = pc .+ AST.zext 64<rt> label
    !!ir (AST.interjmp jumpTarget InterJmpKind.Base)
    !>ir insLen
  elif (ins.Opcode = Opcode.FBN) then
    !>ir insLen
  else
    let annoffset =
      if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
      else numI32PC 0
    let fallThrough = pc .+ numI32PC 4 .+ annoffset
    let jumpTarget = pc .+ AST.zext 64<rt> label
    !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
    !>ir insLen

let fbranchpfcc ins insLen ctxt =
  let ir = IRBuilder (16)
  let struct (cc, label, an, pr) = transFourOprs ins insLen ctxt
  let pc = !.ctxt Register.PC
  let fsr = getRegVar ctxt Register.FSR
  let fcc0 = getCCVar ctxt ConditionCode.Fcc0
  let fcc1 = getCCVar ctxt ConditionCode.Fcc1
  let fcc2 = getCCVar ctxt ConditionCode.Fcc2
  let fcc3 = getCCVar ctxt ConditionCode.Fcc3
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
  !<ir insLen
  let annoffset =
    if (AST.extract an 1<rt> 0 = AST.b1) then numI32PC 4
    else numI32PC 0
  let fallThrough = pc .+ numI32PC 4 .+ annoffset
  let jumpTarget = pc .+ AST.zext 64<rt> label
  !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir insLen

let fcmps ins insLen ctxt =
  let struct (cc, src, src1) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let pc = !.ctxt Register.PC
  let fsr = getRegVar ctxt Register.FSR
  let fcc0 = getCCVar ctxt ConditionCode.Fcc0
  let fcc1 = getCCVar ctxt ConditionCode.Fcc1
  let fcc2 = getCCVar ctxt ConditionCode.Fcc2
  let fcc3 = getCCVar ctxt ConditionCode.Fcc3
  let pos =
    if (cc = fcc0) then 10
    elif (cc = fcc1) then 32
    elif (cc = fcc2) then 34
    elif (cc = fcc3) then 36
    else raise InvalidOperandException
  let op = AST.extract src 32<rt> 0
  let op1 = AST.extract src1 32<rt> 0
  !<ir insLen
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (AST.feq op op1)
  let cond1 = ((AST.flt op op1) == AST.b1)
  let cond2 = ((AST.fgt op op1) == AST.b1)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 0 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 1 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 2 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 3 2<rt>))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fcmpd ins insLen ctxt =
  let struct (cc, src, src1) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let regSize = 64<rt>
  let fsr = getRegVar ctxt Register.FSR
  let fcc0 = getCCVar ctxt ConditionCode.Fcc0
  let fcc1 = getCCVar ctxt ConditionCode.Fcc1
  let fcc2 = getCCVar ctxt ConditionCode.Fcc2
  let fcc3 = getCCVar ctxt ConditionCode.Fcc3
  let pos =
    if (cc = fcc0) then 10
    elif (cc = fcc1) then 32
    elif (cc = fcc2) then 34
    elif (cc = fcc3) then 36
    else raise InvalidOperandException
  let op = !+ir regSize
  let op1 = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  !<ir insLen
  getDFloatOp ctxt ir src op
  getDFloatOp ctxt ir src1 op1
  let cond0 = (AST.feq op op1)
  let cond1 = ((AST.flt op op1) == AST.b1)
  let cond2 = ((AST.fgt op op1) == AST.b1)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 0 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 1 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 2 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 3 2<rt>))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fcmpq ins insLen ctxt =
  let struct (cc, src, src1) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let regSize = 64<rt>
  let fsr = getRegVar ctxt Register.FSR
  let fcc0 = getCCVar ctxt ConditionCode.Fcc0
  let fcc1 = getCCVar ctxt ConditionCode.Fcc1
  let fcc2 = getCCVar ctxt ConditionCode.Fcc2
  let fcc3 = getCCVar ctxt ConditionCode.Fcc3
  let pos =
    if (cc = fcc0) then 10
    elif (cc = fcc1) then 32
    elif (cc = fcc2) then 34
    elif (cc = fcc3) then 36
    else raise InvalidOperandException
  let op01 = !+ir regSize
  let op02 = !+ir regSize
  let op11 = !+ir regSize
  let op12 = !+ir regSize
  let op64 = !+ir regSize
  let op164 = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  !<ir insLen
  getQFloatOp ctxt ir src op01 op02
  getQFloatOp ctxt ir src1 op11 op12
  cast128to64 ctxt ir op01 op02 op64
  cast128to64 ctxt ir op11 op12 op164
  let cond0 = (AST.feq op64 op164)
  let cond1 = ((AST.flt op64 op164) == AST.b1)
  let cond2 = ((AST.fgt op64 op164) == AST.b1)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 0 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 1 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 2 2<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir ((AST.extract fsr 2<rt> pos) := (numI32 3 2<rt>))
  !!ir (AST.lmark lblEnd)
  !>ir insLen


let fdivs ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := (AST.fdiv src src1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fdivd ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let op = !+ir regSize
  let op1 = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  getDFloatOp ctxt ir src1 op1
  !!ir (res := (AST.fdiv op op1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fdivq ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = !+ir regSize
  let res2 = !+ir regSize
  let op01 = !+ir regSize
  let op02 = !+ir regSize
  let op11 = !+ir regSize
  let op12 = !+ir regSize
  let op64 = !+ir 64<rt>
  let op164 = !+ir 64<rt>
  let res64 = !+ir 64<rt>
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getQFloatOp ctxt ir src op01 op02
  getQFloatOp ctxt ir src1 op11 op12
  cast128to64 ctxt ir op01 op02 op64
  cast128to64 ctxt ir op11 op12 op164
  !!ir (res64 := (AST.fdiv op64 op164))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fmovscc ins insLen ctxt =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = getRegVar ctxt Register.CCR
  let offset =
    if (cc = getCCVar ctxt ConditionCode.Icc) then 0
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
  !<ir insLen
  if (ins.Opcode = Opcode.FMOVsA) then
    !!ir (fdst := fsrc)
    !>ir insLen
  elif (ins.Opcode = Opcode.FMOVsA) then
    !>ir insLen
  else
    !!ir (fdst := AST.ite (cond) (fsrc) (fdst))
    !>ir insLen

let fmovdcc ins insLen ctxt =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let ccr = getRegVar ctxt Register.CCR
  let offset =
    if (cc = getCCVar ctxt ConditionCode.Icc) then 0
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
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  !<ir insLen
  if (ins.Opcode = Opcode.FMOVdA) then
    movFregD ctxt ir fsrc fdst
    !>ir insLen
  elif (ins.Opcode = Opcode.FMOVdN) then
    !>ir insLen
  else
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    movFregD ctxt ir fsrc fdst
    !!ir (AST.lmark lblEnd)
    !>ir insLen

let fmovqcc ins insLen ctxt =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = getRegVar ctxt Register.CCR
  let offset =
    if (cc = getCCVar ctxt ConditionCode.Icc) then 0
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
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  !<ir insLen
  if (ins.Opcode = Opcode.FMOVqA) then
    movFregQ ctxt ir fsrc fdst
    !>ir insLen
  elif (ins.Opcode = Opcode.FMOVqN) then
    !>ir insLen
  else
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    movFregQ ctxt ir fsrc fdst
    !!ir (AST.lmark lblEnd)
    !>ir insLen

let fmovfscc ins insLen ctxt =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let pos =
    if (cc = getCCVar ctxt ConditionCode.Fcc0) then 10
    elif (cc = getCCVar ctxt ConditionCode.Fcc1) then 32
    elif (cc = getCCVar ctxt ConditionCode.Fcc2) then 34
    elif (cc = getCCVar ctxt ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos+1)
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
    | Opcode.FMOVFsO -> (e .|l .| g)
    | _ -> raise InvalidOpcodeException
  !<ir insLen
  if (ins.Opcode = Opcode.FMOVFsA) then
    !!ir (fdst := fsrc)
    !>ir insLen
  elif (ins.Opcode = Opcode.FMOVFsN) then
    !>ir insLen
  else
    !!ir (fdst := AST.ite (cond) (fsrc) (fdst))
    !>ir insLen

let fmovfdcc ins insLen ctxt =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let pos =
    if (cc = getCCVar ctxt ConditionCode.Fcc0) then 10
    elif (cc = getCCVar ctxt ConditionCode.Fcc1) then 32
    elif (cc = getCCVar ctxt ConditionCode.Fcc2) then 34
    elif (cc = getCCVar ctxt ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos+1)
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
    | Opcode.FMOVFdO -> (e .|l .| g)
    | _ -> raise InvalidOpcodeException
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  !<ir insLen
  if (ins.Opcode = Opcode.FMOVFdA) then
    movFregD ctxt ir fsrc fdst
    !>ir insLen
  elif (ins.Opcode = Opcode.FMOVFdN) then
    !>ir insLen
  else
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    movFregD ctxt ir fsrc fdst
    !!ir (AST.lmark lblEnd)
    !>ir insLen

let fmovfqcc ins insLen ctxt =
  let struct (cc, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let pos =
    if (cc = getCCVar ctxt ConditionCode.Fcc0) then 10
    elif (cc = getCCVar ctxt ConditionCode.Fcc1) then 32
    elif (cc = getCCVar ctxt ConditionCode.Fcc2) then 34
    elif (cc = getCCVar ctxt ConditionCode.Fcc3) then 36
    else raise InvalidRegisterException
  let fsr0 = AST.extract fsr 1<rt> pos
  let fsr1 = AST.extract fsr 1<rt> (pos+1)
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
    | Opcode.FMOVFqO -> (e .|l .| g)
    | _ -> raise InvalidOpcodeException
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  !<ir insLen
  if (ins.Opcode = Opcode.FMOVFqA) then
    movFregQ ctxt ir fsrc fdst
    !>ir insLen
  elif (ins.Opcode = Opcode.FMOVFqN) then
    !>ir insLen
  else
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    movFregQ ctxt ir fsrc fdst
    !!ir (AST.lmark lblEnd)
    !>ir insLen

let fmovrs ins insLen ctxt =
  let struct (src, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.FMOVRsZ ->
    !!ir (fdst := AST.ite (src == AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsLEZ ->
    !!ir (fdst := AST.ite (src ?<= AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsLZ ->
    !!ir (fdst := AST.ite (src ?< AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsNZ ->
    !!ir (fdst := AST.ite (src != AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsGZ ->
    !!ir (fdst := AST.ite (src ?> AST.num0 oprSize) (fsrc) (fdst))
  | Opcode.FMOVRsGEZ ->
    !!ir (fdst := AST.ite (src ?>= AST.num0 oprSize) (fsrc) (fdst))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let fmovrd ins insLen ctxt =
  let struct (src, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
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
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL0)
  movFregD ctxt ir fsrc fdst
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fmovrq ins insLen ctxt =
  let struct (src, fsrc, fdst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
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
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  !<ir insLen
  !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL0)
  movFregQ ctxt ir fsrc fdst
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fmuls ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := (AST.fmul src src1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fmuld ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let op = !+ir regSize
  let op1 = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  getDFloatOp ctxt ir src1 op1
  !!ir (res := (AST.fmul op op1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fmulq ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = !+ir regSize
  let res2 = !+ir regSize
  let op01 = !+ir regSize
  let op02 = !+ir regSize
  let op11 = !+ir regSize
  let op12 = !+ir regSize
  let op64 = !+ir 64<rt>
  let op164 = !+ir 64<rt>
  let res64 = !+ir 64<rt>
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getQFloatOp ctxt ir src op01 op02
  getQFloatOp ctxt ir src1 op11 op12
  cast128to64 ctxt ir op01 op02 op64
  cast128to64 ctxt ir op11 op12 op164
  !!ir (res64 := (AST.fmul op64 op164))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fsmuld ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  let op1 = AST.cast CastKind.FloatCast 64<rt> src
  let op2 = AST.cast CastKind.FloatCast 64<rt> src1
  !!ir (res := (AST.fmul op1 op2))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fdmulq ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let res1 = !+ir regSize
  let res2 = !+ir regSize
  let op = !+ir regSize
  let op1 = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  getDFloatOp ctxt ir src1 op1
  !!ir (res := (AST.fmul op op1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fsqrts ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := (AST.fsqrt src))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fsqrtd ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let op = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  !!ir (res := (AST.fsqrt op))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fsqrtq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = !+ir regSize
  let res2 = !+ir regSize
  let op01 = !+ir regSize
  let op02 = !+ir regSize
  let op64 = !+ir 64<rt>
  let res64 = !+ir 64<rt>
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getQFloatOp ctxt ir src op01 op02
  cast128to64 ctxt ir op01 op02 op64
  !!ir (res64 := (AST.fsqrt op64))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fstox ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let cst = !+ir oprSize
  !<ir insLen
  !!ir (cst := AST.cast CastKind.FtoITrunc oprSize src)
  setDFloatOp ctxt ir dst cst
  !>ir insLen

let fdtox ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let op = !+ir oprSize
  let cst = !+ir oprSize
  !<ir insLen
  getDFloatOp ctxt ir src op
  !!ir (cst := AST.cast CastKind.FtoITrunc oprSize op)
  setDFloatOp ctxt ir dst cst
  !>ir insLen

let fqtox ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let regSize = 64<rt>
  let ir = IRBuilder (16)
  let op1 = !+ir regSize
  let op2 = !+ir regSize
  let op64 = !+ir regSize
  let cst = !+ir oprSize
  !<ir insLen
  getQFloatOp ctxt ir src op1 op2
  cast128to64 ctxt ir op1 op2 op64
  !!ir (cst := AST.cast CastKind.FtoITrunc oprSize op64)
  setDFloatOp ctxt ir dst cst
  !>ir insLen

let fstoi ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (16)
  let cst = !+ir oprSize
  !<ir insLen
  !!ir (dst := AST.cast CastKind.FtoITrunc oprSize src)
  !>ir insLen

let fdtoi ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let regSize = 32<rt>
  let ir = IRBuilder (16)
  let op = !+ir oprSize
  let cst = !+ir regSize
  !<ir insLen
  getDFloatOp ctxt ir src op
  !!ir (dst := AST.cast CastKind.FtoITrunc regSize op)
  !>ir insLen

let fqtoi ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 32<rt>
  let regSize = 64<rt>
  let ir = IRBuilder (16)
  let op1 = !+ir regSize
  let op2 = !+ir regSize
  let op64 = !+ir regSize
  let cst = !+ir oprSize
  !<ir insLen
  getQFloatOp ctxt ir src op1 op2
  cast128to64 ctxt ir op1 op2 op64
  !!ir (dst := AST.cast CastKind.FtoITrunc oprSize op64)
  !>ir insLen

let fstod ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = !+ir oprSize
  let rounded = !+ir oprSize
  let regSize = 64<rt>
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := AST.cast CastKind.FloatCast oprSize src)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize res)
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fstoq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res1 = !+ir oprSize
  let res2 = !+ir oprSize
  let res64 = !+ir oprSize
  let rounded = !+ir oprSize
  let regSize = 64<rt>
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res64 := AST.cast CastKind.FloatCast oprSize src)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fdtos ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !>ir insLen

let fdtoq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !>ir insLen

let fqtos ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !>ir insLen

let fqtod ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !>ir insLen

let fsubs ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 32<rt>
  let res = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := (AST.fsub src src1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fsubd ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res = !+ir regSize
  let op = !+ir regSize
  let op1 = !+ir regSize
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  getDFloatOp ctxt ir src1 op1
  !!ir (res := (AST.fsub op op1))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fsubq ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let regSize = 64<rt>
  let res1 = !+ir regSize
  let res2 = !+ir regSize
  let op01 = !+ir regSize
  let op02 = !+ir regSize
  let op11 = !+ir regSize
  let op12 = !+ir regSize
  let op64 = !+ir 64<rt>
  let op164 = !+ir 64<rt>
  let res64 = !+ir 64<rt>
  let rounded = !+ir regSize
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getQFloatOp ctxt ir src op01 op02
  getQFloatOp ctxt ir src1 op11 op12
  cast128to64 ctxt ir op01 op02 op64
  cast128to64 ctxt ir op11 op12 op164
  !!ir (res64 := (AST.fsub op64 op164))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res64))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res64))
  !!ir (AST.lmark lblEnd)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fxtos ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = !+ir oprSize
  let op = !+ir 64<rt>
  let regSize = !+ir 32<rt>
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  getDFloatOp ctxt ir src op
  !!ir (res := (AST.cast CastKind.SIntToFloat oprSize op))
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := (AST.cast (CastKind.FtoFRound) oprSize op))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := (AST.cast (CastKind.FtoFTrunc) oprSize (res)))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := (AST.cast (CastKind.FtoFCeil) oprSize (res)))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := (AST.cast (CastKind.FtoFFloor) oprSize (res)))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fitos ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 32<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = !+ir oprSize
  let regSize = 32<rt>
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := AST.cast CastKind.SIntToFloat oprSize src)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (dst := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (dst := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (dst := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (dst := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let fxtod ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let fsr = getRegVar ctxt Register.FSR
  let fsr30 = AST.extract fsr 1<rt> 30
  let fsr31 = AST.extract fsr 1<rt> 31
  let res = !+ir oprSize
  let rounded = !+ir oprSize
  let regSize = 64<rt>
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblL2 = !%ir "L2"
  let lblL3 = !%ir "L3"
  let lblL4 = !%ir "L4"
  let lblL5 = !%ir "L5"
  let lblEnd = !%ir "End"
  let cond0 = (fsr31 == AST.b0) .& (fsr30 == AST.b0)
  let cond1 = (fsr31 == AST.b0) .& (fsr30 == AST.b1)
  let cond2 = (fsr31 == AST.b1) .& (fsr30 == AST.b0)
  !<ir insLen
  !!ir (res := AST.cast CastKind.SIntToFloat oprSize src)
  !!ir (AST.cjmp cond0 (AST.jmpDest lblL0) (AST.jmpDest lblL1))
  !!ir (AST.lmark lblL0)
  !!ir (rounded := AST.cast CastKind.FtoFRound regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL1)
  !!ir (AST.cjmp cond1 (AST.jmpDest lblL2) (AST.jmpDest lblL3))
  !!ir (AST.lmark lblL2)
  !!ir (rounded := AST.cast CastKind.FtoFTrunc regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL3)
  !!ir (AST.cjmp cond2 (AST.jmpDest lblL4) (AST.jmpDest lblL5))
  !!ir (AST.lmark lblL4)
  !!ir (rounded := AST.cast CastKind.FtoFCeil regSize (res))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL5)
  !!ir (rounded := AST.cast CastKind.FtoFFloor regSize (res))
  !!ir (AST.lmark lblEnd)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fitod ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let rounded = !+ir oprSize
  !<ir insLen
  !!ir (rounded := AST.cast CastKind.SIntToFloat 64<rt> src)
  setDFloatOp ctxt ir dst rounded
  !>ir insLen

let fxtoq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let op = !+ir oprSize
  let op64 = !+ir oprSize
  let rounded = !+ir 64<rt>
  let res1 = !+ir oprSize
  let res2 = !+ir oprSize
  !<ir insLen
  getDFloatOp ctxt ir src op
  !!ir (rounded := AST.cast CastKind.SIntToFloat 64<rt> op)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let fitoq ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let rounded = !+ir 64<rt>
  let res1 = !+ir oprSize
  let res2 = !+ir oprSize
  !<ir insLen
  !!ir (rounded := AST.cast CastKind.SIntToFloat oprSize src)
  cast64To128 ctxt ir rounded res1 res2
  setQFloatOp ctxt ir dst res1 res2
  !>ir insLen

let jmpl ins insLen ctxt =
  let struct (addr, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir insLen
  !!ir (AST.jmp addr)
  !!ir (dst := !.ctxt Register.PC)
  !>ir insLen

let ldf ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.LDF -> !!ir (dst := (AST.loadBE 32<rt> addr))
  | Opcode.LDDF ->
    let op = !+ir oprSize
    !!ir (op := (AST.loadBE oprSize addr))
    setDFloatOp ctxt ir dst op
  | Opcode.LDQF ->
    let op0 = !+ir oprSize
    let op1 = !+ir oprSize
    !!ir (op0 := (AST.loadBE oprSize addr))
    !!ir (op1 := (AST.loadBE oprSize (addr .+ numI64 8 64<rt>)))
    setQFloatOp ctxt ir dst op0 op1
  | Opcode.LDFSR -> !!ir ((AST.extract dst 32<rt> 0) :=
    (AST.loadBE 32<rt> addr))
  | Opcode.LDXFSR -> !!ir (dst := (AST.loadBE oprSize addr))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let ldfa ins insLen ctxt =
  let struct (addr, asi, dst) = transAddrFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.LDFA -> !!ir (dst := (AST.loadBE 32<rt> (addr .+ asi)))
  | Opcode.LDDFA ->
    let op = !+ir oprSize
    !!ir (op := (AST.loadBE oprSize (addr .+ asi)))
    setDFloatOp ctxt ir dst op
  | Opcode.LDQFA ->
    let op0 = !+ir oprSize
    let op1 = !+ir oprSize
    !!ir (op0 := (AST.loadBE oprSize (addr .+ asi)))
    !!ir (op1 := (AST.loadBE oprSize ((addr .+ asi) .+ numI64 8 64<rt>)))
    setQFloatOp ctxt ir dst op0 op1
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let ld ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.LDSB -> !!ir (dst := (AST.sext oprSize (AST.loadBE 8<rt> addr)))
  | Opcode.LDSH -> !!ir (dst := (AST.sext oprSize (AST.loadBE 16<rt> addr)))
  | Opcode.LDSW -> !!ir (dst := (AST.sext oprSize (AST.loadBE 32<rt> addr)))
  | Opcode.LDUB -> !!ir (dst := (AST.zext oprSize (AST.loadBE 8<rt> addr)))
  | Opcode.LDUH -> !!ir (dst := (AST.zext oprSize (AST.loadBE 16<rt> addr)))
  | Opcode.LDUW -> !!ir (dst := (AST.zext oprSize (AST.loadBE 32<rt> addr)))
  | Opcode.LDX -> !!ir (dst := AST.loadBE oprSize addr)
  | Opcode.LDD ->
    if (dst = getRegVar ctxt Register.G0) then
      let nxt = getRegVar ctxt Register.G1
      !!ir (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize addr) 32<rt> 32)))
    else
      let nxt = getRegVar ctxt (getNextReg ctxt dst)
      !!ir (dst := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize addr) 32<rt> 0)))
      !!ir (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize addr) 32<rt> 32)))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let lda ins insLen ctxt =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let addr = src .+ src1
  match ins.Opcode with
  | Opcode.LDSBA -> !!ir (dst := (AST.sext oprSize
                          (AST.loadBE 8<rt> (addr .+ asi))))
  | Opcode.LDSHA -> !!ir (dst := (AST.sext oprSize
                          (AST.loadBE 16<rt> (addr .+ asi))))
  | Opcode.LDSWA -> !!ir (dst := (AST.sext oprSize
                          (AST.loadBE 32<rt> (addr .+ asi))))
  | Opcode.LDUBA -> !!ir (dst := (AST.zext oprSize
                          (AST.loadBE 8<rt> (addr .+ asi))))
  | Opcode.LDUHA -> !!ir (dst := (AST.zext oprSize
                          (AST.loadBE 16<rt> (addr .+ asi))))
  | Opcode.LDUWA -> !!ir (dst := (AST.zext oprSize
                          (AST.loadBE 32<rt> (addr .+ asi))))
  | Opcode.LDXA -> !!ir (dst := AST.loadBE oprSize (addr .+ asi))
  | Opcode.LDDA ->
    if (dst = getRegVar ctxt Register.G0) then
      let nxt = getRegVar ctxt Register.G1
      !!ir (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize (addr .+ asi)) 32<rt> 32)))
    else
      let nxt = getRegVar ctxt (getNextReg ctxt dst)
      !!ir (dst := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize (addr .+ asi)) 32<rt> 0)))
      !!ir (nxt := (AST.zext oprSize (AST.extract
        (AST.loadBE oprSize (addr .+ asi)) 32<rt> 32)))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let ldstub ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := (AST.zext oprSize (AST.loadBE 8<rt> addr)))
  !!ir ((AST.loadBE 8<rt> addr) := (numI32 0xff 8<rt>))
  !>ir insLen

let ldstuba ins insLen ctxt =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let addr = src .+ src1
  !!ir (dst := (AST.zext oprSize (AST.loadBE 8<rt> (addr .+ asi))))
  !!ir ((AST.loadBE 8<rt> (addr .+ asi)) := (numI32 0xff 8<rt>))
  !>ir insLen

let membar ins insLen ctxt = (* FIXME *)
  let mask = transOneOpr ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir insLen
  !!ir (t1 := mask)
  !>ir insLen

let movcc ins insLen ctxt =
  let struct (cc, src, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = getRegVar ctxt Register.CCR
  let fsr = getRegVar ctxt Register.FSR
  !<ir insLen
  if (dst <> getRegVar ctxt Register.G0) then
    match ins.Opcode with
      | Opcode.MOVA | Opcode.MOVFA ->
        !!ir (dst := src)
      | Opcode.MOVN | Opcode.MOVFN ->
        ()
      | Opcode.MOVNE ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let cond = (AST.extract ccr 1<rt> 2 == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract ccr 1<rt> 6 == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVE ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let cond = (AST.extract ccr 1<rt> 2 == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract ccr 1<rt> 6 == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVG ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let z = AST.extract ccr 1<rt> 2
          let v = AST.extract ccr 1<rt> 1
          let cond = ((z .| (n <+> v)) == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let z = AST.extract ccr 1<rt> 6
          let v = AST.extract ccr 1<rt> 5
          let cond = ((z .| (n <+> v)) == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVLE ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let z = AST.extract ccr 1<rt> 2
          let v = AST.extract ccr 1<rt> 1
          let cond = ((z .| (n <+> v)) == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let z = AST.extract ccr 1<rt> 6
          let v = AST.extract ccr 1<rt> 5
          let cond = ((z .| (n <+> v)) == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVGE ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let v = AST.extract ccr 1<rt> 1
          let cond = ((n <+> v) == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let v = AST.extract ccr 1<rt> 5
          let cond = ((n <+> v) == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVL ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let v = AST.extract ccr 1<rt> 1
          let cond = ((n <+> v) == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let v = AST.extract ccr 1<rt> 5
          let cond = ((n <+> v) == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVGU ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let z = AST.extract ccr 1<rt> 2
          let c = AST.extract ccr 1<rt> 0
          let cond = ((c .| z) == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let z = AST.extract ccr 1<rt> 6
          let c = AST.extract ccr 1<rt> 4
          let cond = ((c .| z) == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVLEU ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let z = AST.extract ccr 1<rt> 2
          let c = AST.extract ccr 1<rt> 0
          let cond = ((c .| z) == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let z = AST.extract ccr 1<rt> 6
          let c = AST.extract ccr 1<rt> 4
          let cond = ((c .| z) == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVCC ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let c = AST.extract ccr 1<rt> 0
          let cond = (c == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let c = AST.extract ccr 1<rt> 4
          let cond = (c == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVCS ->
        let lblL1 = !%ir "L1"
        let lblEnd = !%ir "End"
        let ccr = getRegVar ctxt Register.CCR
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let c = AST.extract ccr 1<rt> 0
          let cond = (c == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let c = AST.extract ccr 1<rt> 4
          let cond = (c == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVPOS ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let cond = (n == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let cond = (n == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVNEG ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let n = AST.extract ccr 1<rt> 3
          let cond = (n == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let n = AST.extract ccr 1<rt> 7
          let cond = (n == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVVC ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let v = AST.extract ccr 1<rt> 1
          let cond = (v == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let v = AST.extract ccr 1<rt> 5
          let cond = (v == AST.b0)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVVS ->
        if (cc = getCCVar ctxt ConditionCode.Icc) then
          let v = AST.extract ccr 1<rt> 1
          let cond = (v == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let v = AST.extract ccr 1<rt> 5
          let cond = (v == AST.b1)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFU ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>))
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFG ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>))
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFUG ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFL ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>))
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFUL ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFLG ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFNE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | Opcode.MOVFE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = ((AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>))
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond) (src) (dst))
      | Opcode.MOVFUE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFGE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFUGE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | Opcode.MOVFLE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond2 =  (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2) (src) (dst))
      | Opcode.MOVFULE ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 3 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | Opcode.MOVFO ->
        if (cc = getCCVar ctxt ConditionCode.Fcc0) then
          let cond = (AST.extract fsr 2<rt> 10) == (numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 10) == (numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 10) == (numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc1) then
          let cond = (AST.extract fsr 2<rt> 32 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 32 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 32 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        elif (cc = getCCVar ctxt ConditionCode.Fcc2) then
          let cond = (AST.extract fsr 2<rt> 34 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 34 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 34 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
        else
          let cond = (AST.extract fsr 2<rt> 36 == numI32 1 2<rt>)
          let cond2 = (AST.extract fsr 2<rt> 36 == numI32 2 2<rt>)
          let cond3 = (AST.extract fsr 2<rt> 36 == numI32 0 2<rt>)
          !!ir (dst := AST.ite (cond .| cond2 .| cond3) (src) (dst))
      | _ ->
        raise InvalidOpcodeException
  !>ir insLen

let movr ins insLen ctxt = (* TODO : check that destination is not g0*)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.MOVRZ ->
    !!ir (dst := AST.ite (src == AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRLEZ ->
    !!ir (dst := AST.ite (src ?<= AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRLZ ->
    !!ir (dst := AST.ite (src ?< AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRNZ ->
    !!ir (dst := AST.ite (src != AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRGZ ->
    !!ir (dst := AST.ite (src ?> AST.num0 oprSize) (src1) (dst))
  | Opcode.MOVRGEZ ->
    !!ir (dst := AST.ite (src ?>= AST.num0 oprSize) (src1) (dst))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let mulscc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let src32 = !+ir 32<rt>
  let y = !.ctxt Register.Y
  let ccr = !.ctxt Register.CCR
  let src2 = !+ir 32<rt>
  let hbyte = !+ir 4<rt>
  !<ir insLen
  !!ir (src32 := AST.concat ((AST.extract ccr 1<rt> 3) <+>
    (AST.extract ccr 1<rt> 1)) (AST.extract src 31<rt> 1))
  !!ir (src2 := AST.ite ((AST.extract y 1<rt> 0) == AST.b0)
    (AST.num0 32<rt>) (AST.extract src1 32<rt> 0))
  !!ir (res := AST.zext  64<rt> (src32 .+ src2))
  if (dst <> getRegVar ctxt Register.G0) then
    !!ir (dst := res)
  !!ir ((AST.extract y 32<rt> 0) :=  AST.concat (AST.extract src 1<rt> 0)
    (AST.extract y 31<rt> 1))
  !!ir (hbyte := getConditionCodeMulscc res src src1)
  !!ir (AST.extract ccr 4<rt> 0 := hbyte)
  !>ir insLen

let mulx ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := src .* src1)
  !>ir insLen

let nop insLen =
  let ir = IRBuilder (16)
  !<ir insLen
  !>ir insLen

let ``or`` ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src .| src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen


let orcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .| src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeLog res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let orn ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := (src .| AST.not (src1)))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let orncc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := (src .| AST.not (src1)))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeLog res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let popc ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let max = numI32 (RegType.toBitWidth oprSize) 64<rt>
  let ir = IRBuilder (16)
  let lblLoop = ir.NewSymbol "Loop"
  let lblExit = ir.NewSymbol "Exit"
  let lblLoopCond = ir.NewSymbol "LoopCond"
  let struct (i, count) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (i := AST.num0 oprSize)
  !!ir (count := AST.num0 oprSize)
  !!ir (AST.lmark lblLoopCond)
  !!ir (AST.cjmp (AST.lt i max) (AST.jmpDest lblLoop) (AST.jmpDest lblExit))
  !!ir (AST.lmark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  !!ir (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  !!ir (i := i .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.jmpDest lblLoopCond))
  !!ir (AST.lmark lblExit)
  !!ir (dst := count)
  !>ir insLen

let rd ins insLen ctxt =
  let struct (reg, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := reg)
  !>ir insLen

let restore ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src .+ src1)
  !>ir insLen

let restored ins insLen ctxt =
  let ir = IRBuilder (16)
  let cs = getRegVar ctxt Register.CANSAVE
  let cr = getRegVar ctxt Register.CANRESTORE
  let ow = getRegVar ctxt Register.OTHERWIN
  !<ir insLen
  !!ir (cs := (cs .+ AST.num1 64<rt>))
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let cond = (ow == AST.num0 64<rt>)
  !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (cr := (cs .- AST.num1 64<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (ow := (ow .- AST.num1 64<rt>))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let ret ins insLen ctxt =
  let struct (src, src1) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (!.ctxt Register.PC := (src .+ src1))
  !>ir insLen

let retry ins insLen ctxt =
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (!.ctxt Register.PC := !.ctxt Register.TPC)
  !!ir (!.ctxt Register.NPC := !.ctxt Register.TNPC)
  !>ir insLen

let save ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src .+ src1)
  !>ir insLen

let saved ins insLen ctxt =
  let ir = IRBuilder (16)
  let cs = getRegVar ctxt Register.CANSAVE
  let cr = getRegVar ctxt Register.CANRESTORE
  let ow = getRegVar ctxt Register.OTHERWIN
  !<ir insLen
  !!ir (cs := (cs .+ AST.num1 64<rt>))
  let lblL0 = !%ir "L0"
  let lblEnd = !%ir "End"
  let cond = (ow == AST.num0 64<rt>)
  !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblEnd))
  !!ir (AST.lmark lblL0)
  !!ir (cr := (cr .- AST.num1 64<rt>))
  !!ir (AST.jmp (AST.jmpDest lblEnd))
  !!ir (ow := (ow .- AST.num1 64<rt>))
  !!ir (AST.lmark lblEnd)
  !>ir insLen

let sdiv ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let divisor = !+ir 32<rt>
  let dividend = !+ir 64<rt>
  let quotient = !+ir 64<rt>
  let y = getRegVar ctxt Register.Y
  let ccr = getRegVar ctxt Register.CCR
  !<ir insLen
  !!ir (divisor := AST.extract src1 32<rt> 0)
  !!ir (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1  = getRegVar ctxt Register.G0) then
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen ctxt) then
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    !!ir (AST.lmark lblL1)
    if (dst <> getRegVar ctxt Register.G0) then
      !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
    !!ir (AST.jmp (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
  !!ir (AST.extract ccr 4<rt> 4 := AST.num0 4<rt>)
  !!ir (AST.extract ccr 1<rt> 3 := AST.ite
    ((AST.extract quotient 1<rt> 31) == AST.b1) (AST.b1) (AST.b0))
  !!ir (AST.extract ccr 1<rt> 2 := AST.ite
    ((AST.extract quotient 32<rt> 0) == AST.num0 32<rt>) (AST.b1) (AST.b0))
  !!ir (AST.extract ccr 1<rt> 0 := AST.b0)
  !>ir insLen

let sdivcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let divisor = !+ir 32<rt>
  let dividend = !+ir 64<rt>
  let quotient = !+ir 64<rt>
  let y = getRegVar ctxt Register.Y
  let ccr = getRegVar ctxt Register.CCR
  !<ir insLen
  !!ir (divisor := AST.extract src1 32<rt> 0)
  !!ir (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1  = getRegVar ctxt Register.G0) then
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen ctxt) then
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    !!ir (AST.lmark lblL1)
    if (dst <> getRegVar ctxt Register.G0) then
      !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
    !!ir (AST.jmp (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
  !!ir (AST.extract ccr 4<rt> 4 := AST.num0 4<rt>)
  !!ir (AST.extract ccr 1<rt> 3 := AST.ite
    ((AST.extract quotient 1<rt> 31) == AST.b1) (AST.b1) (AST.b0))
  !!ir (AST.extract ccr 1<rt> 2 := AST.ite
    ((AST.extract quotient 32<rt> 0) == AST.num0 32<rt>) (AST.b1) (AST.b0))
  !!ir (AST.extract ccr 1<rt> 0 := AST.b0)
  !>ir insLen

let sdivx ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let cond = (src1 == AST.num0 64<rt>)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  if (src1 = AST.num0 64<rt> || src1  = getRegVar ctxt Register.G0) then
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen ctxt) then
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    !!ir (AST.lmark lblL1)
    if (dst = getRegVar ctxt Register.G0) then
      !!ir (dst := AST.num0 64<rt>)
    else
      !!ir (dst := src ?/ src1)
    !!ir (AST.jmp (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
    !!ir (AST.lmark lblEnd)
  else
    if (dst = getRegVar ctxt Register.G0) then
      !!ir (dst := AST.num0 64<rt>)
    else
      !!ir (dst := src ?/ src1)
  !>ir insLen

let sethi ins insLen ctxt =
  let struct (imm, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst <> getRegVar ctxt Register.G0) then
    !!ir (dst := AST.concat (AST.zext 32<rt> AST.b0)
      (AST.extract imm 32<rt> 0))
  !>ir insLen

let sll ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := src << src1)
  !>ir insLen

let smul ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let yreg  = getRegVar ctxt Register.Y
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := AST.sext 64<rt>  ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    !!ir (AST.extract yreg 64<rt> 0 :=  AST.zext 64<rt>
      (AST.extract dst 32<rt> 32))
  !>ir insLen

let smulcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let yreg  = getRegVar ctxt Register.Y
  let ccr  = getRegVar ctxt Register.CCR
  let oprSize = 64<rt>
  let byte = !+ir 8<rt>
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := AST.sext 64<rt>  ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    !!ir (AST.extract yreg 64<rt> 0 :=  AST.zext 64<rt>
      (AST.extract dst 32<rt> 32))
    !!ir (byte := (getConditionCodeMul dst src src1))
    !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let sra ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := src ?>> src1)
  !>ir insLen

let srl ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := src >> src1)
  !>ir insLen

let st ins insLen ctxt =
  let struct (src, addr) = transTwooprsAddr ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.STB -> !!ir ((AST.loadBE 8<rt> addr) := (AST.extract src 8<rt> 0))
  | Opcode.STH -> !!ir ((AST.loadBE 16<rt> addr) := (AST.extract src 16<rt> 0))
  | Opcode.STW -> !!ir ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
  | Opcode.STX -> !!ir ((AST.loadBE 64<rt> addr) := (AST.extract src 64<rt> 0))
  | Opcode.STD ->
    if (src = getRegVar ctxt Register.G0) then
      let nxt = getRegVar ctxt Register.G1
      !!ir ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
    else
      let nxt = getRegVar ctxt (getNextReg ctxt src)
      !!ir ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
      !!ir ((AST.loadBE 32<rt> (addr .+ numI64 4 64<rt>)) :=
        (AST.extract nxt 32<rt> 0))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let sta ins insLen ctxt =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let addr = src .+ src1
  match ins.Opcode with
  | Opcode.STBA -> !!ir ((AST.loadBE 8<rt> (addr .+ asi))
                          := (AST.extract src 8<rt> 0))
  | Opcode.STHA -> !!ir ((AST.loadBE 16<rt> (addr .+ asi))
                          := (AST.extract src 16<rt> 0))
  | Opcode.STWA -> !!ir ((AST.loadBE 32<rt> (addr .+ asi))
                          := (AST.extract src 32<rt> 0))
  | Opcode.STXA -> !!ir ((AST.loadBE 64<rt> (addr .+ asi))
                          := (AST.extract src 64<rt> 0))
  | Opcode.STDA ->
    if (src = getRegVar ctxt Register.G0) then
      let nxt = getRegVar ctxt Register.G1
      !!ir ((AST.loadBE 32<rt> (addr .+ asi)) := (AST.extract src 32<rt> 0))
    else
      let nxt = getRegVar ctxt (getNextReg ctxt src)
      !!ir ((AST.loadBE 32<rt> (addr .+ asi)) := (AST.extract src 32<rt> 0))
      !!ir ((AST.loadBE 32<rt> ((addr .+ asi) .+ numI64 4 64<rt>)) :=
        (AST.extract nxt 32<rt> 0))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let stf ins insLen ctxt =
  let struct (src, addr) = transTwooprsAddr ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.STF -> !!ir ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
  | Opcode.STDF ->
    let op = !+ir oprSize
    getDFloatOp ctxt ir src op
    !!ir ((AST.loadBE 64<rt> addr) := (AST.extract op 64<rt> 0))
  | Opcode.STQF ->
    let op0 = !+ir oprSize
    let op1 = !+ir oprSize
    getQFloatOp ctxt ir src op0 op1
    !!ir ((AST.loadBE 64<rt> addr) := (AST.extract op0 64<rt> 0))
    !!ir ((AST.loadBE 64<rt> (addr .+ numI64 8 64<rt>)) :=
      (AST.extract op1 64<rt> 0))
  | Opcode.STFSR ->
    !!ir ((AST.loadBE 32<rt> addr) := (AST.extract src 32<rt> 0))
  | Opcode.STXFSR ->
    !!ir ((AST.loadBE 64<rt> addr) := src)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let stfa ins insLen ctxt =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let addr = dst .+ src1 .+ asi
  match ins.Opcode with
  | Opcode.STFA -> !!ir ((AST.loadBE 32<rt> (addr)) :=
                        (AST.extract src 32<rt> 0))
  | Opcode.STDFA ->
    let op = !+ir oprSize
    getDFloatOp ctxt ir src op
    !!ir ((AST.loadBE 64<rt> (addr)) :=
          (AST.extract op 64<rt> 0))
  | Opcode.STQFA ->
    let op0 = !+ir oprSize
    let op1 = !+ir oprSize
    getQFloatOp ctxt ir src op0 op1
    !!ir ((AST.loadBE 64<rt> (addr)) := (AST.extract op0 64<rt> 0))
    !!ir ((AST.loadBE 64<rt> ((addr) .+ numI64 8 64<rt>)) :=
      (AST.extract op1 64<rt> 0))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let sub ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src .- src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let subcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .- src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeSub res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen


let subC ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let byte = !+ir 8<rt>
  let ccr = !.ctxt Register.CCR
  !<ir insLen
  !!ir (res := src .- src1 .- AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let subCcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src .- src1 .- AST.zext 64<rt> (AST.extract ccr 1<rt> 0))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeSub res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let swap ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let addr = !+ir oprSize
  !<ir insLen
  !!ir (addr := (src .+ src1))
  !!ir (dst := (AST.zext oprSize (AST.loadBE 32<rt> addr)))
  !>ir insLen

let swapa ins insLen ctxt =
  let struct (src, src1, asi, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (dst := (AST.zext oprSize (AST.loadBE 32<rt> (src .+ src1 .+ asi))))
  !>ir insLen

let udiv ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let divisor = !+ir 32<rt>
  let dividend = !+ir 64<rt>
  let quotient = !+ir 64<rt>
  let y = getRegVar ctxt Register.Y
  !<ir insLen
  !!ir (divisor := AST.extract src1 32<rt> 0)
  !!ir (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1  = getRegVar ctxt Register.G0) then
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen ctxt) then
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    !!ir (AST.lmark lblL1)
    if (dst <> getRegVar ctxt Register.G0) then
      !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.jmp (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
  !>ir insLen

let udivcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  let divisor = !+ir 32<rt>
  let dividend = !+ir 64<rt>
  let quotient = !+ir 64<rt>
  let y = getRegVar ctxt Register.Y
  let ccr = getRegVar ctxt Register.CCR
  !<ir insLen
  !!ir (divisor := AST.extract src1 32<rt> 0)
  !!ir (dividend := AST.concat (AST.extract y 32<rt> 0)
    (AST.extract src 32<rt> 0))
  let cond = (divisor == AST.num0 32<rt>)
  if (divisor = AST.num0 32<rt> || src1  = getRegVar ctxt Register.G0) then
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen ctxt) then
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    !!ir (AST.lmark lblL1)
    if (dst <> getRegVar ctxt Register.G0) then
      !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
    !!ir (AST.jmp (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
    !!ir (AST.lmark lblEnd)
  else
    !!ir (quotient := dividend ./ (AST.zext 64<rt> divisor))
    !!ir (dst := AST.ite ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>)
      (AST.zext 64<rt> (AST.extract quotient 32<rt> 0))
      (numU64 0x0000FFFFUL 64<rt>))
    !!ir (AST.extract ccr 1<rt> 1 := AST.ite
      ((AST.extract quotient 32<rt> 32) == AST.num0 32<rt>) (AST.b0) (AST.b1))
  !!ir (AST.extract ccr 4<rt> 4 := AST.num0 4<rt>)
  !!ir (AST.extract ccr 1<rt> 3 := AST.ite
    ((AST.extract quotient 1<rt> 31) == AST.b1) (AST.b1) (AST.b0))
  !!ir (AST.extract ccr 1<rt> 2 := AST.ite
    ((AST.extract quotient 32<rt> 0) == AST.num0 32<rt>) (AST.b1) (AST.b0))
  !!ir (AST.extract ccr 1<rt> 0 := AST.b0)
  !>ir insLen

let udivx ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let cond = (src1 == AST.num0 64<rt>)
  let lblL0 = !%ir "L0"
  let lblL1 = !%ir "L1"
  let lblEnd = !%ir "End"
  !<ir insLen
  if (src1 = AST.num0 64<rt> || src1  = getRegVar ctxt Register.G0) then
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
  elif (isRegOpr ins insLen ctxt) then
    !!ir (AST.cjmp (cond) (AST.jmpDest lblL0) (AST.jmpDest lblL1))
    !!ir (AST.lmark lblL1)
    if (dst = getRegVar ctxt Register.G0) then
      !!ir (dst := AST.num0 64<rt>)
    else
      !!ir (dst := src ./ src1)
    !!ir (AST.jmp (AST.jmpDest lblEnd))
    !!ir (AST.lmark lblL0)
    !!ir (AST.sideEffect (Exception "Division by zero exception"))
    !!ir (AST.lmark lblEnd)
  else
    if (dst = getRegVar ctxt Register.G0) then
      !!ir (dst := AST.num0 64<rt>)
    else
      !!ir (dst := src ./ src1)
  !>ir insLen

let umul ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let yreg  = getRegVar ctxt Register.Y
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := AST.zext 64<rt>  ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    !!ir (AST.extract yreg 64<rt> 0 :=
      AST.zext 64<rt> (AST.extract dst 32<rt> 32))
  !>ir insLen

let umulcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let ir = IRBuilder (16)
  let yreg  = getRegVar ctxt Register.Y
  let ccr = getRegVar ctxt Register.CCR
  let oprSize = 64<rt>
  let byte = !+ir 8<rt>
  !<ir insLen
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := AST.zext 64<rt>  ((AST.extract src 32<rt> 0)
      .* (AST.extract src1 32<rt> 0)))
    !!ir (AST.extract yreg 64<rt> 0 :=
      AST.zext 64<rt> (AST.extract dst 32<rt> 32))
    !!ir (byte := (getConditionCodeMul dst src src1))
    !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let wr ins insLen ctxt =
  let struct (src, src1, reg) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (reg := src <+> src1)
  !>ir insLen

let xor ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src <+> src1)
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let xorcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (dst := src <+> src1)
  !!ir (byte := (getConditionCodeLog res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen

let xnor ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  !<ir insLen
  !!ir (res := src <+> AST.not (src1))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !>ir insLen

let xnorcc ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let res = !+ir oprSize
  let ccr = !.ctxt Register.CCR
  let byte = !+ir 8<rt>
  !<ir insLen
  !!ir (res := src <+> AST.not (src1))
  if (dst = getRegVar ctxt Register.G0) then
    !!ir (dst := AST.num0 64<rt>)
  else
    !!ir (dst := res)
  !!ir (byte := (getConditionCodeLog res src src1))
  !!ir (AST.extract ccr 8<rt> 0 := byte)
  !>ir insLen
