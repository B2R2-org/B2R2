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

module internal B2R2.FrontEnd.AVR.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.AVR
open type Register

let inline numI32 n = numI32 n 8<rt>

let inline numI32PC n = LiftingUtils.numI32 n 16<rt>

let inline numI22 n = LiftingUtils.numI32 n 22<rt>

let private cfOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHighComp = AST.neg (AST.xthi 1<rt> r)
  (e1High .& e2High) .| (e1High .& rHighComp) .| (e2High .& rHighComp)

/// OF on add.
let private ofOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  (e1High .& e2High .& (AST.neg rHigh))
    .| ((AST.neg e1High) .& (AST.neg e2High) .& rHigh)

let transOprToExpr bld = function
| OprReg reg -> regVar bld reg
| OprImm imm -> numI32 imm
| OprAddr addr -> numI32PC addr
| _ -> Terminator.impossible ()

let transMemOprToExpr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprMemory (PreIdxMode (reg1)))
    -> regVar bld reg, regVar bld reg1, -1
  | TwoOperands(OprReg reg,OprMemory (PostIdxMode (reg1)))
    -> regVar bld reg, regVar bld reg1, 1
  | TwoOperands(OprReg reg,OprMemory (UnchMode (reg1)))
    -> regVar bld reg, regVar bld reg1, 0
  | _ -> Terminator.impossible ()

let transMemOprToExpr2 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprMemory (PreIdxMode (reg1)), OprReg reg)
    -> regVar bld reg1, regVar bld reg, -1
  | TwoOperands(OprMemory (PostIdxMode (reg1)), OprReg reg)
    -> regVar bld reg1, regVar bld reg, 1
  | TwoOperands(OprMemory (UnchMode (reg1)), OprReg reg)
    -> regVar bld reg1, regVar bld reg, 0
  | _ -> Terminator.impossible ()

let transMemOprToExpr1 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprMemory (DispMode (reg1, imm)))
    -> regVar bld reg, regVar bld reg1, numI32PC imm
  | _ -> Terminator.impossible ()

let transMemOprToExpr3 (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprMemory (DispMode (reg1, imm)), OprReg reg)
    -> regVar bld reg1, regVar bld reg, numI32PC imm
  | _ -> Terminator.impossible ()

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o1 -> transOprToExpr bld o1
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr bld o1,
            transOprToExpr bld o2)
  | _ -> raise InvalidOperandException

let sideEffects insAddr insLen name bld =
  bld <!-- (insAddr, insLen)
  bld <+ (AST.sideEffect name)
  bld --!> insLen

let getIndAdrReg (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands (_, OprReg reg1) ->
    let dst = reg1 |> regVar bld
    let dst1 = reg1 |> Register.toRegID |> int |> (fun n -> n + 1) |>
               RegisterID.create |> Register.ofRegID |> regVar bld
    (AST.concat dst1 dst)
  | _ -> raise InvalidOperandException

let adc ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .+ t2 .+ AST.zext 8<rt> (regVar bld CF))
  bld <+ (dst := t3)
  bld <+ (regVar bld HF := cfOnAdd (AST.extract t1 1<rt> 3)
                                   (AST.extract t2 1<rt> 3)
                                   (AST.extract t3 1<rt> 3))
  bld <+ (regVar bld CF := cfOnAdd t1 t2 t3)
  bld <+ (regVar bld VF := ofOnAdd t1 t2 t3)
  bld <+ (regVar bld NF := AST.xthi 1<rt> t3)
  bld <+ (regVar bld ZF := t3 == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let add ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .+ t2)
  bld <+ (dst := t3)
  bld <+ (regVar bld HF := cfOnAdd (AST.extract t1 1<rt> 3)
                                   (AST.extract t2 1<rt> 3)
                                   (AST.extract t3 1<rt> 3))
  bld <+ (regVar bld CF := cfOnAdd t1 t2 t3)
  bld <+ (regVar bld VF := ofOnAdd t1 t2 t3)
  bld <+ (regVar bld NF := AST.xthi 1<rt> t3)
  bld <+ (regVar bld ZF := t3 == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let adiw (ins: Instruction) len bld =
  let struct (t1, t2) = tmpVars2 bld 8<rt>
  let t3 = tmpVar bld 16<rt>
  let struct (dst, dst1, src) =
    match ins.Operands with
    | TwoOperands (OprReg reg1, OprImm imm) ->
      let dst = reg1 |> regVar bld
      let dst1 =
        reg1 |> Register.toRegID |> int
        |> (fun n -> n + 1)
        |> RegisterID.create |> Register.ofRegID |> regVar bld
      let src = imm |> numI32
      struct (dst, dst1, src)
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst1)
  bld <+ (t2 := dst)
  bld <+ (t3 := (AST.concat t1 t2) .+ AST.zext 16<rt> src)
  bld <+ (dst1 := AST.extract t3 8<rt> 8)
  bld <+ (dst := AST.extract t3 8<rt> 0)
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst1)
  bld <+ (regVar bld VF := (AST.neg (AST.xthi 1<rt> t1)) .& AST.xthi 1<rt> dst1)
  bld <+ (regVar bld ZF := t3 == (AST.num0 16<rt>))
  bld <+ (regVar bld CF := (AST.neg (AST.xthi 1<rt> dst1)) .& AST.xthi 1<rt> t1)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let ``and`` ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let r = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (r := dst .& src)
  bld <+ (dst := r)
  bld <+ (regVar bld VF := AST.b0)
  bld <+ (regVar bld NF := AST.xthi 1<rt> r)
  bld <+ (regVar bld ZF := r == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let andi ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let r = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (r := dst .& src)
  bld <+ (dst := r)
  bld <+ (regVar bld VF := AST.b0)
  bld <+ (regVar bld NF := AST.xthi 1<rt> r)
  bld <+ (regVar bld ZF := r == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let ``asr`` ins len bld =
  let dst = transOneOpr ins bld
  let oprSize = 8<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (dst := dst ?>> AST.num1 oprSize)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld CF := AST.xtlo 1<rt> t1)
  bld <+ (regVar bld VF := regVar bld NF <+> regVar bld CF)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let bld ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let imm =
    match ins.Operands with
    | TwoOperands (_, OprImm imm) -> imm
    | _ -> Terminator.impossible ()
  bld <!-- (ins.Address, len)
  bld <+ ((AST.extract dst 1<rt> imm) := regVar bld TF)
  bld --!> len

let bst ins len bld =
  let struct (dst, _) = transTwoOprs ins bld
  let imm =
    match ins.Operands with
    | TwoOperands (_, OprImm imm) -> imm
    | _ -> Terminator.impossible ()
  let r = tmpVar bld 1<rt>
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld TF := (AST.extract dst 1<rt> imm))
  bld --!> len

let call ins len bld =
  let dst = transOneOpr ins bld
  let sp = regVar bld SP
  let pc = regVar bld PC
  bld <!-- (ins.Address, len)
  bld <+ (pc := dst)
  bld <+ (AST.loadLE 16<rt> sp := pc .+ numI32PC 2)
  bld <+ (sp := sp .- numI32PC 2)
  bld --!> len

let clc (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld CF := AST.b0)
  bld --!> len

let clh (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld HF := AST.b0)
  bld --!> len

let cli (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld IF := AST.b0)
  bld --!> len

let cln (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld NF := AST.b0)
  bld --!> len

let clr ins len bld =
  let dst = transOneOpr ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst <+> dst)
  bld <+ (regVar bld SF := AST.b0)
  bld <+ (regVar bld VF := AST.b0)
  bld <+ (regVar bld NF := AST.b0)
  bld <+ (regVar bld ZF := AST.b1)
  bld --!> len

let cls (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld SF := AST.b0)
  bld --!> len

let clt (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld TF := AST.b0)
  bld --!> len

let clv (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld VF := AST.b0)
  bld --!> len

let clz (ins: Instruction) len bld =
  bld <!-- (ins.Address, len)
  bld <+ (regVar bld ZF := AST.b0)
  bld --!> len

let com ins len bld =
  let oprSize = 8<rt>
  let dst = transOneOpr ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := numI32 0xff .- dst)
  bld <+ (regVar bld CF := AST.b1)
  bld <+ (regVar bld VF := AST.b0)
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let cp ins len bld =
  let oprSize = 8<rt>
  let struct (dst, src) = transTwoOprs ins bld
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .- t2)
  bld <+ (dst := t3)
  bld <+ (regVar bld HF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld CF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld VF := ofOnAdd t3 t2 t1)
  bld <+ (regVar bld NF := AST.xthi 1<rt> t3)
  bld <+ (regVar bld ZF := t3 == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let cpc ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .- t2 .- AST.zext 8<rt> (regVar bld CF))
  bld <+ (dst := t3)
  bld <+ (regVar bld HF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld CF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld VF := ofOnAdd t3 t2 t1)
  bld <+ (regVar bld NF := AST.xthi 1<rt> t3)
  bld <+ (regVar bld ZF := (t3 == (AST.num0 oprSize)) .& regVar bld ZF)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let cpi ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .- t2)
  bld <+ (dst := t3)
  bld <+ (regVar bld HF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld CF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld VF := ofOnAdd t3 t2 t1)
  bld <+ (regVar bld NF := AST.xthi 1<rt> t3)
  bld <+ (regVar bld ZF := t3 == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let cpse ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let pc = regVar bld PC
  bld <!-- (ins.Address, len)
  let fallThrough = pc .+ numI32PC 2
  let jumpTarget = pc .+ numI32PC 4
  bld <+ (AST.intercjmp (dst == src) jumpTarget fallThrough)
  bld --!> len

let dec ins len bld =
  let dst = transOneOpr ins bld
  let oprSize = 8<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (dst := t1 .- AST.num1 oprSize)
  bld <+ (regVar bld VF := t1 == numI32 0x80)
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let fmul ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 16<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  let t4 = tmpVar bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.zext oprSize dst)
  bld <+ (t2 := AST.zext oprSize src)
  bld <+ (t3 := t1 .* t2)
  bld <+ (t4 := t3 << AST.num1 oprSize)
  bld <+ (regVar bld R1 := (AST.extract t1 8<rt> 8))
  bld <+ (regVar bld R0 := (AST.extract t1 8<rt> 0))
  bld <+ (regVar bld CF := AST.extract t3 1<rt> 15)
  bld <+ (regVar bld ZF := t4 == (AST.num0 oprSize))
  bld --!> len

let fmuls ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 16<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  let t4 = tmpVar bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.sext oprSize dst)
  bld <+ (t2 := AST.sext oprSize src)
  bld <+ (t3 := t1 .* t2)
  bld <+ (t4 := t3 << AST.num1 oprSize)
  bld <+ (regVar bld R1 := (AST.extract t1 8<rt> 8))
  bld <+ (regVar bld R0 := (AST.extract t1 8<rt> 0))
  bld <+ (regVar bld CF := AST.extract t3 1<rt> 15)
  bld <+ (regVar bld ZF := t4 == (AST.num0 oprSize))
  bld --!> len

let fmulsu ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 16<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  let t4 = tmpVar bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.sext oprSize dst)
  bld <+ (t2 := AST.zext oprSize src)
  bld <+ (t3 := t1 .* t2)
  bld <+ (t4 := t3 << AST.num1 oprSize)
  bld <+ (regVar bld R1 := (AST.extract t1 8<rt> 8))
  bld <+ (regVar bld R0 := (AST.extract t1 8<rt> 0))
  bld <+ (regVar bld CF := AST.extract t3 1<rt> 15)
  bld <+ (regVar bld ZF := t4 == (AST.num0 oprSize))
  bld --!> len

let eicall (ins: Instruction) len bld = (* FIXME *)
  bld <!-- (ins.Address, len)
  bld --!> len

let eijmp (ins: Instruction) len bld = (* FIXME *)
  bld <!-- (ins.Address, len)
  bld --!> len

let eor ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst <+> src)
  bld <+ (regVar bld VF := AST.b0)
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld ZF := dst == AST.num0 oprSize)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let icall (ins: Instruction) len bld =  (* ADD 22bit PC *)
  let pc = regVar bld PC
  let sp = regVar bld SP
  bld <!-- (ins.Address, len)
  bld <+ (pc := regVar bld Z)
  bld <+ (AST.loadLE 16<rt> sp := pc .+ numI32PC 2)
  bld <+ (sp := sp .- numI32PC 2)
  bld --!> len

let ijmp (ins: Instruction) len bld =   (* ADD 22bit PC *)
  let pc = regVar bld PC
  bld <!-- (ins.Address, len)
  bld <+ (pc := regVar bld Z)
  bld --!> len

let inc ins len bld =
  let dst = transOneOpr ins bld
  let oprSize = 8<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (dst := t1 .+ AST.num1 oprSize)
  bld <+ (regVar bld VF := t1 == numI32 0x7f)
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let ``lsr`` ins len bld =
  let dst = transOneOpr ins bld
  let oprSize = 8<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (dst := dst >> AST.num1 oprSize)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld NF := AST.b0)
  bld <+ (regVar bld CF := AST.xtlo 1<rt> t1)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld <+ (regVar bld VF := regVar bld NF <+> regVar bld CF)
  bld --!> len

let branch ins len bld =
  let dst = transOneOpr ins bld
  let pc = regVar bld PC
  let branchCond =
    match ins.Opcode with
    | Opcode.BRCC -> regVar bld CF == AST.b0
    | Opcode.BRCS -> regVar bld CF == AST.b1
    | Opcode.BREQ -> regVar bld ZF == AST.b1
    | Opcode.BRGE -> regVar bld SF == AST.b0
    | Opcode.BRHC -> regVar bld HF == AST.b0
    | Opcode.BRHS -> regVar bld HF == AST.b1
    | Opcode.BRID -> regVar bld IF == AST.b0
    | Opcode.BRIE -> regVar bld IF == AST.b1
    | Opcode.BRLT -> regVar bld SF == AST.b1
    | Opcode.BRMI -> regVar bld NF == AST.b1
    | Opcode.BRNE -> regVar bld ZF == AST.b0
    | Opcode.BRPL -> regVar bld NF == AST.b0
    | Opcode.BRTC -> regVar bld TF == AST.b0
    | Opcode.BRTS -> regVar bld TF == AST.b1
    | Opcode.BRVC -> regVar bld VF == AST.b0
    | Opcode.BRVS -> regVar bld VF == AST.b1
    | _ -> raise InvalidOpcodeException
  bld <!-- (ins.Address, len)
  let fallThrough = pc .+ numI32PC 2
  let jumpTarget = pc .+ AST.zext 16<rt> dst .+ numI32PC 2
  bld <+ (AST.intercjmp branchCond jumpTarget fallThrough)
  bld --!> len

let jmp ins len bld =
  let dst = transOneOpr ins bld
  bld <!-- (ins.Address, len)
  bld <+ (AST.interjmp dst InterJmpKind.Base)
  bld --!> len

let mov ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := src)
  bld --!> len

let movw (ins: Instruction) len bld =
  let struct (dst, dst1, src, src1) =
    match ins.Operands with
    | TwoOperands (OprReg reg1, OprReg reg2) ->
      let dst = reg1 |> regVar bld
      let dst1 =
        reg1 |> Register.toRegID |> int |> (fun n -> n + 1)
        |> RegisterID.create |> Register.ofRegID |> regVar bld
      let src = reg2 |> regVar bld
      let src1 =
        reg2 |> Register.toRegID |> int |> (fun n -> n + 1)
        |> RegisterID.create |> Register.ofRegID |> regVar bld
      struct (dst, dst1, src, src1)
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, len)
  bld <+ (dst := src)
  bld <+ (dst1 := src1)
  bld --!> len

let nop insAddr len bld =
  bld <!-- (insAddr, len)
  bld --!> len

let ``or`` ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (dst := dst .| src)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst)
  bld <+ (regVar bld VF := AST.b0)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let rjmp ins len bld =
  let dst = transOneOpr ins bld
  bld <!-- (ins.Address, len)
  bld <+ (AST.interjmp (regVar bld PC .+ dst .+ numI32PC 2)
                      InterJmpKind.Base)
  bld --!> len

let ror ins len bld =
  let dst = transOneOpr ins bld
  let oprSize = 8<rt>
  let t1 = tmpVar bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (dst := t1 >> AST.num1 oprSize)
  bld <+ ((AST.extract dst 1<rt> 7) := regVar bld CF)
  bld <+ (regVar bld ZF := dst == (AST.num0 oprSize))
  bld <+ (regVar bld CF := AST.xtlo 1<rt> t1)
  bld <+ (regVar bld NF := AST.xtlo 1<rt> dst)
  bld <+ (regVar bld VF := regVar bld NF <+> regVar bld CF)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let sbc ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .- t2 .- AST.zext 8<rt> (regVar bld CF))
  bld <+ (regVar bld HF := cfOnAdd (AST.extract t3 1<rt> 3)
                                 (AST.extract t2 1<rt> 3)
                                 (AST.extract t1 1<rt> 3))
  bld <+ (regVar bld CF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld VF := ofOnAdd t3 t2 t1)
  bld <+ (regVar bld ZF := (dst == AST.num0 oprSize .& regVar bld ZF))
  bld <+ (regVar bld NF := AST.xtlo 1<rt> t3)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let sbiw (ins: Instruction) len bld =
  let struct (t1, t2) = tmpVars2 bld 8<rt>
  let t3 = tmpVar bld 16<rt>
  let struct (dst, dst1, src) =
    match ins.Operands with
    | TwoOperands (OprReg reg1, OprImm imm) ->
      let dst = reg1 |> regVar bld
      let dst1 =
        reg1 |> Register.toRegID |> int |> (fun n -> n + 1)
        |> RegisterID.create |> Register.ofRegID |> regVar bld
      let src = imm |> numI32
      struct (dst, dst1, src)
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst1)
  bld <+ (t2 := dst)
  bld <+ (t3 := (AST.concat t1 t2) .- AST.zext 16<rt> src)
  bld <+ (dst1 := AST.extract t3 8<rt> 8)
  bld <+ (dst := AST.extract t3 8<rt> 0)
  bld <+ (regVar bld NF := AST.xthi 1<rt> dst1)
  bld <+ (regVar bld VF := (AST.neg (AST.xthi 1<rt> t1)) .& AST.xthi 1<rt> dst1)
  bld <+ (regVar bld ZF := t3 == (AST.num0 16<rt>))
  bld <+ (regVar bld CF := (AST.neg (AST.xthi 1<rt> dst1)) .& AST.xthi 1<rt> t1)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let sf (ins: Instruction) len bld =
  let setFlag =
    match ins.Opcode with
    | Opcode.SEC -> regVar bld CF := AST.b1
    | Opcode.SEH -> regVar bld HF := AST.b1
    | Opcode.SEI -> regVar bld IF := AST.b1
    | Opcode.SEN -> regVar bld NF := AST.b1
    | Opcode.SES -> regVar bld SF := AST.b1
    | Opcode.SET -> regVar bld TF := AST.b1
    | Opcode.SEV -> regVar bld VF := AST.b1
    | Opcode.SEZ -> regVar bld ZF := AST.b1
    | _ -> raise InvalidOpcodeException
  bld <!-- (ins.Address, len)
  bld <+ setFlag
  bld --!> len

let sub ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld oprSize
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (t2 := src)
  bld <+ (t3 := t1 .- t2)
  bld <+ (dst := t3)
  bld <+ (regVar bld ZF := dst == AST.num0 oprSize)
  bld <+ (regVar bld NF := AST.xtlo 1<rt> dst)
  bld <+ (regVar bld HF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld CF := cfOnAdd t3 t2 t1)
  bld <+ (regVar bld VF := ofOnAdd t3 t2 t1)
  bld <+ (regVar bld NF := AST.xthi 1<rt> t3)
  bld <+ (regVar bld ZF := t3 == AST.num0 oprSize)
  bld <+ (regVar bld SF := regVar bld NF <+> regVar bld VF)
  bld --!> len

let swap ins len bld =
  let dst = transOneOpr ins bld
  let t1 = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := dst)
  bld <+ (AST.extract t1 4<rt> 4 := AST.extract dst 4<rt> 0)
  bld <+ (AST.extract t1 4<rt> 0 := AST.extract dst 4<rt> 4)
  bld <+ (dst := t1)
  bld --!> len

let lac ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let t1 = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.loadLE 8<rt> dst)
  bld <+ (AST.loadLE 8<rt> dst := (numI32 0xff .- src) .& AST.loadLE 8<rt> dst)
  bld <+ (src := t1)
  bld --!> len

let las ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let t1 = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.loadLE 8<rt> dst)
  bld <+ (AST.loadLE 8<rt> dst := src .| AST.loadLE 8<rt> dst)
  bld <+ (src := t1)
  bld --!> len

let lat ins len bld =
  let struct (dst, src) = transTwoOprs ins bld
  let t1 = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.loadLE 8<rt> dst)
  bld <+ (AST.loadLE 8<rt> dst := src <+> AST.loadLE 8<rt> dst)
  bld <+ (src := t1)
  bld --!> len

let ld ins len bld =
  let (dst, src, mode) = transMemOprToExpr ins bld
  bld <!-- (ins.Address, len)
  match mode with
  | 0 -> bld <+ (dst := AST.loadLE 8<rt> src)
  | 1 ->
    bld <+ (dst := AST.loadLE 8<rt> src)
    match src with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2, _) ->
      bld <+ (exp1 := AST.extract (src .+ numI32PC 1) 8<rt> 8)
      bld <+ (exp2 := AST.extract (src .+ numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
  | -1 ->
    match src with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2, _) ->
      bld <+ (exp1 := AST.extract (src .- numI32PC 1) 8<rt> 8)
      bld <+ (exp2 := AST.extract (src .- numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
    bld <+ (dst := AST.loadLE 8<rt> src)
  | _ -> Terminator.impossible ()
  bld --!> len

let ldd ins len bld =
  let (dst, src, src1) = transMemOprToExpr1 ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.loadLE 8<rt> (src .+ src1))
  bld --!> len

let pop ins len bld =
  let dst = transOneOpr ins bld
  let sp = regVar bld SP
  bld <!-- (ins.Address, len)
  bld <+ (sp := sp .+ AST.num1 16<rt>)
  bld <+ (AST.loadLE 8<rt> sp := dst)
  bld --!> len

let push ins len bld =
  let dst = transOneOpr ins bld
  let sp = regVar bld SP
  bld <!-- (ins.Address, len)
  bld <+ (AST.loadLE 8<rt> sp := dst)
  bld <+ (sp := sp .- AST.num1 16<rt>)
  bld --!> len

let ldi ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := src)
  bld --!> len

let lds ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (dst := AST.loadLE 8<rt> src)
  bld --!> len

let mul ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.zext 16<rt> dst)
  bld <+ (t2 := AST.zext 16<rt> src)
  bld <+ (t3 := t1 .* t2)
  bld <+ (regVar bld R1 := AST.extract t3 8<rt> 8)
  bld <+ (regVar bld R0 := AST.extract t3 8<rt> 0)
  bld <+ (regVar bld CF := AST.extract t3 1<rt> 15)
  bld <+ (regVar bld ZF := t3 == AST.num0 16<rt>)
  bld --!> len

let muls ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.sext 16<rt> dst)
  bld <+ (t2 := AST.sext 16<rt> src)
  bld <+ (t3 := t1 .* t2)
  bld <+ (regVar bld R1 := AST.extract t3 8<rt> 8)
  bld <+ (regVar bld R0 := AST.extract t3 8<rt> 0)
  bld <+ (regVar bld CF := AST.extract t3 1<rt> 15)
  bld <+ (regVar bld ZF := t3 == AST.num0 16<rt>)
  bld --!> len

let mulsu ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 bld 16<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.sext 16<rt> dst)
  bld <+ (t2 := AST.zext 16<rt> src)
  bld <+ (t3 := t1 .* t2)
  bld <+ (regVar bld R1 := AST.extract t3 8<rt> 8)
  bld <+ (regVar bld R0 := AST.extract t3 8<rt> 0)
  bld <+ (regVar bld CF := AST.extract t3 1<rt> 15)
  bld <+ (regVar bld ZF := t3 == AST.num0 16<rt>)
  bld --!> len

let ret insAddr len opr bld =
  let sp = regVar bld SP
  bld <!-- (insAddr, len)
  bld <+ (sp := sp .+ numI32PC 2)
  bld <+ (regVar bld PC := AST.loadLE 16<rt> sp)
  if opr = Opcode.RETI then bld <+ (regVar bld IF := AST.b1)
  bld --!> len

let rcall ins len bld = (* ADD 22bit PC *)
  let dst = transOneOpr ins bld
  let sp = regVar bld SP
  let pc = regVar bld PC
  bld <!-- (ins.Address, len)
  bld <+ (pc := pc .+ dst .+ numI32PC 2)
  bld <+ (AST.loadLE 16<rt> sp := pc .+ numI32PC 2)
  bld <+ (sp := sp .- numI32PC 2)
  bld --!> len

let st ins len bld =
  let (dst, src, mode) = transMemOprToExpr2 ins bld
  bld <!-- (ins.Address, len)
  match mode with
  | 0 -> bld <+ (AST.loadLE 8<rt> dst := src)
  | 1 ->
    bld <+ (AST.loadLE 8<rt> dst := src)
    match dst with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2, _) ->
      bld <+ (exp1 := AST.extract (dst .+ numI32PC 1) 8<rt> 8)
      bld <+ (exp2 := AST.extract (dst .+ numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
  | -1 ->
    match dst with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2, _) ->
      bld <+ (exp1 := AST.extract (dst .- numI32PC 1) 8<rt> 8)
      bld <+ (exp2 := AST.extract (dst .- numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
    bld <+ (AST.loadLE 8<rt> dst := src)
  | _ -> Terminator.impossible ()
  bld --!> len

let std ins len bld =
  let (dst, src, disp) = transMemOprToExpr3 ins bld
  bld <!-- (ins.Address, len)
  bld <+ (AST.loadLE 8<rt> (dst .+ disp) := src)
  bld --!> len

let sts ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  bld <!-- (ins.Address, len)
  bld <+ (AST.loadLE 8<rt> (dst) := src)
  bld --!> len

let des ins len bld =
  let dst = transOneOpr ins bld
  bld <!-- (ins.Address, len)
  bld <+ (AST.sideEffect UnsupportedExtension)
  bld --!> len

let xch ins len bld =
  let struct(dst, src) = transTwoOprs ins bld
  let t1 = tmpVar bld 8<rt>
  bld <!-- (ins.Address, len)
  bld <+ (t1 := AST.loadLE 8<rt> dst)
  bld <+ (AST.loadLE 8<rt> dst := src)
  bld <+ (src := t1)
  bld --!> len
