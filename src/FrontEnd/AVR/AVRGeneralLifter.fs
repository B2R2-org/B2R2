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
open B2R2.FrontEnd.BinLifter.LiftingOperators
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

let inline ( !. ) (ctxt: TranslationContext) reg =
  Register.toRegID reg |> ctxt.GetRegVar

let transOprToExpr ctxt = function
| OprReg reg -> !.ctxt reg
| OprImm imm -> numI32 imm
| OprAddr addr -> numI32PC addr
| _ -> Terminator.impossible ()

let transMemOprToExpr ins ctxt =
  match ins.Operands with
  | TwoOperands(OprReg reg, OprMemory (PreIdxMode(reg1)))
    -> !.ctxt reg,!.ctxt reg1,-1
  | TwoOperands(OprReg reg,OprMemory (PostIdxMode(reg1)))
    -> !.ctxt reg, !.ctxt reg1, 1
  | TwoOperands(OprReg reg,OprMemory (UnchMode(reg1)))
    -> !.ctxt reg, !.ctxt reg1, 0
  | _ -> Terminator.impossible ()

let transMemOprToExpr2 ins ctxt =
  match ins.Operands with
  | TwoOperands(OprMemory (PreIdxMode(reg1)), OprReg reg)
    -> !.ctxt reg1, !.ctxt reg, -1
  | TwoOperands(OprMemory (PostIdxMode(reg1)), OprReg reg)
    -> !.ctxt reg1, !.ctxt reg, 1
  | TwoOperands(OprMemory (UnchMode(reg1)), OprReg reg)
    -> !.ctxt reg1, !.ctxt reg, 0
  | _ -> Terminator.impossible ()

let transMemOprToExpr1 ins ctxt=
  match ins.Operands with
  | TwoOperands(OprReg reg, OprMemory (DispMode (reg1, imm)))
    -> !.ctxt reg, !.ctxt reg1, numI32PC imm
  | _ -> Terminator.impossible ()

let transMemOprToExpr3 ins ctxt=
  match ins.Operands with
  | TwoOperands(OprMemory (DispMode (reg1, imm)), OprReg reg)
    -> !.ctxt reg1,!.ctxt reg, numI32PC imm
  | _ -> Terminator.impossible ()

let transOneOpr (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand o1 -> transOprToExpr ctxt o1
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr ctxt o1,
            transOprToExpr ctxt o2)
  | _ -> raise InvalidOperandException

let sideEffects insLen name =
  let ir = IRBuilder (4)
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let getIndAdrReg ins ctxt=
  match ins.Operands with
  | TwoOperands (_, OprReg reg1) ->
    let dst = reg1 |> !.ctxt
    let dst1 = reg1 |> Register.toRegID |> int |> (fun n -> n+1) |>
               RegisterID.create |> Register.ofRegID |> !.ctxt
    (AST.concat dst1 dst)
  | _ -> raise InvalidOperandException

let adc ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .+ t2 .+ AST.zext 8<rt> (!.ctxt CF) )
  !!ir (dst := t3)
  !!ir (!.ctxt HF := cfOnAdd (AST.extract t1 1<rt> 3)
                                 (AST.extract t2 1<rt> 3)
                                 (AST.extract t3 1<rt> 3))
  !!ir (!.ctxt CF := cfOnAdd t1 t2 t3)
  !!ir (!.ctxt VF := ofOnAdd t1 t2 t3)
  !!ir (!.ctxt NF := AST.xthi 1<rt> t3)
  !!ir (!.ctxt ZF := t3 == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let add ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !!ir (!.ctxt HF := cfOnAdd (AST.extract t1 1<rt> 3)
                                 (AST.extract t2 1<rt> 3)
                                 (AST.extract t3 1<rt> 3))
  !!ir (!.ctxt CF := cfOnAdd t1 t2 t3)
  !!ir (!.ctxt VF := ofOnAdd t1 t2 t3)
  !!ir (!.ctxt NF := AST.xthi 1<rt> t3)
  !!ir (!.ctxt ZF := t3 == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let adiw ins len ctxt =
  let ir = IRBuilder(8)
  let struct (t1, t2) = tmpVars2 ir 8<rt>
  let t3 = !+ir 16<rt>
  let struct (dst, dst1, src) =
    match ins.Operands with
    | TwoOperands (OprReg reg1, OprImm imm) ->
      let dst = reg1 |> !.ctxt
      let dst1 = reg1 |> Register.toRegID |> int |> (fun n -> n+1) |>
                 RegisterID.create |> Register.ofRegID |> !.ctxt
      let src = imm |> numI32
      struct (dst, dst1, src)
    | _ -> raise InvalidOperandException
  !<ir len
  !!ir (t1 := dst1)
  !!ir (t2 := dst)
  !!ir (t3 := (AST.concat t1 t2) .+ AST.zext 16<rt> src)
  !!ir (dst1 := AST.extract t3 8<rt> 8 )
  !!ir (dst := AST.extract t3 8<rt> 0)
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst1)
  !!ir (!.ctxt VF := (AST.neg (AST.xthi 1<rt> t1)) .& AST.xthi 1<rt> dst1)
  !!ir (!.ctxt ZF := t3 == (AST.num0 16<rt>))
  !!ir (!.ctxt CF := (AST.neg (AST.xthi 1<rt> dst1)) .& AST.xthi 1<rt> t1)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let ``and`` ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let r = !+ir oprSize
  !<ir len
  !!ir (r := dst .& src)
  !!ir (dst := r)
  !!ir (!.ctxt VF := AST.b0)
  !!ir (!.ctxt NF := AST.xthi 1<rt> r)
  !!ir (!.ctxt ZF := r == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let andi ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let r = !+ir oprSize
  !<ir len
  !!ir (r := dst .& src)
  !!ir (dst := r)
  !!ir (!.ctxt VF := AST.b0)
  !!ir (!.ctxt NF := AST.xthi 1<rt> r)
  !!ir (!.ctxt ZF := r == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let ``asr`` ins len ctxt =
  let dst = transOneOpr ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (dst := dst ?>> AST.num1 oprSize)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst)
  !!ir (!.ctxt CF := AST.xtlo 1<rt> t1)
  !!ir (!.ctxt VF := !.ctxt NF <+> !.ctxt CF)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let bld ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let imm =
    match ins.Operands with
    | TwoOperands (_, OprImm imm) -> imm
    | _ -> Terminator.impossible ()
  let ir = IRBuilder (16)
  !<ir len
  !!ir ( (AST.extract dst 1<rt> imm) := !.ctxt TF)
  !>ir len

let bst ins len ctxt =
  let struct (dst, _) = transTwoOprs ins ctxt
  let imm =
    match ins.Operands with
    | TwoOperands (_, OprImm imm) -> imm
    | _ -> Terminator.impossible ()
  let ir = IRBuilder (16)
  let r = !+ir 1<rt>
  !<ir len
  !!ir (!.ctxt TF := (AST.extract dst 1<rt> imm))
  !>ir len

let call ins len ctxt =
  let ir = IRBuilder (4)
  let dst = transOneOpr ins ctxt
  let sp = !.ctxt SP
  let pc = !.ctxt PC
  !<ir len
  !!ir (pc := dst)
  !!ir (AST.loadLE 16<rt> sp := pc .+ numI32PC 2)
  !!ir (sp := sp .- numI32PC 2)
  !>ir len

let clc ins len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt CF := AST.b0)
  !>ir len

let clh len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt HF := AST.b0)
  !>ir len

let cli len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt IF := AST.b0)
  !>ir len

let cln len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt NF := AST.b0)
  !>ir len

let clr ins len ctxt =
  let dst = transOneOpr ins ctxt
  let ir = IRBuilder (8)
  !<ir len
  !!ir (dst := dst <+> dst)
  !!ir (!.ctxt SF := AST.b0)
  !!ir (!.ctxt VF := AST.b0)
  !!ir (!.ctxt NF := AST.b0)
  !!ir (!.ctxt ZF := AST.b1)
  !>ir len

let cls len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt SF := AST.b0)
  !>ir len

let clt len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt TF := AST.b0)
  !>ir len

let clv len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt VF := AST.b0)
  !>ir len

let clz len ctxt =
  let ir = IRBuilder (4)
  !<ir len
  !!ir (!.ctxt ZF := AST.b0)
  !>ir len

let com ins len ctxt =
  let ir = IRBuilder(4)
  let oprSize = 8<rt>
  let dst = transOneOpr ins ctxt
  !<ir len
  !!ir (dst := numI32 0xff .- dst)
  !!ir (!.ctxt CF := AST.b1)
  !!ir (!.ctxt VF := AST.b0)
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let cp ins len ctxt =
  let ir = IRBuilder(4)
  let oprSize = 8<rt>
  let struct (dst, src) = transTwoOprs ins ctxt
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .- t2)
  !!ir (dst := t3)
  !!ir (!.ctxt HF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt CF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt VF := ofOnAdd t3 t2 t1)
  !!ir (!.ctxt NF := AST.xthi 1<rt> t3)
  !!ir (!.ctxt ZF := t3 == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let cpc ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .- t2 .- AST.zext 8<rt> (!.ctxt CF) )
  !!ir (dst := t3)
  !!ir (!.ctxt HF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt CF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt VF := ofOnAdd t3 t2 t1)
  !!ir (!.ctxt NF := AST.xthi 1<rt> t3)
  !!ir (!.ctxt ZF := (t3 == (AST.num0 oprSize)) .& !.ctxt ZF)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let cpi ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .- t2)
  !!ir (dst := t3)
  !!ir (!.ctxt HF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt CF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt VF := ofOnAdd t3 t2 t1)
  !!ir (!.ctxt NF := AST.xthi 1<rt> t3)
  !!ir (!.ctxt ZF := t3 == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let cpse ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (4)
  let pc = !.ctxt PC
  !<ir len
  let fallThrough = pc .+ numI32PC 2
  let jumpTarget = pc .+ numI32PC 4
  !!ir (AST.intercjmp (dst == src) jumpTarget fallThrough)
  !>ir len

let dec ins len ctxt =
  let dst = transOneOpr ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (dst := t1 .- AST.num1 oprSize)
  !!ir (!.ctxt VF := t1 == numI32 0x80)
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let fmul ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 16<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let t4 = !+ir 16<rt>
  !<ir len
  !!ir (t1 := AST.zext oprSize dst)
  !!ir (t2 := AST.zext oprSize src)
  !!ir (t3 := t1 .* t2)
  !!ir (t4 := t3 << AST.num1 oprSize)
  !!ir (!.ctxt R1 := (AST.extract t1 8<rt> 8))
  !!ir (!.ctxt R0 := (AST.extract t1 8<rt> 0))
  !!ir (!.ctxt CF := AST.extract t3 1<rt> 15)
  !!ir (!.ctxt ZF := t4 == (AST.num0 oprSize))
  !>ir len

let fmuls ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 16<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let t4 = !+ir 16<rt>
  !<ir len
  !!ir (t1 := AST.sext oprSize dst)
  !!ir (t2 := AST.sext oprSize src)
  !!ir (t3 := t1 .* t2)
  !!ir (t4 := t3 << AST.num1 oprSize)
  !!ir (!.ctxt R1 := (AST.extract t1 8<rt> 8))
  !!ir (!.ctxt R0 := (AST.extract t1 8<rt> 0))
  !!ir (!.ctxt CF := AST.extract t3 1<rt> 15)
  !!ir (!.ctxt ZF := t4 == (AST.num0 oprSize))
  !>ir len

let fmulsu ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 16<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let t4 = !+ir 16<rt>
  !<ir len
  !!ir (t1 := AST.sext oprSize dst)
  !!ir (t2 := AST.zext oprSize src)
  !!ir (t3 := t1 .* t2)
  !!ir (t4 := t3 << AST.num1 oprSize)
  !!ir (!.ctxt R1 := (AST.extract t1 8<rt> 8))
  !!ir (!.ctxt R0 := (AST.extract t1 8<rt> 0))
  !!ir (!.ctxt CF := AST.extract t3 1<rt> 15)
  !!ir (!.ctxt ZF := t4 == (AST.num0 oprSize))
  !>ir len

let eicall len =  (*ADD ME*)
  let ir = IRBuilder(4)
  !<ir len
  !>ir len

let eijmp len =  (*ADD ME*)
  let ir = IRBuilder(4)
  !<ir len
  !>ir len

let eor ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  !<ir len
  !!ir (dst := dst <+> src)
  !!ir (!.ctxt VF := AST.b0)
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst)
  !!ir (!.ctxt ZF := dst == AST.num0 oprSize)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let icall len ctxt =  (* ADD 22bit PC *)
  let ir = IRBuilder(4)
  let pc = !.ctxt PC
  let sp = !.ctxt SP
  !<ir len
  !!ir (pc := !.ctxt Z)
  !!ir (AST.loadLE 16<rt> sp := pc .+ numI32PC 2)
  !!ir (sp := sp .- numI32PC 2)
  !>ir len

let ijmp len ctxt =   (* ADD 22bit PC *)
  let ir = IRBuilder (4)
  let pc = !.ctxt PC
  !<ir len
  !!ir (pc := !.ctxt Z)
  !>ir len

let inc ins len ctxt =
  let dst = transOneOpr ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (dst := t1 .+ AST.num1 oprSize)
  !!ir (!.ctxt VF := t1 == numI32 0x7f)
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let ``lsr`` ins len ctxt =
  let dst = transOneOpr ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (dst := dst >> AST.num1 oprSize)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt NF := AST.b0)
  !!ir (!.ctxt CF := AST.xtlo 1<rt> t1)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !!ir (!.ctxt VF := !.ctxt NF <+> !.ctxt CF)
  !>ir len

let branch ins len ctxt =
  let ir = IRBuilder (8)
  let dst = transOneOpr ins ctxt
  let pc = !.ctxt PC
  let branchCond =
    match ins.Opcode with
    | Opcode.BRCC -> !.ctxt CF == AST.b0
    | Opcode.BRCS -> !.ctxt CF == AST.b1
    | Opcode.BREQ -> !.ctxt ZF == AST.b1
    | Opcode.BRGE -> !.ctxt SF == AST.b0
    | Opcode.BRHC -> !.ctxt HF == AST.b0
    | Opcode.BRHS -> !.ctxt HF == AST.b1
    | Opcode.BRID -> !.ctxt IF == AST.b0
    | Opcode.BRIE -> !.ctxt IF == AST.b1
    | Opcode.BRLT -> !.ctxt SF == AST.b1
    | Opcode.BRMI -> !.ctxt NF == AST.b1
    | Opcode.BRNE -> !.ctxt ZF == AST.b0
    | Opcode.BRPL -> !.ctxt NF == AST.b0
    | Opcode.BRTC -> !.ctxt TF == AST.b0
    | Opcode.BRTS -> !.ctxt TF == AST.b1
    | Opcode.BRVC -> !.ctxt VF == AST.b0
    | Opcode.BRVS -> !.ctxt VF == AST.b1
    | _ -> raise InvalidOpcodeException
  !<ir len
  let fallThrough = pc .+ numI32PC 2
  let jumpTarget = pc .+ AST.zext 16<rt> dst .+ numI32PC 2
  !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir len

let jmp ins len ctxt =
  let dst = transOneOpr ins ctxt
  let ir = IRBuilder (4)
  !<ir len
  !!ir (AST.interjmp dst InterJmpKind.Base)
  !>ir len

let mov ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (4)
  !<ir len
  !!ir (dst := src)
  !>ir len

let movw ins len ctxt =
  let struct (dst, dst1, src, src1) =
    match ins.Operands with
    | TwoOperands (OprReg reg1, OprReg reg2) ->
      let dst = reg1 |> !.ctxt
      let dst1 = reg1 |> Register.toRegID |> int |> (fun n -> n+1) |>
                 RegisterID.create |> Register.ofRegID |> !.ctxt
      let src = reg2 |> !.ctxt
      let src1 = reg2 |> Register.toRegID |> int |> (fun n -> n+1) |>
                 RegisterID.create |> Register.ofRegID |> !.ctxt
      struct (dst, dst1, src, src1)
    | _ -> raise InvalidOperandException
  let ir = IRBuilder (4)
  !<ir len
  !!ir (dst := src)
  !!ir (dst1 := src1)
  !>ir len

let nop len =
  let ir = IRBuilder (2)
  !<ir len
  !>ir len

let ``or`` ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (4)
  !<ir len
  !!ir (dst := dst .| src)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst)
  !!ir (!.ctxt VF := AST.b0)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let rjmp ins len ctxt =
  let ir = IRBuilder (4)
  let dst = transOneOpr ins ctxt
  !<ir len
  !!ir (AST.interjmp (!.ctxt PC .+ dst .+ numI32PC 2)
                      InterJmpKind.Base)
  !>ir len

let ror ins len ctxt =
  let dst = transOneOpr ins ctxt
  let ir = IRBuilder (16)
  let oprSize = 8<rt>
  let t1 = !+ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (dst := t1 >> AST.num1 oprSize)
  !!ir ( (AST.extract dst 1<rt> 7) := !.ctxt CF)
  !!ir (!.ctxt ZF := dst == (AST.num0 oprSize))
  !!ir (!.ctxt CF := AST.xtlo 1<rt> t1)
  !!ir (!.ctxt NF := AST.xtlo 1<rt> dst)
  !!ir (!.ctxt VF := !.ctxt NF <+> !.ctxt CF)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let sbc ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (8)
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .- t2 .- AST.zext 8<rt> (!.ctxt CF))
  !!ir (!.ctxt HF := cfOnAdd (AST.extract t3 1<rt> 3)
                                 (AST.extract t2 1<rt> 3)
                                 (AST.extract t1 1<rt> 3))
  !!ir (!.ctxt CF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt VF := ofOnAdd t3 t2 t1)
  !!ir (!.ctxt ZF := (dst == AST.num0 oprSize .& !.ctxt ZF))
  !!ir (!.ctxt NF := AST.xtlo 1<rt> t3)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let sbiw ins len ctxt =
  let ir = IRBuilder(8)
  let struct (t1, t2) = tmpVars2 ir 8<rt>
  let t3 = !+ir 16<rt>
  let struct (dst, dst1, src) =
    match ins.Operands with
    | TwoOperands (OprReg reg1, OprImm imm) ->
      let dst = reg1 |> !.ctxt
      let dst1 = reg1 |> Register.toRegID |> int |> (fun n -> n+1) |>
                 RegisterID.create |> Register.ofRegID |> !.ctxt
      let src = imm |> numI32
      struct (dst, dst1, src)
    | _ -> raise InvalidOperandException
  !<ir len
  !!ir (t1 := dst1)
  !!ir (t2 := dst)
  !!ir (t3 := (AST.concat t1 t2) .- AST.zext 16<rt> src)
  !!ir (dst1 := AST.extract t3 8<rt> 8 )
  !!ir (dst := AST.extract t3 8<rt> 0)
  !!ir (!.ctxt NF := AST.xthi 1<rt> dst1)
  !!ir (!.ctxt VF := (AST.neg (AST.xthi 1<rt> t1)) .& AST.xthi 1<rt> dst1)
  !!ir (!.ctxt ZF := t3 == (AST.num0 16<rt>))
  !!ir (!.ctxt CF := (AST.neg (AST.xthi 1<rt> dst1)) .& AST.xthi 1<rt> t1)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let sf ins len ctxt =
  let ir = IRBuilder(4)
  let setFlag =
    match ins.Opcode with
    | Opcode.SEC -> !.ctxt CF := AST.b1
    | Opcode.SEH -> !.ctxt HF := AST.b1
    | Opcode.SEI -> !.ctxt IF := AST.b1
    | Opcode.SEN -> !.ctxt NF := AST.b1
    | Opcode.SES -> !.ctxt SF := AST.b1
    | Opcode.SET -> !.ctxt TF := AST.b1
    | Opcode.SEV -> !.ctxt VF := AST.b1
    | Opcode.SEZ -> !.ctxt ZF := AST.b1
    | _ -> raise InvalidOpcodeException
  !<ir len
  !!ir setFlag
  !>ir len

let sub ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (8)
  let oprSize = 8<rt>
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir len
  !!ir (t1 := dst)
  !!ir (t2 := src)
  !!ir (t3 := t1 .- t2)
  !!ir (dst := t3)
  !!ir (!.ctxt ZF := dst == AST.num0 oprSize)
  !!ir (!.ctxt NF := AST.xtlo 1<rt> dst)
  !!ir (!.ctxt HF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt CF := cfOnAdd t3 t2 t1)
  !!ir (!.ctxt VF := ofOnAdd t3 t2 t1)
  !!ir (!.ctxt NF := AST.xthi 1<rt> t3)
  !!ir (!.ctxt ZF := t3 == AST.num0 oprSize)
  !!ir (!.ctxt SF := !.ctxt NF <+> !.ctxt VF)
  !>ir len

let swap ins len ctxt =
  let dst = transOneOpr ins ctxt
  let ir = IRBuilder (4)
  let t1 = !+ir 8<rt>
  !<ir len
  !!ir (t1 := dst)
  !!ir (AST.extract t1 4<rt> 4 := AST.extract dst 4<rt> 0)
  !!ir (AST.extract t1 4<rt> 0 := AST.extract dst 4<rt> 4)
  !!ir (dst := t1)
  !>ir len

let lac ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (4)
  let t1 = !+ir 8<rt>
  !<ir len
  !!ir (t1 := AST.loadLE 8<rt> dst)
  !!ir (AST.loadLE 8<rt> dst := (numI32 0xff .- src) .& AST.loadLE 8<rt> dst)
  !!ir (src := t1)
  !>ir len

let las ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (4)
  let t1 = !+ir 8<rt>
  !<ir len
  !!ir (t1 := AST.loadLE 8<rt> dst)
  !!ir (AST.loadLE 8<rt> dst := src .| AST.loadLE 8<rt> dst)
  !!ir (src := t1)
  !>ir len

let lat ins len ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (4)
  let t1 = !+ir 8<rt>
  !<ir len
  !!ir (t1 := AST.loadLE 8<rt> dst)
  !!ir (AST.loadLE 8<rt> dst := src <+> AST.loadLE 8<rt> dst)
  !!ir (src := t1)
  !>ir len

let ld ins len ctxt =
  let ir = IRBuilder (8)
  let (dst, src, mode) = transMemOprToExpr ins ctxt
  !<ir len
  match mode with
  | 0 -> !!ir (dst := AST.loadLE 8<rt> src)
  | 1 ->
    !!ir (dst := AST.loadLE 8<rt> src)
    match src.E with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2) ->
      !!ir (exp1 := AST.extract (src .+ numI32PC 1) 8<rt> 8)
      !!ir (exp2 := AST.extract (src .+ numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
  | -1 ->
    match src.E with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2) ->
      !!ir (exp1 := AST.extract (src .- numI32PC 1) 8<rt> 8)
      !!ir (exp2 := AST.extract (src .- numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
    !!ir (dst := AST.loadLE 8<rt> src)
  | _ -> Terminator.impossible ()
  !>ir len

let ldd ins len ctxt =
  let (dst, src, src1) = transMemOprToExpr1 ins ctxt
  let ir = IRBuilder (8)
  !<ir len
  !!ir (dst := AST.loadLE 8<rt> (src .+  src1))
  !>ir len

let pop ins len ctxt =
  let dst = transOneOpr ins ctxt
  let ir = IRBuilder (8)
  let sp = !.ctxt SP
  !<ir len
  !!ir (sp := sp .+ AST.num1 16<rt>)
  !!ir (AST.loadLE 8<rt> sp := dst)
  !>ir len

let push ins len ctxt =
  let dst = transOneOpr ins ctxt
  let ir = IRBuilder (8)
  let sp = !.ctxt SP
  !<ir len
  !!ir (AST.loadLE 8<rt> sp := dst)
  !!ir (sp := sp .- AST.num1 16<rt>)
  !>ir len

let ldi ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (8)
  !<ir len
  !!ir (dst := src)
  !>ir len

let lds ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder (8)
  !<ir len
  !!ir (dst := AST.loadLE 8<rt> src)
  !>ir len

let mul ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (8)
  let struct (t1, t2, t3) = tmpVars3 ir 16<rt>
  !<ir len
  !!ir (t1 := AST.zext 16<rt> dst)
  !!ir (t2 := AST.zext 16<rt> src)
  !!ir (t3 := t1 .* t2)
  !!ir (!.ctxt R1 := AST.extract t3 8<rt> 8)
  !!ir (!.ctxt R0 := AST.extract t3 8<rt> 0)
  !!ir (!.ctxt CF := AST.extract t3 1<rt> 15)
  !!ir (!.ctxt ZF := t3 == AST.num0 16<rt>)
  !>ir len

let muls ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (8)
  let struct (t1, t2, t3) = tmpVars3 ir 16<rt>
  !<ir len
  !!ir (t1 := AST.sext 16<rt> dst)
  !!ir (t2 := AST.sext 16<rt> src)
  !!ir (t3 := t1 .* t2)
  !!ir (!.ctxt R1 := AST.extract t3 8<rt> 8)
  !!ir (!.ctxt R0 := AST.extract t3 8<rt> 0)
  !!ir (!.ctxt CF := AST.extract t3 1<rt> 15)
  !!ir (!.ctxt ZF := t3 == AST.num0 16<rt>)
  !>ir len

let mulsu ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let oprSize = 8<rt>
  let ir = IRBuilder (8)
  let struct (t1, t2, t3) = tmpVars3 ir 16<rt>
  !<ir len
  !!ir (t1 := AST.sext 16<rt> dst)
  !!ir (t2 := AST.zext 16<rt> src)
  !!ir (t3 := t1 .* t2)
  !!ir (!.ctxt R1 := AST.extract t3 8<rt> 8)
  !!ir (!.ctxt R0 := AST.extract t3 8<rt> 0)
  !!ir (!.ctxt CF := AST.extract t3 1<rt> 15)
  !!ir (!.ctxt ZF := t3 == AST.num0 16<rt>)
  !>ir len

let ret len opr ctxt =
  let sp = !.ctxt SP
  let ir = IRBuilder(8)
  !<ir len
  !!ir (sp := sp .+ numI32PC 2)
  !!ir (!.ctxt PC := AST.loadLE 16<rt> sp)
  if opr = Opcode.RETI then !!ir (!.ctxt IF := AST.b1)
  !>ir len

let rcall ins len ctxt = (* ADD 22bit PC *)
  let ir = IRBuilder (4)
  let dst = transOneOpr ins ctxt
  let sp = !.ctxt SP
  let pc = !.ctxt PC
  !<ir len
  !!ir (pc := pc .+ dst .+ numI32PC 2)
  !!ir (AST.loadLE 16<rt> sp := pc .+ numI32PC 2)
  !!ir (sp := sp .- numI32PC 2)
  !>ir len

let st ins len ctxt =
  let ir = IRBuilder (8)
  let (dst, src, mode) = transMemOprToExpr2 ins ctxt
  !<ir len
  match mode with
  | 0 -> !!ir (AST.loadLE 8<rt> dst :=  src)
  | 1 ->
    !!ir (AST.loadLE 8<rt> dst :=  src)
    match dst.E with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2) ->
      !!ir (exp1 := AST.extract (dst .+ numI32PC 1) 8<rt> 8)
      !!ir (exp2 := AST.extract (dst .+ numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
  | -1 ->
    match dst.E with
    | BinOp (BinOpType.CONCAT, _, exp1, exp2) ->
      !!ir (exp1 := AST.extract (dst .- numI32PC 1) 8<rt> 8)
      !!ir (exp2 := AST.extract (dst .- numI32PC 1) 8<rt> 0)
    | _ -> Terminator.impossible ()
    !!ir (AST.loadLE 8<rt> dst := src)
  | _ -> Terminator.impossible ()
  !>ir len

let std ins len ctxt =
  let (dst, src, disp) = transMemOprToExpr3 ins ctxt
  let ir = IRBuilder (8)
  !<ir len
  !!ir (AST.loadLE 8<rt> (dst .+ disp) := src)
  !>ir len

let sts ins len ctxt =
  let struct(dst, src) = transTwoOprs ins ctxt
  let ir = IRBuilder(4)
  !<ir len
  !!ir (AST.loadLE 8<rt> (dst) := src)
  !>ir len

let des ins len ctxt =
  let ir = IRBuilder (4)
  let dst = transOneOpr ins ctxt
  !<ir len
  !!ir (AST.sideEffect UnsupportedExtension)
  !>ir len

let xch ins len ctxt =
  let ir = IRBuilder (4)
  let struct(dst, src) = transTwoOprs ins ctxt
  let t1 = !+ir 8<rt>
  !<ir len
  !!ir (t1 := AST.loadLE 8<rt> dst)
  !!ir (AST.loadLE 8<rt> dst := src)
  !!ir (src := t1)
  !>ir len
