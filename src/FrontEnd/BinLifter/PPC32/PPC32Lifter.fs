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

module internal B2R2.FrontEnd.BinLifter.PPC32.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.BinLifter.PPC32
open B2R2.FrontEnd.BinLifter.PPC32.OperandHelper

let inline ( !. ) (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let getOneOpr (ins: InsInfo) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: InsInfo) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: InsInfo) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getExtMask mb me =
  let struct (mb, me) =
    match mb.E, me.E with
    | Num b, Num m -> struct (b.SmallValue () |> int, m.SmallValue () |> int)
    | _ -> raise InvalidExprException
  let mask = (System.UInt32.MaxValue >>> (32 - (me - mb + 1))) <<< mb
  numU32 mask 32<rt>

let transOprToExpr ins (ctxt: TranslationContext) = function
  | OprReg reg -> !.ctxt reg
  | OprRegBit (reg, idx) -> AST.extract (!.ctxt reg) 1<rt> (int idx)
  | OprMem (d, b) -> /// FIXME
    AST.loadLE 32<rt> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
  | OprImm imm -> numU64 imm ctxt.WordBitSize
  | OprAddr addr ->
    numI64 (int64 (ins.Address + addr) + int64 ins.NumBytes) ctxt.WordBitSize
    |> AST.loadLE ctxt.WordBitSize
  | OprBI bi -> numU32 bi ctxt.WordBitSize

let transOneOpr (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand o ->
    transOprToExpr ins ctxt o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOprToExpr ins ctxt o1, transOprToExpr ins ctxt o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOprToExpr ins ctxt o1,
            transOprToExpr ins ctxt o2,
            transOprToExpr ins ctxt o3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOprToExpr ins ctxt o1,
            transOprToExpr ins ctxt o2,
            transOprToExpr ins ctxt o3,
            transOprToExpr ins ctxt o4)
  | _ -> raise InvalidOperandException

let transFiveOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | FiveOperands (o1, o2, o3, o4, o5) ->
    struct (transOprToExpr ins ctxt o1,
            transOprToExpr ins ctxt o2,
            transOprToExpr ins ctxt o3,
            transOprToExpr ins ctxt o4,
            transOprToExpr ins ctxt o5)
  | _ -> raise InvalidOperandException

let getImmValue = function
  | OprImm imm -> uint32 imm
  | OprBI imm -> imm
  | _ -> raise InvalidOperandException

let setCondReg ctxt ir result =
  let cr0 = !.ctxt R.CR0
  !!ir (AST.extract cr0 1<rt> 0 := result .< AST.num0 32<rt>)
  !!ir (AST.extract cr0 1<rt> 1 := result .> AST.num0 32<rt>)
  !!ir (AST.extract cr0 1<rt> 2 := result == AST.num0 32<rt>)
  !!ir (AST.extract cr0 1<rt> 3 := AST.b0) /// FIXME: XER[SO]

let sideEffects insLen ctxt name =
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.sideEffect name)
  !>ir insLen

let add ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2)
  setCondReg ctxt ir dst
  !>ir insLen

let addc ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2)
  /// Affected: XER[CA]
  !>ir insLen

let adde ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xer = !.ctxt R.XER
  let ca = AST.zext 32<rt> (AST.extract xer 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2 .+ ca)
  /// Affected: XER[CA]
  !>ir insLen

let addi ins insLen ctxt =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let cond = src1 == AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.ite cond simm (src1 .+ simm)))
  !>ir insLen

let addic ins insLen ctxt =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ simm)
  /// Affected: XER[CA]
  !>ir insLen

let addis ins insLen ctxt =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let cond = src1 == AST.num0 32<rt>
  let simm = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.ite cond simm (src1 .+ simm)))
  !>ir insLen

let addze ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xer = !.ctxt R.XER
  let ca = AST.zext 32<rt> (AST.extract xer 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ ca)
  !>ir insLen

let addzedot ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xer = !.ctxt R.XER
  let ca = AST.zext 32<rt> (AST.extract xer 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ ca)
  setCondReg ctxt ir dst
  !>ir insLen

let andx ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& src2)
  !>ir insLen

let andidot ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = AST.concat (AST.num0 16<rt>) (AST.xtlo 16<rt> uimm)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .& uimm)
  !>ir insLen

let b ins insLen ctxt =
  let addr = numU64 ins.Address 32<rt> .+ transOneOpr ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.interjmp addr InterJmpKind.Base)
  !>ir insLen

let ba ins insLen ctxt =
  let addr = transOneOpr ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.interjmp addr InterJmpKind.Base)
  !>ir insLen

let bl ins insLen ctxt =
  let addr = numU64 ins.Address 32<rt> .+ transOneOpr ins ctxt
  let lr = !.ctxt R.LR
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.interjmp addr InterJmpKind.Base)
  !!ir (lr := numU64 ins.Address 32<rt> .+ numI32 4 32<rt>)
  !>ir insLen

let bla ins insLen ctxt =
  let addr = transOneOpr ins ctxt
  let lr = !.ctxt R.LR
  let ir = !*ctxt
  !<ir insLen
  !!ir (AST.interjmp addr InterJmpKind.Base)
  !!ir (lr := numU64 ins.Address 32<rt> .+ numI32 4 32<rt>)
  !>ir insLen

let bc ins insLen ctxt =
  let struct (bo, bi, addr) = getThreeOprs ins
  let bo = transOprToExpr ins ctxt bo
  let bi = getImmValue bi
  let cr = getCondRegister (bi / 4u) |> !.ctxt
  let addr = transOprToExpr ins ctxt addr
  let ir = !*ctxt
  let ctr = !.ctxt R.CTR
  let idx = numU32 (bi % 4u) 4<rt>
  let bo x = AST.extract bo 1<rt> x (* bo x *)
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (ctr := AST.ite (AST.not (bo 2)) (ctr .- AST.num1 32<rt>) ctr)
  !!ir (ctrOk := bo 2 .| ((ctr != AST.num0 32<rt>) <+> bo 3))
  !!ir (condOk := bo 0 .| (AST.xtlo 1<rt> (cr >> idx) <+> AST.not (bo 1)))
  !!ir (temp := AST.ite (ctrOk .& condOk) nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bge ins insLen ctxt =
  let struct (crs, addr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := (AST.xtlo 1<rt> crs <+> AST.b1)) (* FIXME: BO[0], BO[1] *)
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let ble ins insLen ctxt =
  let struct (crs, addr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  (* FIXME: BO[0], BO[1] *)
  !!ir (condOk := (AST.extract crs 1<rt> 1 <+> AST.b1))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bne ins insLen ctxt =
  let struct (crs, addr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  (* FIXME: BO[0], BO[1] *)
  !!ir (condOk := (AST.extract crs 1<rt> 2 <+> AST.b1))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let blt ins insLen ctxt =
  let struct (crs, addr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := (AST.xtlo 1<rt> crs <+> AST.b1)) (* FIXME: BO[0], BO[1] *)
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bgt ins insLen ctxt =
  let struct (crs, addr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  (* FIXME: BO[0], BO[1] *)
  !!ir (condOk := (AST.extract crs 1<rt> 1 <+> AST.b1))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let beq ins insLen ctxt =
  let struct (crs, addr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  (* FIXME: BO[0], BO[1] *)
  !!ir (condOk := (AST.extract crs 1<rt> 2 <+> AST.b1))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bcl ins insLen ctxt =
  let struct (bo, bi, addr) = getThreeOprs ins
  let bo = transOprToExpr ins ctxt bo
  let bi = getImmValue bi
  let cr = getCondRegister (bi / 4u) |> !.ctxt
  let addr = transOprToExpr ins ctxt addr
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let idx = numU32 (bi % 4u) 4<rt>
  let bo x = AST.extract bo 1<rt> x
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ AST.zext 32<rt> addr
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (lr := cia .+ numI32 4 32<rt>)
  !!ir (ctr := AST.ite (AST.not (bo 2)) (ctr .- AST.num1 32<rt>) ctr)
  !!ir (ctrOk := bo 2 .| ((ctr != AST.num0 32<rt>) <+> bo 3))
  !!ir (condOk := bo 0 .| (AST.xtlo 1<rt> (cr >> idx) <+> AST.not (bo 1)))
  !!ir (temp := AST.ite (ctrOk .& condOk) nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bcctr ins insLen ctxt =
  let struct (bo, bi) = getTwoOprs ins
  let bo = transOprToExpr ins ctxt bo
  let bi = getImmValue bi
  let cr = getCondRegister (bi / 4u) |> !.ctxt
  let ir = !*ctxt
  let ctr = !.ctxt R.CTR
  let idx = numU32 (bi % 4u) 4<rt>
  let bo x = AST.extract bo 1<rt> x
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> ctr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := bo 0 .| (AST.xtlo 1<rt> (cr >> idx) <+> AST.not (bo 1)))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bcctrl ins insLen ctxt =
  let struct (bo, bi) = getTwoOprs ins
  let bo = transOprToExpr ins ctxt bo
  let bi = getImmValue bi
  let cr = getCondRegister (bi / 4u) |> !.ctxt
  let ir = !*ctxt
  let ctr = !.ctxt R.CTR
  let idx = numU32 (bi % 4u) 4<rt>
  let bo x = AST.extract bo 1<rt> x
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> ctr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  let lr = !.ctxt R.LR
  !<ir insLen
  !!ir (condOk := bo 0 .| (AST.xtlo 1<rt> (cr >> idx) <+> AST.not (bo 1)))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !!ir (lr := cia .+ numI32 4 32<rt>)
  !>ir insLen

let bctr ins insLen ctxt =
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cr = !.ctxt R.CR0
  let ctr = !.ctxt R.CTR
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> ctr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := (AST.xtlo 1<rt> cr) <+> AST.b1)
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bctrl ins insLen ctxt =
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cr = !.ctxt R.CR0
  let ctr = !.ctxt R.CTR
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> ctr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  let lr = !.ctxt R.LR
  !<ir insLen
  !!ir (condOk := (AST.xtlo 1<rt> cr) <+> AST.b1)
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !!ir (lr := cia .+ numI32 4 32<rt>)
  !>ir insLen

let bclr ins insLen ctxt =
  let struct (bo, bi) = getTwoOprs ins
  let bo = transOprToExpr ins ctxt bo
  let bi = getImmValue bi
  let cr = getCondRegister (bi / 4u) |> !.ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let idx = numU32 (bi % 4u) 4<rt>
  let bo x = AST.extract bo 1<rt> x (* bo x *)
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> lr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (ctr := AST.ite (AST.not (bo 2)) (ctr .- AST.num1 32<rt>) ctr)
  !!ir (ctrOk := bo 2 .| ((ctr != AST.num0 32<rt>) <+> bo 3))
  !!ir (condOk := bo 0 .| (AST.xtlo 1<rt> (cr >> idx) <+> AST.not (bo 1)))
  !!ir (temp := AST.ite (ctrOk .& condOk) nia (cia .+ numI32 4 32<rt>))
  !>ir insLen

let bclrl ins insLen ctxt =
  let struct (bo, bi) = getTwoOprs ins
  let bo = transOprToExpr ins ctxt bo
  let bi = getImmValue bi
  let cr = getCondRegister (bi / 4u) |> !.ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let idx = numU32 (bi % 4u) 4<rt>
  let bo x = AST.extract bo 1<rt> x (* bo x *)
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> lr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (ctr := AST.ite (AST.not (bo 2)) (ctr .- AST.num1 32<rt>) ctr)
  !!ir (ctrOk := bo 2 .| ((ctr != AST.num0 32<rt>) <+> bo 3))
  !!ir (condOk := bo 0 .| (AST.xtlo 1<rt> (cr >> idx) <+> AST.not (bo 1)))
  !!ir (temp := AST.ite (ctrOk .& condOk) nia (cia .+ numI32 4 32<rt>))
  !!ir (lr := cia .+ numI32 4 32<rt>)
  !>ir insLen

let beqlr ins insLen ctxt =
  let crs = transOneOpr ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let lr = !.ctxt R.LR
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> lr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  (* FIXME: BO[0], BO[1] *)
  !!ir (condOk := (AST.extract crs 1<rt> 2 <+> AST.b1))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !>ir insLen

let beqlrl ins insLen ctxt =
  let crs = transOneOpr ins ctxt
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let lr = !.ctxt R.LR
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> lr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  (* FIXME: BO[0], BO[1] *)
  !!ir (condOk := (AST.extract crs 1<rt> 2 <+> AST.b1))
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (lr := cia .+ numI32 4 32<rt>)
  !>ir insLen

let blr ins insLen ctxt =
  let ir = !*ctxt
  let condOk = !+ir 1<rt>
  let cr = !.ctxt R.CR0
  let lr = !.ctxt R.LR
  let cia = numU64 ins.Address 32<rt>
  let nia = AST.concat (AST.xtlo 30<rt> lr) (AST.num0 2<rt>)
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := (AST.xtlo 1<rt> cr) <+> AST.b1)
  !!ir (temp := AST.ite condOk nia (cia .+ numI32 4 32<rt>))
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let clrlwi ins insLen ctxt =
  let struct (ra, rs, n) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen (* No rotation *)
  !!ir (ra := rs .& (getExtMask n (numI32 31 32<rt>)))
  !>ir insLen

let cmpi ins insLen ctxt =
  let struct (crf, l, ra, simm) = transFourOprs ins ctxt
  if l = (AST.num1 32<rt>) then raise ParsingFailureException
  let cond1 = simm .>= ra
  let cond2 = simm == ra
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cmpw ins insLen ctxt =
  let struct (crf, ra, rb) = transThreeOprs ins ctxt
  let cond1 = rb .>= ra
  let cond2 = rb == ra
  let xer = !.ctxt R.XER
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cmpwi ins insLen ctxt =
  let struct (crf, ra, simm) = transThreeOprs ins ctxt
  let cond1 = simm .>= ra
  let cond2 = simm == ra
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cmpl ins insLen ctxt =
  let struct (crf, l, ra, rb) = transFourOprs ins ctxt
  if l = (AST.num1 32<rt>) then raise ParsingFailureException
  let cond1 = rb .>= ra
  let cond2 = rb == ra
  let xer = !.ctxt R.XER
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cmpli ins insLen ctxt =
  let struct (crf, l, ra, uimm) = transFourOprs ins ctxt
  if l = (AST.num1 32<rt>) then raise ParsingFailureException
  let uimm = AST.concat (AST.num0 16<rt>) (AST.xtlo 16<rt> uimm)
  let cond1 = uimm .>= ra
  let cond2 = uimm == ra
  let xer = !.ctxt R.XER
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cmplw ins insLen ctxt =
  let struct (crf, ra, rb) = transThreeOprs ins ctxt
  let cond1 = rb .>= ra
  let cond2 = rb == ra
  let xer = !.ctxt R.XER
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cmplwi ins insLen ctxt =
  let struct (crf, ra, uimm) = transThreeOprs ins ctxt
  let uimm = AST.concat (AST.num0 16<rt>) (AST.xtlo 16<rt> uimm)
  let cond1 = uimm .>= ra
  let cond2 = uimm == ra
  let a = numI32 0b1000 4<rt>
  let b = numI32 0b0100 4<rt>
  let c = numI32 0b0010 4<rt>
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  let tmp = !+ir 4<rt>
  !<ir insLen
  !!ir (tmp := AST.ite cond1 (AST.ite cond2 c a) b)
  !!ir (crf := tmp .| AST.zext 4<rt> (AST.xtlo 1<rt> xer))
  !>ir insLen

let cntlzw ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  let lblChkExit = !%ir "CheckExit"
  let lblCmp = !%ir "Compare"
  let lblInc = !%ir "Increase"
  let lblLeave = !%ir "Leave"
  let n = !+ir 32<rt> (* Temp Var *)
  let n1 = AST.num1 32<rt>
  !!ir (n := AST.num0 32<rt>)
  !!ir (AST.lmark lblChkExit)
  !!ir (AST.cjmp (n == numI32 32 32<rt>) (AST.name lblLeave) (AST.name lblCmp))
  !!ir (AST.lmark lblCmp)
  !!ir (AST.cjmp ((src >> n) .& n1) (AST.name lblLeave) (AST.name lblInc))
  !!ir (AST.lmark lblInc)
  !!ir (n := n .+ n1)
  !!ir (AST.jmp (AST.name lblChkExit))
  !!ir (AST.lmark lblLeave)
  !!ir (dst := n)
  !>ir insLen

let crclr ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.b0)
  !>ir insLen

let cror ins insLen ctxt =
  let struct (dst, srcA, srcB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := srcA .| srcB)
  !>ir insLen

let crset ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := dst <+> AST.not dst)
  !>ir insLen

let divw ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 ?/ src2)
  !>ir insLen

let divwu ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 ./ src2)
  !>ir insLen

let extsb ins insLen ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 8<rt>
  !<ir insLen
  !!ir (tmp := AST.xthi 8<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  setCondReg ctxt ir ra
  !>ir insLen

let fmadd ins insLen ctxt =
  let struct (dst, src1, src2, src3) = transFourOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (src1 .* src2) .+ src3)
  /// Affected: FPRF, FR, FI, FX, OX, UX, XX, VXSNAN, VXISI, VXIMZ
  !>ir insLen

let fmr ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let fmsub ins insLen ctxt =
  let struct (dst, src1, src2, src3) = transFourOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (src1 .* src2) .- src3)
  /// Affected: FPRF, FR, FI, FX, OX, UX, XX, VXSNAN, VXISI, VXIMZ
  !>ir insLen

let lbz ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let ea =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
    | _ -> raise InvalidOperandException
  let dst = transOprToExpr ins ctxt o1
  let ir = !*ctxt
  !<ir insLen

  !!ir (dst := AST.concat (AST.num0 24<rt>) (AST.loadLE 8<rt> ea))
  !>ir insLen

let lbzx ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let cond = src1 == AST.num0 32<rt>
  let ir = !*ctxt
  let ea = !+ir 32<rt>
  !<ir insLen
  !!ir (ea := (AST.ite cond (AST.num0 32<rt>) src1) .+ src2)
  !!ir (dst := AST.concat (AST.num0 24<rt>) (AST.loadLE 8<rt> ea))
  !>ir insLen

let lfd ins insLen ctxt =
  let struct (o1 , o2) = getTwoOprs ins
  let ea =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
    | _ -> raise InvalidOperandException
  let dst = transOprToExpr ins ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.loadLE 64<rt> ea))
  !>ir insLen

let lfs ins insLen ctxt =
  let struct (dst, ea) = transTwoOprs ins ctxt
  let w1 = AST.extract ea 1<rt> 1
  let w2 = (AST.zext 64<rt> (AST.xthi 30<rt> ea)) << numI32 29 64<rt>
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  /// use normalized operand
  !!ir (AST.xtlo 2<rt> tmp:= AST.xtlo 2<rt> ea)
  !!ir (AST.extract tmp 1<rt> 2 := AST.not w1)
  !!ir (AST.extract tmp 1<rt> 3 := AST.not w1)
  !!ir (AST.extract tmp 1<rt> 4 := AST.not w1)
  !!ir (dst := tmp .& w2)
  !>ir insLen

let lhz ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let ea =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
    | _ -> raise InvalidOperandException
  let dst = transOprToExpr ins ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.concat (AST.num0 16<rt>) (AST.loadLE 16<rt> ea))
  !>ir insLen

let li ins insLen ctxt =
  let struct (dst, simm) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := simm)
  !>ir insLen

let lis ins insLen ctxt =
  let struct (dst, simm) = transTwoOprs ins ctxt
  let simm = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := simm)
  !>ir insLen

let lwz ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let lwzu ins insLen ctxt =
  let struct ( _ , o2) = getTwoOprs ins
  let ea, ra =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize), !.ctxt b
    | _ -> raise InvalidOperandException
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src)
  !!ir (ra := ea)
  !>ir insLen

let lwzx ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let cond = src1 == AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.loadLE 32<rt>
               ((AST.ite cond (AST.num0 32<rt>) src1) .+ src2))
  !>ir insLen

let mfspr ins insLen ctxt =
  let struct (dst, spr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := spr)
  !>ir insLen

let mfctr ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let ctr = !.ctxt R.CTR
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := ctr)
  !>ir insLen

let mffs ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let fpscr = !.ctxt R.FPSCR
  let ir = !*ctxt
  !<ir insLen
  !!ir ((AST.xthi 32<rt> dst) := fpscr)
  !>ir insLen

let mflr ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let lr = !.ctxt R.LR
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := lr)
  !>ir insLen

let mfxer ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := xer)
  !>ir insLen

let mr ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .| src)
  !>ir insLen

let mtspr ins insLen ctxt =
  let struct (src, spr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (spr := src)
  !>ir insLen

let mtctr ins insLen ctxt =
  let src = transOneOpr ins ctxt
  let ctr = !.ctxt R.CTR
  let ir = !*ctxt
  !<ir insLen
  !!ir (ctr := src)
  !>ir insLen

let mtlr ins insLen ctxt =
  let src = transOneOpr ins ctxt
  let lr = !.ctxt R.LR
  let ir = !*ctxt
  !<ir insLen
  !!ir (lr := src)
  !>ir insLen

let mtfsb0 ins insLen ctxt =
  let crb = transOneOpr ins ctxt
  let fpscr = !.ctxt R.FPSCR
  let cond = (crb == numI32 1 32<rt>) .| (crb == numI32 2 32<rt>)
  let ir = !*ctxt
  let tmp = AST.not ((numI32 0x80000000 32<rt>) >> crb)
  !<ir insLen
  !!ir (fpscr := AST.ite cond fpscr (fpscr .& tmp))
  /// Affected: FX
  !>ir insLen

let mtfsb1 ins insLen ctxt =
  let crb = transOneOpr ins ctxt
  let fpscr = !.ctxt R.FPSCR
  let cond = (crb == numI32 1 32<rt>) .| (crb == numI32 2 32<rt>)
  let ir = !*ctxt
  let tmp = (numI32 0x80000000 32<rt>) >> crb
  !<ir insLen
  !!ir (fpscr := AST.ite cond fpscr (fpscr .| tmp))
  /// Affected: FX
  !>ir insLen

let mtfsf ins insLen ctxt =
  let struct (fm, frB) = getTwoOprs ins
  let frB = transOprToExpr ins ctxt frB
  let fm = getImmValue fm
  let idx = System.Math.Log2 (float fm) |> int
  let cond = numI32 idx 32<rt> == AST.num0 32<rt>
  let fpscr = !.ctxt R.FPSCR
  let ir = !*ctxt
  !<ir insLen
  let lblFm0 = !%ir "Fm0"
  let lblLeave = !%ir "Leave"
  !!ir (AST.extract fpscr 4<rt> (idx * 4) := AST.extract frB 4<rt> (idx * 4))
  !!ir (AST.cjmp cond (AST.name lblFm0) (AST.name lblLeave))
  !!ir (AST.lmark lblFm0)
  !!ir (AST.extract fpscr 1<rt> 0 := AST.extract frB 1<rt> 32)
  !!ir (AST.extract fpscr 1<rt> 3 := AST.extract frB 1<rt> 35)
  !!ir (AST.lmark lblLeave)
  !>ir insLen

let mtxer ins insLen ctxt =
  let src = transOneOpr ins ctxt
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  !<ir insLen
  !!ir (xer := src)
  !>ir insLen

let mulhw ins insLen ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> rb))
  !!ir (dst := AST.xthi 32<rt> tmp)
  !>ir insLen

let mulhwu ins insLen ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> rb))
  !!ir (dst := AST.xtlo 32<rt> tmp)
  !>ir insLen

let mulli ins insLen ctxt =
  let struct (dst, ra, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 48<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 48<rt> ra) .* (AST.sext 48<rt> simm))
  !!ir (dst := AST.extract tmp 32<rt> 16)
  !>ir insLen

let mullw ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .* src2)
  !>ir insLen

let neg ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src) .+ AST.num1 32<rt>)
  !>ir insLen

let nor ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.not (src1 .| src2))
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let orx ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| src2)
  !>ir insLen

let ordot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let cr0 = !.ctxt R.CR0
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| src2)
  setCondReg ctxt ir dst
  !>ir insLen

let ori ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = AST.concat (AST.num0 16<rt>) (AST.xtlo 16<rt> uimm)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .| uimm)
  !>ir insLen

let oris ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = AST.concat (AST.xtlo 16<rt> uimm) (AST.num0 16<rt>)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .| uimm)
  !>ir insLen

let rlwinm ins insLen ctxt =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins ctxt
  let ir = !*ctxt
  let rol = (rs << sh) .| (rs >> ((numI32 32 32<rt>) .- sh))
  !<ir insLen
  !!ir (ra := rol .& (getExtMask mb me))
  !>ir insLen

let rlwimi ins insLen ctxt =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins ctxt
  let ir = !*ctxt
  let m = getExtMask mb me
  let rol = (rs << sh) .| (rs >> ((numI32 32 32<rt>) .- sh))
  !<ir insLen
  !!ir (ra := (rol .& m) .| (ra .& AST.not m))
  !>ir insLen

let rotlw ins insLen ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = AST.sext 32<rt> (AST.xthi 4<rt> rb)
  let rol = (rs << n) .| (rs >> ((numI32 32 32<rt>) .- n))
  !<ir insLen
  !!ir (ra := rol) (* no mask *)
  !>ir insLen

let rotlwi ins insLen ctxt =
  let struct (ra, rs, n) = transThreeOprs ins ctxt
  let rol = (rs << n) .| (rs >> ((numI32 32 32<rt>) .- n))
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := rol) (* no mask *)
  !>ir insLen

let slw ins insLen ctxt =
  let struct (dst, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = AST.sext 32<rt> (AST.xthi 4<rt> rb)
  let bit26 = AST.xtlo 1<rt> (rs >> numI32 26 32<rt> .& AST.num1 32<rt>)
  let cond = bit26 == AST.b0
  let z = AST.num0 32<rt>
  let rol = (rs << n) .| (rs >> ((numI32 32 32<rt>) .- n))
  !<ir insLen
  !!ir (dst := AST.ite cond rol z)
  !>ir insLen

let slwi ins insLen ctxt =
  let struct (ra, rs, n) = transThreeOprs ins ctxt
  let rol = (rs << n) .| (rs >> ((numI32 32 32<rt>) .- n))
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := rol .& (getExtMask (AST.num0 32<rt>) (numI32 31 32<rt> .- n)))
  !>ir insLen

let sraw ins insLen ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let xer = !.ctxt R.XER
  let z = AST.num0 32<rt>
  let cond = AST.extract rb 1<rt> 26 == AST.b0
  let ir = !*ctxt
  let n = !+ir 32<rt>
  let r = !+ir 32<rt>
  let m = !+ir 32<rt>
  let ca = !+ir 32<rt>
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir (n := AST.zext 32<rt> (AST.xthi 5<rt> rb))
  !!ir (r := (rs << n) .| (rs >> ((numI32 32 32<rt>) .- n)))
  !!ir (m := AST.ite cond (numI32 0xF8000000 32<rt>) z)
  !!ir (ra := (r .& m) .| (rs .& AST.not m))
  !!ir (tmp := AST.ite ((r .& AST.not m) != z)(AST.num1 32<rt>) z)
  !!ir (ca := rs .& tmp)
  !!ir ((AST.extract xer 1<rt> 2) := (AST.xtlo 1<rt> ca))
  !>ir insLen

let srawi ins insLen ctxt =
  let struct (ra, rs, sh) = transThreeOprs ins ctxt
  let xer = !.ctxt R.XER
  let z = AST.num0 32<rt>
  let m = numI32 0xF8000000 32<rt>
  let ir = !*ctxt
  let r = !+ir 32<rt>
  let ca = !+ir 32<rt>
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir (r := (rs << ((numI32 32 32<rt>) .- sh)) .| (rs >> sh))
  !!ir (ra := (r .& m) .| (rs .& AST.not m))
  !!ir (tmp := AST.ite ((r .& AST.not m) != z)(AST.num1 32<rt>) z)
  !!ir (ca := rs .& tmp)
  !!ir ((AST.extract xer 1<rt> 2) := (AST.xtlo 1<rt> ca))
  !>ir insLen

let srawidot ins insLen ctxt =
  let struct (ra, rs, sh) = transThreeOprs ins ctxt
  let xer = !.ctxt R.XER
  let z = AST.num0 32<rt>
  let m = numI32 0xF8000000 32<rt>
  let ir = !*ctxt
  let r = !+ir 32<rt>
  let ca = !+ir 32<rt>
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir (r := (rs << ((numI32 32 32<rt>) .- sh)) .| (rs >> sh))
  !!ir (ra := (r .& m) .| (rs .& AST.not m))
  !!ir (tmp := AST.ite ((r .& AST.not m) != z)(AST.num1 32<rt>) z)
  !!ir (ca := rs .& tmp)
  !!ir ((AST.extract xer 1<rt> 2) := (AST.xtlo 1<rt> ca))
  setCondReg ctxt ir ra
  !>ir insLen

let srw ins insLen ctxt =
  let struct (dst, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = AST.sext 32<rt> (AST.xthi 4<rt> rb)
  !<ir insLen
  !!ir (dst := (rs << ((numI32 32 32<rt>) .- n)) .| (rs >> n))
  !>ir insLen

let srwi ins insLen ctxt =
  let struct (ra, rs, n) = transThreeOprs ins ctxt
  let rol = (rs << ((numI32 32 32<rt>) .- n)) .| (rs >> n)
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := rol .& (getExtMask n (numI32 31 32<rt>)))
  !>ir insLen

let stb ins insLen ctxt =
  let struct (o1 , o2) = getTwoOprs ins
  let ea =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
    | _ -> raise InvalidOperandException
  let src = transOprToExpr ins ctxt o1
  let dst = AST.loadLE 8<rt> ea
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.xthi 8<rt> src))
  !>ir insLen

let stbx ins insLen ctxt =
  let struct (src, dst1, dst2) = transThreeOprs ins ctxt
  let cond = dst1 == AST.num0 32<rt>
  let ir = !*ctxt
  let ea = !+ir 32<rt>
  !<ir insLen
  !!ir (ea := (AST.ite cond (AST.num0 32<rt>) dst1) .+ dst2)
  !!ir ((AST.loadLE 8<rt> ea) := (AST.xtlo 8<rt> src))
  !>ir insLen

let stfd ins insLen ctxt =
  let struct (o1 , o2) = getTwoOprs ins
  let ea =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
    | _ -> raise InvalidOperandException
  let src = transOprToExpr ins ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir ((AST.loadLE 64<rt> ea) := src)
  !>ir insLen

let stfs ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir ((AST.xtlo 2<rt> tmp) := AST.xtlo 2<rt> src)
  !!ir ((AST.xthi 29<rt> tmp) := AST.xtlo 29<rt> (AST.xthi 59<rt> src))
  !!ir (dst := tmp)
  !>ir insLen

let sth ins insLen ctxt =
  let struct (o1 , o2) = getTwoOprs ins
  let ea =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
    | _ -> raise InvalidOperandException
  let src = transOprToExpr ins ctxt o1
  let dst = AST.loadLE 16<rt> ea
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst :=(AST.xtlo 16<rt> src))
  !>ir insLen

let stw ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let stwu ins insLen ctxt =
  let struct ( _ , o2) = getTwoOprs ins
  let ea, ra =
    match o2 with
    | OprMem (d, b) -> (!.ctxt b .+ numI32 d ctxt.WordBitSize), !.ctxt b
    | _ -> raise InvalidOperandException
  let struct (src, dst) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src)
  !!ir (ra := ea)
  !>ir insLen

let stwux ins insLen ctxt =
  let struct (rs, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let ea = !+ir 32<rt>
  !<ir insLen
  !!ir (ea := ra .+ rb)
  !!ir ((AST.loadLE 32<rt> ea) := rs)
  !!ir (ra := ea)
  !>ir insLen

let subf ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ (AST.num1 32<rt>))
  !>ir insLen

let subfc ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ AST.num1 32<rt>)
  /// Affected: XER[CA]
  !>ir insLen

let subfe ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xer = !.ctxt R.XER
  let ca = AST.zext 32<rt> (AST.extract xer 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ ca)
  /// Affected: XER[CA]
  !>ir insLen

let subfic ins insLen ctxt  =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ simm .+ AST.num1 32<rt>)
  /// Affected: XER[CA]
  !>ir insLen

let subfze ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xer = !.ctxt R.XER
  let ca = AST.zext 32<rt> (AST.extract xer 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src) .+ ca)
  !>ir insLen

let xor ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (src1 <+> src2))
  !>ir insLen

let xordot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (src1 <+> src2))
  setCondReg ctxt ir dst
  !>ir insLen

let xori ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = AST.concat (AST.num0 16<rt>) (AST.xtlo 16<rt> uimm)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src <+> uimm)
  !>ir insLen

let xoris ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = AST.concat (AST.xtlo 16<rt> uimm) (AST.num0 16<rt>)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src <+> uimm)
  !>ir insLen

/// Translate IR.
let translate (ins: InsInfo) insLen (ctxt: TranslationContext) =
  match ins.Opcode with
  | Op.ADD -> add ins insLen ctxt
  | Op.ADDC -> addc ins insLen ctxt
  | Op.ADDE -> adde ins insLen ctxt
  | Op.ADDI -> addi ins insLen ctxt
  | Op.ADDIC -> addic ins insLen ctxt
  | Op.ADDIS -> addis ins insLen ctxt
  | Op.ADDZE -> addze ins insLen ctxt
  | Op.ADDZEdot -> addzedot ins insLen ctxt
  | Op.AND -> andx ins insLen ctxt
  | Op.ANDIdot -> andidot ins insLen ctxt
  | Op.B -> b ins insLen ctxt
  | Op.BA -> ba ins insLen ctxt
  | Op.BL -> bl ins insLen ctxt
  | Op.BLA -> bla ins insLen ctxt
  | Op.BC -> bc ins insLen ctxt
  | Op.BGE -> bge ins insLen ctxt
  | Op.BLE -> ble ins insLen ctxt
  | Op.BNE -> bne ins insLen ctxt
  | Op.BLT -> blt ins insLen ctxt
  | Op.BGT -> bgt ins insLen ctxt
  | Op.BEQ -> beq ins insLen ctxt
  | Op.BCL -> bcl ins insLen ctxt
  | Op.BCCTR -> bcctr ins insLen ctxt
  | Op.BCCTRL -> bcctrl ins insLen ctxt
  | Op.BCTR -> bctr ins insLen ctxt
  | Op.BCTRL -> bctrl ins insLen ctxt
  | Op.BCLR -> bclr ins insLen ctxt
  | Op.BCLRL -> bclrl ins insLen ctxt
  | Op.BEQLR -> beqlr ins insLen ctxt
  | Op.BEQLRL -> beqlrl ins insLen ctxt
  | Op.BLR -> blr ins insLen ctxt
  | Op.CLRLWI -> clrlwi ins insLen ctxt
  | Op.CMPI -> cmpi ins insLen ctxt
  | Op.CMPWI -> cmpwi ins insLen ctxt
  | Op.CMPL -> cmpl ins insLen ctxt
  | Op.CMPLI -> cmpli ins insLen ctxt
  | Op.CMPLW -> cmplw ins insLen ctxt
  | Op.CMPLWI -> cmplwi ins insLen ctxt
  | Op.CMPW -> cmpw ins insLen ctxt
  | Op.CNTLZW -> cntlzw ins insLen ctxt
  | Op.CRCLR -> crclr ins insLen ctxt
  | Op.CROR -> cror ins insLen ctxt
  | Op.CRSET -> crset ins insLen ctxt
  | Op.DIVW -> divw ins insLen ctxt
  | Op.DIVWU -> divwu ins insLen ctxt
  | Op.EXTSB -> extsb ins insLen ctxt
  | Op.FABS | Op.FADD | Op.FADDS | Op.FCMPU | Op.FCTIWZ | Op.FDIV | Op.FDIVS
  | Op.FMUL | Op.FMULS | Op.FRSP | Op.FSUB | Op.FSUBS ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.FMADD -> fmadd ins insLen ctxt
  | Op.FMR -> fmr ins insLen ctxt
  | Op.FMSUB -> fmsub ins insLen ctxt
  | Op.LBZ -> lbz ins insLen ctxt
  | Op.LBZX -> lbzx ins insLen ctxt
  | Op.LFD -> lfd ins insLen ctxt
  | Op.LFS -> lfs ins insLen ctxt
  | Op.LHZ -> lhz ins insLen ctxt
  | Op.LI -> li ins insLen ctxt
  | Op.LIS -> lis ins insLen ctxt
  | Op.LWZ -> lwz ins insLen ctxt
  | Op.LWZU -> lwzu ins insLen ctxt
  | Op.LWZX -> lwzx ins insLen ctxt
  | Op.MFSPR -> mfspr ins insLen ctxt
  | Op.MFCTR -> mfctr ins insLen ctxt
  | Op.MFFS -> mffs ins insLen ctxt
  | Op.MFLR -> mflr ins insLen ctxt
  | Op.MFXER -> mfxer ins insLen ctxt
  | Op.MR -> mr ins insLen ctxt
  | Op.MTSPR -> mtspr ins insLen ctxt
  | Op.MTCTR -> mtctr ins insLen ctxt
  | Op.MTFSB0 -> mtfsb0 ins insLen ctxt
  | Op.MTFSB1 -> mtfsb1 ins insLen ctxt
  | Op.MTFSF -> mtfsf ins insLen ctxt
  | Op.MTLR -> mtlr ins insLen ctxt
  | Op.MTXER -> mtxer ins insLen ctxt
  | Op.MULHW -> mulhw ins insLen ctxt
  | Op.MULHWU -> mulhwu ins insLen ctxt
  | Op.MULLI -> mulli ins insLen ctxt
  | Op.MULLW -> mullw ins insLen ctxt
  | Op.NEG -> neg ins insLen ctxt
  | Op.NOR -> nor ins insLen ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.OR -> orx ins insLen ctxt
  | Op.ORdot -> ordot ins insLen ctxt
  | Op.ORI -> ori ins insLen ctxt
  | Op.ORIS -> oris ins insLen ctxt
  | Op.RLWIMI -> rlwimi ins insLen ctxt
  | Op.RLWINM -> rlwinm ins insLen ctxt
  | Op.ROTLW -> rotlw ins insLen ctxt
  | Op.ROTLWI -> rotlwi ins insLen ctxt
  | Op.SLW -> slw ins insLen ctxt
  | Op.SLWI -> slwi ins insLen ctxt
  | Op.SRAW -> sraw ins insLen ctxt
  | Op.SRAWI -> srawi ins insLen ctxt
  | Op.SRAWIdot -> srawidot ins insLen ctxt
  | Op.SRW -> srw ins insLen ctxt
  | Op.SRWI -> srwi ins insLen ctxt
  | Op.STB -> stb ins insLen ctxt
  | Op.STBX -> stbx ins insLen ctxt
  | Op.STFD -> stfd ins insLen ctxt
  | Op.STFS -> stfs ins insLen ctxt
  | Op.STH -> sth ins insLen ctxt
  | Op.STW -> stw ins insLen ctxt
  | Op.STWU -> stwu ins insLen ctxt
  | Op.STWUX -> stwux ins insLen ctxt
  | Op.SUBF -> subf ins insLen ctxt
  | Op.SUBFC -> subfc ins insLen ctxt
  | Op.SUBFE -> subfe ins insLen ctxt
  | Op.SUBFIC -> subfic ins insLen ctxt
  | Op.SUBFZE -> subfze ins insLen ctxt
  | Op.XOR -> xor ins insLen ctxt
  | Op.XORdot -> xordot ins insLen ctxt
  | Op.XORI -> xori ins insLen ctxt
  | Op.XORIS -> xoris ins insLen ctxt
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
