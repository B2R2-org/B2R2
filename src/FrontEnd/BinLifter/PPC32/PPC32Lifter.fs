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
  let mb, me = 31 - me, 31 - mb
  let mask = (System.UInt32.MaxValue >>> (32 - (me - mb + 1))) <<< mb
  numU32 mask 32<rt>

let rotateLeft rs sh = (rs << sh) .| (rs >> ((numI32 32 32<rt>) .- sh))

let loadNative (ctxt: TranslationContext) rt addr =
  match ctxt.Endianness with
  | Endian.Big -> AST.loadBE rt addr
  | Endian.Little -> AST.loadLE rt addr
  | _ -> raise InvalidEndianException

/// Operand of the form d(rA) where the EA is (rA|0) + d.
let transEAWithOffset opr (ctxt: TranslationContext) =
  match opr with
  | OprMem (d, R.R0) -> numI32 d ctxt.WordBitSize
  | OprMem (d, b) -> !.ctxt b .+ numI32 d ctxt.WordBitSize
  | _ -> raise InvalidOperandException

/// Operand of the form d(rA) where the EA is rA + d. rA is updated with EA.
let transEAWithOffsetForUpdate opr (ctxt: TranslationContext) =
  match opr with
  | OprMem (d, b) ->
    let rA = !.ctxt b
    struct (rA .+ numI32 d ctxt.WordBitSize, rA)
  | _ -> raise InvalidOperandException

/// Operands of the form "rA, rB" where the EA is (rA|0) + rB.
let transEAWithIndexReg rA rB (ctxt: TranslationContext) =
  match rA, rB with
  | OprReg R.R0, OprReg rB -> !.ctxt rB
  | OprReg reg, OprReg rB -> !.ctxt reg .+ !.ctxt rB
  | _ -> raise InvalidOpcodeException

/// Operands of the form "rA, rB" where the EA is rA + rB, and rA is updated.
let transEAWithIndexRegForUpdate rA rB (ctxt: TranslationContext) =
  match rA, rB with
  | OprReg rA, OprReg rB ->
    let rA = !.ctxt rA
    struct (rA .+ !.ctxt rB, rA)
  | _ -> raise InvalidOpcodeException

let transOpr (ctxt: TranslationContext) = function
  | OprReg reg -> !.ctxt reg
  | OprMem (d, b) -> (* FIXME *)
    loadNative ctxt 32<rt> (!.ctxt b .+ numI32 d ctxt.WordBitSize)
  | OprImm imm -> numU64 imm ctxt.WordBitSize
  | OprAddr addr ->
    numI64 (int64 addr) ctxt.WordBitSize
  | OprBI bi -> getCRbitRegister bi |> !.ctxt

let transOneOpr (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand o -> transOpr ctxt o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOpr ctxt o1, transOpr ctxt o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOpr ctxt o1,
            transOpr ctxt o2,
            transOpr ctxt o3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOpr ctxt o1,
            transOpr ctxt o2,
            transOpr ctxt o3,
            transOpr ctxt o4)
  | _ -> raise InvalidOperandException

let transFiveOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | FiveOperands (o1, o2, o3, o4, o5) ->
    struct (transOpr ctxt o1,
            transOpr ctxt o2,
            transOpr ctxt o3,
            transOpr ctxt o4,
            transOpr ctxt o5)
  | _ -> raise InvalidOperandException

let transCRxToExpr ctxt reg =
  match reg with
  | R.CR0 -> !.ctxt R.CR0_0, !.ctxt R.CR0_1, !.ctxt R.CR0_2, !.ctxt R.CR0_3
  | R.CR1 -> !.ctxt R.CR1_0, !.ctxt R.CR1_1, !.ctxt R.CR1_2, !.ctxt R.CR1_3
  | R.CR2 -> !.ctxt R.CR2_0, !.ctxt R.CR2_1, !.ctxt R.CR2_2, !.ctxt R.CR2_3
  | R.CR3 -> !.ctxt R.CR3_0, !.ctxt R.CR3_1, !.ctxt R.CR3_2, !.ctxt R.CR3_3
  | R.CR4 -> !.ctxt R.CR4_0, !.ctxt R.CR4_1, !.ctxt R.CR4_2, !.ctxt R.CR4_3
  | R.CR5 -> !.ctxt R.CR5_0, !.ctxt R.CR5_1, !.ctxt R.CR5_2, !.ctxt R.CR5_3
  | R.CR6 -> !.ctxt R.CR6_0, !.ctxt R.CR6_1, !.ctxt R.CR6_2, !.ctxt R.CR6_3
  | R.CR7 -> !.ctxt R.CR7_0, !.ctxt R.CR7_1, !.ctxt R.CR7_2, !.ctxt R.CR7_3
  | _ -> raise InvalidOperandException

let transCmpOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg o1, o2, o3) ->
    struct (transCRxToExpr ctxt o1,
            transOpr ctxt o2,
            transOpr ctxt o3)

  | FourOperands (OprReg o1, _ , o3, o4) ->
    struct (transCRxToExpr ctxt o1,
            transOpr ctxt o3,
            transOpr ctxt o4)
  | _ -> raise InvalidOperandException

let transCondOneOpr (ins: InsInfo) ctxt =
  match ins.Operands with
  | OneOperand (OprReg o) ->
    transCRxToExpr ctxt o
  | _ -> raise InvalidOperandException

let transCondTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprReg o1, OprReg o2) ->
    struct (transCRxToExpr ctxt o1, transCRxToExpr ctxt o2)
  | _ -> raise InvalidOperandException

let transCondThreeOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprReg o1, OprReg o2, OprReg o3) ->
    struct (transCRxToExpr ctxt o1,
            transCRxToExpr ctxt o2,
            transCRxToExpr ctxt o3)
  | _ -> raise InvalidOperandException

let getCRRegValue ir cr ctxt =
  for i in 0 .. 31 do
    let crbit = uint32 (31 - i) |> getCRbitRegister |> !.ctxt
    !!ir (AST.extract cr 1<rt> i := crbit)

let getImmValue = function
  | OprImm imm -> uint32 imm
  | OprBI imm -> imm
  | _ -> raise InvalidOperandException

let getSPRReg ctxt imm  =
  match uint32 imm with
  | 1u -> !.ctxt R.XER
  | 8u -> !.ctxt R.LR
  | 9u -> !.ctxt R.CTR
  | 287u -> !.ctxt R.PVR
  | 18u | 19u | 22u | 25u | 26u | 27u | 272u | 273u | 274u | 275u | 282u | 528u
  | 529u | 530u | 531u | 532u | 533u | 534u | 535u | 536u | 537u | 538u | 539u
  | 540u | 541u | 542u | 543u | 1013u -> raise UnhandledRegExprException
  | _ -> raise InvalidOperandException

let setCondReg ctxt ir result =
  let xerSO = AST.xtlo 1<rt> (!.ctxt R.XER)
  let cr0LT = !.ctxt R.CR0_0
  let cr0GT = !.ctxt R.CR0_1
  let cr0EQ = !.ctxt R.CR0_2
  let cr0SO = !.ctxt R.CR0_3
  !!ir (cr0LT := result ?< AST.num0 32<rt>)
  !!ir (cr0GT := result ?> AST.num0 32<rt>)
  !!ir (cr0EQ := result == AST.num0 32<rt>)
  !!ir (cr0SO := xerSO)

let setCarryOut ctxt expA expB ir =
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 2
  !!ir (xerCA := AST.lt expA expB)

let setCRRegValue ir cr ctxt =
  for i in 0 .. 31 do
    let crbit = uint32 (31 - i) |> getCRbitRegister |> !.ctxt
    !!ir (crbit := AST.extract cr 1<rt> i)

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
  !>ir insLen

let adddot ins insLen ctxt =
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
  setCarryOut ctxt dst src1 ir
  !>ir insLen

let addcdot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2)
  setCondReg ctxt ir dst
  !>ir insLen

let adde ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2 .+ xerCA)
  setCarryOut ctxt dst src1 ir
  !>ir insLen

let addedot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2 .+ xerCA)
  setCondReg ctxt ir dst
  setCarryOut ctxt dst src1 ir
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
  setCarryOut ctxt dst src1 ir
  !>ir insLen

let addicdot ins insLen ctxt =
  let struct (dst, src, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ simm)
  setCondReg ctxt ir dst
  setCarryOut ctxt dst src ir
  !>ir insLen

let addis ins insLen ctxt =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let cond = src1 == AST.num0 32<rt>
  let simm = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.ite cond simm (src1 .+ simm)))
  !>ir insLen

let addme ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA .- AST.num1 32<rt>)
  setCarryOut ctxt dst src ir
  !>ir insLen

let addmedot ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA .- AST.num1 32<rt>)
  setCondReg ctxt ir dst
  setCarryOut ctxt dst src ir
  !>ir insLen

let addze ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA)
  setCarryOut ctxt dst src ir
  !>ir insLen

let addzedot ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA)
  setCondReg ctxt ir dst
  setCarryOut ctxt dst src ir
  !>ir insLen

let andx ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& src2)
  !>ir insLen

let anddot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& src2)
  setCondReg ctxt ir dst
  !>ir insLen

let andc ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& AST.not(src2))
  !>ir insLen

let andcdot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& AST.not(src2))
  setCondReg ctxt ir dst
  !>ir insLen

let andidot ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .& uimm)
  setCondReg ctxt ir dst
  !>ir insLen

let andisdot ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = uimm << numI32 16 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .& uimm)
  setCondReg ctxt ir dst
  !>ir insLen

let b ins insLen ctxt lk =
  let addr = transOneOpr ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  !<ir insLen
  if lk then !!ir (lr := numU64 ins.Address 32<rt> .+ numI32 4 32<rt>)
  !!ir (AST.interjmp addr InterJmpKind.Base)
  !>ir insLen

let bc ins insLen ctxt aa lk =
  let struct (bo, cr, addr) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let boA = AST.extract bo 1<rt> 4
  let boB = AST.extract bo 1<rt> 3
  let boC = AST.extract bo 1<rt> 2
  let boD = AST.extract bo 1<rt> 1
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = !+ir 32<rt>
  !<ir insLen
  if lk then !!ir (lr := nia)
  !!ir (ctr := AST.ite (AST.not boC) (ctr .- AST.num1 32<rt>) ctr)
  !!ir (ctrOk := boC .| ((ctr != AST.num0 32<rt>) <+> boD))
  !!ir (condOk := boA .| (cr <+> AST.not boB))
  if aa then !!ir (temp := AST.ite (ctrOk .& condOk) addr nia)
  else !!ir (temp := AST.ite (ctrOk .& condOk) (cia .+ addr) nia)
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bclr ins insLen ctxt lk =
  let struct (bo, cr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let boA = AST.extract bo 1<rt> 4
  let boB = AST.extract bo 1<rt> 3
  let boC = AST.extract bo 1<rt> 2
  let boD = AST.extract bo 1<rt> 1
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (ctr := AST.ite (AST.not boC) (ctr .- AST.num1 32<rt>) ctr)
  !!ir (ctrOk := boC .| ((ctr != AST.num0 32<rt>) <+> boD))
  !!ir (condOk := boA .| (cr <+> AST.not boB))
  !!ir (temp := AST.ite (ctrOk .& condOk) (lr .& numI32 0xfffffffc 32<rt>) nia)
  if lk then !!ir (lr := nia)
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bcctr ins insLen ctxt lk =
  let struct (bo, cr) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let boA = AST.extract bo 1<rt> 4
  let boB = AST.extract bo 1<rt> 3
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := boA .| (cr <+> AST.not boB))
  !!ir (temp := AST.ite condOk (ctr .& numI32 0xfffffffc 32<rt>) nia)
  if lk then !!ir (lr := nia)
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let cmp ins insLen ctxt =
  let struct ((crf0, crf1, crf2, crf3), ra, rb) = transCmpOprs ins ctxt
  let cond1 = ra ?< rb
  let cond2 = ra ?> rb
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  !<ir insLen
  !!ir (crf0 := cond1)
  !!ir (crf1 := cond2)
  !!ir (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  !!ir (crf3 := AST.xtlo 1<rt> xer)
  !>ir insLen

let cmpl ins insLen ctxt =
  let struct ((crf0, crf1, crf2, crf3), ra, rb) = transCmpOprs ins ctxt
  let cond1 = ra .< rb
  let cond2 = ra .> rb
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  !<ir insLen
  !!ir (crf0 := cond1)
  !!ir (crf1 := cond2)
  !!ir (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  !!ir (crf3 := AST.xtlo 1<rt> xer)
  !>ir insLen

let cmpli ins insLen ctxt =
  let struct ((crf0, crf1, crf2, crf3), ra, uimm) = transCmpOprs ins ctxt
  let cond1 = ra .< uimm
  let cond2 = ra .> uimm
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  !<ir insLen
  !!ir (crf0 := cond1)
  !!ir (crf1 := cond2)
  !!ir (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  !!ir (crf3 := AST.xtlo 1<rt> xer)
  !>ir insLen

let cntlzw ins insLen ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let mask1 = numI32 0x55555555 32<rt>
  let mask2 = numI32 0x33333333 32<rt>
  let mask3 = numI32 0x0f0f0f0f 32<rt>
  !<ir insLen
  let x = !+ir 32<rt>
  !!ir (x := rs)
  !!ir (x := x .| (x >> numI32 1 32<rt>))
  !!ir (x := x .| (x >> numI32 2 32<rt>))
  !!ir (x := x .| (x >> numI32 4 32<rt>))
  !!ir (x := x .| (x >> numI32 8 32<rt>))
  !!ir (x := x .| (x >> numI32 16 32<rt>))
  !!ir (x := x .- ((x >> numI32 1 32<rt>) .& mask1))
  !!ir (x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2))
  !!ir (x := ((x >> numI32 4 32<rt>) .+ x) .& mask3)
  !!ir (x := x .+ (x >> numI32 8 32<rt>))
  !!ir (x := x .+ (x >> numI32 16 32<rt>))
  !!ir (ra := numI32 32 32<rt> .- (x .& numI32 63 32<rt>))
  !>ir insLen

let crclr ins insLen ctxt =
  let crbd = transOneOpr ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbd := AST.b0)
  !>ir insLen

let cror ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbA .| crbB)
  !>ir insLen

let crset ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbA <+> AST.not(crbB))
  !>ir insLen

let crnand ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := AST.not (crbA .& crbB))
  !>ir insLen

let crxor ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbA <+> crbB)
  !>ir insLen

let divw ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.ite (src2 == AST.num0 32<rt>) dst (src1 ?/ src2))
  !>ir insLen

let divwu ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.ite (src2 == AST.num0 32<rt>) dst (src1 ./ src2))
  !>ir insLen

let extsb ins insLen ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 8<rt>
  !<ir insLen
  !!ir (tmp := AST.xtlo 8<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  !>ir insLen

let extsbdot ins insLen ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 8<rt>
  !<ir insLen
  !!ir (tmp := AST.xtlo 8<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  setCondReg ctxt ir ra
  !>ir insLen

let extsh ins insLen ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 16<rt>
  !<ir insLen
  !!ir (tmp := AST.xtlo 16<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  !>ir insLen

let extshdot ins insLen ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 16<rt>
  !<ir insLen
  !!ir (tmp := AST.xtlo 16<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  setCondReg ctxt ir ra
  !>ir insLen

let eqvx ins insLen updateCond ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := AST.not (rs <+> rb))
  if updateCond then setCondReg ctxt ir ra else ()
  !>ir insLen

let fmadd ins insLen ctxt =
  let struct (dst, src1, src2, src3) = transFourOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (src1 .* src2) .+ src3)
  (* Affected: FPRF, FR, FI, FX, OX, UX, XX, VXSNAN, VXISI, VXIMZ *)
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
  (* Affected: FPRF, FR, FI, FX, OX, UX, XX, VXSNAN, VXISI, VXIMZ *)
  !>ir insLen

let lbz ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let dst = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.zext 32<rt> (loadNative ctxt 8<rt> ea))
  !>ir insLen

let lbzu ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let rd = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 8<rt> ea))
  !!ir (ra := ea)
  !>ir insLen

let lbzux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 8<rt> tmpEA))
  !!ir (rA := tmpEA)
  !>ir insLen

let lbzx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 8<rt> ea))
  !>ir insLen

let lfd ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let dst = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := loadNative ctxt 64<rt> ea)
  !>ir insLen

let lfs ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let dst = transOpr ctxt o1
  let v = loadNative ctxt 32<rt> ea
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.cast CastKind.FloatCast 64<rt> v)
  !>ir insLen

let lha ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let rd = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.sext 32<rt> (loadNative ctxt 16<rt> ea))
  !>ir insLen

let lhau ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let rd = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.sext 32<rt> (loadNative ctxt 16<rt> ea))
  !!ir (ra := ea)
  !>ir insLen

let lhaux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (rd := AST.sext 32<rt> (loadNative ctxt 16<rt> tmpEA))
  !!ir (rA := tmpEA)
  !>ir insLen

let lhax ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.sext 32<rt> (loadNative ctxt 16<rt> ea))
  !>ir insLen

let lhz ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let rd = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 16<rt> ea))
  !>ir insLen

let lhzu ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let rd = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 16<rt> ea))
  !!ir (ra := ea)
  !>ir insLen

let lhzux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 16<rt> tmpEA))
  !!ir (rA := tmpEA)
  !>ir insLen

let lhzx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := AST.zext 32<rt> (loadNative ctxt 16<rt> ea))
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

let lwarx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA= !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (AST.extCall <| AST.app "Reserve" [tmpEA] 32<rt>)
  !!ir (rd := loadNative ctxt 32<rt> tmpEA)
  !>ir insLen

let lwz ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let dst = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := loadNative ctxt 32<rt> ea)
  !>ir insLen

let lwzu ins insLen ctxt =
  let struct (o1 , o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let rd = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := loadNative ctxt 32<rt> ea)
  !!ir (ra := ea)
  !>ir insLen

let lwzux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (rd := loadNative ctxt 32<rt> tmpEA)
  !!ir (rA := tmpEA)
  !>ir insLen

let lwzx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (rd := loadNative ctxt 32<rt> ea)
  !>ir insLen

let mcrf ins insLen ctxt =
  let struct ((crd0, crd1, crd2, crd3),
              (crs0, crs1, crs2, crs3)) = transCondTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crd0 := crs0)
  !!ir (crd1 := crs1)
  !!ir (crd2 := crs2)
  !!ir (crd3 := crs3)
  !>ir insLen

let mcrxr ins insLen ctxt =
  let crd0, crd1, crd2, crd3 = transCondOneOpr ins ctxt
  let ir = !*ctxt
  let xer = !.ctxt R.XER
  !<ir insLen
  !!ir (crd0 := AST.extract xer 1<rt> 0)
  !!ir (crd1 := AST.extract xer 1<rt> 1)
  !!ir (crd2 := AST.extract xer 1<rt> 2)
  !!ir (crd3 := AST.extract xer 1<rt> 3)
  !!ir (xer := xer .& numI32 0xfffffff0 32<rt>)
  !>ir insLen

let mfcr ins insLen ctxt =
  let dst = transOneOpr ins ctxt
  let ir = !*ctxt
  let cr = !+ir 32<rt>
  !<ir insLen
  getCRRegValue ir cr ctxt
  !!ir (dst := cr)
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

let mfspr ins insLen ctxt =
  let struct (dst, spr) =
    match ins.Operands with
    | TwoOperands (o1, OprImm o2) ->
      transOpr ctxt o1, getSPRReg ctxt o2
    | _ -> raise InvalidOperandException
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := spr)
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

let mtctr ins insLen ctxt =
  let src = transOneOpr ins ctxt
  let ctr = !.ctxt R.CTR
  let ir = !*ctxt
  !<ir insLen
  !!ir (ctr := src)
  !>ir insLen

let mtspr ins insLen ctxt =
  let struct (src, spr) =
    match ins.Operands with
    | TwoOperands (o1, OprImm o2) ->
      transOpr ctxt o1, getSPRReg ctxt o2
    | _ -> raise InvalidOperandException
  let ir = !*ctxt
  !<ir insLen
  !!ir (spr := src)
  !>ir insLen

let private crmMask ir crm =
  let tCrm = Array.init 4 (fun _ -> !+ir 8<rt>)
  for i in 0..3 do
    let cond1 = AST.extract crm 1<rt> (i * 2)
    let cond2 = AST.extract crm 1<rt> (i * 2 + 1)
    !!ir (tCrm[i] :=
      AST.ite cond1 (AST.ite cond2 (numI32 0xff 8<rt>)(numI32 0xf 8<rt>))
       (AST.ite cond2 (numI32 0xf0 8<rt>) (AST.num0 8<rt>)))
  tCrm |> AST.concatArr

let mtcrf ins insLen ctxt =
  let struct (crm, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let mask = !+ir 32<rt>
  let cr = !+ir 32<rt>
  !<ir insLen
  !!ir (mask := crmMask ir crm)
  getCRRegValue ir cr ctxt
  !!ir (cr := (rs .& mask) .| (cr .& AST.not mask))
  setCRRegValue ir cr ctxt
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
  (* Affected: FX *)
  !>ir insLen

let mtfsb1 ins insLen ctxt =
  let crb = transOneOpr ins ctxt
  let fpscr = !.ctxt R.FPSCR
  let cond = (crb == numI32 1 32<rt>) .| (crb == numI32 2 32<rt>)
  let ir = !*ctxt
  let tmp = (numI32 0x80000000 32<rt>) >> crb
  !<ir insLen
  !!ir (fpscr := AST.ite cond fpscr (fpscr .| tmp))
  (* Affected: FX *)
  !>ir insLen

let mtfsf ins insLen ctxt =
  let struct (fm, frB) = getTwoOprs ins
  let frB = transOpr ctxt frB
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

let mulhwdot ins insLen ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> rb))
  !!ir (dst := AST.xthi 32<rt> tmp)
  setCondReg ctxt ir dst
  !>ir insLen

let mulhwu ins insLen ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.zext 64<rt> ra) .* (AST.zext 64<rt> rb))
  !!ir (dst := AST.xthi 32<rt> tmp)
  !>ir insLen

let mulhwudot ins insLen ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.zext 64<rt> ra) .* (AST.zext 64<rt> rb))
  !!ir (dst := AST.xthi 32<rt> tmp)
  setCondReg ctxt ir dst
  !>ir insLen

let mulli ins insLen ctxt =
  let struct (dst, ra, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> simm))
  !!ir (dst := AST.xtlo 32<rt> tmp)
  !>ir insLen

let mullw ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  !!ir (dst := AST.xtlo 32<rt> tmp)
  !>ir insLen

let mullwdot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  !!ir (dst := AST.xtlo 32<rt> tmp)
  setCondReg ctxt ir dst
  !>ir insLen

let mullwo ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerOV = AST.extract (!.ctxt R.XER) 1<rt> 1
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  !!ir (xerOV := AST.ite (tmp .< numU64 0xFFFFFFFFUL 64<rt>) AST.b0 AST.b1)
  !!ir (dst := AST.xtlo 32<rt> tmp)
  !>ir insLen

let mullwodot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerOV = AST.extract (!.ctxt R.XER) 1<rt> 1
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  !!ir (xerOV := AST.ite (tmp .< numU64 0xFFFFFFFFUL 64<rt>) AST.b0 AST.b1)
  !!ir (dst := AST.xtlo 32<rt> tmp)
  setCondReg ctxt ir dst
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

let nordot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.not (src1 .| src2))
  setCondReg ctxt ir dst
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
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| src2)
  setCondReg ctxt ir dst
  !>ir insLen

let orc ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| AST.not(src2))
  !>ir insLen

let orcdot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| AST.not(src2))
  setCondReg ctxt ir dst
  !>ir insLen

let ori ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = AST.zext 32<rt> (AST.xtlo 16<rt> uimm)
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
  let rol = !+ir 32<rt>
  !<ir insLen
  !!ir (rol := rotateLeft rs sh)
  !!ir (ra := rol .& (getExtMask mb me))
  !>ir insLen

let rlwinmdot ins insLen ctxt =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins ctxt
  let ir = !*ctxt
  let rol = !+ir 32<rt>
  !<ir insLen
  !!ir (rol := rotateLeft rs sh)
  !!ir (ra := rol .& (getExtMask mb me))
  setCondReg ctxt ir ra
  !>ir insLen

let rlwimi ins insLen ctxt =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins ctxt
  let ir = !*ctxt
  let m = getExtMask mb me
  let rol = rotateLeft rs sh
  !<ir insLen
  !!ir (ra := (rol .& m) .| (ra .& AST.not m))
  !>ir insLen

let rotlw ins insLen ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = rb .& numI32 0x1f 32<rt>
  let rol = rotateLeft rs n
  !<ir insLen
  !!ir (ra := rol) (* no mask *)
  !>ir insLen

let slw ins insLen ctxt =
  let struct (dst, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = !+ir 32<rt>
  let z = AST.num0 32<rt>
  !<ir insLen
  !!ir (n := rb .& numI32 0x1f 32<rt>)
  !!ir (dst := rs << n)
  !>ir insLen

let sraw ins insLen ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 2
  let z = AST.num0 32<rt>
  let cond1 = rb .& numI32 0x20 32<rt> == z
  let ir = !*ctxt
  let n = !+ir 32<rt>
  !<ir insLen
  !!ir (n := rb .& numI32 0x1f 32<rt>)
  !!ir (ra := AST.ite cond1 (rs ?>> n) (rs ?>> numI32 31 32<rt>))
  let cond2 = ra ?< z
  let cond3 = (rs .& ((AST.num1 32<rt> << n) .- AST.num1 32<rt>)) == z
  !!ir (xerCA := AST.ite cond2 (AST.ite cond3 AST.b0 AST.b1) AST.b0)
  !>ir insLen

let srawi ins insLen ctxt =
  let struct (ra, rs, sh) = transThreeOprs ins ctxt
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 2
  let z = AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := rs ?>> sh)
  let cond1 = ra ?< z
  let cond2 = (rs .& ((AST.num1 32<rt> << sh) .- AST.num1 32<rt>)) == z
  !!ir (xerCA := AST.ite cond1 (AST.ite cond2 AST.b0 AST.b1) AST.b0)
  !>ir insLen

let srawidot ins insLen ctxt =
  let struct (ra, rs, sh) = transThreeOprs ins ctxt
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 2
  let z = AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := rs ?>> sh)
  let cond1 = ra ?< z
  let cond2 = (rs .& ((AST.num1 32<rt> << sh) .- AST.num1 32<rt>)) == z
  !!ir (xerCA := AST.ite cond1 (AST.ite cond2 AST.b0 AST.b1) AST.b0)
  setCondReg ctxt ir ra
  !>ir insLen

let srw ins insLen ctxt =
  let struct (dst, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = !+ir 32<rt>
  !<ir insLen
  !!ir (n := rb .& numI32 0x1f 32<rt>)
  !!ir (dst := rs >> n)
  !>ir insLen

let stb ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 8<rt> ea := AST.xtlo 8<rt> src)
  !>ir insLen

let stbx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 8<rt> ea := AST.xtlo 8<rt> rs)
  !>ir insLen

let stbu ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (loadNative ctxt 8<rt> tmpEA := AST.xtlo 8<rt> src)
  !!ir (ra := tmpEA)
  !>ir insLen

let stbux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (loadNative ctxt 8<rt> tmpEA := AST.xtlo 8<rt> rs)
  !!ir (rA := tmpEA)
  !>ir insLen

let stfd ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 64<rt> ea := src)
  !>ir insLen

let stfs ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 32<rt> ea := AST.cast CastKind.FloatCast 32<rt> src)
  !>ir insLen

let sth ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 16<rt> ea := AST.xtlo 16<rt> src)
  !>ir insLen

let sthx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 16<rt> ea := AST.xtlo 16<rt> rs)
  !>ir insLen

let sthu ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let rs = transOpr ctxt o1
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (loadNative ctxt 16<rt> tmpEA := AST.xtlo 16<rt> rs)
  !!ir (ra := tmpEA)
  !>ir insLen

let sthux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (loadNative ctxt 16<rt> tmpEA := AST.xtlo 16<rt> rs)
  !!ir (rA := tmpEA)
  !>ir insLen

let stw ins insLen (ctxt: TranslationContext) =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 32<rt> ea := src)
  !>ir insLen

let stwcxdot ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let res = !.ctxt R.RES
  let xerSO = AST.xtlo 1<rt> (!.ctxt R.XER)
  let cr0LT = !.ctxt R.CR0_0
  let cr0GT = !.ctxt R.CR0_1
  let cr0EQ = !.ctxt R.CR0_2
  let cr0SO = !.ctxt R.CR0_3
  let ir = !*ctxt
  !<ir insLen
  let lblRes = !%ir "Reserved"
  let lblNoRes = !%ir "NotReserved"
  let lblEnd = !%ir "End"
  let tmpEA = !+ir 32<rt>
  !!ir (tmpEA := ea)
  !!ir (AST.extCall <| AST.app "IsReserved" [tmpEA] 32<rt>)
  !!ir (AST.cjmp (res == AST.b1) (AST.name lblRes) (AST.name lblNoRes))
  !!ir (AST.lmark lblRes)
  !!ir (loadNative ctxt 32<rt> tmpEA := rs)
  !!ir (res := AST.b0)
  !!ir (cr0EQ := AST.b1)
  !!ir (AST.jmp (AST.name lblEnd))
  !!ir (AST.lmark lblNoRes)
  !!ir (cr0EQ := AST.b0)
  !!ir (AST.lmark lblEnd)
  !!ir (cr0LT := AST.b0)
  !!ir (cr0GT := AST.b0)
  !!ir (cr0SO := xerSO)
  !>ir insLen

let stwu ins insLen ctxt =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 ctxt
  let src = transOpr ctxt o1
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (loadNative ctxt 32<rt> tmpEA := src)
  !!ir (ra := tmpEA)
  !>ir insLen

let stwux ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 ctxt
  let ir = !*ctxt
  let tmpEA = !+ir 32<rt>
  !<ir insLen
  !!ir (tmpEA := ea)
  !!ir (loadNative ctxt 32<rt> tmpEA := rs)
  !!ir (rA := tmpEA)
  !>ir insLen

let stwx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (loadNative ctxt 32<rt> ea := rs)
  !>ir insLen

let subf ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ (AST.num1 32<rt>))
  !>ir insLen

let subfdot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ (AST.num1 32<rt>))
  setCondReg ctxt ir dst
  !>ir insLen

let subfc ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ AST.num1 32<rt>)
  setCarryOut ctxt dst src2 ir
  !>ir insLen

let subfe ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ src2 .+ xerCA)
  setCarryOut ctxt dst src2 ir
  !>ir insLen

let subfic ins insLen ctxt  =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src1) .+ simm .+ AST.num1 32<rt>)
  setCarryOut ctxt dst simm ir
  !>ir insLen

let subfme ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  let minusone = AST.num (BitVector.OfUInt32 0xffffffffu 32<rt>)
  !<ir insLen
  !!ir (dst := (AST.not src) .+ xerCA .+ minusone)
  setCarryOut ctxt dst minusone ir
  !>ir insLen

let subfze ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 2)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src) .+ xerCA)
  setCarryOut ctxt dst (AST.num0 32<rt>) ir
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
  let uimm = AST.zext 32<rt> (AST.xtlo 16<rt> uimm)
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
  | Op.ADDdot -> adddot ins insLen ctxt
  | Op.ADDC -> addc ins insLen ctxt
  | Op.ADDCdot -> addcdot ins insLen ctxt
  | Op.ADDE -> adde ins insLen ctxt
  | Op.ADDEdot -> addedot ins insLen ctxt
  | Op.ADDI -> addi ins insLen ctxt
  | Op.ADDIC -> addic ins insLen ctxt
  | Op.ADDICdot -> addicdot ins insLen ctxt
  | Op.ADDIS -> addis ins insLen ctxt
  | Op.ADDME -> addme ins insLen ctxt
  | Op.ADDMEdot -> addmedot ins insLen ctxt
  | Op.ADDZE -> addze ins insLen ctxt
  | Op.ADDZEdot -> addzedot ins insLen ctxt
  | Op.AND -> andx ins insLen ctxt
  | Op.ANDdot -> anddot ins insLen ctxt
  | Op.ANDC -> andc ins insLen ctxt
  | Op.ANDCdot -> andcdot ins insLen ctxt
  | Op.ANDIdot -> andidot ins insLen ctxt
  | Op.ANDISdot -> andisdot ins insLen ctxt
  | Op.B -> b ins insLen ctxt false
  | Op.BA -> b ins insLen ctxt false
  | Op.BL -> b ins insLen ctxt true
  | Op.BLA -> b ins insLen ctxt true
  | Op.BC -> bc ins insLen ctxt false false
  | Op.BCA -> bc ins insLen ctxt true false
  | Op.BCL -> bc ins insLen ctxt false true
  | Op.BCLA -> bc ins insLen ctxt true true
  | Op.BCCTR -> bcctr ins insLen ctxt false
  | Op.BCCTRL -> bcctr ins insLen ctxt true
  | Op.BCLR -> bclr ins insLen ctxt false
  | Op.BCLRL -> bclr ins insLen ctxt true
  | Op.CMPI | Op.CMPL | Op.CMPLI -> raise InvalidOperandException (* invaild *)
  | Op.CMP -> cmp ins insLen ctxt
  | Op.CMPW -> cmp ins insLen ctxt
  | Op.CMPLW -> cmpl ins insLen ctxt
  | Op.CMPLWI -> cmpli ins insLen ctxt
  | Op.CMPWI -> cmp ins insLen ctxt
  | Op.CNTLZW -> cntlzw ins insLen ctxt
  | Op.CRCLR -> crclr ins insLen ctxt
  | Op.CRXOR -> crxor ins insLen ctxt
  | Op.CROR -> cror ins insLen ctxt
  | Op.CRSET -> crset ins insLen ctxt
  | Op.DCBT -> nop insLen ctxt
  | Op.DCBTST -> nop insLen ctxt
  | Op.DIVW -> divw ins insLen ctxt
  | Op.DIVWU -> divwu ins insLen ctxt
  | Op.EXTSB -> extsb ins insLen ctxt
  | Op.EXTSBdot -> extsbdot ins insLen ctxt
  | Op.EXTSH -> extsh ins insLen ctxt
  | Op.EXTSHdot -> extshdot ins insLen ctxt
  | Op.EIEIO -> nop insLen ctxt
  | Op.EQV -> eqvx ins insLen false ctxt
  | Op.EQVdot -> eqvx ins insLen true ctxt
  | Op.FABS | Op.FADD | Op.FADDS | Op.FCMPU | Op.FCTIWZ | Op.FDIV | Op.FDIVS
  | Op.FMUL | Op.FMULS | Op.FRSP | Op.FSUB | Op.FSUBS ->
    sideEffects insLen ctxt UnsupportedFP
  | Op.FMADD -> fmadd ins insLen ctxt
  | Op.FMR -> fmr ins insLen ctxt
  | Op.FMSUB -> fmsub ins insLen ctxt
  | Op.ISYNC -> nop insLen ctxt
  | Op.LBZ -> lbz ins insLen ctxt
  | Op.LBZU -> lbzu ins insLen ctxt
  | Op.LBZUX -> lbzux ins insLen ctxt
  | Op.LBZX -> lbzx ins insLen ctxt
  | Op.LFD -> lfd ins insLen ctxt
  | Op.LFS -> lfs ins insLen ctxt
  | Op.LHA -> lha ins insLen ctxt
  | Op.LHAU -> lhau ins insLen ctxt
  | Op.LHAUX ->lhaux ins insLen ctxt
  | Op.LHAX -> lhax ins insLen ctxt
  | Op.LHZ -> lhz ins insLen ctxt
  | Op.LHZU -> lhzu ins insLen ctxt
  | Op.LHZUX ->lhzux ins insLen ctxt
  | Op.LHZX -> lhzx ins insLen ctxt
  | Op.LI -> li ins insLen ctxt
  | Op.LIS -> lis ins insLen ctxt
  | Op.LWARX -> lwarx ins insLen ctxt
  | Op.LWZ -> lwz ins insLen ctxt
  | Op.LWZU -> lwzu ins insLen ctxt
  | Op.LWZUX -> lwzux ins insLen ctxt
  | Op.LWZX -> lwzx ins insLen ctxt
  | Op.MCRF -> mcrf ins insLen ctxt
  | Op.MCRXR -> mcrxr ins insLen ctxt
  | Op.MFCR -> mfcr ins insLen ctxt
  | Op.MFSPR -> mfspr ins insLen ctxt
  | Op.MFCTR -> mfctr ins insLen ctxt
  | Op.MFFS -> mffs ins insLen ctxt
  | Op.MFLR -> mflr ins insLen ctxt
  | Op.MFXER -> mfxer ins insLen ctxt
  | Op.MR -> mr ins insLen ctxt
  | Op.MTSPR -> mtspr ins insLen ctxt
  | Op.MTCTR -> mtctr ins insLen ctxt
  | Op.MTCRF -> mtcrf ins insLen ctxt
  | Op.MTFSB0 -> mtfsb0 ins insLen ctxt
  | Op.MTFSB1 -> mtfsb1 ins insLen ctxt
  | Op.MTFSF -> mtfsf ins insLen ctxt
  | Op.MTLR -> mtlr ins insLen ctxt
  | Op.MTXER -> mtxer ins insLen ctxt
  | Op.MULHW -> mulhw ins insLen ctxt
  | Op.MULHWU -> mulhwu ins insLen ctxt
  | Op.MULLI -> mulli ins insLen ctxt
  | Op.MULLW -> mullw ins insLen ctxt
  | Op.MULLWdot -> mullwdot ins insLen ctxt
  | Op.MULLWO -> mullwo ins insLen ctxt
  | Op.MULLWOdot -> mullwodot ins insLen ctxt
  | Op.NEG -> neg ins insLen ctxt
  | Op.NOR -> nor ins insLen ctxt
  | Op.NORdot -> nordot ins insLen ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.ORC -> orc ins insLen ctxt
  | Op.ORCdot -> orcdot ins insLen ctxt
  | Op.OR -> orx ins insLen ctxt
  | Op.ORdot -> ordot ins insLen ctxt
  | Op.ORI -> ori ins insLen ctxt
  | Op.ORIS -> oris ins insLen ctxt
  | Op.RLWIMI -> rlwimi ins insLen ctxt
  | Op.RLWINM -> rlwinm ins insLen ctxt
  | Op.RLWINMdot -> rlwinmdot ins insLen ctxt
  | Op.ROTLW -> rotlw ins insLen ctxt
  | Op.SC -> sideEffects insLen ctxt SysCall
  | Op.SLW -> slw ins insLen ctxt
  | Op.SRAW -> sraw ins insLen ctxt
  | Op.SRAWI -> srawi ins insLen ctxt
  | Op.SRAWIdot -> srawidot ins insLen ctxt
  | Op.SRW -> srw ins insLen ctxt
  | Op.STB -> stb ins insLen ctxt
  | Op.STBU -> stbu ins insLen ctxt
  | Op.STBX -> stbx ins insLen ctxt
  | Op.STBUX -> stbux ins insLen ctxt
  | Op.STFD -> stfd ins insLen ctxt
  | Op.STFS -> stfs ins insLen ctxt
  | Op.STH -> sth ins insLen ctxt
  | Op.STHU -> sthu ins insLen ctxt
  | Op.STHX -> sthx ins insLen ctxt
  | Op.STHUX -> sthux ins insLen ctxt
  | Op.STW -> stw ins insLen ctxt
  | Op.STWCXdot -> stwcxdot ins insLen ctxt
  | Op.STWU -> stwu ins insLen ctxt
  | Op.STWUX -> stwux ins insLen ctxt
  | Op.STWX -> stwx ins insLen ctxt
  | Op.SUBF -> subf ins insLen ctxt
  | Op.SUBFdot -> subfdot ins insLen ctxt
  | Op.SUBFC -> subfc ins insLen ctxt
  | Op.SUBFE -> subfe ins insLen ctxt
  | Op.SUBFIC -> subfic ins insLen ctxt
  | Op.SUBFZE -> subfze ins insLen ctxt
  | Op.SYNC -> nop insLen ctxt
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
