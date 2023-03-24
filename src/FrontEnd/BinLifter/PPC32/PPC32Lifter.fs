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

let transBranchTwoOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | TwoOperands (OprImm o1, OprBI o2) ->
    struct (uint32 o1, getCRbitRegister o2 |> !.ctxt)
  | _ -> raise InvalidOperandException

let transBranchThreeOprs (ins: InsInfo) ctxt =
  match ins.Operands with
  | ThreeOperands (OprImm o1, OprBI o2, OprAddr o3) ->
    struct (uint32 o1,
            getCRbitRegister o2 |> !.ctxt,
            numI64 (int64 o3) ctxt.WordBitSize)
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

let setCR0Reg ctxt ir result =
  let xerSO = AST.xthi 1<rt> (!.ctxt R.XER)
  let cr0LT = !.ctxt R.CR0_0
  let cr0GT = !.ctxt R.CR0_1
  let cr0EQ = !.ctxt R.CR0_2
  let cr0SO = !.ctxt R.CR0_3
  !!ir (cr0LT := result ?< AST.num0 32<rt>)
  !!ir (cr0GT := result ?> AST.num0 32<rt>)
  !!ir (cr0EQ := result == AST.num0 32<rt>)
  !!ir (cr0SO := xerSO)

let setCR1Reg ctxt ir =
  let fpscr = !.ctxt R.FPSCR
  let cr1FX = !.ctxt R.CR1_0
  let cr1FEX = !.ctxt R.CR1_1
  let cr1VX = !.ctxt R.CR1_2
  let cr1OX = !.ctxt R.CR1_3
  !!ir (cr1FX := AST.extract fpscr 1<rt> 31)
  !!ir (cr1FEX := AST.extract fpscr 1<rt> 30)
  !!ir (cr1VX := AST.extract fpscr 1<rt> 29)
  !!ir (cr1OX := AST.extract fpscr 1<rt> 28)

let isNaN frx =
  let exponent = (frx >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
  let fraction = frx .& numU64 0xffffffffffffUL 64<rt>
  let e = numI32 0x7ff 64<rt>
  let zero = AST.num0 64<rt>
  AST.xtlo 1<rt> ((exponent == e) .& (fraction != zero))

let isInfinity frx =
  let exponent = (frx >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
  let fraction = frx .& numU64 0xffffffffffffUL 64<rt>
  let e = numI32 0x7ff 64<rt>
  let zero = AST.num0 64<rt>
  AST.xtlo 1<rt> ((exponent == e) .& (fraction == zero))

let isDenormailized frx =
  let exponent = (frx >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
  let fraction = frx .& numU64 0xffffffffffffUL 64<rt>
  let zero = AST.num0 64<rt>
  AST.xtlo 1<rt> ((exponent == zero) .& (fraction != zero))

let setFPRF ctxt ir result =
  let fpscr = !.ctxt R.FPSCR
  let c = AST.extract fpscr 1<rt> 16
  let fl = AST.extract fpscr 1<rt> 15
  let fg = AST.extract fpscr 1<rt> 14
  let fe = AST.extract fpscr 1<rt> 13
  let fu = AST.extract fpscr 1<rt> 12
  let nzero = numU64 0x8000000000000000UL 64<rt>
  !!ir (c := isNaN result .| isDenormailized result .| AST.eq result nzero)
  !!ir (fl := AST.flt result (AST.num0 64<rt>))
  !!ir (fg := AST.fgt result (AST.num0 64<rt>))
  !!ir (fe := AST.eq (result << AST.num1 64<rt>) (AST.num0 64<rt>))
  !!ir (fu := isNaN result .| isInfinity result)

let setCarryOut ctxt expA expB ir =
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 29
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

let add ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2)
  if updateCond then setCR0Reg ctxt ir dst else ()
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
  setCR0Reg ctxt ir dst
  !>ir insLen

let adde ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2 .+ xerCA)
  setCarryOut ctxt dst src1 ir
  !>ir insLen

let addedot ins insLen ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ src2 .+ xerCA)
  setCR0Reg ctxt ir dst
  !>ir insLen

let addi ins insLen ctxt =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let cond = src1 == AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.ite cond simm (src1 .+ simm)))
  !>ir insLen

let addic ins insLen updateCond ctxt =
  let struct (dst, src1, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .+ simm)
  if updateCond then setCR0Reg ctxt ir dst else ()
  setCarryOut ctxt dst src1 ir
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
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA .- AST.num1 32<rt>)
  setCarryOut ctxt dst src ir
  !>ir insLen

let addmedot ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA .- AST.num1 32<rt>)
  setCR0Reg ctxt ir dst
  !>ir insLen

let addze ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA)
  setCarryOut ctxt dst src ir
  !>ir insLen

let addzedot ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .+ xerCA)
  setCR0Reg ctxt ir dst
  !>ir insLen

let andx ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& src2)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let andc ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .& AST.not(src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let andidot ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .& uimm)
  setCR0Reg ctxt ir dst
  !>ir insLen

let andisdot ins insLen ctxt =
  let struct (dst, src, uimm) = transThreeOprs ins ctxt
  let uimm = uimm << numI32 16 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src .& uimm)
  setCR0Reg ctxt ir dst
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
  let struct (bo, cr, addr) = transBranchThreeOprs ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
  let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
  let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
  let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = !+ir 32<rt>
  !<ir insLen
  if lk then !!ir (lr := nia)
  !!ir (ctr :=
          if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 32<rt>))
  !!ir (ctrOk := bo2 .| ((ctr != AST.num0 32<rt>) <+> bo3))
  !!ir (condOk := bo0 .| (cr <+> AST.not bo1))
  if aa then !!ir (temp := AST.ite (ctrOk .& condOk) addr nia)
  else !!ir (temp := AST.ite (ctrOk .& condOk) (cia .+ addr) nia)
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bclr ins insLen ctxt lk =
  let struct (bo, cr) = transBranchTwoOprs ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
  let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
  let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
  let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
  let ctrOk = !+ir 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (ctr :=
          if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 32<rt>))
  !!ir (ctrOk := bo2 .| ((ctr != AST.num0 32<rt>) <+> bo3))
  !!ir (condOk := bo0 .| (cr <+> AST.not bo1))
  !!ir (temp := AST.ite (ctrOk .& condOk) (lr .& numI32 0xfffffffc 32<rt>) nia)
  if lk then !!ir (lr := nia)
  !!ir (AST.interjmp temp InterJmpKind.Base)
  !>ir insLen

let bcctr ins insLen ctxt lk =
  let struct (bo, cr) = transBranchTwoOprs ins ctxt
  let ir = !*ctxt
  let lr = !.ctxt R.LR
  let ctr = !.ctxt R.CTR
  let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
  let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
  let condOk = !+ir 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = !+ir 32<rt>
  !<ir insLen
  !!ir (condOk := bo0 .| (cr <+> AST.not bo1))
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
  !!ir (crf3 := AST.xthi 1<rt> xer)
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
  !!ir (crf3 := AST.xthi 1<rt> xer)
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
  !!ir (crf3 := AST.xthi 1<rt> xer)
  !>ir insLen

let cntlzw ins insLen updateCond ctxt =
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
  if updateCond then setCR0Reg ctxt ir ra else ()
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

let crorc ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbA .| (AST.not crbB))
  !>ir insLen

let creqv ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbA <+> AST.not(crbB))
  !>ir insLen

let crset ins insLen ctxt =
  let crbD = transOneOpr ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbD <+> AST.not(crbD))
  !>ir insLen

let crnand ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := AST.not (crbA .& crbB))
  !>ir insLen

let crnor ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := AST.not (crbA .| crbB))
  !>ir insLen

let crnot ins insLen ctxt =
  let struct (crbD, crbA) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := AST.not crbA)
  !>ir insLen

let crxor ins insLen ctxt =
  let struct (crbD, crbA, crbB) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (crbD := crbA <+> crbB)
  !>ir insLen

let divw ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.ite (src2 == AST.num0 32<rt>) dst (src1 ?/ src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let divwu ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.ite (src2 == AST.num0 32<rt>) dst (src1 ./ src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let extsb ins insLen updateCond ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 8<rt>
  !<ir insLen
  !!ir (tmp := AST.xtlo 8<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  if updateCond then setCR0Reg ctxt ir ra else ()
  !>ir insLen

let extsh ins insLen updateCond ctxt =
  let struct (ra, rs) = transTwoOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 16<rt>
  !<ir insLen
  !!ir (tmp := AST.xtlo 16<rt> rs)
  !!ir (ra := AST.sext 32<rt> tmp)
  if updateCond then setCR0Reg ctxt ir ra else ()
  !>ir insLen

let eqvx ins insLen updateCond ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := AST.not (rs <+> rb))
  if updateCond then setCR0Reg ctxt ir ra else ()
  !>ir insLen

let fabs ins insLen updateCond ctxt =
  let struct (frd, frb) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (frd := frb .& numU64 0x7fffffffffffffffUL 64<rt>)
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fadd ins insLen updateCond isDouble ctxt =
  let struct (frd, fra, frb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  if isDouble then !!ir (frd := AST.fadd fra frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    !!ir (tmp := AST.fadd fraS frbS)
    !!ir (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF ctxt ir frd
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fcmpu ins insLen ctxt =
  let struct ((crf0, crf1, crf2, crf3), fra, frb) = transCmpOprs ins ctxt
  let cond1 = AST.flt fra frb
  let cond2 = AST.fgt fra frb
  let ir = !*ctxt
  !<ir insLen
  !!ir (crf0 := cond1)
  !!ir (crf1 := cond2)
  !!ir (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  !!ir (crf3 := (isNaN fra) .| (isNaN frb))
  !>ir insLen

let fdiv ins insLen updateCond isDouble ctxt =
  let struct (frd, fra, frb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  if isDouble then !!ir (frd := AST.fdiv fra frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    !!ir (tmp := AST.fdiv fraS frbS)
    !!ir (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF ctxt ir frd
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fsub ins insLen updateCond isDouble ctxt =
  let struct (frd, fra, frb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  if isDouble then !!ir (frd := AST.fsub fra frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    !!ir (tmp := AST.fsub fraS frbS)
    !!ir (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF ctxt ir frd
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fmadd ins insLen updateCond isDouble ctxt =
  let struct (frd, fra, frc, frb) = transFourOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  if isDouble then !!ir (frd := AST.fadd (AST.fmul fra frc) frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    let frcS = AST.cast CastKind.FloatCast 32<rt> frc
    !!ir (tmp := AST.fadd (AST.fmul fraS frcS) frbS)
    !!ir (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF ctxt ir frd
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fmr ins insLen updateCond ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src)
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fmsub ins insLen updateCond isDouble ctxt =
  let struct (frd, fra, frc, frb) = transFourOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  if isDouble then !!ir (frd := AST.fsub (AST.fmul fra frc) frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    let frcS = AST.cast CastKind.FloatCast 32<rt> frc
    !!ir (tmp := AST.fsub (AST.fmul fraS frcS) frbS)
    !!ir (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF ctxt ir frd
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fmul ins insLen updateCond isDouble ctxt =
  let struct (frd, fra, frb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  if isDouble then !!ir (frd := AST.fmul fra frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    !!ir (tmp := AST.fmul fraS frbS)
    !!ir (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF ctxt ir frd
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fnabs ins insLen updateCond ctxt =
  let struct (frd, frb) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (frd := frb .| numU64 0x8000000000000000UL 64<rt>)
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fneg ins insLen updateCond ctxt =
  let struct (frd, frb) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (frd := AST.fneg frb)
  if updateCond then setCR1Reg ctxt ir else ()
  !>ir insLen

let fsel ins insLen updateCond ctxt =
  let struct(frd, fra, frc, frb) = transFourOprs ins ctxt
  let ir = !*ctxt
  let cond = AST.fge fra (AST.num0 64<rt>)
  !<ir insLen
  !!ir (frd := AST.ite cond frc frb)
  if updateCond then setCR1Reg ctxt ir else ()
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
  let v = loadNative ctxt 64<rt> ea
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.cast CastKind.FloatCast 64<rt> v)
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

let lhbrx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  let tmp = !+ir 16<rt>
  let revtmp = !+ir 16<rt>
  !<ir insLen
  !!ir (tmp := loadNative ctxt 16<rt> ea)
  !!ir (AST.xthi 8<rt> revtmp := AST.xtlo 8<rt> tmp)
  !!ir (AST.xtlo 8<rt> revtmp := AST.xthi 8<rt> tmp)
  !!ir (rd := AST.zext 32<rt> revtmp)
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

let lwbrx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  let tmp = !+ir 32<rt>
  !<ir insLen
  !!ir (tmp := loadNative ctxt 32<rt> ea)
  !!ir (AST.extract rd 8<rt> 0:= AST.extract tmp 8<rt> 24)
  !!ir (AST.extract rd 8<rt> 8:= AST.extract tmp 8<rt> 16)
  !!ir (AST.extract rd 8<rt> 16:= AST.extract tmp 8<rt> 8)
  !!ir (AST.extract rd 8<rt> 24:= AST.extract tmp 8<rt> 0)
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
  !!ir (crd0 := AST.extract xer 1<rt> 31)
  !!ir (crd1 := AST.extract xer 1<rt> 30)
  !!ir (crd2 := AST.extract xer 1<rt> 29)
  !!ir (crd3 := AST.extract xer 1<rt> 28)
  !!ir (xer := xer .& numI32 0x0fffffff 32<rt>)
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

let mtfsb0 ins insLen updateCond ctxt =
  let crbD = getOneOpr ins |> getImmValue |> int
  let fpscr = !.ctxt R.FPSCR
  let ir = !*ctxt
  !<ir insLen
  if crbD <> 1 && crbD <> 2 then
    !!ir (AST.extract fpscr 1<rt> crbD := AST.b0)
  if updateCond then setCR1Reg ctxt ir else ()
  (* Affected: FX *)
  !>ir insLen

let mtfsb1 ins insLen updateCond ctxt =
  let crbD = getOneOpr ins |> getImmValue |> int
  let fpscr = !.ctxt R.FPSCR
  let ir = !*ctxt
  !<ir insLen
  if crbD <> 1 && crbD <> 2 then
    !!ir (AST.extract fpscr 1<rt> crbD := AST.b1)
  if updateCond then setCR1Reg ctxt ir else ()
  (* Affected: FX *)
  !>ir insLen

let mtfsf ins insLen ctxt =
  let struct (fm, frB) = getTwoOprs ins
  let frB = transOpr ctxt frB
  let fm = getImmValue fm
  let fpscr = !.ctxt R.FPSCR
  let ir = !*ctxt
  !<ir insLen
  for i in 0 .. 6 do
    if (fm >>> (7 - i)) &&& 1u = 1u then
      let n = i * 4
      !!ir (AST.extract fpscr 1<rt> n := AST.extract frB 1<rt> n)
      !!ir (AST.extract fpscr 1<rt> (n + 1) := AST.extract frB 1<rt> (n + 1))
      !!ir (AST.extract fpscr 1<rt> (n + 2) := AST.extract frB 1<rt> (n + 2))
      !!ir (AST.extract fpscr 1<rt> (n + 3) := AST.extract frB 1<rt> (n + 3))
    done
  if fm &&& 1u = 1u then
    !!ir (AST.extract fpscr 1<rt> 31 := AST.extract frB 1<rt> 31)
    !!ir (AST.extract fpscr 1<rt> 28 := AST.extract frB 1<rt> 28)
  !>ir insLen

let mtxer ins insLen ctxt =
  let src = transOneOpr ins ctxt
  let xer = !.ctxt R.XER
  let ir = !*ctxt
  !<ir insLen
  !!ir (xer := src)
  !>ir insLen

let mulhw ins insLen updateCond ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> rb))
  !!ir (dst := AST.xthi 32<rt> tmp)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let mulhwu ins insLen updateCond ctxt =
  let struct (dst, ra, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.zext 64<rt> ra) .* (AST.zext 64<rt> rb))
  !!ir (dst := AST.xthi 32<rt> tmp)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let mulli ins insLen ctxt =
  let struct (dst, ra, simm) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> simm))
  !!ir (dst := AST.xtlo 32<rt> tmp)
  !>ir insLen

let mullw ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  !!ir (dst := AST.xtlo 32<rt> tmp)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let mullwo ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let xerOV = AST.extract (!.ctxt R.XER) 1<rt> 30
  let ir = !*ctxt
  let tmp = !+ir 64<rt>
  !<ir insLen
  !!ir (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  !!ir (xerOV := AST.ite (tmp .< numU64 0xFFFFFFFFUL 64<rt>) AST.b0 AST.b1)
  !!ir (dst := AST.xtlo 32<rt> tmp)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let nand ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.not(src1 .& src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let neg ins insLen updateCond ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src) .+ AST.num1 32<rt>)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let nor ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := AST.not (src1 .| src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let nop insLen ctxt =
  let ir = !*ctxt
  !<ir insLen
  !>ir insLen

let orx ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| src2)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let orc ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := src1 .| AST.not(src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
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

let rlwinm ins insLen updateCond ctxt =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins ctxt
  let ir = !*ctxt
  let rol = !+ir 32<rt>
  !<ir insLen
  !!ir (rol := rotateLeft rs sh)
  !!ir (ra := rol .& (getExtMask mb me))
  if updateCond then setCR0Reg ctxt ir ra else ()
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

let slw ins insLen updateCond ctxt =
  let struct (dst, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = !+ir 32<rt>
  !<ir insLen
  !!ir (n := rb .& numI32 0x1f 32<rt>)
  !!ir (dst := rs << n)
  if updateCond then setCR0Reg ctxt ir dst else ()
  !>ir insLen

let sraw ins insLen updateCond ctxt =
  let struct (ra, rs, rb) = transThreeOprs ins ctxt
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 29
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
  if updateCond then setCR0Reg ctxt ir ra else ()
  !>ir insLen

let srawi ins insLen updateCond ctxt =
  let struct (ra, rs, sh) = transThreeOprs ins ctxt
  let xerCA = AST.extract (!.ctxt R.XER) 1<rt> 29
  let z = AST.num0 32<rt>
  let ir = !*ctxt
  !<ir insLen
  !!ir (ra := rs ?>> sh)
  let cond1 = ra ?< z
  let cond2 = (rs .& ((AST.num1 32<rt> << sh) .- AST.num1 32<rt>)) == z
  !!ir (xerCA := AST.ite cond1 (AST.ite cond2 AST.b0 AST.b1) AST.b0)
  if updateCond then setCR0Reg ctxt ir ra else ()
  !>ir insLen

let srw ins insLen updateCond ctxt =
  let struct (dst, rs, rb) = transThreeOprs ins ctxt
  let ir = !*ctxt
  let n = !+ir 32<rt>
  !<ir insLen
  !!ir (n := rb .& numI32 0x1f 32<rt>)
  !!ir (dst := rs >> n)
  if updateCond then setCR0Reg ctxt ir dst else ()
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

let sthbrx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  let revtmp = !+ir 16<rt>
  !<ir insLen
  !!ir (revtmp := AST.concat (AST.extract rs 8<rt> 0) (AST.extract rs 8<rt> 8))
  !!ir (loadNative ctxt 16<rt> ea := revtmp)
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

let stwbrx ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let ir = !*ctxt
  let revtmp = !+ir 32<rt>
  !<ir insLen
  !!ir (AST.extract revtmp 8<rt> 0:= AST.extract rs 8<rt> 24)
  !!ir (AST.extract revtmp 8<rt> 8:= AST.extract rs 8<rt> 16)
  !!ir (AST.extract revtmp 8<rt> 16:= AST.extract rs 8<rt> 8)
  !!ir (AST.extract revtmp 8<rt> 24:= AST.extract rs 8<rt> 0)
  !!ir (loadNative ctxt 32<rt> ea := revtmp)
  !>ir insLen

let stwcxdot ins insLen ctxt =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr ctxt o1
  let ea = transEAWithIndexReg o2 o3 ctxt
  let res = !.ctxt R.RES
  let xerSO = AST.xthi 1<rt> (!.ctxt R.XER)
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
  setCR0Reg ctxt ir dst
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
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
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
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  let minusone = AST.num (BitVector.OfUInt32 0xffffffffu 32<rt>)
  !<ir insLen
  !!ir (dst := (AST.not src) .+ xerCA .+ minusone)
  setCarryOut ctxt dst minusone ir
  !>ir insLen

let subfze ins insLen ctxt =
  let struct (dst, src) = transTwoOprs ins ctxt
  let xerCA = AST.zext 32<rt> (AST.extract (!.ctxt R.XER) 1<rt> 29)
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (AST.not src) .+ xerCA)
  setCarryOut ctxt dst (AST.num0 32<rt>) ir
  !>ir insLen

let xor ins insLen updateCond ctxt =
  let struct (dst, src1, src2) = transThreeOprs ins ctxt
  let ir = !*ctxt
  !<ir insLen
  !!ir (dst := (src1 <+> src2))
  if updateCond then setCR0Reg ctxt ir dst else ()
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
  | Op.ADD -> add ins insLen false ctxt
  | Op.ADDdot -> add ins insLen true ctxt
  | Op.ADDC -> addc ins insLen ctxt
  | Op.ADDCdot -> addcdot ins insLen ctxt
  | Op.ADDE -> adde ins insLen ctxt
  | Op.ADDEdot -> addedot ins insLen ctxt
  | Op.ADDI -> addi ins insLen ctxt
  | Op.ADDIC -> addic ins insLen false ctxt
  | Op.ADDICdot -> addic ins insLen true ctxt
  | Op.ADDIS -> addis ins insLen ctxt
  | Op.ADDME -> addme ins insLen ctxt
  | Op.ADDMEdot -> addmedot ins insLen ctxt
  | Op.ADDZE -> addze ins insLen ctxt
  | Op.ADDZEdot -> addzedot ins insLen ctxt
  | Op.AND -> andx ins insLen false ctxt
  | Op.ANDdot -> andx ins insLen true ctxt
  | Op.ANDC -> andc ins insLen false ctxt
  | Op.ANDCdot -> andc ins insLen true ctxt
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
  | Op.CNTLZW -> cntlzw ins insLen false ctxt
  | Op.CNTLZWdot -> cntlzw ins insLen true ctxt
  | Op.CRCLR -> crclr ins insLen ctxt
  | Op.CREQV -> creqv ins insLen ctxt
  | Op.CRXOR -> crxor ins insLen ctxt
  | Op.CROR -> cror ins insLen ctxt
  | Op.CRORC -> crorc ins insLen ctxt
  | Op.CRSET -> crset ins insLen ctxt
  | Op.CRNOR -> crnor ins insLen ctxt
  | Op.CRNOT -> crnot ins insLen ctxt
  | Op.DCBT -> nop insLen ctxt
  | Op.DCBTST -> nop insLen ctxt
  | Op.DIVW -> divw ins insLen false ctxt
  | Op.DIVWU -> divwu ins insLen true ctxt
  | Op.EXTSB -> extsb ins insLen false ctxt
  | Op.EXTSBdot -> extsb ins insLen true ctxt
  | Op.EXTSH -> extsh ins insLen false ctxt
  | Op.EXTSHdot -> extsh ins insLen true ctxt
  | Op.EIEIO -> nop insLen ctxt
  | Op.EQV -> eqvx ins insLen false ctxt
  | Op.EQVdot -> eqvx ins insLen true ctxt
  | Op.FABS -> fabs ins insLen false ctxt
  | Op.FABSdot  -> fabs ins insLen true ctxt
  | Op.FADD -> fadd ins insLen false true ctxt
  | Op.FADDS -> fadd ins insLen false false ctxt
  | Op.FADDdot -> fadd ins insLen true true ctxt
  | Op.FADDSdot -> fadd ins insLen true false ctxt
  | Op.FCMPU -> fcmpu ins insLen ctxt
  | Op.FDIV -> fdiv ins insLen false true ctxt
  | Op.FDIVS -> fdiv ins insLen false false ctxt
  | Op.FDIVdot -> fdiv ins insLen true true ctxt
  | Op.FDIVSdot -> fdiv ins insLen true false ctxt
  | Op.FSUB -> fsub ins insLen false true ctxt
  | Op.FSUBS -> fsub ins insLen false false ctxt
  | Op.FSUBdot -> fsub ins insLen true true ctxt
  | Op.FSUBSdot -> fsub ins insLen true false ctxt
  | Op.FCTIWZ | Op.FRSP -> sideEffects insLen ctxt UnsupportedFP
  | Op.FMADD -> fmadd ins insLen false true ctxt
  | Op.FMADDS -> fmadd ins insLen false false ctxt
  | Op.FMADDdot -> fmadd ins insLen true true ctxt
  | Op.FMADDSdot -> fmadd ins insLen true false ctxt
  | Op.FMR -> fmr ins insLen false ctxt
  | Op.FMRdot -> fmr ins insLen true ctxt
  | Op.FMSUB -> fmsub ins insLen false true ctxt
  | Op.FMSUBS -> fmsub ins insLen false false ctxt
  | Op.FMSUBdot -> fmsub ins insLen true true ctxt
  | Op.FMSUBSdot -> fmsub ins insLen true false ctxt
  | Op.FMUL -> fmul ins insLen false true ctxt
  | Op.FMULS -> fmul ins insLen false false ctxt
  | Op.FMULdot -> fmul ins insLen true true ctxt
  | Op.FMULSdot -> fmul ins insLen true false ctxt
  | Op.FNABS -> fnabs ins insLen false ctxt
  | Op.FNABSdot -> fnabs ins insLen true ctxt
  | Op.FNEG -> fneg ins insLen false ctxt
  | Op.FNEGdot -> fneg ins insLen true ctxt
  | Op.FSEL -> fsel ins insLen false ctxt
  | Op.FSELdot -> fsel ins insLen true ctxt
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
  | Op.LHBRX -> lhbrx ins insLen ctxt
  | Op.LHZ -> lhz ins insLen ctxt
  | Op.LHZU -> lhzu ins insLen ctxt
  | Op.LHZUX ->lhzux ins insLen ctxt
  | Op.LHZX -> lhzx ins insLen ctxt
  | Op.LI -> li ins insLen ctxt
  | Op.LIS -> lis ins insLen ctxt
  | Op.LWARX -> lwarx ins insLen ctxt
  | Op.LWBRX -> lwbrx ins insLen ctxt
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
  | Op.MTFSB0 -> mtfsb0 ins insLen false ctxt
  | Op.MTFSB0dot -> mtfsb0 ins insLen true ctxt
  | Op.MTFSB1 -> mtfsb1 ins insLen false ctxt
  | Op.MTFSB1dot -> mtfsb1 ins insLen true ctxt
  | Op.MTFSF -> mtfsf ins insLen ctxt
  | Op.MTLR -> mtlr ins insLen ctxt
  | Op.MTXER -> mtxer ins insLen ctxt
  | Op.MULHW -> mulhw ins insLen false ctxt
  | Op.MULHWU -> mulhwu ins insLen true ctxt
  | Op.MULLI -> mulli ins insLen ctxt
  | Op.MULLW -> mullw ins insLen false ctxt
  | Op.MULLWdot -> mullw ins insLen true ctxt
  | Op.MULLWO -> mullwo ins insLen false ctxt
  | Op.MULLWOdot -> mullwo ins insLen true ctxt
  | Op.NAND -> nand ins insLen false ctxt
  | Op.NANDdot -> nand ins insLen true ctxt
  | Op.NEG -> neg ins insLen false ctxt
  | Op.NEGdot -> neg ins insLen true ctxt
  | Op.NOR -> nor ins insLen false ctxt
  | Op.NORdot -> nor ins insLen true ctxt
  | Op.NOP -> nop insLen ctxt
  | Op.ORC -> orc ins insLen false ctxt
  | Op.ORCdot -> orc ins insLen true ctxt
  | Op.OR -> orx ins insLen false ctxt
  | Op.ORdot -> orx ins insLen true ctxt
  | Op.ORI -> ori ins insLen ctxt
  | Op.ORIS -> oris ins insLen ctxt
  | Op.RLWIMI -> rlwimi ins insLen ctxt
  | Op.RLWINM -> rlwinm ins insLen false ctxt
  | Op.RLWINMdot -> rlwinm ins insLen true ctxt
  | Op.ROTLW -> rotlw ins insLen ctxt
  | Op.SC -> sideEffects insLen ctxt SysCall
  | Op.SLW -> slw ins insLen false ctxt
  | Op.SLWdot -> slw ins insLen true ctxt
  | Op.SRAW -> sraw ins insLen false ctxt
  | Op.SRAWdot -> sraw ins insLen true ctxt
  | Op.SRAWI -> srawi ins insLen false ctxt
  | Op.SRAWIdot -> srawi ins insLen true ctxt
  | Op.SRW -> srw ins insLen false ctxt
  | Op.SRWdot -> srw ins insLen true ctxt
  | Op.STB -> stb ins insLen ctxt
  | Op.STBU -> stbu ins insLen ctxt
  | Op.STBX -> stbx ins insLen ctxt
  | Op.STBUX -> stbux ins insLen ctxt
  | Op.STFD -> stfd ins insLen ctxt
  | Op.STFS -> stfs ins insLen ctxt
  | Op.STH -> sth ins insLen ctxt
  | Op.STHBRX -> sthbrx ins insLen ctxt
  | Op.STHU -> sthu ins insLen ctxt
  | Op.STHX -> sthx ins insLen ctxt
  | Op.STHUX -> sthux ins insLen ctxt
  | Op.STW -> stw ins insLen ctxt
  | Op.STWBRX -> stwbrx ins insLen ctxt
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
  | Op.XOR -> xor ins insLen false ctxt
  | Op.XORdot -> xor ins insLen true ctxt
  | Op.XORI -> xori ins insLen ctxt
  | Op.XORIS -> xoris ins insLen ctxt
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:
