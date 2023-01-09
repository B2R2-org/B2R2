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

module B2R2.FrontEnd.BinLifter.SPARC.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.SPARC

let inline getRegVar (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

let inline numI32 n = BitVector.OfInt32 n 64<rt> |> AST.num

let inline numI32PC n = BitVector.OfInt32 n 64<rt> |> AST.num

let inline numU32 n t = BitVector.OfUInt32 n t |> AST.num

let inline numU64 n t = BitVector.OfUInt64 n t |> AST.num

let inline numI64 n t = BitVector.OfInt64 n t |> AST.num


let inline tmpVars2 ir t =
  struct (!+ir t, !+ir t)

let inline ( !. ) (ctxt: TranslationContext) name =
  Register.toRegID name |> ctxt.GetRegVar

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

/// OF on add.
let private ofOnAdd e1 e2 r =
  let e1High = AST.xthi 1<rt> e1
  let e2High = AST.xthi 1<rt> e2
  let rHigh = AST.xthi 1<rt> r
  (e1High .& e2High .& (AST.neg rHigh))
    .| ((AST.neg e1High) .& (AST.neg e2High) .& rHigh)

let transOprToExpr ins insLen ctxt = function
  | OprReg reg -> !.ctxt reg
  | OprImm imm -> numI32 imm
  | OprAddr addr -> numI32PC addr
  | OprCC cc -> getCCVar ctxt cc
  | _ -> Utils.impossible ()

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

let add ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !>ir insLen

let addcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let ccr = !.ctxt R.CCR
  let tmpc = !+ir 1<rt>
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  (* xcc field bits *)
  !!ir (tmpc := AST.b0 ?> dst)
  !!ir ((AST.extract ccr 1<rt> 7) := AST.extract tmpc 1<rt> 1)
  !!ir (tmpc := AST.b0 == dst)
  !!ir ((AST.extract ccr 1<rt> 6) := AST.extract tmpc 1<rt> 1)
  (* Add v bit (OverFlow) and icc field bits *)
  !>ir insLen

let addC ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let ccr = !.ctxt R.CCR
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2 .+ (AST.extract ccr 1<rt> 4))
  !!ir (dst := t3)
  !>ir insLen

let addCcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let ccr = !.ctxt R.CCR
  let tmpc = !+ir 1<rt>
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2 .+ (AST.extract ccr 1<rt> 4))
  (* xcc field bits *)
  !!ir (tmpc := AST.b0 ?> dst)
  !!ir ((AST.extract ccr 1<rt> 7) := AST.extract tmpc 1<rt> 1)
  !!ir (tmpc := AST.b0 == dst)
  !!ir ((AST.extract ccr 1<rt> 6) := AST.extract tmpc 1<rt> 1)
  !!ir ((AST.extract ccr 1<rt> 4) := AST.extract tmpc 1<rt> 1)
  (* Add v bit (OverFlow) and icc field bits *)
  !!ir (dst := t3)
  !>ir insLen

let ``and`` ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let r = !+ir oprSize
  !<ir insLen
  !!ir (r := src .& src1)
  !!ir (dst := r)
  !>ir insLen

let andcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = !.ctxt R.CCR
  let r = !+ir oprSize
  let tmpc = !+ir 1<rt>
  !<ir insLen
  !!ir (r := src .& src1)
  !!ir (dst := r)
  (* xcc field bits *)
  !!ir (tmpc := AST.b0 ?> dst)
  !!ir ((AST.extract ccr 1<rt> 7) := AST.extract tmpc 1<rt> 1)
  !!ir (tmpc := AST.b0 == dst)
  !!ir ((AST.extract ccr 1<rt> 6) := AST.extract tmpc 1<rt> 1)
  (* Add v bit (OverFlow) and icc field bits *)
  !>ir insLen

let andn ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let r = !+ir oprSize
  !<ir insLen
  !!ir (r := (AST.not src) .& src1)
  !!ir (dst := r)
  !>ir insLen

let andncc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let ccr = !.ctxt R.CCR
  let r = !+ir oprSize
  let tmpc = !+ir 1<rt>
  !<ir insLen
  !!ir (r := (AST.not src) .& src1)
  !!ir (dst := r)
  (* xcc field bits *)
  !!ir (tmpc := AST.b0 ?> dst)
  !!ir ((AST.extract ccr 1<rt> 7) := AST.extract tmpc 1<rt> 1)
  !!ir (tmpc := AST.b0 == dst)
  !!ir ((AST.extract ccr 1<rt> 6) := AST.extract tmpc 1<rt> 1)
  (* Add v bit (OverFlow) and icc field bits *)
  !>ir insLen

let branch ins insLen ctxt = (* FIXME *)
  let ir = IRBuilder (16)
  let struct (cc, dst) = transTwoOprs ins insLen ctxt
  let pc = !.ctxt R.PC
  let ccr = !.ctxt R.CCR
  let branchCond =
    match ins.Opcode with
    | Opcode.BPA -> !.ctxt
    | Opcode.BPN -> !.ctxt
    | Opcode.BPNE -> !.ctxt
    | Opcode.BPE -> !.ctxt
    | Opcode.BPG -> !.ctxt
    | Opcode.BPLE -> !.ctxt
    | Opcode.BPGE -> !.ctxt
    | Opcode.BPL -> !.ctxt
    | Opcode.BPGU -> !.ctxt
    | Opcode.BPLEU -> !.ctxt
    | Opcode.BPCC -> !.ctxt // (AST.extract ccr 1<rt> 4) == AST.b0
    | Opcode.BPCS -> !.ctxt // (AST.extract ccr 1<rt> 4) == AST.b1
    | Opcode.BPPOS -> !.ctxt
    | Opcode.BPNEG -> !.ctxt
    | Opcode.BPVC -> !.ctxt
    | Opcode.BPVS -> !.ctxt
    | Opcode.BRZ -> !.ctxt
    | Opcode.BRLEZ -> !.ctxt
    | Opcode.BRLZ -> !.ctxt
    | Opcode.BRNZ -> !.ctxt
    | Opcode.BRGZ -> !.ctxt
    | Opcode.BRGEZ -> !.ctxt
    | _ -> raise InvalidOpcodeException
  !<ir insLen
  let fallThrough = pc .+ numI32PC 4
  let jumpTarget = pc .+ AST.zext 64<rt> dst .+ numI32PC 4
  // !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir insLen

let call ins insLen ctxt =
  let ir = IRBuilder (16)
  let dst = transOneOpr ins insLen ctxt
  let sp = !.ctxt R.I6
  let pc = !.ctxt R.PC
  !<ir insLen
  !!ir (pc := dst)
  !!ir (AST.loadLE 64<rt> sp := pc .+ numI32PC 2)
  !!ir (sp := sp.- numI32PC 2)
  !>ir insLen

let casa ins insLen ctxt = (* FIXME *)
  let struct (src, src1, src2, dst) = transFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3, t4) = tmpVars4 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := src2)
  if t1 = t2 then
    !!ir (t4 := t1)
    !!ir (dst := t4)
  else
    !!ir (dst := AST.b0)
  !>ir insLen

let ``done`` ins insLen ctxt =
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (!.ctxt R.PC := !.ctxt R.TNPC)
  !!ir (!.ctxt R.NPC := !.ctxt R.TNPC .+ numI32PC 4)
  !>ir insLen

let fabs ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := AST.cast CastKind.FtoIFloor 64<rt> src)
  !>ir insLen

let fmov ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let fneg ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := AST.cast CastKind.SignExt 64<rt> src)
  !>ir insLen

let fadd ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let r = !+ir oprSize
  !<ir insLen
  !!ir (r := src .+ src1)
  !!ir (dst := r)
  !>ir insLen

let fbranch ins insLen ctxt = (* FIXME *)
  let ir = IRBuilder (16)
  let struct (cc, dst) = transTwoOprs ins insLen ctxt
  let pc = !.ctxt R.PC
  let branchCond =
    match ins.Opcode with
    | Opcode.FBA -> !.ctxt
    | Opcode.FBN -> !.ctxt
    | Opcode.FBU -> !.ctxt
    | Opcode.FBG -> !.ctxt
    | Opcode.FBUG -> !.ctxt
    | Opcode.FBL -> !.ctxt
    | Opcode.FBUL -> !.ctxt
    | Opcode.FBLG -> !.ctxt
    | Opcode.FBNE -> !.ctxt
    | Opcode.FBE -> !.ctxt
    | Opcode.FBUE -> !.ctxt
    | Opcode.FBGE -> !.ctxt
    | Opcode.FBUGE -> !.ctxt
    | Opcode.FBLE -> !.ctxt
    | Opcode.FBULE -> !.ctxt
    | Opcode.FBO -> !.ctxt
    | _ -> raise InvalidOpcodeException
  !<ir insLen
  let fallThrough = pc .+ numI32PC 2
  let jumpTarget = pc .+ AST.zext 64<rt> dst .+ numI32PC 2
  // !!ir (AST.intercjmp branchCond jumpTarget fallThrough)
  !>ir insLen

let fcmp ins insLen ctxt =
  let struct (cc, src, src1) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  let t = !+ir 64<rt>
  match cc.E with
  | Var (_,_,s,_) ->
    if s.EndsWith "0" then
      !!ir (t := src == src1)
    elif s.EndsWith "1" then
      !!ir (t := src ?< src1)
    elif s.EndsWith "2" then
      !!ir (t := src ?> src1)
    elif s.EndsWith "3" then
      raise InvalidOperandException
    else
      raise InvalidOperandException
    !>ir insLen
  | _ -> Utils.impossible()


let fdiv ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 ./ t2)
  !!ir (dst := t3)
  !>ir insLen

let fito ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  match ins.Opcode with
  | Opcode.FiTOs ->
    !!ir (dst := AST.cast CastKind.IntToFloat 32<rt> t1)
  | Opcode.FiTOd ->
    !!ir (dst := AST.cast CastKind.IntToFloat 64<rt> t1)
  | Opcode.FiTOq ->
    !!ir (dst := AST.cast CastKind.IntToFloat 128<rt> t1)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let fmovcc ins insLen ctxt = (* fix me *)
  let struct (cc, src, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := cc)
  !!ir (dst := src)
  !>ir insLen

let fmovr ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  match t1.E with
  | Num n ->
    match ins.Opcode with
    | Opcode.FMOVRZ ->
      !!ir (t3 := AST.ite (AST.num n == AST.num0 oprSize) (t2) (dst))
    | Opcode.FMOVRLEZ ->
      !!ir (t3 := AST.ite (AST.num n ?<= AST.num0 oprSize) (t2) (dst))
    | Opcode.FMOVRLZ ->
      !!ir (t3 := AST.ite (AST.num n ?< AST.num0 oprSize) (t2) (dst))
    | Opcode.FMOVRNZ ->
      !!ir (t3 := AST.ite (AST.num n != AST.num0 oprSize) (t2) (dst))
    | Opcode.FMOVRGZ ->
      !!ir (t3 := AST.ite (AST.num n ?> AST.num0 oprSize) (t2) (dst))
    | Opcode.FMOVRGEZ ->
      !!ir (t3 := AST.ite (AST.num n ?>= AST.num0 oprSize) (t2) (dst))
    | _ -> raise InvalidOpcodeException
  | _ -> raise InvalidOperandException
  !!ir (dst := t3)
  !>ir insLen

let fmul ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let t4 = !+ir 64<rt>
  !<ir insLen
  !!ir (t1 := AST.zext oprSize src)
  !!ir (t2 := AST.zext oprSize src1)
  !!ir (t3 := src .* src1)
  !!ir (t4 := t3 << AST.num1 oprSize)
  !!ir (dst := t4)
  !>ir insLen

let fsmuld ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  let t4 = !+ir 64<rt>
  !<ir insLen
  !!ir (t1 := AST.zext oprSize src)
  !!ir (t2 := AST.zext oprSize src1)
  !!ir (t3 := src .* src1)
  !!ir (t4 := t3 << AST.num1 oprSize)
  !!ir (dst := t4)
  !>ir insLen

let fsqrt ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src .* src)
  !>ir insLen

let ftox ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := AST.cast CastKind.FtoIRound 64<rt> src)
  !!ir (dst := t1)
  !>ir insLen

let ftoi ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := AST.cast CastKind.FtoIRound 32<rt> src)
  !!ir (dst := t1)
  !>ir insLen

let fto ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  match ins.Opcode with
  | Opcode.FsTOd ->
    !!ir (dst := AST.cast CastKind.FloatCast 64<rt> t1)
  | Opcode.FsTOq ->
    !!ir (dst := AST.cast CastKind.FloatCast 128<rt> t1)
  | Opcode.FdTOs ->
    !!ir (dst := AST.cast CastKind.FloatCast 32<rt> t1)
  | Opcode.FdTOq ->
    !!ir (dst := AST.cast CastKind.FloatCast 128<rt> t1)
  | Opcode.FqTOs ->
    !!ir (dst := AST.cast CastKind.FloatCast 32<rt> t1)
  | Opcode.FqTOd ->
    !!ir (dst := AST.cast CastKind.FloatCast 64<rt> t1)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let fsub ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := src .- src1)
  !!ir (dst := t3)
  !>ir insLen

let fxto ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  match ins.Opcode with
  | Opcode.FxTOs ->
    !!ir (dst := AST.cast CastKind.IntToFloat 32<rt> t1)
  | Opcode.FxTOd ->
    !!ir (dst := AST.cast CastKind.IntToFloat 64<rt> t1)
  | Opcode.FxTOq ->
    !!ir (dst := AST.cast CastKind.IntToFloat 128<rt> t1)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let jmpl ins insLen ctxt =
  let struct (addr, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let t1 = !+ir oprSize
  !<ir insLen
  !!ir (AST.jmp addr)
  !!ir (dst := !.ctxt R.PC)
  !>ir insLen

let ldf ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := addr)
  !>ir insLen

let ldfa ins insLen ctxt =
  let struct (addr, asi, dst) = transAddrFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := addr)
  !>ir insLen

let ldfsr ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := addr)
  !>ir insLen

let ld ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.LDSB -> !!ir (dst := AST.cast CastKind.SignExt 8<rt> addr)
  | Opcode.LDSH -> !!ir (dst := AST.cast CastKind.SignExt 16<rt> addr)
  | Opcode.LDSW -> !!ir (dst := AST.cast CastKind.SignExt 32<rt> addr)
  | Opcode.LDUB -> !!ir (dst := AST.cast CastKind.ZeroExt 8<rt> addr)
  | Opcode.LDUH -> !!ir (dst := AST.cast CastKind.ZeroExt 16<rt> addr)
  | Opcode.LDUW -> !!ir (dst := addr)
  | Opcode.LDX -> !!ir (dst := addr) (* FIXME *)
  | Opcode.LDD -> !!ir (dst := addr) (* FIXME *)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let lda ins insLen ctxt =
  let struct (addr, asi, dst) = transAddrFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.LDSBA -> !!ir (dst := AST.cast CastKind.SignExt 8<rt> addr)
  | Opcode.LDSHA -> !!ir (dst := AST.cast CastKind.SignExt 16<rt> addr)
  | Opcode.LDSWA -> !!ir (dst := AST.cast CastKind.SignExt 32<rt> addr)
  | Opcode.LDUBA -> !!ir (dst := AST.cast CastKind.ZeroExt 8<rt> addr)
  | Opcode.LDUHA -> !!ir (dst := AST.cast CastKind.ZeroExt 16<rt> addr)
  | Opcode.LDUWA -> !!ir (dst := AST.cast CastKind.ZeroExt 32<rt> addr)
  | Opcode.LDXA -> !!ir (dst := addr) (* FIXME *)
  | Opcode.LDDA -> !!ir (dst := addr) (* FIXME *)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let ldstub ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := AST.cast CastKind.ZeroExt 8<rt> addr)
  !>ir insLen

let ldstuba ins insLen ctxt = (* FIXME *)
  let struct (addr, asi, dst) = transAddrFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := AST.cast CastKind.ZeroExt 8<rt> addr)
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
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := cc)
  !!ir (dst := src)
  !>ir insLen

let movr ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  match t1.E with
  | Num n ->
    match ins.Opcode with
    | Opcode.MOVRZ ->
      !!ir (t3 := AST.ite (AST.num n == AST.num0 oprSize) (t2) (dst))
    | Opcode.MOVRLEZ ->
      !!ir (t3 := AST.ite (AST.num n ?<= AST.num0 oprSize) (t2) (dst))
    | Opcode.MOVRLZ ->
      !!ir (t3 := AST.ite (AST.num n ?< AST.num0 oprSize) (t2) (dst))
    | Opcode.MOVRNZ ->
      !!ir (t3 := AST.ite (AST.num n != AST.num0 oprSize) (t2) (dst))
    | Opcode.MOVRGZ ->
      !!ir (t3 := AST.ite (AST.num n ?> AST.num0 oprSize) (t2) (dst))
    | Opcode.MOVRGEZ ->
      !!ir (t3 := AST.ite (AST.num n ?>= AST.num0 oprSize) (t2) (dst))
    | _ -> raise InvalidOpcodeException
  | _ -> raise InvalidOperandException
  !!ir (dst := t3)
  !>ir insLen

let mulscc ins insLen ctxt = (* FIXME (page.202) *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let mulx ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
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
  !<ir insLen
  match ins.Opcode with
  | Opcode.OR | Opcode.ORcc -> !!ir (dst := src .| src1)
  | Opcode.ORN | Opcode.ORNcc -> !!ir (dst := (AST.not (src .| src1)))
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let popc ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let max = numI32 (RegType.toBitWidth oprSize)
  let ir = IRBuilder (16)
  let lblLoop = ir.NewSymbol "Loop"
  let lblExit = ir.NewSymbol "Exit"
  let lblLoopCond = ir.NewSymbol "LoopCond"
  let struct (i, count) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (i := AST.num0 oprSize)
  !!ir (count := AST.num0 oprSize)
  !!ir (AST.lmark lblLoopCond)
  !!ir (AST.cjmp (AST.lt i max) (AST.name lblLoop) (AST.name lblExit))
  !!ir (AST.lmark lblLoop)
  let cond = (AST.xtlo 1<rt> (src >> i)) == AST.b1
  !!ir (count := AST.ite cond (count .+ AST.num1 oprSize) count)
  !!ir (i := i .+ AST.num1 oprSize)
  !!ir (AST.jmp (AST.name lblLoopCond))
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
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !>ir insLen

let retry ins insLen ctxt =
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (!.ctxt R.PC := !.ctxt R.TPC)
  !!ir (!.ctxt R.NPC := !.ctxt R.TNPC)
  !>ir insLen

let save ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !>ir insLen

let sdiv ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen

  !>ir insLen

let sdivcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := (!.ctxt R.Y) .+ src ?/ src1)
  !!ir (dst := t3)
  !>ir insLen

let sdivx ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 ?/ t2)
  !!ir (dst := t3)
  !>ir insLen

let sethi ins insLen ctxt = (* FIXME *)
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src)
  !>ir insLen

let sll ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src << src1)
  !>ir insLen

let smul ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src .* src1)
  !>ir insLen

let sra ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src ?>> src1)
  !>ir insLen

let srl ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src >> src1)
  !>ir insLen

let st ins insLen ctxt =
  let struct (dst, addr) = transTwooprsAddr ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.STB -> !!ir (dst := AST.cast CastKind.SignExt 8<rt> addr)
  | Opcode.STH -> !!ir (dst := AST.cast CastKind.SignExt 16<rt> addr)
  | Opcode.STW -> !!ir (dst := addr)
  (* Extended Word *)
  | Opcode.STX -> !!ir (dst := AST.cast CastKind.ZeroExt 64<rt> addr)
  | Opcode.STD -> !!ir (dst := AST.cast CastKind.ZeroExt 64<rt> addr)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let sta ins insLen ctxt =
  let struct (dst, addr, asi) = transThroprsAddr ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.STBA -> !!ir (dst := AST.cast CastKind.SignExt 8<rt> addr)
  | Opcode.STHA -> !!ir (dst := AST.cast CastKind.SignExt 16<rt> addr)
  | Opcode.STWA -> !!ir (dst := addr)
  (* Extended Word *)
  | Opcode.STXA -> !!ir (dst := AST.cast CastKind.ZeroExt 64<rt> addr)
  | Opcode.STDA -> !!ir (dst := AST.cast CastKind.ZeroExt 64<rt> addr)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let stf ins insLen ctxt =
  let struct (src, dst) = transTwoOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  match ins.Opcode with
  | Opcode.STF -> !!ir (dst := AST.cast CastKind.FloatCast 32<rt> t1)
  | Opcode.STDF -> !!ir (dst := AST.cast CastKind.FloatCast 64<rt> t1)
  | Opcode.STQF -> !!ir (dst := AST.cast CastKind.FloatCast 128<rt> t1)
  | Opcode.STFSR -> !!ir (dst := t1) (* FIXME *)
  | Opcode.STXFSR -> !!ir (dst :=  t1) (* FIXME *)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let stfa ins insLen ctxt =
  let struct (dst, addr, asi) = transThroprsAddr ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  match ins.Opcode with
  | Opcode.STFA -> !!ir (dst := AST.cast CastKind.SignExt 32<rt> addr)
  | Opcode.STDFA -> !!ir (dst := AST.cast CastKind.SignExt 64<rt> addr)
  | Opcode.STQFA -> !!ir (dst := AST.cast CastKind.SignExt 128<rt> addr)
  | _ -> raise InvalidOpcodeException
  !>ir insLen

let sub ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .- t2)
  !!ir (dst := t3)
  !>ir insLen

let subcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .- t2)
  !!ir (dst := t3)
  !>ir insLen

let subC ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .- t2 .- AST.zext 64<rt> (!.ctxt R.CCR))
  !!ir (dst := t3)
  !>ir insLen

let subCcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .- t2 .- AST.zext 64<rt> (!.ctxt R.CCR))
  !!ir (dst := t3)
  !>ir insLen

let swap ins insLen ctxt =
  let struct (addr, dst) = transAddrThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (AST.extract t1 oprSize 0 := addr)
  !!ir (AST.extract t1 oprSize 32 := AST.num0 0<rt>)
  !!ir (dst := t1)
  !>ir insLen

let swapa ins insLen ctxt =
  let struct (addr, asi, dst) = transAddrFourOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2) = tmpVars2 ir oprSize
  !<ir insLen
  !!ir (AST.extract t1 oprSize 0 := addr)
  !!ir (AST.extract t1 oprSize 32 := AST.num0 0<rt>)
  !!ir (dst := t1)
  !>ir insLen

let taddcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !>ir insLen

let taddcctv ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !>ir insLen

let tsubcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .- t2)
  !!ir (dst := t3)
  !>ir insLen

let tsubcctv ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 .+ t2)
  !!ir (dst := t3)
  !>ir insLen

let udivx ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (t1 := src)
  !!ir (t2 := src1)
  !!ir (t3 := t1 ./ t2)
  !!ir (dst := t3)
  !>ir insLen

let umul ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (dst := src .* src1)
  !>ir insLen

let umulcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  let struct (t1, t2, t3) = tmpVars3 ir oprSize
  !<ir insLen
  !!ir (dst := src .* src1)
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
  !<ir insLen
  !!ir (dst := src <+> src1)
  !>ir insLen

let xorcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := src <+> src1)
  !>ir insLen

let xnor ins insLen ctxt =
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := AST.not (src <+> src1))
  !>ir insLen

let xnorcc ins insLen ctxt = (* FIXME *)
  let struct (src, src1, dst) = transThreeOprs ins insLen ctxt
  let oprSize = 64<rt>
  let ir = IRBuilder (16)
  !<ir insLen
  !!ir (dst := AST.not (src <+> src1))
  !>ir insLen
