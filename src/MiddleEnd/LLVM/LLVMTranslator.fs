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

module B2R2.MiddleEnd.LLVM.LLVMTranslator

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR

let rec private translateExpr (builder: LLVMIRBuilder) tempMap expr =
  match expr with
  | Num(bv, _) ->
    builder.Number(bv.SmallValue(), bv.Length)
  | Var(_, reg, _, _) ->
    builder.EmitRegLoad reg
  | PCVar _ ->
    builder.EmitPCLoad()
  | TempVar(_, n, _) ->
    (tempMap: Dictionary<_, _>)[n]
  | Load(_, typ, addr, _) ->
    let id = translateExpr builder tempMap addr
    builder.EmitMemLoad(id, typ)
  | UnOp(op, exp, _) ->
    translateUnOp builder tempMap op exp
  | BinOp(op, typ, lhs, rhs, _) ->
    translateBinOp builder tempMap op typ lhs rhs
  | RelOp(op, lhs, rhs, _) ->
    let etyp = Expr.TypeOf lhs
    translateRelOp builder tempMap op etyp lhs rhs
  | Cast(kind, rt, e, _) ->
    let etyp = Expr.TypeOf e
    translateCast builder tempMap e kind etyp rt
  | Extract(e, len, pos, _) ->
    let etyp = Expr.TypeOf e
    let e = translateExpr builder tempMap e
    builder.EmitExtract(e, etyp, len, pos)
  | e -> printfn "%A" e; Terminator.futureFeature ()

and private translateUnOp builder tempMap op exp =
  match op with
  | UnOpType.NOT ->
    let etyp = Expr.TypeOf exp
    let exp = translateExpr builder tempMap exp
    builder.EmitUnOp("not", exp, etyp)
  | _ -> Terminator.futureFeature ()

and private translateBinOp builder tempMap op typ lhs rhs =
  match op with
  | BinOpType.ADD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("add", typ, lhs, rhs)
  | BinOpType.SUB ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("sub", typ, lhs, rhs)
  | BinOpType.MUL ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("mul", typ, lhs, rhs)
  | BinOpType.DIV ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("udiv", typ, lhs, rhs)
  | BinOpType.SDIV ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("sdiv", typ, lhs, rhs)
  | BinOpType.MOD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("urem", typ, lhs, rhs)
  | BinOpType.SMOD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("srem", typ, lhs, rhs)
  | BinOpType.SHL ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("shl", typ, lhs, rhs)
  | BinOpType.SHR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("lshr", typ, lhs, rhs)
  | BinOpType.SAR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("ashr", typ, lhs, rhs)
  | BinOpType.AND ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("and", typ, lhs, rhs)
  | BinOpType.OR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("or", typ, lhs, rhs)
  | BinOpType.XOR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("xor", typ, lhs, rhs)
  | BinOpType.FADD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("fadd", typ, lhs, rhs)
  | BinOpType.FSUB ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("fsub", typ, lhs, rhs)
  | BinOpType.FMUL ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("fmul", typ, lhs, rhs)
  | BinOpType.FDIV ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp("fdiv", typ, lhs, rhs)
  | _ -> Terminator.futureFeature ()

and private translateRelOp builder tempMap op typ lhs rhs =
  match op with
  | RelOpType.EQ ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("eq", typ, lhs, rhs)
  | RelOpType.NEQ ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("ne", typ, lhs, rhs)
  | RelOpType.GT ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("ugt", typ, lhs, rhs)
  | RelOpType.GE ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("uge", typ, lhs, rhs)
  | RelOpType.LT ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("ult", typ, lhs, rhs)
  | RelOpType.LE ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("ule", typ, lhs, rhs)
  | RelOpType.SGT ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("sgt", typ, lhs, rhs)
  | RelOpType.SGE ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("uge", typ, lhs, rhs)
  | RelOpType.SLT ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("slt", typ, lhs, rhs)
  | RelOpType.SLE ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitRelOp("sle", typ, lhs, rhs)
  | _ -> Terminator.futureFeature ()

and private translateCast builder tempMap e kind etyp rt =
  match kind with
  | CastKind.SignExt ->
    let e = translateExpr builder tempMap e
    builder.EmitCast(e, "sext", etyp, rt)
  | CastKind.ZeroExt ->
    let e = translateExpr builder tempMap e
    builder.EmitCast(e, "zext", etyp, rt)
  | _ -> Terminator.futureFeature ()

let private translateStmts (builder: LLVMIRBuilder) addr succs (stmts: Stmt[]) =
  let mutable lastAddr = addr
  let mutable lastLen = 0UL
  let tempMap = Dictionary<int, LLVMExpr>()
  let translateStmt stmt =
    match stmt with
    | ISMark(insLen, _) ->
      lastAddr <- lastAddr + lastLen
      lastLen <- uint64 insLen
      builder.EmitComment $"0x{lastAddr:x}"
    | IEMark _ -> ()
    | Put(_, Undefined _, _) -> ()
    | Put(Var(_, reg, _, _), rhs, _) ->
      let r = translateExpr builder tempMap rhs
      builder.EmitRegStore(reg, r)
    | Put(TempVar(_, n, _), rhs, _) ->
      let r = translateExpr builder tempMap rhs
      tempMap[n] <- r
    | Store(_, addr, v, _) ->
      let addr = translateExpr builder tempMap addr
      let t = Expr.TypeOf v
      let v = translateExpr builder tempMap v
      builder.EmitMemStore(addr, t, v)
    | InterJmp(target, _, _) ->
      let target = translateExpr builder tempMap target
      builder.EmitInterJmp(target, succs)
    | InterCJmp(c, t, f, _) ->
      let typ = Expr.TypeOf t
      let c = translateExpr builder tempMap c
      let t = translateExpr builder tempMap t
      let f = translateExpr builder tempMap f
      builder.EmitInterCJmp(typ, c, t, f, succs)
    | s -> printfn "%A" s; Terminator.futureFeature ()
  if builder.Address = addr then () else builder.EmitLabel addr
  for stmt in stmts do
    translateStmt stmt
  done

let createBuilder (hdl: BinHandle) (addr: Addr) =
  let fname = addr.ToString("x16")
  let ctxt = LLVMIRHelper.initializeContext hdl.File.ISA
  LLVMIRBuilder(fname, addr, hdl, ctxt)

let translate builder addr succs stmts =
  translateStmts builder addr succs stmts
