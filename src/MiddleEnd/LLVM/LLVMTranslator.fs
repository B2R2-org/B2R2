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
open B2R2.FrontEnd.BinInterface
open B2R2.BinIR
open B2R2.BinIR.LowUIR

let rec private translateExpr (builder: LLVMIRBuilder) tempMap expr =
  match expr.E with
  | Num bv ->
    bv.SmallValue () |> string
  | Var (_, reg, _, _) ->
    builder.EmitRegLoad reg
  | PCVar _ ->
    builder.EmitPCLoad ()
  | TempVar (_, n) ->
    (tempMap: Dictionary<_, _>)[n]
  | Load (_, typ, addr, _) ->
    let id = translateExpr builder tempMap addr
    builder.EmitMemLoad id typ
  | BinOp (op, typ, lhs, rhs, _) ->
    translateBinOp builder tempMap op typ lhs rhs
  | Extract (e, len, pos, _) ->
    let etyp = TypeCheck.typeOf e
    let e = translateExpr builder tempMap e
    builder.EmitExtract e etyp len pos
  | e -> printfn "%A" e; "%0"

and private translateBinOp builder tempMap op typ lhs rhs =
  match op with
  | BinOpType.ADD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "add" typ lhs rhs
  | BinOpType.SUB ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "sub" typ lhs rhs
  | BinOpType.MUL ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "mul" typ lhs rhs
  | BinOpType.DIV ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "udiv" typ lhs rhs
  | BinOpType.SDIV ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "sdiv" typ lhs rhs
  | BinOpType.MOD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "urem" typ lhs rhs
  | BinOpType.SMOD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "srem" typ lhs rhs
  | BinOpType.SHL ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "shl" typ lhs rhs
  | BinOpType.SHR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "lshr" typ lhs rhs
  | BinOpType.SAR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "ashr" typ lhs rhs
  | BinOpType.AND ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "and" typ lhs rhs
  | BinOpType.OR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "or" typ lhs rhs
  | BinOpType.XOR ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "xor" typ lhs rhs
  | BinOpType.FADD ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "fadd" typ lhs rhs
  | BinOpType.FSUB ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "fsub" typ lhs rhs
  | BinOpType.FMUL ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "fmul" typ lhs rhs
  | BinOpType.FDIV ->
    let lhs = translateExpr builder tempMap lhs
    let rhs = translateExpr builder tempMap rhs
    builder.EmitBinOp "fdiv" typ lhs rhs
  | _ -> Utils.futureFeature ()

let private translateStmts (builder: LLVMIRBuilder) addr (stmts: Stmt[]) =
  let mutable lastAddr = addr
  let mutable lastLen = 0UL
  let tempMap = Dictionary<int, string> ()
  let translateStmt stmt =
    match stmt.S with
    | ISMark insLen ->
      lastAddr <- lastAddr + lastLen
      lastLen <- uint64 insLen
      builder.EmitComment $"0x{lastAddr:x}"
    | IEMark _ -> ()
    | Put ({ E = Var (_, reg, _, _) }, rhs) ->
      let r = translateExpr builder tempMap rhs
      builder.EmitRegStore reg r
    | Put ({ E = TempVar (_, n) }, rhs) ->
      let r = translateExpr builder tempMap rhs
      tempMap[n] <- r
    | Store (_, addr, v) ->
      let addr = translateExpr builder tempMap addr
      let t = TypeCheck.typeOf v
      let v = translateExpr builder tempMap v
      builder.EmitMemStore addr t v
    | InterJmp (target, _) ->
      let target = translateExpr builder tempMap target
      builder.EmitPCStore target
    | s -> printfn "%A" s; Utils.futureFeature ()
  for stmt in stmts do
    translateStmt stmt
  done

/// Translate the given LowUIR stmts to a string representing LLVM IR stmts
/// (i.e., an LLVM function).
let toLLVMString (addr: Addr) (hdl: BinHandle) stmts =
  let fname = addr.ToString ("x16")
  let ctxt = LLVMIRHelper.initializeContext hdl.ISA
  let builder = LLVMIRBuilder (fname, hdl, ctxt)
  translateStmts builder addr stmts
  builder.Finalize ()

