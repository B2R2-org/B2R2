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

namespace B2R2.BinIR.LowUIR

open System.Collections.Generic
open B2R2
open B2R2.BinIR

/// <summary>
/// Represents statically resolvable memory access addresses and constant
/// register definitions in a sequence of LowUIR statements.
/// </summary>
type StaticValueFacts =
  { MemReadAddrs: Addr[]
    MemWriteAddrs: Addr[]
    RegConstDefs: (RegisterID * BitVector)[]
    PCDefs: Addr[] }

/// <summary>
/// Provides functions for extracting statically resolvable memory access
/// addresses and constant register definitions from LowUIR statements.
/// </summary>
[<RequireQualifiedAccess>]
module StaticValueFacts =

  /// Represents known concrete values while scanning LowUIR statements.
  type private Context =
    { PC: Addr
      Regs: Map<RegisterID, BitVector>
      Temps: Map<int, BitVector>
      Labels: Dictionary<Label, int> }

  let private emptyContext addr labels =
    { PC = addr
      Regs = Map.empty
      Temps = Map.empty
      Labels = labels }

  let private clearContext ctx =
    { ctx with
        Regs = Map.empty
        Temps = Map.empty }

  let private intersectEqual map1 map2 =
    map1
    |> Map.fold (fun acc key value ->
      match Map.tryFind key map2 with
      | Some value' when value = value' -> Map.add key value acc
      | _ -> acc) Map.empty

  let private mergeContext ctx1 ctx2 =
    { ctx1 with
        Regs = intersectEqual ctx1.Regs ctx2.Regs
        Temps = intersectEqual ctx1.Temps ctx2.Temps }

  let rec private evalExpr ctx = function
    | Num(bv, _) ->
      Some bv
    | Var(_, rid, _, _) -> Map.tryFind rid ctx.Regs
    | PCVar(rt, _, _) -> BitVector(ctx.PC, rt) |> Some
    | TempVar(_, n, _) -> Map.tryFind n ctx.Temps
    | ExprList _ -> None
    | UnOp(UnOpType.NEG, e, _) ->
      evalUnOp ctx e BitVector.Neg
    | UnOp(UnOpType.NOT, e, _) ->
      evalUnOp ctx e BitVector.Not
    | UnOp _ -> None
    | BinOp(BinOpType.ADD, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Add
    | BinOp(BinOpType.SUB, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Sub
    | BinOp(BinOpType.MUL, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Mul
    | BinOp(BinOpType.DIV, _, e1, e2, _) ->
      evalDivOp ctx e1 e2 BitVector.Div
    | BinOp(BinOpType.SDIV, _, e1, e2, _) ->
      evalDivOp ctx e1 e2 BitVector.SDiv
    | BinOp(BinOpType.MOD, _, e1, e2, _) ->
      evalDivOp ctx e1 e2 BitVector.Modulo
    | BinOp(BinOpType.SMOD, _, e1, e2, _) ->
      evalDivOp ctx e1 e2 BitVector.SModulo
    | BinOp(BinOpType.AND, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.And
    | BinOp(BinOpType.OR, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Or
    | BinOp(BinOpType.XOR, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Xor
    | BinOp(BinOpType.SHL, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Shl
    | BinOp(BinOpType.SHR, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Shr
    | BinOp(BinOpType.SAR, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Sar
    | BinOp(BinOpType.CONCAT, _, e1, e2, _) ->
      evalBinOp ctx e1 e2 BitVector.Concat
    | _ -> None

  and private evalAddr ctx expr =
    evalExpr ctx expr
    |> Option.bind (fun bv ->
      if bv.Length <= 64<rt> then Some(bv.ToUInt64())
      else None)

  and private evalUnOp ctx e fn =
    evalExpr ctx e |> Option.map fn

  and private evalBinOp ctx e1 e2 fn =
    Option.map2 (fun v1 v2 -> fn (v1, v2)) (evalExpr ctx e1) (evalExpr ctx e2)

  and private evalDivOp ctx e1 e2 fn =
    match evalExpr ctx e1, evalExpr ctx e2 with
    | Some _, Some v2 when v2.IsZero -> None
    | Some v1, Some v2 -> fn (v1, v2) |> Some
    | _ -> None

  let private updateContextAtDef ctx dst src =
    match dst, evalExpr ctx src with
    | Var(_, rid, _, _), Some value ->
      { ctx with Regs = Map.add rid value ctx.Regs }
    | Var(_, rid, _, _), None ->
      { ctx with Regs = Map.remove rid ctx.Regs }
    | TempVar(_, n, _), Some value ->
      { ctx with Temps = Map.add n value ctx.Temps }
    | TempVar(_, n, _), None ->
      { ctx with Temps = Map.remove n ctx.Temps }
    | _ -> ctx

  let rec private collectReadsFromExpr ctx reads writes = function
    | Num _ | Var _ | PCVar _ | TempVar _
    | JmpDest _ | FuncName _ | Undefined _ -> reads, writes
    | ExprList(exprs, _) ->
      List.fold (fun (reads, writes) e ->
        collectReadsFromExpr ctx reads writes e) (reads, writes) exprs
    | UnOp(_, e, _) ->
      collectReadsFromExpr ctx reads writes e
    | BinOp(_, _, e1, e2, _)
    | RelOp(_, e1, e2, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes e1
      collectReadsFromExpr ctx reads writes e2
    | Load(_, _, addrExpr, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes addrExpr
      match evalAddr ctx addrExpr with
      | Some addr -> Set.add addr reads, writes
      | None -> reads, writes
    | Ite(cond, e1, e2, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes cond
      let reads, writes = collectReadsFromExpr ctx reads writes e1
      collectReadsFromExpr ctx reads writes e2
    | Cast(_, _, e, _) ->
      collectReadsFromExpr ctx reads writes e
    | Extract(e, _, _, _) ->
      collectReadsFromExpr ctx reads writes e

  let private collectFromStmt addr ctx reads writes = function
    | ISMark(_, _) | LMark(_, _) ->
      ctx, reads, writes, Set.empty
    | IEMark(len, _) ->
      ctx, reads, writes, Set.singleton (addr + uint64 len)
    | Put(dst, src, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes src
      updateContextAtDef ctx dst src, reads, writes, Set.empty
    | Store(_, addrExpr, src, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes addrExpr
      let reads, writes = collectReadsFromExpr ctx reads writes src
      match evalAddr ctx addrExpr with
      | Some addr -> ctx, reads, Set.add addr writes, Set.empty
      | None -> ctx, reads, writes, Set.empty
    | Jmp(target, _)
    | InterJmp(target, _, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes target
      match evalAddr ctx target with
      | Some addr ->
        ctx, reads, writes, Set.singleton addr
      | None ->
        ctx, reads, writes, Set.empty
    | CJmp(cond, target1, target2, _)
    | InterCJmp(cond, target1, target2, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes cond
      let reads, writes = collectReadsFromExpr ctx reads writes target1
      let reads, writes = collectReadsFromExpr ctx reads writes target2
      match evalAddr ctx target1, evalAddr ctx target2 with
      | Some addr1, Some addr2 ->
        ctx, reads, writes, Set.ofList [ addr1; addr2 ]
      | Some addr1, None ->
        ctx, reads, writes, Set.singleton addr1
      | None, Some addr2 ->
        ctx, reads, writes, Set.singleton addr2
      | None, None ->
        ctx, reads, writes, Set.empty
    | ExternalCall(args, _) ->
      let reads, writes = collectReadsFromExpr ctx reads writes args
      clearContext ctx, reads, writes, Set.empty
    | SideEffect _ ->
      clearContext ctx, reads, writes, Set.empty

  let private buildLabelMap (stmts: Stmt[]) =
    let labelMap = Dictionary<Label, int>()
    stmts
    |> Array.iteri (fun idx -> function
      | LMark(lbl, _) -> labelMap[lbl] <- idx
      | _ -> ())
    labelMap

  let private tryFindLabel ctx lbl =
    match ctx.Labels.TryGetValue lbl with
    | true, idx -> Some idx
    | false, _ -> None

  let private tryFindTarget ctx target =
    match target with
    | JmpDest(lbl, _) -> tryFindLabel ctx lbl
    | _ -> None

  let private targetSucc ctx target =
    match tryFindTarget ctx target with
    | Some idx -> [ idx, ctx ]
    | None -> []

  let private cjmpSuccs ctx cond trueTarget falseTarget =
    match evalExpr ctx cond with
    | Some cond when cond.IsTrue ->
      targetSucc ctx trueTarget
    | Some cond when cond.IsFalse ->
      targetSucc ctx falseTarget
    | _ ->
      [ yield! targetSucc ctx trueTarget
        yield! targetSucc ctx falseTarget ]

  let private fallThroughSucc stmtsLen idx ctx =
    let next = idx + 1
    if next < stmtsLen then [ next, ctx ] else []

  let private getSuccs stmtsLen idx ctx = function
    | Jmp(target, _) ->
      targetSucc ctx target
    | CJmp(cond, trueTarget, falseTarget, _) ->
      cjmpSuccs ctx cond trueTarget falseTarget
    | InterJmp _ | InterCJmp _ ->
      []
    | _ ->
      fallThroughSucc stmtsLen idx ctx

  let private enqueue stmtsLen (visited, worklist) (idx, ctx) =
    if idx < 0 || idx >= stmtsLen then
      visited, worklist
    else
      match Map.tryFind idx visited with
      | None ->
        Map.add idx ctx visited, (idx, ctx) :: worklist
      | Some oldCtx ->
        let mergedCtx = mergeContext oldCtx ctx
        if mergedCtx = oldCtx then visited, worklist
        else Map.add idx mergedCtx visited, (idx, mergedCtx) :: worklist

  let private mergeExitDefs ctx defs =
    match defs with
    | None -> Some ctx.Regs
    | Some regs -> Some(intersectEqual regs ctx.Regs)

  let rec private traverse addr stmts visited worklist reads writes defs pcs =
    match worklist with
    | [] -> reads, writes, Option.defaultValue Map.empty defs, pcs
    | (idx, ctx) :: worklist ->
      let stmt = (stmts: Stmt[])[idx]
      let ctx, reads, writes, pcs = collectFromStmt addr ctx reads writes stmt
      let succs = getSuccs (Array.length stmts) idx ctx stmt
      let defs =
        if List.isEmpty succs then mergeExitDefs ctx defs
        else defs
      let visited, worklist =
        succs
        |> List.fold (enqueue (Array.length stmts)) (visited, worklist)
      traverse addr stmts visited worklist reads writes defs pcs

  /// Extracts statically resolvable memory read/write addresses from statements
  /// given that the initial context is known.
  let private ofStmtsWithContext ctx addr (stmts: Stmt[]) =
    let reads, writes, defs, pcs =
      match Array.length stmts with
      | 0 -> Set.empty, Set.empty, Map.empty, Set.empty
      | _ ->
        let visited = Map.empty |> Map.add 0 ctx
        let worklist = [ 0, ctx ]
        traverse addr stmts visited worklist Set.empty Set.empty None Set.empty
    { MemReadAddrs = Set.toArray reads
      MemWriteAddrs = Set.toArray writes
      RegConstDefs = Map.toArray defs
      PCDefs = Set.toArray pcs }

  /// Extracts statically resolvable memory read/write addresses and constant
  /// register definitions from statements given that the base address is known.
  /// This function assumes that the statements are from a single instruction
  /// located at the given address, so we do not follow inter-instruction
  /// branches (i.e., InterJmp and InterCJmp).
  let ofStmts (addr: Addr) (stmts: Stmt[]) =
    let labelMap = buildLabelMap stmts
    ofStmtsWithContext (emptyContext addr labelMap) addr stmts
