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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.SSA

type private L = ConstantDomain.Lattice

/// Base class for analyzing jump tables.
type JmpTableAnalysis<'FnCtx,
                      'GlCtx when 'FnCtx :> IResettable
                              and 'FnCtx: (new: unit -> 'FnCtx)
                              and 'GlCtx: (new: unit -> 'GlCtx)> () =
  let rec findJumpExpr state g vFst = function
    | (v: IVertex<LowUIRBasicBlock>) :: vs ->
      let ssaStmts = (state: VarBasedDataFlowState<_>).TranslateToSSA g v
      match Array.last ssaStmts with
      | Jmp (InterJmp jmpExpr) -> Ok jmpExpr
      | _ ->
        let vs =
          g.GetSuccs v
          |> Seq.fold (fun acc succ ->
            if succ <> vFst then succ :: acc else acc) vs
        findJumpExpr state g vFst vs
    | [] -> Error ErrorCase.ItemNotFound

  let findIndBranchExpr state (g: LowUIRCFG) addr =
    let v = g.FindVertexBy (fun v -> v.VData.Internals.BlockAddress = addr)
    (* Since there could be multiple SSA vertices, search for the right one. *)
    findJumpExpr state g v [ v ]

  let rec simplify = function
    | Load (v, rt, e) -> Load (v, rt, simplify e)
    | Store (v, rt, e1, e2) -> Store (v, rt, simplify e1, simplify e2)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, Num v1, e), Num v2)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, e, Num v1), Num v2)
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, e, Num v2))
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, Num v2, e)) ->
      BinOp (BinOpType.ADD, rt, e, Num (BitVector.Add (v1, v2)))
    | BinOp (BinOpType.ADD, _, Num v1, Num v2) -> Num (BitVector.Add (v1, v2))
    | BinOp (BinOpType.SUB, _, Num v1, Num v2) -> Num (BitVector.Sub (v1, v2))
    | BinOp (BinOpType.MUL, _, Num v1, Num v2) -> Num (BitVector.Mul (v1, v2))
    | BinOp (BinOpType.DIV, _, Num v1, Num v2) -> Num (BitVector.Div (v1, v2))
    | BinOp (BinOpType.AND, _, Num v1, Num v2) -> Num (BitVector.BAnd (v1, v2))
    | BinOp (BinOpType.OR, _, Num v1, Num v2) -> Num (BitVector.BOr (v1, v2))
    | BinOp (BinOpType.SHR, _, Num v1, Num v2) -> Num (BitVector.Shr (v1, v2))
    | BinOp (BinOpType.SHL, _, Num v1, Num v2) -> Num (BitVector.Shl (v1, v2))
    | BinOp (op, rt, e1, e2) -> BinOp (op, rt, simplify e1, simplify e2)
    | UnOp (op, rt, e) -> UnOp (op, rt, simplify e)
    | RelOp (op, rt, e1, e2) -> RelOp (op, rt, simplify e1, simplify e2)
    | Ite (c, rt, e1, e2) -> Ite (simplify c, rt, simplify e1, simplify e2)
    | Cast (k, rt, e) -> Cast (k, rt, simplify e)
    | Extract (Cast (CastKind.ZeroExt, _, e), rt, 0) when AST.typeOf e = rt -> e
    | Extract (Cast (CastKind.SignExt, _, e), rt, 0) when AST.typeOf e = rt -> e
    | Extract (e, rt, pos) -> Extract (simplify e, rt, pos)
    | expr -> expr

  let rec foldWithConstant (state: VarBasedDataFlowState<_>) e =
    match e with
    | Var v when v.Identifier <> 0 ->
      let vp = state.SSAVarToVp[v]
      match state.GetAbsValue vp with
      | ConstantDomain.Const bv -> Num bv
      | _ ->
        let isPhiVar =
          match vp.IRProgramPoint with
          | IRPPReg pp -> pp.Position = -1
          | IRPPAbs (_, _, -1) -> true
          | _ -> false
        if isPhiVar then e
        else
          let pp = vp.IRProgramPoint
          let _, stmt = state.PpToStmt[pp]
          let ssaStmt = state.TryTranslateStmtToSSA pp stmt |> Option.get
          match ssaStmt with
          | Def (_, e) -> foldWithConstant state e
          | _ -> Utils.impossible ()
    | Load (m, rt, addr) -> Load (m, rt, foldWithConstant state addr)
    | UnOp (op, rt, e) -> UnOp (op, rt, foldWithConstant state e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = foldWithConstant state e1
      let e2 = foldWithConstant state e2
      BinOp (op, rt, e1, e2) |> simplify
    | RelOp (op, rt, e1, e2) ->
      let e1 = foldWithConstant state e1
      let e2 = foldWithConstant state e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = foldWithConstant state e1
      let e2 = foldWithConstant state e2
      let e3 = foldWithConstant state e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) -> Cast (op, rt, foldWithConstant state e)
    | Extract (e, rt, pos) -> Extract (foldWithConstant state e, rt, pos)
    | e -> e

  let rec isJmpTable t = function
    | BinOp (BinOpType.MUL, _, _, Num n)
    | BinOp (BinOpType.MUL, _, Num n, _) ->
      (RegType.toByteWidth t = BitVector.ToInt32 n)
    | BinOp (BinOpType.SHL, _, _, Num n) ->
      (RegType.toByteWidth t = (1 <<< BitVector.ToInt32 n))
    | BinOp (BinOpType.ADD, _, e1, e2) ->
      isJmpTable t e1 || isJmpTable t e2
    | _ -> false

  let rec extractTableExpr = function
    | BinOp (BinOpType.ADD, _, BinOp (BinOpType.MUL, _, _, Num _), e)
    | BinOp (BinOpType.ADD, _, BinOp (BinOpType.MUL, _, Num _, _), e)
    | BinOp (BinOpType.ADD, _, BinOp (BinOpType.SHL, _, _, Num _), e)
    | BinOp (BinOpType.ADD, _, e, BinOp (BinOpType.MUL, _, _, Num _))
    | BinOp (BinOpType.ADD, _, e, BinOp (BinOpType.MUL, _, Num _, _))
    | BinOp (BinOpType.ADD, _, e, BinOp (BinOpType.SHL, _, _, Num _)) -> e
    | BinOp (op, rt, e1, e2) ->
      BinOp (op, rt, extractTableExpr e1, extractTableExpr e2)
    | e -> e

  let extractBaseAddr state expr =
    foldWithConstant state expr
    |> simplify
    |> function
      | Num b -> Ok <| BitVector.ToUInt64 b
      | _ -> Error ErrorCase.ItemNotFound

  let extractTableAddr state memExpr =
    memExpr
    |> extractTableExpr
    |> foldWithConstant state
    |> function
      | Num t -> Ok <| BitVector.ToUInt64 t
      | _ -> Error ErrorCase.ItemNotFound

  let extractTblInfo state insAddr baseExpr tblExpr rt =
    let baseAddr = extractBaseAddr state baseExpr
    let tblAddr = extractTableAddr state tblExpr
    match baseAddr, tblAddr with
    | Ok baseAddr, Ok tblAddr ->
      Ok { InsAddr = insAddr
           JumpBase = baseAddr
           TableAddress = tblAddr
           EntrySize = RegType.toByteWidth rt
           NumEntries = 0 }
    | _ -> Error ErrorCase.ItemNotFound

  let detect state iAddr = function
    | BinOp (BinOpType.ADD, _, Num b, Load (_, t, memExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, memExpr), Num b)
    | BinOp (BinOpType.ADD, _, Num b, Cast (_, _, Load (_, t, memExpr)))
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, memExpr)), Num b) ->
      if isJmpTable t memExpr then
        extractTblInfo state iAddr (Num b) memExpr t
      else Error ErrorCase.ItemNotFound
    | BinOp (BinOpType.ADD, _, (Load (_, _, e1) as m1),
                               (Load (_, t, e2) as m2)) ->
      if isJmpTable t e1 then extractTblInfo state iAddr m2 e1 t
      elif isJmpTable t e2 then extractTblInfo state iAddr m1 e2 t
      else Error ErrorCase.ItemNotFound
    | BinOp (BinOpType.ADD, _, baseExpr, Load (_, t, tblExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, tblExpr), baseExpr) ->
      if isJmpTable t tblExpr then
        extractTblInfo state iAddr baseExpr tblExpr t
      else Error ErrorCase.ItemNotFound
    | Load (_, t, memExpr)
    | Cast (_, _, Load (_, t, memExpr)) ->
      if isJmpTable t memExpr then
        let zero = BitVector.Zero t
        extractTblInfo state iAddr (Num zero) memExpr t
      else Error ErrorCase.ItemNotFound
    | _ -> Error ErrorCase.ItemNotFound

  let setPpZeroPosition = function
    | IRPPReg pp -> IRPPReg <| ProgramPoint (pp.Address, 0)
    | IRPPAbs (cs, fn, _) -> IRPPAbs (cs, fn, 0)

  let expandPhi state vp e =
    match (state: VarBasedDataFlowState<_>).GetAbsValue vp with
    | ConstantDomain.Const bv -> Num bv
    | _ -> e

  /// Expand the given expression by recursively substituting the subexpressions
  /// with their definitions. The recursion stops after folloing the next
  /// definitions.
  let rec symbolicExpand (state: VarBasedDataFlowState<_>) doNext e =
    match e with
    | Num _ -> e
    | Var v when v.Identifier <> 0 && doNext ->
      let vp = state.SSAVarToVp[v]
      let isPhiVar =
        match vp.IRProgramPoint with
        | IRPPReg pp -> pp.Position = -1
        | IRPPAbs (_, _, -1) -> true
        | _ -> false
      if not isPhiVar then
         let pp = vp.IRProgramPoint
         let stmt = state.PpToStmt[pp] |> snd
         let ssaStmt = state.TryTranslateStmtToSSA pp stmt |> Option.get
         match ssaStmt with
         | Def (_, e) -> symbolicExpand state false e
         | _ -> Utils.impossible ()
       else expandPhi state vp e
    | Load (m, rt, addr) ->
      let e = symbolicExpand state doNext addr
      Load (m, rt, e)
    | UnOp (op, rt, e) ->
      let e = symbolicExpand state doNext e
      UnOp (op, rt, e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = symbolicExpand state doNext e1
      let e2 = symbolicExpand state doNext e2
      BinOp (op, rt, e1, e2)
    | RelOp (op, rt, e1, e2) ->
      let e1 = symbolicExpand state doNext e1
      let e2 = symbolicExpand state doNext e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = symbolicExpand state doNext e1
      let e2 = symbolicExpand state doNext e2
      let e3 = symbolicExpand state doNext e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) ->
      let e = symbolicExpand state doNext e
      Cast (op, rt, e)
    | Extract (e, rt, pos) ->
      let e = symbolicExpand state doNext e
      Extract (e, rt, pos)
    | e -> e

  /// This is a practical limit for the depth of symbolic expansion.
  let [<Literal>] MaxDepth = 7

  let rec findSymbolicPattern g state insAddr depth expr =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable"
    <| $"{insAddr:x} ({depth}): {Pp.expToString expr}"
#endif
    match detect state insAddr expr with
    | Ok info ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable" "detected"
#endif
      Ok info
    | Error _ ->
      if depth < MaxDepth then
        let expr = symbolicExpand state true expr |> simplify
        findSymbolicPattern g state insAddr (depth + 1) expr
      else Error ErrorCase.ItemNotFound

  let analyzeSymbolically g state insAddr bblAddr =
    match findIndBranchExpr state g bblAddr with
    | Ok jmpExpr -> findSymbolicPattern g state insAddr 0 jmpExpr
    | Error e -> Error e

  let checkValidity (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) result =
    match result with
    | Ok info ->
      if ctx.BinHandle.File.IsValidAddr info.TableAddress then Ok info
      else Error ErrorCase.InvalidMemoryRead
    | Error e -> Error e

  interface IJmpTableAnalyzable<'FnCtx, 'GlCtx> with
    member _.Identify ctx insAddr bblAddr =
      let cp = ConstantPropagation ctx.BinHandle
      let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
      let state = Option.get ctx.CPState
      let state = dfa.Compute ctx.CFG state
      let g = ctx.CFG
      analyzeSymbolically g state insAddr bblAddr
      |> checkValidity ctx
