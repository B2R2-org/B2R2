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
open B2R2.FrontEnd.BinFile
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
                              and 'GlCtx: (new: unit -> 'GlCtx)>
  public (ssaLifter: ICFGAnalysis<unit -> SSACFG> option) =

  let rec findJumpExpr stmExtractor (g: IGraph<_, _>) vFst = function
    | (v: IVertex<_>) :: vs ->
      match stmExtractor v with
      | Jmp (InterJmp jmpExpr) -> Ok jmpExpr
      | _ ->
        let vs =
          g.GetSuccs v
          |> Seq.fold (fun acc succ ->
            if succ <> vFst then succ :: acc else acc) vs
        findJumpExpr stmExtractor g vFst vs
    | [] -> Error ErrorCase.ItemNotFound

  let findIndBranchExprFromIRCFG state (g: LowUIRCFG) addr =
    (* Since there could be multiple SSA vertices, search for the right one. *)
    let v = g.FindVertexBy (fun v -> v.VData.Internals.BlockAddress = addr)
    let stmExtractor = (state: VarBasedDataFlowState<_>).GetTerminatorInSSA
    findJumpExpr stmExtractor g v [ v ]

  let findIndBranchExprFromSSACFG (ssaCFG: SSACFG) addr =
    (* Since there could be multiple SSA vertices, search for the right one. *)
    let v = ssaCFG.FindVertexBy (fun v -> v.VData.Internals.BlockAddress = addr)
    let stmExtractor (v: IVertex<SSABasicBlock>) = v.VData.Internals.LastStmt
    findJumpExpr stmExtractor ssaCFG v [ v ]

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

  let rec constantFold findConstant findDef e =
    match e with
    | Var v when v.Identifier <> 0 ->
      match findConstant v with
      | ConstantDomain.Const bv -> Num bv
      | _ ->
        match findDef v with
        | Some (Def (_, e)) -> constantFold findConstant findDef e
        | _ -> e
    | Load (m, rt, addr) ->
      Load (m, rt, constantFold findConstant findDef addr)
    | UnOp (op, rt, e) ->
      UnOp (op, rt, constantFold findConstant findDef e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = constantFold findConstant findDef e1
      let e2 = constantFold findConstant findDef e2
      BinOp (op, rt, e1, e2) |> simplify
    | RelOp (op, rt, e1, e2) ->
      let e1 = constantFold findConstant findDef e1
      let e2 = constantFold findConstant findDef e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = constantFold findConstant findDef e1
      let e2 = constantFold findConstant findDef e2
      let e3 = constantFold findConstant findDef e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) ->
      Cast (op, rt, constantFold findConstant findDef e)
    | Extract (e, rt, pos) ->
      Extract (constantFold findConstant findDef e, rt, pos)
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

  let extractBaseAddr findConstant findDef expr =
    constantFold findConstant findDef expr
    |> simplify
    |> function
      | Num b -> Ok <| BitVector.ToUInt64 b
      | _ -> Error ErrorCase.ItemNotFound

  let extractTableAddr findConstant findDef memExpr =
    memExpr
    |> extractTableExpr
    |> constantFold findConstant findDef
    |> function
      | Num t -> Ok <| BitVector.ToUInt64 t
      | _ -> Error ErrorCase.ItemNotFound

  let extractTblInfo findConstant findDef insAddr baseExpr tblExpr rt =
    let baseAddr = extractBaseAddr findConstant findDef baseExpr
    let tblAddr = extractTableAddr findConstant findDef tblExpr
    match baseAddr, tblAddr with
    | Ok baseAddr, Ok tblAddr ->
      Ok { InsAddr = insAddr
           JumpBase = baseAddr
           TableAddress = tblAddr
           EntrySize = RegType.toByteWidth rt
           NumEntries = 0 }
    | _ -> Error ErrorCase.ItemNotFound

  let detect findConstant findDef iAddr = function
    | BinOp (BinOpType.ADD, _, Num b, Load (_, t, memExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, memExpr), Num b)
    | BinOp (BinOpType.ADD, _, Num b, Cast (_, _, Load (_, t, memExpr)))
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, memExpr)), Num b) ->
      if isJmpTable t memExpr then
        extractTblInfo findConstant findDef iAddr (Num b) memExpr t
      else Error ErrorCase.ItemNotFound
    | BinOp (BinOpType.ADD, _, (Load (_, _, e1) as m1),
                               (Load (_, t, e2) as m2)) ->
      if isJmpTable t e1 then
        extractTblInfo findConstant findDef iAddr m2 e1 t
      elif isJmpTable t e2 then
        extractTblInfo findConstant findDef iAddr m1 e2 t
      else
        Error ErrorCase.ItemNotFound
    | BinOp (BinOpType.ADD, _, baseExpr, Load (_, t, tblExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, tblExpr), baseExpr) ->
      if isJmpTable t tblExpr then
        extractTblInfo findConstant findDef iAddr baseExpr tblExpr t
      else Error ErrorCase.ItemNotFound
    | Load (_, t, memExpr)
    | Cast (_, _, Load (_, t, memExpr)) ->
      if isJmpTable t memExpr then
        let zero = BitVector.Zero t
        extractTblInfo findConstant findDef iAddr (Num zero) memExpr t
      else Error ErrorCase.ItemNotFound
    | _ -> Error ErrorCase.ItemNotFound

  /// Expand the given expression by recursively substituting the subexpressions
  /// with their definitions. The recursion stops after following the next
  /// definitions.
  let rec symbExpand expandPhi findConstant findDef doNext e =
    match e with
    | Num _ -> e
    | Var ({ Kind = PCVar _ } as v) -> (* regard PC as a constant *)
      match findConstant v with
      | ConstantDomain.Const bv -> Num bv
      | _ -> e
    | Var v when v.Identifier <> 0 && doNext ->
      match findDef v with
      | Some (Def (_, e)) ->
        symbExpand expandPhi findConstant findDef false e
      | Some (Phi (_, ids)) -> expandPhi findConstant v ids e
      | _ -> e
    | Load (m, rt, addr) ->
      let e = symbExpand expandPhi findConstant findDef doNext addr
      Load (m, rt, e)
    | UnOp (op, rt, e) ->
      let e = symbExpand expandPhi findConstant findDef doNext e
      UnOp (op, rt, e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = symbExpand expandPhi findConstant findDef doNext e1
      let e2 = symbExpand expandPhi findConstant findDef doNext e2
      BinOp (op, rt, e1, e2)
    | RelOp (op, rt, e1, e2) ->
      let e1 = symbExpand expandPhi findConstant findDef doNext e1
      let e2 = symbExpand expandPhi findConstant findDef doNext e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = symbExpand expandPhi findConstant findDef doNext e1
      let e2 = symbExpand expandPhi findConstant findDef doNext e2
      let e3 = symbExpand expandPhi findConstant findDef doNext e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) ->
      let e = symbExpand expandPhi findConstant findDef doNext e
      Cast (op, rt, e)
    | Extract (e, rt, pos) ->
      let e = symbExpand expandPhi findConstant findDef doNext e
      Extract (e, rt, pos)
    | e -> e

  /// This is a practical limit for the depth of symbolic expansion.
  let [<Literal>] MaxDepth = 7

  let rec findSymbPattern expandPhi findConstant findDef insAddr depth expr =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable"
    <| $"{insAddr:x} ({depth}): {Pp.expToString expr}"
#endif
    match detect findConstant findDef insAddr expr with
    | Ok info ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable" "detected"
#endif
      Ok info
    | Error _ ->
      if depth < MaxDepth then
        let e = symbExpand expandPhi findConstant findDef true expr |> simplify
        findSymbPattern expandPhi findConstant findDef insAddr (depth + 1) e
      else Error ErrorCase.ItemNotFound

  let findConstantFromIRCFG (state: VarBasedDataFlowState<_>) v =
    state.DomainSubState.GetAbsValue (v=v)

  let findDefFromIRCFG (state: VarBasedDataFlowState<_>) v =
    state.TryGetSSADef v

  let expandPhiFromIRCFG findConstant v _ e =
    match findConstant v with
    | ConstantDomain.Const bv -> Num bv
    | _ -> e

  let analyzeSymbolicallyWithIRCFG g state insAddr bblAddr =
    match findIndBranchExprFromIRCFG state g bblAddr with
    | Ok jmpExpr ->
      let findConstant = findConstantFromIRCFG state
      let findDef = findDefFromIRCFG state
      findSymbPattern expandPhiFromIRCFG findConstant findDef insAddr 0 jmpExpr
    | Error e -> Error e

  let findConstantFromSSACFG (state: SSAVarBasedDataFlowState<_>) v =
    state.GetRegValue v

  let findDefFromSSACFG (state: SSAVarBasedDataFlowState<_>) v =
    match state.SSAEdges.Defs.TryGetValue v with
    | true, def -> Some def
    | false, _ -> None

  let varToBV findConstant var id =
    let v = { var with Identifier = id }
    match findConstant v with
    | ConstantDomain.Const bv -> Some bv
    | _ -> None

  let expandPhiFromSSACFG findConstant var ids e =
    let bvs = ids |> Array.map (fun id -> varToBV findConstant var id)
    match bvs[0] with
    | Some hd ->
      if bvs |> Array.forall (fun bv -> bv = Some hd) then Num hd
      else e
    | None -> e

  let analyzeSymbolicallyWithSSACFG ssaCFG state insAddr bblAddr =
    match findIndBranchExprFromSSACFG ssaCFG bblAddr with
    | Ok jmpExpr ->
      let findConstant = findConstantFromSSACFG state
      let findDef = findDefFromSSACFG state
      findSymbPattern expandPhiFromSSACFG findConstant findDef insAddr 0 jmpExpr
    | Error e -> Error e

  /// Jump table always belongs to either code or read-only data section.
  let checkBelongingSection ctx (addr: Addr) =
    ctx.BinHandle.File.GetSections addr
    |> Array.exists (fun sec ->
      sec.Kind = SectionKind.CodeSection ||
      sec.Kind = SectionKind.ReadOnlyDataSection)

  let checkValidity (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) result =
    match result with
    | Ok info ->
      let tblAddr = info.TableAddress
      if checkBelongingSection ctx tblAddr then Ok info
      else Error ErrorCase.InvalidMemoryRead
    | Error e -> Error e

  interface IJmpTableAnalyzable<'FnCtx, 'GlCtx> with
    member _.Identify ctx insAddr bblAddr =
      match ssaLifter with
      | Some ssaLifter ->
        let ssaCFG = ssaLifter.Unwrap { Context = ctx } ()
        let cp = SSAConstantPropagation ctx.BinHandle
        let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
        let state = dfa.InitializeState []
        let state = dfa.Compute ssaCFG state
        analyzeSymbolicallyWithSSACFG ssaCFG state insAddr bblAddr
        |> checkValidity ctx
      | None ->
        let cp = ConstantPropagation ctx.BinHandle
        let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
        let state = dfa.Compute ctx.CFG ctx.CPState
        analyzeSymbolicallyWithIRCFG ctx.CFG state insAddr bblAddr
        |> checkValidity ctx
