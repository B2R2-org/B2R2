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

namespace B2R2.MiddleEnd.SSA

open System.Collections.Generic
open B2R2
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.SSA

/// SSACFG's vertex.
type SSAVertex = IVertex<SSABasicBlock>

/// A mapping from an address to an SSACFG vertex.
type SSAVMap = Dictionary<ProgramPoint, SSAVertex>

/// This is a mapping from an edge to an abstract vertex (for external function
/// calls). We first separately create abstract vertices even if they are
/// associated with the same external function (address) in order to compute
/// dominance relationships without introducing incorrect paths or cycles. For
/// convenience, we will always consider as a key "a return edge" from an
/// abstract vertex to a fall-through vertex.
type AbstractVMap = Dictionary<ProgramPoint * ProgramPoint, SSAVertex>

/// Mapping from a variable to a set of defining SSA basic blocks.
type DefSites = Dictionary<VariableKind, HashSet<IVertex<SSABasicBlock>>>

/// Counter for each variable.
type VarCountMap = Dictionary<VariableKind, int>

/// Variable ID stack.
type IDStack = Dictionary<VariableKind, int list>

module private SSALifterFactory =
  /// Lift the given LowUIR statements to SSA statements.
  let liftStmts stmtProcessor (liftedInstrs: LiftedInstruction[]) =
    liftedInstrs
    |> Array.collect (fun liftedIns ->
      let wordSize = liftedIns.Original.WordSize |> WordSize.toRegType
      let stmts = liftedIns.Stmts
      let address = liftedIns.Original.Address
      AST.translateStmts wordSize address stmtProcessor stmts)
    |> Array.map (fun s -> ProgramPoint.GetFake (), s)

  let getVertex stmtProcessor vMap g (src: IVertex<LowUIRBasicBlock>) =
    let bbl = src.VData :> ILowUIRBasicBlock
    let ppoint = bbl.PPoint
    match (vMap: SSAVMap).TryGetValue ppoint with
    | true, v -> v, g
    | false, _ ->
      let stmts = liftStmts stmtProcessor bbl.LiftedInstructions
      let lastAddr = bbl.LastInstruction.Address
      let endPoint = lastAddr + uint64 bbl.LastInstruction.Length - 1UL
      let blk = SSABasicBlock.CreateRegular (stmts, ppoint, endPoint)
      let v, g = (g: SSACFG).AddVertex blk
      vMap.Add (ppoint, v)
      v, g

  let liftRundown stmtProcessor rundown =
    if Array.isEmpty rundown then [||]
    else
      let memVar = { Kind = MemVar; Identifier = -1 }
      [| (* safe approximation: memory is always defined. (optional?) *)
         Def (memVar, Var memVar)
         (* addr should not matter*)
         yield! AST.translateStmts 64<rt> 0UL stmtProcessor rundown |]

  let getAbsVertex stmtProcessor avMap g irBBL ftPpoint =
    let irData = (irBBL: IVertex<_>).VData :> ILowUIRBasicBlock
    let calleePpoint = irData.PPoint
    let key = calleePpoint, ftPpoint
    match (avMap: AbstractVMap).TryGetValue key with
    | true, v -> v, g
    | false, _ ->
      let absContent = irData.AbstractContent
      let rundown = absContent.Rundown |> liftRundown stmtProcessor
      let absContent = FunctionAbstraction<Stmt> (absContent.EntryPoint,
                                                  absContent.UnwindingBytes,
                                                  rundown,
                                                  absContent.IsExternal,
                                                  absContent.ReturningStatus)
      let blk = SSABasicBlock.CreateAbstract (calleePpoint, absContent)
      let v, g = (g: SSACFG).AddVertex blk
      avMap.Add (key, v)
      v, g

  let convertToSSA stmtProcessor (cfg: LowUIRCFG) ssaCFG =
    let vMap = SSAVMap ()
    let avMap = AbstractVMap ()
    let _, ssaCFG = getVertex stmtProcessor vMap ssaCFG cfg.SingleRoot
    let ssaCFG =
      ssaCFG
      |> cfg.FoldEdge (fun ssaCFG e ->
        let src, dst = e.First, e.Second
        (* If a node is abstract, then it is a call target. *)
        if dst.VData.Internals.IsAbstract then
          let last = src.VData.Internals.LastInstruction
          let fallPp = ProgramPoint (last.Address + uint64 last.Length, 0)
          let srcV, ssaCFG = getVertex stmtProcessor vMap ssaCFG src
          let dstV, ssaCFG = getAbsVertex stmtProcessor avMap ssaCFG dst fallPp
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        elif src.VData.Internals.IsAbstract then
          let dstPp = dst.VData.Internals.PPoint
          let srcV, ssaCFG = getAbsVertex stmtProcessor avMap ssaCFG src dstPp
          let dstV, ssaCFG = getVertex stmtProcessor vMap ssaCFG dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        else
          let srcV, ssaCFG = getVertex stmtProcessor vMap ssaCFG src
          let dstV, ssaCFG = getVertex stmtProcessor vMap ssaCFG dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
      )
    ssaCFG

  let computeDominatorInfo g =
    let domCtx = Dominator.initDominatorContext g
    let frontiers = Dominator.frontiers domCtx
    g.IterVertex (fun (v: SSAVertex) ->
      let dfnum = domCtx.ForwardDomInfo.DFNumMap[v.ID]
      v.VData.ImmDominator <- Dominator.idom domCtx v
      v.VData.DomFrontier <- frontiers[dfnum])
    domCtx

  let inline updateGlobalName (globals: HashSet<_>) (varKill: HashSet<_>) v =
    if varKill.Contains v then ()
    else globals.Add v |> ignore

  let rec updateGlobals (globals: HashSet<_>) (varKill: HashSet<_>) = function
    | Num _ | Undefined _ | FuncName _ | Nil -> ()
    | Var v ->
      updateGlobalName globals varKill v.Kind
    | Load (v, _, e)
    | Store (v, _, _, e) ->
      updateGlobalName globals varKill v.Kind
      updateGlobals globals varKill e
    | Cast (_, _, e)
    | UnOp (_, _, e) ->
      updateGlobals globals varKill e
    | BinOp (_, _, lhs, rhs)
    | RelOp (_, _, lhs, rhs) ->
      updateGlobals globals varKill lhs
      updateGlobals globals varKill rhs
    | Ite (cond, _, lhs, rhs) ->
      updateGlobals globals varKill cond
      updateGlobals globals varKill lhs
      updateGlobals globals varKill rhs
    | Extract (e, _, _) ->
      updateGlobals globals varKill e

  let findDefVars (ssaCFG: SSACFG) (defSites: DefSites) =
    let globals = HashSet ()
    let varKill = HashSet ()
    for v in ssaCFG.Vertices do
      varKill.Clear ()
      for _pp, stmt in v.VData.Internals.Statements do
        match stmt with
        | Def ({ Kind = k }, srcExpr) ->
          updateGlobals globals varKill srcExpr
          varKill.Add k |> ignore
          if defSites.ContainsKey k then defSites[k].Add v |> ignore
          else defSites[k] <- HashSet [v]
        | _ -> ()
    globals

  let placePhis g (defSites: DefSites) globals =
    let phiSites = HashSet ()
    for variable in globals do
      let workList =
        if defSites.ContainsKey variable then Queue defSites[variable]
        else Queue ()
      phiSites.Clear ()
      while workList.Count <> 0 do
        let node = workList.Dequeue ()
        for df in node.VData.DomFrontier do
          if phiSites.Contains df then ()
          else
            match variable with
            (* Temporary vars are only meaningful in an instruction boundary.
               Thus, a PhiSite for a TempVar should be an intra-instruction bbl,
               but not the start of an instruction. *)
            | TempVar _ when df.VData.Internals.PPoint.Position = 0 -> ()
            | _ ->
              let preds = (g: IGraph<_, _>).GetPreds df
              df.VData.Internals.PrependPhi variable preds.Length
              phiSites.Add df |> ignore
              workList.Enqueue df

  let renameVar (stack: IDStack) (v: Variable) =
    match stack.TryGetValue v.Kind with
    | false, _ -> v.Identifier <- 0
    | true, ids -> v.Identifier <- List.head ids

  let rec renameVarList stack = function
    | [] -> ()
    | v :: vs -> renameVar stack v; renameVarList stack vs

  let rec renameExpr stack = function
    | Num (_)
    | Undefined (_)
    | FuncName (_)
    | Nil -> ()
    | Var v -> renameVar stack v
    | Load (v, _, expr) ->
      renameVar stack v
      renameExpr stack expr
    | Store (mem, _, addr, expr) ->
      renameVar stack mem
      renameExpr stack addr
      renameExpr stack expr
    | UnOp (_, _, expr) ->
      renameExpr stack expr
    | BinOp (_, _, expr1, expr2) ->
      renameExpr stack expr1
      renameExpr stack expr2
    | RelOp (_, _, expr1, expr2) ->
      renameExpr stack expr1
      renameExpr stack expr2
    | Ite (expr1, _, expr2, expr3) ->
      renameExpr stack expr1
      renameExpr stack expr2
      renameExpr stack expr3
    | Cast (_, _, expr) ->
      renameExpr stack expr
    | Extract (expr, _, _) ->
      renameExpr stack expr

  let renameJmp stack = function
    | IntraJmp _ -> ()
    | IntraCJmp (expr, _, _) ->
      renameExpr stack expr
    | InterJmp (expr) ->
      renameExpr stack expr
    | InterCJmp (cond, target1, target2) ->
      renameExpr stack cond
      renameExpr stack target1
      renameExpr stack target2

  let introduceDef (count: VarCountMap) (stack: IDStack) (v: Variable) =
    count[v.Kind] <- count[v.Kind] + 1
    let i = count[v.Kind]
    stack[v.Kind] <- i :: stack[v.Kind]
    v.Identifier <- i

  let rec introduceDefList count stack = function
    | [] -> ()
    | v :: vs -> introduceDef count stack v; introduceDefList count stack vs

  let renameStmt count stack stmt =
    match stmt with
    | LMark _ -> ()
    | ExternalCall (e, inVars, outVars) ->
      renameExpr stack e
      renameVarList stack inVars
      introduceDefList count stack outVars
    | SideEffect _ -> ()
    | Jmp jmpTy -> renameJmp stack jmpTy
    | Def (def, e) ->
      renameExpr stack e
      introduceDef count stack def
    | Phi (def, _) ->
      introduceDef count stack def

  let renamePhi g (stack: IDStack) (parent: SSAVertex) (succ: SSAVertex) =
    for _, stmt in succ.VData.Internals.Statements do
      match stmt with
      | Phi (def, nums) ->
        let preds = (g: IGraph<_, _>).GetPreds succ
        let idx = preds |> Array.findIndex (fun v -> v.VData = parent.VData)
        nums[idx] <- List.head stack[def.Kind]
      | _ -> ()

  let popStack (stack: IDStack) stmt =
    match stmt with
    | Def (def, _)
    | Phi (def, _) -> stack[def.Kind] <- List.tail stack[def.Kind]
    | _ -> ()

  let rec rename (g: IGraph<_, _>) domTree count stack (v: SSAVertex) =
    for _, stmt in v.VData.Internals.Statements do renameStmt count stack stmt
    for succ in g.GetSuccs v do renamePhi g stack v succ
    traverseChildren g domTree count stack (Map.find v domTree)
    for _, stmt in v.VData.Internals.Statements do popStack stack stmt

  and traverseChildren g domTree count stack = function
    | child :: rest ->
      rename g domTree count stack child
      traverseChildren g domTree count stack rest
    | [] -> ()

  let renameVars g (defSites: DefSites) domCtx =
    let domTree, root = Dominator.dominatorTree domCtx
    let count = VarCountMap ()
    let stack = IDStack ()
    for variable in defSites.Keys do
      count[variable] <- 0
      stack[variable] <- [0]
    rename g domTree count stack root |> ignore

  /// Add phis and rename all the variables in the SSACFG.
  let updatePhis ssaCFG =
    let defSites = DefSites ()
    let domCtx = computeDominatorInfo ssaCFG
    let globals = findDefVars ssaCFG defSites
    placePhis ssaCFG defSites globals
    renameVars ssaCFG defSites domCtx

  let memStore ((pp, _) as stmtInfo) rt addr src =
    match addr with
    | StackPointerDomain.ConstSP addr ->
      let addr = BitVector.ToUInt64 addr
      let offset = int (int64 Constants.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar (rt, offset); Identifier = 0 }
      Some (pp, Def (v, src))
    | _ -> Some stmtInfo

  let loadToVar rt addr =
    match addr with
    | StackPointerDomain.ConstSP addr ->
      let addr = BitVector.ToUInt64 addr
      let offset = int (int64 Constants.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar (rt, offset); Identifier = 0 }
      Some (Var v)
    | _ -> None

  let rec replaceLoad (state: SSAVarBasedDataFlowState<_>) e =
    match e with
    | Load (_, rt, addr) ->
      let addr = state.EvalExpr addr
      loadToVar rt addr
    | Cast (ck, rt, e) ->
      replaceLoad state e
      |> Option.map (fun e -> Cast (ck, rt, e))
    | Extract (e, rt, sPos) ->
      replaceLoad state e
      |> Option.map (fun e -> Extract (e, rt, sPos))
    | _ -> None

  let stmtChooser state ((pp, stmt) as stmtInfo) =
    match stmt with
    | Phi _ -> None
    | Def ({ Kind = MemVar }, Store (_, rt, addr, src)) ->
      let addr = (state: SSAVarBasedDataFlowState<_>).EvalExpr addr
      memStore stmtInfo rt addr src
    | Def (dstVar, e) ->
      match replaceLoad state e with
      | Some e -> Some (pp, Def (dstVar, e))
      | None -> Some stmtInfo
    | _ -> Some stmtInfo

  let promote hdl ssaCFG (callback: ISSAVertexCallback) =
    let spp = SSAStackPointerPropagation hdl
    let dfa = spp :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.InitializeState []
    let state = dfa.Compute ssaCFG state
    for v in ssaCFG.Vertices do
      callback.OnVertexCreation ssaCFG state v
      v.VData.Internals.Statements
      |> Array.choose (stmtChooser state)
      |> v.VData.Internals.UpdateStatements
    updatePhis ssaCFG
    ssaCFG

  let create hdl stmtProcessor callback =
    { new ISSALiftable with
        member _.Lift cfg =
          let ssaCFG =
            match cfg.ImplementationType with
            | Imperative ->
              ImperativeDiGraph<SSABasicBlock, CFGEdgeKind> () :> IGraph<_, _>
            | Persistent ->
              PersistentDiGraph<SSABasicBlock, CFGEdgeKind> () :> IGraph<_, _>
          convertToSSA stmtProcessor cfg ssaCFG
          |> updatePhis
          ssaCFG.IterVertex (fun v -> v.VData.Internals.UpdatePPoints ())
          promote hdl ssaCFG callback }

/// The factory for SSA lifter.
type SSALifterFactory =
  /// Create an SSA lifter with a binary handle.
  static member Create (hdl) =
    SSALifterFactory.create hdl
      { new IStmtPostProcessor with member _.PostProcess stmt = stmt }
      { new ISSAVertexCallback with member _.OnVertexCreation _ _ _ = () }

  /// Create an SSA lifter with a binary handle and a statement processor.
  static member Create (hdl, stmtProcessor) =
    SSALifterFactory.create hdl stmtProcessor
      { new ISSAVertexCallback with member _.OnVertexCreation _ _ _ = () }

  /// Create an SSA lifter with a binary handle and a callback for SSA vertex
  /// creation.
  static member Create (hdl, callback) =
    SSALifterFactory.create hdl
      { new IStmtPostProcessor with member _.PostProcess stmt = stmt }
      callback

  /// Create an SSA lifter with a binary handle, a statement processor, and a
  /// callback for SSA vertex creation.
  static member Create (hdl, stmtProcessor, callback) =
    SSALifterFactory.create hdl stmtProcessor callback
