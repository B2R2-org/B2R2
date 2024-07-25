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
type DefSites = Dictionary<VariableKind, Set<IVertex<SSABasicBlock>>>

/// Defined variables per node in a SSACFG.
type DefsPerNode = Dictionary<IVertex<SSABasicBlock>, Set<VariableKind>>

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

  let collectDefVars defs (_, stmt) =
    match stmt with
    | Def ({ Kind = k }, _) -> Set.add k defs
    | _ -> defs

  let addPhi g defsPerNode variable (phiSites, workList) (v: SSAVertex) =
    if Set.contains v phiSites then phiSites, workList
    else
      match variable with
      (* Temporary vars are only meaningful in an instruction boundary. Thus, a
         PhiSite for a TempVar should be an intra-instruction bbl, but not the
         start of an instruction. *)
      | TempVar _ when v.VData.Internals.PPoint.Position = 0 ->
        phiSites, workList
      | _ ->
        (* Insert Phi for v *)
        let preds = (g: IGraph<_, _>).GetPreds v
        v.VData.Internals.PrependPhi variable preds.Count
        let phiSites = Set.add v phiSites
        let defs = (defsPerNode: DefsPerNode)[v]
        if not <| Set.contains variable defs then phiSites, v :: workList
        else phiSites, workList

  let rec iterDefs g phiSites defsPerNode variable = function
    | [] -> phiSites
    | (v: SSAVertex) :: workList ->
      let phiSites, workList =
        v.VData.DomFrontier
        |> List.fold (addPhi g defsPerNode variable) (phiSites, workList)
      iterDefs g phiSites defsPerNode variable workList

  let findDefVars (ssaCFG: SSACFG) (defSites: DefSites) =
    let defsPerNode = DefsPerNode ()
    ssaCFG.Vertices
    |> Array.iter (fun (v: SSAVertex) ->
      let defs =
        v.VData.Internals.Statements |> Array.fold collectDefVars Set.empty
      defsPerNode[v] <- defs
      defs |> Set.iter (fun d ->
        if defSites.ContainsKey d then defSites[d] <- Set.add v defSites[d]
        else defSites[d] <- Set.singleton v))
    defsPerNode

  let placePhis g defsPerNode (defSites: DefSites) =
    for KeyValue (variable, defs) in defSites do
      Set.toList defs
      |> iterDefs g Set.empty defsPerNode variable
      |> ignore

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

  let renameStmt count stack (_, stmt) =
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

  let renamePhiAux (stack: IDStack) preds (parent: SSAVertex) (_, stmt) =
    match stmt with
    | Phi (def, nums) ->
      let idx =
        Seq.findIndex (fun (v: SSAVertex) -> v.VData = parent.VData) preds
      nums[idx] <- List.head stack[def.Kind]
    | _ -> ()

  let renamePhi (g: IGraph<_, _>) stack parent (succ: SSAVertex) =
    succ.VData.Internals.Statements
    |> Array.iter (renamePhiAux stack (g.GetPreds succ) parent)

  let popStack (stack: IDStack) (_, stmt) =
    match stmt with
    | Def (def, _)
    | Phi (def, _) -> stack[def.Kind] <- List.tail stack[def.Kind]
    | _ -> ()

  let rec rename (g: IGraph<_, _>) domTree count stack (v: SSAVertex) =
    v.VData.Internals.Statements |> Array.iter (renameStmt count stack)
    g.GetSuccs v |> Seq.iter (renamePhi g stack v)
    traverseChildren g domTree count stack (Map.find v domTree)
    v.VData.Internals.Statements |> Array.iter (popStack stack)

  and traverseChildren g domTree count stack = function
    | child :: rest ->
      rename g domTree count stack child
      traverseChildren g domTree count stack rest
    | [] -> ()

  let renameVars g (defSites: DefSites) domCtx =
    let domTree, root = Dominator.dominatorTree domCtx
    let count = VarCountMap ()
    let stack = IDStack ()
    defSites.Keys |> Seq.iter (fun variable ->
      count[variable] <- 0
      stack[variable] <- [0])
    rename g domTree count stack root |> ignore

  /// Add phis and rename all the variables in the SSACFG.
  let updatePhis ssaCFG =
    let defSites = DefSites ()
    let domCtx = computeDominatorInfo ssaCFG
    let defsPerNode = findDefVars ssaCFG defSites
    placePhis ssaCFG defsPerNode defSites
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
