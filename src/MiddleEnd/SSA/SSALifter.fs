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

/// The main lifter for SSA.
type SSALifter<'E when 'E: equality>
  public (postProcessor: IStmtPostProcessor,
          promoter: IPromotable<'E>) =
  /// Lift the given LowUIR statements to SSA statements.
  let liftStmts (liftedInstrs: LiftedInstruction[]) =
    liftedInstrs
    |> Array.collect (fun liftedIns ->
      let wordSize = liftedIns.Original.WordSize |> WordSize.toRegType
      let stmts = liftedIns.Stmts
      let address = liftedIns.Original.Address
      AST.translateStmts wordSize address postProcessor stmts)
    |> Array.map (fun s -> ProgramPoint.GetFake (), s)

  let getVertex vMap g (src: IVertex<_>) =
    let bbl: IRBasicBlock = src.VData
    let ppoint = bbl.PPoint
    match (vMap: SSAVMap).TryGetValue ppoint with
    | true, v -> v, g
    | false, _ ->
      let stmts = liftStmts bbl.LiftedInstructions
      let lastAddr = bbl.LastInstruction.Address
      let endPoint = lastAddr + uint64 bbl.LastInstruction.Length - 1UL
      let blk = SSABasicBlock.CreateRegular (stmts, ppoint, endPoint)
      let v, g = (g: SSACFG<_>).AddVertex blk
      vMap.Add (ppoint, v)
      v, g

  let getAbsVertex avMap g src ftPpoint =
    let srcBbl = (src: IVertex<IRBasicBlock>).VData
    let calleePpoint = srcBbl.PPoint
    let key = calleePpoint, ftPpoint
    match (avMap: AbstractVMap).TryGetValue key with
    | true, v -> v, g
    | false, _ ->
      let absContent = srcBbl.AbstractContent
      let blk = SSABasicBlock.CreateAbstract (calleePpoint, absContent)
      let v, g = (g: SSACFG<_>).AddVertex blk
      avMap.Add (key, v)
      v, g

  let convertToSSA irCFG vMap avMap ssaCFG root =
    let root, ssaCFG = getVertex vMap ssaCFG root
    let ssaCFG =
      ssaCFG
      |> (irCFG: IRCFG<_, _>).FoldEdge (fun ssaCFG e ->
        let src, dst = e.First, e.Second
        (* If a node is abstract, then it is a call target. *)
        if dst.VData.IsAbstract then
          let last = src.VData.LastInstruction
          let fallPp = ProgramPoint (last.Address + uint64 last.Length, 0)
          let srcV, ssaCFG = getVertex vMap ssaCFG src
          let dstV, ssaCFG = getAbsVertex avMap ssaCFG dst fallPp
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        elif src.VData.IsAbstract then
          let dstPp = dst.VData.PPoint
          let srcV, ssaCFG = getAbsVertex avMap ssaCFG src dstPp
          let dstV, ssaCFG = getVertex vMap ssaCFG dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        else
          let srcV, ssaCFG = getVertex vMap ssaCFG src
          let dstV, ssaCFG = getVertex vMap ssaCFG dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
      )
    ssaCFG, root

  let computeDominatorInfo g root =
    let domCtxt = Dominator.initDominatorContext g root
    let frontiers = Dominator.frontiers domCtxt
    g.IterVertex (fun (v: SSAVertex) ->
      let dfnum = domCtxt.ForwardDomInfo.DFNumMap[v.ID]
      v.VData.ImmDominator <- Dominator.idom domCtxt v
      v.VData.DomFrontier <- frontiers[dfnum])
    domCtxt

  let collectDefVars defs (_, stmt) =
    match stmt with
    | Def ({ Kind = k }, _) -> Set.add k defs
    | _ -> defs

  let findPhiSites g defsPerNode variable (phiSites, workList) v =
    if Set.contains v phiSites then phiSites, workList
    else
      match variable with
      (* Temporary vars are only meaningful in an instruction boundary. Thus, a
         PhiSite for a TempVar should be an intra-instruction bbl, but not the
         start of an instruction. *)
      | TempVar _ when (v: SSAVertex).VData.PPoint.Position = 0 ->
        phiSites, workList
      | _ ->
        (* Insert Phi for v *)
        let preds = (g: IGraph<_, _>).GetPreds v
        v.VData.PrependPhi variable preds.Count
        let phiSites = Set.add v phiSites
        let defs = (defsPerNode: DefsPerNode)[v]
        if not <| Set.contains variable defs then phiSites, v :: workList
        else phiSites, workList

  let rec iterDefs g phiSites defsPerNode variable = function
    | [] -> phiSites
    | (v: SSAVertex) :: workList ->
      let phiSites, workList =
        v.VData.DomFrontier
        |> List.fold (findPhiSites g defsPerNode variable) (phiSites, workList)
      iterDefs g phiSites defsPerNode variable workList

  let placePhis g vertices (defSites: DefSites) domCtxt =
    let defsPerNode = DefsPerNode ()
    vertices
    |> Seq.iter (fun (v: SSAVertex) ->
      let defs = v.VData.LiftedSSAStmts |> Array.fold collectDefVars Set.empty
      defsPerNode[v] <- defs
      defs |> Set.iter (fun d ->
        if defSites.ContainsKey d then defSites[d] <- Set.add v defSites[d]
        else defSites[d] <- Set.singleton v))
    for KeyValue (variable, defs) in defSites do
      Set.toList defs
      |> iterDefs g Set.empty defsPerNode variable
      |> ignore
    domCtxt

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
    | ReturnVal (_, _, e) -> renameExpr stack e
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
    succ.VData.LiftedSSAStmts
    |> Array.iter (renamePhiAux stack (g.GetPreds succ) parent)

  let popStack (stack: IDStack) (_, stmt) =
    match stmt with
    | Def (def, _)
    | Phi (def, _) -> stack[def.Kind] <- List.tail stack[def.Kind]
    | _ -> ()

  let rec rename (g: IGraph<_, _>) domTree count stack (v: SSAVertex) =
    v.VData.LiftedSSAStmts |> Array.iter (renameStmt count stack)
    g.GetSuccs v |> Seq.iter (renamePhi g stack v)
    traverseChildren g domTree count stack (Map.find v domTree)
    v.VData.LiftedSSAStmts |> Array.iter (popStack stack)

  and traverseChildren g domTree count stack = function
    | child :: rest ->
      rename g domTree count stack child
      traverseChildren g domTree count stack rest
    | [] -> ()

  let renameVars g (defSites: DefSites) domCtxt =
    let domTree, root = Dominator.dominatorTree domCtxt
    let count = VarCountMap ()
    let stack = IDStack ()
    defSites.Keys |> Seq.iter (fun variable ->
      count[variable] <- 0
      stack[variable] <- [0])
    rename g domTree count stack root |> ignore

  /// Add phis and rename all the variables in the SSACFG.
  let installPhis vertices ssaCFG root =
    let defSites = DefSites ()
    computeDominatorInfo ssaCFG root
    |> placePhis ssaCFG vertices defSites
    |> renameVars ssaCFG defSites

  new () =
    SSALifter<'E> (
      { new IStmtPostProcessor with member _.PostProcess stmt = stmt },
      { new IPromotable<'E> with member _.Promote (g, root) = g, root })

  /// Lift an IRCFG into an SSACFG.
  member _.Lift (g: IRCFG<_, 'E>) (root: IVertex<#IRBasicBlock>) =
    let ssaCFG =
      match g.ImplementationType with
      | Imperative ->
        ImperativeDiGraph<SSABasicBlock, 'E> () :> IGraph<_, _>
      | Persistent ->
        PersistentDiGraph<SSABasicBlock, 'E> () :> IGraph<_, _>
    let vMap = SSAVMap ()
    let avMap = AbstractVMap ()
    let ssaCFG, root = convertToSSA g vMap avMap ssaCFG root
    let vertices = Seq.append vMap.Values avMap.Values
    ssaCFG.FindVertexBy (fun v ->
      v.VData.PPoint = root.VData.PPoint && not <| v.VData.IsAbstract)
    |> installPhis vertices ssaCFG
    ssaCFG.IterVertex (fun v -> v.VData.UpdatePPoints ())
    promoter.Promote (ssaCFG, root)

/// SSACFG's vertex.
and SSAVertex = IVertex<SSABasicBlock>

/// A mapping from an address to an SSACFG vertex.
and SSAVMap =
  Dictionary<ProgramPoint, SSAVertex>

/// This is a mapping from an edge to an abstract vertex (for external function
/// calls). We first separately create abstract vertices even if they are
/// associated with the same external function (address) in order to compute
/// dominance relationships without introducing incorrect paths or cycles. For
/// convenience, we will always consider as a key "a return edge" from an
/// abstract vertex to a fall-through vertex.
and AbstractVMap =
  Dictionary<ProgramPoint * ProgramPoint, SSAVertex>

/// Mapping from a variable to a set of defining SSA basic blocks.
and DefSites =
  Dictionary<VariableKind, Set<IVertex<SSABasicBlock>>>

/// Defined variables per node in a SSACFG.
and DefsPerNode =
  Dictionary<IVertex<SSABasicBlock>, Set<VariableKind>>

/// Counter for each variable.
and VarCountMap = Dictionary<VariableKind, int>

/// Variable ID stack.
and IDStack = Dictionary<VariableKind, int list>
