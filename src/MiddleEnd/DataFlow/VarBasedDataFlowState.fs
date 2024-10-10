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

namespace B2R2.MiddleEnd.DataFlow

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph
open B2R2.BinIR
open B2R2.BinIR.LowUIR

[<RequireQualifiedAccess>]
module DefSite =
  type DefSite =
    | Single of ProgramPoint
    | Phi of VertexID

type UniqueQueue<'T> () =
  let queue = Queue<'T> ()
  let set = HashSet<'T> ()

  member __.Enqueue (x: 'T) =
    if set.Add x |> not then ()
    else queue.Enqueue x

  member __.Dequeue () =
    let x = queue.Dequeue ()
    if set.Remove x then x
    else Utils.impossible ()

  member __.TryDequeue () =
    match queue.TryDequeue () with
    | false, _ -> None
    | true, x ->
      if set.Remove x then Some x
      else Utils.impossible ()

  member __.Count = queue.Count

  member __.Clear () = queue.Clear ()

  member __.IsEmpty with get () = Seq.isEmpty queue

type SparseState<'Lattice> = {
  FlowQueue: UniqueQueue<VertexID * VertexID>
  ExecutedFlows: HashSet<VertexID * VertexID>
  ExecutedVertices: HashSet<VertexID>
  DefSiteQueue: UniqueQueue<DefSite.DefSite>
  Bottom: 'Lattice
  GetAbsValue: VarPoint -> 'Lattice
  SetAbsValue: VarPoint -> 'Lattice -> unit
  Join: 'Lattice -> 'Lattice -> 'Lattice
  Subsume: 'Lattice -> 'Lattice -> bool
}

type PhiInfo = Dictionary<VarKind, Set<DefSite.DefSite>>

[<AllowNullLiteral>]
type VarBasedDataFlowState<'Lattice>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice>) =

  let statementMemo = Dictionary<VertexID, (ProgramPoint * Stmt) array> ()

  let absValues = Dictionary<VarPoint, 'Lattice> ()

  let stackPointers = Dictionary<VarPoint, StackPointerDomain.Lattice> ()

  let initialStackPointers = Dictionary<VarKind, StackPointerDomain.Lattice> ()

  let innerDefs = Dictionary<VertexID, Map<VarKind, DefSite.DefSite>> ()

  let incomingDefs = Dictionary<VertexID, Map<VarKind, DefSite.DefSite>> ()

  let outgoingDefs = Dictionary<VertexID, Map<VarKind, DefSite.DefSite>> ()

  let defUseMap = Dictionary<DefSite.DefSite, Set<DefSite.DefSite>> ()

  let useDefMap = Dictionary<VarPoint, DefSite.DefSite> ()

  let phiInfos = Dictionary<VertexID, PhiInfo> ()

  let ppToStmt = Dictionary<ProgramPoint, VertexID * Stmt> ()

  let vidToPp = Dictionary<VertexID, ProgramPoint> ()

  let pendingVertices = HashSet<VertexID> ()

  let getStackPointer vp =
    match stackPointers.TryGetValue vp with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let setStackPointer vp c = stackPointers[vp] <- c

  let stackPointerSparseState =
    { FlowQueue = UniqueQueue ()
      DefSiteQueue = UniqueQueue ()
      ExecutedFlows = HashSet ()
      ExecutedVertices = HashSet ()
      Bottom = StackPointerDomain.Undef
      GetAbsValue = getStackPointer
      SetAbsValue = setStackPointer
      Join = StackPointerDomain.join
      Subsume = StackPointerDomain.subsume }

  let getAbsValue vp =
    match absValues.TryGetValue vp with
    | false, _ -> analysis.Bottom
    | true, v -> v

  let setAbsValue vp absVal = absValues[vp] <- absVal

  let domainSparseState =
    { FlowQueue = UniqueQueue ()
      DefSiteQueue = UniqueQueue ()
      ExecutedFlows = HashSet ()
      ExecutedVertices = HashSet ()
      Bottom = analysis.Bottom
      GetAbsValue = getAbsValue
      SetAbsValue = setAbsValue
      Join = analysis.Join
      Subsume = analysis.Subsume }

  let getInitialStackPointer varKind =
    match initialStackPointers.TryGetValue varKind with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let initializeStackPointers () =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> ()
    | Some rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64 Constants.InitialStackPointer rt
      let c = StackPointerDomain.ConstSP bv
      initialStackPointers[varKind] <- c

  let evaluateStackPointer varKind pp =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match (useDefMap: Dictionary<_, _>).TryGetValue vp with
    | false, _ -> getInitialStackPointer varKind
    | true, defSite ->
      match defSite with
      | DefSite.Single pp ->
        getStackPointer <| { ProgramPoint = pp; VarKind = varKind }
      | DefSite.Phi vid ->
        match vidToPp.TryGetValue vid with
        | false, _ -> StackPointerDomain.Undef
        | true, pp ->
          let phiPp = pp.WithPosition -1
          let phiVp = { ProgramPoint = phiPp; VarKind = varKind }
          getStackPointer phiVp

  let rec evaluateExprToStackPointer pp (e: Expr) =
    match e.E with
    | Num bv -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> evaluateStackPointer (VarKind.ofIRExpr e) pp
    | Load (_, _, addr) ->
      match evaluateExprToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        evaluateStackPointer (Memory (Some addr)) pp
      | c -> c
    | BinOp (binOpType, _, e1, e2) ->
      let v1 = evaluateExprToStackPointer pp e1
      let v2 = evaluateExprToStackPointer pp e2
      match binOpType with
      | BinOpType.ADD -> StackPointerDomain.add v1 v2
      | BinOpType.SUB -> StackPointerDomain.sub v1 v2
      | BinOpType.AND -> StackPointerDomain.``and`` v1 v2
      | _ -> StackPointerDomain.NotConstSP
    | _ -> StackPointerDomain.NotConstSP

  let getStatements g (v: IVertex<LowUIRBasicBlock>) =
    let maybeStmts =
      match statementMemo.TryGetValue v.ID with
      | false, _ -> None
      | true, stmts -> Some stmts
    match maybeStmts with
    | None ->
      let stmts =
        if v.VData.Internals.IsAbstract then
          let callerV = (g: IGraph<_, _>).GetPreds v |> Seq.exactlyOne
          let callSite = callerV.VData.Internals.LastInstruction.Address
          let callee = v.VData.Internals.AbstractContent.EntryPoint
          let stmts = v.VData.Internals.AbstractContent.Rundown
          Array.mapi (fun i stmt ->
            let pp = ProgramPoint (callSite, callee, i)
            if ppToStmt.ContainsKey pp then ppToStmt[pp] <- (v.ID, stmt)
            else ppToStmt.Add (pp, (v.ID, stmt))
            pp, stmt) stmts
        else
          v.VData.Internals.LiftedInstructions
          |> Array.collect (fun x ->
            x.Stmts |> Array.mapi (fun i stmt ->
              let pp = ProgramPoint (x.Original.Address, i)
              if ppToStmt.ContainsKey pp then ppToStmt[pp] <- (v.ID, stmt)
              else ppToStmt.Add (pp, (v.ID, stmt))
              pp, stmt))
      statementMemo[v.ID] <- stmts
      stmts
    | Some stmts -> stmts

  let vpToSSAVar = Dictionary<VarPoint, SSA.Variable> ()

  let vkToFreshId = Dictionary<VarKind, int> ()

  let ssaVarToVp = Dictionary<SSA.Variable, VarPoint> ()

  let getNewVarId vk =
    match vkToFreshId.TryGetValue vk with
    | true, id ->
      vkToFreshId[vk] <- id + 1
      id
    | false, _ ->
      let id = 1
      vkToFreshId[vk] <- id + 1
      id

  let toSSAVarKind vk =
    match vk with
    | Regular rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let rname = hdl.RegisterFactory.RegIDToString rid
      SSA.RegVar (rt, rid, rname)
    | Memory (Some cellAddr) ->
      let rt = 0<rt>
      let offset = cellAddr - Constants.InitialStackPointer |> int
      SSA.StackVar (rt, offset)
    | Memory None -> SSA.MemVar
    | Temporary n ->
      let rt = 0<rt>
      SSA.TempVar (rt, n)
    | _ -> Utils.impossible ()

  let getSSAVar vp =
    match vpToSSAVar.TryGetValue vp with
    | true, v -> v
    | false, _ ->
      let ssaVarId = getNewVarId vp.VarKind
      let ssaVarKind = toSSAVarKind vp.VarKind
      let ssaVar = { SSA.Kind = ssaVarKind; SSA.Identifier = ssaVarId }
      vpToSSAVar[vp] <- ssaVar
      ssaVarToVp[ssaVar] <- vp
      ssaVar

  let getSSAVarFromDefSite defSite varKind =
    match defSite with
    | DefSite.Single pp ->
      getSSAVar { ProgramPoint = pp; VarKind = varKind }
    | DefSite.Phi vid ->
      let pp = vidToPp[vid].WithPosition -1
      getSSAVar { ProgramPoint = pp; VarKind = varKind }

  let mkEmptySSAVar vk = { SSA.Kind = toSSAVarKind vk; SSA.Identifier = 0 }

  let getSSAVarFromUse pp vk =
    let vp = { ProgramPoint = pp; VarKind = vk }
    match useDefMap.TryGetValue vp with
    | false, _ -> mkEmptySSAVar vp.VarKind (* coming from its caller context *)
    | true, defSite -> getSSAVarFromDefSite defSite vk

  let rec translateToSSAExpr (pp: ProgramPoint) e =
    match e.E with
    | Num bv -> SSA.Num bv
    | PCVar (rt, _) ->
      assert (Option.isNone pp.CallSite)
      SSA.Num <| BitVector.OfUInt64 pp.Address rt
    | Var _ | TempVar _ ->
      let vk = VarKind.ofIRExpr e
      let ssaVar = getSSAVarFromUse pp vk
      SSA.Var ssaVar
    | Load (_, rt, addr) ->
      match evaluateExprToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        let vk = Memory (Some addr)
        let ssaVar = getSSAVarFromUse pp vk
        SSA.Var ssaVar
      | _ ->
        let emptyMemVar = mkEmptySSAVar (Memory None)
        let e = translateToSSAExpr pp addr
        SSA.Load (emptyMemVar, rt, e)
    | BinOp (binOpType, rt, e1, e2) ->
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      SSA.BinOp (binOpType, rt, e1, e2)
    | RelOp (relOpType, e1, e2) ->
      let rt = TypeCheck.typeOf e1
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      SSA.RelOp (relOpType, rt, e1, e2)
    | Extract (e, rt, startPos) ->
      let e = translateToSSAExpr pp e
      SSA.Extract (e, rt, startPos)
    | UnOp (unOpType, e) ->
      let rt = TypeCheck.typeOf e
      let e = translateToSSAExpr pp e
      SSA.UnOp (unOpType, rt, e)
    | Cast (castKind, rt, e) ->
      let e = translateToSSAExpr pp e
      SSA.Cast (castKind, rt, e)
    | FuncName s -> SSA.FuncName s
    | Nil -> SSA.Nil
    | Undefined (rt, s) -> SSA.Undefined (rt, s)
    | Ite (e1, e2, e3) ->
      let rt = TypeCheck.typeOf e2
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      let e3 = translateToSSAExpr pp e3
      SSA.Ite (e1, rt, e2, e3)
    | _ -> Utils.impossible ()

  let translateLabel addr = function
    | Name symb -> addr, symb
    | Undefined (_, s) -> addr, (s, -1)
    | _ -> raise InvalidExprException

  let isPhiPp (pp: ProgramPoint) = pp.Position = -1

  let tryTranslateNonPhiToSSAStmt pp stmt =
    match stmt.S with
    | Put (dst, src) ->
      let vk = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = vk }
      let v = getSSAVar vp
      let e = translateToSSAExpr pp src
      SSA.Def (v, e)
      |> Some
    | Store (_, addr, value) ->
      match evaluateExprToStackPointer pp addr with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        let vk = Memory (Some addr)
        let vp = { ProgramPoint = pp; VarKind = vk }
        let v = getSSAVar vp
        let e = translateToSSAExpr pp value
        SSA.Def (v, e)
        |> Some
      | _ ->
        let prevMemVar = mkEmptySSAVar (Memory None) (* empty one *)
        let newMemVar = getSSAVar { ProgramPoint = pp; VarKind = Memory None }
        let rt = TypeCheck.typeOf value
        let e1 = translateToSSAExpr pp addr
        let e2 = translateToSSAExpr pp value
        let e = SSA.Store (prevMemVar, rt, e1, e2)
        SSA.Def (newMemVar, e)
        |> Some
    | Jmp (expr) ->
      let addr = 0x0UL
      let label = translateLabel addr expr.E
      let e = SSA.IntraJmp label
      SSA.Jmp e
      |> Some
    | CJmp (expr, label1, label2) ->
      let addr = 0x0UL
      let expr = translateToSSAExpr pp expr
      let label1 = translateLabel addr label1.E
      let label2 = translateLabel addr label2.E
      let e = SSA.IntraCJmp (expr, label1, label2)
      SSA.Jmp e
      |> Some
    | InterJmp (expr, _) ->
      let expr = translateToSSAExpr pp expr
      let e = SSA.InterJmp (expr)
      SSA.Jmp e
      |> Some
    | InterCJmp (expr1, expr2, expr3) ->
      let expr1 = translateToSSAExpr pp expr1
      let expr2 = translateToSSAExpr pp expr2
      let expr3 = translateToSSAExpr pp expr3
      let e = SSA.InterCJmp (expr1, expr2, expr3)
      SSA.Jmp e
      |> Some
    | _ -> None

  let convertDefSitesToIds defSites varKind =
    defSites
    |> Seq.map (fun defSite ->
      getSSAVarFromDefSite defSite varKind |> fun v -> v.Identifier)
    |> Seq.toArray

  let insertPhis phiInfo pp acc =
    phiInfo |> Seq.fold (fun acc (KeyValue (vk, defSites)) ->
      let var = getSSAVar { ProgramPoint = pp; VarKind = vk }
      let ids = convertDefSitesToIds defSites vk
      SSA.Phi (var, ids) :: acc) acc

  let translateToSSA g (v: IVertex<LowUIRBasicBlock>) =
    let ssaStmts =
      if not <| phiInfos.ContainsKey v.ID then []
      else insertPhis phiInfos[v.ID] vidToPp[v.ID] []
    getStatements g v
    |> Array.fold (fun ssaStmts (pp, irStmt) ->
      match tryTranslateNonPhiToSSAStmt pp irStmt with
      | None -> ssaStmts
      | Some ssaStmt -> ssaStmt :: ssaStmts) ssaStmts
    |> List.rev
    |> Array.ofList

  let tryTranslatePhiToSSAStmt vp =
    let pp = vp.ProgramPoint.WithPosition 0
    let vid, _ = ppToStmt[pp]
    let phiInfo = phiInfos[vid]
    let varKind = vp.VarKind
    let defSites = phiInfo[varKind]
    let var = getSSAVar vp
    let ids = convertDefSitesToIds defSites varKind
    SSA.Phi (var, ids)
    |> Some

  let tryTranslateToSSAStmt vp =
    if not <| isPhiPp vp.ProgramPoint then (* non-phi *)
      let pp = vp.ProgramPoint
      let stmt = snd ppToStmt[pp]
      tryTranslateNonPhiToSSAStmt pp stmt
    else (* phi *)
      tryTranslatePhiToSSAStmt vp

  let mutable times = (0L, 0L, 0L, 0L)

  do initializeStackPointers ()

  member __.GetStackPointer vp = getStackPointer vp

  member __.SetStackPointer vp c = setStackPointer vp c

  member __.EvaluateExprToStackPointer pp e = evaluateExprToStackPointer pp e

  member __.GetAbsValue vp = getAbsValue vp

  member __.SetAbsValue vp absVal = setAbsValue vp absVal

  member __.GetStatements g v = getStatements g v

  member __.TranslateToSSA g v = translateToSSA g v

  member __.TryTranslateToSSAStmt vp = tryTranslateToSSAStmt vp

  member __.PendingVertices with get () = pendingVertices

  member __.StackPointerSparseState with get () = stackPointerSparseState

  member __.DomainSparseState with get () = domainSparseState

  member __.IncomingDefs with get () = incomingDefs

  member __.InnerDefs with get () = innerDefs

  member __.OutgoingDefs with get () = outgoingDefs

  member __.DefUseMap with get () = defUseMap

  member __.UseDefMap with get () = useDefMap

  member __.VidToPp with get () = vidToPp

  member __.SSAVarToVp with get () = ssaVarToVp

  member __.VpToSSAVar with get () = vpToSSAVar

  member __.PhiInfos with get () = phiInfos

  member __.PpToStmt with get () = ppToStmt

  member __.Times with get () = times and set (v) = times <- v

  member __.Reset () =
    absValues.Clear ()
    stackPointers.Clear ()
    innerDefs.Clear ()
    vidToPp.Clear ()
    vpToSSAVar.Clear ()
    vkToFreshId.Clear ()
    ssaVarToVp.Clear ()
    incomingDefs.Clear ()
    outgoingDefs.Clear ()
    defUseMap.Clear ()
    useDefMap.Clear ()
    phiInfos.Clear ()
    ppToStmt.Clear ()
    pendingVertices.Clear ()
    statementMemo.Clear ()
    stackPointerSparseState.FlowQueue.Clear ()
    stackPointerSparseState.ExecutedFlows.Clear ()
    stackPointerSparseState.ExecutedVertices.Clear ()
    stackPointerSparseState.DefSiteQueue.Clear ()
    domainSparseState.FlowQueue.Clear ()
    domainSparseState.ExecutedFlows.Clear ()
    domainSparseState.ExecutedVertices.Clear ()
    domainSparseState.DefSiteQueue.Clear ()

  interface IDataFlowState<VarPoint, 'Lattice> with
    member __.GetAbsValue absLoc = getAbsValue absLoc

/// The core interface for IR-based data flow analysis.
and IVarBasedDataFlowAnalysis<'Lattice> =
  /// A callback for initializing the state.
  abstract OnInitialize:
       VarBasedDataFlowState<'Lattice>
    -> VarBasedDataFlowState<'Lattice>

  /// Initial abstract value representing the bottom of the lattice. Our
  /// analysis starts with this value until it reaches a fixed point.
  abstract Bottom: 'Lattice

  /// Join operator.
  abstract Join: 'Lattice -> 'Lattice -> 'Lattice

  /// Subsume operator, which checks if the first lattice subsumes the second.
  /// This is to know if the analysis should stop or not.
  abstract Subsume: 'Lattice -> 'Lattice -> bool

  /// Evaluate the given expression based on the current abstract state.
  abstract EvalExpr:
       VarBasedDataFlowState<'Lattice>
    -> ProgramPoint
    -> Expr
    -> 'Lattice
