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

[<AllowNullLiteral>]
type VarBasedDataFlowState<'Lattice>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice>) =

  /// A memoization that maps a vertex ID to its list of statements.
  let perVertexStmtInfos = Dictionary<VertexID, StmtInfo array> ()

  /// A mapping from a variable point to its domain abstract value.
  let domainAbsValues = Dictionary<VarPoint, 'Lattice> ()

  /// A mapping from a variable point to its stack pointer abstract value.
  let spAbsValues = Dictionary<VarPoint, StackPointerDomain.Lattice> ()

  /// A mapping from a variable kind to its initial stack pointer abstract
  /// value.
  let spInitialAbsValues = Dictionary<VarKind, StackPointerDomain.Lattice> ()

  /// A mapping from a vertex ID to its incoming definitions.
  let perVertexIncomingDefs =
    Dictionary<VertexID, Map<VarKind, ProgramPoint>> ()

  /// A mapping from a vertex ID to its inner definitions.
  let perVertexInnerDefs = Dictionary<VertexID, Map<VarKind, ProgramPoint>> ()

  /// A mapping from a vertex ID to its outgoing definitions.
  let perVertexOutgoingDefs =
    Dictionary<VertexID, Map<VarKind, ProgramPoint>> ()

  /// A mapping from a program point of a definition to its use sites.
  let defUseMap = Dictionary<ProgramPoint, Set<ProgramPoint>> ()

  /// A mapping from a variable point of a use to its definition site.
  let useDefMap = Dictionary<VarPoint, ProgramPoint> ()

  /// A mapping from a vertex ID to its phi information.
  let phiInfos = Dictionary<VertexID, PhiInfo> ()

  /// A mapping from a program point to its corresponding statements and the
  /// vertex id that contains the statements.
  let ppToStmt = Dictionary<ProgramPoint, VertexID * Stmt> ()

  /// A mapping from a vertex ID to the program point that corresponds to the
  /// vertex.
  let vidToPp = Dictionary<VertexID, ProgramPoint> ()

  /// A set of pending vertices that need to be processed.
  let pendingVertices = HashSet<VertexID> ()

  //
  // For sparse analysis of domain lattice.
  //
  let domainFlowQueue = UniqueQueue ()
  let domainDefSiteQueue = UniqueQueue ()
  let domainExecutedFlows = HashSet ()
  let domainExecutedVertices = HashSet ()

  //
  // For sparse analysis of stack pointer lattice.
  //
  let spFlowQueue = UniqueQueue ()
  let spDefSiteQueue = UniqueQueue ()
  let spExecutedFlows = HashSet ()
  let spExecutedVertices = HashSet ()

  let spGetAbsValue vp =
    match spAbsValues.TryGetValue vp with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let spSetAbsValue vp c = spAbsValues[vp] <- c

  let domainGetAbsValue vp =
    match domainAbsValues.TryGetValue vp with
    | false, _ -> analysis.Bottom
    | true, v -> v

  let domainSetAbsValue vp absVal = domainAbsValues[vp] <- absVal

  let domainSubState =
    { new IDataFlowSubState<'Lattice> with
        member __.FlowQueue = domainFlowQueue
        member __.DefSiteQueue = domainDefSiteQueue
        member __.ExecutedFlows = domainExecutedFlows
        member __.ExecutedVertices = domainExecutedVertices
        member __.Bottom = analysis.Bottom
        member __.GetAbsValue vp = domainGetAbsValue vp
        member __.SetAbsValue vp absVal = domainSetAbsValue vp absVal
        member __.Join a b = analysis.Join a b
        member __.Subsume a b = analysis.Subsume a b }

  let spSubState =
    { new IDataFlowSubState<StackPointerDomain.Lattice> with
        member __.FlowQueue = spFlowQueue
        member __.DefSiteQueue = spDefSiteQueue
        member __.ExecutedFlows = spExecutedFlows
        member __.ExecutedVertices = spExecutedVertices
        member __.Bottom = StackPointerDomain.Undef
        member __.GetAbsValue vp = spGetAbsValue vp
        member __.SetAbsValue vp absVal = spSetAbsValue vp absVal
        member __.Join a b = StackPointerDomain.join a b
        member __.Subsume a b = StackPointerDomain.subsume a b }

  let spGetInitialAbsValue varKind =
    match spInitialAbsValues.TryGetValue varKind with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let spSetInitialAbsValues () =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> ()
    | Some rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64 Constants.InitialStackPointer rt
      let c = StackPointerDomain.ConstSP bv
      spInitialAbsValues[varKind] <- c

  let spEvaluateVar varKind pp =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match (useDefMap: Dictionary<_, _>).TryGetValue vp with
    | false, _ -> spGetInitialAbsValue varKind
    | true, defPp -> spGetAbsValue { ProgramPoint = defPp; VarKind = varKind }

  let rec spEvaluateExpr pp (e: Expr) =
    match e.E with
    | Num bv -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> spEvaluateVar (VarKind.ofIRExpr e) pp
    | Load (_, _, addr) ->
      match spEvaluateExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let addr = BitVector.ToUInt64 bv
        spEvaluateVar (Memory (Some addr)) pp
      | c -> c
    | BinOp (binOpType, _, e1, e2) ->
      let v1 = spEvaluateExpr pp e1
      let v2 = spEvaluateExpr pp e2
      match binOpType with
      | BinOpType.ADD -> StackPointerDomain.add v1 v2
      | BinOpType.SUB -> StackPointerDomain.sub v1 v2
      | BinOpType.AND -> StackPointerDomain.``and`` v1 v2
      | _ -> StackPointerDomain.NotConstSP
    | _ -> StackPointerDomain.NotConstSP

  /// Updates the mapping from a program point to its corresponding statements.
  let updatePPToStmts stmts vid =
    Array.iter (fun (pp, stmt) -> ppToStmt[pp] <- (vid, stmt)) stmts

  /// Returns the statements of a vertex.
  let rec getStatements (v: IVertex<LowUIRBasicBlock>) =
    let vid = v.ID
    match perVertexStmtInfos.TryGetValue vid with
    | true, stmts -> stmts
    | false, _ ->
      let pp = vidToPp[vid]
      let stmts = getStatementsAux v pp |> Seq.toArray
      updatePPToStmts stmts vid
      perVertexStmtInfos[vid] <- stmts
      stmts

  and getStatementsAux v (pp: ProgramPoint) =
    let isAbstract = (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract
    if not isAbstract then (* regular vertex *)
      let startPos = pp.Position
      v.VData.Internals.LiftedInstructions
      |> Seq.collect (fun x ->
        x.Stmts |> Seq.mapi (fun i stmt ->
          ProgramPoint (x.Original.Address, startPos + i), stmt))
    else (* abstract vertex *)
      let startPos = 1 (* we reserve 0 for phi definitions. *)
      let cs = Option.get pp.CallSite
      let addr = pp.Address
      v.VData.Internals.AbstractContent.Rundown
      |> Seq.mapi (fun i s -> ProgramPoint (cs, addr, startPos + i), s)

  //
  // NOTE: Below are the logics for translating the IR to SSA form!
  // The logics below can be separated into a different module since
  // the data-flow analysis itself does not need to know about the SSA form.
  //

  /// A mapping from a variable kind to its fresh identifier.
  let vkToFreshId = Dictionary<VarKind, int> ()

  /// A mapping from a variable point to its corresponding SSA variable.
  let vpToSSAVar = Dictionary<VarPoint, SSA.Variable> ()

  /// A mapping from an SSA variable to its corresponding variable point.
  let ssaVarToVp = Dictionary<SSA.Variable, VarPoint> ()

  /// Returns a fresh identifier for the given variable kind and increments the
  /// identifier.
  let getNewVarId vk =
    match vkToFreshId.TryGetValue vk with
    | true, id ->
      vkToFreshId[vk] <- id + 1
      id
    | false, _ ->
      let id = 1
      vkToFreshId[vk] <- id + 1
      id

  /// Converts a variable kind to an SSA variable kind.
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

  /// Returns an SSA variable for the given variable point.
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

  /// Returns an empty SSA variable for the given variable kind.
  let mkEmptySSAVar vk = { SSA.Kind = toSSAVarKind vk; SSA.Identifier = 0 }

  /// Returns an SSA variable for the given use.
  let getSSAVarFromUse pp vk =
    let vp = { ProgramPoint = pp; VarKind = vk }
    match useDefMap.TryGetValue vp with
    | false, _ -> mkEmptySSAVar vp.VarKind (* coming from its caller context *)
    | true, defPp -> getSSAVar { ProgramPoint = defPp; VarKind = vp.VarKind }

  /// Translates an IR expression to its SSA expression.
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
      match spEvaluateExpr pp addr with
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

  let convertDefSitesToIds defSites varKind =
    defSites
    |> Seq.map (fun defSite ->
      { ProgramPoint = defSite; VarKind = varKind }
      |> getSSAVar
      |> fun v -> v.Identifier)
    |> Seq.toArray

  /// Try to translate a non-phi (ordinary) IR statement to an SSA statement.
  /// It fails if the statement is not interesting to be translated to SSA.
  let tryTranslateToSSAStmt pp stmt =
    match stmt.S with
    | Put (dst, src) ->
      let vk = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = vk }
      let v = getSSAVar vp
      let e = translateToSSAExpr pp src
      SSA.Def (v, e)
      |> Some
    | Store (_, addr, value) ->
      match spEvaluateExpr pp addr with
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

  /// Generates a phi statement for the given variable point.
  let generatePhiSSAStmt vp =
    let vid, _ = ppToStmt[vp.ProgramPoint]
    let phiInfo = phiInfos[vid]
    let varKind = vp.VarKind
    let defSites = phiInfo[varKind]
    let var = getSSAVar vp
    let ids = convertDefSitesToIds defSites varKind
    SSA.Phi (var, ids)

  /// Inserts phi definitions to the given list.
  let insertPhis phiInfo (pp: ProgramPoint) acc =
    phiInfo |> Seq.fold (fun acc (KeyValue (vk, defSites)) ->
      let var = getSSAVar { ProgramPoint = pp; VarKind = vk }
      let ids = convertDefSitesToIds defSites vk
      SSA.Phi (var, ids) :: acc) acc

  /// Translates a vertex to SSA form.
  let getSSAStmts (v: IVertex<LowUIRBasicBlock>) =
    let header = (* here comes phi definitions. *)
      if not <| phiInfos.ContainsKey v.ID then []
      else insertPhis phiInfos[v.ID] vidToPp[v.ID] []
    getStatements v
    |> Seq.choose (fun (pp, irStmt) -> tryTranslateToSSAStmt pp irStmt)
    |> Seq.append header
    |> Seq.toArray

  /// Tries to translate a variable point to an SSA statement including phi
  /// statements.
  let tryGetSSAStmt vp =
    let pp = vp.ProgramPoint
    let vid, stmt = ppToStmt[pp]
    let pp' = vidToPp[vid]
    let isPhi = pp = pp'
    if not isPhi then tryTranslateToSSAStmt pp stmt
    else generatePhiSSAStmt vp |> Some

  let resetSubState (subState: IDataFlowSubState<_>) =
    subState.FlowQueue.Clear ()
    subState.DefSiteQueue.Clear ()
    subState.ExecutedFlows.Clear ()
    subState.ExecutedVertices.Clear ()

  /// Reset this state.
  let reset () =
    domainAbsValues.Clear ()
    spAbsValues.Clear ()
    perVertexStmtInfos.Clear ()
    vidToPp.Clear ()
    ppToStmt.Clear ()
    perVertexIncomingDefs.Clear ()
    perVertexInnerDefs.Clear ()
    perVertexOutgoingDefs.Clear ()
    defUseMap.Clear ()
    useDefMap.Clear ()
    phiInfos.Clear ()
    pendingVertices.Clear ()
    ssaVarToVp.Clear ()
    vpToSSAVar.Clear ()
    vkToFreshId.Clear ()
    resetSubState spSubState
    resetSubState domainSubState

  do spSetInitialAbsValues ()

  member __.EvaluateToStackPointer pp e = spEvaluateExpr pp e

  member __.GetStackPointerValue vp = spGetAbsValue vp

  member __.SetStackPointerValue vp c = spSetAbsValue vp c

  member __.GetDomainValue vp = domainGetAbsValue vp

  member __.SetDomainValue vp absVal = domainSetAbsValue vp absVal

  member __.GetStmtInfos v = getStatements v

  member __.GetSSAStmts v = getSSAStmts v

  member __.TryGetSSAStmt vp = tryGetSSAStmt vp

  member __.PendingVertices with get () = pendingVertices

  member __.StackPointerSubState with get () = spSubState

  member __.DomainSubState with get () = domainSubState

  member __.PerVertexIncomingDefs with get () = perVertexIncomingDefs

  member __.PerVertexInnerDefs with get () = perVertexInnerDefs

  member __.PerVertexOutgoingDefs with get () = perVertexOutgoingDefs

  member __.DefUseMap with get () = defUseMap

  member __.UseDefMap with get () = useDefMap

  member __.VidToPp with get () = vidToPp

  member __.SSAVarToVp with get () = ssaVarToVp

  member __.VpToSSAVar with get () = vpToSSAVar

  member __.PhiInfos with get () = phiInfos

  member __.PpToStmt with get () = ppToStmt

  member __.BinHandle with get () = hdl

  member __.Reset () = reset ()

  interface IDataFlowState<VarPoint, 'Lattice> with
    member __.GetAbsValue absLoc = domainGetAbsValue absLoc

and StmtInfo = ProgramPoint * Stmt

and IDataFlowSubState<'Lattice> =
  inherit IDataFlowState<VarPoint, 'Lattice>

  /// The edge queue for calculating the data flow.
  abstract FlowQueue: UniqueQueue<VertexID * VertexID>

  /// The definition site queue for calculating the data flow.
  abstract DefSiteQueue: UniqueQueue<ProgramPoint>

  /// Executed edges during the data flow calculation.
  abstract ExecutedFlows: HashSet<VertexID * VertexID>

  /// Executed vertices during the data flow calculation.
  abstract ExecutedVertices: HashSet<VertexID>

  /// The bottom of the lattice.
  abstract Bottom: 'Lattice

  /// Get the abstract value at the given location.
  abstract SetAbsValue: VarPoint -> 'Lattice -> unit

  /// Join two abstract values.
  abstract Join: 'Lattice -> 'Lattice -> 'Lattice

  /// Check if the first abstract value subsumes the second.
  abstract Subsume: 'Lattice -> 'Lattice -> bool

/// A mapping from a variable kind of a phi variable to the program points of
/// its incoming variable.
and PhiInfo = Dictionary<VarKind, Set<ProgramPoint>>

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
