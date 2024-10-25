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

/// LowUIR-variable-based data flow state.
[<AllowNullLiteral>]
type VarBasedDataFlowState<'Lattice>
  public (hdl, analysis: IVarBasedDataFlowAnalysis<'Lattice>) as this =

  /// Initial stack pointer value in the stack pointer domain.
  let spInitial =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | None -> None
    | Some rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let varKind = Regular rid
      let bv = BitVector.OfUInt64 Constants.InitialStackPointer rt
      let c = StackPointerDomain.ConstSP bv
      Some (varKind, c)

  /// Mapping from a CFG vertex to its StmtInfo array.
  let stmtInfoCache = Dictionary<IVertex<LowUIRBasicBlock>, StmtInfo[]> ()

  /// Mapping from a VarPoint to its abstract value in the user's domain.
  let domainAbsValues = Dictionary<VarPoint, 'Lattice> ()

  /// Mapping from a VarPoint to its abstract value in the stack-pointer domain.
  let spAbsValues = Dictionary<VarPoint, StackPointerDomain.Lattice> ()

  let phiInfos = Dictionary<IVertex<LowUIRBasicBlock>, PhiInfo> ()

  let perVertexIncomingDefs =
    Dictionary<IVertex<LowUIRBasicBlock>, Map<VarKind, VarPoint>> ()

  let perVertexOutgoingDefs =
    Dictionary<IVertex<LowUIRBasicBlock>, Map<VarKind, VarPoint>> ()

  let defUseMap = Dictionary<VarPoint, HashSet<VarPoint>> ()

  let useDefMap = Dictionary<VarPoint, VarPoint> ()

  let stmtOfBBLs = Dictionary<ProgramPoint, StmtOfBBL> ()

  /// Set of pending vertices that need to be processed.
  let pendingVertices = HashSet<IVertex<LowUIRBasicBlock>> ()

  /// Queue of vertices that need to be removed.
  let verticesForRemoval = Queue<IVertex<LowUIRBasicBlock>> ()

  /// SSA variable identifier counter.
  let mutable ssaVarCounter = 0

  /// A mapping from a variable point to its corresponding SSA variable.
  let vpToSSAVar = Dictionary<VarPoint, SSA.Variable> ()

  /// A mapping from an SSA variable to its corresponding variable point.
  let ssaVarToVp = Dictionary<SSA.Variable, VarPoint> ()

  let domainGetAbsValue vp =
    match domainAbsValues.TryGetValue vp with
    | false, _ -> analysis.Bottom
    | true, v -> v

  let spGetAbsValue vp =
    match spAbsValues.TryGetValue vp with
    | false, _ -> StackPointerDomain.Undef
    | true, c -> c

  let spGetInitialAbsValue varKind =
    match spInitial with
    | Some (stackVar, c) when varKind = stackVar -> c
    | _ -> StackPointerDomain.Undef

  let spEvaluateVar varKind pp =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match useDefMap.TryGetValue vp with
    | false, _ -> spGetInitialAbsValue varKind
    | true, defVp -> spGetAbsValue defVp

  let rec spEvaluateExpr pp (e: Expr) =
    match e.E with
    | Num bv -> StackPointerDomain.ConstSP bv
    | Var _ | TempVar _ -> spEvaluateVar (VarKind.ofIRExpr e) pp
    | Load (_, _, addr) ->
      match spEvaluateExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset =
          BitVector.ToUInt64 bv |> VarBasedDataFlowState<_>.ToFrameOffset
        spEvaluateVar (StackLocal offset) pp
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
  let updatePPToStmts stmts v =
    Array.iter (fun (stmt, pp) -> stmtOfBBLs[pp] <- (stmt, v)) stmts

  let rec getStatements (v: IVertex<LowUIRBasicBlock>) =
    match stmtInfoCache.TryGetValue v with
    | true, stmts -> stmts
    | false, _ ->
      let pp = v.VData.Internals.PPoint
      let stmts = getStatementsAux v pp
      updatePPToStmts stmts v
      stmtInfoCache[v] <- stmts
      stmts

  and getStatementsAux (v: IVertex<LowUIRBasicBlock>) (pp: ProgramPoint) =
    if not v.VData.Internals.IsAbstract then (* regular vertex *)
      let startPos = pp.Position
      v.VData.Internals.LiftedInstructions
      |> Array.collect (fun ins ->
        ins.Stmts |> Array.mapi (fun i stmt ->
          stmt, ProgramPoint (ins.Original.Address, startPos + i)))
    else (* abstract vertex *)
      let startPos = 1 (* we reserve 0 for phi definitions. *)
      let cs = Option.get pp.CallSite
      let addr = pp.Address
      v.VData.Internals.AbstractContent.Rundown
      |> Array.mapi (fun i s -> s, ProgramPoint (cs, addr, startPos + i))

  /// Returns a fresh identifier for the given variable kind and increments the
  /// identifier.
  let getNewVarId () =
    ssaVarCounter <- ssaVarCounter + 1
    ssaVarCounter

  /// Converts a variable kind to an SSA variable kind.
  let toSSAVarKind vk =
    match vk with
    | Regular rid ->
      let rt = hdl.RegisterFactory.RegIDToRegType rid
      let rname = hdl.RegisterFactory.RegIDToString rid
      SSA.RegVar (rt, rid, rname)
    | Memory (Some _) -> SSA.MemVar
    | Memory None -> SSA.MemVar
    | StackLocal offset -> SSA.StackVar (0<rt>, offset)
    | Temporary n ->
      let rt = 0<rt>
      SSA.TempVar (rt, n)

  /// Returns an SSA variable for the given variable point.
  let getSSAVar vp =
    match vpToSSAVar.TryGetValue vp with
    | true, v -> v
    | false, _ ->
      let ssaVarId = getNewVarId ()
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
    | true, defVp -> getSSAVar defVp

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
        let offset =
          BitVector.ToUInt64 bv |> VarBasedDataFlowState<_>.ToFrameOffset
        let vk = StackLocal offset
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

  /// Translate a ordinary IR statement to an SSA statement. It returns a dummy
  /// exception statement if the given IR statement is invalid.
  let translateToSSAStmt pp stmt =
    match stmt.S with
    | Put (dst, src) ->
      let vk = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = vk }
      let v = getSSAVar vp
      let e = translateToSSAExpr pp src
      SSA.Def (v, e)
    | Store (_, addr, value) ->
      match spEvaluateExpr pp addr with
      | StackPointerDomain.ConstSP bv ->
        let offset =
          BitVector.ToUInt64 bv |> VarBasedDataFlowState<_>.ToFrameOffset
        let vk = StackLocal offset
        let vp = { ProgramPoint = pp; VarKind = vk }
        let v = getSSAVar vp
        let e = translateToSSAExpr pp value
        SSA.Def (v, e)
      | _ ->
        let prevMemVar = mkEmptySSAVar (Memory None) (* empty one *)
        let newMemVar = getSSAVar { ProgramPoint = pp; VarKind = Memory None }
        let rt = TypeCheck.typeOf value
        let e1 = translateToSSAExpr pp addr
        let e2 = translateToSSAExpr pp value
        let e = SSA.Store (prevMemVar, rt, e1, e2)
        SSA.Def (newMemVar, e)
    | Jmp (expr) ->
      let addr = 0x0UL (* use dummy address for simplicity *)
      let label = translateLabel addr expr.E
      let e = SSA.IntraJmp label
      SSA.Jmp e
    | CJmp (expr, label1, label2) ->
      let addr = 0x0UL (* use dummy address for simplicity *)
      let expr = translateToSSAExpr pp expr
      let label1 = translateLabel addr label1.E
      let label2 = translateLabel addr label2.E
      let e = SSA.IntraCJmp (expr, label1, label2)
      SSA.Jmp e
    | InterJmp (expr, _) ->
      let expr = translateToSSAExpr pp expr
      let e = SSA.InterJmp (expr)
      SSA.Jmp e
    | InterCJmp (expr1, expr2, expr3) ->
      let expr1 = translateToSSAExpr pp expr1
      let expr2 = translateToSSAExpr pp expr2
      let expr3 = translateToSSAExpr pp expr3
      let e = SSA.InterCJmp (expr1, expr2, expr3)
      SSA.Jmp e
    | _ ->
      SSA.SideEffect <| Exception "Invalid SSA stmt encountered"

  let convertDefsToIds defs =
    defs
    |> Seq.map (fun def ->
      let v = getSSAVar def
      v.Identifier)
    |> Seq.toArray

  /// Generates a phi statement for the given variable point.
  let generatePhiSSAStmt vp =
    let _, v = stmtOfBBLs[vp.ProgramPoint]
    let phiInfo = phiInfos[v]
    let varKind = vp.VarKind
    let defs = phiInfo[varKind]
    let var = getSSAVar vp
    let ids = convertDefsToIds defs.Values
    SSA.Phi (var, ids)

  let domainSubState =
    let flowQueue = UniqueQueue ()
    let defSiteQueue = UniqueQueue ()
    let executedFlows = HashSet ()
    let executedVertices = HashSet ()
    { new IVarBasedDataFlowSubState<'Lattice> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = analysis.Bottom
        member _.GetAbsValue v = domainGetAbsValue ssaVarToVp[v]
        member _.GetAbsValue vp = domainGetAbsValue vp
        member _.SetAbsValue vp absVal = domainAbsValues[vp] <- absVal
        member _.Join a b = analysis.Join a b
        member _.Subsume a b = analysis.Subsume a b
        member _.EvalExpr pp expr = analysis.EvalExpr this pp expr }

  let spSubState =
    let flowQueue = UniqueQueue ()
    let defSiteQueue = UniqueQueue ()
    let executedFlows = HashSet ()
    let executedVertices = HashSet ()
    { new IVarBasedDataFlowSubState<StackPointerDomain.Lattice> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = StackPointerDomain.Undef
        member _.GetAbsValue v = spGetAbsValue ssaVarToVp[v]
        member _.GetAbsValue vp = spGetAbsValue vp
        member _.SetAbsValue vp absVal = spAbsValues[vp] <- absVal
        member _.Join a b = StackPointerDomain.join a b
        member _.Subsume a b = StackPointerDomain.subsume a b
        member _.EvalExpr pp expr = spEvaluateExpr pp expr }

  let resetSubState (subState: IVarBasedDataFlowSubState<_>) =
    subState.FlowQueue.Clear ()
    subState.DefSiteQueue.Clear ()
    subState.ExecutedFlows.Clear ()
    subState.ExecutedVertices.Clear ()

  let reset () =
    stmtInfoCache.Clear ()
    domainAbsValues.Clear ()
    spAbsValues.Clear ()
    phiInfos.Clear ()
    perVertexIncomingDefs.Clear ()
    perVertexOutgoingDefs.Clear ()
    defUseMap.Clear ()
    useDefMap.Clear ()
    stmtOfBBLs.Clear ()
    pendingVertices.Clear ()
    vpToSSAVar.Clear ()
    ssaVarCounter <- 0
    ssaVarToVp.Clear ()
    resetSubState spSubState
    resetSubState domainSubState

  /// Mapping from a CFG vertex to its phi information.
  member __.PhiInfos with get () = phiInfos

  /// Mapping from a CFG vertex to its incoming definitions.
  member __.PerVertexIncomingDefs with get () = perVertexIncomingDefs

  /// Mapping from a CFG vertex to its outgoing definitions.
  member __.PerVertexOutgoingDefs with get () = perVertexOutgoingDefs

  /// Mapping from a variable def to its uses.
  member __.DefUseMap with get () = defUseMap

  /// Mapping from a variable use to its definition.
  member __.UseDefMap with get () = useDefMap

  /// Mapping from a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and its corresponding vertex that contains the statement.
  member __.StmtOfBBLs with get () = stmtOfBBLs

  /// Sub-state for the stack-pointer domain.
  member __.StackPointerSubState with get () = spSubState

  /// Sub-state for the user's domain.
  member __.DomainSubState with get () = domainSubState

  /// Mark the given vertex as pending, which means that the vertex needs to be
  /// processed.
  member __.MarkVertexAsPending v = pendingVertices.Add v |> ignore

  /// Mark the given vertex as removal, which means that the vertex needs to be
  /// removed.
  member __.MarkVertexAsRemoval v = verticesForRemoval.Enqueue v |> ignore

  /// Check if the given vertex is pending.
  member __.IsVertexPending v = pendingVertices.Contains v

  /// Clear the pending vertices.
  member __.ClearPendingVertices () = pendingVertices.Clear ()

  /// Enqueue the pending vertices to the given sub-state.
  member __.EnqueuePendingVertices (subState: IVarBasedDataFlowSubState<_>) =
    for v in pendingVertices do
      subState.FlowQueue.Enqueue (null, v)

  /// Dequeue the vertex for removal. When there is no vertex to remove, it
  /// returns `false`.
  member __.DequeueVertexForRemoval () = verticesForRemoval.TryDequeue ()

  /// Return the array of StmtInfos of the given vertex.
  member __.GetStmtInfos v = getStatements v

  /// Return the terminator statment of the given vertex in an SSA form.
  member __.GetTerminatorInSSA v =
    getStatements v
    |> Array.last
    |> fun (irStmt, pp) -> translateToSSAStmt pp irStmt

  /// Try to get the definition of the given SSA variable in an SSA form.
  member __.TryGetSSADef v =
    let vp = ssaVarToVp[v]
    let pp = vp.ProgramPoint
    let stmt, v = stmtOfBBLs[pp]
    let pp' = v.VData.Internals.PPoint
    let isPhi = pp = pp'
    if not isPhi then
      match translateToSSAStmt pp stmt with
      | SSA.SideEffect _ -> None
      | s -> Some s
    else generatePhiSSAStmt vp |> Some

  /// Reset this state.
  member __.Reset () = reset ()

  /// Translate the given stack pointer address to a local frame offset.
  static member inline ToFrameOffset stackAddr =
    int (stackAddr - Constants.InitialStackPointer)

  interface IDataFlowState<VarPoint, 'Lattice> with
    member __.GetAbsValue absLoc = domainGetAbsValue absLoc

/// A Low-UIR statement and its corresponding program point.
and private StmtInfo = Stmt * ProgramPoint

/// A Low-UIR statement and its corresponding vertex in the Low-UIR CFG.
and private StmtOfBBL = Stmt * IVertex<LowUIRBasicBlock>

and IVarBasedDataFlowSubState<'Lattice> =
  inherit IDataFlowState<VarPoint, 'Lattice>

  /// The edge queue for calculating the data flow.
  abstract FlowQueue:
    UniqueQueue<IVertex<LowUIRBasicBlock> * IVertex<LowUIRBasicBlock>>

  /// The definition site queue for calculating the data flow.
  abstract DefSiteQueue: UniqueQueue<ProgramPoint>

  /// Executed edges during the data flow calculation.
  abstract ExecutedFlows:
    HashSet<IVertex<LowUIRBasicBlock> * IVertex<LowUIRBasicBlock>>

  /// Executed vertices during the data flow calculation.
  abstract ExecutedVertices: HashSet<IVertex<LowUIRBasicBlock>>

  /// The bottom of the lattice.
  abstract Bottom: 'Lattice

  /// Get the abstract value of the given SSA variable.
  abstract GetAbsValue: v: SSA.Variable -> 'Lattice

  /// Get the abstract value at the given location.
  abstract SetAbsValue: vp: VarPoint -> 'Lattice -> unit

  /// Join two abstract values.
  abstract Join: 'Lattice -> 'Lattice -> 'Lattice

  /// Check if the first abstract value subsumes the second.
  abstract Subsume: 'Lattice -> 'Lattice -> bool

  /// Evaluate the given expression using the current abstract state.
  abstract EvalExpr: ProgramPoint -> Expr -> 'Lattice

/// A mapping from a variable kind of a phi variable to the program points of
/// its incoming variable.
and PhiInfo = Dictionary<VarKind, Dictionary<ProgramPoint, VarPoint>>

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
