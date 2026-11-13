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

/// Implements sparse data-flow analysis over the LowUIR representation.
module B2R2.MiddleEnd.DataFlow.LowUIRSparseDataFlow

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.ABI
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.BinGraph

/// Represents a state used in LowUIR-based sparse dataflow analysis.
type State<'Lattice when 'Lattice: equality>
  public(hdl: BinHandle,
         lattice: ILattice<'Lattice>,
         scheme: IScheme<'Lattice>,
         ?initialValueProvider) =

  /// Holds the initial stack pointer value in the address domain.
  let spInitial = LowUIRAddress.initialValue hdl

  let initialValueProvider =
    defaultArg initialValueProvider (RegisterInitialValueProvider.create hdl)

  /// Caches the statements of every CFG vertex, along with their program
  /// points.
  let stmtCache = LowUIRStmtCache()

  /// Maps a VarPoint to its abstract value in the user's domain.
  let domainAbsValues = Dictionary<VarPoint, 'Lattice>()

  /// Maps a VarPoint to its abstract value in the address domain.
  let spAbsValues = Dictionary<VarPoint, AddressDomain.Lattice>()

  let phiInfos = Dictionary<IVertex<LowUIRBasicBlock>, PhiInfo>()

  let perVertexIncomingDefs =
    Dictionary<IVertex<LowUIRBasicBlock>, Map<VarKind, VarPoint>>()

  let perVertexOutgoingDefs =
    Dictionary<IVertex<LowUIRBasicBlock>, Map<VarKind, VarPoint>>()

  let defUseMap = Dictionary<VarPoint, HashSet<VarPoint>>()

  let useDefMap = Dictionary<VarPoint, VarPoint>()

  /// Caches the variable kinds each vertex reads, so that phi placement does
  /// not re-walk a vertex's statements on every call.
  let usedVarKindsMemo =
    Dictionary<IVertex<LowUIRBasicBlock>, HashSet<VarKind>>()

  /// Accumulates every variable kind ever read anywhere in the function. This
  /// only grows: a vertex is scanned into it once, when it is first pending,
  /// and its statements never change afterwards.
  let everUsedVarKinds = HashSet<VarKind>()

  /// Maps a program point to the stack slot whose address the statement there
  /// puts in a register other than those that follow the stack, where a
  /// callee may get it.
  let stackAddrEscapes = Dictionary<ProgramPoint, int>()

  /// Maps a program point to the stack slot in which the statement there saves
  /// what a register holds on entry.
  let registerSaves = Dictionary<ProgramPoint, int>()

  /// Holds the offsets of the stack slots that the function reads anywhere.
  let usedStackOffsets = SortedSet<int>()

  /// Maps a call to the offsets of the stack slots that its callee may write,
  /// in ascending order.
  let callClobbers = Dictionary<IVertex<LowUIRBasicBlock>, int[]>()

  /// Holds the registers in which the calling convention passes arguments.
  let argRegisters =
    lazy
      match hdl.ISA.Arch with
      | Architecture.EVM ->
        [||]
      | _ ->
        hdl.Conventions.Calling.IntArgs
        |> Array.choose (function
          | ArgLocation.Reg rid -> Some rid
          | _ -> None)

  /// Holds the vertices that need to be analyzed for reconstructing data flow
  /// information.
  let verticesForProcessing = HashSet<IVertex<LowUIRBasicBlock>>()

  /// Holds the vertices that need to be removed.
  let verticesForRemoval = Queue<IVertex<LowUIRBasicBlock>>()

  /// Counts up to give every SSA variable a fresh identifier.
  let mutable ssaVarCounter = 0

  /// Maps a variable point to its corresponding SSA variable.
  let vpToSSAVar = Dictionary<VarPoint, SSA.Variable>()

  /// Maps an SSA variable to its corresponding variable point.
  let ssaVarToVp = Dictionary<SSA.Variable, VarPoint>()

  let domainGetAbsValue vp =
    match domainAbsValues.TryGetValue vp with
    | true, v -> v
    | false, _ when vp.ProgramPoint.IsFake -> scheme.GetBaseCase vp.VarKind
    | false, _ -> lattice.Bottom

  let spGetInitialAbsValue varKind =
    match spInitial with
    | Some(stackVar, c) when varKind = stackVar ->
      c
    | _ ->
      match RegisterInitialValueProvider.tryGetInitialVarValue
              initialValueProvider varKind with
      | Some bv -> AddressDomain.Const bv
      | None -> AddressDomain.Undef

  let spGetAbsValue vp =
    match spAbsValues.TryGetValue vp with
    | true, c -> c
    | false, _ when vp.ProgramPoint.IsFake -> spGetInitialAbsValue vp.VarKind
    | false, _ -> AddressDomain.Undef

  let spEvaluateVar varKind pp =
    let vp = { ProgramPoint = pp; VarKind = varKind }
    match useDefMap.TryGetValue vp with
    | true, defVp -> spGetAbsValue defVp
    | false, _ -> AddressDomain.Undef

  let spEvaluateExpr pp e = LowUIRAddress.evalExpr spEvaluateVar pp e

  let getStatements v = stmtCache.GetStmtInfos v

  /// Returns a fresh identifier for the given variable kind and increments the
  /// identifier.
  let getNewVarId () =
    ssaVarCounter <- ssaVarCounter + 1
    ssaVarCounter

  /// Converts a variable kind to an SSA variable kind.
  let toSSAVarKind vk =
    match vk with
    | Regular rid ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let rname = hdl.RegisterFactory.GetRegisterName rid
      SSA.RegVar(rt, rid, rname)
    | Memory ->
      SSA.MemVar
    | StackLocal offset ->
      SSA.StackVar(0<rt>, offset)
    | Global addr ->
      SSA.GlobalVar(0<rt>, addr)
    | Temporary n ->
      let rt = 0<rt>
      SSA.TempVar(rt, n)

  /// Returns an empty SSA variable for the given variable kind.
  let mkEmptySSAVar vk = { SSA.Kind = toSSAVarKind vk; SSA.Identifier = 0 }

  /// Returns an SSA variable for the given variable point.
  let getSSAVar vp =
    match vpToSSAVar.TryGetValue vp with
    | true, v ->
      v
    | false, _ when vp.ProgramPoint.IsFake ->
      mkEmptySSAVar vp.VarKind
    | false, _ ->
      let ssaVarId = getNewVarId ()
      let ssaVarKind = toSSAVarKind vp.VarKind
      let ssaVar = { SSA.Kind = ssaVarKind; SSA.Identifier = ssaVarId }
      vpToSSAVar[vp] <- ssaVar
      ssaVarToVp[ssaVar] <- vp
      ssaVar

  /// Returns an SSA variable for the given use.
  let getSSAVarFromUse pp vk =
    let vp = { ProgramPoint = pp; VarKind = vk }
    match useDefMap.TryGetValue vp with
    | false, _ -> Terminator.impossible ()
    | true, defVp -> getSSAVar defVp

  /// Translates an IR expression to its SSA expression.
  let rec translateToSSAExpr (pp: ProgramPoint) e =
    match e with
    | Num(Value = bv) ->
      SSA.Num bv
    | PCVar(Type = rt) ->
      assert (Option.isNone pp.CallSite)
      SSA.Num <| BitVector(pp.Address, rt)
    | Var _ | TempVar _ ->
      let vk = VarKind.ofIRExpr e
      let ssaVar = getSSAVarFromUse pp vk
      SSA.Var ssaVar
    | ExprList(Elements = exprs) ->
      List.map (translateToSSAExpr pp) exprs
      |> SSA.ExprList
    | Load(Type = rt; Addr = addr) ->
      let addrValue = spEvaluateExpr pp addr
      match LowUIRAddress.tryGetMemoryVarKind addrValue with
      | Some vk ->
        let ssaVar = getSSAVarFromUse pp vk
        SSA.Var ssaVar
      | None ->
        let emptyMemVar = mkEmptySSAVar Memory
        let e = translateToSSAExpr pp addr
        SSA.Load(emptyMemVar, rt, e)
    | BinOp(Op = binOpType; Type = rt; Left = e1; Right = e2) ->
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      SSA.BinOp(binOpType, rt, e1, e2)
    | RelOp(Op = relOpType; Left = e1; Right = e2) ->
      let rt = Expr.typeOf e1
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      SSA.RelOp(relOpType, rt, e1, e2)
    | Extract(Operand = e; Type = rt; StartPos = startPos) ->
      let e = translateToSSAExpr pp e
      SSA.Extract(e, rt, startPos)
    | UnOp(Op = unOpType; Operand = e) ->
      let rt = Expr.typeOf e
      let e = translateToSSAExpr pp e
      SSA.UnOp(unOpType, rt, e)
    | Cast(Kind = castKind; Type = rt; Operand = e) ->
      let e = translateToSSAExpr pp e
      SSA.Cast(castKind, rt, e)
    | RoundCtrl(Mode = mode; Body = body) ->
      let rt = Expr.typeOf body
      let mode = translateToSSAExpr pp mode
      let body = translateToSSAExpr pp body
      SSA.RoundCtrl(mode, rt, body)
    | FuncName(Name = s) ->
      SSA.FuncName s
    | Undefined(Type = rt; Reason = s) ->
      SSA.Undefined(rt, s)
    | Ite(Cond = e1; TrueExpr = e2; FalseExpr = e3) ->
      let rt = Expr.typeOf e2
      let e1 = translateToSSAExpr pp e1
      let e2 = translateToSSAExpr pp e2
      let e3 = translateToSSAExpr pp e3
      SSA.Ite(e1, rt, e2, e3)
    | _ ->
      Terminator.impossible ()

  let translateLabel addr = function
    | JmpDest(Target = lbl) -> lbl
    | Undefined(Reason = s) -> AST.label s -1 addr
    | _ -> raise InvalidExprException

  /// Translates an ordinary IR statement to an SSA statement. It returns a
  /// dummy exception statement if the given IR statement is invalid.
  let translateToSSAStmt pp stmt =
    match stmt with
    | Put(Dst = dst; Src = src) ->
      let vk = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = vk }
      let v = getSSAVar vp
      let e = translateToSSAExpr pp src
      SSA.Def(v, e)
    | Store(Addr = addr; Value = value) ->
      let addrValue = spEvaluateExpr pp addr
      match LowUIRAddress.tryGetMemoryVarKind addrValue with
      | Some vk ->
        let vp = { ProgramPoint = pp; VarKind = vk }
        let v = getSSAVar vp
        let e = translateToSSAExpr pp value
        SSA.Def(v, e)
      | None ->
        let prevMemVar = mkEmptySSAVar Memory (* empty one *)
        let newMemVar = getSSAVar { ProgramPoint = pp; VarKind = Memory }
        let rt = Expr.typeOf value
        let e1 = translateToSSAExpr pp addr
        let e2 = translateToSSAExpr pp value
        let e = SSA.Store(prevMemVar, rt, e1, e2)
        SSA.Def(newMemVar, e)
    | Jmp(Target = expr) ->
      let addr = 0x0UL (* use dummy address for simplicity *)
      let label = translateLabel addr expr
      let e = SSA.IntraJmp label
      SSA.Jmp e
    | CJmp(Cond = expr; TrueTarget = label1; FalseTarget = label2) ->
      let addr = 0x0UL (* use dummy address for simplicity *)
      let expr = translateToSSAExpr pp expr
      let label1 = translateLabel addr label1
      let label2 = translateLabel addr label2
      let e = SSA.IntraCJmp(expr, label1, label2)
      SSA.Jmp e
    | InterJmp(Target = expr) ->
      let expr = translateToSSAExpr pp expr
      let e = SSA.InterJmp(expr)
      SSA.Jmp e
    | InterCJmp(Cond = expr1; TrueTarget = expr2; FalseTarget = expr3) ->
      let expr1 = translateToSSAExpr pp expr1
      let expr2 = translateToSSAExpr pp expr2
      let expr3 = translateToSSAExpr pp expr3
      let e = SSA.InterCJmp(expr1, expr2, expr3)
      SSA.Jmp e
    | SideEffect(Effect = sideEff) ->
      SSA.SideEffect sideEff
    | _ ->
      SSA.SideEffect UndefinedInstruction

  let convertDefsToIds defs =
    defs
    |> Seq.map (fun def ->
      let v = getSSAVar def
      v.Identifier)
    |> Seq.toArray

  /// Generates a phi statement for the given variable point.
  let generatePhiSSAStmt vp =
    let _, v = stmtCache.StmtOfBBLs[vp.ProgramPoint]
    let phiInfo = phiInfos[v]
    let varKind = vp.VarKind
    let defs = phiInfo[varKind]
    let var = getSSAVar vp
    let ids = convertDefsToIds defs.Values
    SSA.Phi(var, ids)

  /// Finds the variable point that the given empty SSA variable stands for,
  /// which getSSAVar makes of a variable coming in from outside the function:
  /// the fake one of its kind.
  let tryGetFakeVp (v: SSA.Variable) =
    match v.Kind with
    | SSA.RegVar(_, rid, _) -> Some(Regular rid)
    | SSA.TempVar(_, n) -> Some(Temporary n)
    | SSA.StackVar(_, offset) -> Some(StackLocal offset)
    | SSA.GlobalVar(_, addr) -> Some(Global addr)
    | SSA.MemVar -> Some Memory
    | SSA.PCVar _ -> None
    |> Option.map (fun vk -> { ProgramPoint = ProgramPoint.Fake; VarKind = vk })

  /// Gets the definitions that the phi defining the given variable point
  /// joins, if a phi defines it.
  let tryGetPhiOperands vp =
    match stmtCache.StmtOfBBLs.TryGetValue vp.ProgramPoint with
    | true, (_, v) when v.VData.Internals.PPoint = vp.ProgramPoint ->
      match phiInfos.TryGetValue v with
      | true, phiInfo when phiInfo.ContainsKey vp.VarKind ->
        Some(Seq.toArray phiInfo[vp.VarKind].Values)
      | _ ->
        None
    | _ ->
      None

  /// Gets the call that makes the given definition of a stack slot, which a
  /// call makes of a slot that its callee may write.
  let tryGetCallDefining vp =
    match vp.VarKind with
    | StackLocal _ ->
      match stmtCache.StmtOfBBLs.TryGetValue vp.ProgramPoint with
      | true, (_, v) when v.VData.Internals.IsAbstract -> Some v
      | _ -> None
    | _ ->
      None

  /// Gets the definition of the given variable kind that reaches the given
  /// vertex.
  let tryGetIncomingDef v vk =
    match perVertexIncomingDefs.TryGetValue v with
    | true, defs -> Map.tryFind vk defs
    | false, _ -> None

  /// Collects into defs the definitions that statements make and that reach
  /// the given ones through phis and past the calls that may write a stack
  /// slot. Returns false if what the function gets on entry reaches them.
  let rec collectDefsBeyondCalls (visited: HashSet<_>) defs vps =
    match vps with
    | [] ->
      true
    | vp :: _ when vp.ProgramPoint.IsFake ->
      false
    | vp :: rest when not (visited.Add vp) ->
      collectDefsBeyondCalls visited defs rest
    | vp :: rest ->
      match tryGetPhiOperands vp, tryGetCallDefining vp with
      | Some operands, _ ->
        collectDefsBeyondCalls visited defs (List.ofArray operands @ rest)
      | None, Some v ->
        match tryGetIncomingDef v vp.VarKind with
        | Some def -> collectDefsBeyondCalls visited defs (def :: rest)
        | None -> false
      | None, None ->
        (defs: ResizeArray<_>).Add vp
        collectDefsBeyondCalls visited defs rest

  let domainSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let phiQueue = Queue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new ISubState<'Lattice> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.PhiQueue = phiQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = lattice.Bottom
        member _.GetAbsValue vp = domainGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = domainAbsValues[vp] <- absVal
        member _.Join(a, b) = lattice.Join(a, b)
        member _.Subsume(a, b) = lattice.Subsume(a, b) }

  let spSubState =
    let flowQueue = UniqueQueue()
    let defSiteQueue = UniqueQueue()
    let phiQueue = Queue()
    let executedFlows = HashSet()
    let executedVertices = HashSet()
    { new ISubState<AddressDomain.Lattice> with
        member _.FlowQueue = flowQueue
        member _.DefSiteQueue = defSiteQueue
        member _.PhiQueue = phiQueue
        member _.ExecutedFlows = executedFlows
        member _.ExecutedVertices = executedVertices
        member _.Bottom = AddressDomain.Undef
        member _.GetAbsValue vp = spGetAbsValue vp
        member _.SetAbsValue(vp, absVal) = spAbsValues[vp] <- absVal
        member _.Join(a, b) = AddressDomain.join a b
        member _.Subsume(a, b) = AddressDomain.subsume a b }

  let resetSubState (subState: ISubState<_>) =
    subState.FlowQueue.Clear()
    subState.DefSiteQueue.Clear()
    subState.PhiQueue.Clear()
    subState.ExecutedFlows.Clear()
    subState.ExecutedVertices.Clear()

  let reset () =
    stmtCache.Clear()
    domainAbsValues.Clear()
    spAbsValues.Clear()
    phiInfos.Clear()
    perVertexIncomingDefs.Clear()
    perVertexOutgoingDefs.Clear()
    defUseMap.Clear()
    useDefMap.Clear()
    verticesForProcessing.Clear()
    verticesForRemoval.Clear()
    usedVarKindsMemo.Clear()
    everUsedVarKinds.Clear()
    stackAddrEscapes.Clear()
    registerSaves.Clear()
    usedStackOffsets.Clear()
    callClobbers.Clear()
    vpToSSAVar.Clear()
    ssaVarCounter <- 0
    ssaVarToVp.Clear()
    resetSubState spSubState
    resetSubState domainSubState

  /// Returns the binary handle associated with this state.
  member _.BinHandle with get() = hdl

  /// Returns the scheme used for this data flow analysis.
  member _.Scheme with get() = scheme

  /// Maps a CFG vertex to its phi information.
  member _.PhiInfos with get() = phiInfos :> IReadOnlyDictionary<_, _>

  member internal _.MutablePhiInfos with get() = phiInfos

  /// Maps a CFG vertex to its incoming definitions.
  member _.PerVertexIncomingDefs
    with get() = perVertexIncomingDefs :> IReadOnlyDictionary<_, _>

  member internal _.MutablePerVertexIncomingDefs
    with get() = perVertexIncomingDefs

  /// Maps a CFG vertex to its outgoing definitions.
  member _.PerVertexOutgoingDefs
    with get() = perVertexOutgoingDefs :> IReadOnlyDictionary<_, _>

  member internal _.MutablePerVertexOutgoingDefs
    with get() = perVertexOutgoingDefs

  /// Maps a variable def to its uses.
  member _.DefUseMap with get() = defUseMap :> IReadOnlyDictionary<_, _>

  member internal _.MutableDefUseMap with get() = defUseMap

  /// Maps a variable use to its definition.
  member _.UseDefMap with get() = useDefMap :> IReadOnlyDictionary<_, _>

  member internal _.MutableUseDefMap with get() = useDefMap

  member internal _.UsedVarKindsMemo with get() = usedVarKindsMemo

  member internal _.EverUsedVarKinds with get() = everUsedVarKinds

  member internal _.StackAddrEscapes with get() = stackAddrEscapes

  member internal _.RegisterSaves with get() = registerSaves

  member internal _.UsedStackOffsets with get() = usedStackOffsets

  member internal _.CallClobbers with get() = callClobbers

  member internal _.ArgRegisters with get() = argRegisters.Value

  /// Maps an SSA variable to its corresponding variable point.
  member _.SSAVarToVp with get() = ssaVarToVp :> IReadOnlyDictionary<_, _>

  /// Maps a program point to `StmtOfBBL`, which is a pair of a Low-UIR
  /// statement and its corresponding vertex that contains the statement.
  member _.StmtOfBBLs with get() = stmtCache.StmtOfBBLs

  /// Returns the sub-state for the address domain.
  member internal _.StackPointerSubState with get() = spSubState

  /// Returns the sub-state for the user's domain.
  member internal _.DomainSubState with get() = domainSubState

  /// Returns the vertices that are currently pending for processing.
  member _.PendingVertices with get(): IEnumerable<IVertex<LowUIRBasicBlock>> =
    verticesForProcessing

  /// Evaluates the given expression at the given program point in the address
  /// domain, telling an address on the stack from a constant.
  member _.EvaluateAddressExpr(pp, e: Expr) = spEvaluateExpr pp e

  /// Marks the given vertex as pending, which means that the vertex needs to be
  /// processed.
  member _.MarkVertexAsPending v = verticesForProcessing.Add v |> ignore

  /// Marks the given vertex as removal, which means that the vertex needs to be
  /// removed.
  member _.MarkVertexAsRemoval v = verticesForRemoval.Enqueue v |> ignore

  /// Checks if the given vertex is pending for processing.
  member _.IsVertexPending v = verticesForProcessing.Contains v

  /// Clears the pending vertices.
  member _.ClearPendingVertices() = verticesForProcessing.Clear()

  /// Enqueues the pending vertices to the given sub-state.
  member internal _.EnqueuePendingVertices(subState: ISubState<_>) =
    for v in verticesForProcessing do
      subState.FlowQueue.Enqueue(null, v)

  /// Dequeues the vertex for removal. When there is no vertex to remove, it
  /// returns `false`.
  member _.DequeueVertexForRemoval() = verticesForRemoval.TryDequeue()

  /// Returns the array of StmtInfos of the given vertex.
  member _.GetStmtInfos v = getStatements v

  /// Forgets the statements of the given vertex.
  member internal _.RemoveStmtsOf v = stmtCache.Remove v

  /// Returns the terminator statement of the given vertex in an SSA form.
  member _.GetTerminatorInSSA v =
    getStatements v
    |> Array.last
    |> fun (irStmt, pp) -> translateToSSAStmt pp irStmt

  /// Tries to get the definition of the given SSA variable in an SSA form.
  member _.TryGetSSADef var =
    if not <| ssaVarToVp.ContainsKey var then
      None
    else
      let vp = ssaVarToVp[var]
      let pp = vp.ProgramPoint
      let stmt, v = stmtCache.StmtOfBBLs[pp]
      let pp' = v.VData.Internals.PPoint
      let isPhi = pp = pp'
      if not isPhi then
        (* A call defines the stack slots that its callee may write at its
           last statement, which defines something else if anything, so they
           come back as if from outside. *)
        match translateToSSAStmt pp stmt with
        | SSA.Def(defined, _) as s when defined = var -> Some s
        | _ -> None
      else
        generatePhiSSAStmt vp |> Some

  /// Tries to get the operand that the given SSA variable takes along the edge
  /// from pred to v, as an SSA variable. Returns None unless a phi of v defines
  /// the variable.
  member _.TryGetSSAPhiOperand(var, pred, v: IVertex<LowUIRBasicBlock>) =
    match ssaVarToVp.TryGetValue var with
    | true, vp when vp.ProgramPoint = v.VData.Internals.PPoint ->
      let _, endPP = getStatements pred |> Array.last
      match phiInfos.TryGetValue v with
      | true, phiInfo when phiInfo.ContainsKey vp.VarKind ->
        match phiInfo[vp.VarKind].TryGetValue endPP with
        | true, def -> Some(getSSAVar def)
        | false, _ -> None
      | _ ->
        None
    | _ ->
      None

  /// Gets the definitions that the phi defining the given variable point
  /// joins, if a phi defines it.
  member _.TryGetPhiOperands vp = tryGetPhiOperands vp

  /// Returns the abstract value that the given definition would hold if no
  /// call wrote the stack slots that it may write: the join of what the
  /// statements that reach the definition through phis and past such calls
  /// define. A call only may write such a slot, so this tells what the slot
  /// holds if the call does not, which whoever reads it has to confirm on its
  /// own. Returns None if what the function gets on entry reaches it.
  member _.TryGetAbsValueBeyondCalls vp =
    let defs = ResizeArray()
    if collectDefsBeyondCalls (HashSet()) defs [ vp ] then
      defs
      |> Seq.map domainGetAbsValue
      |> Seq.fold (fun acc v -> lattice.Join(acc, v)) lattice.Bottom
      |> Some
    else
      None

  /// Returns the abstract value at the given variable point.
  member _.GetAbsValue vp = domainGetAbsValue vp

  /// Returns the abstract value of the definition that reaches the given use,
  /// or the bottom of the lattice when no definition reaches it.
  member _.GetAbsValueOfUse(pp, varKind) =
    match useDefMap.TryGetValue { ProgramPoint = pp; VarKind = varKind } with
    | true, defVp -> domainGetAbsValue defVp
    | false, _ -> lattice.Bottom

  /// Tries to get the abstract value of the given SSA variable. A variable
  /// that comes in from outside the function holds what the analysis assumes
  /// on entry. It returns None for a variable that the analysis never defined.
  member _.TryGetAbsValueOfSSAVar v =
    match ssaVarToVp.TryGetValue v with
    | true, vp ->
      Some <| domainGetAbsValue vp
    | false, _ when v.Identifier = 0 ->
      tryGetFakeVp v |> Option.map domainGetAbsValue
    | false, _ ->
      None

  /// Resets this state.
  member _.Reset() = reset ()

  interface IAbsValProvider<VarPoint, 'Lattice> with
    member _.GetAbsValue absLoc = domainGetAbsValue absLoc

/// Represents a substate for the LowUIR-based sparse dataflow analysis.
and ISubState<'Lattice when 'Lattice: equality> =
  inherit IAbsValProvider<VarPoint, 'Lattice>
  inherit ILattice<'Lattice>

  /// Returns the edge queue for calculating the data flow.
  abstract FlowQueue:
    UniqueQueue<IVertex<LowUIRBasicBlock> | null * IVertex<LowUIRBasicBlock>>

  /// Returns the definition site queue for calculating the data flow.
  abstract DefSiteQueue: UniqueQueue<ProgramPoint>

  /// Returns the queue of phi operands to join, as pairs of a phi and one of
  /// its operands.
  abstract PhiQueue: Queue<VarPoint * VarPoint>

  /// Returns the edges executed during the data flow calculation.
  abstract ExecutedFlows:
    HashSet<IVertex<LowUIRBasicBlock> * IVertex<LowUIRBasicBlock>>

  /// Returns the vertices executed during the data flow calculation.
  abstract ExecutedVertices: HashSet<IVertex<LowUIRBasicBlock>>

  /// Sets the abstract value at the given location.
  abstract SetAbsValue: vp: VarPoint * 'Lattice -> unit

/// Represents a mapping from a variable kind of a phi to its definitions. We
/// represent each definition as a mapping from a predecessor's program point
/// to a variable point. This way, a definition from the same predecessor can
/// be replaced by the latest definition.
and private PhiInfo = Dictionary<VarKind, Dictionary<ProgramPoint, VarPoint>>

/// Represents how we perform LowUIR-based sparse dataflow analysis.
and IScheme<'Lattice when 'Lattice: equality> =
  inherit IExprEvaluatable<ProgramPoint, 'Lattice>

  /// Returns the abstract value of a variable that the function never defines,
  /// i.e. one that comes in from the outside. Such a variable never receives a
  /// definition that would raise a bottom, so this must be a sound
  /// over-approximation.
  abstract GetBaseCase: VarKind -> 'Lattice

[<AutoOpen>]
module internal AnalysisCore = begin

  /// Removes the phis of `v` from the uses of their operands, as the phis leave
  /// the graph with `v`. A vertex that takes the place of `v` later has phis of
  /// the same variable points, which must not inherit these uses.
  let removePhisOf (state: State<_>) (v: IVertex<LowUIRBasicBlock>) =
    match state.PhiInfos.TryGetValue v with
    | true, phiInfo ->
      let pp = v.VData.Internals.PPoint
      for (KeyValue(vk, defs)) in phiInfo do
        let phi = { ProgramPoint = pp; VarKind = vk }
        for def in defs.Values do
          state.MutableDefUseMap[def].Remove phi |> ignore
    | false, _ ->
      ()

  /// Forgets what the statements of the given vertex tell about the stack:
  /// the slots whose addresses they hand on and those in which they save
  /// registers.
  let forgetStackFacts (state: State<_>) v =
    for _, pp in state.GetStmtInfos v do
      state.StackAddrEscapes.Remove pp |> ignore
      state.RegisterSaves.Remove pp |> ignore
    state.CallClobbers.Remove v |> ignore

  /// Invalidates the dataflow chains of the vertices that are pending
  /// removal, since a vertex leaving the graph makes its chains invalid.
  let rec removeInvalidChains (state: State<_>) =
    match state.DequeueVertexForRemoval() with
    | true, v when state.PerVertexIncomingDefs.ContainsKey v ->
      forgetStackFacts state v
      state.RemoveStmtsOf v
      removePhisOf state v
      state.MutablePhiInfos.Remove v |> ignore
      state.MutablePerVertexIncomingDefs.Remove v |> ignore
      state.MutablePerVertexOutgoingDefs.Remove v |> ignore
      state.UsedVarKindsMemo.Remove v |> ignore
      removeInvalidChains state
    | true, _ ->
      removeInvalidChains state
    | false, _ ->
      ()

  /// Gets the kind of the variable that names the memory at the address that
  /// the given expression gives at the given point, if that is a known one.
  let tryGetMemoryVarKind (state: State<_>) pp e =
    state.EvaluateAddressExpr(pp, e)
    |> LowUIRAddress.tryGetMemoryVarKind

  /// Gets the stack slots that the call at the given vertex lets its callee
  /// write, along with the program point at which it defines them: its last
  /// statement.
  let tryGetCallClobbers (state: State<_>) v =
    match state.CallClobbers.TryGetValue v with
    | true, offsets when offsets.Length > 0 ->
      state.GetStmtInfos v
      |> Array.tryLast
      |> Option.map (fun (_, pp) -> pp, offsets)
    | _ ->
      None

  /// Computes the inverse dominance frontier in linear time.
  let computeInverseDF g (dom: IForwardDominance<_>) v =
    let g: IDiGraph<_, _> = g
    let s = HashSet()
    for pred in g.GetPreds v do
      let mutable x = pred
      while x <> dom.ImmediateDominator v do
        s.Add x |> ignore
        x <- dom.ImmediateDominator x
    s

  /// Collects the vertices that are candidates for phi insertion at this point.
  /// We reduce the search space to only those vertices that are possibly
  /// affected by the changes in the graph.
  let collectPhiInsertionCandidates g state =
    let workset = HashSet()
    for v in (state: State<_>).PendingVertices do
      if not <| (g: IDiGraph<_, _>).Contains v then
        ()
      else
        workset.Add v |> ignore
        for succ in g.GetSuccs v do
          if g.GetPreds succ |> Seq.length > 1 then workset.Add succ |> ignore
          else ()
    workset

  let placePhi state v varKind =
    let phiInfos = (state: State<_>).MutablePhiInfos
    if not <| phiInfos.ContainsKey v then phiInfos[v] <- PhiInfo () else ()
    let phiInfo = phiInfos[v]
    if phiInfo.ContainsKey varKind then
      false
    else
      phiInfo[varKind] <- Dictionary ()
      true

  let isInnerScopeVarKind (v: IVertex<LowUIRBasicBlock>) = function
    | Temporary _ when v.VData.Internals.PPoint.Position = 0 -> true
    | _ -> false

  let getDefinedVarKinds memo (state: State<_>) v =
    match (memo: Dictionary<_, _>).TryGetValue v with
    | true, kinds ->
      kinds
    | false, _ ->
      let varKinds = HashSet()
      for (stmt, pp) in state.GetStmtInfos v do
        match stmt with
        | Put(Dst = dst) ->
          let vk = VarKind.ofIRExpr dst
          varKinds.Add vk |> ignore
        | Store(Addr = addr) ->
          tryGetMemoryVarKind state pp addr
          |> Option.iter (fun vk -> varKinds.Add vk |> ignore)
        | _ ->
          ()
      match tryGetCallClobbers state v with
      | Some(_, offsets) ->
        for off in offsets do varKinds.Add(StackLocal off) |> ignore
      | None ->
        ()
      memo[v] <- varKinds
      varKinds

  /// Returns the variable kinds read by the given vertex, i.e. the ones a phi
  /// placed for this vertex could actually feed. A store's own destination is
  /// a definition, not a use, so only its address and value are walked.
  let getUsedVarKinds memo (state: State<_>) v =
    match (memo: Dictionary<_, _>).TryGetValue v with
    | true, kinds ->
      kinds
    | false, _ ->
      let varKinds = HashSet()
      let onVarRead vk = varKinds.Add vk |> ignore
      for (stmt, pp) in state.GetStmtInfos v do
        match stmt with
        | Put(Src = src) ->
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) src
        | Store(Addr = addr; Value = src) ->
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) addr
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) src
        | Jmp(Target = e) | CJmp(Cond = e) | InterJmp(Target = e) ->
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) e
        | InterCJmp(Cond = c; TrueTarget = e1; FalseTarget = e2) ->
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) c
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) e1
          VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) e2
        | _ ->
          ()
      memo[v] <- varKinds
      varKinds

  /// Returns the variable kinds defined by the phi nodes of the given vertex.
  /// A phi node is a definition on its own, so it can require another phi node
  /// down the dominance frontier.
  let getPhiVarKinds (state: State<_>) v =
    match state.PhiInfos.TryGetValue v with
    | true, phiInfo -> phiInfo.Keys :> seq<_>
    | false, _ -> Seq.empty

  /// Places the phi nodes that the definitions of `affectingVertex` require at
  /// the insertion point `v`. Returns true if a new phi node has been placed.
  /// Skips a variable kind that is never read anywhere in the function: no
  /// query can ever reach such a phi, since every consumer of this analysis
  /// starts from a real use in some IR expression.
  let placePhisFrom (everUsed: HashSet<_>) state buf memo v affectingVertex =
    let mutable changed = false
    for varKind in getDefinedVarKinds memo state affectingVertex do
      if isInnerScopeVarKind v varKind || not (everUsed.Contains varKind) then
        ()
      elif placePhi state v varKind then
        changed <- true
      else
        ()
    (buf: ResizeArray<_>).Clear()
    buf.AddRange(getPhiVarKinds state affectingVertex)
    for varKind in buf do
      if isInnerScopeVarKind v varKind || not (everUsed.Contains varKind) then
        ()
      elif placePhi state v varKind then
        changed <- true
      else
        ()
    changed

  /// Notes the variable kinds that the pending vertices read, along with the
  /// stack slots among them. Every vertex is marked pending at least once,
  /// when it is first added, so folding only the currently pending ones into
  /// the persistent sets (rather than rescanning the whole graph every time)
  /// still accounts for every vertex exactly once over the state's lifetime.
  let noteUsedVarKinds (state: State<_>) =
    for v in state.PendingVertices do
      for varKind in getUsedVarKinds state.UsedVarKindsMemo state v do
        if state.EverUsedVarKinds.Add varKind then
          match varKind with
          | StackLocal off -> state.UsedStackOffsets.Add off |> ignore
          | _ -> ()
        else
          ()

  /// Maps each vertex to the insertion points whose inverse dominance frontier
  /// it belongs to, so that a newly placed phi node only wakes up the insertion
  /// points that can possibly need another one.
  let buildInverseDFIndex g dom candidates =
    let invDFs = Dictionary()
    let dependents = Dictionary()
    for v in candidates do
      let invDF = computeInverseDF g dom v
      invDFs[v] <- invDF
      for affectingVertex in invDF do
        match dependents.TryGetValue affectingVertex with
        | true, lst -> (lst: ResizeArray<_>).Add v
        | false, _ -> dependents[affectingVertex] <- ResizeArray [ v ]
    invDFs, dependents

  /// Places the phi nodes. We do not calculate all dominance frontier sets,
  /// but only those that are selectively used to insert phi nodes. Since a phi
  /// node is itself a definition, we repeat the placement until it converges,
  /// revisiting an insertion point only when one of the vertices it depends on
  /// has gained a phi node.
  let placePhis g state (dom: IForwardDominance<_>) =
    let memo = Dictionary()
    let buf = ResizeArray()
    noteUsedVarKinds state
    let everUsed = state.EverUsedVarKinds
    let candidates = collectPhiInsertionCandidates g state
    let invDFs, dependents = buildInverseDFIndex g dom candidates
    let worklist = Queue candidates
    let queued = HashSet candidates
    while worklist.Count > 0 do
      let v = worklist.Dequeue()
      queued.Remove v |> ignore
      let mutable changed = false
      for affectingVertex in invDFs[v] do
        if placePhisFrom everUsed state buf memo v affectingVertex then
          changed <- true
        else
          ()
      match dependents.TryGetValue v with
      | true, lst when changed ->
        for dependent in lst do
          if queued.Add dependent then worklist.Enqueue dependent else ()
      | _ ->
        ()

  let updateIncomingDefsWithPhis state (v: IVertex<LowUIRBasicBlock>) ins =
    match (state: State<_>).PhiInfos.TryGetValue v with
    | false, _ ->
      ins
    | true, phiInfo ->
      let pp = v.VData.Internals.PPoint
      phiInfo.Keys
      |> Seq.fold (fun ins vk ->
        let vp = { ProgramPoint = pp; VarKind = vk }
        Map.add vk vp ins) ins

  let removeOldChains state useVp defVp =
    match (state: State<_>).UseDefMap.TryGetValue useVp with
    | true, prevDef when prevDef.ProgramPoint <> defVp.ProgramPoint ->
      (* Erase the old def-use. *)
      state.MutableDefUseMap[prevDef].Remove useVp |> ignore
      (* Erase the old use-def which will be overwritten by the new def. *)
      state.MutableUseDefMap.Remove useVp |> ignore
    | _ ->
      ()

  let updateDefUseChain state useVp defVp =
    match (state: State<_>).MutableDefUseMap.TryGetValue defVp with
    | false, _ -> state.MutableDefUseMap[defVp] <- HashSet [ useVp ]
    | true, uses -> uses.Add useVp |> ignore

  let updateUseDefChain state useVp defVp =
    (state: State<_>).MutableUseDefMap[useVp] <- defVp

  /// Gets a fake variable point for the given variable kind. This is used when
  /// there is no definition for the given variable kind (e.g., function
  /// arguments).
  let getFakeVarPoint vk = { ProgramPoint = ProgramPoint.Fake; VarKind = vk }

  let updateChains state vk defs pp =
    let defVp = Map.tryFind vk defs |> Option.defaultValue (getFakeVarPoint vk)
    let useVp = { ProgramPoint = pp; VarKind = vk }
    removeOldChains state useVp defVp
    updateDefUseChain state useVp defVp
    updateUseDefChain state useVp defVp

  let updateWithExpr state defs (pp: ProgramPoint) expr =
    let onVarRead vk = updateChains state vk defs pp
    VarKind.iterUses onVarRead (tryGetMemoryVarKind state pp) expr

  let updateWithJmp state defs pp = function
    | Jmp(Target = expr) ->
      updateWithExpr state defs pp expr
    | CJmp(Cond = expr; TrueTarget = target1; FalseTarget = target2) ->
      updateWithExpr state defs pp expr
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | InterJmp(Target = expr; Kind = _jmpKind) ->
      updateWithExpr state defs pp expr
    | InterCJmp(Cond = cond; TrueTarget = target1; FalseTarget = target2) ->
      updateWithExpr state defs pp cond
      updateWithExpr state defs pp target1
      updateWithExpr state defs pp target2
    | _ ->
      Terminator.impossible ()

  /// Updates DU/UD chains stored in the state as well as the out variables by
  /// executing the given statement. The `defs` stores every definition
  /// including temporary variables, but the `outs` only stores the
  /// non-temporary variables.
  let updateWithStmt state (outs: byref<_>) (defs: byref<_>) stmt pp =
    match stmt with
    | Put(Dst = dst; Src = src) ->
      updateWithExpr state defs pp src
      let kind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = kind }
      defs <- Map.add kind vp defs
      if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
      else ()
    | Store(Addr = addr; Value = value) ->
      updateWithExpr state defs pp addr
      updateWithExpr state defs pp value
      match tryGetMemoryVarKind state pp addr with
      | Some kind ->
        let vp = { ProgramPoint = pp; VarKind = kind }
        defs <- Map.add kind vp defs
        if not (VarKind.isTemporary kind) then outs <- Map.add kind vp outs
        else ()
      | None ->
        ()
    | Jmp _
    | CJmp _
    | InterJmp _
    | InterCJmp _ ->
      updateWithJmp state defs pp stmt
    | _ ->
      ()

  let isIntraEdge lbl =
    match lbl with
    | IntraCJmpTrueEdge
    | IntraCJmpFalseEdge
    | IntraJmpEdge -> true
    | _ -> false

  /// Adds to the given definitions going out of the given vertex those that it
  /// makes of the stack slots that a callee may write, if it is a call that
  /// lets its callee write them.
  let addClobberDefs state v defs =
    match tryGetCallClobbers state v with
    | Some(pp, offsets) ->
      offsets
      |> Array.fold (fun defs off ->
        let kind = StackLocal off
        Map.add kind { ProgramPoint = pp; VarKind = kind } defs) defs
    | None ->
      defs

  /// Updates the DU/UD chains for the given basic block and return the defined
  /// variables in the block.
  let updateChainsWithBBLStmts g (state: State<_>) v defs =
    let blkAddr = (v: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint.Address
    let intraBlockContinues =
      (g: IDiGraph<_, _>).GetSuccEdges v
      |> Array.exists (fun e -> isIntraEdge e.Label)
    let stmtInfos = state.GetStmtInfos v
    let mutable outs = defs
    let mutable defs = defs
    let mutable prevAddr = blkAddr
    for i = 0 to stmtInfos.Length - 1 do
      let stmt, pp = stmtInfos[i]
      if pp.Address <> prevAddr then defs <- outs else ()
      updateWithStmt state &outs &defs stmt pp
      prevAddr <- pp.Address
    if intraBlockContinues then defs else addClobberDefs state v outs

  /// Updates the def-use/use-def chains for the vertices in the dominator tree.
  let rec update g state domTree (visited: HashSet<_>) v ins =
    assert (not <| visited.Contains v)
    visited.Add v |> ignore
    let ins = updateIncomingDefsWithPhis state v ins
    let outs = updateChainsWithBBLStmts g state v ins
    for child in (domTree: DominatorTree<_>).GetChildren v do
      update g state domTree visited child outs
    state.MutablePerVertexIncomingDefs[v] <- ins
    state.MutablePerVertexOutgoingDefs[v] <- outs

  let getOutgoingDefs (state: State<_>) v =
    match state.PerVertexOutgoingDefs.TryGetValue v with
    | false, _ -> Map.empty
    | true, defs -> defs

  /// Updates the data-flow chains, visiting only the vertices that have
  /// changed.
  let rec incrementalUpdate g state visited (dom: IForwardDominance<_>) v =
    if (visited: HashSet<_>).Contains v then
      ()
    elif (state: State<_>).IsVertexPending v
         && (g: IDiGraph<_, _>).Contains v then
      let idom = dom.ImmediateDominator v
      let defs = if isNull idom then Map.empty else getOutgoingDefs state idom
      update g state dom.DominatorTree visited v defs
    else
      for child in dom.DominatorTree.GetChildren v do
        incrementalUpdate g state visited dom child

  #if DEBUG
  let hasProperPhiOperandNumbers state g v =
    match (state: State<_>).PhiInfos.TryGetValue v with
    | false, _ ->
      true
    | true, phiInfo ->
      let predCount = (g: IDiGraph<_, _>).GetPreds v |> Seq.length
      phiInfo.Values |> Seq.forall (fun d -> d.Count <= predCount)
  #endif

  let getEndPP (state: State<_>) v =
    (state: State<_>).GetStmtInfos v
    |> Array.last
    |> snd

  /// Removes the phi `useSite` from the uses of `def`, an operand that it has
  /// just lost, unless another predecessor still brings `def` in. The uses of
  /// a definition thus tell exactly which phis it is an operand of.
  let removePhiUse (state: State<_>) (inDefs: Dictionary<_, _>) def useSite =
    if Seq.contains def inDefs.Values then ()
    else state.MutableDefUseMap[def].Remove useSite |> ignore

  /// Queues a phi operand that the chains have just added or replaced, since
  /// the phi may belong to a vertex that has already run, and no flow is bound
  /// to bring the operand in. The stack pointer propagation has already run
  /// when the second pass of the chains adds operands, so it joins those on
  /// its next run.
  let enqueuePhiOperand (state: State<_>) phi def =
    state.StackPointerSubState.PhiQueue.Enqueue((phi, def))
    state.DomainSubState.PhiQueue.Enqueue((phi, def))

  let updatePhiWithPredecessor state inDefs pred incomingDef useSite =
    let incomingPP = getEndPP state pred
    match (inDefs: Dictionary<_, _>).TryGetValue incomingPP with
    | true, oldDef when oldDef = incomingDef ->
      () (* already added *)
    | true, oldDef ->
      inDefs[incomingPP] <- incomingDef
      removePhiUse state inDefs oldDef useSite
      updateDefUseChain state useSite incomingDef
      enqueuePhiOperand state useSite incomingDef
    | false, _ ->
      inDefs[incomingPP] <- incomingDef
      updateDefUseChain state useSite incomingDef
      enqueuePhiOperand state useSite incomingDef

  /// Updates the dataflow information of phis. Unlike Cytron's approach though,
  /// the update process is done **after** the dominator tree traversal. This is
  /// to ensure that the predecessors of phi insertion points are executed
  /// before updating the phi information.
  let updatePhis g (state: State<_>) visited =
    for v in visited do
      match state.PhiInfos.TryGetValue v with
      | true, phiInfo ->
        for pred in (g: IDiGraph<_, _>).GetPreds v do
          let outDefs = getOutgoingDefs state pred
          for (KeyValue(vk, inDefs)) in phiInfo do
            let def =
              Map.tryFind vk outDefs |> Option.defaultValue (getFakeVarPoint vk)
            { ProgramPoint = v.VData.Internals.PPoint; VarKind = vk }
            |> updatePhiWithPredecessor state inDefs pred def
      | false, _ ->
        ()
  #if DEBUG
      assert (hasProperPhiOperandNumbers state g v)
  #endif

  /// Calculates the def-use/use-def chains. This is a modification of
  /// Cytron's algorithm that uses the dominator tree
  /// to calculate the def-use/use-def chains. This has theoretically the same
  /// worst-case time complexity as the original algorithm, but it is more
  /// efficient for incremental changes in practice since its search space is
  /// reduced to the affected vertices that are possibly updated.
  let calculateChains g state dom =
    let visited = HashSet<IVertex<LowUIRBasicBlock>>()
    placePhis g state dom
    (* A vertex that two roots of the graph share has no dominator, so the
       walk starts from it as well. *)
    for root in dom.DominatorTree.Roots do
      incrementalUpdate g state visited dom root
    updatePhis g state visited

  let isStackRelatedRegister (hdl: BinHandle) rid =
    hdl.RegisterFactory.IsStackPointer rid
    || hdl.RegisterFactory.IsFramePointer rid

  /// Queues a use of the definition `def`, whose value has just grown. A phi
  /// sits at position 0 and joins only this one operand, as joining all of its
  /// operands again would cost a pass over every predecessor of its vertex.
  /// Any other use has its statement evaluated again.
  let enqueueUse (subState: ISubState<_>) def (useVp: VarPoint) =
    if useVp.ProgramPoint.Position = 0 then
      subState.PhiQueue.Enqueue((useVp, def))
    else
      subState.DefSiteQueue.Enqueue useVp.ProgramPoint

  let updateAbsValue subState defUseMap vp prev curr =
    if (subState: ISubState<_>).Subsume(prev, curr) then
      ()
    else
      subState.SetAbsValue(vp, subState.Join(prev, curr))
      match (defUseMap: IReadOnlyDictionary<_, _>).TryGetValue vp with
      | false, _ ->
        ()
      | true, uses ->
        uses |> Seq.iter (enqueueUse subState vp)

  /// Notes whether the given value, which the statement at pp puts in a
  /// register other than those that follow the stack, is the address of a
  /// stack slot.
  let noteStackAddrEscape (state: State<_>) pp value =
    match value with
    | AddressDomain.StackAddr off ->
      state.StackAddrEscapes[pp] <- LowUIRAddress.toFrameOffset off
    | _ ->
      state.StackAddrEscapes.Remove pp |> ignore

  /// Checks if no definition in the function reaches the given use of a
  /// variable at pp, which then holds what it held on entry.
  let readsEntryValue (state: State<_>) pp e =
    let vp = { ProgramPoint = pp; VarKind = VarKind.ofIRExpr e }
    match state.UseDefMap.TryGetValue vp with
    | true, def -> def.ProgramPoint.IsFake
    | false, _ -> false

  /// Checks if the given value, which the statement at pp stores, is what a
  /// register holds on entry, or the low part of it, as MIPS stores a word.
  let isEntryValueOfRegister state pp value =
    match value with
    | Var _ ->
      readsEntryValue state pp value
    | Extract(Operand = Var _ as reg; StartPos = 0) ->
      readsEntryValue state pp reg
    | _ ->
      false

  /// Notes whether the store at pp saves in a stack slot what a register holds
  /// on entry.
  let noteRegisterSave (state: State<_>) pp addr value =
    match state.EvaluateAddressExpr(pp, addr) with
    | AddressDomain.StackAddr off when isEntryValueOfRegister state pp value ->
      state.RegisterSaves[pp] <- LowUIRAddress.toFrameOffset off
    | _ ->
      state.RegisterSaves.Remove pp |> ignore

  let spTransfer (state: State<_>) (stmt, pp) =
    match stmt with
    | Put(Dst = dst; Src = src) ->
      let varKind = VarKind.ofIRExpr dst
      let currConst =
        match varKind with
        | Regular rid when isStackRelatedRegister state.BinHandle rid ->
          state.EvaluateAddressExpr(pp, src)
          |> Some
        | Regular _ ->
          noteStackAddrEscape state pp (state.EvaluateAddressExpr(pp, src))
          AddressDomain.NotAConst |> Some
        | Temporary _ ->
          state.EvaluateAddressExpr(pp, src) |> Some
        | _ ->
          None
      match currConst with
      | None ->
        ()
      | Some currConst ->
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let subState = state.StackPointerSubState
        let prevConst = subState.GetAbsValue vp
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp prevConst currConst
    | Store(Addr = addr; Value = value) ->
      noteRegisterSave state pp addr value
    | _ ->
      ()

  let transferStmtInDomain (state: State<_>) (stmt, pp) =
    match stmt with
    | Put(Dst = dst; Src = src) ->
      let varKind = VarKind.ofIRExpr dst
      let vp = { ProgramPoint = pp; VarKind = varKind }
      let subState = state.DomainSubState
      let prev = subState.GetAbsValue vp
      let curr = state.Scheme.EvalExpr(pp, src)
      let defUseMap = state.DefUseMap
      updateAbsValue subState defUseMap vp prev curr
    | Store(Addr = addr; Value = value) ->
      match tryGetMemoryVarKind state pp addr with
      | Some varKind ->
        let vp = { ProgramPoint = pp; VarKind = varKind }
        let subState = state.DomainSubState
        let prev = subState.GetAbsValue vp
        let curr = state.Scheme.EvalExpr(pp, value)
        let defUseMap = state.DefUseMap
        updateAbsValue subState defUseMap vp prev curr
      | None ->
        ()
    | _ ->
      ()

  /// Gets the stack slots that a call defines at the statement at pp, if it
  /// is the one at which the call lets its callee write them.
  let tryGetClobbersAt (state: State<_>) (pp: ProgramPoint) =
    if pp.CallSite.IsSome then
      match state.StmtOfBBLs.TryGetValue pp with
      | true, (_, v) ->
        match tryGetCallClobbers state v with
        | Some(clobberPP, offsets) when clobberPP = pp -> Some offsets
        | _ -> None
      | false, _ ->
        None
    else
      None

  /// Lets a call define at pp the given stack slots, which its callee may
  /// write, as holding what the analysis cannot tell.
  let transferClobbers (state: State<_>) pp offsets =
    let subState = state.DomainSubState
    let rt = WordSize.toRegType state.BinHandle.ISA.WordSize
    let unknown = state.Scheme.EvalExpr(pp, AST.undef rt "clobbered")
    for off in offsets do
      let vp = { ProgramPoint = pp; VarKind = StackLocal off }
      let prev = subState.GetAbsValue vp
      updateAbsValue subState state.DefUseMap vp prev unknown

  let domainTransfer state (stmt, pp) =
    transferStmtInDomain state (stmt, pp)
    tryGetClobbersAt state pp |> Option.iter (transferClobbers state pp)

  let transferPhi state subState phiInfo defPp =
    phiInfo
    |> Seq.iter (fun (KeyValue(varKind, defs: Dictionary<_, _>)) ->
      let vp = { ProgramPoint = defPp; VarKind = varKind }
      let prev = (subState: ISubState<_>).GetAbsValue vp
      let curr =
        defs.Values |> Seq.fold (fun c (def: VarPoint) ->
          subState.Join(c, subState.GetAbsValue def)) subState.Bottom
      let defUseMap = (state: State<_>).DefUseMap
      updateAbsValue subState defUseMap vp prev curr)

  /// Joins into each phi of a vertex the operand that comes from `pred`.
  let transferPhiFrom state subState phiInfo defPp pred =
    let predPp = getEndPP state pred
    phiInfo
    |> Seq.iter (fun (KeyValue(varKind, defs: Dictionary<_, _>)) ->
      match defs.TryGetValue predPp with
      | true, def ->
        let vp = { ProgramPoint = defPp; VarKind = varKind }
        let prev = (subState: ISubState<_>).GetAbsValue vp
        let curr = subState.GetAbsValue def
        updateAbsValue subState (state: State<_>).DefUseMap vp prev curr
      | false, _ ->
        ())

  let isExecuted state (subState: ISubState<_>) defPp =
    match (state: State<_>).StmtOfBBLs.TryGetValue defPp with
    | false, _ -> false
    | true, (_, v) -> subState.ExecutedVertices.Contains v

  let processDefSite state (subState: ISubState<_>) fnTransfer =
    match subState.DefSiteQueue.TryDequeue() with
    | true, defPp when isExecuted state subState defPp ->
      let stmt, _ = (state: State<_>).StmtOfBBLs[defPp]
      fnTransfer state (stmt, defPp)
    | _ ->
      ()

  /// Tells whether a queued operand is to be joined into its phi. It is not if
  /// the vertex of the phi has yet to run, as the first run of the vertex joins
  /// every operand anyway, or if the chains have replaced the operand after it
  /// was queued, as the phi no longer reads it.
  let isJoinable state subState (phi: VarPoint) def =
    isExecuted state subState phi.ProgramPoint
    && (state: State<_>).DefUseMap[def].Contains phi

  /// Joins a queued operand into its phi.
  let processPhiOperand state (subState: ISubState<_>) =
    match subState.PhiQueue.TryDequeue() with
    | true, (phi, def) when isJoinable state subState phi def ->
      let prev = subState.GetAbsValue phi
      let curr = subState.GetAbsValue def
      updateAbsValue subState (state: State<_>).DefUseMap phi prev curr
    | _ ->
      ()

  /// Executes the phis of `v` on the flow from `src`. The first run joins every
  /// operand, but a later flow brings in only the operand of its own edge, as
  /// every other operand comes through the phi queue whenever it changes. The
  /// phis of a vertex inside an instruction are not on that queue, so they
  /// join every operand on every flow.
  let transferPhis state subState isFirstRun src v =
    match (state: State<_>).PhiInfos.TryGetValue v with
    | false, _ ->
      ()
    | true, phiInfo ->
      let defPp = (v: IVertex<LowUIRBasicBlock>).VData.Internals.PPoint
      match src with
      | NonNull pred when not isFirstRun && defPp.Position = 0 ->
        transferPhiFrom state subState phiInfo defPp pred
      | _ ->
        transferPhi state subState phiInfo defPp

  let transferFlow state subState g src v fnTransfer =
    let isFirstRun = (subState: ISubState<_>).ExecutedVertices.Add v
    (* Execute phis first. *)
    transferPhis state subState isFirstRun src v
    for stmt in state.GetStmtInfos v do fnTransfer state stmt done
    (g: IDiGraph<_, _>).GetSuccs v
    |> Array.map (fun succ -> v, succ)
    |> Array.iter subState.FlowQueue.Enqueue

  let processFlow g state subState fnTransfer =
    match (subState: ISubState<_>).FlowQueue.TryDequeue() with
    | false, _ ->
      ()
    | true, (src, dst) ->
      (* A flow queued before the graph was rebuilt can name a vertex the
         graph no longer holds, and such a flow leads nowhere. *)
      if not <| subState.ExecutedFlows.Add(src, dst) then
        ()
      elif not <| (g: IDiGraph<_, _>).Contains dst then
        ()
      else
        transferFlow state subState g src dst fnTransfer

  let registerPendingVertices state (subState: ISubState<_>) =
    (state: State<_>).EnqueuePendingVertices subState

  let propagateAux g state subState fnTransfer =
    registerPendingVertices state subState
    while not subState.FlowQueue.IsEmpty
          || not subState.DefSiteQueue.IsEmpty
          || subState.PhiQueue.Count > 0 do
      processFlow g state subState fnTransfer
      processDefSite state subState fnTransfer
      processPhiOperand state subState

  let propagateStackPointer g state =
    propagateAux g state state.StackPointerSubState spTransfer

  let propagateDomain g state =
    propagateAux g state state.DomainSubState domainTransfer

  /// Gets the stack slot whose address the given register holds as the call
  /// at a vertex with the given incoming definitions starts.
  let tryGetSlotAtCall (state: State<_>) defs rid =
    match Map.tryFind (Regular rid) defs with
    | Some def ->
      match state.StackAddrEscapes.TryGetValue def.ProgramPoint with
      | true, start -> Some start
      | false, _ -> None
    | None ->
      None

  /// Finds what the given summary says that its function writes through the
  /// pointer in the given register.
  let tryGetExtent writes rid =
    match writes with
    | UnknownPointerWrites -> Some AnyBytes
    | PointerWritesOf extents -> Map.tryFind rid extents

  /// Gets the offsets from lo up to hi that a callee writes through a pointer
  /// to the stack slot at start, as the given extent tells. An object whose
  /// size nothing tells runs up to the first slot above it in which the
  /// function saves a register, or else up to the stack pointer on entry. The
  /// address of a slot that saves a register hands on no object, as a frame
  /// pointer of Thumb code points there.
  let tryGetWrittenRange (saves: SortedSet<int>) start extent =
    match extent with
    | WrittenBytes(lo, hi) ->
      Some(start + lo, start + hi)
    | AnyBytes when start < 0 && not (saves.Contains start) ->
      let above = saves.GetViewBetween(start + 1, 0)
      Some(start, if above.Count > 0 then above.Min else 0)
    | AnyBytes ->
      None

  /// Computes the offsets of the stack slots that the callee of the call at
  /// the given vertex may write, among those that the function reads: what
  /// its summary says that it writes through each argument register that
  /// holds the address of a slot as the call starts.
  let computeCallClobbers (state: State<_>) saves v =
    let summary = (v: IVertex<LowUIRBasicBlock>).VData.Internals.AbstractContent
    let defs =
      match state.PerVertexIncomingDefs.TryGetValue v with
      | true, defs -> defs
      | false, _ -> Map.empty
    let clobbered = SortedSet<int>()
    for rid in state.ArgRegisters do
      tryGetSlotAtCall state defs rid
      |> Option.bind (fun start ->
        tryGetExtent summary.PointerWrites rid
        |> Option.bind (tryGetWrittenRange saves start))
      |> Option.iter (fun (lo, hi) ->
        if lo < hi then
          clobbered.UnionWith(state.UsedStackOffsets.GetViewBetween(lo, hi - 1))
        else
          ())
    Seq.toArray clobbered

  /// Updates the stack slots that each call may write, once the stack pointer
  /// propagation has found the slots whose addresses the function puts in
  /// registers. A call whose slots change defines new ones, so it is pending
  /// again, as a new vertex would be, and writes its slots again if it has
  /// run.
  let updateCallClobbers g (state: State<_>) =
    noteUsedVarKinds state
    let saves = SortedSet(state.RegisterSaves.Values)
    for v in (g: IDiGraph<LowUIRBasicBlock, _>).Vertices do
      if v.VData.Internals.IsAbstract then
        let offsets = computeCallClobbers state saves v
        match state.CallClobbers.TryGetValue v with
        | true, prev when prev = offsets ->
          ()
        | false, _ when Array.isEmpty offsets ->
          ()
        | _ ->
          state.CallClobbers[v] <- offsets
          state.MarkVertexAsPending v
          tryGetCallClobbers state v
          |> Option.iter (fst >> state.DomainSubState.DefSiteQueue.Enqueue)
      else
        ()

end (* end of AnalysisCore *)

/// Computes the data flow incrementally.
[<CompiledName "Compute">]
let compute g (state: State<_>) =
  let df = Dominance.CooperDominanceFrontier()
  let dom = Dominance.LengauerTarjanDominance.create g df
  removeInvalidChains state
  calculateChains g state dom
  propagateStackPointer g state
  (* Stack pointer propagation lets us recognize stack slot reads that the
     first pass could not, so the memoized used variable kinds are stale. *)
  state.UsedVarKindsMemo.Clear()
  updateCallClobbers g state
  calculateChains g state dom
  propagateDomain g state
  state.ClearPendingVertices()
  state
