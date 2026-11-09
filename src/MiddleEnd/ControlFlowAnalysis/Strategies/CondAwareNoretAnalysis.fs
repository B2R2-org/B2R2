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

open System.Collections.Generic
open System.Runtime.InteropServices
open B2R2
open B2R2.ABI
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open type UntouchedValueDomain.UntouchedTag

[<AutoOpen>]
module private CondAwareNoretAnalysisHelper =
  let hasNonZeroInRegister st rid =
    match (st: ConcState).TryGetReg rid with
    | Def bv -> not bv.IsZero
    | _ -> false

  let tryGetStackPointer (hdl: BinHandle) (st: ConcState) =
    hdl.RegisterFactory.StackPointer
    |> Option.bind (fun rid ->
      match st.TryGetReg rid with
      | Def sp -> Some sp
      | _ -> None)

  let hasNonZeroOnStack (hdl: BinHandle) st (layout: StackArgLayout) =
    match tryGetStackPointer hdl st with
    | Some sp ->
      let p = sp + BitVector(layout.FirstOffset, sp.Length)
      let rt = RegType.fromByteWidth layout.SlotSize
      match Memory.read (p.ToUInt64()) hdl.ISA.Endian rt st.Memory with
      | Ok v -> not v.IsZero
      | Error _ -> false
    | None ->
      false

  /// Locally analyzes the given basic blocks, through which the control runs
  /// in turn, and checks if the argument at the given location, which the call
  /// ending the last block passes, is non-zero.
  let hasNonZero hdl blks loc =
    let st = CFGEvaluator.evalBlocksFromScratch hdl blks
    match loc with
    | ArgLocation.Reg rid -> hasNonZeroInRegister st rid
    | ArgLocation.Stack layout -> hasNonZeroOnStack hdl st layout
    | ArgLocation.RegPair _ -> false

  /// Checks if every predecessor of the given caller, none of which may be a
  /// call it returns from, sets the argument at the given location to a
  /// non-zero one that the call ending the caller passes.
  let hasNonZeroFromPreds hdl (g: IDiGraph<_, _>) caller loc =
    let preds = g.GetPreds caller
    not (Array.isEmpty preds)
    && preds |> Array.forall (fun (pred: IVertex<LowUIRBasicBlock>) ->
      not pred.VData.Internals.IsAbstract
      && hasNonZero hdl [| pred; caller |] loc)

  /// Represents what holds a value within the statements of a vertex: a
  /// register, or a temporary of the instruction that they belong to.
  [<RequireQualifiedAccess>]
  type Holder =
    | Reg of RegisterID
    | Temp of int

  let tryHolderOf e =
    match e with
    | LowUIR.Var(RegisterID = r) -> Some(Holder.Reg r)
    | LowUIR.TempVar(Index = i) -> Some(Holder.Temp i)
    | _ -> None

  /// Follows the given holder of a value back from the i-th of the given
  /// statements to what holds the value before the first one, through the
  /// copies that pass it on, unless a statement computes the value.
  let rec tryTraceCopy (stmts: LowUIR.Stmt[]) i holder =
    if i < 0 then
      Some holder
    else
      match stmts[i] with
      | LowUIR.Put(Dst = dst; Src = src) when tryHolderOf dst = Some holder ->
        tryHolderOf src |> Option.bind (tryTraceCopy stmts (i - 1))
      | _ ->
        tryTraceCopy stmts (i - 1) holder

  /// Follows the given holder of a value at the end of the given vertex back
  /// to what holds the value at its start, unless the vertex computes it.
  let tryTraceBack (v: IVertex<LowUIRBasicBlock>) holder =
    let stmts = v.VData.Internals.LiftedInstructions |> Array.collect _.Stmts
    tryTraceCopy stmts (stmts.Length - 1) holder

  /// Checks if the given holder holds a non-zero value at the end of the given
  /// vertex, whatever the control brings into it.
  let isNonZeroAtEnd hdl v holder =
    let st = CFGEvaluator.evalBlockWith hdl [||] v
    let value =
      match holder with
      | Holder.Reg r -> st.TryGetReg r
      | Holder.Temp i -> st.TryGetTmp i
    match value with
    | Def bv -> not bv.IsZero
    | _ -> false

  /// Tells whether the given vertex starts past the first statement of an
  /// instruction, where only the conditional jumps within the instruction
  /// lead, so that no other code may come to enter it.
  let isWithinInstruction (v: IVertex<LowUIRBasicBlock>) =
    v.VData.Internals.PPoint.Position > 0

  /// Returns which way a conditional jump goes as the control takes an edge of
  /// the given kind, if the edge stands for one.
  let tryGetOutcome kind =
    match kind with
    | IntraCJmpTrueEdge | InterCJmpTrueEdge -> Some true
    | IntraCJmpFalseEdge | InterCJmpFalseEdge -> Some false
    | _ -> None

  /// Gets the condition of the conditional jump that ends the given vertex.
  let tryGetJumpCondition (v: IVertex<LowUIRBasicBlock>) =
    (Array.last v.VData.Internals.LiftedInstructions).Stmts
    |> Array.rev
    |> Array.tryPick (fun stmt ->
      match stmt with
      | LowUIR.CJmp(Cond = c) | LowUIR.InterCJmp(Cond = c) -> Some c
      | _ -> None)

  /// Checks if the conditional jump that ends the given vertex would not go the
  /// given way, were the value that the given holder holds at the end of the
  /// vertex zero: the value comes from a register that the vertex compares, as
  /// when a conditional move turns any value up to one into one.
  let isCutOnZero hdl u holder outcome =
    match tryTraceBack u holder, tryGetJumpCondition u with
    | Some(Holder.Reg r), Some cond ->
      let zero = BitVector.Zero((hdl: BinHandle).RegisterFactory.GetRegType r)
      let st = CFGEvaluator.evalBlockWith hdl [| r, zero |] u
      match SafeEvaluator.evalExpr st cond with
      | Ok(Def taken) -> taken.IsZero = outcome
      | _ -> false
    | _ ->
      false

  /// The most vertices that the paths to a call may cross back to find what
  /// sets the argument that the call passes.
  let [<Literal>] MaxPathLength = 16

  /// Checks if the value that the given holder holds at the end of the given
  /// vertex is non-zero on every path to it, crossing back at most the given
  /// number of vertices. A path ends where a vertex computes the value or a
  /// guard would turn a zero one away. Only the caller of the call that passes
  /// the value and the parts of an instruction past its conditional jumps let
  /// a path go further back, as no other code may come to enter the parts,
  /// while the caller is judged again once it gains a predecessor.
  let rec isNonZeroOnPaths hdl g caller fuel v holder =
    match tryTraceBack v holder with
    | None ->
      isNonZeroAtEnd hdl v holder
    | Some start when fuel > 0 && (v = caller || isWithinInstruction v) ->
      let edges = (g: IDiGraph<LowUIRBasicBlock, _>).GetPredEdges v
      not (Array.isEmpty edges)
      && edges |> Array.forall (isNonZeroAcross hdl g caller (fuel - 1) start)
    | Some _ ->
      false

  and isNonZeroAcross hdl g caller fuel holder (e: Edge<_, _>) =
    let u = e.First
    not u.VData.Internals.IsAbstract
    && (tryGetOutcome e.Label |> Option.exists (isCutOnZero hdl u holder)
        || isNonZeroOnPaths hdl g caller fuel u holder)

  /// Checks if every path to the call ending the given caller sets the
  /// argument at the given location to a non-zero one or passes a guard that a
  /// zero one would not pass, such as the comparison that decides whether a
  /// conditional move turns the argument into one.
  let passesNonZeroOnGuards hdl g caller loc =
    match loc with
    | ArgLocation.Reg rid ->
      isNonZeroOnPaths hdl g caller MaxPathLength caller (Holder.Reg rid)
    | _ ->
      false

  [<return: Struct>]
  let (|Zero|_|) e =
    match e with
    | LowUIR.Num(Value = n) when n.IsZero -> ValueSome()
    | _ -> ValueNone

  /// Matches the difference that ARM computes to compare one operand with
  /// another, adding the complement of the other and one to the first, and
  /// gives the two operands.
  [<return: Struct>]
  let (|SubByComplement|_|) e =
    match e with
    | LowUIR.BinOp(Op = BinOpType.ADD
                   Left = LowUIR.BinOp(Op = BinOpType.ADD
                                       Left = e1
                                       Right = LowUIR.UnOp(Op = UnOpType.NOT
                                                           Operand = e2))
                   Right = LowUIR.Num(Value = n)) when n.IsOne ->
      ValueSome(e1, e2)
    | _ ->
      ValueNone

/// Represents a non-returning function identification strategy that can check
/// conditionally non-returning functions. We currently support only those
/// simple patterns that are handled by compilers, but we may have to extend
/// this as the compilers evolve.
type CondAwareNoretAnalysis([<Optional; DefaultParameterValue(true)>] strict) =
  /// Default value used for unknown non-returning status.
  let defaultStatus = if strict then NoRet else NotNoRet

  let meet a b =
    match a, b with
    | _ when a = b -> a
    | UnknownNoRet, _ -> b
    | _, UnknownNoRet -> a
    | NotNoRet, _ -> a
    | _, NotNoRet -> b
    | NoRet, ConditionalNoRet _ -> b
    | ConditionalNoRet _, NoRet -> a
    (* Returning when one argument is zero on some paths and when another is
       on others is returning on no single condition. *)
    | ConditionalNoRet _, ConditionalNoRet _ -> NotNoRet
    | _ -> Terminator.impossible ()

  let tryGetValue (state: LowUIRSparseDataFlow.State<_>) v varKind =
    let defs = state.PerVertexIncomingDefs[v]
    match Map.tryFind varKind defs with
    | Some defVp -> state.GetAbsValue defVp |> Some
    | None -> None

  /// Gets the location of the argument that the given register holds on
  /// entry. A callee preserves none of the registers it takes arguments in,
  /// whichever convention a compiler picks for a function of its own.
  let tryGetRegArgLocation (hdl: BinHandle) rid =
    let cc = hdl.Conventions.Calling
    if cc.IsCalleeSaved rid || hdl.RegisterFactory.IsStackPointer rid then None
    else Some(ArgLocation.Reg rid)

  /// Gets the location of the argument that lies at the given offset from the
  /// stack pointer on entry, if the calling convention passes arguments there.
  let tryGetStackArgLocation (hdl: BinHandle) offset =
    match Array.tryLast hdl.Conventions.Calling.IntArgs with
    | Some(ArgLocation.Stack layout) when offset >= layout.FirstOffset ->
      Some(ArgLocation.Stack { layout with FirstOffset = offset })
    | _ ->
      None

  /// Gets the location of the argument that the function takes in the given
  /// variable of the IR-level data flow, whose stack offsets grow upward from
  /// the stack pointer on entry.
  let tryGetArgLocationFromIR hdl varKind =
    match varKind with
    | Regular rid -> tryGetRegArgLocation hdl rid
    | StackLocal offset -> tryGetStackArgLocation hdl offset
    | _ -> None

  let isStackPointer (hdl: BinHandle) dst =
    match dst with
    | LowUIR.Var(RegisterID = rid) -> hdl.RegisterFactory.IsStackPointer rid
    | _ -> false

  /// Gets the stack pointer on entry to the callee of the given abstract
  /// vertex, which the summary of the callee reads to adjust it.
  let tryGetCalleeEntrySP hdl (state: LowUIRSparseDataFlow.State<_>) absV =
    state.GetStmtInfos absV
    |> Array.tryPick (fun (stmt, pp) ->
      match stmt with
      | LowUIR.Put(Dst = dst) when isStackPointer hdl dst ->
        match state.EvaluateAddressExpr(pp, dst) with
        | AddressDomain.StackAddr sp -> Some sp
        | _ -> None
      | _ ->
        None)

  /// Finds the variable in which the caller of the given abstract vertex
  /// passes the callee its argument at the given location.
  let tryGetPassingVarFromIR hdl state absV loc =
    match loc with
    | ArgLocation.Reg rid ->
      Some(Regular rid)
    | ArgLocation.Stack layout ->
      tryGetCalleeEntrySP hdl state absV
      |> Option.map (fun sp ->
        let offset = LowUIRAddress.toFrameOffset sp
        StackLocal(offset + layout.FirstOffset))
    | ArgLocation.RegPair _ ->
      None

  /// Finds where the caller of the given abstract vertex takes the argument
  /// that it passes the callee at the given location, if it passes on one of
  /// its own arguments untouched.
  let tryGetConnectedArgumentFromIRCFG hdl state absV loc =
    tryGetPassingVarFromIR hdl state absV loc
    |> Option.bind (fun varKind ->
      match tryGetValue state absV varKind with
      | Some(UntouchedValueDomain.Untouched(RegisterTag origin)) ->
        tryGetArgLocationFromIR hdl origin
      | Some _ ->
        None
      | None ->
        (* With no definition reaching the callee, the caller passes on what
           it took in the same variable. *)
        tryGetArgLocationFromIR hdl varKind)

  /// Collects the abstract vertices of the calls to conditionally
  /// non-returning functions, each with the location of the argument that
  /// decides whether its callee returns.
  let collectCondNoRetCallees (ctx: CFGBuildingContext<_, _>) =
    ctx.IntraCallTable.Callees
    |> Seq.fold (fun acc (KeyValue(cs, calleeKind)) ->
      match calleeKind with
      | RegularCallee callee ->
        if ctx.FunctionAddress = callee then acc
        else ProgramPoint(cs, callee, 0) :: acc
      | IndirectCallees callees ->
        Set.fold (fun acc c -> ProgramPoint(cs, c, 0) :: acc) acc callees
      | _ ->
        acc) []
    |> List.choose (fun pp ->
      let absV = ctx.Vertices[pp]
      match absV.VData.Internals.AbstractContent.ReturningStatus with
      | ConditionalNoRet loc -> Some(pp, absV, loc)
      | _ -> None)

  /// Makes a function that finds where the caller takes the argument that it
  /// passes at the call to a conditionally non-returning function which the
  /// given abstract vertex stands for, if it passes on one of its own. The
  /// given tryConnect finds that for a call, once at most, so that the data
  /// flow it needs is computed only for a call that matters.
  let connectArguments ctx tryConnect =
    let callerLocs = Dictionary()
    for pp, absV, loc in collectCondNoRetCallees ctx do
      callerLocs[absV] <- lazy tryConnect pp absV loc
    fun absV ->
      match callerLocs.TryGetValue absV with
      | true, callerLoc -> callerLoc.Value
      | false, _ -> None

  let getLazyIRState g (uva: UntouchedValueAnalysis) =
    lazy ((uva :> IDataFlowComputable<_, _, _>).Compute g |> ignore
          uva.State)

  let connectArgumentsInIRCFG ctx (state: Lazy<_>) =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    connectArguments ctx (fun _ absV loc ->
      tryGetConnectedArgumentFromIRCFG hdl state.Value absV loc)

  let findSSAVertexByAddr (ssa: SSACFG) addr =
    ssa.FindVertexBy(fun v ->
      if v.VData.Internals.IsAbstract then false
      else v.VData.Internals.Range.IsIncluding addr)

  let tryGetFrameDistance (ctx: CFGBuildingContext<_, _>) callSite =
    match ctx.IntraCallTable.TryGetFrameDistance callSite with
    | true, dist -> Some dist
    | false, _ -> None

  /// Finds the variable in which the caller passes the callee its argument at
  /// the given location, where the frame of the callee lies at the given
  /// distance below the stack pointer of the caller on entry.
  let tryGetPassingVarFromSSA (hdl: BinHandle) frameDist loc =
    match loc, frameDist with
    | ArgLocation.Reg rid, _ ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let name = hdl.RegisterFactory.GetRegisterName rid
      Some(SSA.RegVar(rt, rid, name))
    | ArgLocation.Stack layout, Some dist ->
      let rt = RegType.fromByteWidth layout.SlotSize
      Some(SSA.StackVar(rt, dist - layout.FirstOffset))
    | _ ->
      None

  /// Gets the location of the argument that the function takes in the given
  /// variable of the SSA-level data flow, whose stack offsets grow downward
  /// from the stack pointer on entry.
  let tryGetArgLocationFromSSA hdl varKind =
    match varKind with
    | Regular rid -> tryGetRegArgLocation hdl rid
    | StackLocal offset -> tryGetStackArgLocation hdl (-offset)
    | _ -> None

  let tryGetConnectedArgumentFromSSACFG ctx (ssa: SSACFG) dom state pp loc =
    let callSite = (pp: ProgramPoint).CallSite |> Option.get
    let callerSSAV = findSSAVertexByAddr ssa callSite.CallSiteAddress
    let absSSAV = ssa.GetSuccs callerSSAV |> Seq.exactlyOne
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    let frameDist = tryGetFrameDistance ctx callSite
    tryGetPassingVarFromSSA hdl frameDist loc
    |> Option.bind (fun varKind ->
      match SSACFG.findReachingDef dom absSSAV varKind with
      | Some(SSA.Def(var, _))
      | Some(SSA.Phi(var, _)) ->
        match (state: SSASparseDataFlow.State<_>).GetRegValue var with
        | UntouchedValueDomain.Untouched(RegisterTag origin) ->
          tryGetArgLocationFromSSA hdl origin
        | _ ->
          None
      | Some _ ->
        None
      | None ->
        (* With no definition reaching the callee, the caller passes on what
           it took in the same variable. *)
        tryGetArgLocationFromSSA hdl (VarKind.ofSSAVarKind varKind))

  let getLazySSAState g (uva: SSAUntouchedValueAnalysis) =
    lazy ((uva :> IDataFlowComputable<_, _, _>).Compute g |> ignore
          uva.State)

  let connectArgumentsInSSACFG ctx ssaCFG dom =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    let state = SSAUntouchedValueAnalysis hdl |> getLazySSAState ssaCFG
    connectArguments ctx (fun pp _ loc ->
      tryGetConnectedArgumentFromSSACFG ctx ssaCFG dom state.Value pp loc)

  /// Finds where the function takes the argument that it passes on at a call
  /// to a conditionally non-returning function dominating the given vertex.
  let tryFindCondNoRetDom (dom: IForwardDominance<_>) tryGetCallerLoc v =
    (* When there are two or more conditionally returning (and dominating)
       abstract vertices, we assume that they will be referring to the same
       callee. *)
    dom.Dominators v |> Seq.tryPick tryGetCallerLoc

  /// Gets the status of the given exit, through which the function returns
  /// unless a call to a conditionally non-returning function dominates it.
  /// Leaves to judgeReturn an exit that no such call dominates.
  let getStatusFromDominators dom tryGetCallerLoc judgeReturn exit =
    match tryFindCondNoRetDom dom tryGetCallerLoc exit with
    | Some callerLoc -> ConditionalNoRet callerLoc
    | None -> judgeReturn exit

  /// Checks if the given exit vertex has a corrupted stack pointer value before
  /// executing the return instruction. This means we cannot statically decide
  /// whether the return instruction will jump to the caller or not.
  let hasUndecidableReturnTarget (ctx: CFGBuildingContext<_, _>) v =
    let hdl = ctx.BinHandle
    let st = CFGEvaluator.evalBlockFromScratch hdl v
    let rid = hdl.RegisterFactory.StackPointer.Value
    match st.TryGetReg(rid) with
    | Def(_) ->
      false
    | _ ->
#if CFGDEBUG
      let blkAddr = v.VData.Internals.PPoint.Address
      let fnAddr = ctx.FunctionAddress
      dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
      <| $"[*] Undecidable return: {blkAddr:x} @ {fnAddr}"
#endif
      true

  let isTailCall (g: IDiGraph<_, _>) v =
    g.GetPredEdges v |> Array.exists (fun e -> e.Label = TailCallEdge)

  /// Judges whether the function returns through the given abstract vertex,
  /// which exits the function by calling a conditionally non-returning one
  /// that takes the argument deciding it at the given location. A call exits
  /// only once it is found to pass a non-zero argument, but a tail call
  /// returns for the function itself: on the same condition if the function
  /// passes on one of its own arguments.
  let judgeConditionalExit ctx tryGetCallerLoc v loc =
    let g = (ctx: CFGBuildingContext<_, _>).CFG
    if isTailCall g v then
      match tryGetCallerLoc v with
      | Some callerLoc ->
        ConditionalNoRet callerLoc
      | None ->
        let caller = g.GetPreds v |> Seq.exactlyOne
        if hasNonZero ctx.BinHandle [| caller |] loc then NoRet else NotNoRet
    else
      NoRet

  /// Judges whether the function returns through the given exit vertex,
  /// leaving to judgeReturn an exit through which it returns unless a call to
  /// a conditionally non-returning function dominates the exit.
  let judgeExit ctx dom tryGetCallerLoc judgeReturn (v: IVertex<_>) =
    let vData = v.VData :> ILowUIRBasicBlock
    if not vData.IsAbstract then
      if vData.LastInstruction.IsRET then
        if hasUndecidableReturnTarget ctx v then
          NoRet
        else
          getStatusFromDominators dom tryGetCallerLoc judgeReturn v
      elif vData.LastInstruction.IsIndirectBranch then
        NotNoRet
      else
        UnknownNoRet
    else
      match vData.AbstractContent.ReturningStatus with
      | ConditionalNoRet loc ->
        judgeConditionalExit ctx tryGetCallerLoc v loc
      | NotNoRet ->
        getStatusFromDominators dom tryGetCallerLoc judgeReturn v
      | status ->
        status

  /// Meets the statuses that the given judge finds for the given exits, until
  /// the function turns out to return.
  let rec meetExits judge status exits =
    match exits with
    | v :: rest when status <> NotNoRet ->
      meetExits judge (meet status (judge v)) rest
    | _ ->
      status

  /// Gets the condition of the conditional jump that ends the given vertex,
  /// whether it jumps out of its instruction or within it, along with the
  /// statements of the vertex, which tell what it reads.
  let tryGetCondition (state: LowUIRSparseDataFlow.State<_>) v =
    if (v: IVertex<LowUIRBasicBlock>).VData.Internals.IsAbstract then
      None
    else
      let stmts = state.GetStmtInfos v
      match fst stmts[stmts.Length - 1] with
      | LowUIR.InterCJmp(Cond = c; TrueTarget = t; FalseTarget = f)
      | LowUIR.CJmp(Cond = c; TrueTarget = t; FalseTarget = f) when t <> f ->
        Some(stmts, c)
      | _ ->
        None

  /// Finds the statement before the i-th of the given ones that defines the
  /// given variable, along with its index and what it defines the variable as.
  let rec tryFindLocalDef (stmts: (LowUIR.Stmt * ProgramPoint)[]) i var =
    if i = 0 then
      None
    else
      match fst stmts[i - 1] with
      | LowUIR.Put(Dst = dst; Src = src) when dst = var -> Some(i - 1, src)
      | _ -> tryFindLocalDef stmts (i - 1) var

  /// Checks if the given expression, which the i-th of the given statements
  /// reads, is zero, following the definitions in the block.
  let rec isLocallyZero stmts i e =
    match e with
    | Zero ->
      true
    | LowUIR.Var _ | LowUIR.TempVar _ ->
      match tryFindLocalDef stmts i e with
      | Some(j, src) -> isLocallyZero stmts j src
      | None -> false
    | _ ->
      false

  /// Finds what the given expression, which the i-th of the given statements
  /// of a block reads, tests against zero: a register or memory read, along
  /// with the program point at which it is read, and whether the expression
  /// is non-zero exactly when the read is zero. Only those tests that tell
  /// zero from any other value count, and the definitions in the block are
  /// followed.
  let rec tryFindZeroTest stmts i e =
    let find = tryFindZeroTest stmts i
    let negate = Option.map (fun (read, pp, onZero) -> read, pp, not onZero)
    match e with
    | LowUIR.Var _ | LowUIR.TempVar _ ->
      match tryFindLocalDef stmts i e with
      | Some(j, src) -> tryFindZeroTest stmts j src
      | None -> Some(e, snd stmts[i], false)
    | LowUIR.Load _ ->
      Some(e, snd stmts[i], false)
    | LowUIR.RelOp(Op = RelOpType.EQ; Left = e; Right = Zero)
    | LowUIR.RelOp(Op = RelOpType.EQ; Left = Zero; Right = e) ->
      find e |> negate
    | LowUIR.RelOp(Op = RelOpType.NEQ; Left = e; Right = Zero)
    | LowUIR.RelOp(Op = RelOpType.NEQ; Left = Zero; Right = e) ->
      find e
    | LowUIR.UnOp(Op = UnOpType.NOT; Operand = e)
      when LowUIR.Expr.typeOf e = 1<rt> ->
      find e |> negate
    (* Thumb tells CBNZ from CBZ by xoring the test of the register with one
       rather than zero. *)
    | LowUIR.BinOp(Op = BinOpType.XOR; Left = LowUIR.Num(Value = n); Right = e)
    | LowUIR.BinOp(Op = BinOpType.XOR; Left = e; Right = LowUIR.Num(Value = n))
      when LowUIR.Expr.typeOf e = 1<rt> ->
      if n.IsZero then find e else find e |> negate
    | LowUIR.BinOp(Op = (BinOpType.AND | BinOpType.OR); Left = e1; Right = e2)
      when e1 = e2 ->
      find e1
    | LowUIR.BinOp(Op = BinOpType.SUB; Left = e; Right = Zero) ->
      find e
    (* ARM subtracts zero to compare with it by adding its complement and one,
       which leaves what it compares. *)
    | SubByComplement(e, z) when isLocallyZero stmts i z ->
      find e
    (* The low part of a register holds an argument narrower than the
       register, such as an int in RDI, which is what a test of it tells. *)
    | LowUIR.Extract(Operand = e; StartPos = 0)
    | LowUIR.Cast(Kind = (CastKind.ZeroExt | CastKind.SignExt); Operand = e) ->
      find e
    | _ ->
      None

  /// Gets the location of the argument that the given read at the given
  /// program point gets untouched since the entry.
  let tryGetUntouchedArgument hdl state pp read =
    match (state: LowUIRSparseDataFlow.State<_>).Scheme.EvalExpr(pp, read) with
    | UntouchedValueDomain.Untouched(RegisterTag origin) ->
      tryGetArgLocationFromIR hdl origin
    | _ ->
      None

  /// Finds the definition that alone reaches the given read of a variable at
  /// the given program point from another block, as the statements of that
  /// block, the index of the definition among them, and what it defines the
  /// variable as. Where several definitions meet, a phi defines the variable
  /// at the start of its block, where no statement defines anything.
  let tryFindOuterDef (state: LowUIRSparseDataFlow.State<_>) pp read =
    let vp = { ProgramPoint = pp; VarKind = VarKind.ofIRExpr read }
    match state.UseDefMap.TryGetValue vp with
    | true, defVp ->
      match state.StmtOfBBLs.TryGetValue defVp.ProgramPoint with
      | true, (LowUIR.Put(Src = src), v) ->
        let stmts = state.GetStmtInfos v
        let i = stmts |> Array.findIndex (fun (_, p) -> p = defVp.ProgramPoint)
        Some(stmts, i, src)
      | _ ->
        None
    | false, _ ->
      None

  /// Traces the given test of a read at a program point back to the argument
  /// that the function gets untouched, through the definitions that reach the
  /// read from other blocks, as when a conditional instruction of ARM parts a
  /// comparison from the instruction that reads its flag. Gives the argument
  /// along with whether the test holds exactly when the argument is zero.
  let rec tryTraceZeroTest hdl state (read, pp, onZero) =
    match tryGetUntouchedArgument hdl state pp read, read with
    | Some loc, _ ->
      Some(loc, onZero)
    | None, (LowUIR.Var _ | LowUIR.TempVar _) ->
      tryFindOuterDef state pp read
      |> Option.bind (fun (stmts, i, src) -> tryFindZeroTest stmts i src)
      |> Option.bind (fun (read, pp, onDefZero) ->
        tryTraceZeroTest hdl state (read, pp, onZero <> onDefZero))
    | None, _ ->
      None

  /// Finds the argument that the given guard finds zero whenever it lets a
  /// path through. The data flow that tells whether the guard tests one is
  /// computed only once the guard tests something that may be one.
  let tryGetZeroOnGuard hdl (state: Lazy<_>) ((stmts, cond), outcome) =
    match tryFindZeroTest stmts (Array.length stmts - 1) cond with
    | Some test ->
      match tryTraceZeroTest hdl state.Value test with
      | Some(loc, onZero) when onZero = outcome -> Some loc
      | _ -> None
    | None ->
      None

  /// Finds the argument that a guard on every path to the given vertex finds
  /// zero, reading the statements that the given analysis lifts and the data
  /// flow that it computes into the given state.
  let tryFindZeroArgument ctx (uva: UntouchedValueAnalysis) state dom v =
    let g = (ctx: CFGBuildingContext<_, _>).CFG
    Guard.collectDominating (tryGetCondition uva.State) g dom v
    |> List.tryPick (tryGetZeroOnGuard ctx.BinHandle state)

  /// Judges whether the function returns through the given exit, which no
  /// call to a conditionally non-returning function dominates: if the exit is
  /// reached only when an argument is zero, the function never returns while
  /// the argument is non-zero.
  let judgeReturn ctx uva state dom v =
    match tryFindZeroArgument ctx uva state dom v with
    | Some loc -> ConditionalNoRet loc
    | None -> NotNoRet

  let analyze (ctx: CFGBuildingContext<_, _>) uva state tryGetCallerLoc =
    let df = Dominance.CooperDominanceFrontier()
    let dom = Dominance.LengauerTarjanDominance.create ctx.CFG df
    let returns = List()
    let deferReturn v =
      returns.Add v
      UnknownNoRet
    let judge = judgeExit ctx dom tryGetCallerLoc deferReturn
    let status = meetExits judge UnknownNoRet (List.ofArray ctx.CFG.Exits)
    (* A return that only a zero argument reaches keeps the function from
       returning on a non-zero one only if another exit never returns, so the
       data flow that tells it waits until one does. *)
    let judgeReturn =
      match status with
      | NoRet | ConditionalNoRet _ -> judgeReturn ctx uva state dom
      | _ -> fun _ -> NotNoRet
    meetExits judgeReturn status (List.ofSeq returns)

  (* Non-returning function identification for IR-based CFG. *)
  interface ICFGAnalysis<unit -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
      fun () ->
        let uva = UntouchedValueAnalysis(ctx.BinHandle, ctx.CFG.Vertices)
        let state = getLazyIRState ctx.CFG uva
        let tryGetCallerLoc = connectArgumentsInIRCFG ctx state
        match analyze ctx uva state tryGetCallerLoc with
        | UnknownNoRet -> ctx.NonReturningStatus <- defaultStatus
        | status -> ctx.NonReturningStatus <- status
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
        <| $"{ctx.FunctionAddress:x}: {ctx.NonReturningStatus}"
#endif

  (* Non-returning function identification for SSA-based CFG. *)
  interface ICFGAnalysis<SSACFGWithDominance -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
      fun (r: SSACFGWithDominance) ->
        let uva = UntouchedValueAnalysis(ctx.BinHandle, ctx.CFG.Vertices)
        let state = getLazyIRState ctx.CFG uva
        let tryGetCallerLoc = connectArgumentsInSSACFG ctx r.Graph r.Dominance
        match analyze ctx uva state tryGetCallerLoc with
        | UnknownNoRet -> ctx.NonReturningStatus <- defaultStatus
        | status -> ctx.NonReturningStatus <- status
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
        <| $"{ctx.FunctionAddress:x}: {ctx.NonReturningStatus} (w/ SSA)"
#endif

module CondAwareNoretAnalysis =
  /// Locally analyzes the given basic block and checks if the argument at the
  /// given location, which the call ending the block passes, is non-zero.
  let hasNonZero hdl caller loc =
    CondAwareNoretAnalysisHelper.hasNonZero hdl [| caller |] loc

  /// Checks if the call ending the given caller in the given CFG passes a
  /// non-zero argument at the given location, however the control reaches it.
  /// A caller that sets no argument of its own leaves it to its predecessors,
  /// as when a compiler merges the calls of several paths into one, or to a
  /// guard that a zero argument would not pass, so the answer holds only while
  /// no other predecessor joins them.
  let passesNonZero hdl g caller loc =
    CondAwareNoretAnalysisHelper.hasNonZero hdl [| caller |] loc
    || CondAwareNoretAnalysisHelper.hasNonZeroFromPreds hdl g caller loc
    || CondAwareNoretAnalysisHelper.passesNonZeroOnGuards hdl g caller loc
