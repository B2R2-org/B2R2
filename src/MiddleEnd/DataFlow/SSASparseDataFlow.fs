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

/// Provides SSA-based sparse data flow analysis framework, which is based on
/// the idea of sparse conditional constant propagation algorithm by Wegman et
/// al.
module B2R2.MiddleEnd.DataFlow.SSASparseDataFlow

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Represents an edge of an SSA CFG as the pair of its endpoints. The source
/// is absent for the edge into a root, which comes from no vertex at all.
type private SSAFlowEdge =
  (IVertex<SSABasicBlock> | null) * IVertex<SSABasicBlock>

/// Represents an SSA-variable-based data flow state.
type State<'Lattice when 'Lattice: equality>
  public(hdl: BinHandle,
         lattice: ILattice<'Lattice>,
         scheme: IScheme<'Lattice>) =

  let mutable ssaEdges: SSAEdges | null = null

  /// Represents register values per SSA variable.
  let regValues = Dictionary<Variable, 'Lattice>()

  /// Represents memory values for constant cells. Each SSA memory instance has
  /// its own mapping because SSA expressions do not track data dependencies
  /// between memory cells. That is, memory cells (even though their addresses
  /// are constant) do not have an SSA edge to its dependent memory cells.
  let memValues = Dictionary<int, Map<Addr, 'Lattice>>()

  /// Holds the executable edges from a vertex to another. If there is no
  /// element in this set, the edge is not executable.
  let executableEdges = HashSet<SSAFlowEdge>()

  /// Holds the executed edges from a vertex to another.
  let executedEdges = HashSet<SSAFlowEdge>()

  /// Holds the worklist of blocks.
  let flowWorkList = Queue<SSAFlowEdge>()

  /// Represents a worklist for SSA statements, this stack stores a list of def
  /// variables, and we will use SSAEdges to find all related SSA statements.
  let ssaWorkList = UniqueQueue<Variable>()

  let markExecutable src dst =
    if executableEdges.Add(src, dst) then flowWorkList.Enqueue(src, dst) else ()

  let isMemVar (var: Variable) =
    match var.Kind with
    | MemVar -> true
    | _ -> false

  let defaultRegType = WordSize.toRegType hdl.ISA.WordSize

  let isAligned rt addr =
    let align = RegType.toByteWidth rt |> uint64
    (rt = defaultRegType) && (addr % align = 0UL)

  /// Gets the scheme that drives this analysis.
  member _.Scheme with get() = scheme

  /// Gets or sets the SSA edges of the CFG under analysis. It is null until
  /// the analysis starts, so it stays hidden behind the accessors below.
  member internal _.SSAEdges with get() = ssaEdges and set v = ssaEdges <- v

  /// Gets the worklist of CFG edges that are executable but not yet executed.
  member _.FlowWorkList with get() = flowWorkList

  /// Gets the worklist of SSA variables whose definitions have changed, and
  /// whose uses therefore need to be revisited.
  member _.SSAWorkList with get() = ssaWorkList

  /// Gets the set of CFG edges that the analysis has already executed.
  member _.ExecutedEdges with get() = executedEdges

  /// Tries to get the statement that defines the given SSA variable. It
  /// returns None when the analysis has yet to build its SSA edges.
  member _.TryGetSSADef var =
    match ssaEdges with
    | null ->
      None
    | edges ->
      match edges.Defs.TryGetValue var with
      | true, stmt -> Some stmt
      | false, _ -> None

  /// Returns the locations that use the given SSA variable, which is empty
  /// when the analysis has yet to build its SSA edges.
  member internal _.GetSSAUses var =
    match ssaEdges with
    | null ->
      Seq.empty
    | edges ->
      match edges.Uses.TryGetValue var with
      | true, uses -> uses :> seq<_>
      | false, _ -> Seq.empty

  /// Gets register value.
  member _.GetRegValue(var: Variable) =
    match regValues.TryGetValue var with
    | true, v -> v
    | false, _ when var.Identifier = 0 -> scheme.GetBaseCase var
    | false, _ -> lattice.Bottom

  /// Seeds the abstract value of the given register without waking the
  /// worklist, which is how an analysis states what holds on entry.
  member _.SeedRegValue(var: Variable, value: 'Lattice) =
    regValues[var] <- value

  /// Checks if the register has been initialized.
  member _.IsRegSet(var: Variable) = regValues.ContainsKey var

  /// Sets register value.
  member _.SetRegValue(var: Variable, value: 'Lattice) =
    if not (regValues.ContainsKey var) then
      regValues[var] <- value
      ssaWorkList.Enqueue var
    elif lattice.Subsume(regValues[var], value) then
      ()
    else
      regValues[var] <- lattice.Join(regValues[var], value)
      ssaWorkList.Enqueue var

  /// Returns the abstract value of the memory cell at the given address. An
  /// access that the value map cannot answer is handed over to the scheme.
  member _.GetMemValue(var: Variable, rt: RegType, addr: Addr) =
    assert (isMemVar var)
    match memValues.TryGetValue var.Identifier with
    | true, map when isAligned rt addr -> Map.tryFind addr map
    | _ -> None
    |> Option.defaultWith (fun () -> scheme.ReadMemFromBinaryFile(rt, addr))

  /// Gets the list of executed source vertices.
  member _.GetExecutedSources(ssaCFG, blk: IVertex<_>, srcIDs) =
    let preds = (ssaCFG: IDiGraph<_, _>).GetPreds blk |> Seq.toArray
    srcIDs
    |> Array.mapi (fun i srcID ->
      if executedEdges.Contains(preds[i], blk) then Some srcID else None)
    |> Array.choose id

  /// Marks every outgoing edge of the given vertex as executable.
  member _.MarkSuccessorsExecutable(ssaCFG, blk: IVertex<_>) =
    for succ in (ssaCFG: IDiGraph<_, _>).GetSuccs blk do
      markExecutable blk succ

  /// Marks the edge from the given source to the given destination as
  /// executable, and enqueues it when it was not already marked.
  member _.MarkExecutable(src, dst) = markExecutable src dst

  /// Returns how many of the incoming edges of the given vertex have been
  /// executed.
  member _.GetNumIncomingExecutedEdges(ssaCFG, blk: IVertex<_>) =
    let mutable count = 0
    for pred in (ssaCFG: IDiGraph<_, _>).GetPreds blk do
      if executedEdges.Contains(pred, blk) then count <- count + 1 else ()
    count

  /// Evaluates the given expression in the current abstract state.
  member _.EvalExpr expr = scheme.EvalExpr expr

  interface IAbsValProvider<SSAVarPoint, 'Lattice> with
    member this.GetAbsValue ssaVarPoint =
      match ssaVarPoint with
      | RegularSSAVar v ->
        this.GetRegValue v
      | MemorySSAVar(id, addr) ->
        match memValues.TryGetValue id with
        | true, map -> Map.find addr map
        | false, _ -> lattice.Bottom

/// Represents the core interface for SSA-based data flow analysis.
and IScheme<'Lattice when 'Lattice: equality> =
  /// Computes the next abstract value from the current abstract value by
  /// executing the given statement.
  abstract Transfer:
      Stmt
    * IDiGraph<SSABasicBlock, CFGEdgeKind>
    * IVertex<SSABasicBlock>
    -> unit

  /// Returns the abstract value of the memory cell at the given address, which
  /// a scheme may read off the binary file. A scheme that cannot tell must
  /// return the top of its lattice: a memory cell never receives a definition
  /// that would later raise a bottom, so a bottom here stays bottom and gets
  /// absorbed by every join.
  abstract ReadMemFromBinaryFile: RegType * Addr -> 'Lattice

  /// Returns the abstract value of a variable that the function never defines,
  /// i.e. one that comes in from the outside. Such a variable never receives a
  /// definition that would raise a bottom, so this must be a sound
  /// over-approximation.
  abstract GetBaseCase: Variable -> 'Lattice

  /// Evaluates the given expression based on the current abstract state.
  abstract EvalExpr: Expr -> 'Lattice

/// Represents an SSA variable point.
and SSAVarPoint =
  /// Everything except memory variable, i.e., register, temporary, stack var,
  /// etc.
  | RegularSSAVar of Variable
  /// Memory variable. Since SSA.Variable doesn't have a field for address, we
  /// use this type to represent a memory variable at a specific address. The
  /// first field is the ID of the SSA memory instance.
  | MemorySSAVar of memId: int * addr: Addr

/// Takes one executable edge off the flow worklist, runs the transfer function
/// over every statement of its destination, and marks the fall-through
/// successors executable.
let private processFlow (state: State<_>) ssaCFG =
  match state.FlowWorkList.TryDequeue() with
  | false, _ ->
    ()
  | true, (parent, blk) ->
    state.ExecutedEdges.Add(parent, blk) |> ignore
    blk.VData.Internals.Statements
    |> Array.iter (fun (_, stmt) ->
      state.Scheme.Transfer(stmt, ssaCFG, blk))
    match blk.VData.Internals.LastStmt with
    | Jmp _ ->
      ()
    | _ -> (* Fall-through cases. *)
      ssaCFG.GetSuccs blk
      |> Seq.iter (fun succ -> state.MarkExecutable(blk, succ))

/// Takes one changed definition off the SSA worklist and runs the transfer
/// function over each of its uses that sits in an already executed vertex.
let private processSSA (state: State<_>) ssaCFG =
  match state.SSAWorkList.TryDequeue() with
  | false, _ ->
    ()
  | true, def ->
    for (v, idx) in state.GetSSAUses def do
      if state.GetNumIncomingExecutedEdges(ssaCFG, v) > 0 then
        let _, stmt = v.VData.Internals.Statements[idx]
        state.Scheme.Transfer(stmt, ssaCFG, v)
      else
        ()

/// Runs the sparse data flow analysis on the given SSA CFG until both
/// worklists are exhausted, and returns the resulting state.
[<CompiledName "Compute">]
let compute cfg (state: State<_>) =
  state.SSAEdges <- SSAEdges cfg
  cfg.Roots
  |> Seq.iter (fun root -> state.FlowWorkList.Enqueue(null, root))
  while state.FlowWorkList.Count > 0 || state.SSAWorkList.Count > 0 do
    processFlow state cfg
    processSSA state cfg
  state
