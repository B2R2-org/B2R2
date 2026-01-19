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

/// SSA-variable-based data flow state.
type State<'Lattice when 'Lattice: equality>
  public(hdl: BinHandle,
         lattice: ILattice<'Lattice>,
         scheme: IScheme<'Lattice>) =

  let mutable ssaEdges: SSAEdges | null = null

  /// Register values per SSA variable.
  let regValues = Dictionary<Variable, 'Lattice>()

  /// Memory values for constant cells. Each SSA memory instance has its own
  /// mapping because SSA expressions do not track data dependencies between
  /// memory cells. That is, memory cells (even though their addresses are
  /// constant) do not have an SSA edge to its dependent memory cells.
  let memValues = Dictionary<SSAMemID, Map<Addr, 'Lattice>>()

  /// Executable edges from a vertex to another. If there is no element in this
  /// set, the edge is not executable.
  let executableEdges = HashSet<VertexID * VertexID>()

  /// Executed edges from a vertex to another.
  let executedEdges = HashSet<VertexID * VertexID>()

  /// Worklist for blocks.
  let flowWorkList = Queue<VertexID * VertexID>()

  /// Worklist for SSA stmt, this stack stores a list of def variables, and we
  /// will use SSAEdges to find all related SSA statements.
  let ssaWorkList = UniqueQueue<Variable>()

  let markExecutable src dst =
    if executableEdges.Add(src, dst) then flowWorkList.Enqueue(src, dst)
    else ()

  let isMemVar (var: Variable) =
    match var.Kind with
    | MemVar -> true
    | _ -> false

  let defaultRegType = WordSize.toRegType hdl.File.ISA.WordSize

  let isAligned rt addr =
    let align = RegType.toByteWidth rt |> uint64
    (rt = defaultRegType) && (addr % align = 0UL)

  member _.Scheme with get() = scheme

  member _.SSAEdges with get() = ssaEdges and set v = ssaEdges <- v

  member _.FlowWorkList with get() = flowWorkList

  member _.SSAWorkList with get() = ssaWorkList

  member _.ExecutedEdges with get() = executedEdges

  /// Get register value.
  member _.GetRegValue(var: Variable) =
    match regValues.TryGetValue var with
    | true, v -> v
    | false, _ -> lattice.Bottom

  /// Set register value without adding it to the worklist.
  member _.SetRegValueWithoutAdding(var: Variable, value: 'Lattice) =
    regValues[var] <- value

  /// Check if the register has been initialized.
  member _.IsRegSet(var: Variable) = regValues.ContainsKey var

  /// Set register value.
  member _.SetRegValue(var: Variable, value: 'Lattice) =
    if not (regValues.ContainsKey var) then
      regValues[var] <- value
      ssaWorkList.Enqueue var
    elif lattice.Subsume(regValues[var], value) then ()
    else
      regValues[var] <- lattice.Join(regValues[var], value)
      ssaWorkList.Enqueue var

  /// Try to get memory value. Unaligned access will always return Bottom.
  member _.GetMemValue(var: Variable, rt: RegType, addr: Addr) =
    assert (isMemVar var)
    if isAligned rt addr then
      match memValues.TryGetValue var.Identifier with
      | true, map -> Map.tryFind addr map
      | false, _ -> None
      |> Option.defaultWith (fun () -> scheme.UpdateMemFromBinaryFile(rt, addr))
    else lattice.Bottom

  /// Get the list of executed source vertices.
  member _.GetExecutedSources(ssaCFG, blk: IVertex<_>, srcIDs) =
    let preds = (ssaCFG: IDiGraph<_, _>).GetPreds blk |> Seq.toArray
    srcIDs
    |> Array.mapi (fun i srcID ->
      if executedEdges.Contains(preds[i].ID, blk.ID) then Some srcID
      else None)
    |> Array.choose id

  member _.MarkSuccessorsExecutable(ssaCFG, blk: IVertex<_>) =
    for succ in (ssaCFG: IDiGraph<_, _>).GetSuccs blk do
      markExecutable blk.ID succ.ID

  member _.MarkExecutable(src, dst) = markExecutable src dst

  member _.GetNumIncomingExecutedEdges(ssaCFG, blk: IVertex<_>) =
    let mutable count = 0
    for pred in (ssaCFG: IDiGraph<_, _>).GetPreds blk do
      if executedEdges.Contains(pred.ID, blk.ID) then count <- count + 1
      else ()
    count

  member _.EvalExpr expr = scheme.EvalExpr expr

  interface IAbsValProvider<SSAVarPoint, 'Lattice> with
    member this.GetAbsValue ssaVarPoint =
      match ssaVarPoint with
      | RegularSSAVar v -> this.GetRegValue v
      | MemorySSAVar(id, addr) ->
        match memValues.TryGetValue id with
        | true, map -> Map.find addr map
        | false, _ -> lattice.Bottom

/// The core interface for SSA-based data flow analysis.
and IScheme<'Lattice when 'Lattice: equality> =
  /// The transfer function, which computes the next abstract value from the
  /// current abstract value by executing the given 'WorkUnit.
  abstract Transfer:
      Stmt
    * IDiGraph<SSABasicBlock, CFGEdgeKind>
    * IVertex<SSABasicBlock>
    -> unit

  /// Update memory value by reading constant values from a binary file when
  /// the memory value is not found in the memory value map.
  abstract UpdateMemFromBinaryFile: RegType * Addr -> 'Lattice

  /// Evaluate the given expression based on the current abstract state.
  abstract EvalExpr: Expr -> 'Lattice

/// SSA variable point.
and SSAVarPoint =
  /// Everything except memory variable, i.e., register, temporary, stack var,
  /// etc.
  | RegularSSAVar of Variable
  /// Memory variable. Since SSA.Variable doesn't have a field for address, we
  /// use this type to represent a memory variable at a specific address.
  | MemorySSAVar of SSAMemID * Addr

/// An ID of an SSA memory instance.
and private SSAMemID = int

let processFlow (state: State<_>) ssaCFG =
  match state.FlowWorkList.TryDequeue() with
  | false, _ -> ()
  | true, (parentId, myId) ->
    state.ExecutedEdges.Add(parentId, myId) |> ignore
    let blk = (ssaCFG :> IDiGraph<SSABasicBlock, _>).FindVertexByID myId
    blk.VData.Internals.Statements
    |> Array.iter (fun (_, stmt) ->
      state.Scheme.Transfer(stmt, ssaCFG, blk))
    match blk.VData.Internals.LastStmt with
    | Jmp _ -> ()
    | _ -> (* Fall-through cases. *)
      ssaCFG.GetSuccs blk
      |> Seq.iter (fun succ -> state.MarkExecutable(myId, succ.ID))

let processSSA (state: State<_>) ssaCFG =
  match state.SSAWorkList.TryDequeue() with
  | false, _ -> ()
  | true, def ->
    match state.SSAEdges.Uses.TryGetValue def with
    | false, _ -> ()
    | _, uses ->
      for (vid, idx) in uses do
        let v = (ssaCFG :> IDiGraph<SSABasicBlock, _>).FindVertexByID vid
        if state.GetNumIncomingExecutedEdges(ssaCFG, v) > 0 then
          let _, stmt = v.VData.Internals.Statements[idx]
          state.Scheme.Transfer(stmt, ssaCFG, v)
        else ()

let compute cfg (state: State<_>) =
  state.SSAEdges <- SSAEdges cfg
  cfg.GetRoots()
  |> Seq.iter (fun root -> state.FlowWorkList.Enqueue(0, root.ID))
  while state.FlowWorkList.Count > 0 || state.SSAWorkList.Count > 0 do
    processFlow state cfg
    processSSA state cfg
  state

//interface IDataFlowComputable<SSAVarPoint,
//                            'Lattice,
//                            SSAVarBasedDataFlowState<'Lattice>,
//                            SSABasicBlock> with
//  member _.InitializeState _vs =
//    SSAVarBasedDataFlowState<'Lattice> (hdl, analysis)
//    |> analysis.OnInitialize

//  member _.Compute cfg (state: SSAVarBasedDataFlowState<'Lattice>) =
