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

namespace B2R2.MiddleEnd.DataFlow.SSA

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

/// An ID of an SSA memory instance.
type private SSAMemID = int

/// SSA-variable-based data flow state.
type SSAVarBasedDataFlowState<'Lattice>
  public (hdl: BinHandle,
          analysis: ISSAVarBasedDataFlowAnalysis<'Lattice>) =

  let mutable ssaEdges: SSAEdges = null

  /// Register values per SSA variable.
  let regValues = Dictionary<Variable, 'Lattice> ()

  /// Memory values for constant cells. Each SSA memory instance has its own
  /// mapping because SSA expressions do not track data dependencies between
  /// memory cells. That is, memory cells (even though their addresses are
  /// constant) do not have an SSA edge to its dependent memory cells.
  let memValues = Dictionary<SSAMemID, Map<Addr, 'Lattice>> ()

  /// Executable edges from a vertex to another. If there is no element in this
  /// set, the edge is not executable.
  let executableEdges = HashSet<VertexID * VertexID> ()

  /// Executed edges from a vertex to another.
  let executedEdges = HashSet<VertexID * VertexID> ()

  /// Worklist for blocks.
  let flowWorkList = Queue<VertexID * VertexID> ()

  /// Worklist for SSA stmt, this stack stores a list of def variables, and we
  /// will use SSAEdges to find all related SSA statements.
  let ssaWorkList = UniqueQueue<Variable> ()

  let markExecutable src dst =
    if executableEdges.Add (src, dst) then flowWorkList.Enqueue (src, dst)
    else ()

  let isMemVar (var: Variable) =
    match var.Kind with
    | MemVar -> true
    | _ -> false

  let defaultRegType = WordSize.toRegType hdl.File.ISA.WordSize

  let isAligned rt addr =
    let align = RegType.toByteWidth rt |> uint64
    (rt = defaultRegType) && (addr % align = 0UL)

  member _.SSAEdges with get() = ssaEdges and set v = ssaEdges <- v

  member _.FlowWorkList with get() = flowWorkList

  member _.SSAWorkList with get() = ssaWorkList

  member _.ExecutedEdges with get() = executedEdges

  /// Get register value.
  member _.GetRegValue (var: Variable) =
    match regValues.TryGetValue var with
    | true, v -> v
    | false, _ -> analysis.Bottom

  /// Set register value without adding it to the worklist.
  member _.SetRegValueWithoutAdding (var: Variable) (value: 'Lattice) =
    regValues[var] <- value

  /// Check if the register has been initialized.
  member _.IsRegSet (var: Variable) =
    regValues.ContainsKey var

  /// Set register value.
  member _.SetRegValue (var: Variable, value: 'Lattice) =
    if not (regValues.ContainsKey var) then
      regValues[var] <- value
      ssaWorkList.Enqueue var
    elif analysis.Subsume regValues[var] value then ()
    else
      regValues[var] <- analysis.Join regValues[var] value
      ssaWorkList.Enqueue var

  /// Try to get memory value. Unaligned access will always return Bottom.
  member _.GetMemValue (var: Variable) (rt: RegType) (addr: Addr) =
    assert (isMemVar var)
    if isAligned rt addr then
      match memValues.TryGetValue var.Identifier with
      | true, map -> Map.tryFind addr map
      | false, _ -> None
      |> Option.defaultWith (fun () -> analysis.UpdateMemFromBinaryFile rt addr)
    else analysis.Bottom

  /// Get the list of executed source vertices.
  member _.GetExecutedSources ssaCFG (blk: IVertex<_>) srcIDs =
    let preds = (ssaCFG: IDiGraph<_, _>).GetPreds blk |> Seq.toArray
    srcIDs
    |> Array.mapi (fun i srcID ->
      if executedEdges.Contains (preds[i].ID, blk.ID) then Some srcID
      else None)
    |> Array.choose id

  member _.MarkSuccessorsExecutable ssaCFG (blk: IVertex<_>) =
    for succ in (ssaCFG: IDiGraph<_, _>).GetSuccs blk do
      markExecutable blk.ID succ.ID

  member _.MarkExecutable src dst = markExecutable src dst

  member _.GetNumIncomingExecutedEdges ssaCFG (blk: IVertex<_>) =
    let mutable count = 0
    for pred in (ssaCFG: IDiGraph<_, _>).GetPreds blk do
      if executedEdges.Contains (pred.ID, blk.ID) then count <- count + 1
      else ()
    count

  member this.EvalExpr expr = analysis.EvalExpr this expr

  interface IDataFlowState<SSAVarPoint, 'Lattice> with
    member this.GetAbsValue ssaVarPoint =
      match ssaVarPoint with
      | RegularSSAVar v -> this.GetRegValue v
      | MemorySSAVar (id, addr) ->
        match memValues.TryGetValue id with
        | true, map -> Map.find addr map
        | false, _ -> analysis.Bottom

/// The core interface for SSA-based data flow analysis.
and ISSAVarBasedDataFlowAnalysis<'Lattice> =
  /// A callback for initializing the state.
  abstract OnInitialize:
       SSAVarBasedDataFlowState<'Lattice>
    -> SSAVarBasedDataFlowState<'Lattice>

  /// Initial abstract value representing the bottom of the lattice. Our
  /// analysis starts with this value until it reaches a fixed point.
  abstract Bottom: 'Lattice

  /// Join operator.
  abstract Join: 'Lattice -> 'Lattice -> 'Lattice

  /// Transfer function. Since SSAVarBasedDataFlowState is a mutable object, we
  /// don't need to return the updated state.
  abstract Transfer:
       IDiGraph<SSABasicBlock, CFGEdgeKind>
    -> IVertex<SSABasicBlock>
    -> ProgramPoint
    -> Stmt
    -> SSAVarBasedDataFlowState<'Lattice>
    -> unit

  /// Subsume operator, which checks if the first lattice subsumes the second.
  /// This is to know if the analysis should stop or not.
  abstract Subsume: 'Lattice -> 'Lattice -> bool

  /// Update memory value by reading constant values from a binary file when
  /// the memory value is not found in the memory value map.
  abstract UpdateMemFromBinaryFile: RegType -> Addr -> 'Lattice

  /// Evaluate the given expression based on the current abstract state.
  abstract EvalExpr: SSAVarBasedDataFlowState<'Lattice> -> Expr -> 'Lattice

/// SSA variable point.
and SSAVarPoint =
  /// Everything except memory variable, i.e., register, temporary, stack var,
  /// etc.
  | RegularSSAVar of Variable
  /// Memory variable. Since SSA.Variable doesn't have a field for address, we
  /// use this type to represent a memory variable at a specific address.
  | MemorySSAVar of SSAMemID * Addr
