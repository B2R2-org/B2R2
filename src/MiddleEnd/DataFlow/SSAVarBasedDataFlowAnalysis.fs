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
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.DataFlow

/// An ID of an SSA memory instance.
type private SSAMemID = int

[<AbstractClass>]
type SSAVarBasedDataFlowAnalysis<'Lattice,
                                 'E when 'Lattice: equality
                                     and 'E: equality> (hdl: BinHandle) =
  let mutable ssaEdges: SSAEdges<'E> = null

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
  let ssaWorkList = Stack<Variable> ()

  let markExecutable src dst =
    if executableEdges.Add (src, dst) then flowWorkList.Enqueue (src, dst)
    else ()

  let getNumIncomingExecutedEdges (ssaCFG: SSACFG<'E>) (blk: SSAVertex) =
    let mutable count = 0
    for pred in ssaCFG.GetPreds blk do
      if executedEdges.Contains (pred.ID, blk.ID) then count <- count + 1
      else ()
    count

  let isMemVar (var: Variable) =
    match var.Kind with
    | MemVar -> true
    | _ -> false

  let defaultRegType = WordSize.toRegType hdl.File.ISA.WordSize

  let isAligned rt addr =
    let align = RegType.toByteWidth rt |> uint64
    (rt = defaultRegType) && (addr % align = 0UL)

  /// The initial abstract value. Our analysis starts with this value until
  /// a fixed point is reached.
  abstract Bottom: 'Lattice

  /// Join operator.
  abstract Join: 'Lattice -> 'Lattice -> 'Lattice

  /// Transfer function.
  abstract Transfer:
    SSACFG<'E> -> IVertex<SSABasicBlock> -> ProgramPoint -> Stmt -> unit

  /// Update memory value by reading constant values from a binary file when
  /// the memory value is not found in the memory value map.
  abstract UpdateMemFromBinaryFile: RegType -> Addr -> 'Lattice

  /// Get register value.
  member __.GetRegValue (var: Variable) =
    match regValues.TryGetValue var with
    | true, v -> v
    | false, _ -> __.Bottom

  /// Set register value without pushing it to the worklist.
  member __.SetRegValueWithoutPushing (var: Variable) (value: 'Lattice) =
    regValues[var] <- value

  /// Set register value.
  member __.SetRegValue (pp: ProgramPoint, var: Variable, value: 'Lattice) =
    if not (regValues.ContainsKey var) then regValues[var] <- value
    else regValues[var] <- __.Join regValues[var] value
    ssaWorkList.Push var

  /// Try to get memory value. Unaligned access will always return Bottom.
  member __.GetMemValue (var: Variable) (rt: RegType) (addr: Addr) =
    assert (isMemVar var)
    if isAligned rt addr then
      match memValues.TryGetValue var.Identifier with
      | true, map -> Map.tryFind addr map
      | false, _ -> None
      |> Option.defaultWith (fun () -> __.UpdateMemFromBinaryFile rt addr)
    else __.Bottom

  /// Get the list of executed source vertices.
  member __.GetExecutedSources (ssaCFG: SSACFG<'E>) (blk: SSAVertex) srcIDs =
    let preds = ssaCFG.GetPreds blk |> Seq.toArray
    srcIDs
    |> Array.mapi (fun i srcID ->
      if executedEdges.Contains (preds[i].ID, blk.ID) then Some srcID
      else None)
    |> Array.choose id

  member __.MarkSuccessorsExecutable (ssaCFG: SSACFG<'E>) (blk: SSAVertex) =
    for succ in ssaCFG.GetSuccs blk do
      markExecutable blk.ID succ.ID

  member private __.ProcessFlow (ssaCFG: SSACFG<'E>) =
    match flowWorkList.TryDequeue () with
    | false, _ -> ()
    | true, (parentId, myId) ->
      executableEdges.Add (parentId, myId) |> ignore
      let blk = ssaCFG.FindVertexByID myId
      blk.VData.LiftedSSAStmts
      |> Array.iter (fun (ppoint, stmt) -> __.Transfer ssaCFG blk ppoint stmt)
      if blk.VData.IsAbstract then ()
      else
        match blk.VData.LastStmt with
        | Jmp _ -> ()
        | _ -> (* Fall-through cases. *)
          ssaCFG.GetSuccs blk
          |> Seq.iter (fun succ -> markExecutable myId succ.ID)

  member private __.ProcessSSA (ssaCFG: SSACFG<'E>) =
    match ssaWorkList.TryPop () with
    | false, _ -> ()
    | true, def ->
      match ssaEdges.Uses.TryGetValue def with
      | false, _ -> ()
      | _, uses ->
        uses |> Set.iter (fun (vid, idx) ->
          let v = ssaCFG.FindVertexByID vid
          if getNumIncomingExecutedEdges ssaCFG v > 0 then
            let ppoint, stmt = v.VData.LiftedSSAStmts[idx]
            __.Transfer ssaCFG v ppoint stmt
          else ()
        )

  interface IDataFlowAnalysis<SSAVarPoint, 'Lattice, SSABasicBlock, 'E> with
    member __.Compute (cfg: SSACFG<'E>) =
      ssaEdges <- SSAEdges cfg
      cfg.GetRoots ()
      |> Seq.iter (fun root -> flowWorkList.Enqueue (0, root.ID))
      while flowWorkList.Count > 0 || ssaWorkList.Count > 0 do
        __.ProcessFlow cfg
        __.ProcessSSA cfg

    member __.GetAbsValue ssaVarPoint =
      match ssaVarPoint with
      | Regular v -> __.GetRegValue v
      | Memory (id, addr) ->
        match memValues.TryGetValue id with
        | true, map -> Map.find addr map
        | false, _ -> __.Bottom

/// SSA variable point.
and SSAVarPoint =
  /// Everything except memory variable, i.e., register, temporary, stack var,
  /// etc.
  | Regular of Variable
  /// Memory variable. Since SSA.Variable doesn't have a field for address, we
  /// use this type to represent a memory variable at a specific address.
  | Memory of SSAMemID * Addr
