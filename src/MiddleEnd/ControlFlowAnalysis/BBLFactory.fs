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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open System.Collections.Concurrent
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

/// Per-function factory for basic blocks. Each BBL is memoized so that we do
/// not create multiple BBLs for the same address. As this is a per-function
/// structure, each function may see overlapping basic blocks.
type BBLFactory (hdl: BinHandle, instrs: InstructionCollection) =
  let temporaryBBLs = ConcurrentDictionary<Addr, IRBasicBlock> ()
  let mutable bbls: ARMap<BasicBlock> = ARMap.empty

  member private __.LiftAndFill bblAddr (arr: LiftedInstruction[]) instrs idx =
    match instrs with
    | ins :: tl ->
      let stmts = hdl.LiftOptimizedInstr (ins=ins)
      let liftedIns = { Original = ins; Stmts = stmts; BBLAddr = bblAddr }
      arr[idx] <- liftedIns
      __.LiftAndFill bblAddr arr tl (idx - 1)
    | [] -> arr

  member private __.LiftBlock leaderAddr (instrs: Instruction list) insCount =
    assert (insCount <> 0)
    let arr = Array.zeroCreate insCount
    let arr = __.LiftAndFill leaderAddr arr instrs (insCount - 1)
    let ppoint = ProgramPoint (leaderAddr, 0)
    IRBasicBlock.CreateRegular (arr, ppoint)

  member private __.ParseBlock acc insCount addr =
    match instrs.Find addr with
    | Ok ins ->
      let nextAddr = addr + uint64 ins.Length
      if ins.IsBBLEnd () || temporaryBBLs.ContainsKey nextAddr then
        __.LiftBlock addr (ins :: acc) (insCount + 1) |> Ok
      else __.ParseBlock (ins :: acc) (insCount + 1) nextAddr
    | Error e ->
#if CFGDEBUG
      dbglog (nameof __) $"Failed to parse instruction at {addr:x}"
#endif
      Error e

  /// Parse from the given address and return the BBL. If there exists a BBL
  /// at the given address, then simply return it. When parsing fails, this
  /// function can return an error result.
  member private __.TryParse addr =
    match temporaryBBLs.TryGetValue addr with
    | true, bbl -> Ok bbl
    | false, _ ->
      __.ParseBlock [] 0 addr
      |> Result.bind (fun bbl ->
        temporaryBBLs[addr] <- bbl
        Ok bbl)

  member private __.GetSortedBBLs () =
    temporaryBBLs
    |> Seq.toArray
    |> Array.sortBy (fun (KeyValue (addr, _)) -> addr)

  /// Commit the temporary BBLs to the interval map so that we can efficiently
  /// find basic blocks later by their addresses.
  member private __.Commit () =
    let temporaries = __.GetSortedBBLs ()
    for i = 0 to temporaries.Length - 1 do
      let (KeyValue (_, bbl)) = temporaries[i]
      if i = temporaries.Length - 1 then
        bbls <- ARMap.add bbl.Range bbl bbls
      else
        let (KeyValue (nextAddr, _)) = temporaries[i + 1]
        if bbl.Range.IsIncluding nextAddr then
          let bbl = bbl.Cut nextAddr|> fst
          bbls <- ARMap.add bbl.Range bbl bbls
        else bbls <- ARMap.add bbl.Range bbl bbls
    done
    temporaryBBLs.Clear ()

  /// Scan all directly reachable BBLs from the given addresses. This function
  /// does not handle indirect branches.
  member __.ScanBBLs addrs =
    let queue = Queue<Addr> (collection=addrs)
    while queue.Count <> 0 do
      let addr = queue.Dequeue ()
      match __.TryParse addr with
      | Ok bbl ->
        match bbl.LastInstruction.DirectBranchTarget () with
        | true, target -> queue.Enqueue target
        | false, _ -> ()
      | Error e -> ()
    __.Commit ()

  /// Find an existing BBL that contains the given address.
  member __.TryFind (addr: Addr) =
    ARMap.tryFindByAddr addr bbls
