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
open System.Runtime.CompilerServices
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Provides what the function identifications of binaries without call frame
/// information for every function read, whatever the architecture: where code
/// lies, what the loader writes, and where the functions that the recovery
/// has built jump to others.
module internal FunctionIdentificationCommon =
  /// Returns the values that the loader writes where it relocates the binary.
  let relocatedValues (file: IBinFile) =
    match file.Relocations with
    | Some relocs ->
      relocs.Relocations
      |> Seq.choose (fun reloc ->
        relocs.TryComputeRelocationValue reloc.Address |> Result.toOption)
    | None ->
      Seq.empty

  /// Tells whether the section holds code that a function may start in: it is
  /// executable, and it does not link the binary to others, as a PLT does,
  /// which serves imports.
  let private isCodeSection (s: BinSection) =
    s.Permission.HasFlag Permission.Executable
    && s.Kind <> DynamicLinkageSection
    && s.Size > 0UL

  /// Lists the address ranges of the sections that hold code that a function
  /// may start in, or of the executable segments of a file without sections,
  /// such as a raw image.
  let findCodeRanges (file: IBinFile) =
    let rangeOf (addr: Addr) size = AddrRange.create addr (addr + size - 1UL)
    let sections = BinFileOps.getSections file
    if sections.IsEmpty then
      BinFileOps.getSegments file
      |> Seq.filter (fun s -> s.Permission.HasFlag Permission.Executable)
      |> Seq.map (fun s -> rangeOf s.Address s.Size)
      |> Seq.toArray
    else
      sections
      |> Seq.filter isCodeSection
      |> Seq.map (fun s -> rangeOf s.Address s.Size)
      |> Seq.toArray

  /// Returns where the executable sections start, which no code runs into from
  /// above.
  let findSectionStarts (file: IBinFile) =
    BinFileOps.getSections file
    |> Seq.filter (fun s -> s.Permission.HasFlag Permission.Executable)
    |> Seq.map (fun s -> s.Address)
    |> Set.ofSeq

  /// Pairs each of the given functions, in the order of their entries, with
  /// the entry of the next one.
  let withNextEntries (fns: Function[]) =
    let sorted = fns |> Array.sortBy (fun fn -> fn.EntryPoint)
    sorted
    |> Array.mapi (fun i fn ->
      if i + 1 < sorted.Length then fn, sorted[i + 1].EntryPoint
      else fn, System.UInt64.MaxValue)

  /// Returns where the direct jump that ends the vertex goes, if it ends with
  /// one.
  let private tryDirectJumpTarget (v: IVertex<LowUIRBasicBlock>) =
    match v.VData.Internals.Terminator with
    | InterJmp(Target = Num(Value = n); Kind = InterJmpKind.Base) ->
      Some(n.ToUInt64())
    | _ ->
      None

  /// Finds the direct jumps of the function that leave the span from its entry
  /// up to the given next entry, from within the span, each as the vertex
  /// that it ends and where it goes. Only a jump to another function leaves,
  /// as a compiler that emits no call frame information for a function keeps
  /// it in one piece, while code that the function has taken in past the
  /// span, as a call that never returns may run it into the next function,
  /// tells nothing.
  let private findLeavingJumps (fn: Function, next) =
    let isWithin addr = fn.EntryPoint <= addr && addr < next
    fn.CFG.Vertices
    |> Array.filter (fun v ->
      let blk = v.VData.Internals
      not blk.IsAbstract && isWithin blk.LastInstruction.Address)
    |> Array.choose (fun v ->
      match tryDirectJumpTarget v with
      | Some target when not (isWithin target) -> Some(v, target)
      | _ -> None)

  /// Collects what the blocks cover that the function reaches from its roots
  /// without leaving it through the given vertices, as it takes in the code
  /// of a function that it jumps to before the recovery knows of that one.
  let private collectHomeRanges (fn: Function) (exits: HashSet<_>) =
    let cfg = fn.CFG
    let visited = HashSet<IVertex<LowUIRBasicBlock>>()
    let work = Queue<IVertex<LowUIRBasicBlock>>(cfg.Roots)
    let ranges = List<AddrRange>()
    while work.Count > 0 do
      let v = work.Dequeue()
      let blk = v.VData.Internals
      if visited.Add v then
        if blk.IsAbstract then () else ranges.Add blk.Range
        if exits.Contains v then ()
        else for succ in cfg.GetSuccs v do work.Enqueue succ
      else
        ()
    ranges.ToArray()

  /// Returns what reading the given function gives, which the given table
  /// keeps by its CFG, with the counts of its vertices and edges, so that a
  /// function is read anew only once it has changed, while most stay the same
  /// from round to round of identification.
  let readOnce (table: ConditionalWeakTable<LowUIRCFG, _>) read (fn: Function) =
    let cfg = fn.CFG
    let stamp = cfg.VertexCount, cfg.EdgeCount
    match table.TryGetValue cfg with
    | true, (stampOfCache, value) when stampOfCache = stamp ->
      value
    | _ ->
      let value = read fn
      table.AddOrUpdate(cfg, (stamp, value))
      value

  /// Where the jumps that leave each recovered function go, and what it covers
  /// but for what it reaches only through them, by its CFG, with the counts of
  /// its vertices and edges and the next entry that they hold for, as finding
  /// them takes walking the whole CFG, while most functions stay the same from
  /// round to round of identification.
  let private leavingByCFG = ConditionalWeakTable<LowUIRCFG, _>()

  /// Finds where the jumps that leave the given function, up to the given next
  /// entry, go, and what it covers but for what it reaches only through them.
  let private findLeavingOnce (fn: Function, next) =
    let cfg = fn.CFG
    let stamp = cfg.VertexCount, cfg.EdgeCount, next
    match leavingByCFG.TryGetValue cfg with
    | true, (stampOfCache, leaving) when stampOfCache = stamp ->
      leaving
    | _ ->
      let jumps = findLeavingJumps (fn, next)
      let home =
        collectHomeRanges fn (HashSet(Array.map fst jumps))
        |> AddrRangeUnion.ofArray
      let leaving = Array.map snd jumps, home.Ranges
      leavingByCFG.AddOrUpdate(cfg, (stamp, leaving))
      leaving

  /// Returns where jumps leave the given functions for code that none of them
  /// covers but through such jumps, as a jump into the middle of a function
  /// that the recovery has built calls no function.
  let findTailCallTargets internals =
    let leaving = withNextEntries internals |> Array.map findLeavingOnce
    let home = leaving |> Array.collect snd |> AddrRangeUnion.ofArray
    leaving
    |> Array.collect fst
    |> Array.filter (fun t -> not (AddrRangeUnion.containsAddr t home))

  /// Returns what the code that the recovery has built for the functions
  /// covers.
  let coverOf (fns: Function[]) =
    fns
    |> Array.collect (fun fn ->
      fn.CFG.Vertices
      |> Array.filter (fun v -> not v.VData.Internals.IsAbstract)
      |> Array.map (fun v -> v.VData.Internals.Range))
    |> AddrRangeUnion.ofArray
