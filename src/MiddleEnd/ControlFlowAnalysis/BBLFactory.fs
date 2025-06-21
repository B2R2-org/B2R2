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

open System.Runtime.InteropServices
open System.Collections.Generic
open System.Collections.Immutable
open System.Collections.Concurrent
open System.Threading.Tasks.Dataflow
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

/// Per-function factory for basic blocks. Each BBL is memoized so that we do
/// not create multiple BBLs for the same address. As this is a per-function
/// structure, each different function has its own BBLFactory.
[<AllowNullLiteral>]
type BBLFactory (hdl: BinHandle, instrs) =
  let interProceduralLeaders = ConcurrentDictionary<Addr, unit> ()
  let bbls = ConcurrentDictionary<ProgramPoint, LowUIRBasicBlock> ()

  let rec parseBlock (channel: BufferBlock<_>) acc insCount addr leader =
    match (instrs: InstructionCollection).TryFind addr with
    | Ok ins ->
      let nextAddr = addr + uint64 ins.Length
      if ins.IsTerminator () || interProceduralLeaders.ContainsKey nextAddr then
        channel.Post (leader, ins :: acc, insCount + 1) |> ignore
        if ins.IsCall () then Ok [||]
        else
          ins.GetNextInstrAddrs () (* TODO: ARM mode switch *)
          |> Ok
      else parseBlock channel (ins :: acc) (insCount + 1) nextAddr leader
    | Error e ->
#if CFGDEBUG
      dbglog ManagerTid (nameof BBLFactory)
      <| $"Failed to parse instruction at {addr:x}"
#endif
      Error e

  /// Parse from the given address and return reachable addresses. If there
  /// exists a BBL at the given address, then simply return an empty array. When
  /// parsing fails, this function can return an error result.
  let tryParse channel addr =
    if interProceduralLeaders.ContainsKey addr then Ok [||]
    else parseBlock channel [] 0 addr addr

  let visited = ConcurrentDictionary<Addr, unit> ()

  let instrProducer channel addrs =
    let queue = Queue<Addr> (collection=addrs)
    task {
      while queue.Count <> 0 do
        let addr = queue.Dequeue ()
        if visited.ContainsKey addr then ()
        else
          visited.TryAdd (addr, ()) |> ignore
          match tryParse channel addr with
          | Ok nextAddrs ->
            nextAddrs |> Array.iter queue.Enqueue
          | Error _e ->
            queue.Clear ()
            channel.Post (0UL, [], -1) |> ignore (* post error *)
            channel.Complete ()
      channel.Complete ()
    }

  let hasProperISMark (stmts: Stmt array) =
    match stmts[0] with
    | ISMark _ -> true
    | _ -> false

  /// The given list is reversed, so we fill the array in reverse order.
  let rec liftAndFill lunit bblAddr (arr: LiftedInstruction[]) instrs ndx =
    match instrs with
    | ins :: tl ->
      let stmts = (lunit: LiftingUnit).LiftInstruction (ins=ins, optimize=true)
      assert (hasProperISMark stmts)
      let liftedIns = { Original = ins; Stmts = stmts; BBLAddr = bblAddr }
      arr[ndx] <- liftedIns
      liftAndFill lunit bblAddr arr tl (ndx - 1)
    | [] -> arr

  let rec addLeaderHead (intraLeaders: LinkedList<_>) lastLeader idx =
    if isNull (lastLeader: LinkedListNode<_>) then
      intraLeaders.AddFirst ((idx, 0)) |> ignore
    elif lastLeader.Value = (idx, 0) then () (* due to `hasIntraFlow` *)
    elif fst lastLeader.Value < idx then
      intraLeaders.AddAfter (lastLeader, (idx, 0)) |> ignore
    else addLeaderHead intraLeaders lastLeader.Previous idx

  let scanIntraLeaders (liftedInss: LiftedInstruction[]) =
    let lblMap = Dictionary<Label, ProgramPoint> ()
    let intraLeaders = LinkedList<int * int> () (* instruction ndx, stmt ndx *)
    let mutable hasIntraFlow = false (* has intra control flow(s)? *)
    for i = 0 to liftedInss.Length - 1 do
      let liftedIns = liftedInss[i]
      if hasIntraFlow then intraLeaders.AddLast ((i, 0)) |> ignore else ()
      hasIntraFlow <- false
      for j = 0 to liftedIns.Stmts.Length - 1 do
        match liftedIns.Stmts[j] with
        | LMark (label, _) ->
          let insAddr = liftedIns.Original.Address
          lblMap[label] <- ProgramPoint (insAddr, j)
          intraLeaders.AddLast ((i, j)) |> ignore
          hasIntraFlow <- true
        | InterJmp (PCVar _, InterJmpKind.Base, _)
        | InterCJmp (_, PCVar _, _, _)
        | InterCJmp (_, _, PCVar _, _) ->
          (* JMP PC means that the instruction jumps to itself. *)
          if i = 0 then () (* Ignore if it is the first lifted instruction. *)
          else addLeaderHead intraLeaders intraLeaders.Last i
        | _ -> ()
    struct (lblMap, intraLeaders)

  let extractInstrs (liftedInss: LiftedInstruction[]) startNdxs endNdxs =
    match startNdxs, endNdxs with
    | (insStartNdx, stmStartNdx), Some (insEndNdx, 0) ->
      assert (insStartNdx <> insEndNdx)
      let r = liftedInss[insStartNdx..insEndNdx-1]
      r[0] <- { r[0] with Stmts = r[0].Stmts[stmStartNdx..] }
      r
    | (insStartNdx, stmStartNdx), Some (insEndNdx, stmEndNdx) ->
      let r = liftedInss[insStartNdx..insEndNdx]
      let last = r.Length - 1
      if last = 0 then
        r[0] <- { r[0] with Stmts = r[0].Stmts[stmStartNdx..(stmEndNdx-1)] }
      else
        r[0] <- { r[0] with Stmts = r[0].Stmts[stmStartNdx..] }
        r[last] <- { r[last] with Stmts = r[last].Stmts[..(stmEndNdx-1)] }
      r
    | (insStartNdx, stmStartNdx), None ->
      let r = liftedInss[insStartNdx..]
      r[0] <- { r[0] with Stmts = r[0].Stmts[stmStartNdx..] }
      r

  let rec extractLabelInfo (lblMap: Dictionary<_, _>) liftedIns insAddr ndx =
    match liftedIns.Stmts[ndx] with
    | IEMark _ -> extractLabelInfo lblMap liftedIns insAddr (ndx - 1)
    | Jmp (JmpDest (label, _), _) -> [ KeyValuePair (label, lblMap[label]) ]
    | CJmp (_, JmpDest (label1, _), JmpDest (label2, _), _) ->
      [ KeyValuePair (label1, lblMap[label1])
        KeyValuePair (label2, lblMap[label2]) ]
    | CJmp (_, JmpDest (label, _), _, _)
    | CJmp (_, _, JmpDest (label, _), _) ->
      [ KeyValuePair (label, lblMap[label]) ]
    | _ -> []

  let buildLabelMap lblMap liftedIns =
    let insAddr = liftedIns.Original.Address
    extractLabelInfo lblMap liftedIns insAddr (liftedIns.Stmts.Length - 1)
    |> ImmutableDictionary.CreateRange

  let addInterProceduralLeader addr =
    interProceduralLeaders.TryAdd (addr, ()) |> ignore

  let addIRBBL liftedInss lblMap prevInsNdx prevStmtNdx endNdx =
    let instrs = extractInstrs liftedInss (prevInsNdx, prevStmtNdx) endNdx
    let ppoint = ProgramPoint (instrs[0].Original.Address, prevStmtNdx)
    let lastIns = instrs[instrs.Length - 1]
    let lblMap = buildLabelMap lblMap lastIns
    let bbl = LowUIRBasicBlock.CreateRegular (instrs, ppoint, lblMap)
    if prevStmtNdx = 0 then addInterProceduralLeader ppoint.Address else ()
    bbls.TryAdd (ppoint, bbl) |> ignore

  let rec gatherIntraBBLs liftedInss lblMap prevInsNdx prevStmtNdx idxs =
    match idxs with
    | (insNdx, stmtNdx) as endNdx :: tl ->
      addIRBBL liftedInss lblMap prevInsNdx prevStmtNdx (Some endNdx)
      gatherIntraBBLs liftedInss lblMap insNdx stmtNdx tl
    | [] ->
      addIRBBL liftedInss lblMap prevInsNdx prevStmtNdx None

  let liftBlock liftingUnit leaderAddr instrs insCount =
    assert (insCount <> 0)
    addInterProceduralLeader leaderAddr
    let arr = Array.zeroCreate insCount
    let arr = liftAndFill liftingUnit leaderAddr arr instrs (insCount - 1)
    let struct (lblMap, intraLeaders) = scanIntraLeaders arr
    if intraLeaders.Count = 0 then
      let ppoint = ProgramPoint (leaderAddr, 0)
      let bbl = LowUIRBasicBlock.CreateRegular (arr, ppoint)
      bbls.TryAdd (ppoint, bbl) |> ignore
    else
      gatherIntraBBLs arr lblMap 0 0 (Seq.toList intraLeaders)

  let bblLifter (channel: BufferBlock<Addr * IInstruction list * int>) =
    let liftingUnit = hdl.NewLiftingUnit ()
    let mutable isSuccessful = true
    let mutable canContinue = true
    task {
      while canContinue do
        let! available = channel.OutputAvailableAsync ()
        if available then
          match channel.TryReceive () with
          | true, (_, _, -1) -> (* error case*)
            isSuccessful <- false; canContinue <- false
          | true, (leaderAddr, instrs, insCount) ->
            try liftBlock liftingUnit leaderAddr instrs insCount
            with e ->
#if CFGDEBUG
              dbglog ManagerTid (nameof BBLFactory)
              <| $"Failed to lift instruction at {leaderAddr:x} {e}"
#endif
              isSuccessful <- false; canContinue <- false
          | false, _ -> ()
        else canContinue <- false
      return isSuccessful
    }

  let getSortedLeaders () =
    interProceduralLeaders.Keys
    |> Seq.toArray
    |> Array.sort

  let isInstructionAddress (currentBBL: LowUIRBasicBlock) addr =
    currentBBL.Internals.LiftedInstructions
    |> Array.exists (fun lifted -> lifted.Original.Address = addr)

  /// We do *not* split BBLs when there is an instruction-level overlap. One may
  /// still split such BBLs by finding a merging instruction, but it is not
  /// desirable as it can introduce more bogus edges. For example, let BBL_1 and
  /// BBL_2 be two BBLs that are located at address 1 and 2, respectively. BBL_1
  /// has three instructions (i_1, i_3, i_5) where i_n is the instruction at
  /// address n. BBL_2 has three instructions (i_2, i_3, i_5). And let i_5 be an
  /// indirect jump instruction (jmp rcx), representing a switch-case statement.
  /// One may split both BBLs at address 3, but it will introduce a bogus edge
  /// reaching the jmp instruction, which makes our dataflow analysis fails to
  /// detect the jump table for the jmp instruction. However, by *not* splitting
  /// the BBLs and having the two independent BBLs untouched, we can still
  /// detect the jump table for the jmp instruction (although the two BBLs have
  /// an overlapping jmp instruction), and this allows us to perform a more
  /// precise jump table analysis in the end.
  ///
  /// Nonetheless, we have to check if there is any subsequent leaders that have
  /// a BBL-level overlap because when there is an instruction-level overlap,
  /// our pairwise check will miss the overlapping BBLs.
  let rec findOverlappingLeader currentBBL (leaders: Addr[]) idx =
    if idx = leaders.Length then Error ErrorCase.ItemNotFound
    else
      let nextAddr = leaders[idx]
      if (currentBBL :> IAddressable).Range.IsIncluding nextAddr then
        if isInstructionAddress currentBBL nextAddr then Ok nextAddr
        else findOverlappingLeader currentBBL leaders (idx + 1)
      else Error ErrorCase.ItemNotFound

  /// Iterate over all the BBL leaders and split the BBLs if necessary.
  let commit () =
    let leaders = getSortedLeaders ()
    let dividedEdges = List ()
    for i = 0 to leaders.Length - 1 do
      if i = leaders.Length - 1 then ()
      else
        let currPPoint = ProgramPoint (leaders[i], 0)
        let currentBBL = bbls[currPPoint]
        match findOverlappingLeader currentBBL leaders (i+1) with
        | Ok nextAddr ->
          let nextPPoint = ProgramPoint (nextAddr, 0)
          let fst, snd = currentBBL.Cut nextAddr
          bbls[currPPoint] <- fst
          bbls[nextPPoint] <- snd
          dividedEdges.Add ((currPPoint, nextPPoint))
        | Error _ -> ()
    done
    Ok dividedEdges

  /// Number of BBLs in the factory.
  member _.Count with get() = bbls.Count

  /// Scan all directly reachable intra-procedural BBLs from the given
  /// addresses. This function does not handle indirect branches nor call
  /// instructions. It always assumes that a call instruction will never return
  /// in order to avoid parsing incorrect BBLs. Fall-through BBLs should be
  /// considered only after we know that the target function can return (after a
  /// no-return analysis), which is not the scope of BBLFactory. In the end,
  /// this function returns a list of divided edges, which are pairs of BBL
  /// addresses that have been created from a single BBL by splitting it. A BBL
  /// can be divided if there is a new control flow target within the BBL.
  /// When the `allowOverlap` argument is true, however, we do not split BBLs
  /// and allow overlapping BBLs. This is useful when we analyze EVM binaries,
  /// for instance.
  member _.ScanBBLs (addrs,
                     [<Optional; DefaultParameterValue(false)>] allowOverlap) =
    task {
      let channel = BufferBlock<Addr * IInstruction list * int> ()
      instrProducer channel addrs |> ignore
      let! isSuccessful = bblLifter channel
      if isSuccessful then
        return if allowOverlap then Ok (List ()) else commit ()
      else return Error ErrorCase.ParsingFailure
    }

  /// Peek the BBL at the given address without caching it. This function is
  /// useful when we want to check if an arbitrary address contains a meaningful
  /// BBL without affecting the BBLFactory state.
  member _.PeekBBL (addr) =
    let rec parse acc addr =
      match instrs.TryFind addr with
      | Ok ins ->
        let nextAddr = addr + uint64 ins.Length
        if ins.IsTerminator () then Ok (List.rev (ins :: acc))
        else parse (ins :: acc) nextAddr
      | Error _ ->
#if CFGDEBUG
        dbglog ManagerTid (nameof BBLFactory)
        <| $"Failed to parse instruction at {addr:x}"
#endif
        Error (List.rev acc)
    parse [] addr

  /// Check if there is a BBL at the given program point.
  member _.Contains (ppoint: ProgramPoint) = bbls.ContainsKey ppoint

  /// Find an existing BBL that is located at the given program point. If there
  /// is no such BBL, then this function will return an error.
  member _.TryFind (ppoint: ProgramPoint) =
    match bbls.TryGetValue ppoint with
    | true, bbl -> Ok bbl
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Find an existing BBL that contains the given program point.
  member _.Find (ppoint: ProgramPoint) = bbls[ppoint]

#if DEBUG
  /// Dump all BBLs in the factory for debugging purposes.
  member _.DumpBBLs () =
    bbls
    |> Seq.iter (fun kv ->
      printfn "# %s" (kv.Key.ToString ())
      kv.Value.Internals.LiftedInstructions
      |> Array.iter (fun lifted ->
        lifted.Stmts
        |> Array.iter (Pp.stmtToString >> (printfn "  -> %s"))
      )
    )
#endif
