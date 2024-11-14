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
/// structure, each different function has its own BBLFactory. The third
/// argument `allowOverlap` controls whether we allow overlapping basic blocks
/// or not. When `allowOverlap` is false, we split basic blocks whenever we
/// found an edge that jumps to the middle of an existing basic block. However,
/// when it is true, we do not split basic blocks and allow overlapping basic
/// blocks. Overlapping basic blocks could be useful when we analyze EVM
/// binaries, for instance.
[<AllowNullLiteral>]
type BBLFactory (hdl: BinHandle,
                 instrs,
                 [<Optional; DefaultParameterValue(false)>] allowOverlap) =
  let interProceduralLeaders = ConcurrentDictionary<Addr, unit> ()
  let bbls = ConcurrentDictionary<ProgramPoint, LowUIRBasicBlock> ()

  let rec parseBlock (channel: BufferBlock<_>) acc insCount addr leader mode =
    match (instrs: InstructionCollection).TryFind (addr, mode) with
    | Ok ins ->
      let nextAddr = addr + uint64 ins.Length
      if ins.IsTerminator () || interProceduralLeaders.ContainsKey nextAddr then
        channel.Post (leader, ins :: acc, insCount + 1) |> ignore
        if ins.IsCall () then Ok [||]
        else
          ins.GetNextInstrAddrs ()
          |> Array.choose (fun (nextAddr, nextMode) ->
            if nextMode = mode then Some nextAddr else None)
          |> Ok
      else parseBlock channel (ins :: acc) (insCount + 1) nextAddr leader mode
    | Error e ->
#if CFGDEBUG
      dbglog ManagerTid (nameof BBLFactory)
      <| $"Failed to parse instruction at {addr:x}"
#endif
      Error e

  /// Parse from the given address and return reachable addresses. If there
  /// exists a BBL at the given address, then simply return an empty array. When
  /// parsing fails, this function can return an error result.
  let tryParse channel addr mode =
    if interProceduralLeaders.ContainsKey addr then Ok [||]
    else parseBlock channel [] 0 addr addr mode

  let visited = ConcurrentDictionary<Addr, unit> ()

  let instrProducer channel mode addrs =
    let queue = Queue<Addr> (collection=addrs)
    task {
      while queue.Count <> 0 do
        let addr = queue.Dequeue ()
        if visited.ContainsKey addr then ()
        else
          visited.TryAdd (addr, ()) |> ignore
          match tryParse channel addr mode with
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
    | { S = ISMark _ } -> true
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
      intraLeaders.AddFirst ((idx, 0))
    elif fst lastLeader.Value < idx then
      intraLeaders.AddAfter (lastLeader, (idx, 0))
    else addLeaderHead intraLeaders lastLeader.Previous idx

  let scanIntraLeaders (liftedInss: LiftedInstruction[]) =
    let lblMap = Dictionary<Addr * Symbol, ProgramPoint> ()
    let intraLeaders = LinkedList<int * int> () (* instruction ndx, stmt ndx *)
    let mutable hasIntraFlow = false (* has intra control flow(s)? *)
    for i = 0 to liftedInss.Length - 1 do
      let liftedIns = liftedInss[i]
      if hasIntraFlow then intraLeaders.AddLast ((i, 0)) |> ignore else ()
      hasIntraFlow <- false
      for j = 0 to liftedIns.Stmts.Length - 1 do
        match liftedIns.Stmts[j].S with
        | LMark symb ->
          let insAddr = liftedIns.Original.Address
          lblMap[(insAddr, symb)] <- ProgramPoint (insAddr, j)
          intraLeaders.AddLast ((i, j)) |> ignore
          hasIntraFlow <- true
        | InterJmp ({ E = PCVar _ }, InterJmpKind.Base)
        | InterCJmp (_, { E = PCVar _ }, _)
        | InterCJmp (_, _, { E = PCVar _ }) ->
          (* JMP PC means that the instruction jumps to itself. *)
          if i = 0 then () (* Ignore if it is the first lifted instruction. *)
          else addLeaderHead intraLeaders intraLeaders.Last i |> ignore
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
    match liftedIns.Stmts[ndx].S with
    | IEMark _ -> extractLabelInfo lblMap liftedIns insAddr (ndx - 1)
    | Jmp { E = Name symbol } ->
      let key = insAddr, symbol
      [ KeyValuePair (symbol, lblMap[key]) ]
    | CJmp (_, { E = Name symbol1 }, { E = Name symbol2 }) ->
      let key1 = insAddr, symbol1
      let key2 = insAddr, symbol2
      [ KeyValuePair (symbol1, lblMap[key1])
        KeyValuePair (symbol2, lblMap[key2]) ]
    | CJmp (_, { E = Name symbol }, _)
    | CJmp (_, _, { E = Name symbol }) ->
      let key = insAddr, symbol
      [ KeyValuePair (symbol, lblMap[key]) ]
    | _ -> []

  let buildLabelMap lblMap liftedIns =
    let insAddr = liftedIns.Original.Address
    extractLabelInfo lblMap liftedIns insAddr (liftedIns.Stmts.Length - 1)
    |> ImmutableDictionary.CreateRange

  let addInterProceduralLeader addr =
    interProceduralLeaders.TryAdd (addr, ()) |> ignore

  let addIRBBL domJT liftedInss lblMap prevInsNdx prevStmtNdx endNdx =
    let instrs = extractInstrs liftedInss (prevInsNdx, prevStmtNdx) endNdx
    let ppoint = ProgramPoint (instrs[0].Original.Address, prevStmtNdx)
    let lastIns = instrs[instrs.Length - 1]
    let lblMap = buildLabelMap lblMap lastIns
    let bbl = LowUIRBasicBlock.CreateRegular (instrs, ppoint, lblMap, domJT)
    if prevStmtNdx = 0 then addInterProceduralLeader ppoint.Address else ()
    bbls.TryAdd (ppoint, bbl) |> ignore

  let rec gatherIntraBBLs domJT liftedInss lblMap prevInsNdx prevStmtNdx idxs =
    match idxs with
    | (insNdx, stmtNdx) as endNdx :: tl ->
      addIRBBL domJT liftedInss lblMap prevInsNdx prevStmtNdx (Some endNdx)
      gatherIntraBBLs domJT liftedInss lblMap insNdx stmtNdx tl
    | [] ->
      addIRBBL domJT liftedInss lblMap prevInsNdx prevStmtNdx None

  let liftBlock domJT liftingUnit leaderAddr instrs insCount =
    assert (insCount <> 0)
    addInterProceduralLeader leaderAddr
    let arr = Array.zeroCreate insCount
    let arr = liftAndFill liftingUnit leaderAddr arr instrs (insCount - 1)
    let struct (lblMap, intraLeaders) = scanIntraLeaders arr
    if intraLeaders.Count = 0 then
      let ppoint = ProgramPoint (leaderAddr, 0)
      let bbl = LowUIRBasicBlock.CreateRegular (arr, ppoint, domJT)
      bbls.TryAdd (ppoint, bbl) |> ignore
    else
      gatherIntraBBLs domJT arr lblMap 0 0 (Seq.toList intraLeaders)

  let bblLifter domJT (channel: BufferBlock<Addr * Instruction list * int>) =
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
            try liftBlock domJT liftingUnit leaderAddr instrs insCount
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

  /// Iterate over all the BBL leaders and split the BBLs if necessary.
  let commit () =
    let leaders = getSortedLeaders ()
    let dividedEdges = List ()
    for i = 0 to leaders.Length - 1 do
      if i = leaders.Length - 1 then ()
      else
        let nextAddr = leaders[i+1]
        let currPPoint = ProgramPoint (leaders[i], 0)
        let nextPPoint = ProgramPoint (nextAddr, 0)
        let currentBBL = bbls[currPPoint]
        if (currentBBL :> IAddressable).Range.IsIncluding nextAddr
          && isInstructionAddress currentBBL nextAddr
        then
          let fst, snd = currentBBL.Cut nextAddr
          bbls[currPPoint] <- fst
          bbls[nextPPoint] <- snd
          dividedEdges.Add ((currPPoint, nextPPoint))
        else
          (* We do *not* split BBLs when there is an instruction-level overlap.
             One may still split such BBLs by finding a merging instruction, but
             it is not desirable as it can introduce more bogus edges. For
             example, let BBL_1 and BBL_2 be two BBLs that are located at
             address 1 and 2, respectively. BBL_1 has three instructions (i_1,
             i_3, i_5) where i_n is the instruction at address n. BBL_2 has
             three instructions (i_2, i_3, i_5). And let i_5 be an indirect jump
             instruction (jmp rcx), representing a switch-case statement. One
             may split both BBLs at address 3, but it will introduce a bogus
             edge reaching the jmp instruction, which makes our dataflow
             analysis fails to detect the jump table for the jmp instruction.
             However, by *not* splitting the BBLs and having the two independent
             BBLs untouched, we can still detect the jump table for the jmp
             instruction (although the two BBLs have an overlapping jmp
             instruction), and this allows us to perform a more precise jump
             table analysis in the end. *)
          ()
    done
    Ok dividedEdges

  /// Number of BBLs in the factory.
  member __.Count with get() = bbls.Count

  /// Whether the factory allows overlapping BBLs or not.
  member __.AllowOverlap with get() = allowOverlap

  /// Scan all directly reachable intra-procedural BBLs from the given
  /// addresses. This function does not handle indirect branches nor call
  /// instructions. It always assumes that a call instruction will never return
  /// in order to avoid parsing incorrect BBLs. Fall-through BBLs should be
  /// considered only after we know that the target function can return (after a
  /// no-return analysis), which is not the scope of BBLFactory. In the end,
  /// this function returns a list of divided edges, which are pairs of BBL
  /// addresses that have been created from a single BBL by splitting it. A BBL
  /// can be divided if there is a new control flow target within the BBL.
  member __.ScanBBLs domJT mode addrs =
    task {
      let channel = BufferBlock<Addr * Instruction list * int> ()
      instrProducer channel mode addrs |> ignore
      let! isSuccessful = bblLifter domJT channel
      if isSuccessful then
        return if allowOverlap then Ok (List ()) else commit ()
      else return Error ErrorCase.ParsingFailure
    }

  /// Check if there is a BBL at the given program point.
  member __.Contains (ppoint: ProgramPoint) = bbls.ContainsKey ppoint

  /// Find an existing BBL that is located at the given program point. If there
  /// is no such BBL, then this function will return an error.
  member __.TryFind (ppoint: ProgramPoint) =
    match bbls.TryGetValue ppoint with
    | true, bbl -> Ok bbl
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Find an existing BBL that contains the given address.
  member __.Find (ppoint: ProgramPoint) = bbls[ppoint]

#if DEBUG
  /// Dump all BBLs in the factory for debugging purposes.
  member __.DumpBBLs () =
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
