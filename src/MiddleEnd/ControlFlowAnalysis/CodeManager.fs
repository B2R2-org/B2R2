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
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

/// CodeManager manages all the processed information about the binary code
/// including *parsed* instructions, their basic blocks, functions, as well as
/// exception handling routines.
type CodeManager (hdl) =
  let insMap = Dictionary<Addr, InstructionInfo> ()
  let bblMap = Dictionary<Addr, BBLInfo> ()
  let excTbl = ExceptionTable (hdl)
  let history = HistoryManager ()
  let fnMaintainer = FunctionMaintainer.Init hdl history

  let newInstructionInfo (hdl: BinHandle) (ins: Instruction) bblAddr =
    let stmts = hdl.LiftOptimizedInstr ins
    { Instruction = ins
      Stmts = stmts
      BBLAddr = bblAddr }

  let rec postProcessInstrs hdl leaderAddr acc instrs =
    match instrs with
    | (ins: Instruction) :: tl ->
      let addr = ins.Address
      let info = newInstructionInfo hdl ins leaderAddr
      insMap[addr] <- info
      postProcessInstrs hdl leaderAddr (info :: acc) tl
    | [] -> acc

  /// This function *NEVER* returns an empty list.
  let rec parseSingleBBL (hdl: BinHandle) mode acc pc =
    hdl.Parser.OperationMode <- mode
    match hdl.TryParseInstr (addr=pc) with
    | Ok ins ->
      let nextAddr = pc + uint64 ins.Length
      if ins.IsBBLEnd () || bblMap.ContainsKey nextAddr then
        Ok <| struct (ins :: acc, ins)
      else parseSingleBBL hdl mode (ins :: acc) nextAddr
    | Error _ -> Error pc

  /// Parse an instruction-level basic block starting from the given leader
  /// address. Return new CFG events to handle.
  member __.ParseBBL hdl mode leaderAddr func evts =
    match parseSingleBBL hdl mode [] leaderAddr with
    | Ok (instrs, lastIns) ->
      let inss = postProcessInstrs hdl leaderAddr [] instrs
      let nextAddr = lastIns.Address + uint64 lastIns.Length
      let struct (bbl, evts) =
        BBLManager.parseBBLInfo hdl inss leaderAddr nextAddr func
                                fnMaintainer excTbl evts
      bblMap[leaderAddr] <- bbl
      Ok evts
    | Error addr ->
#if DEBUG
      printfn "Parsing error detected at %x" addr
#endif
      Error ErrorCase.ParsingFailure

  member private __.ScanInstructionsAndLeaders hdl mode sAddr eAddr =
    let leaders = SortedSet<Addr> ([| sAddr |])
    (hdl: BinHandle).Parser.OperationMode <- mode
    let updateLeader (addr, _) =
      if addr >= sAddr && addr <= eAddr then leaders.Add addr |> ignore
      else ()
    let rec linearSweep instrs currAddr =
      if currAddr <= eAddr then
        match hdl.TryParseInstr (addr=currAddr) with
        | Ok ins ->
          let nextAddr = currAddr + uint64 ins.Length
          if not (ins.IsBBLEnd ()) then ()
          else ins.GetNextInstrAddrs () |> Array.iter updateLeader
          linearSweep (ins :: instrs) nextAddr
        | Error _ ->
#if DEBUG
          printfn "Parsing error detected at %x" currAddr
#endif
          Error ErrorCase.ParsingFailure
      else Ok (instrs, leaders)
    linearSweep [] sAddr

  member private __.AccumulateInstrs acc instrs lastAddr leaders revInstrs =
    match revInstrs with
    | (ins: Instruction) :: tl ->
      if (leaders: SortedSet<Addr>).Contains ins.Address then
        let acc = (ins.Address, lastAddr, ins :: instrs) :: acc
        __.AccumulateInstrs acc [] ins.Address leaders tl
      else __.AccumulateInstrs acc (ins :: instrs) lastAddr leaders tl
    | [] -> acc

  member private __.ConvertToInsInfos hdl leader instrs =
    instrs
    |> List.map (fun ins ->
      let info = newInstructionInfo hdl ins leader
      insMap[ins.Address] <- info
      info)

  member private __.PostProcess hdl instrs leaders fn evts =
    let (lastIns: Instruction) = List.head instrs
    let lastAddr = lastIns.Address + uint64 lastIns.Length
    __.AccumulateInstrs [] [] lastAddr leaders instrs
    |> List.fold (fun evts (leaderAddr, nextAddr, instrs) ->
      let inss = __.ConvertToInsInfos hdl leaderAddr instrs
      let struct (bbl, evts) =
        BBLManager.parseBBLInfo hdl inss leaderAddr nextAddr fn
                                fnMaintainer excTbl evts
      bblMap[leaderAddr] <- bbl
      evts
    ) evts

  /// Parse a sequence of instructions starting from the given start address
  /// (sAddr) to the given end address (eAddr) assuming the sequence has no bad
  /// instruction. Unlike `ParseBBL`, this function parses multiple
  /// instruction-level basic blocks, and returns new CFG events to handle.
  member __.ParseSequence hdl mode sAddr eAddr func evts =
    match __.ScanInstructionsAndLeaders hdl mode sAddr eAddr with
    | Ok (instrs, leaders) ->
      __.PostProcess hdl instrs leaders func evts |> Ok
    | Error e -> Error e

  /// Get the current instruction count.
  member __.InstructionCount with get() = insMap.Count

  /// Check if the manager contains parsed InstructionInfo located at the given
  /// address.
  member __.HasInstruction addr = insMap.ContainsKey addr

  /// Access instruction at the given address.
  member __.GetInstruction (addr: Addr) = insMap[addr]

  /// Fold every instruction stored in the CodeManager.
  member __.FoldInstructions fn acc =
    insMap |> Seq.fold fn acc

  /// Get the current basic block count.
  member __.BBLCount with get() = bblMap.Count

  /// Check if the manager contains a basic block starting at the given address.
  member __.HasBBL addr = bblMap.ContainsKey addr

  /// Find the corresponding BBL address from the given instruction address.
  member __.GetBBL addr = bblMap[insMap[addr].BBLAddr]

  /// Try to find the corresponding BBL address from the given instruction
  /// address.
  member __.TryGetBBL addr =
    match insMap.TryGetValue addr with
    | true, ins ->
      match bblMap.TryGetValue ins.BBLAddr with
      | true, bbl -> Some bbl
      | _ -> None
    | _ -> None

  /// Add the given bbl information; update the instruction-to-bbl mapping
  /// information.
  member __.AddBBL blkRange irLeaders funcEntry insAddrs =
    match insAddrs with
    | leaderAddr :: _ ->
      insAddrs
      |> List.iter (fun addr ->
        let ins = insMap[addr]
        insMap[addr] <- { ins with BBLAddr = leaderAddr })
      bblMap[leaderAddr] <-
        BBLManager.initBBLInfo blkRange insAddrs irLeaders funcEntry
    | [] -> ()

  /// Remove the given BBLInfo.
  member __.RemoveBBL (bbl) =
    bblMap.Remove bbl.BlkRange.Min |> ignore

  /// Remove the given BBL located at the bblAddr.
  member __.RemoveBBL (bblAddr) =
    if bblMap.ContainsKey bblAddr then __.RemoveBBL bblMap[bblAddr]
    else ()

  /// Fold every instruction stored in the CodeManager.
  member __.FoldBBLs fn acc =
    bblMap |> Seq.fold fn acc

  member private __.SplitBBLInfo (bbl: BBLInfo) splitAddr splitPp =
    __.RemoveBBL (bbl)
    let fstAddrs, sndAddrs =
      Set.partition (fun insAddr -> insAddr < splitAddr) bbl.InstrAddrs
    let fstAddrs = Set.toList fstAddrs
    let sndAddrs = Set.toList sndAddrs
    let fstLeaders, sndLeaders =
      Set.add splitPp bbl.IRLeaders
      |> Set.partition (fun pp -> pp < splitPp)
    let oldRange = bbl.BlkRange
    let fstRange = AddrRange (oldRange.Min, splitAddr - 1UL)
    let sndRange = AddrRange (splitAddr, oldRange.Max)
    let entry = bbl.FunctionEntry
    __.AddBBL fstRange fstLeaders entry fstAddrs
    __.AddBBL sndRange sndLeaders entry sndAddrs

  /// This is when a contiguous bbl (it is even contiguous at the IR-level) is
  /// divided into two at the splitPoint.
  member private __.SplitCFG fn prevBBL splitPoint evts =
    let bblPoint = (* The program point of the dividing block. *)
      prevBBL.IRLeaders
      |> Set.partition (fun pp -> pp < splitPoint)
      |> fst |> Set.maxElement
    (fn: RegularFunction).SplitBBL (bblPoint, splitPoint) |> ignore
    Some bblPoint, CFGEvents.updateEvtsAfterBBLSplit bblPoint splitPoint evts

  /// Split the given basic block into two at the given address (splitAddr), and
  /// returns a pair of (the address of the front bbl after the cut-out, and new
  /// events). The front bbl may not exist if the split point is at the address
  /// of an existing bbl leader.
  member __.SplitBlock bbl splitAddr evts =
    let splitPp = ProgramPoint (splitAddr, 0)
#if CFGDEBUG
    dbglog (nameof CodeManager) "Split BBL @ %x%s"
      splitAddr (if Set.contains splitPp bbl.IRLeaders then " (& CFG)" else "")
#endif
    let func = fnMaintainer.FindRegular bbl.FunctionEntry
    __.SplitBBLInfo bbl splitAddr splitPp
    if Set.contains splitPp bbl.IRLeaders then None, evts
    else __.SplitCFG func bbl splitPp evts

  member private __.MergeBBLInfoAndReplaceInlinedAssembly addrs fstBBL sndBBL =
    let restAddrs = List.tail addrs
    __.RemoveBBL (bbl=fstBBL)
    __.RemoveBBL (bbl=sndBBL)
    let blkRange = AddrRange (fstBBL.BlkRange.Min, sndBBL.BlkRange.Max)
    let leaders =
      Set.union fstBBL.IRLeaders sndBBL.IRLeaders
      |> Set.filter (fun leader ->
        not <| List.contains leader.Address restAddrs)
    let addrs =
      Set.union fstBBL.InstrAddrs sndBBL.InstrAddrs
      |> Set.filter (fun addr -> not <| List.contains addr restAddrs)
      |> Set.toList
    let entry = fstBBL.FunctionEntry
    __.AddBBL blkRange leaders entry addrs

  member __.ReplaceInlinedAssemblyChunk insAddrs (chunk: Instruction) evts =
    let fstBBL = __.GetBBL chunk.Address
    let sndBBL = __.GetBBL (fstBBL.BlkRange.Max + 1UL)
    __.MergeBBLInfoAndReplaceInlinedAssembly insAddrs fstBBL sndBBL
    let fn = fnMaintainer.FindRegular fstBBL.FunctionEntry
    let srcPoint = fstBBL.IRLeaders.MaximumElement
    let dstPoint = sndBBL.IRLeaders.MinimumElement
    let dstLeaders = sndBBL.IRLeaders
    fn.MergeVerticesWithInlinedAsmChunk (insAddrs, srcPoint, dstLeaders, chunk)
    CFGEvents.updateEvtsAfterBBLMerge srcPoint dstPoint evts

  /// Update function entry information for the basic block located at the given
  /// address.
  member __.UpdateFunctionEntry bblAddr funcEntry =
    match bblMap.TryGetValue bblAddr with
    | true, bbl ->
      let bbl = { bbl with FunctionEntry = funcEntry }
      bblMap[bbl.BlkRange.Min] <- bbl
    | _ -> ()

  /// The BBL had been created as a non-function bbl; there was a jump edge to
  /// this BBL. However, we later found that this block was a function and the
  /// jump edge must be changed to a tail-call edge. So we turn the BBL into a
  /// function. We call this process as BBL promotion.
  member __.PromoteBBL hdl bblAddr (bbl: BBLInfo) evts =
#if CFGDEBUG
    dbglog (nameof CodeManager) "Turn BBL @ %x into func" bblAddr
#endif
    let entry = bbl.FunctionEntry
    let prevFn = fnMaintainer.FindRegular entry
    let vertices, fn = prevFn.SplitFunction (hdl, bblAddr)
    vertices
    |> Set.iter (fun v ->
      let addr = v.VData.PPoint.Address
      let bbl = __.GetBBL addr
      __.UpdateFunctionEntry bbl.BlkRange.Min bblAddr)
    fnMaintainer.AddFunction fn
    fn,
    CFGEvents.updateEvtsAfterFuncSplit fn evts
    |> CFGEvents.addPerFuncAnalysisEvt entry

  /// Return the exception table.
  member __.ExceptionTable with get() = excTbl

  /// Return the function maintainer.
  member __.FunctionMaintainer with get() = fnMaintainer

  /// Return the history manager.
  member __.HistoryManager with get() = history

  member private __.RemoveFunction fnAddr =
    match fnMaintainer.TryFindRegular fnAddr with
    | Some fn ->
      fn.IterRegularVertexPps (fun pp -> __.RemoveBBL pp.Address)
      fnMaintainer.RemoveFunction fnAddr
    | None -> () (* Already removed. *)

  member private __.RollBackFact evts fact =
#if CFGDEBUG
    dbglog (nameof CodeManager) "Rollback %s" (HistoricalFact.toString fact)
#endif
    match fact with
    | CreatedFunction (fnAddr) ->
      __.RemoveFunction fnAddr
      CFGEvents.addFuncEvt fnAddr ArchOperationMode.NoMode evts (* XXX *)

  member __.RollBack (evts, fnAddrs: Addr list) =
    fnAddrs
    |> List.fold (fun evts fnAddr ->
      history.PeekFunctionHistory fnAddr
      |> Array.fold __.RollBackFact evts
    ) evts
