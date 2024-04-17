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
open System.Collections.Immutable
open System.Collections.Concurrent
open System.Threading.Tasks
open System.Threading.Tasks.Dataflow
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowGraph

/// Per-function factory for basic blocks. Each BBL is memoized so that we do
/// not create multiple BBLs for the same address. As this is a per-function
/// structure, each function may see overlapping basic blocks.
type BBLFactory<'Abs when 'Abs: null> (hdl: BinHandle,
                                       instrs) =
  let interProceduralLeaders = HashSet<Addr> ()
  let bbls = ConcurrentDictionary<ProgramPoint, IRBasicBlock<'Abs>> ()

  let rec parseBlock (channel: BufferBlock<_>) acc insCount addr leader mode =
    match (instrs: InstructionCollection).TryFind (addr, mode) with
    | Ok ins ->
      let nextAddr = addr + uint64 ins.Length
      if ins.IsTerminator () || interProceduralLeaders.Contains nextAddr then
        channel.Post (leader, ins :: acc, insCount + 1) |> ignore
        ins.GetNextInstrAddrs () |> Ok
      else parseBlock channel (ins :: acc) (insCount + 1) nextAddr leader mode
    | Error e ->
#if CFGDEBUG
      dbglog 0 (nameof BBLFactory) $"Failed to parse instruction at {addr:x}"
#endif
      Error e

  /// Parse from the given address and return reachable addresses. If there
  /// exists a BBL at the given address, then simply return an empty array. When
  /// parsing fails, this function can return an error result.
  let tryParse channel addr mode =
    if interProceduralLeaders.Contains addr then Ok [||]
    else parseBlock channel [] 0 addr addr mode

  let instrProducer channel addrs =
    let queue = Queue<Addr * ArchOperationMode> (collection=addrs)
    task {
      while queue.Count <> 0 do
        let addr, mode = queue.Dequeue ()
        match tryParse channel addr mode with
        | Ok nextAddrs -> nextAddrs |> Array.iter queue.Enqueue
        | Error e ->
          eprintfn "%s" (ErrorCase.toString e)
          raise ParsingFailureException (* This is a fatal error. *)
      channel.Complete ()
    }

  /// The given list is reversed, so we fill the array in reverse order.
  let rec liftAndFill lunit bblAddr (arr: LiftedInstruction[]) instrs idx =
    match instrs with
    | ins :: tl ->
      let stmts = (lunit: LiftingUnit).LiftInstruction (ins=ins, optimize=true)
      let liftedIns = { Original = ins; Stmts = stmts; BBLAddr = bblAddr }
      arr[idx] <- liftedIns
      liftAndFill lunit bblAddr arr tl (idx - 1)
    | [] -> arr

  let scanIntraLeaders (liftedInstrs: LiftedInstruction[]) =
    let labelMap = Dictionary<Addr * Symbol, ProgramPoint> ()
    let intraLeaders = List<int * int> () (* instruction idx, stmt idx *)
    for i = 0 to liftedInstrs.Length - 1 do
      let liftedIns = liftedInstrs[i]
      for j = 0 to liftedIns.Stmts.Length - 1 do
        match liftedIns.Stmts[j].S with
        | LMark symb ->
          let insAddr = liftedIns.Original.Address
          labelMap[(insAddr, symb)] <- ProgramPoint (insAddr, j)
          intraLeaders.Add ((i, j))
        (* JMP PC means that the instruction jumps to itself, but this is not
           allowed in our IR. We should fix the lifter in such a case. *)
        | InterJmp ({ E = PCVar _ }, InterJmpKind.Base)
        | InterCJmp (_, { E = PCVar _ }, _)
        | InterCJmp (_, _, { E = PCVar _ }) -> Utils.impossible ()
        | _ -> ()
    struct (labelMap, intraLeaders)

  let extractInstrs (liftedInstrs: LiftedInstruction[]) startIdx endIdx =
    match startIdx, endIdx with
    | (insStartIdx, stmtStartIdx), Some (insEndIdx, stmtEndIdx) ->
      let out = liftedInstrs[insStartIdx..insEndIdx]
      let last = out.Length - 1
      out[0] <- { out[0] with Stmts = out[0].Stmts[stmtStartIdx..] }
      out[last] <- { out[last] with Stmts = out[last].Stmts[..stmtEndIdx] }
      out
    | (insStartIdx, stmtStartIdx), None ->
      let out = liftedInstrs[insStartIdx..]
      out[0] <- { out[0] with Stmts = out[0].Stmts[stmtStartIdx..] }
      out

  let rec extractLabelInfo (labelMap: Dictionary<_, _>) liftedIns insAddr idx =
    match liftedIns.Stmts[idx].S with
    | IEMark _ -> extractLabelInfo labelMap liftedIns insAddr (idx - 1)
    | Jmp { E = Name symbol } ->
      let key = insAddr, symbol
      [ KeyValuePair (symbol, labelMap[key]) ]
    | CJmp (_, { E = Name symbol1 }, { E = Name symbol2 }) ->
      let key1 = insAddr, symbol1
      let key2 = insAddr, symbol2
      [ KeyValuePair (symbol1, labelMap[key1])
        KeyValuePair (symbol2, labelMap[key2]) ]
    | CJmp (_, { E = Name symbol }, _)
    | CJmp (_, _, { E = Name symbol }) ->
      let key = insAddr, symbol
      [ KeyValuePair (symbol, labelMap[key]) ]
    | _ -> []

  let buildLabelMap labelMap liftedIns =
    let insAddr = liftedIns.Original.Address
    extractLabelInfo labelMap liftedIns insAddr (liftedIns.Stmts.Length - 1)
    |> ImmutableDictionary.CreateRange

  let addIRBasicBlock liftedInstrs labelMap prevInsIdx prevStmtIdx endIdx =
    let instrs = extractInstrs liftedInstrs (prevInsIdx, prevStmtIdx) endIdx
    let ppoint = ProgramPoint (instrs[0].Original.Address, prevStmtIdx)
    let lastIns = instrs[instrs.Length - 1]
    let labelMap = buildLabelMap labelMap lastIns
    let bbl = IRBasicBlock.CreateRegular (instrs, ppoint, labelMap)
    bbls.TryAdd (ppoint, bbl) |> ignore

  let rec gatherIntraBBLs liftedInstrs labelMap prevInsIdx prevStmtIdx indices =
    match indices with
    | (insIdx, stmtIdx) as endIdx :: tl ->
      addIRBasicBlock liftedInstrs labelMap prevInsIdx prevStmtIdx (Some endIdx)
      gatherIntraBBLs liftedInstrs labelMap insIdx stmtIdx tl
    | [] ->
      addIRBasicBlock liftedInstrs labelMap prevInsIdx prevStmtIdx None

  let liftBlock liftingUnit leaderAddr (instrs: Instruction list) insCount =
    assert (insCount <> 0)
    interProceduralLeaders.Add leaderAddr |> ignore
    let arr = Array.zeroCreate insCount
    let arr = liftAndFill liftingUnit leaderAddr arr instrs (insCount - 1)
    let struct (labelMap, intraLeaders) = scanIntraLeaders arr
    if intraLeaders.Count = 0 then
      let ppoint = ProgramPoint (leaderAddr, 0)
      let bbl = IRBasicBlock.CreateRegular (arr, ppoint)
      bbls.TryAdd (ppoint, bbl) |> ignore
    else gatherIntraBBLs arr labelMap 0 0 (Seq.toList intraLeaders)

  let bblLifter (channel: BufferBlock<Addr * Instruction list * int>) =
    let liftingUnit = hdl.NewLiftingUnit ()
    task {
      while! channel.OutputAvailableAsync () do
        match channel.TryReceive () with
        | true, (leaderAddr, instrs, insCount) ->
          liftBlock liftingUnit leaderAddr instrs insCount
        | false, _ -> ()
    }

  let getSortedLeaders () =
    interProceduralLeaders
    |> Seq.toArray
    |> Array.sort

  /// Iterate over all the BBL leaders and split the BBLs if necessary.
  let commit () =
    let leaders = getSortedLeaders ()
    for i = 0 to leaders.Length - 1 do
      let leaderAddr = leaders[i]
      let ppoint = ProgramPoint (leaderAddr, 0)
      if bbls.ContainsKey ppoint then ()
      else
        let prevPP = ProgramPoint (leaders[i-1], 0)
        match bbls.TryGetValue prevPP with
        | true, prevBBL ->
          let fst, snd = prevBBL.Cut leaderAddr
          bbls[prevPP] <- fst
          bbls[ppoint] <- snd
        | false, _ -> Utils.impossible ()
    done

  /// Number of BBLs in the factory.
  member __.Count with get() = bbls.Count

  /// Scan all directly reachable BBLs from the given addresses. This function
  /// does not handle indirect branches nor fall-throughs of call instructions.
  /// In particular, it always assumes that a call instruction will never return
  /// in order to avoid parsing incorrect BBLs. Fall-through BBLs should be
  /// considered only after we know that the target function can return (after a
  /// no-return analysis), which is not the scope of BBLFactory.
  member __.ScanBBLs addrs =
    task {
      let channel = BufferBlock<Addr * Instruction list * int> ()
      instrProducer channel addrs |> ignore
      let lifters = Array.init 1 (fun _ -> bblLifter channel) (* TODO: opt? *)
      let! _ = Task.WhenAll lifters
      return commit ()
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
