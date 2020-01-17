(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinCorpus

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// A mapping from an instruction address to computed jump targets. This table
/// stores only "computed" jump targets.
type JmpTargetMap = Map<Addr, Addr list>

/// <summary>
///   Binary apparatus (Apparatus) contains the key components and information
///   about our CFG analysis, such as all the parsed instructions from the
///   target binary as well as the positions of all the leaders found. This will
///   be updated through our CFG analyses.
/// </summary>
/// <remarks>
///   <para>B2R2's CFG analyses roughly work as follows.</para>
///   <para>
///     In the very first stage, we recursively parse (and lift) binary
///     instructions starting from the given entry point. In this stage, we
///     simply follow concrete edges. Therefore we may miss indirect branches in
///     this stage, but we will handle them later. After parsing the entire
///     binary, we obtain a mapping (InstrMap) from an address to an InsInfo.
///   </para>
///   <para>
///     Next, we recursively traverse every instruction found again as we did in
///     the first stage, but in this stage, we will analyze lifted LowUIR
///     statements to figure out any internal branches (intra-instruction
///     branches). This step is important to gather all possible program points
///     (ProgramPoint), which are a jump target, i.e., a leader. The leader
///     information is stored in the LeaderInfos field.
///   </para>
///   <para>
///     While we compute the leader positions, we mark every call target
///     encountered to build both CallerMap and CalleeMap. Normally, being a
///     call target (i.e., callee) implies being a function entry. However, this
///     is not always the case. We should not always consider a callee as a
///     function. Nevertheless, our lens-based framework can provide a valid CFG
///     at any callee, which can greatly help further analyses.
///   </para>
///   <para>
///     Once Apparatus is constructed, our SCFG module will then build a graph
///     based on the information found in the Apparatus. The details should be
///     found in the SCFG module.
///   </para>
///   <para>
///     Now that we have obtained basic information (Apparatus and SCFG) to work
///     with, we perform some post analyses to improve the information. For
///     example, we remove unnecessary edges from the SCFG by disconnecting
///     return edges from a function that termiates the process (e.g., exit
///     function), and we recover indirect branch targets to discover more
///     instructions. After the post analyses, we may or may not have an updated
///     Apparatus, in which case we rerun the above steps to update our SCFG
///     (with newly found instructions, etc.). We terminate our analysis when
///     our post analayses do not bring a different Apparatus.
///   </para>
/// </remarks>
type Apparatus = {
  InstrMap: InstrMap
  LabelMap: Map<Symbol, Addr * int>
  LeaderInfos: Set<LeaderInfo>
  CallerMap: CallerMap
  CalleeMap: CalleeMap
  /// This is a flag representing whether this Apparatus has been modified
  /// by our post analysis.
  Modified: bool
}

[<RequireQualifiedAccess>]
module Apparatus =
  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the other analyses.
  let private getInitialEntryPoints hdl =
    let fi = hdl.FileInfo
    fi.GetFunctionAddresses ()
    |> Seq.map (fun addr -> LeaderInfo.Init (hdl, addr))
    |> Set.ofSeq
    |> Set.add (LeaderInfo.Init (hdl, fi.EntryPoint))

  let private findLabels labels (KeyValue (addr, instr)) =
    instr.Stmts
    |> Array.foldi (fun labels idx stmt ->
         match stmt with
         | LMark (s) -> Map.add s (addr, idx) labels
         | _ -> labels) labels
    |> fst

  /// A temporary accumulator for folding all the IR statements.
  type private StmtAccumulator = {
    Labels: Map<Symbol, Addr * int>
    /// This is a set of leaders, each of which is a tuple of a ProgramPoint and
    /// an address offset. The offset is used to readjust the address of the
    /// instruction when parsing it (it is mostly 0 though).
    Leaders: Set<LeaderInfo>
    /// Collect all the address that are being a target of a direct call
    /// instruction (not indirect calls, since we don't know the target at this
    /// point).
    FunctionAddrs: Set<Addr>
  }

  let private addLabelLeader s i acc =
    let ppoint = Map.find s acc.Labels |> ProgramPoint
    let leaderInfo = LeaderInfo.Init (ppoint, i.ArchOperationMode, i.Offset)
    (* Replacement will not be made if the same PPoint exsits in the set. *)
    { acc with Leaders = Set.add leaderInfo acc.Leaders }

  let private addAddrLeader addr i acc =
    let leaderInfo =
      LeaderInfo.Init (ProgramPoint (addr, 0), i.ArchOperationMode, i.Offset)
    (* Replacement will not be made if the same PPoint exsits in the set. *)
    { acc with Leaders = Set.add leaderInfo acc.Leaders }

  let private addFunction addr acc =
    { acc with FunctionAddrs = Set.add addr acc.FunctionAddrs }

  /// Fold all the statements to get the leaders, function positions, etc.
  let private foldStmts acc (KeyValue (_, i)) =
    i.Stmts
    |> Array.fold (fun acc stmt ->
      match stmt with
      | Jmp (Name s) -> addLabelLeader s i acc
      | CJmp (_, Name s1, Name s2) ->
        addLabelLeader s1 i acc |> addLabelLeader s2 i
      | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
        let addr = BitVector.toUInt64 addr
        addAddrLeader addr i acc
        |> addAddrLeader (i.Instruction.Address + uint64 i.Instruction.Length) i
        |> addFunction addr
      | InterJmp (_, Num addr, _) ->
        addAddrLeader (BitVector.toUInt64 addr) i acc
      | InterCJmp (_, _, Num addr1, Num addr2) ->
        addAddrLeader (BitVector.toUInt64 addr1) i acc
        |> addAddrLeader (BitVector.toUInt64 addr2) i
      | InterCJmp (_, _, Num addr, _)
      | InterCJmp (_, _, _, Num addr) ->
        addAddrLeader (BitVector.toUInt64 addr) i acc
      | InterJmp (_, _, InterJmpInfo.IsCall) (* indirect call *)
      | SideEffect (SysCall)
      | SideEffect (Interrupt _) ->
        let fallAddr = i.Instruction.Address + uint64 i.Instruction.Length
        addAddrLeader fallAddr i acc
      | _ -> acc) acc

  let rec private findLeaders hdl acc (instrMap: InstrMap) =
    let acc = { acc with Labels = instrMap |> Seq.fold findLabels Map.empty }
    let acc = instrMap |> Seq.fold foldStmts acc
    let oldCount = instrMap.Count
    let instrMap =
      acc.Leaders
      |> Set.filter (fun l -> not <| instrMap.ContainsKey l.Point.Address)
      |> InstrMap.update hdl instrMap
    if oldCount <> instrMap.Count then findLeaders hdl acc instrMap
    else struct (instrMap, acc)

  let private initApparatus hdl auxEntries =
    let initial = getInitialEntryPoints hdl
    let leaders = auxEntries |> Seq.fold (fun set e -> Set.add e set) initial
    let instrMap = InstrMap.build hdl leaders
    (* First, recursively parse all possible instructions. *)
    let addrs = leaders |> Seq.map (fun e -> e.Point.Address) |> Set.ofSeq
    let acc = { Labels = Map.empty; Leaders = leaders; FunctionAddrs = addrs }
#if DEBUG
    printfn "[*] Loaded basic information."
#endif
    (* Then, find all possible leaders by scanning lifted IRs. We need to do
       this at a IR-level because LowUIR may have intra-instruction branches. *)
    let struct (instrMap, acc) = findLeaders hdl acc instrMap
    let calleeMap = CalleeMap.build hdl acc.FunctionAddrs instrMap
#if DEBUG
    printfn "[*] The apparatus is ready to use."
#endif
    { InstrMap = instrMap
      LabelMap = acc.Labels
      LeaderInfos = acc.Leaders
      CallerMap = CallerMap.build calleeMap
      CalleeMap = calleeMap
      Modified = true }

  /// Create a binary apparatus from the given BinHandler.
  [<CompiledName("Init")>]
  let init hdl = initApparatus hdl Seq.empty

  /// Update instruction info for the given binary apparatus based on the given
  /// target addresses. Those addresses should represent a function entry point.
  /// Regular branch destinations should not be handled here.
  let update hdl app addrs =
    if Seq.isEmpty addrs then app
    else initApparatus hdl addrs

  /// Return the list of function addresses from the Apparatus.
  let getFunctionAddrs app =
    app.CalleeMap.Callees
    |> Seq.choose (fun c -> c.Addr)

  /// Return the list of callees that have a concrete mapping to the binary.
  let getInternalFunctions app =
    app.CalleeMap.Callees
    |> Seq.filter (fun c -> c.Addr.IsSome)
