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

namespace B2R2.BinCorpus

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// A mapping from an instruction address to computed jump targets. This table
/// stores only "computed" jump targets.
type JmpTargetMap = Map<Addr, Addr list>

/// Jump table (for switch-case) information: (table range * entry size).
type JumpTableInfo = AddrRange * RegType

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
  /// Instruction map.
  InstrMap: InstrMap
  /// Label map.
  LabelMap: Map<Symbol, Addr * int>
  /// Leader set.
  LeaderInfos: Set<LeaderInfo>
  /// Recovered function entries.
  RecoveredEntries: Set<LeaderInfo>
  /// Caller map.
  CallerMap: CallerMap
  /// Callee map.
  CalleeMap: CalleeMap
  /// Indirect branches' target addresses.
  IndirectBranchMap: Map<Addr, Set<Addr> * JumpTableInfo option>
  /// Excluded callee addresses.
  ExcludedCallees: Set<Addr>
}

[<RequireQualifiedAccess>]
module Apparatus =

  /// Return the list of function addresses from the Apparatus.
  let getFunctionAddrs app =
    app.CalleeMap.Callees
    |> Seq.choose (fun c -> c.Addr)

  /// Return the list of callees that have a concrete mapping to the binary.
  let getInternalFunctions app =
    app.CalleeMap.Callees
    |> Seq.filter (fun c -> c.Addr.IsSome)

  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the other analyses.
  let private getInitialEntryPoints hdl =
    let fi = hdl.FileInfo
    fi.GetFunctionAddresses ()
    |> Seq.map (fun addr -> LeaderInfo.Init (hdl, addr))
    |> Set.ofSeq
    |> fun set ->
      match fi.EntryPoint with
      | None -> set
      | Some entry -> Set.add (LeaderInfo.Init (hdl, entry)) set

  let private findLabels complexInstrs labels (KeyValue (addr, instr)) =
    instr.Stmts
    |> Array.foldi (fun labels idx stmt ->
         match stmt with
         | LMark (s) ->
           (complexInstrs: HashSet<Addr>).Add addr |> ignore
           Map.add s (addr, idx) labels
         | _ -> labels) labels
    |> fst

  /// A temporary accumulator for folding all the IR statements.
  type private StmtAccumulator = {
    /// Label name to a ProgramPoint (Addr * int).
    Labels: Map<Symbol, Addr * int>
    /// Complex instruction set. A complex instruction is an instruction that
    /// contains intra-branches.
    ComplexInstrs: HashSet<Addr>
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

  /// Fold all the statements to get the leaders, function entries, etc.
  let private foldStmts hdl indMap exclusion acc i =
    i.Stmts
    |> Array.fold (fun acc stmt ->
      match stmt with
      | Jmp (Name s) -> addLabelLeader s i acc
      | CJmp (_, Name s1, Name s2) ->
        addLabelLeader s1 i acc |> addLabelLeader s2 i
      | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
        let addr = BitVector.toUInt64 addr
        if Set.contains addr exclusion then acc
        elif hdl.FileInfo.IsValidAddr addr then
          addAddrLeader addr i acc
          |> addAddrLeader
            (i.Instruction.Address + uint64 i.Instruction.Length) i
          |> addFunction addr
        else acc
      | InterJmp (_, Num addr, _) ->
        let addr = BitVector.toUInt64 addr
        if hdl.FileInfo.IsValidAddr addr then addAddrLeader addr i acc
        else acc
      | InterCJmp (_, _, Num addr1, Num addr2) ->
        let addr1 = BitVector.toUInt64 addr1
        let addr2 = BitVector.toUInt64 addr2
        if hdl.FileInfo.IsValidAddr addr1 && hdl.FileInfo.IsValidAddr addr2 then
          addAddrLeader addr1 i acc
          |> addAddrLeader addr2 i
        else acc
      | InterCJmp (_, _, Num addr, _)
      | InterCJmp (_, _, _, Num addr) ->
        let addr = BitVector.toUInt64 addr
        if hdl.FileInfo.IsValidAddr addr then addAddrLeader addr i acc
        else acc
      | InterJmp (_, _, InterJmpInfo.IsCall) -> (* indirect call *)
        (* FIXME: we will have to handle newly found callees *)
        let fallAddr = i.Instruction.Address + uint64 i.Instruction.Length
        if hdl.FileInfo.IsValidAddr fallAddr then addAddrLeader fallAddr i acc
        else acc
      | InterJmp (_, _, _) ->
        match Map.tryFind i.Instruction.Address indMap with
        | None -> acc
        | Some (targets, _) ->
          targets |> Set.fold (fun acc target -> addAddrLeader target i acc) acc
      | SideEffect (SysCall)
      | SideEffect (Interrupt _) ->
        let fallAddr = i.Instruction.Address + uint64 i.Instruction.Length
        if hdl.FileInfo.IsValidAddr fallAddr then addAddrLeader fallAddr i acc
        else acc
      | IEMark (a) when acc.ComplexInstrs.Contains i.Instruction.Address ->
        addAddrLeader a i acc
      | _ -> acc) acc

  let rec private findLeaders hdl acc (instrMap: InstrMap) foldStmts =
    let labels = instrMap |> Seq.fold (findLabels acc.ComplexInstrs) Map.empty
    let acc = { acc with Labels = labels }
    let acc = instrMap.Values |> Seq.fold foldStmts acc
    let oldCount = instrMap.Count
    let instrMap, _ =
      acc.Leaders
      |> Set.filter (fun l -> not <| instrMap.ContainsKey l.Point.Address)
      |> InstrMap.update hdl instrMap None
    if oldCount <> instrMap.Count then findLeaders hdl acc instrMap foldStmts
    else struct (instrMap, acc)

  let updateNoReturnInfo oldNoRet (calleeMap: CalleeMap) =
    oldNoRet |> Seq.iter (fun (addr: Addr) ->
      match calleeMap.Find addr with
      | None -> ()
      | Some c -> c.IsNoReturn <- true)
    calleeMap

  let private buildApp hdl entries leaders instrMap indMap noRets exclusion =
    let acc =
      { Labels = Map.empty; ComplexInstrs = HashSet ()
        Leaders = leaders; FunctionAddrs = entries }
    (* Find all possible leaders by scanning lifted IRs. We need to do this at
       the IR-level because LowUIR may have intra-instruction branches. *)
    let struct (instrMap, acc) =
      findLeaders hdl acc instrMap (foldStmts hdl indMap exclusion)
    let calleeMap =
      CalleeMap.build hdl acc.FunctionAddrs instrMap
      |> updateNoReturnInfo noRets
    { InstrMap = instrMap
      LabelMap = acc.Labels
      LeaderInfos = acc.Leaders
      RecoveredEntries = Set.map (fun a -> LeaderInfo.Init (hdl, a)) entries
      IndirectBranchMap = indMap
      CallerMap = CallerMap.build calleeMap
      CalleeMap = calleeMap
      ExcludedCallees = exclusion }

  let private initApp hdl auxLeaders exclusion bblBound =
    match auxLeaders with
    | None -> getInitialEntryPoints hdl
    | Some leaders -> leaders
    |> fun leaders ->
      let entries = leaders |> Seq.map (fun i -> i.Point.Address) |> Set.ofSeq
      (* First, recursively parse all possible instructions. *)
      let instrMap, leaders = InstrMap.build hdl leaders bblBound
      buildApp hdl entries leaders instrMap Map.empty Seq.empty exclusion

  let inline private append seq = Seq.foldBack Set.add seq

  let private computeFuncAddrs app entries =
    entries
    |> Seq.fold (fun acc leader ->
      Set.add leader.Point.Address acc) (getFunctionAddrs app |> Set.ofSeq)

  let private updateApp hdl app entries leaders =
    let entries = Seq.foldBack Set.add entries app.RecoveredEntries
    let leaders = app.LeaderInfos |> append leaders |> append entries
    let funcAddrs = computeFuncAddrs app entries
    let instrMap, _ = InstrMap.update hdl app.InstrMap None leaders
    let indMap = app.IndirectBranchMap
    let noRets =
      app.CalleeMap.Callees
      |> Seq.filter (fun callee -> callee.IsNoReturn)
      |> Seq.choose (fun callee -> callee.Addr)
    buildApp hdl funcAddrs leaders instrMap indMap noRets app.ExcludedCallees

  /// Create a binary apparatus from the given BinHandler. The resulting
  /// apparatus will include default entries found by reading the binary file
  /// itself (including symbols).
  [<CompiledName("Init")>]
  let init hdl =
    initApp hdl None Set.empty None

  /// Create a binary apparatus soley based on the given leaders and exclusion
  /// set of callees. The resulting appratus will not include default entries
  /// found by parsing binary file itself.
  let initByEntries hdl leaders exclusion bblBound =
    initApp hdl (Some leaders) exclusion bblBound

  /// Update instruction info of the given binary apparatus based on the given
  /// function entry addresses and leader infos.
  let update hdl app entries leaders =
    updateApp hdl app entries leaders

  /// Register newly recovered entries to the apparatus.
  let registerRecoveredEntries hdl app entries =
    updateApp hdl app entries Seq.empty

  /// Add a resolved indirect branch target.
  let addIndirectBranchMap app indmap =
    let indmap' =
      Map.fold (fun acc fromAddr indbranchinfo ->
        Map.add fromAddr indbranchinfo acc) app.IndirectBranchMap indmap
    { app with IndirectBranchMap = indmap' }
