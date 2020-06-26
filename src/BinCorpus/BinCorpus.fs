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
  /// Caller map.
  CallerMap: CallerMap
  /// Callee map.
  CalleeMap: CalleeMap
  /// Function entries.
  Entries: Set<LeaderInfo>
  /// Indirect branches' target addresses.
  IndirectBranchMap: Map<Addr, IndirectBranchInfo>
  /// No-return function info.
  NoReturnInfo: NoReturnInfo
}

and IndirectBranchInfo = {
  /// The host function (owner) of the indirect jump.
  HostFunctionAddr: Addr
  /// Possible target addresses.
  TargetAddresses: Set<Addr>
  /// Information about the corresponding jump table (if exists).
  JumpTableInfo: JumpTableInfo option
}

/// Jump table (for switch-case) information.
and JumpTableInfo = {
  /// Base address of the jump table.
  JTBaseAddr: Addr
  /// The start and the end address of the jump table (AddrRange).
  JTRange: AddrRange
  /// Size of each entry of the table.
  JTEntrySize: RegType
}

/// No-return function info.
and NoReturnInfo = {
  /// No-return function addresses.
  NoReturnFuncs: Set<Addr>
  /// Program points of no-return call sites.
  NoReturnCallSites: Set<ProgramPoint>
}

[<RequireQualifiedAccess>]
module JumpTableInfo =
  let init b range size =
    { JTBaseAddr = b; JTRange = range; JTEntrySize = size }

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

  /// A temporary accumulator for calculating leaders.
  type private LeaderAccumulator = {
    /// Collection of instructions parsed until now.
    InstrMap: InstrMap
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
  let private foldStmts hdl indMap acc i =
    i.Stmts
    |> Array.fold (fun acc stmt ->
      match stmt with
      | Jmp (Name s) -> addLabelLeader s i acc
      | CJmp (_, Name s1, Name s2) ->
        addLabelLeader s1 i acc |> addLabelLeader s2 i
      | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
        let addr = BitVector.toUInt64 addr
        if hdl.FileInfo.IsValidAddr addr then
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
        | Some (indInfo) ->
          indInfo.TargetAddresses
          |> Set.fold (fun acc target -> addAddrLeader target i acc) acc
      | SideEffect (SysCall)
      | SideEffect (Interrupt _) ->
        let fallAddr = i.Instruction.Address + uint64 i.Instruction.Length
        if hdl.FileInfo.IsValidAddr fallAddr then addAddrLeader fallAddr i acc
        else acc
      | IEMark (a) when acc.ComplexInstrs.Contains i.Instruction.Address ->
        addAddrLeader a i acc
      | _ -> acc) acc

  let private findLeaders acc foldStmts =
    let labels =
      acc.InstrMap |> Seq.fold (findLabels acc.ComplexInstrs) Map.empty
    let acc = { acc with Labels = labels }
    (* Find all possible leaders by scanning lifted IRs. We need to do this at
       the IR-level because LowUIR may have intra-instruction branches. *)
    acc.InstrMap.Values |> Seq.fold foldStmts acc

  let private updateInstrMap hdl acc =
    let instrMap, leaders =
      acc.Leaders
      |> Set.filter (fun l -> not <| acc.InstrMap.ContainsKey l.Point.Address)
      |> InstrMap.update hdl acc.InstrMap None
    { acc with InstrMap = instrMap ; Leaders = Set.union acc.Leaders leaders }

  let rec private updateAcc hdl acc foldStmts =
    let acc = findLeaders acc foldStmts
    let oldCount = acc.InstrMap.Count
    let acc = updateInstrMap hdl acc
    if oldCount <> acc.InstrMap.Count then updateAcc hdl acc foldStmts
    else acc

  let updateNoReturnInfo oldNoRet (calleeMap: CalleeMap) =
    oldNoRet |> Seq.iter (fun (addr: Addr) ->
      match calleeMap.Find addr with
      | None -> ()
      | Some c -> c.IsNoReturn <- true)
    calleeMap

  let private buildApp hdl entries leaders instrMap indMap noretInfo =
    let acc =
      { InstrMap = instrMap
        Labels = Map.empty
        ComplexInstrs = HashSet ()
        Leaders = leaders
        FunctionAddrs = Set.map (fun leader -> leader.Point.Address) entries }
    let acc = updateAcc hdl acc (foldStmts hdl indMap)
    let calleeMap =
      CalleeMap.build hdl acc.FunctionAddrs acc.InstrMap
      |> updateNoReturnInfo noretInfo.NoReturnFuncs
    { InstrMap = acc.InstrMap
      LabelMap = acc.Labels
      LeaderInfos = acc.Leaders
      CallerMap = CallerMap.build calleeMap
      CalleeMap = calleeMap
      Entries = entries
      IndirectBranchMap = indMap
      NoReturnInfo = noretInfo }

  let private initApp hdl auxLeaders bblBound =
    match auxLeaders with
    | None -> getInitialEntryPoints hdl
    | Some leaders -> leaders
    |> fun leaders ->
      let entries = Set.ofSeq leaders
      (* First, recursively parse all possible instructions. *)
      let instrMap, leaders = InstrMap.build hdl leaders bblBound
      let nrempty = { NoReturnFuncs = Set.empty; NoReturnCallSites = Set.empty}
      buildApp hdl entries leaders instrMap Map.empty nrempty

  /// Create a binary apparatus from the given BinHandler. The resulting
  /// apparatus will include default entries found by reading the binary file
  /// itself (including symbols).
  [<CompiledName("Init")>]
  let init hdl =
    initApp hdl None None

  /// Create a binary apparatus soley based on the given leaders. The resulting
  /// appratus will not include default entries found by parsing binary file
  /// itself.
  let initByEntries hdl leaders bblBound =
    initApp hdl (Some leaders) bblBound

  let inline private append seq = Seq.foldBack Set.add seq

  let private computeFuncAddrs hdl app entries =
    getFunctionAddrs app
    |> Set.ofSeq
    |> Set.map (fun addr -> LeaderInfo.Init (hdl, addr))
    |> Set.union entries

  /// Update the given apparatus based on the auxiliary information stored in
  /// it. For example, there can be new entries (Entries) or indirect branches
  /// (IndirectBranchMap). This function makes the given app up-to-date.
  let update hdl app =
    let entries = app.Entries
    let leaders = app.LeaderInfos |> append entries
    let entries = computeFuncAddrs hdl app entries
    let instrMap, leaders = InstrMap.update hdl app.InstrMap None leaders
    buildApp hdl entries leaders instrMap app.IndirectBranchMap app.NoReturnInfo

  /// Register newly recovered entries to the apparatus.
  let addRecoveredEntries app entries =
    { app with Apparatus.Entries = Set.union entries app.Entries }

  /// Add a resolved indirect branch target to the app.
  let addIndirectBranchMap app indMap =
    let indMap =
      indMap
      |> Map.fold (fun acc addr info ->
        Map.add addr info acc) app.IndirectBranchMap
    { app with IndirectBranchMap = indMap }

  /// Add no-return information to the app.
  let addNoReturnInfo app noRetFuncs noRetCallSites =
    let noRetFuncs' = app.NoReturnInfo.NoReturnFuncs
    let noRetCallSites' = app.NoReturnInfo.NoReturnCallSites
    let noretInfo' =
      { NoReturnFuncs = Set.union noRetFuncs noRetFuncs'
        NoReturnCallSites = Set.union noRetCallSites noRetCallSites' }
    { app with NoReturnInfo = noretInfo' }
