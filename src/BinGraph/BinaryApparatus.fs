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

namespace B2R2.BinGraph

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// A mapping from an instruction address to computed jump targets. This table
/// stores only "computed" jump targets.
type JmpTargetMap = Map<Addr, Addr list>

/// Binary apparatus contains the key components and information for our CFG
/// analysis, such as all the parsed instructions from the target binary as well
/// as the positions of all the leaders found. This will be updated through our
/// CFG analyses.
type BinaryApparatus = {
  InstrMap: InstrMap
  LabelMap: Map<Symbol, Addr * int>
  LeaderPositions: Set<ProgramPoint>
  CallerMap: CallerMap
  CalleeMap: CalleeMap
  /// This is a flag representing whether this BinaryApparatus has been modified
  /// by our post analysis.
  Modified: bool
}

[<RequireQualifiedAccess>]
module BinaryApparatus =
  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the analysis.
  let private getInitialEntryPoints hdl =
    let fi = hdl.FileInfo
    fi.GetFunctionAddresses ()
    |> Seq.map (InstrMap.translateEntry hdl)
    |> Set.ofSeq
    |> Set.add (InstrMap.translateEntry hdl fi.EntryPoint)

  let private findLabels labels (KeyValue (addr, (_, stmts))) =
    stmts
    |> Array.foldi (fun labels idx stmt ->
         match stmt with
         | LMark (s) -> Map.add s (addr, idx) labels
         | _ -> labels) labels
    |> fst

  /// A temporary accumulator for folding all the IR statements.
  type private StmtAccumulator = {
    Labels: Map<Symbol, Addr * int>
    Leaders: Set<ProgramPoint>
    /// Collect all the address that are being a target of a direct call
    /// instruction (not indirect calls, since we don't know the target at this
    /// point).
    FunctionAddrs: Set<Addr>
  }

  let private addLabelLeader s acc =
    { acc with
        Leaders = Set.add (Map.find s acc.Labels |> ProgramPoint) acc.Leaders }

  let private addAddrLeader addr acc =
    { acc with Leaders = Set.add (ProgramPoint (addr, 0)) acc.Leaders }

  let private addFunction addr acc =
    { acc with FunctionAddrs = Set.add addr acc.FunctionAddrs }

  /// Fold all the statements to get the leaders, function positions, etc.
  let private foldStmts acc (KeyValue (_, (i: Instruction, stmts))) =
    stmts
    |> Array.fold (fun acc stmt ->
      match stmt with
      | Jmp (Name s) -> addLabelLeader s acc
      | CJmp (_, Name s1, Name s2) -> addLabelLeader s1 acc |> addLabelLeader s2
      | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
        let addr = BitVector.toUInt64 addr
        addAddrLeader addr acc
        |> addAddrLeader (i.Address + uint64 i.Length)
        |> addFunction addr
      | InterJmp (_, Num addr, _) -> addAddrLeader (BitVector.toUInt64 addr) acc
      | InterCJmp (_, _, Num addr1, Num addr2) ->
        addAddrLeader (BitVector.toUInt64 addr1) acc
        |> addAddrLeader (BitVector.toUInt64 addr2)
      | InterCJmp (_, _, Num addr, _)
      | InterCJmp (_, _, _, Num addr) ->
        addAddrLeader (BitVector.toUInt64 addr) acc
      | InterJmp (_, _, InterJmpInfo.IsCall) (* indirect call *)
      | SideEffect (SysCall)
      | SideEffect (Interrupt _) ->
        addAddrLeader (i.Address + uint64 i.Length) acc
      | _ -> acc) acc

  let private initAux hdl auxEntries =
    let entries =
      auxEntries
      |> Seq.fold (fun set ent -> Set.add ent set) (getInitialEntryPoints hdl)
      |> Set.toSeq
    let instrMap = InstrMap.build hdl entries
    let lblmap = instrMap |> Seq.fold findLabels Map.empty
    let leaders =
      entries |> Seq.map (fun a -> ProgramPoint (fst a, 0)) |> Set.ofSeq
    let acc =
      { Labels = lblmap
        Leaders = leaders
        FunctionAddrs = entries |> Seq.map fst |> Set.ofSeq }
#if DEBUG
    printfn "[*] Loaded basic information."
#endif
    let acc = instrMap |> Seq.fold foldStmts acc
    let calleeMap = CalleeMap.build hdl acc.FunctionAddrs instrMap
#if DEBUG
    printfn "[*] The apparatus is ready to use."
#endif
    { InstrMap = instrMap
      LabelMap = lblmap
      LeaderPositions = acc.Leaders
      CallerMap = CallerMap.build calleeMap
      CalleeMap = calleeMap
      Modified = true }

  /// Create a binary apparatus from the given BinHandler.
  [<CompiledName("Init")>]
  let init hdl = initAux hdl Seq.empty

  /// Update instruction info for the given binary appratus based on the given
  /// target addresses.
  let internal update hdl app addrs =
    if Seq.isEmpty addrs then app
    else initAux hdl addrs

  /// Return the list of function addresses from the BinaryApparatus.
  let getFunctionAddrs app =
    app.CalleeMap.Callees
    |> Seq.choose (fun c -> c.Addr)

  /// Return the list of callees that have a concrete mapping to the binary.
  let getInternalFunctions app =
    app.CalleeMap.Callees
    |> Seq.filter (fun c -> c.Addr.IsSome)
