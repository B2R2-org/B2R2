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

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// Instruction and the corresponding IR statements.
type InsIRPair = Instruction * Stmt []

/// Address to an InsIRPair mapping.
type InstrMap = Dictionary<Addr, InsIRPair>

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
  FunctionNames: Map<Addr, string>
  FunctionAddrs: Map<string, Addr>
  JmpTargetMap: JmpTargetMap
}

[<RequireQualifiedAccess>]
module BinaryApparatus =
  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the analysis.
  let private getInitialEntryPoints hdl =
    let fi = hdl.FileInfo
    let funaddrs = fi.GetFunctionAddresses ()
    if Seq.exists (fun addr -> addr = fi.EntryPoint) funaddrs then funaddrs
    else Seq.singleton fi.EntryPoint |> Seq.append funaddrs

  let private updateEntries (map: InstrMap) entries newaddrs =
    let rec loop entries = function
      | [] -> entries
      | addr :: rest ->
        if map.ContainsKey addr then loop entries rest
        else loop (addr :: entries) rest
    Seq.toList newaddrs |> loop entries

  /// Remove unnecessary IEMark to ease the analysis.
  let private trimIEMark (stmts: Stmt []) =
    let last = stmts.[stmts.Length - 1]
    let secondLast = stmts.[stmts.Length - 2]
    match secondLast, last with
    | InterJmp _, IEMark _
    | InterCJmp _, IEMark _
    | SideEffect _, IEMark _ ->
      Array.sub stmts 0 (stmts.Length - 1)
    | _ -> stmts

  let private trim stmts =
    BinHandler.Optimize stmts
    |> trimIEMark

  let private toInsIRPair hdl (ins: Instruction) =
    ins, try BinHandler.LiftInstr hdl ins |> trim with _ -> [||]

  let rec private updateInstrMapAndGetTheLastInstr hdl (map: InstrMap) insList =
    match (insList: Instruction list) with
    | [] -> failwith "Fatal error: an empty block encountered."
    | last :: [] ->
      map.[last.Address] <- toInsIRPair hdl last
      last
    | instr :: rest ->
      map.[instr.Address] <- toInsIRPair hdl instr
      updateInstrMapAndGetTheLastInstr hdl map rest

  /// Build a mapping from Addr to Instruction. This function recursively parses
  /// the binary, but does not lift it yet.
  let private buildInstrMap hdl entries =
    let map = InstrMap ()
    let rec buildLoop = function
      | [] -> map
      | entry :: rest ->
        match BinHandler.ParseBBlock hdl entry with
        | Error _ -> buildLoop rest
        | Ok instrs ->
          let last = updateInstrMapAndGetTheLastInstr hdl map instrs
          let entries = last.GetNextInstrAddrs () |> updateEntries map rest
          buildLoop entries
    buildLoop (Seq.toList entries)

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
    FunctionNameMap: Map<Addr, string>
    FunctionAddrMap: Map<string, Addr>
  }

  let private addLabelLeader s acc =
    { acc with
        Leaders = Set.add (Map.find s acc.Labels |> ProgramPoint) acc.Leaders }

  let private addAddrLeader addr acc =
    { acc with Leaders = Set.add (ProgramPoint (addr, 0)) acc.Leaders }

  let private obtainFuncName (hdl: BinHandler) addr =
    match hdl.FileInfo.TryFindFunctionSymbolName addr |> Utils.tupleToOpt with
    | None -> "func_" + addr.ToString("X")
    | Some name -> name

  let private addFunction hdl addr acc =
    let name = obtainFuncName hdl addr
    { acc with FunctionNameMap = Map.add addr name acc.FunctionNameMap
               FunctionAddrMap = Map.add name addr acc.FunctionAddrMap }

  /// Fold all the statements to get the leaders, function positions, etc.
  let private foldStmts hdl acc (KeyValue (_, (i: Instruction, stmts))) =
    stmts
    |> Array.fold (fun acc stmt ->
      match stmt with
      | Jmp (Name s) -> addLabelLeader s acc
      | CJmp (_, Name s1, Name s2) -> addLabelLeader s1 acc |> addLabelLeader s2
      | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
        let addr = BitVector.toUInt64 addr
        addAddrLeader addr acc
        |> addAddrLeader (i.Address + uint64 i.Length)
        |> addFunction hdl addr
      | InterJmp (_, Num addr, _) -> addAddrLeader (BitVector.toUInt64 addr) acc
      | InterCJmp (_, _, Num addr1, Num addr2) ->
        addAddrLeader (BitVector.toUInt64 addr1) acc
        |> addAddrLeader (BitVector.toUInt64 addr2)
      | SideEffect (SysCall)
      | SideEffect (Interrupt _) ->
        addAddrLeader (i.Address + uint64 i.Length) acc
      | _ -> acc) acc

  /// Create a binary apparatus from the given BinHandler.
  [<CompiledName("Init")>]
  let init hdl =
    let entries = getInitialEntryPoints hdl
    let instrmap = buildInstrMap hdl entries
    let lblmap = instrmap |> Seq.fold findLabels Map.empty
    let leaders = entries |> Seq.map (fun a -> ProgramPoint (a, 0)) |> Set.ofSeq
    let fpairs = entries |> Seq.map (fun e -> e, obtainFuncName hdl e)
    let acc =
      { Labels = lblmap
        Leaders = leaders
        FunctionNameMap = fpairs |> Map.ofSeq
        FunctionAddrMap = fpairs |> Seq.map (fun (a, b) -> b, a) |> Map.ofSeq }
    let acc = instrmap |> Seq.fold (foldStmts hdl) acc
    { InstrMap = instrmap
      LabelMap = lblmap
      LeaderPositions = acc.Leaders
      FunctionNames = acc.FunctionNameMap
      FunctionAddrs = acc.FunctionAddrMap
      JmpTargetMap = Map.empty }

  let internal updateFuncs hdl app newaddrs =
    let funcs =
      newaddrs
      |> List.fold (fun acc addr ->
        Map.add addr (obtainFuncName hdl addr) acc) app.FunctionNames
    { app with FunctionNames = funcs }
