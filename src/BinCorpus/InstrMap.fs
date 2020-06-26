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

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR
open System.Collections.Generic

/// Abstract information about the instruction and its corresponding IR
/// statements.
type InstructionInfo = {
  Instruction: Instruction
  Stmts: Stmt []
  ArchOperationMode: ArchOperationMode
  /// Instruction itself contains its address, but we may want to place this
  /// instruction in a different location in a virtual address space. This field
  /// is useful in such cases to give a specific offset to the instruction. This
  /// field is zero in most cases (except EVM) though.
  Offset: Addr
}

/// Address to an InstructionInfo mapping.
type InstrMap = Dictionary<Addr, InstructionInfo>

[<RequireQualifiedAccess>]
module InstrMap =
  let private updateLeaders hdl (map: InstrMap) leaders offset newTargets =
    let rec loop leaders = function
      | [] -> leaders
      | (addr, mode) :: rest ->
        if map.ContainsKey addr then loop leaders rest
        else
          let info = LeaderInfo.Init (hdl, addr, mode, offset)
          loop (info :: leaders) rest
    Seq.toList newTargets |> loop leaders

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

  let private newInstructionInfo hdl (ins: Instruction) =
    { Instruction = ins
      Stmts = BinHandler.LiftInstr hdl ins |> trim
      ArchOperationMode = hdl.ParsingContext.ArchOperationMode
      Offset = hdl.ParsingContext.CodeOffset }

  let rec private updateInstrMapAndGetTheLastInstr hdl (map: InstrMap) insList =
    match (insList: Instruction list) with
    | [] -> failwith "Fatal error: an empty block encountered."
    | last :: [] ->
      try map.[last.Address] <- newInstructionInfo hdl last with _ -> ()
      last
    | instr :: rest ->
      try map.[instr.Address] <- newInstructionInfo hdl instr with _ -> ()
      updateInstrMapAndGetTheLastInstr hdl map rest

  let inline private isExecutableLeader hdl leaderInfo =
    hdl.FileInfo.IsExecutableAddr leaderInfo.Point.Address

  let inline private isAlreadyParsed (map: InstrMap) leaderInfo =
    map.ContainsKey leaderInfo.Point.Address

  let inline private isMeetBound bblBound instrs =
    match bblBound with
    | Some bblBound ->
      instrs |> List.exists (fun (i: Instruction) -> i.Address = bblBound)
    | None -> false

  /// Update the map (InstrMap) from the given leaders, and returns both
  /// InstrMap and a set of leaders. The set may change when a leader falls
  /// through an existing basic block without an explicit branch instruction.
  /// See InstrMap.build for more explanation about our design choice.
  let update (hdl: BinHandler) map bblBound leaders =
    let newLeaders = Dictionary<Addr, LeaderInfo> ()
    let rec buildLoop leaderSet = function
      | [] -> map, leaderSet
      | leaderInfo :: rest when isExecutableLeader hdl leaderInfo |> not ->
        buildLoop (Set.remove leaderInfo leaderSet) rest
      | leaderInfo :: rest when isAlreadyParsed map leaderInfo ->
        buildLoop leaderSet rest
      | leaderInfo :: rest ->
        hdl.ParsingContext.ArchOperationMode <- leaderInfo.Mode
        hdl.ParsingContext.CodeOffset <- leaderInfo.Offset
        match BinHandler.ParseBBlock hdl leaderInfo.Point.Address with
        | Ok instrs ->
          if isMeetBound bblBound instrs then
            buildLoop (Set.remove leaderInfo leaderSet) rest
          else
            let last = updateInstrMapAndGetTheLastInstr hdl map instrs
            let leaders =
              last.GetNextInstrAddrs ()
              |> updateLeaders hdl map rest leaderInfo.Offset
            newLeaders.[leaderInfo.Point.Address] <- leaderInfo
            buildLoop leaderSet leaders
        | _ -> buildLoop (Set.remove leaderInfo leaderSet) rest
    let map, set = buildLoop leaders (Set.toList leaders)
    map, newLeaders.Values |> Seq.fold (fun set l -> Set.add l set) set

  /// Build a mapping from Addr to Instruction. This function recursively parses
  /// the binary, but does not lift it yet. Since GetNextInstrAddrs returns next
  /// concrete target addresses, this function does *not* reveal all reachable
  /// instructions. Such uncovered instructions should be handled in the next
  /// phase. If the bblBound parameter is given, this function will exclude any
  /// block that falls to the bblBound address without having an explicit branch
  /// instruction. This means, we discard any block that starts with no-op(s)
  /// followed by a known valid basic block, as this is against the definition
  /// of basic block. Note, however, we do not exclude overlapping basic blocks
  /// that appear in obfuscated code. In other words, we do *include* cases
  /// where a block falls through the middle of another block.
  let build (hdl: BinHandler) leaders bblBound =
    let map = InstrMap ()
    update hdl map bblBound leaders
