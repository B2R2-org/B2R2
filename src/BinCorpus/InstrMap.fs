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

module InstrMap =
  let private updateEntries hdl (map: InstrMap) entries offset newTargets =
    let rec loop entries = function
      | [] -> entries
      | (addr, mode) :: rest ->
        if map.ContainsKey addr then loop entries rest
        else
          let info = LeaderInfo.Init (hdl, addr, mode, offset)
          loop (info :: entries) rest
    Seq.toList newTargets |> loop entries

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

  /// Update the map (InstrMap) from the given entries.
  let update (hdl: BinHandler) map leaders =
    let rec buildLoop = function
      | [] -> map
      | leaderInfo :: rest when isExecutableLeader hdl leaderInfo |> not ->
        buildLoop rest
      | leaderInfo :: rest ->
        hdl.ParsingContext.ArchOperationMode <- leaderInfo.Mode
        hdl.ParsingContext.CodeOffset <- leaderInfo.Offset
        match BinHandler.ParseBBlock hdl leaderInfo.Point.Address with
        | Error _ -> buildLoop rest
        | Ok instrs ->
          let last = updateInstrMapAndGetTheLastInstr hdl map instrs
          let entries =
            last.GetNextInstrAddrs ()
            |> updateEntries hdl map rest leaderInfo.Offset
          buildLoop entries
    buildLoop (Seq.toList leaders)

  /// Build a mapping from Addr to Instruction. This function recursively parses
  /// the binary, but does not lift it yet. Since GetNextInstrAddrs returns next
  /// concrete target addresses, this function does *not* reveal all reachable
  /// instructions. Such uncovered instructions should be handled in the next
  /// phase.
  let build (hdl: BinHandler) entries =
    let map = InstrMap ()
    update hdl map entries
