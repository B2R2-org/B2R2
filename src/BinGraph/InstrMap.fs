(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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
open B2R2.BinIR.LowUIR
open System.Collections.Generic

/// Instruction and the corresponding IR statements.
type InsIRPair = Instruction * Stmt []

/// Address to an InsIRPair mapping.
type InstrMap = Dictionary<Addr, InsIRPair>

module InstrMap =
  let translateEntry (hdl: BinHandler) addr =
    match hdl.ISA.Arch with
    | Arch.ARMv7 ->
      if addr &&& 1UL = 0UL then addr, ArchOperationMode.ARMMode
      else addr - 1UL, ArchOperationMode.ThumbMode
    | _ -> addr, ArchOperationMode.NoMode

  let private updateEntries hdl (map: InstrMap) entries newTargets =
    let rec loop entries = function
      | [] -> entries
      | (addr, mode) :: rest ->
        if map.ContainsKey addr then loop entries rest
        else
          let entryAddr, _ = translateEntry hdl addr
          loop ((entryAddr, mode) :: entries) rest
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

  /// Update the map (InstrMap) from the given entries.
  let update (hdl: BinHandler) map entries =
    let rec buildLoop = function
      | [] -> map
      | (entry, mode) :: rest ->
        hdl.ParsingContext.ArchOperationMode <- mode
        match BinHandler.ParseBBlock hdl entry with
        | Error _ -> buildLoop rest
        | Ok instrs ->
          let last = updateInstrMapAndGetTheLastInstr hdl map instrs
          let entries = last.GetNextInstrAddrs () |> updateEntries hdl map rest
          buildLoop entries
    buildLoop (Seq.toList entries)

  /// Build a mapping from Addr to Instruction. This function recursively parses
  /// the binary, but does not lift it yet. Since GetNextInstrAddrs returns next
  /// concrete target addresses, this function does *not* reveal all reachable
  /// instructions. Such uncovered instructions should be handled in the next
  /// phase.
  let build (hdl: BinHandler) entries =
    let map = InstrMap ()
    update hdl map entries
