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

namespace B2R2.BinEssence

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open System.Collections.Generic

/// Abstract information about the instruction and its corresponding IR
/// statements.
type InstructionInfo = {
  Instruction: Instruction
  Stmts: Stmt []
  Labels: Map<Symbol, ProgramPoint>
  IRLeaders: Set<ProgramPoint>
  ArchOperationMode: ArchOperationMode
  /// Instruction itself contains its address, but we may want to place this
  /// instruction in a different location in a virtual address space. This field
  /// is useful in such cases to give a specific offset to the instruction. This
  /// field is zero in most cases (except EVM) though.
  Offset: Addr
}

/// Address to an InstructionInfo mapping. InstrMap contains both valid and
/// bogus instructions so do not use InstrMap directly for analyses.
type InstrMap = Dictionary<Addr, InstructionInfo>

[<RequireQualifiedAccess>]
module InstrMap =

  let private updateParseMode hdl parseMode leader =
    match parseMode with
    | Some (mode, offset) ->
      hdl.ParsingContext.ArchOperationMode <- mode
      hdl.ParsingContext.CodeOffset <- offset
    | None ->
      match hdl.ISA.Arch with
      | Arch.ARMv7 when leader &&& 1UL <> 0UL ->
        hdl.ParsingContext.ArchOperationMode <- ArchOperationMode.ThumbMode
      | _ -> ()
    match hdl.ParsingContext.ArchOperationMode with
    | ArchOperationMode.ThumbMode when leader &&& 1UL <> 0UL -> leader - 1UL
    | _ -> leader

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

  let private findLabels addr stmts =
    stmts
    |> Array.foldi (fun labels idx stmt ->
      match stmt with
      | LMark (s) ->
        Map.add s (ProgramPoint (addr, idx)) labels
      | _ -> labels) Map.empty
    |> fst

  let private findIRLeaders labels stmts =
    stmts
    |> Array.fold (fun targets stmt ->
      match stmt with
      | Jmp (Name s) -> Set.add (Map.find s labels) targets
      | CJmp (_, Name t, Name f) ->
        targets |> Set.add (Map.find t labels) |> Set.add (Map.find f labels)
      | CJmp (_, Name t, Undefined _) ->
        Set.add (Map.find t labels) targets
      | CJmp (_, Undefined _, Name f) ->
        Set.add (Map.find f labels) targets
      | InterJmp (_, Num bv, _) ->
        let ppoint = ProgramPoint (BitVector.toUInt64 bv, 0)
        Set.add ppoint targets
      | InterCJmp (_, _, Num tBv, Num fBv) ->
        let tPpoint = ProgramPoint (BitVector.toUInt64 tBv, 0)
        let fPpoint = ProgramPoint (BitVector.toUInt64 fBv, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, _, Num tBv, _) ->
        let tPpoint = ProgramPoint (BitVector.toUInt64 tBv, 0)
        Set.add tPpoint targets
      | InterCJmp (_, _, _, Num fBv) ->
        let fPpoint = ProgramPoint (BitVector.toUInt64 fBv, 0)
        Set.add fPpoint targets
      | _ -> targets) Set.empty

  let private newInstructionInfo hdl (ins: Instruction) =
    let stmts = BinHandler.LiftInstr hdl ins |> trim
    let labels = findLabels ins.Address stmts
    { Instruction = ins
      Stmts = stmts
      Labels = labels
      IRLeaders = findIRLeaders labels stmts
      ArchOperationMode = hdl.ParsingContext.ArchOperationMode
      Offset = hdl.ParsingContext.CodeOffset }

  let rec private updateInstrMap hdl (instrMap: InstrMap) (instr: Instruction) =
    instrMap.[instr.Address] <- newInstructionInfo hdl instr
    instrMap

  /// InstrMap will only have this api: to update InstrMap, developer should use
  /// use this function. Removing instruction from InstrMap should be prohibited.
  let parse hdl parseMode instrMap leader =
    let leader = updateParseMode hdl parseMode leader
    match BinHandler.ParseBBlock hdl leader with
    | Ok [] -> failwith "Fatal error: an empty block encountered."
    | Ok instrs ->
      let instrMap = List.fold (updateInstrMap hdl) instrMap instrs
      let addrs = List.map (fun (instr: Instruction) -> instr.Address) instrs
      Ok (instrMap, addrs)
    | Error _ -> Error ()
