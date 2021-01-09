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

namespace B2R2.MiddleEnd.BinEssence

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open System.Collections.Generic

/// Address to an InstructionInfo mapping. InstrMap contains both valid and
/// bogus instructions so do not use InstrMap directly for analyses.
type InstrMap = Dictionary<Addr, InstructionInfo>

[<RequireQualifiedAccess>]
module InstrMap =

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

  let private transform stmts =
    BinHandle.Optimize stmts
    |> trimIEMark

  let private findLabels addr stmts =
    stmts
    |> Array.foldi (fun labels idx stmt ->
      match stmt with
      | LMark (s) ->
        Map.add s (ProgramPoint (addr, idx)) labels
      | _ -> labels) Map.empty
    |> fst

  let private findReachablePPs insAddr mask labels stmts =
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
      | InterJmp (Num bv, _) ->
        let ppoint = ProgramPoint (BitVector.toUInt64 bv, 0)
        Set.add ppoint targets
      | InterJmp (PCVar _, _) ->
        let ppoint = ProgramPoint (insAddr, 0)
        Set.add ppoint targets
      | InterJmp (BinOp (BinOpType.ADD, _, PCVar (_), Num bv, _, _), _)
      | InterJmp (BinOp (BinOpType.ADD, _, Num bv, PCVar (_), _, _), _) ->
        let ppoint = ProgramPoint ((insAddr + BitVector.toUInt64 bv) &&& mask, 0)
        Set.add ppoint targets
      | InterCJmp (_, Num tBv, Num fBv) ->
        let tPpoint = ProgramPoint (BitVector.toUInt64 tBv, 0)
        let fPpoint = ProgramPoint (BitVector.toUInt64 fBv, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, BinOp (BinOpType.ADD, _, PCVar (_), Num tBv, _, _),
                      BinOp (BinOpType.ADD, _, PCVar (_), Num fBv, _, _))
      | InterCJmp (_, BinOp (BinOpType.ADD, _, PCVar (_), Num tBv, _, _),
                      BinOp (BinOpType.ADD, _, Num fBv, PCVar (_), _, _))
      | InterCJmp (_, BinOp (BinOpType.ADD, _, Num tBv, PCVar (_), _, _),
                      BinOp (BinOpType.ADD, _, PCVar (_), Num fBv, _, _))
      | InterCJmp (_, BinOp (BinOpType.ADD, _, Num tBv, PCVar (_), _, _),
                      BinOp (BinOpType.ADD, _, Num fBv, PCVar (_), _, _)) ->
        let tPpoint = ProgramPoint ((insAddr + BitVector.toUInt64 tBv) &&& mask, 0)
        let fPpoint = ProgramPoint ((insAddr + BitVector.toUInt64 fBv) &&& mask, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, PCVar (_),
                      BinOp (BinOpType.ADD, _, PCVar (_), Num fBv, _, _))
      | InterCJmp (_, PCVar (_),
                      BinOp (BinOpType.ADD, _, Num fBv, PCVar (_), _, _)) ->
        let tPpoint = ProgramPoint (insAddr, 0)
        let fPpoint = ProgramPoint ((insAddr + BitVector.toUInt64 fBv) &&& mask, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, BinOp (BinOpType.ADD, _, PCVar (_), Num tBv, _, _),
                      PCVar (_))
      | InterCJmp (_, BinOp (BinOpType.ADD, _, Num tBv, PCVar (_), _, _),
                      PCVar (_)) ->
        let tPpoint = ProgramPoint ((insAddr + BitVector.toUInt64 tBv) &&& mask, 0)
        let fPpoint = ProgramPoint (insAddr, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, Num tBv, _) ->
        let tPpoint = ProgramPoint (BitVector.toUInt64 tBv, 0)
        Set.add tPpoint targets
      | InterCJmp (_, _, Num fBv) ->
        let fPpoint = ProgramPoint (BitVector.toUInt64 fBv, 0)
        Set.add fPpoint targets
      | InterCJmp (_, BinOp (BinOpType.ADD, _, PCVar (_), Num bv, _, _), _)
      | InterCJmp (_, _, BinOp (BinOpType.ADD, _, PCVar (_), Num bv, _, _)) ->
        let tPpoint = ProgramPoint ((insAddr + BitVector.toUInt64 bv) &&& mask, 0)
        Set.add tPpoint targets
      | InterCJmp (_, PCVar _, _)
      | InterCJmp (_, _, PCVar _) ->
        let tPpoint = ProgramPoint (insAddr, 0)
        Set.add tPpoint targets
      | _ -> targets) Set.empty

  let private newInstructionInfo hdl (ins: Instruction) =
    let stmts = BinHandle.LiftInstr hdl ins |> transform
    let rt =
      hdl.ISA.WordSize
      |> WordSize.toRegType
    let mask = BitVector.unsignedMax rt |> BitVector.toUInt64
    let labels = findLabels ins.Address stmts
    { Instruction = ins
      Stmts = stmts
      Labels = labels
      ReachablePPs = findReachablePPs ins.Address mask labels stmts
      ArchOperationMode = hdl.DefaultParsingContext.ArchOperationMode
      Offset = hdl.DefaultParsingContext.CodeOffset }

  let rec private updateInstrMap hdl (instrMap: InstrMap) (instr: Instruction) =
    instrMap.[instr.Address] <- newInstructionInfo hdl instr

  let rec private parseBBL hdl ctxt bblMap acc pc =
    match BinHandle.TryParseInstr (hdl, ctxt, addr=pc) with
    | Ok ins ->
      let ctxt = ins.NextParsingContext
      let nextAddr = pc + uint64 ins.Length
      if ins.IsExit () || Map.containsKey nextAddr bblMap then
        Ok <| struct (List.rev (ins :: acc), ins.Address)
      else parseBBL hdl ctxt bblMap (ins :: acc) nextAddr
    | Error _ -> Error <| List.rev acc

  /// InstrMap will only have this API. Removing instructions from InstrMap is
  /// not allowed.
  let parse hdl ctxt instrMap bblStore leaderAddr =
    match parseBBL hdl ctxt bblStore.BBLMap [] leaderAddr with
    | Ok ([], _) -> failwith "Fatal error: an empty block encountered."
    | Ok (instrs, lastAddr) ->
      try
        List.iter (updateInstrMap hdl instrMap) instrs
        let addrs = List.map (fun (instr: Instruction) -> instr.Address) instrs
        Ok <| struct (instrMap, addrs, lastAddr)
      with
        | _ ->
#if DEBUG
          printfn "Not Implemented IR starting from %x" leaderAddr
#endif
          Error ()
    | Error _ -> Error ()
