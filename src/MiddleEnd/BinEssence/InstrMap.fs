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

  let private findLabels addr stmts =
    stmts
    |> Array.foldi (fun labels idx stmt ->
      match stmt.S with
      | LMark (s) ->
        Map.add s (ProgramPoint (addr, idx)) labels
      | _ -> labels) Map.empty
    |> fst

  let private findReachablePPs insAddr mask labels stmts =
    stmts
    |> Array.fold (fun targets stmt ->
      match stmt.S with
      | Jmp ({ E = Name s }) -> Set.add (Map.find s labels) targets
      | CJmp (_, { E = Name t }, { E = Name f }) ->
        targets |> Set.add (Map.find t labels) |> Set.add (Map.find f labels)
      | CJmp (_, { E = Name t }, { E = Undefined _ }) ->
        Set.add (Map.find t labels) targets
      | CJmp (_, { E = Undefined _ }, { E = Name f }) ->
        Set.add (Map.find f labels) targets
      | InterJmp ({ E = Num bv }, _) ->
        let ppoint = ProgramPoint (BitVector.toUInt64 bv, 0)
        Set.add ppoint targets
      | InterJmp ({ E = PCVar _ }, _) ->
        let ppoint = ProgramPoint (insAddr, 0)
        Set.add ppoint targets
      | InterJmp ({ E = BinOp (BinOpType.ADD, _,
                               { E = PCVar (_) }, { E = Num bv }, _) }, _)
      | InterJmp ({ E = BinOp (BinOpType.ADD, _,
                               { E = Num bv }, { E = PCVar (_) }, _) }, _) ->
        let ppoint =
          ProgramPoint ((insAddr + BitVector.toUInt64 bv) &&& mask, 0)
        Set.add ppoint targets
      | InterCJmp (_, { E = Num tBv }, { E = Num fBv }) ->
        let tPpoint = ProgramPoint (BitVector.toUInt64 tBv, 0)
        let fPpoint = ProgramPoint (BitVector.toUInt64 fBv, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num tBv }, _) },
                      { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num fBv }, _) })
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num tBv }, _) },
                      { E = BinOp (BinOpType.ADD, _,
                                   { E = Num fBv }, { E = PCVar (_) }, _) })
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                                   { E = Num tBv }, { E = PCVar (_) }, _) },
                      { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num fBv }, _) })
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                                   { E = Num tBv }, { E = PCVar (_) }, _) },
                      { E = BinOp (BinOpType.ADD, _,
                                   { E = Num fBv }, { E = PCVar (_) }, _) }) ->
        let tPpoint =
          ProgramPoint ((insAddr + BitVector.toUInt64 tBv) &&& mask, 0)
        let fPpoint =
          ProgramPoint ((insAddr + BitVector.toUInt64 fBv) &&& mask, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, { E = PCVar (_) },
                      { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num fBv }, _) })
      | InterCJmp (_, { E = PCVar (_) },
                      { E = BinOp (BinOpType.ADD, _,
                                   { E = Num fBv }, { E = PCVar (_) }, _) }) ->
        let tPpoint =
          ProgramPoint (insAddr, 0)
        let fPpoint =
          ProgramPoint ((insAddr + BitVector.toUInt64 fBv) &&& mask, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num tBv }, _) },
                      { E = PCVar (_) })
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                             { E = Num tBv }, { E = PCVar (_) }, _) },
                      { E = PCVar (_) }) ->
        let tPpoint =
          ProgramPoint ((insAddr + BitVector.toUInt64 tBv) &&& mask, 0)
        let fPpoint =
          ProgramPoint (insAddr, 0)
        targets |> Set.add tPpoint |> Set.add fPpoint
      | InterCJmp (_, { E = Num tBv }, _) ->
        let tPpoint = ProgramPoint (BitVector.toUInt64 tBv, 0)
        Set.add tPpoint targets
      | InterCJmp (_, _, { E = Num fBv }) ->
        let fPpoint = ProgramPoint (BitVector.toUInt64 fBv, 0)
        Set.add fPpoint targets
      | InterCJmp (_, { E = BinOp (BinOpType.ADD, _,
                                   { E = PCVar (_) }, { E = Num bv }, _) }, _)
      | InterCJmp (_, _, { E = BinOp (BinOpType.ADD, _,
                                      { E = PCVar (_) }, { E = Num bv }, _) })
        ->
        let tPpoint =
          ProgramPoint ((insAddr + BitVector.toUInt64 bv) &&& mask, 0)
        Set.add tPpoint targets
      | InterCJmp (_, { E = PCVar _ }, _)
      | InterCJmp (_, _, { E = PCVar _ }) ->
        let tPpoint = ProgramPoint (insAddr, 0)
        Set.add tPpoint targets
      | _ -> targets) Set.empty

  let private newInstructionInfo hdl (ins: Instruction) =
    let stmts = BinHandle.LiftOptimizedInstr hdl ins
    let mask = Helper.computeJumpTargetMask hdl
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
      if ins.IsBBLEnd () || Map.containsKey nextAddr bblMap then
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
