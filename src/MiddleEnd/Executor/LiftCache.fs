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

namespace B2R2.MiddleEnd.Executor

open System.Collections.Generic
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

/// Parses and lifts the instruction at an address, remembering every outcome,
/// so that code an execution revisits -- a loop body, or a callee reached a
/// second time -- is parsed and lifted only once.
type LiftCache(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()
  let parseResults = Dictionary<Addr, Result<IInstruction, ErrorCase>>()
  let liftResults = Dictionary<Addr, Result<Stmt[], ErrorCase>>()

  let memoize (results: Dictionary<Addr, Result<_, ErrorCase>>) addr compute =
    match results.TryGetValue addr with
    | true, result ->
      result
    | false, _ ->
      let result = compute ()
      results[addr] <- result
      result

  let parse addr =
    if hdl.File.IsValidAddr addr then lifter.TryParseInstruction addr
    else Error ErrorCase.ParsingFailure

  (* Parsing already accepted the bytes, so a lifter that cannot express this
     instruction is the one expected failure; naming it keeps a defect in a
     lifter from being reported as a property of the input, which catching
     everything did, and under the wrong error case at that. *)
  let lift (ins: IInstruction) =
    try lifter.LiftInstruction ins |> Ok
    with NotImplementedIRException _ -> Error ErrorCase.NotImplementedIR

  (* A step of zero, or one that wraps past the end of the address space, would
     leave the walk on the same address forever; either one ends it instead. *)
  let advance addr amount finishAddr =
    let nextAddr = addr + amount
    if nextAddr <= addr then finishAddr else nextAddr

  /// Parses the instruction at the given address.
  member _.TryParse addr = memoize parseResults addr (fun () -> parse addr)

  /// Parses and lifts the instruction at the given address.
  member this.TryLift addr =
    this.TryParse addr
    |> Result.bind (fun ins ->
      memoize liftResults addr (fun () -> lift ins)
      |> Result.map (fun stmts -> { Instruction = ins; Stmts = stmts }))

  /// Parses and lifts every instruction in the given half-open address ranges,
  /// so that a run over them finds each instruction already lifted.
  member this.WarmUp(ranges: (Addr * Addr) list) =
    for startAddr, finishAddr in ranges do
      this.WarmUpRange(startAddr, finishAddr)

  member private this.WarmUpRange(addr, finishAddr) =
    if addr >= finishAddr then
      ()
    else
      let nextAddr = advance addr (this.StepFrom addr) finishAddr
      this.WarmUpRange(nextAddr, finishAddr)

  (* A parsed instruction says how long it is, so the walk lands on the one
     that follows it; where parsing fails there is nothing to go by but the
     alignment the architecture guarantees. *)
  member private this.StepFrom addr =
    this.TryLift addr |> ignore
    match this.TryParse addr with
    | Ok ins -> uint64 ins.Length
    | Error _ -> uint64 lifter.InstructionAlignment

/// Represents an instruction that has been parsed and lifted.
and LiftedInstruction =
  { /// Machine instruction that the parser read.
    Instruction: IInstruction
    /// LowUIR statements that the lifter produced for it.
    Stmts: Stmt[] }
