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

/// <summary>
/// Parses and lifts the instruction at an address, remembering every outcome,
/// so that code an execution revisits -- a loop body, or a callee reached a
/// second time -- is parsed and lifted only once.
/// </summary>
/// <remarks>
/// An address can be asked for in a <see
/// cref='T:B2R2.MiddleEnd.Executor.DecodeMode'/>, the one the program is in
/// there, which the parser is put in before it reads; an execution that
/// follows the mode as the program moves it asks this way. Asked without one,
/// the parser reads in whatever mode it has carried itself into, as it parsed
/// one instruction after another. The two ways never share an outcome.
/// </remarks>
type LiftCache(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()
  let initialMode = DecodeMode.ofLiftingUnit lifter
  let parseResults =
    Dictionary<struct (Addr * DecodeMode voption),
               Result<IInstruction, ErrorCase>>()
  let liftResults =
    Dictionary<struct (Addr * DecodeMode voption), Result<Stmt[], ErrorCase>>()

  let memoize (results: Dictionary<_, Result<_, ErrorCase>>) key compute =
    match results.TryGetValue key with
    | true, result ->
      result
    | false, _ ->
      let result = compute ()
      results[key] <- result
      result

  let parse addr mode =
    match mode with
    | ValueSome mode -> DecodeMode.apply lifter mode
    | ValueNone -> ()
    if hdl.File.IsValidAddr addr then lifter.TryParseInstruction addr
    else Error ErrorCase.ParsingFailure

  let tryParse addr mode =
    memoize parseResults struct (addr, mode) (fun () -> parse addr mode)

  (* Parsing already accepted the bytes, so the expected failures are a lifter
     that cannot express this instruction and a branch whose delay slot lies
     past the bytes the file holds; naming them keeps a defect in a lifter
     from being reported as a property of the input, which catching everything
     did, and under the wrong error case at that. *)
  let lift (ins: IInstruction) =
    try
      lifter.LiftInstruction ins |> Ok
    with
    | NotImplementedIRException _ -> Error ErrorCase.NotImplementedIR
    | MissingDelaySlotException -> Error ErrorCase.ParsingFailure

  let tryLift addr mode =
    tryParse addr mode
    |> Result.bind (fun ins ->
      memoize liftResults struct (addr, mode) (fun () -> lift ins)
      |> Result.map (fun stmts -> { Instruction = ins; Stmts = stmts }))

  (* A MIPS call transfers control only after its delay slot has run, so the
     callee returns past that slot rather than to the next address. The slot
     is read in the mode of the call. *)
  let fallThrough addr (length: uint32) mode =
    match hdl.ISA with
    | MIPS ->
      let delaySlotAddr = addr + uint64 length
      match tryParse delaySlotAddr mode with
      | Ok delaySlot -> delaySlotAddr + uint64 delaySlot.Length
      | Error _ -> delaySlotAddr + uint64 length
    | _ ->
      addr + uint64 length

  (* A step of zero, or one that wraps past the end of the address space, would
     leave the walk on the same address forever; either one ends it instead. *)
  let advance addr amount finishAddr =
    let nextAddr = addr + amount
    if nextAddr <= addr then finishAddr else nextAddr

  /// The mode the binary starts in, which is the one a fresh lifting unit
  /// decodes in.
  member _.InitialMode with get(): DecodeMode = initialMode

  /// Parses the instruction at the given address, in the mode the parser has
  /// carried itself into.
  member _.TryParse(addr: Addr) = tryParse addr ValueNone

  /// Parses the instruction at the given address in the given mode.
  member _.TryParse(addr: Addr, mode: DecodeMode) =
    tryParse addr (ValueSome mode)

  /// Parses and lifts the instruction at the given address, in the mode the
  /// parser has carried itself into.
  member _.TryLift(addr: Addr) = tryLift addr ValueNone

  /// Parses and lifts the instruction at the given address in the given mode.
  member _.TryLift(addr: Addr, mode: DecodeMode) =
    tryLift addr (ValueSome mode)

  /// Returns the address that a callee returns to, given the address and the
  /// length of the call instruction it was called from.
  member _.FallThroughAddr(addr, length: uint32) =
    fallThrough addr length ValueNone

  /// Returns the address that a callee returns to, given the address and the
  /// length of the call instruction it was called from, and the mode it was
  /// read in.
  member _.FallThroughAddr(addr, length: uint32, mode: DecodeMode) =
    fallThrough addr length (ValueSome mode)

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
