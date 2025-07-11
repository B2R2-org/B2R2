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

namespace B2R2.FrontEnd

open System.Collections.Concurrent
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// Represents a collection of lifted instructions. When this class is
/// instantiated, it will automatically lift all possible instructions from the
/// given binary, and store them in the internal collection. This is shared
/// across all functions.
[<AllowNullLiteral>]
type InstructionCollection (collector: IInstructionCollectable) =
  let dict = ConcurrentDictionary<Addr, InstructionCandidate> ()
  let updateFn (addr, insCandidate) = dict.TryAdd (addr, insCandidate) |> ignore
  do task { collector.Collect updateFn } |> ignore

  /// Number of instructions in the collection.
  member _.Count with get() = dict.Count

  member inline private _.ExtractInstruction candidate =
    match candidate with
    | OnlyOne ins-> Ok ins
    | _ -> Error ErrorCase.ParsingFailure

  /// Find cached one or parse (and cache) the instruction at the given address.
  member this.TryFind (addr: Addr) =
    match dict.TryGetValue addr with
    | true, candidate -> this.ExtractInstruction candidate
    | false, _ ->
      match collector.ParseInstructionCandidate addr with
      | Ok candidate ->
        let ins = this.ExtractInstruction candidate
        if Result.isOk ins then dict.TryAdd (addr, candidate) |> ignore else ()
        ins
      | Error e -> Error e

  /// Get the instruction at the given address. Raise an exception if not found.
  member _.Find (addr: Addr) =
    match dict.[addr] with
    | OnlyOne ins -> ins
    | _ -> raise ParsingFailureException

/// Represents one or more candidate instructions located at the same address.
/// There could be two instructions at the same address when considering the
/// operation mode of ARM CPU: one for ARM and the other for Thumb mode.
and InstructionCandidate =
  | OnlyOne of IInstruction
  | MaybeTwo of IInstruction option * IInstruction option (* arm or thumb *)

/// Provides an interface for collecting instructions.
and IInstructionCollectable =
  /// Collects instructions from the binary. The `updateFn` is called for each
  /// instruction that is parsed.
  abstract Collect:
       updateFn: (Addr * InstructionCandidate -> unit)
    -> unit

  /// Parses one or more instruction candidates from the given address.
  abstract ParseInstructionCandidate:
       Addr
    -> Result<InstructionCandidate, ErrorCase>

/// Represents a linear sweep instruction collector, which is the most basic
/// instruction collector performing linear sweep disassembly.
type LinearSweepInstructionCollector (hdl: BinHandle,
                                      liftingUnit: LiftingUnit) =
  let rec update updateFn shift (ptr: BinFilePointer) =
    if ptr.IsValid then
      match liftingUnit.TryParseInstruction (ptr = ptr) with
      | Ok ins ->
        updateFn (ptr.Addr, OnlyOne ins) |> ignore
        update updateFn shift (BinFilePointer.Advance ptr (int ins.Length))
      | Error _ ->
        update updateFn shift (BinFilePointer.Advance ptr shift)
    else ()

  new (hdl: BinHandle) =
    LinearSweepInstructionCollector (hdl, hdl.NewLiftingUnit ())

  interface IInstructionCollectable with
    member _.Collect updateFn =
      let ptr = liftingUnit.File.GetTextSectionPointer ()
      let shiftAmount = 1 (* FIXME *)
      update updateFn shiftAmount ptr

    member _.ParseInstructionCandidate addr =
      let liftingUnit = hdl.NewLiftingUnit () (* always create a new one! *)
      match liftingUnit.TryParseInstruction (addr = addr) with
      | Ok ins -> Ok (OnlyOne ins)
      | Error _ -> Error ErrorCase.ParsingFailure
