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

/// Collection of lifted instructions. When this class is instantiated, it will
/// automatically lift all possible instructions from the given binary, and
/// store them in the internal collection. This is shared across all functions.
[<AllowNullLiteral>]
type InstructionCollection (collector: IInstructionCollectable) =
  let dict = ConcurrentDictionary<Addr, InstructionCandidate> ()
  let updateFn (addr, insCandidate) = dict.TryAdd (addr, insCandidate) |> ignore
  do task { collector.Collect updateFn } |> ignore

  /// Number of instructions in the collection.
  member __.Count with get() = dict.Count

  member inline private __.ExtractInstruction candidate mode =
    match candidate with
    | OnlyOne ins-> Ok ins
    | MaybeTwo (Some ins1, _) when mode = ArchOperationMode.ARMMode -> Ok ins1
    | MaybeTwo (_, Some ins2) when mode = ArchOperationMode.ThumbMode -> Ok ins2
    | _ -> Error ErrorCase.ParsingFailure

  /// Find cached one or parse (and cache) the instruction at the given address.
  member __.TryFind (addr: Addr, mode) =
    match dict.TryGetValue addr with
    | true, candidate -> __.ExtractInstruction candidate mode
    | false, _ ->
      match collector.ParseInstructionCandidate (addr, mode) with
      | Ok candidate ->
        let ins = __.ExtractInstruction candidate mode
        if Result.isOk ins then dict.TryAdd (addr, candidate) |> ignore else ()
        ins
      | Error e -> Error e

  /// Get the instruction at the given address. Raise an exception if not found.
  member __.Find (addr: Addr, mode) =
    match dict.[addr] with
    | OnlyOne ins -> ins
    | MaybeTwo (Some ins1, _) when mode = ArchOperationMode.ARMMode -> ins1
    | MaybeTwo (_, Some ins2) when mode = ArchOperationMode.ThumbMode -> ins2
    | _ -> raise ParsingFailureException

  /// Get the instruction at the given address. Raise an exception if not found
  /// or if the mode needs to be specified.
  member __.Find (addr: Addr) =
    match dict.[addr] with
    | OnlyOne ins -> ins
    | _ -> raise ParsingFailureException

/// There could be two instructions at the same address, one for ARM and the
/// other for Thumb mode.
and InstructionCandidate =
  | OnlyOne of Instruction
  | MaybeTwo of Instruction option * Instruction option (* arm or thumb *)

/// Interface for collecting instructions.
and IInstructionCollectable =
  /// Collect instructions from the binary. The `updateFn` is called for each
  /// instruction that is parsed.
  abstract Collect:
       updateFn: (Addr * InstructionCandidate -> unit)
    -> unit

  /// Parse one or more instruction candidates from the given address.
  abstract ParseInstructionCandidate:
       Addr * ArchOperationMode
    -> Result<InstructionCandidate, ErrorCase>

/// Perform linear sweep to collect instructions.
type LinearSweepInstructionCollector (hdl: BinHandle,
                                      liftingUnit: LiftingUnit) =
  let rec update updateFn shift ptr =
    if BinFilePointer.IsValid ptr then
      match liftingUnit.TryParseInstruction (ptr=ptr) with
      | Ok ins ->
        updateFn (ptr.Addr, OnlyOne ins) |> ignore
        update updateFn shift (BinFilePointer.Advance ptr (int ins.Length))
      | Error _ ->
        update updateFn shift (BinFilePointer.Advance ptr shift)
    else ()

  new (hdl: BinHandle) =
    LinearSweepInstructionCollector (hdl, hdl.NewLiftingUnit ())

  interface IInstructionCollectable with
    member __.Collect (updateFn) =
      let ptr =
        liftingUnit.File.EntryPoint
        |> Option.defaultValue 0UL
        |> liftingUnit.File.ToBinFilePointer
      let shiftAmount = 1 (* FIXME *)
      update updateFn shiftAmount ptr

    member __.ParseInstructionCandidate (addr, _mode) =
      let liftingUnit = hdl.NewLiftingUnit () (* always create a new one! *)
      match liftingUnit.TryParseInstruction (addr=addr) with
      | Ok ins -> Ok (OnlyOne ins)
      | Error _ -> Error ErrorCase.ParsingFailure
