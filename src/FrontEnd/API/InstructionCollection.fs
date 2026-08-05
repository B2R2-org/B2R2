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
open System.Threading
open System.Threading.Tasks
open B2R2
open B2R2.FrontEnd.BinLifter

/// <summary>
/// Represents a collection of lifted instructions, shared across all functions.
/// Instantiating this class starts a background sweep that lifts every
/// instruction it can find in the given binary. Lookups work while the sweep is
/// in flight because a miss is parsed on demand, so callers only need to await
/// <see cref='P:B2R2.FrontEnd.InstructionCollection.Completion'/> when they
/// depend on the sweep having covered the whole binary.
/// </summary>
type InstructionCollection(collector: IInstructionCollectable) =
  let dict = ConcurrentDictionary<Addr, InstructionCandidate>()

  let updateFn (addr, insCandidate) = dict.TryAdd(addr, insCandidate) |> ignore

  let cts = new CancellationTokenSource()

  (* The sweep is CPU-bound and runs for seconds on a large binary, so it takes
     a dedicated thread rather than a pool thread that CFG recovery is competing
     for. Note a task expression would not do: with no await point inside, it
     runs the whole body on the calling thread. *)
  let completion =
    Task.Factory.StartNew(
      (fun () -> collector.Collect(updateFn, cts.Token)),
      TaskCreationOptions.LongRunning)

  /// <summary>
  /// A task that completes when the background sweep has finished or has been
  /// cancelled. Awaiting it is what makes <see cref="Count"/> final, and it is
  /// the only way to observe a failure raised by the collector.
  /// </summary>
  member _.Completion with get(): Task = completion

  /// Number of instructions collected so far. This keeps growing while the
  /// background sweep is in flight, so it is final only once Completion has
  /// finished.
  member _.Count with get() = dict.Count

  /// Requests the background sweep to stop. Lookups keep working afterwards,
  /// since a miss is parsed on demand.
  member _.Cancel() = cts.Cancel()

  member inline private _.ExtractInstruction candidate =
    match candidate with
    | OnlyOne ins -> Ok ins
    | _ -> Error ErrorCase.ParsingFailure

  /// Find cached one or parse (and cache) the instruction at the given address.
  member this.TryFind(addr: Addr) =
    match dict.TryGetValue addr with
    | true, candidate ->
      this.ExtractInstruction candidate
    | false, _ ->
      match collector.ParseInstructionCandidate addr with
      | Ok candidate ->
        let ins = this.ExtractInstruction candidate
        if Result.isOk ins then dict.TryAdd(addr, candidate) |> ignore else ()
        ins
      | Error e ->
        Error e

  /// <summary>
  /// Gets the instruction at the given address, parsing it on demand when the
  /// background sweep has not reached the address yet. Raises <see
  /// cref='T:B2R2.FrontEnd.BinLifter.ParsingFailureException'/> when no single
  /// instruction can be found there.
  /// </summary>
  member this.Find(addr: Addr) =
    match this.TryFind addr with
    | Ok ins -> ins
    | Error _ -> raise ParsingFailureException

/// Represents one or more candidate instructions located at the same address.
/// There could be two instructions at the same address when considering the
/// operation mode of ARM CPU: one for ARM and the other for Thumb mode.
and InstructionCandidate =
  | OnlyOne of IInstruction
  | MaybeTwo of IInstruction option * IInstruction option (* arm or thumb *)

/// Provides an interface for collecting instructions.
and IInstructionCollectable =
  /// <summary>
  /// Collects instructions from the binary, calling <paramref name="updateFn"/>
  /// for each instruction that is parsed. Implementations should stop and
  /// return once <paramref name="token"/> is signalled, leaving whatever has
  /// been collected so far in place.
  /// </summary>
  abstract Collect:
       updateFn: (Addr * InstructionCandidate -> unit)
     * token: CancellationToken
    -> unit

  /// Parses one or more instruction candidates from the given address. This can
  /// be called from any thread while Collect is in flight.
  abstract ParseInstructionCandidate:
       Addr
    -> Result<InstructionCandidate, ErrorCase>
