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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System
open System.Collections.Concurrent
open System.Threading

/// Represents a stream of commands consumed by task workers. A worker blocks
/// on the stream until a command arrives, and posting the command wakes it up
/// directly instead of queueing work on the thread pool.
type TaskWorkerCommandStream<'FnCtx, 'GlCtx>() =
  let stream = new BlockingCollection<TaskWorkerCommand<'FnCtx, 'GlCtx>>()

  /// Posts a command to the stream. A command posted after the stream is
  /// closed is dropped.
  member _.Post(command: TaskWorkerCommand<'FnCtx, 'GlCtx>) =
    try
      stream.Add command
    with :? InvalidOperationException ->
      ()

  /// Receives a command from the stream, blocking until one arrives. It
  /// returns NotAvailable once the stream is closed and drained.
  member _.Receive(ct: CancellationToken) =
    let mutable command = Unchecked.defaultof<_>
    if stream.TryTake(&command, Timeout.Infinite, ct) then Received command
    else NotAvailable

  /// Stops receiving and producing commands.
  member _.Close() = stream.CompleteAdding()

/// Status of a task worker command.
and TaskWorkerCommandStatus<'FnCtx, 'GlCtx> =
  | NotAvailable
  | Received of TaskWorkerCommand<'FnCtx, 'GlCtx>