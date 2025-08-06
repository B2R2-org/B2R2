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

open System.Threading.Tasks.Dataflow

/// Stream of commands consumed by task workers.
type TaskWorkerCommandStream<'FnCtx,
                             'GlCtx when 'FnCtx :> IResettable
                                     and 'FnCtx: (new: unit -> 'FnCtx)
                                     and 'GlCtx: (new: unit -> 'GlCtx)>() =
    let stream = BufferBlock<TaskWorkerCommand<'FnCtx, 'GlCtx>>()

    /// Post a command to the stream.
    member _.Post(command: TaskWorkerCommand<'FnCtx, 'GlCtx>) =
      stream.Post command |> ignore

    /// Receive a command from the stream.
    member _.Receive(ct) =
      task {
        match! stream.OutputAvailableAsync(ct) with
        | false -> return NotAvailable
        | true ->
          match stream.TryReceive() with
          | true, command -> return Received command
          | false, _ -> return AvailableButNotReceived
      }

    /// Stop receiving nor producing commands.
    member _.Close() =
      stream.Complete()

/// Status of a task worker command.
and TaskWorkerCommandStatus<'FnCtx,
                            'GlCtx when 'FnCtx :> IResettable
                                    and 'FnCtx: (new: unit -> 'FnCtx)
                                    and 'GlCtx: (new: unit -> 'GlCtx)> =
  | NotAvailable
  | AvailableButNotReceived
  | Received of TaskWorkerCommand<'FnCtx, 'GlCtx>