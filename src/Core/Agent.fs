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

namespace B2R2

open System
open System.Threading.Tasks
open System.Threading.Tasks.Dataflow

/// The agent for processing messages based on the TPL Dataflow.
type Agent<'Msg> private (ch: BufferBlock<'Msg>, task: Task) =

  /// Post a message to the agent.
  member _.Post (msg: 'Msg) =
    ch.Post msg |> ignore

  /// Post a message and get a reply from the agent.
  member _.PostAndReply callback =
    let replyChan = BufferBlock<_> ()
    let reply = AgentReplyChannel<_> (replyChan.Post >> ignore)
    let msg = callback reply
    ch.Post msg |> ignore
    replyChan.Receive ()

  /// Agent's task.
  member _.Task with get() = task

  /// Start a new agent with a given task function and a cancellation token.
  static member Start (taskFn: IAgentMessageReceivable<'Msg> -> unit, token) =
    let ch = BufferBlock<'Msg> ()
    let receivable =
      { new IAgentMessageReceivable<'Msg> with
          member _.Receive () = ch.Receive (cancellationToken=token)
          member _.IsCancelled with get() = token.IsCancellationRequested }
    let fn = fun () ->
      try taskFn receivable
      with e -> Console.Error.WriteLine e.Message
    Agent (ch, Task.Run (fn, cancellationToken=token))

/// Reply channel for the agent.
and AgentReplyChannel<'Reply> (replyf: 'Reply -> unit) =
  member _.Reply (reply: 'Reply) = replyf reply

/// Interface for receiving agent messages.
and IAgentMessageReceivable<'Msg> =
  /// Receive a message from the agent.
  abstract Receive: unit -> 'Msg

  /// Is the agent cancelled?
  abstract IsCancelled: bool
