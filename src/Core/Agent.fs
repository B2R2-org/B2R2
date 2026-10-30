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
open System.Collections.Concurrent
open System.Threading
open System.Threading.Tasks

/// <summary>
/// Represents an agent that processes messages one at a time on a thread of
/// its own. See also <see cref='T:B2R2.AgentReplyChannel`1'/>.
/// </summary>
/// <remarks>
/// Neither handing a message to the agent nor handing a reply back takes a
/// thread pool thread: the side that waits is woken directly. Callers often
/// block on a reply from pool threads themselves, so a hand-over that queued
/// work on the pool would leave both sides stuck for good whenever the pool
/// does not get to run it.
/// </remarks>
type Agent<'Msg> private(ch: BlockingCollection<'Msg>, task: Task) =

  /// Gets the task associated with this agent.
  member _.Task with get() = task

  /// Starts a new agent with a given task function and a cancellation token.
  /// Cancelling the token stops the agent, even one waiting for a message.
  static member Start(taskFn: IAgentMessageReceivable<'Msg> -> unit, token) =
    let ch = new BlockingCollection<'Msg>()
    let receivable =
      { new IAgentMessageReceivable<'Msg> with
          member _.Receive() =
            let mutable msg = Unchecked.defaultof<'Msg>
            if ch.TryTake(&msg, Timeout.Infinite, token) then msg
            else raise <| OperationCanceledException()
          member _.Complete() = ch.CompleteAdding()
          member _.IsCancelled with get() = token.IsCancellationRequested
          member _.Count with get() = ch.Count }
    let fn = fun () ->
      try
        taskFn receivable
      with
      | :? OperationCanceledException when token.IsCancellationRequested -> ()
      | e -> e.ToString() |> Terminator.fatalExit
    let options = TaskCreationOptions.LongRunning
    let scheduler = TaskScheduler.Default
    let loop = Task.Factory.StartNew(Action fn, token, options, scheduler)
    Agent(ch, loop)

  /// Posts a message to the agent. A message posted after the agent has
  /// stopped taking messages is dropped.
  member _.Post(msg: 'Msg) =
    try
      ch.Add msg
    with :? InvalidOperationException ->
      ()

  /// Posts a message and returns a reply from the agent.
  member this.PostAndReply callback =
    use cts = new CancellationTokenSource()
    let reply = TaskCompletionSource<_>()
    let msg = callback cts (AgentReplyChannel<_>(reply.TrySetResult >> ignore))
    this.Post msg
    reply.Task.Wait(cts.Token)
    reply.Task.Result

/// <summary>
/// Represents a reply channel for an agent (<see cref='T:B2R2.Agent`1'/>). The
/// agent will receive a message synchronously from the reply channel.
/// </summary>
and AgentReplyChannel<'Reply>(replyf: 'Reply -> unit) =
  member _.Reply(reply: 'Reply) = replyf reply

/// Interface for receiving agent messages.
and IAgentMessageReceivable<'Msg> =
  /// Receives a message from the agent.
  abstract Receive: unit -> 'Msg

  /// Notifies the agent that no more messages will be sent.
  abstract Complete: unit -> unit

  /// Returns true if the agent has been cancelled; otherwise, false.
  abstract IsCancelled: bool

  /// Gets the number of messages remaining in the agent's buffer.
  abstract Count: int