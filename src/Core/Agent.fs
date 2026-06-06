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
open System.Threading
open System.Threading.Tasks
open System.Threading.Tasks.Dataflow

/// <summary>
/// Represents an agent that processes messages asynchronously using the TPL
/// Dataflow. See also <see cref='T:B2R2.AgentReplyChannel`1'/>.
/// </summary>
type Agent<'Msg> private(ch: BufferBlock<'Msg>, task: Task) =

  /// Gets the task associated with this agent.
  member _.Task with get() = task

  /// Starts a new agent with a given task function and a cancellation token.
  static member Start(taskFn: IAgentMessageReceivable<'Msg> -> unit, token) =
    let ch = BufferBlock<'Msg>()
    let receivable =
      { new IAgentMessageReceivable<'Msg> with
          member _.Receive() =
            task {
              let! isAvailable = ch.OutputAvailableAsync token
              if isAvailable then
                match ch.TryReceive() with
                | true, msg -> return msg
                | false, _ -> return raise <| InvalidOperationException()
              else return raise <| OperationCanceledException()
            } |> fun task -> task.Result
          member _.Complete() = ch.Complete()
          member _.IsCancelled with get() = token.IsCancellationRequested
          member _.Count with get() = ch.Count }
    let fn = fun () ->
      try taskFn receivable
      with e -> e.ToString() |> Terminator.fatalExit
    Agent(ch, Task.Run(fn, cancellationToken = token))

  /// Posts a message to the agent.
  member _.Post(msg: 'Msg) = ch.Post msg |> ignore

  /// Posts a message and returns a reply from the agent.
  member _.PostAndReply callback =
    use cts = new CancellationTokenSource()
    let replyChan = BufferBlock<_>()
    let reply = AgentReplyChannel<_>(replyChan.Post >> ignore)
    let msg = callback cts reply
    ch.Post msg |> ignore
    replyChan.Receive cts.Token

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