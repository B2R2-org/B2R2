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

namespace B2R2.Core.Tests

open System
open System.Threading
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type AgentTests() =

  /// Runs the given function on a thread of its own while the thread pool can
  /// run nothing else, telling whether the function finished in time. Anything
  /// that waits on the pool times out.
  let runWithoutThreadPool (timeout: TimeSpan) f =
    let mutable minWorkers, minIOs = 0, 0
    let mutable maxWorkers, maxIOs = 0, 0
    ThreadPool.GetMinThreads(&minWorkers, &minIOs)
    ThreadPool.GetMaxThreads(&maxWorkers, &maxIOs)
    let limit = max minWorkers Environment.ProcessorCount
    (* Never disposed, since a blocker that is still queued when this returns
       waits on it afterwards. *)
    let release = new ManualResetEventSlim()
    ThreadPool.SetMaxThreads(limit, maxIOs) |> ignore
    try
      (* With as many blockers as the pool may have threads, whatever is queued
         after them runs only once they are released. *)
      for _ in 1 .. limit do
        ThreadPool.QueueUserWorkItem(fun _ -> release.Wait()) |> ignore
      let thread = Thread(ThreadStart f, IsBackground = true)
      thread.Start()
      thread.Join timeout
    finally
      release.Set()
      ThreadPool.SetMaxThreads(maxWorkers, maxIOs) |> ignore

  [<TestMethod>]
  member _.``Agent replies while every thread pool thread is blocked``() =
    use cts = new CancellationTokenSource()
    let reply = ref 0
    let answer (inbox: IAgentMessageReceivable<AgentReplyChannel<int>>) =
      while not inbox.IsCancelled do
        let ch = inbox.Receive()
        ch.Reply(42)
    (* A worker that blocks on a reply from a pool thread must not depend on
       the pool to deliver its request or the reply. *)
    let finished =
      runWithoutThreadPool (TimeSpan.FromSeconds 10.0) (fun () ->
        let agent = Agent<_>.Start(answer, cts.Token)
        reply.Value <- agent.PostAndReply(fun _ ch -> ch))
    cts.Cancel()
    Assert.AreEqual<bool * int>((true, 42), (finished, reply.Value))

  [<TestMethod>]
  member _.``Agent stops when cancelled while waiting for a message``() =
    use cts = new CancellationTokenSource()
    use waiting = new ManualResetEventSlim()
    let agent =
      Agent<int>.Start((fun inbox ->
        while not inbox.IsCancelled do
          waiting.Set()
          inbox.Receive() |> ignore), cts.Token)
    waiting.Wait()
    cts.Cancel()
    let stopped = agent.Task.Wait(TimeSpan.FromSeconds 10.0)
    Assert.AreEqual<bool>(true, stopped)
