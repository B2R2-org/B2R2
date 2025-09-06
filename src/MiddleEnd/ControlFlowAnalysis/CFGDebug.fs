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

[<AutoOpen>]
module internal B2R2.MiddleEnd.ControlFlowAnalysis.CFGDebug

#if CFGDEBUG
open System.IO
open System.Text
open System.Threading
open B2R2
open B2R2.Logging

let [<Literal>] ManagerTid = -1

type LogMessage =
  | Log of int * string
  | Flush of int

type CFGLogger(numThreads) =
  let logBuilders = Array.init (numThreads + 1) (fun _ -> StringBuilder ())

  let cts = new CancellationTokenSource()

  let lock = System.Object()

  let logger =
    let fileName = Path.ChangeExtension(Path.GetRandomFileName(), "log")
    System.Console.Error.WriteLine $"[!] CFG log is written @ {fileName}"
    let path = Path.Combine(Directory.GetCurrentDirectory(), fileName)
    new FileLogger(path) :> ILogger

  let flushLog tid =
    Monitor.Enter lock
    try
      let sb = logBuilders[tid]
      sb.ToString() |> logger.Log
      sb.Clear() |> ignore
    finally
      Monitor.Exit lock

  let task = fun (inbox: IAgentMessageReceivable<LogMessage>) ->
    while not inbox.IsCancelled do
      match inbox.Receive() with
      | Log(tid, msg) ->
        if tid = ManagerTid then
          logBuilders[numThreads].AppendLine msg |> ignore
          flushLog numThreads
        else
          logBuilders[tid].AppendLine msg |> ignore
      | Flush tid ->
        flushLog (if tid = ManagerTid then numThreads else tid)

  let agent = Agent<LogMessage>.Start(task, cts.Token)

  member inline _.Log(tid, locationName: string, msg) =
    let t = if tid = ManagerTid then "m " else $"{tid, -2}"
    let log = $"{t} | {locationName, -22} | {msg}"
    agent.Post <| Log(tid, log)

  member inline _.Flush tid =
    agent.Post <| Flush tid

let mutable logger: CFGLogger | null = null

let initLogger numThreads =
  if isNull logger then logger <- CFGLogger numThreads
  else ()

let inline dbglog tid locationName msg =
  logger.Log(tid, locationName, msg)

let inline flushLog tid =
  logger.Flush tid
#endif
