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

namespace B2R2.RearEnd.BinExplorer

open System.IO
open B2R2
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a command message that can be sent to the arbiter.
type private ArbiterCommand<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                            and 'FnCtx: (new: unit -> 'FnCtx)
                                            and 'GlCtx: (new: unit -> 'GlCtx)> =
  | Command of Action * AsyncReplyChannel<ReplyMsg<'FnCtx, 'GlCtx>>

and private Action =
  | GetBinaryBrew
  | LogString of string
  | Terminate

and private ReplyMsg<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                     and 'FnCtx: (new: unit -> 'FnCtx)
                                     and 'GlCtx: (new: unit -> 'GlCtx)> =
  | Ack
  | ReplyBinaryBrew of BinaryBrew<'FnCtx, 'GlCtx>

/// Represents an arbiter that manages a BinaryBrew instance and logging.
type Arbiter<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                     and 'FnCtx: (new: unit -> 'FnCtx)
                                     and 'GlCtx: (new: unit -> 'GlCtx)>
  public(brew: BinaryBrew<'FnCtx, 'GlCtx>, logFile) =

  let logger = new StreamWriter(path = logFile, AutoFlush = true)

  let mailbox =
    MailboxProcessor.Start(fun inbox ->
      let rec loop brew =
        async {
          let! msg = inbox.Receive()
          match msg with
          | Command(GetBinaryBrew, ch) ->
            ch.Reply(ReplyBinaryBrew brew)
          | Command(LogString str, ch) ->
            logger.WriteLine str
            ch.Reply Ack
          | Command(Terminate, ch) ->
            logger.Close()
            logger.Dispose()
            ch.Reply Ack
          return! loop brew
        }
      loop brew
    )

  member _.GetBinaryBrew() =
    match mailbox.PostAndReply(fun ch -> Command(GetBinaryBrew, ch)) with
    | ReplyBinaryBrew brew -> brew
    | _ -> Terminator.fatalExit "Failed to obtain the BinaryBrew."


  member _.LogString str =
    match mailbox.PostAndReply(fun ch -> Command(LogString str, ch)) with
    | Ack -> ()
    | _ -> Terminator.fatalExit "Failed to log message."

  member _.Terminate() =
    match mailbox.PostAndReply(fun ch -> Command(Terminate, ch)) with
    | Ack -> ()
    | _ -> Terminator.fatalExit "Failed to terminate."
