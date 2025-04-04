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

open B2R2.MiddleEnd
open System.IO

type SendMsg =
  | GetBinaryBrew
  | LogString of string
  | Terminate

type ReplyMsg =
  | Ack
  | ReplyBinaryBrew of BinaryBrew
  | ReplyExitStatus of bool (* Either success (true) or failure (false) *)

type Msg =
  | Send of SendMsg
  | Reply of ReplyMsg

module internal Protocol =

  type Agent = MailboxProcessor<Msg * AsyncReplyChannel<Msg>>

  let genArbiter brew logFile =
    let logger = new StreamWriter (path=logFile, AutoFlush=true)
    Agent.Start (fun inbox ->
      let rec loop brew = async {
        let! (msg, channel) = inbox.Receive ()
        match msg with
        | Send GetBinaryBrew ->
          Reply (ReplyBinaryBrew brew) |> channel.Reply
        | Send (LogString str) ->
          logger.WriteLine str
          channel.Reply (Reply Ack)
        | Send (Terminate) ->
          logger.Close ()
          logger.Dispose ()
          channel.Reply (Reply Ack)
        | _ -> ()
        return! loop brew
      }
      loop brew
    )

  let getBinaryBrew (arbiter: Agent) =
    match arbiter.PostAndReply (fun ch -> Send GetBinaryBrew, ch) with
    | Reply (ReplyBinaryBrew brew) -> brew
    | _ -> failwith "Failed to obtain the BinaryBrew."

  let logString (arbiter: Agent) str =
    match arbiter.PostAndReply (fun ch -> Send (LogString str), ch) with
    | Reply Ack -> ()
    | _ -> failwith "Failed to log message."

  let terminate (arbiter: Agent) =
    match arbiter.PostAndReply (fun ch -> Send Terminate, ch) with
    | Reply Ack -> ()
    | _ -> failwith "Failed to terminate."

// vim: set tw=80 sts=2 sw=2:
