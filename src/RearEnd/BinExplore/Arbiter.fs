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

namespace B2R2.RearEnd.BinExplore

open B2R2
open B2R2.Logging
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a command message that can be sent to the arbiter.
type private ArbiterCommand<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                            and 'FnCtx: (new: unit -> 'FnCtx)
                                            and 'GlCtx: (new: unit -> 'GlCtx)> =
  | Command of Action * AsyncReplyChannel<ReplyMsg<'FnCtx, 'GlCtx>>

and private Action =
  /// Adds a binary instance to the workspace with the given file path.
  | AddBinary of string
  /// Gets a binary brew instance by the given file path. If the given path is
  /// None, it returns the current binary brew instance.
  | GetBinaryBrew of string option
  /// Logs a string message to the arbiter's logger.
  | LogString of string
  /// Terminates the arbiter and releases all resources.
  | Terminate

and private ReplyMsg<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                                     and 'FnCtx: (new: unit -> 'FnCtx)
                                     and 'GlCtx: (new: unit -> 'GlCtx)> =
  | Ack of Result<unit, string>
  | ReplyBinaryBrew of BinaryBrew<'FnCtx, 'GlCtx> option

/// Represents an arbiter that manages Workspace instances.
type Arbiter<'FnCtx, 'GlCtx when 'FnCtx :> IResettable
                             and 'FnCtx: (new: unit -> 'FnCtx)
                             and 'GlCtx: (new: unit -> 'GlCtx)>
  public(brewLoader: IBrewLoadable<'FnCtx, 'GlCtx>, logFile) =

  let logger =
    match logFile with
    | Some path -> new FilePrinter(path) :> IPrinter
    | None -> new ConsoleNullPrinter() :> IPrinter

  let ok = Ack(Ok())

  let mutable workspace = Workspace<'FnCtx, 'GlCtx>(brewLoader)

  let mailbox =
    MailboxProcessor.Start(fun inbox ->
      let rec loop () =
        async {
          let! msg = inbox.Receive()
          match msg with
          | Command(AddBinary(path), ch) ->
            ch.Reply(Ack(workspace.AddBinary(path)))
          | Command(GetBinaryBrew(None), ch) ->
            let brew = workspace.CurrentBinary
            ch.Reply(ReplyBinaryBrew brew)
          | Command(GetBinaryBrew(Some path), ch) ->
            let brew = workspace.TryFindBinary path
            ch.Reply(ReplyBinaryBrew brew)
          | Command(LogString str, ch) ->
            logger.PrintLine str
            ch.Reply ok
          | Command(Terminate, ch) ->
            logger.Dispose()
            ch.Reply ok
            return ()
          return! loop ()
        }
      loop ()
    )

  member _.AddBinary(path) =
    match mailbox.PostAndReply(fun ch -> Command(AddBinary(path), ch)) with
    | Ack(Ok()) -> printsn $"[*] Successfully loaded {path}"; Ok()
    | Ack(Error e) -> Error e
    | _ -> Terminator.fatalExit "Failed to add binary."

  member _.GetBinaryBrew() =
    match mailbox.PostAndReply(fun ch -> Command(GetBinaryBrew None, ch)) with
    | ReplyBinaryBrew brew -> brew
    | _ -> None

  member _.GetBinaryBrew(path) =
    let path = Some path
    match mailbox.PostAndReply(fun ch -> Command(GetBinaryBrew path, ch)) with
    | ReplyBinaryBrew brew -> brew
    | _ -> None

  member _.LogString str =
    match mailbox.PostAndReply(fun ch -> Command(LogString str, ch)) with
    | Ack(Ok()) -> ()
    | _ -> Terminator.fatalExit "Failed to log message."

  member _.Terminate() =
    match mailbox.PostAndReply(fun ch -> Command(Terminate, ch)) with
    | Ack(Ok()) -> ()
    | _ -> Terminator.fatalExit "Failed to terminate."
