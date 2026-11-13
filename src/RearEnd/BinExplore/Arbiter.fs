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
type private ArbiterCommand<'FnCtx, 'GlCtx> =
  | Command of Action * AsyncReplyChannel<ReplyMsg<'FnCtx, 'GlCtx>>

and private Action =
  /// Opens a binary or selects the existing binary at the given path.
  | OpenBinaryFile of string
  /// Gets a binary brew instance by the given file path. If the given path is
  /// None, it returns the current binary brew instance.
  | GetBinaryBrew of string option
  /// Gets a binary by identity without changing the current selection.
  | GetBinaryByID of BinaryID
  /// Gets the opened binaries and current selection atomically.
  | GetSessionSnapshot
  /// Selects the binary used by current-binary commands.
  | SelectBinary of BinaryID
  /// Logs a string message to the arbiter's logger.
  | LogString of string
  /// Closes the current session.
  | CloseSession
  /// Terminates the arbiter and releases all resources.
  | Terminate

and private ReplyMsg<'FnCtx, 'GlCtx> =
  | Ack of Result<unit, string>
  | ReplyOpenedBinary of Result<BinaryInfo, string>
  | ReplyBinaryBrew of BinaryBrew<'FnCtx, 'GlCtx> option
  | ReplySessionSnapshot of SessionSnapshot

/// Represents an arbiter that manages AnalysisSession instances.
type Arbiter<'FnCtx, 'GlCtx>
  public(brewLoader: IBrewLoadable<'FnCtx, 'GlCtx>, logFile) =

  let logger =
    match logFile with
    | Some path -> new FilePrinter(path) :> IPrinter
    | None -> new ConsoleNullPrinter() :> IPrinter

  let ok = Ack(Ok())

  let mutable session = AnalysisSession<'FnCtx, 'GlCtx>(brewLoader)

  let mailbox =
    MailboxProcessor.Start(fun inbox ->
      let rec loop () =
        async {
          let! msg = inbox.Receive()
          match msg with
          | Command(OpenBinaryFile path, ch) ->
            ch.Reply(ReplyOpenedBinary(session.OpenBinary(path)))
          | Command(GetBinaryBrew(None), ch) ->
            let brew = session.CurrentBinary
            ch.Reply(ReplyBinaryBrew brew)
          | Command(GetBinaryBrew(Some path), ch) ->
            let brew = session.TryFindBinary path
            ch.Reply(ReplyBinaryBrew brew)
          | Command(GetBinaryByID id, ch) ->
            ch.Reply(ReplyBinaryBrew(session.TryGetBinary(id)))
          | Command(GetSessionSnapshot, ch) ->
            ch.Reply(ReplySessionSnapshot session.Snapshot)
          | Command(SelectBinary id, ch) ->
            ch.Reply(Ack(session.SelectBinary(id)))
          | Command(LogString str, ch) ->
            logger.PrintLine str
            ch.Reply ok
          | Command(CloseSession, ch) ->
            session <- AnalysisSession<'FnCtx, 'GlCtx>(brewLoader)
            ch.Reply ok
          | Command(Terminate, ch) ->
            logger.Dispose()
            ch.Reply ok
            return ()
          return! loop ()
        }
      loop ()
    )

  /// Opens and selects a binary, reusing an existing load of the same path.
  member _.OpenBinary(path) =
    match mailbox.PostAndReply(fun ch -> Command(OpenBinaryFile path, ch)) with
    | ReplyOpenedBinary(Ok info) ->
      printsn $"[*] Successfully opened {info.Path}"
      Ok info
    | ReplyOpenedBinary(Error e) ->
      Error e
    | _ ->
      Terminator.fatalExit "Failed to open binary."

  member this.AddBinary(path) =
    this.OpenBinary(path) |> Result.map ignore

  /// Returns an immutable snapshot of the opened binaries and selection.
  member _.GetSessionSnapshot() =
    match mailbox.PostAndReply(fun ch -> Command(GetSessionSnapshot, ch)) with
    | ReplySessionSnapshot snapshot -> snapshot
    | _ -> Terminator.fatalExit "Failed to get session snapshot."

  /// Explicitly selects the binary used by current-binary commands.
  member _.SelectBinary(id) =
    match mailbox.PostAndReply(fun ch -> Command(SelectBinary id, ch)) with
    | Ack result -> result
    | _ -> Terminator.fatalExit "Failed to select binary."

  member _.GetBinaryBrew() =
    match mailbox.PostAndReply(fun ch -> Command(GetBinaryBrew None, ch)) with
    | ReplyBinaryBrew(Some brew) -> Ok brew
    | _ -> Error "Failed to get current binary brew."

  /// Looks up a binary by path without changing the current selection.
  member _.GetBinaryBrew(path: string) =
    let path = Some path
    match mailbox.PostAndReply(fun ch -> Command(GetBinaryBrew path, ch)) with
    | ReplyBinaryBrew(Some(brew)) -> Ok brew
    | _ -> Error $"Failed to get binary brew for ({path})"

  /// Looks up a binary by identity without changing the current selection.
  member _.GetBinaryBrew(id: BinaryID) =
    match mailbox.PostAndReply(fun ch -> Command(GetBinaryByID id, ch)) with
    | ReplyBinaryBrew(Some brew) -> Ok brew
    | _ -> Error $"Failed to get binary brew for ({id})"

  /// Binds analysis queries to one binary independently of later selections.
  member this.ForBinary(id) =
    { new IBinarySource<'FnCtx, 'GlCtx> with
        member _.GetBinaryBrew() = this.GetBinaryBrew(id: BinaryID) }

  member _.LogString str =
    match mailbox.PostAndReply(fun ch -> Command(LogString str, ch)) with
    | Ack(Ok()) -> ()
    | _ -> Terminator.fatalExit "Failed to log message."

  member _.CloseSession() =
    match mailbox.PostAndReply(fun ch -> Command(CloseSession, ch)) with
    | Ack(Ok()) -> printsn "[*] Session closed."
    | _ -> Terminator.fatalExit "Failed to close session."

  member _.Terminate() =
    match mailbox.PostAndReply(fun ch -> Command(Terminate, ch)) with
    | Ack(Ok()) -> ()
    | _ -> Terminator.fatalExit "Failed to terminate."

  interface IBinarySource<'FnCtx, 'GlCtx> with
    member this.GetBinaryBrew() = this.GetBinaryBrew()
