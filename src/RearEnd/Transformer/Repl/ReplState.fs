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

namespace B2R2.RearEnd.Transformer

open System
open System.Globalization
open B2R2

[<RequireQualifiedAccess>]
type ReplValueShape =
  | Scalar
  | Collection
  | List
  | Array
  | Tuple

/// A typed value retained by an interactive Transformer session.
type ReplValue =
  { Kind: ReplValueKind
    IsCollection: bool
    Shape: ReplValueShape
    Collection: ObjCollection }

/// One result in the persistent value history of a session.
type ReplValueHistoryEntry =
  { ID: int
    Name: string option
    Value: ReplValue }

/// Outcome recorded for an evaluated command.
[<RequireQualifiedAccess>]
type ReplExecutionStatus =
  | Succeeded
  | Failed
  | Cancelled

/// Whether successful analysis commands are recorded into the replay script.
[<RequireQualifiedAccess>]
type ReplReplayMode =
  | Reproducible
  | Exploratory

/// One detailed execution-log entry.
type ReplExecutionLogEntry =
  { ID: int
    Timestamp: DateTimeOffset
    Duration: TimeSpan
    Status: ReplExecutionStatus
    Command: string
    Detail: string option }

/// Restorable state captured before a value-producing command.
type ReplUndoCapture =
  { Bindings: Map<string, ReplValue>
    Current: ReplValue option
    ValueHistory: ReplValueHistoryEntry list
    LastNeeds: ContextRequirements option
    ReplayCommands: string list }

/// State that persists across commands in a Transformer REPL session.
type TransformerReplState =
  { Bindings: Map<string, ReplValue>
    Current: ReplValue option
    ValueHistory: ReplValueHistoryEntry list
    CommandHistory: string list
    ReplayCommands: string list
    ReplayMode: ReplReplayMode
    SessionPath: string option
    ExecutionLog: ReplExecutionLogEntry list
    LastNeeds: ContextRequirements option
    LastError: string option
    NextValueID: int
    NextLogID: int
    UndoStack: ReplUndoCapture list }

module ReplValue =
  let private kindOfType (typ: Type) =
    if typ = typeof<Binary> then ReplValueKind.Binary
    elif typ = typeof<BinaryBytes> then ReplValueKind.ByteArray
    elif typ = typeof<Instruction[]> then ReplValueKind.InstructionArray
    elif typ = typeof<CFG> then ReplValueKind.CFG
    elif typ = typeof<TextArtifact> then ReplValueKind.TextArtifact
    elif typ = typeof<Fingerprint> then ReplValueKind.Fingerprint
    elif typ = typeof<ClusterResult> then ReplValueKind.ClusterResult
    elif typ = typeof<ConcExecutorValue> then ReplValueKind.ConcExecutor
    elif typ = typeof<SymbExecutorValue> then ReplValueKind.SymbExecutor
    elif typ = typeof<SymbSolverValue> then ReplValueKind.SymbSolver
    elif typ = typeof<SymbRunValue> then ReplValueKind.SymbRunResult
    elif typ = typeof<RegisterView> then ReplValueKind.RegisterView
    elif typ = typeof<MemoryView> then ReplValueKind.MemoryView
    elif typ = typeof<ExecutionTrace> then ReplValueKind.ExecutionTrace
    elif typ = typeof<ContextRequirements> then
      ReplValueKind.ContextRequirements
    elif typ = typeof<AddressValue> then ReplValueKind.Address
    elif typ = typeof<BinarySlice> then ReplValueKind.BinarySlice
    elif typ = typeof<StringMatch> then ReplValueKind.StringMatch
    elif typ = typeof<SectionInfo> then ReplValueKind.SectionInfo
    elif typ = typeof<FunctionInfo> then ReplValueKind.FunctionInfo
    elif typ = typeof<string> then ReplValueKind.Text
    elif typeof<OutString>.IsAssignableFrom typ then ReplValueKind.Text
    elif typ = typeof<int> then ReplValueKind.Int
    elif typ = typeof<float> then ReplValueKind.Float
    elif typ = typeof<bool> then ReplValueKind.Bool
    else ReplValueKind.Any

  let rec private kindOfObject (value: obj) =
    match value with
    | null -> ReplValueKind.Unit
    | :? Binary -> ReplValueKind.Binary
    | :? BinaryBytes -> ReplValueKind.ByteArray
    | :? (Instruction[]) -> ReplValueKind.InstructionArray
    | :? CFG -> ReplValueKind.CFG
    | :? TextArtifact -> ReplValueKind.TextArtifact
    | :? Fingerprint -> ReplValueKind.Fingerprint
    | :? ClusterResult -> ReplValueKind.ClusterResult
    | :? ConcExecutorValue -> ReplValueKind.ConcExecutor
    | :? SymbExecutorValue -> ReplValueKind.SymbExecutor
    | :? SymbSolverValue -> ReplValueKind.SymbSolver
    | :? SymbRunValue -> ReplValueKind.SymbRunResult
    | :? RegisterView -> ReplValueKind.RegisterView
    | :? MemoryView -> ReplValueKind.MemoryView
    | :? ExecutionTrace -> ReplValueKind.ExecutionTrace
    | :? ContextRequirements -> ReplValueKind.ContextRequirements
    | :? AddressValue -> ReplValueKind.Address
    | :? BinarySlice -> ReplValueKind.BinarySlice
    | :? StringMatch -> ReplValueKind.StringMatch
    | :? SectionInfo -> ReplValueKind.SectionInfo
    | :? FunctionInfo -> ReplValueKind.FunctionInfo
    | :? string -> ReplValueKind.Text
    | :? OutString -> ReplValueKind.Text
    | :? int -> ReplValueKind.Int
    | :? float -> ReplValueKind.Float
    | :? bool -> ReplValueKind.Bool
    | _ ->
      let typ = value.GetType()
      if typ.IsArray then
        let elementType = typ.GetElementType()
        let directKind = kindOfType typ
        let elementKind = kindOfType elementType
        if directKind <> ReplValueKind.Any then directKind
        elif elementKind <> ReplValueKind.Any then elementKind
        else
          let values = value :?> Array
          let kinds =
            values
            |> Seq.cast<obj>
            |> Seq.map kindOfObject
            |> Seq.filter (fun kind -> kind <> ReplValueKind.Unit)
            |> Seq.distinct
            |> Seq.truncate 2
            |> Seq.toList
          match kinds with
          | [ kind ] -> kind
          | _ -> ReplValueKind.Any
      else
        kindOfType typ

  let kindOf value = kindOfObject value

  let tryArgumentText (value: obj) =
    match value with
    | null -> Some ""
    | :? AddressValue as value -> Some $"0x{value.Address:x}"
    | :? int as value ->
      Some(value.ToString(CultureInfo.InvariantCulture))
    | :? float as value ->
      Some(value.ToString("R", CultureInfo.InvariantCulture))
    | :? bool as value -> Some(if value then "true" else "false")
    | :? string as value -> Some value
    | :? SymbSolverValue as value -> Some("@" + value.ID)
    | _ -> None

  let private tupleKind values =
    values |> Array.map kindOfObject |> Array.toList |> ReplValueKind.Tuple

  let private elementKind values =
    let kinds =
      values
      |> Array.map kindOfObject
      |> Array.filter (fun kind -> kind <> ReplValueKind.Unit)
      |> Array.distinct
    match kinds with
    | [| kind |] -> kind
    | _ -> ReplValueKind.Any

  let validateHomogeneous literalName values =
    let kinds =
      values
      |> Array.map kindOfObject
      |> Array.filter (fun kind -> kind <> ReplValueKind.Unit)
      |> Array.distinct
    if kinds.Length <= 1 then
      Ok()
    else
      let kinds = kinds |> Array.map ReplValueKind.toString
      let detail = String.concat ", " kinds
      Error $"{literalName} elements must have one type, but found {detail}."

  let ofCollection fallback collection =
    let elementKind =
      if collection.Values.Length = 0 then
        match fallback with
        | ReplValueKind.Collection kind -> kind
        | kind -> kind
      else
        elementKind collection.Values
    let kind =
      match fallback with
      | ReplValueKind.Collection _ ->
        ReplValueKind.Collection elementKind
      | ReplValueKind.Any ->
        elementKind
      | kind when collection.Values.Length = 1
                  && elementKind = ReplValueKind.Any ->
        kind
      | _ when collection.Values.Length > 1 ->
        ReplValueKind.Collection elementKind
      | _ when collection.Values.Length = 0 -> fallback
      | _ -> elementKind
    let isCollection =
      collection.Values.Length > 1
      || match kind with
         | ReplValueKind.Collection _ -> true
         | _ -> false
    { Kind = kind
      IsCollection = isCollection
      Shape =
        if isCollection then ReplValueShape.Collection
        else ReplValueShape.Scalar
      Collection = collection }

  let ofList values =
    { Kind = ReplValueKind.List(elementKind values)
      IsCollection = true
      Shape = ReplValueShape.List
      Collection = { Values = values } }

  let ofArray values =
    { Kind = ReplValueKind.Array(elementKind values)
      IsCollection = true
      Shape = ReplValueShape.Array
      Collection = { Values = values } }

  let ofTuple values =
    { Kind = tupleKind values
      IsCollection = values.Length > 1
      Shape = ReplValueShape.Tuple
      Collection = { Values = values } }

  let emptyInput =
    { Kind = ReplValueKind.Unit
      IsCollection = false
      Shape = ReplValueShape.Scalar
      Collection = { Values = [||] } }

module TransformerReplState =
  let empty =
    { Bindings = Map.empty
      Current = None
      ValueHistory = []
      CommandHistory = []
      ReplayCommands = []
      ReplayMode = ReplReplayMode.Reproducible
      SessionPath = None
      ExecutionLog = []
      LastNeeds = None
      LastError = None
      NextValueID = 1
      NextLogID = 1
      UndoStack = [] }

  let private undoCapture state =
    { Bindings = state.Bindings
      Current = state.Current
      ValueHistory = state.ValueHistory
      LastNeeds = state.LastNeeds
      ReplayCommands = state.ReplayCommands }

  let recordCommand command state =
    { state with CommandHistory = command :: state.CommandHistory }

  let recordReplayCommand command (state: TransformerReplState) =
    match state.ReplayMode with
    | ReplReplayMode.Reproducible ->
      { state with ReplayCommands = command :: state.ReplayCommands }
    | ReplReplayMode.Exploratory ->
      state

  let recordReplayComment comment (state: TransformerReplState) =
    match state.ReplayMode with
    | ReplReplayMode.Reproducible ->
      let line = "# " + comment
      { state with ReplayCommands = line :: state.ReplayCommands }
    | ReplReplayMode.Exploratory ->
      state

  let setReplayMode mode state =
    { state with ReplayMode = mode }

  let setSessionPath path state =
    { state with SessionPath = Some path }

  let setLastNeeds needs state =
    { state with LastNeeds = Some needs; LastError = None }

  let recordExecution timestamp duration status command detail state =
    let entry =
      { ID = state.NextLogID
        Timestamp = timestamp
        Duration = duration
        Status = status
        Command = command
        Detail = detail }
    { state with
        ExecutionLog = entry :: state.ExecutionLog
        NextLogID = state.NextLogID + 1 }

  let setError message state =
    { state with LastError = Some message }

  let setValue name value state =
    let bindings =
      match name with
      | Some name -> Map.add name value state.Bindings
      | None -> state.Bindings
    let history =
      { ID = state.NextValueID; Name = name; Value = value }
      :: state.ValueHistory
    { state with
        Bindings = bindings
        Current = Some value
        ValueHistory = history
        LastError = None
        NextValueID = state.NextValueID + 1
        UndoStack = undoCapture state :: state.UndoStack }

  let tryFind name state = Map.tryFind name state.Bindings

  let tryFindHistory id state =
    state.ValueHistory |> List.tryFind (fun entry -> entry.ID = id)

  let restoreValue id name state =
    match tryFindHistory id state with
    | Some entry -> Ok(setValue name entry.Value state)
    | None -> Error $"Unknown value history ID: {id}"

  let undo state =
    match state.UndoStack with
    | previous :: rest ->
      Ok
        { state with
            Bindings = previous.Bindings
            Current = previous.Current
            ValueHistory = previous.ValueHistory
            LastNeeds = previous.LastNeeds
            ReplayCommands = previous.ReplayCommands
            LastError = None
            UndoStack = rest }
    | [] -> Error "There is no value-producing command to undo."

  let replaceAnalysis replacement state =
    { replacement with
        CommandHistory = state.CommandHistory
        ExecutionLog = state.ExecutionLog
        ReplayMode = state.ReplayMode
        SessionPath = state.SessionPath
        NextLogID = state.NextLogID }

  let reset state =
    { empty with
        CommandHistory = state.CommandHistory
        ExecutionLog = state.ExecutionLog
        ReplayMode = state.ReplayMode
        SessionPath = state.SessionPath
        NextLogID = state.NextLogID }
