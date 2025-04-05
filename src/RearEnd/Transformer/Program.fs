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

module B2R2.RearEnd.Transformer.Program

open System
open System.IO
open System.Reflection
open B2R2
open B2R2.RearEnd.Utils

let [<Literal>] private Usage = """[Usage]

b2r2 transformer [-d file] [action] (-- [action] ...)

Transformer runs a chain of transforming actions (IAction). An action takes in a
collection of objects as input and returns another collection of objects as
output. Any number of actions can be chained together as long as their types
match. Users can define their own action(s) by implementing the IAction
interface.

[Options]

-d <dll file>  : Load a dll file defining custom actions.

[Actions]
"""

/// The `help` action.
type private HelpAction (map: Map<string, IAction>) =
  interface IAction with
    member _.ActionID with get() = "help"
    member _.Signature with get() = "'a -> 'b"
    member _.Description with get() = ""
    member _.Transform _args _ =
      Printer.PrintToConsoleLine ()
      CmdOpts.WriteIntro ()
      Printer.PrintToConsoleLine Usage
      map |> Map.iter (fun id act ->
        Printer.PrintToConsoleLine $"- {id}: {act.Signature}"
        Printer.PrintToConsoleLine $"{act.Description}")
      exit 0

let private accumulateActions map actions =
  actions
  |> Array.fold (fun map t ->
    let act = Activator.CreateInstance t :?> IAction
    if Map.containsKey act.ActionID map then
      invalidOp $"Duplicate action ID: {act.ActionID}"
    else
      Map.add act.ActionID act map) map

let inline private filterIActionType types =
  (types: System.Type[])
  |> Array.filter (fun t ->
    t.IsPublic
    && (t.GetInterface (nameof IAction) |> isNull |> not))

let private loadUserDLL dllPath =
  if File.Exists dllPath then
    let dllPath = Path.GetFullPath dllPath
    let dll = Assembly.LoadFile dllPath
    dll.GetExportedTypes ()
    |> filterIActionType
    |> accumulateActions Map.empty
  else invalidOp $"File not found: {dllPath}"

let private retrieveActionMap map =
  let actionType = typeof<IAction>
  let map =
    actionType.Assembly.GetExportedTypes ()
    |> filterIActionType
    |> accumulateActions map
  let helpAction = HelpAction map :> IAction
  Map.add helpAction.ActionID helpAction map

let private splitBySpecialSeparators (args: string list) =
  args
  |> List.collect (fun arg ->
    arg.Replace("--", " -- ")
       .Replace(",", " , ")
       .Split (' ', StringSplitOptions.RemoveEmptyEntries) |> Array.toList)

let rec private breakCommandByComma cmds cmd = function
  | [] -> List.rev (List.rev cmd :: cmds)
  | "," :: rest ->
    let cmds = if List.isEmpty cmd then cmds else (List.rev cmd) :: cmds
    breakCommandByComma cmds [] rest
  | arg :: rest -> breakCommandByComma cmds (arg :: cmd) rest

let private accumulateIfNotEmpty grp acc =
  if List.isEmpty grp then acc
  else List.rev grp :: acc

let rec private parseActionCommands grps grp = function
  | [] -> List.rev (accumulateIfNotEmpty grp grps)
  | "--" :: rest ->
    let grps =
      if List.isEmpty grp then grps else accumulateIfNotEmpty grp grps
    parseActionCommands grps [] rest
  | arg :: rest -> parseActionCommands grps (arg :: grp) rest

let private checkValidityOfCommandGroup cmdgrp =
  let actionIDs = cmdgrp |> List.map List.tryHead
  let fstActionID = List.head actionIDs
  if actionIDs |> List.forall (fun actionID -> actionID = fstActionID) then ()
  else
    Printer.PrintErrorToConsole "different actions in the same group."
    exit 1

let private runCommand actionMap input (cmd: string list) =
  let actionID = List.head cmd
  let args = List.tail cmd
  let action: IAction =
    match Map.tryFind (actionID.ToLowerInvariant ()) actionMap with
    | Some act -> act
    | None ->
      Printer.PrintErrorToConsole $"({actionID}) is not a valid action."
      exit 1
#if DEBUG
  if actionID <> "help" then Printer.PrintToConsoleLine $"[*] {actionID}"
  else ()
#endif
  try
    action.Transform args input
  with
    | :? InvalidCastException ->
      Printer.PrintErrorToConsole $"({actionID}) action type mismatch."
      exit 1
    | :? NullReferenceException ->
      Printer.PrintErrorToConsole $"({actionID}) action should follow another."
      exit 1
    | :? ArgumentException as e ->
      Printer.PrintErrorToConsole $"{e.Message}"
      exit 1
    | e ->
      Printer.PrintErrorToConsole $"({actionID}): {e}"
      exit 1

let inline private unwrap (c: ObjCollection) = c.Values

let autoPrint actionMap collection =
  if collection.Values.Length = 0 then ()
  else runCommand actionMap collection [ "print" ] |> ignore

let private parseActions args actionMap =
  args
  |> splitBySpecialSeparators
  |> parseActionCommands [] []
  |> List.map (breakCommandByComma [] [])
  |> List.fold (fun input cmdgrp ->
    checkValidityOfCommandGroup cmdgrp
    { Values =
        cmdgrp
        |> List.map (fun cmd -> runCommand actionMap input cmd |> unwrap)
        |> Array.concat }
  ) { Values = [| () |] }
  |> autoPrint actionMap

[<EntryPoint>]
let main argv =
  match List.ofArray argv with
  | [] ->
    retrieveActionMap Map.empty
    |> parseActions [ "help" ]
    |> ignore
  | "-d" :: file :: args ->
    loadUserDLL file
    |> retrieveActionMap
    |> parseActions args
    |> ignore
  | args ->
    retrieveActionMap Map.empty
    |> parseActions args
    |> ignore
  0