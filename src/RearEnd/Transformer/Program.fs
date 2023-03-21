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
open FSharp.Compiler.CodeAnalysis
open B2R2
open B2R2.RearEnd

let [<Literal>] private Usage = """[Usage]

b2r2 transformer [-f file|-d file] [action] (-- [action] ...)

Transformer runs a chain of transforming actions (IAction). An action takes in
an object as input and returns another object as output. Any number of actions
can be chained together as long as their types match. Users can define their own
action(s) by implementing the IAction interface.

[Options]

-f <fsx file>  : Load a custom fsx (F# script) file to define custom actions.
-d <dll file>  : Load a dll file defining custom actions.

[Actions]
"""

/// The `help` action.
type private HelpAction (map: Map<string, IAction>) =
  interface IAction with
    member __.ActionID with get() = "help"
    member __.InputType with get() = typeof<obj>
    member __.OutputType with get() = typeof<unit>
    member __.Description with get() = ""
    member __.Transform _args _ =
      Console.WriteLine ()
      CmdOpts.WriteIntro ()
      Console.WriteLine Usage
      map |> Map.iter (fun id act ->
        Console.WriteLine
          $"- {id}: {act.InputType.Name} -> {act.OutputType.Name}"
        Console.WriteLine $"{act.Description}")
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

let private compileUserActions filePath =
  if File.Exists filePath then
    let filePath = Path.GetFullPath filePath
    let checker = FSharpChecker.Create ()
    let dllPath = Path.ChangeExtension (filePath, ".dll")
    let asmPath = Assembly.GetEntryAssembly().GetName().Name
    let compArgs =
      [| "fsc.exe"; "-o"; dllPath; "-a"; filePath; $"--reference:{asmPath}" |]
    let errs, exitCode = checker.Compile compArgs |> Async.RunSynchronously
    if exitCode = 0 then
      loadUserDLL dllPath
    else
      errs |> Array.iter (fun d -> d.ToString () |> Console.WriteLine)
      invalidOp $"Failed to compile {filePath}"
  else
    invalidOp $"File not found: {filePath}"

let private retrieveActionMap map =
  let actionType = typeof<IAction>
  let map =
    actionType.Assembly.GetExportedTypes ()
    |> filterIActionType
    |> accumulateActions map
  let helpAction = HelpAction map :> IAction
  Map.add helpAction.ActionID helpAction map

let rec private groupActions grps grp = function
  | [] -> List.rev (List.rev grp :: grps)
  | "--" :: rest ->
    let grps = if List.isEmpty grp then grps else (List.rev grp) :: grps
    groupActions grps [] rest
  | arg :: rest -> groupActions grps (arg :: grp) rest

let private parseActions args actionMap =
  groupActions [] [] args
  |> List.fold (fun input grp ->
    let actionID = List.head grp
    let args = List.tail grp
    let action: IAction = Map.find (actionID.ToLowerInvariant ()) actionMap
#if DEBUG
    if actionID <> "help" then Console.WriteLine $"[*] {actionID}" else ()
#endif
    action.Transform args input
  ) ()

[<EntryPoint>]
let main argv =
  match List.ofArray argv with
  | [] ->
    retrieveActionMap Map.empty
    |> parseActions [ "help" ]
    |> ignore
  | "-f" :: file :: args ->
    compileUserActions file
    |> retrieveActionMap
    |> parseActions args
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