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

open System.Collections.Generic
open B2R2.RearEnd.Utils

/// Raised when there are duplicate commands with the same name or alias.
exception DuplicateCommandException

/// This is a mapping from a command name to the corresponding command (Cmd).
type CmdStore(spec) as this =
  /// Mapping from command name to ICmd.
  let cmdMap = Dictionary<string, ICmd>()

  /// List of command names and aliases.
  let cmdList = ResizeArray<string>()

  let warnUnknown (cmd: string) =
    [| "[*] Unknown command: '" + cmd + "'"
       "" (* for new line *) |]

  let generalHelpStr =
    """
[*] Current B2R2 commands (type 'help <command>' for more info):
  """

  let generalHelp () =
    [| yield generalHelpStr
       for KeyValue(name, cmd) in cmdMap do
         if cmd.CmdName = name then yield "- " + name + ": " + cmd.CmdDescr
         else () |]

  let specificHelp cmd =
    match cmdMap.TryGetValue cmd with
    | true, cmd ->
      [| yield "[*] Usage of the command (" + cmd.CmdName + ")\n"
         if cmd.CmdHelp.Length > 0 then yield cmd.CmdHelp else () |]
    | false, _ -> warnUnknown cmd

  do
    for cmd in spec @ [ CmdHelp this :> ICmd; CmdExit() ] do
      cmd.SubCommands
      |> List.map (fun sub -> cmd.CmdName + " " + sub)
      |> List.append (cmd.CmdName :: cmd.CmdAlias)
      |> List.iter (fun name ->
        if cmdMap.ContainsKey name then raise DuplicateCommandException
        else cmdMap.Add(name, cmd); cmdList.Add name)

  member _.Commands with get() = cmdList |> Seq.toList

  member _.Handle(brew, cmd, args) =
    match cmdMap.TryGetValue cmd with
    | true, cmd -> cmd.CallBack(brew, args)
    | false, _ -> warnUnknown cmd |> Array.map OutputNormal

  member _.CreateHelpString() = generalHelp ()

  member _.CreateHelpString cmd = specificHelp cmd

and private CmdHelp(cmdStore: CmdStore) =
  interface ICmd with

    member _.CmdName = "help"

    member _.CmdAlias = []

    member _.CmdDescr = "Show the usage."

    member _.CmdHelp =
      "Usage: help [cmd]\n\n\
      If the optional argument [cmd] presents, the specific usage of the\n\
      command will show. For example, type `help bininfo` to see the usage of\n\
      the command `bininfo`."

    member _.SubCommands = []

    member _.CallBack(_, args) =
      match args with
      | [] -> cmdStore.CreateHelpString()
      | cmd :: _ -> cmdStore.CreateHelpString cmd
      |> Array.map OutputNormal

and private CmdExit() =
  interface ICmd with

    member _.CmdName = "exit"

    member _.CmdAlias = [ "quit"; "q" ]

    member _.CmdDescr = "Exit B2R2."

    member _.CmdHelp = "Usage: exit"

    member _.SubCommands = []

    member _.CallBack(_, _) = [||]