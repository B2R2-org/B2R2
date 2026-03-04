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

open System
open System.Collections.Generic
open B2R2

/// Raised when there are duplicate commands with the same name or alias.
exception DuplicateCommandException

/// This is a mapping from a command name to the corresponding command (Cmd).
type CmdStore(spec) as this =
  /// Mapping from command name to ICmd.
  let cmdMap = Dictionary<string, ICmd>()

  /// List of command names and aliases.
  let cmdList = ResizeArray<string>()

  let warnUnknown (cmd: string) =
    let msg =
      ColoredString()
        .Add(NoColor, "[")
        .Add(Red, "*")
        .Add(NoColor, "] Unknown command: '")
        .Add(Red, cmd)
        .Add(NoColor, "'")
    [| msg |]

  let generalHelpStr =
    ColoredString()
      .Add(NoColor, "[")
      .Add(DarkCyan, "*")
      .Add(NoColor, "] Current B2R2 commands (type '")
      .Add(DarkCyan, "help")
      .Add(NoColor, " <command>' for more info):")

  let generalHelp () =
    [| yield generalHelpStr
       for KeyValue(name, cmd) in cmdMap do
         if cmd.CmdName = name then
           let item =
             ColoredString()
               .Add(NoColor, "- ")
               .Add(DarkCyan, name)
               .Add(NoColor, ": " + cmd.CmdDescr)
           yield item
         else () |]

  let specificHelp cmd =
    match cmdMap.TryGetValue cmd with
    | true, cmd ->
      let head =
        ColoredString()
          .Add(NoColor, "[")
          .Add(DarkCyan, "*")
          .Add(NoColor, "] Usage of the command '")
          .Add(DarkCyan, cmd.CmdName)
          .Add(NoColor, "':\n")
      [| yield head
         if cmd.CmdHelp.Length > 0 then yield cmd.CmdHelp
         else () |]
    | false, _ ->
      warnUnknown cmd

  do
    for cmd in [ CmdHelp this :> ICmd; CmdExit(); yield! spec ] do
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
    | false, _ -> warnUnknown cmd |> Array.map OutputColored

  member _.CreateHelpString() =
    generalHelp ()
    |> Array.map OutputColored

  member _.CreateHelpString cmd =
    specificHelp cmd
    |> Array.map OutputColored

and private CmdHelp(cmdStore: CmdStore) =

  let [<Literal>] CmdName = "help"

  let [<Literal>] Desc = "Show the usage."

  interface ICmd with

    member _.CmdName = CmdName

    member _.CmdAlias = [ "h" ]

    member _.CmdDescr = Desc

    member _.CmdHelp =
      let extra =
        "If the optional argument [cmd] presents, the specific usage of the\n\
         command will show. For example, type `help bininfo` to see the usage\n\
         of the command `bininfo`."
      ColoredString()
        .Add(NoColor, "Usage: ")
        .Add(DarkCyan, $"{CmdName}")
        .Add(NoColor, " [cmd]\n\n")
        .Add(NoColor, extra)

    member _.SubCommands = []

    member _.CallBack(_, args) =
      match args with
      | [] ->
        cmdStore.CreateHelpString()
      | cmd :: _ when String.IsNullOrEmpty cmd ->
        cmdStore.CreateHelpString()
      | cmd :: _ ->
        cmdStore.CreateHelpString cmd

and private CmdExit() =
  let [<Literal>] CmdName = "exit"

  let [<Literal>] Desc = "Exit B2R2."

  interface ICmd with

    member _.CmdName = CmdName

    member _.CmdAlias = [ "quit"; "q" ]

    member _.CmdDescr = Desc

    member _.CmdHelp =
      ColoredString()
        .Add(NoColor, "Usage: ")
        .Add(DarkCyan, $"{CmdName}\n\n")
        .Add(NoColor, $"{Desc}")

    member _.SubCommands = []

    member _.CallBack(_, _) = [||]
