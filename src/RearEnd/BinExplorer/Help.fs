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

open B2R2.RearEnd.Utils

type CmdHelp() =
  inherit Cmd()

  let generalHelpStr = """
[*] Current B2R2 commands (type 'help <command>' for more info):
  """

  let generalHelp cmdMap =
    [| yield generalHelpStr
       for KeyValue(name, cmd) in cmdMap.CmdMap do
         if cmd.CmdName = name then yield "- " + name + ": " + cmd.CmdDescr
         else () |]

  let specificHelp cmd cmdMap =
    match Map.tryFind cmd cmdMap.CmdMap with
    | None -> Cmd.warnUnknown cmd
    | Some cmd ->
      [| yield "[*] Usage of the command (" + cmd.CmdName + ")\n"
         if cmd.CmdHelp.Length > 0 then yield cmd.CmdHelp else () |]

  override _.CmdName = "help"

  override _.CmdAlias = []

  override _.CmdDescr = "Show the usage."

  override _.CmdHelp =
    "Usage: help [cmd]\n\n\
     If the optional argument [cmd] presents, the specific usage of the\n\
     command will show. For example, type `help bininfo` to see the usage of\n\
     the command `bininfo`."

  override _.SubCommands =
    []

  override _.CallBack(cmdMap, _, args) =
    match args with
    | [] -> generalHelp cmdMap
    | cmd :: _ -> specificHelp cmd cmdMap
    |> Array.map OutputNormal

type CmdExit() =
  inherit Cmd()

  override _.CmdName = "exit"

  override _.CmdAlias = [ "quit"; "q" ]

  override _.CmdDescr = "Exit B2R2."

  override _.CmdHelp = "Usage: exit"

  override _.SubCommands = []

  override _.CallBack(_, _, _) = [||]
