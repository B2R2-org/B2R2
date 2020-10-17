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

open B2R2.MiddleEnd.BinEssence
open B2R2.RearEnd

/// Raised when there are duplicate commands with the same name or alias.
exception DuplicateCommandException

/// Cmd represents a command that can be invoked within B2R2's CLI.
[<AbstractClass>]
type Cmd () =
  /// The name of the command.
  abstract member CmdName: string

  /// Aliases for the command.
  abstract member CmdAlias: string list

  /// Short command description.
  abstract member CmdDescr: string

  /// Command-specific help string.
  abstract member CmdHelp: string

  /// A list of sub-command strings that can be used with this command. This
  /// list provides a way to tab-complete a keyword.
  abstract member SubCommands: string list

  /// A command callback function. This function takes in an Agent (arbiter), a
  /// CmdMap, and a list of arguments as input, and produces some side effects.
  abstract member CallBack: CmdMap -> BinEssence -> string list -> OutString []

/// This is a mapping from a command name to the corresponding command (Cmd).
and CmdMap = {
  /// Mapping from command name to Cmd.
  CmdMap: Map<string, Cmd>
  /// List of command names and aliases.
  CmdList: string list
}

module internal Cmd =
  let warnUnknown (cmd: string) =
    [| "[*] Unknown command: '" + cmd + "'"
       "" (* for new line *) |]

  let handle cmdMap binEssence cmd args =
    match Map.tryFind cmd cmdMap.CmdMap with
    | None -> warnUnknown cmd |> Array.map OutputNormal
    | Some cmd -> cmd.CallBack cmdMap binEssence args

module internal CmdMap =

  let private addCmdMap name cmd m =
    if Map.containsKey name m.CmdMap then raise DuplicateCommandException
    else { CmdMap = Map.add name cmd m.CmdMap
           CmdList = name :: m.CmdList }

  let private commandBuilder m (cmd: Cmd) =
    let subs = cmd.SubCommands |> List.map (fun sub -> cmd.CmdName + " " + sub)
    List.append (cmd.CmdName :: cmd.CmdAlias) subs
    |> List.fold (fun m name -> addCmdMap name cmd m) m

  let build spec =
    let m = { CmdMap = Map.empty; CmdList = [] }
    spec |> List.fold commandBuilder m

// vim: set tw=80 sts=2 sw=2:
