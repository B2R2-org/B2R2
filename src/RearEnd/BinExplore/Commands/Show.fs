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

namespace B2R2.RearEnd.BinExplore.Commands

open B2R2
open B2R2.RearEnd.BinExplore

type Show() =
  let [<Literal>] CmdName = "show"

  let [<Literal>] Desc = "Show information about an abstract component."

  interface ICmd with

    member _.CmdName = CmdName

    member _.CmdAlias = []

    member _.CmdDescr = Desc

    member _.CmdHelp =
      let extra =
        "<component> is an abstract component in the binary, and below are\n\
         available subcommands:\n\
         - caller <instruction addr in hex>\n\
         - callee/function <callee name or addr in hex>"
      ColoredString()
        .Append(NoColor, "Usage: ")
        .Append(DarkCyan, $"{CmdName}")
        .Append(NoColor, " <component> [option(s)]\n\n")
        .Append(NoColor, $"{Desc}\n\n{extra}")

    member _.SubCommands = []

    member this.CallBack(_, args) =
      match args with
      | _ -> [| (this :> ICmd).CmdHelp |]
      |> Array.map OutputColored
