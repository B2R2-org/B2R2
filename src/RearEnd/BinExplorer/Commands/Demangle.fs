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

namespace B2R2.RearEnd.BinExplorer.Commands

open B2R2
open B2R2.FrontEnd.NameMangling
open B2R2.RearEnd.BinExplorer

type Demangle() =
  let mapResult = function
    | Ok s -> [| OutputNormal s |]
    | Error _ -> [| OutputNormal "[*] Invalid input." |]

  interface ICmd with

    member _.CmdName = "demangle"

    member _.CmdAlias = [ "undecorate" ]

    member _.CmdDescr = "Demangle the given mangled string."

    member _.CmdHelp = "Usage: demangle <string>"

    member _.SubCommands = []

    member _.CallBack(_, args) =
      let mangled = String.concat " " args
      Demangler.Demangle mangled |> mapResult
