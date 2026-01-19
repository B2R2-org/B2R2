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

open B2R2.RearEnd.Utils
open B2R2.RearEnd.BinQL
open B2R2.RearEnd.BinExplorer

type SimpleArithEvaluator() =
  let parser = Parser()
  let evaluator = Evaluator()

  member _.Run(args) =
    let args = String.concat " " args
    match parser.Run args with
    | Ok e -> [| evaluator.EvalExprToString e |]
    | Error e -> [| $"{e}" |]

type EvalExpr(name, alias) =
  let evaluator = SimpleArithEvaluator()

  interface ICmd with

    member _.CmdName = name

    member _.CmdAlias = alias

    member _.CmdDescr = "Evaluate and display the value of an expression."

    member _.CmdHelp =
      "Usage: ? <expression>\n\n\
      Evaluate the given BinQL expression and print out the value. This\n\
      command supports basic arithmetic expressions."

    member _.SubCommands = []

    member this.CallBack(_, args) =
      match args with
      | [] -> [| (this :> ICmd).CmdHelp |]
      | _ -> evaluator.Run(args)
      |> Array.map OutputNormal
