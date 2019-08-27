(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Mehdi Aghakishiyev <agakisiyev.mehdi@gmail.com>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.Utilities.BinExplorer
open FParsec
open System.Numerics
open SimpleArithHelper
open SimpleArithConverter
open Size
open DataType

type SimpleArithEvaluator () =
  let final str flag =
    let str, err = concatenate "" str 0
    if err = 0 then
      match run SimpleArithParser.expr str with
        | Success ((CError _, NError (a, b)), _, _) ->
          let result = str + "\n"
          let space = sprintf "%*s^" (int(b) - 2) ""
          let fin = result + space + "\n" + a
          [|fin|]
        | Success (v, _, p) ->
          if p.Column <> int64 (str.Length + 1) then
            let result = str + "\n"
            let space = sprintf "%*s^" (int(p.Column) - 2) ""
            let fin =
              result + space + "\n" + "Expecting: Digit, Suffix or Operator"
            [|fin|]
          else
            let value = Numbers.getValue (snd v)
            let str = (getWhole value)
            let int_value = BigInteger.Parse str
            let int_value =
              if (DataType.getType (fst v) = 2 &&
                  snd (checkFloat value) = false &&
                  int_value <= 0I) then (int_value - 1I)
              else int_value
            if flag = 0 || flag = 1 || flag = 2 || flag = 3 then
              let size = (getPriority (getSize (fst v)))
              [| final_converter int_value flag size |]
            else
              if value.IndexOf ('.') = -1 then [| value + ".0" |]
              else [| value |]
        | Failure (v, _, _) ->
          [|v|]
     else
       let result = str + "\n"
       let space = sprintf "%*s^" (err) ""
       let fin = result + space + "\n" + "Expecting: Digit or Operator"
       [|fin|]

  member __.Run str flag = final str flag

type CmdEvalExpr () =
  inherit Cmd ()

  override __.CmdName = "?"

  override __.CmdAlias = ["?x"]

  override __.CmdDescr = "Evaluates and displays the value of an expression."

  override __.CmdHelp =
    "Usage: ? <expression>\n\n\
     Evaluates the given expression and prints out the value. This command\n\
     supports basic arithmetic expressions."

  override __.SubCommands = []

  override __.CallBack _ _ args =
    match args with
    | [] -> [|__.CmdHelp|]
    | _ -> SimpleArithEvaluator().Run args 0

type CmdEvalExprDecimal () =
  inherit Cmd ()

  override __.CmdName = "?d"

  override __.CmdAlias = []

  override __.CmdDescr = "Evaluates and displays the value of an expression."

  override __.CmdHelp =
    "Usage: ? <expression>\n\n\
     Evaluates the given expression and prints out the value. This command\n\
     supports basic arithmetic expressions."

  override __.SubCommands = []

  override __.CallBack _ _ args =
    match args with
    | [] -> [|__.CmdHelp|]
    | _ -> SimpleArithEvaluator().Run args 1

type CmdEvalExprBinary () =
  inherit Cmd ()

  override __.CmdName = "?b"

  override __.CmdAlias = []

  override __.CmdDescr = "Evaluates and displays the value of an expression."

  override __.CmdHelp =
    "Usage: ? <expression>\n\n\
     Evaluates the given expression and prints out the value. This command\n\
     supports basic arithmetic expressions."

  override __.SubCommands = []

  override __.CallBack _ _ args =
    match args with
    | [] -> [|__.CmdHelp|]
    | _ -> SimpleArithEvaluator().Run args 2

type CmdEvalExprOctal () =
  inherit Cmd ()

  override __.CmdName = "?o"

  override __.CmdAlias = []

  override __.CmdDescr = "Evaluates and displays the value of an expression."

  override __.CmdHelp =
    "Usage: ? <expression>\n\n\
     Evaluates the given expression and prints out the value. This command\n\
     supports basic arithmetic expressions."

  override __.SubCommands = []

  override __.CallBack _ _ args =
    match args with
    | [] -> [|__.CmdHelp|]
    | _ -> SimpleArithEvaluator().Run args 3

type CmdEvalExprFloat () =
  inherit Cmd ()

  override __.CmdName = "?f"

  override __.CmdAlias = []

  override __.CmdDescr = "Evaluates and displays the value of an expression."

  override __.CmdHelp =
    "Usage: ? <expression>\n\n\
     Evaluates the given expression and prints out the value. This command\n\
     supports basic arithmetic expressions."

  override __.SubCommands = []

  override __.CallBack _ _ args =
    match args with
    | [] -> [|__.CmdHelp|]
    | _ -> SimpleArithEvaluator().Run args 4

