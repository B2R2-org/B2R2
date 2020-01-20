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

namespace B2R2.Utilities.BinExplorer
open FParsec
open System.Numerics
open SimpleArithHelper
open SimpleArithConverter
open B2R2

type SimpleArithEvaluator () =
  /// Concatenating given array of strings. Returning place of error when there
  /// is space between digits of number.
  let concatenate arg =
    let rec doConcatenation res input errorPos =
      match input with
      | [] -> (res, errorPos)
      | hd :: tail ->
        if hd = "" then
          doConcatenation res tail errorPos
        elif res = "" then
          doConcatenation (res + hd) tail errorPos
        else
          let lastChar = res.[res.Length - 1]
          let firstChar = hd.[0]
          if System.Char.IsDigit lastChar && System.Char.IsDigit firstChar then
            doConcatenation (res + " " + hd) tail res.Length
          else
            doConcatenation (res + " " + hd) tail errorPos
    doConcatenation "" arg 0

  let processError str (position: Position) =
    let result = str + "\n"
    let space = sprintf "%*s^" (int position.Column - 2) ""
    [| result + space + "\n" + "Expecting: Digit, Suffix or Operator" |]

  let processIntegerorFloat result typ =
    let value = Number.toString result
    let str = getIntegerPart value
    let intValue = BigInteger.Parse str
    let intValue =
      if hasZeroFraction value = false && result.FloatValue < 0.0 then
        intValue - 1I
      else intValue
    match typ with
    | DecimalF | OctalF | HexadecimalF | BinaryF ->
      [| getOutputValueString intValue typ result.Type |]
    | _ ->
      if value.IndexOf '.' = -1 then [| value + ".0" |]
      else [| value |]

  let checkIntegerOrFloatResult (str: string) result (position: Position) typ =
    if position.Column <> int64 (str.Length + 1) then
      processError str position
    else
      processIntegerorFloat result typ

  let postProcess str result position typ =
    match result.Type with
    | CError pos -> ErrorMessage.constructErrorMessage str pos
    | _ -> checkIntegerOrFloatResult str result position typ

  let processArithmetic str representation =
    match run SimpleArithParser.expr str with
    | Success (v, _, p) ->
      postProcess str v p representation
    | Failure (v, _, _) ->
      [| v |]

  let processASCIIError str (position: Position) =
    let result = str + "\n"
    let space = sprintf "%*s^" (int position.Column - 2) ""
    [| result + space + "\n" + "Wrong Input" |]

  let processASCIICharacters str =
    match SimpleArithASCIIPArser.run str with
    | Success (v, _, position) ->
      if position.Column <> int64 (str.Length + 1) then
        processASCIIError str position
      else
        processBytes v
    | Failure (v, _, _) ->
      [| v |]

  member __.Run args representation =
    let str, err = concatenate args
    if err = 0 then
      if representation = CharacterF then
        processASCIICharacters str
      else
        processArithmetic str representation
    else
      let result = str + "\n"
      let space = sprintf "%*s^" err ""
      [| result + space + "\n" + "Expecting: Digit or Operator" |]

type CmdEvalExpr (name, alias, descrSuffix, helpSuffix, outFormat) =
  inherit Cmd ()

  let evaluator = SimpleArithEvaluator ()

  override __.CmdName = name

  override __.CmdAlias = alias

  override __.CmdDescr =
    "Evaluate and display the value of an expression in " + descrSuffix + "."

  override __.CmdHelp =
    "Usage: ?" + helpSuffix + " <expression>\n\n\
     Evaluate the given expression and print out the value. This command\n\
     supports basic arithmetic expressions."

  override __.SubCommands = []

  override __.CallBack _ _ args =
    match args with
    | [] -> [| __.CmdHelp |]
    | _ -> evaluator.Run args outFormat
