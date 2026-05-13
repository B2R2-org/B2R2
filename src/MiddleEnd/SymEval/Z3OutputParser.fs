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

namespace B2R2.MiddleEnd.SymEval

open System
open System.Text
open B2R2

/// Parses the small subset of Z3 output used by the SymEval solver backend.
[<RequireQualifiedAccess>]
module Z3OutputParser =
  type private Token =
    | LParen
    | RParen
    | TokAtom of string

  type private SExpr =
    | SAtom of string
    | SList of SExpr list

  let private parseFailure msg =
    SolverFailure(SolverOutputParseFailure(msg, "")) |> Error

  let private isAtomEnd c = Char.IsWhiteSpace c || c = '(' || c = ')'

  let private tokenize (text: string) =
    let readQuoted idx =
      let sb = StringBuilder()
      let mutable idx = idx
      while idx < text.Length && text[idx] <> '|' do
        sb.Append text[idx] |> ignore
        idx <- idx + 1
      if idx >= text.Length then parseFailure "Unterminated quoted symbol."
      else Ok(idx + 1, sb.ToString())
    let rec loop idx acc =
      if idx >= text.Length then List.rev acc |> Ok
      else
        match text[idx] with
        | c when Char.IsWhiteSpace c -> loop (idx + 1) acc
        | '(' -> loop (idx + 1) (LParen :: acc)
        | ')' -> loop (idx + 1) (RParen :: acc)
        | '|' ->
          match readQuoted (idx + 1) with
          | Ok(nextIdx, symbol) -> loop nextIdx (TokAtom symbol :: acc)
          | Error e -> Error e
        | _ ->
          let mutable endIdx = idx
          while endIdx < text.Length && not (isAtomEnd text[endIdx]) do
            endIdx <- endIdx + 1
          let atom = text.Substring(idx, endIdx - idx)
          loop endIdx (TokAtom atom :: acc)
    loop 0 []

  let rec private parseOne = function
    | [] -> parseFailure "Unexpected end of Z3 output."
    | TokAtom atom :: rest -> Ok(SAtom atom, rest)
    | RParen :: _ -> parseFailure "Unexpected closing parenthesis."
    | LParen :: rest -> parseList [] rest

  and private parseList acc = function
    | [] -> parseFailure "Unterminated S-expression list."
    | RParen :: rest -> Ok(SList(List.rev acc), rest)
    | tokens ->
      match parseOne tokens with
      | Ok(expr, rest) -> parseList (expr :: acc) rest
      | Error e -> Error e

  let private parseAll tokens =
    let rec loop acc = function
      | [] -> List.rev acc |> Ok
      | tokens ->
        match parseOne tokens with
        | Ok(expr, rest) -> loop (expr :: acc) rest
        | Error e -> Error e
    loop [] tokens

  let private digitValue c =
    if c >= '0' && c <= '9' then Some(int c - int '0')
    elif c >= 'a' && c <= 'f' then Some(int c - int 'a' + 10)
    elif c >= 'A' && c <= 'F' then Some(int c - int 'A' + 10)
    else None

  let private parseUnsigned radix (text: string): Result<bigint, SymEvalError> =
    if text.Length = 0 then parseFailure "Expected an unsigned integer."
    else
      let rec loop idx (value: bigint) =
        if idx = text.Length then Ok value
        else
          match digitValue text[idx] with
          | Some digit when digit < radix ->
            loop (idx + 1) (value * bigint radix + bigint digit)
          | _ -> parseFailure $"Invalid unsigned integer: {text}"
      loop 0 0I

  let private toBitVector width (value: bigint) =
    if width <= 0 then parseFailure $"Invalid bit-vector width: {width}"
    else Ok(BitVector(value, width * 1<rt>))

  let private parseHexLiteral (text: string) =
    let digits = text.Substring 2
    parseUnsigned 16 digits
    |> Result.bind (toBitVector (digits.Length * 4))

  let private parseBinLiteral (text: string) =
    let digits = text.Substring 2
    parseUnsigned 2 digits
    |> Result.bind (toBitVector digits.Length)

  let private parseDecimalBitVecLiteral (valueText: string)
                                        (widthText: string) =
    let valueText = valueText.Substring 2
    match Int32.TryParse widthText with
    | true, width ->
      parseUnsigned 10 valueText |> Result.bind (toBitVector width)
    | false, _ -> parseFailure $"Invalid bit-vector width: {widthText}"

  let private parseBitVector = function
    | SAtom atom when atom.StartsWith("#x", StringComparison.Ordinal) ->
      parseHexLiteral atom
    | SAtom atom when atom.StartsWith("#b", StringComparison.Ordinal) ->
      parseBinLiteral atom
    | SList [ SAtom "_"; SAtom value; SAtom width ]
      when value.StartsWith("bv", StringComparison.Ordinal) ->
      parseDecimalBitVecLiteral value width
    | expr -> parseFailure $"Unsupported get-value expression: {expr}"

  let private parseValuePair = function
    | SList [ SAtom name; value ] ->
      parseBitVector value
      |> Result.map (fun value -> { Name = name; Value = value })
    | expr -> parseFailure $"Invalid get-value pair: {expr}"

  let private parseValues = function
    | [] -> Ok []
    | [ SList pairs ] ->
      pairs
      |> List.fold (fun acc pair ->
        match acc, parseValuePair pair with
        | Ok values, Ok value -> Ok(value :: values)
        | Error e, _ | _, Error e -> Error e) (Ok [])
      |> Result.map List.rev
    | _ -> parseFailure "Expected a single get-value result list."

  let private parseOutput sexprs =
    match sexprs with
    | SAtom "sat" :: rest ->
      parseValues rest
      |> Result.map (fun values -> { Status = Sat; Values = values })
    | SAtom "unsat" :: _ -> Ok { Status = Unsat; Values = [] }
    | SAtom "unknown" :: _ -> Ok { Status = Unknown; Values = [] }
    | [] -> parseFailure "Empty Z3 output."
    | expr :: _ -> parseFailure $"Unexpected Z3 status: {expr}"

  /// Parse Z3 stdout produced by check-sat and, optionally, get-value.
  let parse (stdout: string) =
    tokenize stdout
    |> Result.bind parseAll
    |> Result.bind parseOutput
