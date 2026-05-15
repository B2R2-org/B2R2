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

/// Parses the small subset of solver output used by SymEval.
[<RequireQualifiedAccess>]
module SolverOutputParser =
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
    | [] -> parseFailure "Unexpected end of solver output."
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
    | expr -> parseFailure $"Unsupported bit-vector expression: {expr}"

  let private parseStatusAtom = function
    | "sat" | "SATISFIABLE" -> Ok Sat
    | "unsat" | "UNSATISFIABLE" -> Ok Unsat
    | "unknown" | "UNKNOWN" -> Ok Unknown
    | status -> parseFailure $"Unexpected solver status: {status}"

  let private parseStatusOutput = function
    | SAtom status :: _ -> parseStatusAtom status
    | [] -> parseFailure "Empty solver status."
    | expr :: _ -> parseFailure $"Unexpected solver status: {expr}"

  let private parseModelValue = function
    | SList [ SAtom "define-fun"; SAtom name; SList []
              SList [ SAtom "_"; SAtom "BitVec"; SAtom _ ]; value ] ->
      parseBitVector value |> Result.map (fun value -> Some(name, value))
    | SList(SAtom "define-fun" :: _) ->
      parseFailure "Unsupported define-fun model entry."
    | _ -> Ok None

  let private collectModelValues sexprs =
    let rec collect acc sexpr =
      match parseModelValue sexpr with
      | Ok(Some value) -> Ok(value :: acc)
      | Ok None ->
        match sexpr with
        | SList sexprs -> List.fold folder (Ok acc) sexprs
        | SAtom _ -> Ok acc
      | Error e -> Error e
    and folder acc sexpr =
      match acc with
      | Ok values -> collect values sexpr
      | Error e -> Error e
    sexprs
    |> List.fold folder (Ok [])
    |> Result.map (List.rev >> Map.ofList)

  /// Parse a raw solver status string.
  let parseStatus (stdout: string) =
    tokenize stdout
    |> Result.bind parseAll
    |> Result.bind parseStatusOutput

  /// Parse zero-arity bit-vector definitions in a raw solver model.
  let parseModel (modelText: string) =
    tokenize modelText
    |> Result.bind parseAll
    |> Result.bind collectModelValues

  let private serializationFailure msg =
    SolverFailure(SolverSerializationFailure msg) |> Error

  let private validateQueryValue = function
    | Var(name, typ) -> Ok(name, typ)
    | _ -> serializationFailure "Only variable model queries are supported."

  let private foldResult folder state values =
    let rec loop state = function
      | [] -> Ok(List.rev state)
      | value :: rest ->
        match folder state value with
        | Ok state -> loop state rest
        | Error e -> Error e
    loop state values

  let private requestedValues values =
    foldResult
      (fun acc value ->
        validateQueryValue value
        |> Result.map (fun value -> value :: acc))
      [] values

  let private zeroValue typ = BitVector.Zero typ

  /// Extract requested SymEval values from raw solver model text.
  let extract values modelText =
    match requestedValues values with
    | Error e -> Error e
    | Ok requested ->
      match parseModel modelText with
      | Error e -> Error e
      | Ok model ->
        requested
        |> List.map (fun (name, typ) ->
          { Name = name
            Value =
              model
              |> Map.tryFind name
              |> Option.defaultWith (fun () -> zeroValue typ) })
        |> fun values -> { Status = Sat; Values = values }
        |> Ok

  /// Validate requested SymEval values before asking for a model.
  let validate values =
    requestedValues values |> Result.map ignore
