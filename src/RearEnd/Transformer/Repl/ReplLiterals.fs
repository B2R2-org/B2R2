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

namespace B2R2.RearEnd.Transformer

open System
open System.Globalization
open System.Numerics
open B2R2

/// Resolves scalar and collection literals in REPL pipelines.
module internal ReplLiterals =

  let private splitLiteralElements separator tokens =
    ReplLanguage.splitTopLevelStrict separator tokens

  let private scalarObject name (value: ReplValue) =
    if value.Collection.Values.Length = 1 then
      Ok value.Collection.Values[0]
    else
      Error $"Literal element must be a scalar value: {name}"

  let private resolveLiteralElement state eval tokens =
    match tokens with
    | [ name ] ->
      match TransformerReplState.tryFind name state with
      | Some value ->
        scalarObject name value
      | None ->
        TransformerReplParser.parsePipelineTokens tokens
        |> Result.bind eval
        |> Result.bind (scalarObject name)
    | [] ->
      Error "Empty literal element."
    | _ ->
      TransformerReplParser.parsePipelineTokens tokens
      |> Result.bind eval
      |> Result.bind (scalarObject (String.concat " " tokens))

  let private resolveLiteralElements state eval separator tokens =
    splitLiteralElements separator tokens
    |> Result.bind (List.fold (fun result tokens ->
      result
      |> Result.bind (fun values ->
        resolveLiteralElement state eval tokens
        |> Result.map (fun value -> value :: values))) (Ok []))
    |> Result.map (List.rev >> List.toArray)

  let private tryTrimmedLiteral closeToken tokens =
    match List.rev tokens with
    | token :: body when token = closeToken ->
      Some(List.rev body)
    | _ ->
      None

  let private tryAddressLiteral (token: string) =
    if token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
      let text = token[2..]
      match UInt64.TryParse(
        text,
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture
      ) with
      | true, value ->
        Some({ Address = value } |> box)
      | _ ->
        None
    else
      None

  let private tryIntLiteral (token: string) =
    match Int32.TryParse(
      token,
      NumberStyles.Integer,
      CultureInfo.InvariantCulture
    ) with
    | true, value ->
      Some(value |> box)
    | _ ->
      match BigInteger.TryParse(
              token,
              NumberStyles.Integer,
              CultureInfo.InvariantCulture
            ) with
      | true, value ->
        Some(value |> box)
      | _ ->
        None

  let private tryBoolLiteral (token: string) =
    match Boolean.TryParse token with
    | true, value ->
      Some(value |> box)
    | _ ->
      None

  let private tryScalarLiteral tokens =
    match tokens with
    | [ token ] ->
      tryAddressLiteral token
      |> Option.orElseWith (fun () -> tryIntLiteral token)
      |> Option.orElseWith (fun () -> tryBoolLiteral token)
      |> Option.orElseWith (fun () ->
        ReplLanguage.tryQuotedString token |> Option.map box)
      |> Option.map (fun value ->
        ReplValue.ofCollection ReplValueKind.Any { Values = [| value |] })
    | _ ->
      None

  let private validateLiteralSeparators separator tokens =
    let invalid =
      if separator = ";" then "," else ";"
    if List.contains invalid tokens then
      Error $"Use '{separator}' to separate literal elements."
    else
      Ok tokens

  let private homogeneousLiteral name makeValue values =
    ReplValue.validateHomogeneous name values
    |> Result.map (fun () -> makeValue values |> Some)

  let tryLiteral state eval segment =
    let tokens = segment.Head :: segment.Arguments
    match tokens with
    | "(" :: rest ->
      match tryTrimmedLiteral ")" rest with
      | Some [] ->
        Ok(Some ReplValue.emptyInput)
      | Some body when List.contains "," body ->
        body
        |> validateLiteralSeparators ","
        |> Result.bind (resolveLiteralElements state eval ",")
        |> Result.map (ReplValue.ofTuple >> Some)
      | Some _ ->
        Ok None
      | None ->
        Ok None
    | "[" :: rest ->
      match tryTrimmedLiteral "]" rest with
      | Some body ->
        body
        |> validateLiteralSeparators ";"
        |> Result.bind (resolveLiteralElements state eval ";")
        |> Result.bind (homogeneousLiteral "List" ReplValue.ofList)
      | None ->
        Ok None
    | "[|" :: rest ->
      match tryTrimmedLiteral "|]" rest with
      | Some body ->
        body
        |> validateLiteralSeparators ";"
        |> Result.bind (resolveLiteralElements state eval ";")
        |> Result.bind (homogeneousLiteral "Array" ReplValue.ofArray)
      | None ->
        Ok None
    | _ ->
      Ok(tryScalarLiteral tokens)
