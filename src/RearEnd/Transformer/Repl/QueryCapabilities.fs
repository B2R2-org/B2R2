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

/// One searchable property exposed by a Transformer value kind.
type ReplQueryProperty =
  { Name: string
    Description: string
    Matches: string -> obj -> bool }

/// Search capabilities exposed by one Transformer value kind.
type ReplQueryProvider =
  { ValueKind: ReplValueKind
    Properties: ReplQueryProperty list }

/// Defines the query capabilities used by generic REPL actions.
module ReplQueryCapabilities =
  let private parseAddress (text: string) =
    let style, text =
      if text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, text[2..]
      else
        NumberStyles.Integer, text
    UInt64.TryParse(text, style, CultureInfo.InvariantCulture)

  let private symbolProperty =
    { Name = "symbol"
      Description = "Function symbol name."
      Matches = fun expected value ->
        match value with
        | :? FunctionInfo as functionInfo ->
          functionInfo.Symbol
          |> Option.exists (fun symbol ->
            String.Equals(expected, symbol, StringComparison.Ordinal))
        | _ ->
          false }

  let private entryProperty =
    { Name = "entry"
      Description = "Function entry address."
      Matches = fun expected value ->
        match parseAddress expected, value with
        | (true, entry), (:? FunctionInfo as functionInfo) ->
          functionInfo.Entry = entry
        | _ ->
          false }

  let private providers =
    [ { ValueKind = ReplValueKind.FunctionInfo
        Properties = [ symbolProperty; entryProperty ] } ]

  let propertiesFor (kind: ReplValueKind) =
    providers
    |> List.tryFind (fun provider -> provider.ValueKind = kind)
    |> Option.map (fun provider -> provider.Properties)
    |> Option.defaultValue []

  let tryFilter
    (kind: ReplValueKind)
    (propertyName: string)
    (expected: string)
    (values: obj[]) =
    let comparison = StringComparison.OrdinalIgnoreCase
    let property =
      propertiesFor kind
      |> List.tryFind (fun property ->
        String.Equals(property.Name, propertyName, comparison))
    match property with
    | Some property ->
      values |> Array.filter (property.Matches expected) |> Ok
    | None ->
      let kindName = ReplValueKind.toString kind
      Error $"{propertyName} is not searchable on {kindName}."
