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
open System.IO
open System.Text.RegularExpressions
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// Value validation shared by action execution and argument completion.
module ActionArgumentValidation =
  let private isHexString (value: string) =
    not (String.IsNullOrWhiteSpace value)
    && value.Length % 2 = 0
    && value |> Seq.forall Uri.IsHexDigit

  let private tryParseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    match UInt64.TryParse(value, style, CultureInfo.InvariantCulture) with
    | true, number ->
      Some number
    | _ ->
      None

  let private isAddress (value: string) =
    not (value.StartsWith '+')
    && tryParseUInt64 value |> Option.isSome

  let private isSize (value: string) =
    let value = if value.StartsWith '+' then value[1..] else value
    match tryParseUInt64 value with
    | Some size ->
      size > 0UL
    | None ->
      false

  let private tryParseInt32 (value: string) =
    if value.StartsWith '+' then
      None
    else
      let style, value =
        if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
          NumberStyles.HexNumber, value[2..]
        else
          NumberStyles.Integer, value
      match Int32.TryParse(value, style, CultureInfo.InvariantCulture) with
      | true, number ->
        Some number
      | _ ->
        None

  let private tryParseFloat (value: string) =
    let style = NumberStyles.Float
    match Double.TryParse(value, style, CultureInfo.InvariantCulture) with
    | true, number ->
      Some number
    | _ ->
      match Double.TryParse value with
      | true, number ->
        Some number
      | _ ->
        None

  let private isISA (value: string) =
    try
      ISA value |> ignore
      true
    with _ ->
      false

  let private isRegex (value: string) =
    try
      Regex value |> ignore
      true
    with :? ArgumentException ->
      false

  let private isPath (value: string) =
    if String.IsNullOrWhiteSpace value then
      false
    else
      try
        Path.GetFullPath value |> ignore
        true
      with _ ->
        false

  let private sectionExists (input: ReplValue) sectionName =
    let sectionInsideSlice (slice: BinarySlice) section =
      let section: BinSection = section
      let finish = section.Address + section.FileSize
      section.Address >= slice.StartAddress && finish <= slice.EndAddress
    input.Collection.Values
    |> Array.exists (function
      | :? Binary as binary ->
        let file = (Binary.Handle binary).File
        BinFileOps.tryFindSectionByName file sectionName |> Result.isOk
      | :? BinarySlice as slice ->
        let file = (Binary.Handle slice.Source).File
        match BinFileOps.tryFindSectionByName file sectionName with
        | Ok section ->
          sectionInsideSlice slice section
        | Error _ ->
          false
      | _ ->
        false)

  let private validateWith sectionExists argument value =
    let argument: ActionArgument = argument
    let value: string = value
    let valid, expected =
      match argument.Kind with
      | ActionArgumentKind.Text ->
        not (String.IsNullOrWhiteSpace value), "non-empty text"
      | ActionArgumentKind.Path ->
        isPath value, "a valid path"
      | ActionArgumentKind.ExistingPath ->
        File.Exists value || Directory.Exists value, "an existing path"
      | ActionArgumentKind.OutputPath ->
        isPath value, "a valid output path"
      | ActionArgumentKind.ISA ->
        isISA value, "a supported ISA name"
      | ActionArgumentKind.Integer ->
        let isValid = tryParseInt32 value |> Option.isSome
        isValid, "a 32-bit integer (0x... hex or decimal)"
      | ActionArgumentKind.ArbitraryInteger ->
        let isValid = IntegerParsing.tryParse value |> Option.isSome
        isValid, "an integer (0x... hex or decimal)"
      | ActionArgumentKind.Float ->
        let isValid = tryParseFloat value |> Option.isSome
        isValid, "a floating-point number"
      | ActionArgumentKind.HexPattern ->
        isRegex value, "a valid hexadecimal regular expression"
      | ActionArgumentKind.HexBytes ->
        isHexString value, "even-length hexadecimal bytes"
      | ActionArgumentKind.Address ->
        isAddress value, "an address (0x... hex or decimal)"
      | ActionArgumentKind.Size ->
        isSize value, "a positive size (0x... hex or decimal)"
      | ActionArgumentKind.Section ->
        sectionExists value, "a section in the current binary"
      | ActionArgumentKind.Action ->
        not (String.IsNullOrWhiteSpace value), "an action reference"
      | ActionArgumentKind.ParameterFunction ->
        not (String.IsNullOrWhiteSpace value), "a parameter function"
      | ActionArgumentKind.Choice ->
        List.contains value argument.Choices,
        String.concat "|" argument.Choices
    if valid then
      Ok()
    else
      Error $"{argument.Name} must be {expected}; received '{value}'."

  let validate input argument value =
    validateWith (sectionExists input) argument value

  let canonicalize argument value =
    let argument: ActionArgument = argument
    let value: string = value
    match argument.Kind with
    | ActionArgumentKind.Integer ->
      tryParseInt32 value
      |> Option.map (fun number ->
        number.ToString(CultureInfo.InvariantCulture))
      |> Option.defaultValue value
    | ActionArgumentKind.Float ->
      tryParseFloat value
      |> Option.map (fun number ->
        number.ToString("R", CultureInfo.InvariantCulture))
      |> Option.defaultValue value
    | ActionArgumentKind.Size when not (value.StartsWith '+') ->
      "+" + value
    | _ ->
      value

  let canSuggestBinding argument value =
    let argument: ActionArgument = argument
    match argument.Kind with
    | ActionArgumentKind.Path
    | ActionArgumentKind.ExistingPath
    | ActionArgumentKind.OutputPath
    | ActionArgumentKind.HexPattern
    | ActionArgumentKind.Section ->
      not (String.IsNullOrWhiteSpace value)
    | _ ->
      validateWith (fun _ -> false) argument value |> Result.isOk
