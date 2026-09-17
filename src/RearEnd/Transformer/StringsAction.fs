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
open System.Text
open System.Threading

/// The `strings` action.
type StringsAction() =
  let tryParseInt (value: string) =
    match Int32.TryParse value with
    | true, number ->
      Some number
    | _ ->
      None

  let parseInt (value: string) =
    Int32.Parse(value, NumberStyles.Integer, CultureInfo.InvariantCulture)

  let parseMinLength (args: string list) =
    match args with
    | [] ->
      4
    | [ minLength ] when tryParseInt minLength |> Option.isSome ->
      parseInt minLength
    | [ _ ] ->
      4
    | minLength :: _ ->
      parseInt minLength

  let parsePattern (args: string list) =
    match args with
    | [] ->
      None
    | [ pattern ] when tryParseInt pattern |> Option.isSome ->
      None
    | [ pattern ] ->
      Some pattern
    | _ :: pattern :: _ ->
      Some pattern

  let isPrintable byte =
    byte >= 0x20uy && byte <= 0x7euy

  let collectStrings
    minLength
    pattern
    source
    baseAddress
    (bytes: ReadOnlySpan<byte>) =
    let builder = StringBuilder()
    let strings = ResizeArray<StringMatch>()
    let flush startIndex =
      if builder.Length >= minLength then
        let text = builder.ToString()
        if pattern |> Option.forall (fun (pat: string) ->
          text.IndexOf(pat, StringComparison.OrdinalIgnoreCase) >= 0) then
          strings.Add
            { Source = source
              Address = baseAddress + uint64 startIndex
              Text = text }
        else
          ()
      else
        ()
      builder.Clear() |> ignore
    let mutable startIndex = 0
    for index = 0 to bytes.Length - 1 do
      if isPrintable bytes[index] then
        if builder.Length = 0 then startIndex <- index else ()
        builder.Append(char bytes[index]) |> ignore
      else
        flush startIndex
    flush startIndex
    strings.ToArray() |> Array.map box

  let collectFromBinary minLength pattern binary =
    let hdl = Binary.Handle binary
    collectStrings
      minLength
      pattern
      binary
      hdl.File.BaseAddress
      hdl.File.RawBytes.Span

  let collectFromSlice minLength pattern slice =
    let slice: BinarySlice = slice
    collectStrings
      minLength
      pattern
      slice.Source
      slice.StartAddress
      (ReadOnlySpan slice.Bytes)

  let transform cancellationToken args collection =
    let cancellationToken: CancellationToken = cancellationToken
    let minLength = parseMinLength args
    let pattern = parsePattern args
    if minLength <= 0 then
      invalidArg (nameof args) "min must be positive."
    else
      { Values =
          collection.Values
          |> Array.collect (fun input ->
            cancellationToken.ThrowIfCancellationRequested()
            match input with
            | :? Binary as binary ->
              collectFromBinary minLength pattern binary
            | :? BinarySlice as slice ->
              collectFromSlice minLength pattern slice
            | _ ->
              invalidArg (nameof input) "Invalid input type.") }

  interface IAction with
    member _.ActionID with get() = "strings"
    member _.Signature with get() =
      "Binary | BinarySlice -> strings [min] [pattern] "
      + "-> StringMatch collection"
    member _.Description with get() =
      "Extract printable ASCII strings, optionally filtered by text."
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
