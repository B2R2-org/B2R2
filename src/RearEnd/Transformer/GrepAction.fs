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
open System.Threading
open System.Text.RegularExpressions
open B2R2
open B2R2.RearEnd.Transformer.Utils

/// The `grep` action.
type GrepAction() =
  let grepBytes cancellationToken source baseAddress (pattern: string)
                bytesBefore bytesAfter (bs: byte[]) =
    let cancellationToken: CancellationToken = cancellationToken
    let hs = byteArrayToHexStringArray bs |> String.concat ""
    let regex = Regex(pattern.ToLowerInvariant())
    regex.Matches hs
    |> Seq.choose (fun m ->
      cancellationToken.ThrowIfCancellationRequested()
      if m.Index % 2 = 0 && m.Length % 2 = 0 then
        Some(m.Index / 2, m.Length / 2)
      else None)
    |> Seq.toArray
    |> Array.map (fun (i, len) ->
      let soff = if (i - bytesBefore) < 0 then 0 else i - bytesBefore
      let eoff = i + len + bytesAfter
      let eoff = if eoff > bs.Length then bs.Length else eoff
      { Source = source
        StartAddress = baseAddress + uint64 soff
        EndAddress = baseAddress + uint64 eoff
        Label = Some "grep" })

  let grepFromBinary cancellationToken pattern before after bin =
    let hdl = Binary.Handle bin
    let bs = hdl.File.RawBytes.ToArray()
    grepBytes cancellationToken bin hdl.File.BaseAddress pattern before after bs

  let grepFromSlice cancellationToken pattern before after slice =
    let slice: BinarySlice = slice
    grepBytes cancellationToken slice.Source slice.StartAddress pattern before
      after slice.Bytes

  let grep cancellationToken pattern bytesBefore bytesAfter (input: obj) =
    match input with
    | :? Binary as bin ->
      grepFromBinary cancellationToken pattern bytesBefore bytesAfter bin
      |> Array.map box
    | :? BinarySlice as slice ->
      grepFromSlice cancellationToken pattern bytesBefore bytesAfter slice
      |> Array.map box
    | _ -> invalidArg (nameof input) "Invalid object is given."

  let transform cancellationToken args collection =
    let args: string list = args
    let collect pattern before after =
      collection.Values
      |> Array.collect (grep cancellationToken pattern before after)
    match args with
    | pattern :: bytesBefore :: bytesAfter :: [] ->
      let bytesBefore = Convert.ToInt32 bytesBefore
      let bytesAfter = Convert.ToInt32 bytesAfter
      { Values = collect pattern bytesBefore bytesAfter }
    | pattern :: bytesBefore :: [] ->
      let bytesBefore = Convert.ToInt32 bytesBefore
      { Values = collect pattern bytesBefore 0 }
    | [ pattern ] ->
      { Values = collect pattern 0 0 }
    | _ -> invalidArg (nameof args) "Single pattern should be given."

  interface IAction with
    member _.ActionID with get() = "grep"
    member _.Signature with get() =
      "Binary | BinarySlice -> grep pattern=<hex> [bytes-before=<n>] "
      + "[bytes-after=<n>] -> BinarySlice collection"
    member _.Description with get() =
      """
    Take in an array as input and return one or more matched items from the
    array as in the `grep` command. The pattern represents a binary pattern
    using a regular expression with hex strings. For example, the pattern
    "3031.." will match a three-byte sequence {{ 0x30, 0x31, * }}, where * means
    any byte. Note that '.' means any 4-bit value in our regular expression.
    Similarly, the pattern "(30)+" means a sequence of 0x30s of any length,
    e.g., {{ 0x30, 0x30, 0x30, 0x30, 0x30 }} will match the pattern.

    bytes-before and bytes-after can be given to include context around each
    match. If the matched items are at the beginning or end of the array, the
    context will be truncated accordingly.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
