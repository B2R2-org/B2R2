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
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Transformer.Utils

/// The `grep` action.
type GrepAction() =
  let trySectionByOffset bin (offset: uint64) =
    let hdl = Binary.Handle bin
    if offset > uint64 UInt32.MaxValue then
      None
    else
      match BinFileOps.tryFindSectionByOffset hdl.File (uint32 offset) with
      | Ok section when Option.isSome section.Offset ->
        Some section
      | _ ->
        None

  let mappedAddress bin (offset: uint64) =
    match trySectionByOffset bin offset with
    | Some section ->
      section.Address + offset - Option.get section.Offset
    | None ->
      let hdl = Binary.Handle bin
      hdl.File.BaseAddress + offset

  let mappedEndAddress bin (offset: uint64) =
    if offset = 0UL then
      mappedAddress bin offset
    else
      mappedAddress bin (offset - 1UL) + 1UL

  let bytesPattern (bytes: BinaryBytes) =
    Convert.ToHexString bytes.Bytes

  let parseInt name (value: string) =
    let value = Convert.ToInt32 value
    if value < 0 then
      invalidArg name "Context size must be non-negative."
    else
      value

  let sameContext value =
    let context = parseInt "context" value
    context, context

  let asymmetricContext before after =
    parseInt "before" before, parseInt "after" after

  let patternAndContext = function
    | [ pattern ] ->
      pattern, 0, 0
    | [ pattern; context ] ->
      let before, after = sameContext context
      pattern, before, after
    | [ pattern; before; after ] ->
      let before, after = asymmetricContext before after
      pattern, before, after
    | _ ->
      invalidArg "args" "Invalid grep arguments."

  let tupleContext = function
    | [] ->
      0, 0
    | [ context ] ->
      sameContext context
    | [ before; after ] ->
      asymmetricContext before after
    | _ ->
      invalidArg "args" "Invalid grep arguments."

  let grepBytes
    cancellationToken
    source
    addressAt
    endAddressAt
    (pattern: string)
    bytesBefore
    bytesAfter
    (bs: ReadOnlySpan<byte>) =
    let cancellationToken: CancellationToken = cancellationToken
    let length = bs.Length
    let hs = Convert.ToHexString bs
    let regex = Regex(pattern, RegexOptions.IgnoreCase)
    regex.Matches hs
    |> Seq.choose (fun m ->
      cancellationToken.ThrowIfCancellationRequested()
      if m.Index % 2 = 0 && m.Length % 2 = 0 then
        Some(m.Index / 2, m.Length / 2)
      else
        None)
    |> Seq.map (fun (i, len) ->
      let soff = if (i - bytesBefore) < 0 then 0 else i - bytesBefore
      let eoff = i + len + bytesAfter
      let eoff = if eoff > length then length else eoff
      let matchAddress = addressAt i
      { Source = source
        StartAddress = addressAt soff
        EndAddress = endAddressAt eoff
        Label = Some $"grep match=0x{matchAddress:x}" })
    |> Seq.toArray

  let grepFromBinary cancellationToken pattern before after bin =
    let hdl = Binary.Handle bin
    let addressAt offset = mappedAddress bin (uint64 offset)
    let endAddressAt offset = mappedEndAddress bin (uint64 offset)
    grepBytes
      cancellationToken
      bin
      addressAt
      endAddressAt
      pattern
      before
      after
      hdl.File.RawBytes.Span

  let grepFromSlice cancellationToken pattern before after slice =
    let slice: BinarySlice = slice
    let addressAt offset = slice.StartAddress + uint64 offset
    grepBytes
      cancellationToken
      slice.Source
      addressAt
      addressAt
      pattern
      before
      after
      (ReadOnlySpan slice.Bytes)

  let grep cancellationToken pattern bytesBefore bytesAfter (input: obj) =
    match input with
    | :? Binary as bin ->
      grepFromBinary cancellationToken pattern bytesBefore bytesAfter bin
      |> Array.map box
    | :? BinarySlice as slice ->
      grepFromSlice cancellationToken pattern bytesBefore bytesAfter slice
      |> Array.map box
    | _ ->
      invalidArg (nameof input) "Invalid object is given."

  let grepTuple cancellationToken before after (left: obj, right: obj) =
    match left, right with
    | (:? Binary as bin), (:? BinaryBytes as bytes) ->
      grepFromBinary cancellationToken (bytesPattern bytes) before after bin
      |> Array.map box
    | (:? BinarySlice as slice), (:? BinaryBytes as bytes) ->
      grepFromSlice cancellationToken (bytesPattern bytes) before after slice
      |> Array.map box
    | _ ->
      invalidArg "input" "Invalid tuple is given."

  let transform cancellationToken args collection =
    let args: string list = args
    let collectTuple before after =
      match collection.Values with
      | [| left; right |] ->
        grepTuple cancellationToken before after (left, right)
      | _ ->
        invalidArg (nameof collection) "Two tuple values are required."
    let isTupleInput () =
      match collection.Values with
      | [| _; (:? BinaryBytes) |] ->
        true
      | _ ->
        false
    let collect pattern before after =
      collection.Values
      |> Array.collect (grep cancellationToken pattern before after)
    if isTupleInput () then
      let before, after = tupleContext args
      { Values = collectTuple before after }
    else
      let pattern, before, after = patternAndContext args
      { Values = collect pattern before after }

  interface IAction with
    member _.ActionID with get() = "grep"
    member _.Signature with get() =
      "Binary | BinarySlice -> grep pattern=<hex> [context=<n>] | "
      + "pattern=<hex> [before=<n>] [after=<n>] "
      + "-> BinarySlice collection | Binary * ByteArray -> "
      + "grep [context=<n>] | [before=<n>] [after=<n>] "
      + "-> BinarySlice collection"
    member _.Description with get() =
      """
    Take in an array as input and return one or more matched items from the
    array as in the `grep` command. The pattern represents a binary pattern
    using a regular expression with hex strings. For example, the pattern
    "3031.." will match a three-byte sequence {{ 0x30, 0x31, * }}, where * means
    any byte. Note that '.' means any 4-bit value in our regular expression.
    Similarly, the pattern "(30)+" means a sequence of 0x30s of any length,
    e.g., {{ 0x30, 0x30, 0x30, 0x30, 0x30 }} will match the pattern.

    context can be given to include the same number of bytes before and after
    each match. before and after can be given when asymmetric context is needed.
    These two forms are mutually exclusive. If the matched items are at the
    beginning or end of the array, the context will be truncated accordingly.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
