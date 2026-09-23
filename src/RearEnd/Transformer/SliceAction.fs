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
open System.Threading
open B2R2
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile

/// The `slice` action.
type SliceAction() =
  let formatRange startAddress endAddress =
    $"0x{startAddress:x}-0x{endAddress:x} (end exclusive)"

  let sectionRange (section: BinSection) =
    section.Address, section.Address + section.FileSize

  let rawRange (hdl: BinHandle) =
    let startAddress = hdl.File.BaseAddress
    startAddress, startAddress + uint64 hdl.File.Length

  let fileBackedSections (hdl: BinHandle) =
    BinFileOps.getSections hdl.File
    |> ImmutableArray.filter (fun section -> section.FileSize > 0UL)

  let describeSections sections =
    if Array.isEmpty sections then
      "No file-backed sections are available."
    else
      sections
      |> Array.map (fun section ->
        let startAddress, endAddress = sectionRange section
        $"{section.Name} {formatRange startAddress endAddress}")
      |> String.concat "; "

  let rangeInsideSection startAddress endAddress section =
    let sectionStart, sectionEnd = sectionRange section
    startAddress >= sectionStart && endAddress <= sectionEnd

  let rangeInsideRaw hdl startAddress endAddress =
    let rawStart, rawEnd = rawRange hdl
    startAddress >= rawStart && endAddress <= rawEnd

  let rangeInsideSlice (slice: BinarySlice) startAddress endAddress =
    startAddress >= slice.StartAddress && endAddress <= slice.EndAddress

  let makeSlice bin startAddress endAddress label =
    let size = endAddress - startAddress
    if size > uint64 Int32.MaxValue then
      invalidArg (nameof bin) "The slice is too large."
    else
      { Source = bin
        StartAddress = startAddress
        EndAddress = endAddress
        Label = label }

  let parseUInt64 (value: string) =
    let style, value =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        NumberStyles.HexNumber, value[2..]
      else
        NumberStyles.Integer, value
    UInt64.Parse(value, style, CultureInfo.InvariantCulture)

  let sliceByAddrRange bin startAddress endAddress =
    let hdl = Binary.Handle bin
    if startAddress >= endAddress then
      invalidArg (nameof bin) "Invalid address range."
    elif hdl.File.Format = FileFormat.RawBinary then
      if rangeInsideRaw hdl startAddress endAddress then
        makeSlice bin startAddress endAddress None
      else
        let range = formatRange startAddress endAddress
        let rawStart, rawEnd = rawRange hdl
        let rawRange = formatRange rawStart rawEnd
        invalidArg (nameof hdl)
          $"Slice range {range} is outside raw binary range: {rawRange}"
    else
      let sections = fileBackedSections hdl
      let containsRange = rangeInsideSection startAddress endAddress
      match sections |> Array.tryFind containsRange with
      | Some _ ->
        makeSlice bin startAddress endAddress None
      | None ->
        let range = formatRange startAddress endAddress
        let sections = describeSections sections
        invalidArg (nameof hdl)
          $"Slice range {range} is outside file-backed sections: {sections}"

  let sliceByAddrRangeInSlice slice startAddress endAddress =
    let slice: BinarySlice = slice
    if startAddress >= endAddress then
      invalidArg (nameof slice) "Invalid address range."
    elif rangeInsideSlice slice startAddress endAddress then
      makeSlice slice.Source startAddress endAddress slice.Label
    else
      let range = formatRange startAddress endAddress
      let sourceRange = formatRange slice.StartAddress slice.EndAddress
      invalidArg (nameof slice)
        $"Slice range {range} is outside source slice {sourceRange}"

  let sliceBySectionName bin secName =
    let hdl = Binary.Handle bin
    match BinFileOps.tryFindSectionByName hdl.File secName with
    | Ok section when section.FileSize > uint64 Int32.MaxValue ->
      invalidArg (nameof secName) "The section is too large to slice."
    | Ok section when section.FileSize > 0UL ->
      makeSlice
        bin
        section.Address
        (section.Address + section.FileSize)
        (Some section.Name)
    | Ok _ ->
      invalidArg (nameof secName) "The section has no file-backed data."
    | Error _ ->
      invalidArg (nameof secName) $"Section not found: {secName}"

  let sliceBySectionNameInSlice slice secName =
    let slice: BinarySlice = slice
    let sliced = sliceBySectionName slice.Source secName
    if rangeInsideSlice slice sliced.StartAddress sliced.EndAddress then
      sliced
    else
      let sectionRange = formatRange sliced.StartAddress sliced.EndAddress
      let sourceRange = formatRange slice.StartAddress slice.EndAddress
      invalidArg (nameof secName)
        $"Section range {sectionRange} is outside source slice {sourceRange}"

  let parseTwoArgs (a1: string) (a2: string) =
    let a1 = parseUInt64 a1
    let endAddress =
      if a2.StartsWith '+' then
        a1 + parseUInt64 (a2[1..])
      else
        parseUInt64 a2
    a1, endAddress

  let sliceBin args bin =
    match args with
    | a1 :: a2 :: [] ->
      let a1, a2 = parseTwoArgs a1 a2
      sliceByAddrRange bin a1 a2 |> box
    | secName :: [] ->
      sliceBySectionName bin secName |> box
    | _ ->
      invalidArg (nameof args) "Invalid argument."

  let sliceSlice args (slice: BinarySlice) =
    match args with
    | a1 :: a2 :: [] ->
      let a1, a2 = parseTwoArgs a1 a2
      sliceByAddrRangeInSlice slice a1 a2 |> box
    | secName :: [] ->
      sliceBySectionNameInSlice slice secName |> box
    | _ ->
      invalidArg (nameof args) "Invalid argument."

  let slice cancellationToken args (input: obj) =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    match input with
    | :? Binary as bin ->
      sliceBin args bin
    | :? BinarySlice as slice ->
      sliceSlice args slice
    | _ ->
      invalidArg (nameof input) "Invalid input type."

  let transform cancellationToken args collection =
    { Values =
        collection.Values |> Array.map (slice cancellationToken args) }

  interface IAction with
    member _.ActionID with get() = "slice"
    member _.Signature with get() =
      "Binary | BinarySlice -> slice section=<section> | "
      + "start=<addr> end=<addr> | "
      + "start=<addr> offset=<size> -> BinarySlice"
    member _.Description with get() =
      """
    Take in a binary and return a source-aware slice over the requested address
    range or section. The slice keeps the original binary, so later actions can
    still map addresses back to the source file.

      - `section=<section>` returns the section with the given name.
      - `start=<addr> end=<addr>` returns the half-open range [start, end).
      - `start=<addr> offset=<n>` returns n bytes starting at start.
"""
    member _.Transform(args, collection) =
      transform CancellationToken.None args collection

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      transform cancellationToken args collection
