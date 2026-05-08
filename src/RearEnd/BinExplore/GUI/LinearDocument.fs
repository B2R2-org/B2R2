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

namespace B2R2.RearEnd.BinExplore.GUI

open B2R2

/// Represents the shared linear-view document data.
type LinearDocument =
  { LinearBaseAddress: Addr
    LinearTotalLength: int64
    LinearItems: ResizeArray<LinearItem> }

/// Describes the location of a linear-view item within the loaded binary.
/// Different item kinds can share this contract while keeping their payloads
/// separate.
and ILinearItemLocation =
  /// Runtime address where this item begins.
  abstract Address: Addr
  /// Zero-based file offset where this item begins.
  abstract Offset: int
  /// Length of the represented binary region in bytes.
  abstract ItemLength: int

/// Represents the concrete location of a linear-view item. This is the default
/// implementation used by the initial byte-only linear view.
and LinearItemLocation =
  { Address: Addr
    Offset: int
    ItemLength: int }
  interface ILinearItemLocation with
    member this.Address = this.Address
    member this.Offset = this.Offset
    member this.ItemLength = this.ItemLength

/// Represents a renderable item in the linear view.
and LinearItem =
  /// Represents a single raw byte that has not yet been lifted to a richer
  /// semantic form.
  | RawByte of ILinearItemLocation * byte
  /// Represents a synthetic listing row marking the start of a section.
  | SectionHeader of ILinearItemLocation * string

[<RequireQualifiedAccess>]
module LinearDocument =
  let private tryGetSectionLocation baseAddress (section: SectionItem) =
    match section.Content with
    | ELF sh ->
      Some { Address = section.Address
             Offset = int sh.SecOffset
             ItemLength = int sh.SecSize }
    | Empty when section.Address >= baseAddress ->
      Some { Address = section.Address
             Offset = int (section.Address - baseAddress)
             ItemLength = 0 }
    | _ ->
      None

  let private buildSectionHeaders baseAddress sections =
    sections
    |> Seq.choose (fun section ->
      tryGetSectionLocation baseAddress section
      |> Option.map (fun loc ->
        let iloc: ILinearItemLocation = loc :> ILinearItemLocation
        loc.Offset, SectionHeader(iloc, section.Name)))
    |> Seq.groupBy fst
    |> Seq.map (fun (offset, items) ->
      offset, items |> Seq.map snd |> Seq.toList)
    |> dict

  let private buildItems baseAddress (bytes: byte[]) sections =
    let headers = buildSectionHeaders baseAddress sections
    let items = ResizeArray<LinearItem>(bytes.Length + headers.Count)
    for i = 0 to bytes.Length - 1 do
      match headers.TryGetValue i with
      | true, sectionHeaders ->
        for header in sectionHeaders do items.Add header
      | _ ->
        ()
      let location: ILinearItemLocation =
        { Address = baseAddress + uint64 i
          Offset = i
          ItemLength = 1 }
      items.Add(RawByte(location, bytes[i]))
    items

  let ofBytes baseAddress (bytes: byte[]) sections =
    { LinearBaseAddress = baseAddress
      LinearTotalLength = bytes.LongLength
      LinearItems = buildItems baseAddress bytes sections }

  let tryGetItem doc index =
    if index < 0 || index >= doc.LinearItems.Count then
      None
    else
      Some doc.LinearItems[index]

  let itemOffset doc index =
    match tryGetItem doc index with
    | Some(RawByte(loc, _))
    | Some(SectionHeader(loc, _)) ->
      Some loc.Offset
    | None ->
      None

[<RequireQualifiedAccess>]
module LinearItem =
  let rawByte address offset byteValue =
    let location: ILinearItemLocation =
      { Address = address
        Offset = offset
        ItemLength = 1 }
    RawByte(location, byteValue)

  let sectionHeader address offset length name =
    let location: ILinearItemLocation =
      { Address = address
        Offset = offset
        ItemLength = length }
    SectionHeader(location, name)

  let location = function
    | RawByte(loc, _) -> loc
    | SectionHeader(loc, _) -> loc
