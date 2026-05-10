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
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd

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
  | SectionHeader of ILinearItemLocation * string * isNoBit: bool
  /// Represents a disassembled instruction.
  | Disassembly of ILinearItemLocation * disasm: string

[<RequireQualifiedAccess>]
module LinearDocument =
  open System.Collections.Generic

  let private buildInstructionInfo (brew: BinaryBrew<_, _>) =
    let disasms = Dictionary<Addr, string * uint32>()
    let lifter = brew.BinHandle.NewLiftingUnit()
    lifter.ConfigureDisassembly(showAddr = false)
    for fn in brew.Functions.Sequence do
      for v in fn.CFG.Vertices do
        for ins in v.VData.Internals.Instructions do
          disasms[ins.Address] <- lifter.DisasmInstruction ins, ins.Length
    disasms

  let private tryGetSectionLocAndNoBitInfo (section: SectionItem) =
    match section.Content with
    | ELF sh ->
      Some(
        { Address = section.Address
          Offset = int sh.SecOffset
          ItemLength = int sh.SecSize },
        sh.SecType = ELF.SectionType.SHT_NOBITS
      )
    | _ ->
      None

  let private buildSectionHeadersByOffset sections =
    sections
    |> List.choose (fun section ->
      tryGetSectionLocAndNoBitInfo section
      |> Option.map (fun (loc, isNoBit) ->
        let iloc = loc :> ILinearItemLocation
        loc.Offset, SectionHeader(iloc, section.Name, isNoBit)))
    |> List.groupBy fst
    |> List.map (fun (offset, items) -> offset, items |> List.map snd)
    |> dict

  let private buildItems brew (bytes: byte[]) sections =
    let disasms = buildInstructionInfo brew
    let secHeaders = buildSectionHeadersByOffset sections
    let items = ResizeArray<LinearItem>(bytes.Length + secHeaders.Count)
    let mutable baseAddress = 0UL
    let mutable baseOffset = 0
    let mutable nextInsAddr = 0UL
    for i = 0 to bytes.Length - 1 do
      match secHeaders.TryGetValue i with
      | true, sectionHeaders ->
        for header in sectionHeaders do
          items.Add header
          match header with
          | SectionHeader(loc, _, false) ->
            baseAddress <- loc.Address
            baseOffset <- loc.Offset
            nextInsAddr <- 0UL
          | _ ->
            ()
      | _ ->
        ()
      let addr = baseAddress + uint64 (i - baseOffset)
      match disasms.TryGetValue addr with
      | true, (disasm, insLen) ->
        let location =
          { Address = addr
            Offset = i
            ItemLength = int insLen }
        items.Add(Disassembly(location, disasm))
        nextInsAddr <- addr + uint64 insLen
      | false, _ ->
        if addr >= nextInsAddr then
          let location = { Address = addr; Offset = i; ItemLength = 1 }
          items.Add(RawByte(location, bytes[i]))
        else ()
    items

  let load (brew: BinaryBrew<_, _>) sections =
    let hdl = brew.BinHandle
    let bytes = hdl.File.RawBytes
    { LinearBaseAddress = hdl.File.BaseAddress
      LinearTotalLength = bytes.LongLength
      LinearItems = buildItems brew bytes sections }

  let tryGetItem doc index =
    if index < 0 || index >= doc.LinearItems.Count then
      None
    else
      Some doc.LinearItems[index]

  let itemOffset doc index =
    match tryGetItem doc index with
    | Some(RawByte(loc, _))
    | Some(SectionHeader(loc, _, _))
    | Some(Disassembly(loc, _)) ->
      Some loc.Offset
    | None ->
      None

[<RequireQualifiedAccess>]
module LinearItem =
  let location = function
    | RawByte(loc, _)
    | SectionHeader(loc, _, _)
    | Disassembly(loc, _) -> loc
