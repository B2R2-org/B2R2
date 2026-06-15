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

module internal B2R2.FrontEnd.BinFile.PE.Relocation

open B2R2
open B2R2.FrontEnd.BinFile.PE.Helper

let private isValidEntry entry =
  entry.Type <> BaseRelocType.IMAGE_REL_BASED_ABSOLUTE

let private getRelocAddr pe block entry =
  uint64 block.PageRVA + uint64 entry.Offset + pe.BaseAddr

let private tryFindEntry pe relocAddr =
  pe.RelocBlocks
  |> List.tryPick (fun block ->
    block.Entries
    |> Array.tryFind (fun entry ->
      isValidEntry entry && getRelocAddr pe block entry = relocAddr)
    |> Option.map (fun entry -> block, entry))

let private tryGetRawOffset pe relocAddr size =
  let rva = int (relocAddr - pe.BaseAddr)
  let idx = PEUtils.findMappedSectionIndex pe.SectionHeaders rva
  if idx < 0 then None
  else
    let sec = pe.SectionHeaders[idx]
    let offset = rva + sec.PointerToRawData - sec.VirtualAddress
    if offset + size <= sec.PointerToRawData + sec.SizeOfRawData then
      Some offset
    else None

let contains pe addr =
  tryFindEntry pe addr |> Option.isSome

let tryGetRelocatedAddr (bytes: byte[]) pe relocAddr =
  match tryFindEntry pe relocAddr with
  | Some(_, entry) ->
    match entry.Type with
    | BaseRelocType.IMAGE_REL_BASED_HIGHLOW ->
      match tryGetRawOffset pe relocAddr 4 with
      | Some offset -> pe.BinReader.ReadUInt32(bytes, offset) |> uint64 |> Ok
      | None -> Error ErrorCase.ItemNotFound
    | BaseRelocType.IMAGE_REL_BASED_DIR64 ->
      match tryGetRawOffset pe relocAddr 8 with
      | Some offset -> pe.BinReader.ReadUInt64(bytes, offset) |> Ok
      | None -> Error ErrorCase.ItemNotFound
    | _ -> Error ErrorCase.ItemNotFound
  | None -> Error ErrorCase.ItemNotFound
