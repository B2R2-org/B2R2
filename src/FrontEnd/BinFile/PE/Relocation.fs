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

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile.PE.Helper

/// <summary>
/// Represents the relocations a PE file carries, indexed by what each one
/// patches so that a lookup answers without walking the whole of the table.
/// </summary>
type internal RelocationIndex =
  { /// Every relocation the file carries, in the order it keeps them.
    Relocations: FrontEnd.BinFile.BinRelocation[]
    /// The kind of base relocation at each address an image relocates, which
    /// is what reading the slot behind one takes. An object relocates by
    /// naming a symbol rather than by holding an address, so it has none.
    Kinds: Dictionary<Addr, BaseRelocType>
    /// Every address the file relocates, an object file's own included.
    Addresses: HashSet<Addr> }

let private isValidEntry entry =
  entry.Type <> BaseRelocType.IMAGE_REL_BASED_ABSOLUTE

let private getRelocAddr pe block entry =
  uint64 block.PageRVA + uint64 entry.Offset + pe.BaseAddr

let private toRelocation addr: FrontEnd.BinFile.BinRelocation =
  { Address = addr; SymbolName = None; Addend = None }

/// Reads the relocations an object keeps per section, which name a symbol
/// apiece and so have no kind to index them by.
let private buildForObject bytes pe =
  let coff = pe.Header.CoffHeader
  let names = Coff.getSymbolNames bytes pe.BinReader coff
  let secs = pe.SectionHeaders
  let relocs = Coff.getRelocations bytes pe.BinReader secs names pe.BaseAddr
  { Relocations = relocs
    Kinds = Dictionary()
    Addresses = HashSet(relocs |> Array.map _.Address) }

/// Reads the base relocations an image keeps in its .reloc blocks, which
/// hold an address apiece and so are read back by kind.
let private buildForImage pe =
  let kinds = Dictionary<Addr, BaseRelocType>()
  let relocs = ResizeArray()
  for block in pe.RelocBlocks do
    for entry in block.Entries do
      if isValidEntry entry then
        let addr = getRelocAddr pe block entry
        kinds[addr] <- entry.Type
        relocs.Add(toRelocation addr)
      else
        ()
  { Relocations = relocs.ToArray()
    Kinds = kinds
    Addresses = HashSet kinds.Keys }

/// Reads every relocation of the file and indexes it by what it patches.
let build bytes pe =
  if pe.Header.IsCoffOnly then buildForObject bytes pe else buildForImage pe

let private tryGetRawOffset pe relocAddr size =
  let rva = int (relocAddr - pe.BaseAddr)
  let idx = PEUtils.findMappedSectionIndex pe.SectionHeaders rva
  if idx < 0 then
    None
  else
    let sec = pe.SectionHeaders[idx]
    let offset = rva + sec.PointerToRawData - sec.VirtualAddress
    if offset + size <= sec.PointerToRawData + sec.SizeOfRawData then
      Some offset
    else
      None

let private readSlot (bytes: byte[]) pe relocAddr size =
  match tryGetRawOffset pe relocAddr size with
  | Some offset when size = 4 ->
    pe.BinReader.ReadUInt32(bytes, offset) |> uint64 |> Ok
  | Some offset ->
    pe.BinReader.ReadUInt64(bytes, offset) |> Ok
  | None ->
    Error ErrorCase.ItemNotFound

let tryGetRelocatedAddr bytes pe index relocAddr =
  match (index: RelocationIndex).Kinds.TryGetValue relocAddr with
  | true, BaseRelocType.IMAGE_REL_BASED_HIGHLOW ->
    readSlot bytes pe relocAddr 4
  | true, BaseRelocType.IMAGE_REL_BASED_DIR64 ->
    readSlot bytes pe relocAddr 8
  | _ ->
    Error ErrorCase.ItemNotFound
