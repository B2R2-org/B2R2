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

/// Provides convenience operations over optional capabilities of IBinFile.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.BinFileOps

open B2R2

/// <summary>
/// Slices the given binary file into a span of bytes of the specified length
/// starting from the specified file offset. Raises <see
/// cref='T:B2R2.FrontEnd.BinFile.InvalidAddrReadException'/> when the requested
/// region falls outside the file content.
/// </summary>
[<CompiledName "SliceByOffset">]
let sliceByOffset (file: IBinFile) offset len =
  let bytes = file.RawBytes
  if offset >= 0 && len >= 0 && offset <= bytes.Length - len then ()
  else raise InvalidAddrReadException
  bytes.Span.Slice(offset, len)

/// Tries to find the symbolic name associated with the given address.
[<CompiledName "TryFindName">]
let tryFindName (file: IBinFile) addr =
  match file.NameResolver with
  | Some names -> names.TryFindName addr
  | None -> Error ErrorCase.SymbolNotFound

/// Returns a pointer to the text section of the given binary file.
[<CompiledName "GetTextSectionPointer">]
let getTextSectionPointer (file: IBinFile) =
  match file.Structure with
  | Some org -> org.GetTextSectionPointer()
  | None -> BinFilePointer.Null

/// Returns the default code pointer for disassembling the given binary file.
[<CompiledName "GetDefaultCodePointer">]
let getDefaultCodePointer (file: IBinFile) =
  match file.Structure with
  | Some org -> org.GetTextSectionPointer()
  | None ->
    match file.EntryPoint with
    | Some entry -> file.GetBoundedPointer entry
    | None -> BinFilePointer.Null

/// Returns a pointer to the section with the given name.
[<CompiledName "GetSectionPointer">]
let getSectionPointer (file: IBinFile) name =
  match file.Structure with
  | Some org -> org.GetSectionPointer name
  | None -> BinFilePointer.Null

/// Tries to find the section name containing the given address.
[<CompiledName "TryFindSectionNameByAddr">]
let tryFindSectionNameByAddr (file: IBinFile) addr =
  match file.Structure with
  | Some org -> org.TryFindSectionNameByAddr addr
  | None -> Error ErrorCase.ItemNotFound

/// Tries to find the section name containing the given file offset.
[<CompiledName "TryFindSectionNameByOffset">]
let tryFindSectionNameByOffset (file: IBinFile) offset =
  match file.Structure with
  | Some org -> org.TryFindSectionNameByOffset offset
  | None -> Error ErrorCase.ItemNotFound

/// Returns known function entry addresses from the given binary file.
[<CompiledName "GetFunctionAddresses">]
let getFunctionAddresses (file: IBinFile) =
  match file.Structure with
  | Some org -> org.GetFunctionAddresses()
  | None -> [||]

/// Checks if the given address has relocation information.
[<CompiledName "HasRelocationInfo">]
let hasRelocationInfo (file: IBinFile) addr =
  match file.Relocations with
  | Some relocs -> relocs.HasRelocationInfo addr
  | None -> false

/// Tries to find the relocated target address of the given address.
[<CompiledName "GetRelocatedAddr">]
let getRelocatedAddr (file: IBinFile) relocAddr =
  match file.Relocations with
  | Some relocs -> relocs.GetRelocatedAddr relocAddr
  | None -> Error ErrorCase.ItemNotFound

/// Returns all linkage table entries from the given binary file.
[<CompiledName "GetLinkageTableEntries">]
let getLinkageTableEntries (file: IBinFile) =
  match file.Linkage with
  | Some linkage -> linkage.GetLinkageTableEntries()
  | None -> [||]

/// Checks if the given address falls within the linkage table.
[<CompiledName "IsInLinkageTable">]
let isInLinkageTable (file: IBinFile) addr =
  match file.Linkage with
  | Some linkage -> linkage.IsInLinkageTable addr
  | None -> false

/// Returns all VM-mapped regions of the given binary file.
[<CompiledName "GetVMMappedRegions">]
let getVMMappedRegions (file: IBinFile) =
  match file.MemoryLayout with
  | Some layout -> layout.GetVMMappedRegions()
  | None -> [||]

/// Returns the VM-mapped regions that carry the given permission.
[<CompiledName "GetVMMappedRegionsByPermission">]
let getVMMappedRegionsByPermission (file: IBinFile) perm =
  match file.MemoryLayout with
  | Some layout -> layout.GetVMMappedRegions perm
  | None -> [||]
