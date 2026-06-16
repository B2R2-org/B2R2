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

/// Tries to resolve the symbolic name associated with the given address.
[<CompiledName "TryResolveName">]
let tryResolveName (file: IBinFile) addr =
  match file.NameResolver with
  | Some resolver -> resolver.TryResolveName addr
  | None -> Error ErrorCase.SymbolNotFound

/// Checks whether the given binary lacks its non-essential symbol table.
[<CompiledName "IsStripped">]
let isStripped (file: IBinFile) =
  file.SymbolTable
  |> Option.map (fun symbolTable -> symbolTable.IsStripped)
  |> Option.defaultValue false

/// Returns all symbols in the given binary file.
[<CompiledName "GetSymbols">]
let getSymbols (file: IBinFile) =
  match file.SymbolTable with
  | Some symbolTable -> symbolTable.Symbols
  | None -> [||]

/// Tries to find the symbol located at the given address.
[<CompiledName "TryFindSymbolByAddr">]
let tryFindSymbolByAddr (file: IBinFile) addr =
  match file.SymbolTable with
  | Some symbolTable -> symbolTable.TryFindSymbolByAddr addr
  | None -> Error ErrorCase.ItemNotFound

/// Returns the instruction-set mode markers of the given binary file.
[<CompiledName "GetCodeModeMarkers">]
let getCodeModeMarkers (file: IBinFile) =
  match file.SymbolTable with
  | Some symbolTable -> symbolTable.CodeModeMarkers
  | None -> [||]

/// Returns a pointer to the code section of the given binary file.
[<CompiledName "GetCodeSectionPointer">]
let getCodeSectionPointer (file: IBinFile) =
  match file.Structure with
  | Some structure -> structure.GetCodeSectionPointer()
  | None -> BinFilePointer.Null

/// Returns the default code pointer for disassembling the given binary file.
[<CompiledName "GetDefaultCodePointer">]
let getDefaultCodePointer (file: IBinFile) =
  match file.Structure with
  | Some structure -> structure.GetCodeSectionPointer()
  | None ->
    match file.EntryPoint with
    | Some entry -> file.GetBoundedPointer entry
    | None -> BinFilePointer.Null

/// Returns a pointer to the section with the given name.
[<CompiledName "GetSectionPointer">]
let getSectionPointer (file: IBinFile) name =
  match file.Structure with
  | Some structure -> structure.GetSectionPointer name
  | None -> BinFilePointer.Null

/// Returns all binary sections in the given binary file.
[<CompiledName "GetSections">]
let getSections (file: IBinFile) =
  match file.Structure with
  | Some structure -> structure.Sections
  | None -> [||]

/// Tries to find the section whose name matches the given name.
[<CompiledName "TryFindSectionByName">]
let tryFindSectionByName (file: IBinFile) name =
  match file.Structure with
  | Some structure -> structure.TryFindSectionByName name
  | None -> Error ErrorCase.ItemNotFound

/// Tries to find the section containing the given address.
[<CompiledName "TryFindSectionByAddr">]
let tryFindSectionByAddr (file: IBinFile) addr =
  match file.Structure with
  | Some structure -> structure.TryFindSectionByAddr addr
  | None -> Error ErrorCase.ItemNotFound

/// Tries to find the section containing the given file offset.
[<CompiledName "TryFindSectionByOffset">]
let tryFindSectionByOffset (file: IBinFile) offset =
  match file.Structure with
  | Some structure -> structure.TryFindSectionByOffset offset
  | None -> Error ErrorCase.ItemNotFound

/// Tries to find the section name containing the given address.
[<CompiledName "TryFindSectionNameByAddr">]
let tryFindSectionNameByAddr (file: IBinFile) addr =
  match file.Structure with
  | Some structure -> structure.TryFindSectionNameByAddr addr
  | None -> Error ErrorCase.ItemNotFound

/// Tries to find the section name containing the given file offset.
[<CompiledName "TryFindSectionNameByOffset">]
let tryFindSectionNameByOffset (file: IBinFile) offset =
  match file.Structure with
  | Some structure -> structure.TryFindSectionNameByOffset offset
  | None -> Error ErrorCase.ItemNotFound

/// Returns known function entry addresses from the given binary file.
[<CompiledName "GetFunctionAddresses">]
let getFunctionAddresses (file: IBinFile) =
  match file.Structure with
  | Some structure -> structure.GetFunctionAddresses()
  | None -> [||]

/// Returns all relocations in the given binary file.
[<CompiledName "GetRelocations">]
let getRelocations (file: IBinFile) =
  match file.Relocations with
  | Some relocs -> relocs.GetRelocations()
  | None -> [||]

/// Checks if the given address has relocation information.
[<CompiledName "ContainsRelocation">]
let containsRelocation (file: IBinFile) addr =
  match file.Relocations with
  | Some relocs -> relocs.ContainsRelocation addr
  | None -> false

/// Tries to find the relocated target address of the given address.
[<CompiledName "TryGetRelocatedAddr">]
let tryGetRelocatedAddr (file: IBinFile) relocAddr =
  match file.Relocations with
  | Some relocs -> relocs.TryGetRelocatedAddr relocAddr
  | None -> Error ErrorCase.ItemNotFound

/// Tries to resolve the relocation at the given address to an internal
/// function defined within the given binary file itself.
[<CompiledName "TryGetInternalFunctionAddr">]
let tryGetInternalFunctionAddr (file: IBinFile) relocAddr =
  match file.Relocations with
  | Some relocs -> relocs.TryGetInternalFunctionAddr relocAddr
  | None -> Error ErrorCase.ItemNotFound

/// Returns all per-function exception frames of the given binary file.
[<CompiledName "GetExceptionFrames">]
let getExceptionFrames (file: IBinFile) =
  match file.ExceptionTable with
  | Some exnTable -> exnTable.Frames
  | None -> [||]

/// Returns all imported symbols from the given binary file.
[<CompiledName "GetImports">]
let getImports (file: IBinFile) =
  match file.ImportTable with
  | Some importTable -> importTable.GetImports()
  | None -> [||]

/// Checks if the given address falls within the import table.
[<CompiledName "IsInImportTable">]
let isInImportTable (file: IBinFile) addr =
  match file.ImportTable with
  | Some importTable -> importTable.IsInImportTable addr
  | None -> false

/// Returns all memory-mapped segments of the given binary file.
[<CompiledName "GetSegments">]
let getSegments (file: IBinFile) =
  match file.MemoryLayout with
  | Some layout -> layout.GetSegments()
  | None -> [||]

/// Returns all memory-mapped regions of the given binary file.
[<CompiledName "GetMemoryMappedRegions">]
let getMemoryMappedRegions (file: IBinFile) =
  getSegments file
  |> Array.map (fun seg ->
    AddrRange.create seg.Address (seg.Address + seg.Size - 1UL))

/// Returns the memory-mapped regions that carry the given permission.
[<CompiledName "GetMemoryMappedRegionsByPermission">]
let getMemoryMappedRegionsByPermission (file: IBinFile) perm =
  getSegments file
  |> Array.choose (fun seg ->
    if seg.Permission.HasFlag perm then
      AddrRange.create seg.Address (seg.Address + seg.Size - 1UL) |> Some
    else None)
