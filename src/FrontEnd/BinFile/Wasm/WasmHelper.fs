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

module internal B2R2.FrontEnd.BinFile.Wasm.Helper

open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile

let fileTypeOf wm =
  match wm.StartSection with
  | Some _ -> FileType.ExecutableFile
  | None -> FileType.LibFile

let entryPointOf wm =
  match wm.StartSection with
  | Some ss ->
    match ss.Contents with
    | Some fi ->
      let ii =
        wm.IndexMap
        |> Array.find (fun ii ->
          ii.Kind = IndexKind.Function
          && ii.Index = fi)
      Some (uint64 ii.ElemOffset)
    | None -> None
  | None -> None

let importDescToSymKind desc =
  match desc with
  | ImpFunc _ -> SymExternFunctionType
  | ImpTable _
  | ImpMem _
  | ImpGlobal _ -> SymObjectType

let importEntryToSymbol (importEntry: Import) =
  { Address = uint64 importEntry.Offset
    Name = importEntry.Name
    Kind = importDescToSymKind importEntry.Desc
    Visibility = SymbolVisibility.DynamicSymbol
    LibraryName = importEntry.ModuleName
    ARMLinkerSymbol = ARMLinkerSymbol.None }

let exportDescToSymKind desc =
  match desc with
  | ExpFunc _ -> SymFunctionType
  | ExpTable _
  | ExpMem _
  | ExpGlobal _ -> SymObjectType

let exportEntryToSymbol (exportEntry: Export) =
  { Address = uint64 exportEntry.Offset
    Name = exportEntry.Name
    Kind = exportDescToSymKind exportEntry.Desc
    Visibility = SymbolVisibility.DynamicSymbol
    LibraryName = ""
    ARMLinkerSymbol = ARMLinkerSymbol.None }

let getDynamicSymbols wm excludeImported =
  let excludeImported = defaultArg excludeImported false
  let imports =
    if not excludeImported then
      match wm.ImportSection with
      | Some is ->
        match is.Contents with
        | Some iv -> iv.Elements |> Array.map importEntryToSymbol
        | None -> [||]
      | None -> [||]
    else [||]
  let exports =
    match wm.ExportSection with
    | Some es ->
      match es.Contents with
      | Some ev -> ev.Elements |> Array.map exportEntryToSymbol
      | None -> [||]
    | None -> [||]
  Array.append imports exports

let getSymbols wm =
  getDynamicSymbols wm None

let sectionIdToKind id =
  match id with
  | SectionId.Table
  | SectionId.Memory
  | SectionId.Global -> SectionKind.InitializedDataSection
  | SectionId.Code -> SectionKind.CodeSection
  | _ -> SectionKind.ExtraSection

let secSummaryToGenericSection (secSumm: SectionSummary) =
  { Address = uint64 secSumm.Offset
    FileOffset = uint32 secSumm.Offset
    Kind = sectionIdToKind secSumm.Id
    Size = secSumm.HeaderSize + secSumm.ContentsSize
    Name = secSumm.Name }

let getSections wm =
  wm.SectionsInfo.SecArray
  |> Array.map secSummaryToGenericSection

let getSectionsByAddr wm addr =
  match NoOverlapIntervalMap.tryFindByAddr addr wm.SectionsInfo.SecByAddr with
  | Some s -> [| secSummaryToGenericSection s |]
  | None -> [||]

let getSectionsByName wm name =
  match Map.tryFind name wm.SectionsInfo.SecByName with
  | Some s -> [| secSummaryToGenericSection s |]
  | None -> [||]

let importToLinkageTableEntry (entry: Import) =
  { FuncName = entry.Name
    LibraryName = entry.ModuleName
    TrampolineAddress = 0UL
    TableAddress = uint64 entry.Offset }

let getImports wm =
  match wm.ImportSection with
  | Some sec ->
    match sec.Contents with
    | Some conts ->
      conts.Elements
      |> Array.filter (fun ie ->
          match ie.Desc with
          | ImpFunc _ -> true
          | _ -> false)
      |> Array.map importToLinkageTableEntry
    | None -> [||]
  | None -> [||]

let tryFindFunSymName wm addr =
  let sym =
    getSymbols wm
    |> Seq.filter (fun s ->
      s.Address = addr
      && (s.Kind = SymExternFunctionType || s.Kind = SymFunctionType)
    )
    |> Seq.tryHead
  match sym with
  | Some s -> Ok s.Name
  | None -> Error ErrorCase.SymbolNotFound
