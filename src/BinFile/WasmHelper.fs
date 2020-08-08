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

module internal B2R2.BinFile.Wasm.Helper

open B2R2
open B2R2.BinFile

let defaultISA =
  //FIXME
  { Arch = Architecture.UnknownISA
    Endian = Endian.Little;
    WordSize = WordSize.Bit32 }

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

let textStartAddrOf wm =
  match wm.CodeSection with
  | Some cs ->
    uint64 cs.Offset
  | None -> 0UL//8UL//FAKE

let importDescToSymKind desc =
  match desc with
  | ImpFunc _ -> SymbolKind.ExternFunctionType
  | ImpTable _
  | ImpMem _
  | ImpGlobal _ -> SymbolKind.ObjectType

let importEntryToSymbol (importEntry: Import) =
  {
    Address = uint64 importEntry.Offset
    Name = importEntry.Name
    Kind = importDescToSymKind importEntry.Desc
    Target = TargetKind.DynamicSymbol
    LibraryName = importEntry.ModuleName
  }

let exportDescToSymKind desc =
  match desc with
  | ExpFunc _ -> SymbolKind.FunctionType
  | ExpTable _
  | ExpMem _
  | ExpGlobal _ -> SymbolKind.ObjectType

let exportEntryToSymbol (exportEntry: Export) =
  {
    Address = uint64 exportEntry.Offset
    Name = exportEntry.Name
    Kind = exportDescToSymKind exportEntry.Desc
    Target = TargetKind.DynamicSymbol
    LibraryName = ""
  }

let getDynamicSymbols wm excludeImported =
  let excludeImported = defaultArg excludeImported false
  let imports =
    if not excludeImported then
      match wm.ImportSection with
      | Some is ->
        match is.Contents with
        | Some iv ->
          iv.Elements
          |> Array.map (fun ie -> importEntryToSymbol ie)
        | None -> [||]
      | None -> [||]
    else [||]
  let exports =
    match wm.ExportSection with
    | Some es ->
      match es.Contents with
      | Some ev ->
        ev.Elements
        |> Array.map (fun ee -> exportEntryToSymbol ee)
      | None -> [||]
    | None -> [||]
  Seq.append imports exports

let getSymbols wm =
  getDynamicSymbols wm None

let sectionIdToKind id =
  match id with
  | SectionId.Table
  | SectionId.Memory
  | SectionId.Global -> SectionKind.WritableSection
  | SectionId.Element
  | SectionId.Code -> SectionKind.ExecutableSection
  | _ -> SectionKind.ExtraSection

let secSummaryToGenericSection (secSumm: SectionSummary) =
  {
    Address = uint64 secSumm.Offset
    Kind = sectionIdToKind secSumm.Id
    Size = uint64 (secSumm.HeaderSize + secSumm.ContentsSize)
    Name = secSumm.Name
  }

let getSections wm =
  wm.SectionsInfo.SecArray
  |> Array.map secSummaryToGenericSection
  |> Array.toSeq

let getSectionsByAddr wm addr =
  match ARMap.tryFindByAddr addr wm.SectionsInfo.SecByAddr with
  | Some s -> secSummaryToGenericSection s |> Seq.singleton
  | None -> Seq.empty

let getSectionsByName wm name =
  match Map.tryFind name wm.SectionsInfo.SecByName with
  | Some s -> secSummaryToGenericSection s |> Seq.singleton
  | None -> Seq.empty

let importToLinkageTableEntry (entry: Import) =
  {
    FuncName = entry.Name
    LibraryName = entry.ModuleName
    TrampolineAddress = 0UL
    TableAddress = uint64 entry.Offset
  }

let getImports wm =
  match wm.ImportSection with
  | Some sec ->
    match sec.Contents with
    | Some conts ->
      conts.Elements
      |> Array.filter
        (fun ie ->
          match ie.Desc with
          | ImpFunc _ -> true
          | _ -> false
        )
      |> Array.map (fun ie -> importToLinkageTableEntry ie)
      |> Seq.ofArray
    | None -> Seq.empty
  | None -> Seq.empty

let tryFindFunSymName wm addr (name: byref<string>) =
  let sym =
    getSymbols wm
    |> Seq.filter (fun s ->
      s.Address = addr &&
      (s.Kind = SymbolKind.ExternFunctionType ||
        s.Kind = SymbolKind.FunctionType)
      )
    |> Seq.tryHead
  match sym with
  | Some s -> name <- s.Name; true
  | None -> false

let getNotInFileIntervals (range: AddrRange) (len: int64) =
  let maxAddr = uint64 len
  if range.Max <= 0UL then Seq.singleton range
  elif range.Max <= maxAddr && range.Min < 0UL
  then Seq.singleton (AddrRange (range.Min, 0UL))
  elif range.Max > maxAddr && range.Min < 0UL then
    [ AddrRange (range.Min, 0UL);
      AddrRange (maxAddr, range.Max) ]
    |> List.toSeq
  elif range.Max > maxAddr && range.Min <= maxAddr
  then Seq.singleton (AddrRange (maxAddr, range.Max))
  elif range.Max > maxAddr && range.Min > maxAddr
  then Seq.singleton range
  else Seq.empty