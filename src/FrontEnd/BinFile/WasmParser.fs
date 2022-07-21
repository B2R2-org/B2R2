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

module internal B2R2.FrontEnd.BinFile.Wasm.Parser

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Wasm.Section
open System

let sectionIdToName (secId: SectionId) (off: int) =
  match secId with
  | SectionId.Custom -> String.Format ("custom_{0:x}", off)
  | SectionId.Type -> "type"
  | SectionId.Import -> "import"
  | SectionId.Function -> "function"
  | SectionId.Table -> "table"
  | SectionId.Memory -> "memory"
  | SectionId.Global -> "global"
  | SectionId.Export -> "export"
  | SectionId.Start -> "start"
  | SectionId.Element -> "element"
  | SectionId.Code -> "code"
  | SectionId.Data -> "data"
  | _ -> ""

let private summerizeSections (bs: byte[]) (reader: IBinReader) offset =
  let rec loop (acc: _ list) no =
    if bs.Length <= no then
      List.rev acc
    else
      let id, size, len = peekSectionHeader bs reader no
      let headerSize = len + 1
      let no' = no + headerSize + int size
      let summary = {
        Id = id
        Name = sectionIdToName id no
        Offset = no
        HeaderSize = uint32 headerSize
        ContentsSize = size
      }
      loop (summary :: acc) no'
  loop [] offset

let private idLtId id1 id2 =
  let id1' = LanguagePrimitives.EnumToValue id1
  let id2' = LanguagePrimitives.EnumToValue id2
  id1' < id2'

let private peekSecSummPair (secsSumm: SectionSummary list) =
  let sec1 = List.head secsSumm
  let secsSumm' = List.tail secsSumm
  let sec2 = List.tryHead secsSumm'
  sec1, sec2, secsSumm'

let validateSectionsOrder secsSummary =
  let rec validationLoop secsSumm isValid =
    if List.isEmpty secsSumm then isValid
    else
    let sec1, sec2, secsSumm' = peekSecSummPair secsSumm
    match sec2 with
    | Some sec ->
      let id1 = sec1.Id
      let id2 = sec.Id
      let isValid' =
        if id1 = SectionId.Custom || id2 = SectionId.Custom
        then true
        else idLtId id1 id2
      if not isValid' then isValid'
      else validationLoop secsSumm' isValid'
    | None -> isValid
  validationLoop secsSummary true

let updateSection bs reader wm id updateRec parseSec secsSumm =
  let secSumm =
    (secsSumm: SectionSummary list)
    |> List.filter (fun sm -> sm.Id = id)
    |> List.tryHead
  match secSumm with
  | Some sm ->
    let secsSummary' =
      secsSumm |> List.except [sm]
    let sec =
      parseSec bs reader sm.Offset
    (updateRec wm sec), secsSummary'
  | None -> wm, secsSumm

let updateCustomSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with CustomSections = wm.CustomSections @ [ sec ] }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Custom ur parseCustomSec

let updateTypeSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with TypeSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Type ur parseTypeSec

let updateImportSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with ImportSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Import ur parseImportSec

let updateFunctionSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with FunctionSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Function ur parseFunctionSec

let updateTableSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with TableSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Table ur parseTableSec

let updateMemorySection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with MemorySection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Memory ur parseMemorySec

let updateGlobalSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with GlobalSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Global ur parseGlobalSec

let updateExportSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with ExportSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Export ur parseExportSec

let updateStartSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with StartSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Start ur parseStartSec

let updateElementSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with ElementSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Element ur parseElementSec

let updateCodeSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with CodeSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Code ur parseCodeSec

let updateDataSection bs reader wasmModule secsSummary =
  let ur wm sec =
    { wm with DataSection = Some sec }
  secsSummary
  |> updateSection bs reader wasmModule SectionId.Data ur parseDataSec

let renameSecSumm (sm: SectionSummary) (secConts: CustomContents option) =
  let name =
    match secConts with
    | Some conts ->
      conts.Name
    | None -> sm.Name
  { sm with Name = name }

let addSecSummToAddrMap (secSumm: SectionSummary) map =
  let startAddr = uint64 secSumm.Offset
  let endAddr =
    startAddr + uint64 (secSumm.HeaderSize + secSumm.ContentsSize) - 1UL
  ARMap.addRange startAddr endAddr secSumm map

let addSecSummToSecsInfo (secSumm: SectionSummary) (info: SectionsInfo) =
  {
    info with
      SecByAddr = addSecSummToAddrMap secSumm info.SecByAddr
      SecByName = Map.add secSumm.Name secSumm info.SecByName
      SecArray = Array.append info.SecArray [| secSumm |]
  }

let private parseWasmModule (bs: byte[]) (reader: IBinReader) offset =
  let version = Header.peekFormatVersion (ReadOnlySpan bs) reader (offset + 4)
  let contOff = offset + 8
  let secsSummary = summerizeSections bs reader contOff
  if not (validateSectionsOrder secsSummary)
  then raise InvalidFileTypeException
  else
  let rec parsingLoop wasmModule info (secsSummary: SectionSummary list) =
    if List.isEmpty secsSummary then
      { wasmModule with SectionsInfo = info }
    else
    let secSumm = List.head secsSummary
    let info' =
        if secSumm.Id = SectionId.Custom then info
        else addSecSummToSecsInfo secSumm info
    match secSumm.Id with
    | SectionId.Custom ->
      let wm, sm = updateCustomSection bs reader wasmModule secsSummary
      let lastCS = List.last wm.CustomSections
      let secSumm' = renameSecSumm secSumm lastCS.Contents
      let updatedInfo = addSecSummToSecsInfo secSumm' info'
      parsingLoop wm updatedInfo sm
    | SectionId.Type ->
      let wm, sm = updateTypeSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Import ->
      let wm, sm = updateImportSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Function ->
      let wm, sm = updateFunctionSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Table ->
      let wm, sm = updateTableSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Memory ->
      let wm, sm = updateMemorySection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Global ->
      let wm, sm = updateGlobalSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Export ->
      let wm, sm = updateExportSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Start ->
      let wm, sm = updateStartSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Element ->
      let wm, sm = updateElementSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Code ->
      let wm, sm = updateCodeSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | SectionId.Data ->
      let wm, sm = updateDataSection bs reader wasmModule secsSummary
      parsingLoop wm info' sm
    | _ -> wasmModule
  let wasmModule = {
    FormatVersion = version
    CustomSections = []
    TypeSection = None
    ImportSection = None
    FunctionSection = None
    TableSection = None
    MemorySection = None
    GlobalSection = None
    ExportSection = None
    StartSection = None
    ElementSection = None
    CodeSection = None
    DataSection = None
    SectionsInfo = {
        SecByAddr = ARMap.empty
        SecByName = Map.empty
        SecArray = Array.empty
      }
    IndexMap = Array.empty
  }
  parsingLoop wasmModule wasmModule.SectionsInfo secsSummary

let buildFuncIndexMap (wm: WasmModule) =
  let makeFuncIdxInfo secOff idx elemOff =
    { SecOffset = secOff
      Index = idx
      Kind = IndexKind.Function
      ElemOffset = elemOff }

  let importedFuncs, impSecOff =
    match wm.ImportSection with
    | Some sec ->
      match sec.Contents with
      | Some conts ->
        conts.Elements
        |> Array.filter (fun ie ->
          match ie.Desc with
          | ImpFunc _ -> true
          | _ -> false
        ), sec.Offset
      | None -> [||], 0
    | None -> [||], 0
  let lastIdx =
    let len = Array.length importedFuncs
    if len = 0 then 0u
    else uint32 (len - 1)
  let impFuncsIdxMap =
    if Array.isEmpty importedFuncs then [||]
    else
      importedFuncs
      |> Array.map2 (fun idx ifun ->
        makeFuncIdxInfo impSecOff idx ifun.Offset) [| 0u .. lastIdx |]
  let localFuncsIdxMap =
    match wm.CodeSection with
    | Some sec ->
      match sec.Contents with
      | Some conts ->
        let idxSeq = [| (lastIdx + 1u) .. (lastIdx + conts.Length) |]
        conts.Elements
        |> Array.map2 (fun idx lfun ->
          let funBodyOff = (lfun.Offset + lfun.LenFieldSize)
          makeFuncIdxInfo sec.Offset idx funBodyOff) idxSeq
      | None -> [||]
    | None -> [||]
  Array.append impFuncsIdxMap localFuncsIdxMap

(*
  Only function index maps are supported for now,
  other index maps maybe added in the future as needed.
*)
let buildModuleIndexMap wm =
  { wm with
      IndexMap = buildFuncIndexMap wm }

let parse (bs: byte[]) =
  if Header.isWasm (ReadOnlySpan bs) BinReader.binReaderLE then ()
  else raise FileFormatMismatchException
  parseWasmModule bs BinReader.binReaderLE 0
  |> buildModuleIndexMap