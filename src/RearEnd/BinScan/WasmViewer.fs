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

module internal B2R2.RearEnd.BinScan.WasmViewer

open B2R2
open B2R2.Logging
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils

let private sectionEndOffset (sec: Wasm.SectionSummary) =
  uint64 sec.Offset + uint64 (sec.HeaderSize + sec.ContentsSize) - 1UL

let dumpFileHeader _ (file: WasmBinFile) =
  let wasm = file.WASM
  resetToDefaultTwoColumnConfig ()
  printsr [| "Magic:"; HexString.ofUInt64 0x6D736100UL |]
  printsr [| "Version:"; wasm.FormatVersion.ToString() |]
  printsr [| "Number of sections:"; file.Sections.Length.ToString() |]
  printsn ""

let makeSectionHeadersFormatVerbose () =
  [| LeftAligned 4
     LeftAligned 12
     LeftAligned 12
     LeftAligned 24
     LeftAligned 12
     LeftAligned 12
     LeftAligned 12 |]

let makeSectionHeadersTableHeaderVerbose () =
  [| "Num"
     "Start"
     "End"
     "Name"
     "Id"
     "HeaderSize"
     "ContentsSize" |]

let dumpSectionHeadersVerbose (file: WasmBinFile) =
  setTableColumnFormats <| makeSectionHeadersFormatVerbose ()
  printDoubleHorizontalRule ()
  printsr <| makeSectionHeadersTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for i in 0 .. file.Sections.Length - 1 do
    let sec = file.Sections[i]
    printsr [| String.wrapSquareBracket (i.ToString())
               HexString.ofUInt64 (uint64 sec.Offset)
               HexString.ofUInt64 (sectionEndOffset sec)
               normalizeEmpty sec.Name
               sec.Id.ToString()
               toNBytes (uint64 sec.HeaderSize)
               toNBytes (uint64 sec.ContentsSize) |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeadersSimple (file: WasmBinFile) =
  setTableColumnFormats
    [| LeftAligned 4; LeftAligned 12; LeftAligned 12; LeftAligned 24 |]
  printDoubleHorizontalRule ()
  printsr [| "Num"; "Start"; "End"; "Name" |]
  printSingleHorizontalRule ()
  for i in 0 .. file.Sections.Length - 1 do
    let sec = file.Sections[i]
    printsr [| String.wrapSquareBracket (i.ToString())
               HexString.ofUInt64 (uint64 sec.Offset)
               HexString.ofUInt64 (sectionEndOffset sec)
               normalizeEmpty sec.Name |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeaders (opts: BinScanOpts) (file: WasmBinFile) =
  if opts.Verbose then dumpSectionHeadersVerbose file
  else dumpSectionHeadersSimple file

let dumpSectionDetails (secName: string) (file: WasmBinFile) =
  file.Sections
  |> Array.tryFind (fun sec -> sec.Name = secName)
  |> function
    | Some sec ->
      resetToDefaultTwoColumnConfig ()
      printsr [| "Section name:"; normalizeEmpty sec.Name |]
      printsr [| "Section id:"; sec.Id.ToString() |]
      printsr [| "Offset:"; HexString.ofUInt64 (uint64 sec.Offset) |]
      printsr [| "End offset:"; HexString.ofUInt64 (sectionEndOffset sec) |]
      printsr [| "Header size:"; toNBytes (uint64 sec.HeaderSize) |]
      printsr [| "Contents size:"; toNBytes (uint64 sec.ContentsSize) |]
      printsn ""
    | None ->
      printsn "Not found."
      printsn ""

let private resolvedName (file: IBinFile) addr =
  match BinFileOps.tryFindName file addr with
  | Ok name -> name
  | Error _ -> ""

let dumpSymbols _ (file: WasmBinFile) =
  let file = file :> IBinFile
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  setTableColumnFormats
    [| LeftAligned 8; addrColumn; LeftAligned 50; LeftAligned 20 |]
  printDoubleHorizontalRule ()
  printsr [| "Kind"; "Address"; "Name"; "Lib Name" |]
  printSingleHorizontalRule ()
  for entry in BinFileOps.getLinkageEntries file do
    printsr [| "import"
               Addr.toString file.ISA.WordSize entry.TableAddress
               normalizeEmpty entry.FuncName
               normalizeEmpty entry.LibraryName |]
  printSingleHorizontalRule ()
  for addr in BinFileOps.getFunctionAddresses file do
    printsr [| "func"
               Addr.toString file.ISA.WordSize addr
               normalizeEmpty (resolvedName file addr)
               "(n/a)" |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpRelocs _ (_: WasmBinFile) =
  Terminator.futureFeature ()

let dumpFunctions _ (file: WasmBinFile) =
  let file = file :> IBinFile
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  setTableColumnFormats [| addrColumn; LeftAligned 75 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Name" |]
  printSingleHorizontalRule ()
  for addr in BinFileOps.getFunctionAddresses file do
    printsr [| Addr.toString file.ISA.WordSize addr
               normalizeEmpty (resolvedName file addr) |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpExceptionTable _ (_: WasmBinFile) =
  Terminator.futureFeature ()
