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

module internal B2R2.FrontEnd.BinFile.Mach.Reloc

open System
open B2R2
open B2R2.FrontEnd.BinFile

let parseRelocSymbol data =
  let n = data &&& 0xFFFFFF
  if (data >>> 27) &&& 1 = 1 then SymIndex (n)
  else SecOrdinal (n)

let parseRelocLength data =
  match (data >>> 25) &&& 3 with
  | 0 -> 8<rt>
  | 1 -> 16<rt>
  | _ -> 32<rt>

let rec updateReloc relocs (binReader: BinReader) sec offset endOffset =
  if offset >= endOffset then relocs
  else
    let addr = binReader.PeekInt32 offset
    let data = binReader.PeekInt32 (offset + 4)
    let sym = parseRelocSymbol data
    let len = parseRelocLength data
    let rel = (data >>> 24) &&& 1 = 1
    let r =
      { RelocAddr = addr
        RelocSymbol = sym
        RelocLength = len
        RelocSection = sec
        IsPCRel = rel }
    updateReloc (r :: relocs) binReader sec (offset + 8) endOffset

let translateRelocAddr reloc =
  reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr

let translateRelocSymbol (symbols: MachSymbol []) (secs: MachSection []) reloc =
  match reloc.RelocSymbol with
  | SymIndex (n) -> symbols[n].SymName
  | SecOrdinal (n) -> secs[n - 1].SecName

let toSymbol symbols secs reloc =
  { Address = translateRelocAddr reloc
    Name = translateRelocSymbol symbols secs reloc
    Kind = SymbolKind.NoType (* FIXME *)
    Target = TargetKind.DynamicSymbol
    LibraryName = ""
    ArchOperationMode = ArchOperationMode.NoMode }

let parseRelocs binReader secs =
  secs
  |> Array.fold (fun relocs sec ->
    if sec.SecNumOfReloc = 0 then relocs
    else
      let startOffset = sec.SecRelOff |> Convert.ToInt32
      let endOffset = startOffset + (8 * int sec.SecNumOfReloc)
      updateReloc relocs binReader sec startOffset endOffset) []
  |> List.rev
  |> List.toArray
