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

module internal B2R2.BinFile.ELF.Parser

open System
open B2R2
open B2R2.BinFile

let pltSkipBytes = function
  | Arch.IntelX86
  | Arch.IntelX64 -> 0x10UL
  | Arch.ARMv7 -> 0x14UL
  | Arch.AARCH64 -> 0x20UL
  | _ -> Utils.futureFeature ()

let isThumbPltELFSymbol sAddr (plt: ELFSection) (reader: BinReader) =
  let offset = Convert.ToInt32 (sAddr - plt.SecAddr + plt.SecOffset)
  let pltThumbStubBytes = [| 0x78uy; 0x47uy; 0xc0uy; 0x46uy |]
  reader.PeekBytes (4, offset) = pltThumbStubBytes

let findPltSize sAddr plt reader = function
  | Arch.IntelX86
  | Arch.IntelX64 -> 0x10UL
  | Arch.ARMv7 ->
    if isThumbPltELFSymbol sAddr plt reader then 0x10UL else 0x0CUL
  | Arch.AARCH64 -> 0x10UL
  | _ -> failwith "Implement"

let parsePLT arch sections (reloc: RelocInfo) reader =
  match Map.tryFind ".plt" sections.SecByName with
  | Some plt ->
    let pltStartAddr = plt.SecAddr + pltSkipBytes arch
    let folder (map, sAddr) _ (rel: RelocationEntry) =
      match rel.RelType with
      | RelocationX86 RelocationX86.Reloc386JmpSlot
      | RelocationX64 RelocationX64.RelocX64JmpSlot
      | RelocationARMv7 RelocationARMv7.RelocARMJmpSlot
      | RelocationARMv8 RelocationARMv8.RelocAARCH64JmpSlot ->
        let nextStartAddr = sAddr + findPltSize sAddr plt reader arch
        let addrRange = AddrRange (sAddr, nextStartAddr)
        let symb = Option.get rel.RelSymbol
        let symb = { symb with Addr = rel.RelOffset }
        ARMap.add addrRange symb map, nextStartAddr
      | _ -> map, sAddr
    Map.fold folder (ARMap.empty, pltStartAddr) reloc.RelocByAddr |> fst
  | None -> ARMap.empty

let parseGlobalSymbols reloc =
  let folder map addr (rel: RelocationEntry) =
    match rel.RelType with
    | RelocationX86 RelocationX86.Reloc386GlobData
    | RelocationX64 RelocationX64.RelocX64GlobData ->
      Map.add addr (Option.get rel.RelSymbol) map
    | _ -> map
  reloc.RelocByAddr |> Map.fold folder Map.empty

let invRanges wordSize segs getNextStartAddr =
  segs
  |> List.sortBy (fun seg -> seg.PHAddr)
  |> List.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       FileHelper.addInvRange set saddr seg.PHAddr, n) (IntervalSet.empty, 0UL)
  |> FileHelper.addLastInvRange wordSize

let private parseELF offset reader =
  let eHdr = Header.parse reader offset
  let cls = eHdr.Class
  let secs = Section.parse eHdr reader
  let proghdrs = ProgHeader.parse eHdr reader
  let segs = ProgHeader.getLoadableProgHeaders proghdrs
  let loadableSecNums = ProgHeader.getLoadableSecNums secs segs
  let symbs = Symbol.parse eHdr secs reader
  let reloc = Relocs.parse eHdr secs symbs reader
  let plt = parsePLT eHdr.MachineType secs reloc reader
  let globals = parseGlobalSymbols reloc
  let symbs = Symbol.updatePLTSymbols plt symbs |> Symbol.updateGlobals globals
  { ELFHdr = eHdr
    ProgHeaders = proghdrs
    LoadableSegments = segs
    LoadableSecNums = loadableSecNums
    SecInfo = secs
    SymInfo = symbs
    RelocInfo = reloc
    PLT = plt
    Globals = globals
    InvalidAddrRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHMemSize)
    NotInFileRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHFileSize)
    BinReader = reader }

let parse bytes =
  let reader = BinReader.Init (bytes, Endian.Little)
  if Header.isELF reader 0 then ()
  else raise FileFormatMismatchException
  Header.peekEndianness reader 0
  |> BinReader.RenewReader reader
  |> parseELF 0
