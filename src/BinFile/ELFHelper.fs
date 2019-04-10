(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module internal B2R2.BinFile.ELF.Helper

open System
open B2R2
open B2R2.Monads.Maybe
open B2R2.BinFile

let [<Literal>] secPLT = ".plt"
let [<Literal>] secTEXT = ".text"

let private pltThumbStubBytes = [| 0x78uy; 0x47uy; 0xc0uy; 0x46uy |]

let elfTypeToSymbKind ndx = function
  | SymbolType.STTObject -> SymbolKind.ObjectType
  | SymbolType.STTGNUIFunc
  | SymbolType.STTFunc ->
    if ndx = SHNUndef then SymbolKind.NoType
    elif ndx = SHNCommon then SymbolKind.ExternFunctionType
    else SymbolKind.FunctionType
  | SymbolType.STTSection -> SymbolKind.SectionType
  | SymbolType.STTFile ->SymbolKind.FileType
  | _ -> SymbolKind.NoType

let elfVersionToLibName version =
  match version with
  | Some version -> version.VerName
  | None -> ""

let pltFirstSkipBytes = function
| Arch.IntelX86
| Arch.IntelX64 -> 0x10UL
| Arch.ARMv7 -> 0x14UL
| Arch.AARCH64 -> 0x20UL
| _ -> failwith "Implement"

let isThumbPltELFSymbol sAddr (plt: ELFSection) (reader: BinReader) =
 let offset = Convert.ToInt32 (sAddr - plt.SecAddr + plt.SecOffset)
 reader.PeekBytes (4, offset) = pltThumbStubBytes

let findPltSize sAddr plt reader = function
  | Arch.IntelX86
  | Arch.IntelX64 -> 0x10UL
  | Arch.ARMv7 ->
    if isThumbPltELFSymbol sAddr plt reader then 0x10UL else 0x0CUL
  | Arch.AARCH64 -> 0x10UL
  | _ -> failwith "Implement"

let inline tryFindFuncSymb elf addr =
  if addr >= elf.PLTStart && addr < elf.PLTEnd then
    ARMap.tryFindByAddr addr elf.PLT
    >>= (fun s -> Some s.SymName)
  else
    ARMap.tryFindByAddr addr elf.SymInfo.SymChunks
    >>= (fun c -> c.FuncELFSymbol)
    >>= (fun s -> if s.Addr = addr then Some s.SymName else None)

let tryFindELFSymbolChunkRange elf addr =
  match ARMap.tryFindKey (addr + 1UL) elf.SymInfo.SymChunks with
  | Some range when range.Min = addr + 1UL -> Some range
  | _ -> ARMap.tryFindKey addr elf.SymInfo.SymChunks

let parsePLTELFSymbols arch sections (reloc: RelocInfo) reader =
  let plt = Map.find secPLT sections.SecByName
  let pltStartAddr = plt.SecAddr + pltFirstSkipBytes arch
  let pltEndAddr = plt.SecAddr + plt.SecSize
  let folder (map, sAddr) _ (rel: RelocationEntry) =
    match rel.RelType with
    | RelocationX86 RelocationX86.Reloc386JmpSlot
    | RelocationX64 RelocationX64.RelocX64JmpSlot
    | RelocationARMv7 RelocationARMv7.RelocARMJmpSlot
    | RelocationARMv8 RelocationARMv8.RelocAARCH64JmpSlot ->
      let nextStartAddr = sAddr + findPltSize sAddr plt reader arch
      let addrRange = AddrRange (sAddr, nextStartAddr)
      ARMap.add addrRange rel.RelSymbol map, nextStartAddr
    | _ -> map, sAddr
  struct (
    Map.fold folder (ARMap.empty, pltStartAddr) reloc.RelocByAddr |> fst,
    pltStartAddr,
    pltEndAddr
  )

let private hasPLT secs = Map.containsKey secPLT secs.SecByName

let private parseELF offset reader =
  let eHdr = Header.parse reader offset
  let secs = Section.parse eHdr reader
  let proghdrs = ProgHeader.parse eHdr reader
  let loadableSegs = ProgHeader.getLoadableProgHeaders proghdrs
  let loadableSecNums = ProgHeader.getLoadableSecNums secs loadableSegs
  let symbs = Symbol.parse eHdr secs reader
  let reloc = Relocs.parse eHdr secs symbs reader
  let struct (plt, pltStart, pltEnd) =
    if hasPLT secs then parsePLTELFSymbols eHdr.MachineType secs reloc reader
    else struct (ARMap.empty, 0UL, 0UL)
  {
    ELFHdr = eHdr
    ProgHeaders = proghdrs
    LoadableSegments = loadableSegs
    LoadableSecNums = loadableSecNums
    SecInfo = secs
    SymInfo = symbs
    RelocInfo = reloc
    PLT = plt
    PLTStart = pltStart
    PLTEnd = pltEnd
  }

let initELF bytes =
  let reader = BinReader.Init (bytes, Endian.Little)
  if Header.isELF reader 0 then ()
  else raise FileFormatMismatchException
  Header.peekEndianness reader 0
  |> BinReader.RenewReader reader
  |> parseELF 0

let elfSymbolToSymbol target (symb: ELFSymbol) =
  {
    Address = symb.Addr
    Name = symb.SymName
    Kind = elfTypeToSymbKind symb.SecHeaderIndex symb.SymType
    Target = target
    LibraryName = elfVersionToLibName symb.VerInfo
  }

let secFlagToSectionKind flag entrySize =
  if flag &&& SectionFlag.SHFExecInstr = SectionFlag.SHFExecInstr then
    if entrySize > 0UL then SectionKind.LinkageTableSection
    else SectionKind.ExecutableSection
  elif flag &&& SectionFlag.SHFWrite = SectionFlag.SHFWrite then
    SectionKind.WritableSection
  else
    SectionKind.ExtraSection

let elfSectionToSection (sec: ELFSection) =
  {
    Address = sec.SecAddr
    Kind = secFlagToSectionKind sec.SecFlags sec.SecEntrySize
    Size = sec.SecSize
    Name = sec.SecName
  }

let rec isValid addr = function
  | seg :: tl ->
    let vAddr = seg.PHAddr
    if addr >= vAddr && addr < vAddr + seg.PHFileSize then true
    else isValid addr tl
  | [] -> false

let rec translateAddr addr = function
  | seg :: tl ->
    let vAddr = seg.PHAddr
    if addr >= vAddr && addr < vAddr + seg.PHFileSize then
      Convert.ToInt32 (addr - vAddr + seg.PHOffset)
    else translateAddr addr tl
  | [] -> raise InvalidAddrReadException

// vim: set tw=80 sts=2 sw=2:
