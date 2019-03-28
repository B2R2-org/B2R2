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
open B2R2.BinFile.FileHelper

let [<Literal>] secPLT = ".plt"
let [<Literal>] secTEXT = ".text"

/// The start offset for parsing ELF files.
let [<Literal>] startOffset = 0

let private pltThumbStubBytes = [| 0x78uy; 0x47uy; 0xc0uy; 0x46uy |]

let elfTypeToSymbKind ndx = function
  | SymbolType.STTObject -> SymbolKind.ObjectType
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

/// PHTTLS segment contains only SHFTLS sections, PHTPhdr no sections at all.
/// TLS sections is contained only in PHTTLS, PHTGNURelro and PHTLoad.
let checkSHFTLS pHdr sec =
  let checkTLS = Section.hasSHFTLS sec.SecFlags
  let checkPtypeWithoutTLS = function
    | ProgramHeaderType.PHTTLS | ProgramHeaderType.PHTPhdr -> false
    | _ -> true
  let checkPtypeWithinTLS = function
    | ProgramHeaderType.PHTTLS
    | ProgramHeaderType.PHTGNURelro
    | ProgramHeaderType.PHTLoad -> true
    | _ -> false
  let chkCaseOfwithoutSHFTLS = not checkTLS && checkPtypeWithoutTLS pHdr.PHType
  let chkCaseOfWithinSHFTLS = checkTLS && checkPtypeWithinTLS pHdr.PHType
  chkCaseOfWithinSHFTLS || chkCaseOfwithoutSHFTLS

/// PHTLoad, PHTDynamic, PHTGNUEHFrame, PHTGNURelro and PHTGNUStack segment
/// contain only SHFAlloc sections.
let checkSHFAlloc pHdr sec =
  let checkPtype = function
    | ProgramHeaderType.PHTLoad
    | ProgramHeaderType.PHTDynamic
    | ProgramHeaderType.PHTGNUEHFrame
    | ProgramHeaderType.PHTGNURelro
    | ProgramHeaderType.PHTGNUStack -> true
    | _ -> false
  (Section.hasSHFAlloc sec.SecFlags |> not && checkPtype pHdr.PHType) |> not

let checkSecOffset isNoBits secSize pHdr sec =
  let pToSOffset = sec.SecOffset - pHdr.PHOffset
  isNoBits || (sec.SecOffset >= pHdr.PHOffset
  && pToSOffset < pHdr.PHFileSize
  && pToSOffset + secSize <= pHdr.PHFileSize)

let checkVMA secSize pHdr sec =
  let progToSec = sec.SecAddr - pHdr.PHAddr
  (* Check if the section is in the range of the VMA (program header) *)
  let inRange = sec.SecAddr >= pHdr.PHAddr
                && progToSec < pHdr.PHMemSize
                && progToSec + secSize <= pHdr.PHMemSize
  (Section.hasSHFAlloc sec.SecFlags |> not) || inRange

let checkDynamicProc isNoBits pHdr sec =
  let pToSOffset = sec.SecOffset - pHdr.PHOffset
  let checkOff = sec.SecOffset > pHdr.PHOffset && pToSOffset < pHdr.PHFileSize
  let checkALLOC = Section.hasSHFAlloc sec.SecFlags |> not
  let progToSec = sec.SecAddr - pHdr.PHAddr
  let checkMem = sec.SecAddr > pHdr.PHAddr && progToSec < pHdr.PHMemSize
  let checkDynSize = (isNoBits || checkOff) && (checkALLOC || checkMem)
  let checkSizeZero = sec.SecSize <> 0UL || pHdr.PHMemSize = 0UL
  pHdr.PHType <> ProgramHeaderType.PHTDynamic
  || checkSizeZero
  || checkDynSize

let isTbss isNoBits pHdr sec =
  Section.hasSHFTLS sec.SecFlags
  && isNoBits
  && pHdr.PHType <> ProgramHeaderType.PHTTLS

/// Check if a section can be included in the program header, i.e., loaded in
/// memory when executed. The logic here is derived from OBJDUMP code.
let isSecInPHdr pHdr sec =
  let isNoBits = sec.SecType = SectionType.SHTNoBits
  let isTbss = isTbss isNoBits pHdr sec
  let secSize = if isTbss then 0UL else sec.SecEntrySize
  checkSHFTLS pHdr sec
  && checkSHFAlloc pHdr sec
  && checkSecOffset isNoBits secSize pHdr sec
  && checkVMA secSize pHdr sec
  && checkDynamicProc isNoBits pHdr sec
  && not isTbss

let gatherLoadlabeSecNums pHdr secs =
  let foldSHdr acc sec =
    let lb = pHdr.PHOffset
    let ub = lb + pHdr.PHFileSize
    if sec.SecOffset >= lb && sec.SecOffset < ub then sec.SecNum :: acc else acc
  ARMap.fold (fun acc _ s -> foldSHdr acc s) [] secs.SecByAddr

let readPHdrType (reader: BinReader) offset: ProgramHeaderType =
  reader.PeekUInt32 offset |> LanguagePrimitives.EnumOfValue

let readPHdrFlags (reader: BinReader) cls offset =
  let pHdrPHdrFlagsOffset = if cls = WordSize.Bit32 then 24 else 4
  offset + pHdrPHdrFlagsOffset |> reader.PeekInt32

let readPHdrOffset (reader: BinReader) cls offset =
  let offsetOfPHdrOffset = if cls = WordSize.Bit32 then 4 else 8
  offset + offsetOfPHdrOffset |> peekUIntOfType reader cls

let readPHdrAddr (reader: BinReader) cls offset =
  let pHdrAddrOffset = if cls = WordSize.Bit32 then 8 else 16
  offset + pHdrAddrOffset |> peekUIntOfType reader cls

let readPHdrPhyAddr (reader: BinReader) cls offset =
  let pHdrPhyAddrOffset = if cls = WordSize.Bit32 then 12 else 24
  offset + pHdrPhyAddrOffset |> peekUIntOfType reader cls

let readPHdrFileSize (reader: BinReader) cls offset =
  let pHdrPHdrFileSizeOffset = if cls = WordSize.Bit32 then 16 else 32
  offset + pHdrPHdrFileSizeOffset |> peekUIntOfType reader cls

let readPHdrMemSize (reader: BinReader) cls offset =
  let pHdrPHdrMemSizeOffset = if cls = WordSize.Bit32 then 20 else 40
  offset + pHdrPHdrMemSizeOffset |> peekUIntOfType reader cls

let readPHdrAlign (reader: BinReader) cls offset =
  let pHdrPHdrAlignOffset = if cls = WordSize.Bit32 then 28 else 48
  offset + pHdrPHdrAlignOffset |> peekUIntOfType reader cls

let parseProgHeader cls (reader: BinReader) offset =
  {
    PHType = readPHdrType reader offset
    PHFlags = readPHdrFlags reader cls offset
    PHOffset = readPHdrOffset reader cls offset
    PHAddr = readPHdrAddr reader cls offset
    PHPhyAddr = readPHdrPhyAddr reader cls offset
    PHFileSize = readPHdrFileSize reader cls offset
    PHMemSize = readPHdrMemSize reader cls offset
    PHAlignment = readPHdrAlign reader cls offset
  }

let nextPHdrOffset cls offset =
  offset + if cls = WordSize.Bit32 then 32 else 56

/// Parse and associate program headers with section headers to return the list
/// of segments.
let parseProgHeaders eHdr reader =
  let rec parseLoop pNum acc offset =
    if pNum = 0us then List.rev acc
    else
      let phdr = parseProgHeader eHdr.Class reader offset
      parseLoop (pNum - 1us) (phdr :: acc) (nextPHdrOffset eHdr.Class offset)
  Convert.ToInt32 eHdr.PHdrTblOffset
  |> parseLoop eHdr.PHdrNum []

let computeLoadableSecNums secs segs =
  let loop set seg =
    gatherLoadlabeSecNums seg secs
    |> List.fold (fun set n -> Set.add n set) set
  segs |> List.fold loop Set.empty

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
    match rel.RelSecName with
    | ".rel.plt" | ".rela.plt" ->
      let nextStartAddr = sAddr + findPltSize sAddr plt reader arch
      let addrRange = AddrRange (sAddr, nextStartAddr)
      ARMap.add addrRange rel.RelSymbol map, nextStartAddr
    | _ -> map, sAddr
  struct (
    Map.fold folder (ARMap.empty, pltStartAddr) reloc.RelocByAddr |> fst,
    pltStartAddr,
    pltEndAddr
  )

let hasPLT secs = Map.containsKey secPLT secs.SecByName

let parseELF offset reader =
  let eHdr = Header.parse reader offset
  let secs = Section.parse eHdr reader
  let segs = parseProgHeaders eHdr reader // FIXME
  let loadableSegs =
    segs |> List.filter (fun seg -> seg.PHType = ProgramHeaderType.PHTLoad)
  let loadableSecNums = computeLoadableSecNums secs loadableSegs
  let symbs = Symbol.parse eHdr secs reader
  let reloc = Relocs.parse eHdr secs symbs.DynSymArr reader
  let struct (plt, pltStart, pltEnd) =
    if hasPLT secs then parsePLTELFSymbols eHdr.MachineType secs reloc reader
    else struct (ARMap.empty, 0UL, 0UL)
  {
    ELFHdr = eHdr
    Segments = segs
    LoadableSegments = loadableSegs
    LoadableSecNums = loadableSecNums
    SecInfo = secs
    SymInfo = symbs
    RelocInfo = reloc
    PLT = plt
    PLTStart = pltStart
    PLTEnd = pltEnd
  }

let elfSymbolToSymbol target (symb: ELFSymbol) =
  {
    Address = symb.Addr
    Name = symb.SymName
    Kind = elfTypeToSymbKind symb.SecHeaderIndex symb.SymType
    Target = target
    LibraryName = elfVersionToLibName symb.VerInfo
  }

let getAllStaticSymbols elf =
  elf.SymInfo.StaticSymArr
  |> Array.map (elfSymbolToSymbol TargetKind.StaticSymbol)

let getAllDynamicSymbols elf =
  elf.SymInfo.DynSymArr
  |> Array.map (elfSymbolToSymbol TargetKind.DynamicSymbol)

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

let getAllSections elf =
  elf.SecInfo.SecByNum
  |> Array.map (elfSectionToSection)
  |> Array.toSeq

let getSectionsByAddr elf addr =
  match ARMap.tryFindByAddr addr elf.SecInfo.SecByAddr with
  | Some s -> Seq.singleton (elfSectionToSection s)
  | None -> Seq.empty

let getSectionsByName elf name =
  match Map.tryFind name elf.SecInfo.SecByName with
  | Some s -> Seq.singleton (elfSectionToSection s)
  | None -> Seq.empty

let progHdrToSegment phdr =
  {
    Address = phdr.PHAddr
    Size = phdr.PHFileSize
    Permission = phdr.PHFlags |> LanguagePrimitives.EnumOfValue
  }

let getAllSegments elf =
  elf.LoadableSegments
  |> List.map progHdrToSegment
  |> List.toSeq

let getLinkageTableEntries elf =
  let create pltAddr (symb: ELFSymbol) =
    {
      FuncName = symb.SymName
      LibraryName = elfVersionToLibName symb.VerInfo
      TrampolineAddress = pltAddr
      TableAddress = symb.Addr
    }
  elf.PLT
  |> ARMap.fold (fun acc addrRange s -> create addrRange.Min s :: acc) []
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toSeq

let getRelocSymbols elf =
  elf.RelocInfo.RelocByName
  |> Map.toSeq
  |> Seq.map (fun (_, i) -> { i.RelSymbol with Addr = i.RelOffset }
                            |> elfSymbolToSymbol TargetKind.DynamicSymbol)

let initELF bytes =
  let reader = BinReader.Init (bytes, Endian.Little)
  if Header.isELF reader startOffset then ()
  else raise FileFormatMismatchException
  Header.readEndianness reader startOffset
  |> BinReader.RenewReader reader
  |> parseELF startOffset

let getTextSectionStartAddr elf =
  (Map.find secTEXT elf.SecInfo.SecByName).SecAddr

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
