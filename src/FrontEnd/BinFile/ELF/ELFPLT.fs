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

module internal B2R2.FrontEnd.BinFile.ELF.PLT

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

type CodeKind =
  | PIC
  | NonPIC
  | DontCare

type PLTLinkMethod =
  | LazyBinding
  | EagerBinding
  | AnyBinding

type PLTEntryInfo = {
  /// This is the address where a relocation operation is performed on.
  EntryRelocAddr: Addr
  /// Next PLT entry address.
  NextEntryAddr: Addr
}

/// General descriptor of a PLT section.
type PLTDescriptor = {
  /// PIC or non-PIC.
  CodeKind: CodeKind
  /// Lazy vs. Non-lazy (eager) binding.
  LinkMethod: PLTLinkMethod
  /// Has secondary PLT?
  HasSecondary: bool
  /// Entry size of the PLT.
  EntrySize: uint64
  /// Offset from a start of a PLT entry to the relocatable expression. This can
  /// be an offset to a GOT entry or a GOT index, depending on whether the
  /// binary is PIC or non-PIC. For example, in an x86 PIE, a PLT entry may
  /// include `jmp [ebx+0xc]`. In such a case, we get the GOT index by getting
  /// the displacement `0xc`.
  RelocOffset: Addr
  /// Extra offset field. This is used for different purposes for different
  /// architectures.
  ExtraOffset: Addr
}

type PLTSectionType =
  /// The regular PLT.
  | PLT of desc: PLTDescriptor
  /// The PLT pattern is unknown.
  | UnknownPLT

[<AbstractClass>]
type PLTParser () =
  /// Parse PLT entries. This function returns a mapping from a PLT entry
  /// address range to LinkageTableEntry.
  abstract member Parse: ELFToolbox -> ARMap<LinkageTableEntry>

  /// Parse the given PLT section.
  abstract member ParseSection:
    ELFToolbox * ELFSection * ARMap<LinkageTableEntry>
    -> ARMap<LinkageTableEntry>

  /// Parse the given PLT section.
  abstract member ParseEntry:
    addr: Addr * idx: int * ELFSection * PLTDescriptor * IBinReader * ByteSpan
    -> PLTEntryInfo

let [<Literal>] private SecRelPLT = ".rel.plt"
let [<Literal>] private SecRelaPLT = ".rela.plt"
let [<Literal>] private SecPLT = ".plt"
let [<Literal>] private SecPLTSnd = ".plt.sec"
let [<Literal>] private SecPLTGOT = ".plt.got"
let [<Literal>] private SecPLTBnd = ".plt.bnd"
let [<Literal>] private SecGOT = ".got"
let [<Literal>] private SecGOTPLT = ".got.plt"
let [<Literal>] private SecMIPSStubs = ".MIPS.stubs"

let inline private newDesc kind lm hasSecondary entSize relocOff extra =
  { CodeKind = kind
    LinkMethod = lm
    HasSecondary = hasSecondary
    EntrySize = entSize
    RelocOffset = relocOff
    ExtraOffset = extra }

let private newPLT kind lm hasSecondary entSize relocOff extra =
  newDesc kind lm hasSecondary entSize relocOff extra |> PLT

let private tryFindGOTAddr shdrs =
  match Array.tryFind (fun s -> s.SecName = SecGOTPLT) shdrs with
  | Some s -> Some s.SecAddr
  | None ->
    match Array.tryFind (fun s -> s.SecName = SecGOT) shdrs with
    | Some s -> Some s.SecAddr
    | None -> None

let private tryFindFirstEntryAddrWithRelPLT reloc shdrs =
  match Array.tryFind (fun s -> s.SecName = SecRelPLT) shdrs with
  | Some s ->
    reloc.RelocByAddr.Values
    |> Seq.fold (fun minval r ->
      if r.RelSecNumber = s.SecNum then
        if r.RelOffset < minval then r.RelOffset else minval
      else minval) UInt64.MaxValue
    |> Some
  | None -> None

let private tryFindFirstEntryAddrWithRelocation reloc =
  reloc.RelocByAddr.Values
  |> Seq.fold (fun minval r ->
    match r.RelType with
    | RelocationARMv8 RelocationARMv8.R_AARCH64_JUMP_SLOT ->
      if r.RelOffset < minval then r.RelOffset else minval
    | _ -> minval) UInt64.MaxValue
  |> fun addr -> if addr = UInt64.MaxValue then None else Some addr

let isPLTSectionName name =
  name = SecPLT || name = SecPLTSnd || name = SecPLTGOT || name = SecPLTBnd

let private findPLTSections shdrs =
  shdrs
  |> Array.fold (fun acc s ->
    if isPLTSectionName s.SecName then s :: acc else acc) []
  |> List.rev (* .plt, .plt.got, .plt.sec *)

let private makePLTEntry symbs addr relocAddr (r: RelocationEntry) =
  match r.RelSymbol with
  | Some symb ->
    symbs.AddrToSymbTable[addr] <- symb (* Update the symbol table. *)
    { FuncName = symb.SymName
      LibraryName = Symbol.versionToLibName symb.VerInfo
      TrampolineAddress = addr
      TableAddress = r.RelOffset }
  | None ->
    { FuncName = ""
      LibraryName = ""
      TrampolineAddress = addr
      TableAddress = relocAddr }

let rec parseEntryLoop p sec rdr span desc symbs rel map idx eAddr addr =
  if addr >= eAddr then map
  else
    let entry =
      (p: PLTParser).ParseEntry (addr, idx, sec, desc, rdr, span)
    let nextAddr = entry.NextEntryAddr
    match rel.RelocByAddr.TryGetValue entry.EntryRelocAddr with
    | true, r ->
      let entry = makePLTEntry symbs addr entry.EntryRelocAddr r
      let ar = AddrRange (addr, nextAddr - 1UL)
      let map = ARMap.add ar entry map
      parseEntryLoop p sec rdr span desc symbs rel map (idx + 1) eAddr nextAddr
    | _ ->
      parseEntryLoop p sec rdr span desc symbs rel map (idx + 1) eAddr nextAddr

let private parseEntries p sec span reader desc symbs rel map eAddr addr =
  parseEntryLoop p sec reader span desc symbs rel map 0 eAddr addr

let rec private parseSections p toolBox map = function
  | sec :: rest ->
    let map = (p: PLTParser).ParseSection (toolBox, sec, map)
    parseSections p toolBox map rest
  | [] -> map

/// This uses relocation information to parse PLT entries. This can be a general
/// parser, but it is rather slow compared to platform-specific parsers. RISCV64
/// relies on this.
type GeneralPLTParser (shdrs, relocInfo, symbInfo, pltHdrSize, relType) =
  inherit PLTParser ()

  let relocs =
    relocInfo.RelocByAddr.Values
    |> Seq.filter (fun r -> r.RelType = relType)
    |> Seq.toArray

  member internal __.Relocs with get() = relocs

  member private __.CreateGeneralPLTDescriptor rsec sec =
    let count = rsec.SecSize / rsec.SecEntrySize (* number of PLT entries *)
    let pltEntrySize = (sec.SecSize - pltHdrSize) / count
    let addr = sec.SecAddr + pltHdrSize
    assert (__.Relocs.Length = int count)
    newPLT DontCare AnyBinding false pltEntrySize 0UL addr

  member private __.FindGeneralPLTType sec =
    match Array.tryFind (fun s -> s.SecName = SecRelPLT) shdrs with
    | Some rsec -> __.CreateGeneralPLTDescriptor rsec sec
    | None ->
      match Array.tryFind (fun s -> s.SecName = SecRelaPLT) shdrs with
      | Some rsec -> __.CreateGeneralPLTDescriptor rsec sec
      | None -> UnknownPLT

  override __.ParseEntry (addr, idx, _sec, desc, _rdr, _span) =
    { EntryRelocAddr = __.Relocs[idx].RelOffset
      NextEntryAddr = addr + desc.EntrySize }

  override __.ParseSection (toolBox, sec, map) =
    match __.FindGeneralPLTType sec with
    | PLT desc ->
      let sAddr, eAddr = desc.ExtraOffset, sec.SecAddr + sec.SecSize
      let bytes = toolBox.Bytes
      let reader = toolBox.Reader
      let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
      parseEntries __ sec span reader desc symbInfo relocInfo map eAddr sAddr
    | UnknownPLT -> map

  override __.Parse toolBox =
    let pltSections = findPLTSections shdrs
    parseSections __ toolBox ARMap.empty pltSections

/// Intel x86 PLT parser.
type X86PLTParser (shdrs, relocInfo, symbInfo) =
  inherit PLTParser ()

  let gotAddrOpt = tryFindGOTAddr shdrs

  let picLazyZeroEntry = (* push indirect addr; jmp; *)
    [| OneByte 0xffuy; OneByte 0xb3uy; OneByte 0x04uy; AnyByte; AnyByte; AnyByte
       OneByte 0xffuy; OneByte 0xa3uy; OneByte 0x08uy; AnyByte; AnyByte; AnyByte
    |]

  let picLazyIbtEntry = (* (Ind-Branch-Tracking) endbr32; push; jmp rel; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy;
       OneByte 0x68uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xe9uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let nonPicZeroEntry = (* push absolute addr; jmp; *)
    [| OneByte 0xffuy; OneByte 0x35uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte |]

  let nonPicIbtEntry = (* (Ind-Branch-Tracking) endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy;
       OneByte 0x68uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xe9uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let picNonLazyEntry = (* jmp indirect addr; nop *)
    [| OneByte 0xffuy; OneByte 0xa3uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let picNonLazyIbtEntry = (* endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy
       OneByte 0xffuy; OneByte 0xa3uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]

  let nonPicNonLazyEntry = (* jmp indirect addr; nop *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let nonPicNonLazyIbtEntry = (* endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]

  let findX86PLTType (plt: ByteSpan) =
    if BytePattern.matchSpan picLazyZeroEntry plt then
      let isIBT = BytePattern.matchSpan picLazyIbtEntry (plt.Slice 16)
      let gotoff = if isIBT then 6UL else 2UL
      newPLT PIC LazyBinding isIBT 16UL gotoff 0UL
    elif BytePattern.matchSpan nonPicZeroEntry plt then
      let isIBT = BytePattern.matchSpan nonPicIbtEntry (plt.Slice 16)
      let gotoff = if isIBT then 6UL else 2UL
      newPLT NonPIC LazyBinding isIBT 16UL gotoff 0UL
    elif BytePattern.matchSpan picNonLazyEntry plt then
      newPLT PIC EagerBinding false 8UL 2UL 0UL
    elif BytePattern.matchSpan picNonLazyIbtEntry plt then
      newPLT PIC EagerBinding true 16UL 6UL 0UL
    elif BytePattern.matchSpan nonPicNonLazyEntry plt then
      newPLT NonPIC EagerBinding false 8UL 2UL 0UL
    elif BytePattern.matchSpan nonPicNonLazyIbtEntry plt then
      newPLT NonPIC EagerBinding true 16UL 6UL 0UL
    else UnknownPLT

  member private __.ComputeRelocAddr (codeKind, baseAddr, relocV) =
    match codeKind with
    | PIC -> baseAddr + relocV
    | NonPIC -> relocV
    | DontCare -> Utils.impossible ()

  override __.ParseEntry (addr, _, sec, desc, reader, span) =
    let baseAddr = Option.get gotAddrOpt
    let addrDiff = int (addr - sec.SecAddr)
    let o = addrDiff + int desc.RelocOffset
    let relocV = reader.ReadInt32 (span, o) |> uint64
    let relocAddr = __.ComputeRelocAddr (desc.CodeKind, baseAddr, relocV)
    { EntryRelocAddr = relocAddr; NextEntryAddr = addr + desc.EntrySize }

  override __.ParseSection (toolBox, sec, map) =
    let bytes = toolBox.Bytes
    let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
    match findX86PLTType span with
    | PLT desc ->
      (* This section is an IBT PLT section and it uses lazy binding. This
         means we can safely ignore this section because the secondary PLT is
         the actual jump table. *)
      if desc.LinkMethod = LazyBinding && desc.HasSecondary then map
      else
        let sAddr, eAddr = sec.SecAddr, sec.SecAddr + sec.SecSize
        let reader = toolBox.Reader
        parseEntries __ sec span reader desc symbInfo relocInfo map eAddr sAddr
    | UnknownPLT -> map

  override __.Parse toolBox =
    let pltSections = findPLTSections shdrs
    if Option.isSome gotAddrOpt then
      parseSections __ toolBox ARMap.empty pltSections
    else ARMap.empty

/// Intel x86-64 PLT parser.
type X64PLTParser (shdrs, relocInfo, symbInfo) =
  inherit PLTParser ()

  let gotAddrOpt = tryFindGOTAddr shdrs

  let lazyZeroEntry = (* push [got+8]; jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x35uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte |]

  let lazyIbtZeroEntry = (* (Ind-Br-Tracking) push [got+8]; bnd jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x35uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let lazyIbtEntry = (* endbr64; push imm; bnd jmp rel; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfauy
       OneByte 0x68uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xf2uy; OneByte 0xe9uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte |]

  let nonLazyEntry = (* jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let eagerBndEntry = (* bnd jmp [got+n]] *)
    [| OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]

  let eagerIbtEntry = (* endbr64; bnd jmp [got+n]] *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfauy
       OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy;
       AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]

  let findX64PLTType (plt: ByteSpan) =
    if BytePattern.matchSpan lazyZeroEntry plt then
      newPLT DontCare LazyBinding false 16UL 2UL 6UL
    elif BytePattern.matchSpan lazyIbtZeroEntry plt then
      let off, inssz =
        if BytePattern.matchSpan lazyIbtEntry (plt.Slice 16) then 7UL, 11UL
        else 3UL, 7UL (* bnd *)
      newPLT DontCare LazyBinding true 16UL off inssz
    elif BytePattern.matchSpan nonLazyEntry plt then
      newPLT DontCare EagerBinding false 8UL 2UL 6UL
    elif BytePattern.matchSpan eagerBndEntry plt then
      newPLT DontCare EagerBinding true 16UL 3UL 7UL
    elif BytePattern.matchSpan eagerIbtEntry plt then
      newPLT DontCare EagerBinding true 16UL 7UL 11UL
    else UnknownPLT

  override __.ParseEntry (addr, _, sec, desc, reader, span) =
    let addrDiff = int (addr - sec.SecAddr)
    let o = addrDiff + int desc.RelocOffset
    let displ = reader.ReadInt32 (span, o) |> uint64
    { EntryRelocAddr = addr + desc.ExtraOffset + displ
      NextEntryAddr = addr + desc.EntrySize }

  override __.ParseSection (toolBox, sec, map) =
    let bytes = toolBox.Bytes
    let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
    match findX64PLTType span with
    | PLT desc ->
      (* This section is an IBT PLT section and it uses lazy binding. This
         means we can safely ignore this section because the secondary PLT is
         the actual jump table. *)
      if desc.LinkMethod = LazyBinding && desc.HasSecondary then map
      else
        let sAddr, eAddr = sec.SecAddr, sec.SecAddr + sec.SecSize
        let reader = toolBox.Reader
        parseEntries __ sec span reader desc symbInfo relocInfo map eAddr sAddr
    | UnknownPLT -> map

  override __.Parse toolBox =
    let pltSections = findPLTSections shdrs
    if Option.isSome gotAddrOpt then
      parseSections __ toolBox ARMap.empty pltSections
    else ARMap.empty

/// Get the size of the header of PLT (PLT Zero)
let private computeARMPLTHeaderSize reader (span: ByteSpan) =
  let v = (reader: IBinReader).ReadInt32 (span, 0)
  if v = 0xe52de004 then (* str lr, [sp, #-4] *)
    let v = reader.ReadInt32 (span, 16)
    if v = 0xe28fc600 then (* add ip, pc, #0, 12 *) Some 16UL
    else Some 20UL
  elif v = 0xf8dfb500 then (* push {lr} *) Some 16UL
  else None

let private computeARMPLTEntrySize reader (span: ByteSpan) hdrSize delta =
  if (reader: IBinReader).ReadInt32 (span, 0) = 0xf8dfb500 then
    Ok 16UL (* THUMB-only *)
  else
    let offset = int hdrSize + delta
    let size = if reader.ReadInt16 (span, offset) = 0x4778s then 4 else 0
    let offset = offset + size
    let ins = reader.ReadInt32 (span, offset) &&& 0xffffff00 (* strip imm *)
    if (hdrSize = 16UL && ins = 0xe28fc600) || ins = 0xe28fc200 then
      Ok (uint64 (size + 16))
    elif ins = 0xe28fc600 then Ok (uint64 (size + 12))
    else Error ErrorCase.InvalidFileFormat

/// ARMv7 PLT parser.
type ARMv7PLTParser (shdrs, relocInfo, symbInfo) =
  inherit PLTParser ()

  let baseAddrOpt = tryFindFirstEntryAddrWithRelPLT relocInfo shdrs

  let findARMv7PLTType (span: ByteSpan) reader sec =
    match computeARMPLTHeaderSize reader span with
    | Some headerSize ->
      let startAddr = sec.SecAddr + headerSize
      if reader.ReadInt32 (span, 0) = 0xf8dfb500 then
        (* push {lr} *)
        newPLT DontCare AnyBinding false 16UL 0UL startAddr
      else
        match computeARMPLTEntrySize reader span headerSize 0 with
        | Ok sz -> newPLT DontCare AnyBinding false sz 0UL startAddr
        | Error _ -> UnknownPLT
    | None -> UnknownPLT

  override __.ParseEntry (addr, idx, _sec, desc, reader, span) =
    let addrDiff = int (addr - desc.ExtraOffset)
    let hdrSize = computeARMPLTHeaderSize reader span |> Option.get
    let baseAddr = Option.get baseAddrOpt
    match computeARMPLTEntrySize reader span hdrSize addrDiff with
    | Ok entSize ->
      { EntryRelocAddr = baseAddr + uint64 (idx * 4)
        NextEntryAddr = addr + uint64 entSize }
    | Error _ -> (* Just ignore this entry using the default entry size 16. *)
      { EntryRelocAddr = 0UL; NextEntryAddr = addr + 16UL }

  override __.ParseSection (toolBox, sec, map) =
    let bytes = toolBox.Bytes
    let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
    match findARMv7PLTType span toolBox.Reader sec with
    | PLT desc ->
      let sAddr, eAddr = desc.ExtraOffset, sec.SecAddr + sec.SecSize
      let reader = toolBox.Reader
      parseEntries __ sec span reader desc symbInfo relocInfo map eAddr sAddr
    | UnknownPLT -> map

  override __.Parse toolBox =
    let pltSections = findPLTSections shdrs
    if Option.isSome baseAddrOpt then
      parseSections __ toolBox ARMap.empty pltSections
    else ARMap.empty

/// AARCH64 PLT parser.
type AARCH64PLTParser (shdrs, relocInfo, symbInfo) =
  inherit PLTParser ()

  let baseAddrOpt = tryFindFirstEntryAddrWithRelocation relocInfo

  override __.ParseEntry (addr, idx, _sec, _desc, _rdr, _span) =
    let baseAddr = Option.get baseAddrOpt
    { EntryRelocAddr = baseAddr + uint64 (idx * 8)
      NextEntryAddr = addr + 16UL }

  override __.ParseSection (toolBox, sec, map) =
    let startAddr = sec.SecAddr + 32UL
    let desc = newDesc DontCare AnyBinding false 16UL 0UL startAddr
    let sAddr, eAddr = desc.ExtraOffset, sec.SecAddr + sec.SecSize
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
    parseEntries __ sec span reader desc symbInfo relocInfo map eAddr sAddr

  override __.Parse toolBox =
    let pltSections = findPLTSections shdrs
    if Option.isSome baseAddrOpt then
      parseSections __ toolBox ARMap.empty pltSections
    else ARMap.empty

let private readMicroMIPSOpcode (span: ByteSpan) (reader: IBinReader) offset =
  let v1 = reader.ReadUInt16 (span, offset) |> uint32
  let v2 = reader.ReadUInt16 (span, offset + 2) |> uint32
  int (v1 <<< 16 ||| v2)

let private computeMIPSPLTHeaderSize span reader =
  let opcode = readMicroMIPSOpcode span reader 12
  if opcode = 0x3302fffe then 24UL
  else 32UL

let rec private parseMIPSStubEntries armap offset maxOffset tbl reader span =
  if offset >= maxOffset then armap
  else
    let fst = (reader: IBinReader).ReadInt32 (span = span, offset=offset)
    let snd = reader.ReadInt32 (span, offset=offset + 4)
    let thr = reader.ReadInt32 (span, offset=offset + 8)
    if (fst = 0x8f998010 (* lw t9, -32752(gp) *)
        || fst = 0xdf998010 (* ld t9, -32752(gp) *))
      && snd = 0x03e07825 (* move t7, ra *)
      && thr = 0x0320f809 (* jalr t9 *)
    then
      let insBytes = reader.ReadUInt32 (span, offset + 12)
      (* FIXME: we could just get the index from .dynamic DT_MIPS_GOTSYM *)
      let index = int (insBytes &&& 0xffffu)
      let symbol = (tbl: ELFSymbol[])[index]
      let entry =
        { FuncName = symbol.SymName
          LibraryName = Symbol.versionToLibName symbol.VerInfo
          TrampolineAddress = symbol.Addr
          TableAddress = 0UL }
      let ar = AddrRange (symbol.Addr, symbol.Addr + 15UL)
      let armap = ARMap.add ar entry armap
      parseMIPSStubEntries armap (offset + 16) maxOffset tbl reader span
    else armap

/// MIPS PLT parser.
type MIPSPLTParser (hdr, shdrs, relocInfo, symbInfo) =
  inherit PLTParser ()

  let isMIPSGOTSym t = t.DTag = DynamicTag.DT_MIPS_GOTSYM

  member __.ParseMIPSStubs toolBox =
    match Array.tryFind (fun s -> s.SecName = SecMIPSStubs) shdrs with
    | Some sec ->
      let bytes, reader = toolBox.Bytes, toolBox.Reader
      let entries = DynamicSection.readEntries toolBox shdrs
      let offset = 0
      let maxOffset = int sec.SecSize
      let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
      match Array.tryFind isMIPSGOTSym entries with
      | Some tag ->
        let n = Symbol.getDynamicSymbolSectionNumbers shdrs|> Array.head
        let tbl = symbInfo.SecNumToSymbTbls[n]
        assert (tbl.Length > int tag.DVal)
        parseMIPSStubEntries ARMap.empty offset maxOffset tbl reader span
      | None -> ARMap.empty
    | None -> ARMap.empty

  override __.ParseEntry (addr, _idx, sec, _desc, reader, span) =
    let offset = int (addr - sec.SecAddr)
    let opcode = readMicroMIPSOpcode span reader (offset + 4)
    match opcode with
    | 0x651aeb00 -> (* MIPS16 *)
      let entryAddr = reader.ReadUInt32 (span, offset + 12) |> uint64
      { EntryRelocAddr = entryAddr; NextEntryAddr = addr + 16UL }
    | 0xff220000 -> (* microMIPS no 32 *)
      let hi = uint32 (reader.ReadUInt16 (span, offset)) &&& 0x7fu
      let lo = reader.ReadUInt16 (span, offset + 2) |> uint32
      let entryAddr = ((hi ^^^ 0x40u - 0x40u) <<< 18) + (lo <<< 2)
      { EntryRelocAddr = uint64 entryAddr; NextEntryAddr = addr + 12UL }
    | opcode when opcode &&& 0xffff0000 = 0xff2f0000 -> (* microMIPS 32 *)
      let hi = reader.ReadUInt16 (span, offset + 2) |> uint32
      let lo = reader.ReadUInt16 (span, offset + 6) |> uint32
      let entryAddr =
        (((hi ^^^ 0x8000u) - 0x8000u) <<< 16) + ((lo ^^^ 0x8000u) - 0x8000u)
      { EntryRelocAddr = uint64 entryAddr; NextEntryAddr = addr + 16UL }
    | _ -> (* Regular cases. *)
      let hi = reader.ReadUInt16 (span, offset) |> uint64
      let lo = reader.ReadInt16 (span, offset + 4) |> uint64
      let entryAddr = (hi <<< 16) + lo
      { EntryRelocAddr = uint64 entryAddr; NextEntryAddr = addr + 16UL }

  override __.ParseSection (toolBox, sec, map) =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let span = ReadOnlySpan (bytes, int sec.SecOffset, int sec.SecSize)
    let headerSize = computeMIPSPLTHeaderSize span reader
    let startAddr = sec.SecAddr + headerSize
    let desc = newDesc DontCare AnyBinding false 16UL 0UL startAddr
    let sAddr, eAddr = desc.ExtraOffset, sec.SecAddr + sec.SecSize
    parseEntries __ sec span reader desc symbInfo relocInfo map eAddr sAddr

  override __.Parse toolBox =
    let pltSections = findPLTSections shdrs
    if List.isEmpty pltSections then __.ParseMIPSStubs toolBox
    else parseSections __ toolBox ARMap.empty pltSections

/// Classic PPC that uses the .plt section. Modern PPC binaries use the "glink".
type PPCClassicPLTParser (shdrs, relocInfo, symbInfo, pltHdrSize, relType) =
  inherit GeneralPLTParser (shdrs, relocInfo, symbInfo, pltHdrSize, relType)

  override __.ParseEntry (_addr, idx, _sec, _desc, _rdr, _span) =
    let nextIdx = idx + 1
    let nextEntryAddr =
      if __.Relocs.Length > nextIdx then __.Relocs[nextIdx].RelOffset
      else UInt64.MaxValue (* No more entries to parse. *)
    { EntryRelocAddr = __.Relocs[idx].RelOffset
      NextEntryAddr = nextEntryAddr }

/// PPC PLT parser.
type PPCPLTParser (hdr, shdrs, relocInfo, symbInfo) =
  inherit PLTParser ()

  override __.ParseEntry (_, _, _, _, _, _) = Utils.impossible ()

  override __.ParseSection (toolBox, sec, map) =
    let rtyp = RelocationPPC32 RelocationPPC32.R_PPC_JMP_SLOT
    let p = PPCClassicPLTParser (shdrs, relocInfo, symbInfo, 0x48UL, rtyp)
    p.ParseSection (toolBox, sec, map)

  member private __.ComputeGLinkAddrWithGOT toolBox =
    let tags = DynamicSection.readEntries toolBox shdrs
    match Array.tryFind (fun t -> t.DTag = DynamicTag.DT_PPC_GOT) tags with
    | Some tag ->
      let gotAddr = tag.DVal
      match Array.tryFind (fun s -> s.SecName = SecGOT) shdrs with
      | Some gotSection ->
        let bytes, reader = toolBox.Bytes, toolBox.Reader
        let gotElemOneOffset = (* The second elem of GOT, i.e., GOT[1] *)
          gotAddr - gotSection.SecAddr + 4UL + gotSection.SecOffset
        let gotElemOne = reader.ReadUInt32 (bytes, int gotElemOneOffset)
        if gotElemOne = 0u then None else Some (uint64 gotElemOne)
      | None -> None
    | None -> None

  member private __.ComputeGLinkAddrWithPLT toolBox =
    match Array.tryFind (fun s -> s.SecName = SecPLT) shdrs with
    | Some sec -> (* Get the glink address from the first entry of PLT *)
      let bytes, reader = toolBox.Bytes, toolBox.Reader
      let glinkVMA = reader.ReadUInt32 (bytes, int sec.SecOffset)
      if glinkVMA = 0u then None else Some (uint64 glinkVMA)
    | None -> None

  member private __.ComputePLTEntryDelta (span, reader, stubOff, delta) =
    let lastPLTEntryOffset = stubOff - delta
    let ins1 = (reader: IBinReader).ReadUInt32 (span=span,
                                                offset=lastPLTEntryOffset)
    let ins2 = reader.ReadUInt32 (span, lastPLTEntryOffset + 4)
    let ins3 = reader.ReadUInt32 (span, lastPLTEntryOffset + 8)
    let ins4 = reader.ReadUInt32 (span, lastPLTEntryOffset + 12)
    let isNonPICGlinkStub =
      ((ins1 &&& 0xffff0000u) = 0x3d600000u) (* lis r11, ... *)
      && ((ins2 &&& 0xffff0000u) = 0x816b0000u) (* lwz r11, ... *)
      && (ins3 = 0x7d6903a6u) (* mtctr r11 *)
      && (ins4 = 0x4e800420u) (* bctr *)
    if isNonPICGlinkStub then Some delta
    elif delta < 32 then
      __.ComputePLTEntryDelta (span, reader, stubOff, delta + 8)
    else None

  member private __.ReadEntryLoop relocs delta idx map addr =
    if idx >= 0 then
      let reloc = (relocs: RelocationEntry[])[idx]
      let ar = AddrRange (addr, addr + delta - 1UL)
      let entry = makePLTEntry symbInfo addr addr reloc
      let map = ARMap.add ar entry map
      __.ReadEntryLoop relocs delta (idx - 1) map (addr - delta)
    else map

  /// Read from the last PLT entry to the first. This is possible because we
  /// have computed the delta between the last entry to the glink stub.
  member private __.ReadPLTEntriesBackwards (glinkAddr, delta, count) =
    let rtype = RelocationPPC32 RelocationPPC32.R_PPC_JMP_SLOT
    let relocs =
      relocInfo.RelocByAddr.Values
      |> Seq.filter (fun r -> r.RelType = rtype)
      |> Seq.toArray
    assert (relocs.Length = count)
    let addr = glinkAddr - delta
    __.ReadEntryLoop relocs (uint64 delta) (count - 1) ARMap.empty addr

  member private __.ReadPLTWithGLink (toolBox, glinkAddr) =
    let relaPltSecOpt = Array.tryFind (fun s -> s.SecName = SecRelaPLT) shdrs
    let glinkSecOpt =
      Array.tryFind (fun s -> s.SecAddr <= glinkAddr
                              && glinkAddr < s.SecAddr + s.SecSize) shdrs
    match glinkSecOpt, relaPltSecOpt with
    | Some glinkSec, Some relaSec ->
      let bytes, reader = toolBox.Bytes, toolBox.Reader
      let glinkSecAddr = glinkSec.SecAddr
      let glinkOffset, glinkSize = int glinkSec.SecOffset, int glinkSec.SecSize
      let glinkSec = ReadOnlySpan (bytes, glinkOffset, glinkSize)
      let stubOff = glinkAddr - glinkSecAddr |> int
      let count = relaSec.SecSize / 12UL |> int (* Each entry has 12 bytes. *)
      match __.ComputePLTEntryDelta (glinkSec, reader, stubOff, 16) with
      | Some delta ->
        __.ReadPLTEntriesBackwards (glinkAddr, uint64 delta, count)
      | None -> ARMap.empty
    | _ -> ARMap.empty

  member private __.ParseWithGLink toolBox =
    match __.ComputeGLinkAddrWithGOT toolBox with
    | Some glinkAddr -> __.ReadPLTWithGLink (toolBox, glinkAddr)
    | None ->
      match __.ComputeGLinkAddrWithPLT toolBox with
      | Some glinkAddr -> __.ReadPLTWithGLink (toolBox, glinkAddr)
      | None -> ARMap.empty

  override __.Parse toolBox =
    match Array.tryFind (fun s -> s.SecName = SecPLT) shdrs with
    | Some sec when sec.SecFlags.HasFlag SectionFlag.SHF_EXECINSTR ->
      (* The given binary uses the classic format. *)
      parseSections __ toolBox ARMap.empty [ sec ]
    | _ -> __.ParseWithGLink toolBox

/// This will simply return an empty map.
type NullPLTParser () =
  inherit PLTParser ()
  override __.ParseEntry (_, _, _, _, _, _) = Utils.impossible ()
  override __.ParseSection (_, _, _) = Utils.impossible ()
  override __.Parse _ = ARMap.empty

let initPLTParser hdr shdrs relocInfo symbInfo =
  match hdr.MachineType with
  | Arch.IntelX86 -> X86PLTParser (shdrs, relocInfo, symbInfo) :> PLTParser
  | Arch.IntelX64 -> X64PLTParser (shdrs, relocInfo, symbInfo) :> PLTParser
  | Arch.ARMv7 | Arch.AARCH32 ->
    ARMv7PLTParser (shdrs, relocInfo, symbInfo) :> PLTParser
  | Arch.AARCH64 ->
    AARCH64PLTParser (shdrs, relocInfo, symbInfo) :> PLTParser
  | Arch.MIPS32 | Arch.MIPS64 ->
    MIPSPLTParser (hdr, shdrs, relocInfo, symbInfo) :> PLTParser
  | Arch.PPC32 ->
    PPCPLTParser (hdr, shdrs, relocInfo, symbInfo) :> PLTParser
  | Arch.RISCV64 ->
    let rtype = RelocationRISCV RelocationRISCV.R_RISCV_JUMP_SLOT
    GeneralPLTParser (shdrs, relocInfo, symbInfo, 32UL, rtype) :> PLTParser
  | Arch.SH4 ->
    let rtype = RelocationSH4 RelocationSH4.R_SH_JMP_SLOT
    GeneralPLTParser (shdrs, relocInfo, symbInfo, 28UL, rtype) :> PLTParser
  | _ -> NullPLTParser () :> PLTParser

let parse toolBox shdrs symbInfo relocInfo =
  let parser = initPLTParser toolBox.Header shdrs relocInfo symbInfo
  parser.Parse toolBox
