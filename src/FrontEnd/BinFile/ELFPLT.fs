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

type CodeKind =
  | PIC
  | NonPIC
  | DontCare

type PLTLinkMethod =
  | LazyBinding
  | EagerBinding

type PLTEntryInfo = {
  EntryRelocAddr: Addr
  NextEntryAddr: Addr
}

type PLTDescriptor = {
  /// PLT start address.
  StartAddr: Addr
  /// PIC or non-PIC.
  CodeKind: CodeKind
  /// Lazy vs. Non-lazy (eager) binding.
  LinkMethod: PLTLinkMethod
  /// Is secondary PLT?
  IsSecondary: bool
  /// Entry size of the PLT.
  EntrySize: uint64
  /// Offset from a start of a PLT entry to the index to the GOT.
  GOTOffset: Addr
  /// Size of the instruction that refers to the GOT.
  InstrSize: Addr
  /// Compute a EntryInfo from (Entry index, current entry address,
  /// PLTDescriptor, BinReader, gotBaseAddr). Each PLT has its own retriever.
  InfoRetriever: IPLTInfoRetriever
}

and IPLTInfoRetriever =
  abstract Get:
    Addr
    * int
    * PLTDescriptor
    * ByteSpan
    * IBinReader
    * ELFSection
    * Addr
    -> Result<PLTEntryInfo, ErrorCase>

type PLTType =
  /// The regular PLT.
  | PLT of desc: PLTDescriptor
  /// The PLT pattern is unknown.
  | UnknownPLT

let newPLT start kind lm isSecondary size gotoff inslen retriever =
  PLT { StartAddr = start
        CodeKind = kind
        LinkMethod = lm
        IsSecondary = isSecondary
        EntrySize = size
        GOTOffset = gotoff
        InstrSize = inslen
        InfoRetriever = retriever }

let isPLTSectionName name =
  name = ".plt" || name = ".plt.sec" || name = ".plt.got" || name = ".plt.bnd"

let isSecondaryLazy desc =
  desc.IsSecondary && desc.LinkMethod = LazyBinding

let tryFindGOTAddr sections =
  match Map.tryFind ".got.plt" sections.SecByName with
  | Some s -> Some s.SecAddr
  | None ->
    match Map.tryFind ".got" sections.SecByName with
    | Some s -> Some s.SecAddr
    | None -> None

let findFirstPLTGOTAddr reloc sections =
  match Map.tryFind ".rel.plt" sections.SecByName with
  | Some s ->
    reloc.RelocByAddr.Values
    |> Seq.fold (fun minval r ->
      if r.RelSecNumber = s.SecNum then
        if r.RelOffset < minval then r.RelOffset else minval
      else minval) UInt64.MaxValue
  | None -> 0UL

let findFirstJumpSlot reloc =
  reloc.RelocByAddr.Values
  |> Seq.fold (fun minval r ->
    match r.RelType with
    | RelocationARMv8 RelocationARMv8.R_AARCH64_JUMP_SLOT ->
      if r.RelOffset < minval then r.RelOffset else minval
    | _ -> minval) UInt64.MaxValue

let findGOTBase arch reloc sections =
  let bAddr = tryFindGOTAddr sections
  match arch with
  | Arch.IntelX86
  | Arch.IntelX64 -> bAddr
  | Arch.ARMv7
  | Arch.AARCH32 ->
    bAddr |> Option.map (fun _ -> findFirstPLTGOTAddr reloc sections)
  | Arch.AARCH64 ->
    bAddr |> Option.map (fun _ -> findFirstJumpSlot reloc)
  | _ -> bAddr

let filterPLTSections sections =
  sections.SecByName |> Map.fold (fun acc _ s ->
    if isPLTSectionName s.SecName then s :: acc else acc) []
  |> List.rev (* .plt, .plt.got, .plt.sec *)

type X86NonPICRetriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, _) =
      let addrDiff = int (addr - typ.StartAddr)
      let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
      { EntryRelocAddr = r.ReadInt32 (span, offset) |> uint64
        NextEntryAddr = addr + typ.EntrySize } |> Ok

type X86PICRetriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, baseAddr) =
      let addrDiff = int (addr - typ.StartAddr)
      let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
      { EntryRelocAddr = (r.ReadInt32 (span, offset) |> uint64) + baseAddr
        NextEntryAddr = addr + typ.EntrySize } |> Ok

let x86PICLazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let zeroEntry = (* push indirect addr; jmp; *)
    [| OneByte 0xffuy; OneByte 0xb3uy; OneByte 0x04uy; AnyByte; AnyByte; AnyByte
       OneByte 0xffuy; OneByte 0xa3uy; OneByte 0x08uy; AnyByte; AnyByte; AnyByte
    |]
  let ibtEntry = (* (Ind-Branch-Tracking) endbr32; push; jmp rel; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy;
       OneByte 0x68uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xe9uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  if BytePattern.matchSpan zeroEntry plt then
    let isIBT = BytePattern.matchSpan ibtEntry (plt.Slice 16)
    let gotoff = if isIBT then 6UL else 2UL
    let retriever = X86PICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr PIC LazyBinding isIBT 16UL gotoff 0UL retriever |> Some
  else None

let x86NonPICLazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let zeroEntry = (* push absolute addr; jmp; *)
    [| OneByte 0xffuy; OneByte 0x35uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte |]
  let ibtEntry = (* (Ind-Branch-Tracking) endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy;
       OneByte 0x68uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xe9uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  if BytePattern.matchSpan zeroEntry plt then
    let isIBT = BytePattern.matchSpan ibtEntry (plt.Slice 16)
    let gotoff = if isIBT then 6UL else 2UL
    let retriever = X86NonPICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr NonPIC LazyBinding isIBT 16UL gotoff 0UL retriever
    |> Some
  else None

let x86PICNonLazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let entry = (* jmp indirect addr; nop *)
    [| OneByte 0xffuy; OneByte 0xa3uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy
       OneByte 0xffuy; OneByte 0xa3uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    let retriever = X86PICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr PIC EagerBinding false 8UL 2UL 0UL retriever |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    let retriever = X86PICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr PIC EagerBinding true 8UL 6UL 0UL retriever |> Some
  else None

let x86NonPICNonLazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let entry = (* jmp indirect addr; nop *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    let retriever = X86NonPICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr NonPIC EagerBinding false 8UL 2UL 0UL retriever |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    let retriever = X86NonPICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr NonPIC EagerBinding true 8UL 6UL 0UL retriever |> Some
  else None

type X64Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, _) =
      let addrDiff = int (addr - typ.StartAddr)
      let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
      let v = r.ReadInt32 (span, offset)
      { EntryRelocAddr = addr + typ.InstrSize + uint64 v
        NextEntryAddr = addr + typ.EntrySize } |> Ok

let x64Lazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let zeroEntry = (* push [got+8]; jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x35uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte |]
  let ibtZeroEntry = (* (Ind-Branch-Tracking) push [got+8]; bnd jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x35uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr64; push imm; bnd jmp rel; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfauy
       OneByte 0x68uy; AnyByte; AnyByte; AnyByte; AnyByte
       OneByte 0xf2uy; OneByte 0xe9uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte |]
  if BytePattern.matchSpan zeroEntry plt then
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare LazyBinding false 16UL 2UL 6UL retriever |> Some
  elif BytePattern.matchSpan ibtZeroEntry plt then
    let off, inssz =
      if BytePattern.matchSpan ibtEntry (plt.Slice 16) then 7UL, 11UL
      else 3UL, 7UL (* bnd *)
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare LazyBinding true 16UL off inssz retriever
    |> Some
  else None

let x64NonLazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let entry = (* jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare EagerBinding false 8UL 2UL 6UL retriever |> Some
  else None

let x64IBT (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let bndEntry = (* bnd jmp [got+n]] *)
    [| OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr64; bnd jmp [got+n]] *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfauy
       OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy;
       AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]
  if BytePattern.matchSpan bndEntry plt then
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare EagerBinding true 16UL 3UL 7UL retriever |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare EagerBinding true 16UL 7UL 11UL retriever
    |> Some
  else None

let computeARMPLTEntrySize (span: ByteSpan) reader sec headerSize delta =
  if (reader: IBinReader).ReadInt32 (span, int sec.SecOffset) = 0xf8dfb500 then
    Ok 16UL (* THUMB-only *)
  else
    let offset = int sec.SecOffset + int headerSize + delta
    let size = if reader.ReadInt16 (span, offset) = 0x4778s then 4 else 0
    let offset = offset + size
    let ins = reader.ReadInt32 (span, offset) &&& 0xffffff00 (* strip imm *)
    if (headerSize = 16UL && ins = 0xe28fc600) || ins = 0xe28fc200 then
      Ok (uint64 (size + 16))
    elif ins = 0xe28fc600 then Ok (uint64 (size + 12))
    else Error ErrorCase.InvalidFileFormat

/// Get the size of the header of PLT (PLT Zero)
let computeARMPLTHeaderSize (span: ByteSpan) reader sec =
  let v = (reader: IBinReader).ReadInt32 (span, int sec.SecOffset)
  if v = 0xe52de004 then (* str lr, [sp, #-4] *)
    let v = reader.ReadInt32 (span, int sec.SecOffset + 16)
    if v = 0xe28fc600 then (* add ip, pc, #0, 12 *) Some 16UL
    else Some 20UL
  elif v = 0xf8dfb500 then (* push {lr} *) Some 16UL
  else None

type ARMv7Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, idx, typ, span: ByteSpan, r, sec, baseAddr) =
      let addrDiff = int (addr - typ.StartAddr)
      let hdrSize = computeARMPLTHeaderSize span r sec |> Option.get
      match computeARMPLTEntrySize span r sec hdrSize addrDiff with
      | Ok entSize ->
        { EntryRelocAddr = baseAddr + uint64 (idx * 4)
          NextEntryAddr = addr + uint64 entSize } |> Ok
      | Error _ -> (* Just ignore this entry using the default entry size 16. *)
        { EntryRelocAddr = 0UL; NextEntryAddr = addr + 16UL } |> Ok

let armv7PLT span reader sec =
  match computeARMPLTHeaderSize span reader sec with
  | Some headerSize ->
    let startAddr = sec.SecAddr + headerSize
    if reader.ReadInt32 (span, int sec.SecOffset) = 0xf8dfb500 then
      (* push {lr} *)
      let retriever = ARMv7Retriever () :> IPLTInfoRetriever
      newPLT startAddr DontCare LazyBinding false 16UL 4UL 4UL retriever
    else
      match computeARMPLTEntrySize span reader sec headerSize 0 with
      | Ok sz ->
        let retriever = ARMv7Retriever () :> IPLTInfoRetriever
        newPLT startAddr DontCare LazyBinding false sz 4UL 4UL retriever
      | Error _ -> UnknownPLT
  | None -> UnknownPLT

type AArch64Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, idx, _, _, _reader, _sec, baseAddr) =
      { EntryRelocAddr = baseAddr + uint64 (idx * 8)
        NextEntryAddr = addr + 16UL } |> Ok

let aarchPLT _reader sec =
  let startAddr = sec.SecAddr + 32UL
  let retriever = AArch64Retriever () :> IPLTInfoRetriever
  newPLT startAddr DontCare LazyBinding false 16UL 0UL 4UL retriever

let readMicroMIPSOpcode (span: ByteSpan) (reader: IBinReader) offset =
  let v1 = reader.ReadUInt16 (span, offset) |> uint32
  let v2 = reader.ReadUInt16 (span, offset + 2) |> uint32
  int (v1 <<< 16 ||| v2)

let computeMIPSPLTHeaderSize span reader sec =
  let offset = int sec.SecOffset + 12
  let opcode = readMicroMIPSOpcode span reader offset
  if opcode = 0x3302fffe then Some 24UL
  else Some 32UL

type MIPSRetriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, _, span: ByteSpan, r: IBinReader, sec, _) =
      let offset = int (addr - sec.SecAddr + sec.SecOffset)
      let opcode = readMicroMIPSOpcode span r (offset + 4)
      match opcode with
      | 0x651aeb00 -> (* MIPS16 *)
        let entryAddr = r.ReadUInt32 (span, offset + 12) |> uint64
        Ok { EntryRelocAddr = entryAddr; NextEntryAddr = addr + 16UL }
      | 0xff220000 -> (* microMIPS no 32 *)
        let hi = uint32 (r.ReadUInt16 (span, offset)) &&& 0x7fu
        let lo = r.ReadUInt16 (span, offset + 2) |> uint32
        let entryAddr = ((hi ^^^ 0x40u - 0x40u) <<< 18) + (lo <<< 2)
        Ok { EntryRelocAddr = uint64 entryAddr; NextEntryAddr = addr + 12UL }
      | opcode when opcode &&& 0xffff0000 = 0xff2f0000 -> (* microMIPS 32 *)
        let hi = r.ReadUInt16 (span, offset + 2) |> uint32
        let lo = r.ReadUInt16 (span, offset + 6) |> uint32
        let entryAddr =
          (((hi ^^^ 0x8000u) - 0x8000u) <<< 16) + ((lo ^^^ 0x8000u) - 0x8000u)
        Ok { EntryRelocAddr = uint64 entryAddr; NextEntryAddr = addr + 16UL }
      | _ -> (* Regular cases. *)
        let hi = r.ReadUInt16 (span, offset) |> uint64
        let lo = r.ReadInt16 (span, offset + 4) |> uint64
        let entryAddr = (hi <<< 16) + lo
        Ok { EntryRelocAddr = uint64 entryAddr; NextEntryAddr = addr + 16UL }

let mipsPLT span reader sec =
  match computeMIPSPLTHeaderSize span reader sec with
  | Some headerSize ->
    let startAddr = sec.SecAddr + headerSize
    let retriever = MIPSRetriever () :> IPLTInfoRetriever
    newPLT startAddr DontCare LazyBinding false 16UL 0UL 4UL retriever
  | None -> UnknownPLT

type SH4Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, _) =
      let offset = int (addr - sec.SecAddr + sec.SecOffset) + 24
      Ok { EntryRelocAddr = r.ReadInt32 (span, offset) |> uint64
           NextEntryAddr = addr + typ.EntrySize }

let sh4PLT sec =
  let retriever = SH4Retriever () :> IPLTInfoRetriever
  newPLT (sec.SecAddr + 28UL) DontCare LazyBinding false 28UL 0UL 2UL retriever

let findX86PLTType span sec =
  (* This is dirty, but we cannot use a monad due to Span. *)
  match x86PICLazy span sec with
  | Some t -> t
  | None ->
    match x86NonPICLazy span sec with
    | Some t -> t
    | None ->
      match x86PICNonLazy span sec with
      | Some t -> t
      | None ->
        match x86NonPICNonLazy span sec with
        | Some t -> t
        | None -> UnknownPLT

let findX64PLTType span sec =
  (* This is dirty, but we cannot use a monad due to Span. *)
  match x64Lazy span sec with
  | Some t -> t
  | None ->
    match x64NonLazy span sec with
    | Some t -> t
    | None ->
      match x64IBT span sec with
      | Some t -> t
      | None -> UnknownPLT

type GeneralRetriever (relocs: RelocationEntry[]) =
  interface IPLTInfoRetriever with
    member __.Get (addr, idx, typ, _, _, _, _) =
      Ok { EntryRelocAddr = relocs[idx].RelOffset
           NextEntryAddr = addr + typ.EntrySize }

let createGeneralPLTDescriptor relocInfo rsec pltHeaderSize sec rtyp =
  let count = rsec.SecSize / rsec.SecEntrySize (* number of PLT entries *)
  let pltEntrySize = (sec.SecSize - pltHeaderSize) / count
  let addr = sec.SecAddr + pltHeaderSize
  let relocs =
    relocInfo.RelocByAddr.Values
    |> Seq.filter (fun r -> r.RelType = rtyp)
    |> Seq.toArray
  assert (relocs.Length = int count)
  let retriever = GeneralRetriever (relocs) :> IPLTInfoRetriever
  newPLT addr DontCare LazyBinding false pltEntrySize 0UL 0UL retriever

let findGeneralPLTType relocInfo (secInfo: SectionInfo) pltHeaderSize sec rtyp =
  match Map.tryFind ".rel.plt" secInfo.SecByName with
  | Some rsec ->
    createGeneralPLTDescriptor relocInfo rsec pltHeaderSize sec rtyp
  | None ->
    match Map.tryFind ".rela.plt" secInfo.SecByName with
    | Some rsec ->
      createGeneralPLTDescriptor relocInfo rsec pltHeaderSize sec rtyp
    | None -> UnknownPLT

let findPLTType arch reloc span reader secInfo sec =
  match arch with
  | Arch.IntelX86 -> findX86PLTType span sec
  | Arch.IntelX64 -> findX64PLTType span sec
  | Arch.ARMv7
  | Arch.AARCH32 -> armv7PLT span reader sec
  | Arch.AARCH64 -> aarchPLT reader sec
  | Arch.MIPS32
  | Arch.MIPS64 -> mipsPLT span reader sec
  | Arch.SH4 -> sh4PLT sec
  | Arch.PPC32 ->
    if sec.SecFlags.HasFlag SectionFlag.SHFExecInstr then
      (* let rtyp = RelocationPPC32 RelocationPPC32.R_PPC_JMP_SLOT *)
      Utils.futureFeature () (* TODO: call findGeneralPLTType here. *)
    else UnknownPLT
  | Arch.RISCV64 ->
    let rtyp = RelocationRISCV RelocationRISCV.R_RISCV_JUMP_SLOT
    findGeneralPLTType reloc secInfo 32UL sec rtyp
  | _ -> Utils.futureFeature ()

let rec private
  parsePLTLoop bAddr t rel symbs span reader s eAddr idx map addr =
  if addr >= eAddr then map
  else
    let info =
      t.InfoRetriever.Get (addr, idx, t, span, reader, s, bAddr) |> Result.get
    let nextAddr = info.NextEntryAddr
    let ar = AddrRange (addr, nextAddr - 1UL)
    match rel.RelocByAddr.TryGetValue info.EntryRelocAddr with
    | true, r ->
      let entry =
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
            TableAddress = info.EntryRelocAddr }
      let map = ARMap.add ar entry map
      parsePLTLoop bAddr t rel symbs span reader s eAddr (idx + 1) map nextAddr
    | _ ->
      parsePLTLoop bAddr t rel symbs span reader s eAddr (idx + 1) map nextAddr

let private parsePLT baseAddr typ reloc symbs span reader (s: ELFSection) map =
  let startAddr, endAddr = typ.StartAddr, s.SecAddr + s.SecSize
  parsePLTLoop baseAddr typ reloc symbs span reader s endAddr 0 map startAddr

let rec loopSections map baseAddr arch reloc symbs span reader secInfo
  = function
  | sec :: rest ->
    match findPLTType arch reloc span reader secInfo sec with
    | PLT desc ->
      let map =
        if isSecondaryLazy desc then map (* Ignore secondary lazy plt. *)
        else parsePLT baseAddr desc reloc symbs span reader sec map
      loopSections map baseAddr arch reloc symbs span reader secInfo rest
    | _ -> map
  | [] -> map

let rec parseMIPSStubEntries armap offset maxOffset tbl span reader =
  if offset >= maxOffset then armap
  else
    let fst = (reader: IBinReader).ReadInt32 (span = span, offset = int offset)
    let snd = reader.ReadInt32 (span, offset = int offset + 4)
    let thr = reader.ReadInt32 (span, offset = int offset + 8)
    if fst = 0x8f998010 (* lw t9, -32752(gp) *)
      && snd = 0x03e07825 (* move t7, ra *)
      && thr = 0x0320f809 (* jalr t9 *)
    then
      let insBytes = reader.ReadUInt32 (span, int offset + 12)
      let index = int (insBytes &&& 0xffffu)
      let symbol = (tbl: ELFSymbol[])[index]
      let entry =
        { FuncName = symbol.SymName
          LibraryName = Symbol.versionToLibName symbol.VerInfo
          TrampolineAddress = symbol.Addr
          TableAddress = 0UL }
      let ar = AddrRange (symbol.Addr, symbol.Addr + 15UL)
      let armap = ARMap.add ar entry armap
      parseMIPSStubEntries armap (offset + 16UL) maxOffset tbl span reader
    else armap

let parseMIPSStubs secInfo symbs span reader =
  match Map.tryFind ".MIPS.stubs" secInfo.SecByName with
  | Some sec ->
    let tags = Section.getDynamicSectionEntries span reader secInfo
    let offset = sec.SecOffset
    let maxOffset = offset + sec.SecSize
    match List.tryFind (fun t -> t.DTag = DynamicTag.DT_MIPS_GOTSYM) tags with
    | Some tag ->
      let n = secInfo.DynSymSecNums |> List.head
      let tbl = symbs.SecNumToSymbTbls[n]
      assert (tbl.Length > int tag.DVal)
      parseMIPSStubEntries ARMap.empty offset maxOffset tbl span reader
    | None -> ARMap.empty
  | None -> ARMap.empty

let parse arch secInfo reloc symbs span reader =
  let baseAddr = findGOTBase arch reloc secInfo
  let sections = filterPLTSections secInfo
  match baseAddr, sections with
  | Some baseAddr, secs when not (List.isEmpty secs) ->
    loopSections ARMap.empty baseAddr arch reloc symbs span reader secInfo secs
  | _ ->
    if arch = Architecture.MIPS32 || arch = Architecture.MIPS64 then
      parseMIPSStubs secInfo symbs span reader
    else ARMap.empty
