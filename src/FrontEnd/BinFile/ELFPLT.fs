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
  EntrySize: int
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

let gotAddr sections =
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
    | RelocationARMv8 RelocationARMv8.RelocAARCH64JmpSlot ->
      if r.RelOffset < minval then r.RelOffset else minval
    | _ -> minval) UInt64.MaxValue

let findGOTBase arch reloc sections =
  let got = gotAddr sections
  match arch with
  | Arch.IntelX86
  | Arch.IntelX64 -> got
  | Arch.ARMv7
  | Arch.AARCH32 ->
    got |> Option.map (fun _ -> findFirstPLTGOTAddr reloc sections)
  | Arch.AARCH64 ->
    got |> Option.map (fun _ -> findFirstJumpSlot reloc)
  | _ -> got

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
        NextEntryAddr = addr + uint64 typ.EntrySize } |> Ok

type X86PICRetriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, gotBase) =
      let addrDiff = int (addr - typ.StartAddr)
      let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
      { EntryRelocAddr = (r.ReadInt32 (span, offset) |> uint64) + gotBase
        NextEntryAddr = addr + uint64 typ.EntrySize } |> Ok

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
    newPLT sec.SecAddr PIC LazyBinding isIBT 16 gotoff 0UL retriever |> Some
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
    newPLT sec.SecAddr NonPIC LazyBinding isIBT 16 gotoff 0UL retriever |> Some
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
    newPLT sec.SecAddr PIC EagerBinding false 8 2UL 0UL retriever |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    let retriever = X86PICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr PIC EagerBinding true 8 6UL 0UL retriever |> Some
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
    newPLT sec.SecAddr NonPIC EagerBinding false 8 2UL 0UL retriever |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    let retriever = X86NonPICRetriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr NonPIC EagerBinding true 8 6UL 0UL retriever |> Some
  else None

type X64Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, _) =
      let addrDiff = int (addr - typ.StartAddr)
      let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
      let v = r.ReadInt32 (span, offset)
      { EntryRelocAddr = addr + typ.InstrSize + uint64 v
        NextEntryAddr = addr + uint64 typ.EntrySize } |> Ok

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
    newPLT sec.SecAddr DontCare LazyBinding false 16 2UL 6UL retriever |> Some
  elif BytePattern.matchSpan ibtZeroEntry plt then
    let off, inssz =
      if BytePattern.matchSpan ibtEntry (plt.Slice 16) then 7UL, 11UL
      else 3UL, 7UL (* bnd *)
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare LazyBinding true 16 off inssz retriever |> Some
  else None

let x64NonLazy (span: ByteSpan) sec =
  let plt = span.Slice (int sec.SecOffset, int sec.SecSize)
  let entry = (* jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare EagerBinding false 8 2UL 6UL retriever |> Some
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
    newPLT sec.SecAddr DontCare EagerBinding true 16 3UL 7UL retriever |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    let retriever = X64Retriever () :> IPLTInfoRetriever
    newPLT sec.SecAddr DontCare EagerBinding true 16 7UL 11UL retriever |> Some
  else None

let computeARMPLTEntrySize (span: ByteSpan) reader sec headerSize delta =
  if (reader: IBinReader).ReadInt32 (span, int sec.SecOffset) = 0xf8dfb500 then
    Ok 16 (* THUMB-only *)
  else
    let offset = int sec.SecOffset + int headerSize + delta
    let size = if reader.ReadInt16 (span, offset) = 0x4778s then 4 else 0
    let offset = offset + size
    let ins = reader.ReadInt32 (span, offset) &&& 0xffffff00 (* strip imm *)
    if (headerSize = 16UL && ins = 0xe28fc600) || ins = 0xe28fc200 then
      Ok (size + 16)
    elif ins = 0xe28fc600 then Ok (size + 12)
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
    member __.Get (addr, idx, typ, span: ByteSpan, r, sec, gotBase) =
      let addrDiff = int (addr - typ.StartAddr)
      let hdrSize = computeARMPLTHeaderSize span r sec |> Option.get
      match computeARMPLTEntrySize span r sec hdrSize addrDiff with
      | Ok entSize ->
        { EntryRelocAddr = gotBase + uint64 (idx * 4)
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
      newPLT startAddr DontCare LazyBinding false 16 4UL 4UL retriever
    else
      match computeARMPLTEntrySize span reader sec headerSize 0 with
      | Ok sz ->
        let retriever = ARMv7Retriever () :> IPLTInfoRetriever
        newPLT startAddr DontCare LazyBinding false sz 4UL 4UL retriever
      | Error _ -> UnknownPLT
  | None -> UnknownPLT

type AArch64Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, idx, _, _, _reader, _sec, gotBase) =
      { EntryRelocAddr = gotBase + uint64 (idx * 8)
        NextEntryAddr = addr + 16UL } |> Ok

let aarchPLT _reader sec =
  let startAddr = sec.SecAddr + 32UL
  let retriever = AArch64Retriever () :> IPLTInfoRetriever
  newPLT startAddr DontCare LazyBinding false 16 0UL 4UL retriever

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
    newPLT startAddr DontCare LazyBinding false 16 0UL 4UL retriever
  | None -> UnknownPLT

type SH4Retriever () =
  interface IPLTInfoRetriever with
    member __.Get (addr, _, typ, span: ByteSpan, r: IBinReader, sec, _) =
      let offset = int (addr - sec.SecAddr + sec.SecOffset) + 24
      Ok { EntryRelocAddr = r.ReadInt32 (span, offset) |> uint64
           NextEntryAddr = addr + uint64 typ.EntrySize }

let sh4PLT sec =
  let retriever = SH4Retriever () :> IPLTInfoRetriever
  newPLT (sec.SecAddr + 28UL) DontCare LazyBinding false 28 0UL 2UL retriever

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

let findPLTType arch span reader sec =
  match arch with
  | Arch.IntelX86 -> findX86PLTType span sec
  | Arch.IntelX64 -> findX64PLTType span sec
  | Arch.ARMv7
  | Arch.AARCH32 -> armv7PLT span reader sec
  | Arch.AARCH64 -> aarchPLT reader sec
  | Arch.MIPS1
  | Arch.MIPS2
  | Arch.MIPS3
  | Arch.MIPS32
  | Arch.MIPS32R2
  | Arch.MIPS32R6
  | Arch.MIPS4
  | Arch.MIPS5
  | Arch.MIPS64
  | Arch.MIPS64R2
  | Arch.MIPS64R6 -> mipsPLT span reader sec
  | Arch.SH4 -> sh4PLT sec
  | _ -> Utils.futureFeature ()

let rec private parsePLTLoop gotBase typ rel span reader s eAddr idx map addr =
  if addr >= eAddr then map
  else
    let info =
      typ.InfoRetriever.Get (addr, idx, typ, span, reader, s, gotBase)
      |> Result.get
    // printfn "%x -> %x" addr info.EntryRelocAddr
    let nextAddr = info.NextEntryAddr
    let ar = AddrRange (addr, nextAddr - 1UL)
    match rel.RelocByAddr.TryGetValue info.EntryRelocAddr with
    | true, r when r.RelSymbol.IsSome ->
      let symb = Option.get r.RelSymbol
      let symb = { symb with Addr = r.RelOffset }
      let map = ARMap.add ar symb map
      parsePLTLoop gotBase typ rel span reader s eAddr (idx + 1) map nextAddr
    | _ ->
      parsePLTLoop gotBase typ rel span reader s eAddr (idx + 1) map nextAddr

let private parsePLT gotBase typ reloc span reader (s: ELFSection) map =
  let startAddr, endAddr = typ.StartAddr, s.SecAddr + s.SecSize
  parsePLTLoop gotBase typ reloc span reader s endAddr 0 map startAddr

let rec loopSections map gotBase arch reloc span reader = function
  | sec :: rest ->
    match findPLTType arch span reader sec with
    | PLT desc ->
      let map =
        if isSecondaryLazy desc then map (* Ignore secondary lazy plt. *)
        else parsePLT gotBase desc reloc span reader sec map
      loopSections map gotBase arch reloc span reader rest
    | _ -> map
  | [] -> map

let parse arch sections reloc span reader =
  let gotBase = findGOTBase arch reloc sections
  let sections = filterPLTSections sections
  match gotBase with
  | Some gotBase ->
    loopSections ARMap.empty gotBase arch reloc span reader sections
  | _ -> ARMap.empty
