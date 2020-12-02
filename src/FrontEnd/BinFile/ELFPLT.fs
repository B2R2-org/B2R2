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
open B2R2.Monads.OrElse

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
  /// PLTDescriptor, BinReader, gotBaseAddr). Each PLT has its own getter.
  InfoGetter:
    Addr
    -> int
    -> PLTDescriptor
    -> BinReader
    -> ELFSection
    -> Addr
    -> Result<PLTEntryInfo, ErrorCase>
}

type PLTType =
  /// The regular PLT.
  | PLT of desc: PLTDescriptor
  /// The PLT pattern is unknown.
  | UnknownPLT

let newPLT start kind lm isSecondary size gotoff inslen getter =
  PLT { StartAddr = start
        CodeKind = kind
        LinkMethod = lm
        IsSecondary = isSecondary
        EntrySize = size
        GOTOffset = gotoff
        InstrSize = inslen
        InfoGetter = getter }

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
    reloc.RelocByAddr
    |> Map.fold (fun minval addr r ->
      if r.RelSecNumber = s.SecNum then
        if r.RelOffset < minval then r.RelOffset else minval
      else minval) UInt64.MaxValue
  | None -> 0UL

let findFirstJumpSlot reloc sections =
  reloc.RelocByAddr
  |> Map.fold (fun minval addr r ->
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
    got |> Option.map (fun _ -> findFirstJumpSlot reloc sections)
  | _ -> got

let filterPLTSections sections =
  sections.SecByName |> Map.fold (fun acc _ s ->
    if isPLTSectionName s.SecName then s :: acc else acc) []
  |> List.rev (* .plt, .plt.got, .plt.sec *)

let x86NonPICGetter addr _idx typ (reader: BinReader) sec _gotBase =
  let addrDiff = int (addr - typ.StartAddr)
  let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
  { EntryRelocAddr = reader.PeekInt32 offset |> uint64
    NextEntryAddr = addr + uint64 typ.EntrySize } |> Ok

let x86PICGetter addr _idx typ (reader: BinReader) sec gotBase =
  let addrDiff = int (addr - typ.StartAddr)
  let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
  { EntryRelocAddr = (reader.PeekInt32 offset |> uint64) + gotBase
    NextEntryAddr = addr + uint64 typ.EntrySize } |> Ok

let x86PICLazy (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
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
    newPLT sec.SecAddr PIC LazyBinding isIBT 16 gotoff 0UL x86PICGetter |> Some
  else None

let x86NonPICLazy (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
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
    newPLT sec.SecAddr NonPIC LazyBinding isIBT 16 gotoff 0UL x86NonPICGetter
    |> Some
  else None

let x86PICNonLazy (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
  let entry = (* jmp indirect addr; nop *)
    [| OneByte 0xffuy; OneByte 0xa3uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy
       OneByte 0xffuy; OneByte 0xa3uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    newPLT sec.SecAddr PIC EagerBinding false 8 2UL 0UL x86PICGetter |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    newPLT sec.SecAddr PIC EagerBinding true 8 6UL 0UL x86PICGetter |> Some
  else None

let x86NonPICNonLazy (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
  let entry = (* jmp indirect addr; nop *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr32; jmp got; *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfbuy
       OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    newPLT sec.SecAddr NonPIC EagerBinding false 8 2UL 0UL x86NonPICGetter
    |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    newPLT sec.SecAddr NonPIC EagerBinding true 8 6UL 0UL x86NonPICGetter
    |> Some
  else None

let x64Getter addr _idx typ (reader: BinReader) sec _gotBase =
  let addrDiff = int (addr - typ.StartAddr)
  let offset = addrDiff + int typ.GOTOffset + int sec.SecOffset
  let v = reader.PeekInt32 offset
  { EntryRelocAddr = addr + typ.InstrSize + uint64 v
    NextEntryAddr = addr + uint64 typ.EntrySize } |> Ok

let x64Lazy (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
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
    newPLT sec.SecAddr DontCare LazyBinding false 16 2UL 6UL x64Getter |> Some
  elif BytePattern.matchSpan ibtZeroEntry plt then
    let off, inssz =
      if BytePattern.matchSpan ibtEntry (plt.Slice 16) then 7UL, 11UL
      else 3UL, 7UL (* bnd *)
    newPLT sec.SecAddr DontCare LazyBinding true 16 off inssz x64Getter |> Some
  else None

let x64NonLazy (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
  let entry = (* jmp [got+16]; *)
    [| OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  if BytePattern.matchSpan entry plt then
    newPLT sec.SecAddr DontCare EagerBinding false 8 2UL 6UL x64Getter |> Some
  else None

let x64IBT (reader: BinReader) sec =
  let plt = reader.PeekSpan (int sec.SecSize, int sec.SecOffset)
  let bndEntry = (* bnd jmp [got+n]] *)
    [| OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte |]
  let ibtEntry = (* endbr64; bnd jmp [got+n]] *)
    [| OneByte 0xf3uy; OneByte 0x0fuy; OneByte 0x1euy; OneByte 0xfauy
       OneByte 0xf2uy; OneByte 0xffuy; OneByte 0x25uy;
       AnyByte; AnyByte; AnyByte; AnyByte
       AnyByte; AnyByte; AnyByte; AnyByte; AnyByte |]
  if BytePattern.matchSpan bndEntry plt then
    newPLT sec.SecAddr DontCare EagerBinding true 16 3UL 7UL x64Getter |> Some
  elif BytePattern.matchSpan ibtEntry plt then
    newPLT sec.SecAddr DontCare EagerBinding true 16 7UL 11UL x64Getter |> Some
  else None

let computeARMPLTEntrySize (reader: BinReader) sec headerSize delta =
  let offset = int sec.SecOffset + int headerSize + delta
  let size = if reader.PeekInt16 offset = 0x4778s then 4 else 0
  let offset = offset + size
  let ins = reader.PeekInt32 offset
  if (headerSize = 16UL && ins = 0xe28fc600) || ins = 0xe28fc200 then
    Ok (size + 16)
  elif ins = 0xe28fc600 then Ok (size + 12)
  else Error ErrorCase.InvalidFileFormat

/// Get the size of the header of PLT (PLT Zero)
let computeARMPLTHeaderSize (reader: BinReader) sec =
  let v = reader.PeekInt32 (int sec.SecOffset)
  if v = 0xe52de004 then (* str lr, [sp, #-4] *)
    let v = reader.PeekInt32 (int sec.SecOffset + 16)
    if v = 0xe28fc600 then (* add ip, pc, #0, 12 *) Some 16UL
    else Some 20UL
  elif v = 0xf8dfb500 then (* push {lr} *) Some 16UL
  else None

let armv7Getter addr idx typ reader sec gotBase =
  let addrDiff = int (addr - typ.StartAddr)
  let hdrSize = computeARMPLTHeaderSize reader sec |> Option.get
  match computeARMPLTEntrySize reader sec hdrSize addrDiff with
  | Ok entSize ->
    { EntryRelocAddr = gotBase + uint64 (idx * 4)
      NextEntryAddr = addr + uint64 entSize } |> Ok
  | Error e -> (* Just ignore this entry using the default entry size 16. *)
    { EntryRelocAddr = 0UL; NextEntryAddr = addr + 16UL } |> Ok

let armv7PLT reader sec =
  match computeARMPLTHeaderSize reader sec with
  | Some headerSize ->
    let startAddr = sec.SecAddr + headerSize
    if reader.PeekInt32 (int sec.SecOffset) = 0xf8dfb500 then (* push {lr} *)
      newPLT startAddr DontCare LazyBinding false 16 4UL 4UL armv7Getter
    else
      match computeARMPLTEntrySize reader sec headerSize 0 with
      | Ok sz ->
        newPLT startAddr DontCare LazyBinding false sz 4UL 4UL armv7Getter
      | Error _ -> UnknownPLT
  | None -> UnknownPLT

let aarch64Getter addr idx _typ _reader _sec gotBase =
  { EntryRelocAddr = gotBase + uint64 (idx * 8)
    NextEntryAddr = addr + 16UL } |> Ok

let aarchPLT _reader sec =
  let startAddr = sec.SecAddr + 32UL
  newPLT startAddr DontCare LazyBinding false 16 0UL 4UL aarch64Getter

let findPLTType arch reader sec =
  match arch with
  | Arch.IntelX86 ->
    orElse {
      yield! x86PICLazy reader sec
      yield! x86NonPICLazy reader sec
      yield! x86PICNonLazy reader sec
      yield! x86NonPICNonLazy reader sec
    } |> Option.defaultValue UnknownPLT
  | Arch.IntelX64 ->
    orElse {
      yield! x64Lazy reader sec
      yield! x64NonLazy reader sec
      yield! x64IBT reader sec
    } |> Option.defaultValue UnknownPLT
  | Arch.ARMv7
  | Arch.AARCH32 -> armv7PLT reader sec
  | Arch.AARCH64 -> aarchPLT reader sec
  | _ -> Utils.futureFeature ()

let private parsePLT gotBase typ reloc (reader: BinReader) (s: ELFSection) map =
  let startAddr, endAddr = typ.StartAddr, s.SecAddr + s.SecSize
  let rec parseLoop idx map addr =
    if addr >= endAddr then map
    else
      let info = typ.InfoGetter addr idx typ reader s gotBase |> Result.get
      // printfn "%x -> %x" addr info.EntryRelocAddr
      let nextAddr = info.NextEntryAddr
      let ar = AddrRange (addr, nextAddr)
      match Map.tryFind info.EntryRelocAddr reloc.RelocByAddr with
      | Some r ->
        let symb = Option.get r.RelSymbol
        let symb = { symb with Addr = r.RelOffset }
        let map = ARMap.add ar symb map
        parseLoop (idx + 1) map nextAddr
      | None -> parseLoop (idx + 1) map nextAddr
  parseLoop 0 map startAddr

let parse arch sections reloc (reader: BinReader) =
  let gotBase = findGOTBase arch reloc sections
  filterPLTSections sections
  |> List.fold (fun map s ->
    match gotBase, findPLTType arch reader s with
    | Some gotBase, PLT desc ->
      if isSecondaryLazy desc then map (* Ignore secondary lazy plt. *)
      else parsePLT gotBase desc reloc reader s map
    | _, _ -> map
    ) ARMap.empty
