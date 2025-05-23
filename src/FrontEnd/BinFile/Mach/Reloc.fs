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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2
open B2R2.FrontEnd.BinLifter

type RelocSymbol =
  | SymIndex of int (* Symbol table index *)
  | SecOrdinal of int (* Section number *)

/// Reloc info.
type RelocationInfo = {
  /// Offset in the section to what is being relocated.
  RelocAddr: int
  /// RelocSymbol
  RelocSymbol: RelocSymbol
  /// Relocation length.
  RelocLength: RegType
  /// Parent section
  RelocSection: MachSection
  /// Is this address part of an instruction that uses PC-relative addressing?
  IsPCRel: bool
}
with
  member this.GetName (symbols: MachSymbol[], sections: MachSection[]) =
    match this.RelocSymbol with
    | SymIndex n -> symbols[n].SymName
    | SecOrdinal n -> sections[n-1].SecName

module internal Reloc =
  let private parseRelocSymbol data =
    let n = data &&& 0xFFFFFF
    if (data >>> 27) &&& 1 = 1 then SymIndex (n)
    else SecOrdinal (n)

  let private parseRelocLength data =
    match (data >>> 25) &&& 3 with
    | 0 -> 8<rt>
    | 1 -> 16<rt>
    | _ -> 32<rt>

  let private countRelocs secs =
    secs |> Array.fold (fun cnt sec -> cnt + sec.SecNumOfReloc) 0

  let private parseReloc (span: ByteSpan) (reader: IBinReader) sec =
    let addr = reader.ReadInt32 (span, 0)
    let data = reader.ReadInt32 (span, 4)
    let sym = parseRelocSymbol data
    let len = parseRelocLength data
    let rel = (data >>> 24) &&& 1 = 1
    { RelocAddr = addr
      RelocSymbol = sym
      RelocLength = len
      RelocSection = sec
      IsPCRel = rel }

  let parse { Bytes = bytes; Reader = reader } secs =
    let numRelocs = countRelocs secs
    let relocs = Array.zeroCreate numRelocs
    let mutable i = 0
    for sec in secs do
      let relOffset, relSize = int sec.SecRelOff, int sec.SecNumOfReloc * 8
      let relSpan = ReadOnlySpan (bytes, relOffset, relSize)
      for n = 0 to sec.SecNumOfReloc - 1 do
        let offset = n * 8
        relocs[i] <- parseReloc (relSpan.Slice offset) reader sec
        i <- i + 1
    relocs
