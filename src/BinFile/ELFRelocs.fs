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

module internal B2R2.BinFile.ELF.Relocs

open System
open B2R2
open B2R2.BinFile.FileHelper

let readRelOffset (reader: BinReader) cls offset =
  peekUIntOfType reader cls offset

let readRelInfo (reader: BinReader) cls offset =
  let relInfoOffset = if cls = WordSize.Bit32 then 4 else 8
  offset + relInfoOffset |> peekUIntOfType reader cls

let readRelAddend (reader: BinReader) isRel cls offset =
  let relAddendOffset = if cls = WordSize.Bit32 then 8 else 16
  if isRel then 0UL else offset + relAddendOffset  |> peekUIntOfType reader cls

let nextRelOffset isRel cls offset =
  match isRel with
  | true when cls = WordSize.Bit32 -> 8 + offset
  | true -> 16 + offset
  | false when cls = WordSize.Bit32 -> 12 + offset
  | false -> 24 + offset

let readInfoWithArch reader eHdr offset =
  let info = readRelInfo reader eHdr.Class offset
  match eHdr.MachineType with
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 ->
    if eHdr.Endian = Endian.Little then
      (info &&& 0xffffffffUL) <<< 32
      ||| (info >>> 56) &&& 0xffUL
      ||| (info >>> 40) &&& 0xff00UL
      ||| (info >>> 24) &&& 0xff000000UL
      ||| (info >>> 8) &&& 0xff00000000UL
    else info
  | _ -> info

let parseRelocELFSymbol isRel eHdr (dSym: ELFSymbol []) sec reader offset =
  let getRelocSIdx i = if eHdr.Class = WordSize.Bit32 then i >>> 8 else i >>> 32
  let relOffset = readRelOffset reader eHdr.Class offset
  let info = readInfoWithArch reader eHdr offset
  let addend = readRelAddend reader isRel eHdr.Class offset
  let sym = dSym.[(getRelocSIdx info |> Convert.ToInt32)]
  {
    RelOffset = relOffset
    RelSecName = sec.SecName
    RelSymbol = sym
    RelAddend = addend
  }

let foldRelocation relInfo rel =
  {
    RelocByAddr = Map.add rel.RelOffset rel relInfo.RelocByAddr
    RelocByName = Map.add rel.RelSymbol.SymName rel relInfo.RelocByName
  }

let relRelocs eHdr (reader: BinReader) sec dynSym relInfo offset =
  let rec parseRelMap rNum isRel relInfo offset =
    if rNum = 0UL then relInfo
    else let rel = parseRelocELFSymbol isRel eHdr dynSym sec reader offset
         let nextOffset = nextRelOffset isRel eHdr.Class offset
         parseRelMap (rNum - 1UL) isRel (foldRelocation relInfo rel) nextOffset
  let isRel = sec.SecType = SectionType.SHTRel
  let len = if isRel then (uint64 <| WordSize.toByteWidth eHdr.Class * 2)
            else (uint64 <| WordSize.toByteWidth eHdr.Class * 3)
  parseRelMap (sec.SecSize / len) isRel relInfo offset

let parse eHdr secs (dynSym: ELFSymbol []) reader =
  let parseRelMap acc sec =
    let invaldSecType =
      sec.SecType <> SectionType.SHTRela && sec.SecType <> SectionType.SHTRel
    if invaldSecType || sec.SecSize = 0UL || dynSym.Length = 0 then acc
    else relRelocs eHdr reader sec dynSym acc (Convert.ToInt32 sec.SecOffset)
  let emptyRelInfo = { RelocByAddr = Map.empty; RelocByName = Map.empty }
  Array.fold parseRelMap emptyRelInfo secs.SecByNum

