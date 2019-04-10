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

let peekInfoWithArch reader eHdr offset =
  let info = peekHeaderNative reader eHdr.Class offset 4 8
  match eHdr.MachineType with
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 ->
    if eHdr.Endian = Endian.Little then
      (info &&& 0xffffffffUL) <<< 32
      ||| (info >>> 56) &&& 0xffUL
      ||| (info >>> 40) &&& 0xff00UL
      ||| (info >>> 24) &&& 0xff0000UL
      ||| (info >>> 8) &&& 0xff000000UL
    else info
  | _ -> info

let inline getRelocSIdx eHdr i =
  if eHdr.Class = WordSize.Bit32 then i >>> 8 else i >>> 32

let inline parseRelocELFSymbol hasAdd eHdr typMask symTbl reader pos sec =
  let info = peekInfoWithArch reader eHdr pos
  let cls = eHdr.Class
  {
    RelOffset = peekUIntOfType reader cls pos
    RelType = typMask &&& info |> RelocationType.FromNum eHdr.MachineType
    RelSymbol = Array.get symTbl (getRelocSIdx eHdr info |> Convert.ToInt32)
    RelAddend = if hasAdd then peekHeaderNative reader cls pos 8 16 else 0UL
    RelSecNumber = sec.SecNum
  }

let nextRelOffset hasAdd cls offset =
  if cls = WordSize.Bit32 then offset + (if hasAdd then 12 else 8)
  else offset + (if hasAdd then 24 else 16)

let accumulateRelocInfo relInfo rel =
  {
    RelocByAddr = Map.add rel.RelOffset rel relInfo.RelocByAddr
    RelocByName = Map.add rel.RelSymbol.SymName rel relInfo.RelocByName
  }

let parseRelocSection eHdr reader sec symbInfo relInfo =
  let hasAdd = sec.SecType = SectionType.SHTRela (* Has addend? *)
  let typMask = if eHdr.Class = WordSize.Bit32 then 0xFFUL else 0xFFFFFFFFUL
  let rec parseLoop rNum relInfo offset =
    if rNum = 0UL then relInfo
    else
      let symTbl = symbInfo.SecNumToSymbTbls.[int sec.SecLink]
      let rel = parseRelocELFSymbol hasAdd eHdr typMask symTbl reader offset sec
      let nextOffset = nextRelOffset hasAdd eHdr.Class offset
      parseLoop (rNum - 1UL) (accumulateRelocInfo relInfo rel) nextOffset
  let entrySize =
    if hasAdd then (uint64 <| WordSize.toByteWidth eHdr.Class * 3)
    else (uint64 <| WordSize.toByteWidth eHdr.Class * 2)
  let numEntries = sec.SecSize / entrySize
  Convert.ToInt32 sec.SecOffset
  |> parseLoop numEntries relInfo

let parse eHdr secInfo symbInfo reader =
  let folder acc sec =
    match sec.SecType with
    | SectionType.SHTRel
    | SectionType.SHTRela ->
      if sec.SecSize = 0UL then acc
      else parseRelocSection eHdr reader sec symbInfo acc
    | _ -> acc
  let emptyRelInfo = { RelocByAddr = Map.empty; RelocByName = Map.empty }
  Array.fold folder emptyRelInfo secInfo.SecByNum
