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

module internal B2R2.FrontEnd.BinFile.ELF.Relocs

open System
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let peekInfoWithArch span reader eHdr offset =
  let info = peekHeaderNative span reader eHdr.Class offset 4 8
  match eHdr.MachineType with
  | Arch.MIPS64 ->
    (* MIPS64el has a a 32-bit LE symbol index followed by four individual byte
       fields. *)
    if eHdr.Endian = Endian.Little then
      (info &&& 0xffffffffUL) <<< 32
      ||| ((info >>> 56) &&& 0xffUL)
      ||| ((info >>> 40) &&& 0xff00UL)
      ||| ((info >>> 24) &&& 0xff0000UL)
      ||| ((info >>> 8) &&& 0xff000000UL)
    else info
  | _ -> info

let inline getRelocSIdx eHdr (i: uint64) =
  if eHdr.Class = WordSize.Bit32 then i >>> 8 else i >>> 32

let inline relocEntry baseAddr hasAdd eHdr typMask symTbl span reader pos sec =
  let info = peekInfoWithArch span reader eHdr pos
  let cls = eHdr.Class
  { RelOffset = peekUIntOfType span reader cls pos + baseAddr
    RelType = typMask &&& info |> RelocationType.FromNum eHdr.MachineType
    RelSymbol = Array.tryItem (getRelocSIdx eHdr info |> Convert.ToInt32) symTbl
    RelAddend =
      if hasAdd then peekHeaderNative span reader cls pos 8 16 else 0UL
    RelSecNumber = sec.SecNum }

let nextRelOffset hasAdd cls offset =
  if cls = WordSize.Bit32 then offset + (if hasAdd then 12 else 8)
  else offset + (if hasAdd then 24 else 16)

let tryFindSymbTable idx symbInfo =
  match symbInfo.SecNumToSymbTbls.TryGetValue idx with
  | true, tbl -> tbl
  | false, _ -> [||]

let accumulateRelocInfo relInfo rel =
  match rel.RelSymbol with
  | None -> relInfo.RelocByAddr[rel.RelOffset] <- rel
  | Some name ->
    relInfo.RelocByAddr[rel.RelOffset] <- rel
    relInfo.RelocByName[name.SymName] <- rel

let parseRelocSection baseAddr eHdr span reader sec symbInfo relInfo =
  let hasAdd = sec.SecType = SectionType.SHTRela (* Has addend? *)
  let typMask = if eHdr.Class = WordSize.Bit32 then 0xFFUL else 0xFFFFFFFFUL
  let entrySize =
    if hasAdd then (uint64 <| WordSize.toByteWidth eHdr.Class * 3)
    else (uint64 <| WordSize.toByteWidth eHdr.Class * 2)
  let numEntries = int (sec.SecSize / entrySize)
  let mutable ofs = Convert.ToInt32 sec.SecOffset
  for _ = numEntries downto 1 do
    let symTbl = tryFindSymbTable (int sec.SecLink) symbInfo
    relocEntry baseAddr hasAdd eHdr typMask symTbl span reader ofs sec
    |> accumulateRelocInfo relInfo
    ofs <- nextRelOffset hasAdd eHdr.Class ofs

let parse baseAddr eHdr secInfo symbInfo span reader =
  let relInfo = { RelocByAddr = Dictionary (); RelocByName = Dictionary () }
  for sec in secInfo.SecByNum do
    match sec.SecType with
    | SectionType.SHTRel
    | SectionType.SHTRela ->
      if sec.SecSize = 0UL then ()
      else parseRelocSection baseAddr eHdr span reader sec symbInfo relInfo
    | _ -> ()
  relInfo
