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
open System.IO
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let peekInfoWithArch reader hdr span =
  let info = peekHeaderNative span reader hdr.Class 4 8
  match hdr.MachineType with
  | Arch.MIPS64 ->
    (* MIPS64el has a a 32-bit LE symbol index followed by four individual byte
       fields. *)
    if hdr.Endian = Endian.Little then
      (info &&& 0xffffffffUL) <<< 32
      ||| ((info >>> 56) &&& 0xffUL)
      ||| ((info >>> 40) &&& 0xff00UL)
      ||| ((info >>> 24) &&& 0xff0000UL)
      ||| ((info >>> 8) &&& 0xff000000UL)
    else info
  | _ -> info

let inline getRelocSIdx hdr (i: uint64) =
  if hdr.Class = WordSize.Bit32 then i >>> 8 else i >>> 32

let inline relocEntry reader hdr baseAddr hasAdd typMask symTbl span sec =
  let info = peekInfoWithArch reader hdr span
  let cls = hdr.Class
  { RelOffset = peekUIntOfType span reader cls 0 + baseAddr
    RelType = typMask &&& info |> RelocationType.FromNum hdr.MachineType
    RelSymbol = Array.tryItem (getRelocSIdx hdr info |> Convert.ToInt32) symTbl
    RelAddend = if hasAdd then peekHeaderNative span reader cls 8 16 else 0UL
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

let parseRelocSection
  reader hdr baseAddr sec (secBuf: byte[]) symbInfo relInfo =
  let hasAdd = sec.SecType = SectionType.SHTRela (* Has addend? *)
  let typMask = if hdr.Class = WordSize.Bit32 then 0xFFUL else 0xFFFFFFFFUL
  let entrySize =
    if hasAdd then (uint64 <| WordSize.toByteWidth hdr.Class * 3)
    else (uint64 <| WordSize.toByteWidth hdr.Class * 2)
  let numEntries = int (sec.SecSize / entrySize)
  let mutable ofs = 0
  let span = ReadOnlySpan secBuf
  for _ = numEntries downto 1 do
    let symTbl = tryFindSymbTable (int sec.SecLink) symbInfo
    relocEntry reader hdr baseAddr hasAdd typMask symTbl (span.Slice ofs) sec
    |> accumulateRelocInfo relInfo
    ofs <- nextRelOffset hasAdd hdr.Class ofs

let parse stream reader hdr baseAddr (shdrs: Lazy<_>) (symbInfo: Lazy<_>) =
  let relInfo = { RelocByAddr = Dictionary (); RelocByName = Dictionary () }
  for sec in shdrs.Value do
    match sec.SecType with
    | SectionType.SHTRel
    | SectionType.SHTRela ->
      if sec.SecSize = 0UL then ()
      else
        let secBuf = Array.zeroCreate (int sec.SecSize)
        (stream: Stream).Seek (int64 sec.SecOffset, SeekOrigin.Begin) |> ignore
        readOrDie stream secBuf
        parseRelocSection reader hdr baseAddr sec secBuf symbInfo.Value relInfo
    | _ -> ()
  relInfo
