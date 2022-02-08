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

module internal B2R2.FrontEnd.BinFile.Mach.Section

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let parseSection baseAddr span reader cls pos =
  let secFlag = peekHeaderI32 span reader cls pos 56 64
  { SecName = peekCString span pos
    SegName = peekCString span (pos + 16)
    SecAddr = peekUIntOfType span reader cls (pos + 32) + baseAddr
    SecSize = peekHeaderNative span reader cls pos 36 40
    SecOffset = peekHeaderU32 span reader cls pos 40 48
    SecAlignment = peekHeaderU32 span reader cls pos 44 52
    SecRelOff = peekHeaderU32 span reader cls pos 48 56
    SecNumOfReloc = peekHeaderI32 span reader cls pos 52 60
    SecType = secFlag &&& 0xFF |> LanguagePrimitives.EnumOfValue
    SecAttrib = secFlag &&& 0xFFFFFF00 |> LanguagePrimitives.EnumOfValue
    SecReserved1 = peekHeaderI32 span reader cls pos 60 68
    SecReserved2 = peekHeaderI32 span reader cls pos 64 72 }

let foldSecInfo acc sec =
  let secEnd = sec.SecAddr + sec.SecSize - 1UL
  let secByAddr = ARMap.addRange sec.SecAddr secEnd sec acc.SecByAddr
  let secByName = Map.add sec.SecName sec acc.SecByName
  { acc with SecByAddr = secByAddr; SecByName = secByName }

let parseSections baseAddr span reader cls segs =
  let sections = List<MachSection> ()
  for seg in segs do
    let mutable pos = seg.SecOff
    for _ = 1 to int seg.NumSecs do
      let sec = parseSection baseAddr span reader cls pos
      sections.Add sec
      pos <- pos + if cls = WordSize.Bit64 then 80 else 68
  let acc = { SecByAddr = ARMap.empty; SecByName = Map.empty; SecByNum = [||] }
  let secInfo = Seq.fold foldSecInfo acc sections
  { secInfo with SecByNum = Array.ofSeq sections }

let getTextSectionIndex secs =
  secs |> Array.findIndex (fun s -> s.SecName = "__text")
