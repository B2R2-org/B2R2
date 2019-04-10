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

module B2R2.BinFile.Mach.Section

open B2R2
open B2R2.BinFile.FileHelper

let parseSection (reader: BinReader) cls pos =
  let secFlag = peekHeaderI32 reader cls pos 56 64
  { SecName = peekCString reader pos 16
    SegName = peekCString reader (pos + 16) 16
    SecAddr = peekUIntOfType reader cls (pos + 32)
    SecSize = peekHeaderNative reader cls pos 36 40
    SecOffset = peekHeaderU32 reader cls pos 40 48
    SecAlignment = peekHeaderU32 reader cls pos 44 52
    SecRelOff = peekHeaderU32 reader cls pos 48 56
    SecNumOfReloc = peekHeaderU32 reader cls pos 52 60
    SecType = secFlag &&& 0xFF |> LanguagePrimitives.EnumOfValue
    SecAttrib = secFlag &&& 0xFFFFFF00 |> LanguagePrimitives.EnumOfValue
    SecReserved1 = peekHeaderI32 reader cls pos 60 68
    SecReserved2 = peekHeaderI32 reader cls pos 64 72 }

let foldSecInfo acc sec =
  let secEnd = sec.SecAddr + sec.SecSize
  let secByAddr = ARMap.addRange sec.SecAddr secEnd sec acc.SecByAddr
  let secByName = Map.add sec.SecName sec acc.SecByName
  { acc with SecByAddr = secByAddr; SecByName = secByName }

let parseSections reader cls segs =
  let rec parseLoop count acc pos =
    if count = 0u then List.rev acc
    else let sec = parseSection reader cls pos
         let nextPos = pos + if cls = WordSize.Bit64 then 80 else 68
         parseLoop (count - 1u) (sec :: acc) nextPos
  let foldSections acc seg = parseLoop seg.NumSecs acc seg.SecOff
  let sections = List.fold foldSections [] segs
  let acc = { SecByAddr = ARMap.empty; SecByName = Map.empty; SecByNum = [||] }
  let secInfo = List.fold foldSecInfo acc sections
  { secInfo with SecByNum = Array.ofList sections }
