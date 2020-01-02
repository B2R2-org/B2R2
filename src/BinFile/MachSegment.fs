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

module internal B2R2.BinFile.Mach.Segment

open B2R2
open B2R2.BinFile

let extract cmds =
  let chooser = function
    | Segment s -> Some s
    | _ -> None
  List.choose chooser cmds

let buildMap (segs: SegCmd list) =
  segs
  |> List.fold (fun map s ->
       ARMap.addRange s.VMAddr (s.VMAddr + s.VMSize) s map) ARMap.empty

let segCmdToSegment seg =
  { Address = seg.VMAddr
    Size = seg.VMSize
    Permission = seg.MaxProt |> LanguagePrimitives.EnumOfValue }

let getSegments mach isLoadable =
  mach.Segments
  |> fun segs ->
    if isLoadable then segs |> List.filter (fun s -> s.FileSize > 0UL)
    else segs
  |> List.map segCmdToSegment
  |> List.toSeq

