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

module internal B2R2.FrontEnd.BinFile.Mach.Segment

open B2R2.Collections

let private chooser = function
  | Segment(_, _, s) -> Some s
  | _ -> None

let extract cmds = Array.choose chooser cmds

/// Builds a map from the address range of each segment to the segment itself.
/// A segment that occupies no virtual memory names no range, and a kernel
/// image carries several of those, so they go in nowhere.
let buildMap segs =
  segs
  |> Array.filter (fun s -> s.VMSize > 0UL)
  |> Array.fold (fun map s ->
    NoOverlapIntervalMap.addByBounds s.VMAddr (s.VMAddr + s.VMSize - 1UL) s map
  ) NoOverlapIntervalMap.empty

let [<Literal>] Text = "__TEXT"

let [<Literal>] LinkEdit = "__LINKEDIT"

/// Returns the virtual address the image is loaded at, which is the vmaddr of
/// its __TEXT segment. A relocatable object has no such segment, so the answer
/// is optional; the callers that can carry on without one use zero.
let tryGetImageBase segs =
  segs
  |> Array.tryFind (fun s -> s.SegCmdName = Text)
  |> Option.map (fun s -> s.VMAddr)
