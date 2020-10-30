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

module B2R2.RearEnd.BinDump.Helper

open B2R2
open B2R2.RearEnd

module CS = ColoredSegment

let padSpaceColored chuckSize (arr: ColoredSegment []) =
  let m = arr.Length % chuckSize
  if m = 0 then arr
  else Array.create (chuckSize - m) (NoColor, "  ") |> Array.append arr

let addSpaceColored idx cs =
  let c, s = cs
  match idx with
  | 0 -> c, s
  | 8 | 16 | 24 -> c, "  " + s
  | _ -> c, " " + s

let dumpHexColored chuckSize (bytes: byte []) =
  bytes
  |> Array.map CS.byteToHex
  |> padSpaceColored chuckSize
  |> Array.mapi addSpaceColored

let dumpASCIIColored (bytes: byte []) = bytes |> Array.map CS.byteToAscii

let dumpLineColored chuckSize wordSize addr linenum bytes =
  let addrStr = Addr.toString wordSize (addr + uint64 (linenum * chuckSize))
  dumpASCIIColored bytes
  |> Array.append [| ColoredSegment (NoColor, " | ") |]
  |> Array.append (dumpHexColored chuckSize bytes)
  |> Array.append [| ColoredSegment (NoColor, addrStr + ": ") |]
  |> List.ofArray
  |> ColoredString.compile

let hexdumpColored chuckSize wordSize addr bytes =
  Array.chunkBySize chuckSize bytes
  |> Array.mapi (dumpLineColored chuckSize wordSize addr)

let padSpace chuckSize (arr: string []) =
  let m = arr.Length % chuckSize
  if m = 0 then arr else Array.create (chuckSize - m) "  " |> Array.append arr

let addSpace idx s =
  match idx with
  | 0 -> s
  | 8 | 16 | 24 -> "  " + s
  | _ -> " " + s

let dumpHex chuckSize (bytes: byte []) =
  bytes
  |> Array.map (fun b -> b.ToString ("X2"))
  |> padSpace chuckSize
  |> Array.mapi addSpace
  |> Array.fold (fun hex s -> hex + s) ""

let dumpASCII (bytes: byte []) =
  bytes
  |> Array.map (fun b -> CS.getRepresentation b)
  |> Array.fold (fun ascii s -> ascii + s) ""

let dumpLine chuckSize wordSize addr linenum bytes =
  let addrStr = Addr.toString wordSize (addr + uint64 (linenum * chuckSize))
  let hex = dumpHex chuckSize bytes
  let ascii = dumpASCII bytes
  OutputNormal (addrStr + ": " + hex + " | " + ascii)

let hexdump chuckSize wordSize addr bytes =
  Array.chunkBySize chuckSize bytes
  |> Array.mapi (dumpLine chuckSize wordSize addr)
