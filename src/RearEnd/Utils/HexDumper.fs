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

namespace B2R2.RearEnd.Utils

open B2R2

module HexDumper =
  let internal padSpace chuckSize length =
    let m = length % chuckSize
    if m = 0 then Array.empty else Array.create (chuckSize - m) "  "

  let internal addSpace idx s =
    match idx with
    | 0 -> s
    | 8 | 16 | 24 -> "  " + s
    | _ ->  " " + s

  let internal colorHexDumper addrStr chuckSize (bytes: byte[]) =
    let padding =
      padSpace chuckSize bytes.Length
      |> Array.map (fun pad -> ColoredSegment (NoColor, pad))
    let coloredHex =
      Array.append (bytes |> Array.map ColoredSegment.hexOfByte) padding
      |> Array.mapi (fun idx (color, hex) -> color, addSpace idx hex)
    let coloredAscii = bytes |> Array.map ColoredSegment.asciiOfByte
    [| [| ColoredSegment (NoColor, addrStr + ": ") |]
       coloredHex
       [| ColoredSegment (NoColor, " | ") |]
       coloredAscii |]
    |> Array.concat
    |> List.ofArray
    |> ColoredString.compile
    |> OutputColored

  let internal regularHexDumper addrStr chuckSize (bytes: byte[]) =
    let padding = padSpace chuckSize (bytes.Length)
    let hex =
      Array.append (bytes |> Array.map (fun b -> b.ToString ("X2"))) padding
      |> Array.mapi addSpace
      |> Array.fold (+) ""
    let ascii =
      bytes |> Array.fold (fun arr b -> arr + Byte.getRepresentation b) ""
    addrStr + ": " + hex + " | " + ascii
    |> OutputNormal

  let internal dumpLine chuckSize wordSize isColored addr linenum bytes =
    let addrStr = Addr.toString wordSize (addr + uint64 (linenum * chuckSize))
    let dumper = if isColored then colorHexDumper else regularHexDumper
    dumper addrStr chuckSize bytes

  let dump chuckSize wordSize isColored addr bytes =
    Array.chunkBySize chuckSize bytes
    |> Array.mapi (dumpLine chuckSize wordSize isColored addr)
