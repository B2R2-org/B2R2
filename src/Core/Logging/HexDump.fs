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

namespace B2R2.Logging

open B2R2

/// Provides hex dumping functionality.
[<RequireQualifiedAccess>]
module HexDump =
  let private padSpace numBytes length =
    let m = length % numBytes
    if m = 0 then Array.empty else Array.create (numBytes - m) "  "

  let private addSpace idx s =
    match idx with
    | 0 -> s
    | 8 | 16 | 24 -> "  " + s
    | _ -> " " + s

  let private dumpColoredLine addrStr numBytes (bytes: byte[]) =
    let padding =
      padSpace numBytes bytes.Length
      |> Array.map (fun pad -> ColoredSegment(NoColor, pad))
    let coloredHex =
      Array.append (bytes |> Array.map ColoredSegment.hexOfByte) padding
      |> Array.mapi (fun idx (color, hex) -> color, addSpace idx hex)
    let coloredAscii = bytes |> Array.map ColoredSegment.asciiOfByte
    [| [| ColoredSegment(NoColor, addrStr + ": ") |]
       coloredHex
       [| ColoredSegment(NoColor, " | ") |]
       coloredAscii |]
    |> Array.concat
    |> List.ofArray
    |> ColoredString

  let private dumpPlainLine addrStr numBytes (bytes: byte[]) =
    let padding = padSpace numBytes (bytes.Length)
    let hex =
      Array.append (bytes |> Array.map (fun b -> b.ToString("X2"))) padding
      |> Array.mapi addSpace
      |> Array.fold (+) ""
    let ascii =
      bytes |> Array.fold (fun arr b -> arr + Byte.getRepresentation b) ""
    addrStr + ": " + hex + " | " + ascii

  let private dumpLine numBytes wordSize useColor addr lineIdx bytes =
    let addrStr = Addr.toString wordSize (addr + uint64 (lineIdx * numBytes))
    if useColor then dumpColoredLine addrStr numBytes bytes |> OutputColored
    else dumpPlainLine addrStr numBytes bytes |> OutputNormal

  /// <summary>
  /// Converts a byte array into an array of hex dump lines (OutString[]), where
  /// each line displays the address, hexadecimal values, and ASCII
  /// representation. Supports both colored and plain text output.
  /// </summary>
  /// <param name="bytesPerLine">Number of bytes to display per line.</param>
  /// <param name="wordSize">Word size used for address formatting.</param>
  /// <param name="useColor">Whether to use colored output.</param>
  /// <param name="addr">Starting address for the dump.</param>
  /// <param name="bytes">The byte array to render.</param>
  /// <returns>
  /// An array of hex dump lines in either colored or plain text format.
  /// </returns>
  let makeLines bytesPerLine wordSize useColor addr bytes =
    Array.chunkBySize bytesPerLine bytes
    |> Array.mapi (dumpLine bytesPerLine wordSize useColor addr)
