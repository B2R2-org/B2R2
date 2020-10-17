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

namespace B2R2.RearEnd.BinExplorer

open System
open B2R2.MiddleEnd.BinEssence
open B2R2.RearEnd

type CmdHexDump () =
  inherit Cmd ()

  let parseAddr addr =
    try Ok (Convert.ToUInt64 (addr, 16))
    with _ -> Error "[*] Invalid address given."

  let parseCount count addr =
    try Ok (addr, Convert.ToInt32 (count, 10))
    with _ -> Error "[*] Invalid byte count given."

  let readBytes (binEssence: BinEssence) (addr, count) =
    try (addr, binEssence.BinHandle.ReadBytes (addr, count)) |> Ok
    with _ -> Error "[*] Failed to read bytes."

  let padSpace (arr: ColoredSegment []) =
    let m = arr.Length % 16
    if m = 0 then arr
    else Array.create (16 - m) (NoColor, "  ") |> Array.append arr

  let addSpace idx cs =
    let c, s = cs
    match idx with
    | 0 -> c, s
    | 8 -> c, "  " + s
    | _ -> c, " " + s

  let dumpHex (bytes: byte []) =
    bytes
    |> Array.map ColoredSegment.byteToHex
    |> padSpace
    |> Array.mapi addSpace

  let dumpASCII (bytes: byte []) =
    bytes
    |> Array.map ColoredSegment.byteToAscii

  let dumpLine addr linenum bytes =
    let addr = (addr + uint64 (linenum * 16)).ToString ("X16")
    dumpASCII bytes
    |> Array.append [| ColoredSegment (NoColor, " | ") |]
    |> Array.append (dumpHex bytes)
    |> Array.append [| ColoredSegment (NoColor, addr + ": ") |]
    |> List.ofArray
    |> ColoredString.compile

  let hexdump = function
    | Ok (addr, bytes: byte []) ->
      Array.chunkBySize 16 bytes
      |> Array.mapi (dumpLine addr)
    | Error e -> [| [ ColoredSegment (NoColor, e) ] |]

  override __.CmdName = "hexdump"

  override __.CmdAlias = [ "hd" ]

  override __.CmdDescr = "Dump the binary contents in a hex+ASCII format."

  override __.CmdHelp =
    "Usage: hexdump <addr> <bytes>\n\n\
     Dump the contents in a HEX + ASCII format up to the number of given bytes."

  override __.SubCommands = []

  override __.CallBack _ binEssence args =
    match args with
    | addr :: cnt :: _ ->
      parseAddr addr
      |> Result.bind (parseCount cnt)
      |> Result.bind (readBytes binEssence)
      |> hexdump
      |> Array.map OutputColored
    | _ -> [| __.CmdHelp |] |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
