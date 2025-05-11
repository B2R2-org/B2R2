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
open B2R2.MiddleEnd
open B2R2.RearEnd.Utils

type CmdHexDump () =
  inherit Cmd ()

  let parseAddr addr =
    try Ok (Convert.ToUInt64 (addr, 16))
    with _ -> Error "[*] Invalid address given."

  let parseCount count addr =
    try Ok (addr, Convert.ToInt32 (count, 10))
    with _ -> Error "[*] Invalid byte count given."

  let readBytes (brew: BinaryBrew<_, _>) (addr, count) =
    try (addr, brew.BinHandle.ReadBytes (addr=addr, nBytes=count)) |> Ok
    with _ -> Error "[*] Failed to read bytes."

  override _.CmdName = "hexdump"

  override _.CmdAlias = [ "hd" ]

  override _.CmdDescr = "Dump the binary contents in a hex+ASCII format."

  override _.CmdHelp =
    "Usage: hexdump <addr> <bytes>\n\n\
     Dump the contents in a HEX + ASCII format up to the number of given bytes."

  override _.SubCommands = []

  override this.CallBack _ brew args =
    match args with
    | addr :: cnt :: _ ->
      let result =
        parseAddr addr
        |> Result.bind (parseCount cnt)
        |> Result.bind (readBytes brew)
      match result with
      | Ok (addr, bytes: byte []) ->
        let wordSize = brew.BinHandle.File.ISA.WordSize
        HexDumper.dump 16 wordSize true addr bytes
      | Error e -> [| OutputColored [ ColoredSegment (NoColor, e) ] |]
    | _ -> [| this.CmdHelp |] |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
