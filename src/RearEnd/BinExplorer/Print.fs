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
open System.Text.RegularExpressions
open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinEssence
open B2R2.RearEnd

type PrintFormat =
  | Hexadecimal
  | Decimal
  | UnsignedDecimal
  | ASCII
  | UnknownFormat
with
  static member FromString str =
    match str with
    | "d" -> Decimal
    | "u" -> UnsignedDecimal
    | "x" -> Hexadecimal
    | "s" -> ASCII
    | _ -> UnknownFormat

type PrintSize =
  /// 1 byte (b).
  | OneByte
  /// 2 bytes (h).
  | TwoBytes
  /// 4 bytes (w).
  | FourBytes
  /// 8 bytes (g).
  | EightBytes
  /// Zero size is used to indicate ASCII string.
  | Zero
  /// Unknown Size
  | UnknownSize
with
  static member FromString str =
    match str with
    | "" -> Zero
    | "b" -> OneByte
    | "h" -> TwoBytes
    | "w" -> FourBytes
    | "g" -> EightBytes
    | _ -> UnknownSize
  static member ToInt sz =
    match sz with
    | OneByte -> 1
    | TwoBytes -> 2
    | FourBytes -> 4
    | EightBytes -> 8
    | _ -> 0

type CmdPrint () =
  inherit Cmd ()

  let convertCount (v: string) =
    try Convert.ToInt32 (v) |> Ok
    with _ -> Error ("[*] Invalid count is given.")

  let convertFmtLetter v count =
    match PrintFormat.FromString v with
    | UnknownFormat -> Error ("[*] Invalid format letter given.")
    | fmt -> Ok (count, fmt)

  let convertSize v (count, fmt) =
    match PrintSize.FromString v with
    | UnknownSize -> Error ("[*] Invalid size letter given.")
    | sz -> Ok (sz, count, fmt)

  let regexFormat = new Regex (@"(\d+)([duxs])([bhwg]?)")

  let parseFormat fmt =
    let m = regexFormat.Match (fmt)
    if m.Success then
      convertCount m.Groups.[1].Value
      |> Result.bind (convertFmtLetter m.Groups.[2].Value)
      |> Result.bind (convertSize m.Groups.[3].Value)
    else
      Error ("[*] Invalid format string is given.")

  let parseAddr addr (sz, count, fmt) =
    try Ok (sz, count, fmt, Convert.ToUInt64 (addr, 16))
    with _ -> Error "[*] Invalid address given."

  let hexPrint sz (i: uint64) =
    i.ToString ("X" + (sz * 2).ToString ())

  let print handler sz fmt addr =
    match fmt with
    | Hexadecimal ->
      BinHandle.ReadUInt (handler, addr=addr, size=sz) |> hexPrint sz
    | UnsignedDecimal ->
      BinHandle.ReadUInt(handler, addr=addr, size=sz).ToString ()
    | Decimal ->
      BinHandle.ReadInt(handler, addr=addr, size=sz).ToString ()
    | _ -> failwith "This is impossible"

  let getAddressPrefix handler (addr: uint64) =
    let hexWidth = WordSize.toByteWidth handler.ISA.WordSize * 2
    addr.ToString ("X" + hexWidth.ToString ()) + ": "

  let rec iter handler sz fmt addr endAddr acc =
    if addr >= endAddr then List.rev acc |> List.toArray
    else
      let addrstr = getAddressPrefix handler addr
      let acc =
        try (addrstr + print handler sz fmt addr) :: acc
        with _ -> (addrstr + "(invalid)") :: acc
      iter handler sz fmt (addr + uint64 sz) endAddr acc

  let rec printStrings handler addr cnt acc =
    if cnt <= 0 then List.rev acc |> List.toArray
    else
      let s =
        try BinHandle.ReadASCII (handler, addr=addr) |> Some with _ -> None
      match s with
      | None -> printStrings handler addr 0 acc
      | Some s ->
        let addrstr = getAddressPrefix handler addr
        let len = String.length s |> uint64
        printStrings handler (addr + len + 1UL) (cnt - 1) ((addrstr + s) :: acc)

  let validateRequest (binEssence: BinEssence) = function
    | Ok (_, count, ASCII, addr) ->
      let handler = binEssence.BinHandle
      printStrings handler addr count []
    | Ok (sz, count, fmt, addr) ->
      let handler = binEssence.BinHandle
      let sz = PrintSize.ToInt sz
      let endAddr = addr + uint64 (sz * count)
      if addr > endAddr then [| "[*] Invalid address range given."|]
      else iter handler sz fmt addr endAddr []
    | Error str -> [| str |]

  override __.CmdName = "print"

  override __.CmdAlias = [ "p" ]

  override __.CmdDescr = "Output the contents of the binary in a given format."

  override __.CmdHelp =
    "Usage: print <format> <addr>\n\n\
     The <format> is a repeat count followed by a format letter, and a size\n\
     letter. The size letter can be omitted only for string format.\n\n\
     Format letters are:\n\
     - d (signed decimal)\n\
     - u (unsigned decimal)\n\
     - x (hexadecimal)\n\
     - s (string)\n\n\
     Size letters are:\n\
     - b (byte) or 1\n\
     - h (half word) or 2\n\
     - w (word) or 4\n\
     - g (giant) or 8"

  override __.SubCommands = []

  override __.CallBack _ binEssence args =
    match args with
    | fmt :: addr :: _ ->
      parseFormat fmt
      |> Result.bind (parseAddr addr)
      |> validateRequest binEssence
    | _ -> [| __.CmdHelp |]
    |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
