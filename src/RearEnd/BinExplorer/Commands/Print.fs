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

namespace B2R2.RearEnd.BinExplorer.Commands

open System
open System.Text.RegularExpressions
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.RearEnd.BinExplorer

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

type Print() =
  let convertCount (v: string) =
    try Convert.ToInt32(v) |> Ok
    with _ -> Error("[*] Invalid count is given.")

  let convertFmtLetter v count =
    match PrintFormat.FromString v with
    | UnknownFormat -> Error("[*] Invalid format letter given.")
    | fmt -> Ok(count, fmt)

  let convertSize v (count, fmt) =
    match PrintSize.FromString v with
    | UnknownSize -> Error("[*] Invalid size letter given.")
    | sz -> Ok(sz, count, fmt)

  let regexFormat = Regex(@"(\d+)([duxs])([bhwg]?)")

  let parseFormat fmt =
    let m = regexFormat.Match(fmt)
    if m.Success then
      convertCount m.Groups[1].Value
      |> Result.bind (convertFmtLetter m.Groups[2].Value)
      |> Result.bind (convertSize m.Groups[3].Value)
    else
      Error("[*] Invalid format string is given.")

  let parseAddr addr (sz, count, fmt) =
    try Ok(sz, count, fmt, Convert.ToUInt64(addr, 16))
    with _ -> Error "[*] Invalid address given."

  let hexPrint sz (i: uint64) = i.ToString("x" + (sz * 2).ToString())

  let print (hdl: BinHandle) sz fmt addr =
    match fmt with
    | Hexadecimal ->
      hdl.ReadUInt(addr = addr, size = sz) |> hexPrint sz
    | UnsignedDecimal ->
      hdl.ReadUInt(addr = addr, size = sz).ToString()
    | Decimal ->
      hdl.ReadInt(addr = addr, size = sz).ToString()
    | _ -> failwith "This is impossible"

  let getAddressPrefix (hdl: BinHandle) (addr: uint64) =
    let hexWidth = WordSize.toByteWidth hdl.File.ISA.WordSize * 2
    addr.ToString("x" + hexWidth.ToString()) + ": "

  let rec iter hdl sz fmt addr endAddr acc =
    if addr >= endAddr then List.rev acc |> List.toArray
    else
      let addrstr = getAddressPrefix hdl addr
      let acc =
        try (addrstr + print hdl sz fmt addr) :: acc
        with _ -> (addrstr + "(invalid)") :: acc
      iter hdl sz fmt (addr + uint64 sz) endAddr acc

  let rec printStrings (hdl: BinHandle) addr cnt acc =
    if cnt <= 0 then List.rev acc |> List.toArray
    else
      let s = try hdl.ReadASCII(addr = addr) |> Some with _ -> None
      match s with
      | None -> printStrings hdl addr 0 acc
      | Some s ->
        let addrstr = getAddressPrefix hdl addr
        let len = String.length s |> uint64
        printStrings hdl (addr + len + 1UL) (cnt - 1) ((addrstr + s) :: acc)

  let validateRequest (brew: BinaryBrew<_, _>) = function
    | Ok(_, count, ASCII, addr) ->
      let hdl = brew.BinHandle
      printStrings hdl addr count []
    | Ok(sz, count, fmt, addr) ->
      let hdl = brew.BinHandle
      let sz = PrintSize.ToInt sz
      let endAddr = addr + uint64 (sz * count)
      if addr > endAddr then [| "[*] Invalid address range given." |]
      else iter hdl sz fmt addr endAddr []
    | Error str -> [| str |]

  interface ICmd with

    member _.CmdName = "print"

    member _.CmdAlias = [ "p" ]

    member _.CmdDescr = "Output the contents of the binary in a given format."

    member _.CmdHelp =
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

    member _.SubCommands = []

    member this.CallBack(brew, args) =
      match args with
      | fmt :: addr :: _ ->
        parseFormat fmt
        |> Result.bind (parseAddr addr)
        |> validateRequest brew
      | _ -> [| (this :> ICmd).CmdHelp |]
      |> Array.map OutputNormal