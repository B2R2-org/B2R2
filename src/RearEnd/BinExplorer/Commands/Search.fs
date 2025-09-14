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
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils
open B2R2.RearEnd.BinExplorer

type Search() =
  let toResult (idx: uint64) = $"Found @ {idx:x}"

  let search (hdl: BinHandle) pattern =
    hdl.File.GetVMMappedRegions Permission.Readable
    |> Seq.collect (fun reg ->
      let size = reg.Max - reg.Min + 1UL
      hdl.ReadBytes(reg.Min, int size)
      |> ByteArray.findIdxs 0UL pattern
      |> List.map (fun idx -> idx + reg.Min))
    |> Seq.map toResult
    |> Seq.toList

  member _.Search(hdl, strPattern, bytePattern) =
    let ret = [| "[*] Searching for (" + strPattern + ") ..." |]
    match search hdl bytePattern with
    | [] -> Array.append ret [| "[*] The pattern not found." |]
    | results ->
      Array.append ret (List.toArray results)

  member this.CmdHandle(hdl, pattern: string) = function
    | "s" | "string" ->
      this.Search(hdl, pattern, Text.Encoding.ASCII.GetBytes pattern)
    | "h" | "hex" ->
      this.Search(hdl, pattern, ByteArray.ofHexString pattern)
    | c -> [| "Unknown type " + c |]

  interface ICmd with

    member _.CmdName = "search"

    member _.CmdAlias = [ "s" ]

    member _.CmdDescr = "Search expressions."

    member _.CmdHelp =
      "Usage: search <type> [expr]\n\n\
      Search the given expression from the binary.\n\
      <type> is the data type for the expression, which can be:\n\
        - s (string)\n\
        - h (hex string)"

    member _.SubCommands = []

    member this.CallBack(ess, args) =
      let res =
        match args with
        | []
        | _ :: [] -> [| (this :> ICmd).CmdHelp |]
        | t :: pattern :: _ ->
          t.ToLowerInvariant()
          |> this.CmdHandle(ess.BinHandle, pattern)
      Array.map OutputNormal res