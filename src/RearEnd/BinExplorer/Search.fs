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
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils

type CmdSearch () =
  inherit Cmd ()

  let toResult (idx: uint64) = $"Found @ {idx:x}"

  let search (hdl: BinHandle) pattern =
    hdl.File.GetSegments (Permission.Readable)
    |> Seq.collect (fun s ->
      hdl.ReadBytes (s.Address, int s.Size)
      |> ByteArray.findIdxs 0UL pattern
      |> List.map (fun idx -> idx + s.Address))
    |> Seq.map toResult
    |> Seq.toList

  override _.CmdName = "search"

  override _.CmdAlias = [ "s" ]

  override _.CmdDescr = "Search expressions."

  override _.CmdHelp =
    "Usage: search <type> [expr]\n\n\
     Search the given expression from the binary.\n\
     <type> is the data type for the expression, which can be:\n\
       - s (string)\n\
       - h (hex string)"

  override _.SubCommands = []

  member _.Search hdl strPattern bytePattern =
    let ret = [| "[*] Searching for (" + strPattern + ") ..." |]
    match search hdl bytePattern with
    | [] -> Array.append ret [| "[*] The pattern not found." |]
    | results ->
      Array.append ret (List.toArray results)

  member this.CmdHandle hdl (pattern: string) = function
    | "s" | "string" ->
      Text.Encoding.ASCII.GetBytes pattern |> this.Search hdl pattern
    | "h" | "hex" ->
      ByteArray.ofHexString pattern |> this.Search hdl pattern
    | c -> [| "Unknown type " + c |]

  override this.CallBack _ ess args =
    let res =
      match args with
      | []
      | _ :: [] -> [| this.CmdHelp |]
      | t :: pattern :: _ ->
        t.ToLowerInvariant ()
        |> this.CmdHandle ess.BinHandle pattern
    Array.map OutputNormal res
