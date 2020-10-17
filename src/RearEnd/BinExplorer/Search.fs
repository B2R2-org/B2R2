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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd

type CmdSearch () =
  inherit Cmd ()

  let search hdl pattern =
    hdl.FileInfo.GetSegments (Permission.Readable)
    |> Seq.map (fun s -> BinHandle.ReadBytes (hdl, s.Address, int s.Size)
                         |> ByteArray.findIdxs 0UL pattern
                         |> List.map (fun idx -> idx + s.Address))
    |> Seq.concat
    |> Seq.map (fun idx -> "Found @ " + idx.ToString("X"))
    |> Seq.toList

  override __.CmdName = "search"

  override __.CmdAlias = [ "s" ]

  override __.CmdDescr = "Search expressions."

  override __.CmdHelp =
    "Usage: search <type> [expr]\n\n\
     Search the given expression from the binary.\n\
     <type> is the data type for the expression, which can be:\n\
       - s (string)\n\
       - h (hex string)"

  override __.SubCommands = []

  member __.Search hdl strPattern bytePattern =
    let ret = [| "[*] Searching for (" + strPattern + ") ..." |]
    match search hdl bytePattern with
    | [] -> Array.append ret [| "[*] The pattern not found." |]
    | results ->
      Array.append ret (List.toArray results)

  member __.CmdHandle hdl (pattern: string) = function
    | "s" | "string" ->
      Text.Encoding.ASCII.GetBytes pattern |> __.Search hdl pattern
    | "h" | "hex" ->
      ByteArray.ofHexString pattern |> __.Search hdl pattern
    | c -> [| "Unknown type " + c |]

  override __.CallBack _ ess args =
    match args with
    | []
    | _ :: [] -> [| __.CmdHelp |]
    | t :: pattern :: _ -> t.ToLower () |> __.CmdHandle ess.BinHandle pattern
    |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
