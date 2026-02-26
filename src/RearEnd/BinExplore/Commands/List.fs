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

namespace B2R2.RearEnd.BinExplore.Commands

open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.RearEnd.BinExplore

type List() =
  let createFuncString (hdl: BinHandle) (addr, name) =
    Addr.toString hdl.File.ISA.WordSize addr + ": " + name

  let listFunctions (brew: BinaryBrew<_, _>) =
    brew.Functions.Sequence
    |> Seq.map (fun c -> c.EntryPoint, c.Name)
    |> Seq.sortBy fst
    |> Seq.map (createFuncString brew.BinHandle)
    |> Seq.toArray

  let createRegionString wordSize (region: AddrRange) =
    let size = region.Max - region.Min + 1UL
    "- "
    + Addr.toString wordSize region.Min
    + ":"
    + Addr.toString wordSize region.Max
    + " (" + size.ToString() + ")"

  let listSegments (hdl: BinHandle) =
    let wordSize = hdl.File.ISA.WordSize
    hdl.File.GetVMMappedRegions()
    |> Seq.map (createRegionString wordSize)
    |> Seq.toArray

  interface ICmd with

    member _.CmdName = "list"

    member _.CmdAlias = [ "ls" ]

    member _.CmdDescr = "List the contents of the binary."

    member _.CmdHelp =
      "Usage: list <cmds> [options]\n\n\
      Currently available commands are:\n\
      - functions: List functions in the binary.\n\
      - segments: List segments to be loaded.\n\
      - sections: List sections in the binary."

    member _.SubCommands = [ "functions"; "segments" ]

    member _.CallBack(brew, args) =
      match args with
      | "functions" :: _
      | "funcs" :: _ -> listFunctions brew
      | "segments" :: _
      | "segs" :: _ -> listSegments brew.BinHandle
      | _ -> [| "[*] Unknown list cmd is given." |]
      |> Array.map OutputNormal
