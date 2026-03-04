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
  let [<Literal>] CmdName = "list"

  let [<Literal>] Desc = "List the contents of the binary."

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

    member _.CmdName = CmdName

    member _.CmdAlias = [ "ls" ]

    member _.CmdDescr = Desc

    member _.CmdHelp =
      ColoredString()
        .Add(NoColor, "Usage: ")
        .Add(DarkCyan, $"{CmdName}")
        .Add(NoColor, " <cmds> [options]\n\n")
        .Add(NoColor, $"{Desc}\n\n")
        .Add(NoColor, $"Currently available commands are:\n")
        .Add(NoColor, $"- functions: List functions in the binary.\n")
        .Add(NoColor, $"- segments: List segments in the binary.\n")
        .Add(NoColor, $"- sections: List sections in the binary.")

    member _.SubCommands = [ "functions"; "segments" ]

    member _.CallBack(arbiter, args) =
      match args, arbiter.GetBinaryBrew() with
      | "functions" :: _, Some brew
      | "funcs" :: _, Some brew ->
        listFunctions brew
        |> Array.map OutputNormal
      | "segments" :: _, Some brew
      | "segs" :: _, Some brew ->
        listSegments brew.BinHandle
        |> Array.map OutputNormal
      | _, None ->
        ICmd.buildErrorOutput "No binary is currently loaded."
      | _ ->
        ICmd.buildErrorOutput "Unknown list cmd is given."
