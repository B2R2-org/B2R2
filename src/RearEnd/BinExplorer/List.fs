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

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinEssence

type CmdList () =
  inherit Cmd ()

  let createFuncString hdl (addr, name) =
    Addr.toString hdl.ISA.WordSize addr + ": " + name

  let listFunctions ess =
    ess.CodeManager.FunctionMaintainer.RegularFunctions
    |> Seq.map (fun c -> c.EntryPoint, c.FunctionID)
    |> Seq.sortBy fst
    |> Seq.map (createFuncString ess.BinHandle)
    |> Seq.toArray

  let createSegmentString handler (seg: Segment) =
    "- "
    + Addr.toString handler.ISA.WordSize seg.Address
    + ":"
    + Addr.toString handler.ISA.WordSize (seg.Address + seg.Size)
    + " (" + seg.Size.ToString () + ") ("
    + BinFile.PermissionToString seg.Permission + ")"

  let listSegments (handler: BinHandle) =
    handler.BinFile.GetSegments ()
    |> Seq.map (createSegmentString handler)
    |> Seq.toArray

  let createSectionString handler (idx: int) (sec: Section) =
    idx.ToString ("D2")
    + ". "
    + Addr.toString handler.ISA.WordSize sec.Address
    + ":"
    + Addr.toString handler.ISA.WordSize (sec.Address + sec.Size)
    + " (" + sec.Size.ToString ("D6") + ")"
    + " [" + sec.Name + "] "

  let listSections (handler: BinHandle) =
    handler.BinFile.GetSections ()
    |> Seq.mapi (createSectionString handler)
    |> Seq.toArray

  override __.CmdName = "list"

  override __.CmdAlias = [ "ls" ]

  override __.CmdDescr = "List the contents of the binary."

  override __.CmdHelp =
    "Usage: list <cmds> [options]\n\n\
     Currently available commands are:\n\
     - functions: List functions in the binary.\n\
     - segments: List segments to be loaded.\n\
     - sections: List sections in the binary."

  override __.SubCommands = [ "functions"; "segments"; ]

  override __.CallBack _ (ess: BinEssence) args =
    match args with
    | "functions" :: _
    | "funcs" :: _ -> listFunctions ess
    | "segments" :: _
    | "segs" :: _ -> listSegments ess.BinHandle
    | "sections" :: _
    | "secs" :: _ -> listSections ess.BinHandle
    | _ -> [| "[*] Unknown list cmd is given." |]
    |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:
