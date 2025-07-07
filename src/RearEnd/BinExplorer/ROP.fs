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
open B2R2.RearEnd.Utils
open B2R2.RearEnd.ROP

type CmdGadgetSearch () =
  inherit Cmd ()

  override _.CmdName = "gadgetlist"

  override _.CmdAlias = [ "gl" ]

  override _.CmdDescr = "Search for the list of ROP gadgets."

  override _.CmdHelp = "Usage: gadgetlist\n\n\
                        Show the list of available ROP gadgets."

  override _.SubCommands = []

  override _.CallBack _ ess _args =
    let hdl = ess.BinHandle
    let liftingUnit = hdl.NewLiftingUnit ()
    [| Galileo.findGadgets hdl |> GadgetMap.toString liftingUnit |]
    |> Array.map OutputNormal

type CmdROP () =
  inherit Cmd ()

  member _.ShowResult hdl = function
    | Some payload -> [| ROPPayload.toString hdl 0u payload |]
    | None -> [| "Cannot find gadgets." |]

  override _.CmdName = "rop"

  override _.CmdAlias = []

  override _.CmdDescr = "Compile an ROP chain."

  override _.CmdHelp =
    "Usage: rop <cmd> [options]\n\n\
     Compile a ROP chain based on the given command.\n\
     - exec: a ROP payload for invoking a shell (execve)\n\
     - func: a ROP payload for calling a function at a specific target.\n\
     - write: a ROP payload for writing a value to a target memory.\n\
     - pivot: a ROP payload for stack pivoting."

  override _.SubCommands = []

  override this.CallBack _ ess args =
    let hdl = ess.BinHandle
    match hdl.File.ISA with
    | X86 ->
      let rop = ROPHandle.init hdl 0UL
      this.HandleSubCmd rop args
      |> Array.map OutputNormal
    | isa ->
      [| $"[*] We currently do not support {isa}" |]
      |> Array.map OutputNormal

  member private this.HandleSubCmd rop args =
    match args with
    | "exec" :: _ ->
      ROPHandle.execShell rop
      |> this.ShowResult rop.LiftingUnit
    | "func" :: target :: args ->
      let args = Array.ofList args |> Array.map ROPExpr.ofUInt32
      ROPHandle.funCall rop (ROPExpr.ofUInt32 target) args
      |> this.ShowResult rop.LiftingUnit
    | "write" :: target :: vals ->
      let vals = Array.ofList vals |> Array.map ROPExpr.ofUInt32
      ROPHandle.write32s rop (ROPExpr.ofUInt32 target) vals
      |> this.ShowResult rop.LiftingUnit
    | "pivot" :: [ esp ] ->
      ROPHandle.stackPivot rop (ROPExpr.ofUInt32 esp)
      |> this.ShowResult rop.LiftingUnit
    | _ -> [| "[*] Unknown ROP cmd." |]

// vim: set tw=80 sts=2 sw=2:
