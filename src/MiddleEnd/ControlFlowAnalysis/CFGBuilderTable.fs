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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

type CFGBuilderTable<'FnCtx,
                     'GlCtx when 'FnCtx :> IResettable
                             and 'FnCtx: (new: unit -> 'FnCtx)
                             and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl, exnInfo, instrs, cfgConstructor) =

  let builders =
    SortedList<Addr, ICFGBuildable<'FnCtx, 'GlCtx>> ()

  let getOrCreateInternalBuilder managerMsgbox addr mode =
    match builders.TryGetValue addr with
    | true, builder -> builder
    | false, _ ->
      let builder =
        InternalFnCFGBuilder (hdl,
                              exnInfo,
                              instrs,
                              addr,
                              mode,
                              cfgConstructor,
                              managerMsgbox)
      builders[addr] <- builder
      builder

  let loadFromPLT (elf: ELFBinFile) =
    elf.PLT
    |> ARMap.iter (fun range entry ->
      match ELF.findInternalFuncReloc elf entry with
      | Ok fnAddr ->
        (* We create a mapping from a PLT address to an internal function
           address because some static binaries have a PLT entry for an internal
           function. *)
        let mode = ArchOperationMode.NoMode
        let builder = getOrCreateInternalBuilder null fnAddr mode
        builders[range.Min] <- builder
      | Error _ ->
        let addr, name = entry.TableAddress, entry.FuncName
        let isNoRet = ELF.getNoReturnStatusFromKnownFunc name
        let builder = ExternalFnCFGBuilder (hdl, exnInfo, addr, name, isNoRet)
        builders[range.Min] <- builder
    )

  (* Load external function builders by parsing the PLT. *)
  do match hdl.File.Format with
     | FileFormat.ELFBinary -> hdl.File :?> ELFBinFile |> loadFromPLT
     | _ -> ()

  /// Retrieve a function builder by its address.
  member _.Item with get(addr:Addr) = builders[addr]

  /// Retrieve all function builders.
  member _.Values with get() = builders.Values |> Seq.toArray

  /// Get the CFG constructor associated with this table.
  member _.CFGConstructor with get() = cfgConstructor

  /// Return the current termination status of all function builders.
  member _.GetTerminationStatus () =
    let mutable allDone = true
    let forceTerminated = List ()
    for bld in builders.Values do
      if bld.BuilderState = Finished || bld.BuilderState = Invalid then ()
      else allDone <- false
      if bld.Context.ForceFinish then forceTerminated.Add bld else ()
    if allDone && forceTerminated.Count = 0 then AllDone
    elif allDone then ForceTerminated <| forceTerminated.ToArray ()
    else YetDone

  /// Get or create a function builder by its address and operation mode.
  member _.GetOrCreateBuilder managerMsgbox addr mode =
    getOrCreateInternalBuilder managerMsgbox addr mode

  /// Update existing function builder to have a new manager msgbox.
  member _.Reload (builder: ICFGBuildable<_, _>) managerMsgbox =
    let old = builders[builder.EntryPoint]
    builders[builder.EntryPoint] <- old.MakeNew managerMsgbox

  /// Try to retrieve a function builder by its address.
  member _.TryGetBuilder (addr: Addr) =
    match builders.TryGetValue addr with
    | true, builder -> Ok builder
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Try to retrieve a function builder right next (based on its address) to
  /// the builder of the given address.
  member _.TryGetNextBuilder (addr: Addr) =
    match builders.IndexOfKey addr with
    | -1 -> Error ErrorCase.ItemNotFound
    | idx ->
      if idx + 1 < builders.Count then Ok <| builders.GetValueAtIndex (idx + 1)
      else Error ErrorCase.ItemNotFound

and TerminationStatus<'FnCtx,
                      'GlCtx when 'FnCtx :> IResettable
                              and 'FnCtx: (new: unit -> 'FnCtx)
                              and 'GlCtx: (new: unit -> 'GlCtx)> =
  /// Everything is finished and there's no forcefully terminated builders.
  | AllDone
  /// Everything is finished, but there are some builders that are forcefully
  /// terminated, which need to be reanalyzed.
  | ForceTerminated of ICFGBuildable<'FnCtx, 'GlCtx>[]
  /// Not all builders are finished.
  | YetDone