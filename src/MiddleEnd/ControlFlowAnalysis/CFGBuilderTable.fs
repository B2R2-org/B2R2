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
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

type CFGBuilderTable<'FnCtx,
                     'GlCtx when 'FnCtx :> IResettable
                             and 'FnCtx: (new: unit -> 'FnCtx)
                             and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl, exnInfo, instrs) =

  let builders =
    SortedList<Addr, ICFGBuildable<'FnCtx, 'GlCtx>> ()

  let updateNextFunctionOfPrevBuilder idx addr =
    if idx <= 0 then ()
    else builders.Values[idx - 1].NextFunctionAddress <- Some addr

  let updateNextFunctionOfNewBuilder (newBuilder: ICFGBuildable<_, _>) idx =
    let endPoint =
      if idx = (builders.Count - 1) then None
      else Some (builders.Values[idx + 1].EntryPoint)
    newBuilder.NextFunctionAddress <- endPoint

  let updateNextFunctionAddrs newBuilder addr =
    let idx = builders.IndexOfKey addr
    updateNextFunctionOfPrevBuilder idx addr
    updateNextFunctionOfNewBuilder newBuilder idx

  let getOrCreateInternalBuilder managerMsgbox addr =
    match builders.TryGetValue addr with
    | true, builder -> builder
    | false, _ ->
      let builder =
        InternalFnCFGBuilder (hdl,
                              exnInfo,
                              instrs,
                              addr,
                              managerMsgbox) :> ICFGBuildable<'FnCtx, 'GlCtx>
      builders[addr] <- builder
      updateNextFunctionAddrs builder addr
      builder

  let loadFromPLT (elf: ELFBinFile) =
    elf.PLT
    |> NoOverlapIntervalMap.iter (fun range entry ->
      match ELF.findInternalFuncReloc elf entry with
      | Ok fnAddr ->
        (* We create a mapping from a PLT address to an internal function
           address because some static binaries have a PLT entry for an internal
           function. *)
        let builder = getOrCreateInternalBuilder null fnAddr
        builders[fnAddr] <- builder
      | Error _ ->
        let addr, name = entry.TrampolineAddress, entry.FuncName
        let isNoRet = ELF.getNoReturnStatusFromKnownFunc name
        let builder = ExternalFnCFGBuilder (hdl, exnInfo, addr, name, isNoRet)
        builders[range.Min] <- builder
    )

  let rec getTerminationStatus (builders: IList<ICFGBuildable<_, _>>) acc idx =
    if idx < 0 then
      if List.isEmpty acc then AllDone
      else ForceTerminated <| List.toArray acc
    else
      let b = builders[idx]
      match b.BuilderState with
      | Finished | Invalid -> getTerminationStatus builders acc (idx - 1)
      | ForceFinished -> getTerminationStatus builders (b :: acc) (idx - 1)
      | _ -> YetDone

  (* Load external function builders by parsing the PLT. *)
  do match hdl.File.Format with
     | FileFormat.ELFBinary -> hdl.File :?> ELFBinFile |> loadFromPLT
     | _ -> ()

  /// Retrieve a function builder by its address.
  member _.Item with get(addr: Addr) = builders[addr]

  /// Retrieve all function builders.
  member _.Values with get() = builders.Values |> Seq.toArray

  /// Return the current termination status of all function builders.
  member _.GetTerminationStatus () =
    getTerminationStatus builders.Values [] (builders.Count - 1)

  /// Get or create a function builder by its address.
  member _.GetOrCreateBuilder managerMsgbox addr =
    getOrCreateInternalBuilder managerMsgbox addr

  /// Update existing function builder to have a new manager msgbox.
  member _.Reload (builder: ICFGBuildable<_, _>) managerMsgbox =
    let old = builders[builder.EntryPoint]
    builders[builder.EntryPoint] <- old.MakeNew managerMsgbox

  /// Try to retrieve a function builder by its address.
  member _.TryGetBuilder (addr: Addr) =
    match builders.TryGetValue addr with
    | true, builder -> Ok builder
    | false, _ -> Error ErrorCase.ItemNotFound

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