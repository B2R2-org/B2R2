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

type CFGBuilderTable<'FnCtx, 'GlCtx>
  public(hdl, exnInfo, instrs, irBlkOptimizer, contexts) =

  let builders = SortedList<Addr, ICFGBuildable<'FnCtx, 'GlCtx>>()

  let updateNextFunctionOfPrevBuilder idx addr =
    if idx <= 0 then ()
    else builders.Values[idx - 1].NextFunctionAddress <- Some addr

  let updateNextFunctionOfNewBuilder (newBuilder: ICFGBuildable<_, _>) idx =
    let endPoint =
      if idx = (builders.Count - 1) then None
      else Some(builders.Values[idx + 1].EntryPoint)
    newBuilder.NextFunctionAddress <- endPoint

  let updateNextFunctionAddrs newBuilder addr =
    let idx = builders.IndexOfKey addr
    updateNextFunctionOfPrevBuilder idx addr
    updateNextFunctionOfNewBuilder newBuilder idx

  let createFunctionContext () =
    (contexts: IContextProvidable<'FnCtx, 'GlCtx>).CreateFunctionContext()

  let getOrCreateInternalBuilder managerMsgbox addr =
    match builders.TryGetValue addr with
    | true, builder ->
      builder
    | false, _ ->
      let fnCtx = createFunctionContext ()
      let builder =
        InternalFnCFGBuilder(hdl,
                             exnInfo,
                             instrs,
                             addr,
                             managerMsgbox,
                             irBlkOptimizer,
                             fnCtx) :> ICFGBuildable<'FnCtx, 'GlCtx>
      builders[addr] <- builder
      updateNextFunctionAddrs builder addr
      builder

  let isOwnFunctionSlot slot =
    BinFileOps.tryGetInternalFunctionAddr hdl.File slot |> Result.isOk

  let addExternalBuilder (reference: ExternalFunctionReference) symbol name =
    let isNoRet = ELF.getNoReturnStatusFromKnownFunc symbol
    let fnCtx = createFunctionContext ()
    let builder =
      ExternalFnCFGBuilder(hdl, exnInfo, reference, name, isNoRet, fnCtx)
    builders[reference.ReferenceAddress] <- builder
    builder

  /// Tags the symbol with the kind of the reference, for a reference to a
  /// function that this binary defines itself, so that the reference does not
  /// take the name of the function it refers to.
  let tagOwnSymbol reference symbol =
    match reference with
    | PLTTrampoline _ -> symbol + "@plt"
    | RelocationSlot _ -> symbol + "@got"

  let getOrCreateExternalBuilder (reference: ExternalFunctionReference) name =
    match builders.TryGetValue reference.ReferenceAddress with
    | true, builder ->
      builder
    | false, _ ->
      match reference with
      | RelocationSlot slot when isOwnFunctionSlot slot ->
        addExternalBuilder reference name (tagOwnSymbol reference name)
      | _ ->
        addExternalBuilder reference name name

  /// Finds the symbol that an import stub refers to when its slot resolves to
  /// a function of this binary. An ifunc slot names no symbol, but the ifunc
  /// symbol sits at the address of its resolver, which is where we find it.
  let tryFindOwnSymbol file (entry: BinImport) fnAddr =
    if entry.Name <> "" then
      Some entry.Name
    else
      match BinFileOps.tryResolveName file fnAddr with
      | Ok name when name <> "" -> Some name
      | _ -> None

  /// Adds the builder for an import stub whose slot resolves to a function of
  /// this binary. The stub only refers to that function, which the loader may
  /// still interpose on or an ifunc resolver may pick, so it is an import all
  /// the same, tagged so as not to take the name of the function itself.
  let addOwnImportBuilder file entry fnAddr stubAddr =
    let reference = PLTTrampoline stubAddr
    match tryFindOwnSymbol file entry fnAddr with
    | Some symbol ->
      let name = tagOwnSymbol reference symbol
      addExternalBuilder reference symbol name |> ignore
    | None ->
      addExternalBuilder reference "" (Addr.toFuncName stubAddr) |> ignore

  let loadFromImportTable (file: IBinFile) (tbl: IImportTable) =
    for entry in tbl.Imports do
      match entry.TrampolineAddress with
      | Some stubAddr ->
        match BinFileOps.tryGetInternalFunctionAddr file entry.TableAddress with
        | Ok fnAddr ->
          addOwnImportBuilder file entry fnAddr stubAddr
        | Error _ ->
          let reference = PLTTrampoline stubAddr
          addExternalBuilder reference entry.Name entry.Name |> ignore
      | None ->
        ()

  let rec getTerminationStatus (builders: IList<ICFGBuildable<_, _>>) acc idx =
    if idx < 0 then
      if List.isEmpty acc then AllDone else ForceTerminated <| List.toArray acc
    else
      let b = builders[idx]
      match b.BuilderState with
      | Finished | Invalid -> getTerminationStatus builders acc (idx - 1)
      | ForceFinished -> getTerminationStatus builders (b :: acc) (idx - 1)
      | _ -> YetDone

  (* Load external function builders from the import (PLT/linkage) table. *)
  do match hdl.File.ImportTable with
     | Some tbl -> loadFromImportTable hdl.File tbl
     | _ -> ()

  /// Retrieves a function builder by its address.
  member _.Item with get(addr: Addr) = builders[addr]

  /// Retrieves all function builders.
  member _.Values with get() = builders.Values |> Seq.toArray

  /// Returns the current termination status of all function builders.
  member _.GetTerminationStatus() =
    getTerminationStatus builders.Values [] (builders.Count - 1)

  /// Gets or creates a function builder by its address.
  member _.GetOrCreateBuilder(managerMsgbox, addr) =
    getOrCreateInternalBuilder managerMsgbox addr

  /// Gets or creates an external function builder for the given reference.
  member _.GetOrCreateExternalBuilder(reference, name) =
    getOrCreateExternalBuilder reference name

  /// Updates the existing function builder to have a new manager msgbox.
  member _.Reload(builder: ICFGBuildable<_, _>, managerMsgbox) =
    let old = builders[builder.EntryPoint]
    builders[builder.EntryPoint] <- old.MakeNew managerMsgbox

  /// Tries to retrieve a function builder by its address.
  member _.TryGetBuilder(addr: Addr) =
    match builders.TryGetValue addr with
    | true, builder -> Ok builder
    | false, _ -> Error ErrorCase.ItemNotFound

and TerminationStatus<'FnCtx, 'GlCtx> =
  /// Everything is finished and there's no forcefully terminated builders.
  | AllDone
  /// Everything is finished, but there are some builders that are forcefully
  /// terminated, which need to be reanalyzed.
  | ForceTerminated of ICFGBuildable<'FnCtx, 'GlCtx>[]
  /// Not all builders are finished.
  | YetDone
