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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

type CFGBuilderTable<'FnCtx, 'GlCtx>
  public(hdl, exnInfo, irBlkOptimizer, strategy) =

  let builders = SortedList<Addr, IFunctionBuilder>()

  /// The instruction set a function starts in when nothing says which: the
  /// one the ISA names, or in a raw image the one BinHandle picks, which an odd
  /// base address makes Thumb. Only 32-bit ARM has a choice, and every other
  /// ISA reads its one instruction set under the name of ARM.
  let defaultEntryMode =
    match (hdl: BinHandle).ISA with
    | ARM32 when hdl.File.Format = FileFormat.RawBinary ->
      if hdl.NewLiftingUnit().IsThumb then ARM32Mode.Thumb else ARM32Mode.ARM
    | ARM32 ->
      hdl.ISA.ARM32Mode
    | _ ->
      ARM32Mode.ARM

  /// Makes the collection of the instructions in the given instruction set,
  /// which starts sweeping the binary in it.
  let collectInstructions mode =
    let unit = hdl.NewLiftingUnit()
    unit.IsThumb <- (mode = ARM32Mode.Thumb)
    InstructionCollection(LinearSweepInstructionCollector(hdl, unit))

  let armInstrs = lazy collectInstructions ARM32Mode.ARM

  let thumbInstrs = lazy collectInstructions ARM32Mode.Thumb

  let instrsOf mode =
    if mode = ARM32Mode.Thumb then thumbInstrs.Value else armInstrs.Value

  let defaultInstrs = instrsOf defaultEntryMode

  /// The instruction sets that functions are known to start in, noted before
  /// their builders are made.
  let entryModes = Dictionary<Addr, ARM32Mode>()

  let entryModeOf addr =
    match entryModes.TryGetValue addr with
    | true, mode -> mode
    | false, _ -> defaultEntryMode

  /// Returns the builder of a function that the binary defines, or None for an
  /// external function, which has nothing to build.
  let tryAsBuildable (builder: IFunctionBuilder) =
    match builder with
    | :? ICFGBuildable<'FnCtx, 'GlCtx> as builder -> Some builder
    | _ -> None

  let asBuildable addr builder =
    match tryAsBuildable builder with
    | Some builder -> builder
    | None -> invalidOp $"Nothing builds the external function at {addr:x}."

  let updateNextFunctionOfPrevBuilder idx addr =
    if idx <= 0 then ()
    else builders.Values[idx - 1].NextFunctionAddress <- Some addr

  let updateNextFunctionOfNewBuilder (newBuilder: IFunctionBuilder) idx =
    let endPoint =
      if idx = (builders.Count - 1) then None
      else Some(builders.Values[idx + 1].EntryPoint)
    newBuilder.NextFunctionAddress <- endPoint

  let updateNextFunctionAddrs newBuilder addr =
    let idx = builders.IndexOfKey addr
    updateNextFunctionOfPrevBuilder idx addr
    updateNextFunctionOfNewBuilder newBuilder idx

  let getOrCreateInternalBuilder managerMsgbox addr =
    match builders.TryGetValue addr with
    | true, builder ->
      tryAsBuildable builder
    | false, _ ->
      let builder =
        InternalFnCFGBuilder(hdl,
                             exnInfo,
                             instrsOf (entryModeOf addr),
                             addr,
                             managerMsgbox,
                             irBlkOptimizer,
                             strategy) :> ICFGBuildable<'FnCtx, 'GlCtx>
      builders[addr] <- builder
      updateNextFunctionAddrs builder addr
      Some builder

  let isOwnFunctionSlot slot =
    BinFileOps.tryGetInternalFunctionAddr hdl.File slot |> Result.isOk

  let addExternalBuilder (reference: ExternalFunctionReference) symbol name =
    let cc = hdl.Conventions.Calling
    let isNoRet = ELF.getNoReturnStatusFromKnownFunc cc symbol
    let builder = ExternalFnCFGBuilder(hdl, reference, name, isNoRet)
    builders[reference.ReferenceAddress] <- builder
    builder :> IFunctionBuilder

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

  let rec getTerminationStatus (builders: IList<IFunctionBuilder>) acc idx =
    if idx < 0 then
      if List.isEmpty acc then AllDone else ForceTerminated <| List.toArray acc
    else
      let b = builders[idx]
      match b.BuilderState with
      | Finished | Invalid ->
        getTerminationStatus builders acc (idx - 1)
      | ForceFinished ->
        let acc = asBuildable b.EntryPoint b :: acc
        getTerminationStatus builders acc (idx - 1)
      | _ ->
        YetDone

  /// Splits off the instruction set that a 32-bit ARM binary states in the
  /// lowest bit of a function address, which it sets for Thumb, from where the
  /// function starts. A raw image states nothing that way, as its addresses
  /// are wherever it was loaded.
  let trySplitEntry addr =
    let isRaw = hdl.File.Format = FileFormat.RawBinary
    match hdl.ISA with
    | ARM32 when not isRaw && addr % 2UL = 1UL ->
      Some(addr - 1UL, ARM32Mode.Thumb)
    | _ ->
      None

  (* Load external function builders from the import (PLT/linkage) table. *)
  do match hdl.File.ImportTable with
     | Some tbl -> loadFromImportTable hdl.File tbl
     | _ -> ()

  /// Retrieves the builder of the function at the given address, which the
  /// binary defines. This raises an exception for an external function.
  member _.Item with get(addr: Addr) = asBuildable addr builders[addr]

  /// Retrieves all function builders, including those of external functions.
  member _.Values with get() = builders.Values |> Seq.toArray

  /// The instructions in the instruction set that functions start in when
  /// nothing says otherwise.
  member _.Instructions with get() = defaultInstrs

  /// Returns where the function at the given address starts, and notes the
  /// instruction set that the address states for the builder to come.
  member _.RegisterEntry(addr: Addr) =
    match trySplitEntry addr with
    | Some(entry, mode) ->
      entryModes[entry] <- mode
      entry
    | None ->
      addr

  /// Notes that the callee starts in the instruction set of its caller, as a
  /// call that does not switch instruction sets says, unless a builder or a
  /// note for the callee came first.
  member _.InheritEntryMode(callee, caller) =
    if builders.ContainsKey callee || entryModes.ContainsKey callee then ()
    else entryModes[callee] <- entryModeOf caller

  /// Returns the current termination status of all function builders.
  member _.GetTerminationStatus() =
    getTerminationStatus builders.Values [] (builders.Count - 1)

  /// Gets or creates the builder of the function at the given address. This
  /// returns None if an external function sits at the address, as there is
  /// nothing to build.
  member _.TryGetOrCreateBuilder(managerMsgbox, addr) =
    getOrCreateInternalBuilder managerMsgbox addr

  /// Gets or creates an external function builder for the given reference.
  member _.GetOrCreateExternalBuilder(reference, name) =
    getOrCreateExternalBuilder reference name

  /// Tries to retrieve the builder of the function at the given address, which
  /// may be an external function.
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
