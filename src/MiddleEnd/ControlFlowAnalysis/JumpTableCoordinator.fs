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

/// Represents the manager-side coordinator of jump table recovery. Jump tables
/// can be shared or overlapped by multiple functions, so this arbitrates them
/// across functions. This is not thread-safe, so it should be accessed only by
/// the TaskManager.
type JumpTableCoordinator<'FnCtx, 'GlCtx>
  public(builders: CFGBuilderTable<'FnCtx, 'GlCtx>,
         restartIfNotInProgress: ICFGBuildable<'FnCtx, 'GlCtx> -> unit) =

  let notes = JmpTableRecoveryNotebook()

  /// Functions that have recovered a jump table at least once.
  let hostFunctions = HashSet<Addr>()

  /// Restarts the functions that recover the given phantom tables, which start
  /// within the entries of the table that the given function has registered.
  /// The given function reloads instead if it is one of them.
  let restartPhantomHosts fnAddr phantoms =
    let hosts = HashSet<Addr>()
    for note in phantoms do
#if CFGDEBUG
      dbglog ManagerTid "JumpTable phantom"
      <| notes.GetNoteString note.StartingPoint
#endif
      hosts.Add note.HostFunctionAddr |> ignore
      hosts.UnionWith note.WaitingFunctions
    for host in hosts do
      if host <> fnAddr then restartIfNotInProgress builders[host] else ()
    if hosts.Contains fnAddr then StopRecoveryButReload else GoRecovery

  /// Decides what the given function does after registering its table.
  let proceedAfterRegistration fnAddr (jmptbl: JmpTableInfo) result =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable registered"
    <| notes.GetNoteString jmptbl.TableAddress
#endif
    match result with
    | RegisteredOverPhantoms phantoms ->
      restartPhantomHosts fnAddr phantoms
    | _ ->
      assert (result = RegistrationSucceeded)
      GoRecovery

  let transferOwnership fnAddr oldFnAddr (jmptbl: JmpTableInfo) =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable shared"
    <| $"change owner from {oldFnAddr:x} to {fnAddr:x}"
#endif
    let waitingFunctions = notes.Unregister(jmptbl.TableAddress, oldFnAddr)
    restartIfNotInProgress builders[oldFnAddr]
    let result = notes.Register(fnAddr, jmptbl)
    notes.AddWaitingFunction(jmptbl.TableAddress, oldFnAddr)
    for waitingFnAddr in waitingFunctions do
      notes.AddWaitingFunction(jmptbl.TableAddress, waitingFnAddr)
    proceedAfterRegistration fnAddr jmptbl result

  let shareByFunctions fnAddr oldFnAddr (jmptbl: JmpTableInfo) =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable failed"
    <| $"{jmptbl.InsAddr:x}:{jmptbl.TableAddress:x} shared by two funcs."
#endif
    let smallerFnAddr = min oldFnAddr fnAddr
    let largerFnAddr = max oldFnAddr fnAddr
    let ownerFnAddr =
      if jmptbl.InsAddr < largerFnAddr then smallerFnAddr else largerFnAddr
    if oldFnAddr = ownerFnAddr then
#if CFGDEBUG
      dbglog ManagerTid "JumpTable shared"
      <| $"keep owner {oldFnAddr:x}; continue waiter {fnAddr:x}"
#endif
      notes.AddWaitingFunction(jmptbl.TableAddress, fnAddr)
      GoRecovery
    else
      assert (fnAddr = ownerFnAddr)
      transferOwnership fnAddr oldFnAddr jmptbl

  let shareByInstructions fnAddr (jmptbl: JmpTableInfo) =
#if CFGDEBUG
    let insAddr = jmptbl.InsAddr
    dbglog ManagerTid "JumpTable failed"
    <| $"{insAddr:x}:{jmptbl.TableAddress:x}) shared by two instrs."
#endif
    (* We found two different jmp instructions for the same jump table, in
       which case we cannot decide which one is wrong. Thus, we just ignore
       this error, meaning that we ignore the later found one. *)
    (* Instead, we add the instruction to the waiting list of the owning
       function's own jump table so that the edges can be added after the
       table is recovered by the first instruction. We deliberately keep this
       list in the function context (not in the global note) so that it is
       discarded together with the CFG whenever the builder is rolled back. *)
    let ctx = builders[fnAddr].Context
    match ctx.JumpTables.TryGetValue jmptbl.TableAddress with
    | true, ownerTbl ->
      if List.contains jmptbl.InsAddr ownerTbl.WaitingInstructions then
        ()
      else
        ownerTbl.WaitingInstructions <-
          jmptbl.InsAddr :: ownerTbl.WaitingInstructions
    | false, _ ->
      ()
    StopRecoveryAndContinue

  let resolveOverlap fnAddr (jmptbl: JmpTableInfo) oldNote =
    let oldTblAddr, newTblAddr = oldNote.StartingPoint, jmptbl.TableAddress
    let entrySize = uint64 jmptbl.EntrySize
    let newEndPoint = newTblAddr - entrySize
    let entryBeingAnalyzed = oldNote.ConfirmedEndPoint + entrySize
#if CFGDEBUG
    let str = notes.GetNoteString oldNote.StartingPoint
    dbglog ManagerTid "JumpTable overlap"
    <| $"{jmptbl.InsAddr:x}:{newTblAddr:x} overlapped with ({str})"
#endif
    notes.SetPotentialEndPointByAddr(oldTblAddr, newEndPoint)
    if entryBeingAnalyzed <= newEndPoint then
#if CFGDEBUG
      dbglog ManagerTid "JumpTable" $"overlap resolved and continue"
#endif
      notes.Register(fnAddr, jmptbl) |> proceedAfterRegistration fnAddr jmptbl
    else
#if CFGDEBUG
      dbglog ManagerTid "JumpTable rollback"
      <| $"changed potential endpoint to {oldNote.PotentialEndPoint:x}"
#endif
      if oldNote.HostFunctionAddr <> fnAddr then
        restartIfNotInProgress builders[oldNote.HostFunctionAddr]
      else
        ()
      StopRecoveryButReload

  let registerNote fnAddr jmptbl =
    match notes.Register(fnAddr, jmptbl) with
    | RegistrationSucceeded
    | RegisteredOverPhantoms _ as result ->
      proceedAfterRegistration fnAddr jmptbl result
    | SharedByFunctions oldFnAddr ->
      shareByFunctions fnAddr oldFnAddr jmptbl
    | SharedByInstructions ->
      shareByInstructions fnAddr jmptbl
    | OverlappingNote oldNote ->
      resolveOverlap fnAddr jmptbl oldNote
    | PhantomStart ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable phantom"
      <| $"{jmptbl.InsAddr:x}:{jmptbl.TableAddress:x} ignored"
#endif
      StopRecoveryAndContinue

  /// Registers the given table, unless it starts within the entries that the
  /// range check of another table admits, in which case its function learns
  /// where those entries end.
  let register fnAddr (jmptbl: JmpTableInfo) =
    match notes.TryFindHeldEnd jmptbl with
    | Some tableEnd ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable overlap"
      <| $"{jmptbl.InsAddr:x}:{jmptbl.TableAddress:x} lies before {tableEnd:x}"
#endif
      Overlapping tableEnd
    | None ->
      registerNote fnAddr jmptbl

  let markBogus fnAddr tblAddr idx =
    let currentIdx = notes.GetPotentialEndPointIndex tblAddr
    if idx > 0 && (idx - 1) <= currentIdx then
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus so set the idx to {idx-1}"
#endif
      notes.SetPotentialEndPointByIndex(tblAddr, idx - 1)
      true
    elif idx = 0 && idx < currentIdx then
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus so set the idx to 0"
#endif
      notes.SetPotentialEndPointByIndex(tblAddr, 0)
      true
    else
#if CFGDEBUG
      dbglog ManagerTid "BogusJumpTableEntry"
      <| $"{tblAddr:x}:[{idx}] @ {fnAddr:x} is bogus but didn't rollback"
#endif
      false

  let cancel fnAddr insAddr tblAddr =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable canceled" $"{insAddr:x} @ {fnAddr:x}"
#endif
    notes.Unregister(tblAddr, fnAddr) |> ignore

  let isExpandable fnAddr nextJumpTarget isFPTab =
    match builders[fnAddr].NextFunctionAddress with
    | Some nextFnAddr ->
      let nextBuilder = builders[nextFnAddr]
      isFPTab (* Since we are handling a function pointer table, we just go *)
      || (fnAddr < nextJumpTarget && nextJumpTarget < nextBuilder.EntryPoint)
    | None ->
      false

  let confirm fnAddr tblAddr idx nextJumpTarget isFPTab =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable success"
    <| $"{tblAddr:x}[{idx}] @ {fnAddr:x} -> {nextJumpTarget:x}"
#endif
    hostFunctions.Add fnAddr |> ignore
    notes.SetConfirmedEndPoint(tblAddr, idx)
    if notes.IsExpandable(tblAddr, idx + 1) then
      isExpandable fnAddr nextJumpTarget isFPTab
    else
      false

  /// Handles a jump table recovery request from a function builder.
  member _.Handle req =
    match req with
    | NotifyRecovery(fnAddr, jmptbl, ch) ->
      ch.Reply <| register fnAddr jmptbl
    | NotifyBogusEntry(fnAddr, tblAddr, idx, ch) ->
      ch.Reply <| markBogus fnAddr tblAddr idx
    | CancelRecovery(fnAddr, insAddr, tblAddr) ->
      cancel fnAddr insAddr tblAddr
    | ReportSuccess(fnAddr, tblAddr, idx, nextTarget, isFPTab, ch) ->
      ch.Reply <| confirm fnAddr tblAddr idx nextTarget isFPTab

  /// Rolls back the jump table entry that the builder was recovering, if any,
  /// by shrinking the table to the entries before it, or by marking the table
  /// as a phantom if the entry was its first. Returns true if there was such
  /// an entry.
  member _.Rollback(builder: ICFGBuildable<'FnCtx, 'GlCtx>) =
    match builder.Context.JumpTableRecoveryStatus.TryPeek() with
    | false, _ ->
      false
    | true, (tblAddr, 0) ->
#if CFGDEBUG
      dbglog ManagerTid "Rollback for jump table"
      <| $"{tblAddr:x}[0] @ {builder.EntryPoint:x} is a phantom"
#endif
      (* No entry is left, so no table starts there. *)
      notes.MarkPhantom tblAddr
      true
    | true, (tblAddr, idx) ->
#if CFGDEBUG
      dbglog ManagerTid "Rollback for jump table"
      <| $"{tblAddr:x}[{idx}] @ {builder.EntryPoint:x}"
#endif
      notes.SetPotentialEndPointByIndex(tblAddr, idx - 1)
      true

  /// Has the function ever recovered a jump table? This stays true even after
  /// the function is rebuilt from scratch.
  member _.HasJumpTable fnAddr = hostFunctions.Contains fnAddr
