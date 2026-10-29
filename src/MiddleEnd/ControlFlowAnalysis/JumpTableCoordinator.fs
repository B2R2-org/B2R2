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

  let transferOwnership fnAddr oldFnAddr (jmptbl: JmpTableInfo) =
#if CFGDEBUG
    dbglog ManagerTid "JumpTable shared"
    <| $"change owner from {oldFnAddr:x} to {fnAddr:x}"
#endif
    let waitingFunctions = notes.Unregister(jmptbl.TableAddress, oldFnAddr)
    restartIfNotInProgress builders[oldFnAddr]
    let result = notes.Register(fnAddr, jmptbl)
    assert (result = RegistrationSucceeded)
    notes.AddWaitingFunction(jmptbl.TableAddress, oldFnAddr)
    for waitingFnAddr in waitingFunctions do
      notes.AddWaitingFunction(jmptbl.TableAddress, waitingFnAddr)
    GoRecovery

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
      let result = notes.Register(fnAddr, jmptbl)
      assert (result = RegistrationSucceeded)
      GoRecovery
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

  let register fnAddr jmptbl =
    match notes.Register(fnAddr, jmptbl) with
    | RegistrationSucceeded ->
#if CFGDEBUG
      dbglog ManagerTid "JumpTable registered"
      <| notes.GetNoteString jmptbl.TableAddress
#endif
      GoRecovery
    | SharedByFunctions oldFnAddr ->
      shareByFunctions fnAddr oldFnAddr jmptbl
    | SharedByInstructions ->
      shareByInstructions fnAddr jmptbl
    | OverlappingNote oldNote ->
      resolveOverlap fnAddr jmptbl oldNote

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
  /// by shrinking the table to the entries before it. Returns true if there
  /// was such an entry.
  member _.Rollback(builder: ICFGBuildable<'FnCtx, 'GlCtx>) =
    match builder.Context.JumpTableRecoveryStatus.TryPeek() with
    | false, _ ->
      false
    | true, (tblAddr, idx) ->
#if CFGDEBUG
      dbglog ManagerTid "Rollback for jump table"
      <| $"{tblAddr:x}[{idx}] @ {builder.EntryPoint:x}"
#endif
      assert (idx > 0)
      notes.SetPotentialEndPointByIndex(tblAddr, idx - 1)
      true

  /// Has the function ever recovered a jump table? This stays true even after
  /// the function is rebuilt from scratch.
  member _.HasJumpTable fnAddr = hostFunctions.Contains fnAddr
