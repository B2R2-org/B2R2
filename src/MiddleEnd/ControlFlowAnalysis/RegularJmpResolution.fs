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

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis.IRHelper
open B2R2.MiddleEnd.DataFlow

[<AutoOpen>]
module private RegularJmpResolution =

  let rec isJmpTblAddr cpState = function
    | Var v ->
      match Map.tryFind v cpState.SSAEdges.Defs with
      | Some (Def (_, e)) -> isJmpTblAddr cpState e
      | _ -> false
    | BinOp (BinOpType.MUL, _, _, Num _)
    | BinOp (BinOpType.MUL, _, Num _, _)
    | BinOp (BinOpType.SHL, _, _, Num _) -> true
    | BinOp (_, _, e1, e2) ->
      isJmpTblAddr cpState e1 || isJmpTblAddr cpState e2
    | _ -> false

  let rec extractTableExpr = function
    | BinOp (BinOpType.ADD, _, BinOp (BinOpType.MUL, _, _, Num _), e)
    | BinOp (BinOpType.ADD, _, BinOp (BinOpType.MUL, _, Num _, _), e)
    | BinOp (BinOpType.ADD, _, BinOp (BinOpType.SHL, _, _, Num _), e)
    | BinOp (BinOpType.ADD, _, e, BinOp (BinOpType.MUL, _, _, Num _))
    | BinOp (BinOpType.ADD, _, e, BinOp (BinOpType.MUL, _, Num _, _))
    | BinOp (BinOpType.ADD, _, e, BinOp (BinOpType.SHL, _, _, Num _)) -> e
    | BinOp (op, rt, e1, e2) ->
      BinOp (op, rt, extractTableExpr e1, extractTableExpr e2)
    | UnOp (op, rt, e) -> UnOp (op, rt, extractTableExpr e)
    | Cast (op, rt, e) -> Cast (op, rt, extractTableExpr e)
    | Extract (e, rt, pos) -> Extract (extractTableExpr e, rt, pos)
    | e -> e

  let computeMask size =
    let rt = RegType.fromByteWidth size
    (* It is reasonable enough to assume that jump target addresses will never
       overflow when rt is greater than 64<rt>. *)
    if rt > 64<rt> then 0xFFFFFFFFFFFFFFFFUL
    else BitVector.UnsignedMax rt |> BitVector.ToUInt64

  /// Read a table entry and compute jump target
  let readTable hdl bAddr (entryAddr: Addr) size =
    let addr = bAddr + BinHandle.ReadUInt (hdl, entryAddr, size)
    addr &&& computeMask size

  let recoverIndirectEdge bld fn src dst =
    let evts =
      CFGEvents.empty
      |> CFGEvents.addPerFuncAnalysisEvt (fn: RegularFunction).EntryPoint
      |> CFGEvents.addEdgeEvt fn src dst IndirectJmpEdge
    (bld: ICFGBuildable).Update evts

  let recoverOneEntry bld hdl codeMgr (dataMgr: DataManager) fn jt entryAddr =
    let dst = readTable hdl jt.BranchBaseAddr entryAddr jt.JTEntrySize
    let brAddr = jt.InstructionAddr
    let bblInfo = (codeMgr: CodeManager).GetBBL brAddr
    let src = bblInfo.IRLeaders |> Set.maxElement
#if CFGDEBUG
    dbglog "IndJmpRecovery" "@%x Recovering %x -> %x (%x)"
      (fn: RegularFunction).EntryPoint src.Address dst entryAddr
#endif
    recoverIndirectEdge bld fn src dst
    |> Result.bind (fun _ ->
      (* This is really an exceptional case where we found a nested switch
         table, whose location is overlapping with our current entryAddr.
         Thus, the potential end-point address has been updated during the
         Update process, and we found out late that our attempt with entryAddr
         was wrong. *)
      let ep = dataMgr.JumpTables.FindPotentialEndPoint jt.JTStartAddr
      if entryAddr >= ep then Error ErrorLateDetection
      else Ok dst)
    |> function
      | Ok recoveredAddr ->
#if CFGDEBUG
        dbglog "IndJmpRecovery" "Successfully recovered %x from %x (tbl %x)"
          recoveredAddr entryAddr jt.JTStartAddr
#endif
        let ep = entryAddr + uint64 jt.JTEntrySize
        dataMgr.JumpTables.UpdateConfirmedEndPoint jt.JTStartAddr ep |> Ok
      | Error e -> Error e

  let getJumpTables (fn: RegularFunction) =
    fn.IndirectJumps.Values
    |> Seq.fold (fun acc jmpKind ->
      match jmpKind with
      | JmpTbl tAddr -> tAddr :: acc
      | _ -> acc
    ) []
    |> List.rev

  /// Analyze less explored jump tables first.
  let sortJumpTablesByProgress (dataMgr: DataManager) jmpTbls =
    jmpTbls
    |> List.sortBy (fun addr ->
      (dataMgr.JumpTables.FindConfirmedEndPoint addr) - addr)

  /// We first recover the very first entry, since we are 100% sure about it.
  let rec getInitialRecoveryTarget (dataMgr: DataManager) = function
    | tAddr :: tl ->
      let endPoint = dataMgr.JumpTables.FindConfirmedEndPoint tAddr
      if tAddr = endPoint then (* First entry *)
        Some (dataMgr.JumpTables[tAddr], tAddr)
      else getInitialRecoveryTarget dataMgr tl
    | [] -> None

  let isSemanticallyNop hdl (ins: Instruction) =
    if ins.IsNop () then true
    else
      match BinHandle.LiftOptimizedInstr hdl ins with
      | [| { LowUIR.S = LowUIR.ISMark (_) }
           { LowUIR.S = LowUIR.IEMark (_) } |] -> true
      | _ -> false

  let rec findNextNonNopAddr hdl addr =
    match BinHandle.TryParseInstr (hdl, addr=addr) with
    | Ok ins ->
      if isSemanticallyNop hdl ins then
        findNextNonNopAddr hdl (addr + uint64 ins.Length)
      else Ok addr
    | Error e -> Error e

  /// We examine every gap address and see if each gap starts with a no-op
  /// chunk. If so, we add the first non-no-op instruction's address in the gap
  /// to gaps. This way, we do not miss valid indirect jumps that may point to a
  /// gap right after no-op instruction(s).
  let rearrangeGapsByNoOp hdl gaps =
    gaps
    |> Map.fold (fun gaps sAddr eAddr ->
      match findNextNonNopAddr hdl sAddr with
      | Ok nonNopAddr ->
        if sAddr <> nonNopAddr && nonNopAddr < eAddr then
          Map.remove sAddr gaps
          |> Map.add sAddr nonNopAddr
          |> Map.add nonNopAddr eAddr
        elif nonNopAddr = eAddr then Map.remove sAddr gaps
        else gaps
      | Error _ ->
        (* The gap contains data (as we cannot parse it), so we remove it. *)
        Map.remove sAddr gaps
    ) gaps

  /// Incrementally search for a jump table entry pointing to the current gap.
  /// The search continues until we find an invalid address in the table.
  let rec findGapPointingAddr hdl (dataMgr: DataManager) jt entryAddr gaps =
    let size = jt.JTEntrySize
    if dataMgr.JumpTables.FindPotentialEndPoint jt.JTStartAddr <= entryAddr then
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Nothing from gap (tbl %x) (potential = %x)"
        jt.JTStartAddr
        (dataMgr.JumpTables.FindPotentialEndPoint jt.JTStartAddr)
#endif
      None
    else
      let addr = readTable hdl jt.BranchBaseAddr entryAddr size
      if hdl.BinFile.IsValidAddr addr then
        let nextAddr = entryAddr + uint64 size
        if Map.containsKey addr gaps then
          let confirmedEndPoint =
            dataMgr.JumpTables.FindConfirmedEndPoint jt.JTStartAddr
          let entryAddr = min confirmedEndPoint entryAddr
#if CFGDEBUG
          dbglog "IndJmpRecovery" "Found entry %x (for tbl %x) from gap"
           entryAddr jt.JTStartAddr
#endif
          Some (jt, entryAddr)
        else findGapPointingAddr hdl dataMgr jt nextAddr gaps
      else
#if CFGDEBUG
        dbglog "IndJmpRecovery" "Invalid gap pointing addr %x => %x (tbl %x)"
          entryAddr addr jt.JTStartAddr
#endif
        None

  /// Find a recovery end-point address that can fill in the gap.
  let rec getRecoveryTargetFromGap hdl (dataMgr: DataManager) gaps = function
    | tAddr :: tl ->
      let jt = dataMgr.JumpTables[tAddr]
      let entryAddr = dataMgr.JumpTables.FindConfirmedEndPoint tAddr
      match findGapPointingAddr hdl dataMgr jt entryAddr gaps with
      | Some _ as target -> target
      | None -> getRecoveryTargetFromGap hdl dataMgr gaps tl
    | [] -> None

  /// Increment the current entry address of a jump table only if it can point
  /// to a valid entry.
  let incEntryAddr hdl fn nextFnAddr jt entryAddr =
    let addr = readTable hdl jt.BranchBaseAddr entryAddr jt.JTEntrySize
#if CFGDEBUG
    dbglog "IndJmpRecovery" "Read %x from %x" addr entryAddr
#endif
    if addr < (fn: RegularFunction).EntryPoint || addr >= nextFnAddr then None
    else Some entryAddr

  /// This is a less safer path than the gap-oriented search. We compute the
  /// next recovery end-point address by simply pointing to the next entry.
  let rec getNextRecoveryTargetFromTable hdl codeMgr dataMgr fn gaps = function
    | tAddr :: tl ->
      let jt = (dataMgr: DataManager).JumpTables[tAddr]
      let deadEnd = dataMgr.JumpTables.FindPotentialEndPoint tAddr
      let entryAddr = dataMgr.JumpTables.FindConfirmedEndPoint tAddr
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Last resort (tbl %x) %x < %x"
        tAddr entryAddr deadEnd
#endif
      if entryAddr < deadEnd then
        let nextFnAddr =
          (codeMgr: CodeManager).FunctionMaintainer.FindNextFunctionAddr fn
        match incEntryAddr hdl fn nextFnAddr jt entryAddr with
        | Some entry ->
#if CFGDEBUG
          dbglog "IndJmpRecovery" "Found entry %x from table (%x)"
            entry jt.JTStartAddr
#endif
          Some (jt, entry)
        | None -> getNextRecoveryTargetFromTable hdl codeMgr dataMgr fn gaps tl
      else getNextRecoveryTargetFromTable hdl codeMgr dataMgr fn gaps tl
    | [] -> None

  /// Get the next analysis target information, such as end-point addresses
  /// where we should stop our recovery process, for recovering jump tables.
  let getNextAnalysisTarget hdl codeMgr (dataMgr: DataManager) func =
    let jmpTbls =
      getJumpTables func
      |> sortJumpTablesByProgress dataMgr
#if CFGDEBUG
    dbglog "IndJmpRecovery" "%d table(s) at hand" (List.length jmpTbls)
#endif
    match getInitialRecoveryTarget dataMgr jmpTbls with
    | Some (jt, _) as target ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Found the first entry from table (%x)"
        jt.JTStartAddr
#endif
      target
    | None ->
      let gaps = (func: RegularFunction).GapAddresses |> rearrangeGapsByNoOp hdl
      match getRecoveryTargetFromGap hdl dataMgr gaps jmpTbls with
      | Some _ as target -> target
      | None ->
        getNextRecoveryTargetFromTable hdl codeMgr dataMgr func gaps jmpTbls

  let rec rollback
    (codeMgr: CodeManager) (dataMgr: DataManager) fn evts jt entryAddr e =
    let fnAddr = (fn: RegularFunction).EntryPoint
    let brAddr = jt.InstructionAddr
#if CFGDEBUG
    dbglog "IndJmpRecovery" "@%x Failed to recover %x (tbl %x), so rollback %s"
      fnAddr entryAddr jt.JTStartAddr (CFGError.toString e)
#endif
    dataMgr.JumpTables.UpdateConfirmedEndPoint jt.JTStartAddr jt.JTStartAddr
    match e with
    | ErrorBranchRecovery (errFnAddr, errBrAddr, rollbackFuncs) ->
      let rollbackFuncs = Set.add fnAddr rollbackFuncs
      if codeMgr.HistoryManager.HasFunctionLater fnAddr then
        Error <| ErrorBranchRecovery (errFnAddr, errBrAddr, rollbackFuncs)
      else codeMgr.RollBack (evts, Set.toList rollbackFuncs) |> Ok
    | ErrorLateDetection ->
      dataMgr.JumpTables.UpdatePotentialEndPoint jt.JTStartAddr entryAddr
      finishIfEmpty codeMgr fnAddr brAddr evts
    | ErrorConnectingEdge _ | ErrorParsing _ ->
      dataMgr.JumpTables.UpdatePotentialEndPoint jt.JTStartAddr entryAddr
      finishIfEmpty codeMgr fnAddr brAddr evts

  and finishIfEmpty codeMgr fnAddr brAddr evts =
    if codeMgr.HistoryManager.HasFunctionLater fnAddr then
      Error (ErrorBranchRecovery (fnAddr, brAddr, Set.singleton fnAddr))
    else Ok <| (codeMgr: CodeManager).RollBack (evts, [ fnAddr ])

  let getRelocatedAddr (file: BinFile) relocationTarget defaultAddr =
    match file.GetRelocatedAddr relocationTarget with
    | Ok addr -> addr
    | Error _ -> defaultAddr

  let classifyPCRelative hdl cpState pcVar offset =
    match CPState.findReg cpState pcVar with
    | Const bv ->
      let ptr = BitVector.ToUInt64 bv + BitVector.ToUInt64 offset
      let size = hdl.ISA.WordSize |> WordSize.toByteWidth
      let file = hdl.BinFile
      match BinHandle.TryReadUInt (hdl, ptr, size) with
      | Ok target when target <> 0UL && file.IsExecutableAddr target ->
        ConstJmpPattern <| getRelocatedAddr file ptr target
      | _ -> UnknownPattern
    | _ -> UnknownPattern

  let classifyJumpTableExpr cpState baseExpr tblExpr rt =
    let baseExpr = foldWithConstant cpState baseExpr |> simplify
    let tblExpr =
      symbolicExpand cpState tblExpr
      |> extractTableExpr
      |> foldWithConstant cpState
#if CFGDEBUG
    dbglog "IndJmpRecovery" "base(%s); table(%s)"
      (Pp.expToString baseExpr) (Pp.expToString tblExpr)
#endif
    match baseExpr, tblExpr with
    | Num b, Num t
    | Num b, BinOp (BinOpType.ADD, _, Num t, _)
    | Num b, BinOp (BinOpType.ADD, _, _, Num t) ->
      let baseAddr = BitVector.ToUInt64 b
      let tblAddr = BitVector.ToUInt64 t
      JmpTablePattern (baseAddr, tblAddr, rt)
    | _ -> UnknownPattern

  let classifyJmpExpr hdl cpState = function
    | BinOp (BinOpType.ADD, _, Num b, Load (_, t, memExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, memExpr), Num b)
    | BinOp (BinOpType.ADD, _, Num b, Cast (_, _, Load (_, t, memExpr)))
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, memExpr)), Num b) ->
      if isJmpTblAddr cpState memExpr then
        classifyJumpTableExpr cpState (Num b) memExpr t
      else UnknownPattern
    (* Symbolic patterns should be resolved with our constant analysis. *)
    | BinOp (BinOpType.ADD, _, (Load (_, _, e1) as l1),
                               (Load (_, t, e2) as l2)) ->
      if isJmpTblAddr cpState e1 then classifyJumpTableExpr cpState l2 e1 t
      elif isJmpTblAddr cpState e2 then classifyJumpTableExpr cpState l1 e2 t
      else UnknownPattern
    | BinOp (BinOpType.ADD, _, baseExpr, Load (_, t, tblExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, tblExpr), baseExpr) ->
      if isJmpTblAddr cpState tblExpr then
        classifyJumpTableExpr cpState baseExpr tblExpr t
      else UnknownPattern
    (* This pattern is jump to an address stored at [PC + offset] *)
    | Load (_, _, BinOp (BinOpType.ADD, _,
                         Var ({ Kind = PCVar _} as pcVar), Num offset)) ->
      classifyPCRelative hdl cpState pcVar offset
    (* Patterns from non-pie executables. *)
    | Load (_, t, memExpr)
    | Cast (_, _, Load (_, t, memExpr)) ->
      if isJmpTblAddr cpState memExpr then
        classifyJumpTableExpr cpState (Num <| BitVector.Zero t) memExpr t
      else UnknownPattern
    | _ -> UnknownPattern

/// RegularJmpResolution recovers indirect tail calls and jump targets of
/// indirect jumps by inferring their jump tables. It first identifies
/// jump table bases with constant propagation and recovers the entire
/// table ranges by leveraging the structural properties of the binary.
type RegularJmpResolution (bld) =
  inherit IndirectJumpResolution ()

  override __.Name = "RegularJmpResolution"

  override __.Classify hdl _srcV cpState jmpType =
    match jmpType with
    | InterJmp jmpExpr ->
      let symbExpr = resolveExpr cpState false jmpExpr
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Pattern indjmp: %s" (Pp.expToString symbExpr)
#endif
      classifyJmpExpr hdl cpState symbExpr
    | _ -> Utils.impossible ()

  override __.MarkIndJmpAsTarget codeMgr dataMgr fn insAddr _ evts pattern =
    match pattern with
    | JmpTablePattern (bAddr, tAddr, rt) ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Found known pattern %x, %x" bAddr tAddr
#endif
      let tbls = dataMgr.JumpTables
      match tbls.Register fn.EntryPoint insAddr bAddr tAddr rt with
      | Ok () ->
        fn.MarkIndJumpAsJumpTbl insAddr tAddr
        Ok (true, evts)
      | Error jt -> Error (jt, tAddr) (* Overlapping jump table. *)
    | ConstJmpPattern (target) ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Found ConstJmpPattern %x" target
#endif
      fn.RemoveIndJump insAddr
      let evts =
        if codeMgr.FunctionMaintainer.Contains (addr=target) then
          let callee = IndirectCallees <| Set.singleton target
          CFGEvents.addPerFuncAnalysisEvt (fn: RegularFunction).EntryPoint evts
          |> CFGEvents.addIndTailCallEvt fn insAddr callee
        else
          fn.MarkIndJumpAsKnownJumpTargets insAddr (Set.singleton target)
          let bblInfo = (codeMgr: CodeManager).GetBBL insAddr
          let src = bblInfo.IRLeaders |> Set.maxElement
          CFGEvents.addPerFuncAnalysisEvt (fn: RegularFunction).EntryPoint evts
          |> CFGEvents.addEdgeEvt fn src target IndirectJmpEdge
      Ok (false, evts)
    | _ ->
      fn.MarkIndJumpAsUnknown insAddr
      Ok (false, evts)

  override __.RecoverTarget hdl codeMgr dataMgr fn evts =
    match getNextAnalysisTarget hdl codeMgr dataMgr fn with
    | Some (jt, entryAddr) ->
      match recoverOneEntry bld hdl codeMgr dataMgr fn jt entryAddr with
      | Ok () -> RecoverContinue
      | Error e ->
        let res = rollback codeMgr dataMgr fn evts jt entryAddr e
        RecoverDone res
    | None -> RecoverDone <| Ok evts

  override __.OnError codeMgr dataMgr fn evts errInfo =
    match errInfo with
    | oldJT, newTblAddr ->
      let oldBrAddr = oldJT.InstructionAddr
      let oldFnAddr = oldJT.HostFunctionEntry
      let oldTblAddr = oldJT.JTStartAddr
#if CFGDEBUG
      dbglog "IndJmpRecovery" "@%x Failed to make jmptbl due to overlap: %x@%x"
        fn.EntryPoint oldBrAddr oldFnAddr
#endif
      dataMgr.JumpTables.UpdatePotentialEndPoint oldTblAddr newTblAddr
      let fnToRollback = codeMgr.FunctionMaintainer.FindRegular oldFnAddr
      fnToRollback.JumpTableAddrs |> List.iter (fun tAddr ->
        dataMgr.JumpTables.UpdateConfirmedEndPoint tAddr tAddr)
      finishIfEmpty codeMgr oldFnAddr oldBrAddr evts
