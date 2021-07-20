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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

type BranchPattern =
  /// This encodes an indirect jump with a jump table where baseAddr is the jump
  /// target's base address, tblAddr is the start address of a jump table, and
  /// rt is the size of each entry in the jump table.
  | JmpTablePattern of baseAddr: Addr * tblAddr: Addr * rt: RegType
  /// Unknown pattern.
  | UnknownPattern

module private IndirectJumpResolution =

  let varToBV cpState var id =
    let v = { var with Identifier = id }
    match CPState.findReg cpState v with
    | Const bv | Thunk bv | Pointer bv -> Some bv
    | _ -> None

  let expandPhi cpState var ids e =
    let bvs = ids |> Array.toList |> List.map (fun id -> varToBV cpState var id)
    match bvs.[0] with
    | Some hd ->
      if bvs.Tail |> List.forall (function Some bv -> bv = hd | None -> false)
      then Num hd
      else e
    | None -> e

  /// Recursively expand vars until we meet a Load expr.
  let rec symbolicExpand cpState = function
    | Num _ as e -> e
    | Var v as e ->
      match Map.tryFind v cpState.SSAEdges.Defs with
      | Some (Def (_, e)) -> symbolicExpand cpState e
      | Some (Phi (_, ids)) -> expandPhi cpState v ids e
      | _ -> e
    | Load _ as e -> e
    | UnOp (_, _, Load _) as e -> e
    | UnOp (op, rt, e) ->
      let e = symbolicExpand cpState e
      UnOp (op, rt, e)
    | BinOp (_, _, Load _, _)
    | BinOp (_, _, _, Load _) as e -> e
    | BinOp (op, rt, e1, e2) ->
      let e1 = symbolicExpand cpState e1
      let e2 = symbolicExpand cpState e2
      BinOp (op, rt, e1, e2)
    | RelOp (_, _, Load _, _)
    | RelOp (_, _, _, Load _) as e -> e
    | RelOp (op, rt, e1, e2) ->
      let e1 = symbolicExpand cpState e1
      let e2 = symbolicExpand cpState e2
      RelOp (op, rt, e1, e2)
    | Ite (Load _, _, _, _)
    | Ite (_, _, Load _, _)
    | Ite (_, _, _, Load _) as e -> e
    | Ite (e1, rt, e2, e3) ->
      let e1 = symbolicExpand cpState e1
      let e2 = symbolicExpand cpState e2
      let e3 = symbolicExpand cpState e3
      Ite (e1, rt, e2, e3)
    | Cast (_, _, Load _) as e -> e
    | Cast (op, rt, e) ->
      let e = symbolicExpand cpState e
      Cast (op, rt, e)
    | Extract (Load _, _, _) as e -> e
    | Extract (e, rt, pos) ->
      let e = symbolicExpand cpState e
      Extract (e, rt, pos)
    | e -> e

  let rec simplify = function
    | Load (v, rt, e) -> Load (v, rt, simplify e)
    | Store (v, rt, e1, e2) -> Store (v, rt, simplify e1, simplify e2)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, Num v1, e), Num v2)
    | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, e, Num v1), Num v2)
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, e, Num v2))
    | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, Num v2, e)) ->
      BinOp (BinOpType.ADD, rt, e, Num (BitVector.add v1 v2))
    | BinOp (BinOpType.ADD, _, Num v1, Num v2) -> Num (BitVector.add v1 v2)
    | BinOp (BinOpType.SUB, _, Num v1, Num v2) -> Num (BitVector.sub v1 v2)
    | BinOp (op, rt, e1, e2) -> BinOp (op, rt, simplify e1, simplify e2)
    | UnOp (op, rt, e) -> UnOp (op, rt, simplify e)
    | RelOp (op, rt, e1, e2) -> RelOp (op, rt, simplify e1, simplify e2)
    | Ite (c, rt, e1, e2) -> Ite (simplify c, rt, simplify e1, simplify e2)
    | Cast (k, rt, e) -> Cast (k, rt, simplify e)
    | Extract (Cast (CastKind.ZeroExt, _, e), rt, 0) when AST.typeOf e = rt -> e
    | Extract (Cast (CastKind.SignExt, _, e), rt, 0) when AST.typeOf e = rt -> e
    | Extract (e, rt, pos) -> Extract (simplify e, rt, pos)
    | expr -> expr

  let rec foldWithConstant cpState = function
    | Var v as e ->
      match CPState.findReg cpState v with
      | Const bv | Thunk bv | Pointer bv -> Num bv
      | _ ->
        match Map.tryFind v cpState.SSAEdges.Defs with
        | Some (Def (_, e)) -> foldWithConstant cpState e
        | _ -> e
    | Load (m, rt, addr) as e ->
      match foldWithConstant cpState addr with
      | Num addr ->
        let addr = BitVector.toUInt64 addr
        match CPState.tryFindMem cpState m rt addr with
        | Some (Const bv) | Some (Thunk bv) | Some (Pointer bv) -> Num bv
        | _ -> e
      | _ -> e
    | UnOp (op, rt, e) -> UnOp (op, rt, foldWithConstant cpState e)
    | BinOp (op, rt, e1, e2) ->
      let e1 = foldWithConstant cpState e1
      let e2 = foldWithConstant cpState e2
      BinOp (op, rt, e1, e2) |> simplify
    | RelOp (op, rt, e1, e2) ->
      let e1 = foldWithConstant cpState e1
      let e2 = foldWithConstant cpState e2
      RelOp (op, rt, e1, e2)
    | Ite (e1, rt, e2, e3) ->
      let e1 = foldWithConstant cpState e1
      let e2 = foldWithConstant cpState e2
      let e3 = foldWithConstant cpState e3
      Ite (e1, rt, e2, e3)
    | Cast (op, rt, e) -> Cast (op, rt, foldWithConstant cpState e)
    | Extract (e, rt, pos) -> Extract (foldWithConstant cpState e, rt, pos)
    | e -> e

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

  let classifyWithSymbolicExpr cpState baseExpr tblExpr rt =
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
      let baseAddr = BitVector.toUInt64 b
      let tblAddr = BitVector.toUInt64 t
      JmpTablePattern (baseAddr, tblAddr, rt)
    | _ -> UnknownPattern

  /// Classify "base address" and "jump table address" based on a symbolic
  /// pattern. (jump target addr = base addr + [jump table addr + index])
  let classify cpState = function
    (* The easiest pattern where base address is a plain constant. *)
    | BinOp (BinOpType.ADD, _, Num b, Load (_, t, memExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, memExpr), Num b)
    | BinOp (BinOpType.ADD, _, Num b, Cast (_, _, Load (_, t, memExpr)))
    | BinOp (BinOpType.ADD, _, Cast (_, _, Load (_, t, memExpr)), Num b) ->
      if isJmpTblAddr cpState memExpr then
        classifyWithSymbolicExpr cpState (Num b) memExpr t
      else UnknownPattern
    (* Symbolic patterns should be resolved with our constant analysis. *)
    | BinOp (BinOpType.ADD, _, (Load (_, _, e1) as l1),
                               (Load (_, t, e2) as l2)) ->
      if isJmpTblAddr cpState e1 then classifyWithSymbolicExpr cpState l2 e1 t
      elif isJmpTblAddr cpState e2 then classifyWithSymbolicExpr cpState l1 e2 t
      else UnknownPattern
    | BinOp (BinOpType.ADD, _, baseExpr, Load (_, t, tblExpr))
    | BinOp (BinOpType.ADD, _, Load (_, t, tblExpr), baseExpr) ->
      if isJmpTblAddr cpState tblExpr then
        classifyWithSymbolicExpr cpState baseExpr tblExpr t
      else UnknownPattern
    (* Patterns from non-pie executables. *)
    | Load (_, t, memExpr)
    | Cast (_, _, Load (_, t, memExpr)) ->
      if isJmpTblAddr cpState memExpr then
        classifyWithSymbolicExpr cpState (Num <| BitVector.zero t) memExpr t
      else UnknownPattern
    | _ -> UnknownPattern

  let rec findIndJumpExpr ssaCFG callerBlkAddr fstV (vs: SSAVertex list) =
    match vs with
    | v :: rest ->
      match v.VData.GetLastStmt () with
      | Jmp (InterJmp jmpExpr) -> jmpExpr
      | _ ->
        let vs =
          DiGraph.getSuccs ssaCFG v
          |> List.fold (fun acc succ ->
            if succ <> fstV then succ :: acc else acc) rest
        findIndJumpExpr ssaCFG callerBlkAddr fstV vs
    | [] -> Utils.impossible ()

  /// Symbolically expand the indirect jump expression with the constant
  /// information obtained from the constatnt propagation step, and see if the
  /// jump target is in the form of loading a jump table.
  let analyzeIndirectBranchPattern ssaCFG cpState callerBlkAddr =
    let callerV =
      DiGraph.findVertexBy ssaCFG (fun (v: SSAVertex) ->
        v.VData.PPoint.Address = callerBlkAddr)
    let symbExpr =
      findIndJumpExpr ssaCFG callerBlkAddr callerV [ callerV ]
      |> symbolicExpand cpState
      |> simplify
#if CFGDEBUG
    dbglog "IndJmpRecovery" "Pattern of indjmp: %s" (Pp.expToString symbExpr)
#endif
    classify cpState symbExpr

  let computeMask size =
    let rt = RegType.fromByteWidth size
    (* It is reasonable enough to assume that jump target addresses will never
       overflow when rt is greater than 64<rt>. *)
    if rt > 64<rt> then 0xFFFFFFFFFFFFFFFFUL
    else BitVector.unsignedMax rt |> BitVector.toUInt64

  /// Read a table entry and compute jump target
  let readTable hdl bAddr (entryAddr: Addr) size =
    let addr = bAddr + BinHandle.ReadUInt (hdl, entryAddr, size)
    addr &&& computeMask size

  let recoverIndirectEdge bld fn src dst =
    let evts =
      CFGEvents.empty
      |> CFGEvents.addPerFuncAnalysisEvt (fn: RegularFunction).Entry
      |> CFGEvents.addEdgeEvt fn src dst IndirectJmpEdge
    (bld: ICFGBuildable).Update evts

  let recoverOneEntry bld hdl codeMgr (dataMgr: DataManager) fn jt entryAddr =
    let dst = readTable hdl jt.BranchBaseAddr entryAddr jt.JTEntrySize
    let brAddr = jt.InstructionAddr
    let bblInfo = (codeMgr: CodeManager).GetBBL brAddr
    let src = bblInfo.IRLeaders |> Set.maxElement
#if CFGDEBUG
    dbglog "IndJmpRecovery" "@%x Recovering %x -> %x (%x)"
      (fn: RegularFunction).Entry src.Address dst entryAddr
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

  let rec analyzeNewJmpTables hdl codeMgr dataMgr func addrs needRecovery =
    let struct (cpState, ssaCFG) = PerFunctionAnalysis.runCP hdl func None
    match addrs with
    | insAddr :: restAddrs ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "@%x Detected indjmp @ %x" func.Entry insAddr
#endif
      let bblInfo = (codeMgr: CodeManager).GetBBL insAddr
      let blkAddr = Set.minElement bblInfo.InstrAddrs
      match analyzeIndirectBranchPattern ssaCFG cpState blkAddr with
      | UnknownPattern ->
#if CFGDEBUG
        dbglog "IndJmpRecovery" "The pattern is unknown"
#endif
        func.MarkIndJumpAsUnknown insAddr
        analyzeNewJmpTables hdl codeMgr dataMgr func restAddrs needRecovery
      | JmpTablePattern (bAddr, tAddr, rt) ->
#if CFGDEBUG
        dbglog "IndJmpRecovery" "Found known pattern %x, %x" bAddr tAddr
#endif
        let tbls = (dataMgr: DataManager).JumpTables
        match tbls.Register func.Entry insAddr bAddr tAddr rt with
        | Ok () ->
          func.MarkIndJumpAsAnalyzed insAddr tAddr
          analyzeNewJmpTables hdl codeMgr dataMgr func restAddrs true
        | Error jt -> Error (jt, tAddr) (* Overlapping jump table. *)
    | [] -> Ok needRecovery

  /// Find out jump table bases only for those never seen before.
  let analyzeJmpTables hdl codeMgr dataMgr fn =
    let addrs = (fn: RegularFunction).YetAnalyzedIndirectJumpAddrs
    if List.isEmpty addrs then Ok true (* We are in a loop, so keep going. *)
    else analyzeNewJmpTables hdl codeMgr dataMgr fn addrs false

  let getJumpTables (fn: RegularFunction) =
    fn.IndirectJumps.Values
    |> Seq.fold (fun acc jmpKind ->
      match jmpKind with
      | NotJmpTbl | YetAnalyzed -> acc
      | JmpTbl tAddr -> tAddr :: acc
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
        Some (dataMgr.JumpTables.[tAddr], tAddr)
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
      if hdl.FileInfo.IsValidAddr addr then
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
      let jt = dataMgr.JumpTables.[tAddr]
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
    if addr < (fn: RegularFunction).Entry || addr >= nextFnAddr then None
    else Some entryAddr

  /// This is a less safer path than the gap-oriented search. We compute the
  /// next recovery end-point address by simply pointing to the next entry.
  let rec getNextRecoveryTargetFromTable hdl codeMgr dataMgr fn gaps = function
    | tAddr :: tl ->
      let jt = (dataMgr: DataManager).JumpTables.[tAddr]
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

  let rec resolve bld hdl codeMgr dataMgr fn evts =
    match analyzeJmpTables hdl codeMgr dataMgr fn with
    | Ok true ->
      match getNextAnalysisTarget hdl codeMgr dataMgr fn with
      | Some (jt, entryAddr) ->
        match recoverOneEntry bld hdl codeMgr dataMgr fn jt entryAddr with
        | Ok () -> resolve bld hdl codeMgr dataMgr fn evts
        | Error e -> rollback codeMgr dataMgr fn evts jt entryAddr e
      | None -> Ok evts
    | Ok false ->
      (* We are in a nested update call, and found nothing to resolve. So, just
         return to the caller, and keep resolving the rest entries. *)
      Ok evts
    | Error (oldJT, newTblAddr) ->
      let oldBrAddr = oldJT.InstructionAddr
      let oldFnAddr = oldJT.HostFunctionEntry
      let oldTblAddr = oldJT.JTStartAddr
#if CFGDEBUG
      dbglog "IndJmpRecovery" "@%x Failed to make jmptbl due to overlap: %x@%x"
        fn.Entry oldBrAddr oldFnAddr
#endif
      dataMgr.JumpTables.UpdatePotentialEndPoint oldTblAddr newTblAddr
      let fnToRollback = codeMgr.FunctionMaintainer.FindRegular oldFnAddr
      fnToRollback.JumpTableAddrs |> List.iter (fun tAddr ->
        dataMgr.JumpTables.UpdateConfirmedEndPoint tAddr tAddr)
      finishIfEmpty codeMgr oldFnAddr oldBrAddr evts

  and rollback codeMgr dataMgr fn evts jt entryAddr e =
    let fnAddr = fn.Entry
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
    | ErrorConnectingEdge | ErrorParsing ->
      dataMgr.JumpTables.UpdatePotentialEndPoint jt.JTStartAddr entryAddr
      finishIfEmpty codeMgr fnAddr brAddr evts

  and finishIfEmpty codeMgr fnAddr brAddr evts =
    if codeMgr.HistoryManager.HasFunctionLater fnAddr then
      Error (ErrorBranchRecovery (fnAddr, brAddr, Set.singleton fnAddr))
    else codeMgr.RollBack (evts, [ fnAddr ]) |> Ok

/// IndirectJumpResolution recovers jump targets of indirect jumps by inferring
/// their jump tables. It first identifies jump table bases with constant
/// propagation and recovers the entire table ranges by leveraging the
/// structural properties of the binary.
type IndirectJumpResolution (bld) =
  inherit PerFunctionAnalysis ()

  override __.Name = "IndirectJumpResolution"

  override __.Run hdl codeMgr dataMgr func evts =
    codeMgr.HistoryManager.StartRecordingFunctionHistory func.Entry
    let res = IndirectJumpResolution.resolve bld hdl codeMgr dataMgr func evts
    codeMgr.HistoryManager.StopRecordingFunctionHistory func.Entry
    res
