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
open B2R2.MiddleEnd.ControlFlowAnalysis.IRHelper
open B2R2.MiddleEnd.DataFlow
open System.Collections.Generic

type BranchPattern =
  /// This encodes an indirect jump with a jump table where baseAddr is the jump
  /// target's base address, tblAddr is the start address of a jump table, and
  /// rt is the size of each entry in the jump table.
  | JmpTablePattern of baseAddr: Addr * tblAddr: Addr * rt: RegType
  /// For EVM
  | ConstJmpPattern of addr: Addr
  /// For EVM
  | ConstCJmpPattern of tAddr: Addr * fAddr: Addr
  /// For EVM
  | ConstCallPattern of calleeAddr: Addr * ftAddr: Addr
  /// For EVM
  | ReturnPattern of sp: Addr
  /// Unknown pattern.
  | UnknownPattern

module private IndirectJumpResolution =

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

  let tryGetLastSp callerV cpState =
    let sp = EVM.Register.SP
    let t = sp |> EVM.Register.toRegType
    let id = sp |> EVM.Register.toRegID
    let str = sp |> EVM.Register.toString
    let k = SSA.RegVar (t, id, str)
    match SSACFG.findDef callerV k with
    | Some (Def (_, e)) ->
      match tryResolveExprToUInt64 cpState e with
      | Some v -> v |> Some
      | None -> None
    | _ -> None

  /// Get elements in the latest stack frame. The upper bound of SP should be
  /// calculated in first. Note that we handle EVM's SP in the ascending-order.
  let rec getStackVarExprsUntil v sp (ret: Dictionary<VariableKind, Expr>) =
    let offLB = - int (sp - Utils.initialStackPointer)
    let stmtInfos = (v: SSAVertex).VData.SSAStmtInfos
    None
    |> Array.foldBack (fun (_, stmt) _ ->
      match stmt with
      | Def ({ Kind = StackVar (_, off) as k }, e) when off >= offLB ->
        if ret.ContainsKey k then ()
        else ret.Add (k, e) |> ignore
        None
      | _ -> None) stmtInfos |> ignore
    match v.VData.ImmDominator with
    | Some idom -> getStackVarExprsUntil idom sp ret
    | None -> ret

  /// Check if the latest stack frame has the fall-through address (ftAddr). It
  /// assumes that the last instruction is either a jump or a conditional jump.
  let rec checkIfStackHasFtAddr callerV cpState ftAddr isCJmp =
    match tryGetLastSp callerV cpState with
    | Some sp ->
      let wordSize = uint64 <| RegType.toByteWidth 256<rt>
      (* Note that the addresses in stack have already been popped out. *)
      let spDiff = if isCJmp then wordSize * 2UL else wordSize
      let sp = sp + spDiff
      let stackVarExprMap = Dictionary () |> getStackVarExprsUntil callerV sp
      stackVarExprMap.Values
      |> Seq.exists (fun e ->
        match tryResolveExprToUInt64 cpState e with
        | Some v when v = ftAddr -> true
        | _ -> false)
    | None -> false

  let checkCall callerV cpState addr ftAddr =
    (* It is based on heuristics, and could be replaced by argument analysis. *)
    if addr = ftAddr then false
    else checkIfStackHasFtAddr callerV cpState ftAddr false

  let analyzeIndirectBranchPatternForEVM cpState (callerV: SSAVertex) =
    match callerV.VData.GetLastStmt () with
    | Jmp (InterJmp jmpExpr) ->
      match resolveExpr cpState jmpExpr with
      | Var ({ Kind = StackVar (_, _); Identifier = 0; }) ->
        (* If it's referring to a StackVar out of scope here, then it indicates
           ReturnPattern. Note that it's purely on heuristics. It may be not
           the case: it could be given as a function pointer to somewhere. *)
        match tryGetLastSp callerV cpState with
        | Some sp -> ReturnPattern <| sp
        | _ -> UnknownPattern
      | Num addr ->
        match tryResolveBVToUInt64 addr with
        | Some addr ->
          let insInfos = callerV.VData.InsInfos
          let lastInsInfo = Array.last insInfos
          let lastInsAddr = lastInsInfo.Instruction.Address
          let lastInsLength = uint64 lastInsInfo.Instruction.Length
          let ftAddr = lastInsAddr + lastInsLength
          if checkCall callerV cpState addr ftAddr then
            ConstCallPattern <| (addr, ftAddr)
          else
            ConstJmpPattern <| addr
        | _ -> UnknownPattern
      | _ -> UnknownPattern
    | Jmp (InterCJmp (_, tJmpExpr, fJmpExpr)) ->
      let tAddr = tJmpExpr |> tryResolveExprToUInt64 cpState
      let fAddr = fJmpExpr |> tryResolveExprToUInt64 cpState
      match tAddr, fAddr with
      | Some tAddr, Some fAddr -> ConstCJmpPattern <| (tAddr, fAddr)
      | _ -> UnknownPattern
    /// Does not consider this case in the current implementation. Assume that
    /// we register only the cases above into IndirectJumpResolution for EVM.
    | _ -> Utils.impossible ()

  /// Symbolically expand the indirect jump expression with the constant
  /// information obtained from the constatnt propagation step, and see if the
  /// jump target is in the form of loading a jump table.
  let analyzeIndirectBranchPattern ssaCFG cpState callerV =
    let callerBlkAddr = (callerV: SSAVertex).VData.PPoint.Address
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
    match addrs with
    | insAddr :: restAddrs ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "@%x Detected indjmp @ %x" func.Entry insAddr
#endif
      let struct (cpState, ssaCFG) = PerFunctionAnalysis.runCP hdl func None
      let bblInfo = (codeMgr: CodeManager).GetBBL insAddr
      let blkAddr = Set.minElement bblInfo.InstrAddrs
      let ssaBlk =
        DiGraph.findVertexBy ssaCFG (fun (v: SSAVertex) ->
          v.VData.PPoint.Address = blkAddr)
      match analyzeIndirectBranchPattern ssaCFG cpState ssaBlk with
      | JmpTablePattern (bAddr, tAddr, rt) ->
#if CFGDEBUG
        dbglog "IndJmpRecovery" "Found known pattern %x, %x" bAddr tAddr
#endif
        let tbls = (dataMgr: DataManager).JumpTables
        match tbls.Register func.Entry insAddr bAddr tAddr rt with
        | Ok () ->
          func.MarkIndJumpAsJumpTbl insAddr tAddr
          analyzeNewJmpTables hdl codeMgr dataMgr func restAddrs true
        | Error jt -> Error (jt, tAddr) (* Overlapping jump table. *)
      | _ ->
#if CFGDEBUG
        dbglog "IndJmpRecovery" "The pattern is unknown"
#endif
        func.MarkIndJumpAsUnknown insAddr
        analyzeNewJmpTables hdl codeMgr dataMgr func restAddrs needRecovery
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

  let addEvtsForConstJmp func src addr isEvtAdded evts =
    if isEvtAdded then evts
    else CFGEvents.addPerFuncAnalysisEvt (func: RegularFunction).Entry evts
    |> CFGEvents.addEdgeEvt func src addr InterJmpEdge

  let addEvtsForConstCJmp func src tAddr fAddr isEvtAdded evts =
    if isEvtAdded then evts
    else CFGEvents.addPerFuncAnalysisEvt (func: RegularFunction).Entry evts
    |> CFGEvents.addEdgeEvt func src tAddr InterCJmpTrueEdge
    |> CFGEvents.addEdgeEvt func src fAddr InterCJmpFalseEdge

  let addEvtsForConstCall func src insAddr calleeAddr ftAddr isEvtAdded evts =
    if isEvtAdded then evts
    else CFGEvents.addPerFuncAnalysisEvt (func: RegularFunction).Entry evts
    |> CFGEvents.addEdgeEvt func src ftAddr CallFallThroughEdge
    |> CFGEvents.addCallEvt func insAddr calleeAddr

  let finalizeFunctionInfo (func: RegularFunction) sp =
    let spDiff = int64 <| 0x80000000UL - sp
    let retAddrSize = int64 <| RegType.toByteWidth 256<rt>
    let amountUnwinding = - spDiff - retAddrSize
    func.AmountUnwinding <- amountUnwinding
    func.NoReturnProperty <- NotNoRet

  let rec analyzeNewEVMJmps hdl codeMgr dataMgr func addrs isEvtAdded evts =
    match addrs with
    | insAddr :: restAddrs ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "@%x Detected indjmp @ %x" func.Entry insAddr
#endif
      let struct (cpState, ssaCFG) = PerFunctionAnalysis.runCP hdl func None
      let bblInfo = (codeMgr: CodeManager).GetBBL insAddr
      let blkAddr = Set.minElement bblInfo.InstrAddrs
      let src = Set.maxElement bblInfo.IRLeaders
      let ssaBlk =
        DiGraph.findVertexBy ssaCFG (fun (v: SSAVertex) ->
          v.VData.PPoint.Address = blkAddr)
      match analyzeIndirectBranchPatternForEVM cpState ssaBlk with
      | ConstJmpPattern addr ->
        func.RemoveIndJump insAddr
        addEvtsForConstJmp func src addr isEvtAdded evts
        |> analyzeNewEVMJmps hdl codeMgr dataMgr func restAddrs true
      | ConstCJmpPattern (tAddr, fAddr) ->
        func.RemoveIndJump insAddr
        addEvtsForConstCJmp func src tAddr fAddr isEvtAdded evts
        |> analyzeNewEVMJmps hdl codeMgr dataMgr func restAddrs true
      | ConstCallPattern (calleeAddr, ftAddr) ->
        func.RemoveIndJump insAddr
        addEvtsForConstCall func src insAddr calleeAddr ftAddr isEvtAdded evts
        |> analyzeNewEVMJmps hdl codeMgr dataMgr func restAddrs true
      | ReturnPattern sp ->
        func.RemoveIndJump insAddr
        finalizeFunctionInfo func sp
        analyzeNewEVMJmps hdl codeMgr dataMgr func restAddrs isEvtAdded evts
      | _ ->
#if CFGDEBUG
        dbglog "IndJmpRecovery" "The pattern is unknown"
#endif
        func.MarkIndJumpAsUnknown insAddr
        analyzeNewEVMJmps hdl codeMgr dataMgr func restAddrs isEvtAdded evts
    | [] -> evts

  let resolveEVMJmps hdl codeMgr dataMgr fn evts =
    let addrs = (fn: RegularFunction).YetAnalyzedIndirectJumpAddrs
    if List.isEmpty addrs then Ok <| evts
    else Ok <| analyzeNewEVMJmps hdl codeMgr dataMgr fn addrs false evts

  let rec resolveJmpTables bld hdl codeMgr dataMgr fn evts =
    match analyzeJmpTables hdl codeMgr dataMgr fn with
    | Ok true ->
      match getNextAnalysisTarget hdl codeMgr dataMgr fn with
      | Some (jt, entryAddr) ->
        match recoverOneEntry bld hdl codeMgr dataMgr fn jt entryAddr with
        | Ok () -> resolveJmpTables bld hdl codeMgr dataMgr fn evts
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

  let resolve bld hdl codeMgr dataMgr fn evts =
    match (hdl: BinHandle).ISA.Arch with
    | Arch.EVM -> resolveEVMJmps hdl codeMgr dataMgr fn evts
    | _ -> resolveJmpTables bld hdl codeMgr dataMgr fn evts

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
