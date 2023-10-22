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
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis.IRHelper
open B2R2.MiddleEnd.DataFlow

[<AutoOpen>]
module private EVMJmpResolution =

  let tryGetStackPointerValue (hdl: BinHandle) srcV cpState =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let t = hdl.RegisterBay.RegIDToRegType sp
      let str = hdl.RegisterBay.RegIDToString sp
      let k = RegVar (t, sp, str)
      match SSACFG.findDef srcV k with
      | Some (Def (_, e)) ->
        match tryResolveExprToUInt64 cpState e with
        | Some _ as v -> v
        | None -> None
      | _ -> None
    | None -> None

  /// Get elements in the latest stack frame. The upper bound of SP should be
  /// calculated in first. Note that we handle EVM's SP in the ascending-order.
  let rec getStackVarExprsUntil v sp (ret: Dictionary<VariableKind, Expr>) =
    let offLB = - int (sp - Utils.InitialStackPointer)
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
  let rec checkIfStackHasFtAddr hdl srcV cpState ftAddr isCJmp =
    match tryGetStackPointerValue hdl srcV cpState with
    | Some sp ->
      let wordSize = uint64 <| RegType.toByteWidth 256<rt>
      (* Note that the addresses in the stack have already been popped out. *)
      let spDiff = if isCJmp then wordSize * 2UL else wordSize
      let sp = sp + spDiff
      let stackVarExprMap = getStackVarExprsUntil srcV sp <| Dictionary ()
      stackVarExprMap.Values
      |> Seq.exists (fun e ->
        match tryResolveExprToUInt64 cpState e with
        | Some v when v = ftAddr -> true
        | _ -> false)
    | None -> false

  let isCallPattern hdl srcV cpState addr ftAddr =
    (* It is based on heuristics, and could be replaced by argument analysis. *)
    if addr = ftAddr then false
    else checkIfStackHasFtAddr hdl srcV cpState ftAddr false

  let classifyJmpExpr hdl srcV cpState = function
    | Var ({ Kind = StackVar _; Identifier = 0; }) ->
      match tryGetStackPointerValue hdl srcV cpState with
      (* Return back to a constant address stored on the stack. *)
      | Some addr -> ReturnPattern addr
      | _ -> UnknownPattern
    | Num addr ->
      match tryConvertBVToUInt64 addr with
      | Some addr ->
        let insInfos = srcV.VData.InsInfos
        let lastInsInfo = Array.last insInfos
        let lastInsAddr = lastInsInfo.Instruction.Address
        let lastInsLength = uint64 lastInsInfo.Instruction.Length
        let ftAddr = lastInsAddr + lastInsLength
        if isCallPattern hdl srcV cpState addr ftAddr then
          ConstCallPattern (addr, ftAddr)
        else
          ConstJmpPattern addr
      | _ -> UnknownPattern
    | _ -> UnknownPattern

/// IndirectJumpResolution recovers jump targets of indirect jumps by inferring
/// their jump tables. It first identifies jump table bases with constant
/// propagation and recovers the entire table ranges by leveraging the
/// structural properties of the binary.
type EVMJmpResolution () =
  inherit IndirectJumpResolution ()

  let mutable isEvtAdded = false

  member private __.AddPerFuncEvt (fn: RegularFunction) evts =
    if isEvtAdded then evts
    else
      isEvtAdded <- true
      CFGEvents.addPerFuncAnalysisEvt fn.EntryPoint evts

  member private __.AddEvtsForConstJmp fn src addr evts =
    __.AddPerFuncEvt fn evts
    |> CFGEvents.addEdgeEvt fn src addr InterJmpEdge

  member private __.AddEvtsForConstCJmp fn src tAddr fAddr evts =
    __.AddPerFuncEvt fn evts
    |> CFGEvents.addEdgeEvt fn src tAddr InterCJmpTrueEdge
    |> CFGEvents.addEdgeEvt fn src fAddr InterCJmpFalseEdge

  member private __.AddEvtsForConstCall fn src insAddr calleeAddr ftAddr evts =
    __.AddPerFuncEvt fn evts
    |> CFGEvents.addEdgeEvt fn src ftAddr CallFallThroughEdge
    |> CFGEvents.addCallEvt fn insAddr calleeAddr

  member private __.FinalizeFunctionInfo (fn: RegularFunction) sp =
    let spDiff = int64 <| Utils.InitialStackPointer - sp
    let retAddrSize = int64 <| RegType.toByteWidth 256<rt>
    let amountUnwinding = - spDiff - retAddrSize
    fn.AmountUnwinding <- amountUnwinding
    fn.NoReturnProperty <- NotNoRet

  override __.Name = "EVMJmpResolution"

  override __.Classify hdl srcV cpState jmpType =
    match jmpType with
    | InterJmp jmpExpr ->
      let symbExpr = resolveExpr cpState true jmpExpr
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Pattern indjmp: %s" (Pp.expToString symbExpr)
#endif
      classifyJmpExpr hdl srcV cpState symbExpr
    | InterCJmp (_, tJmpExpr, fJmpExpr) ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "Pattern indcjmp(t): %s" (Pp.expToString tJmpExpr)
      dbglog "IndJmpRecovery" "Pattern indcjmp(f): %s" (Pp.expToString fJmpExpr)
#endif
      let tAddr = tryResolveExprToUInt64 cpState tJmpExpr
      let fAddr = tryResolveExprToUInt64 cpState fJmpExpr
      match tAddr, fAddr with
      | Some tAddr, Some fAddr -> ConstCJmpPattern (tAddr, fAddr)
      | _ -> UnknownPattern
    | _ -> Utils.impossible ()

  override __.MarkIndJmpAsTarget _ _ fn insAddr src evts pattern =
    match pattern with
    | ConstJmpPattern addr ->
      (fn: RegularFunction).RemoveIndJump insAddr
      let evts = __.AddEvtsForConstJmp fn src addr evts
      Ok (false, evts)
    | ConstCJmpPattern (tAddr, fAddr) ->
      fn.RemoveIndJump insAddr
      let evts = __.AddEvtsForConstCJmp fn src tAddr fAddr evts
      Ok (false, evts)
    | ConstCallPattern (calleeAddr, ftAddr) ->
      fn.RemoveIndJump insAddr
      let evts =
        __.AddEvtsForConstCall fn src insAddr calleeAddr ftAddr evts
      Ok (false, evts)
    | ReturnPattern sp ->
      fn.RemoveIndJump insAddr
      __.FinalizeFunctionInfo fn sp
      Ok (false, evts)
    | _ ->
      fn.MarkIndJumpAsUnknown insAddr
      Ok (false, evts)

  override __.RecoverTarget _ _ _ _ evts = RecoverDone <| Ok evts

  override __.OnError _ _ _ evts _ = Ok evts
