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
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

type BranchPattern =
  /// This encodes an indirect jump with a jump table where baseAddr is the jump
  /// target's base address, tblAddr is the start address of a jump table, and
  /// rt is the size of each entry in the jump table.
  | JmpTablePattern of baseAddr: Addr * tblAddr: Addr * rt: RegType
  /// Jump to a single constant target.
  | ConstJmpPattern of addr: Addr
  /// Conditional jump for constant targets. This pattern appears in EVM.
  | ConstCJmpPattern of tAddr: Addr * fAddr: Addr
  /// Call to a single constant target.
  | ConstCallPattern of calleeAddr: Addr * ftAddr: Addr
  /// Return back to caller pattern found in EVM.
  | ReturnPattern of sp: Addr
  /// Unknown pattern.
  | UnknownPattern

/// The resulting status of RecoverTarget.
type RecoveryStatus =
  /// Recovery process should stop.
  | RecoverDone of Result<CFGEvents, CFGError>
  /// Recovery process should continue.
  | RecoverContinue

/// Indirect jump resolution.
[<AbstractClass>]
type IndirectJumpResolution () =
  inherit PerFunctionAnalysis ()

  override __.Name = "IndirectJumpResolution"

  /// Analyze the given indirect jump type (JmpType) and return a BranchPattern.
  abstract member Classify:
    BinHandle
    -> SSAVertex
    -> CPState<SCPValue>
    -> JmpType
    -> BranchPattern

  /// Check the given BranchPattern and mark the indirect jump as an analysis
  /// target.
  abstract member MarkIndJmpAsTarget:
    CodeManager
    -> JumpTableCollection
    -> RegularFunction
    -> Addr
    -> ProgramPoint
    -> CFGEvents
    -> BranchPattern
    -> Result<bool * CFGEvents, JumpTable * Addr>

  /// Recover the current target.
  abstract member RecoverTarget:
    BinHandle
    -> CodeManager
    -> JumpTableCollection
    -> RegularFunction
    -> CFGEvents
    -> RecoveryStatus

  /// Process recovery error(s).
  abstract member OnError:
    CodeManager
    -> JumpTableCollection
    -> RegularFunction
    -> CFGEvents
    -> (JumpTable * Addr)
    -> Result<CFGEvents, CFGError>

  member private __.FindIndJmpKind ssaCFG srcBlkAddr fstV (vs: SSAVertex list) =
    match vs with
    | v :: rest ->
      match v.VData.GetLastStmt () with
      | Jmp (InterJmp _ as jk)
      | Jmp (InterCJmp _ as jk) -> jk
      | _ ->
        let vs =
          (ssaCFG: IGraph<_, _>).GetSuccs v
          |> Seq.fold (fun acc succ ->
            if succ <> fstV then succ :: acc else acc) rest
        __.FindIndJmpKind ssaCFG srcBlkAddr fstV vs
    | [] -> Utils.impossible ()

  /// Symbolically expand the indirect jump expression with the constant
  /// information obtained from the constatnt propagation step, and see if the
  /// jump target is in the form of loading a jump table.
  member private __.AnalyzeBranchPattern hdl ssaCFG cpState blkAddr =
    let srcV = (* may not contain Jmp: get the right one @ FindIndJmpKind. *)
      (ssaCFG: IGraph<_, _>).FindVertexBy (fun (v: SSAVertex) ->
        v.VData.PPoint.Address = blkAddr)
    let srcBlkAddr = (srcV: SSAVertex).VData.PPoint.Address
    __.FindIndJmpKind ssaCFG srcBlkAddr srcV [ srcV ]
    |> __.Classify hdl srcV cpState

  member private __.Analyze
    hdl codeMgr jmpTbls fn cpSt ssaCFG addrs needRecovery evts =
    match addrs with
    | iAddr :: rest ->
#if CFGDEBUG
      dbglog "IndJmpRecovery" "@%x Detected indjmp @ %x"
        (fn: RegularFunction).EntryPoint iAddr
#endif
      let bblInfo = (codeMgr: CodeManager).GetBBL iAddr
      let blkAddr = Set.minElement bblInfo.InstrAddrs
      let src = Set.maxElement bblInfo.IRLeaders
      __.AnalyzeBranchPattern hdl ssaCFG cpSt blkAddr
      |> __.MarkIndJmpAsTarget codeMgr jmpTbls fn iAddr src evts
      |> function
        | Ok (true, evts) ->
          __.Analyze hdl codeMgr jmpTbls fn cpSt ssaCFG rest true evts
        | Ok (false, evts) ->
          __.Analyze hdl codeMgr jmpTbls fn cpSt ssaCFG rest needRecovery evts
        | Error err -> Error err
    | [] -> Ok (needRecovery, evts)

  member private __.AnalyzeIndJmps hdl codeMgr jmpTbls fn evts =
    let addrs = (fn: RegularFunction).YetAnalyzedIndirectJumpAddrs
    if List.isEmpty addrs then Ok (true, evts)
    else
      let struct (cpState, ssaCFG) = PerFunctionAnalysis.runCP hdl fn None
      __.Analyze hdl codeMgr jmpTbls fn cpState ssaCFG addrs false evts

  member private __.Resolve hdl codeMgr jmpTbls fn evts =
    match __.AnalyzeIndJmps hdl codeMgr jmpTbls fn evts with
    | Ok (true, evts) ->
      match __.RecoverTarget hdl codeMgr jmpTbls fn evts with
      | RecoverDone res -> res
      | RecoverContinue -> __.Resolve hdl codeMgr jmpTbls fn evts
    | Ok (false, evts) ->
      (* We are in a nested update call, and found nothing to resolve. So, just
         return to the caller, and keep resolving the rest entries. *)
      Ok evts
    | Error err ->
      __.OnError codeMgr jmpTbls fn evts err

  override __.Run hdl codeMgr jmpTbls fn evts =
    codeMgr.HistoryManager.StartRecordingFunctionHistory fn.EntryPoint
    let res = __.Resolve hdl codeMgr jmpTbls fn evts
    codeMgr.HistoryManager.StopRecordingFunctionHistory fn.EntryPoint
    res
