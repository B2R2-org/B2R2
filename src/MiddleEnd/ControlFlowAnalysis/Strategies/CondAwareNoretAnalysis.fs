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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System.Runtime.InteropServices
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.SSA
open type B2R2.MiddleEnd.DataFlow.UntouchedValueDomain.UntouchedTag

/// This is a non-returning function identification strategy that can check
/// conditionally non-returning functions. We currently support only those
/// simple patterns that are handled by compilers, but we may have to extend
/// this as the compilers evolve.
type CondAwareNoretAnalysis ([<Optional; DefaultParameterValue(true)>] strict) =
  /// Default value used for unknown non-returning status.
  let defaultStatus = if strict then NoRet else NotNoRet

  let meet a b =
    match a, b with
    | _ when a = b -> a
    | UnknownNoRet, _ -> b
    | _, UnknownNoRet -> a
    | NotNoRet, _ -> a
    | _, NotNoRet -> b
    | NoRet, ConditionalNoRet _ -> b
    | ConditionalNoRet _, NoRet -> a
    | ConditionalNoRet n1, ConditionalNoRet n2 when n1 <> n2 -> NoRet
    | _ -> Utils.impossible ()

  let untouchedArgIndexX86 frameDist absV uvAnalysis nth =
    let argOff = frameDist - 4 * nth
    let varKind = SSA.StackVar (32<rt>, argOff)
    SSACFG.findReachingDef absV varKind
    |> Option.bind (function
      | SSA.Def (var, _) ->
        match (uvAnalysis: SSAUntouchedValuePropagation<_>).GetRegValue var with
        | UntouchedValueDomain.Untouched (RegisterTag (StackLocal off)) ->
          Some (- off / 4)
        | _ -> None
      | _ -> None)

  let ssaRegToArgNumX64 hdl rid =
    [ 1 .. 6 ]
    |> List.tryFind (fun nth ->
      rid = CallingConvention.functionArgRegister hdl OS.Linux nth)

  let untouchedArgIndexX64 hdl absV uvAnalysis nth =
    let argReg = CallingConvention.functionArgRegister hdl OS.Linux nth
    let name = hdl.RegisterFactory.RegIDToString argReg
    let varKind = SSA.RegVar (64<rt>, argReg, name)
    match SSACFG.findReachingDef absV varKind with
    | Some (SSA.Def (var, _)) ->
      match (uvAnalysis: SSAUntouchedValuePropagation<_>).GetRegValue var with
      | UntouchedValueDomain.Untouched (RegisterTag (Regular rid)) ->
        ssaRegToArgNumX64 hdl rid
      | _ -> None
    | _ ->
      (* If no definition is found, this means the parameter register is
         untouched, thus conditional no return. *)
      Some nth

  let hasCallFallthroughNode ctx absCallEdge =
    let absV = ctx.AbsVertices[absCallEdge]
    let succs = ctx.CFG.GetSuccs absV
    not <| Seq.isEmpty succs

  let collectReturningCallEdges ctx =
    ctx.CallTable.Callees
    |> Seq.fold (fun acc (KeyValue (callSite, calleeKind)) ->
      match calleeKind with
      | RegularCallee callee -> (callSite, Some callee) :: acc
      | IndirectCallees callees ->
        Set.fold (fun acc callee -> (callSite, Some callee) :: acc) acc callees
      | _ -> acc) []
    |> List.filter (hasCallFallthroughNode ctx)

  let tryGetConnectedArgument ctx ssa uvAnalysis callEdge nth =
    let callSite = fst callEdge
    let callerSSAV = SSACFG.findVertexByAddr ssa callSite
    let absSSAV = ssa.GetSuccs callerSSAV |> Seq.exactlyOne
    let arch = (ctx: CFGBuildingContext<_, _, _, _>).BinHandle.File.ISA.Arch
    match ctx.CallTable.TryGetFrameDistance callSite with
    | true, frameDist when arch = Architecture.IntelX86 ->
      untouchedArgIndexX86 frameDist absSSAV uvAnalysis nth
    | true, _ when arch = Architecture.IntelX64 ->
      untouchedArgIndexX64 ctx.BinHandle absSSAV uvAnalysis nth
    | _ -> None

  let collectConditionalNoRetCalls ctx =
    let ssa = ctx.SSACFG
    let hdl = ctx.BinHandle
    let uvAnalysis = SSAUntouchedValuePropagation (hdl)
    (uvAnalysis: IDataFlowAnalysis<_, _, _, _>).Compute ssa
    collectReturningCallEdges ctx
    |> List.choose (fun callEdge ->
      let absV = ctx.AbsVertices[callEdge]
      match absV.VData.AbstractContent.ReturningStatus with
      | ConditionalNoRet nth ->
        tryGetConnectedArgument ctx ssa uvAnalysis callEdge nth
        |> Option.bind (fun nth' -> Some (absV, nth'))
      | NotNoRet | UnknownNoRet -> None
      | NoRet -> Utils.impossible ())

  let tryFindCondNoRetDom domCtx absVSet v =
    Dominator.doms domCtx v
    |> Array.filter (fun v -> Set.contains v absVSet)
    |> fun doms ->
      if Array.isEmpty doms then None
      else
        (* When there are two or more conditionally returning (and dominating)
           abstract vertices, we assume that they will be referring to the same
           callee. *)
        Some doms[0]

  let getStatusFromDominators domCtx absVSet argNumMap exit =
    match tryFindCondNoRetDom domCtx absVSet exit with
    | None -> NotNoRet
    | Some dom -> ConditionalNoRet <| Map.find dom argNumMap

  let analyze ctx =
    let domCtx = Dominator.initDominatorContext ctx.CFG
    let exits = ctx.CFG.Exits
    let condNoRetCalls = collectConditionalNoRetCalls ctx
    let absVSet = condNoRetCalls |> List.map fst |> Set.ofList
    let argNumMap = condNoRetCalls |> Map.ofSeq
    let mutable status = UnknownNoRet
    let mutable i = 0
    let updateStatus foundStatus = status <- meet status foundStatus
    while i < exits.Length && status <> NotNoRet do
      let v = exits[i]
      i <- i + 1
      if not v.VData.IsAbstract then
        if not <| v.VData.LastInstruction.IsRET () then ()
        else
          updateStatus (getStatusFromDominators domCtx absVSet argNumMap v)
      else
        match v.VData.AbstractContent.ReturningStatus with
        | ConditionalNoRet _ -> updateStatus NoRet
        | NotNoRet ->
          updateStatus (getStatusFromDominators domCtx absVSet argNumMap v)
        | status -> updateStatus status
    status

  interface IPostAnalysis<unit -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
      fun () ->
        match analyze ctx with
        | UnknownNoRet -> ctx.NonReturningStatus <- defaultStatus
        | status -> ctx.NonReturningStatus <- status
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
        <| $"{ctx.FunctionAddress:x}: {ctx.NonReturningStatus}"
#endif

module CondAwareNoretAnalysis =
  let private hasNonZeroOnX86 st nth =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match (st: EvalState).TryGetReg esp with
    | Def esp ->
      let p = esp.Add (BitVector.OfInt32 (4 * nth) 32<rt>)
      let endian = Endian.Little
      match st.Memory.Read (BitVector.ToUInt64 p) endian 32<rt> with
      | Ok v -> not <| BitVector.IsZero v
      | _ -> false
    | _ -> false

  let private hasNonZeroOnX64 hdl st nth =
    let reg = CallingConvention.functionArgRegister hdl OS.Linux nth
    match (st: EvalState).TryGetReg reg with
    | Def bv -> not <| bv.IsZero ()
    | _ -> false

  let hasLocallyZeroOrTopCondition (hdl: BinHandle) caller nth =
    let st = CFGEvaluator.evalBlockFromScratch hdl caller
    match hdl.File.ISA.Arch with
    | Architecture.IntelX86 -> not <| hasNonZeroOnX86 st nth
    | Architecture.IntelX64 -> not <| hasNonZeroOnX64 hdl st nth
    | _ -> false
