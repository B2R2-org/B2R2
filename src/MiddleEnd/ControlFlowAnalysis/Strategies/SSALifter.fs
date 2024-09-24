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

open B2R2
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.SSA

/// Perform stack pointer propgation analysis on the current SSACFG. This
/// analysis performs mainly two tasks: (1) identify stack variables and promote
/// the SSACFG, and (2) calculate the stack frame size of the function.
type SSALifter () =
  let extractStackVar stmt =
    match stmt with
    | Def (v, _) -> v
    | _ -> Utils.impossible ()

  let findLastStackDef v targetVarKind =
    SSACFG.findReachingDef v targetVarKind
    |> Option.map extractStackVar

  let updateIfStackValueIsConstant ctx (ssaCFG: SSACFG) state v sp =
    match (state: SSAVarBasedDataFlowState<_>).GetRegValue sp with
    | StackPointerDomain.ConstSP bv ->
      let spValue = BitVector.ToUInt64 bv
      let offset = Constants.InitialStackPointer - spValue |> int
      let intraCallTable = (ctx: CFGBuildingContext<_, _>).IntraCallTable
      let pred = ssaCFG.GetPreds v |> Seq.exactlyOne
      let stmts = pred.VData.Internals.Statements
      let lastPP, _ = stmts[stmts.Length - 1]
      intraCallTable.UpdateFrameDistance lastPP.Address offset
#if CFGDEBUG
      dbglog ctx.ThreadID "FrameDistance" $"{lastPP.Address:x}: {offset}"
#endif
    | _ -> ()

  let updateFrameDistance ctx ssaCFG state (v: IVertex<SSABasicBlock>) =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    match hdl.RegisterFactory.StackPointer with
    | Some rid ->
      let spName = hdl.RegisterFactory.RegIDToString rid
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let spRegKind = RegVar (rt, rid, spName)
      match findLastStackDef v spRegKind with
      | Some sp -> updateIfStackValueIsConstant ctx ssaCFG state v sp
      | None -> ()
    | None -> ()

  let createCallback ctx =
    { new ISSAVertexCallback with
        member _.OnVertexCreation ssaCFG state v =
          if (v.VData :> IAbstractable<_>).IsAbstract then
            updateFrameDistance ctx ssaCFG state v
          else () }

  interface ICFGAnalysis<unit -> SSACFG> with
    member _.Unwrap env =
      let ctx = env.Context
      fun () ->
        let vCallback = createCallback ctx
        let ssaLifter =
          SSALifterFactory.Create (ctx.BinHandle, vCallback)
        ssaLifter.Lift ctx.CFG
