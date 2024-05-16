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
open B2R2.MiddleEnd.DataFlow

/// Perform stack memory analysis on the current SSACFG. This analysis performs
/// mainly two tasks: (1) identify stack variables and update the SSACFG, and
/// (2) calculate the stack frame size of the function.
type StackAnalysis () =
  let extractStackVar stmt =
    match stmt with
    | Def (v, _) -> v
    | _ -> Utils.impossible ()

  let findLastStackDef v targetVarKind =
    SSACFG.findReachingDef v targetVarKind
    |> Option.map extractStackVar

  let updateIfStackValueIsConstant ctx spState (v: IVertex<SSABasicBlock>) sp =
    match CPState.findReg spState sp with
    | SPValue.Const bv ->
      let spValue = BitVector.ToUInt64 bv
      let offset = Utils.InitialStackPointer - spValue |> int
      let callTable = (ctx: CFGBuildingContext<_, _, _, _>).CallTable
      let pred = ctx.SSACFG.GetPreds v |> Seq.exactlyOne
      let stmts = pred.VData.LiftedSSAStmts
      let lastPP, _ = stmts[stmts.Length - 1]
      callTable.UpdateFrameDistance lastPP.Address offset
#if CFGDEBUG
      dbglog ctx.ThreadID "FrameDistance" $"{lastPP.Address:x}: {offset}"
#endif
    | _ -> ()

  let updateFrameDistance ctx spState (v: IVertex<SSABasicBlock>) =
    let hdl = (ctx: CFGBuildingContext<_, _, _, _>).BinHandle
    match hdl.RegisterFactory.StackPointer with
    | Some rid ->
      let spName = hdl.RegisterFactory.RegIDToString rid
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let spRegKind = RegVar (rt, rid, spName)
      match findLastStackDef v spRegKind with
      | Some sp -> updateIfStackValueIsConstant ctx spState v sp
      | None -> ()
    | None -> ()

  let memStore ((pp, _) as stmtInfo) rt addr src =
    match addr with
    | SPValue.Const addr ->
      let addr = BitVector.ToUInt64 addr
      let offset = int (int64 Utils.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar (rt, offset); Identifier = 0 }
      Some (pp, Def (v, src))
    | _ -> Some stmtInfo

  let loadToVar rt addr =
    match addr with
    | SPValue.Const addr ->
      let addr = BitVector.ToUInt64 addr
      let offset = int (int64 Utils.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar (rt, offset); Identifier = 0 }
      Some (Var v)
    | _ -> None

  let rec replaceLoad spState v e =
    match e with
    | Load (_, rt, addr) ->
      let addr = SPTransfer.evalExpr spState v addr
      loadToVar rt addr
    | Cast (ck, rt, e) ->
      replaceLoad spState v e
      |> Option.map (fun e -> Cast (ck, rt, e))
    | Extract (e, rt, sPos) ->
      replaceLoad spState v e
      |> Option.map (fun e -> Extract (e, rt, sPos))
    | ReturnVal (addr, rt, e) ->
      replaceLoad spState v e
      |> Option.map (fun e -> ReturnVal (addr, rt, e))
    | _ -> None

  let stmtChooser spState v ((pp, stmt) as stmtInfo) =
    match stmt with
    | Phi _ -> None
    | Def ({ Kind = MemVar }, Store (_, rt, addr, src)) ->
      let addr = SPTransfer.evalExpr spState v addr
      memStore stmtInfo rt addr src
    | Def (dstVar, e) ->
      match replaceLoad spState v e with
      | Some e -> Some (pp, Def (dstVar, e))
      | None -> Some stmtInfo
    | _ -> Some stmtInfo

  interface IPostAnalysis<CPState<SPValue> -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof StackAnalysis) $"{ctx.FunctionAddress:x}"
#endif
      fun spState ->
        for v in ctx.SSACFG.Vertices do
          if v.VData.IsAbstract then updateFrameDistance ctx spState v else ()
          v.VData.LiftedSSAStmts
          |> Array.choose (stmtChooser spState v)
          |> fun stmts -> v.VData.LiftedSSAStmts <- stmts
        env.SSALifter.UpdatePhis (ctx.SSACFG, env.SSARoot)
