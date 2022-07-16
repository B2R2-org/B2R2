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

[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.ControlFlowAnalysis.SSAPromotion

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

let private extractStackVar stmt =
  match stmt with
  | Def (v, _) -> v
  | _ -> Utils.impossible ()

let private findLastStackDef v targetVarKind =
  SSACFG.findReachingDef v targetVarKind
  |> Option.map extractStackVar

let private updateIfStackValueIsConstant (v: Vertex<SSABasicBlock>) spState sp =
  match CPState.findReg spState sp with
  | SPValue.Const bv ->
    let spValue = BitVector.ToUInt64 bv
    let offset = Utils.InitialStackPointer - spValue |> int |> Some
    v.VData.FakeBlockInfo <-
      { v.VData.FakeBlockInfo with FrameDistance = offset }
  | _ -> ()

/// If the vertex is fake, it means the vertex represents a function. We check
/// if the function's stack frame (activation record) is located at a constant
/// stack offset. If so, we remember the offset.
let private updateStackFrameDistance hdl g (v: Vertex<SSABasicBlock>) spState =
  match hdl.RegisterBay.StackPointer with
  | Some rid ->
    let spName = hdl.RegisterBay.RegIDToString rid
    let spRegKind = RegVar (hdl.ISA.WordSize |> WordSize.toRegType, rid, spName)
    match findLastStackDef v spRegKind with
    | Some sp -> updateIfStackValueIsConstant v spState sp
    | None -> ()
  | None -> ()

let private memStore ((pp, _) as stmtInfo) rt addr src =
  match addr with
  | SPValue.Const addr ->
    let addr = BitVector.ToUInt64 addr
    let offset = int (int64 Utils.InitialStackPointer - int64 addr)
    let v = { Kind = StackVar (rt, offset); Identifier = 0 }
    Some (pp, Def (v, src))
  | _ -> Some stmtInfo

let private loadToVar rt addr =
  match addr with
  | SPValue.Const addr ->
    let addr = BitVector.ToUInt64 addr
    let offset = int (int64 Utils.InitialStackPointer - int64 addr)
    let v = { Kind = StackVar (rt, offset); Identifier = 0 }
    Some (Var v)
  | _ -> None

let rec private replaceLoad spState v e =
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
  | _ -> None

let private stmtChooser spState v ((pp, stmt) as stmtInfo) =
  match stmt with
  | Phi (_, _) -> None
  | Def ({ Kind = MemVar }, Store (_, rt, addr, src)) ->
    let addr = SPTransfer.evalExpr spState v addr
    memStore stmtInfo rt addr src
  | Def (dstVar, e) ->
    match replaceLoad spState v e with
    | Some e -> Some (pp, Def (dstVar, e))
    | None -> Some stmtInfo
  | _ -> Some stmtInfo

/// The basic preparation step: remove Phis and replace stack variables.
let prepare hdl ssaCFG spState vertices (v: Vertex<SSABasicBlock>) =
  (vertices: List<SSAVertex>).Add v
  if v.VData.IsFakeBlock () then updateStackFrameDistance hdl ssaCFG v spState
  else ()
  v.VData.SSAStmtInfos
  |> Array.choose (stmtChooser spState v)
  |> fun stmts -> v.VData.SSAStmtInfos <- stmts

/// Promote the given SSA CFG into another SSA CFG that contains resolved
/// stack/global variables.
let promote hdl (ssaCFG: DiGraph<SSABasicBlock, CFGEdgeKind>) ssaRoot =
  let spp = StackPointerPropagation (hdl, ssaCFG)
  let spState = spp.Compute ssaRoot
  let vertices = List<SSAVertex> ()
  DiGraph.iterVertex ssaCFG (prepare hdl ssaCFG spState vertices)
  SSACFG.installPhis vertices ssaCFG ssaRoot
  struct (ssaCFG, ssaRoot)
