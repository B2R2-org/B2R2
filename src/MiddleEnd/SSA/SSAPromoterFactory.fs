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

namespace B2R2.MiddleEnd.SSA

open B2R2
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

module private SSAPromoterFactory =
  let memStore pp rt addr src =
    match addr with
    | StackPointerDomain.ConstSP addr ->
      let addr = addr.ToUInt64()
      let offset = int (int64 Constants.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar(rt, offset); Identifier = 0 }
      Some(pp, Def(v, src))
    | _ ->
      None

  let loadToVar rt addr =
    match addr with
    | StackPointerDomain.ConstSP addr ->
      let addr = addr.ToUInt64()
      let offset = int (int64 Constants.InitialStackPointer - int64 addr)
      let v = { Kind = StackVar(rt, offset); Identifier = 0 }
      Some(Var v)
    | _ ->
      None

  let rec replaceLoad (state: SSASparseDataFlow.State<_>) e =
    match e with
    | Load(memVar, rt, addr) ->
      let addrValue = state.EvalExpr addr
      match loadToVar rt addrValue with
      | Some e ->
        Some e
      | None ->
        match replaceLoad state addr with
        | Some addr -> Some(Load(memVar, rt, addr))
        | None -> None
    | ExprList exprs ->
      let exprs' = List.map (replaceLoad state) exprs
      if List.forall Option.isNone exprs' then
        None
      else
        exprs'
        |> List.map2 Option.defaultValue exprs
        |> ExprList
        |> Some
    | Store(memVar, rt, addr, src) ->
      let addr' = replaceLoad state addr |> Option.defaultValue addr
      let src' = replaceLoad state src |> Option.defaultValue src
      if addr' = addr && src' = src then None
      else Some(Store(memVar, rt, addr', src'))
    | UnOp(op, rt, e) ->
      replaceLoad state e
      |> Option.map (fun e -> UnOp(op, rt, e))
    | BinOp(op, rt, le, re) ->
      let le' = replaceLoad state le |> Option.defaultValue le
      let re' = replaceLoad state re |> Option.defaultValue re
      if le' = le && re' = re then None else Some(BinOp(op, rt, le', re'))
    | RelOp(op, rt, le, re) ->
      let le' = replaceLoad state le |> Option.defaultValue le
      let re' = replaceLoad state re |> Option.defaultValue re
      if le' = le && re' = re then None else Some(RelOp(op, rt, le', re'))
    | Ite(cond, rt, le, re) ->
      let cond' = replaceLoad state cond |> Option.defaultValue cond
      let le' = replaceLoad state le |> Option.defaultValue le
      let re' = replaceLoad state re |> Option.defaultValue re
      if cond' = cond && le' = le && re' = re then None
      else Some(Ite(cond', rt, le', re'))
    | Cast(ck, rt, e) ->
      replaceLoad state e
      |> Option.map (fun e -> Cast(ck, rt, e))
    | Extract(e, rt, sPos) ->
      replaceLoad state e
      |> Option.map (fun e -> Extract(e, rt, sPos))
    | _ ->
      None

  let stmtChooser state ((pp, stmt) as stmtInfo) =
    match stmt with
    | Phi _ ->
      None
    | Def({ Kind = MemVar } as dstMemVar, Store(memVar, rt, addrExpr, src)) ->
      let addr = (state: SSASparseDataFlow.State<_>).EvalExpr addrExpr
      let src = replaceLoad state src |> Option.defaultValue src
      match memStore pp rt addr src with
      | Some stmtInfo ->
        Some stmtInfo
      | None ->
        let addrExpr =
          replaceLoad state addrExpr |> Option.defaultValue addrExpr
        Some(pp, Def(dstMemVar, Store(memVar, rt, addrExpr, src)))
    | Def(dstVar, e) ->
      match replaceLoad state e with
      | Some e -> Some(pp, Def(dstVar, e))
      | None -> Some stmtInfo
    | _ ->
      Some stmtInfo

  /// Propagates the stack pointer through the given SSACFG.
  let propagateStackPointer hdl ssaCFG =
    let spp = SSAStackPointerPropagation hdl
    let dfa = spp :> IDataFlowComputable<_, _, _, _>
    dfa.Compute ssaCFG

  /// Rewrites every stack slot the given propagation knows the address of
  /// into a variable of its own.
  let promote state ssaCFG =
    for v in (ssaCFG: SSACFG).Vertices do
      v.VData.Internals.Statements
      |> Array.choose (stmtChooser state)
      |> v.VData.Internals.UpdateStatements

  let create hdl (observer: ISSAStackPointerObserver) =
    { new ISSAPromotable with
        member _.Promote lifted =
          let ssaCFG, dom = lifted.Graph, lifted.Dominance
          let state = propagateStackPointer hdl ssaCFG
          (* The propagation is observed on the graph it read, and before the
             form is built below over variables whose identifiers it is keyed
             under. Later than here it is unreadable. *)
          observer.Observe(ssaCFG, dom, state)
          promote state ssaCFG
          (* Promotion turns stack slots into variables the phi placement that
             lifted the graph knew nothing about, and it drops every phi that
             placement left, so the form is built once more over what
             promotion leaves behind. *)
          SSAForm.build ssaCFG dom
          lifted }

/// Provides ways to create an SSA promoter.
type SSAPromoterFactory =
  /// Creates an SSA promoter for the given binary.
  static member Create(hdl: BinHandle) =
    SSAPromoterFactory.create hdl
      { new ISSAStackPointerObserver with
          member _.Observe(_, _, _) = () }

  /// Creates an SSA promoter for the given binary, handing the stack pointer
  /// propagation it reads to the given observer.
  static member Create(hdl, observer) =
    SSAPromoterFactory.create hdl observer
