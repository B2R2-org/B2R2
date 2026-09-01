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


/// Provides the stack-pointer reasoning that the LowUIR-based data-flow
/// frameworks share.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.DataFlow.LowUIRStackPointer

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd

/// Translates the given stack pointer address to a local frame offset.
let inline toFrameOffset stackAddr =
  int (stackAddr - Constants.InitialStackPointer)

/// Returns the variable kind of the stack pointer along with the value it
/// holds on function entry, or None when the architecture has none.
let initialValue (hdl: BinHandle) =
  match hdl.RegisterFactory.StackPointer with
  | None ->
    None
  | Some rid ->
    let rt = hdl.RegisterFactory.GetRegType rid
    let bv = BitVector(Constants.InitialStackPointer, rt)
    Some(Regular rid, StackPointerDomain.ConstSP bv)

/// Evaluates the given expression in the stack-pointer domain at the given
/// point, resolving every variable it reads through `evalVar`.
let rec evalExpr evalVar pt (e: Expr) =
  match e with
  | Num(bv, _) ->
    StackPointerDomain.ConstSP bv
  | Var _ | TempVar _ ->
    evalVar (VarKind.ofIRExpr e) pt
  | Load(_, _, addr, _) ->
    match evalExpr evalVar pt addr with
    | StackPointerDomain.ConstSP bv ->
      let offset = bv.ToUInt64() |> toFrameOffset
      evalVar (StackLocal offset) pt
    | c ->
      c
  | BinOp(binOpType, _, e1, e2, _) ->
    let v1 = evalExpr evalVar pt e1
    let v2 = evalExpr evalVar pt e2
    match binOpType with
    | BinOpType.ADD -> StackPointerDomain.add v1 v2
    | BinOpType.SUB -> StackPointerDomain.sub v1 v2
    | BinOpType.AND -> StackPointerDomain.``and`` v1 v2
    | _ -> StackPointerDomain.NotConstSP
  | _ ->
    StackPointerDomain.NotConstSP
