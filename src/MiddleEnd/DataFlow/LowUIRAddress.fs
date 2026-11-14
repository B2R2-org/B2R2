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


/// Provides the reasoning about addresses that the LowUIR-based data-flow
/// frameworks share.
[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.DataFlow.LowUIRAddress

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd

/// Translates the given address on the stack, i.e., its offset from where the
/// stack pointer points on entry, to a local frame offset. The offset wraps
/// around in the width of the stack pointer, which may be narrower or wider
/// than the frame offset.
let toFrameOffset (offset: BitVector) =
  let low =
    if offset.Length > 32<rt> then BitVector.Extract(offset, 32<rt>, 0)
    else BitVector.SExt(offset, 32<rt>)
  int (low.ToUInt64())

/// Returns the variable kind of the stack pointer along with the value it
/// holds on function entry, or None when the architecture has none.
let initialValue (hdl: BinHandle) =
  match hdl.RegisterFactory.StackPointer with
  | None ->
    None
  | Some rid ->
    let rt = hdl.RegisterFactory.GetRegType rid
    Some(Regular rid, AddressDomain.StackAddr(BitVector.Zero rt))

/// Gets the kind of the variable that names the memory at the given address,
/// if the address is a known one: a slot of the stack frame or a global
/// variable.
let tryGetMemoryVarKind = function
  | AddressDomain.OnStack off -> Some(StackLocal(toFrameOffset off))
  | AddressDomain.Const addr -> Some(Global(addr.ToUInt64()))
  | _ -> None

/// Evaluates the given expression in the address domain at the given point,
/// resolving every variable it reads through `evalVar`. The domain follows no
/// value through memory, so what a load reads is unknown once its address is
/// known.
let rec evalExpr evalVar pt (e: Expr) =
  match e with
  | Num(Value = bv) ->
    AddressDomain.Const bv
  | Var _ | TempVar _ ->
    evalVar (VarKind.ofIRExpr e) pt
  | Load(Addr = addr) ->
    match evalExpr evalVar pt addr with
    | AddressDomain.Undef -> AddressDomain.Undef
    | _ -> AddressDomain.NotAConst
  | BinOp(Op = binOpType; Left = e1; Right = e2) ->
    let v1 = evalExpr evalVar pt e1
    let v2 = evalExpr evalVar pt e2
    match binOpType with
    | BinOpType.ADD -> AddressDomain.add v1 v2
    | BinOpType.SUB -> AddressDomain.sub v1 v2
    | BinOpType.AND -> AddressDomain.``and`` v1 v2
    | BinOpType.OR -> AddressDomain.``or`` v1 v2
    | _ -> AddressDomain.NotAConst
  | _ ->
    AddressDomain.NotAConst
