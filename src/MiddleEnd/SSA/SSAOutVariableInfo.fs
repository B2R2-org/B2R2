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
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd

/// A mapping from a defined SSA variable to the corresponding value expression.
type SSAOutVariableInfo = Map<VariableKind, Expr>

module SSAOutVariableInfo =
  /// Translate the given expression into another one w.r.t caller's context.
  /// Its translation is done by replacing the stack variable with the
  /// corresponding load expression. Note that our current impl of SSA
  /// construction does not rename stack variables in abstract basic blocks
  /// for simplicity.
  let rec private translateExprForCallerContext hdl = function
    | Var { Kind = StackVar (rt, off) } -> (* convert into Load(...) *)
      let memVar: Variable = { Kind = MemVar; Identifier = -1 }
      let spRid = (hdl: BinHandle).RegisterFactory.StackPointer |> Option.get
      let spRegStr = hdl.RegisterFactory.RegIDToString spRid
      let spVar: Variable =
        { Kind = RegVar (rt, spRid, spRegStr); Identifier = -1 }
      let sp = Var spVar
      let amount = Num <| BitVector.OfInt32 off rt
      let shiftedAddr = BinOp (BinOpType.SUB, rt, sp, amount)
      Load (memVar, rt, shiftedAddr)
    | Var var -> Var { var with Identifier = -1 }
    | BinOp (op, rt, e1, e2) ->
      let e1 = translateExprForCallerContext hdl e1
      let e2 = translateExprForCallerContext hdl e2
      BinOp (op, rt, e1, e2)
    | UnOp (op, rt, e) ->
      UnOp (op, rt, translateExprForCallerContext hdl e)
    | Load (v, rt, e) ->
      Load (v, rt, translateExprForCallerContext hdl e)
    | Cast (kind, rt, e) ->
      Cast (kind, rt, translateExprForCallerContext hdl e)
    | RelOp (op, rt, e1, e2) ->
      let e1 = translateExprForCallerContext hdl e1
      let e2 = translateExprForCallerContext hdl e2
      RelOp (op, rt, e1, e2)
    | Extract (e, rt, pos) ->
      Extract (translateExprForCallerContext hdl e, rt, pos)
    | e -> e

  let add hdl var e varMap =
    let e = translateExprForCallerContext hdl e
    Map.add var e varMap
