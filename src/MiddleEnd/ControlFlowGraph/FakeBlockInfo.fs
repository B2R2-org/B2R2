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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd

/// A mapping from the return value type to the return value expression.
type OutVariableInfo = Map<SSA.VariableKind, SSA.Expr>

module OutVariableInfo =

  /// Translate the given expression into another one w.r.t caller's context.
  /// Its translation is done by replacing the stack variable with the
  /// corresponding load expression. Note that our current impl of SSA
  /// construction does not rename stack variables in fake blocks due to the
  /// order of steps.
  let rec private translateExprForCallerContext hdl = function
    | SSA.Var { Kind = SSA.StackVar (rt, off) } -> (* convert into Load(...) *)
      let memVar: SSA.Variable = { Kind = SSA.MemVar; Identifier = -1 }
      let spRid = (hdl: BinHandle).RegisterFactory.StackPointer |> Option.get
      let spRegStr = hdl.RegisterFactory.RegIDToString spRid
      let spVar: SSA.Variable =
        { Kind = SSA.RegVar (rt, spRid, spRegStr); Identifier = -1 }
      let sp = SSA.Var spVar
      let amount = SSA.Num <| BitVector.OfInt32 off rt
      let shiftedAddr = SSA.BinOp (BinOpType.SUB, rt, sp, amount)
      SSA.Load (memVar, rt, shiftedAddr)
    | SSA.Var var -> SSA.Var { var with Identifier = -1 }
    | SSA.BinOp (op, rt, e1, e2) ->
      let e1 = translateExprForCallerContext hdl e1
      let e2 = translateExprForCallerContext hdl e2
      SSA.BinOp (op, rt, e1, e2)
    | SSA.UnOp (op, rt, e) ->
      SSA.UnOp (op, rt, translateExprForCallerContext hdl e)
    | SSA.Load (v, rt, e) ->
      SSA.Load (v, rt, translateExprForCallerContext hdl e)
    | SSA.Cast (kind, rt, e) ->
      SSA.Cast (kind, rt, translateExprForCallerContext hdl e)
    | SSA.RelOp (op, rt, e1, e2) ->
      let e1 = translateExprForCallerContext hdl e1
      let e2 = translateExprForCallerContext hdl e2
      SSA.RelOp (op, rt, e1, e2)
    | SSA.Extract (e, rt, pos) ->
      SSA.Extract (translateExprForCallerContext hdl e, rt, pos)
    | e -> e

  let add hdl var e i =
    let e = translateExprForCallerContext hdl e
    Map.add var e i

/// IRBasicBlock can be either a fake block or a regular block. FakeBlockInfo
/// exists only for fake blocks.
type FakeBlockInfo = {
  /// Call site address, i.e., the call instruction's address.
  CallSite: Addr
  /// How many bytes of the stack does this function unwind when return?
  UnwindingBytes: int64
  /// What is the distance between the caller's stack frame (activation record)
  /// and the callee's stack frame? If the distance is always constant, we
  /// remember the value here.
  FrameDistance: int option
  ///
  OutVariableInfo: OutVariableInfo
  /// Is this fake block points to a PLT entry?
  IsPLT: bool
  /// Is this fake block represents a tail call? So, this fake block is
  /// connected with a regular jump edge, not with a call edge.
  IsTailCall: bool
  /// Is the caller invoke this fake block as an indirect call?
  IsIndirectCall: bool
  /// Is this a system call? This is possible when a `call` instruction is used
  /// to make a system call. For example, in x86, `call dword ptr [GS:0x10]`
  /// will be a system call.
  IsSysCall: bool
}
