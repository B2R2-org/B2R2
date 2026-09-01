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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR

/// <summary>
/// Represents a variable at a specific program point.
/// </summary>
type VarPoint =
  { /// Program point of the variable.
    ProgramPoint: ProgramPoint
    /// Kind of the variable.
    VarKind: VarKind }

/// Represents the kind of a variable.
and VarKind =
  /// Regular variable that represents a register.
  | Regular of RegisterID
  /// Temporary variable that represents a temporary variable used in our IR.
  | Temporary of int
  /// Memory instance. The optional field is used only when the memory address
  /// is a constant.
  | Memory of Addr option
  /// Stack local variable at a specific offset.
  | StackLocal of int

/// Provides utility functions for VarKind.
module VarKind =
  /// Converts a LowUIR expression to a VarKind.
  let ofIRExpr (e: LowUIR.Expr) =
    match e with
    | LowUIR.Var(_, rid, _, _) -> Regular rid
    | LowUIR.TempVar(_, n, _) -> Temporary n
    | _ -> Terminator.impossible ()

  /// Converts an SSA variable kind to a VarKind.
  let ofSSAVarKind (kind: SSA.VariableKind) =
    match kind with
    | SSA.RegVar(_, rid, _) -> Regular rid
    | SSA.TempVar(_, n) -> Temporary n
    | SSA.StackVar(_, offset) -> StackLocal offset
    | _ -> Terminator.impossible ()

  /// Returns true if the given VarKind is a temporary variable.
  let isTemporary (kind: VarKind) =
    match kind with
    | Temporary _ -> true
    | _ -> false

  /// Walks the given expression and hands the kind of every variable it reads
  /// to `onVarRead`. A load reads a stack slot too whenever `tryStackOffset`
  /// can turn its address into a frame offset.
  let rec iterUses onVarRead tryStackOffset (e: LowUIR.Expr) =
    match e with
    | LowUIR.Var(_, rid, _, _) ->
      onVarRead (Regular rid)
    | LowUIR.TempVar(_, n, _) ->
      onVarRead (Temporary n)
    | LowUIR.ExprList(exprs, _) ->
      for e in exprs do iterUses onVarRead tryStackOffset e
    | LowUIR.Load(_, _, addr, _) ->
      iterUses onVarRead tryStackOffset addr
      match tryStackOffset addr with
      | Some offset -> onVarRead (StackLocal offset)
      | None -> ()
    | LowUIR.UnOp(_, e, _)
    | LowUIR.Cast(_, _, e, _)
    | LowUIR.Extract(e, _, _, _) ->
      iterUses onVarRead tryStackOffset e
    | LowUIR.BinOp(_, _, e1, e2, _)
    | LowUIR.RelOp(_, e1, e2, _) ->
      iterUses onVarRead tryStackOffset e1
      iterUses onVarRead tryStackOffset e2
    | LowUIR.Ite(e1, e2, e3, _) ->
      iterUses onVarRead tryStackOffset e1
      iterUses onVarRead tryStackOffset e2
      iterUses onVarRead tryStackOffset e3
    | _ ->
      ()
