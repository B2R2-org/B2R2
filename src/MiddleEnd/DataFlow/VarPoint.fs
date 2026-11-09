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
  /// Memory instance, which stands for all the memory that the code reaches
  /// through an address that is not known.
  | Memory
  /// Stack local variable at a specific offset from where the stack pointer
  /// points on entry.
  | StackLocal of int
  /// Global variable at the given address, which the code reaches through a
  /// constant address.
  | Global of Addr

/// Provides utility functions for VarKind.
module VarKind =
  /// Converts a LowUIR expression to a VarKind.
  let ofIRExpr (e: LowUIR.Expr) =
    match e with
    | LowUIR.Var(RegisterID = rid) -> Regular rid
    | LowUIR.TempVar(Index = n) -> Temporary n
    | _ -> Terminator.impossible ()

  /// Converts an SSA variable kind to a VarKind.
  let ofSSAVarKind (kind: SSA.VariableKind) =
    match kind with
    | SSA.RegVar(_, rid, _) -> Regular rid
    | SSA.TempVar(_, n) -> Temporary n
    | SSA.StackVar(_, offset) -> StackLocal offset
    | SSA.GlobalVar(_, addr) -> Global addr
    | _ -> Terminator.impossible ()

  /// Returns true if the given VarKind is a temporary variable.
  let isTemporary (kind: VarKind) =
    match kind with
    | Temporary _ -> true
    | _ -> false

  /// Walks the given expression and hands the kind of every variable it reads
  /// to `onVarRead`. A load reads a variable in memory too whenever
  /// `tryMemoryVarKind` can name the memory at its address.
  let rec iterUses onVarRead tryMemoryVarKind (e: LowUIR.Expr) =
    match e with
    | LowUIR.Var(RegisterID = rid) ->
      onVarRead (Regular rid)
    | LowUIR.TempVar(Index = n) ->
      onVarRead (Temporary n)
    | LowUIR.ExprList(Elements = exprs) ->
      for e in exprs do iterUses onVarRead tryMemoryVarKind e
    | LowUIR.Load(Addr = addr) ->
      iterUses onVarRead tryMemoryVarKind addr
      match tryMemoryVarKind addr with
      | Some vk -> onVarRead vk
      | None -> ()
    | LowUIR.UnOp(Operand = e)
    | LowUIR.Cast(Operand = e)
    | LowUIR.Extract(Operand = e) ->
      iterUses onVarRead tryMemoryVarKind e
    | LowUIR.BinOp(Left = e1; Right = e2)
    | LowUIR.RelOp(Left = e1; Right = e2) ->
      iterUses onVarRead tryMemoryVarKind e1
      iterUses onVarRead tryMemoryVarKind e2
    | LowUIR.Ite(Cond = e1; TrueExpr = e2; FalseExpr = e3) ->
      iterUses onVarRead tryMemoryVarKind e1
      iterUses onVarRead tryMemoryVarKind e2
      iterUses onVarRead tryMemoryVarKind e3
    | LowUIR.RoundCtrl(Mode = mode; Body = body) ->
      iterUses onVarRead tryMemoryVarKind mode
      iterUses onVarRead tryMemoryVarKind body
    | _ ->
      ()
