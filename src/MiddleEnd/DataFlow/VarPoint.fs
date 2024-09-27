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

/// Variable at a specific program point.
type VarPoint = {
  /// Program point of the variable.
  ProgramPoint: ProgramPoint
  /// Kind of the variable.
  VarKind: VarKind
}

/// VarPoint with IRProgramPoint.
and IRVarPoint = {
  /// Program point of the variable.
  IRProgramPoint: IRProgramPoint
  /// Kind of the variable.
  VarKind: VarKind
}

/// Special program point that expresses either (1) a regular program point or
/// (2) a program point in an abstract vertex.
and IRProgramPoint =
  /// Regular program point.
  | IRPPReg of ProgramPoint
  /// Program point in an abstract vertex.
  | IRPPAbs of callsite: Addr * callee: Addr * position: int

/// Variable kinds of our interest.
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

module VarKind =
  let ofIRExpr (e: LowUIR.Expr) =
    match e.E with
    | LowUIR.Var (_, rid, _) -> Regular rid
    | LowUIR.TempVar (_, n) -> Temporary n
    | _ -> Utils.impossible ()

  let ofSSAVarKind (kind: SSA.VariableKind) =
    match kind with
    | SSA.RegVar (_, rid, _) -> Regular rid
    | SSA.TempVar (_, n) -> Temporary n
    | SSA.StackVar (_, offset) -> StackLocal offset
    | _ -> Utils.impossible ()
