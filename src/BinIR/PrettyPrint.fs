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

namespace B2R2.BinIR

open System
open System.Text

/// <summary>
/// Exposes pretty printing functions for LowUIR and SSA statements.
/// </summary>
type PrettyPrinter =
  /// <summary>
  ///   Given a list of LowUIR statements, return a well-formated string.
  /// </summary>
  /// <param name="lowuirStmts">LowUIR statements.</param>
  static member ToString(lowuirStmts: LowUIR.Stmt[]) =
    let sb = StringBuilder()
    for stmt in lowuirStmts do
      LowUIR.Stmt.AppendToString(stmt, sb)
      sb.Append(Environment.NewLine) |> ignore
    sb.ToString()

  /// <summary>
  ///   Given a LowUIR statement, return a well-formated string.
  /// </summary>
  /// <param name="lowuirStmt">LowUIR statement.</param>
  static member inline ToString(lowuirStmt: LowUIR.Stmt) =
    LowUIR.Stmt.ToString lowuirStmt

  /// <summary>
  ///   Given a LowUIR expression, return a well-formated string.
  /// </summary>
  /// <param name="lowuirExpr">LowUIR expression.</param>
  static member inline ToString(lowuirExpr: LowUIR.Expr) =
    LowUIR.Expr.ToString lowuirExpr

  /// <summary>
  ///   Given a list of SSA statements, return a well-formated string.
  /// </summary>
  /// <param name="ssaStmts">LowUIR statements.</param>
  static member ToString(ssaStmts: SSA.Stmt[]) =
    let sb = StringBuilder()
    for stmt in ssaStmts do
      SSA.Stmt.AppendToString(stmt, sb)
      sb.Append(Environment.NewLine) |> ignore
    sb.ToString()

  /// <summary>
  ///   Given an SSA statement, return a well-formated string.
  /// </summary>
  /// <param name="ssaStmt">SSA statement.</param>
  static member inline ToString(ssaStmt: SSA.Stmt) =
    SSA.Stmt.ToString ssaStmt

  /// <summary>
  ///   Given an SSA expression, return a well-formated string.
  /// </summary>
  /// <param name="ssaExpr">SSA expression.</param>
  static member inline ToString(ssaExpr: SSA.Expr) =
    SSA.Expr.ToString ssaExpr
