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

namespace B2R2.FrontEnd.BinLifter

open System.Collections
open B2R2.BinIR.LowUIR

/// IRBuilder accumulates IR statements while lifting, and emits them into an
/// array of statements at the end of a lifting process.
type IRBuilder =
  inherit Generic.List<Stmt>

  val TempVarCount: AST.IDCounter
  val LabelCount: AST.IDCounter

  /// <summary>
  ///   Initialize an IR statement builder of internal buffer size n.
  /// </summary>
  /// <param name="n">The size of the internal buffer.</param>
  new (n: int) =
    { inherit Generic.List<Stmt>(n)
      TempVarCount = AST.IDCounter.Init ()
      LabelCount = AST.IDCounter.Init () }

  /// <summary>
  ///   Create a new temporary variable of RegType (rt).
  /// </summary>
  member inline __.NewTempVar rt = AST.tmpvar rt __.TempVarCount

  /// <summary>
  ///   Create a new symbol for a label.
  /// </summary>
  member inline __.NewSymbol name = AST.symbol name __.LabelCount

  /// <summary>
  ///   Append a new IR statement to the builder.
  /// </summary>
  /// <param name="stmt">IR statement to add.</param>
  member __.Append stmt = __.Add (stmt)

  /// <summary>
  ///   Create an array of IR statements from the buffer.
  /// </summary>
  /// <returns>
  ///   Returns a list of IR statements.
  /// </returns>
  member __.ToStmts () = __.ToArray ()
