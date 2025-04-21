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
open B2R2
open B2R2.BinIR.LowUIR

/// IRBuilder accumulates IR statements while lifting, and emits them into an
/// array of statements at the end of a lifting process.
type IRBuilder =
  inherit Generic.List<Stmt>

  val mutable TempVarCount: int
  val mutable LabelCount: int
  val mutable InsAddress: Addr

  /// <summary>
  ///   Initialize an IR statement builder of internal buffer size n.
  /// </summary>
  /// <param name="n">The size of the internal buffer.</param>
  new (n: int) =
    { inherit Generic.List<Stmt>(n)
      TempVarCount = 0
      LabelCount = 0
      InsAddress = 0UL }

  /// <summary>
  ///   Create a new temporary variable of RegType (rt).
  /// </summary>
  member inline this.NewTempVar rt =
    this.TempVarCount <- this.TempVarCount + 1
    AST.tmpvar rt this.TempVarCount

  /// <summary>
  ///   Create a new label.
  /// </summary>
  member inline this.NewLabel name =
    this.LabelCount <- this.LabelCount + 1
    AST.label name this.LabelCount this.InsAddress

  /// <summary>
  ///   Append a new IR statement to the builder and set the instruction
  ///   address. This is used for the very first statement of an instruction.
  /// </summary>
  /// <param name="stmt">IR statement to add.</param>
  member this.Append (addr, stmt) =
    this.InsAddress <- addr
    this.Add stmt

  /// <summary>
  ///   Append a new IR statement to the builder.
  /// </summary>
  /// <param name="stmt">IR statement to add.</param>
  member this.Append stmt = this.Add stmt

  /// <summary>
  ///   Create an array of IR statements from the buffer. This function will
  ///   clear up the buffer and initialize the tempvar count, too.
  /// </summary>
  /// <returns>
  ///   Returns an array of IR statements.
  /// </returns>
  member this.ToStmts () =
#if EMULATION
    this.TempVarCount <- 0
#endif
    let stmts = this.ToArray ()
    this.Clear ()
    stmts
