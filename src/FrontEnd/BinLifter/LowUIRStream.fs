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

/// <summary>
/// Provides a stream for building LowUIR statements. This will accumulate
/// LowUIR statements and return them as an array when requested. It also
/// maintains internal counters for temporary variables and labels to avoid
/// name collisions.
/// </summary>
type LowUIRStream(capacity) =
  inherit Generic.List<Stmt>(capacity = capacity)

  let mutable tempVarCount = 0
  let mutable labelCount = 0
  let mutable insAddress = 0UL

  /// <summary>
  /// Create a new LowUIRStream.
  /// </summary>
  new() = LowUIRStream 241

  /// <summary>
  ///   Create a new temporary variable of RegType (rt).
  /// </summary>
  member _.NewTempVar rt =
    tempVarCount <- tempVarCount + 1
    AST.tmpvar rt tempVarCount

  /// <summary>
  ///   Create a new label.
  /// </summary>
  member _.NewLabel name =
    labelCount <- labelCount + 1
    AST.label name labelCount insAddress

  /// <summary>
  ///   Append a new IR statement to the builder and set the instruction
  ///   address. This is used for the very first statement of an instruction.
  /// </summary>
  /// <param name="stmt">IR statement to add.</param>
  member _.Append(addr, stmt) =
    insAddress <- addr
    base.Add stmt

  /// <summary>
  ///   Append a new IR statement to the builder.
  /// </summary>
  /// <param name="stmt">IR statement to add.</param>
  member _.Append stmt = base.Add stmt

  /// <summary>
  ///   Create an array of IR statements from the buffer. This function will
  ///   clear up the buffer and initialize the tempvar count, too.
  /// </summary>
  /// <returns>
  ///   Returns an array of IR statements.
  /// </returns>
  member _.ToStmts() =
#if EMULATION
    tempVarCount <- 0
#endif
    let stmts = base.ToArray()
    base.Clear()
    stmts

  /// <summary>
  /// Starts a new instruction located at the given address. This is used for
  /// the very first statement of an instruction to create an ISMark statement.
  /// </summary>
  member _.MarkStart(addr, insLen: uint32) =
    insAddress <- addr
    base.Add(AST.ismark insLen)

  /// <summary>
  /// Finishes the current instruction. This is used for the last statement of
  /// an instruction to create an IEMark statement.
  /// </summary>
  member _.MarkEnd insLen =
    base.Add(AST.iemark insLen)
