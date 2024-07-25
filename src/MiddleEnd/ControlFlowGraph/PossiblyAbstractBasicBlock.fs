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

/// This exception is thrown when an abstract basic block is accessed as if it
/// is a regular block.
exception AbstractBlockAccessException

/// Basic block that may or may not be in an abstract form. For example, we
/// create an abstract basic block for a function while building an
/// intra-procedural CFG.
[<AbstractClass>]
type PossiblyAbstractBasicBlock<'Stmt>
  public (ppoint, absContent: FunctionAbstraction<'Stmt>) =
  inherit BasicBlock (ppoint)

  /// Return if this is an abstract basic block inserted by our analysis. We
  /// create an abstract block to represent a function in a CFG.
  member __.IsAbstract with get () = not (isNull absContent)

  /// The abstract content of the basic block summarizing a function. If the
  /// block is not an abstract one, this property raises an exception.
  member __.AbstractContent with get() =
    if isNull absContent then raise AbstractBlockAccessException
    else absContent
