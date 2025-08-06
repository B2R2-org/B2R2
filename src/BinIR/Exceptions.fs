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

/// <namespacedoc>
///   <summary>
///   Contains types that define intermediate representations (IRs) used in
///   B2R2 including LowUIR and SSA.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Raised when an illegal AST type is used. This should never be raised in
/// normal situation.
/// </summary>
exception IllegalASTTypeException
/// Raised when an assignment expression has an invalid destination expression.
exception InvalidAssignmentException
/// Rasied when an invalid expression is encountered during type checking or
/// evaluation.
exception InvalidExprException
/// Raised when an expression does not type-check.
exception TypeCheckException of string
/// Raised when an illegal number of bits is used to represent floats.
exception InvalidFloatTypeException
