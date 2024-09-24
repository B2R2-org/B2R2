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

namespace B2R2

/// Error cases and corresponding numbers for B2R2.
type ErrorCase =
  /// Failed to parse instruction(s), or encoded data.
  | ParsingFailure = 0
  /// Invalid access to memory.
  | InvalidMemoryRead = 1
  /// Invalid expression is evaluated.
  | InvalidExprEvaluation = 2
  /// Symbol does not exist.
  | SymbolNotFound = 3
  /// Item does not exist.
  | ItemNotFound = 4
  /// Invalid format.
  | InvalidFormat = 5
  /// The IR is not implemented yet.
  | NotImplementedIR = 6
  /// Invalid use of operand has been encountered.
  | InvalidOperand = 7
  /// Invalid operand size has been used.
  | InvalidOperandSize = 8
  /// Invalid opcode has been used.
  | InvalidOpcode = 9
  /// Invalid register has been used.
  | InvalidRegister = 10
  /// Encountered register expression that is not yet handled.
  | UnhandledRegExpr = 11
  /// Encountered a not executable address while parsing binaries.
  | NotExecutableAddress = 12
  /// Invalid function address is encountered during a CFG analysis.
  | InvalidFunctionAddress = 13
  /// Encountered an instruction address at the middle of an exisitng
  /// instruction while parsing binaries.
  | IntrudingInstruction = 14
  /// Encountered fatal error while recovering CFG.
  | FailedToRecoverCFG = 15
  /// Encountered unexpected error.
  | UnexpectedError = 16

[<RequireQualifiedAccess>]
module ErrorCase =
  /// Convert an error case type to a string.
  [<CompiledName "ToString">]
  let toString errCase =
    match errCase with
    | ErrorCase.ParsingFailure -> "Failed to parse."
    | ErrorCase.InvalidMemoryRead -> "Read invalid memory."
    | ErrorCase.InvalidExprEvaluation -> "Attempted to evalute invalid expr."
    | ErrorCase.SymbolNotFound -> "Symbol not found."
    | ErrorCase.ItemNotFound -> "Item not found."
    | ErrorCase.InvalidFormat -> "Given invalid format."
    | ErrorCase.NotImplementedIR -> "Not implemented IR."
    | ErrorCase.InvalidOperand -> "Invalid operand."
    | ErrorCase.InvalidOperandSize -> "Invalid operand size."
    | ErrorCase.InvalidOpcode -> "Invalid opcode."
    | ErrorCase.InvalidRegister -> "Invalid register."
    | ErrorCase.UnhandledRegExpr -> "Unhandled register expression."
    | ErrorCase.NotExecutableAddress -> "Not executable address."
    | ErrorCase.InvalidFunctionAddress -> "Given invalid function address."
    | ErrorCase.IntrudingInstruction -> "Intruding instruction."
    | ErrorCase.FailedToRecoverCFG -> "Failed to recover CFG."
    | ErrorCase.UnexpectedError -> "Unexpected error."
    | _ -> invalidArg (nameof errCase) "Unknown error case."
