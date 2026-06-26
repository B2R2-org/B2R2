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

/// The kind of synchronous CPU exception an instruction raised.
type ExceptionKind =
  /// Integer divide error, e.g., divide-by-zero or signed overflow.
  | DivideError
  /// Signed integer arithmetic overflow trap.
  | IntegerOverflow
  /// General-protection or privilege fault.
  | ProtectionFault
  /// Misaligned memory access.
  | MisalignedAccess
  /// Floating-point exception.
  | FloatingPointException

/// <summary>
/// Provides functions to access <see cref='T:B2R2.BinIR.ExceptionKind'/>.
/// </summary>
[<RequireQualifiedAccess>]
module ExceptionKind =

  /// <summary>
  /// Retrieves the LowUIR string representation of the exception kind.
  /// </summary>
  [<CompiledName "ToString">]
  let toString = function
    | DivideError -> "DivideError"
    | IntegerOverflow -> "IntegerOverflow"
    | ProtectionFault -> "ProtectionFault"
    | MisalignedAccess -> "MisalignedAccess"
    | FloatingPointException -> "FloatingPointException"

  /// <summary>
  /// Tries to retrieve an exception kind from a LowUIR string representation.
  /// </summary>
  [<CompiledName "TryOfString">]
  let tryOfString (s: string) =
    match s.ToLowerInvariant() with
    | "divideerror" -> Some DivideError
    | "integeroverflow" -> Some IntegerOverflow
    | "protectionfault" -> Some ProtectionFault
    | "misalignedaccess" -> Some MisalignedAccess
    | "floatingpointexception" -> Some FloatingPointException
    | _ -> None

  /// <summary>
  /// Creates an exception kind from a LowUIR string representation.
  /// </summary>
  [<CompiledName "OfString">]
  let ofString s =
    match tryOfString s with
    | Some kind -> kind
    | None -> raise IllegalASTTypeException
